import unittest
import yaml
import re
import tempfile
import json
import os
import io
import contextlib
import csv
from collections import Counter

from bluekit.paths import get_kb_path
from bluekit.kb.query import KB
from bluekit.logs.detect import detect_event
from bluekit.logs.parse import load
from bluekit.ir.correlator import extract_canonical
from bluekit.logs.report import analyze_logs

class TestRansomwareHeuristic(unittest.TestCase):
    def test_yaml_rule_regex(self):
        yaml_path = os.path.join("bluekit", "kb", "heuristics.yaml")
        with open(yaml_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
            
        t1486_rules = [r for r in data if 'T1486' in r.get('techniques', []) or r.get('technique') == 'T1486' or 'T1486' in r.get('tags', [])]
        self.assertEqual(len(t1486_rules), 1)
        
        pattern = t1486_rules[0]['pattern']
        p = re.compile(pattern, re.I)
        
        should_match = [
            r"C:\ProgramData\lock.exe -enc D:\Shares",
            r"lock.exe -enc C:\VMs",
            r'"C:\Users\Public\x.exe" --encrypt \\fs01\share',
            r"locker -encrypt=D:\ ",
            r"enc.exe /encrypt E:\backup",
            r"./locker --encrypt /vmfs/volumes",
            r"crypt.exe -enc Shares"
        ]
        
        for s in should_match:
            self.assertTrue(p.search(s), msg=s)
            
        should_not_match = [
            r"powershell.exe -nop -w hidden -enc SQBFAFgA",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -enc JABzAD0A",
            r"pwsh -enc AAAA",
            r"gpg --encrypt C:\backup\a.txt",
            r"openssl enc -aes-256-cbc -in C:\a",
            r"cipher /e C:\secret",
            r"ffmpeg -i a.mp4 -enc x264",
            r"tool.exe -encoding utf8 C:\x",
            r"node app.js --enc-key abc",
            r"lock.exe -enc"
        ]
        
        for s in should_not_match:
            self.assertFalse(p.search(s), msg=s)

    def test_detect_event_kb(self):
        kb_path = get_kb_path()
        if not os.path.exists(kb_path):
            self.skipTest("KB directory not found")
        kb = KB(kb_path)
        
        ev = {'channel': 'Microsoft-Windows-Sysmon/Operational', 'event_id': '1', 'command_line': r'C:\ProgramData\lock.exe -enc D:\Shares', 'message': '', 'src_ip': None}
        hits = detect_event(kb, ev)
        t1486_hits = [h for h in hits if h['technique'] == 'T1486' and h['confidence'] == 'high']
        self.assertEqual(len(t1486_hits), 1)
        
        ev2 = {'channel': 'Microsoft-Windows-Sysmon/Operational', 'event_id': '1', 'command_line': r'powershell.exe -nop -w hidden -enc SQBFAFgA', 'message': '', 'src_ip': None}
        hits2 = detect_event(kb, ev2)
        
        t1486_hits2 = [h for h in hits2 if h['technique'] == 'T1486']
        self.assertEqual(len(t1486_hits2), 0)
        
        t1059_hits2 = [h for h in hits2 if h['technique'] == 'T1059.001']
        self.assertEqual(len(t1059_hits2), 1)

class TestTargetUserFallback(unittest.TestCase):
    def setUp(self):
        self.header = "@timestamp,host.name,user.name,winlog.channel,event.code,process.name,process.parent.name,process.command_line,source.ip,destination.ip,winlog.event_data.TargetUserName,message"

    def test_empty_user_uses_target(self):
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.csv') as f:
            f.write(self.header + "\n")
            f.write("2026-09-25T01:10:00Z,RDP-GW,,Security,4625,,,,45.9.148.200,,administrator,failed logon\n")
            path = f.name
        
        try:
            evs = load(path)
            self.assertEqual(evs[0]['user'], 'administrator')
            self.assertEqual(evs[0]['target'], 'administrator')
            
            evs2 = load(path, preset='ecs')
            self.assertEqual(evs2[0]['user'], 'administrator')
            self.assertEqual(evs2[0]['target'], 'administrator')
        finally:
            os.remove(path)
            
    def test_user_name_wins(self):
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.csv') as f:
            f.write(self.header + "\n")
            f.write("2026-09-25T01:10:00Z,RDP-GW,SYSTEM,Security,4625,,,,45.9.148.200,,administrator,failed logon\n")
            path = f.name
            
        try:
            evs = load(path)
            self.assertEqual(evs[0]['user'], 'SYSTEM')
        finally:
            os.remove(path)

    def test_dash_target_ignored(self):
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.csv') as f:
            f.write(self.header + "\n")
            f.write("2026-09-25T01:10:00Z,RDP-GW,,Security,4625,,,,45.9.148.200,,-,failed logon\n")
            path = f.name
            
        try:
            evs = load(path)
            self.assertIn(evs[0]['user'], ('', None))
        finally:
            os.remove(path)

    def test_nested_json(self):
        data = [{"@timestamp": "2026-09-25T01:10:00Z", "host": {"name": "DC1"}, "user": {"name": ""}, "event": {"code": "4625"}, "winlog": {"channel": "Security", "event_data": {"TargetUserName": "bob"}}, "source": {"ip": "10.0.0.9"}}]
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.json') as f:
            json.dump(data, f)
            path = f.name
            
        try:
            evs = load(path, preset='ecs')
            self.assertEqual(evs[0]['user'], 'bob')
        finally:
            os.remove(path)
            
    def test_target_filename_not_user(self):
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.csv') as f:
            f.write("@timestamp,host.name,user.name,TargetFilename\n")
            f.write("2026-09-25T01:10:00Z,WS1,,C:\\Users\\Public\\a.exe\n")
            path = f.name
            
        try:
            evs = load(path)
            self.assertIn(evs[0]['user'], ('', None))
        finally:
            os.remove(path)

class TestCorrelatorUser(unittest.TestCase):
    def test_flat(self):
        ev = {'@timestamp': '2026-09-25T01:10:00Z', 'user.name': '', 'winlog.event_data.TargetUserName': 'administrator'}
        canon = extract_canonical(ev)
        self.assertEqual(canon['user'], 'administrator')
        
    def test_nested(self):
        ev = {'@timestamp': '2026-09-25T01:10:00Z', 'winlog': {'event_data': {'TargetUserName': 'bob'}}}
        canon = extract_canonical(ev)
        self.assertEqual(canon['user'], 'bob')
        
    def test_user_wins(self):
        ev = {'@timestamp': '2026-09-25T01:10:00Z', 'user': {'name': 'alice'}, 'winlog': {'event_data': {'TargetUserName': 'bob'}}}
        canon = extract_canonical(ev)
        self.assertEqual(canon['user'], 'alice')

class TestExternalLogon(unittest.TestCase):
    def setUp(self):
        kb_path = get_kb_path()
        if not os.path.exists(kb_path):
            self.skipTest("KB directory not found")
        self.kb = KB(kb_path)
        
    def test_external_ip(self):
        ev = {'channel': 'Security', 'event_id': '4624', 'command_line': None, 'message': '', 'src_ip': '45.9.148.200'}
        hits = detect_event(self.kb, ev)
        hit_dict = {h['technique']: h['confidence'] for h in hits}
        self.assertEqual(hit_dict.get('T1133'), 'medium')
        self.assertEqual(hit_dict.get('T1078'), 'medium')
        self.assertEqual(hit_dict.get('T1021.001'), 'low')
        
    def test_internal_ip(self):
        ev = {'channel': 'Security', 'event_id': '4624', 'command_line': None, 'message': '', 'src_ip': '10.20.0.5'}
        hits = detect_event(self.kb, ev)
        hit_dict = {h['technique']: h['confidence'] for h in hits}
        self.assertEqual(hit_dict.get('T1021.001'), 'medium')
        self.assertEqual(hit_dict.get('T1078'), 'medium')
        self.assertNotIn('T1133', hit_dict)
        
    def test_no_ip(self):
        ev = {'channel': 'Security', 'event_id': '4624', 'command_line': None, 'message': '', 'src_ip': None}
        hits = detect_event(self.kb, ev)
        hit_dict = {h['technique']: h['confidence'] for h in hits}
        self.assertEqual(hit_dict.get('T1021.001'), 'medium')
        self.assertNotIn('T1133', hit_dict)
        
    def test_noise_downgrade(self):
        ev = {'channel': 'Security', 'event_id': '4624', 'command_line': None, 'message': 'An account was successfully logged on. Logon type 3', 'src_ip': '45.9.148.200'}
        hits = detect_event(self.kb, ev)
        hit_dict = {h['technique']: h['confidence'] for h in hits}
        self.assertEqual(hit_dict.get('T1133'), 'low')

class TestScn01EndToEnd(unittest.TestCase):
    def test_end_to_end(self):
        csv_path = r"D:\Claude Projects\CTF\mashq\2026-10-01-scn01-ransomware\events\collector_all_hosts.csv"
        if not os.path.exists(csv_path):
            self.skipTest(f"Data file not found: {csv_path}")
            
        kb_path = get_kb_path()
        if not os.path.exists(kb_path):
            self.skipTest("KB directory not found")
            
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.json') as tmp:
            json_path = tmp.name
            
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                analyze_logs([csv_path], KB(kb_path), json_path=json_path)
                
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            timeline = data.get('timeline', [])
            chains = data.get('chains', [])
            
            t1486_high = [t for t in timeline if any(h.get('technique') == 'T1486' and h.get('confidence') == 'high' for h in t.get('techniques', []))]
            self.assertEqual(len(t1486_high), 2)
            
            hosts = set(t.get('host') for t in t1486_high)
            self.assertEqual(hosts, {'FS-01', 'HV-01'})
            
            fs01_chains = [c for c in chains if c.get('host') == 'FS-01']
            hv01_chains = [c for c in chains if c.get('host') == 'HV-01']
            
            for c in fs01_chains:
                self.assertIn('impact', c.get('tactics', []))
            for c in hv01_chains:
                self.assertIn('impact', c.get('tactics', []))
                
            logons = [t for t in timeline if str(t.get('raw', {}).get('event.code')) in ('4624', '4625')]
            self.assertEqual(len(logons), 41)
            
            users = [t.get('user') for t in logons]
            self.assertEqual(set(users), {'administrator'})
            self.assertEqual(len(users), 41)
            
            rdpgw_chains = [c for c in chains if c.get('host') == 'RDP-GW']
            for c in rdpgw_chains:
                tactics = c.get('tactics', [])
                self.assertNotIn('lateral-movement', tactics)
                self.assertIn('initial-access', tactics)
                
            rdpgw_logons = [t for t in timeline if t.get('host') == 'RDP-GW' and str(t.get('raw', {}).get('event.code')) == '4624']
            has_t1133 = False
            for t in rdpgw_logons:
                if any(h.get('technique') == 'T1133' for h in t.get('techniques', [])):
                    has_t1133 = True
                    break
            self.assertTrue(has_t1133)
            
        finally:
            os.remove(json_path)
