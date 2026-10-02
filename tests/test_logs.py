import unittest
import os
from bluekit.kb.query import KB
from bluekit.logs.parse import load
from bluekit.logs.detect import detect_event
from bluekit.logs.timeline import build

class TestLogs(unittest.TestCase):
    def setUp(self):
        self.sample_path = r"D:\Claude Projects\CTF\blue-kit\data\samples\win_phishing.csv"
        try:
            self.kb = KB()
        except:
            self.skipTest("KB not available")
            
        if not os.path.exists(self.sample_path):
            self.skipTest("Sample missing")

    def test_logs(self):
        events = load(self.sample_path)
        self.assertGreater(len(events), 0)
        
        hits_by_index = {}
        found_techs = set()
        for i, ev in enumerate(events):
            hits = detect_event(self.kb, ev)
            if hits:
                hits_by_index[i] = hits
                for h in hits:
                    found_techs.add(h['technique'])
                    
        has_expected = 'T1566.001' in found_techs or 'T1204.002' in found_techs or 'T1053.005' in found_techs or 'T1003.001' in found_techs
        self.assertTrue(has_expected, f"Expected techniques not found. Found: {found_techs}")
        
        timeline, chains, iocs, checkers = build(events, hits_by_index, self.kb)
        self.assertGreaterEqual(len(chains), 1)
        
        ips = [i['value'] for i in iocs if i['type'] == 'ip']
        self.assertTrue(any(ips), "No IPs extracted")

    def test_siem_agnostic_splunk(self):
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv', encoding='utf-8') as f:
            f.write("_time,host,user,EventCode,CommandLine\n")
            f.write("2026-10-05T10:00:00Z,WIN-1,admin,1,vssadmin delete shadows /all /quiet\n")
            f.flush()
            path = f.name
            
        events = load(path, preset='splunk')
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev['host'], 'WIN-1')
        hits = detect_event(self.kb, ev)
        techs = [h['technique'] for h in hits]
        self.assertIn("T1490", techs)
        os.remove(path)
        
    def test_siem_agnostic_sentinel(self):
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv', encoding='utf-8') as f:
            f.write("TimeGenerated,DeviceName,AccountName,ProcessCommandLine\n")
            f.write("2026-10-05T10:00:00Z,WIN-2,admin,vssadmin delete shadows /all /quiet\n")
            f.flush()
            path = f.name
            
        events = load(path, preset='sentinel')
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev['host'], 'WIN-2')
        hits = detect_event(self.kb, ev)
        techs = [h['technique'] for h in hits]
        self.assertIn("T1490", techs)
        os.remove(path)

    def test_siem_agnostic_json(self):
        import tempfile
        import json
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json', encoding='utf-8') as f:
            data = {"timestamp": "2026-10-05T10:00:00Z", "agent": {"name": "WIN-3"}, "data": {"win": {"eventdata": {"commandLine": "vssadmin delete shadows /all /quiet"}}}}
            f.write(json.dumps(data) + "\n")
            f.flush()
            path = f.name
            
        events = load(path, preset='wazuh')
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev['host'], 'WIN-3')
        hits = detect_event(self.kb, ev)
        techs = [h['technique'] for h in hits]
        self.assertIn("T1490", techs)
        os.remove(path)

    def test_no_revoked_ids(self):
        events = load(self.sample_path)
        hits_by_index = {}
        for i, ev in enumerate(events):
            hits = detect_event(self.kb, ev)
            if hits:
                hits_by_index[i] = hits
                
        timeline, chains, _, _ = build(events, hits_by_index, self.kb)
        
        all_ids = set()
        for t in timeline:
            for h in t['techniques']:
                all_ids.add(h['technique'])
                
        if all_ids:
            val_res = self.kb.validate(list(all_ids))
            for res in val_res:
                self.assertTrue(res['found'], f"ID {res['input']} not found in KB")
                self.assertEqual(res['status'], 'active', f"ID {res['input']} is {res['status']}, should be active")

    def test_web_linux_logs(self):
        web_sample_path = r"D:\Claude Projects\CTF\blue-kit\data\samples\practice\web_linux.csv"
        if not os.path.exists(web_sample_path):
            self.skipTest("Web sample missing")
            
        events = load(web_sample_path)
        self.assertGreater(len(events), 0)
        
        hits_by_index = {}
        found_techs = set()
        for i, ev in enumerate(events):
            hits = detect_event(self.kb, ev)
            if hits:
                hits_by_index[i] = hits
                for h in hits:
                    found_techs.add(h['technique'])
                    
        self.assertIn('T1190', found_techs)
        self.assertIn('T1505.003', found_techs)
        
        timeline, chains, iocs, checkers = build(events, hits_by_index, self.kb)
        
        found_content = False
        for t in timeline:
            cmd = t.get('command_line') or ""
            msg = t.get('message') or ""
            if "UNION SELECT" in cmd or "shell.php" in cmd or "UNION SELECT" in msg or "shell.php" in msg:
                found_content = True
                break
                
        self.assertTrue(found_content, "Timeline events missing web request content")
