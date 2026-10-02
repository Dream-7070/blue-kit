import unittest
import json
import os
import io
import contextlib
import tempfile
from bluekit.resp.logbridge import load_log_artifacts
from bluekit.resp.triage import analyze
from bluekit.logs.report import analyze_logs
from bluekit.kb.query import KB
from bluekit import paths

class TestRespScn01(unittest.TestCase):

    def setUp(self):
        self.kb_path = paths.get_kb_path()
        if os.path.exists(self.kb_path):
            self.kb = KB(self.kb_path)
        else:
            self.kb = None

    def test_bridge_splits_checker_and_beacon(self):
        data = {
            'checkers': [
                {'src': '10.20.0.5', 'dst': '193.43.72.19', 'key': 'k1', 'count': 314, 'interval_seconds': 45.0},
                {'src': '172.16.99.5', 'dst': '10.20.0.20', 'key': 'k2', 'count': 50, 'interval_seconds': 60.0}
            ],
            'iocs': [],
            'timeline': []
        }
        art = load_log_artifacts(data)
        self.assertEqual(art['checker_ips'], {'172.16.99.5'})
        self.assertEqual(art['beacon_ips'], {'193.43.72.19'})
        self.assertNotIn('10.20.0.5', art['checker_ips'])
        self.assertEqual(art['beacon_info']['193.43.72.19']['count'], 314)

    def test_scn01_fs01_end_to_end(self):
        if not self.kb:
            self.skipTest("KB kerak")
            
        csv = r'D:\Claude Projects\CTF\mashq\2026-10-01-scn01-ransomware\events\collector_all_hosts.csv'
        snap_path = r'D:\Tools\blue-kit-dist\case\scn01-ransomware\snapshots\snap_FS-01.json'
        base_path = r'D:\Tools\blue-kit-dist\case\scn01-ransomware\snapshots\base_FS-01.json'
        
        if not os.path.exists(csv) or not os.path.exists(snap_path) or not os.path.exists(base_path):
            self.skipTest("Fayllar yo'q")

        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
            tmp_name = tmp.name

        try:
            f = io.StringIO()
            with contextlib.redirect_stdout(f):
                analyze_logs(csv, self.kb, json_path=tmp_name)
                
            art = load_log_artifacts(tmp_name)
            
            with open(snap_path, 'r', encoding='utf-8-sig') as f_snap:
                snap_FS01 = json.load(f_snap)
            with open(base_path, 'r', encoding='utf-8-sig') as f_base:
                base_FS01 = json.load(f_base)
                
            findings, extra = analyze(self.kb, snap_FS01, base_FS01, None, log_artifacts=art)
            
            # connections
            conn_findings = [f for f in findings if f['category'] == 'connections' and '193.43.72.19' in f['item']]
            self.assertEqual(len(conn_findings), 1)
            f_conn = conn_findings[0]
            self.assertEqual(f_conn['confidence'], 'high')
            self.assertNotIn('checker IP (loglardan)', f_conn['reasons'])
            beacon_reasons = [r for r in f_conn['reasons'] if str(r).startswith('C2 beacon nomzodi')]
            self.assertEqual(len(beacon_reasons), 1)
            tech_ids = [t['id'] for t in f_conn['techniques']]
            self.assertIn('T1071.001', tech_ids)
            
            self.assertNotIn('193.43.72.19', extra['checker_candidates'])
            self.assertNotIn('10.20.0.5', extra['checker_candidates'])
            b_cands = [b['ip'] for b in extra['beacon_candidates']]
            self.assertIn('193.43.72.19', b_cands)
            
            # ransomware
            rw_findings = [f for f in findings if f['category'] == 'ransomware']
            self.assertEqual(len(rw_findings), 2)
            rw_lockbit = [f for f in rw_findings if '.LOCKBIT' in f['item'] and '1 fayl' in f['item']]
            self.assertEqual(len(rw_lockbit), 1)
            self.assertEqual(rw_lockbit[0]['confidence'], 'high')
            self.assertIn('T1486', [t['id'] for t in rw_lockbit[0]['techniques']])
            
            rw_note = [f for f in rw_findings if 'HOW_TO_DECRYPT.txt' in f['item']]
            self.assertEqual(len(rw_note), 1)
            self.assertEqual(rw_note[0]['confidence'], 'high')
            self.assertIn('T1486', [t['id'] for t in rw_note[0]['techniques']])
            
            # tasks
            task_findings = [f for f in findings if f['category'] == 'tasks' and 'SysUpdate' in str(f['item'])]
            self.assertEqual(len(task_findings), 1)
            f_task = task_findings[0]
            self.assertEqual(f_task['confidence'], 'high')
            self.assertIn('T1053.005', [t['id'] for t in f_task['techniques']])
            
            # unmatched
            main = {u['artifact'] for u in extra.get('unmatched_log_artifacts', [])}
            self.assertIn('45.9.148.200', main)
            
            for item in ['8.8.8.8', '20.190.130.44', '151.101.65.69', '52.113.194.132', '140.82.112.3', 'svchost.exe', 'explorer.exe', r'C:\Windows\System32\svchost.exe', r'C:\Windows\explorer.exe']:
                self.assertNotIn(item, main)
                
            other = {u['artifact'] for u in extra.get('unmatched_other', [])}
            self.assertIn('8.8.8.8', other)
            
        finally:
            if os.path.exists(tmp_name):
                os.remove(tmp_name)

    def test_ransomware_patterns_unit(self):
        if not self.kb:
            self.skipTest("KB kerak")
            
        snap_benign = {
            'meta': {'os': 'windows', 'hostname': 'X'},
            'recent_modified': [
                r'C:\a\report.xlsx',
                r'C:\a\x.txt.bak',
                r'C:\a\notes.backup',
                r'C:\a\recovery.log',
                r'C:\a\README.md',
                r'C:\a\data.xlsx.old',
                r'C:\a\setup.exe',
                r'C:\a\photo.jpg.webp',
                r'C:\a\big.zip.part1',
                r'C:\a\doc.pdf.sha256'
            ]
        }
        findings, _ = analyze(self.kb, snap_benign)
        rw_benign = [f for f in findings if f['category'] == 'ransomware']
        self.assertEqual(len(rw_benign), 0)
        
        snap_mal = {
            'meta': {'os': 'windows', 'hostname': 'X'},
            'recent_modified': [
                r'C:\a\b.docx.akira',
                r'C:\a\c.pdf.akira',
                r'C:\a\d.jpg.xyzw123',
                r'C:\a\RESTORE_MY_FILES.txt'
            ]
        }
        findings, _ = analyze(self.kb, snap_mal)
        rw_mal = [f for f in findings if f['category'] == 'ransomware']
        self.assertEqual(len(rw_mal), 3)
        
        akira_f = [f for f in rw_mal if '.akira' in f['item']]
        self.assertEqual(len(akira_f), 1)
        self.assertIn('2 fayl', akira_f[0]['item'])
        
        xyzw_f = [f for f in rw_mal if '.xyzw123' in f['item']]
        self.assertEqual(len(xyzw_f), 1)
        self.assertIn('1 fayl', xyzw_f[0]['item'])
        
        note_f = [f for f in rw_mal if 'RESTORE_MY_FILES.txt' in f['item']]
        self.assertEqual(len(note_f), 1)
        
    def test_bridge_few_outbound_not_beacon(self):
        art = load_log_artifacts({'checkers': [{'src': '10.20.2.20', 'dst': '104.18.32.7', 'key': 'EXCEL', 'count': 4, 'interval_seconds': 7076.0}]})
        self.assertEqual(art['beacon_ips'], set())
        self.assertEqual(art['checker_ips'], set())

    def test_bridge_hosts_entry_regex(self):
        # logbridge hosts-fayl yozuvi regexi (raw string ichida \s, \d — literal backslash emas)
        art = load_log_artifacts({'timeline': [{'host': 'W1', 'techniques': [],
            'command_line': r'cmd /c echo 10.1.2.3 bank.uz >> C:\Windows\System32\drivers\etc\hosts'}]})
        self.assertEqual(art['hosts_entries'], {'10.1.2.3 bank.uz'})
        self.assertEqual(art['artifact_hosts'].get('10.1.2.3 bank.uz'), {'W1'})

    def test_unmatched_backward_compat(self):
        data = {
            'iocs': [{'type': 'ip', 'value': '8.8.8.8'}],
            'timeline': []
        }
        art = load_log_artifacts(data)
        art.pop('artifact_hosts', None)
        
        snap = {
            'meta': {'hostname': 'X'}
        }
        _, extra = analyze(None, snap, log_artifacts=art)
        
        main = {u['artifact'] for u in extra.get('unmatched_log_artifacts', [])}
        self.assertIn('8.8.8.8', main)
        self.assertEqual(extra.get('unmatched_other', []), [])
