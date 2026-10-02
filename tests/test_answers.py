import unittest
import os
import tempfile
import json
from bluekit.answers import collect, rank, load_ledger, record

class MockKB:
    def validate(self, ids):
        res = []
        for i in ids:
            if i == 'T1070.001':
                res.append({'input': i, 'found': True, 'status': 'revoked', 'name': 'Clear Windows Event Logs', 'replacement': 'T1685.005', 'parent_id': 'T1070'})
            elif i == 'T1059':
                res.append({'input': i, 'found': True, 'status': 'active', 'name': 'Command and Scripting Interpreter', 'replacement': None, 'parent_id': None})
            elif i == 'T1059.001':
                res.append({'input': i, 'found': True, 'status': 'active', 'name': 'PowerShell', 'replacement': None, 'parent_id': 'T1059'})
            elif i == 'UNKNOWN':
                res.append({'input': i, 'found': False, 'status': 'not_found', 'name': 'Unknown', 'replacement': None, 'parent_id': None})
            else:
                res.append({'input': i, 'found': True, 'status': 'active', 'name': f'Name {i}', 'replacement': None, 'parent_id': i.split('.')[0] if '.' in i else None})
        return res

class TestAnswers(unittest.TestCase):
    def setUp(self):
        self.kb = MockKB()
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_multi_source_priority(self):
        # 1. Ko'p manba ustunligi
        c = {
            'T1': {'sources': {'sigma'}, 'sigma_strong_rules': {1,2,3,4,5}, 'sigma_weak_rules': set(), 'sigma_high_crit_rules': set(), 'sigma_count': 5, 'ir_timeline_steps': 0, 'ir_occurrences': 0, 'log_high_conf': False, 'log_low_conf': False, 'log_blob': False, 'log_count': 0, 'evidence': []},
            'T2': {'sources': {'sigma', 'ir_chain'}, 'sigma_strong_rules': {1}, 'sigma_weak_rules': set(), 'sigma_high_crit_rules': set(), 'sigma_count': 1, 'ir_timeline_steps': 0, 'ir_occurrences': 1, 'log_high_conf': False, 'log_low_conf': False, 'log_blob': False, 'log_count': 0, 'evidence': []}
        }
        r = rank(c)
        # T1 score: min(6, 5*3) = 6. No multimanba. Total < 6 occurrences. Total = 6.
        # T2 score: ir_occ(2) + sigma_strong(3) + multimanba(3) = 8.
        self.assertEqual(r[0]['technique'], 'T2')

    def test_chain_step_priority(self):
        # 2. Zanjir qadami eng og'ir
        c = {
            'T1': {'sources': {'ir_chain'}, 'sigma_strong_rules': set(), 'sigma_weak_rules': set(), 'sigma_high_crit_rules': set(), 'sigma_count': 0, 'ir_timeline_steps': 1, 'ir_occurrences': 1, 'log_high_conf': False, 'log_low_conf': False, 'log_blob': False, 'log_count': 0, 'evidence': []},
            'T2': {'sources': {'sigma'}, 'sigma_strong_rules': set(), 'sigma_weak_rules': {1}, 'sigma_high_crit_rules': set(), 'sigma_count': 1, 'ir_timeline_steps': 0, 'ir_occurrences': 0, 'log_high_conf': False, 'log_low_conf': False, 'log_blob': False, 'log_count': 0, 'evidence': []}
        }
        r = rank(c)
        # T1 score: timeline_steps(4) = 4
        # T2 score: weak_sigma(0.5) = 0.5
        self.assertEqual(r[0]['technique'], 'T1')

    def test_revoked_id(self):
        # 3. Revoked ID
        c = {
            'T1070.001': {'sources': {'ir_chain'}, 'sigma_strong_rules': set(), 'sigma_weak_rules': set(), 'sigma_high_crit_rules': set(), 'sigma_count': 0, 'ir_timeline_steps': 1, 'ir_occurrences': 1, 'log_high_conf': False, 'log_low_conf': False, 'log_blob': False, 'log_count': 0, 'evidence': []}
        }
        r = rank(c, kb=self.kb)
        self.assertEqual(r[0]['kb_status'], 'revoked')
        self.assertEqual(r[0]['replacement'], 'T1685.005')

    def test_parent_sub_priority(self):
        # 4. Ota/sub
        c = {
            'T1059': {'sources': {'ir_chain'}, 'sigma_strong_rules': {1}, 'sigma_weak_rules': set(), 'sigma_high_crit_rules': set(), 'sigma_count': 1, 'ir_timeline_steps': 1, 'ir_occurrences': 1, 'log_high_conf': False, 'log_low_conf': False, 'log_blob': False, 'log_count': 0, 'evidence': []},
            'T1059.001': {'sources': {'ir_chain'}, 'sigma_strong_rules': {2}, 'sigma_weak_rules': set(), 'sigma_high_crit_rules': set(), 'sigma_count': 1, 'ir_timeline_steps': 1, 'ir_occurrences': 1, 'log_high_conf': False, 'log_low_conf': False, 'log_blob': False, 'log_count': 0, 'evidence': []}
        }
        # default: sub is higher if scores are equal
        r = rank(c, kb=self.kb)
        self.assertEqual(r[0]['technique'], 'T1059.001')
        
        # prefer_parent=True
        r2 = rank(c, kb=self.kb, prefer_parent=True)
        self.assertEqual(r2[0]['technique'], 'T1059')

    def test_ledger(self):
        # 5. Daftar
        c = {
            'T1': {'sources': {'ir_chain'}, 'sigma_strong_rules': set(), 'sigma_weak_rules': set(), 'sigma_high_crit_rules': set(), 'sigma_count': 0, 'ir_timeline_steps': 1, 'ir_occurrences': 1, 'log_high_conf': False, 'log_low_conf': False, 'log_blob': False, 'log_count': 0, 'evidence': []},
            'T2': {'sources': {'sigma'}, 'sigma_strong_rules': {1}, 'sigma_weak_rules': set(), 'sigma_high_crit_rules': set(), 'sigma_count': 1, 'ir_timeline_steps': 0, 'ir_occurrences': 0, 'log_high_conf': False, 'log_low_conf': False, 'log_blob': False, 'log_count': 0, 'evidence': []}
        }
        ledger_path = os.path.join(self.temp_dir.name, 'answers.json')
        record(ledger_path, 'T1', 'accepted')
        
        ledger = load_ledger(ledger_path)
        r = rank(c, submitted=ledger)
        self.assertEqual(r[0]['technique'], 'T2')
        self.assertEqual(r[1]['technique'], 'T1')
        self.assertTrue(r[1]['submitted'])

    def test_atomic_write(self):
        # 6. Atomik yozuv
        ledger_path = os.path.join(self.temp_dir.name, 'atomic.json')
        for i in range(50):
            record(ledger_path, f'T{i}', 'accepted')
        
        with open(ledger_path, 'r') as f:
            data = json.load(f)
        self.assertEqual(len(data['entries']), 50)

    def test_corrupt_input(self):
        # 7. Buzuq kirish -> warnings
        bad_path = os.path.join(self.temp_dir.name, 'bad.json')
        with open(bad_path, 'w') as f:
            f.write("not json")
            
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            c = collect([bad_path])
            self.assertEqual(len(c), 0)
            self.assertTrue(any("Failed to read/parse" in str(warn.message) for warn in w))

    def test_rank_dynamic(self):
        # 8. Reyting o'zgaruvchan
        c1 = {'T1': {'sources': {'ir_chain'}, 'sigma_strong_rules': set(), 'sigma_weak_rules': set(), 'sigma_high_crit_rules': set(), 'sigma_count': 0, 'ir_timeline_steps': 1, 'ir_occurrences': 1, 'log_high_conf': False, 'log_low_conf': False, 'log_blob': False, 'log_count': 0, 'evidence': []}}
        r1 = rank(c1)
        self.assertEqual(r1[0]['technique'], 'T1')
        
        c2 = {'T2': {'sources': {'ir_chain'}, 'sigma_strong_rules': set(), 'sigma_weak_rules': set(), 'sigma_high_crit_rules': set(), 'sigma_count': 0, 'ir_timeline_steps': 1, 'ir_occurrences': 1, 'log_high_conf': False, 'log_low_conf': False, 'log_blob': False, 'log_count': 0, 'evidence': []}}
        r2 = rank(c2)
        self.assertEqual(r2[0]['technique'], 'T2')

    def test_real_file(self):
        # 9. Haqiqiy fayl bilan
        # We simulate writing `bk ir chain data/samples/win_phishing.csv --json` output to temp file
        # and collecting it. I'll mock the ir_chain json structure.
        ir_path = os.path.join(self.temp_dir.name, 'real_chain.json')
        with open(ir_path, 'w') as f:
            json.dump({
                "mitre_attack_techniques": [
                    {"technique_id": "T1059", "technique_name": "CMD", "occurrences": 2}
                ],
                "attack_chain_timeline": [
                    {"mitre_id": "T1059", "step": 1, "evidence": "cmd.exe"}
                ]
            }, f)
        
        c = collect([ir_path])
        self.assertIn("T1059", c)
        self.assertEqual(c["T1059"]['ir_timeline_steps'], 1)

if __name__ == '__main__':
    unittest.main()
