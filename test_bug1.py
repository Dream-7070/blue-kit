import unittest
from bluekit.logs.sigma import SigmaEngine

class TestBug1(unittest.TestCase):
    def test_masquerading(self):
        engine = SigmaEngine()
        rule = next((r for r in engine.rules if r['title'] == 'Suspicious Process Masquerading As SvcHost.EXE'), None)
        self.assertIsNotNone(rule)
        engine.rules = [rule]
        
        # Test 1: Should NOT hit
        ev_clean = {'process': r'C:\Windows\System32\svchost.exe', 'raw': {'Image': r'C:\Windows\System32\svchost.exe'}}
        hit = engine.match_event(ev_clean)
        self.assertEqual(len(hit), 0, f"Expected no hits, got {hit}")
        
        # Test 2: Should hit
        ev_mal = {'process': r'C:\Users\x\AppData\Local\Temp\svchost.exe', 'raw': {'Image': r'C:\Users\x\AppData\Local\Temp\svchost.exe'}}
        hit2 = engine.match_event(ev_mal)
        self.assertEqual(len(hit2), 1, "Expected 1 hit")
        
    def test_synthetic_not_1_of(self):
        engine = SigmaEngine(kb_path=None)
        row = {
            'rule_id': '1', 'title': 'test', 'level': 'high', 'techniques': '',
            'detection': '''
condition: selection and not 1 of filter_*
selection:
  Image|endswith: \svchost.exe
filter_a:
  Image: C:\Windows\System32\svchost.exe
filter_b:
  OriginalFileName: svchost.exe
'''
        }
        r = engine._parse_rule(row)
        engine.rules = [r]
        
        # Should hit (no filter matched)
        ev1 = {'raw': {'Image': r'C:\Temp\svchost.exe'}}
        self.assertEqual(len(engine.match_event(ev1)), 1)
        
        # Should NOT hit (filter_a matched)
        ev2 = {'raw': {'Image': r'C:\Windows\System32\svchost.exe'}}
        self.assertEqual(len(engine.match_event(ev2)), 0)
        
        # Should NOT hit (filter_b matched)
        ev3 = {'raw': {'Image': r'C:\Temp\svchost.exe', 'OriginalFileName': 'svchost.exe'}}
        self.assertEqual(len(engine.match_event(ev3)), 0)

if __name__ == '__main__':
    unittest.main()
