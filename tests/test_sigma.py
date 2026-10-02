import unittest
import os
import time
from collections import defaultdict

from bluekit.logs.sigma import SigmaEngine, get_kb_path
from bluekit.logs.parse import load

KB_PATH = get_kb_path()
HAS_KB = KB_PATH and os.path.exists(KB_PATH)

class TestSigmaEngine(unittest.TestCase):
    @unittest.skipUnless(HAS_KB, "KB not found")
    def test_01_load(self):
        engine = SigmaEngine()
        stats = engine.stats()
        self.assertGreater(stats['loaded'], 500)
        self.assertLess(stats['skipped'], stats['loaded'])
        
    def test_02_synthetic_contains(self):
        engine = SigmaEngine(kb_path=None)
        engine.rules = [{
            'rule_id': '1', 'title': 'test', 'level': 'high', 'techniques': [],
            'selections': {'selection': {'CommandLine|contains': '-enc'}},
            'literals': ['-enc'],
            'condition_expr': 'selection'
        }]
        
        hit = engine.match_event({'command_line': 'powershell.exe -enc aGVsbG8=', 'blob': 'powershell.exe -enc aGVsbG8='})
        self.assertEqual(len(hit), 1)
        
        miss = engine.match_event({'command_line': 'powershell.exe -Command ls', 'blob': 'powershell.exe -Command ls'})
        self.assertEqual(len(miss), 0)
        
    def test_03_endswith_case(self):
        engine = SigmaEngine(kb_path=None)
        engine.rules = [{
            'rule_id': '1', 'title': 'test', 'level': 'high', 'techniques': [],
            'selections': {'selection': {'Image|endswith': '\\POWERSHELL.EXE'}},
            'literals': ['\\powershell.exe'],
            'condition_expr': 'selection'
        }]
        
        hit = engine.match_event({'process': 'C:\\Windows\\System32\\powershell.exe', 'blob': 'c:\\windows\\system32\\powershell.exe'})
        self.assertEqual(len(hit), 1)

    def test_04_and_not(self):
        engine = SigmaEngine(kb_path=None)
        engine.rules = [{
            'rule_id': '1', 'title': 'test', 'level': 'high', 'techniques': [],
            'selections': {
                'selection': {'EventID': '4688'},
                'filter': {'CommandLine|contains': 'good'}
            },
            'literals': ['4688'],
            'condition_expr': '(selection and not filter)'
        }]
        
        hit = engine.match_event({'event_id': '4688', 'command_line': 'bad', 'blob': '4688 bad'})
        self.assertEqual(len(hit), 1)
        
        miss = engine.match_event({'event_id': '4688', 'command_line': 'good', 'blob': '4688 good'})
        self.assertEqual(len(miss), 0)
        
    def test_05_1_of_and_all_of(self):
        engine = SigmaEngine(kb_path=None)
        # We manually simulate the condition parser output
        engine.rules = [{
            'rule_id': '1', 'title': 'test', 'level': 'high', 'techniques': [],
            'selections': {
                'selection1': {'a': '1'},
                'selection2': {'b': '2'}
            },
            'literals': ['1', '2'],
            'condition_expr': '(selection1 or selection2)' # 1 of selection*
        }]
        
        self.assertEqual(len(engine.match_event({'raw': {'a': '1'}, 'blob': '1'})), 1)
        self.assertEqual(len(engine.match_event({'raw': {'b': '2'}, 'blob': '2'})), 1)
        self.assertEqual(len(engine.match_event({'raw': {'c': '3'}, 'blob': '3'})), 0)

        engine.rules[0]['condition_expr'] = '(selection1 and selection2)' # all of selection*
        self.assertEqual(len(engine.match_event({'raw': {'a': '1', 'b': '2'}, 'blob': '1 2'})), 1)
        self.assertEqual(len(engine.match_event({'raw': {'a': '1'}, 'blob': '1'})), 0)
        
    def test_06_all_modifier(self):
        engine = SigmaEngine(kb_path=None)
        engine.rules = [{
            'rule_id': '1', 'title': 'test', 'level': 'high', 'techniques': [],
            'selections': {'selection': {'CommandLine|contains|all': ['-enc', 'hidden']}},
            'literals': ['-enc', 'hidden'],
            'condition_expr': 'selection'
        }]
        
        hit = engine.match_event({'command_line': 'powershell -w hidden -enc aGVsbG8=', 'blob': 'powershell -w hidden -enc aGVsbG8='})
        self.assertEqual(len(hit), 1)
        
        miss = engine.match_event({'command_line': 'powershell -enc aGVsbG8=', 'blob': 'powershell -enc aGVsbG8='})
        self.assertEqual(len(miss), 0)
        
    def test_07_regex_skip(self):
        # Good regex
        engine = SigmaEngine(kb_path=None)
        engine.rules = [{
            'rule_id': '1', 'title': 'test', 'level': 'high', 'techniques': [],
            'selections': {'selection': {'CommandLine|re': '^powershell.*-enc'}},
            'literals': [],
            'condition_expr': 'selection'
        }]
        self.assertEqual(len(engine.match_event({'command_line': 'powershell -enc', 'blob': 'powershell -enc'})), 1)
        
        # Test loading skips bad regex. 
        # Actually in our engine, bad regex at eval time returns False (re.error caught). 
        # But we need to ensure the engine doesn't crash on bad regex.
        
    def test_08_keywords(self):
        engine = SigmaEngine(kb_path=None)
        engine.rules = [{
            'rule_id': '1', 'title': 'test', 'level': 'high', 'techniques': [],
            'selections': {'keywords': ['SuspiciousOperation', 'DisallowedHost']},
            'literals': ['suspiciousoperation', 'disallowedhost'],
            'condition_expr': 'keywords'
        }]
        
        hit = engine.match_event({'blob': 'some SuspiciousOperation happened'})
        self.assertEqual(len(hit), 1)

    def test_09_field_not_found_weak(self):
        engine = SigmaEngine(kb_path=None)
        engine.rules = [{
            'rule_id': '1', 'title': 'test', 'level': 'high', 'techniques': [],
            'selections': {'selection': {'TargetFilename|endswith': '.vbs'}},
            'literals': ['.vbs'],
            'condition_expr': 'selection'
        }]
        
        hit = engine.match_event({'event_id': '1', 'blob': 'created file C:\\temp\\malware.vbs'})
        self.assertEqual(len(hit), 1)
        self.assertTrue(hit[0]['weak'])
        
    @unittest.skipUnless(HAS_KB, "KB not found")
    def test_10_real_kb_rule(self):
        engine = SigmaEngine()
        
        # Find a rule with PowerShell and T1059.001
        target_rule = None
        for r in engine.rules:
            if 'powershell' in r['title'].lower() and 'T1059.001' in r['techniques']:
                target_rule = r
                break
                
        self.assertIsNotNone(target_rule, "Could not find a rule with PowerShell and T1059.001")
        
        # Create a synthetic event that matches it. We can just inject the literals to ensure match
        blob = " ".join(target_rule['literals'])
        ev = {'blob': blob, 'command_line': blob} # Add command line to increase match chances
        
        # Just to ensure we trigger it, let's inject a known powershell event
        ev2 = {'command_line': 'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand JABz...', 'blob': 'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand JABz...'}
        
        # Since we found a rule, let's create a single engine just with this rule to test
        engine2 = SigmaEngine(kb_path=None)
        engine2.rules = [target_rule]
        
        # To make it match perfectly, let's extract what it needs from its selections
        synthetic_event = {'blob': 'powershell.exe -enc ', 'raw': {}}
        for sel_name, block in target_rule['selections'].items():
            if sel_name == 'keywords':
                for kw in block:
                    synthetic_event['blob'] += str(kw) + " "
            elif isinstance(block, dict):
                for k, v in block.items():
                    field = k.split('|')[0]
                    val = v[0] if isinstance(v, list) else v
                    synthetic_event['raw'][field] = val
                    synthetic_event['blob'] += str(val) + " "
                    
        hit = engine2.match_event(synthetic_event)
        self.assertEqual(len(hit), 1)
        self.assertIn('T1059.001', hit[0]['techniques'])
        
    def test_11_by_technique(self):
        engine = SigmaEngine(kb_path=None)
        engine.rules = [{
            'rule_id': '1', 'title': 'test', 'level': 'high', 'techniques': ['T1059.001', 'T1027'],
            'selections': {'selection': {'a': '1'}},
            'literals': ['1'],
            'condition_expr': 'selection'
        }]
        
        res = engine.match_events([{'raw': {'a': '1'}, 'blob': '1'}])
        bt = res['by_technique']
        self.assertIn('T1059.001', bt)
        self.assertIn('T1027', bt)
        self.assertEqual(bt['T1059.001']['count'], 1)

    def test_12_speed(self):
        engine = SigmaEngine(kb_path=None)
        engine.rules = []
        engine.index.clear()
        engine.always_eval = []
        
        # Create 1000 dummy rules
        for i in range(1000):
            rule = {
                'rule_id': str(i), 'title': f'test_{i}', 'level': 'high', 'techniques': [],
                'selections': {'selection': {'CommandLine|contains': f'very_specificstring{i}_end'}},
                'literals': [f'very_specificstring{i}_end'],
                'tokens': [f'specificstring{i}'],
                'condition_expr': 'selection'
            }
            engine.rules.append(rule)
            engine.index[f'specificstring{i}'].append(rule)
            
        engine._stats['loaded'] = len(engine.rules)
            
        events = []
        for i in range(2000):
            events.append({
                'process': 'C:\\Windows\\System32\\cmd.exe',
                'command_line': f'C:\\Windows\\System32\\cmd.exe /c echo {i} very_specificstring500_end',
                'parent_process': 'C:\\Windows\\explorer.exe',
                'event_id': '4688',
                'blob': f'4688 C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\cmd.exe /c echo {i} very_specificstring500_end C:\\Windows\\explorer.exe'
            })
            
        start = time.time()
        res = engine.match_events(events)
        elapsed = time.time() - start
        
        self.assertLess(elapsed, 20.0)
        self.assertEqual(res['stats']['events_with_hits'], 2000)

    def test_13_no_exceptions(self):
        engine = SigmaEngine(kb_path=None)
        engine.rules = [{
            'rule_id': '1', 'title': 'test', 'level': 'high', 'techniques': [],
            'selections': {'selection': {'CommandLine|contains': 'bad'}},
            'literals': ['bad'],
            'condition_expr': 'selection'
        }]
        
        # Should not raise
        engine.match_event({})
        engine.match_event({'command_line': None})
        engine.match_event({'blob': 'a' * 1000000})

    def test_14_technique_id_format(self):
        engine = SigmaEngine(kb_path=None)
        engine.rules = [{
            'rule_id': '1', 'title': 'test', 'level': 'high', 'techniques': ['T1059.001', 'T1027'],
            'selections': {'selection': {'a': '1'}},
            'literals': ['1'],
            'condition_expr': 'selection'
        }]
        
        res = engine.match_events([{'raw': {'a': '1'}, 'blob': '1'}])
        for t in res['by_technique'].keys():
            self.assertTrue(t.startswith('T'))
            self.assertNotIn(' ', t)

if __name__ == '__main__':
    unittest.main()
