import unittest
from bluekit.logs.bruteforce import classify_failures

class TestBruteforceClassify(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(classify_failures({'u1': 2, 'u2': 2, 'u3': 2, 'u4': 2, 'u5': 2, 'u6': 2}), 'spray')
        self.assertEqual(classify_failures({'u1': 10, 'u2': 10, 'u3': 10, 'u4': 10, 'u5': 10}), 'spray')
        self.assertEqual(classify_failures({'u1': 30}), 'guessing')
        self.assertEqual(classify_failures({'u1': 28, 'u2': 2}), 'guessing')
        self.assertEqual(classify_failures({'u1': 1, 'u2': 1, 'u3': 1}), 'none')
        
    def test_classify_reverse(self):
        self.assertEqual(classify_failures({'u6': 2, 'u5': 2, 'u4': 2, 'u3': 2, 'u2': 2, 'u1': 2}), 'spray')
        
    def test_bruteforce_stages(self):
        from bluekit.ir.correlator import _bruteforce_stages
        events = []
        for i in range(50):
            u = f"u{(i % 5) + 1}"
            events.append({
                'event.code': '4625',
                'timestamp': f'2026-10-01T10:00:{i:02d}Z',
                'user': u,
                'src_ip': '1.1.1.1',
                'host': 'host1'
            })
        stages, _ = _bruteforce_stages(events)
        self.assertTrue(any(s.technique_id == 'T1110.003' for s, ip in stages))
