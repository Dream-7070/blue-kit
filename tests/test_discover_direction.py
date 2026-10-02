import unittest
from bluekit.resp.scoring import discover, to_allowlist

class TestDiscoverDirection(unittest.TestCase):
    def test_c2_beacon_not_checker(self):
        snapshots = [
            {
                'meta': {'hostname': 'WS01'},
                'listening_ports': [{'port': 80}],
                'connections': [
                    {'raddr': '185.215.113.66', 'rport': 443, 'lport': 50111, 'proto': 'tcp'},
                    {'raddr': '185.215.113.66', 'rport': 443, 'lport': 50112, 'proto': 'tcp'},
                    {'raddr': '185.215.113.66', 'rport': 443, 'lport': 50113, 'proto': 'tcp'},
                ]
            },
            {
                'meta': {'hostname': 'WS02'},
                'listening_ports': [],
                'connections': [
                    {'raddr': '185.215.113.66', 'rport': 443, 'lport': 51001, 'proto': 'tcp'},
                    {'raddr': '185.215.113.66', 'rport': 443, 'lport': 51002, 'proto': 'tcp'},
                ]
            }
        ]
        res = discover(snapshots)
        cand = next((c for c in res['candidates'] if c['value'] == '185.215.113.66'), None)
        self.assertIsNotNone(cand)
        self.assertEqual(cand['kind'], 'outbound')
        self.assertEqual(cand['confidence'], 'past')
        self.assertTrue(any("C2 bo'lishi mumkin" in e for e in cand['evidence']))
        
        al = to_allowlist(res)
        self.assertNotIn('185.215.113.66/32', al['cidrs'])

    def test_real_checker_inbound(self):
        snapshots = [
            {
                'meta': {'hostname': 'WS01'},
                'listening_ports': [{'port': 80}, {'port': 443}],
                'connections': [
                    {'raddr': '10.0.0.50', 'rport': 50001, 'lport': 80, 'proto': 'tcp'},
                    {'raddr': '10.0.0.50', 'rport': 50002, 'lport': 443, 'proto': 'tcp'},
                ]
            },
            {
                'meta': {'hostname': 'WS02'},
                'listening_ports': [{'port': 80}],
                'connections': [
                    {'raddr': '10.0.0.50', 'rport': 50003, 'lport': 80, 'proto': 'tcp'},
                ]
            }
        ]
        res = discover(snapshots)
        cand = next((c for c in res['candidates'] if c['value'] == '10.0.0.50'), None)
        self.assertIsNotNone(cand)
        self.assertEqual(cand['kind'], 'checker_ip')
        self.assertEqual(cand['confidence'], 'yuqori')
        
        al = to_allowlist(res)
        self.assertIn('10.0.0.50/32', al['cidrs'])

    def test_browser_cdn_outbound(self):
        snapshots = [
            {
                'meta': {'hostname': 'WS01'},
                'listening_ports': [],
                'connections': [
                    {'raddr': '142.250.74.110', 'rport': 443, 'lport': 50001, 'proto': 'tcp'},
                    {'raddr': '142.250.74.110', 'rport': 443, 'lport': 50002, 'proto': 'tcp'},
                    {'raddr': '142.250.74.110', 'rport': 443, 'lport': 50003, 'proto': 'tcp'},
                    {'raddr': '142.250.74.110', 'rport': 443, 'lport': 50004, 'proto': 'tcp'},
                    {'raddr': '142.250.74.110', 'rport': 443, 'lport': 50005, 'proto': 'tcp'},
                ]
            }
        ]
        res = discover(snapshots)
        cand = next((c for c in res['candidates'] if c['value'] == '142.250.74.110'), None)
        self.assertIsNotNone(cand)
        self.assertEqual(cand['kind'], 'outbound')
        
        al = to_allowlist(res)
        self.assertNotIn('142.250.74.110/32', al['cidrs'])

    def test_push_monitoring(self):
        snapshots = [
            {
                'meta': {'hostname': 'WS01'},
                'listening_ports': [],
                'connections': [
                    {'raddr': '10.10.20.30', 'rport': 10051, 'lport': 50001, 'proto': 'tcp'},
                ]
            },
            {
                'meta': {'hostname': 'WS02'},
                'listening_ports': [],
                'connections': [
                    {'raddr': '10.10.20.30', 'rport': 10051, 'lport': 50002, 'proto': 'tcp'},
                ]
            }
        ]
        res = discover(snapshots)
        cand = next((c for c in res['candidates'] if c['value'] == '10.10.20.30'), None)
        self.assertIsNotNone(cand)
        self.assertEqual(cand['kind'], 'push_target')

    def test_logs_checker_upgrade(self):
        snapshots = [
            {
                'meta': {'hostname': 'WS01'},
                'listening_ports': [],
                'connections': [
                    {'raddr': '45.1.2.3', 'rport': 80, 'lport': 50001, 'proto': 'tcp'},
                ]
            }
        ]
        res = discover(snapshots, log_artifacts={'checker_ips': {'45.1.2.3'}})
        cand = next((c for c in res['candidates'] if c['value'] == '45.1.2.3'), None)
        self.assertIsNotNone(cand)
        self.assertEqual(cand['kind'], 'checker_ip')

    def test_string_ports(self):
        snapshots = [
            {
                'meta': {'hostname': 'WS01'},
                'listening_ports': [{'port': '80'}, {'port': '443'}],
                'connections': [
                    {'raddr': '10.0.0.50', 'rport': '50001', 'lport': '80', 'proto': 'tcp'},
                    {'raddr': '10.0.0.50', 'rport': '50002', 'lport': '443', 'proto': 'tcp'},
                ]
            },
            {
                'meta': {'hostname': 'WS02'},
                'listening_ports': [{'port': '80'}],
                'connections': [
                    {'raddr': '10.0.0.50', 'rport': '50003', 'lport': '80', 'proto': 'tcp'},
                ]
            }
        ]
        res = discover(snapshots)
        cand = next((c for c in res['candidates'] if c['value'] == '10.0.0.50'), None)
        self.assertIsNotNone(cand)
        self.assertEqual(cand['kind'], 'checker_ip')
        self.assertEqual(cand['confidence'], 'yuqori')
        
        al = to_allowlist(res)
        self.assertIn('10.0.0.50/32', al['cidrs'])

if __name__ == '__main__':
    unittest.main()
