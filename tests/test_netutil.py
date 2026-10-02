import unittest
import ipaddress
import os
import glob
from bluekit.netutil import is_external_ip, is_internal_ip
from bluekit.kb.query import KB
from bluekit.logs.detect import detect_event
from bluekit.ir.correlator import correlate_incident
import bluekit.hunt.beacons
import bluekit.resp.fraud

class TestNetUtil(unittest.TestCase):
    def test_table(self):
        CASES = [
            ('203.0.113.44', True),
            ('198.51.100.7', True),
            ('192.0.2.1', True),
            ('8.8.8.8', True),
            ('198.18.0.5', True),
            ('172.32.0.1', True),
            ('2001:4860:4860::8888', True),
            ('2001:db8::1', True),
            ('::ffff:203.0.113.5', True),
            ('203.0.113.44:443', True),
            ('[2001:db8::1]:443', True),
            (' 203.0.113.9 ', True),
            (ipaddress.ip_address('198.51.100.9'), True),
            ('10.1.2.3', False),
            ('172.16.0.1', False),
            ('172.31.255.255', False),
            ('192.168.1.1', False),
            ('127.0.0.1', False),
            ('169.254.1.1', False),
            ('100.64.0.1', False),
            ('0.0.0.0', False),
            ('224.0.0.251', False),
            ('255.255.255.255', False),
            ('240.0.0.1', False),
            ('::1', False),
            ('fe80::1', False),
            ('fd00::1', False),
            ('::ffff:10.0.0.1', False),
            ('10.0.0.5:3389', False),
            ('', False),
            (None, False),
            ('evil.example', False),
            ('999.1.1.1', False),
        ]
        
        checked = 0
        for val, expected in CASES:
            with self.subTest(val=val):
                self.assertEqual(is_external_ip(val), expected)
                checked += 1
                
        self.assertEqual(checked, len(CASES))
        self.assertGreaterEqual(len(CASES), 32)
        
    def test_internal_helper(self):
        self.assertIs(is_internal_ip('10.0.0.1'), True)
        self.assertIs(is_internal_ip('203.0.113.5'), False)
        self.assertIs(is_internal_ip('garbage'), False)
        self.assertIs(is_internal_ip(None), False)
        
    def test_detect_external_logon_gives_t1133(self):
        kb = KB()
        ev1 = {'channel': 'Security', 'event_id': '4624', 'command_line': None, 'message': 'An account was successfully logged on', 'src_ip': '203.0.113.5', 'process': None}
        hits1 = detect_event(kb, ev1)
        techs1 = [h['technique'] for h in hits1]
        self.assertIn('T1133', techs1)
        
        ev2 = {'channel': 'Security', 'event_id': '4624', 'command_line': None, 'message': 'An account was successfully logged on', 'src_ip': '10.0.0.5', 'process': None}
        hits2 = detect_event(kb, ev2)
        techs2 = [h['technique'] for h in hits2]
        self.assertNotIn('T1133', techs2)
        
    def test_fallback_passes_src_ip(self):
        kb = KB()
        evt1 = {'@timestamp': '2026-10-05T04:00:00Z', 'host': {'name': 'JUMP-01'}, 'user': {'name': 'corp\\bob'}, 'winlog': {'channel': 'Security'}, 'event': {'code': '4624'}, 'source': {'ip': '198.51.100.204'}, 'message': 'An account was successfully logged on'}
        chain1 = correlate_incident([evt1], kb, heuristic_fallback=True)
        t1133_count1 = sum(1 for s in chain1.stages if s.technique_id == 'T1133')
        self.assertGreaterEqual(t1133_count1, 1)
        
        evt2 = {'@timestamp': '2026-10-05T04:00:00Z', 'host': {'name': 'JUMP-01'}, 'user': {'name': 'corp\\bob'}, 'winlog': {'channel': 'Security'}, 'event': {'code': '4624'}, 'source': {'ip': '10.59.1.12'}, 'message': 'An account was successfully logged on'}
        chain2 = correlate_incident([evt2], kb, heuristic_fallback=True)
        t1133_count2 = sum(1 for s in chain2.stages if s.technique_id == 'T1133')
        self.assertEqual(t1133_count2, 0)
        
    def test_ecs_source_dict_without_dataset_does_not_crash(self):
        # source/host/user lug'at bo'lgan, event.dataset yo'q ECS hodisa (Winlogbeat eksporti) -- avval .lower() da yiqilardi
        evt = {'@timestamp': '2026-10-05T04:00:00Z', 'host': {'hostname': 'JUMP-02'}, 'user': {'id': 'S-1-5-21'},
               'winlog': {'channel': 'Security'}, 'event': {'code': '4624'}, 'source': {'ip': '198.51.100.9'}, 'message': 'logon'}
        chain = correlate_incident([evt], KB(), heuristic_fallback=True)
        self.assertEqual(sum(1 for s in chain.stages if s.technique_id == 'T1133'), 1)
        self.assertEqual(chain.stages[0].host, 'JUMP-02')

    def test_beacons_private_helper(self):
        self.assertIs(bluekit.hunt.beacons.is_private_ip('203.0.113.5'), False)
        self.assertIs(bluekit.hunt.beacons.is_private_ip('10.0.0.1'), True)
        self.assertIs(bluekit.hunt.beacons.is_private_ip('garbage'), False)
        
    def test_fraud_public_ip(self):
        self.assertIs(bluekit.resp.fraud._has_public_ip('dns 203.0.113.5'), True)
        self.assertIs(bluekit.resp.fraud._has_public_ip('10.0.0.1 192.168.1.1'), False)
        
    def test_no_adhoc_ip_checks_left(self):
        found = []
        base_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'bluekit')
        
        for root, _, files in os.walk(base_dir):
            if 'siem' in root:
                continue
            for file in files:
                if file.endswith('.py') and file != 'netutil.py':
                    path = os.path.join(root, file)
                    with open(path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                    if '.is_global' in content: found.append(f"{file}: .is_global")
                    if '.is_private' in content: found.append(f"{file}: .is_private")
                    if "startswith('10.')" in content: found.append(f"{file}: startswith('10.')")
                    if "startswith('192.168.')" in content: found.append(f"{file}: startswith('192.168.')")
                    if 'startswith("10.")' in content: found.append(f"{file}: startswith(\"10.\")")
                    if 'startswith("192.168.")' in content: found.append(f"{file}: startswith(\"192.168.\")")
                    
        self.assertEqual(found, [])

if __name__ == '__main__':
    unittest.main()
