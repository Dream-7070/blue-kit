import unittest
from bluekit.ir.correlator import correlate_incident
from bluekit.ir.models import AttackStage

class TestIRDnsTunnel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class KB:
            def __init__(self):
                pass
        cls.kb = KB()

    def q(self, ts, name, qtype='TXT', client='10.57.1.55'):
        return {
            'timestamp': ts,
            'host': 'RESOLVER-A',
            'process': 'named',
            'command_line': f'{qtype} {name}',
            'dst_ip': client,
            'message': ''
        }

    def _run_and_count(self, events):
        # We need to extract the stages from AttackChain if it's an AttackChain object
        chain = correlate_incident(events, kb=self.kb, heuristic_fallback=False)
        stages = getattr(chain, 'stages', chain) if not isinstance(chain, list) else chain
        t1071_004 = [s for s in stages if getattr(s, 'technique_id', '') == 'T1071.004']
        t1048_003 = [s for s in stages if getattr(s, 'technique_id', '') == 'T1048.003']
        return stages, t1071_004, t1048_003

    def test_txt_burst_three_subdomains(self):
        events = [
            {'timestamp': '2023-01-01T10:00:00Z', 'host': 'RND-PC05', 'process': 'chrome.exe', 'src_ip': '10.57.1.55', 'dst_ip': '10.57.0.53', 'message': ''},
            self.q('2023-01-01T10:01:00Z', 'a001.4d5a.data.cdn-sync.example', 'TXT'),
            self.q('2023-01-01T10:01:01Z', 'a002.7f91.data.cdn-sync.example', 'TXT'),
            self.q('2023-01-01T10:01:02Z', 'a120.aa33.data.cdn-sync.example', 'TXT'),
        ]
        stages, t1071, t1048 = self._run_and_count(events)
        self.assertEqual(len(t1071), 1)
        self.assertEqual(t1071[0].host, 'RND-PC05')
        self.assertEqual(t1071[0].iocs.get('domain'), 'cdn-sync.example')

    def test_long_hex_label(self):
        events = [
            {'timestamp': '2023-01-01T10:00:00Z', 'host': 'RND-PC05', 'process': 'chrome.exe', 'src_ip': '10.57.1.55', 'dst_ip': '10.57.0.53', 'message': ''},
            self.q('2023-01-01T10:01:00Z', '4d5a90000300000004000000ffff0000b8000000.evil.example', 'A')
        ]
        stages, t1071, t1048 = self._run_and_count(events)
        self.assertEqual(len(t1071), 1)

    def test_many_subdomains_exfil(self):
        events = [
            {'timestamp': '2023-01-01T10:00:00Z', 'host': 'RND-PC05', 'process': 'chrome.exe', 'src_ip': '10.57.1.55', 'dst_ip': '10.57.0.53', 'message': ''}
        ]
        for i in range(25):
            events.append(self.q(f'2023-01-01T10:01:{i:02d}Z', f'x{i:03d}.t.example', 'A'))
        stages, t1071, t1048 = self._run_and_count(events)
        self.assertEqual(len(t1071), 1)
        self.assertEqual(len(t1048), 1)

    def test_normal_dns_not_flagged(self):
        events = [
            {'timestamp': '2023-01-01T10:00:00Z', 'host': 'RND-PC05', 'process': 'chrome.exe', 'src_ip': '10.57.1.55', 'dst_ip': '10.57.0.53', 'message': ''},
            self.q('2023-01-01T10:01:00Z', 'www.google.com', 'A'),
            self.q('2023-01-01T10:01:01Z', 'cdn.assets.example.test', 'AAAA'),
            self.q('2023-01-01T10:01:02Z', '_dmarc.example.org', 'TXT'),
            self.q('2023-01-01T10:01:03Z', 'sel1._domainkey.example.org', 'TXT'),
            self.q('2023-01-01T10:01:04Z', '_acme-challenge.example.org', 'TXT')
        ]
        stages, t1071, t1048 = self._run_and_count(events)
        self.assertEqual(len(t1071), 0)

    def test_two_txt_not_enough(self):
        events = [
            {'timestamp': '2023-01-01T10:00:00Z', 'host': 'RND-PC05', 'process': 'chrome.exe', 'src_ip': '10.57.1.55', 'dst_ip': '10.57.0.53', 'message': ''},
            self.q('2023-01-01T10:01:00Z', 'a001.example.org', 'TXT'),
            self.q('2023-01-01T10:01:01Z', 'a002.example.org', 'TXT')
        ]
        stages, t1071, t1048 = self._run_and_count(events)
        self.assertEqual(len(t1071), 0)

    def test_dnscat_process(self):
        events = [
            {'timestamp': '2023-01-01T10:00:00Z', 'host': 'RND-PC05', 'process': 'dnscat.exe', 'src_ip': '10.57.1.55', 'dst_ip': '10.57.0.53', 'message': ''}
        ]
        stages, t1071, t1048 = self._run_and_count(events)
        self.assertEqual(len(t1071), 1)

    def test_archive_then_tunnel_is_exfil(self):
        events = [
            {'timestamp': '2023-01-01T04:20:00Z', 'host': 'RND-PC05', 'process': 'tar.exe', 'command_line': 'tar -czf C:\\Users\\Public\\pkg01.tgz R:\\ProjectX', 'message': ''},
            {'timestamp': '2023-01-01T05:40:00Z', 'host': 'RND-PC05', 'process': 'dnscat.exe', 'message': ''}
        ]
        stages, t1071, t1048 = self._run_and_count(events)
        self.assertEqual(len(t1048), 1)

    def test_tunnel_before_archive_no_exfil(self):
        events = [
            {'timestamp': '2023-01-01T04:00:00Z', 'host': 'RND-PC05', 'process': 'dnscat.exe', 'message': ''},
            {'timestamp': '2023-01-01T05:00:00Z', 'host': 'RND-PC05', 'process': 'tar.exe', 'command_line': 'tar -czf C:\\Users\\Public\\pkg01.tgz R:\\ProjectX', 'message': ''}
        ]
        stages, t1071, t1048 = self._run_and_count(events)
        self.assertEqual(len(t1048), 0)

    def test_dns_literals_absent(self):
        import os
        correlator_path = os.path.join(os.path.dirname(__file__), '..', 'bluekit', 'ir', 'correlator.py')
        with open(correlator_path, 'r', encoding='utf-8') as f:
            content = f.read().lower()
            
        literals = ['dns tunnel chunk', '122 txt queries', 'exfil-lab', "txt queries' in msg_lower"]
        found = [lit for lit in literals if lit in content]
        self.assertEqual(found, [])

    def test_non_dns_text_not_parsed_as_query(self):
        # oddiy buyruqdagi "a <hex>.bin" DNS so'rovi emas
        evts = [{'timestamp': f'2026-10-05T04:00:0{i}Z', 'host': 'W1', 'process': 'cmd.exe',
                 'command_line': f'copy a 4d5a90000300000004000000ffff{i:02d}.bin x', 'message': ''} for i in range(3)]
        chain = correlate_incident(evts, kb=self.kb, heuristic_fallback=False)
        self.assertEqual(sum(1 for s in chain.stages if s.technique_id == 'T1071.004'), 0)

if __name__ == '__main__':
    unittest.main()
