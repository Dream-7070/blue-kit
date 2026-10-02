import unittest
from bluekit.ir.correlator import correlate_incident

class KB:
    def get_technique(self, tech_id):
        class Tech:
            def __init__(self, name):
                self.name = name
        return Tech("Unknown")

class TestIRWebRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kb = KB()
        
    def techs(self, evts):
        chain = correlate_incident(evts, self.kb, heuristic_fallback=False)
        return [s.technique_id for s in chain] if isinstance(chain, list) else [s.technique_id for s in getattr(chain, 'stages', [])]
        
    def _run_correlator(self, evts):
        chain = correlate_incident(evts, self.kb, heuristic_fallback=False)
        return chain if isinstance(chain, list) else getattr(chain, 'stages', [])
        
    def test_urlencoded_sqli_in_command_line(self):
        evts = [{'timestamp': '2023-01-01T10:00:00Z', 'host': 'web01', 'user': '', 'process': 'nginx', 'parent_process': '', 'command_line': 'GET /login?id=1%27%20OR%201=1-- HTTP/1.1', 'src_ip': '', 'dst_ip': '203.0.113.44', 'message': ''}]
        stages = self._run_correlator(evts)
        t1190 = [s for s in stages if s.technique_id == 'T1190']
        self.assertEqual(len(t1190), 1)
        self.assertEqual(t1190[0].iocs.get('src_ip'), '203.0.113.44')
        
    def test_double_encoded_union(self):
        evts = [{'timestamp': '2023-01-01T10:00:00Z', 'host': 'web01', 'user': '', 'process': 'nginx', 'parent_process': '', 'command_line': '', 'request': 'GET /p?q=1%2520UNION%2520SELECT%2520password%2520FROM%2520users HTTP/1.1', 'status': 200, 'src_ip': '1.2.3.4', 'dst_ip': '', 'message': ''}]
        stages = self._run_correlator(evts)
        t1190 = [s for s in stages if s.technique_id == 'T1190']
        self.assertEqual(len(t1190), 1)
        
    def test_sqli_in_url_fields(self):
        evts = [{'@timestamp': '2023-01-01T10:00:00Z', 'event': {'dataset': 'nginx.access'}, 'url': {'path': '/item', 'query': 'id=5%27%20AND%20SLEEP(5)--'}, 'source': {'ip': '198.51.100.9'}, 'http': {'response': {'status_code': 500}}}]
        stages = self._run_correlator(evts)
        t1190 = [s for s in stages if s.technique_id == 'T1190']
        self.assertEqual(len(t1190), 1)
        
    def test_benign_queries_no_sqli(self):
        evts = [
            {'timestamp': '2023-01-01T10:00:00Z', 'host': 'web01', 'process': 'nginx', 'command_line': 'GET /search?q=orange+juice HTTP/1.1', 'message': ''},
            {'timestamp': '2023-01-01T10:00:01Z', 'host': 'web01', 'process': 'nginx', 'command_line': 'GET /api?order=asc&sort=name HTTP/1.1', 'message': ''},
            {'timestamp': '2023-01-01T10:00:02Z', 'host': 'web01', 'process': 'nginx', 'command_line': 'GET /docs/select-a-plan HTTP/1.1', 'message': ''},
            {'timestamp': '2023-01-01T10:00:03Z', 'host': 'web01', 'process': 'nginx', 'command_line': 'GET /search?sort=name+and+order=asc HTTP/1.1', 'message': ''},
            {'timestamp': '2023-01-01T10:00:04Z', 'host': 'web01', 'process': 'nginx', 'command_line': 'GET /p?q=red%20or%20blue=green HTTP/1.1', 'message': ''}
        ]
        stages = self._run_correlator(evts)
        t1190 = [s for s in stages if s.technique_id == 'T1190']
        self.assertEqual(len(t1190), 0)
        
    def test_sqli_aggregated_per_ip(self):
        base_evt = {'host': 'web01', 'user': '', 'process': 'nginx', 'parent_process': '', 'command_line': 'GET /login?id=1%27%20OR%201=1-- HTTP/1.1', 'src_ip': '', 'dst_ip': '203.0.113.44', 'message': ''}
        evts = []
        for i in range(5):
            evt = base_evt.copy()
            evt['timestamp'] = f'2023-01-01T10:00:0{i}Z'
            evts.append(evt)
        stages = self._run_correlator(evts)
        t1190 = [s for s in stages if s.technique_id == 'T1190']
        self.assertEqual(len(t1190), 1)
        self.assertEqual(t1190[0].iocs.get('count'), 5)
        
    def test_webserver_proc_runs_shell(self):
        evts = [{'timestamp': '2023-01-01T10:00:00Z', 'host': 'web01', 'user': 'www-data', 'process': 'php-fpm', 'parent_process': '', 'command_line': '/bin/sh -c id', 'src_ip': '', 'dst_ip': '', 'message': ''}]
        stages = self._run_correlator(evts)
        techs = [s.technique_id for s in stages]
        self.assertEqual(techs.count('T1505.003'), 1)
        self.assertEqual(techs.count('T1059.004'), 1)
        self.assertEqual(techs.count('T1033'), 1)
        
    def test_webserver_parent_shell_child(self):
        evts = [{'timestamp': '2023-01-01T10:00:00Z', 'host': 'web01', 'user': 'www-data', 'process': 'bash', 'parent_process': 'apache2', 'command_line': 'bash -c "uname -a"', 'src_ip': '', 'dst_ip': '', 'message': ''}]
        stages = self._run_correlator(evts)
        techs = [s.technique_id for s in stages]
        self.assertEqual(techs.count('T1505.003'), 1)
        self.assertEqual(techs.count('T1059.004'), 1)
        
    def test_w3wp_cmd(self):
        evts = [{'timestamp': '2023-01-01T10:00:00Z', 'host': 'web01', 'user': 'iis_iusrs', 'process': 'cmd.exe', 'parent_process': 'w3wp.exe', 'command_line': 'cmd.exe /c whoami', 'src_ip': '', 'dst_ip': '', 'message': ''}]
        stages = self._run_correlator(evts)
        techs = [s.technique_id for s in stages]
        self.assertEqual(techs.count('T1505.003'), 1)
        self.assertEqual(techs.count('T1059.003'), 1)
        
    def test_webserver_benign_start(self):
        evts = [
            {'timestamp': '2023-01-01T10:00:00Z', 'host': 'web01', 'user': 'root', 'process': 'nginx', 'parent_process': '', 'command_line': 'nginx -c /etc/nginx/nginx.conf', 'message': ''},
            {'timestamp': '2023-01-01T10:00:01Z', 'host': 'web01', 'user': 'root', 'process': 'php-fpm', 'parent_process': '', 'command_line': 'php-fpm: pool www', 'message': ''}
        ]
        stages = self._run_correlator(evts)
        techs = [s.technique_id for s in stages]
        self.assertEqual(techs.count('T1505.003'), 0)
        self.assertEqual(techs.count('T1059.004'), 0)
        
    def test_webshell_aggregated(self):
        evts = [
            {'timestamp': '2023-01-01T10:00:00Z', 'host': 'web01', 'user': 'www-data', 'process': 'php-fpm', 'parent_process': '', 'command_line': '/bin/sh -c id', 'message': ''},
            {'timestamp': '2023-01-01T10:00:01Z', 'host': 'web01', 'user': 'www-data', 'process': 'php-fpm', 'parent_process': '', 'command_line': '/bin/sh -c "uname -a"', 'message': ''},
            {'timestamp': '2023-01-01T10:00:02Z', 'host': 'web01', 'user': 'www-data', 'process': 'php-fpm', 'parent_process': '', 'command_line': '/bin/sh -c "cat /etc/hosts"', 'message': ''}
        ]
        stages = self._run_correlator(evts)
        techs = [s.technique_id for s in stages]
        self.assertEqual(techs.count('T1505.003'), 1)
        self.assertEqual(techs.count('T1059.004'), 1)
        
    def test_traversal_aggregated_per_ip(self):
        evts = [{'timestamp': f'2026-09-18T10:14:{i:02d}Z', 'host': 'vpn-01', 'process': 'nginx',
                 'command_line': 'GET /dana-na/../../../etc/passwd HTTP/1.1', 'src_ip': '203.0.113.7', 'message': ''} for i in range(12)]
        st = [s for s in correlate_incident(evts, self.kb, heuristic_fallback=False).stages if s.technique_id == 'T1190']
        self.assertEqual(len(st), 1)
        self.assertEqual(st[0].iocs.get('count'), 12)

if __name__ == '__main__':
    unittest.main()
