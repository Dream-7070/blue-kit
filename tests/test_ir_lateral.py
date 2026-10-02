import unittest
from bluekit.ir.models import AttackStage
from bluekit.ir.lateral import build_ip_map, build_lateral_edges, attack_path, edges_mermaid

class TestIRLateral(unittest.TestCase):
    def test_synthetic_windows(self):
        events = [
            {'dataset': 'sysmon', 'host': 'A', 'event.code': '3', 'src_ip': '10.0.0.11', 'timestamp': '2026-01-01T08:00:00Z'},
            {'dataset': 'sysmon', 'host': 'B', 'event.code': '3', 'src_ip': '10.0.0.12', 'timestamp': '2026-01-01T08:00:00Z'},
            {'dataset': 'sysmon', 'host': 'C', 'event.code': '3', 'src_ip': '10.0.0.13', 'timestamp': '2026-01-01T08:00:00Z'},
            {'dataset': 'wineventlog', 'host': 'B', 'event.code': '4624', 'src_ip': '10.0.0.11', 'user': 'svc', 'timestamp': '2026-01-01T10:00:00Z', 'message': 'Logon type: 3'},
            {'dataset': 'wineventlog', 'host': 'B', 'event.code': '7045', 'timestamp': '2026-01-01T10:00:08Z', 'message': 'Service Name: PSEXESVC'},
            {'dataset': 'wineventlog', 'host': 'B', 'event.code': '4624', 'src_ip': '10.0.0.13', 'user': 'user2', 'timestamp': '2026-01-01T10:05:00Z', 'message': 'Logon type: 3'},
            {'dataset': 'wineventlog', 'host': 'B', 'event.code': '4624', 'src_ip': '10.0.0.12', 'user': 'user3', 'timestamp': '2026-01-01T10:10:00Z', 'message': 'Logon type: 2'},
        ]
        stages = [AttackStage(stage_id="1", timestamp='2026-01-01T09:00:00Z', host='A', confidence='HIGH', technique_id='T1111', phase='Unknown', technique_name='Test')]
        edges = build_lateral_edges(events, stages)
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]['src_host'], 'A')
        self.assertEqual(edges[0]['dst_host'], 'B')
        self.assertEqual(edges[0]['method'], 'SMB/PsExec')
        self.assertEqual(edges[0]['techniques'], ['T1021.002', 'T1569.002'])
        self.assertEqual(edges[0]['status'], 'CONFIRMED')

    def test_ip_map_direction(self):
        events = [{'dataset': 'wineventlog', 'host': 'B', 'event.code': '4624', 'src_ip': '10.0.0.11', 'timestamp': '2026-01-01T10:00:00Z'}]
        m = build_ip_map(events)
        self.assertNotIn('10.0.0.11', m)

    def test_ssh(self):
        events = [
            {'dataset': 'sysmon', 'host': 'A', 'event.code': '3', 'src_ip': '10.0.0.11', 'timestamp': '2026-01-01T08:00:00Z'},
            {'dataset': 'auth', 'host': 'D', 'message': 'Accepted publickey for dbadmin from 10.0.0.11 port 5 ssh2', 'timestamp': '2026-01-01T10:00:00Z'}
        ]
        stages = [AttackStage(stage_id="1", timestamp='2026-01-01T09:00:00Z', host='A', confidence='HIGH', technique_id='T1111', phase='Unknown', technique_name='Test')]
        edges = build_lateral_edges(events, stages)
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]['src_host'], 'A')
        self.assertEqual(edges[0]['dst_host'], 'D')
        self.assertEqual(edges[0]['method'], 'SSH')
        self.assertEqual(edges[0]['techniques'], ['T1021.004'])
        self.assertEqual(edges[0]['user'], 'dbadmin')

    def test_scp_pull(self):
        events = [
            {'dataset': 'sysmon', 'host': 'E', 'event.code': '3', 'src_ip': '10.0.0.14', 'timestamp': '2026-01-01T08:00:00Z'},
            {'dataset': 'auth', 'host': 'E', 'message': 'Accepted password for ... from ...', 'dst_ip': '10.0.0.14', 'timestamp': '2026-01-01T08:00:00Z'},
            {'dataset': 'bash', 'host': 'W', 'cmd': 'scp dbadmin@10.0.0.14:/tmp/x.gz /dev/shm/', 'timestamp': '2026-01-01T10:00:00Z', 'user': 'local_usr'}
        ]
        stages = [AttackStage(stage_id="1", timestamp='2026-01-01T09:00:00Z', host='W', confidence='HIGH', technique_id='T1111', phase='Unknown', technique_name='Test')]
        edges = build_lateral_edges(events, stages)
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]['src_host'], 'E')
        self.assertEqual(edges[0]['dst_host'], 'W')
        self.assertEqual(edges[0]['method'], 'SCP')
        self.assertEqual(edges[0]['techniques'], ['T1570'])

    def test_kech_kuz(self):
        import os
        from bluekit.ir.correlator import load_events_from_files, correlate_incident
        try:
            from bluekit.kb.query import KB
            kb = KB()
        except Exception:
            self.skipTest("KB ochilmadi")
            return
            
        path = r"D:\Claude Projects\CTF\mashq\2026-09-30-operation-kech-kuz\events\collector_all_hosts.csv"
        if not os.path.exists(path):
            self.skipTest("Fayl yo'q")
            return
            
        res = load_events_from_files([path])
        events = res[0] if isinstance(res, tuple) else res
        chain = correlate_incident(events, kb)
        edges = build_lateral_edges(events, chain.stages, kb)
        
        pairs = {(e['src_host'], e['dst_host']) for e in edges if e['status'] == 'CONFIRMED'}
        self.assertIn(('HR-PC01', 'IT-ADM-02'), pairs)
        self.assertIn(('IT-ADM-02', 'DC01'), pairs)
        self.assertIn(('DC01', 'FILE-SRV-01'), pairs)
        self.assertIn(('FILE-SRV-01', 'db-prod-02'), pairs)
        
        hr_it = [e for e in edges if e['src_host'] == 'HR-PC01' and e['dst_host'] == 'IT-ADM-02'][0]
        self.assertEqual(hr_it['method'], 'SMB/PsExec')
        
        path_nodes = attack_path(edges)
        self.assertEqual(path_nodes[:5], ['HR-PC01', 'IT-ADM-02', 'DC01', 'FILE-SRV-01', 'db-prod-02'])
        
        confirmed_count = len([e for e in edges if e['status'] == 'CONFIRMED'])
        self.assertLessEqual(confirmed_count, 8)

    def test_15k_drill(self):
        import os
        from bluekit.ir.correlator import load_events_from_files, correlate_incident
        try:
            from bluekit.kb.query import KB
            kb = KB()
        except Exception:
            self.skipTest("KB ochilmadi")
            return
            
        path = r"D:\Claude Projects\CTF\elasticsearch_export.json"
        if not os.path.exists(path):
            self.skipTest("Fayl yo'q")
            return
        
        res = load_events_from_files([path])
        events = res[0] if isinstance(res, tuple) else res
        stages = correlate_incident(events, kb).stages
        edges = build_lateral_edges(events, stages)
        
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]['src_host'], 'web-prod-01')
        self.assertEqual(edges[0]['dst_host'], 'db-prod-02')
        self.assertEqual(edges[0]['user'], 'root')
        self.assertEqual(edges[0]['method'], 'SSH')
        self.assertEqual(edges[0]['status'], 'CONFIRMED')

    def test_ssh_without_compromised_dropped(self):
        events = [
            {'dataset': 'sysmon', 'host': 'A', 'event.code': '3', 'src_ip': '10.0.0.11', 'timestamp': '2026-01-01T08:00:00Z'},
            {'dataset': 'auth', 'host': 'D', 'message': 'Accepted publickey for dbadmin from 10.0.0.11 port 5 ssh2', 'timestamp': '2026-01-01T10:00:00Z'}
        ]
        edges = build_lateral_edges(events, [])
        self.assertEqual(len(edges), 0)

    def test_kb_validate_filters(self):
        from bluekit.ir.lateral import _validate_techniques
        class DummyKB:
            def validate(self, ids):
                return [
                    {'input': 'T1021.002', 'normalized': 'T1021.002', 'found': True, 'status': 'active', 'replacement': None},
                    {'input': 'T9999', 'found': False, 'message': 'Not found'},
                    {'input': 'T1070.001', 'found': True, 'status': 'revoked', 'replacement': 'T1685.005'}
                ]
        res = _validate_techniques(DummyKB(), ['T1021.002', 'T9999', 'T1070.001'])
        self.assertEqual(res, ['T1021.002', 'T1685.005'])

    def test_mermaid(self):
        edges = [
            {'src_host': 'HR-PC01', 'dst_host': 'IT-ADM-02', 'user': 'svc_helpdesk', 'method': 'SMB/PsExec', 'status': 'CONFIRMED'},
            {'src_host': '', 'dst_host': 'DC01', 'user': 'admin"1', 'method': 'Network logon', 'status': 'SUSPECTED'}
        ]
        res = edges_mermaid(edges)
        lines = res.split('\n')
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[0], 'flowchart LR')
        self.assertIn('-->|"#1 svc_helpdesk · SMB/PsExec"|', lines[1])
        label_part = lines[2].split('|')[1]
        self.assertNotIn('admin"1', label_part)
        self.assertIn("admin'1", label_part)
        self.assertIn("-.->", lines[2])
        self.assertIn('["?"]', lines[2])

    def test_corrupted_events(self):
        events = [
            None,
            {},
            {'dataset': 'sysmon', 'host': 'A', 'event.code': '3', 'src_ip': '10.0.0.11', 'timestamp': '2026-01-01T08:00:00Z'},
            {'dataset': 'sysmon', 'host': 'B', 'event.code': '3', 'src_ip': '10.0.0.12', 'timestamp': '2026-01-01T08:00:00Z'},
            {'dataset': 'wineventlog', 'host': 'B', 'event.code': '4624', 'src_ip': '10.0.0.11', 'user': 'svc', 'timestamp': '2026-01-01T10:00:00Z', 'message': 'Logon type: 3'},
            {'dataset': 'wineventlog', 'host': 'B', 'event.code': '7045', 'timestamp': '2026-01-01T10:00:08Z', 'message': 'Service Name: PSEXESVC'},
        ]
        stages = [AttackStage(stage_id="1", timestamp='2026-01-01T09:00:00Z', host='A', confidence='HIGH', technique_id='T1111', phase='Unknown', technique_name='Test')]
        edges = build_lateral_edges(events, stages)
        self.assertEqual(len(edges), 1)

if __name__ == '__main__':
    unittest.main()
