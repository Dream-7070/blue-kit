import unittest
from datetime import datetime, timedelta
from bluekit.ir.correlator import correlate_incident
from bluekit.kb.query import KB

class TestGenericRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.kb = KB()
        except Exception:
            cls.kb = None

    def techs(self, evts):
        res = correlate_incident(evts, self.kb, heuristic_fallback=False)
        return [s.technique_id for s in res.stages]

    def _make_event(self, **kwargs):
        d = {
            'timestamp': '2026-10-02T10:00:00Z',
            'host': 'test-host',
            'user': 'test-user',
            'process': '',
            'command_line': '',
            'src_ip': '',
            'dst_ip': '',
            'event_code': '',
            'message': '',
            'channel': 'Security',
            'dataset': 'sysmon'
        }
        d.update(kwargs)
        return d

    def test_spray_6_users_from_one_ip(self):
        evts = []
        base_time = datetime(2026, 10, 2, 10, 0, 0)
        for i in range(6):
            evts.append(self._make_event(
                timestamp=(base_time + timedelta(seconds=10*i)).isoformat() + 'Z',
                event_code='4625',
                user=f'user{i}',
                src_ip='198.51.100.77',
                channel='Security'
            ))
        t = self.techs(evts)
        self.assertEqual(t.count('T1110.003'), 1)
        self.assertEqual(t.count('T1110.001'), 0)

    def test_bruteforce_one_user_12_attempts(self):
        evts = []
        base_time = datetime(2026, 10, 2, 10, 0, 0)
        for i in range(12):
            evts.append(self._make_event(
                timestamp=(base_time + timedelta(seconds=i)).isoformat() + 'Z',
                user='root',
                message='Failed password for root from 203.0.113.50 port 4000 ssh2'
            ))
        t = self.techs(evts)
        self.assertEqual(t.count('T1110.001'), 1)

    def test_single_failure_no_stage(self):
        evts = [self._make_event(event_code='4625')]
        t = self.techs(evts)
        self.assertEqual(t.count('T1110.003'), 0)
        self.assertEqual(t.count('T1110.001'), 0)

    def test_backup_cli_delete_restore_point(self):
        evts = [self._make_event(process='backupctl', command_line='delete restore-point weekly-2026-39')]
        t = self.techs(evts)
        self.assertEqual(t.count('T1490'), 1)

    def test_wbadmin_delete_catalog(self):
        evts = [self._make_event(process='wbadmin.exe', command_line='wbadmin delete catalog -quiet')]
        t = self.techs(evts)
        self.assertEqual(t.count('T1490'), 1)

    def test_backup_listing_is_discovery(self):
        evts = [self._make_event(process='backupctl', command_line='list repositories and restore points')]
        t = self.techs(evts)
        self.assertEqual(t.count('T1083'), 1)
        self.assertEqual(t.count('T1490'), 0)

    def test_backup_word_alone_is_nothing(self):
        evts = [
            self._make_event(process='bash', command_line='cat /etc/backup.conf'),
            self._make_event(command_line='echo backup completed')
        ]
        t = self.techs(evts)
        self.assertEqual(t.count('T1490'), 0)
        self.assertEqual(t.count('T1083'), 0)

    def test_archive_by_process_name(self):
        evts = [self._make_event(process='tar', command_line='archive config and credentials metadata to /tmp/cfg.tgz')]
        t = self.techs(evts)
        self.assertEqual(t.count('T1560.001'), 1)

    def test_tar_regex_no_duplicate(self):
        evts = [self._make_event(process='tar', command_line='tar -czf /tmp/a.tgz /etc')]
        t = self.techs(evts)
        self.assertEqual(t.count('T1560.001'), 1)

    def test_docker_api_create_external(self):
        evts = [self._make_event(process='dockerd', command_line='POST /v1.41/containers/create image=alpine:latest privileged=true', dst_ip='203.0.113.129')]
        t = self.techs(evts)
        self.assertEqual(t.count('T1610'), 1)
        self.assertEqual(t.count('T1190'), 1)

    def test_docker_api_internal_no_t1190(self):
        evts = [self._make_event(process='dockerd', command_line='POST /v1.41/containers/create image=alpine:latest privileged=true', dst_ip='10.56.2.5', src_ip='')]
        t = self.techs(evts)
        self.assertEqual(t.count('T1610'), 1)
        self.assertEqual(t.count('T1190'), 0)

    def test_xmrig_pool(self):
        evts = [self._make_event(process='sh', command_line='xmrig -o 192.0.2.210:3333 -u wallet')]
        t = self.techs(evts)
        self.assertEqual(t.count('T1496'), 1)

    def test_miner_process_pool_port(self):
        evts = [self._make_event(process='miner', command_line='', dst_ip='192.0.2.210', event_code='3', dst_port='3333')]
        t = self.techs(evts)
        self.assertEqual(t.count('T1496'), 1)

    def test_stress_tool_not_miner(self):
        evts = [self._make_event(process='stress-ng', command_line='stress-ng --cpu 8 --timeout 60s')]
        t = self.techs(evts)
        self.assertEqual(t.count('T1496'), 0)

    def test_rclone_copy(self):
        evts = [self._make_event(process='rclone.exe', command_line='rclone copy C:\\\\data remote:bucket')]
        t = self.techs(evts)
        self.assertEqual(t.count('T1567.002'), 1)

    def test_removed_literals_absent(self):
        import os
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(base_dir, 'bluekit', 'ir', 'correlator.py')
        with open(path, 'r', encoding='utf-8') as f:
            text = f.read().lower()
            
        LIST = [
            'spray 43 accounts', 'service rnstage installed', 'ransomware staging service',
            'locker_stage', 'cryptominer process', 'stratum-like connection',
            'resource anomaly cpu 99%', 'cloud upload 188331002 bytes',
            'upload completed to personal cloud', 'bkp_cfg.tgz', 'rdp logon type 10',
            'backup discovery', 'collection staged', 'delete requested',
            "'backup' in msg_lower", 'unauthenticated docker api', 'docker api create'
        ]
        found = [x for x in LIST if x in text]
        self.assertEqual(found, [])

if __name__ == '__main__':
    unittest.main()
