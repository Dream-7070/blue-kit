import unittest
from bluekit.resp.triage import analyze
from bluekit.resp.logbridge import load_log_artifacts

class KB:
    def search(self, text, limit=5): return []
    def validate(self, ids): return [{'status': 'valid', 'replacement': None}]

class TestTriageP2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kb = KB()

    def techs_of(self, f):
        if 'techniques' in f:
            return [t['id'] for t in f['techniques']]
        if 'techs' in f:
            return [t['id'] for t in f['techs']]
        return []

    def test_webroot_php_autorun_no_baseline(self):
        current = {
            'meta': {'os': 'linux', 'hostname': 'WEB-9'},
            'autoruns': [{'location': '/var/www/html', 'name': 'img_resize.php', 'value': 'x'}]
        }
        findings, _ = analyze(self.kb, current, baseline=None)
        f_list = [f for f in findings if f['category'] == 'autoruns' and f['item'] == 'img_resize.php']
        self.assertEqual(len(f_list), 1)
        f = f_list[0]
        techs = self.techs_of(f)
        self.assertIn('T1505.003', techs)
        self.assertNotIn('T1547.001', techs)
        self.assertEqual(f['confidence'], 'high')
        self.assertGreaterEqual(f['score'], 0.85)

    def test_webroot_aspx_windows(self):
        current = {
            'meta': {'os': 'windows', 'hostname': 'WEB-2'},
            'autoruns': [{'location': 'C:\\inetpub\\wwwroot\\uploads', 'name': 'help.aspx', 'value': 'x'}]
        }
        findings, _ = analyze(self.kb, current, baseline=None)
        f_list = [f for f in findings if f['category'] == 'autoruns' and f['item'] == 'help.aspx']
        self.assertEqual(len(f_list), 1)
        techs = self.techs_of(f_list[0])
        self.assertIn('T1505.003', techs)

    def test_non_webroot_php_unchanged(self):
        current = {
            'meta': {'os': 'linux'},
            'autoruns': [{'location': '/home/dev/project', 'name': 'test.php', 'value': 'x'}]
        }
        findings, _ = analyze(self.kb, current, baseline=None)
        f_list = [f for f in findings if f['category'] == 'autoruns' and f['item'] == 'test.php']
        if f_list:
            techs = self.techs_of(f_list[0])
            self.assertNotIn('T1505.003', techs)

    def test_webroot_in_baseline_not_boosted(self):
        current = {
            'meta': {'os': 'linux'},
            'autoruns': [{'location': '/var/www/html', 'name': 'img_resize.php', 'value': 'x'}]
        }
        baseline = {
            'autoruns': [{'location': '/var/www/html', 'name': 'img_resize.php', 'value': 'x'}]
        }
        findings, _ = analyze(self.kb, current, baseline=baseline)
        f_list = [f for f in findings if f['category'] == 'autoruns' and f['item'] == 'img_resize.php']
        if f_list:
            f = f_list[0]
            self.assertLess(f['score'], 0.85)

    def test_linux_cron_task(self):
        current = {
            'meta': {'os': 'linux'},
            'tasks': [{'name': 'sysmon-agent', 'action': 'docker start abc', 'trigger': '*/10 * * * *'}]
        }
        findings, _ = analyze(self.kb, current, baseline=None)
        f_list = [f for f in findings if f['category'] == 'tasks' and f['item'] == 'sysmon-agent']
        self.assertEqual(len(f_list), 1)
        f = f_list[0]
        techs = self.techs_of(f)
        self.assertIn('T1053.003', techs)
        self.assertNotIn('T1053.005', techs)

    def test_cron_by_trigger_on_unknown_os(self):
        current = {
            'meta': {'os': 'synthetic'},
            'tasks': [{'name': 'sysmon-agent', 'action': 'docker start abc', 'trigger': '*/10 * * * *'}]
        }
        findings, _ = analyze(self.kb, current, baseline=None)
        f_list = [f for f in findings if f['category'] == 'tasks' and f['item'] == 'sysmon-agent']
        self.assertEqual(len(f_list), 1)
        techs = self.techs_of(f_list[0])
        self.assertIn('T1053.003', techs)

    def test_windows_task_stays_t1053_005(self):
        current = {
            'meta': {'os': 'windows'},
            'tasks': [{'name': 'Updater', 'action': 'C:\\Users\\Public\\u.exe', 'trigger': 'Daily 09:00'}]
        }
        findings, _ = analyze(self.kb, current, baseline=None)
        f_list = [f for f in findings if f['category'] == 'tasks' and f['item'] == 'Updater']
        self.assertEqual(len(f_list), 1)
        techs = self.techs_of(f_list[0])
        self.assertIn('T1053.005', techs)
        self.assertNotIn('T1053.003', techs)

    def test_log_attack_ip_boosts_connection(self):
        current = {
            'meta': {'os': 'linux'},
            'connections': [{'proto': 'tcp', 'raddr': '203.0.113.44', 'rport': 443, 'process': 'curl'}]
        }
        log_data = {
            'timeline': [{
                'ts': '2026-10-05T04:00:00',
                'host': 'WAF-01',
                'command_line': 'GET /login?id=1',
                'raw': {'dst_ip': '203.0.113.44'},
                'techniques': [{'technique': 'T1190', 'confidence': 'high'}]
            }]
        }
        log_artifacts = load_log_artifacts(log_data)
        findings, _ = analyze(self.kb, current, baseline=None, log_artifacts=log_artifacts)
        f_list = [f for f in findings if f['category'] == 'connections' and '203.0.113.44' in f['item']]
        self.assertEqual(len(f_list), 1)
        f = f_list[0]
        self.assertEqual(f['confidence'], 'high')
        self.assertGreaterEqual(f['score'], 0.85)
        self.assertTrue(any('hujum qadamida' in r for r in f['reasons']))

    def test_log_ip_without_technique_not_boosted(self):
        current = {
            'meta': {'os': 'linux'},
            'connections': [{'proto': 'tcp', 'raddr': '203.0.113.44', 'rport': 443, 'process': 'curl'}]
        }
        log_data = {
            'timeline': [{
                'ts': '2026-10-05T04:00:00',
                'host': 'WAF-01',
                'command_line': 'GET /login?id=1',
                'raw': {'dst_ip': '203.0.113.44'},
                'techniques': []
            }]
        }
        log_artifacts = load_log_artifacts(log_data)
        findings, _ = analyze(self.kb, current, baseline=None, log_artifacts=log_artifacts)
        f_list = [f for f in findings if f['category'] == 'connections' and '203.0.113.44' in f['item']]
        self.assertEqual(len(f_list), 1)
        f = f_list[0]
        self.assertLess(f['score'], 0.85)

    def test_attack_ips_set(self):
        log_data_with = {
            'timeline': [{
                'ts': '2026-10-05T04:00:00',
                'command_line': 'GET /login?id=1',
                'raw': {'dst_ip': '203.0.113.44'},
                'techniques': [{'technique': 'T1190', 'confidence': 'high'}]
            }]
        }
        a = load_log_artifacts(log_data_with)
        self.assertIn('203.0.113.44', a['attack_ips'])

        log_data_without = {
            'timeline': [{
                'ts': '2026-10-05T04:00:00',
                'command_line': 'GET /login?id=1',
                'raw': {'dst_ip': '203.0.113.44'},
                'techniques': []
            }]
        }
        a_without = load_log_artifacts(log_data_without)
        self.assertNotIn('203.0.113.44', a_without.get('attack_ips', set()))

if __name__ == '__main__':
    unittest.main()
