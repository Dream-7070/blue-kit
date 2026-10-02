import unittest
from bluekit.kb.query import KB
from bluekit.logs.detect import detect_event


def _techs(hits, conf=('high', 'medium')):
    return {h['technique'] for h in hits if h['confidence'] in conf}


class TestNoiseLogonPsexec(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kb = KB()

    def det(self, channel, eid, cmd=None, msg=''):
        return detect_event(self.kb, {'channel': channel, 'event_id': eid, 'command_line': cmd, 'message': msg})

    def test_psexec_service_install_survives_signed_path_drop(self):
        # 7045 PSEXESVC: buyruq qatori argumentsiz C:\Windows\ yo'li — oldin butunlay tashlanardi
        hits = self.det('System', '7045', r'C:\Windows\PSEXESVC.exe', 'A service was installed: PSEXESVC')
        self.assertEqual(_techs(hits, ('high',)), {'T1543.003', 'T1569.002'})

    def test_signed_path_without_strong_eventid_still_dropped(self):
        ev = {'channel': 'Microsoft-Windows-Sysmon/Operational', 'event_id': '1',
              'command_line': r'C:\Windows\System32\svchost.exe', 'message': ''}
        self.assertEqual(detect_event(self.kb, ev), [])

    def test_windows_temp_not_treated_as_signed(self):
        from bluekit.logs.detect import load_noise
        rule = [r for r in load_noise() if r['name'] == 'Windows signed binary path'][0]
        self.assertIsNone(rule['pattern'].search(r'C:\Windows\Temp\svchost.exe'))
        self.assertIsNotNone(rule['pattern'].search(r'C:\Windows\System32\svchost.exe'))

    def test_logon_type_formats_downgraded(self):
        for msg in ('An account was successfully logged on (type 2)',
                    'An account was successfully logged on.\r\n\tLogon Type:\t\t\t3\r\n',
                    'Logon Type 3 from 10.0.0.5'):
            hits = self.det('Security', '4624', None, msg)
            self.assertEqual(len(hits), 2, msg)
            self.assertEqual(_techs(hits), set(), msg)

    def test_rdp_logon_type_10_kept(self):
        for msg in ('Logon Type 10 from 10.0.0.5', 'Logon Type:\t\t\t10', 'logged on (type 10)'):
            self.assertIn('T1021.001', _techs(self.det('Security', '4624', None, msg)), msg)


if __name__ == '__main__':
    unittest.main()
