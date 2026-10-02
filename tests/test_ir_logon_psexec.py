import unittest
from bluekit.ir.correlator import correlate_incident, AttackStage

class KB:
    pass

def ev(ts, host, user, code, channel='Security', src=None, proc=None, cmd=None, msg='', logon_type=None):
    e = {'@timestamp': ts, 'host': {'name': host}, 'user': {'name': user},
         'winlog': {'channel': channel, 'event_data': {'TargetUserName': user}}, 'event': {'code': code}, 'message': msg}
    if src: e['source'] = {'ip': src}
    if proc or cmd: e['process'] = {'name': proc or '', 'command_line': cmd or ''}
    if logon_type: e['winlog']['event_data']['LogonType'] = logon_type
    return e

def techs(chain): return [s.technique_id for s in chain.stages]

class TestIRLogonPsExec(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kb = KB()

    def test_psexec_service_two_techniques(self):
        events = [ev('2026-10-05T05:00:03Z', 'APP-01', 'SYSTEM', '7045', channel='System', proc='PSEXESVC.exe', cmd='PSEXESVC service installed')]
        chain = correlate_incident(events, self.kb, heuristic_fallback=True)
        t = techs(chain)
        self.assertEqual(t.count('T1569.002'), 1)
        self.assertEqual(t.count('T1021.002'), 1)

    def test_psexec_repeated_aggregated(self):
        events = [
            ev('2026-10-05T05:00:00Z', 'APP-01', 'SYSTEM', '7045', channel='System', proc='PSEXESVC.exe'),
            ev('2026-10-05T05:01:00Z', 'APP-01', 'SYSTEM', '7045', channel='System', proc='PSEXESVC.exe'),
            ev('2026-10-05T05:02:00Z', 'APP-01', 'SYSTEM', '7045', channel='System', proc='PSEXESVC.exe'),
            ev('2026-10-05T05:03:00Z', 'APP-01', 'SYSTEM', '7045', channel='System', proc='PSEXESVC.exe')
        ]
        chain = correlate_incident(events, self.kb, heuristic_fallback=True)
        t = techs(chain)
        self.assertEqual(t.count('T1569.002'), 1)
        # Verify count
        s = next(s for s in chain.stages if s.technique_id == 'T1569.002')
        self.assertEqual(s.iocs.get('count'), 4)

    def test_normal_service_not_psexec(self):
        events = [ev('2026-10-05T05:00:00Z', 'APP-01', 'SYSTEM', '7045', channel='System', proc='GoogleUpdate.exe', cmd='Google Update Service installed')]
        chain = correlate_incident(events, self.kb, heuristic_fallback=True)
        t = techs(chain)
        self.assertEqual(t.count('T1021.002'), 0)

    def test_external_domain_logon(self):
        events = [ev('2026-10-05T04:00:00Z', 'ADM-JUMP02', 'corp\\backup.admin', '4624', src='198.51.100.204')]
        chain = correlate_incident(events, self.kb, heuristic_fallback=True)
        t = techs(chain)
        self.assertEqual(t.count('T1133'), 1)
        self.assertEqual(t.count('T1078.002'), 1)
        self.assertEqual(t.count('T1021.001'), 0)

    def test_external_rdp_logon_type10(self):
        events = [ev('2026-10-05T04:00:00Z', 'ADM-JUMP02', 'corp\\backup.admin', '4624', src='198.51.100.204', logon_type='10')]
        chain = correlate_incident(events, self.kb, heuristic_fallback=True)
        t = techs(chain)
        self.assertEqual(t.count('T1021.001'), 1)

    def test_logon_type_from_message(self):
        events = [ev('2026-10-05T04:00:00Z', 'ADM-JUMP02', 'corp\\backup.admin', '4624', src='203.0.113.9', msg='An account was successfully logged on (Logon Type 10) from 203.0.113.9')]
        chain = correlate_incident(events, self.kb, heuristic_fallback=True)
        t = techs(chain)
        self.assertEqual(t.count('T1021.001'), 1)

    def test_external_logons_aggregated(self):
        events = [ev(f'2026-10-05T04:{i:02d}:00Z', 'ADM-JUMP02', 'corp\\backup.admin', '4624', src='198.51.100.204') for i in range(20)]
        chain = correlate_incident(events, self.kb, heuristic_fallback=True)
        t = techs(chain)
        self.assertEqual(t.count('T1133'), 1)
        self.assertEqual(t.count('T1078.002'), 1)
        s = next(s for s in chain.stages if s.technique_id == 'T1133')
        self.assertEqual(s.iocs.get('count'), 20)

    def test_internal_sshd_logon(self):
        events = [ev('2026-10-05T04:00:00Z', 'VAULT-5', 'backupsvc', '4624', src='10.59.1.12', proc='sshd')]
        chain = correlate_incident(events, self.kb, heuristic_fallback=True)
        t = techs(chain)
        self.assertEqual(t.count('T1021.004'), 1)
        self.assertEqual(t.count('T1133'), 0)

    def test_internal_plain_logon_ignored(self):
        events = [ev('2026-10-05T04:00:00Z', 'FILE-01', 'corp\\a.k', '4624', src='10.50.1.27', logon_type='3')]
        chain = correlate_incident(events, self.kb, heuristic_fallback=True)
        t = techs(chain)
        self.assertEqual(t.count('T1133'), 0)
        self.assertEqual(t.count('T1078.002'), 0)
        self.assertEqual(t.count('T1021.001'), 0)
        self.assertEqual(t.count('T1021.004'), 0)

    def test_machine_account_ignored(self):
        events = [ev('2026-10-05T04:00:00Z', 'ADM-JUMP02', 'WS01$', '4624', src='198.51.100.204')]
        chain = correlate_incident(events, self.kb, heuristic_fallback=True)
        t = techs(chain)
        self.assertEqual(t.count('T1133'), 0)

    def test_local_account_kind(self):
        events = [ev('2026-10-05T04:00:00Z', 'ADM-JUMP02', 'ADM-JUMP02\\admin', '4624', src='198.51.100.204')]
        chain = correlate_incident(events, self.kb, heuristic_fallback=True)
        t = techs(chain)
        self.assertEqual(t.count('T1078.003'), 1)
        self.assertEqual(t.count('T1078.002'), 0)

if __name__ == '__main__':
    unittest.main()
