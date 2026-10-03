import unittest
from bluekit.ir.correlator import correlate_incident
from bluekit.kb.query import KB

class TestIRCloudRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kb = KB()

    def get_base_event(self, cmd="", dst_ip=None, user="u1", host="LOGSRV-7"):
        return {
            'command_line': cmd,
            'message': '',
            'process': 'svc',
            'host': host,
            'user': user,
            'timestamp': '2026-01-01T12:00:00Z',
            'dst_ip': dst_ip,
            'src_ip': None
        }

    def test_consent_risky_scope(self):
        ev = self.get_base_event('Consent to app DocPreview scope Mail.Read Files.Read.All offline_access', dst_ip='203.0.113.81')
        chain = correlate_incident([ev], self.kb, heuristic_fallback=False)
        t1528 = [s for s in chain.stages if s.technique_id == "T1528"]
        t1566 = [s for s in chain.stages if s.technique_id == "T1566.002"]
        self.assertEqual(len(t1528), 1)
        self.assertEqual(len(t1566), 1)
        self.assertEqual(t1528[0].iocs.get('src_ip'), '203.0.113.81')

    def test_admin_consent_no_phishing(self):
        ev = self.get_base_event('Consent to application HRConnector IsAdminConsent=True scope User.Read')
        chain = correlate_incident([ev], self.kb, heuristic_fallback=False)
        t1528 = [s for s in chain.stages if s.technique_id == "T1528"]
        t1566 = [s for s in chain.stages if s.technique_id == "T1566.002"]
        self.assertEqual(len(t1528), 1)
        self.assertEqual(len(t1566), 0)

    def test_inbox_rule_forward(self):
        ev = self.get_base_event('New-InboxRule forward invoices to audit-box@external.test')
        chain = correlate_incident([ev], self.kb, heuristic_fallback=False)
        t1114 = [s for s in chain.stages if s.technique_id == "T1114.003"]
        self.assertEqual(len(t1114), 1)

    def test_inbox_rule_hide(self):
        ev = self.get_base_event('create inbox rule HideSecurityAlerts move to RSS Feeds')
        chain = correlate_incident([ev], self.kb, heuristic_fallback=False)
        t1564 = [s for s in chain.stages if s.technique_id == "T1564.008"]
        t1114 = [s for s in chain.stages if s.technique_id == "T1114.003"]
        self.assertEqual(len(t1564), 1)
        self.assertEqual(len(t1114), 0)

    def test_mailbox_delegate(self):
        ev = self.get_base_event('Add-MailboxPermission -Identity ceo -User attacker -AccessRights FullAccess')
        chain = correlate_incident([ev], self.kb, heuristic_fallback=False)
        t1098 = [s for s in chain.stages if s.technique_id == "T1098.002"]
        self.assertEqual(len(t1098), 1)

    def test_remote_mail_collection(self):
        ev1 = self.get_base_event('list messages query subject NDA', user='u1')
        ev2 = self.get_base_event('download attachment merger_draft.docx', user='u1')
        chain = correlate_incident([ev1, ev2], self.kb, heuristic_fallback=False)
        t1114 = [s for s in chain.stages if s.technique_id == "T1114.002"]
        t1530 = [s for s in chain.stages if s.technique_id == "T1530"]
        self.assertEqual(len(t1114), 1)
        self.assertEqual(t1114[0].iocs.get('count', 1), 2)
        self.assertEqual(len(t1530), 0)

    def test_cloud_file_download(self):
        ev1 = self.get_base_event('download Sales/Q4_targets.xlsx 824112 bytes', user='u1')
        ev2 = self.get_base_event('FileDownloaded Legal/term_sheet.xlsx', user='u2')
        ev2['Workload'] = 'SharePoint'
        chain = correlate_incident([ev1, ev2], self.kb, heuristic_fallback=False)
        t1530 = [s for s in chain.stages if s.technique_id == "T1530"]
        t1213 = [s for s in chain.stages if s.technique_id == "T1213.002"]
        self.assertEqual(len(t1530), 1)
        self.assertEqual(len(t1213), 1)

    def test_drive_enumeration(self):
        ev = self.get_base_event('GET /me/drive/root:/Sales:/children')
        chain = correlate_incident([ev], self.kb, heuristic_fallback=False)
        t1619 = [s for s in chain.stages if s.technique_id == "T1619"]
        self.assertEqual(len(t1619), 1)

    def test_refresh_token_without_mfa(self):
        ev1 = self.get_base_event('refresh_token grant; MFA not requested', dst_ip='203.0.113.81')
        chain1 = correlate_incident([ev1], self.kb, heuristic_fallback=False)
        t1078_1 = [s for s in chain1.stages if s.technique_id == "T1078.004"]
        self.assertEqual(len(t1078_1), 1)

        ev2 = self.get_base_event('refresh_token grant; MFA not requested', dst_ip='')
        chain2 = correlate_incident([ev2], self.kb, heuristic_fallback=False)
        t1078_2 = [s for s in chain2.stages if s.technique_id == "T1078.004"]
        self.assertEqual(len(t1078_2), 0)

    def test_operation_field_only(self):
        ev = {
            'Operation': 'Consent to application',
            'command_line': '',
            'message': '',
            'user': 'u@x.test',
            'host': 'LOGSRV-7',
            'timestamp': '2026-01-01T12:00:00Z',
            'dst_ip': None,
            'src_ip': None
        }
        chain = correlate_incident([ev], self.kb, heuristic_fallback=False)
        t1528 = [s for s in chain.stages if s.technique_id == "T1528"]
        self.assertEqual(len(t1528), 1)

    def test_host_name_not_required(self):
        ev = self.get_base_event('Consent to app DocPreview scope Mail.Read Files.Read.All offline_access', host='WS-17')
        chain = correlate_incident([ev], self.kb, heuristic_fallback=False)
        t1528 = [s for s in chain.stages if s.technique_id == "T1528"]
        self.assertEqual(len(t1528), 1)

    def test_plain_words_not_cloud(self):
        evs = [
            self.get_base_event('download complete for update package'),
            self.get_base_event('consent form printed'),
            self.get_base_event('move file to archive')
        ]
        chain = correlate_incident(evs, self.kb, heuristic_fallback=False)
        t1528 = [s for s in chain.stages if s.technique_id == "T1528"]
        t1530 = [s for s in chain.stages if s.technique_id == "T1530"]
        t1564 = [s for s in chain.stages if s.technique_id == "T1564.008"]
        self.assertEqual(len(t1528), 0)
        self.assertEqual(len(t1530), 0)
        self.assertEqual(len(t1564), 0)

    def test_cloud_literals_absent(self):
        with open('bluekit/ir/correlator.py', 'r', encoding='utf-8') as f:
            content = f.read().lower()
        
        forbidden = [
            'user consent phishing', 'malicious oauth consent', 'onedrive enumeration',
            'download deals', 'bulk download executive files', 'mailbox forwarding persistence',
            'mail rule persistence', 'password compromise not observed', 'legacy password grant denied',
            'app-only refresh token', 'credential reset initiated by attacker', 'sp-audit',
            'mail-audit', 'idp-log'
        ]
        
        found = [w for w in forbidden if w in content]
        self.assertEqual(found, [])

if __name__ == '__main__':
    unittest.main()
