import unittest
from bluekit.ir.correlator import correlate_incident
from bluekit.kb.query import KB

def share(ts, user, sharename, rel, host='FS-01', code='5145', src='10.54.1.19'):
    return {'@timestamp': ts, 'host': {'name': host}, 'user': {'name': user}, 'winlog': {'channel': 'Security',
            'event_data': {'ShareName': sharename, 'RelativeTargetName': rel}}, 'event': {'code': code},
            'source': {'ip': src}, 'message': ''}

class TestIRShareUSB(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kb = KB()

    def test_bulk_share_read(self):
        events = []
        for i in range(25):
            events.append(share(f"2026-01-01T10:0{i//5}:00Z", "corp\\m.r", "\\\\*\\Projects", f"doc_{i}.pdf"))
        
        chain = correlate_incident(events, kb=self.kb, heuristic_fallback=False)
        t1039_stages = [s for s in chain.stages if s.technique_id == 'T1039']
        self.assertEqual(len(t1039_stages), 1)
        self.assertEqual(t1039_stages[0].confidence, 'HIGH')
        self.assertEqual(t1039_stages[0].iocs.get('files'), 25)

    def test_sensitive_share_single_file(self):
        events = [share("2026-01-01T10:00:00Z", "corp\\m.r", "\\\\*\\Finance", "payroll_2026.xlsx")]
        chain = correlate_incident(events, kb=self.kb, heuristic_fallback=False)
        t1039_stages = [s for s in chain.stages if s.technique_id == 'T1039']
        self.assertEqual(len(t1039_stages), 1)
        self.assertEqual(t1039_stages[0].confidence, 'MEDIUM')

    def test_plain_share_few_files_ignored(self):
        events = [
            share("2026-01-01T10:00:00Z", "corp\\m.r", "\\\\*\\Public", "menu.pdf"),
            share("2026-01-01T10:01:00Z", "corp\\m.r", "\\\\*\\Public", "guide.pdf"),
            share("2026-01-01T10:02:00Z", "corp\\m.r", "\\\\*\\Public", "rules.pdf"),
        ]
        chain = correlate_incident(events, kb=self.kb, heuristic_fallback=False)
        t1039_stages = [s for s in chain.stages if s.technique_id == 'T1039']
        self.assertEqual(len(t1039_stages), 0)

    def test_ipc_and_admin_share_not_t1039(self):
        events = [
            share("2026-01-01T10:00:00Z", "corp\\m.r", "\\\\*\\IPC$", "test"),
            share("2026-01-01T10:01:00Z", "corp\\m.r", "\\\\*\\ADMIN$", "test2"),
        ]
        chain = correlate_incident(events, kb=self.kb, heuristic_fallback=False)
        t1039_stages = [s for s in chain.stages if s.technique_id == 'T1039']
        self.assertEqual(len(t1039_stages), 0)

    def test_bulk_outside_window(self):
        events = []
        for i in range(25):
            events.append(share(f"2026-01-{i+1:02d}T10:00:00Z", "corp\\m.r", "\\\\*\\Projects", f"doc_{i}.pdf"))
        
        chain = correlate_incident(events, kb=self.kb, heuristic_fallback=False)
        t1039_stages = [s for s in chain.stages if s.technique_id == 'T1039']
        self.assertEqual(len(t1039_stages), 0)

    def test_unc_in_message_text(self):
        evt = {'@timestamp': "2026-01-01T10:00:00Z", 'host': {'name': 'FS-01'}, 'user': {'name': 'corp\\m.r'},
               'event': {'code': '5145'}, 'source': {'ip': '10.54.1.19'}, 'message': 'share access \\\\FILE-01\\Finance\\payroll_2026.xlsx'}
        chain = correlate_incident([evt], kb=self.kb, heuristic_fallback=False)
        t1039_stages = [s for s in chain.stages if s.technique_id == 'T1039']
        self.assertEqual(len(t1039_stages), 1)

    def test_usbstor_device(self):
        evt = {'timestamp': "2026-01-01T10:00:00Z", 'host': 'HR-LT09', 'user': 'corp\\m.r', 'process': 'USBSTOR', 'command_line': 'device serial 4C53-0001 mounted E:', 'message': ''}
        chain = correlate_incident([evt], kb=self.kb, heuristic_fallback=False)
        t1052_stages = [s for s in chain.stages if s.technique_id == 'T1052.001']
        self.assertEqual(len(t1052_stages), 1)

    def test_copy_to_removable(self):
        evt = {'timestamp': "2026-01-01T10:00:00Z", 'host': 'SEC-GW3', 'user': 'corp\\m.r', 'process': 'DLP', 'command_line': 'copy q3_pack.7z to removable media 201554433 bytes'}
        chain = correlate_incident([evt], kb=self.kb, heuristic_fallback=False)
        t1052_stages = [s for s in chain.stages if s.technique_id == 'T1052.001']
        self.assertEqual(len(t1052_stages), 1)
        self.assertEqual(t1052_stages[0].confidence, 'HIGH')

    def test_event_6416(self):
        evt = {'timestamp': "2026-01-01T10:00:00Z", 'host': 'HR-LT09', 'user': 'corp\\m.r', 'event': {'code': '6416'}, 'winlog': {'event_data': {'ClassName': 'DiskDrive'}}, 'message': ''}
        chain = correlate_incident([evt], kb=self.kb, heuristic_fallback=False)
        t1052_stages = [s for s in chain.stages if s.technique_id == 'T1052.001']
        self.assertEqual(len(t1052_stages), 1)

    def test_usb_mouse_not_exfil(self):
        evt = {'timestamp': "2026-01-01T10:00:00Z", 'host': 'HR-LT09', 'user': 'corp\\m.r', 'event': {'code': '6416'}, 'winlog': {'event_data': {'ClassName': 'Mouse'}}, 'DeviceDescription': 'HID-compliant mouse', 'message': ''}
        chain = correlate_incident([evt], kb=self.kb, heuristic_fallback=False)
        t1052_stages = [s for s in chain.stages if s.technique_id == 'T1052.001']
        self.assertEqual(len(t1052_stages), 0)

    def test_share_usb_literals_absent(self):
        import os
        correlator_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'bluekit', 'ir', 'correlator.py')
        with open(correlator_path, 'r', encoding='utf-8') as f:
            content = f.read().lower()
            
        literals = ['read 327 employee files', 'hr-confidential', 'synth-usb', 'hr_docs', 'usb exfil blocked', 'usb inserted', 'unauthorized mass file copy']
        found = [l for l in literals if l in content]
        self.assertEqual(found, [])


    def test_admin_dollar_share_bulk_not_t1039(self):
        evts = [share(f'2026-10-05T04:00:{i:02d}Z', 'corp\\u', '\\\\*\\C$', f'Finance\\f{i}.xlsx') for i in range(25)]
        chain = correlate_incident(evts, self.kb, heuristic_fallback=False)
        self.assertEqual(sum(1 for s in chain.stages if s.technique_id == 'T1039'), 0)

    def test_usb_input_device_mouse_ignored(self):
        e = {'@timestamp': '2026-10-05T04:00:00Z', 'host': {'name': 'W'}, 'user': {'name': 'u'},
             'winlog': {'channel': 'Security', 'event_data': {'ClassName': 'Mouse'}},
             'DeviceDescription': 'USB Input Device', 'event': {'code': '6416'}, 'message': ''}
        chain = correlate_incident([e], self.kb, heuristic_fallback=False)
        self.assertEqual(sum(1 for s in chain.stages if s.technique_id == 'T1052.001'), 0)

if __name__ == '__main__':
    unittest.main()
