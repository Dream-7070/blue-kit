import unittest
from bluekit.ir.proctree import process_tree_stages
from bluekit.ir.correlator import extract_canonical

class TestProcTree(unittest.TestCase):
    def test_proctree_a(self):
        events = [
            {'host': 'h1', 'process_name': 'chrome.exe', 'cmd': 'chrome.exe https://evil.com', 'timestamp': '2026-10-01T10:00:00Z', 'process': {'parent': {'name': 'explorer.exe'}}},
            {'host': 'h1', 'process_name': 'x.exe', 'cmd': r'C:\Users\u\Downloads\x.exe', 'timestamp': '2026-10-01T10:05:00Z', 'process': {'parent': {'name': 'chrome.exe'}}}
        ]
        stages, _ = process_tree_stages(events, extract_canonical)
        t1204 = [s[0] for s in stages if s[0].technique_id == 'T1204.002']
        t1189 = [s[0] for s in stages if s[0].technique_id == 'T1189']
        self.assertEqual(len(t1204), 1)
        self.assertEqual(len(t1189), 1)
        self.assertEqual(t1204[0].confidence, "HIGH")
        
        events2 = [
            {'host': 'h1', 'process_name': 'x.exe', 'cmd': r'C:\Users\u\Downloads\x.exe', 'timestamp': '2026-10-01T10:05:00Z', 'process': {'parent': {'name': 'chrome.exe'}}}
        ]
        stages2, _ = process_tree_stages(events2, extract_canonical)
        self.assertEqual(len([s[0] for s in stages2 if s[0].technique_id == 'T1204.002']), 1)
        self.assertEqual(len([s[0] for s in stages2 if s[0].technique_id == 'T1189']), 0)

    def test_proctree_b(self):
        events = [
            {'host': 'h1', 'process_name': 'MicrosoftEdgeUpdate.exe', 'cmd': r'C:\Users\u\Downloads\MicrosoftEdgeUpdate.exe', 'timestamp': '2026-10-01T10:05:00Z', 'process': {'parent': {'name': 'msedge.exe'}}}
        ]
        stages, _ = process_tree_stages(events, extract_canonical)
        self.assertEqual(len(stages), 0)
        
    def test_proctree_c(self):
        events = [
            {'host': 'h1', 'process_name': 'powershell.exe', 'cmd': 'powershell -enc x', 'timestamp': '2026-10-01T10:05:00Z', 'process': {'parent': {'name': 'WINWORD.EXE'}}}
        ]
        stages, _ = process_tree_stages(events, extract_canonical)
        self.assertEqual(len([s[0] for s in stages if s[0].technique_id == 'T1566.001']), 1)
        self.assertEqual(len([s[0] for s in stages if s[0].technique_id == 'T1204.002']), 1)
        
    def test_proctree_d(self):
        events = [
            {'host': 'h1', 'process_name': 'winword.exe', 'cmd': 'winword doc.docx', 'timestamp': '2026-10-01T10:05:00Z', 'process': {'parent': {'name': 'outlook.exe'}}}
        ]
        stages, _ = process_tree_stages(events, extract_canonical)
        self.assertEqual(len(stages), 0)
        
    def test_proctree_e(self):
        events = [
            {'host': 'h1', 'process_name': 'x.exe', 'cmd': r'C:\Users\u\Downloads\x.exe', 'timestamp': '2026-10-01T10:05:00Z', 'process': {'parent': {'name': 'explorer.exe'}}}
        ]
        stages, _ = process_tree_stages(events, extract_canonical)
        self.assertEqual(len(stages), 0)
        
    def test_proctree_f(self):
        events = []
        for i in range(50):
            events.append({'host': 'h1', 'process_name': f'proc{i}.exe', 'cmd': f'proc{i}.exe', 'timestamp': f'2026-10-01T10:00:{i:02d}Z', 'process': {'parent': {'name': 'svchost.exe'}}})
        stages, _ = process_tree_stages(events, extract_canonical)
        self.assertEqual(len(stages), 0)


class TestProcTreeEcsShape(unittest.TestCase):
    """Real ECS/CSV ko'rinishi (tekis kalitlar) va tirnoqli, bo'shliqli yo'l."""
    def _row(self, ts, pname, parent, cmd):
        return {'@timestamp': ts, 'host.name': 'wks1', 'event.code': '1', 'process.name': pname,
                'process.parent.name': parent, 'process.command_line': cmd,
                'winlog.channel': 'Microsoft-Windows-Sysmon/Operational'}

    def test_quoted_path_with_spaces_is_detected(self):
        events = [
            self._row('2026-10-01T10:00:00Z', 'msedge.exe', 'explorer.exe', r'"C:\Program Files\Microsoft\Edge\msedge.exe" https://dl.example.org/get'),
            self._row('2026-10-01T10:02:00Z', 'player update.exe', 'msedge.exe', r'"C:\Users\John Smith\Downloads\player update.exe" /S'),
        ]
        stages, _ = process_tree_stages(events, extract_canonical)
        ids = sorted(s[0].technique_id for s in stages)
        self.assertEqual(ids, ['T1189', 'T1204.002'])
        t = [s[0] for s in stages if s[0].technique_id == 'T1204.002'][0]
        self.assertEqual(t.iocs['process'], r'C:\Users\John Smith\Downloads\player update.exe')
        self.assertEqual(t.confidence, 'HIGH')

    def test_quoted_program_files_child_is_ignored(self):
        events = [self._row('2026-10-01T10:02:00Z', 'helper.exe', 'chrome.exe', r'"C:\Program Files\Vendor\helper.exe" --child')]
        stages, _ = process_tree_stages(events, extract_canonical)
        self.assertEqual(len(stages), 0)
