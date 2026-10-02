import unittest
import os
import tempfile
from bluekit.logs.formats import identify
from bluekit.logs.parse import load_rows

class TestJournalParse(unittest.TestCase):
    def test_binary_journal_identification(self):
        with tempfile.NamedTemporaryFile(suffix='.journal', delete=False) as f:
            f.write(b'LPKSHHRH\x01\x00\x00\x00\x00\x00\x00\x00')
            tmp_path = f.name
        try:
            info = identify(tmp_path)
            self.assertEqual(info['format'], 'journal_bin')
            self.assertFalse(info['supported'])
            self.assertIn('journalctl', info['hint'])
            
            rows = load_rows(tmp_path)
            self.assertEqual(len(rows), 0)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_text_journal_parsing(self):
        sample = """TIME=2026-10-05T09:15:00Z
EVENT_ID=4688
SOURCE=Security
_HOSTNAME=VAULT-01
_COMM=powershell.exe
_PID=1234
MESSAGE=Process created
DETAIL=User=admin Image=C:\\Windows\\powershell.exe CommandLine=powershell.exe -enc AAAA

TIME=2026-10-05T09:20:00Z
EVENT_ID=7045
SOURCE=System
_HOSTNAME=VAULT-01
_COMM=services.exe
_PID=456
MESSAGE=Service installed
DETAIL=ServiceName=RnStage
"""
        with tempfile.NamedTemporaryFile('w', suffix='.journal', delete=False, encoding='utf-8') as f:
            f.write(sample)
            tmp_path = f.name
        try:
            rows = load_rows(tmp_path)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]['timestamp'], '2026-10-05T09:15:00Z')
            self.assertEqual(rows[0]['host'], 'VAULT-01')
            self.assertEqual(rows[0]['process'], 'powershell.exe')
            self.assertEqual(rows[0]['pid'], '1234')
            self.assertEqual(rows[0]['source'], 'Security')
            self.assertEqual(rows[0]['message'], 'Process created')
            self.assertEqual(rows[0]['User'], 'admin')
            self.assertEqual(rows[0]['CommandLine'], 'powershell.exe -enc AAAA')
            
            self.assertEqual(rows[1]['ServiceName'], 'RnStage')
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

if __name__ == '__main__':
    unittest.main()
