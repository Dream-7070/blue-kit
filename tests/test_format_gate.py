import unittest
import os
import tempfile
import json
import gzip
import subprocess
import sys

from bluekit.logs.formats import identify
from bluekit.logs.parse import load_rows
from bluekit.ir.correlator import load_events_from_files

JSONL_SAMPLE = """{"timestamp": "2026-10-05T02:00:00Z", "host": "web-01", "user": "alice", "process": "sshd", "message": "a"}
{"timestamp": "2026-10-05T02:01:00Z", "host": "web-02", "user": "bob", "process": "sshd", "message": "b"}
{"timestamp": "2026-10-05T02:02:00Z", "host": "db-01", "user": "carol", "process": "sshd", "message": "c"}
"""

SYSLOG_SAMPLE = """Oct  2 10:00:01 web01 sshd[123]: Failed password for root from 198.51.100.7 port 4444 ssh2
Oct  2 10:00:05 web01 sshd[123]: Accepted password for alice from 198.51.100.7 port 4445 ssh2
"""

class TestFormatGate(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp = self.temp_dir.name
        self.repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def tearDown(self):
        self.temp_dir.cleanup()

    def make_file(self, name, content, binary=False):
        path = os.path.join(self.tmp, name)
        mode = 'wb' if binary else 'w'
        kwargs = {} if binary else {'newline': '', 'encoding': 'utf-8'}
        with open(path, mode, **kwargs) as f:
            f.write(content)
        return path

    def test_text_names_accepted(self):
        names = {
            'secure': SYSLOG_SAMPLE,
            'messages': SYSLOG_SAMPLE,
            'auth.log.1': SYSLOG_SAMPLE,
            'a.txt': SYSLOG_SAMPLE,
            'a.jsonl': JSONL_SAMPLE,
            'a.ndjson': JSONL_SAMPLE,
            'app_events': JSONL_SAMPLE,
        }
        checked = 0
        for name, content in names.items():
            path = self.make_file(name, content)
            with self.subTest(name=name):
                r = identify(path)
                self.assertTrue(r.get('supported', False))
                self.assertEqual(r.get('format'), 'supported')
                checked += 1
        self.assertEqual(checked, 7)

    def test_empty_file_accepted(self):
        path = self.make_file('empty.jsonl', '')
        r = identify(path)
        self.assertTrue(r.get('supported', False))
        rows = list(load_rows(path))
        self.assertEqual(len(rows), 0)

    def test_jsonl_fields_parsed(self):
        path = self.make_file('a.jsonl', JSONL_SAMPLE)
        rows = list(load_rows(path))
        self.assertEqual(len(rows), 3)
        self.assertEqual([r.get('host') for r in rows], ['web-01', 'web-02', 'db-01'])
        self.assertEqual([r.get('user') for r in rows], ['alice', 'bob', 'carol'])
        # JSON matn xom holda message ga tushmagan: har qatorning o'z message maydoni
        self.assertEqual([r.get('message') for r in rows], ['a', 'b', 'c'])

    def test_extensionless_jsonl_fields_parsed(self):
        for name in ['app_events', 'events.log']:
            path = self.make_file(name, JSONL_SAMPLE)
            rows = list(load_rows(path))
            self.assertEqual(len(rows), 3)
            self.assertEqual([r.get('host') for r in rows], ['web-01', 'web-02', 'db-01'])
            self.assertEqual([r.get('user') for r in rows], ['alice', 'bob', 'carol'])

    def test_syslog_extensionless_stays_text(self):
        for name in ['secure', 'auth.log.1']:
            path = self.make_file(name, SYSLOG_SAMPLE)
            rows = list(load_rows(path))
            self.assertEqual(len(rows), 2)
            self.assertIn('Failed password', rows[0].get('message', ''))

    def test_brace_line_not_json_falls_back_to_text(self):
        content = "{not json} first\nsecond line\nthird line\n"
        path = self.make_file('notes', content)
        rows = list(load_rows(path))
        self.assertEqual(len(rows), 3)
        self.assertIn('{not json}', rows[0].get('message', ''))

    def test_binary_formats_rejected_with_hint(self):
        files = {
            'x.evtx': b'ElfFile\x00' + b'a'*32,
            'x.pcap': b'\xd4\xc3\xb2\xa1' + b'z'*32,
            'x.zip': b'PK\x03\x04' + b'z'*32,
            'auth.log.2.gz': gzip.compress(SYSLOG_SAMPLE.encode('utf-8')),
            'u16.csv': 'host,user\r\nweb,alice\r\n'.encode('utf-16'),
            'blob': b'ab\x00cd' * 10
        }
        expected_formats = {
            'x.evtx': 'evtx',
            'x.pcap': 'pcap',
            'x.zip': 'zip',
            'auth.log.2.gz': 'gzip',
            'u16.csv': 'utf16',
            'blob': 'unknown'
        }
        expected_hints = {
            'x.evtx': 'hayabusa',
            'x.pcap': 'tshark',
            'x.zip': 'oching',
            'auth.log.2.gz': 'gzip -d',
            'u16.csv': 'utf8',
            'blob': '' 
        }
        
        checked = 0
        for name, data in files.items():
            path = self.make_file(name, data, binary=True)
            with self.subTest(name=name):
                r = identify(path)
                self.assertFalse(r.get('supported', True))
                self.assertEqual(r.get('format'), expected_formats[name])
                hint = r.get('hint', '').lower()
                self.assertTrue(bool(hint))
                if expected_hints[name]:
                    self.assertIn(expected_hints[name], hint)
                checked += 1
        self.assertEqual(checked, 6)

    def test_correlator_loads_jsonl_and_extensionless(self):
        p1 = self.make_file('a.jsonl', JSONL_SAMPLE)
        p2 = self.make_file('secure', SYSLOG_SAMPLE)
        events, source_name = load_events_from_files([p1, p2])
        self.assertEqual(len(events), 5)

    def test_cli_ir_chain_accepts_jsonl_and_secure(self):
        p1 = self.make_file('a.jsonl', JSONL_SAMPLE)
        p2 = self.make_file('secure', SYSLOG_SAMPLE)
        out_json = os.path.join(self.tmp, 'o.json')
        cmd = [sys.executable, 'bk.py', '--src-tz', 'utc', 'ir', 'chain', '--json', '--out', out_json, p1, p2]
        res = subprocess.run(cmd, cwd=self.repo_root, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=180)
        self.assertEqual(res.returncode, 0, f"STDOUT: {res.stdout}\nSTDERR: {res.stderr}")
        self.assertNotIn("Noma'lum format", res.stdout)
        self.assertTrue(os.path.exists(out_json))
        with open(out_json, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.assertIn('attack_chain_timeline', data)

    def test_cli_logs_analyze_accepts_extensionless(self):
        p_sec = self.make_file('secure', SYSLOG_SAMPLE)
        la_json = os.path.join(self.tmp, 'la.json')
        cmd = [sys.executable, 'bk.py', 'logs', 'analyze', p_sec, '--json-out', la_json]
        res = subprocess.run(cmd, cwd=self.repo_root, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=180)
        self.assertEqual(res.returncode, 0, f"STDOUT: {res.stdout}\nSTDERR: {res.stderr}")
        self.assertTrue(os.path.exists(la_json))

    def test_cli_rejects_gzip_with_hint(self):
        p_gz = self.make_file('auth.log.2.gz', gzip.compress(SYSLOG_SAMPLE.encode('utf-8')), binary=True)
        cmd = [sys.executable, 'bk.py', 'logs', 'analyze', p_gz]
        res = subprocess.run(cmd, cwd=self.repo_root, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=180)
        self.assertEqual(res.returncode, 1)
        self.assertIn("gzip -d", res.stdout.lower() + res.stderr.lower())

if __name__ == '__main__':
    unittest.main()
