import unittest
import tempfile
import shutil
import json
import os
import urllib.request
import urllib.parse
import urllib.error

from bluekit.kb.query import KB
from bluekit.web.server import WebKitServer, WebKitHandler

class TestLogsFilterWeb(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.kb = KB()
        except Exception:
            raise unittest.SkipTest("KB topilmadi")
        cls.workdir = tempfile.mkdtemp()
        cls.server = WebKitServer(('127.0.0.1', 0), WebKitHandler, cls.kb, cls.workdir)
        import threading
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.daemon = True
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"
        
        sample = os.path.join(os.path.dirname(__file__), '..', 'data', 'samples', 'win_phishing.csv')
        with open(sample, 'r', encoding='utf-8') as f:
            cls.log_content = f.read()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'server'):
            cls.server.shutdown()
            cls.server.server_close()
        if hasattr(cls, 'workdir'):
            shutil.rmtree(cls.workdir, ignore_errors=True)

    def _post(self, path, data):
        req = urllib.request.Request(
            self.base_url + path,
            method='POST',
            headers={'Content-Type': 'application/json'},
            data=json.dumps(data).encode('utf-8')
        )
        try:
            with urllib.request.urlopen(req) as response:
                return response.status, json.loads(response.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode('utf-8'))

    def _get(self, path):
        req = urllib.request.Request(self.base_url + path, method='GET')
        try:
            with urllib.request.urlopen(req) as response:
                return response.status, response.read().decode('utf-8')
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode('utf-8')

    def test_01_host(self):
        status, data = self._post('/api/logs/analyze', {
            'content': self.log_content, 'filename': 'win_phishing.csv',
            'host': 'dc01'
        })
        self.assertEqual(status, 200)
        self.assertEqual(data['stats']['events'], 7)
        self.assertEqual(data['stats']['filter'], {'from': None, 'to': None, 'host': 'dc01', 'loaded': 33})

    def test_02_time_bound(self):
        status, data = self._post('/api/logs/analyze', {
            'content': self.log_content, 'filename': 'win_phishing.csv',
            'from': '2026-10-05 14:20:00', 'to': '2026-10-05 14:21:30'
        })
        self.assertEqual(status, 200)
        self.assertEqual(data['stats']['events'], 8)

    def test_03_tz(self):
        status, data = self._post('/api/logs/analyze', {
            'content': self.log_content, 'filename': 'win_phishing.csv',
            'src_tz': 'utc', 'from': '2026-10-05 09:20:00', 'to': '2026-10-05 09:21:30'
        })
        self.assertEqual(status, 200)
        self.assertEqual(data['stats']['events'], 8)

        status2, data2 = self._post('/api/logs/analyze', {
            'content': self.log_content, 'filename': 'win_phishing.csv',
            'from': '2026-10-05 14:20:00', 'to': '2026-10-05 14:21:30'
        })
        self.assertEqual(status2, 200)
        self.assertEqual(data2['stats']['events'], 8)

    def test_04_iso_with_tz(self):
        status, data = self._post('/api/logs/analyze', {
            'content': self.log_content, 'filename': 'win_phishing.csv',
            'from': '2026-10-05T09:20:00Z', 'to': '2026-10-05T12:21:30+03:00'
        })
        self.assertEqual(status, 200)
        self.assertEqual(data['stats']['events'], 8)

    def test_05_invalid_date(self):
        status, data = self._post('/api/logs/analyze', {
            'content': self.log_content, 'filename': 'win_phishing.csv',
            'from': 'notadate'
        })
        self.assertEqual(status, 400)
        self.assertIn('notadate', data['error'])

    def test_06_from_after_to(self):
        status, data = self._post('/api/logs/analyze', {
            'content': self.log_content, 'filename': 'win_phishing.csv',
            'from': '2026-10-05 15:00', 'to': '2026-10-05 14:00'
        })
        self.assertEqual(status, 400)

    def test_07_invalid_type(self):
        status, data = self._post('/api/logs/analyze', {
            'content': self.log_content, 'filename': 'win_phishing.csv',
            'from': 123
        })
        self.assertEqual(status, 400)

    def test_08_empty_strings(self):
        status, data = self._post('/api/logs/analyze', {
            'content': self.log_content, 'filename': 'win_phishing.csv',
            'from': '', 'to': '   ', 'host': ''
        })
        self.assertEqual(status, 200)
        self.assertEqual(data['stats']['events'], 33)
        self.assertNotIn('filter', data['stats'])

    def test_09_html_content(self):
        status, data = self._get('/')
        self.assertEqual(status, 200)
        self.assertIn('id="log-from"', data)
        self.assertIn('id="log-to"', data)
        self.assertIn('id="log-host"', data)
        self.assertIn('clearLogFilters()', data)

    def test_10_js_content(self):
        status, data = self._get('/app.js')
        self.assertEqual(status, 200)
        self.assertIn('function clearLogFilters', data)
        self.assertIn('res.stats.filter', data)
        
        idx_start = data.find('async function buildLogInputBody')
        self.assertNotEqual(idx_start, -1)
        idx_end = data.find('async function', idx_start + 1)
        self.assertNotEqual(idx_end, -1)
        body = data[idx_start:idx_end]
        self.assertIn('log-file', body)
        self.assertNotIn('log-from', body)
