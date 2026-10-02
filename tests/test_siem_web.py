import unittest
import json
import urllib.error
import urllib.request
import os

from bluekit.kb.query import KB
from bluekit.paths import get_kb_path
from bluekit.web.server import WebKitServer, WebKitHandler
import threading
import time

class TestSiemWeb(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        kb_path = get_kb_path('data')
        if not os.path.exists(kb_path):
            raise unittest.SkipTest("KB topilmadi")
        cls.kb = KB(kb_path)
        cls.port = 19191
        cls.server = WebKitServer(('127.0.0.1', cls.port), WebKitHandler, cls.kb, 'test-work')
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.daemon = True
        cls.thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def _get(self, path):
        req = urllib.request.Request(f'http://127.0.0.1:{self.port}{path}')
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode())

    def _post(self, path, data):
        req = urllib.request.Request(f'http://127.0.0.1:{self.port}{path}', method='POST')
        req.add_header('Content-Type', 'application/json')
        with urllib.request.urlopen(req, data=json.dumps(data).encode('utf-8')) as response:
            return json.loads(response.read().decode())

    def test_01_get_dialects(self):
        res = self._get('/api/siem/dialects')
        self.assertEqual(len(res), 12)
        qradar = res.get('qradar')
        self.assertIsNotNone(qradar)
        self.assertEqual(qradar['bk_preset'], 'qradar')

    def test_02_get_hunts(self):
        res = self._get('/api/siem/hunts')
        self.assertEqual(len(res['hunts']), 37)
        self.assertEqual(len(res['categories']), 8)

    def test_03_get_hunts_category(self):
        res = self._get('/api/siem/hunts?category=auth')
        self.assertEqual(len(res['hunts']), 9)
        names = [h['id'] for h in res['hunts']]
        self.assertNotIn('web-attack-patterns', names)

    def test_04_get_hunts_search(self):
        res = self._get('/api/siem/hunts?search=T1110')
        ids = [h['id'] for h in res['hunts']]
        self.assertIn('auth-bruteforce', ids)

    def test_05_post_query(self):
        res = self._post('/api/siem/query', {'hunt_id': 'auth-bruteforce', 'siem': 'qradar'})
        self.assertEqual(len(res['results']), 1)
        query = res['results'][0]['query']
        self.assertIn('4625', query)
        self.assertIn('LAST 7 DAYS', query)

    def test_06_post_query_days(self):
        res = self._post('/api/siem/query', {'hunt_id': 'auth-bruteforce', 'siem': 'qradar', 'days': 30})
        query = res['results'][0]['query']
        self.assertIn('LAST 30 DAYS', query)

    def test_07_post_query_all(self):
        res = self._post('/api/siem/query', {'hunt_id': 'auth-bruteforce', 'siem': 'all'})
        self.assertEqual(len(res['results']), 12)

    def test_08_post_query_unknown(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._post('/api/siem/query', {'hunt_id': 'unknown-hunt', 'siem': 'qradar'})
        self.assertEqual(ctx.exception.code, 400)

    def test_09_post_query_empty_params(self):
        res = self._post('/api/siem/query', {'hunt_id': 'auth-bruteforce', 'siem': 'qradar', 'days': None, 'threshold': ''})
        query = res['results'][0]['query']
        self.assertIn('LAST 7 DAYS', query)
        self.assertIn('>= 20', query)

    def test_10_js_no_hardcoded(self):
        html_path = os.path.join(os.path.dirname(__file__), '../bluekit/web/static/index.html')
        js_path = os.path.join(os.path.dirname(__file__), '../bluekit/web/static/app.js')
        with open(html_path, 'r', encoding='utf-8') as f:
            html = f.read()
        with open(js_path, 'r', encoding='utf-8') as f:
            js = f.read()
        self.assertNotIn('auth-bruteforce', html)
        self.assertNotIn('T1110', html)
        self.assertNotIn('auth-bruteforce', js)
        self.assertNotIn('T1110', js)

    def test_11_server_regression(self):
        server_path = os.path.join(os.path.dirname(__file__), '../bluekit/web/server.py')
        with open(server_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        self.assertIn('def run_server', content)
        self.assertIn('def do_PUT', content)
        self.assertIn('def do_DELETE', content)
        self.assertIn('def _load_resp_args', content)
        self.assertIn('def _collect_input_files', content)
        
        endpoints = [
            '/api/logs/analyze', '/api/resp/triage', '/api/resp/fix', '/api/resp/sla',
            '/api/resp/doctor', '/api/resp/fraud', '/api/ir/chain', '/api/hunt/beacons',
            '/api/tracker', '/api/report', '/api/info', '/api/validate', '/api/search',
            '/api/id', '/api/related', '/api/ioc', '/api/tactics'
        ]
        for ep in endpoints:
            self.assertIn(ep, content)

if __name__ == '__main__':
    unittest.main()
