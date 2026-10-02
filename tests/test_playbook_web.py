import unittest
import threading
import urllib.request
import urllib.error
import json
import os
import time

from bluekit.paths import get_kb_path
from bluekit.kb.query import KB
from bluekit.web.server import WebKitServer, WebKitHandler

class TestPlaybookWeb(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        kb_path = get_kb_path()
        if not os.path.exists(kb_path):
            raise unittest.SkipTest("KB not built")
        cls.kb = KB(kb_path)
        cls.workdir = os.path.join(os.path.dirname(__file__), 'test_playbook_web_work')
        os.makedirs(cls.workdir, exist_ok=True)
        # clear playbook.json if exists
        pb_file = os.path.join(cls.workdir, 'playbook.json')
        if os.path.exists(pb_file):
            os.remove(pb_file)
            
        cls.server = WebKitServer(('127.0.0.1', 0), WebKitHandler, cls.kb, cls.workdir)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.daemon = True
        cls.thread.start()
        time.sleep(0.5)
        
    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'server'):
            cls.server.shutdown()
            cls.server.server_close()
            cls.thread.join(timeout=2)
            
    def _get(self, path):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}")
        with urllib.request.urlopen(req) as response:
            return response.read(), response.getcode()
            
    def _post(self, path, data):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=json.dumps(data).encode('utf-8'), headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req) as response:
            return response.read(), response.getcode()

    def test_01_get_playbook(self):
        body, status = self._get('/api/playbook')
        self.assertEqual(status, 200)
        res = json.loads(body)
        self.assertEqual(len(res['phases']), 6)
        self.assertEqual(len(res['kill_chain']), 7)
        self.assertEqual(len(res['rules']), 10)
        self.assertEqual(res['progress']['overall']['total'], 51)

    def test_02_post_step(self):
        body, status = self._post('/api/playbook/step', {"id": "1.1", "status": "done"})
        self.assertEqual(status, 200)
        res = json.loads(body)
        self.assertTrue(res['ok'])
        self.assertEqual(res['progress']['overall']['done'], 1)
        
        # Verify persistence via GET
        body, status = self._get('/api/playbook')
        res = json.loads(body)
        self.assertEqual(res['state']['steps']['1.1']['status'], 'done')
        
    def test_03_post_step_invalid(self):
        try:
            self._post('/api/playbook/step', {"id": "9.9", "status": "done"})
            self.fail("Should have returned 400")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)

    def test_04_post_kc(self):
        body, status = self._post('/api/playbook/kc', {"key": "c2", "status": "confirmed"})
        self.assertEqual(status, 200)
        res = json.loads(body)
        kc_prog = next(k for k in res['progress']['kill_chain'] if k['key'] == 'c2')
        self.assertEqual(kc_prog['status'], 'confirmed')
        
    def test_05_post_kc_invalid(self):
        try:
            self._post('/api/playbook/kc', {"key": "yoq", "status": "confirmed"})
            self.fail("Should have returned 400")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)
            
    def test_06_post_reset(self):
        body, status = self._post('/api/playbook/reset', {})
        self.assertEqual(status, 200)
        res = json.loads(body)
        self.assertEqual(res['progress']['overall']['done'], 0)
        
    def test_07_static_files(self):
        html_path = os.path.join(os.path.dirname(__file__), '..', 'bluekit', 'web', 'static', 'index.html')
        with open(html_path, 'r', encoding='utf-8') as f:
            html = f.read()
        self.assertIn("showTab('playbook')", html)
        self.assertIn('id="playbook"', html)
        
        js_path = os.path.join(os.path.dirname(__file__), '..', 'bluekit', 'web', 'static', 'app.js')
        with open(js_path, 'r', encoding='utf-8') as f:
            js = f.read()
        self.assertIn('loadPlaybook', js)
        self.assertIn('/api/playbook/step', js)
        
    def test_08_no_hardcoded_strings(self):
        html_path = os.path.join(os.path.dirname(__file__), '..', 'bluekit', 'web', 'static', 'index.html')
        js_path = os.path.join(os.path.dirname(__file__), '..', 'bluekit', 'web', 'static', 'app.js')
        
        with open(html_path, 'r', encoding='utf-8') as f:
            html = f.read()
        with open(js_path, 'r', encoding='utf-8') as f:
            js = f.read()
            
        forbidden = ['Razvedka', 'T1566.001', 'exfil-large-upload', 'Checker IP ni aniqlamaguncha']
        for s in forbidden:
            self.assertNotIn(s, html, f"Forbidden string '{s}' found in index.html")
            self.assertNotIn(s, js, f"Forbidden string '{s}' found in app.js")

if __name__ == '__main__':
    unittest.main()
