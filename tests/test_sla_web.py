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

class TestSlaWeb(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        kb_path = get_kb_path()
        if not os.path.exists(kb_path):
            raise unittest.SkipTest("KB not built")
        cls.kb = KB(kb_path)
        cls.workdir = os.path.join(os.path.dirname(__file__), 'test_web_work')
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
            
    def _post(self, path, data):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=json.dumps(data).encode('utf-8'), headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req) as response:
                return response.read(), response.getcode()
        except urllib.error.HTTPError as e:
            return e.read(), e.getcode()

    def test_sla_empty(self):
        body, status = self._post('/api/resp/sla', {})
        self.assertEqual(status, 400)
        res = json.loads(body)
        self.assertIn('error', res)
        self.assertIn('services.yaml', res['error'])

    def test_sla_empty_services(self):
        body, status = self._post('/api/resp/sla', {"services": []})
        self.assertEqual(status, 400)
        res = json.loads(body)
        self.assertIn('error', res)
        self.assertIn('services.yaml', res['error'])

    def test_sla_invalid_yaml(self):
        body, status = self._post('/api/resp/sla', {"services_yaml": "services: [\": \""})
        self.assertEqual(status, 400)
        res = json.loads(body)
        self.assertIn('error', res)

    def test_sla_down(self):
        yaml_content = """
services:
  - name: dead-service
    checks:
      - type: tcp
        target: 127.0.0.1:1
"""
        body, status = self._post('/api/resp/sla', {"services_yaml": yaml_content})
        self.assertEqual(status, 200)
        res = json.loads(body)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['state'], 'down')
        self.assertEqual(res[0]['ok'], False)
        self.assertEqual(res[0]['checks'][0]['type'], 'tcp')

    def test_sla_degraded(self):
        yaml_content = f"""
services:
  - name: degraded-service
    checks:
      - type: tcp
        target: 127.0.0.1:1
        critical: false
      - type: tcp
        target: 127.0.0.1:{self.port}
"""
        body, status = self._post('/api/resp/sla', {"services_yaml": yaml_content})
        self.assertEqual(status, 200)
        res = json.loads(body)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['state'], 'degraded')
        self.assertEqual(res[0]['ok'], False)

    def test_static_files(self):
        index_path = os.path.join(os.path.dirname(__file__), '..', 'bluekit', 'web', 'static', 'index.html')
        with open(index_path, 'r', encoding='utf-8') as f:
            index_content = f.read()
            self.assertIn('resp-sla-yaml', index_content)
            
        app_path = os.path.join(os.path.dirname(__file__), '..', 'bluekit', 'web', 'static', 'app.js')
        with open(app_path, 'r', encoding='utf-8') as f:
            app_content = f.read()
            self.assertIn('services_yaml', app_content)
            
            # Find respSla function content
            import re
            m = re.search(r'async function respSla\([^)]*\)\s*\{([^}]*)\}', app_content)
            if m:
                func_content = m.group(1)
                self.assertNotIn('renderSnapshotMissingWarning', func_content)

if __name__ == '__main__':
    unittest.main()
