import unittest
import threading
import urllib.request
import urllib.error
import json
import os
import time
from unittest.mock import patch

from bluekit.paths import get_kb_path
from bluekit.kb.query import KB
from bluekit.web.server import WebKitServer, WebKitHandler
from bluekit.logs.sigma import SigmaEngine, drop_weak
from bluekit.logs import parse

class TestSigmaWeb(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        kb_path = get_kb_path()
        if not kb_path or not os.path.exists(kb_path):
            raise unittest.SkipTest("KB not built")
        cls.kb = KB(kb_path)
        cls.workdir = os.path.join(os.path.dirname(__file__), 'test_sigma_web_work')
        cls.server = WebKitServer(('127.0.0.1', 0), WebKitHandler, cls.kb, cls.workdir)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.daemon = True
        cls.thread.start()
        time.sleep(0.5)
        
        cls.fixture_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'samples', 'win_phishing.csv')
        
    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'server'):
            cls.server.shutdown()
            cls.server.server_close()
            cls.thread.join(timeout=2)
            
    def _get(self, path):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}")
        try:
            with urllib.request.urlopen(req) as response:
                return json.loads(response.read().decode('utf-8')), response.getcode()
        except urllib.error.HTTPError as e:
            return json.loads(e.read().decode('utf-8')), e.code

    def _post(self, path, data):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=json.dumps(data).encode('utf-8'), headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req) as response:
                return json.loads(response.read().decode('utf-8')), response.getcode()
        except urllib.error.HTTPError as e:
            err_body = e.read().decode('utf-8')
            print(f"Error {e.code} on {path}: {err_body}")
            try:
                return json.loads(err_body), e.code
            except:
                return {"error": err_body}, e.code

    def test_info(self):
        res, code = self._get('/api/sigma/info')
        self.assertEqual(code, 200)
        self.assertIn('ecs', res['presets'])
        self.assertIn('splunk', res['presets'])
        self.assertEqual(len(res['levels']), 5)
        self.assertGreater(res['rules']['loaded'], 1000)

    def test_scan_path_matches_cli(self):
        res, code = self._post('/api/sigma/scan', {"path": self.fixture_path})
        self.assertEqual(code, 200)
        self.assertEqual(res['stats']['events'], 33)
        self.assertEqual(len(res['techniques']), len(res['by_technique']))
        
        counts = [t['count'] for t in res['techniques']]
        self.assertEqual(counts, sorted(counts, reverse=True))
        
        events = parse.load(self.fixture_path)
        eng = SigmaEngine(kb_path=self.kb.path)
        expected_res = eng.match_events(events)
        drop_weak(expected_res)
        
        self.assertEqual(set(res['by_technique'].keys()), set(expected_res['by_technique'].keys()))

    def test_scan_content_upload(self):
        with open(self.fixture_path, 'r', encoding='utf-8') as f:
            content = f.read()
        res, code = self._post('/api/sigma/scan', {"content": content, "filename": "win_phishing.csv"})
        self.assertEqual(code, 200)
        
        events = parse.load(self.fixture_path)
        eng = SigmaEngine(kb_path=self.kb.path)
        expected_res = eng.match_events(events)
        drop_weak(expected_res)
        self.assertEqual(set(res['by_technique'].keys()), set(expected_res['by_technique'].keys()))

    def test_scan_multi_files(self):
        with open(self.fixture_path, 'r', encoding='utf-8') as f:
            content = f.read()
        res, code = self._post('/api/sigma/scan', {"files": [
            {"content": content, "filename": "win_phishing_1.csv"},
            {"content": content, "filename": "win_phishing_2.csv"}
        ]})
        self.assertEqual(code, 200)
        self.assertEqual(res['stats']['events'], 66)

    def test_weak_flag(self):
        res_false, _ = self._post('/api/sigma/scan', {"path": self.fixture_path, "weak": False})
        res_true, _ = self._post('/api/sigma/scan', {"path": self.fixture_path, "weak": True})
        
        self.assertGreaterEqual(res_true['hits_total'], res_false['hits_total'])
        self.assertGreater(len(res_false['hits']), 0)
        for h in res_false['hits']:
            for r in h['rules']:
                self.assertFalse(r.get('weak', False))

    def test_level_filter(self):
        res_all, code = self._post('/api/sigma/scan', {"path": self.fixture_path})
        self.assertEqual(code, 200)
        
        # Check if there is any critical, else use high
        has_crit = any('critical' in [r.get('level') for r in h['rules']] for h in res_all['hits'])
        level_to_test = "critical" if has_crit else "high"
        
        res, code = self._post('/api/sigma/scan', {"path": self.fixture_path, "level": level_to_test})
        self.assertEqual(code, 200)
        self.assertGreater(len(res['hits']), 0)
        
        allowed_levels = ['critical'] if level_to_test == 'critical' else ['high', 'critical']
        for h in res['hits']:
            for r in h['rules']:
                self.assertIn(r['level'], allowed_levels)

    @patch('bluekit.web.server.HITS_LIMIT', 3)
    def test_truncation(self):
        res, code = self._post('/api/sigma/scan', {"path": self.fixture_path, "weak": True})
        self.assertEqual(code, 200)
        self.assertEqual(len(res['hits']), 3)
        self.assertTrue(res['hits_truncated'])
        self.assertGreater(res['hits_total'], 3)
        
        events = parse.load(self.fixture_path)
        eng = SigmaEngine(kb_path=self.kb.path)
        expected_res = eng.match_events(events)
        self.assertEqual(set(res['by_technique'].keys()), set(expected_res['by_technique'].keys()))

    def test_validation_errors(self):
        res, code = self._post('/api/sigma/scan', {"path": self.fixture_path, "preset": "nope"})
        self.assertEqual(code, 400)
        self.assertIn('ecs', res['error'])
        
        res, code = self._post('/api/sigma/scan', {"path": self.fixture_path, "level": "nope"})
        self.assertEqual(code, 400)
        
        res, code = self._post('/api/sigma/scan', {"path": self.fixture_path, "products": "windows"})
        self.assertEqual(code, 400)
        
        res, code = self._post('/api/sigma/scan', {})
        self.assertEqual(code, 400)
        
        res, code = self._post('/api/sigma/scan', {"path": "does_not_exist.csv"})
        self.assertEqual(code, 400)

    @patch('bluekit.web.server.SigmaEngine', wraps=SigmaEngine)
    def test_kb_path_used(self, mock_engine):
        res, code = self._post('/api/sigma/scan', {"path": self.fixture_path})
        self.assertEqual(code, 200)
        mock_engine.assert_called()
        self.assertEqual(mock_engine.call_args[1].get('kb_path'), self.kb.path)

    def test_logs_analyze_unchanged(self):
        res, code = self._post('/api/logs/analyze', {"path": self.fixture_path})
        self.assertEqual(code, 200)
        self.assertIn('timeline', res)

    def test_answers_rank_accepts(self):
        from bluekit.answers import collect
        res, code = self._post('/api/sigma/scan', {"path": self.fixture_path})
        self.assertEqual(code, 200)
        
        tmp_path = os.path.join(self.workdir, "test_answers.json")
        with open(tmp_path, 'w', encoding='utf-8') as f:
            json.dump(res, f)
            
        ranked = collect([tmp_path])
        self.assertGreater(len(res['by_technique']), 0)
        for tid in res['by_technique']:
            self.assertIn(tid, ranked)
            self.assertIn('sigma', ranked[tid]['sources'])

    def test_js_no_onclick_literal(self):
        app_js_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'bluekit', 'web', 'static', 'app.js')
        with open(app_js_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        import re
        sigma_scan_match = re.search(r'async function sigmaScan\(\)\s*\{(.+?)\n\}', content, re.DOTALL)
        render_match = re.search(r'function renderSigmaResults\([^)]+\)\s*\{(.+?)\n\}', content, re.DOTALL)
        
        self.assertIsNotNone(sigma_scan_match)
        self.assertIsNotNone(render_match)
        
        combined = sigma_scan_match.group(1) + render_match.group(1)
        self.assertNotIn('onclick="', combined)
        self.assertNotIn('innerHTML = res.error', combined)

    def test_app_js_syntax(self):
        # app.js dagi bitta sintaksis xatosi BUTUN web UI ni o'ldiradi (30-sent: ko\\'rsatildi)
        import shutil, subprocess
        node = shutil.which('node')
        if not node:
            self.skipTest("node topilmadi")
        app_js_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'bluekit', 'web', 'static', 'app.js')
        r = subprocess.run([node, '--check', app_js_path], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

if __name__ == '__main__':
    unittest.main()
