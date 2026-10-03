import unittest
import os
import json
import shutil
import urllib.request
import urllib.error
import threading
import base64
import zipfile
import io
import re

from bluekit.web.server import WebKitServer, WebKitHandler
from bluekit.kb.query import KB
from bluekit.paths import get_kb_path

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), 'fixtures', 'cases')
EXPECTED_FILE = os.path.join(FIXTURES_DIR, 'cases_expected.json')

class TestCaseWeb(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.isfile(EXPECTED_FILE):
            raise unittest.SkipTest("tests/fixtures/cases/ yo'q (CTF topshiriq fayllari repo ga kiritilmaydi)")
        kb_path = get_kb_path()
        if not os.path.exists(kb_path):
            raise unittest.SkipTest("KB topilmadi")
        cls.kb = KB(kb_path)
        
        cls.workdir = os.path.join(os.path.dirname(__file__), 'test_case_web_work')
        os.makedirs(cls.workdir, exist_ok=True)
        
        with open(EXPECTED_FILE, 'r', encoding='utf-8') as f:
            cls.expected = json.load(f)
            
        cls.server = WebKitServer(('127.0.0.1', 0), WebKitHandler, cls.kb, cls.workdir)
        cls.port = cls.server.server_port
        
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.daemon = True
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'server'):
            cls.server.shutdown()
            cls.server.server_close()
        if os.path.exists(cls.workdir):
            shutil.rmtree(cls.workdir)

    def _post(self, path, data):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", method='POST', data=json.dumps(data).encode('utf-8'))
        req.add_header('Content-Type', 'application/json')
        try:
            with urllib.request.urlopen(req) as response:
                return response.getcode(), json.loads(response.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode('utf-8'))

    def _get(self, path):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}")
        try:
            with urllib.request.urlopen(req) as response:
                return response.getcode(), response.read().decode('utf-8')
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode('utf-8')

    def test_1_path_06(self):
        fpath = os.path.join(FIXTURES_DIR, '06_mailbox_mirror.json')
        code, data = self._post('/api/case/solve', {'path': fpath})
        self.assertEqual(code, 200)
        
        # Test 6: baseline formats
        self.assertIn("CHG-5200..5271", data['baseline']['ranges'])
        self.assertEqual(data['baseline']['nets'], ["192.0.2.0/24"])
        
        exp = self.expected["06_mailbox_mirror"]
        self.assertEqual(data['flag'], exp['flag'])
        self.assertEqual([c["id"] for c in data['chain']], exp['ids'])
        self.assertEqual(data['counts']['candidate'], 7)
        self.assertEqual(len(data['lookalike_groups']), 3)
        
        # Test json.dumps doesn't fail
        json.dumps(data)
        
        # 06 da chain[2]['utc'] == "2026-09-05T07:34:20.478Z"
        self.assertEqual(data['chain'][2]['utc'], "2026-09-05T07:34:20.478Z")
        
        # Test 5: links (06 da 3-bosqich, ya'ni index 2, uchun)
        stage_3 = data['chain'][2]
        links = stage_3.get('links', [])
        found_stage_2 = False
        for ln in links:
            if ln['stage'] == 2:
                found_stage_2 = True
                self.assertIn('se-442', ln['values'])
        self.assertTrue(found_stage_2)
        
        with open(fpath, 'r', encoding='utf-8') as f:
            t_data = json.load(f)
            if 'submission_template' in t_data:
                self.assertEqual(set(data['submission'].keys()), set(t_data['submission_template'].keys()))

    def test_2_content_15(self):
        fpath = os.path.join(FIXTURES_DIR, '15_ot_jumpstation.json')
        with open(fpath, 'r', encoding='utf-8') as f:
            content = f.read()
        code, data = self._post('/api/case/solve', {'filename': '15_ot.json', 'content': content})
        self.assertEqual(code, 200)
        
        exp = self.expected["15_ot_jumpstation"]
        self.assertEqual(data['flag'], exp['flag'])
        
        outcomes = {e['action']: e['outcome'] for e in data['chain']}
        self.assertEqual(outcomes.get('LogicDownloadRejected'), 'blocked')
        self.assertEqual(outcomes.get('AccountDisabled'), 'response')
        self.assertIn('success', outcomes.values())

    def test_3_zip_b64(self):
        folder = os.path.join(FIXTURES_DIR, '05_clockwork_vault')
        mem_zip = io.BytesIO()
        with zipfile.ZipFile(mem_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(folder):
                for file in files:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, folder)
                    zf.write(full_path, rel_path)
        
        b64 = base64.b64encode(mem_zip.getvalue()).decode('ascii')
        code, data = self._post('/api/case/solve', {'filename': 'test_05.zip', 'content_b64': b64})
        self.assertEqual(code, 200)
        
        exp = self.expected["05_clockwork_vault"]
        self.assertEqual(data['flag'], exp['flag'])
        self.assertEqual(len(data['chain']), 6)

    def test_4_folder_path(self):
        fpath = os.path.join(FIXTURES_DIR, '05_clockwork_vault')
        code, data = self._post('/api/case/solve', {'path': fpath})
        self.assertEqual(code, 200)
        exp = self.expected["05_clockwork_vault"]
        self.assertEqual(data['flag'], exp['flag'])

    def test_7_errors(self):
        code, data = self._post('/api/case/solve', {})
        self.assertEqual(code, 400)
        
        code, data = self._post('/api/case/solve', {'path': 'yoq.json'})
        self.assertEqual(code, 400)
        
        # Evil path
        staging_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        evil_path = os.path.join(staging_root, 'evil.json')
        if os.path.exists(evil_path): os.remove(evil_path)
        
        code, data = self._post('/api/case/solve', {'filename': '../../evil.json', 'content': '{}'})
        self.assertEqual(code, 400)
        self.assertFalse(os.path.exists(evil_path))
        
        # Check tracebacks
        code, data = self._post('/api/case/solve', {'filename': 'bad.json', 'content': 'not json'})
        self.assertEqual(code, 400)
        err_msg = str(data.get('error', ''))
        self.assertNotIn('Traceback', err_msg)

    def test_8_static(self):
        code, data = self._get('/case.js')
        self.assertEqual(code, 200)
        self.assertIn('caseSolve', data)
        self.assertIn('caseRender', data)
        self.assertIn('escapeHtml(', data)
        
        code, data = self._get('/')
        self.assertEqual(code, 200)
        self.assertIn("showTab('case')", data)
        self.assertIn('id="case"', data)
        self.assertIn('case.js', data)
        self.assertIn('id="btn-case-solve"', data)

    def test_9_static_security(self):
        code, data = self._get('/case.js')
        self.assertEqual(code, 200)
        
        m = re.search(r'onclick=\"[^\"]*\$\{', data)
        self.assertIsNone(m, "onclick ichida template literal topildi")
        
        self.assertNotIn('extra_', data)
        self.assertNotIn('TODO', data)
        self.assertNotIn('placeholder', data)
        self.assertNotIn('escapeHtml(linksStr)', data)
