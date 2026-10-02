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

class TestWeb(unittest.TestCase):
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
            
    def _get(self, path):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}")
        try:
            with urllib.request.urlopen(req) as response:
                return response.read(), response.getcode()
        except urllib.error.HTTPError as e:
            return e.read(), e.code
            
    def _post(self, path, data):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=json.dumps(data).encode('utf-8'), headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req) as response:
                return response.read(), response.getcode()
        except urllib.error.HTTPError as e:
            return e.read(), e.code
            
    def _delete(self, path):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", method='DELETE')
        try:
            with urllib.request.urlopen(req) as response:
                return response.read(), response.getcode()
        except urllib.error.HTTPError as e:
            return e.read(), e.code

    def _put(self, path, data):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=json.dumps(data).encode('utf-8'), headers={'Content-Type': 'application/json'}, method='PUT')
        try:
            with urllib.request.urlopen(req) as response:
                return response.read(), response.getcode()
        except urllib.error.HTTPError as e:
            return e.read(), e.code

    def test_index(self):
        body, status = self._get('/')
        self.assertEqual(status, 200)
        self.assertIn(b'blue-kit', body)
        
    def test_validate(self):
        body, status = self._get('/api/validate?ids=T1070.001')
        self.assertEqual(status, 200)
        res = json.loads(body)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['status'], 'revoked')
        self.assertIn('replacement', res[0])
        
    def test_search(self):
        body, status = self._get('/api/search?q=vssadmin%20delete%20shadows')
        self.assertEqual(status, 200)
        res = json.loads(body)
        self.assertTrue(len(res) > 0)
        self.assertEqual(res[0]['attack_id'], 'T1490')
        
    def test_resp_fix(self):
        current_data = {
            "services": [
                {"name": "test", "state": "running"}
            ]
        }
        body, status = self._post('/api/resp/fix', {
            'current': json.dumps(current_data),
            'os': 'windows'
        })
        self.assertEqual(status, 200)
        res = json.loads(body)
        self.assertIn('script', res)
        
    def test_tracker(self):
        body, status = self._post('/api/tracker', {
            'question': 'test_q',
            'candidates': 'T1000'
        })
        self.assertEqual(status, 200)
        row_id = json.loads(body)['id']
        
        body, status = self._get('/api/tracker')
        self.assertEqual(status, 200)
        tracker = json.loads(body)
        self.assertTrue(any(r['id'] == row_id for r in tracker))
        
        body, status = self._delete(f'/api/tracker/{row_id}')
        self.assertEqual(status, 200)
        
        body, status = self._get('/api/tracker')
        self.assertEqual(status, 200)
        tracker = json.loads(body)
        self.assertFalse(any(r['id'] == row_id for r in tracker))

    def test_tracker_attempts_api(self):
        body, status = self._post('/api/tracker', {"question": "Q2", "max_attempts": 2})
        self.assertEqual(status, 200)
        row_id = json.loads(body)["id"]
        
        body, status = self._post(f'/api/tracker/{row_id}/attempts', {"answer": "T1566.001", "result": "rejected"})
        self.assertEqual(status, 200)
        row = json.loads(body)["row"]
        self.assertEqual(row["used"], 1)
        
        body, status = self._post(f'/api/tracker/{row_id}/attempts', {"answer": "T1566.001"})
        self.assertEqual(status, 409)
        err = json.loads(body)
        self.assertTrue(err.get("needs_confirm"))
        self.assertTrue(err["check"]["duplicate"])
        
        body, status = self._post(f'/api/tracker/{row_id}/attempts', {"answer": "T1566.001", "force": True})
        self.assertEqual(status, 200)
        
        body, status = self._get('/api/tracker')
        rows = json.loads(body)
        r = next(x for x in rows if x["id"] == row_id)
        self.assertEqual(r["used"], 2)
        self.assertTrue(r["exhausted"])
        
        body, status = self._put(f'/api/tracker/{row_id}/attempts/0', {"result": "accepted"})
        self.assertEqual(status, 200)
        row = json.loads(body)["row"]
        self.assertTrue(row["solved"])
        
        body, status = self._delete(f'/api/tracker/{row_id}/attempts/1')
        self.assertEqual(status, 200)
        row = json.loads(body)["row"]
        self.assertEqual(row["used"], 1)
        
        body, status = self._post(f'/api/tracker/{row_id}/check', {"answer": "T1204.002"})
        self.assertEqual(status, 200)
        check = json.loads(body)
        self.assertEqual(check["used"], 1)
        
        self._delete(f'/api/tracker/{row_id}')

    def test_tracker_put_and_errors(self):
        body, status = self._post('/api/tracker', {"question": "Q3", "candidates": ""})
        self.assertEqual(status, 200)
        row_id = json.loads(body)["id"]
        
        body, status = self._put(f'/api/tracker/{row_id}', {"candidates": "T1204.002", "evidence": "e", "status": "s", "id": "hack"})
        self.assertEqual(status, 200)
        row = json.loads(body)["row"]
        self.assertEqual(row["id"], row_id)
        self.assertEqual(row["candidates"], "T1204.002")
        
        _, status = self._put('/api/tracker/yoqid', {"candidates": "C"})
        self.assertEqual(status, 404)
        
        _, status = self._post('/api/tracker', {"question": ""})
        self.assertEqual(status, 400)
        
        _, status = self._put(f'/api/tracker/{row_id}', {"max_attempts": "abc"})
        self.assertEqual(status, 400)
        
        _, status = self._post('/api/tracker/yoqid/attempts', {"answer": "A"})
        self.assertEqual(status, 404)
        
        self._delete(f'/api/tracker/{row_id}')

    def test_tracker_ledger_link(self):
        body, status = self._post('/api/tracker', {"question": "Q4"})
        self.assertEqual(status, 200)
        row_id = json.loads(body)["id"]
        
        body, status = self._post(f'/api/tracker/{row_id}/attempts', {"answer": "T1001", "result": "pending"})
        self.assertEqual(status, 200)
        
        ledger_path = os.path.join(self.workdir, "answers.json")
        with open(ledger_path, 'r', encoding='utf-8') as f:
            ledger = json.load(f)
        entries = ledger.get("entries", [])
        self.assertTrue(any(e["technique"] == "T1001" and e.get("note") == "Q4" for e in entries))
        
        count_before = len(entries)
        
        body, status = self._post(f'/api/tracker/{row_id}/attempts', {"answer": "198.51.100.45", "result": "pending"})
        self.assertEqual(status, 200)
        
        with open(ledger_path, 'r', encoding='utf-8') as f:
            ledger2 = json.load(f)
        entries2 = ledger2.get("entries", [])
        self.assertEqual(len(entries2), count_before)
        
        self._delete(f'/api/tracker/{row_id}')

if __name__ == '__main__':
    unittest.main()
