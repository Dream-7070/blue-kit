import unittest
import json
import os
import tempfile
from bluekit.web.server import WebKitServer, WebKitHandler
from bluekit.hunt.beacons import group_by_dst
from bluekit.kb.query import KB
from bluekit.paths import get_kb_path
import urllib.request
import threading
import time

class TestHunt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        kb_path = get_kb_path()
        if not os.path.exists(kb_path):
            raise unittest.SkipTest("KB not built")
        cls.kb = KB(kb_path)
        cls.workdir = tempfile.mkdtemp()
        cls.server = WebKitServer(('127.0.0.1', 0), WebKitHandler, cls.kb, cls.workdir)
        cls.port = cls.server.server_port
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'server'):
            cls.server.shutdown()
            cls.server.server_close()
        if hasattr(cls, 'server_thread'):
            cls.server_thread.join(timeout=2)
            
    def test_group_by_dst(self):
        results = [
            {'dst_ip': '1.1.1.1', 'score': 50, 'level': 'YUQORI', 'sessions': 10, 'avg_sent': 100, 'max_duration': 50, 'first_seen': '09-20 10:00', 'dst_port': '80', 'dst_host_count': 1, 'median_interval': 30, 'cv_ratio': 0.1, 'reasons': [], 'src_ip': '10.0.0.1', 'host': 'h1'},
            {'dst_ip': '1.1.1.1', 'score': 40, 'level': "O'RTA", 'sessions': 20, 'avg_sent': 200, 'max_duration': 60, 'first_seen': '09-20 10:01', 'dst_port': '80', 'dst_host_count': 1, 'median_interval': 30, 'cv_ratio': 0.1, 'reasons': [], 'src_ip': '10.0.0.2', 'host': 'h2'},
        ]
        
        grouped = group_by_dst(results, all_results=False)
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]['dst_ip'], '1.1.1.1')
        self.assertEqual(grouped[0]['sessions'], 30)
        self.assertEqual(grouped[0]['level'], 'YUQORI')
        self.assertEqual(grouped[0]['score'], 50)
        self.assertEqual(len(grouped[0]['hosts']), 2)
        
    def test_api_hunt_beacons(self):
        csv_content = """timestamp,src_ip,src_port,dst_ip,dst_port,bytes_sent,duration,session_id\n"""
        import datetime
        dt = datetime.datetime(2023, 1, 1, 12, 0, 0)
        for i in range(40):
            csv_content += f"{dt.strftime('%Y-%m-%d %H:%M:%S')},192.168.1.100,{10000+i},9.9.9.9,443,100,5,sess{i}\n"
            dt += datetime.timedelta(seconds=30)
            
        payload = {
            "files": [{"filename": "test.csv", "content": csv_content}],
            "min_sessions": 20,
            "max_hosts": 100
        }
        
        req = urllib.request.Request(f'http://127.0.0.1:{self.port}/api/hunt/beacons', data=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json'}, method='POST')
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
        
        self.assertIn('candidates', data)
        self.assertIn('summary', data)
        cands = data['candidates']
        self.assertTrue(len(cands) > 0)
        
        first = cands[0]
        self.assertEqual(first['dst_ip'], '9.9.9.9')
        self.assertIn(first['level'], ['YUQORI', "O'RTA"])
        self.assertTrue(len(first['hosts']) > 0)
        self.assertEqual(first['hosts'][0]['src_ip'], '192.168.1.100')
        
    def test_api_hunt_beacons_no_results(self):
        csv_content = """timestamp,src_ip,src_port,dst_ip,dst_port,bytes_sent,duration,session_id\n2023-01-01 12:00:00,192.168.1.100,12345,9.9.9.9,443,100,5,sess1\n"""
        payload = {
            "files": [{"filename": "test.csv", "content": csv_content}],
            "min_sessions": 1000,
            "max_hosts": 100
        }
        
        req = urllib.request.Request(f'http://127.0.0.1:{self.port}/api/hunt/beacons', data=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json'}, method='POST')
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            self.assertEqual(len(data['candidates']), 0)
