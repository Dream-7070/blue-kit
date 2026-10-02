import unittest
import socket
import threading
import time
import os
import tempfile
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
import hashlib

from bluekit.resp.sla import check, watch
from bluekit.resp.scoring import discover, to_sla_config, to_allowlist, parse_agent_config

class DummyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Welcome to the server")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

class TestSLA(unittest.TestCase):
    def test_01_tcp_open(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('127.0.0.1', 0))
        s.listen(1)
        port = s.getsockname()[1]
        
        config = {'services': [{'name': 'test', 'checks': [{'type': 'tcp', 'target': f'127.0.0.1:{port}'}]}]}
        res = check(config)
        self.assertTrue(res[0]['ok'])
        self.assertEqual(res[0]['state'], 'ok')
        s.close()

    def test_02_tcp_closed(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close() # Port is now closed
        
        config = {'services': [{'name': 'test', 'checks': [{'type': 'tcp', 'target': f'127.0.0.1:{port}'}]}]}
        res = check(config)
        self.assertFalse(res[0]['ok'])
        self.assertEqual(res[0]['state'], 'down')

    def test_03_http(self):
        server = HTTPServer(('127.0.0.1', 0), DummyHandler)
        port = server.server_port
        
        t = threading.Thread(target=server.serve_forever)
        t.daemon = True
        t.start()
        
        config = {'services': [{'name': 'test', 'checks': [
            {'type': 'http', 'url': f'http://127.0.0.1:{port}/', 'expect_status': 200, 'expect_contains': 'Welcome'},
            {'type': 'http', 'url': f'http://127.0.0.1:{port}/404', 'expect_status': 404}
        ]}]}
        res = check(config)
        self.assertTrue(res[0]['ok'])
        
        config2 = {'services': [{'name': 'test', 'checks': [
            {'type': 'http', 'url': f'http://127.0.0.1:{port}/404', 'expect_status': 200}
        ]}]}
        res2 = check(config2)
        self.assertFalse(res2[0]['ok'])
        
        server.shutdown()
        server.server_close()

    def test_04_three_states(self):
        config_ok = {'services': [{'name': 'test', 'checks': [
            {'type': 'tcp', 'target': '127.0.0.1:0'} # fake fail, wait we need custom check or rely on closed port
        ]}]}
        
        # We can fake it by writing a temp file for absent
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"data")
            fname = f.name
            
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('127.0.0.1', 0))
        s.listen(1)
        port = s.getsockname()[1]
        
        config_degraded = {'services': [{'name': 'test', 'checks': [
            {'type': 'tcp', 'target': f'127.0.0.1:{port}'},
            {'type': 'file_absent', 'path': fname, 'critical': False}
        ]}]}
        res_deg = check(config_degraded)
        self.assertEqual(res_deg[0]['state'], 'degraded')
        self.assertFalse(res_deg[0]['ok'])
        
        config_down = {'services': [{'name': 'test', 'checks': [
            {'type': 'tcp', 'target': '127.0.0.1:0'} # will fail
        ]}]}
        res_down = check(config_down)
        self.assertEqual(res_down[0]['state'], 'down')
        self.assertFalse(res_down[0]['ok'])
        
        s.close()
        os.unlink(fname)

    def test_05_file_hash_absent(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"hello")
            fname = f.name
        
        h = hashlib.sha256(b"hello").hexdigest()
        
        config = {'services': [{'name': 'test', 'checks': [
            {'type': 'file_hash', 'path': fname, 'expect_sha256': h}
        ]}]}
        res = check(config)
        self.assertTrue(res[0]['ok'])
        
        config2 = {'services': [{'name': 'test', 'checks': [
            {'type': 'file_absent', 'path': fname + "_not_exist"}
        ]}]}
        res2 = check(config2)
        self.assertTrue(res2[0]['ok'])
        os.unlink(fname)

    def test_06_no_exceptions(self):
        config = {'services': [{'name': 'test', 'checks': [
            {'type': 'tcp', 'target': '10.255.255.1:1', 'timeout': 0.1},
            {'type': 'http', 'url': 'http://invalid.url.that.does.not.exist', 'timeout': 0.1},
            {'type': 'file_hash', 'path': '/path/does/not/exist/ever'}
        ]}]}
        res = check(config)
        self.assertFalse(res[0]['ok'])
        self.assertEqual(res[0]['state'], 'down')

    def test_07_backward_compat(self):
        config = {'services': [{'name': 'my-svc', 'checks': []}]}
        res = check(config)
        self.assertIsInstance(res, list)
        self.assertEqual(res[0]['name'], 'my-svc')
        self.assertTrue('ok' in res[0])

    def test_08_watch(self):
        config = {'services': [{'name': 'test', 'checks': []}]}
        changes = []
        def on_change(name, old_state, new_state, r):
            changes.append((name, old_state, new_state))
            
        watch(config, interval=0.01, on_change=on_change, iterations=2)
        self.assertEqual(len(changes), 1) # initial state change

    def test_09_discovery_direct(self):
        snapshots = [
            {'meta': {'hostname': 'host1'}, 'listening_ports': [{'port': 80}], 'connections': [{'raddr': '203.0.113.7', 'lport': 80, 'proto': 'tcp'}]},
            {'meta': {'hostname': 'host2'}, 'listening_ports': [{'port': 443}], 'connections': [{'raddr': '203.0.113.7', 'lport': 443, 'proto': 'tcp'}]},
            {'meta': {'hostname': 'host3'}, 'listening_ports': [{'port': 8080}], 'connections': [{'raddr': '203.0.113.7', 'lport': 8080, 'proto': 'tcp'}]}
        ]
        res = discover(snapshots)
        cand = res['candidates'][0]
        self.assertEqual(cand['value'], '203.0.113.7')
        self.assertEqual(cand['confidence'], 'yuqori')
        self.assertEqual(cand['model'], "to'g'ridan-to'g'ri")
        self.assertEqual(len(cand['targets']), 3)

    def test_10_discovery_agent(self):
        snapshots = [
            {'meta': {'hostname': 'host1'}, 'listening_ports': [{'port': 10050, 'process': 'zabbix_agentd.exe'}], 'services': [{'name': 'Zabbix Agent', 'binary_path': 'zabbix_agentd.exe'}]}
        ]
        res = discover(snapshots)
        self.assertTrue(len(res['agents']) > 0)
        self.assertEqual(res['agents'][0]['product'], 'Zabbix Agent')

    def test_11_discovery_c2_not_checker(self):
        snapshots = [
            {'meta': {'hostname': 'host1'}, 'connections': [{'raddr': '8.8.8.8', 'lport': 50000, 'proto': 'tcp'}]}
        ]
        res = discover(snapshots)
        cand = res['candidates'][0]
        self.assertNotEqual(cand['confidence'], 'yuqori')

    def test_12_to_sla_config(self):
        discovery = {
            'candidates': [
                {'value': '203.0.113.7', 'confidence': 'yuqori', 'model': "to'g'ridan-to'g'ri", 'targets': [{'host': '10.0.0.1', 'port': 80, 'proto': 'tcp'}]}
            ]
        }
        config = to_sla_config(discovery)
        res = check(config)
        self.assertIsInstance(res, list)

    def test_13_parse_agent_config(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("UserParameter=mysql.ping,mysqladmin ping\n")
            fname = f.name
        
        res = parse_agent_config(fname)
        self.assertEqual(res[0]['key'], 'mysql.ping')
        os.unlink(fname)
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("command[check_users]=/usr/local/nagios/libexec/check_users -w 5 -c 10\n")
            fname = f.name
            
        res = parse_agent_config(fname)
        self.assertEqual(res[0]['key'], 'check_users')
        os.unlink(fname)

if __name__ == '__main__':
    unittest.main()
