import unittest
import os
import tempfile
import json
import threading
import urllib.request
import urllib.error
import subprocess
from datetime import timedelta
from bluekit.tz import tz_note, set_naive_tz, get_naive_tz, TZ_LABEL, TZ_LABEL_RU, TZ_LABEL_EN
from bluekit.web.server import WebKitServer, WebKitHandler
from bluekit.ir.report import _render_uz, _render_ru, _render_en
from bluekit.kb.query import KB

class TestTzLabels(unittest.TestCase):
    def tearDown(self):
        set_naive_tz(None)

    def test_tz_note(self):
        self.assertIn("+05:00", tz_note())
        self.assertIn("Toshkent (UTC+5)", tz_note())
        self.assertNotIn("+00:00", tz_note())

        set_naive_tz("utc")
        self.assertIn("+00:00", tz_note())

        set_naive_tz("-03:00")
        self.assertIn("-03:00", tz_note())

    def test_no_hardcoded_strings(self):
        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        bluekit_dir = os.path.join(project_dir, 'bluekit')
        
        count = 0
        for root, _, files in os.walk(bluekit_dir):
            for file in files:
                if file.endswith(('.py', '.js', '.html')):
                    path = os.path.join(root, file)
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        self.assertNotIn("+5 soat qo'shing", content, f"Hardcoded string found in {path}")

    def test_ir_report_no_utc(self):
        class DummyStage:
            def __init__(self):
                self.timestamp = "2026-10-05T14:14:00+05:00"
                self.timestamp_display = "2026-10-05 14:14:00"
                self.host = "WS01"
                self.phase = "Execution"
                self.evidence = "test"
                self.technique_id = "T1059"
                self.technique_name = "Command and Scripting Interpreter"
                self.explain_uz = "Izoh"
                self.iocs = {}
                self.status = "CONFIRMED"

        class DummyChain:
            def __init__(self):
                self.stages = [DummyStage()]
                self.attacker_ips = ["1.2.3.4"]
                self.exfiltration_ips = []
                self.compromised_users = []
                self.hosts_involved = ["WS01"]
                self.start_time = "2026-10-05T14:14:00+05:00"
                self.end_time = "2026-10-05T14:14:00+05:00"

        class DummyModel:
            def __init__(self):
                self.case_id = "CASE-1"
                self.title = "Test"
                self.severity = "HIGH"
                self.confidence_pct = 100
                self.status = "confirmed"
                self.source_name = "test"
                self.period_start = "2026-10-05T14:14:00+05:00"
                self.period_end = "2026-10-05T14:14:00+05:00"
                self.period_start_display = "2026-10-05 14:14:00"
                self.period_end_display = "2026-10-05 14:14:00"
                self.hosts = ["WS01"]
                self.accounts = []
                self.total_events_processed = 1
                self.chain = DummyChain()
                self.mitre_summary = []
                self.all_iocs = []
                self.missing_evidence = []
                self.recommendations = {"containment": [], "eradication": [], "recovery": []}
                
        model = DummyModel()
        
        rep_uz = _render_uz(model)
        self.assertNotIn(" UTC", rep_uz)
        self.assertNotIn("(UTC)", rep_uz)
        self.assertIn("vaqtlar logdagi kabi", rep_uz)
        self.assertIn("2026-10-05 14:14:00", rep_uz)
        self.assertNotIn("+05:00", rep_uz.split("Hujum Zanjiri")[1])

        rep_ru = _render_ru(model)
        self.assertNotIn(" UTC", rep_ru)
        self.assertNotIn("(UTC)", rep_ru)
        self.assertIn("время как в логах", rep_ru)
        self.assertIn("2026-10-05 14:14:00", rep_ru)
        self.assertNotIn("+05:00", rep_ru.split("Цепочка атаки")[1])

        rep_en = _render_en(model)
        self.assertNotIn(" UTC", rep_en)
        self.assertNotIn("(UTC)", rep_en)
        self.assertIn("times as in logs", rep_en)
        self.assertIn("2026-10-05 14:14:00", rep_en)
        self.assertNotIn("+05:00", rep_en.split("Attack Chain")[1])

    def test_cli_subprocess(self):
        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        bk_path = os.path.join(project_dir, 'bk.py')
        
        csv_content = "@timestamp,host.name,process.command_line\n2026-10-05 09:14:00,WS07,whoami"
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.csv') as f:
            f.write(csv_content)
            temp_path = f.name
            
        try:
            # Without src-tz
            res = subprocess.run(["python", bk_path, "logs", "analyze", temp_path], capture_output=True, text=True)
            self.assertIn("+05:00", res.stdout)
            
            # With src-tz utc
            res = subprocess.run(["python", bk_path, "--src-tz", "utc", "logs", "analyze", temp_path], capture_output=True, text=True)
            self.assertIn("+00:00", res.stdout)
        finally:
            os.remove(temp_path)

    def test_server_tz_handler_web(self):
        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        kb_path = os.path.join(project_dir, 'data', 'kb', 'kb.sqlite')
        try:
            kb = KB(kb_path)
            workdir = tempfile.mkdtemp()
            
            server = WebKitServer(('127.0.0.1', 0), WebKitHandler, kb, workdir)
            port = server.server_port
            t = threading.Thread(target=server.serve_forever)
            t.daemon = True
            t.start()
            
            base_url = f"http://127.0.0.1:{port}"
            csv_content = "@timestamp,host.name,process.command_line\n2026-10-05 09:14:00,WS07,whoami"
            
            def do_post(path, data):
                req = urllib.request.Request(base_url + path,
                                             data=json.dumps(data).encode(), 
                                             headers={'Content-Type': 'application/json'},
                                             method='POST')
                try:
                    with urllib.request.urlopen(req) as resp:
                        return json.loads(resp.read().decode())
                except urllib.error.HTTPError as e:
                    body = e.read().decode()
                    return {"_error_code": e.code, "error": json.loads(body).get("error", body)}

            # logs/analyze without src_tz
            resp1 = do_post("/api/logs/analyze", {"content": csv_content, "filename": "t.csv"})
            self.assertTrue(resp1["timeline"][0]["ts"].startswith("2026-10-05T09:14:00"))
            self.assertEqual(resp1["stats"]["src_tz"], "+05:00")
            
            # logs/analyze with src_tz utc
            resp2 = do_post("/api/logs/analyze", {"content": csv_content, "filename": "t.csv", "src_tz": "utc"})
            self.assertTrue(resp2["timeline"][0]["ts"].startswith("2026-10-05T14:14:00"))
            self.assertEqual(resp2["stats"]["src_tz"], "+00:00")
            
            self.assertEqual(get_naive_tz(), timedelta(hours=5))
            
            # Check 400s for invalid src_tz
            for ep in ["/api/logs/analyze", "/api/sigma/scan", "/api/ir/chain", "/api/hunt/beacons"]:
                r = do_post(ep, {"content": csv_content, "filename": "t.csv", "src_tz": "abc"})
                self.assertEqual(r.get("_error_code"), 400)
                self.assertIn("vaqt zonasi", r.get("error", "").lower())
                
            # ECS JSON for ir/chain
            ecs_json = '{"hits":{"hits":[{"_source":{"@timestamp":"2026-10-05 09:14:00", "agent":{"hostname":"WS07"}, "process":{"command_line":"whoami"}}}]}}'
            
            r_ir1 = do_post("/api/ir/chain", {"content": ecs_json, "filename": "e.json"})
            self.assertTrue(r_ir1["model"]["period_start"].startswith("2026-10-05T09:14:00"))
            
            r_ir2 = do_post("/api/ir/chain", {"content": ecs_json, "filename": "e.json", "src_tz": "utc"})
            self.assertTrue(r_ir2["model"]["period_start"].startswith("2026-10-05T14:14:00"))
            
            # hunt/beacons tz_note
            r_hunt = do_post("/api/hunt/beacons", {"content": csv_content, "filename": "t.csv", "src_tz": "utc"})
            self.assertIn("+00:00", r_hunt["summary"]["tz_note"])
            
        finally:
            if 'server' in locals():
                server.shutdown()
                server.server_close()

if __name__ == '__main__':
    unittest.main()
