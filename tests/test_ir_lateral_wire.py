import unittest
import os
import json
import subprocess

from bluekit.ir.correlator import correlate_incident, load_events_from_file
from bluekit.ir.report import build_incident_model, render_markdown_report, render_scoring_json
from bluekit.ir.models import AttackChain
from bluekit.kb.query import KB

class TestIRLateralWire(unittest.TestCase):
    KECH_KUZ_PATH = r"D:\Claude Projects\CTF\mashq\2026-09-30-operation-kech-kuz\events\collector_all_hosts.csv"

    @classmethod
    def setUpClass(cls):
        try:
            cls.kb = KB()
        except Exception:
            cls.kb = None
        
        if os.path.exists(cls.KECH_KUZ_PATH) and cls.kb:
            cls.events, cls.source_name = load_events_from_file(cls.KECH_KUZ_PATH)
            cls.chain = correlate_incident(cls.events, cls.kb)
            cls.model = build_incident_model(cls.chain, cls.source_name, len(cls.events))
        else:
            cls.events = None

    def test_1_correlator_kech_kuz(self):
        if not self.events:
            self.skipTest("Missing data or KB for Kech Kuz")
        self.assertEqual(self.chain.attack_path[:5], ['HR-PC01','IT-ADM-02','DC01','FILE-SRV-01','db-prod-02'])
        self.assertGreaterEqual(len(self.chain.lateral_edges), 4)
        
        d = self.chain.to_dict()
        self.assertIn("lateral_edges", d)
        self.assertIn("attack_path", d)

    def test_2_report_markdown(self):
        if not self.events:
            self.skipTest("Missing data or KB for Kech Kuz")
            
        checks = [
            ("uz", "### Hostdan hostga o'tish (Lateral Movement)", "### MITRE ATT&CK Xaritasi"),
            ("ru", "### Перемещение между хостами (Lateral Movement)", "### MITRE ATT&CK Mapping"),
            ("en", "### Lateral Movement (host to host)", "### MITRE ATT&CK Mapping")
        ]
        
        for lang, title, mitre_title in checks:
            rep = render_markdown_report(self.model, lang=lang)
            self.assertIn(title, rep)
            self.assertIn("```mermaid", rep)
            self.assertIn("| HR-PC01 | IT-ADM-02 |", rep)
            
            idx_lat = rep.find(title)
            idx_mitre = rep.find(mitre_title)
            self.assertTrue(0 <= idx_lat < idx_mitre)

    def test_3_report_json(self):
        if not self.events:
            self.skipTest("Missing data or KB for Kech Kuz")
            
        j_str = render_scoring_json(self.model)
        j = json.loads(j_str)
        self.assertEqual(j["attack_path"][0], "HR-PC01")
        self.assertEqual(len(j["lateral_movement"]), len(self.chain.lateral_edges))

    def test_4_empty_chain(self):
        empty_chain = AttackChain(chain_id='X')
        empty_model = build_incident_model(empty_chain, "test", 0)
        rep = render_markdown_report(empty_model, lang='uz')
        
        self.assertIn("Hostdan hostga o'tish aniqlanmadi.", rep)
        self.assertNotIn("```mermaid", rep)
        self.assertEqual(empty_chain.to_dict()["lateral_edges"], [])

    def test_5_cli_output(self):
        if not os.path.exists(self.KECH_KUZ_PATH):
            self.skipTest("Missing Kech Kuz file")
            
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        
        cwd = r"D:\Claude Projects\CTF\blue-kit-staging"
        cmd = ["python", "bk.py", "ir", "chain", self.KECH_KUZ_PATH, "--lang", "uz"]
        
        res = subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8', timeout=300)
        self.assertEqual(res.returncode, 0)
        
        self.assertIn("[LATERAL MOVEMENT] Hujum yo'li: HR-PC01 → IT-ADM-02", res.stdout)
        
        idx_lat = res.stdout.find("[LATERAL MOVEMENT]")
        idx_ioc = res.stdout.find("[EXTRACTED IOCs]")
        self.assertTrue(0 <= idx_lat < idx_ioc)

    def test_6_app_js_static(self):
        app_js_path = r"D:\Claude Projects\CTF\blue-kit-staging\bluekit\web\static\app.js"
        with open(app_js_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        start_idx = content.find("function renderIRResults")
        end_idx = content.find("function irRenderFileList", start_idx)
        if end_idx == -1: end_idx = len(content)
        
        fn_content = content[start_idx:end_idx]
        
        self.assertIn("chain.lateral_edges", fn_content)
        self.assertIn("chain.attack_path", fn_content)
        self.assertIn("Hostdan hostga o'tish", fn_content)
        
        escape_count = fn_content.count("escapeHtml(e.")
        self.assertGreaterEqual(escape_count, 4)
        
        onclick_count = fn_content.count("onclick")
        self.assertEqual(onclick_count, 3)

if __name__ == '__main__':
    unittest.main()
