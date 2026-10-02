import unittest
import json
import os
import sys

# ensure we can import bluekit
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from bluekit.report.model import build
from bluekit.report.render import render_html, render_markdown, load_strings

class TestReport(unittest.TestCase):
    def test_model_build_and_render(self):
        logs = {
            "timeline": [
                {"ts": "2024-01-01", "host": "srv1", "user": "admin", "techniques": [{"technique": "T1078"}], "command": "cmd.exe"}
            ],
            "iocs": [
                {"type": "ip", "value": "1.2.3.4", "count": 5}
            ],
            "coverage": {},
            "techniques": [
                {"id": "T1078", "name": "Valid Accounts", "tactic": "initial-access", "count": 1, "status": "active"}
            ]
        }
        resp = {
            "findings": [
                {"item": "malware.exe", "techniques": [{"id": "T1059", "name": "CLI"}], "status": "bajarildi", "protected": False}
            ],
            "extra": {}
        }
        answers = {
            "title": "Test Title",
            "exec_summary": "" # force auto
        }
        
        model = build(logs, resp, answers)
        
        self.assertEqual(model['meta']['title'], "Test Title")
        self.assertTrue(model['exec_summary']) # Auto-generated
        
        # Check that no revoked techniques are here (they weren't anyway in this test)
        tech_ids = [t['id'] for t in model['techniques']]
        self.assertIn('T1078', tech_ids)
        self.assertIn('T1059', tech_ids)
        
        html_out = render_html(model, 'en')
        self.assertIn("Test Title", html_out)
        self.assertIn("T1078", html_out)
        self.assertIn("T1059", html_out)
        
        md_out = render_markdown(model, 'uz')
        self.assertIn("T1078", md_out)
        
    def test_strings_keys(self):
        s = load_strings()
        keys_uz = set(s['uz'].keys())
        keys_ru = set(s['ru'].keys())
        keys_en = set(s['en'].keys())
        self.assertEqual(keys_uz, keys_ru)
        self.assertEqual(keys_uz, keys_en)
        self.assertIn('title', keys_uz)

    def test_model_build_with_sample(self):
        sample_path = os.path.join(os.path.dirname(__file__), '..', 'logs.json')
        if not os.path.exists(sample_path):
            self.skipTest("logs.json not generated yet")
        with open(sample_path, 'r', encoding='utf-8') as f:
            logs = json.load(f)
            
        triage_path = os.path.join(os.path.dirname(__file__), '..', 'triage.json')
        if not os.path.exists(triage_path):
            self.skipTest("triage.json not generated yet")
        with open(triage_path, 'r', encoding='utf-8') as f:
            resp = json.load(f)
            
        model = build(logs, resp, {})
        
        techs = model['techniques']
        self.assertGreaterEqual(len(techs), 8)
        
        from bluekit.kb.query import KB
        kb = KB()
        for t in techs:
            v = kb.validate([t['id']])
            self.assertTrue(v and v[0]['found'])
            self.assertNotEqual(v[0]['status'], 'revoked')

if __name__ == '__main__':
    unittest.main()
