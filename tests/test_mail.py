import unittest
import os
from bluekit.mail.parse import load_eml
from bluekit.mail.scan import scan_email

class TestMailScan(unittest.TestCase):
    def setUp(self):
        self.samples_dir = os.path.join(os.path.dirname(__file__), "..", "data", "samples", "mail")
        
    def test_phish_sample(self):
        phish_path = os.path.join(self.samples_dir, "phish_sample.eml")
        parsed = load_eml(phish_path)
        res = scan_email(parsed)
        
        self.assertEqual(res["verdict"], "PHISHING")
        self.assertGreaterEqual(len(res["findings"]), 5)
        
        techniques = set()
        for f in res["findings"]:
            techniques.update(f.get("techniques", []))
            
        self.assertIn("T1036.007", techniques)
        self.assertIn("T1566.002", techniques)
        
    def test_clean_sample(self):
        clean_path = os.path.join(self.samples_dir, "clean_sample.eml")
        parsed = load_eml(clean_path)
        res = scan_email(parsed)
        
        self.assertEqual(res["verdict"], "CLEAN")
        self.assertLessEqual(len(res["findings"]), 1)

    def test_threat_sample(self):
        threat_path = os.path.join(self.samples_dir, "threat_sample.eml")
        parsed = load_eml(threat_path)
        res = scan_email(parsed)
        
        self.assertEqual(res["verdict"], "THREAT")
        self.assertTrue("attribution" in res)
        attr = res["attribution"]
        self.assertEqual(attr.get("origin_ip"), "139.28.47.223")
        self.assertEqual(attr.get("anonymous_mailer"), "anonymousemail.eu")
        self.assertTrue(attr.get("tz_mismatch"))
        
        threat_finding = next((f for f in res["findings"] if f["check"] == "threat_language"), None)
        self.assertIsNotNone(threat_finding)

if __name__ == "__main__":
    unittest.main()
