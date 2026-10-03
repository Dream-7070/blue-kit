import csv, os, tempfile, unittest
from unittest import mock
from bluekit.ir.models import AttackChain, AttackStage
from bluekit.ir.report import build_incident_model, compute_verdict
from bluekit.logs.parse import load_rows

def _model(stages):
    return build_incident_model(AttackChain(chain_id="t", stages=stages), "t.csv", 1)

class TestVerdict(unittest.TestCase):
    def test_no_stages_is_no_evidence(self):
        m = _model([])
        self.assertEqual((compute_verdict(m), m.severity, m.confidence_pct), ("NO_EVIDENCE", "NONE", 0))

    def test_suspected_vs_confirmed(self):
        s = AttackStage(stage_id="1", timestamp="2026-10-05T10:00:00", phase="Execution", technique_id="T1059", technique_name="x",
                        host="PC1", evidence="e", confidence="MEDIUM", status="SUSPECTED")
        self.assertEqual(compute_verdict(_model([s])), "SUSPECTED")
        s.confidence, s.status = "HIGH", "CONFIRMED"
        self.assertEqual(compute_verdict(_model([s])), "CONFIRMED_BREACH")

    def test_krbtgt_only_with_dcsync_or_golden(self):
        def recov(tid):
            s = AttackStage(stage_id="1", timestamp="2026-10-05T10:00:00", phase="Credential Access", technique_id=tid,
                            technique_name="x", host="DC1", evidence="e")
            return " ".join(_model([s]).recommendations["recovery"])
        self.assertIn("krbtgt", recov("T1003.006"))
        self.assertIn("krbtgt", recov("T1558.001"))
        self.assertNotIn("krbtgt", recov("T1003.001"))
        self.assertNotIn("krbtgt", recov("T1486"))

class TestCsvApostrophe(unittest.TestCase):
    def test_apostrophe_not_quotechar(self):
        body = "TimeCreated,Computer,message\n" + "".join(f"2026-10-05T10:0{i}:00,PC{i},\"rule 'RSS{i}': forward to external, mark read\"\n" for i in range(5))
        p = os.path.join(tempfile.mkdtemp(), "a.csv")
        with open(p, "w", encoding="utf-8") as f: f.write(body)
        real = csv.Sniffer.sniff
        def bad_sniff(self, sample, delimiters=None):  # scn08 da Sniffer aynan shunday xato qilgan
            d = real(self, sample, delimiters); d.quotechar = "'"; d.doublequote = False; return d
        with mock.patch.object(csv.Sniffer, "sniff", bad_sniff):
            rows = load_rows(p)
        self.assertEqual(len(rows), 5)
        self.assertFalse(any(None in r for r in rows))
        self.assertEqual(rows[0]["Computer"], "PC0")
