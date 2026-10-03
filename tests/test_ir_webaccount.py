import unittest
from bluekit.ir.proctree import process_tree_stages
from bluekit.ir.correlator import extract_canonical as ext_canon

class TestWebAccount(unittest.TestCase):
    def test_a(self):
        ev = {
            "user": "iis_iusrs",
            "process": {"parent": {"name": "w3wp.exe"}, "name": "cmd.exe"},
            "host": "web01",
            "timestamp": "2026-10-01T10:00:00Z"
        }
        st, _ = process_tree_stages([ev], ext_canon)
        self.assertEqual(len([s for s, _ in st if s.technique_id == "T1505.003"]), 1)
        self.assertEqual(len([s for s, _ in st if s.technique_id == "T1059.003"]), 1)

    def test_b(self):
        ev = {
            "user": "IIS_IUSRS",
            "process": {"parent": {"name": "cmd.exe"}, "name": "nslookup.exe"},
            "host": "web01",
            "timestamp": "2026-10-01T10:00:00Z"
        }
        st, _ = process_tree_stages([ev], ext_canon)
        self.assertEqual(len([s for s, _ in st if s.technique_id == "T1505.003"]), 1)
        self.assertEqual(len([s for s, _ in st if s.technique_id == "T1059.003"]), 1)

    def test_c(self):
        ev = {
            "user": "www-data",
            "process": {"parent": {"name": "bash"}, "name": "id"},
            "host": "web01",
            "timestamp": "2026-10-01T10:00:00Z"
        }
        st, _ = process_tree_stages([ev], ext_canon)
        self.assertEqual(len([s for s, _ in st if s.technique_id == "T1505.003"]), 1)
        self.assertEqual(len([s for s, _ in st if s.technique_id == "T1059.004"]), 1)

    def test_d(self):
        ev = {
            "user": "www-data",
            "process": {"parent": {"name": "cron"}, "name": "sh"},
            "host": "web01",
            "timestamp": "2026-10-01T10:00:00Z"
        }
        st, _ = process_tree_stages([ev], ext_canon)
        self.assertEqual(len(st), 0)

    def test_e(self):
        ev = {
            "user": "jsmith",
            "process": {"parent": {"name": "cmd"}, "name": "whoami"},
            "host": "web01",
            "timestamp": "2026-10-01T10:00:00Z"
        }
        st, _ = process_tree_stages([ev], ext_canon)
        self.assertEqual(len(st), 0)

    def test_f(self):
        ev = {
            "user": "www-data",
            "process": {"parent": {"name": "bash"}, "name": "id"},
            "host": "web01",
            "timestamp": "2026-10-01T10:00:00Z"
        }
        events = [ev for _ in range(20)]
        st, _ = process_tree_stages(events, ext_canon)
        self.assertEqual(len([s for s, _ in st if s.technique_id == "T1505.003"]), 1)
        self.assertEqual(len([s for s, _ in st if s.technique_id == "T1059.004"]), 1)
