import unittest
import os
import tempfile
import json
import subprocess
import sys
from datetime import datetime, timezone
from bluekit import tracker

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BK = os.path.join(ROOT, 'bk.py')

class TestTracker(unittest.TestCase):
    def setUp(self):
        self.fd, self.path = tempfile.mkstemp()
        os.close(self.fd)

    def tearDown(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

    def test_legacy_row_loads(self):
        legacy = [{"id": "186ac90e6f6a49e8b6f8177a3dea527b", "question": " dsdsd", "candidates": "wsed", "evidence": "sd", "status": "sd", "extra_key": 5}]
        with open(self.path, 'w', encoding='utf-8') as f:
            json.dump(legacy, f)
        
        rows = tracker.load(self.path)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertIsNone(row["max_attempts"])
        self.assertEqual(row["attempts"], [])
        self.assertEqual(row["id"], "186ac90e6f6a49e8b6f8177a3dea527b")
        self.assertEqual(row["extra_key"], 5)
        
        def do_add(rs):
            tracker.add_attempt(rs[0], "T1234", "pending", force=True)
            return rs
        
        tracker.mutate(self.path, do_add)
        
        rows2 = tracker.load(self.path)
        self.assertEqual(rows2[0]["extra_key"], 5)
        self.assertEqual(len(rows2[0]["attempts"]), 1)

    def test_missing_id_persisted(self):
        with open(self.path, 'w', encoding='utf-8') as f:
            json.dump([{"question": "Q1"}], f)
            
        rows1 = tracker.load(self.path)
        id1 = rows1[0]["id"]
        
        rows2 = tracker.load(self.path)
        id2 = rows2[0]["id"]
        
        self.assertEqual(id1, id2)

    def test_corrupt_file_not_overwritten(self):
        with open(self.path, 'w', encoding='utf-8') as f:
            f.write("{buzuq")
            
        with self.assertRaises(tracker.TrackerError):
            tracker.load(self.path)
            
        with self.assertRaises(tracker.TrackerError):
            tracker.mutate(self.path, lambda rs: rs)
            
        with open(self.path, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertEqual(content, "{buzuq")

    def test_add_row_empty_candidates(self):
        rows = []
        tracker.add_row(rows, {"question": "Q1"})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["candidates"], "")
        
        with self.assertRaises(tracker.TrackerError):
            tracker.add_row(rows, {"question": "   "})

    def test_parse_max_attempts(self):
        self.assertEqual(tracker.parse_max_attempts("3"), 3)
        self.assertEqual(tracker.parse_max_attempts(" 2 "), 2)
        self.assertIsNone(tracker.parse_max_attempts(""))
        self.assertIsNone(tracker.parse_max_attempts(None))
        
        for bad in [0, -1, "abc", 2.5, True]:
            with self.assertRaises(tracker.TrackerError):
                tracker.parse_max_attempts(bad)

    def test_update_row_ignores_protected(self):
        rows = []
        r = tracker.add_row(rows, {"question": "Q1"})
        orig_id = r["id"]
        
        tracker.update_row(rows, orig_id, {"candidates": "T1", "id": "x", "attempts": [], "foo": 1})
        self.assertEqual(r["candidates"], "T1")
        self.assertEqual(r["id"], orig_id)
        self.assertNotIn("foo", r)
        
        with self.assertRaises(tracker.RowNotFound):
            tracker.update_row(rows, "yoqid", {"question": "Q2"})

    def test_attempt_limit_flow(self):
        row = {"max_attempts": 3, "attempts": []}
        
        c1 = tracker.add_attempt(row, "T1001")
        self.assertEqual(row["attempts"][0]["answer"], "T1001")
        
        c2 = tracker.add_attempt(row, "T1002")
        self.assertEqual(len(row["attempts"]), 2)
        
        with self.assertRaises(tracker.AttemptNeedsConfirm) as ctx:
            tracker.add_attempt(row, "T1003")
        self.assertTrue(ctx.exception.check["last_attempt"])
        self.assertTrue(any("2/3" in w for w in ctx.exception.check["warnings"]))
        self.assertEqual(len(row["attempts"]), 2)
        
        tracker.add_attempt(row, "T1003", force=True)
        self.assertEqual(len(row["attempts"]), 3)
        
        with self.assertRaises(tracker.AttemptNeedsConfirm) as ctx2:
            tracker.add_attempt(row, "T1004")
        self.assertTrue(ctx2.exception.check["over_limit"])
        self.assertEqual(ctx2.exception.check["remaining"], 0)
        self.assertTrue(any("3/3" in w for w in ctx2.exception.check["warnings"]))

    def test_duplicate_case_insensitive(self):
        row = {"attempts": []}
        tracker.add_attempt(row, "T1566.001", result="rejected", force=True)
        
        with self.assertRaises(tracker.AttemptNeedsConfirm) as ctx:
            tracker.add_attempt(row, " t1566.001 ")
        self.assertTrue(ctx.exception.check["duplicate"])
        self.assertEqual(ctx.exception.check["duplicate_of"]["answer"], "T1566.001")
        self.assertTrue(any("rejected" in w for w in ctx.exception.check["warnings"]))

    def test_already_accepted(self):
        row = {"attempts": []}
        tracker.add_attempt(row, "T1001", result="accepted", force=True)
        
        with self.assertRaises(tracker.AttemptNeedsConfirm) as ctx:
            tracker.add_attempt(row, "T1002")
        self.assertTrue(ctx.exception.check["already_accepted"])

    def test_no_limit(self):
        row = {"max_attempts": None, "attempts": []}
        for i in range(5):
            c = tracker.add_attempt(row, f"T100{i}")
            self.assertIsNone(c["remaining"])
        self.assertEqual(len(row["attempts"]), 5)

    def test_set_and_delete_attempt(self):
        row = {"attempts": []}
        tracker.add_attempt(row, "T1", "pending", force=True)
        
        tracker.set_attempt_result(row, 0, "accepted")
        self.assertEqual(row["attempts"][0]["result"], "accepted")
        
        with self.assertRaises(tracker.TrackerError):
            tracker.set_attempt_result(row, 0, "bad")
            
        with self.assertRaises(tracker.RowNotFound):
            tracker.set_attempt_result(row, 5, "accepted")
        with self.assertRaises(tracker.RowNotFound):
            tracker.set_attempt_result(row, -1, "accepted")
            
        tracker.delete_attempt(row, 0)
        self.assertEqual(len(row["attempts"]), 0)

    def test_public_row(self):
        row = {"max_attempts": 1, "attempts": [{"answer": "T1", "result": "rejected"}]}
        pub = tracker.public_row(row)
        self.assertEqual(pub["used"], 1)
        self.assertEqual(pub["remaining"], 0)
        self.assertFalse(pub["solved"])
        self.assertTrue(pub["exhausted"])
        
        # save shouldn't have these
        rows = [row]
        tracker.save(self.path, rows)
        with open(self.path, 'r', encoding='utf-8') as f:
            d = json.load(f)
            self.assertNotIn("used", d[0])

    def test_timestamp_utc(self):
        row = {"attempts": []}
        now = datetime(2026, 10, 5, 8, 51, 2, tzinfo=timezone.utc)
        tracker.add_attempt(row, "T1", now=now, force=True)
        self.assertEqual(row["attempts"][0]["at"], "2026-10-05T08:51:02Z")

    def test_atomic_save_unicode(self):
        q = "Savol: o'g'irlangan ma'lumot — qayerga?"
        rows = [{"question": q}]
        tracker.save(self.path, rows)
        
        with open(self.path, 'rb') as f:
            b = f.read()
            self.assertIn("o'g'irlangan".encode('utf-8'), b)
            
        loaded = tracker.load(self.path)
        self.assertEqual(loaded[0]["question"], q)

    def test_none_and_attack_id_upper(self):
        rows = []
        r = tracker.add_row(rows, {"question": "Q", "candidates": None, "evidence": None})
        self.assertEqual((r["candidates"], r["evidence"]), ("", ""))
        tracker.update_row(rows, r["id"], {"candidates": None})
        self.assertEqual(r["candidates"], "")
        tracker.add_attempt(r, " t1566.001 ")
        tracker.add_attempt(r, "198.51.100.45")
        self.assertEqual([a["answer"] for a in r["attempts"]], ["T1566.001", "198.51.100.45"])
        norm = tracker.normalize_row({"question": "Q", "attempts": [{"answer": "T1", "at": 12345}, {"answer": "  "}]})
        self.assertEqual(norm["attempts"], [{"answer": "T1", "result": "pending", "at": ""}])

    def test_concurrent_load_and_mutate(self):
        # Windows: qulfsiz o'qish os.replace ni PermissionError bilan yiqitardi
        import threading
        errors = []
        def reader():
            for _ in range(200):
                try: tracker.load(self.path)
                except Exception as e: errors.append(e)
        def writer():
            for i in range(200):
                try: tracker.mutate(self.path, lambda rs: tracker.add_row(rs, {"question": "Q%d" % i}))
                except Exception as e: errors.append(e)
        ts = [threading.Thread(target=reader), threading.Thread(target=writer)]
        for t in ts: t.start()
        for t in ts: t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(tracker.load(self.path)), 200)

    def test_cli_submit_with_question(self):
        l_fd, l_path = tempfile.mkstemp()
        os.close(l_fd)
        
        try:
            cmd = [sys.executable, BK, 'answers', 'submit', 'T1566.001', 'rejected', '--question', 'Q1', '--max', '2', '--tracker', self.path, '--ledger', l_path]
            res = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
            self.assertEqual(res.returncode, 0)
            
            rows = tracker.load(self.path)
            self.assertEqual(len(rows), 1)
            self.assertEqual(len(rows[0]["attempts"]), 1)
            
            # second time -> duplicate -> exit 2
            res2 = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
            self.assertEqual(res2.returncode, 2)
            
            rows2 = tracker.load(self.path)
            self.assertEqual(len(rows2[0]["attempts"]), 1)
            
            # with --force -> exit 0
            cmd.append('--force')
            res3 = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
            self.assertEqual(res3.returncode, 0)
            
            rows3 = tracker.load(self.path)
            self.assertEqual(len(rows3[0]["attempts"]), 2)
            
            # old call without --question
            cmd4 = [sys.executable, BK, 'answers', 'submit', 'T1566.001', 'pending', '--ledger', l_path]
            # remove tracker file
            os.unlink(self.path)
            res4 = subprocess.run(cmd4, capture_output=True, text=True, cwd=ROOT)
            self.assertEqual(res4.returncode, 0)
            self.assertFalse(os.path.exists(self.path))
            
        finally:
            if os.path.exists(l_path):
                os.unlink(l_path)
