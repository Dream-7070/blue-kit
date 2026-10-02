import unittest
import os
import shutil
import subprocess
import csv
import tempfile
import time
import re

def find_bash():
    if os.path.exists(r"C:\Program Files\Git\bin\bash.exe"):
        return r"C:\Program Files\Git\bin\bash.exe"
    bash = shutil.which("bash")
    if bash:
        try:
            res = subprocess.run([bash, "-c", "echo ok"], capture_output=True, text=True)
            if res.stdout.strip() == "ok":
                return bash
        except:
            pass
    return None

class TestCollectLinuxEvents(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bash = find_bash()
        cls.tmp_dir = tempfile.TemporaryDirectory()
        cls.csv_path = cls.tmp_dir.name.replace("\\", "/") + "/ev.csv"
        
        if cls.bash:
            dt = time.mktime(time.strptime("2026-09-30 12:00:00", "%Y-%m-%d %H:%M:%S"))
            fixture_dir = os.path.abspath("tests/fixtures/linux_events").replace("\\", "/")
            os.utime(os.path.join(fixture_dir, "var/log/auth.log"), (dt, dt))
            
            cmd = [cls.bash, "responder/collect_linux.sh", "-O", "-q", "-R", fixture_dir, "-E", cls.csv_path, "-Z", "+05:00", "-D", "100000"]
            cls.run_res = subprocess.run(cmd, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp_dir.cleanup()

    def test_static(self):
        with open("responder/collect_linux.sh", "r", encoding="utf-8") as f:
            content = f.read()
        
        self.assertIn("D:E:NM:R:OZ:", content)
        self.assertIn("TimeCreated,Computer,Channel,EventID,user,process,parent_process,CommandLine,src,dst,message", content)
        
        self.assertIn("journalctl", content)
        self.assertIn("short-iso-precise", content)
        self.assertIn("audit.log", content)
        self.assertIn(".bash_history", content)
        self.assertIn(".zsh_history", content)

        # CRLF bo'lsa Linux da bash `$'\r': command not found` bilan yiqiladi
        with open("responder/collect_linux.sh", "rb") as f:
            self.assertNotIn(b"\r", f.read())

        start_idx = content.find("collect_events() {")
        end_idx = content.find("\nif [ $events_only -eq 1 ]; then\n  collect_events")
        self.assertNotEqual(start_idx, -1)
        self.assertNotEqual(end_idx, -1)
        eb = content[start_idx:end_idx]
        self.assertGreater(len(eb), 5000)
        for forbidden in ["strftime", "mktime", "systime", "gensub", "asort", "grep -P", "rm -", "mktemp", "trap ",
                          "truncate", "> /var/log", "shred", "journalctl --vacuum", "journalctl --rotate", "\\x00", "\\x1F"]:
            self.assertNotIn(forbidden, eb)
        # mawk (Ubuntu 22.04 / Debian 12) regex intervallarini qo'llamaydi
        self.assertIsNone(re.search(r"\]\{[0-9]", eb))
        self.assertIn("[[:cntrl:]]", eb)
        self.assertIn("int(doe/1460)", eb)

        self.assertTrue(content.find("escape() {") < content.find("collect_events() {"))
        
        if self.bash:
            res = subprocess.run([self.bash, "-n", "responder/collect_linux.sh"])
            self.assertEqual(res.returncode, 0)

    def test_fixture_csv(self):
        if not self.bash:
            self.skipTest("No bash found")
        self.assertTrue(os.path.exists(self.csv_path), self.run_res.stderr)
            
        with open(self.csv_path, "r", encoding="utf-8") as f:
            content = f.read()
            
        self.assertNotIn("\ufeff", content)
        self.assertNotIn("command not found", self.run_res.stderr)
        
        with open(self.csv_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)
            self.assertEqual(header, ["TimeCreated","Computer","Channel","EventID","user","process","parent_process","CommandLine","src","dst","message"])
            rows = list(reader)
            
                
        # New fixture checks
        self.assertEqual(len(rows), 18)
        
        # All Computer == "web01" since we didn't pass -H
        for r in rows:
            self.assertEqual(r[1], "web01")
            
        # Bob history
        bob_rows = [r for r in rows if r[4] == "bob" and r[2] == "bash_history"]
        self.assertEqual(len(bob_rows), 4)
        bob_dict = {r[7]: r[0] for r in bob_rows}
        self.assertEqual(bob_dict.get("a"), "2000-02-29T00:00:00Z")
        self.assertEqual(bob_dict.get("b"), "2023-12-31T23:59:59Z")
        self.assertEqual(bob_dict.get("c"), "2024-02-29T00:00:00Z")
        self.assertEqual(bob_dict.get("d"), "2025-01-01T00:00:00Z")
        
        # Carol history
        carol_rows = [r for r in rows if r[4] == "carol" and r[2] == "zsh_history"]
        self.assertEqual(len(carol_rows), 3)
        carol_id = next(r for r in carol_rows if r[7] == "id")
        self.assertEqual(carol_id[0], "2026-09-30T05:00:01Z")
        self.assertEqual(carol_id[3], "history")
        
        carol_ls = next(r for r in carol_rows if r[7] == "ls -la /tmp")
        self.assertEqual(carol_ls[3], "history")
        
        carol_untimed = next(r for r in carol_rows if r[7] == "oddiy_qator")
        self.assertEqual(carol_untimed[3], "history_untimed")
        
        auth1 = rows[0]
        self.assertEqual(auth1[0], "2026-09-30T10:00:01+05:00")
        self.assertEqual(auth1[1], "web01")
        self.assertEqual(auth1[2], "auth")
        self.assertEqual(auth1[3], "sshd")
        self.assertEqual(auth1[4], "root")
        self.assertEqual(auth1[8], "10.0.0.9")
        
        auth2 = rows[1]
        self.assertEqual(auth2[0], "2026-09-03T09:05:00+05:00")
        self.assertEqual(auth2[4], "admin")
        self.assertEqual(auth2[8], "203.0.113.5")
        
        sudo = rows[2]
        self.assertEqual(sudo[4], "alice")
        self.assertEqual(sudo[7], "/usr/bin/id")
        self.assertEqual(sudo[3], "sudo")
        self.assertTrue(sudo[0].startswith("2026-09-30T10:00:05"))
        self.assertTrue(sudo[0].endswith("+05:00"))
        
        useradd = rows[3]
        self.assertEqual(useradd[0], "2026-09-30T10:01:00+05:00")
        self.assertEqual(useradd[4], "support")
        self.assertEqual(useradd[3], "useradd")
        self.assertEqual(useradd[2], "auth")
        
        execve500 = rows[4]
        self.assertTrue(execve500[0].startswith("2026-09-30T05:01:00"))
        self.assertTrue(execve500[0].endswith("Z"))
        self.assertEqual(execve500[7], "id -u")
        self.assertEqual(execve500[5], "/usr/bin/id")
        self.assertEqual(execve500[4], "1000")
        
        execve501 = rows[5]
        self.assertEqual(execve501[7], "sh -c echo hi")
        self.assertEqual(execve501[4], "33")
        
        userlogin = rows[6]
        self.assertEqual(userlogin[4], "root")
        self.assertEqual(userlogin[8], "10.0.0.9")
        self.assertEqual(userlogin[3], "USER_LOGIN")
        
        self.assertEqual(rows[7][0], "2026-09-30T05:00:01Z")
        self.assertEqual(rows[7][3], "history")
        self.assertEqual(rows[8][3], "history")
        
        self.assertEqual(rows[9][3], "history_untimed")
        self.assertEqual(rows[9][4], "alice")
        self.assertEqual(rows[10][3], "history_untimed")
        self.assertEqual(rows[10][4], "alice")
        
        for r in rows:
            self.assertNotEqual(r[10].strip(), "bu qator vaqtsiz va tashlanishi kerak")

    def test_csv_to_bk(self):
        if not self.bash:
            self.skipTest("No bash found")
        self.assertTrue(os.path.exists(self.csv_path), self.run_res.stderr)
        
        from bluekit.logs.parse import load
        from bluekit.logs.detect import detect_event
        from bluekit.kb.query import KB
        from bluekit.paths import get_kb_path
        
        try:
            kb_path = get_kb_path()
        except Exception:
            self.skipTest("Could not import get_kb_path")
        
        if not os.path.exists(kb_path):
            self.skipTest("KB not found")
            
        kb = KB(kb_path)
        
        events = list(load(self.csv_path))
        self.assertEqual(len(events), 18)
        for ev in events:
            self.assertIn("ts", ev)
        
        useradd_events = [e for e in events if e.get("event_id") == "useradd"]
        self.assertTrue(len(useradd_events) > 0)
        
        alerts = detect_event(kb, useradd_events[0])
        t1136_alerts = [a for a in alerts if a.get("technique") == "T1136.001" and a.get("confidence") == "high"]
        self.assertEqual(len(t1136_alerts), 1)


    def test_host_flag(self):
        if not self.bash:
            self.skipTest("No bash found")
        fixture_dir = os.path.abspath("tests/fixtures/linux_events").replace("\\", "/")
        csv_tmp = self.csv_path + "_myhost.csv"
        cmd = [self.bash, "responder/collect_linux.sh", "-O", "-q", "-R", fixture_dir, "-E", csv_tmp, "-Z", "+05:00", "-H", "myhost"]
        subprocess.run(cmd, capture_output=True, text=True)
        
        if not os.path.exists(csv_tmp):
            self.skipTest("No csv generated")
            
        with open(csv_tmp, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)
            rows = list(reader)
            
        for r in rows:
            if r[2] not in ("auth", "syslog", "cron"):
                self.assertEqual(r[1], "myhost")

    def test_events_only_requires_output(self):
        if not self.bash:
            self.skipTest("No bash found")
        cmd = [self.bash, "responder/collect_linux.sh", "-O"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 2)

    def test_noevents(self):
        if not self.bash:
            self.skipTest("No bash found")
        cmd = [self.bash, "responder/collect_linux.sh", "-O", "-N"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("Events skipped: NoEvents", res.stderr)

if __name__ == '__main__':
    unittest.main()
