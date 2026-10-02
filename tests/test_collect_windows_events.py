import unittest
import os
import tempfile
import csv
import json
import shutil
import platform
import subprocess
import re

class TestCollectWindowsEvents(unittest.TestCase):
    def setUp(self):
        self.script_path = os.path.join(os.path.dirname(__file__), "..", "responder", "collect_windows.ps1")
        self.powershell = shutil.which("powershell")
        self.is_windows = platform.system() == "Windows"

    def test_static(self):
        with open(self.script_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Should be in script
        self.assertIn("Get-WinEvent", content)
        self.assertIn("FilterHashtable", content)
        self.assertIn("ToXml()", content)
        self.assertIn("$EventsOut", content)
        self.assertIn("$EventsDays", content)
        self.assertIn("$EventsMax", content)
        self.assertIn("$NoEvents", content)
        self.assertIn("UTF8Encoding $False", content)
        self.assertIn("GetLogNames()", content)
        self.assertIn("IsInRole(", content)
        self.assertIn("Generic.List", content)

        # Header exact match (or ordered)
        # Check order of columns
        self.assertTrue(
            re.search(r'TimeCreated.*Computer.*Channel.*EventID.*user.*process.*parent_process.*CommandLine.*src.*dst.*message', content, re.IGNORECASE | re.DOTALL),
            "Header columns order not found"
        )
        
        # Security ID count <= 23
        m = re.search(r'LogName\s*=\s*["\']Security["\']\s*;\s*Id\s*=\s*@\(([^)]+)\)', content, re.IGNORECASE)
        self.assertIsNotNone(m, "Security log id list not found")
        ids = m.group(1).split(",")
        self.assertTrue(len(ids) <= 23, f"Security log ids count > 23: {len(ids)}")

        # Should NOT be in script
        self.assertNotIn("Clear-EventLog", content)
        self.assertNotIn("Remove-EventLog", content)
        self.assertNotIn("Limit-EventLog", content)
        self.assertNotIn("wevtutil", content)
        self.assertNotIn("Remove-Item", content)
        self.assertNotIn("Stop-Process", content)
        self.assertNotIn("Invoke-Expression", content)
        self.assertNotIn("Start-Process", content)
        self.assertNotIn("No events were found", content)
        
        # Check all `.Message` instances (excluding Exception.Message)
        message_matches = re.finditer(r'(?<!Exception)\.Message\b', content, re.IGNORECASE)
        bad_messages = [m.group(0) for m in message_matches]
        self.assertEqual(len(bad_messages), 0, f"Found restricted .Message usage: {bad_messages}")

    def test_ps_parse(self):
        if not self.is_windows or not self.powershell:
            self.skipTest("powershell or windows not available")
        ps_script = f"""
        $parserError = $null
        $tokens = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile('{self.script_path}', [ref]$tokens, [ref]$parserError)
        if ($parserError.Count -gt 0) {{
            $parserError | ForEach-Object {{ Write-Output $_.Message }}
            exit 1
        }}
        exit 0
        """
        proc = subprocess.run([self.powershell, "-Command", ps_script], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout)

    def test_csv_maps_to_parser(self):
        try:
            from bluekit.logs import parse, detect
            from bluekit.kb.query import KB
            from bluekit.paths import get_kb_path
        except ImportError:
            self.skipTest("bluekit package not found")
            
        with tempfile.TemporaryDirectory() as td:
            csv_path = os.path.join(td, "test_events.csv")
            rows = [
                ["TimeCreated","Computer","Channel","EventID","user","process","parent_process","CommandLine","src","dst","message"],
                ["2026-10-05T09:14:00.1230000+05:00", "PC1", "Security", "4624", "admin", "lsass.exe", "", "", "10.0.0.5", "", "Logon Type 3 | TargetDomainName=CORP"],
                ["2026-10-05T09:14:01.1230000+05:00", "PC1", "Security", "4624", "admin", "lsass.exe", "", "", "10.0.0.5", "", "Logon Type 10 | TargetDomainName=CORP"],
                ["2026-10-05T09:14:02.1230000+05:00", "PC1", "System", "7045", "SYSTEM", "", "", "C:\\Users\\Public\\updsvc.exe", "", "", "ServiceName=updsvc"],
                ["2026-10-05T09:14:03.1230000+05:00", "PC1", "Microsoft-Windows-Sysmon/Operational", "3", "SYSTEM", "C:\\Users\\Public\\a.exe", "", "", "10.0.0.5", "203.0.113.7", "DestinationPort=8443"]
            ]
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerows(rows)
            
            events = parse.load(csv_path)
            self.assertEqual(len(events), 4)
            for ev in events:
                self.assertIsNotNone(ev.get("ts"))
                self.assertIn("host", ev)
                self.assertIn("event_id", ev)
                self.assertIn("channel", ev)
            
            ev_d = events[3]
            self.assertEqual(ev_d.get("dest_ip"), "203.0.113.7")
            self.assertEqual(ev_d.get("process"), "C:\\Users\\Public\\a.exe")
            
            kb_path = get_kb_path()
            if not os.path.exists(kb_path):
                self.skipTest("KB not built")
            kb = KB(kb_path)
            
            hits_a = detect.detect_event(kb, events[0])
            self.assertEqual(len([h for h in hits_a if h['technique'] == 'T1021.001' and h['confidence'] == 'low']), 1)
            
            hits_b = detect.detect_event(kb, events[1])
            self.assertEqual(len([h for h in hits_b if h['technique'] == 'T1021.001' and h['confidence'] == 'medium']), 1)
            
            hits_c = detect.detect_event(kb, events[2])
            self.assertEqual(len([h for h in hits_c if h['technique'] == 'T1543.003' and h['confidence'] == 'high']), 1)

    def test_runtime(self):
        if not self.is_windows or os.environ.get("BK_RUNTIME_TESTS") != "1":
            self.skipTest("only Windows + BK_RUNTIME_TESTS=1")
            
        with tempfile.TemporaryDirectory() as td:
            snap_path = os.path.join(td, "snap.json")
            events_csv = os.path.join(td, "snap_events.csv")
            
            cmd = [self.powershell, "-ExecutionPolicy", "Bypass", "-File", self.script_path, "-NoDeep", "-Quiet", "-EventsDays", "30", "-Out", snap_path]
            subprocess.run(cmd, check=True)
            
            self.assertTrue(os.path.exists(events_csv), "Events CSV yaratilmadi")
            
            with open(events_csv, "rb") as f:
                head = f.read(3)
                self.assertNotEqual(head, b'\xef\xbb\xbf', "Fayl boshida BOM mavjud")
                
            with open(events_csv, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader)
                self.assertEqual(header, ["TimeCreated","Computer","Channel","EventID","user","process","parent_process","CommandLine","src","dst","message"])
                row_count = sum(1 for row in reader)
                f.seek(0)
                next(f)
                for row in csv.reader(f):
                    self.assertEqual(len(row), 11)
            
            with open(snap_path, "r", encoding="utf-8") as f:
                snap = json.load(f)
            
            total = snap.get("meta", {}).get("events", {}).get("total", 0)
            self.assertEqual(total, row_count, "total json and csv lines count mismatch")
            out_json = snap.get("meta", {}).get("events", {}).get("out", "")
            self.assertEqual(os.path.normpath(out_json), os.path.normpath(events_csv))
            
            if total == 0:
                self.skipTest("event yo'q yoki admin emas")
            
            from bluekit.logs import parse
            events = parse.load(events_csv)
            for ev in events:
                self.assertIsNotNone(ev.get("ts"))
                self.assertIsNotNone(ev.get("event_id"))
                
            # NoEvents qayta ishga tushirish
            snap2_path = os.path.join(td, "snap2.json")
            cmd2 = [self.powershell, "-ExecutionPolicy", "Bypass", "-File", self.script_path, "-NoDeep", "-Quiet", "-NoEvents", "-Out", snap2_path]
            subprocess.run(cmd2, check=True)
            
            with open(snap2_path, "r", encoding="utf-8") as f:
                snap2 = json.load(f)
            self.assertEqual(snap2.get("meta", {}).get("events", {}).get("skipped"), "NoEvents")
            self.assertFalse(os.path.exists(os.path.join(td, "snap2_events.csv")))

if __name__ == "__main__":
    unittest.main()
