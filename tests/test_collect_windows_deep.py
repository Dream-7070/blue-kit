import unittest
import subprocess
import json
import os
import shutil
import platform

class TestCollectWindowsDeep(unittest.TestCase):
    def setUp(self):
        self.script_path = os.path.join(os.path.dirname(__file__), "..", "responder", "collect_windows.ps1")
        self.powershell = shutil.which("powershell")
        # Haqiqiy kollektor yurgizish daqiqalar oladi (imzo + hash) — faqat BK_RUNTIME_TESTS=1 bo'lganda
        self.is_windows = platform.system() == "Windows" and os.environ.get("BK_RUNTIME_TESTS") == "1"

    def test_01_run_nodeep(self):
        if not self.powershell or not self.is_windows:
            self.skipTest("runtime test: Windows + BK_RUNTIME_TESTS=1 kerak")
        
        tmp_out = "test_snap_nodeep.json"
        try:
            cmd = [self.powershell, "-ExecutionPolicy", "Bypass", "-File", self.script_path, "-NoDeep", "-Quiet", "-Out", tmp_out]
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            with open(tmp_out, "r", encoding="utf-8") as f:
                data = json.load(f)
                
            self.assertEqual(data.get("meta", {}).get("collector_version"), "1.1")
            
            procs = data.get("processes", [])
            self.assertTrue(len(procs) > 0, "Processes list is empty")
            
            for p in procs:
                self.assertIn("pid", p)
                self.assertIn("ppid", p)
                self.assertIn("name", p)
                self.assertIn("path", p)
                self.assertIn("cmdline", p)
                self.assertIn("user", p)
                self.assertIn("start_time", p)
                self.assertIn("signed", p)
                self.assertIn("sha256", p)
                self.assertIn("exe_deleted", p)
                
                for k, v in p.items():
                    self.assertIsNotNone(v, f"Value for {k} is None")
                    
            self.assertEqual(data.get("meta", {}).get("deep", {}).get("processes"), len(procs))
            
        finally:
            if os.path.exists(tmp_out):
                os.remove(tmp_out)

    def test_02_static_analysis(self):
        with open(self.script_path, "r", encoding="utf-8") as f:
            content = f.read()
            
        # Should be in script
        self.assertIn("$DaysBack", content)
        self.assertIn("$DeepTimeoutSec", content)
        self.assertIn("$NoDeep", content)
        self.assertIn("Get-AuthenticodeSignature", content)
        self.assertIn("Get-FileHash", content)
        self.assertIn("suspicious_files", content)
        
        # Should NOT be in script
        self.assertNotIn("Remove-Item", content)
        self.assertNotIn("Set-MpPreference", content)
        self.assertNotIn("Stop-Process", content)
        self.assertNotIn("Invoke-Expression", content)
        self.assertNotIn("Start-Process", content)

    def test_03_run_deep(self):
        if not self.powershell or not self.is_windows:
            self.skipTest("runtime test: Windows + BK_RUNTIME_TESTS=1 kerak")
            
        tmp_out = "test_snap_deep.json"
        try:
            cmd = [self.powershell, "-ExecutionPolicy", "Bypass", "-File", self.script_path, "-Quiet", "-DeepTimeoutSec", "20", "-Out", tmp_out]
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            with open(tmp_out, "r", encoding="utf-8") as f:
                data = json.load(f)
                
            files = data.get("suspicious_files")
            self.assertIsInstance(files, list, "suspicious_files is not a list")
            
            for f_item in files:
                self.assertIn("path", f_item)
                self.assertIn("ext", f_item)
                self.assertIn("size", f_item)
                self.assertIn("mtime", f_item)
                self.assertIn("ctime", f_item)
                self.assertIn("sha256", f_item)
                self.assertIn("signed", f_item)
                self.assertIn("exe_magic", f_item)
                self.assertIn("hidden", f_item)
                self.assertIn("head", f_item)
                self.assertIn("webshell_hint", f_item)
                
        finally:
            if os.path.exists(tmp_out):
                os.remove(tmp_out)

if __name__ == "__main__":
    unittest.main()
