import unittest
import os
import subprocess
import json

class TestCollectLinuxDeep(unittest.TestCase):
    def setUp(self):
        self.script_path = os.path.join(os.path.dirname(__file__), "..", "responder", "collect_linux.sh")
        with open(self.script_path, "r", encoding="utf-8") as f:
            self.script_content = f.read()

    def test_static_requirements(self):
        self.assertIn("/proc/", self.script_content)
        self.assertIn("readlink", self.script_content)
        self.assertIn("suspicious_files", self.script_content)
        self.assertIn("collector_version", self.script_content)
        self.assertIn("1.1", self.script_content)
        self.assertIn("webshell_hint", self.script_content)
        self.assertIn("exe_deleted", self.script_content)
        
        self.assertNotIn(" rm -", self.script_content)
        self.assertNotIn("\nrm -", self.script_content)
        self.assertNotIn("kill ", self.script_content)
        self.assertNotIn("chmod ", self.script_content)
        self.assertNotIn("chattr", self.script_content)

    def test_no_while_read_pipe_in_deep(self):
        parts = self.script_content.split("# --- deep processes ---")
        self.assertGreater(len(parts), 1, "deep processes marker missing")
        deep_part_1 = parts[1].split("# --- deep processes end ---")[0]
        
        parts2 = self.script_content.split("# --- deep suspicious_files ---")
        self.assertGreater(len(parts2), 1, "deep suspicious_files marker missing")
        deep_part_2 = parts2[1].split("# --- deep suspicious_files end ---")[0]
        
        self.assertNotIn("| while", deep_part_1)
        self.assertNotIn("| while", deep_part_2)

    def test_bash_syntax(self):
        import shutil
        if shutil.which("bash"):
            result = subprocess.run(["bash", "-n", self.script_path], capture_output=True)
            self.assertEqual(result.returncode, 0, f"Bash syntax error: {result.stderr.decode()}")
        else:
            self.skipTest("bash not found")

    def test_runtime_linux(self):
        import shutil
        if not shutil.which("bash") or not os.path.exists("/proc"):
            self.skipTest("Not running on Linux with bash and /proc")
        
        result = subprocess.run(["bash", self.script_path, "-q"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            self.fail("Output is not valid JSON")
            
        self.assertIn("processes", data)
        self.assertIn("suspicious_files", data)
        self.assertIn("meta", data)
        self.assertIn("deep", data["meta"])
        
        # Check that processes is not empty
        self.assertTrue(len(data["processes"]) > 0, "processes list is empty")
        
        # Check schema keys for first process
        proc = data["processes"][0]
        expected_proc_keys = ["pid", "ppid", "name", "path", "cmdline", "user", "start_time", "signed", "sha256", "exe_deleted"]
        for k in expected_proc_keys:
            self.assertIn(k, proc)
            self.assertIsNotNone(proc[k], f"Process key {k} is None")
            
        if len(data["suspicious_files"]) > 0:
            file_obj = data["suspicious_files"][0]
            expected_file_keys = ["path", "ext", "size", "mtime", "ctime", "sha256", "signed", "exe_magic", "hidden", "head", "webshell_hint"]
            for k in expected_file_keys:
                self.assertIn(k, file_obj)
                self.assertIsNotNone(file_obj[k], f"File key {k} is None")

if __name__ == '__main__':
    unittest.main()
