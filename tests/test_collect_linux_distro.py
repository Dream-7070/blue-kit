import unittest
import os
import re
import subprocess
import json

class TestCollectLinuxDistro(unittest.TestCase):
    def setUp(self):
        self.script_path = os.path.join(os.path.dirname(__file__), "..", "responder", "collect_linux.sh")
        with open(self.script_path, "rb") as f:
            self.script_bytes = f.read()
        self.script_text = self.script_bytes.decode("utf-8")

    def test_bash_guard_first(self):
        lines = self.script_text.split("\n")[:20]
        guard_found = False
        getopts_found = False
        for i, line in enumerate(lines):
            if "BASH_VERSION" in line and "exit 2" in self.script_text.split("\n")[i+2]:
                guard_found = True
                guard_idx = i
            if "getopts" in line:
                getopts_found = True
                getopts_idx = i
                break
        
        self.assertTrue(guard_found)
        self.assertTrue(getopts_found)
        self.assertLess(guard_idx, getopts_idx)
        
        pre_guard = "\n".join(self.script_text.split("\n")[:guard_idx])
        self.assertNotIn("[[", pre_guard)
        self.assertNotIn("$'", pre_guard)
        self.assertNotIn("local ", pre_guard)
        self.assertNotIn("<(", pre_guard)

    def test_ca_paths(self):
        self.assertIn("/etc/ssl/certs/ca-certificates.crt", self.script_text)
        self.assertIn("/etc/pki/tls/certs/ca-bundle.crt", self.script_text)
        self.assertIn("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", self.script_text)
        self.assertIn("/etc/ssl/ca-bundle.pem", self.script_text)
        
        self.assertIn("/usr/local/share/ca-certificates/", self.script_text)
        self.assertIn("/etc/pki/ca-trust/source/anchors/", self.script_text)
        self.assertIn("/etc/pki/trust/anchors/", self.script_text)
        
        self.assertIn("bundle_path", self.script_text)
        self.assertIn("ca_certificates_crt_count", self.script_text)
        self.assertIn("local_share", self.script_text)

    def test_pkg_proxy(self):
        self.assertIn("dnf.conf", self.script_text)
        self.assertIn("yum.conf", self.script_text)
        self.assertIn("zypp.conf", self.script_text)
        self.assertIn("pkg", self.script_text)
        self.assertIn("apt", self.script_text)

    def test_find_fallback(self):
        self.assertIn("find_mode", self.script_text)
        self.assertIn("stat -c", self.script_text)
        self.assertIn("-maxdepth 0 -printf", self.script_text)
        self.assertIn("-printf '%p\\t%s\\t%T@\\t%C@\\t%m\\n'", self.script_text)

    def test_meta_distro(self):
        self.assertIn("os-release", self.script_text)
        self.assertIn("\"distro\"", self.script_text)
        self.assertIn("\"capabilities\"", self.script_text)
        self.assertIn("\"collector_rev\"", self.script_text)
        self.assertNotIn(". /etc/os-release", self.script_text)
        self.assertNotIn("source /etc/os-release", self.script_text)

    def test_no_cr_and_no_awk_intervals(self):
        self.assertNotIn(b"\r", self.script_bytes)
        
        awk_programs = re.findall(r"awk '(.*?)'", self.script_text, re.DOTALL)
        awk_programs += re.findall(r"awk_.*=\'(.*?)\'", self.script_text, re.DOTALL)
        
        for prog in awk_programs:
            self.assertFalse(re.search(r"[^\\]\{\d+(,\d*)?\}", prog), f"Found interval in awk program")

    def test_bash_syntax(self):
        try:
            subprocess.check_call(["bash", "-n", self.script_path])
        except FileNotFoundError:
            self.skipTest("bash not found")
        except subprocess.CalledProcessError:
            self.fail("bash -n failed")

    def test_runtime_sh_refused(self):
        try:
            bash_ver = subprocess.check_output(["sh", "-c", "echo $BASH_VERSION"]).decode("utf-8").strip()
            if bash_ver:
                self.skipTest("sh is bash")
        except FileNotFoundError:
            self.skipTest("sh not found")
            
        try:
            p = subprocess.run(["sh", self.script_path, "-q"], capture_output=True, text=True)
            self.assertEqual(p.returncode, 2)
            self.assertIn("bash talab qiladi", p.stderr)
        except FileNotFoundError:
            self.skipTest("sh not found")

    def test_runtime_find_shim(self):
        if not os.environ.get("BK_RUNTIME_TESTS") == "1" or not os.path.exists("/proc"):
            self.skipTest("Not enabled or not on Linux")
        
        # We simulate the test on actual environment, skipping here since it's hard to replicate fully locally on Windows if testing from there.
        # But wait, we can just write the test logic exactly as described.
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            shim_path = os.path.join(tmp, "find")
            with open(shim_path, "w", newline='\n') as f:
                f.write("#!/bin/bash\n")
                f.write("for arg in \"$@\"; do if [ \"$arg\" = \"-printf\" ]; then exit 1; fi; done\n")
                f.write("exec /usr/bin/find \"$@\"\n")
            os.chmod(shim_path, 0o755)
            
            env = os.environ.copy()
            env["PATH"] = f"{tmp}:{env.get('PATH', '')}"
            out_json = os.path.join(tmp, "s.json")
            
            subprocess.run(["bash", self.script_path, "-q", "-N", "-o", out_json], env=env)
            
            self.assertTrue(os.path.exists(out_json))
            with open(out_json, "r") as f:
                data = json.load(f)
            
            self.assertEqual(data["meta"]["deep"]["find_mode"], "stat")
            self.assertFalse(data["meta"]["capabilities"]["find_printf"])

if __name__ == '__main__':
    unittest.main()
