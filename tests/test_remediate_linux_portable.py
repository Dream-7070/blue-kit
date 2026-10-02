import unittest
import shutil
import os
import subprocess
from bluekit.resp.remediate import generate, generate_all

def F(cat, item, **kw):
    d = {'category': cat, 'item': item, 'score': 0}
    d.update(kw)
    return d

class TestRemediateLinuxPortable(unittest.TestCase):
    def test_1_users_linux(self):
        res = generate(F('users', 'a b'), 'linux')
        self.assertIn("usermod -L -e 1 'a b' 2>/dev/null || passwd -l 'a b'", res)
        self.assertIn("usermod -U -e '' 'a b' 2>/dev/null || passwd -u 'a b'", res)
        self.assertNotIn("Disable-LocalUser", res)
        pkill_lines = [l for l in res.split('\n') if 'pkill' in l]
        self.assertEqual(len(pkill_lines), 1)
        self.assertTrue(pkill_lines[0].startswith('#'))

    def test_2_users_windows(self):
        res = generate(F('users', "a'b"), 'windows')
        expected = "# FINDING: a'b []  score=0\n# BACKUP\nnet user 'a''b'\n# REMOVE\nDisable-LocalUser -Name 'a''b'\n# VERIFY\nnet user 'a''b'\n# ROLLBACK\nEnable-LocalUser -Name 'a''b'"
        self.assertEqual(res, expected)

    def test_3_services_linux_full(self):
        res = generate(F('services', 'bad svc'), 'linux', full=True)
        self.assertIn("systemctl stop 'bad svc'", res)
        self.assertIn("systemctl mask 'bad svc'", res)
        self.assertIn("rm -f '/etc/systemd/system/bad svc.service'", res)
        self.assertIn("rc-service 'bad svc' stop", res)
        self.assertIn("rc-update del 'bad svc'", res)
        self.assertIn("service 'bad svc' stop", res)
        self.assertIn("chkconfig 'bad svc' off", res)
        self.assertIn("rc-update add 'bad svc' default", res)
        self.assertEqual(res.count("if command -v systemctl"), 4)

    def test_4_services_linux_service_ext(self):
        res = generate(F('services', 'evil.service'), 'linux')
        self.assertIn("systemctl stop evil.service", res)
        self.assertIn("rc-service evil stop", res)
        self.assertNotIn("rc-service evil.service", res)

    def test_5_rat_linux_not_full(self):
        res = generate(F('remote_access_tools', 'anydesk'), 'linux', full=False)
        self.assertNotIn("systemctl mask", res)
        self.assertNotIn("rm -f", res)
        self.assertIn("rc-service anydesk stop", res)
        rollback = res.split("# ROLLBACK")[1]
        self.assertIn("systemctl enable anydesk", rollback)

    def test_6_injection(self):
        res = generate(F('services', 'x; touch /tmp/pwned'), 'linux')
        # find lines not starting with # FINDING:
        lines = [l for l in res.split('\n') if not l.startswith('# FINDING:')]
        stripped_res = '\n'.join(lines)
        stripped_res = stripped_res.replace("'x; touch /tmp/pwned'", "")
        stripped_res = stripped_res.replace("'/etc/init.d/x; touch /tmp/pwned'", "")
        # zaxira fayl nomi: faqat [A-Za-z0-9._-], ya'ni buyruq emas
        self.assertIn("/tmp/ir_backup/x_touch_tmp_pwned.backup", stripped_res)
        stripped_res = stripped_res.replace("x_touch_tmp_pwned", "")
        self.assertNotIn("touch", stripped_res)

    def test_7_syntax(self):
        if not shutil.which('bash'):
            self.skipTest("bash not found")
        findings = [
            F('users', 'u1'),
            F('services', 'bad svc'),
            F('remote_access_tools', 'anydesk'),
            F('services', 'evil.service')
        ]
        res = generate_all(findings, 'linux', True)
        import tempfile
        test_file = os.path.join(tempfile.mkdtemp(), 'test_remediate_syntax.sh')
        with open(test_file, 'w', newline='\n') as f:
            f.write(res)
        p = subprocess.run(['bash', '-n', test_file], capture_output=True)
        try:
            self.assertEqual(p.returncode, 0, p.stderr.decode())
        finally:
            if os.path.exists(test_file):
                os.remove(test_file)

    def test_9_backup_name_no_shell_metachars(self):
        res = generate(F('services', 'x;reboot $(id)`id`&'), 'linux')
        self.assertIn('/tmp/ir_backup/x_reboot_id_id.backup', res)
        cat_lines = [l for l in res.splitlines() if 'systemctl cat' in l]
        self.assertEqual(len(cat_lines), 1)
        outside_quotes = cat_lines[0].replace("'x;reboot $(id)`id`&'", '')
        for ch in ';$`&(':
            self.assertNotIn(ch, outside_quotes)

    def test_10_defender_exclusion_and_vuln_block(self):
        res = generate(F('defender', 'exclusion', raw='C:\\Users\\Public'), 'windows')
        self.assertIn("Remove-MpPreference -ExclusionPath 'C:\\Users\\Public'", res)
        self.assertIn("Add-MpPreference -ExclusionPath 'C:\\Users\\Public'", res)
        self.assertNotIn('REMOVE manually', res)
        v = generate(F('vulnerabilities', 'log4j', suggested_fix_command='apt-get install --only-upgrade liblog4j2-java'), 'linux')
        self.assertIn('# REMEDIATE / PATCH\napt-get install --only-upgrade liblog4j2-java', v)

    def test_8_regression_windows(self):
        res = generate(F('services', 'bad svc'), 'windows')
        self.assertIn('sc stop "bad svc"', res)
        self.assertNotIn('systemctl', res)

if __name__ == '__main__':
    unittest.main()
