import unittest
from bluekit.resp.remediate import generate, generate_all

def F(cat, item, **kw):
    return dict(category=cat, item=item, techniques=[], **kw)

class TestRemediateQuoting(unittest.TestCase):
    def test_hosts_escaped(self):
        w = generate(F('hosts_file', "1.2.3.4 evil.com"), 'windows')
        self.assertEqual(w.count("([regex]::Escape('1.2.3.4 evil.com'))"), 2)
        l = generate(F('hosts_file', "a b'c"), 'linux')
        self.assertIn("grep -vF -- 'a b'\"'\"'c' /etc/hosts", l)
        self.assertNotIn("sed -i", l)
    def test_task_backup_name_safe(self):
        s = generate(F('tasks', '\\Micro\\Evil "x"'), 'windows')
        self.assertEqual(s.count("C:\\ir\\backup\\Micro_Evil_x.xml"), 2)
        self.assertNotIn('Evil "x"', s.split('\n', 1)[1])
        h = generate(F('tasks', 'a\nrm -rf /'), 'linux').split('\n')
        self.assertEqual(h[0], '# FINDING: a rm -rf / []  score=0')
    def test_user_service_quoted(self):
        self.assertIn("Disable-LocalUser -Name 'a''b'", generate(F('users', "a'b"), 'windows'))
        s = generate(F('services', 'bad svc'), 'linux', True)
        self.assertIn("systemctl stop 'bad svc'", s)
        self.assertIn("rm -f '/etc/systemd/system/bad svc.service'", s)
        self.assertIn("C:\\ir\\backup\\bad_svc_qc.txt", generate(F('services', 'bad svc'), 'windows'))
    def test_prep_block(self):
        self.assertEqual(generate_all([], 'windows'), "")
        self.assertTrue(generate_all([F('users', 'u')], 'windows').startswith("# PREP\nNew-Item -ItemType Directory C:\\ir\\backup"))
        self.assertTrue(generate_all([F('users', 'u')], 'linux').startswith("# PREP\nmkdir -p /tmp/ir_backup"))
