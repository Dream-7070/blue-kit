import unittest
import os
from bluekit.ir.correlator import correlate_incident
from bluekit.kb.cve import audit_packages, VULNERABILITY_RULES
from bluekit.resp.remediate import generate

def ev(ts='2026-10-05T09:01:10Z', ds='sysmon', **kw):
    e = {'@timestamp': ts, 'event': {'dataset': ds}, 'host': {'name': 'pc1'}, 'user': {'name': 'bob'}}
    e.update(kw)
    return e

def techs(evs, fb=False):
    return [s.technique_id for s in correlate_incident(evs, heuristic_fallback=fb).stages]

class TestIrTiRegress(unittest.TestCase):

    def test_decoy_word_does_not_hide_c2(self):
        evs1 = [ev(message='decoy check passed; beacon to C2', process={'name': 'update.exe'}, destination={'ip': '45.1.2.3', 'port': 443})]
        self.assertEqual(techs(evs1).count('T1071.001'), 1)
        
        evs2 = [ev(message='sanctioned beacon to C2', process={'name': 'update.exe'}, destination={'ip': '45.1.2.3', 'port': 443})]
        self.assertEqual(techs(evs2).count('T1071.001'), 1)

    def test_no_dataset_literals_in_correlator(self):
        correlator_path = os.path.join(os.path.dirname(__file__), '..', 'bluekit', 'ir', 'correlator.py')
        with open(correlator_path, 'r', encoding='utf-8') as f:
            content = f.read().lower()
            
        literals = ["'decoy' in msg", "'sanctioned'", "'13.107.42.14'", "'map_drives'", "'nightly.7z'", "'/tmp/.sysup'", "'devtool.exe'", "'\\\\finance\\\\'", "'erp.dump'"]
        for lit in literals:
            self.assertNotIn(lit, content)

    def test_logon_type3_alone_not_lateral(self):
        evs = [ev(ds='windows.security', event={'dataset': 'windows.security', 'code': 4624}, message='An account was successfully logged on. Logon Type 3', source={'ip': '10.0.0.9'})]
        self.assertEqual(techs(evs).count('T1021.002'), 0)

    def test_admin_share_is_lateral(self):
        evs1 = [ev(message=r'Share access \\FS-02\C$\Users')]
        self.assertEqual(techs(evs1).count('T1021.002'), 1)
        
        evs2 = [ev(process={'name': 'cmd.exe', 'command_line': r'copy x.exe \\10.0.0.5\ADMIN$\x.exe'})]
        self.assertEqual(techs(evs2).count('T1021.002'), 1)
        
        evs3 = [ev(message=r'Share access \\dc01\SYSVOL\x')]
        self.assertEqual(techs(evs3).count('T1021.002'), 0)
        
        evs4 = [ev(message=r'opened D:\data\x$ file')]
        self.assertEqual(techs(evs4).count('T1021.002'), 0)

    def test_sql_id_not_recon(self):
        evs1 = [ev(ds='postgresql', message='LOG: statement: SELECT id, name FROM products WHERE id = 5')]
        self.assertEqual(techs(evs1).count('T1033'), 0)
        
        evs2 = [ev(ds='auditd', process={'command_line': 'psql -c "SELECT id FROM t"'})]
        self.assertEqual(techs(evs2).count('T1033'), 0)

    def test_shell_c_recon(self):
        cmds = ['/bin/sh -c id', 'sh -c "whoami"', "bash -c 'id;uname -a'", 'id', '/usr/bin/id', 'ls; whoami']
        for cmd in cmds:
            evs = [ev(ds='auditd', process={'command_line': cmd})]
            self.assertEqual(techs(evs).count('T1033'), 1)
            
        cmds_neg = ['pidof x', 'cat /tmp/uuid.txt']
        for cmd in cmds_neg:
            evs = [ev(ds='auditd', process={'command_line': cmd})]
            self.assertEqual(techs(evs).count('T1033'), 0)

    def test_c2_beacons_aggregated(self):
        evs = [ev(ts=f'2026-10-05T09:0{i}:10Z', process={'name': 'beacon.exe', 'command_line': r'C:\Users\a\AppData\Roaming\beacon.exe'}, destination={'ip': '45.1.2.3', 'port': 443}) for i in range(10)]
        
        inc = correlate_incident(evs, heuristic_fallback=False)
        st = [s for s in inc.stages if s.technique_id == 'T1071.001']
        self.assertEqual(len(st), 1)
        self.assertEqual(st[0].iocs.get('connections'), 10)
        self.assertTrue(':09:10' in str(st[0].iocs.get('last_seen', '')))
        
        inc2 = correlate_incident(evs, heuristic_fallback=True)
        st2 = [s for s in inc2.stages if s.technique_id == 'T1071.001']
        self.assertEqual(len(st2), 1)
        
        evs3 = [ev(ts=f'2026-10-05T09:0{i}:10Z', process={'name': 'beacon.exe', 'command_line': r'C:\Users\a\AppData\Roaming\beacon.exe'}, destination={'ip': '45.1.2.3' if i < 5 else '45.9.9.9', 'port': 443}) for i in range(10)]
        self.assertEqual(techs(evs3).count('T1071.001'), 2)

    def test_benign_noise_no_fp(self):
        evs1 = [ev(message='Connection closed', source={'ip': '10.0.0.5', 'port': 47690})]
        self.assertEqual(techs(evs1), [])
        
        evs2 = [ev(message='Status 0x1700 returned by driver')]
        self.assertEqual(techs(evs2), [])
        
        evs3 = [ev(message='smbd service started successfully')]
        self.assertEqual(techs(evs3), [])
        
        evs4 = [ev(process={'name': 'rsync'}, destination={'ip': '93.184.216.34', 'port': 443}, message='sync done')]
        self.assertEqual(techs(evs4), [])
        
        evs5 = [ev(process={'name': 'powershell.exe', 'command_line': 'powershell Get-Content a.txt -Encoding UTF8'})]
        self.assertEqual(techs(evs5), [])

    def test_bad_dst_ip_no_crash(self):
        correlate_incident([ev(process={'name': 'curl'}, destination={'ip': 'evil.example.com', 'port': 443})])
        correlate_incident([ev(process={'name': 'curl'}, destination={'ip': '10.0.2.0/24', 'port': 443})])

    def test_hidden_tmp_ingress(self):
        self.assertEqual(techs([ev(ds='auditd', process={'command_line': 'ls /tmp/.X11-unix'})]).count('T1105'), 0)
        self.assertEqual(techs([ev(ds='auditd', process={'command_line': '/tmp/.cache/xm -o pool'})]).count('T1105'), 1)

    def test_cve_debian12_backport(self):
        self.assertEqual([f['cve'] for f in audit_packages([{'name': 'openssh-server', 'version': '1:9.2p1-2+deb12u2'}])], ['CVE-2024-6387'])
        self.assertEqual([f['cve'] for f in audit_packages([{'name': 'openssh-server', 'version': '1:9.2p1-2+deb12u3'}])], [])
        self.assertEqual([f['cve'] for f in audit_packages([{'name': 'openssh-server', 'version': '1:9.7p1-7'}])], ['CVE-2024-6387'])
        self.assertEqual([f['cve'] for f in audit_packages([{'name': 'openssh-server', 'version': '1:8.9p1-3ubuntu0.10'}])], [])

    def test_remediation_text_is_comment(self):
        allowed_cmds = {'apt', 'apt-get', 'yum', 'dnf', 'chmod'}
        bad = []
        screenconnect_rule = None
        for rule in VULNERABILITY_RULES:
            if 'remediation' in rule:
                r = rule['remediation']
                if not (r.startswith('#') or r.split()[0] in allowed_cmds):
                    bad.append(r)
            if rule.get('cve') == 'CVE-2024-1709':
                screenconnect_rule = rule

        self.assertEqual(bad, [])
        
        self.assertIsNotNone(screenconnect_rule)
        res = generate({'category': 'vulnerabilities', 'item': 'ScreenConnect 23.9.7', 'suggested_fix_command': screenconnect_rule['remediation']}, 'windows')
        lines = [l.strip() for l in res.split('\n')]
        self.assertIn('# REMEDIATE / PATCH', lines)
        nxt = lines[lines.index('# REMEDIATE / PATCH') + 1:]
        self.assertGreater(len(nxt), 0)
        self.assertTrue(nxt[0].startswith('#'))

if __name__ == '__main__':
    unittest.main()
