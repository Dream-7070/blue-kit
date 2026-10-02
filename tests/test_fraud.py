import unittest
from bluekit.resp.fraud import scan
from bluekit.kb.query import KB

def get_active_techniques():
    try:
        kb = KB()
        res = kb.validate(['T1685', 'T1562'])
        return [r['normalized'] for r in res if r['found'] and r['status'] == 'active']
    except:
        return ['T1685', 'T1562']

active_techniques = get_active_techniques()

class TestFraud(unittest.TestCase):
    def test_new_cert(self):
        baseline = {'root_cas': [{'thumbprint': '1', 'subject': 'Old1'}, {'thumbprint': '2', 'subject': 'Old2'}]}
        current = {'root_cas': [{'thumbprint': '1', 'subject': 'Old1'}, {'thumbprint': '2', 'subject': 'Old2'}, {'thumbprint': '3', 'subject': 'New3'}]}
        res = scan(current, baseline)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['techniques'][0]['id'], 'T1553.004')
        self.assertIn("baseline'da yo'q", res[0]['reasons'][0])
        
    def test_unchanged_cert(self):
        baseline = {'root_cas': [{'thumbprint': '1', 'subject': 'Old1'}]}
        current = {'root_cas': [{'thumbprint': '1', 'subject': 'Old1'}]}
        res = scan(current, baseline)
        self.assertEqual(len(res), 0)
        
    def test_pac_file(self):
        current = {'proxy': {'AutoConfigURL': 'http://evil.com/wpad.dat'}}
        res = scan(current)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['item'], 'http://evil.com/wpad.dat')
        
    def test_proxy_changed(self):
        baseline = {'proxy': {'ProxyEnable': 0}}
        current = {'proxy': {'ProxyEnable': 1}}
        res = scan(current, baseline)
        self.assertEqual(len(res), 1)
        self.assertIn("Proxy yoqilgan", res[0]['reasons'][0])
        
    def test_dns_changed(self):
        baseline = {'dns_servers': [{'interface': 'eth0', 'addresses': '192.168.1.1'}]}
        current = {'dns_servers': [{'interface': 'eth0', 'addresses': '8.8.8.8'}]}
        res = scan(current, baseline)
        self.assertEqual(len(res), 1)
        self.assertIn("DNS baselinedan farq qiladi", res[0]['reasons'][0])
        
    def test_portproxy(self):
        current = {'portproxy': [{'rule': 'v4tov4 listenport=4444 connectaddress=1.1.1.1'}]}
        res = scan(current)
        self.assertEqual(len(res), 1)
        
    def test_firewall_off(self):
        current = {'firewall_profiles': [{'name': 'Domain', 'state': 'off'}]}
        res = scan(current)
        self.assertEqual(len(res), 1)
        
    def test_no_baseline(self):
        current = {
            'proxy': {'AutoConfigURL': 'x'},
            'portproxy': [{'rule': 'x'}],
            'firewall_profiles': [{'name': 'x', 'state': 'off'}],
            'dns_servers': [{'interface': 'x', 'addresses': '8.8.8.8'}]
        }
        res = scan(current)
        self.assertEqual(len(res), 4)
        
    def test_old_snapshot(self):
        current = {'users': [], 'services': []}
        res = scan(current)
        self.assertEqual(len(res), 0)
        
    def test_format(self):
        current = {'firewall_profiles': [{'name': 'Domain', 'state': 'off'}]}
        res = scan(current)[0]
        keys = ['category', 'item', 'score', 'confidence', 'techniques', 'reasons']
        for k in keys:
            self.assertIn(k, res)
            
    @unittest.skipUnless('T1685' in active_techniques or 'T1562' in active_techniques, "ATT&CK ID must be active in KB")
    def test_kb_active(self):
        current = {'firewall_profiles': [{'name': 'Domain', 'state': 'off'}]}
        res = scan(current)[0]
        tech = res['techniques'][0]['id']
        self.assertIn(tech, active_techniques)

    def test_ps1_syntax(self):
        import subprocess
        # try to parse collect_windows.ps1 using PowerShell
        ps_script = """
        $parserError = $null
        $tokens = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile('responder\\collect_windows.ps1', [ref]$tokens, [ref]$parserError)
        if ($parserError.Count -gt 0) {
            Write-Output "Errors found:"
            $parserError | ForEach-Object { Write-Output $_.Message }
            exit 1
        }
        exit 0
        """
        import sys
        if sys.platform == 'win32':
            proc = subprocess.run(["powershell", "-Command", ps_script], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stdout)

    def test_sh_syntax(self):
        import subprocess, sys, shutil
        if sys.platform == 'win32' and not shutil.which('bash'):
            self.skipTest('Bash not found on Windows')
        proc = subprocess.run(["bash", "-n", "responder/collect_linux.sh"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

import os
import json
import sys
import subprocess
from unittest.mock import patch

class TestFraudRatHosts(unittest.TestCase):
    def setUp(self):
        self.base_dir = os.path.dirname(os.path.dirname(__file__))
        self.cur_path = os.path.join(self.base_dir, 'data', 'samples', 'resp', 'current_win.json')
        self.bas_path = os.path.join(self.base_dir, 'data', 'samples', 'resp', 'baseline_win.json')
        with open(self.cur_path, encoding='utf-8-sig') as f:
            self.cur_win = json.load(f)
        with open(self.bas_path, encoding='utf-8-sig') as f:
            self.bas_win = json.load(f)
        try:
            from bluekit.paths import get_kb_path
            self.kb = KB(get_kb_path(None))
        except:
            self.kb = None

    def test_current_no_baseline(self):
        res = scan(self.cur_win, None, self.kb)
        rats = [r for r in res if r['category'] == 'remote_access_tools']
        hosts = [r for r in res if r['category'] == 'hosts_file']
        self.assertEqual(len(rats), 1)
        self.assertEqual(rats[0]['item'], 'AnyDesk')
        self.assertTrue(any(t.get('id') == 'T1219' for t in rats[0]['techniques']))
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]['item'], '91.238.50.10 ibank.example.uz')
        self.assertTrue(any(t.get('id') == 'T1565.001' for t in hosts[0]['techniques']))

    def test_current_with_baseline(self):
        res = scan(self.cur_win, self.bas_win, self.kb)
        rats = [r for r in res if r['category'] == 'remote_access_tools']
        hosts = [r for r in res if r['category'] == 'hosts_file']
        self.assertEqual(len(rats), 1)
        self.assertEqual(len(hosts), 1)

    def test_custom_baseline(self):
        bas = {
            'remote_access_tools': [{'name': 'AnyDesk'}],
            'hosts_file': ['91.238.50.10 ibank.example.uz']
        }
        res = scan(self.cur_win, bas, self.kb)
        rats = [r for r in res if r['category'] == 'remote_access_tools']
        hosts = [r for r in res if r['category'] == 'hosts_file']
        self.assertEqual(len(rats), 0)
        self.assertEqual(len(hosts), 1)

    def test_internal_hosts(self):
        cur = {'hosts_file': ['192.168.1.5 fileserver']}
        res1 = scan(cur, None, self.kb)
        hosts1 = [r for r in res1 if r['category'] == 'hosts_file']
        self.assertEqual(len(hosts1), 1)
        self.assertEqual(hosts1[0]['confidence'], 'medium')
        
        bas = {'hosts_file': ['192.168.1.5 fileserver']}
        res2 = scan(cur, bas, self.kb)
        hosts2 = [r for r in res2 if r['category'] == 'hosts_file']
        self.assertEqual(len(hosts2), 0)

    def test_keys_and_med(self):
        res = scan(self.cur_win, None, self.kb)
        self.assertGreaterEqual(len(res), 2)
        for r in res:
            self.assertEqual(set(r.keys()), {'category', 'item', 'score', 'confidence', 'techniques', 'reasons', 'protected'})
            self.assertNotEqual(r['confidence'], 'med')

    @patch('bluekit.resp.triage.analyze')
    def test_mock_exception(self, mock_analyze):
        mock_analyze.side_effect = RuntimeError('boom')
        cur = {'proxy': {'AutoConfigURL': 'http://evil.example/wpad.dat'}}
        res = scan(cur, None, self.kb)
        proxies = [r for r in res if r['category'] == 'proxy']
        errors = [r for r in res if r['category'] == 'fraud_error']
        self.assertEqual(len(proxies), 1)
        self.assertEqual(len(errors), 1)
        self.assertIn('boom', errors[0]['item'])

    def test_cli(self):
        cmd = [sys.executable, 'bk.py', 'resp', 'fraud', self.cur_path]
        result = subprocess.run(cmd, cwd=self.base_dir, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn('AnyDesk', result.stdout)
        self.assertIn('ibank.example.uz', result.stdout)
        
        cmd_json = [sys.executable, 'bk.py', '--json', 'resp', 'fraud', self.cur_path]
        result_json = subprocess.run(cmd_json, cwd=self.base_dir, capture_output=True, text=True)
        self.assertEqual(result_json.returncode, 0)
        out = json.loads(result_json.stdout)
        self.assertIsInstance(out, list)
