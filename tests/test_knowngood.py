import unittest
import os
import json
import yaml
import copy
from bluekit.resp.triage import analyze
from bluekit import paths

class TestKnownGood(unittest.TestCase):
    def setUp(self):
        self.kb = None
        self.cur_path = os.path.join('data', 'samples', 'resp', 'current_win.json')
        self.base_path = os.path.join('data', 'samples', 'resp', 'baseline_win.json')
        
        with open(self.cur_path, encoding='utf-8') as f:
            self.cur = json.load(f)
            
        self.kg_path = paths.get_resource_path('bluekit/resp/knowngood.yaml')
        with open(self.kg_path, encoding='utf-8') as f:
            self.kg = yaml.safe_load(f)

    def test_behavior_baseline_none(self):
        from bluekit.paths import get_kb_path
        from bluekit.kb.query import KB
        kb_path = get_kb_path()
        if not os.path.exists(kb_path):
            raise unittest.SkipTest("KB not built")
        self.kb = KB(kb_path)
        
        f, ex = analyze(self.kb, self.cur, baseline=None, protected=['checker_admin'])
        
        # Check 'used' in extra
        self.assertTrue(ex['knowngood']['used'])
        
        high_items = [x['item'] for x in f if x['confidence'] == 'high' and not x['protected']]
        
        self.assertIn('Updater', high_items) # tasks / Updater
        self.assertIn('admin', high_items) # users / admin
        # 'Updater' autoruns might be combined if item is name, let's just check high_items
        
        # 45.142.212.61
        self.assertTrue(any('45.142.212.61' in x for x in high_items))
        
        # hosts_file
        self.assertTrue(any('91.238.50.10' in x for x in high_items))
        self.assertTrue(len(high_items) >= 5)
        
        self.assertNotIn('Administrator', high_items)
        
        ch = [x for x in f if x['item'] == 'checker_admin']
        self.assertTrue(all(x['protected'] for x in ch))
        self.assertNotIn('checker_admin', high_items)
        
        self.assertNotIn('Spooler', high_items)
        self.assertNotIn('GoogleUpdateTaskMachine', high_items)
        self.assertNotIn('SecurityHealth', high_items)

    def test_masquerade(self):
        cur2 = copy.deepcopy(self.cur)
        cur2['services'].append({
            "name": "Spooler", "display": "Print Spooler",
            "state": "Running", "start_mode": "Auto",
            "binary_path": "C:\\Users\\Public\\spoolsv.exe", "run_as": "LocalSystem"
        })
        f, _ = analyze(self.kb, cur2, baseline=None)
        spool_findings = [x for x in f if x['item'] == 'Spooler' and x['confidence'] == 'high']
        self.assertTrue(len(spool_findings) > 0, "Spooler masquerade should be high")
        
        cur3 = copy.deepcopy(self.cur)
        cur3['autoruns'].append({
            "name": "SecurityHealth", "value": "C:\\Users\\hr.olim\\AppData\\Local\\Temp\\x.exe"
        })
        f2, _ = analyze(self.kb, cur3, baseline=None)
        sec_findings = [x for x in f2 if x['item'] == 'SecurityHealth' and x['confidence'] == 'high']
        self.assertTrue(len(sec_findings) > 0, "SecurityHealth masquerade should be high")

    def test_regression_with_baseline(self):
        with open(self.base_path, encoding='utf-8') as f:
            base = json.load(f)
        fnd, _ = analyze(self.kb, self.cur, baseline=base)
        
        highs = [x for x in fnd if x['confidence'] == 'high']
        self.assertTrue(len(highs) >= 4)
        
        tasks_updater = [x for x in highs if x['category'] == 'tasks' and x['item'] == 'Updater']
        self.assertTrue(len(tasks_updater) > 0)
        
        auto_updater = [x for x in highs if x['category'] == 'autoruns' and x['item'] == 'Updater']
        self.assertTrue(len(auto_updater) > 0)

    def test_data_quality(self):
        self.assertEqual(self.kg['version'], 1)
        w = self.kg['windows']
        l = self.kg['linux']
        
        self.assertTrue(len(w['services']) >= 120, f"windows.services len: {len(w['services'])}")
        self.assertTrue(len(w['users']) >= 12, f"windows.users len: {len(w['users'])}")
        self.assertTrue(len(w['autoruns']) >= 15, f"windows.autoruns len: {len(w['autoruns'])}")
        self.assertTrue(len(l['services']) >= 40, f"linux.services len: {len(l['services'])}")
        self.assertTrue(len(l['users']) >= 20, f"linux.users len: {len(l['users'])}")
        
        req_w = ['wuauserv', 'windefend', 'bits', 'lanmanserver', 'lanmanworkstation', 'dnscache',
                 'eventlog', 'schedule', 'termservice', 'winrm', 'w32time', 'spooler', 'msiserver',
                 'trustedinstaller', 'sysmain', 'wscsvc', 'dhcp', 'netlogon', 'samss', 'rpcss']
        for r in req_w:
            self.assertIn(r, w['services'])
            
        req_l = ['sshd', 'cron', 'systemd-journald', 'systemd-logind', 'dbus', 'rsyslog',
                 'networkd-dispatcher', 'unattended-upgrades', 'polkit', 'udisks2']
        for r in req_l:
            self.assertIn(r, l['services'])
            
        # No duplicates
        for sect in ['services', 'users', 'autoruns']:
            self.assertEqual(len(w[sect]), len(set(w[sect])))
        for sect in ['services', 'users']:
            self.assertEqual(len(l[sect]), len(set(l[sect])))
            
        import re
        gen_regex = re.compile(r'^(item|name|service|task|user|entry)[-_]?\d+$')
        
        for os_name, data in self.kg.items():
            if os_name == 'version': continue
            for k, vlist in data.items():
                if isinstance(vlist, list) and len(vlist) > 0 and isinstance(vlist[0], str):
                    for v in vlist:
                        self.assertEqual(v, v.lower(), f"Must be lowercase: {v}")
                        self.assertFalse(gen_regex.match(v), f"No generated names: {v}")

    def test_resilience(self):
        # Override get_resource_path
        old = paths.get_resource_path
        paths.get_resource_path = lambda x: 'non_existent_file.yaml'
        try:
            from importlib import reload
            import bluekit.resp.triage as t
            # analyze function handles reloading inside, but we need to run it again
            f, ex = t.analyze(self.kb, self.cur, baseline=None)
            self.assertEqual(ex['knowngood'], "topilmadi")
        finally:
            paths.get_resource_path = old
            
if __name__ == '__main__':
    unittest.main()