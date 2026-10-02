import unittest
import os
import tempfile
import html
from bluekit.resp.servicedoctor import diagnose
from bluekit.resp.report import generate_html

# Assuming bluekit.kb.query.KB is available, try importing
try:
    from bluekit.kb.query import KB
    has_kb = True
except ImportError:
    has_kb = False


class TestDoctor(unittest.TestCase):
    def test_different_cause_for_disabled_and_stopped(self):
        # 1. Har xil sabab - har xil javob
        snap_disabled = {
            'meta': {'os': 'windows'},
            'services': [{'name': 'W3SVC', 'start_mode': 'Disabled', 'state': 'Stopped'}]
        }
        snap_stopped = {
            'meta': {'os': 'windows'},
            'services': [{'name': 'W3SVC', 'start_mode': 'Auto', 'state': 'Stopped'}]
        }
        res_dis = diagnose(snap_disabled, 'W3SVC')
        res_stop = diagnose(snap_stopped, 'W3SVC')
        self.assertNotEqual(res_dis[0]['cause'], res_stop[0]['cause'])
        self.assertIn('Disabled', res_dis[0]['cause'])

    def test_command_contains_actual_name(self):
        # 2. Buyruqda haqiqiy xizmat nomi
        snap = {
            'meta': {'os': 'windows'},
            'services': [{'name': 'W3SVC', 'start_mode': 'Disabled', 'state': 'Stopped'}]
        }
        res = diagnose(snap, 'W3SVC')
        self.assertIn('W3SVC', res[0]['suggested_fix_command'])
        self.assertNotIn('service', res[0]['suggested_fix_command'].replace('service', 'xxxx'))

    def test_service_not_found(self):
        # 3. Xizmat topilmadi
        snap = {'meta': {'os': 'windows'}, 'services': []}
        res = diagnose(snap, 'W3SVC')
        self.assertIn("Xizmat umuman yo'q", res[0]['cause'])

    def test_baseline_diff_and_suspicious_folder(self):
        # 4. Baseline bilan farq va shubhali papka
        snap = {
            'meta': {'os': 'windows'},
            'services': [{'name': 'W3SVC', 'start_mode': 'Auto', 'state': 'Running', 'binary_path': r'C:\Users\x\AppData\Local\Temp\a.exe'}]
        }
        baseline = {
            'services': [{'name': 'W3SVC', 'start_mode': 'Auto', 'state': 'Running', 'binary_path': r'C:\Windows\System32\a.exe'}]
        }
        res = diagnose(snap, 'W3SVC', baseline=baseline)
        causes = [r['cause'] for r in res]
        self.assertTrue(any("Binary yo'li o'zgargan" in c for c in causes))
        self.assertTrue(any("Shubhali papkadan ishga tushyapti" in c for c in causes))

    def test_unquoted_path_with_space(self):
        # 5. Qo'shtirnoqsiz yo'l
        snap = {
            'meta': {'os': 'windows'},
            'services': [{'name': 'W3SVC', 'start_mode': 'Auto', 'state': 'Running', 'binary_path': r'C:\Program Files\App\svc.exe'}]
        }
        res = diagnose(snap, 'W3SVC')
        causes = [r['cause'] for r in res]
        self.assertTrue(any("Qo'shtirnoqsiz yo'l" in c for c in causes))
        techniques = [r['technique'] for r in res]
        self.assertIn('T1574.009', techniques)

    def test_stopper_task(self):
        # 6. Qayta to'xtatuvchi vazifa
        snap = {
            'meta': {'os': 'windows'},
            'services': [{'name': 'W3SVC', 'start_mode': 'Auto', 'state': 'Running', 'binary_path': r'C:\a.exe'}],
            'tasks': [{'name': 'StopIt', 'action': 'sc stop W3SVC'}]
        }
        res = diagnose(snap, 'W3SVC')
        causes = [r['cause'] for r in res]
        self.assertTrue(any("qayta to'xtatyapti" in c for c in causes))

    def test_linux_commands(self):
        # 7. Linux
        snap = {
            'meta': {'os': 'linux'},
            'services': [{'name': 'nginx', 'start_mode': 'disabled', 'state': 'stopped', 'binary_path': '/usr/sbin/nginx'}]
        }
        res = diagnose(snap, 'nginx')
        self.assertIn('systemctl enable', res[0]['suggested_fix_command'])
        self.assertNotIn('sc ', res[0]['suggested_fix_command'])

    def test_sla_result(self):
        # 8. sla_result bilan
        snap = {
            'meta': {'os': 'windows'},
            'services': [{'name': 'W3SVC', 'start_mode': 'Auto', 'state': 'Running', 'binary_path': r'C:\a.exe'}]
        }
        sla = {'checks': [{'type': 'tcp', 'ok': True}, {'type': 'http', 'ok': False}]}
        res = diagnose(snap, 'W3SVC', sla_result=sla)
        causes = [r['cause'] for r in res]
        self.assertTrue(any("ilova javob bermayapti" in c for c in causes))

    def test_sla_result_tcp_ok_http_fail(self):
        # Yangi 1. sla_result = haqiqiy shakl, tcp ok + http ok=False
        snap = {
            'meta': {'os': 'windows'},
            'services': [{'name': 'W3SVC', 'start_mode': 'Auto', 'state': 'Running'}]
        }
        sla = {'checks': [{'type': 'tcp', 'ok': True}, {'type': 'http', 'ok': False}]}
        res = diagnose(snap, 'W3SVC', sla_result=sla)
        causes = [r['cause'] for r in res]
        self.assertTrue(any("ilova javob bermayapti" in c for c in causes))
        self.assertNotIn("sabab aniqlanmadi", causes)

    def test_sla_result_tcp_fail(self):
        # Yangi 2. tcp ok=False -> "port tinglanmayapti"
        snap = {
            'meta': {'os': 'windows'},
            'services': [{'name': 'W3SVC', 'start_mode': 'Auto', 'state': 'Running'}]
        }
        sla = {'checks': [{'type': 'tcp', 'ok': False}]}
        res = diagnose(snap, 'W3SVC', sla_result=sla)
        causes = [r['cause'] for r in res]
        self.assertTrue(any("port tinglanmayapti" in c for c in causes))

    def test_linux_inactive_enabled(self):
        # Yangi 3. Linux: state='inactive', start_mode='enabled'
        snap = {
            'meta': {'os': 'linux'},
            'services': [{'name': 'nginx', 'start_mode': 'enabled', 'state': 'inactive'}]
        }
        res = diagnose(snap, 'nginx')
        causes = [r['cause'] for r in res]
        self.assertTrue(any("to'xtagan" in c for c in causes))
        cmds = [r['suggested_fix_command'] for r in res if "to'xtagan" in r['cause']]
        self.assertTrue(any('systemctl start' in cmd for cmd in cmds))

    def test_linux_failed(self):
        # Yangi 4. Linux: state='failed' -> sabab aniqlanadi
        snap = {
            'meta': {'os': 'linux'},
            'services': [{'name': 'nginx', 'start_mode': 'enabled', 'state': 'failed'}]
        }
        res = diagnose(snap, 'nginx')
        causes = [r['cause'] for r in res]
        self.assertTrue(any("yiqilgan" in c for c in causes))
        self.assertNotIn("sabab aniqlanmadi", causes)

    def test_nothing_found(self):
        # 9. Hech narsa topilmasa
        snap = {
            'meta': {'os': 'windows'},
            'services': [{'name': 'W3SVC', 'start_mode': 'Auto', 'state': 'Running', 'binary_path': r'"C:\a.exe"'}]
        }
        res = diagnose(snap, 'W3SVC')
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['cause'], "sabab aniqlanmadi")
        self.assertIn("Xizmat W3SVC tekshirildi", res[0]['evidence'])

    def test_backward_compatibility(self):
        # 10. Orqaga moslik
        snap = {
            'meta': {'os': 'windows'},
            'services': [{'name': 'X', 'start_mode': 'Disabled', 'state': 'Stopped', 'binary_path': r'"C:\a.exe"'}]
        }
        res = diagnose(snap, 'X')
        self.assertIn('cause', res[0])
        self.assertIn('evidence', res[0])
        self.assertIn('suggested_fix_command', res[0])

    @unittest.skipUnless(has_kb, "bluekit.kb not available")
    def test_attack_ids_valid(self):
        # 11. ATT&CK ID lari KB da active
        kb = KB()
        snap = {
            'meta': {'os': 'windows'},
            'services': [{'name': 'W3SVC', 'start_mode': 'Disabled', 'state': 'Stopped', 'binary_path': r'C:\Temp\a.exe'}]
        }
        res = diagnose(snap, 'W3SVC')
        for r in res:
            tech = r.get('technique')
            if tech:
                self.assertTrue(kb.validate(tech))
                self.assertNotEqual(tech, 'T1562')

    def test_html_report_offline_and_escaped(self):
        # 12, 13, 14. HTML hisobot
        findings = [
            {'category': 'tasks', 'item': '<img src=x onerror=1>', 'score': 0.6, 'confidence': 'high', 'techniques': [{'id': 'T1053.005'}], 'reasons': ["<script>alert(1)</script>"]}
        ]
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as f:
            out_path = f.name
        
        try:
            generate_html(findings, out_path)
            with open(out_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # test offline
            self.assertIn('<meta charset', content)
            self.assertNotIn('<script src=', content)
            self.assertNotIn('http://', content)
            self.assertNotIn('https://', content)
            
            # test escape
            self.assertNotIn('<img src=x onerror=1>', content)
            self.assertIn('&lt;img', content)
            self.assertNotIn('<script>alert(1)</script>', content)
            self.assertIn('&lt;script&gt;', content)
            
            # test empty
            with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as f2:
                out_path2 = f2.name
            try:
                generate_html([], out_path2)
                with open(out_path2, 'r', encoding='utf-8') as f2:
                    content2 = f2.read()
                self.assertIn("Topilma yo'q", content2)
            finally:
                os.remove(out_path2)
                
        finally:
            os.remove(out_path)

if __name__ == '__main__':
    unittest.main()
