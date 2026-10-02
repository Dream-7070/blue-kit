import unittest
import os
from bluekit import doctor
from bluekit import paths

has_kb = os.path.exists(paths.get_kb_path())

class TestSelftest(unittest.TestCase):
    def test_run_checks_format(self):
        results = doctor.run_checks(quick=True)
        self.assertIsInstance(results, list)
        
        ids = set()
        for r in results:
            for k in ['id', 'name', 'ok', 'detail', 'critical']:
                self.assertIn(k, r)
            self.assertNotIn(r['id'], ids)
            ids.add(r['id'])
            
    def test_summary(self):
        results = doctor.run_checks(quick=True)
        s = doctor.summary(results)
        self.assertEqual(s['total'], len(results))
        self.assertEqual(s['ok'] + s['failed'] + s['warnings'], s['total'])
        
    @unittest.skipUnless(has_kb, "KB topilmadi")
    def test_critical_pass(self):
        results = doctor.run_checks()
        failed_critical = [r for r in results if r['critical'] and not r['ok']]
        self.assertEqual(len(failed_critical), 0, f"Critical failures: {failed_critical}")
        
    def test_quick_faster(self):
        full = doctor.run_checks(quick=False)
        quick = doctor.run_checks(quick=True)
        self.assertLess(len(quick), len(full))
        
    @unittest.skipUnless(has_kb, "KB topilmadi")
    def test_fn_sla(self):
        results = doctor.run_checks(quick=False)
        sla_check = next((r for r in results if r['id'] == 'fn_sla'), None)
        self.assertIsNotNone(sla_check)
        self.assertTrue(sla_check['ok'])
        self.assertIn("down", sla_check['detail'].lower())
        
    def test_bad_dir(self):
        results = doctor.run_checks(data_dir="/non/existent/path/999", quick=True)
        self.assertIsInstance(results, list)
        data_dir_check = next((r for r in results if r['id'] == 'data_dir'), None)
        self.assertIsNotNone(data_dir_check)
        self.assertFalse(data_dir_check['ok'])

if __name__ == '__main__':
    unittest.main()
