import unittest
import json
import os
import subprocess
import copy
import re
from datetime import timedelta
from bluekit.case.loaders import load_case
from bluekit.case.solver import solve, P, outcome

class TestCaseSolver(unittest.TestCase):
    def setUp(self):
        self.fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures", "cases")
        if not os.path.isfile(os.path.join(self.fixtures_dir, "cases_expected.json")):
            self.skipTest("tests/fixtures/cases/ yo'q (CTF topshiriq fayllari repo ga kiritilmaydi)")
        with open(os.path.join(self.fixtures_dir, "cases_expected.json")) as f:
            self.expected = json.load(f)
            
    def get_exp_key(self, case_id):
        return {
            "06": "06_mailbox_mirror",
            "10": "10_support_remote",
            "15": "15_ot_jumpstation",
            "05": "05_clockwork_vault"
        }[case_id]

    def test_solve_cases(self):
        for case_id in ["06", "10", "15"]:
            path = os.path.join(self.fixtures_dir, f"{self.get_exp_key(case_id)}.json")
            events, ctx = load_case(path)
            res = solve(events, ctx)
            
            exp = self.expected[self.get_exp_key(case_id)]
            self.assertEqual([e['id'] for e in res['chain']], exp['ids'])
            self.assertEqual(res['flag'], exp['flag'])
            self.assertEqual(len(res['orphans']), 0)
            
            c = res['counts']
            self.assertEqual(c['approved'], 504)
            self.assertEqual(c['telemetry'], 96)
            self.assertEqual(c['candidate'], 7)

        path_05 = os.path.join(self.fixtures_dir, "05_clockwork_vault")
        events, ctx = load_case(path_05)
        res = solve(events, ctx)
        exp = self.expected[self.get_exp_key("05")]
        self.assertEqual([e['id'] for e in res['chain']], exp['ids'])
        self.assertEqual(res['flag'], exp['flag'])
        self.assertEqual(len(res['orphans']), 0)
        c = res['counts']
        self.assertEqual(c['approved'], 3936)
        self.assertEqual(c['candidate'], 6)

    def test_trap_tickets(self):
        # 10 va 15 zanjirlarida HD-818, VND-71, IR-414 bo'lishi kerak
        for case_id in ["10", "15"]:
            path = os.path.join(self.fixtures_dir, f"{self.get_exp_key(case_id)}.json")
            events, ctx = load_case(path)
            res = solve(events, ctx)
            attrs_str = str([e['attrs'] for e in res['chain']])
            if case_id == "10": self.assertIn("HD-818", attrs_str)
            if case_id == "15":
                self.assertIn("VND-71", attrs_str)
                self.assertIn("IR-414", attrs_str)

    def test_overfit(self):
        path = os.path.join(self.fixtures_dir, "06_mailbox_mirror.json")
        events, ctx = load_case(path)
        for e in events:
            for k, v in e['attrs'].items():
                if isinstance(v, str):
                    e['attrs'][k] = re.sub(r'-ops\d+', '', v)
        res = solve(events, ctx)
        self.assertEqual([e['id'] for e in res['chain']], self.expected["06_mailbox_mirror"]["ids"])

    def test_order_and_clock(self):
        path = os.path.join(self.fixtures_dir, "06_mailbox_mirror.json")
        events, ctx = load_case(path)
        events.reverse()
        
        target_source = events[0]['source']
        ctx['clocks'][target_source] += 300
        for e in events:
            if e['source'] == target_source:
                e['raw_time'] = (P(e['raw_time']) + timedelta(seconds=300)).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+'Z'
                
        res = solve(events, ctx)
        self.assertEqual([e['id'] for e in res['chain']], self.expected["06_mailbox_mirror"]["ids"])
        self.assertEqual(res['flag'], self.expected["06_mailbox_mirror"]["flag"])

    def test_ticket_range(self):
        path = os.path.join(self.fixtures_dir, "06_mailbox_mirror.json")
        events, ctx = load_case(path)
        for e in events:
            if 'CHG-' in str(e['attrs']):
                for k, v in e['attrs'].items():
                    if isinstance(v, str) and 'CHG-' in v:
                        e['attrs'][k] = 'CHG-9999'
                        break
                break
        res = solve(events, ctx)
        self.assertEqual(res['counts']['candidate'], 8)

    def test_outcome(self):
        path_15 = os.path.join(self.fixtures_dir, "15_ot_jumpstation.json")
        events, ctx = load_case(path_15)
        for e in events:
            if e['action'] == 'LogicDownloadRejected': self.assertEqual(outcome(e), 'blocked')
            if e['action'] == 'AccountDisabled': self.assertEqual(outcome(e), 'response')
            if e['action'] == 'LoginSuccess': self.assertEqual(outcome(e), 'success')
            
        path_06 = os.path.join(self.fixtures_dir, "06_mailbox_mirror.json")
        events, ctx = load_case(path_06)
        for e in events:
            if e['action'] == 'RevokeSessions': self.assertEqual(outcome(e), 'response')

    def test_submission(self):
        path = os.path.join(self.fixtures_dir, "06_mailbox_mirror.json")
        events, ctx = load_case(path)
        res = solve(events, ctx)
        sub = res['submission']
        self.assertEqual(len(sub['timeline']), 7)
        self.assertEqual(len(sub['benign_exclusions']), 3)
        self.assertGreaterEqual(len(sub['detections']), 3)
        self.assertEqual(sub['flag'], self.expected["06_mailbox_mirror"]["flag"])
        self.assertEqual(set(sub.keys()), set(ctx['template'].keys()))

        # benign_exclusions: IP lar bor va tasdiqlangan tarmoqda, ikkala actor_class qamralgan
        classes = set()
        for be in sub['benign_exclusions']:
            self.assertTrue(len(be['networks']) > 0)
            for n in be['networks']:
                self.assertTrue(n['in_approved_network'])
            classes.add(be['actor_class'])
        self.assertEqual(len(classes), 2)

        # detections: placeholder yo'q, misol shu action li zanjir hodisasi
        for d in sub['detections']:
            self.assertNotIn("extra_", d['logic'])
            self.assertNotIn("generic", d['logic'])
            if d['name'].startswith('Action '):
                act = d['name'][len('Action '):]
                ev = next((e for e in res['chain'] if e['id'] == d['example_event_id']), None)
                self.assertIsNotNone(ev)
                self.assertEqual(ev['action'], act)

        # outcomes
        rev = [e for e in sub['blocked_actions'] if e['action'] == 'RevokeSessions']
        self.assertEqual(len(rev), 1)
        self.assertEqual(rev[0]['outcome'], 'response')
        self.assertFalse(any(e['outcome'] in ('blocked', 'response') for e in sub['successful_actions']))
        self.assertEqual(len(sub['successful_actions']), 6)

        events_15, ctx_15 = load_case(os.path.join(self.fixtures_dir, "15_ot_jumpstation.json"))
        b15 = {e['action']: e['outcome'] for e in solve(events_15, ctx_15)['submission']['blocked_actions']}
        self.assertEqual(b15, {'LogicDownloadRejected': 'blocked', 'AccountDisabled': 'response'})

        # 05: attempt_vs_success va evidence ro'yxat
        events_05, ctx_05 = load_case(os.path.join(self.fixtures_dir, "05_clockwork_vault"))
        res_05 = solve(events_05, ctx_05)
        self.assertEqual(len(res_05['submission']['attempt_vs_success']), 6)
        for t in res_05['submission']['timeline']:
            self.assertIsInstance(t['evidence'], list)

    def test_cli(self):
        import subprocess
        root = os.path.dirname(os.path.dirname(__file__))
        path = os.path.join("tests", "fixtures", "cases", "06_mailbox_mirror.json")
        out_file = os.path.join(root, "submission_test.json")
        
        proc = subprocess.run(["python", "-m", "bluekit.case.cli", "solve", path, "--out", out_file], cwd=root, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("FLAG:", proc.stdout)
        self.assertTrue(os.path.exists(out_file))
        with open(out_file) as f:
            json.load(f)
        os.remove(out_file)
        
        proc2 = subprocess.run(["python", "-m", "bluekit.case.cli", "solve", "nonexistent.json"], cwd=root, capture_output=True, text=True)
        self.assertEqual(proc2.returncode, 1)
        self.assertNotIn("Traceback", proc2.stderr)

        # 15: matn chiqishida natija turlari ko'rinadi
        path_15 = os.path.join("tests", "fixtures", "cases", "15_ot_jumpstation.json")
        proc3 = subprocess.run(["python", "-m", "bluekit.case.cli", "solve", path_15], cwd=root, capture_output=True, text=True, encoding='utf-8')
        self.assertEqual(proc3.returncode, 0)
        for word in ("success", "blocked", "response"):
            self.assertIn(word, proc3.stdout)

    def test_empty_input_no_bogus_flag(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"x": 1}, f)
            with self.assertRaises(ValueError):
                load_case(p)
        # hamma hodisa tasdiqlangan bo'lsa ham bo'sh satr xeshi flag bo'lib chiqmasin
        events, ctx = load_case(os.path.join(self.fixtures_dir, "06_mailbox_mirror.json"))
        events = [e for e in events if e['attrs'].get('change_ticket')]
        res = solve(events, ctx)
        self.assertEqual(res['chain'], [])
        self.assertEqual(res['flag'], '')
        self.assertTrue(any("zanjir bo'sh" in w for w in res['warnings']))

if __name__ == '__main__':
    unittest.main()
