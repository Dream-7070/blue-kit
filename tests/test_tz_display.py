import unittest
from datetime import datetime, timezone, timedelta
from bluekit.tz import display_ts, set_naive_tz, LOCAL_TZ
from bluekit.logs.parse import parse_ts
import tempfile
import os
import subprocess
import json

class TestTzDisplay(unittest.TestCase):
    def setUp(self):
        set_naive_tz(None)
        
    def tearDown(self):
        set_naive_tz(None)

    def test_display_ts_cases(self):
        # 2026-09-18T08:00:02.589261+00:00	sukut	2026-09-18 08:00:02 UTC (Toshkent 13:00:02)
        raw1 = '2026-09-18T08:00:02.589261+00:00'
        dt1 = parse_ts(raw1)
        self.assertEqual(display_ts(dt1, raw1), '2026-09-18 08:00:02 UTC (Toshkent 13:00:02)')

        # 2026-10-05 14:20:00	sukut	2026-10-05 14:20:00
        raw2 = '2026-10-05 14:20:00'
        dt2 = parse_ts(raw2)
        self.assertEqual(display_ts(dt2, raw2), '2026-10-05 14:20:00')

        # 2026-10-05T11:20:00+03:00	sukut	2026-10-05 11:20:00 +03:00 (Toshkent 13:20:00)
        raw3 = '2026-10-05T11:20:00+03:00'
        dt3 = parse_ts(raw3)
        self.assertEqual(display_ts(dt3, raw3), '2026-10-05 11:20:00 +03:00 (Toshkent 13:20:00)')

        # 2026-10-05T22:30:00Z	sukut	2026-10-05 22:30:00 UTC (Toshkent 10-06 03:30:00)
        raw4 = '2026-10-05T22:30:00Z'
        dt4 = parse_ts(raw4)
        self.assertEqual(display_ts(dt4, raw4), '2026-10-05 22:30:00 UTC (Toshkent 10-06 03:30:00)')

        # 2026-10-05T14:20:00+05:00	sukut	2026-10-05 14:20:00 +05:00
        raw5 = '2026-10-05T14:20:00+05:00'
        dt5 = parse_ts(raw5)
        self.assertEqual(display_ts(dt5, raw5), '2026-10-05 14:20:00 +05:00')

        # 2026-10-05 08:00:00	utc	2026-10-05 08:00:00 (Toshkent 13:00:00)
        set_naive_tz('utc')
        raw6 = '2026-10-05 08:00:00'
        dt6 = parse_ts(raw6)
        self.assertEqual(display_ts(dt6, raw6), '2026-10-05 08:00:00 (Toshkent 13:00:00)')

        # None, local_dt=datetime(2026,10,5,14,20)	utc	2026-10-05 14:20:00
        dt7 = datetime(2026, 10, 5, 14, 20)
        self.assertEqual(display_ts(dt7, None), '2026-10-05 14:20:00')

        # epoch 1790000000	sukut	datetime.fromtimestamp(1790000000, timezone.utc) ning %Y-%m-%d %H:%M:%S + UTC (Toshkent ...)
        set_naive_tz(None)
        raw8 = '1790000000'
        dt8 = parse_ts(raw8)
        expected8_dt = datetime.fromtimestamp(1790000000, timezone.utc)
        expected8_str = expected8_dt.strftime('%Y-%m-%d %H:%M:%S') + f" UTC (Toshkent {dt8.strftime('%H:%M:%S')})"
        self.assertEqual(display_ts(dt8, raw8), expected8_str)

        # aware datetime and ISO string, display_ts(None) -> ""
        self.assertEqual(display_ts(None), "")
        self.assertEqual(display_ts('2026-10-05T13:00:02+05:00'), '2026-10-05 13:00:02')

    def test_integration(self):
        import sys
        with tempfile.TemporaryDirectory() as td:
            csv_path = os.path.join(td, 'test.csv')
            with open(csv_path, 'w', encoding='utf-8') as f:
                f.write("timestamp,host,message,command_line\n")
                f.write("2026-10-05T08:00:00Z,host1,msg1,cmd1\n")
                f.write("2026-10-05 12:00:00,host2,msg2,cmd2\n")

            json_out = os.path.join(td, 'out.json')
            cmd = [sys.executable, 'bk.py', 'logs', 'analyze', csv_path, '--json-out', json_out]
            res = subprocess.run(cmd, capture_output=True, text=True, cwd=r'D:\Claude Projects\CTF\blue-kit-staging')
            
            with open(json_out, 'r', encoding='utf-8') as f:
                out = json.load(f)
                
            timeline = out['timeline']
            self.assertEqual(len(timeline), 2)
            
            # Order should be 12:00:00 first, then 08:00:00Z (which is 13:00:00 Toshkent)
            self.assertEqual(timeline[0]['ts_disp'], "2026-10-05 12:00:00")
            self.assertEqual(timeline[0]['ts'], "2026-10-05T12:00:00")
            
            self.assertEqual(timeline[1]['ts_disp'], "2026-10-05 08:00:00 UTC (Toshkent 13:00:00)")
            self.assertEqual(timeline[1]['ts'], "2026-10-05T13:00:00")

            self.assertIn("Timespan:", res.stdout)
            self.assertIn("2026-10-05 12:00:00", res.stdout)
            self.assertIn("UTC (Toshkent 13:00:00)", res.stdout)

    def test_qradar_leef(self):
        from bluekit.logs.qradar import load_qradar
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.csv') as f:
            f.write("eventtime,custom1,custom2,custom3,custom4,custom5,custom6,custom7,custom8,custom9,payload\n")
            leef_str = "LEEF:1.0|Vendor|Product|1.0|EventID|devTime=Oct 05 2026 08:00:00 GMT\tusrName=test"
            import base64
            b64_payload = base64.b64encode(leef_str.encode()).decode().rstrip('=')
            f.write(f"123456789,,,,,,,,,,{b64_payload}\n")
            f_name = f.name
            
        try:
            events = load_qradar(f_name)
            self.assertTrue(len(events) > 0)
            self.assertIn(" UTC (Toshkent ", events[0]['ts_disp'])
            self.assertTrue(events[0]['ts_disp'].startswith("2026-10-05 08:00:00"))
        finally:
            os.remove(f_name)
            
    def test_sigma_hit_record(self):
        from bluekit.logs.sigma import SigmaEngine
        
        engine = SigmaEngine(kb_path='none_existent.db')
        engine.rules = [{
            'rule_id': '1', 'title': 'Test', 'level': 'high', 'techniques': [],
            'selections': {'selection': {'message': 'test'}},
            'literals': ['test'], 'tokens': ['test'],
            'condition_expr': 'selection'
        }]
        engine.always_eval = engine.rules
        
        events = [{'ts': datetime(2026, 10, 5, 12, 0, 0), 'message': 'test', 'blob': 'test'}]
        res = engine.match_events(events)
        
        self.assertEqual(len(res['hits']), 1)
        self.assertEqual(res['hits'][0]['ts_disp'], '2026-10-05 12:00:00')

if __name__ == '__main__':
    unittest.main()
