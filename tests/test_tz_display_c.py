import unittest
from datetime import datetime
from bluekit.logs.filter import parse_bound
from bluekit.tz import set_naive_tz
import os
import tempfile
import json
import subprocess

class TestTzDisplayC(unittest.TestCase):
    def setUp(self):
        set_naive_tz(None)
        
    def tearDown(self):
        set_naive_tz(None)

    def test_filter_parse_bound(self):
        self.assertEqual(parse_bound('2026-09-18 08:00:02 UTC'), datetime(2026, 9, 18, 13, 0, 2))
        self.assertEqual(parse_bound('2026-09-18 08:00:02 UTC (Toshkent 13:00:02)'), datetime(2026, 9, 18, 13, 0, 2))
        self.assertEqual(parse_bound('2026-10-05 11:20:00 +03:00 (Toshkent 13:20:00)'), datetime(2026, 10, 5, 13, 20, 0))
        self.assertEqual(parse_bound('2026-10-05 11:20 -0300'), datetime(2026, 10, 5, 19, 20, 0))
        self.assertEqual(parse_bound('2026-10-05 14:20'), datetime(2026, 10, 5, 14, 20, 0))
        self.assertEqual(parse_bound('2026-10-05', end=True), datetime(2026, 10, 5, 23, 59, 59, 999999))
        self.assertEqual(parse_bound('2026-10-05T09:20:00Z'), datetime(2026, 10, 5, 14, 20, 0))
        with self.assertRaises(ValueError):
            parse_bound('05.10.2026')

    def test_logs_analyze_cli(self):
        import sys
        with tempfile.TemporaryDirectory() as td:
            csv_path = os.path.join(td, 'test.csv')
            with open(csv_path, 'w', encoding='utf-8') as f:
                f.write("timestamp,host,message,command_line,src_ip,dest_ip\n")
                f.write("2026-10-05T08:00:00Z,host1,msg1,cmd1,1.1.1.1,2.2.2.2\n")
                f.write("2026-10-05T08:05:00Z,host1,msg2,cmd2,1.1.1.1,2.2.2.2\n")
            
            json_out = os.path.join(td, 'out.json')
            cmd = [sys.executable, 'bk.py', 'logs', 'analyze', csv_path, '--json-out', json_out]
            res = subprocess.run(cmd, capture_output=True, text=True, cwd=r'D:\Claude Projects\CTF\blue-kit-staging')
            self.assertEqual(res.returncode, 0, msg=res.stderr)
            
            with open(json_out, 'r', encoding='utf-8') as f:
                out = json.load(f)
                
            iocs = out.get('iocs', [])
            ip_iocs = [i for i in iocs if i['type'] == 'ip' and i['value'] == '1.1.1.1']
            self.assertEqual(len(ip_iocs), 1)
            
            ip_ioc = ip_iocs[0]
            self.assertEqual(ip_ioc['first_disp'], '2026-10-05 08:00:00 UTC (Toshkent 13:00:00)')
            self.assertEqual(ip_ioc['last_disp'], '2026-10-05 08:05:00 UTC (Toshkent 13:05:00)')

            cmd2 = [sys.executable, 'bk.py', 'logs', 'analyze', csv_path, '--from', '2026-10-05 08:00:00 UTC', '--to', '2026-10-05 08:02:00 UTC', '--json-out', json_out]
            res2 = subprocess.run(cmd2, capture_output=True, text=True, cwd=r'D:\Claude Projects\CTF\blue-kit-staging')
            self.assertEqual(res2.returncode, 0, msg=res2.stderr)

            with open(json_out, 'r', encoding='utf-8') as f:
                out2 = json.load(f)

            timeline = out2.get('timeline', [])
            self.assertEqual(len(timeline), 1)

    def test_correlate_bruteforce(self):
        from bluekit.logs.bruteforce import correlate_bruteforce
        events = []
        for i in range(10):
            events.append({
                'event_id': '4625',
                'ts': datetime(2026, 10, 5, 12, i),
                'ts_disp': f'disp_{i}',
                'channel': 'Security',
                'target': 'admin',
                'src_ip': '1.1.1.1',
                'host': 'host1'
            })
            
        hits_by_index = {}
        bursts = correlate_bruteforce(events, hits_by_index)
        self.assertEqual(len(bursts), 1)
        self.assertEqual(bursts[0]['first_disp'], 'disp_0')

if __name__ == '__main__':
    unittest.main()
