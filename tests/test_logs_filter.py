import unittest
import os
import tempfile
import sys
import subprocess
from datetime import datetime, timedelta
import json
import bluekit.tz
from bluekit.logs.filter import parse_bound, filter_events, describe
from bluekit.logs.parse import load
from bluekit.logs.report import analyze_logs
from bluekit.kb.query import KB

class TestLogsFilter(unittest.TestCase):
    def setUp(self):
        self.sample_csv = os.path.join(os.path.dirname(__file__), '..', 'data', 'samples', 'win_phishing.csv')
        self.events = load(self.sample_csv)

    def test_filter_host(self):
        self.assertEqual(len(filter_events(self.events, host='hr-pc01')), 15)
        self.assertEqual(len(filter_events(self.events, host='DC01')), 7)
        self.assertEqual(len(filter_events(self.events, host='  dc01 ')), 7)
        self.assertEqual(len(filter_events(self.events, host='HR-PC0')), 0)
        self.assertEqual(len(filter_events(self.events, host='PC01')), 0)

    def test_naive_window(self):
        f_dt = parse_bound('2026-10-05 14:20:00')
        t_dt = parse_bound('2026-10-05 14:21:30', end=True)
        filtered = filter_events(self.events, from_dt=f_dt, to_dt=t_dt)
        self.assertEqual(len(filtered), 8)
        from collections import Counter
        hosts = Counter(e.get('host') for e in filtered)
        self.assertEqual(dict(hosts), {'DC01': 7, 'HR-PC01': 1})

    def test_zulu_window(self):
        f_dt = parse_bound('2026-10-05T09:20:00Z')
        t_dt = parse_bound('2026-10-05T09:21:30Z', end=True)
        filtered = filter_events(self.events, from_dt=f_dt, to_dt=t_dt)
        self.assertEqual(len(filtered), 8)

    def test_offset_window(self):
        f_dt = parse_bound('2026-10-05T12:20:00+03:00')
        t_dt = parse_bound('2026-10-05T12:21:30+03:00', end=True)
        filtered = filter_events(self.events, from_dt=f_dt, to_dt=t_dt)
        self.assertEqual(len(filtered), 8)

    def test_naive_utc(self):
        self.addCleanup(bluekit.tz.set_naive_tz, None)
        bluekit.tz.set_naive_tz('utc')
        f_dt = parse_bound('2026-10-05 09:20:00')
        t_dt = parse_bound('2026-10-05 09:21:30', end=True)
        filtered = filter_events(self.events, from_dt=f_dt, to_dt=t_dt)
        self.assertEqual(len(filtered), 8)
        self.assertEqual(parse_bound('2026-10-05 09:20:00'), datetime(2026, 10, 5, 14, 20, 0))

    def test_default_naive(self):
        self.addCleanup(bluekit.tz.set_naive_tz, None)
        bluekit.tz.set_naive_tz('+05:00')
        self.assertEqual(parse_bound('2026-10-05 14:20:00'), datetime(2026, 10, 5, 14, 20, 0))
        self.assertEqual(parse_bound('2026-10-05T09:20:00Z'), datetime(2026, 10, 5, 14, 20, 0))

    def test_half_bounds(self):
        self.assertEqual(len(filter_events(self.events, from_dt=parse_bound('2026-10-05 14:31:00'))), 3)
        self.assertEqual(len(filter_events(self.events, to_dt=parse_bound('2026-10-05 14:01:12', end=True))), 2)

    def test_host_and_from(self):
        filtered = filter_events(self.events, host='DC01', from_dt=parse_bound('2026-10-05 14:21:00'))
        self.assertEqual(len(filtered), 2)

    def test_date_only(self):
        self.assertEqual(len(filter_events(self.events, to_dt=parse_bound('2026-10-05', end=True))), 33)
        self.assertEqual(parse_bound('2026-10-05', end=True), datetime(2026, 10, 5, 23, 59, 59, 999999))
        self.assertEqual(len(filter_events(self.events, from_dt=parse_bound('2026-10-06'))), 0)

    def test_invalid_bounds(self):
        for v in ['notadate', '', '1759654800', '05.10.2026 14:20', '2026-13-01']:
            with self.assertRaises(ValueError):
                parse_bound(v)

    def test_no_ts_event(self):
        fd, path = tempfile.mkstemp(suffix='.csv')
        os.close(fd)
        try:
            with open(path, 'w') as f:
                f.write("@timestamp,host.name,process.command_line\n")
                f.write("2026-10-05T09:00:00Z,WS1,cmd.exe\n")
                f.write(" ,WS1,cmd.exe\n")
            evs = load(path)
            self.assertEqual(len(evs), 2)
            self.assertEqual(len(filter_events(evs, host='ws1')), 2)
            self.assertEqual(len(filter_events(evs, from_dt=parse_bound('2026-10-05 00:00'))), 1)
        finally:
            os.remove(path)

    def test_input_list_unchanged(self):
        orig_len = len(self.events)
        filter_events(self.events, host='HR-PC01')
        self.assertEqual(len(self.events), orig_len)

    def test_describe(self):
        self.assertIsNone(describe(None, None, None))
        self.assertEqual(describe(datetime(2026, 10, 5, 14, 20), None, 'DC01'), 'host=DC01, 2026-10-05 14:20:00 .. ...')

    def test_analyze_logs_with_filter(self):
        try:
            kb = KB()
        except Exception:
            self.skipTest("KB fail")
        fd, tmp = tempfile.mkstemp(suffix='.json')
        os.close(fd)
        try:
            analyze_logs(self.sample_csv, kb, json_path=tmp, host='DC01')
            with open(tmp, 'r') as f:
                data = json.load(f)
            self.assertEqual(data['stats']['events'], 7)
            self.assertEqual(data['stats']['filter'], {'from': None, 'to': None, 'host': 'DC01', 'loaded': 33})
            self.assertGreater(len(data['timeline']), 0)
            for item in data['timeline']:
                self.assertEqual(item['host'], 'DC01')
        finally:
            os.remove(tmp)

    def test_analyze_logs_no_filter(self):
        try:
            kb = KB()
        except Exception:
            self.skipTest("KB fail")
        fd, tmp = tempfile.mkstemp(suffix='.json')
        os.close(fd)
        try:
            analyze_logs(self.sample_csv, kb, json_path=tmp)
            with open(tmp, 'r') as f:
                data = json.load(f)
            self.assertEqual(data['stats']['events'], 33)
            self.assertNotIn('filter', data['stats'])
        finally:
            os.remove(tmp)

    def test_cli_invalid_date(self):
        res = subprocess.run([sys.executable, 'bk.py', 'logs', 'analyze', 'data/samples/win_phishing.csv', '--from', 'notadate'], 
                             cwd=os.path.join(os.path.dirname(__file__), '..'), capture_output=True, text=True, timeout=120)
        self.assertEqual(res.returncode, 2)
        self.assertIn('notadate', res.stderr)

    def test_cli_inverted_dates(self):
        res = subprocess.run([sys.executable, 'bk.py', 'logs', 'analyze', 'data/samples/win_phishing.csv', '--from', '2026-10-05 15:00', '--to', '2026-10-05 14:00'], 
                             cwd=os.path.join(os.path.dirname(__file__), '..'), capture_output=True, text=True, timeout=120)
        self.assertEqual(res.returncode, 2)

    def test_cli_valid_host(self):
        try:
            KB()
        except Exception:
            self.skipTest("KB fail")
        fd, tmp = tempfile.mkstemp(suffix='.json')
        os.close(fd)
        try:
            res = subprocess.run([sys.executable, 'bk.py', 'logs', 'analyze', 'data/samples/win_phishing.csv', '--host', 'DC01', '--json-out', tmp], 
                                 cwd=os.path.join(os.path.dirname(__file__), '..'), capture_output=True, text=True, timeout=120)
            self.assertEqual(res.returncode, 0)
            self.assertIn('-> 7/33 hodisa', res.stdout)
            with open(tmp, 'r') as f:
                data = json.load(f)
            self.assertEqual(data['stats']['events'], 7)
        finally:
            os.remove(tmp)
