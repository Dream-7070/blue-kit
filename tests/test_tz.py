import unittest
import os
import subprocess
from datetime import datetime, timezone
import sys
import base64

from bluekit.tz import set_naive_tz, parse_offset
from bluekit.logs.parse import parse_ts, _parse_text_line
from bluekit.logs.qradar import load_qradar, _parse_ts as qradar_parse_ts, decode_payload, parse_fortinet_kv
from bluekit.ir.correlator import extract_canonical
from bluekit.logs.parse import load_many

class TestTZ(unittest.TestCase):
    def setUp(self):
        set_naive_tz(None)
        
    def tearDown(self):
        set_naive_tz(None)

    def test_table_cases(self):
        target = datetime(2026, 10, 5, 14, 14)
        from bluekit.tz import LOCAL_TZ
        target_aware = target.replace(tzinfo=LOCAL_TZ)
        
        # 1
        self.assertEqual(parse_ts("2026-10-05T09:14:00Z"), target)
        # 2
        self.assertEqual(parse_ts("2026-10-05T14:14:00+05:00"), target)
        # 3
        self.assertEqual(parse_ts("2026-10-05T11:14:00+02:00"), target)
        # 4
        self.assertEqual(parse_ts("2026-10-05 14:14:00"), target)
        # 5
        self.assertEqual(parse_ts("Oct 5, 2026 @ 14:14:00.000"), target)
        # 6
        self.assertEqual(parse_ts("1791191640"), target)
        # 7
        self.assertEqual(parse_ts("1791191640000"), target)
        
        # 8 Apache
        mtime = datetime.now().timestamp()
        res_apache = _parse_text_line("127.0.0.1 - - [05/Oct/2026:14:14:00 +0500] GET /", mtime)
        self.assertEqual(res_apache['timestamp'], target_aware.isoformat())
        
        # 9 Forti
        res_forti = qradar_parse_ts(None, 'forti', parse_fortinet_kv('date=2026-10-05 time=14:14:00 tz=+0500'))
        self.assertEqual(res_forti, target_aware)
        
        # 10 LEEF
        res_leef = qradar_parse_ts("Oct 05 2026 09:14:00 GMT", 'leef', {})
        self.assertEqual(res_leef, target_aware)

    def test_powershell_date(self):
        target = datetime(2026, 10, 5, 14, 14)
        self.assertEqual(parse_ts("/Date(1791191640000)/"), target)
        self.assertEqual(parse_ts(r"\/Date(1791191640000+0500)\/"), target)

    def test_aware_datetime(self):
        target = datetime(2026, 10, 5, 14, 14)
        dt = datetime(2026, 10, 5, 9, 14, tzinfo=timezone.utc)
        self.assertEqual(parse_ts(dt), target)

    def test_set_naive_utc(self):
        target = datetime(2026, 10, 5, 14, 14)
        from bluekit.tz import LOCAL_TZ
        target_aware = target.replace(tzinfo=LOCAL_TZ)
        set_naive_tz("utc")
        self.assertEqual(parse_ts("2026-10-05 09:14:00"), target)
        self.assertEqual(parse_ts("Oct 5, 2026 @ 09:14:00"), target)
        self.assertEqual(qradar_parse_ts("Oct 05 2026 09:14:00", "leef", {}), target_aware)
        # aware should not be affected
        self.assertEqual(parse_ts("2026-10-05T09:14:00Z"), target)
        self.assertEqual(parse_ts("1791191640"), target)

    def test_set_naive_minus_3(self):
        target = datetime(2026, 10, 5, 14, 14)
        set_naive_tz("-03:00")
        self.assertEqual(parse_ts("2026-10-05 06:14:00"), target)

    def test_parse_offset(self):
        self.assertEqual(parse_offset("+0530").total_seconds(), 5.5 * 3600)
        self.assertIsNone(parse_offset("+15:00"))
        self.assertIsNone(parse_offset("abc"))
        with self.assertRaises(ValueError):
            set_naive_tz("abc")

    def test_day_boundary(self):
        self.assertEqual(parse_ts("2026-10-05T21:30:00Z"), datetime(2026, 10, 6, 2, 30))

    def test_correlator_canonical(self):
        vals = [
            "2026-10-05T09:14:00Z",
            "2026-10-05T14:14:00+05:00",
            "1791191640",
            "Oct 5, 2026 @ 14:14:00.000"
        ]
        target = "2026-10-05T14:14:00+05:00"
        for v in vals:
            c = extract_canonical({"timestamp": v})
            self.assertEqual(c['timestamp'], target)

    def test_mixed_order(self):
        # We need to test load_many with mixed formats and ensure sorting is correct
        import tempfile
        import json
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f1:
            json.dump([{"@timestamp": "2026-10-05T09:20:00Z", "host": "json_ev"}], f1)
            f1_name = f1.name
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f2:
            f2.write('timestamp,host\n"Oct 5, 2026 @ 14:15:00.000",csv_ev\n')
            f2_name = f2.name
            
        events = load_many([f1_name, f2_name])
        os.unlink(f1_name)
        os.unlink(f2_name)
        
        self.assertEqual(len(events), 2)
        # csv is 14:15, json is 14:20 (09:20 UTC -> 14:20 local)
        self.assertEqual(events[0]['host'], 'csv_ev')
        self.assertEqual(events[1]['host'], 'json_ev')

    def test_cli_error(self):
        import subprocess
        bk = os.path.join(os.path.dirname(os.path.dirname(__file__)), "bk.py")
        res = subprocess.run([sys.executable, bk, "--src-tz", "abc", "logs", "analyze", "dummy"], capture_output=True)
        self.assertEqual(res.returncode, 2)

    def test_utcfromtimestamp_absence(self):
        res = subprocess.run([sys.executable, "-W", "error::DeprecationWarning", "-c", "from bluekit.logs.parse import parse_ts; parse_ts('1791191640')"])
        self.assertEqual(res.returncode, 0)

    def test_e2e_load_utc(self):
        import tempfile
        from bluekit.logs.parse import load
        from bluekit.ir.correlator import extract_canonical
        target = datetime(2026, 10, 5, 14, 14)
        set_naive_tz("utc")
        
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
            f.write("198.51.100.45 - - [05/Oct/2026:14:14:00 +0500] GET /\n")
            f.write("198.51.100.45 - - [05/Oct/2026:09:14:00 +0000] GET /\n")
            f.write("Oct  5 09:14:00 fw01 kernel: test\n")
            log_name = f.name
        
        # set mtime for syslog
        mtime_dt = datetime(2026, 10, 6, 12, 0, 0)
        os.utime(log_name, (mtime_dt.timestamp(), mtime_dt.timestamp()))
        
        events = load(log_name)
        self.assertEqual(events[0]['ts'], target) # Apache 1
        self.assertEqual(events[1]['ts'], target) # Apache 2
        self.assertEqual(events[2]['ts'], target) # Syslog
        os.unlink(log_name)

        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
            # mock qradar csv structure. row[10] base64 payload.
            payload1 = base64.b64encode(b'date=2026-10-05 time=14:14:00 tz=+0500 devname=FGT srcip=10.0.0.1 msg="test"').decode()
            payload2 = base64.b64encode(b'LEEF:1.0|Vendor|Prod|1|Rule|devTime=Oct 05 2026 09:14:00	src=10.0.0.2').decode()
            payload3 = base64.b64encode(b'LEEF:1.0|Vendor|Prod|1|Rule|devTime=Oct 05 2026 09:14:00 GMT	src=10.0.0.3').decode()
            cols = ['' for _ in range(62)]
            cols[0] = 'eventtime1'
            cols[10] = payload1
            f.write(','.join(cols) + '\n')
            cols[0] = 'eventtime2'
            cols[10] = payload2
            f.write(','.join(cols) + '\n')
            cols[0] = 'eventtime3'
            cols[10] = payload3
            f.write(','.join(cols) + '\n')
            csv_name = f.name
            
        evs_q = load(csv_name)
        self.assertEqual(evs_q[0]['ts'], target)
        self.assertEqual(evs_q[1]['ts'], target)
        self.assertEqual(evs_q[2]['ts'], target)
        
        # korrelyator yo'li: load_qradar -> extract_canonical (spec 5-holat)
        from bluekit.logs.qradar import load_qradar
        from bluekit.hunt.beacon_math import parse_dt
        for q in load_qradar(csv_name):
            ts_c = extract_canonical(q)['timestamp']
            self.assertEqual(ts_c, "2026-10-05T14:14:00+05:00")
            self.assertEqual(parse_dt(ts_c), target)  # qayta o'qish ikkinchi marta surmaydi
        os.unlink(csv_name)

    def test_e2e_load_default(self):
        import tempfile
        from bluekit.logs.parse import load
        from bluekit.ir.correlator import extract_canonical
        target = datetime(2026, 10, 5, 14, 14)
        target_naive = datetime(2026, 10, 5, 9, 14) # Default mode +0500: zoneless 09:14 -> 09:14
        set_naive_tz(None)
        
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
            f.write("198.51.100.45 - - [05/Oct/2026:14:14:00 +0500] GET /\n")
            f.write("198.51.100.45 - - [05/Oct/2026:09:14:00 +0000] GET /\n")
            f.write("Oct  5 09:14:00 fw01 kernel: test\n")
            log_name = f.name
        
        # set mtime for syslog
        mtime_dt = datetime(2026, 10, 6, 12, 0, 0)
        os.utime(log_name, (mtime_dt.timestamp(), mtime_dt.timestamp()))
        
        events = load(log_name)
        self.assertEqual(events[1]['ts'], target) # Apache 1 (+0500)
        self.assertEqual(events[2]['ts'], target) # Apache 2 (+0000)
        self.assertEqual(events[0]['ts'], target_naive) # Syslog (naive) -> sorts before 14:14
        os.unlink(log_name)

        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
            payload1 = base64.b64encode(b'date=2026-10-05 time=14:14:00 tz=+0500 devname=FGT srcip=10.0.0.1 msg="test"').decode()
            payload2 = base64.b64encode(b'LEEF:1.0|Vendor|Prod|1|Rule|devTime=Oct 05 2026 09:14:00	src=10.0.0.2').decode()
            payload3 = base64.b64encode(b'LEEF:1.0|Vendor|Prod|1|Rule|devTime=Oct 05 2026 09:14:00 GMT	src=10.0.0.3').decode()
            cols = ['' for _ in range(62)]
            cols[0] = 'eventtime1'
            cols[10] = payload1
            f.write(','.join(cols) + '\n')
            cols[0] = 'eventtime2'
            cols[10] = payload2
            f.write(','.join(cols) + '\n')
            cols[0] = 'eventtime3'
            cols[10] = payload3
            f.write(','.join(cols) + '\n')
            csv_name = f.name
            
        evs_q = load(csv_name)
        self.assertEqual(evs_q[1]['ts'], target) # Forti +0500
        self.assertEqual(evs_q[0]['ts'], target_naive) # LEEF zoneless naive -> sorts first (09:14)
        self.assertEqual(evs_q[2]['ts'], target) # LEEF GMT
        os.unlink(csv_name)
