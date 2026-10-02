import os
import tempfile
import unittest
from datetime import datetime

from bluekit.logs.parse import parse_ts, load
from bluekit.hunt.beacon_math import parse_dt
from bluekit.ir.correlator import extract_canonical


class TestParseTsExtra(unittest.TestCase):
    def test_kibana_csv_formats(self):
        self.assertEqual(parse_ts("Oct 5, 2026 @ 09:14:00.123"), datetime(2026, 10, 5, 9, 14, 0, 123000))
        self.assertEqual(parse_ts("Oct 05, 2026 @ 09:14:07"), datetime(2026, 10, 5, 9, 14, 7))
        self.assertEqual(parse_ts("Sep 30, 2026 @ 23:59:59.999999"), datetime(2026, 9, 30, 23, 59, 59, 999999))
        self.assertEqual(parse_ts("October 6, 2026 @ 10:00"), datetime(2026, 10, 6, 10, 0, 0))

    def test_russian_excel_formats(self):
        self.assertEqual(parse_ts("05.10.2026 09:14:00"), datetime(2026, 10, 5, 9, 14, 0))
        self.assertEqual(parse_ts("5.10.2026 9:14"), datetime(2026, 10, 5, 9, 14, 0))
        self.assertEqual(parse_ts("06.10.2026, 13:05:09,250"), datetime(2026, 10, 6, 13, 5, 9, 250000))

    def test_day_month_not_swapped(self):
        # 01.02 = 1-fevral (rus tartibi), 1-yanvar emas
        self.assertEqual(parse_ts("01.02.2026 00:00:00"), datetime(2026, 2, 1))

    def test_invalid_stays_none(self):
        for bad in ["Foo 5, 2026 @ 09:14:00", "31.02.2026 09:00:00", "Oct 5, 2026", "hello", "32.13.2026 10:00"]:
            self.assertIsNone(parse_ts(bad), bad)

    def test_existing_formats_unchanged(self):
        self.assertEqual(parse_ts("2026-10-05T09:14:00Z"), datetime(2026, 10, 5, 14, 14, 0))
        self.assertEqual(parse_ts("2026-10-05 09:14:00"), datetime(2026, 10, 5, 9, 14, 0))
        self.assertEqual(parse_ts("10/05/2026 09:14:00 AM"), datetime(2026, 10, 5, 9, 14, 0))
        self.assertEqual(parse_ts("1791191640"), datetime(2026, 10, 5, 14, 14, 0))

    def test_beacon_parse_dt(self):
        self.assertEqual(parse_dt("Oct 5, 2026 @ 09:14:00.000"), datetime(2026, 10, 5, 9, 14))
        self.assertEqual(parse_dt("not a date"), "not a date")

    def test_correlator_normalizes_only_non_iso(self):
        self.assertEqual(extract_canonical({"@timestamp": "Oct 10, 2026 @ 09:14:00.000"})["timestamp"], "2026-10-10T09:14:00+05:00")
        self.assertEqual(extract_canonical({"@timestamp": "05.10.2026 09:14:00"})["timestamp"], "2026-10-05T09:14:00+05:00")
        # Endi ISO va epoch ham normallashadi
        self.assertEqual(extract_canonical({"@timestamp": "2026-10-05T09:14:00Z"})["timestamp"], "2026-10-05T14:14:00+05:00")
        self.assertEqual(extract_canonical({"@timestamp": "1791191640"})["timestamp"], "2026-10-05T14:14:00+05:00")

    def test_kibana_csv_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "kib.csv")
            with open(p, "w", encoding="utf-8") as f:
                f.write('@timestamp,host.name,process.command_line\n'
                        '"Oct 5, 2026 @ 09:20:00.000",WS07,whoami\n'
                        '"Oct 5, 2026 @ 09:14:00.123",WS07,powershell -enc SQBFAFgA\n')
            events = load(p)
            ts = sorted(e["ts"] for e in events)
            self.assertEqual(len(ts), 2)
            self.assertTrue(all(isinstance(t, datetime) for t in ts))
            self.assertEqual(ts[0], datetime(2026, 10, 5, 9, 14, 0, 123000))


if __name__ == "__main__":
    unittest.main()
