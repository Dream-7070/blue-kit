import unittest
import os
import tempfile
import csv
from datetime import datetime, timedelta
from unittest.mock import patch
from bluekit.hunt.beacons import hunt_beacons
import bluekit.hunt.beacons

class TestHuntConn(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        
        # Original is_private_ip to keep loopback/private logic but allow TEST-NET
        self.orig_is_private = bluekit.hunt.beacons.is_private_ip
        def mock_is_private(ip_str):
            if ip_str.startswith('203.0.113.') or ip_str.startswith('198.51.100.'):
                return False
            return self.orig_is_private(ip_str)
            
        self.patcher = patch('bluekit.hunt.beacons.is_private_ip', side_effect=mock_is_private)
        self.patcher.start()
        
    def tearDown(self):
        self.patcher.stop()
        self.temp_dir.cleanup()
        
    def write_csv(self, filename, headers, rows):
        path = os.path.join(self.temp_dir.name, filename)
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
        return path

    def test_sysmon_no_ports_each_event_is_session(self):
        headers = ["@timestamp", "host.name", "source.ip", "destination.ip", "event.code", "process.name"]
        rows = []
        base_time = datetime(2026, 9, 25, 7, 0, 0)
        for i in range(60):
            ts = (base_time + timedelta(seconds=45 * i)).strftime("%Y-%m-%dT%H:%M:%SZ")
            rows.append([ts, "WIN-HOST1", "10.0.0.5", "203.0.113.50", "3", "rundll32.exe"])
            
        csv_path = self.write_csv("test1.csv", headers, rows)
        
        results = hunt_beacons([csv_path], iocs=[], allowlist_path=None, min_sessions=10, max_hosts=100)
        
        # Exact 1 result for 203.0.113.50
        dst_results = [r for r in results if r['dst_ip'] == "203.0.113.50"]
        self.assertEqual(len(dst_results), 1)
        
        res = dst_results[0]
        self.assertEqual(res['sessions'], 60)
        self.assertEqual(res['level'], 'YUQORI')
        self.assertIn('Davriylik', res['reasons'])
        self.assertNotIn('Keepalive hajmi', res['reasons'])
        self.assertTrue(abs(res['median_interval'] - 45) < 1)

    def test_sysmon_irregular_low_count_not_flagged(self):
        headers = ["@timestamp", "host.name", "source.ip", "destination.ip", "event.code", "process.name"]
        rows = []
        base_time = datetime(2026, 9, 25, 7, 0, 0)
        intervals = [37, 410, 95, 1800, 60, 3000, 7] # 7 intervals in minutes => 8 events
        
        for src_last in range(11, 16): # 10.0.0.11 to 10.0.0.15
            src_ip = f"10.0.0.{src_last}"
            current_time = base_time
            rows.append([current_time.strftime("%Y-%m-%dT%H:%M:%SZ"), "WIN-HOST2", src_ip, "198.51.100.7", "3", "rundll32.exe"])
            for m in intervals:
                current_time += timedelta(minutes=m)
                rows.append([current_time.strftime("%Y-%m-%dT%H:%M:%SZ"), "WIN-HOST2", src_ip, "198.51.100.7", "3", "rundll32.exe"])
                
        csv_path = self.write_csv("test2.csv", headers, rows)
        
        results = hunt_beacons([csv_path], iocs=[], allowlist_path=None, min_sessions=10, max_hosts=100)
        
        dst_results = [r for r in results if r['dst_ip'] == "198.51.100.7"]
        self.assertEqual(len(dst_results), 5)
        
        levels = [r['level'] for r in dst_results]
        self.assertEqual(sorted(levels), ['PAST'] * 5)

    def test_firewall_session_id_unchanged(self):
        headers = ["timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "bytes_sent", "duration", "session_id"]
        rows = []
        base_time = datetime(2023, 1, 1, 12, 0, 0)
        
        # 40 rows with session_id
        for i in range(40):
            ts = (base_time + timedelta(seconds=30 * i)).strftime("%Y-%m-%d %H:%M:%S")
            rows.append([ts, "192.168.1.100", str(10000 + i), "9.9.9.9", "443", "100", "5", f"sess{i}"])
            
        # 5 rows ESET-like
        base_time2 = datetime(2023, 1, 1, 13, 0, 0)
        for j in range(5):
            ts = (base_time2 + timedelta(minutes=7 * j)).strftime("%Y-%m-%d %H:%M:%S")
            rows.append([ts, "192.168.1.100", "", "9.9.9.9", "", "", "", ""])
            
        csv_path = self.write_csv("test3.csv", headers, rows)
        
        results = hunt_beacons([csv_path], iocs=[], allowlist_path=None, min_sessions=10, max_hosts=100)
        
        dst_results = [r for r in results if r['dst_ip'] == "9.9.9.9"]
        self.assertEqual(len(dst_results), 1)
        
        res = dst_results[0]
        self.assertEqual(res['score'], 50)
        self.assertEqual(res['level'], 'YUQORI')
        self.assertEqual(res['sessions'], 40)
        self.assertEqual(res['median_interval'], 30.0)
        self.assertEqual(res['cv_ratio'], 0.0)
        self.assertEqual(res['avg_sent'], 100.0)
        self.assertEqual(res['reasons'], ['Davriylik', 'Kam tarqalgan manzil', 'Juda kam tarqalgan'])

    def test_empty_session_id_column_is_conn_mode(self):
        headers = ["timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "bytes_sent", "duration", "session_id"]
        rows = []
        base_time = datetime(2023, 1, 1, 12, 0, 0)
        
        for i in range(30):
            ts = (base_time + timedelta(seconds=60 * i)).strftime("%Y-%m-%d %H:%M:%S")
            rows.append([ts, "10.1.1.1", "", "203.0.113.9", "", "", "", ""])
            
        csv_path = self.write_csv("test4.csv", headers, rows)
        
        results = hunt_beacons([csv_path], iocs=[], allowlist_path=None, min_sessions=10, max_hosts=100)
        
        dst_results = [r for r in results if r['dst_ip'] == "203.0.113.9"]
        self.assertEqual(len(dst_results), 1)
        
        res = dst_results[0]
        self.assertEqual(res['sessions'], 30)
        self.assertIn('Davriylik', res['reasons'])
        self.assertNotIn('Keepalive hajmi', res['reasons'])

    def test_src_port_present_keeps_tuple_key(self):
        headers = ["timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "bytes_sent", "duration", "session_id"]
        rows = []
        base_time = datetime(2023, 1, 1, 12, 0, 0)
        
        for i in range(30):
            ts = (base_time + timedelta(seconds=60 * i)).strftime("%Y-%m-%d %H:%M:%S")
            # All have SAME src_port and dst_port
            rows.append([ts, "10.1.1.2", "50000", "203.0.113.10", "443", "", "", ""])
            
        csv_path = self.write_csv("test5.csv", headers, rows)
        
        results = hunt_beacons([csv_path], iocs=[], allowlist_path=None, min_sessions=10, max_hosts=100)
        
        dst_results = [r for r in results if r['dst_ip'] == "203.0.113.10"]
        self.assertEqual(len(dst_results), 1)
        
        res = dst_results[0]
        self.assertEqual(res['sessions'], 1)
        self.assertEqual(res['level'], 'PAST')

if __name__ == '__main__':
    unittest.main()
