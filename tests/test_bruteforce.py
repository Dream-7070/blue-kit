import unittest
from datetime import datetime, timedelta
import io
import contextlib
import csv
import os

from bluekit.logs.bruteforce import correlate_bruteforce
from bluekit.logs.report import analyze_logs
from bluekit.kb.query import KB
try:
    from bluekit.paths import get_kb_path
except ImportError:
    get_kb_path = None

def ev(ts_str, eid, src_ip='45.9.148.200', target='administrator', host='RDP-GW', channel='Security', user=None):
    return {
        'ts': datetime.fromisoformat(ts_str) if ts_str else None,
        'event_id': eid,
        'src_ip': src_ip,
        'target': target,
        'host': host,
        'channel': channel,
        'user': user,
        'message': '',
        'command_line': None
    }

class TestBruteforce(unittest.TestCase):
    
    def test_rdp_brute_then_success(self):
        events = []
        hits = {}
        ts = datetime(2026, 9, 25, 6, 10, 0)
        
        for i in range(40):
            events.append(ev(ts.isoformat(), '4625'))
            ts += timedelta(seconds=9)
            
        success_ts = ts + timedelta(minutes=7)
        events.append(ev(success_ts.isoformat(), '4624'))
        
        res = correlate_bruteforce(events, hits)
        
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['failures'], 40)
        self.assertTrue(res[0]['success'])
        self.assertEqual(res[0]['technique'], 'T1110.001')
        
        count_4625_hits = 0
        for i in range(40):
            self.assertTrue(i in hits)
            h = hits[i][0]
            self.assertEqual(h['technique'], 'T1110.001')
            self.assertEqual(h['confidence'], 'high')
            self.assertEqual(h['source'], 'correlation')
            count_4625_hits += 1
        self.assertEqual(count_4625_hits, 40)
        
        self.assertTrue(40 in hits)
        success_hit = hits[40][0]
        self.assertEqual(success_hit['technique'], 'T1110.001')
        self.assertIn('MUVAFFAQIYATLI', success_hit['evidence'])

    def test_below_threshold(self):
        events = []
        hits = {}
        ts = datetime(2026, 9, 25, 6, 10, 0)
        for i in range(9):
            events.append(ev(ts.isoformat(), '4625'))
            ts += timedelta(seconds=6)
            
        res = correlate_bruteforce(events, hits)
        self.assertEqual(res, [])
        self.assertEqual(hits, {})

    def test_spread_out_not_burst(self):
        events = []
        hits = {}
        ts = datetime(2026, 9, 25, 6, 10, 0)
        for i in range(12):
            events.append(ev(ts.isoformat(), '4625'))
            ts += timedelta(minutes=2, seconds=30)
            
        res = correlate_bruteforce(events, hits)
        self.assertEqual(res, [])

    def test_password_spraying(self):
        events = []
        hits = {}
        ts = datetime(2026, 9, 25, 6, 10, 0)
        
        for i in range(20):
            events.append(ev(ts.isoformat(), '4625', target=f'user{i+1:02d}'))
            ts += timedelta(seconds=15)
            
        res = correlate_bruteforce(events, hits)
        
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['technique'], 'T1110.003')
        
        count_t1110_003 = 0
        count_t1110_001 = 0
        for i in range(20):
            for h in hits.get(i, []):
                if h['technique'] == 'T1110.003': count_t1110_003 += 1
                if h['technique'] == 'T1110.001': count_t1110_001 += 1
                
        self.assertEqual(count_t1110_003, 20)
        self.assertEqual(count_t1110_001, 0)

    def test_host_user_fallback_without_ip(self):
        events = []
        hits = {}
        ts = datetime(2026, 9, 25, 6, 10, 0)
        
        for i in range(15):
            events.append(ev(ts.isoformat(), '4625', src_ip='-', host='DC1', target='bob'))
            ts += timedelta(seconds=20)
            
        res = correlate_bruteforce(events, hits)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]['key_type'], 'host_user')
        
        count = sum(1 for i in range(15) if hits.get(i) and hits[i][0]['technique'] == 'T1110.001')
        self.assertEqual(count, 15)

    def test_many_ips_few_each(self):
        events = []
        hits = {}
        ts = datetime(2026, 9, 25, 6, 10, 0)
        
        for ip in ['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5']:
            for _ in range(4):
                events.append(ev(ts.isoformat(), '4625', src_ip=ip))
                ts += timedelta(seconds=15)
                
        res = correlate_bruteforce(events, hits)
        self.assertEqual(res, [])

    def test_success_outside_window(self):
        events = []
        hits = {}
        ts = datetime(2026, 9, 25, 6, 10, 0)
        for i in range(40):
            events.append(ev(ts.isoformat(), '4625'))
            ts += timedelta(seconds=9)
            
        success_ts = ts + timedelta(hours=2)
        events.append(ev(success_ts.isoformat(), '4624'))
        
        res = correlate_bruteforce(events, hits)
        self.assertFalse(res[0]['success'])
        self.assertNotIn(40, hits)

    def test_existing_hits_preserved_and_not_duplicated(self):
        events = []
        hits = {0: [
            {'technique':'T1110','confidence':'low','source':'heuristic','evidence':'x'},
            {'technique':'T1110.001','confidence':'high','source':'heuristic','evidence':'KB search match on: x','name':'Password Guessing','score':0.5}
        ]}
        
        ts = datetime(2026, 9, 25, 6, 10, 0)
        for i in range(40):
            events.append(ev(ts.isoformat(), '4625'))
            ts += timedelta(seconds=9)
            
        correlate_bruteforce(events, hits)
        
        h0 = hits[0]
        self.assertTrue(any(h['technique'] == 'T1110' and h['confidence'] == 'low' for h in h0))
        
        t1110_001_hits = [h for h in h0 if h['technique'] == 'T1110.001']
        self.assertEqual(len(t1110_001_hits), 1)
        self.assertEqual(t1110_001_hits[0]['source'], 'correlation')

    def test_channel_filter(self):
        events = []
        hits = {}
        ts = datetime(2026, 9, 25, 6, 10, 0)
        for i in range(40):
            events.append(ev(ts.isoformat(), '4625', channel='Microsoft-Windows-Sysmon/Operational'))
            ts += timedelta(seconds=9)
            
        res = correlate_bruteforce(events, hits)
        self.assertEqual(res, [])

    def test_end_to_end_scn01_message_blanked(self):
        if not get_kb_path:
            self.skipTest("bluekit.paths.get_kb_path not found")
        kb_path = get_kb_path()
        if not kb_path:
            self.skipTest("KB path is empty")
            
        src_csv = r"D:\Claude Projects\CTF\mashq\2026-10-01-scn01-ransomware\events\collector_all_hosts.csv"
        if not os.path.exists(src_csv):
            self.skipTest(f"Source CSV {src_csv} not found")
            
        import tempfile, json
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv', newline='', encoding='utf-8') as tmp_out:
            tmp_csv = tmp_out.name
            with open(src_csv, 'r', encoding='utf-8') as fin:
                reader = csv.reader(fin)
                writer = csv.writer(tmp_out)
                header = next(reader)
                writer.writerow(header)
                
                try:
                    msg_idx = header.index('message')
                except ValueError:
                    msg_idx = -1
                    
                for row in reader:
                    if msg_idx != -1 and msg_idx < len(row):
                        row[msg_idx] = ''
                    writer.writerow(row)
                    
        tmp_json = tmp_csv + '.json'
        
        f = io.StringIO()
        with contextlib.redirect_stdout(f):
            analyze_logs(tmp_csv, KB(kb_path), json_path=tmp_json)
            
        with open(tmp_json, 'r', encoding='utf-8') as jf:
            data = json.load(jf)
            
        count_4625_high = 0
        success_found = False
        
        for t in data.get('timeline', []):
            is_4625 = t.get('raw', {}).get('event.code') == '4625'
            is_4624 = t.get('raw', {}).get('event.code') == '4624'
            
            if is_4625:
                for h in t.get('techniques', []):
                    if h.get('technique') == 'T1110.001' and h.get('confidence') == 'high':
                        count_4625_high += 1
                        
            if is_4624:
                for h in t.get('techniques', []):
                    if h.get('technique') == 'T1110.001' and 'MUVAFFAQIYATLI' in h.get('evidence', ''):
                        success_found = True
                        
        self.assertEqual(count_4625_high, 40)
        self.assertTrue(success_found)
        
        bf = data.get('bruteforce', [])
        self.assertEqual(len(bf), 1)
        self.assertEqual(bf[0]['failures'], 40)
        self.assertTrue(bf[0]['success'])
        self.assertEqual(bf[0]['source'], '45.9.148.200')
        
        os.remove(tmp_csv)
        os.remove(tmp_json)

if __name__ == '__main__':
    unittest.main()
