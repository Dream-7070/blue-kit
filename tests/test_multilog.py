import unittest
import tempfile
import os
import json
from datetime import datetime
from bluekit.logs.parse import load_rows, load, load_many
from bluekit.logs.report import analyze_logs
from bluekit.kb.query import KB

class TestMultilog(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        try:
            self.kb = KB()
        except Exception:
            self.skipTest("KB not available")
        
        self.siem_path = os.path.join(self.tmp.name, 'siem.json')
        self.nginx_path = os.path.join(self.tmp.name, 'nginx_access.log')
        self.fw_path = os.path.join(self.tmp.name, 'firewall.log')
        self.mail_path = os.path.join(self.tmp.name, 'mail.log')
        
        with open(self.siem_path, 'w', encoding='utf-8') as f:
            f.write('{"hits":{"hits":[{"_source":{"@timestamp":"2026-10-05T09:01:10Z","host":{"name":"hr-pc-01"},"event":{"code":4688},"process":{"name":"powershell.exe","command_line":"powershell -enc SQBFAFgA..."},"user":{"name":"hr.anna"}}}]}}')
            
        with open(self.nginx_path, 'w', encoding='utf-8') as f:
            f.write('198.51.100.45 - - [05/Oct/2026:09:10:11 +0000] "POST /api/v1/upload_avatar.php HTTP/1.1" 200 512 "-" "curl/7.68"\n')
            f.write('shell.php?cmd=whoami\n')
            f.write('UNION SELECT\n')
            
        with open(self.fw_path, 'w', encoding='utf-8') as f:
            f.write('Oct  5 09:11:02 fw01 kernel: DROP IN=eth0 SRC=198.51.100.45 DST=10.0.1.15 PROTO=TCP SPT=4444 DPT=22\n')
            
        with open(self.mail_path, 'w', encoding='utf-8') as f:
            f.write('Oct  5 08:55:12 mail postfix/smtpd[1234]: NOQUEUE: reject: RCPT from unknown[198.51.100.45]: 554 5.7.1 Relay access denied\n')
            
        mtime_dt = datetime(2026, 10, 6, 12, 0, 0)
        mtime = mtime_dt.timestamp()
        os.utime(self.fw_path, (mtime, mtime))
        os.utime(self.mail_path, (mtime, mtime))

    def tearDown(self):
        self.tmp.cleanup()

    def test_apache_line(self):
        events = load(self.nginx_path)
        self.assertEqual(len(events), 3)
        self.assertEqual(events[0]['ts'], datetime(2026, 10, 5, 14, 10, 11))
        self.assertEqual(events[0]['src_ip'], '198.51.100.45')
        
    def test_apache_offset(self):
        p = os.path.join(self.tmp.name, 'offset.log')
        with open(p, 'w', encoding='utf-8') as f:
            f.write('198.51.100.45 - - [05/Oct/2026:09:10:11 +0500] "GET /" 200 5\n')
        events = load(p)
        self.assertEqual(events[0]['ts'], datetime(2026, 10, 5, 9, 10, 11))
        
    def test_syslog_line(self):
        events = load(self.fw_path)
        self.assertEqual(events[0]['ts'], datetime(2026, 10, 5, 9, 11, 2))
        self.assertEqual(events[0]['host'], 'fw01')
        self.assertEqual(events[0]['src_ip'], '198.51.100.45')
        self.assertEqual(events[0]['dest_ip'], '10.0.1.15')
        
    def test_year_boundary(self):
        p = os.path.join(self.tmp.name, 'year.log')
        with open(p, 'w', encoding='utf-8') as f:
            f.write('Dec 31 23:59:00 hostx msg\n')
        dt = datetime(2027, 1, 2, 12, 0, 0)
        os.utime(p, (dt.timestamp(), dt.timestamp()))
        events = load(p)
        self.assertEqual(events[0]['ts'], datetime(2026, 12, 31, 23, 59, 0))
        
    def test_postfix_line(self):
        events = load(self.mail_path)
        self.assertEqual(events[0]['ts'], datetime(2026, 10, 5, 8, 55, 12))
        self.assertEqual(events[0]['host'], 'mail')
        self.assertEqual(events[0]['src_ip'], '198.51.100.45')
        
        p = os.path.join(self.tmp.name, 'postfix2.log')
        with open(p, 'w', encoding='utf-8') as f:
            f.write('Oct  5 08:55:12 mail postfix/smtpd: from unknown[unknown]: ...\n')
        dt = datetime(2026, 10, 6, 12, 0, 0)
        os.utime(p, (dt.timestamp(), dt.timestamp()))
        e = load(p)
        self.assertIsNone(e[0]['src_ip'])
        
    def test_invalid_date(self):
        p = os.path.join(self.tmp.name, 'inv.log')
        with open(p, 'w', encoding='utf-8') as f:
            f.write('Feb 31 10:00:00 h x\n')
        e = load(p)
        self.assertEqual(len(e), 1)
        self.assertIsNone(e[0]['ts'])
        self.assertEqual(e[0]['host'], 'h')
        
    def test_load_many(self):
        files = [self.fw_path, self.mail_path, self.siem_path, self.nginx_path]
        events = load_many(files)
        self.assertEqual(len(events), 6)
        self.assertEqual(events[0]['source'], 'mail.log')
        for e in events:
            if e['source'] == 'nginx_access.log' and e['ts'] is None:
                self.assertEqual(e['host'], '[nginx_access.log]')
                
    def test_load_many_reverse(self):
        files = [self.nginx_path, self.siem_path, self.mail_path, self.fw_path]
        events = load_many(files)
        self.assertEqual(len(events), 6)
        self.assertEqual(events[0]['source'], 'mail.log')
        self.assertEqual(events[1]['source'], 'firewall.log')
        self.assertEqual(events[2]['source'], 'siem.json')
        self.assertEqual(events[3]['source'], 'nginx_access.log')
        
    def test_analyze_logs(self):
        files = [self.fw_path, self.mail_path, self.siem_path, self.nginx_path]
        out_json = os.path.join(self.tmp.name, 'out.json')
        analyze_logs(files, self.kb, json_path=out_json)
        with open(out_json, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.assertEqual(len(data['stats']['sources']), 4)
        
        ioc_ip = next((x for x in data['iocs'] if x['value'] == '198.51.100.45'), None)
        self.assertIsNotNone(ioc_ip)
        self.assertEqual(len(ioc_ip['sources']), 3)
        self.assertIn('firewall.log', ioc_ip['sources'])
        self.assertIn('mail.log', ioc_ip['sources'])
        self.assertIn('nginx_access.log', ioc_ip['sources'])
        
        tl_siem = next(x for x in data['timeline'] if x['source'] == 'siem.json')
        tl_nginx = next(x for x in data['timeline'] if x['source'] == 'nginx_access.log' and x['techniques'])
        
        techs_siem = [t['technique'] for t in tl_siem['techniques']]
        techs_nginx = [t['technique'] for t in tl_nginx['techniques']]
        self.assertIn('T1059.001', techs_siem)
        self.assertIn('T1505.003', techs_nginx)
        
    def test_order_independent_of_file_order(self):
        fwd = load_many([self.fw_path, self.mail_path, self.siem_path, self.nginx_path])
        rev = load_many([self.nginx_path, self.siem_path, self.mail_path, self.fw_path])
        key = lambda evs: [(e['ts'], e['source']) for e in evs if e['ts']]
        self.assertEqual(key(fwd), key(rev))
        self.assertEqual(key(fwd), sorted(key(fwd)))

    def test_split_preset(self):
        from bluekit.logs.parse import split_preset
        self.assertEqual(split_preset('a/siem.json@ecs'), ('a/siem.json', 'ecs'))
        self.assertEqual(split_preset('a/siem.json'), ('a/siem.json', None))
        self.assertEqual(split_preset('mail@corp.log'), ('mail@corp.log', None))

    def test_list_with_preset_tuple(self):
        evs = load_many([(self.siem_path, 'ecs'), self.mail_path])
        self.assertEqual({e['source'] for e in evs}, {'siem.json', 'mail.log'})

    def test_regression_single_file(self):
        events, tl, ch, iocs, chk = analyze_logs(self.fw_path, self.kb)
        self.assertEqual(len(events), 1)
        self.assertEqual(len(tl), 1)

if __name__ == '__main__':
    unittest.main()
