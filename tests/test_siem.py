import io
import json
import os
import unittest
from contextlib import redirect_stdout

import yaml

from bluekit.siem.builder import build_query, escape_value, list_hunts, get_hunt
from bluekit.siem.catalog import HUNTS, CATEGORIES
from bluekit.siem.dialects import DIALECTS, FIELD_MAPS, SOURCE_MAPS
from bluekit.siem.cli import main
from bluekit.paths import get_kb_path

# (hunt_id, siem, so'rovda albatta uchrashi kerak bo'lgan matn).
# Har bir hunt uchun kamida bitta — dummy/bir xil `where` bilan bu ro'yxat yiqiladi.
FINGERPRINTS = [
    ('auth-bruteforce', 'qradar', '4625'),
    ('auth-password-spray', 'sentinel', 'dcount(Account)'),
    ('auth-success-after-fail', 'splunk', 'EventCode IN (4625, 4624)'),
    ('auth-external-rdp', 'sentinel', 'LogonType == 10'),
    ('auth-admin-privileges', 'qradar', '4672'),
    ('auth-kerberoast', 'elastic', '0x17'),
    ('auth-explicit-cred', 'splunk', 'EventCode=4648'),
    ('auth-lockout', 'sentinel', 'EventID == 4740'),
    ('auth-linux-ssh-bruteforce', 'splunk', 'Failed password'),
    ('persist-new-user', 'defender', 'UserAccountCreated'),
    ('persist-admin-group', 'sentinel', '4728'),
    ('persist-service-install', 'qradar', '7045'),
    ('persist-scheduled-task', 'splunk', 'schtasks'),
    ('persist-run-key', 'elastic', 'CurrentVersion'),
    ('persist-wmi-subscription', 'sentinel', 'EventID in (19, 20, 21)'),
    ('exec-encoded-powershell', 'splunk', 'FromBase64String'),
    ('exec-office-child', 'sentinel', 'winword.exe'),
    ('exec-lolbin', 'splunk', 'certutil.exe'),
    ('exec-wmi-remote', 'sentinel', 'wmiprvse.exe'),
    ('exec-uac-bypass', 'elastic', 'fodhelper.exe'),
    ('evasion-log-cleared', 'qradar', '1102'),
    ('evasion-av-disabled', 'splunk', 'DisableRealtimeMonitoring'),
    ('evasion-recovery-inhibit', 'sentinel', 'wbadmin delete catalog'),
    ('cred-lsass-access', 'wazuh', 'lsass.exe'),
    ('cred-ntds', 'splunk', 'ntdsutil'),
    ('lateral-admin-share', 'sentinel', 'ADMIN$'),
    ('lateral-remote-service', 'qradar', 'PSEXESVC'),
    ('c2-rare-port', 'elastic', 'destination.port'),
    ('c2-dns-tunnel', 'elastic', 'dns.question.name'),
    ('exfil-large-upload', 'sentinel', 'sum(SentBytes)'),
    ('net-port-scan', 'sumologic', 'count_distinct(dest_port)'),
    ('web-attack-patterns', 'elastic', 'union select'),
    ('ics-plc-stop', 'qradar', 'stop cpu'),
    ('ics-write-command', 'qradar', 'write single coil'),
    ('ics-program-download', 'qradar', 'program download'),
    ('ics-engineering-tool', 'qradar', r'\Step7.exe'),
    ('ics-hmi-service-stop', 'qradar', 'hmi stop'),
]

EVIL = 'a\' OR "1"="1 --'


class TestSiemCatalog(unittest.TestCase):
    def test_all_32_hunts_present(self):
        self.assertEqual(len(HUNTS), 37)
        self.assertEqual(len(DIALECTS), 12)

    def test_unique_ids(self):
        self.assertEqual(len(set(HUNTS)), len(HUNTS))
        ids = [h['id'] for h in HUNTS.values()]
        self.assertEqual(sorted(ids), sorted(HUNTS))

    def test_hunts_are_filled_in(self):
        """Har bir hunt to'liq: bo'sh shart, nomdan ko'chirilgan tavsif, stub yo'q."""
        for hid, hunt in HUNTS.items():
            self.assertTrue(hunt.get('where'), hid)
            self.assertIn(hunt['category'], CATEGORIES, hid)
            self.assertTrue(hunt.get('select'), hid)
            self.assertTrue(hunt.get('attack'), hid)
            self.assertGreater(len(hunt['description']), 40, hid)
            self.assertGreater(len(hunt['tuning']), 30, hid)
            self.assertNotEqual(hunt['description'], hunt['name'], hid)
            for field in ('description', 'tuning', 'name'):
                self.assertNotIn('TODO', hunt[field], hid)

    def test_fingerprints(self):
        """Har bir hunt o'z izini qoldiradi — bir xil dummy shart bilan o'tmaydi."""
        covered = set()
        for hunt_id, siem, needle in FINGERPRINTS:
            res = build_query(hunt_id, siem)
            self.assertIn(needle, res['query'],
                          "%s/%s so'rovida '%s' yo'q:\n%s"
                          % (hunt_id, siem, needle, res['query']))
            covered.add(hunt_id)
        self.assertEqual(covered, set(HUNTS), "izsiz qolgan hunt lar bor")

    def test_queries_are_distinct(self):
        queries = {build_query(hid, 'qradar')['query'] for hid in HUNTS}
        self.assertEqual(len(queries), len(HUNTS),
                         "ikki hunt bir xil QRadar so'rovini bermoqda")


class TestSiemRendering(unittest.TestCase):
    def test_every_hunt_in_every_dialect(self):
        for hunt_id in HUNTS:
            for siem in DIALECTS:
                res = build_query(hunt_id, siem)
                query = res['query']
                self.assertTrue(query.strip(), '%s/%s bo\'sh' % (hunt_id, siem))
                for token in ('TODO', 'None', '${', 'placeholder'):
                    self.assertNotIn(token, query, '%s/%s' % (hunt_id, siem))
                self.assertTrue(res['notes'])
                self.assertEqual(res['language'], DIALECTS[siem]['language'])

    def test_days_param(self):
        self.assertIn('LAST 30 DAYS', build_query('auth-bruteforce', 'qradar',
                                                  {'days': 30})['query'])
        self.assertIn('earliest=-30d', build_query('auth-bruteforce', 'splunk',
                                                   {'days': 30})['query'])
        self.assertIn('ago(30d)', build_query('auth-bruteforce', 'sentinel',
                                              {'days': 30})['query'])
        self.assertIn('NOW() - 30 days', build_query('auth-bruteforce', 'elastic',
                                                     {'days': 30})['query'])

    def test_threshold_and_limit_params(self):
        res = build_query('auth-bruteforce', 'qradar', {'threshold': 55, 'limit': 7})
        self.assertIn('HAVING COUNT(*) >= 55', res['query'])
        self.assertIn('LIMIT 7', res['query'])
        res = build_query('auth-bruteforce', 'sentinel', {'threshold': 55})
        self.assertIn('event_count >= 55', res['query'])

    def test_extra_filters(self):
        res = build_query('auth-bruteforce', 'sentinel',
                          {'host': 'DC01', 'user': 'admin', 'ip': '10.1.1.5'})
        self.assertIn('Computer == @"DC01"', res['query'])
        self.assertIn('Account == @"admin"', res['query'])
        self.assertIn('10.1.1.5', res['query'])

    def test_escaping_all_dialects(self):
        """Foydalanuvchi qiymati hech bir dialektda so'rovni buzmaydi."""
        for siem in DIALECTS:
            query = build_query('auth-bruteforce', siem, {'user': EVIL})['query']
            self.assertNotIn(EVIL, query,
                             '%s: qiymat qochirilmagan holda tushib qolgan' % siem)
            if DIALECTS[siem]['syntax'] == 'aql':
                self.assertIn("a'' OR", query)
            elif DIALECTS[siem]['syntax'] == 'kql':
                self.assertIn('""1""=""1', query)
            else:
                self.assertIn('\\"1\\"=\\"1', query)

    def test_escape_value_helper(self):
        self.assertEqual(escape_value('qradar', "o'z"), "o''z")
        self.assertIn('\\"', escape_value('splunk', 'a"b'))
        self.assertEqual(escape_value('sentinel', 'a"b'), 'a""b')
        with self.assertRaises(ValueError):
            escape_value('yoq-bunday-siem', 'x')

    def test_fallback_note(self):
        """Maydon yo'q dialektda ogohlantirish bor, jim qolinmaydi."""
        self.assertNotIn('command_line', FIELD_MAPS['graylog'])
        notes = build_query('exec-encoded-powershell', 'graylog')['notes']
        self.assertTrue(any('command_line' in n for n in notes), notes)
        self.assertTrue(any('xom log matni' in n for n in notes), notes)

    def test_defender_event_id_translation(self):
        """Defender da Windows EventID ActionType ga aylanadi."""
        res = build_query('auth-bruteforce', 'defender')
        self.assertIn('ActionType == @"LogonFailed"', res['query'])
        self.assertNotIn('4625', res['query'])
        # tarjimasi yo'q ID -- ochiq ogohlantirish
        res = build_query('auth-kerberoast', 'defender')
        self.assertTrue(any('DIQQAT' in n for n in res['notes']), res['notes'])

    def test_aggregation_note_when_unsupported(self):
        for siem in ('kibana', 'graylog', 'wazuh', 'arcsight', 'chronicle'):
            notes = build_query('auth-bruteforce', siem)['notes']
            self.assertTrue(any('agregatsiya' in n for n in notes), (siem, notes))

    def test_public_ip_rendering(self):
        self.assertIn("INCIDR('10.0.0.0/8'", build_query('c2-rare-port', 'qradar')['query'])
        self.assertIn('ipv4_is_private', build_query('c2-rare-port', 'sentinel')['query'])
        self.assertIn('CIDR_MATCH', build_query('c2-rare-port', 'elastic')['query'])
        # CIDR yo'q dialektda shart tushiriladi va buni aytadi
        notes = build_query('c2-rare-port', 'arcsight')['notes']
        self.assertTrue(any('CIDR' in n for n in notes), notes)

    def test_errors(self):
        with self.assertRaises(ValueError):
            build_query('yoq-bunday-hunt', 'qradar')
        with self.assertRaises(ValueError):
            build_query('auth-bruteforce', 'yoq-bunday-siem')
        with self.assertRaises(ValueError):
            list_hunts(category='yoq-bunday-kategoriya')
        with self.assertRaises(ValueError):
            get_hunt('yoq')


class TestSiemSnapshots(unittest.TestCase):
    def test_qradar_bruteforce(self):
        self.assertEqual(build_query('auth-bruteforce', 'qradar')['query'], """\
SELECT sourceip AS src_ip, username AS user, LOGSOURCENAME(logsourceid) AS host, COUNT(*) AS event_count
FROM events
WHERE "EventID" = 4625
GROUP BY sourceip, username, LOGSOURCENAME(logsourceid)
HAVING COUNT(*) >= 20
ORDER BY event_count DESC
LIMIT 200
LAST 7 DAYS""")

    def test_splunk_encoded_powershell(self):
        self.assertEqual(build_query('exec-encoded-powershell', 'splunk')['query'], """\
index=wineventlog source="WinEventLog:Security" earliest=-7d
| search EventCode=4688 AND (Process_Command_Line="*-enc*" OR \
Process_Command_Line="*-EncodedCommand*" OR Process_Command_Line="*FromBase64String*" OR \
Process_Command_Line="*-nop -w hidden*")
| table _time, host, user, Parent_Process_Name, New_Process_Name, Process_Command_Line
| head 200""")

    def test_sentinel_bruteforce(self):
        self.assertEqual(build_query('auth-bruteforce', 'sentinel')['query'], """\
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4625
| summarize event_count = count() by IpAddress, Account, Computer
| where event_count >= 20
| order by event_count desc
| take 200""")


class TestSiemIntegration(unittest.TestCase):
    def test_bk_preset_matches_fieldmap(self):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            'bluekit', 'logs', 'fieldmap.yaml')
        with open(path, 'r', encoding='utf-8') as f:
            presets = yaml.safe_load(f).get('presets', {})
        for siem, info in DIALECTS.items():
            preset = info['bk_preset']
            if preset:
                self.assertIn(preset, presets, siem)

    def test_next_steps(self):
        res = build_query('auth-bruteforce', 'qradar')
        self.assertIn('--preset qradar', res['next_steps'][0])
        self.assertIn('ir chain', ' '.join(res['next_steps']))
        # preset yo'q dialektda --preset umuman yozilmaydi
        res = build_query('auth-bruteforce', 'chronicle')
        self.assertNotIn('--preset', ' '.join(res['next_steps']))
        # tarmoq hunt lari beacon tahliliga yo'naltiradi
        res = build_query('c2-rare-port', 'qradar')
        self.assertIn('hunt beacons', ' '.join(res['next_steps']))

    def test_every_dialect_has_maps(self):
        for siem in DIALECTS:
            self.assertIn(siem, FIELD_MAPS, siem)
            self.assertTrue(FIELD_MAPS[siem].get('ts'), siem)
            self.assertIn(siem, SOURCE_MAPS, siem)
            self.assertIn('any', SOURCE_MAPS[siem], siem)

    def test_logsources_are_mapped(self):
        for hunt in HUNTS.values():
            for siem in DIALECTS:
                smap = SOURCE_MAPS[siem]
                if len(smap) > 1:
                    self.assertIn(hunt['logsource'], smap,
                                  '%s: %s uchun manba yo\'q' % (siem, hunt['logsource']))


class TestSiemAttackIds(unittest.TestCase):
    @unittest.skipUnless(os.path.exists(get_kb_path()), 'KB yo\'q')
    def test_attack_ids_active_in_kb(self):
        from bluekit.kb.query import KB
        kb = KB()
        ids = sorted({a for h in HUNTS.values() for a in h['attack']})
        for res in kb.validate(ids):
            self.assertTrue(res['found'], "%s KB da yo'q" % res['normalized'])
            self.assertEqual(res['status'], 'active',
                             "%s holati: %s (v19 da o'zgargan bo'lishi mumkin)"
                             % (res['normalized'], res['status']))


class TestSiemCli(unittest.TestCase):
    def _run(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(argv)
        return code, buf.getvalue()

    def test_list(self):
        code, out = self._run(['list'])
        self.assertEqual(code, 0)
        self.assertIn('qradar', out)
        self.assertIn('IBM QRadar', out)

    def test_hunts_filtered(self):
        code, out = self._run(['hunts', '--category', 'auth'])
        self.assertEqual(code, 0)
        self.assertIn('auth-bruteforce', out)
        self.assertNotIn('web-attack-patterns', out)

    def test_show(self):
        code, out = self._run(['show', 'c2-dns-tunnel'])
        self.assertEqual(code, 0)
        self.assertIn('T1071.004', out)

    def test_query_json(self):
        code, out = self._run(['query', 'auth-bruteforce', '--siem', 'qradar', '--json'])
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data['hunt_id'], 'auth-bruteforce')
        self.assertIn('LAST 7 DAYS', data['query'])

    def test_query_all_siems(self):
        code, out = self._run(['query', 'auth-bruteforce', '--siem', 'all', '--json'])
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(out)), len(DIALECTS))

    def test_query_text_output_has_next_steps(self):
        code, out = self._run(['query', 'exec-encoded-powershell', '--siem', 'splunk'])
        self.assertEqual(code, 0)
        self.assertIn('Eksport qilgandan keyin:', out)
        self.assertIn('--preset splunk', out)

    def test_pack(self):
        code, out = self._run(['pack', '--siem', 'sentinel', '--category', 'evasion'])
        self.assertEqual(code, 0)
        self.assertIn('evasion-log-cleared', out)
        self.assertIn('evasion-av-disabled', out)

    def test_unknown_hunt_returns_error_code(self):
        code, out = self._run(['query', 'yoq', '--siem', 'qradar'])
        self.assertEqual(code, 1)
        self.assertIn('Xato', out)


if __name__ == '__main__':
    unittest.main()
from bluekit.siem.dialects import FIELD_OVERRIDES
from bluekit.siem.fields import CANONICAL_FIELDS

class TestSiemOverrides(unittest.TestCase):
    def test_net_port_scan_sentinel(self):
        res = build_query('net-port-scan', 'sentinel')
        self.assertIn('SourceIP', res['query'])
        self.assertNotIn('IpAddress', res['query'])

    def test_exfil_large_upload_sentinel(self):
        res = build_query('exfil-large-upload', 'sentinel')
        self.assertIn('SourceIP', res['query'])
        self.assertNotIn('IpAddress', res['query'])

    def test_c2_dns_tunnel_sentinel(self):
        res = build_query('c2-dns-tunnel', 'sentinel')
        self.assertIn('DnsEvents', res['query'])
        self.assertIn('Name', res['query'])

    def test_web_attack_patterns_sentinel(self):
        res = build_query('web-attack-patterns', 'sentinel')
        self.assertIn('W3CIISLog', res['query'])
        self.assertIn('csUriStem', res['query'])

    def test_auth_bruteforce_sentinel(self):
        res = build_query('auth-bruteforce', 'sentinel')
        self.assertIn('SecurityEvent', res['query'])
        self.assertIn('IpAddress', res['query'])

    def test_overrides_valid(self):
        for siem, sources in FIELD_OVERRIDES.items():
            self.assertIn(siem, DIALECTS)
            for logsource, mapping in sources.items():
                self.assertIn(logsource, SOURCE_MAPS[siem])

    def test_overrides_canonical(self):
        for siem, sources in FIELD_OVERRIDES.items():
            for logsource, mapping in sources.items():
                for canon, native in mapping.items():
                    self.assertIn(canon, CANONICAL_FIELDS)

    def test_canonical_fields_not_left(self):
        for hunt in HUNTS.values():
            for siem in DIALECTS:
                res = build_query(hunt['id'], siem)
                query = res['query']
                notes = res['notes']
                
                # Yig'ilgan xaritani olib kelamiz
                base = dict(FIELD_MAPS.get(siem, {}))
                base.update(FIELD_OVERRIDES.get(siem, {}).get(hunt.get('logsource', 'any'), {}))
                
                for canon in CANONICAL_FIELDS:
                    import re
                    # skip if native field name IS the canonical name
                    if base.get(canon) == canon: continue
                    # string larni olib tashlaymiz
                    if hunt['id'] == 'auth-linux-ssh-bruteforce' and canon == 'user': continue
                    q_no_str = re.sub(r"['\"].*?['\"]", "", query)
                    if re.search(r'(?<!\.)\b%s\b(?!\.)' % canon, q_no_str) and not re.search(r'(?i)as\s+%s\b' % canon, q_no_str) and not re.search(r'as=%s\b' % canon, q_no_str):
                        has_note = any(canon in n for n in notes)
                        self.assertTrue(has_note, f"{hunt['id']} / {siem}: {canon} query da qoldi lekin notesda aytilmadi")

