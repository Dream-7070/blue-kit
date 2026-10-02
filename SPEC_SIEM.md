# SPEC_SIEM — SIEM so'rov generatori (`bk siem`)

Loyiha: `D:\Claude Projects\CTF\blue-kit-staging`

## Maqsad

Analitik SIEM oldida o'tiribdi, unda millionlab log bor. U **SIEM turini** va **nima
qidirmoqchi ekanini** tanlaydi — tool esa o'sha SIEM ning o'z tilida tayyor so'rov chiqarib
beradi. Analitik so'rovni SIEM ga paste qiladi, natijani CSV/JSON qilib eksport qiladi va
`bk logs analyze` / `bk ir chain` ga beradi.

Hamma narsa **offline**: internet yo'q, LLM yo'q, API chaqiruvi yo'q. Faqat Python stdlib +
`pyyaml` (allaqachon bog'liqlikda).

## TEGMANG (boshqa ish ostida)

`bk.py`, `bluekit/web/**`, `bluekit/hunt/**`, `bluekit/ir/**`, `bluekit/logs/**`,
`static/**`, `dist/**`, mavjud `tests/test_*.py` fayllari. `bluekit/logs/fieldmap.yaml`
ni **faqat o'qing** (undagi kanonik nomlarga tayanasiz), o'zgartirmang.

CLI ni `bk.py` ga ulashni MEN o'zim qilaman. Siz faqat quyidagi YANGI fayllarni yozasiz:

```
bluekit/siem/__init__.py
bluekit/siem/fields.py
bluekit/siem/dialects.py
bluekit/siem/catalog.py
bluekit/siem/builder.py
bluekit/siem/cli.py
tests/test_siem.py
```

`bluekit/siem/cli.py` ning oxirida `if __name__ == '__main__': sys.exit(main(sys.argv[1:]))`
bo'lsin — shunda `python -m bluekit.siem.cli ...` bilan mustaqil sinab ko'rasiz.

## 1. Kanonik maydonlar (`fields.py`)

`bluekit/logs/fieldmap.yaml` dagi kanonik nomlar bilan **aynan bir xil** bo'lishi shart
(shu sabab eksport qilingan fayl keyin `bk logs analyze --preset ...` ga tushadi):

`ts, host, user, src_ip, dest_ip, event_id, channel, process, pid, ppid, parent_process,
command_line, message, target`

Tarmoq / web / mail uchun qo'shimcha kanonik maydonlar:

`src_port, dest_port, protocol, action, bytes_sent, bytes_recv, url, http_method,
http_status, user_agent, dns_query, rule_name, service_name, registry_path, file_path,
logon_type, sender, recipient, subject, duration`

`fields.py` da: `CANONICAL_FIELDS` (tartiblangan ro'yxat) va har biriga qisqa o'zbekcha
izoh (`FIELD_LABELS`).

## 2. Dialektlar (`dialects.py`)

**Arxitektura talabi:** har bir hunt uchun har bir SIEM ga alohida matn yozilmaydi.
`syntax class` (renderer) + `field_map` + `source_map` uchligi bo'ladi. Yangi SIEM qo'shish =
bitta lug'at qo'shish, 30 ta so'rovni qayta yozish EMAS. Agar sizda hunt matnlari
dialektlar bo'yicha qo'lda takrorlangan bo'lsa — ish noto'g'ri bajarilgan hisoblanadi.

### Syntax klasslar (renderer funksiyalari)

| klass | tavsif | agregatsiya |
|---|---|---|
| `aql` | IBM QRadar AQL | `GROUP BY ... HAVING ...` |
| `spl` | Splunk SPL | `\| stats ... by ... \| where ...` |
| `kql` | Microsoft KQL | `\| summarize ... by ... \| where ...` |
| `esql` | Elasticsearch ES\|QL | `\| STATS ... BY ... \| WHERE ...` |
| `dql` | Lucene/KQL filtr tili (Kibana Discover, Wazuh, Graylog) | YO'Q — pastga qarang |
| `udm` | Google SecOps (Chronicle) UDM search | `match`/`outcome` |
| `sumo` | Sumo Logic | `\| count by ...` |
| `cef_search` | ArcSight Logger qidiruvi | YO'Q |
| `cql` | CrowdStrike Falcon LogScale (Humio) | `\| groupBy(...)` |

Agregatsiyani qo'llab-quvvatlamaydigan klass (`dql`, `cef_search`) uchun: filtr qismi
chiqariladi va `notes` ga o'zbekcha izoh qo'shiladi, masalan:
`"Graylog qidiruv tili agregatsiya qilmaydi — natijaga Aggregation widget qo'shing:
group by src_ip, metric count, filter count >= 20."` **Jim qolmang, noto'g'ri so'rov ham
chiqarmang.**

### Dialektlar ro'yxati (12 ta, hammasi majburiy)

| id | SIEM (UI da ko'rinadigan nom) | klass | `bk_preset` | paste joyi (notes uchun) |
|---|---|---|---|---|
| `qradar` | IBM QRadar | `aql` | `qradar` | Log Activity → Advanced Search |
| `splunk` | Splunk Enterprise / Cloud | `spl` | `splunk` | Search & Reporting |
| `sentinel` | Microsoft Sentinel | `kql` | `sentinel` | Logs (KQL) |
| `defender` | Microsoft Defender XDR | `kql` | `sentinel` | Advanced Hunting |
| `elastic` | Elasticsearch ES\|QL | `esql` | `ecs` | Discover → ES\|QL |
| `kibana` | Kibana Discover (KQL) | `dql` | `ecs` | Discover qidiruv qatori |
| `wazuh` | Wazuh Dashboard | `dql` | `wazuh` | Threat Hunting → qidiruv qatori |
| `graylog` | Graylog | `dql` | `graylog` | Search |
| `chronicle` | Google SecOps (Chronicle) | `udm` | — | UDM Search |
| `sumologic` | Sumo Logic | `sumo` | — | Log Search |
| `arcsight` | Micro Focus ArcSight Logger | `cef_search` | `cef` | Analyze → Search |
| `logscale` | CrowdStrike Falcon LogScale | `cql` | — | Search |

`bk_preset` — `bluekit/logs/fieldmap.yaml` dagi preset nomi (mavjudlari: ecs, splunk,
sentinel, wazuh, qradar, cef, graylog, hayabusa, evtxecmd, zeek, auditd). U bo'lsa
keyingi qadam maslahatida `--preset <bk_preset>` ko'rsatiladi, bo'lmasa ko'rsatilmaydi.

### Har bir dialektning `field_map` i

Kanonik nom → o'sha SIEM dagi haqiqiy maydon nomi. Misollar (to'liq emas, qolganini
shu uslubda to'ldiring):

- `qradar`: `ts→deviceTime`, `src_ip→sourceip`, `dest_ip→destinationip`,
  `src_port→sourceport`, `dest_port→destinationport`, `user→username`,
  `host→logsourcename`, `event_id→"EventID"` (custom property, qo'shtirnoqda),
  `command_line→"Command Line"`, `message→payload` (`UTF8(payload)` bilan qidiriladi)
- `splunk`: `ts→_time`, `src_ip→src_ip`, `dest_ip→dest_ip`, `user→user`, `host→host`,
  `event_id→EventCode`, `process→New_Process_Name`, `parent_process→Parent_Process_Name`,
  `command_line→Process_Command_Line`, `message→_raw`
- `sentinel`: `ts→TimeGenerated`, `host→Computer`, `user→Account`, `src_ip→IpAddress`,
  `event_id→EventID`, `process→NewProcessName`, `parent_process→ParentProcessName`,
  `command_line→CommandLine`, `logon_type→LogonType`
- `defender`: `ts→Timestamp`, `host→DeviceName`, `user→AccountName`,
  `process→FileName`, `parent_process→InitiatingProcessFileName`,
  `command_line→ProcessCommandLine`, `dest_ip→RemoteIP`, `dest_port→RemotePort`,
  `url→RemoteUrl`, `dns_query→ RemoteUrl` (DeviceNetworkEvents)
- `elastic` / `kibana`: ECS — `ts→@timestamp`, `host→host.name`, `user→user.name`,
  `src_ip→source.ip`, `dest_ip→destination.ip`, `dest_port→destination.port`,
  `event_id→event.code`, `process→process.name`,
  `parent_process→process.parent.name`, `command_line→process.command_line`,
  `dns_query→dns.question.name`, `http_status→http.response.status_code`,
  `user_agent→user_agent.original`, `bytes_sent→source.bytes`
- `wazuh`: `ts→timestamp`, `host→agent.name`, `event_id→data.win.system.eventID`,
  `user→data.win.eventdata.targetUserName`,
  `command_line→data.win.eventdata.commandLine`, `rule_name→rule.description`,
  `src_ip→data.srcip`
- `graylog`: `ts→timestamp`, `host→source`, `message→message`, qolganlari uchun
  `full_message` ichidan qidirish (fallback)
- `chronicle`: `ts→metadata.event_timestamp`, `host→principal.hostname`,
  `user→principal.user.userid`, `process→target.process.file.full_path`,
  `command_line→target.process.command_line`, `src_ip→principal.ip`,
  `dest_ip→target.ip`, `dns_query→network.dns.questions.name`
- `sumologic`, `arcsight`, `logscale`: shu uslubda; ArcSight uchun CEF nomlari
  (`src`, `dst`, `duser`, `dhost`, `deviceEventClassId`, `msg`).

**Fallback qoidasi:** dialektda kanonik maydon uchun native nom yo'q bo'lsa —
`message` / raw maydon ichidan matn bo'yicha qidiriladi VA `notes` ga
`"<SIEM> da <maydon> alohida maydon emas — xom log matni bo'yicha qidirilmoqda, noto'g'ri
mos kelish (false positive) ehtimoli bor."` qo'shiladi. Mavjud bo'lmagan maydon nomini
o'ylab topib yozmang.

### `source_map`

Hunt dagi `logsource` (quyida) → o'sha dialektdagi jadval/indeks. Masalan
`windows-security`: `sentinel→SecurityEvent`, `defender→DeviceProcessEvents` yoki
`DeviceLogonEvents` (hunt `logsource` iga qarab), `splunk→index=wineventlog
source="WinEventLog:Security"`, `elastic→FROM logs-windows.*`,
`qradar→FROM events` + `logsourcetype` sharti, `wazuh→rule.groups:windows`.

`logsource` qiymatlari: `windows-security`, `windows-sysmon`, `windows-system`,
`linux-auth`, `firewall`, `proxy`, `dns`, `web`, `edr`, `mail`, `vpn`, `any`.

## 3. Shart IR si va builder (`builder.py`)

Hunt lar shartni **strukturaviy** yozadi, matn sifatida emas:

```python
{'field': 'event_id', 'op': 'in',            'value': [4625]}
{'field': 'command_line', 'op': 'contains_any', 'value': ['-enc', '-EncodedCommand']}
{'field': 'process', 'op': 'endswith_any',   'value': ['\\powershell.exe']}
{'field': 'dest_port', 'op': 'not_in',       'value': [80, 443]}
{'field': 'src_ip', 'op': 'is_public'}
{'op': 'all', 'items': [...]}     # AND
{'op': 'any', 'items': [...]}     # OR
{'op': 'none', 'items': [...]}    # NOT
```

Operatorlar: `eq, ne, in, not_in, contains, contains_any, not_contains, startswith_any,
endswith_any, regex, gt, gte, lt, lte, exists, is_public, is_private, cidr_in`.

`regex` ni qo'llab-quvvatlamaydigan dialektda — `contains_any` ga tushiriladi va `notes`
ga izoh qo'shiladi.

Qiymat parametrga bog'lanishi mumkin: `{'param': 'threshold'}`.

### Agregatsiya

```python
'aggregate': {
    'group_by': ['src_ip', 'user'],
    'metric': 'count',                  # yoki 'distinct_count:user', 'sum:bytes_sent'
    'having': {'op': 'gte', 'param': 'threshold'},
    'window': '10m',                    # ixtiyoriy
}
```

### Parametrlar

Har bir hunt `params` da default beradi; CLI ustiga yozadi:
`days` (default 7), `threshold`, `limit` (default 200), va ixtiyoriy `host`, `user`, `ip`,
`index`/`table`. `host`/`user`/`ip` berilsa so'rovga qo'shimcha AND shart qo'shiladi.

`days` har dialektda o'z ko'rinishida: AQL `LAST 7 DAYS`, SPL `earliest=-7d`,
KQL `| where TimeGenerated > ago(7d)`, ES|QL `| WHERE @timestamp > NOW() - 7 days`,
DQL `@timestamp >= now-7d`, LogScale `@timestamp > now() - 7d`.

### Qochirish (escaping) — MAJBURIY

Foydalanuvchi bergan `host`, `user`, `ip`, `index` qiymatlari har bir dialektning o'z
qoidasi bo'yicha qochiriladi (qo'shtirnoq, apostrof, backslash, `|`). `--user "a' OR 1=1"`
berilganda chiqqan so'rov buzilmasligi kerak. Buning uchun `builder.py` da
`escape_value(dialect, value)` bo'lsin va **barcha** qiymatlar shu orqali o'tsin.

### Asosiy API

```python
build_query(hunt_id: str, siem: str, params: dict = None) -> dict
```

qaytaradi:

```python
{
  'hunt_id': 'auth-bruteforce',
  'hunt_name': "Parolni saralash (brute force)",
  'category': 'auth',
  'siem': 'qradar',
  'siem_name': 'IBM QRadar',
  'language': 'AQL',
  'query': 'SELECT ...',              # paste qilinadigan toza matn, bezaksiz
  'select_fields': ['ts', 'src_ip', ...],   # kanonik nomlar
  'attack': ['T1110', 'T1110.001'],
  'params': {'days': 7, 'threshold': 20, 'limit': 200},
  'notes': ["QRadar: Log Activity → Advanced Search", ...],
  'tuning': "Xizmat akkauntlarini allowlist qiling ...",
  'next_steps': ['python bk.py logs analyze export.csv --preset qradar',
                 'python bk.py ir chain export.csv'],
}
```

Yana: `list_dialects()`, `list_hunts(category=None, search=None, siem=None)`,
`get_hunt(hunt_id)`, `CATEGORIES` (kategoriya → o'zbekcha nomi).

Noto'g'ri `hunt_id` / `siem` uchun `ValueError` va xabarda mavjud variantlar ro'yxati.

## 4. Hunt katalogi (`catalog.py`) — 32 ta, hammasi to'liq

Har biri: `id, name (uz), category, description (uz), logsource, attack, where,
aggregate (ixtiyoriy), select, params, tuning (uz)`. **Bitta ham `TODO`, bo'sh `where`
yoki stub qolmasin.**

ATT&CK ID lari quyida KB (v19.2) bo'yicha **tekshirilgan** — aynan shularni yozing:

**auth** (Kirish/autentifikatsiya)
1. `auth-bruteforce` — bitta IP dan ko'p 4625 — T1110, T1110.001 — threshold 20
2. `auth-password-spray` — bitta IP, ko'p turli user, kam urinish — T1110.003 —
   `distinct_count:user` >= 10
3. `auth-success-after-fail` — 4625 seriyasidan keyin o'sha user/IP da 4624 — T1110
4. `auth-external-rdp` — 4624 + `logon_type=10` + `src_ip` public — T1021.001, T1078
5. `auth-admin-privileges` — 4672 (maxsus imtiyozlar) — T1078.002
6. `auth-kerberoast` — 4769 + encryption type 0x17 + non-machine account — T1558.003
7. `auth-explicit-cred` — 4648 — T1078
8. `auth-lockout` — 4740 — T1110
9. `auth-linux-ssh-bruteforce` — sshd "Failed password" — T1110

**persistence** (Mustahkamlanish)
10. `persist-new-user` — 4720 — T1136.001
11. `persist-admin-group` — 4728 / 4732 / 4756 — T1098
12. `persist-service-install` — 7045 / 4697 — T1543.003
13. `persist-scheduled-task` — 4698 / 4702 / `schtasks.exe` — T1053.005
14. `persist-run-key` — Run/RunOnce registry yozuvi (Sysmon 13) — T1547.001, T1112
15. `persist-wmi-subscription` — Sysmon 19/20/21 — T1546.003

**execution** (Ishga tushirish)
16. `exec-encoded-powershell` — `-enc`, `-EncodedCommand`, `FromBase64String`,
    `-nop -w hidden` — T1059.001, T1027
17. `exec-office-child` — winword/excel/powerpnt/outlook → cmd/powershell/wscript/mshta —
    T1566.001, T1204.002
18. `exec-lolbin` — certutil/mshta/rundll32/regsvr32/bitsadmin + tarmoq argumenti —
    T1218, T1105
19. `exec-wmi-remote` — wmiprvse.exe farzandi yoki `wmic ... /node:` — T1047
20. `exec-uac-bypass` — fodhelper/eventvwr/sdclt farzandi — T1548.002

**evasion** (Yashirinish)
21. `evasion-log-cleared` — 1102 / 104 / `wevtutil cl` — **T1685.005** (T1070.001 EMAS,
    u v19 da revoked)
22. `evasion-av-disabled` — Defender o'chirilishi, `Set-MpPreference -Disable...`,
    Event 5001 — **T1685** (T1562.001 EMAS, revoked)
23. `evasion-recovery-inhibit` — soya nusxalarni o'chirish, `bcdedit` recovery o'zgartirish,
    `wbadmin delete` — T1490

**credential** (Hisob ma'lumotlari)
24. `cred-lsass-access` — Sysmon 10, `TargetImage` lsass — T1003.001
25. `cred-ntds` — `ntdsutil`, `ifm`, `ntds.dit` nusxasi — T1003.003

**lateral** (Yon harakat)
26. `lateral-admin-share` — 5140 / 5145 + ADMIN$ / C$ / IPC$ — T1021.002
27. `lateral-remote-service` — 7045 + tasodifiy/qisqa xizmat nomi, `\\.\pipe\` — T1570,
    T1021.002

**network** (Tarmoq / C2)
28. `c2-rare-port` — ruxsat berilgan chiquvchi ulanish, standart bo'lmagan port — T1571
29. `c2-dns-tunnel` — bitta domen ostida juda ko'p noyob subdomen yoki uzun so'rov,
    TXT/NULL — T1071.004, T1572
30. `exfil-large-upload` — tashqi manzilga katta `bytes_sent` — T1041, T1048, T1567
31. `net-port-scan` — bitta src → ko'p turli dest_port, deny — T1046

**web**
32. `web-attack-patterns` — SQLi / path traversal / webshell / skaner user-agent
    (bitta hunt, `any` shartlari bilan) — T1190, T1505.003, T1595

`c2-beacon-candidates` YOZMANG — buning o'rniga `network` kategoriyasidagi barcha
hunt larning `notes` iga: `"Davriy (beacon) tahlil uchun eksportni
'python bk.py hunt beacons <fayl>' ga bering — SIEM so'rovi buni hisoblay olmaydi."`

Windows event ID lariga tayanadigan hunt larda `select` ichiga albatta:
`ts, host, user, src_ip, event_id, process, parent_process, command_line` (mavjudlari) —
shunda eksport `bk ir chain` uchun yetarli bo'ladi.

## 5. CLI (`cli.py`)

`main(argv)` — argparse, o'zbekcha yordam matnlari, `--json` har bir buyruqda.

```
siem list                          # dialektlar jadvali: ID | SIEM | Til | bk preset
siem hunts [--category auth] [--search parol] [--siem qradar]
siem show <hunt-id>                # to'liq tavsif, ATT&CK, parametrlar, tuning
siem query <hunt-id> --siem qradar [--days 7] [--threshold 20] [--limit 200]
                                   [--host H] [--user U] [--ip I] [--index NAME]
                                   [--out FILE] [--json]
siem query <hunt-id> --siem all    # barcha dialektlar uchun ketma-ket
siem pack --siem qradar [--category auth] [--out fayl.txt]   # bir nechta so'rov bir faylda
```

Chiqish formati (`query`) — so'rovning o'zi **bezaksiz**, ramka/rang/bo'shliqsiz, chunki
foydalanuvchi uni sichqoncha bilan belgilab ko'chiradi:

```
=== auth-bruteforce — Parolni saralash (brute force) ===
SIEM: IBM QRadar (AQL)   |   ATT&CK: T1110, T1110.001
Parametrlar: days=7, threshold=20, limit=200

SELECT ...
FROM events
WHERE ...

Eslatmalar:
  - QRadar: Log Activity -> Advanced Search
  - ...
Sozlash: Xizmat akkauntlarini allowlist qiling ...

Eksport qilgandan keyin:
  python bk.py logs analyze export.csv --preset qradar
  python bk.py ir chain export.csv
```

`print_table` ga o'xshash jadval kerak bo'lsa `cli.py` ichida o'zingiz yozing (`bk.py` ga
tegmaysiz). `sys.stdout.reconfigure(encoding='utf-8', errors='replace')` ni `main()` da
qiling.

## 6. Testlar (`tests/test_siem.py`)

`unittest`, mavjud `tests/test_logs.py` uslubida. Kamida shular:

1. **To'liqlik:** har bir hunt × har bir dialekt (32 × 12 = 384) uchun `build_query`
   istisnosiz ishlaydi; `query` bo'sh emas, ichida `TODO`, `None`, `{`, `}`, `${` yo'q.
2. **ATT&CK:** har bir hunt ning har bir ID si KB da mavjud va `status == 'active'`.
   KB yo'q bo'lsa `unittest.skipUnless` bilan o'tkazib yuboriladi.
3. **Unikal ID:** hunt id lari va dialekt id lari takrorlanmaydi.
4. **Parametr:** `days=30` → qradar da `LAST 30 DAYS`, splunk da `earliest=-30d`,
   sentinel da `ago(30d)`; `threshold=50` agregatsiyali hunt ning so'rovida ko'rinadi.
5. **Escaping:** `params={'user': "a' OR 1=1 --"}` barcha 12 dialektda qochirilgan
   (xom apostrof so'rovga tushmaydi).
6. **Fallback izohi:** maydon yo'q bo'lgan dialektda `notes` bo'sh emas.
7. **`bk_preset` ↔ fieldmap:** har bir dialektning `bk_preset` i (None dan boshqasi)
   haqiqatan `bluekit/logs/fieldmap.yaml` ning `presets` ida bor.
8. **Snapshot:** `qradar/auth-bruteforce`, `splunk/exec-encoded-powershell`,
   `sentinel/persist-service-install` uchun kutilgan so'rov matni (aniq string) bilan
   solishtirish.
9. **Xato:** noma'lum hunt / siem → `ValueError`.
10. **CLI:** `cli.main(['query', 'auth-bruteforce', '--siem', 'qradar', '--json'])` →
    0 qaytaradi va chiqishi to'g'ri JSON (`io.StringIO` + `redirect_stdout`).

## 7. Qabul mezonlari — O'ZINGIZ yugurtirib tekshiring

```
python -m unittest discover -s tests -p "test_*.py" -q
python -m bluekit.siem.cli list
python -m bluekit.siem.cli hunts
python -m bluekit.siem.cli query auth-bruteforce --siem qradar
python -m bluekit.siem.cli query exec-encoded-powershell --siem splunk --days 30
python -m bluekit.siem.cli query c2-dns-tunnel --siem all
python -m bluekit.siem.cli pack --siem sentinel --category auth
```

- Mavjud 33 ta test ham yashil qolishi shart (siz hech qaysi eski faylga tegmaysiz).
- Chiqqan so'rovlar **sintaktik jihatdan haqiqiy** bo'lsin: AQL da `SELECT ... FROM events
  WHERE ... GROUP BY ... HAVING ... LAST N DAYS` tartibi to'g'ri, SPL da `|` pipeline
  to'g'ri, KQL da `summarize count() by ...` to'g'ri. O'ylab topilgan sintaksis yozmang.
- Stub, "TODO", bo'sh funksiya, `pass` qolmasin.
- Ishni O'ZINGIZ bajaring, subagentga topshirmang.
- Hisobotda: har bir yangi faylning qator soni va `unittest` natijasini ko'rsating.
