# REVIEW_SIEM — tayyor kodni tekshirish topshirig'i

Loyiha: `D:\Claude Projects\CTF\blue-kit-staging`

Bu safar **kod yozish emas, tekshirish** topshirig'i.

## Qattiq qoida

Hech qanday faylni **o'zgartirmang, o'chirmang, qayta yozmang**. Yagona yaratadigan
faylingiz — `REVIEW_SIEM_RESULT.md`. Kodni tuzatmang, faqat toping va yozing.
Agar tuzatish kerak deb hisoblasangiz — taklifni hisobotga yozing, kodga
tegmang.

## Nima tekshiriladi

`bluekit/siem/` paketi — SIEM so'rov generatori. 12 ta SIEM dialekti, 32 ta hunt,
`tests/test_siem.py` da 32 ta test (hozir hammasi yashil, jami 65 ta test).

Fayllar:
- `bluekit/siem/dialects.py` — DIALECTS, FIELD_MAPS, SOURCE_MAPS, EVENT_ID_TRANSLATION
- `bluekit/siem/catalog.py` — 32 hunt (shart daraxti ko'rinishida)
- `bluekit/siem/builder.py` — 9 ta renderer (aql, spl, kql, esql, dql, udm, sumo,
  cef_search, cql)
- `bluekit/siem/cli.py`, `bluekit/siem/fields.py`

Chiqishni ko'rish uchun:

```
python bk.py siem list
python bk.py siem query auth-bruteforce --siem all
python bk.py siem query exec-office-child --siem defender
python bk.py siem query c2-dns-tunnel --siem elastic
python bk.py siem query web-attack-patterns --siem chronicle
python bk.py siem query exfil-large-upload --siem logscale
python bk.py siem query net-port-scan --siem sumologic
python bk.py siem query auth-external-rdp --siem arcsight
```

## 1-ustuvorlik: sintaksis haqiqatan to'g'rimi

Har bir dialekt uchun chiqqan so'rovni **o'sha SIEM ning haqiqiy so'rov tili**
bilan solishtiring. Menda eng kam ishonch quyidagilarda — avval shularni qarang:

1. **Chronicle (UDM Search)** — `target.url = /.*union select.*/ nocase` ko'rinishi.
   UDM Search da regex literali shunday yoziladimi? `nocase` shu joyda to'g'rimi?
   `net.ip_in_range_cidr(principal.ip, "10.0.0.0/8")` chaqiruvi to'g'rimi?
2. **CrowdStrike LogScale (CQL)** —
   `| groupBy([SourceIp], function=sum(field=bytes_sent, as=bytes_sent_sum))`,
   `| sort(field=X, order=desc, limit=200)`, `| select([...])`, `| head(200)`.
   Funksiya nomlari va argumentlari to'g'rimi? `count(field=X, distinct=true, as=Y)`
   haqiqatan mavjudmi?
3. **Sumo Logic** — `| count_distinct(dest_port) as dest_port_count by src_ip`,
   `| where x matches "*deny*"`, `!isPrivateIP(dest_ip)`, `| fields`, `| limit`.
4. **ArcSight Logger** — `deviceEventClassId="4624" AND msg CONTAINS "10"`.
   `CONTAINS` / `STARTSWITH` / `ENDSWITH` operatorlari ArcSight qidiruvida shunday
   yoziladimi?
5. **QRadar AQL** — `INCIDR('10.0.0.0/8', sourceip)` argumentlar tartibi;
   `"Command Line"` kabi custom property nomlarini qo'shtirnoqda yozish;
   `UTF8(payload) LIKE '%x%'`; `GROUP BY` + `HAVING` + `ORDER BY` + `LIMIT` +
   `LAST 7 DAYS` tartibi.
6. **ES|QL** — `| WHERE @timestamp > NOW() - 7 days`, `LIKE "*x*"`,
   `CIDR_MATCH(source.ip, "10.0.0.0/8", ...)`, `COUNT_DISTINCT`, `KEEP`, `LIMIT`.
7. **KQL** — `@"..."` verbatim satrlari, `in (...)`, `contains`, `endswith`,
   `ipv4_is_private()`, `summarize X = count() by ...`.
8. **DQL/Lucene** (kibana, wazuh, graylog) — `field:*value*` wildcard va
   Lucene maxsus belgilarini qochirish (`builder.py` dagi `_LUCENE_SPECIAL`).
   Uchala mahsulotda ham ishlaydigan umumiy sintaksismi?

Har bir topilgan xato uchun: qaysi fayl va qator, nima noto'g'ri, to'g'ri variant
qanday bo'lishi kerak.

## 2-ustuvorlik: maydon nomlari

`FIELD_MAPS` dagi nomlar haqiqiy maydonlarmi?
- Splunk: `New_Process_Name`, `Parent_Process_Name`, `Process_Command_Line`,
  `EventCode`, `bytes_out` — Splunk CIM/Windows TA da shundaymi?
- Sentinel: `SecurityEvent` jadvalida `IpAddress`, `Account`, `NewProcessName`,
  `TargetAccount`, `TicketEncryptionType` bormi? `DestinationIP`, `SentBytes`
  `CommonSecurityLog` ga tegishli — bitta jadvalda yo'q maydonlarni aralashtirib
  yubormadimmi?
- Defender XDR: `DeviceProcessEvents` / `DeviceLogonEvents` / `DeviceEvents` da
  `FileName`, `InitiatingProcessFileName`, `ProcessCommandLine`, `LogonType`,
  `AdditionalFields` bormi?
- Wazuh: `data.win.eventdata.commandLine`, `data.win.system.eventID` (katta-kichik
  harf!) to'g'rimi?
- ECS: `winlog.event_data.TargetImage`, `registry.path`, `url.original`.

## 3-ustuvorlik: hunt mantiqi

`catalog.py` dagi har bir hunt uchun:
- Windows Event ID lari to'g'rimi? (4625, 4624, 4672, 4740, 4769, 4648, 4720,
  4728/4732/4756, 7045/4697, 4698/4702, 5140/5145, 1102/104, 5001/5007)
- Sysmon ID lari: 10 (LSASS), 12/13 (registry), 19/20/21 (WMI) — to'g'rimi?
- `EVENT_ID_TRANSLATION['defender']` dagi ActionType qiymatlari
  (`LogonFailed`, `ProcessCreated`, `ServiceInstalled`, `UserAccountCreated`,
  `UserAccountAddedToLocalGroup`, `ScheduledTaskCreated`, `RegistryValueSet`)
  Defender XDR da haqiqatan shunday yoziladimi?
- Biror hunt juda ko'p noto'g'ri natija (false positive) beradimi va bu
  `tuning` matnida aytilganmi?
- Biror muhim hujum turi tushib qolganmi?

## 4-ustuvorlik: xavfsizlik va mustahkamlik

- `builder.py` dagi qochirish (`escape_inner`) har bir dialekt uchun yetarlimi?
  Foydalanuvchi `--user`, `--host`, `--ip` orqali so'rovni buza oladimi yoki
  unga qo'shimcha shart qo'sha oladimi?
- `notes` matnlari to'g'rimi yoki chalg'itadimi? (Masalan "agregatsiya qilmaydi"
  deyilgan dialekt aslida qila oladimi?)
- Aniq noto'g'ri natija beradigan, lekin ogohlantirilmagan holat bormi?

## Hisobot: `REVIEW_SIEM_RESULT.md`

Jadval ko'rinishida, jiddiylik bo'yicha tartiblangan:

| Jiddiylik | Fayl:qator | Muammo | To'g'ri variant |
|---|---|---|---|

Jiddiylik: **YUQORI** (so'rov SIEM da xato beradi yoki noto'g'ri natija qaytaradi),
**O'RTA** (ishlaydi, lekin noaniq yoki ko'p FP), **PAST** (uslub, matn).

Oxirida qisqa xulosa: qaysi dialektlarga ishonsa bo'ladi, qaysilari qayta
ko'rilishi kerak.

**Muhim:** ishonchingiz komil bo'lmagan joyda "bilmadim / tekshirish kerak" deb
yozing. O'ylab topilgan "to'g'ri variant" xato kodni tuzatilgan deb o'ylashimizga
olib keladi — bu hech narsa demagandan yomonroq.
