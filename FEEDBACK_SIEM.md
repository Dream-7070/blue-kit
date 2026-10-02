# FEEDBACK_SIEM — 1-tur rad etildi

Loyiha: `D:\Claude Projects\CTF\blue-kit-staging`. Spec: `SPEC_SIEM.md`.

Hisobotingizda "birorta ham TODO, pass yoki yarim tayyor kod qoldirilmadi, hammasi yashil"
deyilgan. Bu **to'g'ri emas**. Quyidagilar fayllarning o'zidan olingan:

## Aniqlangan nuqsonlar

**1. `bluekit/siem/builder.py:44` — generatorning o'zi yo'q.**

```python
    # ... placeholder for builder logic ...
    query = f"TODO query for {hunt_id} in {siem}"
    if syntax == 'aql':
        query = f"SELECT * FROM events WHERE event_id=1 GROUP BY src_ip HAVING count >= 1 LAST {days} DAYS"
```

`build_query` hunt ning `where`, `aggregate`, `select` maydonlarini **umuman o'qimaydi**.
Qaysi hunt so'ralishidan qat'i nazar bitta xil matn qaytadi. `event_id=1`, `count >= 1`,
`FROM *` — bular o'ylab topilgan qiymatlar, hech bir SIEM da ishlamaydi.
`FIELD_MAPS` va `SOURCE_MAPS` yozilgan, lekin `build_query` ularni bir marta ham
ishlatmaydi (import ham qilinmagan).

**2. `bluekit/siem/catalog.py:13` — 32 ta soxta hunt.**

```python
HUNTS = {}

# We will generate 32 dummy hunts for now to pass criteria
```

Hammasining `where` i bir xil (`event_id == 4625`), `description` = nomi, `tuning` =
`'Tune me'`, va birinchisidan boshqa hammasining ATT&CK ID si `T1003.001`. Ya'ni
`persist-run-key` ham, `c2-dns-tunnel` ham, `web-attack-patterns` ham
"4625 ni src_ip bo'yicha sanash" so'rovini beradi. Spec ning 4-bo'limida 32 ta hunt ning
har biri uchun aniq shart yozilgan edi.

**3. `tests/test_siem.py` — testlarning yarmi bo'sh.**

`test_attack_active`, `test_fallback_notes`, `test_bk_preset_fieldmap`, `test_snapshot` —
to'rttasi ham faqat `pass`. `test_escaping` da tekshiruv umuman yo'q (izoh:
`# Should not throw exception, dummy check`). Qolgan testlar dummy ma'lumot bilan ham
o'tadi — ya'ni ular hech narsani himoya qilmaydi.

**4. `builder.py:6` — `escape_value` noto'g'ri.**

QRadar AQL da matn literali **bitta qo'shtirnoq** (`'`) ichida yoziladi, siz esa qradar
uchun `"` ni qochirayapsiz — `'` esa qochirilmay o'tib ketadi, bu aynan so'rovni buzadigan
belgi. Har bir dialekt uchun o'sha dialekt literalida ishlatiladigan belgi qochirilsin.

**5. `builder.py:86` — `bk_preset` None bo'lganda `'ecs'` ga tushib qolyapti.**

Chronicle/Sumo/LogScale eksporti ECS emas. `bk_preset` None bo'lsa `--preset` **umuman
yozilmasin**.

**6. `builder.py:80` — `'language': syntax.upper()` → `DQL`, `CEF_SEARCH`, `SUMO`.**

Tilning haqiqiy nomi bo'lsin: `AQL, SPL, KQL, ES|QL, KQL/Lucene, UDM Search, Sumo Query,
CEF Search, CQL` — buni `DIALECTS` ichida `language` maydoni sifatida saqlang.

**Ijobiy:** `fields.py`, `dialects.py` dagi `DIALECTS`, `FIELD_MAPS`, `SOURCE_MAPS` —
yaxshi bajarilgan, ularni **saqlang**, qayta yozmang (faqat `language` maydonini qo'shing).
Boshqa fayllarga tegmaganingiz ham to'g'ri.

---

# 2-tur — faqat shu ish (qamrov toraytirildi)

Bu turda **32 ta hunt kerak emas**. Faqat **8 ta haqiqiy hunt** va ular uchun
**haqiqiy ishlaydigan generator**. Qolgan 24 tasini 3-turda so'rayman.

## A. `builder.py` — haqiqiy render

`build_query` hunt ning `where` / `aggregate` / `select` / `logsource` ini o'qib,
`FIELD_MAPS[siem]` va `SOURCE_MAPS[siem]` orqali so'rov yasasin. Har bir syntax klass
uchun alohida funksiya bo'lsin: `render_aql`, `render_spl`, `render_kql`, `render_esql`,
`render_dql`, `render_udm`, `render_sumo`, `render_cef`, `render_cql`.

Shart daraxtini (`all` / `any` / `none` va operatorlar) rekursiv aylanib chiquvchi
umumiy funksiya bo'lsin; har bir klass faqat o'z belgilarini beradi (AND/OR/NOT,
`LIKE '%x%'` yoki `*x*` yoki `contains`, qo'shtirnoq turi). Operatorni har bir hunt uchun
qo'lda yozish MUMKIN EMAS.

Kanonik maydon `FIELD_MAPS[siem]` da yo'q bo'lsa — spec dagi fallback qoidasi:
`message`/raw bo'yicha qidirish + `notes` ga o'zbekcha ogohlantirish.

## B. `catalog.py` — 8 ta TO'LIQ hunt

Dummy sikl butunlay o'chirilsin. Quyidagi 8 tasi qo'lda, to'liq yozilsin
(`description` va `tuning` — mazmunli o'zbekcha matn, `name` dan nusxa emas):

| id | shart (qisqacha) | ATT&CK (KB v19.2 da tekshirilgan) |
|---|---|---|
| `auth-bruteforce` | `event_id in [4625]`, agg: count by `src_ip`,`user` >= threshold(20) | T1110, T1110.001 |
| `auth-password-spray` | `event_id in [4625]`, agg: `distinct_count:user` by `src_ip` >= 10 | T1110.003 |
| `auth-external-rdp` | `event_id in [4624]` AND `logon_type eq 10` AND `src_ip is_public` | T1021.001, T1078 |
| `persist-service-install` | `event_id in [7045, 4697]` | T1543.003 |
| `exec-encoded-powershell` | `event_id in [4688]` AND `command_line contains_any ['-enc','-EncodedCommand','FromBase64String','-nop -w hidden']` | T1059.001, T1027 |
| `exec-office-child` | `parent_process endswith_any [winword.exe, excel.exe, powerpnt.exe, outlook.exe]` AND `process endswith_any [cmd.exe, powershell.exe, wscript.exe, mshta.exe]` | T1566.001, T1204.002 |
| `evasion-log-cleared` | `event_id in [1102, 104]` OR `command_line contains 'wevtutil cl'` | T1685.005 |
| `c2-dns-tunnel` | `logsource: dns`, agg: `distinct_count:dns_query` by `host` >= 200 | T1071.004, T1572 |

**T1070.001 va T1562.001 ni YOZMANG** — ular ATT&CK v19 da revoked. To'g'risi:
`T1685.005` (log tozalash) va `T1685` (AV o'chirish). Buni KB da o'zingiz tasdiqlang:
`python bk.py kb validate T1685.005 T1685 T1070.001 T1562.001`.

## C. Snapshot — aynan shu uchta chiqish

Bular test dagi kutilgan qiymat bo'ladi. Bo'sh joy/qator tartibi shunday bo'lsin.

`build_query('auth-bruteforce', 'qradar')` → `query`:

```
SELECT sourceip AS src_ip, username AS user, logsourcename AS host, COUNT(*) AS event_count
FROM events
WHERE "EventID" = 4625
GROUP BY sourceip, username
HAVING COUNT(*) >= 20
ORDER BY event_count DESC
LIMIT 200
LAST 7 DAYS
```

`build_query('exec-encoded-powershell', 'splunk')` → `query`:

```
index=wineventlog source="WinEventLog:Security" earliest=-7d
| search EventCode=4688 AND (Process_Command_Line="*-enc*" OR Process_Command_Line="*-EncodedCommand*" OR Process_Command_Line="*FromBase64String*" OR Process_Command_Line="*-nop -w hidden*")
| table _time, host, user, Parent_Process_Name, New_Process_Name, Process_Command_Line
| head 200
```

`build_query('auth-bruteforce', 'sentinel')` → `query`:

```
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4625
| summarize event_count = count() by IpAddress, Account, Computer
| where event_count >= 20
| order by event_count desc
| take 200
```

Qolgan 9 dialekt uchun ham **shu darajada haqiqiy** sintaksis kutilmoqda (o'ylab topilgan
kalit so'zlar emas).

## D. Testlar — dummy ma'lumot bilan O'TMAYDIGAN bo'lsin

`pass` qolgan to'rtta test to'ldirilsin va quyidagilar qo'shilsin:

1. **Har bir hunt o'z izini qoldirsin.** Ro'yxat: har bir hunt uchun `(hunt_id, siem,
   so'rovda albatta uchraydigan matn)` — masalan `('exec-encoded-powershell', 'splunk',
   'FromBase64String')`, `('auth-external-rdp', 'sentinel', 'LogonType')`,
   `('c2-dns-tunnel', 'elastic', 'dns.question.name')`,
   `('persist-service-install', 'qradar', '7045')`. 8 ta hunt ning har biri uchun kamida
   bitta shunday tekshiruv. Dummy `where` bilan bu testlar yiqiladi — maqsad shu.
2. **Ikki hunt bir xil so'rov bermasin:** barcha 8 hunt ning `qradar` dagi `query` si
   o'zaro **farqli** (`len(set(...)) == 8`).
3. **ATT&CK:** har bir hunt ning har bir ID si KB da bor va `status == 'active'`
   (`bluekit.kb.query.KB().validate`), KB yo'q bo'lsa `skipUnless`.
4. **Escaping (haqiqiy tekshiruv):** `build_query('auth-bruteforce', siem, {'user': "a' OR
   1=1 --"})` — 12 dialektning hammasida qochirilmagan `'` so'rovga tushmasin.
5. **Snapshot:** yuqoridagi uchta matn bilan `assertEqual` (bo'sh joygacha).
6. **`bk_preset` ↔ fieldmap:** None bo'lmagan har bir `bk_preset`
   `bluekit/logs/fieldmap.yaml` ning `presets` ida bor; None bo'lsa `next_steps` da
   `--preset` **yo'q**.
7. **Fallback:** `FIELD_MAPS['graylog']` da `command_line` yo'q →
   `build_query('exec-encoded-powershell', 'graylog')['notes']` da ogohlantirish bor.

## E. Qabul

```
python -m unittest discover -s tests -p "test_*.py" -q
python -m bluekit.siem.cli query auth-bruteforce --siem qradar
python -m bluekit.siem.cli query exec-encoded-powershell --siem splunk --days 30
python -m bluekit.siem.cli query c2-dns-tunnel --siem all
```

Hisobotda quyidagilarni **ko'chirib** keltiring (o'z so'zingiz bilan emas):
- `python -m bluekit.siem.cli query auth-bruteforce --siem qradar` ning to'liq chiqishi
- `python -m bluekit.siem.cli query c2-dns-tunnel --siem elastic` ning to'liq chiqishi
- `unittest` ning oxirgi 3 qatori

Agar biror talabni bajara olmagan bo'lsangiz — **buni ochiq yozing**. "Hammasi tayyor"
deb yozib, ichida placeholder qoldirish eng yomon variant: keyingi tur shunchaki yana
bir marta yo'qotilgan vaqt bo'ladi.
