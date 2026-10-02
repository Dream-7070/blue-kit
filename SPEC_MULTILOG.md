# SPEC_MULTILOG — `logs analyze` bir nechta turli logni birdaniga tahlil qilsin

Loyiha: `D:\Claude Projects\CTF\blue-kit-staging`

## Muammo

`bk logs analyze` bitta fayl oladi. Musobaqada bir hodisa SIEM eksporti (ELK JSON/CSV),
Windows event, firewall syslog, Linux web-server access logi va pochta serveri logida
birdaniga ko'rinadi. Ularni bitta vaqt chizig'ida birlashtirish kerak.

Hozirgi holatda xom matnli loglar (nginx/apache access, syslog, postfix, iptables) uchun
`load_rows()` faqat `{"message": <qator>}` beradi — **vaqt, host, IP ajratilmaydi**.
Shuning uchun ularni birlashtirib bo'lmaydi: vaqtsiz hodisalar timeline ning oxiriga
tashlanadi, hostsiz hodisalar `chains` ga umuman tushmaydi (`timeline.py:148`).

## 0. Qoidalar

**Mavjud imzolar buziladi:** `load(path, preset=None, map_path=None)` va
`load_rows(path)` **o'zgarmaydi** (ularni `ir/correlator.py`, `doctor.py`, `bk.py:268`,
`tests/test_logs.py`, `tests/test_sigma.py` ishlatadi). Faqat **qo'shimcha** qilinadi.

**TEGMANG:** `bk.py`, `bluekit/web/**`, `bluekit/ir/**`, `bluekit/siem/**`,
`bluekit/resp/**`, `bluekit/kb/**`, `bluekit/logs/detect.py`, `bluekit/logs/eventmap.yaml`,
`bluekit/logs/noise.yaml`, mavjud `tests/test_*.py`. (CLI va web ni Claude o'zi ulaydi.)

**O'zgartiriladigan:** `bluekit/logs/parse.py`, `bluekit/logs/report.py`,
`bluekit/logs/timeline.py` — **faqat qo'shimcha**, fayllarni QAYTA YOZMANG.
**Yangi:** `tests/test_multilog.py`.

Fayllarni UTF-8 saqlang, mavjud Unicode belgilarni (`✔`, `—`, `'` ...) o'zgartirmang,
satr oxirini (LF/CRLF) o'zgartirmang. Hech qanday placeholder/stub/`pass`/TODO
qoldirmang. Tashqi kutubxona qo'shmang (faqat stdlib + mavjud `yaml`).

## 1. `parse.py` — xom matn qatorlaridan ts/host/IP ajratish

`load_rows()` ning oxirgi `else:` shoxi (xom matn) hozir `{'timestamp':..,'message':..}`
yoki `{'message':..}` qaytaradi. Uni **kengaytiring**: yangi yordamchi
`_parse_text_line(line, year_hint)` qaytaradi `dict` (bo'sh bo'lishi mumkin) va
`load_rows` uni `{'message': line}` ustiga qo'shadi. Mavjud ISO-vaqt shoxi
(`^\d{4}-\d{2}-\d{2}[T ]...`) **birinchi** tekshiriladi va xulqi o'zgarmaydi.

Qo'llab-quvvatlanadigan formatlar (tartib bilan sinang, birinchi mos kelgani):

| Format | Misol | Ajratiladigan maydonlar |
|---|---|---|
| Apache/nginx combined | `198.51.100.45 - - [05/Oct/2026:09:10:11 +0000] "GET /x HTTP/1.1" 200 5 "-" "curl"` | `timestamp` (UTC ga o'girilgan ISO), `src_ip` = birinchi maydon (faqat IPv4/IPv6 bo'lsa) |
| syslog RFC3164 | `Oct  5 09:11:02 fw01 kernel: DROP IN=eth0 SRC=1.2.3.4 DST=5.6.7.8 ...` | `timestamp`, `host` = `fw01` |
| iptables/firewall `KEY=VAL` | ustidagi qatordagi `SRC=` `DST=` | `src_ip`, `dest_ip` (faqat `SRC=`/`DST=` bo'lsa; ular syslog qatoridan tashqari ham ishlashi kerak) |
| postfix/dovecot/sendmail syslog | `Oct  5 08:55:12 mail postfix/smtpd[1234]: ... from unknown[198.51.100.45]: ...` | `timestamp`, `host` = `mail`; IP: birinchi `\[(\d+\.\d+\.\d+\.\d+)\]` -> `src_ip` |

Qoidalar:
- Maydon nomlari `fieldmap.yaml` dagi **mavjud** kanonik nomlarga mos kelishi shart:
  `timestamp` (mavjud ISO shoxi ham shuni ishlatadi), `host`, `src_ip`, `dest_ip`. Avval
  `bluekit/logs/fieldmap.yaml` ni o'qib, bu nomlar `default` xaritada `ts`/`host`/`src_ip`/
  `dest_ip` ga borishini **tekshiring**; bormasa `_parse_text_line` shu xaritada bor
  ustun nomini ishlatsin (taxmin qilmang).
- Apache vaqti `[DD/Mon/YYYY:HH:MM:SS +ZZZZ]`: ofsetni hisobga olib **UTC naive** ISO
  (`YYYY-MM-DDTHH:MM:SS`) qaytaring. Oy nomi ingliz (`Jan..Dec`), `locale` ga bog'lanmang.
- syslog vaqti yilsiz: `year_hint` = **fayl `mtime` yili**. Agar hosil bo'lgan sana
  mtime dan 1 kundan ko'p KEYIN bo'lsa (masalan dekabr logi yanvarda saqlangan) yilni
  1 ga kamaytiring. `Oct  5` (bir raqamli kun, ikki bo'sh joy) ham ishlashi shart.
- `load_rows` ga yangi ixtiyoriy parametr **qo'shmang**; yil `os.path.getmtime(path)` dan
  `load_rows` ichida olinadi.
- Noto'g'ri sana (`Feb 31`) — `ValueError` ni ushlab, vaqtsiz qoldiring (qator tushib
  ketmasin).
- `src_ip` faqat haqiqiy IP bo'lsa (`ipaddress.ip_address` bilan tekshiring); `-`,
  `unknown`, hostname bo'lsa qo'shilmasin.

## 2. `parse.py` — `source` va `load_many`

### 2.1 `load()` ga `source`

`load()` qaytaradigan har bir `ev` lug'atiga yangi kalit qo'shing:
`'source': os.path.basename(path)` (ev shablonida, `'raw': row` yonida). Boshqa hech narsa
o'zgarmaydi. Kalit `blob`/`message` ga **kirmasin**.

### 2.2 `load_many(items, preset=None, map_path=None)`

Yangi funksiya. `items` — `str` yoki `(path, preset_or_None)` juftliklari ro'yxati.
Har element uchun `load(path, preset=item_preset or preset, map_path=map_path)`
chaqiriladi; natijalar bitta ro'yxatga yig'iladi va `load()` bilan **bir xil qoida** bilan
saralanadi: ts bor hodisalar ts bo'yicha (barqaror sort — teng ts da fayl tartibi
saqlansin), ts yo'qlari oxirida (o'z tartibida).

Host yo'q bo'lgan hodisa (`ev['host'] is None`) uchun **faqat `load_many` da** (ya'ni
`load()` xulqi o'zgarmaydi): `ev['host'] = '[' + source + ']'`, masalan `[nginx_access.log]`.
Sabab: hostsiz hodisa `chains` ga tushmaydi. Kvadrat qavs bu "haqiqiy host emas, log
manbasi" ekanini ko'rsatadi.

Bitta element bo'lsa `load_many([x])` natijasi `load(x)` ga **teng** bo'lishi kerak
(faqat `source` kaliti va yuqoridagi `[...]` host farqi bundan mustasno emas: bitta fayl
uchun ham `[...]` host qo'llanadi — buni testda tekshiring va hujjatlang).

Bo'sh fayl / o'qib bo'lmaydigan fayl butun jarayonni yiqitmasin: `load_many` uni
o'tkazib yuboradi va `sys.stderr` ga `[!] <fayl>: 0 qator o'qildi` deb yozadi.

## 3. `timeline.py` — manba va manbalararo IOC

`build()` da (faqat qo'shimcha kalitlar, mavjudlari o'zgarmaydi):
- har `timeline` yozuviga `'source': ev.get('source')`;
- `iocs` ichida har `(type, value)` uchun `sources` — shu IOC ko'ringan `source` larning
  **tartiblangan** (alifbo) ro'yxati (`ev.get('source')` None bo'lsa qo'shilmasin);
  `formatted_iocs` elementiga `'sources': [...]` kaliti qo'shiladi.

## 4. `report.py` — `analyze_logs` bir nechta fayl

`analyze_logs(file_path, ...)` birinchi argumenti endi **`str` yoki ro'yxat** (elementlar
`str` yoki `(path, preset)`). Str bo'lsa xulq **aynan bugungidek** (u `load()` ni
chaqiradi, `load_many` ni emas — bitta fayl rejimi ilgarigi natijani o'zgartirmasin).
Ro'yxat bo'lsa `load_many` ishlatiladi.

Ro'yxat rejimida:
- JSON chiqishdagi `stats` ga `'sources': {<source>: {'events': n, 'events_with_hits': n}}`
  qo'shiladi (bitta fayl rejimida ham qo'shilsa bo'ladi, lekin majburiy emas);
  `stats` ning mavjud kalitlari o'zgarmaydi.
- Konsol chiqishida `Events:` qatoridan keyin har manba uchun bir qator:
  `  Source nginx_access.log: 3 events, 2 with hits`.
- Yangi blok "Cross-source IOCs": faqat `len(sources) >= 2` bo'lgan IOC lar, eng ko'p
  manbada uchraganidan boshlab, eng ko'pi 10 ta: `  198.51.100.45 | ip | 3 sources: firewall.log, mail.log, nginx_access.log`.
  Bo'sh bo'lsa blok chop etilmaydi.

## 5. Testlar — `tests/test_multilog.py` (`unittest`)

`tempfile.TemporaryDirectory` da haqiqiy fayllar yarating (namuna 4 fayl):
1. `siem.json` — `{"hits":{"hits":[{"_source":{"@timestamp":"2026-10-05T09:01:10Z","host":{"name":"hr-pc-01"},"event":{"code":4688},"process":{"name":"powershell.exe","command_line":"powershell -enc SQBFAFgA..."},"user":{"name":"hr.anna"}}}]}}`
2. `nginx_access.log` — 3 qator: `198.51.100.45 - - [05/Oct/2026:09:10:11 +0000] "POST /api/v1/upload_avatar.php HTTP/1.1" 200 512 "-" "curl/7.68"`, shell.php?cmd=whoami, `UNION SELECT`.
3. `firewall.log` — `Oct  5 09:11:02 fw01 kernel: DROP IN=eth0 SRC=198.51.100.45 DST=10.0.1.15 PROTO=TCP SPT=4444 DPT=22`.
4. `mail.log` — `Oct  5 08:55:12 mail postfix/smtpd[1234]: NOQUEUE: reject: RCPT from unknown[198.51.100.45]: 554 5.7.1 Relay access denied`.

`syslog` fayllarining `mtime` ini `os.utime` bilan 2026-10-06 ga o'rnating.

Tekshiriladigan narsalar (har biri alohida test metodi):
- apache qatori: `ts == datetime(2026,10,5,9,10,11)`, `src_ip == '198.51.100.45'`.
- apache `+0500` ofsetli qator UTC ga to'g'ri o'giriladi (`09:10:11 +0500` -> `04:10:11`).
- syslog: `ts == datetime(2026,10,5,9,11,2)`, `host == 'fw01'`, `src_ip`/`dest_ip` to'g'ri.
- yil chegarasi: `Dec 31 23:59:00` va mtime `2027-01-02` -> yil 2026.
- postfix: `host=='mail'`, `src_ip=='198.51.100.45'`; `from unknown[unknown]` da src_ip yo'q.
- `Feb 31 10:00:00 h x` — qator yo'qolmaydi (`load_rows` uzunligi 1), ts None.
- `load_many` 4 fayl: 8 hodisa, ts bo'yicha o'sish tartibida (mail 08:55 birinchi),
  `source` to'g'ri, host'i yo'q nginx hodisalarida `[nginx_access.log]`.
- **Tartibni teskari qilib qayta yuguring** (fayllar ro'yxatini `reversed`) — natija
  tartibi aynan bir xil bo'lishi kerak (tartib vaqt bo'yicha, fayl tartibi emas).
- `analyze_logs([4 fayl], kb, json_path=...)`: `stats.sources` da 4 kalit;
  `198.51.100.45` IOC ida `sources` uchta fayl (`firewall.log`, `mail.log`,
  `nginx_access.log`); siem.json dan `T1059.001`, nginx dan `T1505.003` topilgan.
  `kb` uchun `bluekit.kb.query.KB` ni `tests/test_logs.py` qanday yaratsa shunday yarating
  (o'sha faylni o'qing).
- Regressiya: bitta `str` bilan `analyze_logs` natijasi (`timeline` uzunligi, `stats`
  kalitlari) o'zgarmagan; `load_rows` ISO-vaqtli xom qatorni (`2026-10-05 09:00:00 msg`)
  avvalgidek `{'timestamp':..,'message':..}` qaytaradi.

Dummy/hardcode bilan o'tadigan test yozmang: har test yuqoridagi haqiqiy fayl
tarkibidan hisoblangan qiymatni tekshirsin.

## 6. Tugagach

`python -m unittest discover -s tests` — hammasi (204+) yashil bo'lsin. Hisobotda
o'zgargan fayllar va qator sonlarini yozing. `bk.py`, `web/**` ga TEGMANG.
