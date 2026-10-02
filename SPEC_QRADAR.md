# SPEC_QRADAR — QRadar CSV eksporti (ESET LEEF + FortiGate) uchun parser

## Muammo
Haqiqiy SIEM eksporti kitga tushmaydi:
```
bk ir chain "2026-09-21-data_export.csv"
Xato: '...' faylidan hodisalar topilmadi yoki o'qib bo'lmadi.
```

Sabab — bu QRadar CSV eksporti va u quyidagicha:
1. **Sarlavha (header) qatori YO'Q** — fayl to'g'ridan-to'g'ri ma'lumotdan boshlanadi, 84 ta ustun.
2. Xom syslog matni **base64** ichida (10-ustun). Ba'zi qatorlarda ochiq matn (21-ustun),
   ba'zilarida hex (61-ustun).
3. Base64 ichida ikki xil format aralash:
   - **ESET LEEF**: `LEEF:1.0|ESET|RemoteAdministrator|...|Filtered Website Event|cat=...\tsev=5\tdevTime=...`
     (tab bilan ajratilgan `key=value`)
   - **FortiGate syslog**: `<189>date=2026-09-21 time=12:27:24 devname="..." srcip=192.168.19.225 ...`
     (probel bilan ajratilgan `key=value`, qiymatlar goh qo'shtirnoqda)
4. FortiGate HA juftligi bir voqeani **ikki marta** yozadi (192.168.3.101 va 192.168.2.2 kollektorlari) —
   dedup shart, aks holda hamma son ikki barobar.
5. Uzoq sessiyalar davriy **yangilanish** yozuvlari beradi: bitta sessiya uchun `sentbyte`
   o'sib boradi. Yig'indi olinsa bayt hajmi 30 barobar oshib ketadi
   (o'lchadim: sodda yig'indi 403 MB, to'g'ri hisob 12.5 MB).

Sinov fayllari (mahalliy, real hodisa):
```
C:\Users\USER\Downloads\2026-09-21-data_export.csv\2026-09-21-data_export.csv   (760 qator)
C:\Users\USER\Downloads\2026-09-21-data_export.csv (1)\dest.csv                  (6681 qator)
```

## Yangi fayl: `bluekit/logs/qradar.py`

```python
def looks_like_qradar(path)          # -> bool
def load_qradar(path)                # -> list[dict]  (kanonik event)
def decode_payload(row)              # -> (raw_text, kind)   kind: 'leef'|'syslog_kv'|None
def parse_leef(raw)                  # -> dict
def parse_fortinet_kv(raw)           # -> dict
```

### looks_like_qradar
Sarlavhasiz CSV, >= 60 ustun, va birinchi 5 qatordan kamida bittasida 10-ustun
base64 bo'lib, dekodlanganda `LEEF:` yoki `devname=` / `logid=` bo'lsa — True.
`csv.field_size_limit(10**9)` majburiy (maydonlar uzun).

### decode_payload tartibi
1. 21-ustunda `LEEF:` bor bo'lsa — o'sha (ochiq matn).
2. 10-ustun base64 (`base64.b64decode(v + '===')`, `errors='replace'`).
3. 61-ustun hex (`bytes.fromhex(v.replace(' ', ''))`).
Hech biri bo'lmasa `(None, None)`.

### parse_fortinet_kv
`re.finditer(r'(\w+)=("([^"]*)"|\S+)', raw)` — qo'shtirnoqli qiymat ustun.

### Kanonik maydonlarga o'tkazish
| kanonik | LEEF | FortiGate |
|---|---|---|
| `ts` | `devTime` (`MMM dd yyyy HH:mm:ss z`) | `date` + `time` + `tz` |
| `host` | `deviceName` | `devname` |
| `user` | `accountName` | `user` yoki `unauthuser` |
| `src_ip` | `src` | `srcip` |
| `dest_ip` | `dst` | `dstip` |
| `dest_port` | — | `dstport` |
| `process` | `processName` | `app` |
| `event_id` | `ruleID` | `logid` |
| `channel` | `product` (ESET) | `devname` (fortigate) |
| `message` | `eventDesc` + `objectUri` | `msg` + `action` + `service` |
| `url` | `objectUri` | `hostname`/`url` (bo'lsa) |
| `hash` | `hash` | — |
| `action` | `actionTaken` | `action` |
| `bytes_sent` | — | `sentbyte` |
| `bytes_rcvd` | — | `rcvdbyte` |
| `session_id` | — | `sessionid` |
| `group` | `deviceGroupName` | — |

Kodlash: ESET maydonlarida kirill matni bor — fayl `utf-8` o'qilsin,
xato bo'lsa `errors='replace'`.

### Dedup (MAJBURIY)
Kalit: `(eventtime, srcip, srcport, dstip, dstport, action)`.
Birinchi uchragani qoladi. Statistikaga `stats['qradar_ha_duplicates']` yozilsin.

### Sessiya baytlari (MAJBURIY)
`session_id` bir xil bo'lgan yozuvlar uchun `bytes_sent`/`bytes_rcvd` —
**yig'indi emas, MAKSIMUM**. Yig'ish faqat turli sessiyalar orasida.
Buning uchun `aggregate_sessions(events)` yordamchi funksiyasi bo'lsin.

## Wiring
1. `bluekit/logs/parse.py` → `load_rows()` boshida: `.csv` bo'lsa va `looks_like_qradar(path)`
   rost bo'lsa — `load_qradar(path)` natijasi qaytarilsin (DictReader ishlatilmasin).
2. `bluekit/ir/correlator.py` → `load_events_from_file()` ga xuddi shu tekshiruv qo'shilsin
   (hozir u faqat JSON/NDJSON biladi — CSV umuman yo'q).

## IR korrelyator qoidalari (yangi bosqichlar)
`correlate_incident()` ga uchta qoida qo'shilsin:

1. **C2 beacon** — bitta `src_ip` dan bitta tashqi `dest_ip` ga >= 10 sessiya, interval
   medianasi stabil (stdev/median < 0.5):
   phase `Command and Control`, `T1071.001`,
   evidence: `"{src} -> {dst}:{port}, {n} sessiya, ~{interval}s interval, {mb} MB yuborilgan"`.
2. **AV bloklangan URL** — `action` da `Blocked URL` va `url` mavjud:
   phase `Command and Control`, `T1071.001`,
   evidence: `"{process} -> {url} (AV bloklagan, {n} marta)"`.
3. **Masquerading jarayon** — `process` yo'li `C:\ProgramData\` yoki `C:\Users\Public\`
   ostida bo'lsa va nomi Microsoft mahsulotiga o'xshasa (`DeviceSync`, `OneDrive`,
   `Teams`, `Update`, `Defender`, `Host`):
   phase `Defense Evasion`, `T1036.005`,
   evidence: jarayon to'liq yo'li + hash (bo'lsa).

Barcha ID lar `kb.validate()` dan o'tkazilsin: `T1071.001`, `T1036.005` — ikkalasi ham active.

## Testlar
```
python bk.py ir chain "C:\Users\USER\Downloads\2026-09-21-data_export.csv (1)\dest.csv"
python bk.py logs analyze "C:\Users\USER\Downloads\2026-09-21-data_export.csv (1)\dest.csv"
```
Kutilgan (men qo'lda o'lchaganman, shu sonlarga yaqin bo'lishi kerak):
- ikkala fayl birga: **114 ta ESET LEEF** + **3579 ta unikal FortiGate** yozuv
  (HA dedupdan oldin 7327);
- C2: `46.30.190.150`, domen `public.iivuz.online`, port 80;
- 4 ta ichki host FortiGate da: `192.168.19.223/.224/.225`, `192.168.202.51`;
- ESET da yana bittasi: `192.168.213.52`;
- jami yuborilgan **~12.5 MB**, qabul **~6.7 MB** (agar 400 MB chiqsa — sessiya
  agregatsiyasi noto'g'ri);
- zanjirda kamida: C2 beacon + AV blocked URL + masquerading bosqichlari.

Regressiya: `elasticsearch_export.json` bo'yicha `ir chain` avvalgidek 22 qadam bersin,
`logs analyze` 15000 event va `Noise suppressed: 195` bersin.

Ishni O'ZING bajar, subagentga topshirma. Stub qoldirma.
