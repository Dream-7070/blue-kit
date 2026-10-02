# SPEC_NOISE — log analyzer noise reduction (round 1)

## Muammo (o'lchangan)
`elasticsearch_export.json` (15 000 ES hit) bo'yicha hozirgi holat:
- `parse.load()` ES exportni 1 ta event deb o'qiydi (hits.hits unwrap yo'q).
- Qo'lda unwrap qilinganda: 15 000/15 000 event "detection" beradi — 299 777 ta `low`
  hit, hammasi `blob_search` manbasidan (masalan `C:\Program Files\outlook.exe`
  matni T1685, T1112, T1190, T1218 ... ga mos keladi).
- 209 ta `high` hitning 196 tasi Debian default cron qatori:
  `CRON[...]: (root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))`
  → T1053.003 high (soxta).
- Haqiqiy signal: 16 ta auditd/suricata event + nginx SQLi/webshell + 1 beacon.

Sabab: `kb.search()` FTS5 da barcha tokenlarni `OR` bilan qidiradi; `detect.py`
natijaning hammasini `low` hit qilib chiqaradi; benign baseline yo'q.

## O'zgartiriladigan fayllar
1. `bluekit/logs/parse.py`
2. `bluekit/logs/detect.py`
3. `bluekit/logs/noise.yaml` (YANGI)
4. `bluekit/logs/report.py` (faqat detect_event chaqiruvi uchun `deep` uzatish)
5. `bk.py` (yangi `--deep` flag)

---

## 1. parse.py — nested JSON unwrap

`load_rows(path)` ichida, `.json`/`.ndjson` bo'lganda `json.loads` natijasi dict bo'lsa:

- Agar `data["hits"]["hits"]` list bo'lsa (Elasticsearch/OpenSearch export):
  har bir element uchun `flatten_dict(el.get("_source", el))` → row.
  Qo'shimcha: `row["es_index"] = el.get("_index")`, `row["es_id"] = el.get("_id")`
  (faqat mavjud bo'lsa; bu maydonlar fieldmap ga tushmasligi kerak — unmapped bo'lib
  message ga qo'shilmasin, pastga qarang).
- Aks holda, quyidagi kalitlardan birinchi topilgani list bo'lsa, o'shani ishlat:
  `events`, `Events`, `records`, `Records`, `results`, `data`, `logs`, `entries`.
  Har bir element dict bo'lsa `flatten_dict(el)`, aks holda `{"message": str(el)}`.
- Hech biri mos kelmasa — hozirgi xatti-harakat (bitta row) saqlanadi.

`flatten_dict` ni o'zgartirish: qiymat list bo'lsa, hozir u tushib qolyapti.
List qiymat uchun: elementlar oddiy skalyar bo'lsa `", ".join(str(x))`, dict bo'lsa
`flatten_dict(el, f"{key}.{i}")` bilan yoy. (Bu ES `_source` ichidagi massivlar uchun.)

`load()` ichida: `es_index`/`es_id` va `_score` kabi metadata maydonlari `message` ga
qo'shilmasin — `UNMAPPED_SKIP = {"es_index", "es_id", "_score", "took", "timed_out"}`
ro'yxati bo'yicha tashlab ketilsin (ular `raw` da baribir qoladi).

### Qabul mezoni
`bk.exe logs analyze elasticsearch_export.json` → `Events: 15000`, `Hosts: 26`.

---

## 2. detect.py — blob_search default OFF

`detect_event(kb, ev, deep=False, noise=None)` ko'rinishiga o'zgartirilsin
(eski chaqiruvlar `detect_event(kb, ev)` ishlashda davom etsin).

- `eventmap` va `heuristic` hitlar — hozirgidek.
- `blob_search` bloki faqat `deep=True` bo'lganda ishlaydi. Va `deep=True` bo'lganda ham:
  - `kb.search(...)` natijasidan heuristic bo'lmaganlari uchun `max_score` hisoblanadi;
  - faqat `score >= 0.35 * max_score` bo'lganlari qoladi;
  - eng yuqori 3 tasi (score bo'yicha) olinadi, confidence `low`;
  - hit ga `'source': 'blob_search'` va `'evidence'` hozirgidek.
- Matn tanlash: hozir `command_line` bo'lmasa `message`. Shunday qolsin.

## 3. noise.yaml — benign baseline

Yangi fayl `bluekit/logs/noise.yaml`, struktura:

```yaml
- name: "Debian cron.daily anacron"
  pattern: "CRON\[\d+\]:\s*\(root\)\s*CMD\s*\(test -x /usr/sbin/anacron \|\| \( cd / && run-parts"
  action: drop          # drop | downgrade
  note: "OS default crontab entry"
```

Qamrab olinadigan qoidalar (kamida shular):
| name | pattern (mazmuni) | action |
|---|---|---|
| Debian cron.daily anacron | yuqoridagi | drop |
| logrotate cron | `CRON\[\d+\]: \(root\) CMD \(/usr/local/bin/logrotate /etc/logrotate\.conf\)` | drop |
| apt daily systemd | `systemd\[1\]: (Starting\|Finished) Daily apt` | drop |
| rsyslogd action resumed | `rsyslogd: .*action .* resumed` | drop |
| sshd normal disconnect | `sshd\[\d+\]: Received disconnect from .* disconnected by user` | drop |
| Windows signed binary path | `^[A-Za-z]:\\(Windows\|Program Files( \(x86\))?)\\` va command_line faqat shu path bo'lsa | drop |
| nginx static 2xx | `"(GET\|HEAD) /(static\|assets\|favicon)[^"]*" (200\|204\|304)` | drop |

Yuklash: `load_noise()` — `noise.yaml` ni bir marta o'qiydi, `re.compile(pattern, re.I)`
qiladi, xato regex bo'lsa `WARNING:` chop etib o'tkazib yuboradi (eventmap validatsiyasi uslubida).

Qo'llash — `detect_event` oxirida, dedup dan OLDIN:
- Tekshiriladigan matn: `ev.get('command_line') or ev.get('message') or ''`;
- `action: drop` mos kelsa → barcha hitlar tashlanadi, `[]` qaytadi;
- `action: downgrade` mos kelsa → har bir hitning confidence `low` ga tushiriladi va
  `h['noise'] = <rule name>` qo'shiladi.
- Event timeline dan O'CHIRILMAYDI — faqat detectionlari olib tashlanadi.

MUHIM: drop qoidasi hech qachon `eventmap` manbasidan kelgan `high` hitni
o'chirmasin? — Yo'q, o'chirsin: benign baseline ustunroq. Lekin drop bo'lgan
eventlar soni `analyze_logs` natijasida `suppressed` sifatida hisoblansin (pastga qarang).

## 4. report.py

`analyze_logs(file_path, kb, preset=None, map_path=None, json_path=None, html_path=None, deep=False)`:
- `detect_event(kb, ev, deep=deep)` chaqirilsin;
- noise tufayli hitlari o'chirilgan eventlar soni sanalsin va JSON chiqishiga
  `"stats": {"events": N, "events_with_hits": N, "suppressed_by_noise": N, "deep": bool}`
  qo'shilsin. Mavjud kalitlar (`timeline`, `chains`, `iocs`, `coverage`, `checkers`)
  o'zgarmasin — web UI buzilmasligi kerak.
- CLI xulosasiga bitta qator: `Noise suppressed: N events` (faqat N>0 bo'lsa).

## 5. bk.py

`logs analyze` parseriga `--deep` (store_true) qo'shilsin va `analyze_logs(..., deep=args.deep)`
ga uzatilsin. Yordam matni: "KB full-text qidiruvini yoqish (ko'p low-confidence natija beradi)".
`bluekit/web/server.py` da `/api/logs/analyze` uchun `data.get('deep', False)` uzatilsin.

---

## Testlar (o'zing ishga tushirib tekshir)
```
python bk.py logs analyze "C:\Users\USER\Downloads\AyuGram Desktop\elasticsearch_export.json" --json-out out.json
```
Kutilgan natija:
- `Events: 15000`
- `high` hitlar soni **20 dan kam** (196 ta anacron yo'qoladi; qoladigan real hitlar:
  T1190 SQLi x4, T1059.006 reverse shell, T1105 curl|bash cron, T1003.008 /etc/shadow,
  T1136.001 useradd, T1046 nmap, T1033/T1016/T1082 whoami).
- `iocs` va `timeline` ichida `blob_search` manbali hit BO'LMASIN (deep flagsiz).
- `--deep` bilan qayta ishga tushirilganda blob_search hitlar paydo bo'ladi, lekin
  har bir eventda **3 tadan ko'p emas**.
- Mavjud sample bilan regressiya: `python bk.py logs analyze data/samples/win_phishing.csv`
  — high/medium hitlar avvalgidek qolishi kerak (anacron/logrotate yo'q u yerda).

Kod uslubi: mavjud fayllar uslubiga mos (4 space, type hint yo'q, yaml.safe_load,
modul darajasida cache global). Yangi kutubxona qo'shma.
