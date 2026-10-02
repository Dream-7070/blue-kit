# SPEC_NOISE2 — IOC / chain / checker prioritizatsiyasi (round 2)

Oldingi bosqich (SPEC_NOISE.md) detectionlardagi shovqinni kamaytirdi.
Bu bosqich `bluekit/logs/timeline.py` dagi IOC, chain va checker chiqishini tartibga soladi.

## Muammo (o'lchangan, elasticsearch_export.json)
- IOC ro'yxatida har bir eventning src/dest IP si bor: `10.0.1.15` count 10588,
  `10.0.0.5` count 3654, `C:\Program Files\outlook.exe` count 490 — hammasi benign.
- 26 ta chain yaratildi, 24 tasi "no tactics" (hech qanday detection yo'q hostlar).
- Haqiqiy signal: 198.51.100.45 (attacker), 203.0.113.88 (C2 beacon, 120s),
  10.0.2.20 (lateral target), /tmp/.cron_backup, /tmp/stolen_id_rsa.

## O'zgartiriladigan fayllar
1. `bluekit/logs/timeline.py`
2. `bluekit/logs/report.py` (build() qaytishi 5 elementga o'zgargani uchun)
3. `bluekit/logs/report.py` HTML va `bluekit/web/static/app.js` — yangi maydonlarni ko'rsatish

---

## 1. IOC filtri

`build()` ichida har bir event uchun avval aniqlansin:
```
hits = hits_by_index.get(i, [])
has_signal = any(h['confidence'] in ('high', 'medium') for h in hits)
```

`add_ioc(type_, val, ts, linked, techniques)` ga kengaytirilsin. Qoidalar:

- **IP** (`classify()` orqali `private` aniqlanadi):
  - public IP → doim qo'shiladi;
  - private/loopback IP → faqat `has_signal` bo'lsa qo'shiladi.
- **win_path / unix_path** (command_line dan):
  - quyidagi prefikslar benign hisoblanadi va faqat `has_signal` bo'lsa qo'shiladi:
    `C:\Windows\`, `C:\Program Files\`, `C:\Program Files (x86)\`,
    `/usr/bin/`, `/usr/sbin/`, `/bin/`, `/sbin/`, `/lib/`, `/usr/lib/`;
  - qolganlari (masalan `/tmp/...`, `C:\Users\...\AppData\...`) doim qo'shiladi.
- **username** (4720/useradd) — hozirgidek doim.

Har bir IOC yozuvida qo'shimcha maydonlar:
- `linked` (bool) — shu IOC kamida bitta medium/high detectionli eventda uchraganmi;
- `techniques` (list) — o'sha eventlardagi texnika ID lari (unique, tartiblangan);
- `private` (bool, faqat ip uchun).

`formatted_iocs` tartibi: `linked=True` birinchi, keyin `count` kamayish bo'yicha.

## 2. Chainlar

- Chain faqat kamida bitta **medium yoki high** detectionga ega hostlar uchun quriladi.
- Chain `events` — o'sha hostning **detectionga ega** eventlari indekslari
  (low bo'lsa ham kiradi), vaqt bo'yicha tartibda. Qo'shimcha maydonlar:
  - `high_count`, `medium_count` — chaindagi hit sonlari;
  - `event_count_total` — hostdagi umumiy event soni (kontekst uchun).
- Chainlar `high_count` keyin `medium_count` kamayishi bo'yicha tartiblanadi,
  `id` tartiblashdan KEYIN 1 dan beriladi.
- Signalsiz hostlar `stats['hosts_without_signal']` (list of host name) ga yoziladi.

## 3. Checker / beacon

`checkers` ro'yxatidagi har bir yozuvga `external` (bool) qo'shilsin — `dst` public IP bo'lsa True.
Shartlar:
- `external=True` → hozirgi shart (count >= 4, stdev/median < 0.30) yetarli;
- `external=False` → qat'iyroq: `count >= 10` VA `stdev/median < 0.15`.
Tartib: `external=True` birinchi, keyin count kamayishi bo'yicha.

## 4. build() qaytish qiymati

```
return timeline, chains, formatted_iocs, checkers, stats
```
`stats` — dict: `{'hosts_without_signal': [...], 'iocs_filtered': N, 'chains_suppressed': N}`.
`report.py` dagi `analyze_logs` shu 5 qiymatni oladi va o'zining `stats` dictiga
`stats.update(...)` qilib qo'shadi (SPEC_NOISE.md da qo'shilgan `stats` kaliti bilan birlashadi).

## 5. Ko'rsatish (UI/HTML)
- `generate_report()` IOC jadvaliga "Linked" ustuni (✓ / bo'sh) va "Techniques" ustuni
  qo'shilsin; linked bo'lmaganlari `<details>` ichida yig'ilgan holda chiqsin.
- Chainlar bo'limi ostida bitta qator: `N ta hostda detection yo'q (ko'rsatilmadi)`.
- `web/static/app.js` da IOC jadvali xuddi shunday: linked IOC lar yuqorida,
  qolganlari "Kontekst IOC lar (N)" tugmasi ostida yashirin.

## Testlar
```
python bk.py logs analyze "C:\Users\USER\Downloads\AyuGram Desktop\elasticsearch_export.json" --json-out out2.json
```
Kutilgan:
- `chains` soni **2-3 ta** (web-prod-01, db-prod-02), hammasida tactics bor;
- IOC ro'yxatining birinchi qatorlarida `198.51.100.45`, `203.0.113.88`, `10.0.2.20`,
  `/tmp/.cron_backup` bo'lsin; `C:\Program Files\outlook.exe` va `10.0.0.5` chiqmasin;
- `checkers` da `10.0.1.15 -> 203.0.113.88` `external: true` bilan birinchi o'rinda;
- `data/samples/win_phishing.csv` bo'yicha regressiya: chain va IOC lar yo'qolib ketmasin.

Kod uslubi: mavjud fayl uslubi (4 space, defaultdict, type hint yo'q). Yangi kutubxona qo'shma.
