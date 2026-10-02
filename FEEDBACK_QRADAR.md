# FEEDBACK_QRADAR — parser to'g'ri, korrelyator qoidalari noto'g'ri

Parser qismi yaxshi ishladi: `dest.csv` dan 3674 ta event chiqdi, maydonlar to'g'ri
to'ldirilgan (`src_ip`, `dest_ip`, `session_id` 3578 ta, `bytes_sent` 1539 ta, `ts` 100%).
Unga tegmang.

Muammo — `correlate_incident()` dagi uchta yangi qoidada. Hozirgi natija:

```
Jami hodisalar: 3674 | Zanjir qadamlari: 99 | Hostlar: (bo'sh)
T1036.005 Defense Evasion    : 96 qadam   <-- bir xil qatorning 96 marta takrori
T1071.001 Command and Control:  3 qadam
compromised_hosts: []   attacker_ips: []   exfiltration_ips: []
```

99 qadamning 96 tasi bir xil matn. Bu — IR tabdagi shovqin muammosining qaytishi.

---

## 1-defekt: Masquerading qoidasi har event uchun alohida qadam yaratyapti

Hozir: 96 ta bir xil qator, hammasi
`C:\ProgramData\Microsoft\DeviceSync\DeviceSync.exe 4350B192...`.

Kerak: **har (host, process) juftligi uchun BITTA qadam**, agregatsiya bilan:
- `timestamp` = o'sha hostdagi birinchi ko'rinish
- evidence: `"C:\ProgramData\Microsoft\DeviceSync\DeviceSync.exe (SHA1 4350B192...) — {n} marta, {first} .. {last}"`

Kutilgan natija: **5 ta qadam** (5 ta host: d-raxmatullayev, d-mirzayev, asultonov,
f-xamroyeva, f-xakulov).

## 2-defekt: C2 beacon qoidasi umuman ishga tushmadi

0 ta qadam chiqdi, holbuki ma'lumot bor: `dest_ip=46.30.190.150` ga **3578 ta**
FortiGate sessiyasi, 4 ta ichki IP dan.

Sabab — ehtimol `stdev/median < 0.5` sharti. Men o'lchaganda intervallar:
`192.168.19.225` median 7.1s (min 0, max 261), `.224` median 28s (max 5703),
`.223` median 30s (max 16002) — ya'ni uzun tanaffuslar stdev ni portlatadi.

Shartni almashtiring:
- stdev o'rniga **MAD** (median absolute deviation) yoki intervallarning
  **medianaga yaqinlik ulushi** ishlatilsin: intervallarning kamida 60% i
  `[0.5*median, 2*median]` oralig'ida bo'lsa — beacon deb hisoblansin;
- VA sessiya soni >= 10 bo'lsa, davriylik shubhali bo'lmasa ham qadam YARATILSIN
  (faza `Command and Control`, lekin evidence da "davriylik tekshirilmadi" deb qo'shib qo'ying).

Har (src_ip, dest_ip) juftligi uchun **bitta** qadam.

### Bayt hisobi — MUHIM
Evidence da hajm ko'rsatilsin, lekin **sessiya bo'yicha MAKSIMUM** olinsin:
bir `session_id` uchun bir necha yangilanish yozuvi keladi va `bytes_sent` o'sib boradi.
Sodda `sum()` 403 MB beradi, to'g'ri hisob **12.5 MB**.

```
sessions = {}
for e in events_for_pair:
    sid = e.get('session_id') or (e['src_ip'], e.get('src_port'), e['dest_ip'], e.get('dest_port'))
    prev = sessions.get(sid, (0, 0))
    sessions[sid] = (max(prev[0], e.get('bytes_sent') or 0),
                     max(prev[1], e.get('bytes_rcvd') or 0))
sent = sum(v[0] for v in sessions.values())
```

Kutilgan evidence (taxminan):
```
192.168.19.225 -> 46.30.190.150:80 | 175 sessiya | ~7s interval | 6.4 MB yuborilgan / 3.9 MB qabul
192.168.19.224 -> 46.30.190.150:80 | 940 sessiya | ~28s interval | 5.5 MB / 2.5 MB
192.168.19.223 -> 46.30.190.150:80 | 635 sessiya | ~30s interval | 0.5 MB / 0.2 MB
192.168.202.51 -> 46.30.190.150:80 |  43 sessiya | ~?s interval  | 0.1 MB / 0.04 MB
```
Jami ~12.5 MB / ~6.7 MB.

## 3-defekt: AV bloklangan URL qadamlari ham noto'g'ri guruhlangan

Hozir 3 ta qadam (har URL uchun bitta, host aralash).
Kerak: har **(host, url)** uchun bitta qadam, `n marta` bilan.
Kutilgan: ~7 qadam (f-xamroyeva 2 ta URL, asultonov 2 ta, qolgan 3 host 1 tadan).

## 4-defekt: model metadatasi bo'sh

`compromised_hosts`, `attacker_ips`, `exfiltration_ips` — uchalasi ham `[]`.
`build_incident_model()` bu maydonlarni `chain.stages` dan to'ldiradi, lekin qradar
bosqichlarida host/IP boshqa joyda turgani uchun tushmay qolyapti.

Kerak:
- `compromised_hosts` = bosqichlardagi barcha `host` (unikal) → 5 ta
- `exfiltration_ips` / `attacker_ips` = tashqi `dest_ip` lar → `46.30.190.150`
- domen ham chiqsin: `public.iivuz.online` (IOC ro'yxatiga `domain` turida)

## Kutilgan yakuniy natija

```
Jami hodisalar: 3674 | Zanjir qadamlari: ~16 | Hostlar: 5 ta
  T1036.005  Defense Evasion       5 qadam  (har host uchun 1 ta)
  T1071.001  Command and Control   ~11 qadam (4 beacon + ~7 AV blok)
compromised_hosts: 5 ta
exfiltration_ips: 46.30.190.150
IOC: 46.30.190.150, public.iivuz.online, DeviceSync.exe, 4350B1923036348429B0CB174CB6A8699CF99F88
```

## Tekshirish
```
python bk.py ir chain "C:\Users\USER\Downloads\2026-09-21-data_export.csv (1)\dest.csv"
python bk.py ir chain "C:\Users\USER\Downloads\2026-09-21-data_export.csv\2026-09-21-data_export.csv"
python bk.py ir chain "C:\Users\USER\Downloads\AyuGram Desktop\elasticsearch_export.json"
```
Uchinchisi regressiya: avvalgidek **22 qadam** qolishi shart.

Ishni O'ZING bajar, subagentga topshirma. Parser (`qradar.py`) ga tegmang —
faqat `correlator.py` va kerak bo'lsa `ir/report.py`.
