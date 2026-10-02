# SPEC_HUNT — `bk hunt beacons`: noma'lum C2 manzillarini saralash

## Maqsad
Katta hajmdagi firewall/proxy eksportidan **noma'lum C2 nomzodlarini** avtomatik
ajratib, reyting bo'yicha ro'yxat berish. Ma'lum IOC kerak emas — faqat xulq-atvor.

Sabab: haqiqiy hodisada (21.09) uchta alohida C2 kanali topildi, ulardan ikkitasi
faqat vendor tahlilidan ma'lum bo'ldi. Tashkilotda yana qancha borligini bilish uchun
14 kunlik trafikni xulq-atvor bo'yicha saralash kerak.

Beacon matematikasi `bluekit/ir/correlator.py` da allaqachon bor (median + MAD +
sessiya bo'yicha MAX bayt) — uni qayta yozmang, ajratib olib umumiy funksiyaga
ko'chiring va ikkala joy ham shuni ishlatsin.

## Yangi fayllar
```
bluekit/hunt/__init__.py
bluekit/hunt/beacons.py
bluekit/hunt/allowlist.yaml
```

## 1. Kirish ma'lumoti
`bk hunt beacons <fayl|papka>`:
- QRadar CSV (`bluekit/logs/qradar.py` orqali — allaqachon ishlaydi),
- FortiGate syslog matn fayli,
- yoki kanonik maydonlarga ega har qanday CSV/JSON (`bluekit/logs/parse.py`).

Papka berilsa — ichidagi barcha mos fayllar o'qilib birlashtiriladi.

Kerakli maydonlar: `ts`, `src_ip`, `dest_ip`, `dest_port`, `bytes_sent`,
`bytes_rcvd`, `session_id`, `duration` (bo'lmasa — o'sha mezon hisoblanmaydi).

## 2. Filtrlash (nomzodlar to'plami)
Tashlab yuboriladi:
- `dest_ip` privat/loopback/multicast/broadcast (RFC1918, 127/8, 169.254/16, 224/4, 255.255.255.255);
- `dest_ip` `allowlist.yaml` dagi CIDR larga tushsa;
- `src_ip` privat bo'lmasa (ya'ni faqat ichki → tashqi yo'nalish).

## 3. Guruhlash va mezonlar
Guruh kaliti: `(src_ip, dest_ip, dest_port)`.
Sessiya: `session_id` bo'lsa o'sha, aks holda `(src_ip, src_port, dest_ip, dest_port)`.
Bayt: bitta sessiya ichida **MAX**, sessiyalar orasida **yig'indi** (FortiGate uzun
sessiyalar uchun davriy yangilanish yozadi — yig'sak 30 barobar oshib ketadi).

Har guruh uchun:
| ko'rsatkich | hisoblash |
|---|---|
| `sessions` | unikal sessiya soni |
| `median_interval` | sessiya boshlanishlari orasidagi intervallar medianasi (s) |
| `mad_ratio` | MAD / median |
| `avg_sent` | jami yuborilgan / sessiya soni |
| `max_duration` | eng uzun sessiya (s) |
| `dst_host_count` | shu `dest_ip` ga chiqqan **unikal ichki host** soni (guruhlar bo'ylab) |
| `first_seen`, `last_seen` | |
| `night_ratio` | 00:00–06:00 oralig'idagi sessiyalar ulushi |

## 4. Ball (0–100)
| Mezon | Shart | Ball |
|---|---|---|
| Davriylik | `sessions >= 20` VA `5 <= median_interval <= 3600` VA `mad_ratio < 0.3` | +30 |
| Zaif davriylik | yuqoridagi, lekin `mad_ratio < 0.6` | +15 |
| Keepalive hajmi | `sessions >= 100` VA `avg_sent < 50000` | +20 |
| Uzoq sessiya (RAT) | `max_duration >= 3600` | +15 |
| Kam tarqalgan manzil | `dst_host_count <= 5` | +15 |
| Juda kam tarqalgan | `dst_host_count == 1` | +5 (qo'shimcha) |
| Tungi faollik | `night_ratio >= 0.2` | +10 |
| Standart bo'lmagan port | `dest_port` 80/443 dan boshqa | +5 |

`score >= 50` → `YUQORI`, `>= 30` → `O'RTA`, aks holda `PAST`.
Chiqishda default faqat `YUQORI` va `O'RTA` ko'rsatiladi; `--all` bilan hammasi.

## 5. CLI
```
bk hunt beacons <fayl|papka> [--json out.json] [--out report.html]
                             [--min-sessions N] [--max-hosts N] [--all]
                             [--ioc iocs.txt] [--allowlist my.yaml]
```
- `--ioc iocs.txt` — har qatorda IP yoki domen; natijada shunday qatorlar
  `[MA'LUM]` deb belgilanadi va reytingning tepasiga chiqadi (ular bilan solishtirish uchun).
- Oddiy chiqish — jadval:
```
Ball | Daraja | Dst IP          | Port | Host | Sessiya | Median | MAD   | O'rt.bayt | Maks davom | Birinchi
  75 | YUQORI | 46.30.190.150   |   80 |    4 |    1793 |   30s  | 0.08  |    7.1 KB |    4.4 soat | 09-21 01:46
```
- Har nomzod ostida ichki hostlar ro'yxati (maksimal 10 ta).
- Oxirida: `N ta nomzod tekshirildi, M tasi YUQORI/O'RTA`.
- `--json` — to'liq ma'lumot, `mezonlar` maydonida qaysi shart ishlagani ro'yxati.

## 6. allowlist.yaml
```yaml
# Ma'lum benign yo'nalishlar. O'z muhitingizga moslab to'ldiring.
cidrs:
  - 13.107.0.0/16      # Microsoft
  - 20.190.0.0/16      # Microsoft / Azure AD
  - 23.32.0.0/11       # Akamai
  - 52.96.0.0/12       # Microsoft 365
  - 104.16.0.0/12      # Cloudflare
  - 142.250.0.0/15     # Google
  - 8.8.8.0/24         # Google DNS
  - 1.1.1.0/24         # Cloudflare DNS
note: "Bu ro'yxat ataylab qisqa. Kengaytirishdan oldin har bir CIDR ni tekshiring — keraksiz allowlist C2 ni yashiradi."
```

## 7. Testlar
```
python bk.py hunt beacons "C:\Users\USER\Downloads\2026-09-21-data_export.csv (1)\dest.csv"
```
Kutilgan (men qo'lda o'lchaganman):
- `46.30.190.150:80` nomzod sifatida chiqadi, daraja **YUQORI**;
- `dst_host_count` = 4, `sessions` ~1793, `median_interval` ~28-30s, `avg_sent` ~7 KB;
- boshqa nomzod yo'q (bu eksportda faqat bitta tashqi manzil bor).

Regressiya: `bk ir chain` va `bk logs analyze` avvalgidek ishlashi kerak
(`elasticsearch_export.json` → 22 qadam; `dest.csv` → 12 qadam).

Ishni O'ZING bajar, subagentga topshirma. Stub qoldirma.
