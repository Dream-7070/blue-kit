# FEEDBACK_HUNT — `bk hunt beacons` ishladi, 4 ta kamchilik

Natija to'g'ri, qo'lda o'lchaganim bilan mos keldi:
```
  80 | YUQORI | 46.30.190.150 | 5 host | 1797 sessiya | median 30s | MAD 0.10 | 7.1 KB
```
Quyidagilarni tuzating.

## 1-defekt: `duration` umuman o'qilmayapti (eng muhimi)

`bluekit/logs/qradar.py` FortiGate `duration` maydonini kanonik eventga
**ko'chirmaydi** — tekshirdim: `duration bor: 0` (3674 eventdan hech birida yo'q).

Natijada `Maks davom` ustuni doim `0s` va **"Uzoq sessiya (RAT)" mezoni hech qachon
ishlamaydi** (+15 ball). Aynan shu mezon MeshCentral kabi doimiy 443 ulanishini
ushlashi kerak edi — ya'ni hozir ov qilishning bitta muhim qirrasi o'lik.

Tuzatish: `qradar.py` da FortiGate KV dan `duration` (butun son, soniya) kanonik
`duration` maydoniga yozilsin. Shu bilan birga `src_port` ham qo'shilsin
(`srcport`) — sessiya kalitida kerak bo'ladi.

Tekshirish:
```python
from bluekit.logs.qradar import load_qradar
ev = load_qradar(r"...dest.csv")
print(sum(1 for e in ev if e.get('duration')))   # 0 EMAS, minglab bo'lishi kerak
print(max(e.get('duration') or 0 for e in ev))   # ~16000 (4.4 soat) bo'lishi kerak
```
Shundan keyin `Maks davom` ustuni `4.4 soat` ko'rsatishi va ball 80 dan 95 ga
ko'tarilishi kerak.

## 2-defekt: `Port` ustuni bo'sh

Chiqishda `Port` ustuni bo'sh, holbuki ma'lumot bor:
`dest_port` qiymatlari: `80` → 3574 ta, `None` → 100 ta (ESET yozuvlarida port yo'q).

Nomzod `dest_ip` bo'yicha jamlanganda port yo'qolyapti. Kerak: eng ko'p uchragan
portni ko'rsating, bir nechta bo'lsa `80,443` ko'rinishida (maksimal 3 ta).
Port yo'q yozuvlar (ESET) portni aniqlashda hisobga olinmasin.

## 3-defekt: host nomlari va ro'yxat to'liq emas

Hozir:
```
Host: 5     lekin ro'yxatda 4 ta
-> 192.168.19.224 (HA-Cluster_FG4H0F)      <-- firewall qurilmasining nomi
```
`192.168.19.224` aslida `asultonov.digital.local` — bu ESET yozuvlaridan ma'lum.
`correlator.py` da shu maqsadda `ip_to_host` jadvali bor (ESET `channel` li
eventlardan quriladi). Xuddi shu mantiqni `beacons.py` ga ham qo'llang:
ESET nomi bo'lsa o'shani, bo'lmasa firewall nomini ko'rsating.

Va sanoq bilan ro'yxat mos kelsin: 5 ta deb yozilsa, 5 tasi ham chiqsin
(beshinchisi — `192.168.213.52` / f-xakulov, unda firewall sessiyasi yo'q,
faqat ESET yozuvi bor). Sessiyasi yo'q hostlar `(ESET, sessiya yo'q)` deb belgilansin.

## 4-defekt: vaqt ustunida mintaqa ko'rsatilmagan

`Birinchi: 09-20 20:46` — bu **UTC** (mahalliy vaqtda 09-21 01:46, +05).
Konvertatsiya to'g'ri, lekin ustun sarlavhasida yozilmagan. Hisobotga tushganda
chalkashlik beradi. Sarlavha `Birinchi (UTC)` bo'lsin, va jadval ostida bitta qator:
`Vaqtlar UTC da. Mahalliy vaqt uchun +5 soat qo'shing.`

## Tekshirish
```
python bk.py hunt beacons "C:\Users\USER\Downloads\2026-09-21-data_export.csv (1)\dest.csv"
python bk.py ir chain "C:\Users\USER\Downloads\AyuGram Desktop\elasticsearch_export.json"
```
Kutilgan: nomzod qatorida port `80`, `Maks davom` ~`4.4 soat`, 5 ta host to'liq
ro'yxat bilan, ikkinchi buyruq avvalgidek 22 qadam.

Ishni O'ZING bajar, subagentga topshirma.
