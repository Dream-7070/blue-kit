# SPEC_IR_IZOH — IR Attack Chain jadvaliga o'zbekcha "Izoh" ustuni

## Maqsad
`⚡ IR Attack Chain` bo'limidagi asosiy jadval (To'liq Kiberhujum Zanjiri) hozir
faqat texnik ma'lumot beradi: vaqt, host, faza, MITRE ID, xom dalil (payload).
Hakam yoki texnik bo'lmagan o'quvchi uchun **har bir qadamning o'zbekcha izohi**
kerak: shu bosqichda aslida nima sodir bo'ldi va bu nimani anglatadi.

LLM ishlatilmaydi — texnika ID si bo'yicha oflayn shablon.

## Yangi fayl: `bluekit/ir/explain.py`

```python
EXPLAIN_UZ = { "<technique_id>": "<izoh matni>", ... }

def explain_stage_uz(stage):
    """AttackStage uchun o'zbekcha izoh qaytaradi (topilmasa — faza bo'yicha zaxira matn)."""
```

Izlash tartibi: `stage.technique_id` bo'yicha → topilmasa `stage.phase` bo'yicha
zaxira lug'atdan → u ham bo'lmasa `""`.

### Izoh matnlari (aynan shu matnlar ishlatilsin)

| technique_id | izoh |
|---|---|
| `T1595.002` | "Hujumchi saytni avtomatik skanerlagan: admin panel, config va backup fayllarini qidirib ko'plab 404/403 javob olgan. Bu razvedka bosqichi — hali kirish yo'q, lekin nishon tanlanmoqda." |
| `T1190` | "Veb-ilova parametriga SQL in'ektsiya yuborilgan va baza tuzilmasi, foydalanuvchi jadvali o'qib olingan. Bu — hujumchining tizimga birinchi kirish nuqtasi." |
| `T1505.003` | "Serverga web-shell (brauzer orqali buyruq bajaradigan fayl) yuklangan va unga murojaat qilingan. Endi hujumchi veb-server huquqida istalgan buyruqni bajara oladi." |
| `T1033` | "Hujumchi web-shell orqali `whoami`/`id` kabi buyruqlar bilan qaysi huquqda ishlayotganini aniqlagan. Bu — muhitni o'rganish, keyingi qadamni rejalashtirish." |
| `T1059.006` | "Python orqali teskari qobiq (reverse shell) ochilgan: server o'zi hujumchining IP siga ulanib, to'liq interaktiv terminal bergan. Ulanish chiquvchi bo'lgani uchun oddiy firewall uni to'smaydi." |
| `T1053.003` | "Cron jadvaliga har 15 daqiqada tashqi skriptni yuklab ishga tushiruvchi yozuv qo'shilgan. Bu — qayta ishga tushgandan keyin ham kirishni saqlash usuli; cron yozuvi o'chirilmasa, server qayta zararlanadi." |
| `T1548.003` | "`sudo` huquqlari ro'yxatlangan va ruxsat etilgan dastur orqali (GTFOBins usuli) root qobig'i olingan. Shu daqiqadan boshlab hujumchi serverda to'liq nazoratga ega." |
| `T1003.008` | "`/etc/shadow` fayli o'qilgan — barcha lokal parol hashlari hujumchi qo'lida. Parollarni oflayn buzish mumkin, shuning uchun barcha akkaunt parollarini almashtirish shart." |
| `T1552.004` | "Root foydalanuvchining SSH shaxsiy kaliti o'g'irlangan. Bu kalit bilan parolsiz, boshqa serverlarga ham kirish mumkin — kalitni darhol bekor qilib, yangisini generatsiya qiling." |
| `T1136.001` | "Yangi lokal foydalanuvchi yaratilgan, nomi tizim akkauntiga o'xshatib tanlangan. Bu — yashirin zaxira kirish yo'li; akkauntni o'chiring va boshqa hostlarda ham shunga o'xshash akkaunt bor-yo'qligini tekshiring." |
| `T1046` | "Ichki tarmoq skanerlangan (SSH, MySQL, PostgreSQL portlari). Hujumchi qo'shni serverlarga o'tish uchun nishon tanlamoqda — demak hujum bitta host bilan tugamaydi." |
| `T1021.004` | "O'g'irlangan SSH kaliti bilan ichki tarmoqdagi boshqa serverga kirilgan. Bu — lateral movement (yon harakat): buzilgan perimetr endi ichki infratuzilmaga tarqalgan." |
| `T1005` | "Ma'lumotlar bazasi to'liq dump qilingan (mijoz va to'lov jadvallari). Bu hodisaning eng og'ir qismi — shaxsiy ma'lumotlar sizib chiqqan, huquqiy bildirish talab etilishi mumkin." |
| `T1560.001` | "O'g'irlangan fayllar bitta arxivga yig'ilgan (staging). Bu odatda tashqariga jo'natishdan oldingi oxirgi tayyorgarlik qadami." |
| `T1048` | "Ma'lumotlar tashqi IP ga HTTPS orqali davriy ravishda jo'natilgan. Bu — eksfiltratsiya/C2 kanali: shu IP ni firewallda bloklang va jo'natilgan hajmni aniqlang." |

### Zaxira (faza bo'yicha, technique_id topilmasa)
| phase (substring) | izoh |
|---|---|
| `Reconnaissance` | "Razvedka bosqichi — hujumchi nishon haqida ma'lumot yig'moqda." |
| `Initial Access` | "Tizimga birinchi kirish bosqichi." |
| `Execution` | "Hujumchi nishon tizimda buyruq bajargan." |
| `Persistence` | "Hujumchi kirishini doimiy saqlash uchun tizimga o'zgartirish kiritgan." |
| `Privilege Escalation` | "Huquqlar ko'tarilgan — hujumchi yuqoriroq (odatda root/SYSTEM) darajaga chiqqan." |
| `Credential Access` | "Parol yoki kalit kabi maxfiy ma'lumotlar qo'lga kiritilgan." |
| `Discovery` | "Muhit o'rganilmoqda — tizim, foydalanuvchi yoki tarmoq haqida ma'lumot yig'ilgan." |
| `Lateral Movement` | "Hujum boshqa hostga tarqalgan." |
| `Collection` | "Qimmatli ma'lumot yig'ilgan va jo'natishga tayyorlanmoqda." |
| `Exfiltration` | "Ma'lumot tashqariga chiqarilgan." |

## Wiring

1. **`bluekit/ir/models.py`** — `AttackStage` ga yangi maydon:
   `explain_uz: str = ""` (dataclass default, `asdict` orqali JSON ga o'zi tushadi).

2. **`bluekit/ir/report.py`** — `build_incident_model()` ichida, model qurilishidan
   oldin har bir qadam uchun: `s.explain_uz = explain_stage_uz(s)`.
   Bitta joyda to'ldirilsa, web/CLI/JSON/report — hammasi avtomatik oladi.

3. **`bluekit/web/static/app.js`** — `renderIRResults()` dagi zanjir jadvaliga
   yangi **oxirgi** ustun:
   - `<th>Izoh (nima sodir bo'ldi)</th>`
   - katak: `<td style="font-size:13px; line-height:1.5; color:var(--text-main); max-width:360px;">${escapeHtml(s.explain_uz || '')}</td>`

4. **`bk.py`** (`ir chain` jadvali, ~470-qator) — terminalda ustun qo'shilmasin
   (jadval juda kengayadi). O'rniga jadvaldan keyin:
   ```
   IZOHLAR:
     #1  <explain_uz>
     #2  <explain_uz>
   ```

5. **`bluekit/ir/report.py` → `render_markdown_report()`, `lang == "uz"` bloki**
   (~302-305 qator): har bir qadam qatoridan keyin izoh yangi qatorda,
   kursiv ko'rinishda chiqsin:
   ```
   **1. [ts UTC]** — 🟢 `[host]` **Phase:** evidence `[T1190]`
      > *izoh matni*
   ```
   `ru` va `en` bloklari O'ZGARMAYDI.

## Testlar
```
python bk.py ir chain "C:\Users\USER\Downloads\AyuGram Desktop\elasticsearch_export.json"
python bk.py ir chain "C:\Users\USER\Downloads\AyuGram Desktop\elasticsearch_export.json" --json
python bk.py ir report "C:\Users\USER\Downloads\AyuGram Desktop\elasticsearch_export.json" --lang uz --out ir_uz.md
```
Kutilgan:
- CLI jadvaldan keyin `IZOHLAR:` ro'yxati, har bir qadam uchun bo'sh bo'lmagan matn;
- `--json` chiqishidagi har bir stage ichida `explain_uz` maydoni bor;
- `ir_uz.md` da har bir qadam ostida kursiv izoh;
- Web UI da zanjir jadvalining oxirgi ustuni `Izoh (nima sodir bo'ldi)`;
- `--lang ru` va `--lang en` hisobotlari o'zgarmagan.

Kod uslubi: mavjud fayllar uslubi (dataclass, type hint `models.py` da bor —
shu yerda saqlanadi; boshqa fayllarda mavjud uslubga mos). Yangi kutubxona qo'shma.
