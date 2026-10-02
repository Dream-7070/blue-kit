# SPEC_IR_EXPLAIN — IR (Responder) findings jadvaliga o'zbekcha "Izoh" ustuni

## Maqsad
`Responder` bo'limidagi findings jadvalida hozir faqat qisqa teglar bor
("baseline'da yo'q (yangi)", "KB match (T1053.005)"). Musobaqada hakam yoki
jamoadoshi uchun bu yetarli emas. Har bir topilma uchun **2 gapli o'zbekcha izoh**
kerak: bu nima + nega shubhali + nima qilish kerak.

LLM ishlatilmaydi — offline shablon.

## Yangi fayl: `bluekit/resp/explain.py`

```python
def explain_uz(finding):
    """Findings uchun 2 gapli o'zbekcha izoh qaytaradi."""
```

Mantiq: `finding['category']` bo'yicha asosiy matn + `reasons`/`protected`/
`log_confirmed`/`techniques` bo'yicha qo'shimcha jumla. Natija — bitta string
(HTML emas, oddiy matn).

### 1-qism — kategoriya matni (aynan shu matnlar ishlatilsin)

| category | matn |
|---|---|
| `tasks` | "Rejalashtirilgan vazifa (Scheduled Task). Hujumchilar qayta ishga tushish uchun aynan shu yerga yoziladi — vazifa `action` maydonini va u chaqirayotgan faylni tekshiring." |
| `users` | "Lokal foydalanuvchi akkaunti. Hujumchi qayta kirish uchun yaratgan bo'lishi mumkin — kim va qachon yaratganini, oxirgi login vaqtini tekshiring." |
| `autoruns` | "Avtoyuklanish yozuvi (Run kaliti). Tizim har ishga tushganda bu buyruq bajariladi — qiymatdagi fayl yo'lini va imzosini tekshiring." |
| `services` | "Windows xizmati. Zararli xizmat SYSTEM huquqi bilan ishlaydi — `binary_path` ni va xizmat kimga tegishliligini tekshiring." |
| `remote_access_tools` | "Masofaviy boshqaruv dasturi (RAT/RMM). Agar IT jamoasi o'rnatmagan bo'lsa — bu hujumchining kirish kanali; darhol tarmoqdan uzing." |
| `hosts_file` | "`hosts` faylidagi yozuv. DNS ni chetlab o'tib trafikni boshqa IP ga burish uchun ishlatiladi — yozuv qaysi domenni qayerga yo'naltirayotganini tekshiring." |
| `wmi_subscriptions` | "WMI event obunasi — fayl qoldirmaydigan (fileless) persistensiya usuli. Odatda oddiy tizimda bo'lmaydi; `__EventConsumer` buyrug'ini tekshiring." |
| `cron` | "Cron vazifasi (Linux). Muntazam qayta ishga tushish uchun ishlatiladi — qaysi foydalanuvchi nomidan va qanday buyruq bajarilayotganini tekshiring." |
| `ssh_authorized_keys` | "SSH `authorized_keys` yozuvi — parolsiz kirish kaliti. Begona kalit qo'shilgan bo'lsa, hujumchi istalgan vaqtda qayta kira oladi; kalitni o'chiring." |
| `suid_files` | "SUID bitli fayl. Oddiy foydalanuvchi uni root huquqi bilan ishga tushira oladi — standart bo'lmagan SUID fayl privilege escalation yo'li." |
| `connections` | "Tarmoq ulanishi. Tashqi IP ga doimiy/davriy ulanish C2 (boshqaruv serveri) belgisi bo'lishi mumkin — IP obro'sini va ulanish davriyligini tekshiring." |
| (boshqa/noma'lum) | "Snapshotdagi shubhali ob'ekt — qo'lda tekshirish talab etiladi." |

### 2-qism — sabab jumlasi (`reasons` ichidagi teglar bo'yicha, birinchi mosi olinadi)

| reason tegi (substring) | qo'shiladigan jumla |
|---|---|
| `baseline'da yo'q` | "Baseline'da bu ob'ekt yo'q — demak hodisa davrida qo'shilgan." |
| `log korrelyatsiyasi` | "Loglarda ham xuddi shu ob'ekt uchragan — tasodif emas." |
| `KB match` | "Nomi/buyrug'i MITRE ATT&CK texnikasiga mos keldi." |
| `shubhali nom/buyruq` | "Buyruq ichida hujumchilar ko'p ishlatadigan naqsh bor (masalan yashirin rejim, kodlangan buyruq)." |
| `shubhali papka` | "Ob'ekt vaqtinchalik/foydalanuvchi papkasidan ishga tushyapti — qonuniy dasturlar odatda u yerdan ishlamaydi." |
| `admin akkaunt` | "Akkaunt administrator huquqiga ega." |
| `yaqinda o'zgartirilgan` | "Fayl yaqinda o'zgartirilgan — hodisa vaqtiga to'g'ri kelishi mumkin." |
| `checker IP` | "Bu IP loglarda davriy checker sifatida ko'rilgan — C2 emas, monitoring bo'lishi ham mumkin." |

Agar hech qaysi teg mos kelmasa — 2-qism qo'shilmaydi.

### 3-qism — ogohlantirish (agar tegishli bo'lsa, oxiriga qo'shiladi)
- `finding['protected']` True → " ⚠ PROTECTED ro'yxatida: o'chirmang, avval tizim egasi bilan tasdiqlang."
- `finding['confidence'] == 'high'` va protected emas → " ⚠ Yuqori ishonch — birinchi navbatda shu bilan shug'ullaning."

## Wiring (3 joy)

1. **`bluekit/resp/triage.py`** — `analyze()` findings ro'yxatini qaytarishdan oldin
   har bir finding ga `f['explain_uz'] = explain_uz(f)` qo'shsin. MUHIM: bu
   `log_confirmed` va yakuniy `score`/`confidence` hisoblanib bo'lgandan KEYIN
   bajarilsin (fayl oxiridagi korrelyatsiya blokidan so'ng), aks holda izoh
   eskirgan ma'lumot bilan tuziladi.

2. **`bluekit/web/static/app.js`** — `respTriage()` dagi jadvalga yangi ustun.
   Sarlavha: `"Izoh"`, ustunlar tartibi: ... "Log Tasdiqi", **"Izoh"**, "Sabablar".
   Katak: `<span class="explain-cell">${escapeHtml(f.explain_uz || '')}</span>`.
   `style.css` ga: `.explain-cell { font-size:12px; color:var(--text-secondary); line-height:1.45; display:block; max-width:420px; }`

3. **`bk.py`** (~291-qator) — CLI jadvaliga ustun qo'shilsa, terminal juda kengayib
   ketadi. Shuning uchun CLI da **jadvalga ustun qo'shilmasin**; o'rniga jadvaldan
   keyin ro'yxat chiqsin:
   ```
   Izohlar:
     [1] <item> — <explain_uz>
   ```
   va jadvalning birinchi ustuniga `[N]` raqami qo'shilsin, ya'ni izohni topish oson bo'lsin.
   `--json` rejimida `explain_uz` baribir JSON ichida bo'ladi (1-punkt hisobiga).

## Testlar
```
python bk.py resp triage --current dist/data/samples/resp/current_win.json --baseline dist/data/samples/resp/baseline_win.json
python bk.py resp triage --current dist/data/samples/resp/current_win.json --json
```
Kutilgan:
- jadvaldan keyin `Izohlar:` ro'yxati chiqadi, har bir topilma uchun 1-3 gap;
- `--json` da har bir finding ichida bo'sh bo'lmagan `explain_uz` maydoni bor;
- protected topilma izohida "PROTECTED ro'yxatida" ogohlantirishi bor;
- Web UI da `Izoh` ustuni "Log Tasdiqi" va "Sabablar" orasida ko'rinadi.

Kod uslubi: mavjud fayllar uslubi (4 space, type hint yo'q). Yangi kutubxona qo'shma.
