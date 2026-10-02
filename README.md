# Blue Kit (BK) — DFIR & Blue Team Toolkit

Blue Kit — kiberxavfsizlik bo'yicha hodisalarni tahlil qilish (Incident Response), loglarni tekshirish (DFIR), tahdidlarni qidirish (Threat Hunting) va SIEM/Sigma qoidalari bilan ishlash uchun mo'ljallangan keng qamrovli vositalar to'plami.

---

## 🚀 Portable versiyadan foydalanish (`dist/`)

`dist/` papkasi hech qanday qo'shimcha Python yoki muhit o'rnatmasdan to'g'ridan-to'g'ri ishlatish uchun tayyorlangan:

- **`CLI-oyna.bat`** — Blue Kit CLI terminal oynasini ishga tushirish.
- **`WEB-UI.bat`** — Interaktiv Web-interfeysni ishga tushirish (brauzerda ochiladi).
- **`TEKSHIRUV.bat`** — Tizim va komponentlar to'g'ri ishlayotganini diagnostika qilish (`doctor` moduli).
- **`PLAYBOOK.html`** va **`CHEATSHEET.html`** — Tezkor qo'llanmalar va playbooklar.
- **`bk.exe`** — Barcha modullarni o'z ichiga olgan mustaqil ijro etuvchi fayl.

---

## 📂 Loyiha tuzilishi

```text
blue-kit/
├── bluekit/            # Asosiy Python manba kodlari
│   ├── case/           # Case & Incident boshqaruvi
│   ├── hunt/           # Threat Hunting modullari
│   ├── ir/             # Incident Response tahlil vositalari
│   ├── kb/             # Knowledge Base (ATT&CK, Sigma, YARA)
│   ├── logs/           # Loglarni parse qilish va filtrlash
│   ├── mail/           # Email tahlili va header tekshiruvi
│   ├── report/         # Tahlil natijalari bo'yicha hisobot generatori
│   ├── resp/           # Responder ma'lumotlarini qayta ishlash
│   ├── siem/           # SIEM log parsing va qoidalar
│   ├── web/            # Web interfeys backend va API
│   ├── answers.py      # Savol-javob va tavsiyalar
│   ├── decode.py       # Base64, Hex, URL va boshqa dekoderlar
│   ├── doctor.py       # Diagnostika va selftest
│   ├── netutil.py      # Tarmoq utility vositalari
│   ├── playbook.py     # Playbook ijro etuvchisi
│   ├── tracker.py      # Vazifalar va hodisalar kuzatuvi
│   └── tz.py           # Vaqt mintaqalarini boshqarish
├── dist/               # Tayyor portable versiya
│   ├── bk.exe          # Standalone executable
│   ├── CLI-oyna.bat
│   ├── WEB-UI.bat
│   ├── TEKSHIRUV.bat
│   ├── PLAYBOOK.html
│   ├── CHEATSHEET.html
│   └── data/ / responder/ / static/ / web-work/
├── responder/          # Ma'lumot yig'uvchi (triage collector) skriptlar
│   ├── collect_linux.sh
│   └── collect_windows.ps1
├── data/               # ATT&CK, Sigma va qoidalar bazasi
├── tests/              # Avtomatlashtirilgan testlar
└── build.py            # Portable versiyani yig'ish skripti
```

---

## 🛠 CLI buyruqlari

```bash
# Asosiy yordam
bk --help

# Tizim diagnostikasi
bk doctor

# Web interfeysni ishga tushirish
bk web

# Loglarni tahlil qilish
bk logs --help

# Dekoder vositalari
bk decode --help

# IR va Threat Hunting
bk ir --help
bk hunt --help
```

---

## 📦 Qayta yig'ish (Build)

Portable versiyani yangilash yoki qayta yig'ish uchun:

```bash
python build.py
```

---

## 📄 Litsenziya

Maxsus foydalanish uchun mo'ljallangan.
