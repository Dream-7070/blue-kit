# Hodisa Hisoboti CASE-20260922-01

### Pasport
- **Nomi:** Defense Evasion → Command and Control (1 ta host)
- **Holati:** confirmed
- **Xavflilik darajasi (Severity):** HIGH
- **Ishonchlilik darajasi:** 90%
- **Jabrlangan hostlar:** `f-xamroyeva.digital.local`
- **Foydalanuvchi hisoblari:** `f.xamroyeva`
- **Vaqt oralig'i:** 2026-09-21 07:16:04 – 2026-09-21 07:27:24 UTC
- **Manba:** `2026-09-21-data_export.csv`
- **Tahlil qilingan loglar soni:** 463 ta, aniqlangan hujum zanjiri qadamlari: 4 ta

---

### Qisqacha Xulosa (Executive Summary)
🔴 **TASDIQLANGAN (HIGH):** 1 ta host bo'yicha shubhali faoliyat aniqlandi. Tashqi manzil: **46.30.190[.]150** (http://public.iivuz.online:80/command). Kuzatilgan bosqichlar: Command and Control, Defense Evasion. MITRE ATT&CK: T1071.001, T1036.005. Jabrlangan hostlar: `f-xamroyeva.digital.local`.

> Ushbu xulosa faqat tahlil qilingan loglardagi dalillarga asoslanadi. Loglar qamrab olmagan bosqichlar (dastlabki kirish yo'li, persistensiya mexanizmi, ma'lumot sizishi hajmi) alohida tekshirilishi kerak.

---

### Hujum Zanjiri (Attack Chain UTC)
**1. [2026-09-21 07:16:04 UTC]** — 🟢 `[f-xamroyeva.digital.local]` **Command and Control:** C:\ProgramData\Microsoft\DeviceSync\DeviceSync.exe -> http://public.iivuz.online:80/command (AV bloklagan, 10 marta) `[T1071.001]`
   > *Tashqi C2 (boshqaruv) serveriga veb-protokol (HTTP/HTTPS) orqali davriy ulanish va buyruq almashish kanali o'rnatilgan (C2 beaconing / callback).*
**2. [2026-09-21 07:27:14 UTC]** — 🟢 `[f-xamroyeva.digital.local]` **Command and Control:** C:\ProgramData\Microsoft\DeviceSync\DeviceSync.exe -> http://public.iivuz.online:80/online (AV bloklagan, 8 marta) `[T1071.001]`
   > *Tashqi C2 (boshqaruv) serveriga veb-protokol (HTTP/HTTPS) orqali davriy ulanish va buyruq almashish kanali o'rnatilgan (C2 beaconing / callback).*
**3. [2026-09-21 07:27:14 UTC]** — 🟢 `[f-xamroyeva.digital.local]` **Defense Evasion:** C:\ProgramData\Microsoft\DeviceSync\DeviceSync.exe 4350B1923036348429B0CB174CB6A8699CF99F88 `[T1036.005]`
   > *Zararli fayl sezilmaslik uchun qonuniy tizim dasturi nomi (masalan, Microsoft DeviceSync) va papkasidan foydalanib yashiringan (Masquerading).*
**4. [2026-09-21 07:27:24 UTC]** — 🟢 `[f-xamroyeva.digital.local]` **Command and Control:** 192.168.19.225 -> 46.30.190.150:80, 176 sessiya, ~3s interval, 6.36 MB yuborilgan `[T1071.001]`
   > *Tashqi C2 (boshqaruv) serveriga veb-protokol (HTTP/HTTPS) orqali davriy ulanish va buyruq almashish kanali o'rnatilgan (C2 beaconing / callback).*

---

### MITRE ATT&CK Xaritasi
- **T1071.001 — Web Protocols** — 🟢 TASDIQLANGAN: C:\ProgramData\Microsoft\DeviceSync\DeviceSync.exe -> http://public.iivuz.online:80/command (AV bloklagan, 10 
- **T1036.005 — Match Legitimate Resource Name or Location** — 🟢 TASDIQLANGAN: C:\ProgramData\Microsoft\DeviceSync\DeviceSync.exe 4350B1923036348429B0CB174CB6A8699CF99F88

---

### IOC va Artefaktlar
- **`46.30.190[.]150`** `[IPv4]` — Attacker / C2: Initial scanner, SQLi source, and reverse shell listener
- **`C:\ProgramData\Microsoft\DeviceSync\DeviceSync.exe`** `[process]` — Command and Control: Observed in T1071.001 (f-xamroyeva.digital.local)
- **`http://public.iivuz.online:80/command`** `[url]` — Command and Control: Observed in T1071.001 (f-xamroyeva.digital.local)
- **`http://public.iivuz.online:80/online`** `[url]` — Command and Control: Observed in T1071.001 (f-xamroyeva.digital.local)
- **`4350B1923036348429B0CB174CB6A8699CF99F88`** `[hash]` — Defense Evasion: Observed in T1036.005 (f-xamroyeva.digital.local)
- **`192.168.19.225`** `[src_ip]` — Command and Control: Observed in T1071.001 (f-xamroyeva.digital.local)
- **`46.30.190.150`** `[dst_ip]` — Command and Control: Observed in T1071.001 (f-xamroyeva.digital.local)
- **`80`** `[port]` — Command and Control: Observed in T1071.001 (f-xamroyeva.digital.local)
- **`f.xamroyeva`** `[Account]` — Compromised Account: User account leveraged during attack
