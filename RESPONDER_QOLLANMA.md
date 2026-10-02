# Responder tabi — 0 dan qo'llanma

Kimga: musobaqada **Responder** rolini oladigan odamga. Oldindan hech narsa
bilmasangiz ham shu faylni ketma-ket bajarsangiz ishlaydi.

Web UI: `WEB-UI.bat` → brauzerda `http://localhost:8000` → yuqoridagi
`🛡 Responder` tabi.

---

## 0 · Responder kim va NIMA QILMAYDI

| Qiladi | Qilmaydi |
|---|---|
| Nishon hostdan snapshot oladi | Log tahlil qilmaydi (bu Hunter ishi) |
| Snapshotni baseline bilan solishtiradi | ATT&CK ID topshirmaydi (bu Kapitan ishi) |
| Tozalash buyruqlarini **yasaydi** | Toolga hech narsani avtomatik o'chirtirmaydi |
| Buyruqlarni qo'lda bajaradi va vaqtini yozadi | Dalil olinmasdan hech narsaga tegmaydi |
| Xizmatlar tirikligini kuzatadi | Checker IP ni bloklamaydi |

Uchta qoida — buni yodlang, qolganini fayl aytadi:

- **C-3 — Tuzatishdan OLDIN dalil.** Siz vazifani o'chirasiz, Hunter esa aynan
  o'sha vazifa nomi bilan `T1053.005` ni isbotlayotgan bo'ladi. O'chirishdan
  oldin: nima, to'liq yo'li, vaqti — jurnalga.
- **C-1 — Checker IP bloklanmaydi.** Tashkilotchining tekshiruv boti tashqaridan
  keladi. Uni hujumchi deb bloklasangiz availability ballingiz nolga tushadi va
  buni sizga hech kim aytmaydi.
- **C-9 — Tuzatgandan keyin o'sha joyni kuzating** va hujumchi ko'rgan parollarni
  almashtiring. Aks holda u oddiy login bilan qaytadi va logda "normal kirish"
  bo'lib ko'rinadi.

---

## 1 · Musobaqa boshlanishidan OLDIN (bir marta, 5 daqiqa)

### 1.1 Har bir nishon hostdan T0 (birinchi) snapshot oling

**Tashkilotchilar toza host bermasligi katta ehtimol** — host siz ko'rishdan oldin
allaqachon zararlangan bo'lishi mumkin. Shunga qaramay birinchi qilinadigan ish shu:
olingan snapshot "toza baseline" emas, **boshlang'ich nuqta**. Musobaqa ikki kun
davom etadi va hujumchi shu ikki kunda ishlashda davom etadi — u **qo'shgan** har
bir vazifa, xizmat va akkaunt keyingi snapshot bilan solishtirganda `high` ishonch
bilan chiqadi.

Toza baseline bo'lmasa nima yo'qoladi — o'lchangan:

| Rejim | Topilma | `high` |
|---|---|---|
| Toza baseline bilan | 6 | **4** |
| Baseline yo'q | 7 | **1** |

Ya'ni topilmalar yo'qolmaydi, **ishonch tartibi** yo'qoladi: zararli vazifa ham,
soxta `hosts` yozuvi ham `med` ga tushib, ro'yxat ichida ko'milib qoladi. Cheklangan
vaqtda eng qimmat narsa aynan shu tartib — shuning uchun 1.1b ni o'qing.

Windows:
```
powershell -ExecutionPolicy Bypass -File responder\collect_windows.ps1 -Baseline -Out base_WS07.json
```

Linux:
```
bash responder/collect_linux.sh -o base_web01.json
```

Masofadan:
```
Invoke-Command -ComputerName WS07 -FilePath responder\collect_windows.ps1 > base_WS07.json
ssh user@web01 'bash -s' < responder/collect_linux.sh > base_web01.json
```

Nom konvensiyasi: `base_<hostnomi>.json`. Bitta papkada saqlang.

### 1.1b Toza baseline bo'lmasa — zaxira tartibi

`--baseline` ga **istalgan** snapshot berilishi mumkin. Shu tartibda sinang:

1. **O'sha hostning T0 snapshoti.** Musobaqa davomida qo'shilgan hamma narsa chiqadi.
   Hujum siz kelishdan oldin bo'lgan bo'lsa — bu usul uni ko'rsatmaydi.
   ```
   bk resp triage snap_WS07_T1.json --baseline base_WS07.json
   ```
2. **Bir xil rolli qo'shni host.** Infratuzilma bir xil obrazdan yasalgan bo'ladi,
   shuning uchun WS07 da bor, WS08 da yo'q narsa shubhali.
   ```
   bk resp triage snap_WS07.json --baseline snap_WS08.json
   ```
   **Ehtiyot bo'ling:** ikkala host aynan bir xil zararlangan bo'lsa, umumiy
   artefaktlar bir-birini yo'q qiladi va hujum **butunlay ko'rinmay qoladi**
   (o'lchangan: `high` = 0). Bu ikkinchi fikr, asosiy manba emas.
3. **Uyda toza VM dan olingan etalon baseline.** Bu yagona usul — u sizning
   qo'lingizda: musobaqadan oldin toza Windows/Ubuntu o'rnatib, o'sha collector
   bilan snapshot olasiz va kit ichida olib borasiz. Obraz aynan mos kelmasa ham,
   OS ning standart xizmat/vazifa/autorun shovqinining katta qismini olib tashlaydi.
4. **Baseline umuman bo'lmasa** — `--from-logs` dagi **✔ LOG** ustuni asosiy ishonch
   manbaiga aylanadi. Snapshot "bu vazifa shubhali" desa, log "o'sha vazifa
   yaratilganini ko'rdim" deb tasdiqlaydi. Baselinesiz ish rejimida faqat
   ✔ LOG qatorlaridan boshlang.

### 1.1c Host SIEM ga ulanmagan bo'lsa — event loglar CSV ga

Kollektor snapshot bilan birga hostning **o'z loglarini** ham oladi va ularni
`snap_<host>_events.csv` ga yozadi. Bu fayl `bk logs analyze` ga (yoki web Logs
tabiga) to'g'ridan-to'g'ri beriladi va konvertatsiya shart emas. Bir nechta host
CSV sini SIEM eksporti bilan birga bitta buyruqda bersangiz, hammasi bitta vaqt
chizig'iga tushadi.

**Windows** (albatta **admin** PowerShell da, aks holda Security logi o'qilmaydi
va kollektor `[!] Security: admin emas` deb ogohlantiradi):
```
powershell -ExecutionPolicy Bypass -File responder\collect_windows.ps1 -Out snap_WS07.json
  → snap_WS07.json + snap_WS07_events.csv
```
Yig'iladigan loglar: Security (4624/4625/4688/4698/4720/1102…), System 7045,
PowerShell 4104/400, Sysmon (o'rnatilgan bo'lsa), Defender, TaskScheduler,
RDP (TerminalServices), WMI. Opsiyalar: `-EventsDays 7` (necha kun),
`-EventsMax 10000` (har log uchun), `-EventsOut x.csv`, `-NoEvents`.

**Linux** (`sudo` bilan, aks holda auth.log/audit.log o'qilmasligi mumkin):
```
sudo bash collect_linux.sh -o snap_web01.json
  → snap_web01.json + snap_web01_events.csv + snap_web01_logs.tgz (xom loglar, dalil)
    (+ snap_web01_events_journal.log, snap_web01_events_last.txt)
```
CSV ga journal (bo'lmasa `auth.log`/`secure`/`syslog`/`messages`),
`audit.log` (EXECVE buyruqlari, hex argumentlar ochilgan), `.bash_history` va
`.zsh_history` tushadi. Web access loglar arxivda qoladi:
`bk logs analyze access.log` ularni o'zi o'qiydi.
Opsiyalar: `-D 7` (kun), `-M 20000` (har manba uchun), `-E x.csv`, `-N` (logsiz).

Nusxalab olingan `/var/log` (yoki macOS dan olingan `Users/<u>/.zsh_history`)
papkasini **o'z noutbukingizda** (Git Bash) CSV ga aylantirish:
```
bash responder/collect_linux.sh -O -R D:/case/web01_logs -E web01_events.csv -Z +05:00 -H web01
```
(`tar xzf snap_web01_logs.tgz -C D:/case/web01_logs` bilan oching. Yo'lni
**`/` bilan** yozing: bash da `\` yo'lni buzadi. `-H` bermasangiz, host nomi
syslog qatorlaridan olinadi, u ham bo'lmasa `unknown` bo'ladi.)

**Tuzoqlar:**
- **stdout rejimida loglar yig'ilmaydi.** `Invoke-Command ... > snap.json` va
  `ssh ... 'bash -s' < collect_linux.sh > snap.json` faqat snapshot beradi. Loglar
  kerak bo'lsa, skriptni hostga nusxalab `-Out`/`-o` fayl bilan yurgizing yoki
  `-EventsOut`/`-E` bering (fayl hostning o'zida qoladi, keyin uni nusxalab oling).
- Vaqtsiz tarix buyruqlari (`.bash_history` da `HISTTIMEFORMAT` yo'q bo'lsa)
  `EventID=history_untimed` bilan belgilanadi va **fayl mtime** vaqtini oladi.
  Bu buyruq bajarilgan vaqt emas.
- Log bo'sh yoki keskin qisqargan bo'lsa, bu tozalash belgisi (T1070.001 / T1070.002).
  Windows da Security 1102 va System 104 hodisalarini qidiring.
- **Distro:** skript Ubuntu, Debian, Kali, RHEL/CentOS/Rocky/Alma, Fedora va SUSE da
  ishlaydi. Har doim **`bash`** bilan yurgizing, `sh` bilan emas (Debian/Ubuntu da `sh`
  aslida dash). `sh` bilan yurgizilsa, skript `bash talab qiladi` deb exit 2 bilan chiqadi.
  Alpine/BusyBox da avval `bash` kerak; u yerda `find -printf` yo'q, shuning uchun
  sekinroq `stat` yo'li ishlatiladi (`meta.deep.find_mode: "stat"`).
- **Blok bo'sh chiqsa**, avval `meta.capabilities` ga qarang. Masalan `auditd_log:false`
  bo'lsa, EXECVE yozuvlari yo'q (Ubuntu/Debian da auditd sukut bo'yicha o'rnatilmaydi).
  Bu hostda hujum yo'q degani emas. `is_root:false` bo'lsa, loglarning bir qismi o'qilmagan.
  Distro nomi `meta.distro` da.

### 1.1d macOS host — qo'lda buyruqlar (kollektor YO'Q)

Kitda macOS kollektori yo'q: `collect_linux.sh` macOS da ishlamaydi (bash 3.2,
`/proc`/`systemctl`/`find -printf` yo'q). Mac uchragan bo'lsa, quyidagini **Terminal**
da (`sudo` bilan) bajarib, papkani noutbukka olib keling. Buyruqlarning hammasi
**faqat o'qiydi**.

```
H=$(hostname -s); D=/tmp/mac_$H; mkdir -p $D; cd $D

# 1. Loginlar, sudo, SSH, ekran ulashish (Unified Log, 7 kun)
sudo log show --last 7d --style syslog --predicate 'process == "sshd" OR process == "sudo" OR process == "su" OR process == "screensharingd" OR process == "loginwindow"' > mac_${H}_auth.log

# 2. Persistence: LaunchAgents/Daemons, login items, cron
ls -la /Library/LaunchAgents /Library/LaunchDaemons /Users/*/Library/LaunchAgents > persist_ls.txt 2>&1
launchctl list | grep -v com.apple > launchctl.txt
sudo sfltool dumpbtm > btm.txt 2>&1          # macOS 13+: barcha login item/agentlar ro'yxati
sudo crontab -l > cron_root.txt 2>&1; crontab -l > cron_user.txt 2>&1

# 3. Qaysi fayl QAYERDAN yuklab olingan (phishing ilovasini topish uchun eng qimmat dalil)
for u in /Users/*; do sqlite3 "$u/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2" \
  "select datetime(LSQuarantineTimeStamp+978307200,'unixepoch'), LSQuarantineAgentName, LSQuarantineDataURLString, LSQuarantineOriginURLString from LSQuarantineEvent order by 1 desc limit 100" \
  > "quarantine_$(basename $u).txt" 2>&1; done

# 4. Buyruqlar tarixi (zsh — macOS 10.15+ standart shell)
for u in /Users/* /var/root; do cp "$u/.zsh_history" "zsh_history_$(basename $u)" 2>/dev/null; cp "$u/.bash_history" "bash_history_$(basename $u)" 2>/dev/null; done

# 5. Jarayonlar, tarmoq, akkauntlar, proksi/DNS/profillar, SSH kalitlar
ps auxww > ps.txt; lsof -nP -i > lsof_net.txt 2>&1
dscl . list /Users | grep -v '^_' > users.txt; dscl . read /Groups/admin GroupMembership > admins.txt
scutil --proxy > proxy.txt; scutil --dns | grep nameserver > dns.txt; cat /etc/hosts > hosts.txt
sudo profiles list > profiles.txt 2>&1
cat /Users/*/.ssh/authorized_keys /var/root/.ssh/authorized_keys > authorized_keys.txt 2>/dev/null

cd /tmp; tar czf ~/mac_$H.tgz mac_$H
```

Noutbukda:
- `bk logs analyze mac_<host>_auth.log` vaqtlarni o'qiydi (`+0500` offset bilan). Host
  nomi fayl nomidan olinadi.
- `.zsh_history` ni CSV ga aylantirish: `zsh_history_<user>` faylini
  `<papka>/Users/<user>/.zsh_history` qilib qo'ying, keyin
  `bash responder/collect_linux.sh -O -R <papka> -E mac_events.csv -H <mac_host>`.
  `: 1790744401:0;buyruq` qatoridagi vaqt avtomatik o'qiladi.
- Shubhali fayl: `xattr -l <fayl>` va `mdls -name kMDItemWhereFroms <fayl>` fayl
  qaysi URL dan kelganini ko'rsatadi.
- Tozalash (FAQAT qo'lda, ko'rib chiqib): `sudo launchctl bootout system/<label>`
  (yoki `gui/<uid>/<label>`), keyin `.plist` ni o'chirmasdan `/tmp/quarantine/` ga ko'chiring.

### 1.2 Himoyalanadigan ro'yxat (`protected.yaml`)

Bu ro'yxatdagi narsalar triage natijasida **PROTECTED** deb belgilanadi va
tozalash skriptiga tushmaydi. Checker IP, admin akkaunt, baholanadigan xizmat —
shu yerga.

```yaml
items:
  - checker_admin
  - 10.0.0.50
```

Namuna: `responder/protected.example.yaml`.
Avtomatik yasash: `bk resp discover base_*.json --allowlist-out protected.yaml`

### 1.3 Xizmatlar ro'yxati (`services.yaml`) — SLA uchun

Namuna: `responder/sla.example.yaml`. Web UI dagi **⏱ SLA Holati** maydoniga ham,
CLI ga ham shu fayl beriladi (7-bo'limga qarang). **Laptopdan yurgizsangiz faqat
`tcp` va `http` tekshiruvlarini yozing** — sababi 7-bo'limda.

---

## 2 · Tabning anatomiyasi

Ekran uch qismdan iborat:

```
┌─ chap karta ──────────────┐  ┌─ o'ng karta ─────────────┐
│ 📸 Snapshot & Dalillar    │  │ 🛠 Remediation Generator  │
│  • Joriy Snapshot         │  │  • OS: Windows / Linux    │
│  • Baseline Snapshot      │  │  • ☐ Full                 │
│  • Log Analyzer natijasi  │  │  [⚙ Buyruqlarni yasash]   │
│  • Protected YAML         │  └───────────────────────────┘
│  [🔍 Triage] [💰 Fraud]   │
│  [⏱ SLA]  [🩺 Doctor]     │
└───────────────────────────┘
┌─ pastdagi natija maydoni (hamma tugma shu yerga yozadi) ─┐
```

**Muhim:** pastdagi natija maydoni bitta. Yangi tugma bosilsa eskisi
**o'chib ketadi**. Kerakli natijani oldin nusxalab oling yoki skrinshot qiling.

### Maydonlar nima qiladi

| Maydon | Nima beriladi | Majburiymi |
|---|---|---|
| **Joriy Snapshot** | Nishondan hozir olingan `snap_<host>.json`. Fayl tanlash tugmasi yoki fayl yo'li, yoki JSON matnini to'g'ridan-to'g'ri qo'yish (`{` bilan boshlansa matn deb qabul qilinadi) | ✅ ha, busiz hech qaysi tugma ishlamaydi |
| **Baseline Snapshot** | 1.1 da olingan `base_<host>.json` yoki 1.1b dagi zaxira | ⚠️ ixtiyoriy — busiz ham ishlaydi (`knowngood.yaml`), lekin bo'lsa aniqroq |
| **Log Analyzer natijasi** | `bk logs analyze ... --json-out out\f.json` fayli | ixtiyoriy, lekin ✔LOG ustuni shundan chiqadi |
| **Protected YAML** | 1.2 dagi ro'yxat, har bir element `- ` bilan yangi qatordan | ixtiyoriy, lekin C-1 uchun kerak |

**Eng ko'p uchraydigan xato:** Log Analyzer maydoniga `ir chain --json` faylini
berish. U ishlamaydi — jimgina bo'sh natija beradi. Faqat
`logs analyze --json-out` fayli.

Tez sinab ko'rish uchun: **⚡ Namuna Snapshot** tugmasi — buzilgan Linux web
server snapshotini yuklaydi. Musobaqadan oldin hamma tugmani shu demo bilan bir
marta bosib ko'ring.

---

## 3 · Asosiy oqim: TRIAGE

1. **Joriy snapshot** ni oling:
   ```
   powershell -ExecutionPolicy Bypass -File responder\collect_windows.ps1 -Out snap_WS07.json
   ```
2. Chap kartaga: joriy snapshot + baseline + (bo'lsa) log natijasi + protected.
3. **🔍 Triage Tahlili** tugmasini bosing.

Natija jadvali ustunlari:

| Ustun | Ma'nosi | Nima qilasiz |
|---|---|---|
| **Ball (Score)** | Shubha darajasi, katta = yomon | Jadval shu bo'yicha tartiblangan — yuqoridan boshlang |
| **Ishonch** | high / medium / low | `low` larni oxiriga qoldiring |
| **Kategoriya** | service / task / user / autorun / network / file | Qaysi turdagi o'rnashish |
| **Ob'ekt (Item)** | Aniq nom yoki yo'l | Tozalash aynan shunga tegadi |
| **Texnikalar** | ATT&CK ID chiplari | Bosing → KB modali ochiladi. **Kapitanga ayting** — bu topshiriladigan ID bo'lishi mumkin |
| **Himoyalangan** | PROTECTED | Bu narsaga TEGMANG (checker yoki kerakli xizmat) |
| **Log Tasdiqi** | ✔ LOG | Bu topilmani log ham tasdiqlagan — **eng ishonchli qatorlar shular** |
| **Sabablar** | Nega shubhali | Jurnalga va hisobotga shu matn yoziladi |

**Qaysi qatordan boshlash:** yuqori ball + `high` ishonch + ✔ LOG. Bu uchlik bir
qatorda uchrashsa — bu deyarli aniq hujumchining izi.

### "Loglarda bor, lekin Snapshotda topilmadi"

Jadval tagidagi qizil blok. Ma'nosi: log aytadiki bu artefakt bor edi, hozirgi
snapshotda esa yo'q. Ikki sabab bo'lishi mumkin:

- hujumchi o'zidan keyin tozalab ketgan (izni yo'qotish — bu ham ATT&CK texnikasi),
- yoki siz snapshotni noto'g'ri hostdan olgansiz.

Ikkalasi ham qo'lda tekshiriladi va Kapitanga aytiladi.

---

## 4 · Tozalash buyruqlarini yasash (FIX)

1. O'ng kartada **OS** ni tanlang (Windows / Linux) — nishon hostning OS i.
2. **☐ Full** — belgilanmasa faqat yuqori ishonchli topilmalar skriptga kiradi.
   Boshida belgilamang; kam, lekin aniq buyruq yaxshiroq.
3. **⚙ Tozalash Buyruqlarini Yasash**.

Chiqadigan skript to'rt qismdan iborat va shu tartibda o'qiladi:

```
# 1. BACKUP   — o'chirishdan oldin nusxa/eksport
# 2. REMOVE   — asosiy tozalash buyrug'i
# 3. VERIFY   — tozalanganini tekshirish
# 4. ROLLBACK — noto'g'ri narsani o'chirgan bo'lsangiz qaytarish
```

**Tool hech narsani o'zi bajarmaydi.** Siz buyruqni o'qiysiz, tushunasiz,
keyin nishon hostning terminalida qo'lda ishga tushirasiz.

### Bajarishdan oldin — 30 soniyalik ritual (C-3)

Har bir tozalashdan oldin jurnalga bitta qator yozing:

```
vaqt (Toshkent) | host | nima qilindi | buyruq | kim
2026-10-05 09:14 | WS07 | scheduled task "UpdateChk" o'chirildi | schtasks /delete /tn UpdateChk /f | Aziz
```

Jurnal ikki joyda kerak bo'ladi: hisobotda ("birinchi biz tuzatdik" dalili) va
Hunter bilan nizo chiqqanda ("bu izni siz o'chirganmisiz?").

**BACKUP qismini o'tkazib yubormang.** Noto'g'ri narsani o'chirsangiz, xizmat
qulaydi va availability ballingiz ketadi — ROLLBACK faqat backup bo'lsa ishlaydi.

---

## 5 · 💰 Fraud tekshirish

1-kun stsenariysi uchun (phishing → buxgalter akkaunti → soxta pul o'tkazmasi).
Snapshot ichidan qidiradi: masofaviy boshqaruv dasturlari (AnyDesk, RMS, …),
o'zgartirilgan `hosts` fayli (soxta bank manzili), soxta root sertifikat,
shubhali proksi va DNS, portproxy, o'chirilgan firewall profili.

RAT va `hosts` Triage bilan bir xil qoida bo'yicha tekshiriladi. Fraud "toza"
desa ham **🔍 Triage** ni yurgizing: vazifa, xizmat va autorun faqat unda chiqadi.

Natija: ATT&CK texnikasi + tavsiya etilgan tekshiruv. Texnika chipini bosing —
KB modali ochiladi. "Toza" chiqsa yashil karta ko'rsatiladi.

Bu **faqat o'qiydi**, hech narsani o'zgartirmaydi.

---

## 6 · 🩺 Service Doctor

Qachon: bir xizmat o'lgan va nega o'lganini bilmayapsiz.

1. Chapda **"To'xtagan servis nomi"** maydoniga aniq nom yozing: `nginx`,
   `apache2`, `sshd`, `mysql`, `W3SVC`.
2. **🩺 Service Doctor**.

Natija: Sabab → Dalil → Tuzatish buyrug'i (nusxalash tugmasi bilan). Buyruqni
ham qo'lda bajarasiz va jurnalga yozasiz.

---

## 7 · ⏱ SLA tugmasi — DIQQAT, bu yerda tuzoq bor

Web UI dagi **⏱ SLA Holati** tugmasi hozir **hech narsani tekshirmaydi**.
U serverga bo'sh xizmatlar ro'yxati yuboradi, bo'sh javob oladi va
"Snapshotda faol servislar ro'yxati tahlil qilindi" deb yozadi. Bu matn
sizni chalg'itadi — aslida hech qanday xizmat tekshirilmagan.

**Endi web tabda ham, CLI da ham ishlaydi:**

```
bk resp sla services.yaml --watch --interval 30
```

### Nimani tekshiradi — bu yerda adashmang

SLA **sizning laptopingizdagi** xizmatlarni tekshirmaydi. U tashkilotchining
checker boti kabi ishlaydi: **tashqaridan nishon tizimga ulanadi**. Lekin
tekshiruv turlari ikki xil oilaga bo'linadi:

| Tur | Qayerni tekshiradi | Laptopdan foydalimi |
|---|---|---|
| `tcp` | `target: 10.10.20.11:80` — tarmoq orqali | ✅ **ha, asosiy** |
| `http` | `url: http://10.10.20.11/` — tarmoq orqali | ✅ **ha, asosiy** |
| `process` | `tasklist` / `ps` — **bk ishlagan mashinada** | ❌ laptopingizni tekshiradi |
| `service` | `sc query` / `systemctl` — **bk ishlagan mashinada** | ❌ laptopingizni tekshiradi |
| `file_hash`, `file_absent` | lokal fayl yo'li | ❌ laptopingizni tekshiradi |

Ya'ni laptopda turib `type: service, name: W3SVC` yozsangiz, u **sizning**
laptopingizda W3SVC ni qidiradi va "topilmadi" deydi — nishon server bilan
hech qanday aloqasi yo'q.

**Musobaqada qoida oddiy: laptopdan faqat `tcp` va `http` ishlating.** Bu
aynan checker ko'radigan manzara. Agar port ochiq va sahifa 200 qaytarsa —
availability balli hisoblanadi; siz ham shuni ko'rasiz.

`process` / `service` / `file_*` faqat bitta holatda ma'noli: `bk.exe` ni
**nishon hostning o'ziga** ko'chirib, o'sha yerda yurgizsangiz. Odatda
bunga hojat yo'q.

### Ish tartibi

Ikkinchi oynada (yoki web tabda avto-yangilash yoqib) ochib, musobaqa
davomida ochiq qoldiring. Holat `TIRIK` → `O'LGAN` ga o'zgarsa darhol
bilasiz. **Har bir tuzatishdan oldin va keyin qarang** — scoreboard
qizarsa rollback qiling (C-8).

---

## 8 · Tozalashdan KEYIN

1. **Qayta triage** — o'sha snapshotni qaytadan oling va yana tekshiring:
   ```
   powershell -ExecutionPolicy Bypass -File responder\collect_windows.ps1 -Out snap_WS07_after.json
   ```
   Tozalagan narsangiz jadvaldan yo'qolganiga ishonch hosil qiling.
2. **Parollarni almashtiring** — hujumchi ko'rgan hamma akkaunt (C-9).
3. **Kuzating** — tuzatilgan joy qayta buziladi. 10-15 daqiqada bir qayta
   tekshiring.
4. **Playbook tabida belgilang** — 4-faza qadamlarini `Bajarildi` qiling.
   Kapitan shu yerdan ko'radi, og'zaki aytish hisoblanmaydi (C-10).

---

## 9 · Tez-tez uchraydigan xatolar

| Xato | Belgisi | Yechim |
|---|---|---|
| Snapshot berilmagan | Sariq "Joriy Snapshot Kiritilmadi" kartasi | Fayl tanlang yoki demo tugmasini bosing |
| Log maydoniga `chain.json` berilgan | ✔ LOG ustuni hamma joyda bo'sh | `logs analyze --json-out` faylini bering |
| Baseline berilmagan | Hamma narsa `med`, nimadan boshlashni bilmaysiz | 1.1b dagi zaxira tartibi: T0 → qo'shni host → etalon VM → ✔ LOG |
| Qo'shni host baseline qilindi, natija bo'm-bo'sh | Ikkala host bir xil zararlangan | Bu usulni tashlang, T0 yoki ✔ LOG ga o'ting |
| Natija yo'qoldi | Boshqa tugma bosilgan | Natija maydoni bitta — avval nusxalang |
| SLA hamma xizmatni "O'LGAN" deb ko'rsatyapti | `process`/`service`/`file_*` turlari laptopingizni tekshiryapti | Konfigda faqat `tcp` va `http` qoldiring (7-bo'lim) |
| Checker bloklab qo'yildi | Availability ball tushdi, xabar yo'q | Oldindan `protected.yaml` ga checker IP ni qo'ying |

---

## 10 · Bir sahifalik qisqacha

```
OLDIN:   collect_windows.ps1 -Baseline -Out base_<host>.json     (har bir host, T0)
         toza bo'lmasa ham oling — 1.1b dagi zaxira tartibi ishlaydi
         protected.yaml tayyor (checker IP + admin)
         bk resp sla services.yaml --watch   (alohida oynada, doim ochiq)
         services.yaml da FAQAT tcp/http - qolgan turlar laptopni tekshiradi

HODISA:  collect_windows.ps1 -Out snap_<host>.json
         Responder tab -> snapshot + baseline + logs + protected
         [🔍 Triage]  -> yuqori ball + high + ✔LOG qatorlaridan boshlang
                      -> texnika ID larini Kapitanga ayting
         [💰 Fraud]   -> 1-kun stsenariysi uchun
         [⚙ Fix]      -> BACKUP -> jurnalga yozing -> qo'lda bajaring -> VERIFY

KEYIN:   qayta snapshot + qayta triage
         parollarni almashtiring
         Playbook tabida 4-faza qadamlarini belgilang
```
