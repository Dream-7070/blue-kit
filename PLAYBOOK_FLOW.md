# blue-kit — OQIM PLAYBOOK

`PLAYBOOK.html` **stsenariy** bo'yicha (nima bo'lgan bo'lishi mumkin).
Bu fayl **oqim** bo'yicha: qaysi buyruqni qachon yurgizasan va natijani kimga berasan.

Belgilar: ✅ ishlaydi · ⚠️ qisman / qo'lda · ❌ yo'q

> Buyruqlar `python bk.py ...` ko'rinishida. Tarqatilgan `.exe` da `bk.exe ...`.

---

## A · Butun oqim bir ekranda

```
# 0. BOSHLASHDAN OLDIN — baseline (hech narsaga tegmasdan)
powershell -ExecutionPolicy Bypass -File responder\collect_windows.ps1 -Baseline -Out base_<host>.json
bash collect_linux.sh -o base_<host>.json

# 1. SIEM DAN LOG OLISH
python bk.py siem hunts --category network
python bk.py siem query exfil-large-upload --siem qradar --days 7
#    -> SIEM ga paste -> CSV eksport -> case\<sana>\<scope>_<hunt-id>_<vaqt>.csv

# 2. HAR BIR EKSPORTNI TEKSHIR
python bk.py logs columns case\...\f.csv
python bk.py logs analyze case\...\f.csv --preset qradar --json-out out\f.json

# 3. HAMMASINI ZANJIRGA
python bk.py ir chain (Get-ChildItem case\<sana>\*.csv).FullName --lang uz
python bk.py ir chain (Get-ChildItem case\<sana>\*.csv).FullName --json --out out\chain.json

# 4. RESPONDER  (DIQQAT: chain.json EMAS -> D bo'limiga qara)
powershell -ExecutionPolicy Bypass -File responder\collect_windows.ps1 -Out snap_<host>.json
python bk.py resp triage snap_<host>.json --baseline base_<host>.json --from-logs out\f.json
python bk.py resp fix    snap_<host>.json --from-logs out\f.json --os windows

# 5. HISOBOT
python bk.py ir report (Get-ChildItem case\<sana>\*.csv).FullName --lang uz --out report_uz.md
```

PowerShell da `*.csv` ni `bk.py` o'zi ochmaydi — yuqoridagi `(Get-ChildItem ...).FullName`
shakli fayllar ro'yxatini uzatadi. Bash da oddiy `case/*.csv` ishlaydi.

---

## B · Fazalar

### 0-faza · Boshlashdan oldin

| # | Qadam | Buyruq / usul | Holat |
|---|---|---|---|
| 0.1 | Tashkilotchilardan aniqlash (pastda ro'yxat) | og'zaki | ⚠️ |
| 0.2 | **Har bir nishon hostdan baseline** | `collect_windows.ps1 -Baseline` | ✅ |
| 0.3 | Tool tayyorligi: KB, data, resurslar | `bk doctor` (9 tekshiruv) + `bk kb info` | ✅ |
| 0.4 | Vaqt zonasi: tool **Toshkent (UTC+5)** da ko'rsatadi, +5 qo'shmang; zonasiz loglar UTC bo'lsa `--src-tz utc` | — | ✅ chiqishda eslatiladi |
| 0.5 | Case papkasi va nom konvensiyasi | `case\<sana>\<scope>_<hunt-id>_<vaqt>.csv` | ⚠️ qo'lda |

**Tashkilotchilardan so'raladigan savollar (javobi strategiyani o'zgartiradi):**

1. Ota-texnika (`T1059`) qabul qilinadimi yoki faqat sub-texnika (`T1059.001`)?
2. Bitta savolga nechta urinish? Noto'g'ri javob uchun jarima bormi?
3. Qaysi xizmatlar availability uchun baholanadi va qaysi portdan tekshiriladi?
4. Loglarni eksport qilish ruxsatimi? Qaysi formatda?
5. ATT&CK qaysi versiyasi bo'yicha baholanadi? (v19 da raqamlar o'zgargan)

**0.2 ni tashlab ketmang.** Baselinesiz `resp triage` nima normal ekanini bilmaydi va
shovqin beradi. Baseline olish — 30 soniya, keyin qayta olib bo'lmaydi.

### 1-faza · SIEM dan loglarni olish

| # | Qadam | Buyruq | Holat |
|---|---|---|---|
| 1.1 | Nima qidirishni tanlash | `bk siem hunts [--category X] [--search Y]` | ✅ |
| 1.2 | Hunt tafsiloti | `bk siem show <hunt-id>` | ✅ |
| 1.3 | So'rov olish | `bk siem query <hunt-id> --siem qradar --days 7` | ✅ |
| 1.4 | Bir nechta so'rovni bir faylga | `bk siem pack --siem qradar --category auth --out q.txt` | ✅ |
| 1.5 | SIEM ga paste, CSV eksport | qo'lda | — |
| 1.6 | Eksport o'qiladimi | `bk logs columns <fayl>` | ✅ |
| 1.7 | Web UI orqali | `🔍 SIEM So'rov` tabi | ✅ |

**Qaysi hunt dan boshlash (zarardan orqaga, C-2 qoidasiga qara):**

| Tartib | Hunt | Savol |
|---|---|---|
| 1 | `exfil-large-upload`, `evasion-recovery-inhibit` | zarar nima va qayerda |
| 2 | `c2-rare-port`, `c2-dns-tunnel` | tashqariga nima gaplashyapti |
| 3 | `lateral-admin-share`, `lateral-remote-service` | qayoqqa tarqalgan |
| 4 | `persist-*` | qayerga o'rnashgan |
| 5 | `exec-encoded-powershell`, `exec-office-child` | qanday bajarilgan |
| 6 | `auth-bruteforce`, `auth-external-rdp` | qanday kirgan |

12 ta SIEM: `qradar splunk sentinel defender elastic kibana wazuh graylog chronicle
sumologic arcsight logscale` — `bk siem list`.

### 2-faza · Qaysi hostdan qaysi faylni olish

| # | Qadam | Buyruq | Holat |
|---|---|---|---|
| 2.1 | Eksportni tahlil qilish | `bk logs analyze <f> --preset <p> --json-out out\f.json` | ✅ |
| 2.2 | Shubhali hostlarni reytinglash | — | ❌ |
| 2.3 | Host uchun: endi qaysi artefakt | — | ❌ |
| 2.4 | Artefaktni olish buyrug'i | — | ❌ |

**Bu faza bugun avtomatlashtirilmagan.** Qo'lda usul: 3-fazani bir marta yurgizib,
`compromised_hosts` va `mitre_attack_techniques` ro'yxatini olasiz, keyin quyidagi
jadval bo'yicha qaysi artefakt kerakligini tanlaysiz:

| Topilgan texnika | O'sha hostdan olinadigan artefakt |
|---|---|
| T1059.001 PowerShell | PowerShell Operational log, Prefetch, Amcache |
| T1059.003 cmd | Security 4688, Prefetch |
| T1543.003 xizmat | System 7045, SYSTEM hive, Autoruns |
| T1053.005 vazifa | Security 4698/4702, `C:\Windows\System32\Tasks\` |
| T1547.001 Run kaliti | NTUSER.DAT, SOFTWARE hive, Autoruns |
| T1021.001 RDP | TerminalServices-*, Security 4624 (type 10), 4778/4779 |
| T1021.002 SMB | Security 5140/5145 |
| T1003.001 LSASS | Sysmon 10, EDR log |
| T1071 / T1571 C2 | firewall va proxy loglari, o'sha host IP si bo'yicha |
| T1041 / T1048 exfil | firewall (bayt hisobi), proxy, DLP |

EVTX ni CSV ga aylantirish (blue-kit presetlari shularga moslangan):

```
hayabusa.exe csv-timeline -d <evtx-papka> -o hb.csv     ->  --preset hayabusa
EvtxECmd.exe -d <evtx-papka> --csv . --csvf ex.csv      ->  --preset evtxecmd
```

### 3-faza · Attack chain

| # | Qadam | Buyruq | Holat |
|---|---|---|---|
| 3.1 | Hamma fayllarni bitta zanjirga | `bk ir chain f1 f2 f3 --lang uz` | ✅ |
| 3.2 | Mashina o'qiydigan chiqish | `bk ir chain ... --json --out out\chain.json` | ✅ |
| 3.3 | Beacon tahlili (davriylik) | `bk hunt beacons <firewall.csv>` | ✅ |
| 3.4 | Javob reytingi va topshirish daftari | `bk answers rank` / `bk answers submit` | ✅ |
| 3.5 | **ID ni topshirishdan oldin tekshirish** | `bk kb validate T1059.001 T1053.005` | ✅ |

`ir chain` papka va `*.csv` ni qabul qilmaydi — fayllarni ro'yxat qilib bering
(A bo'limidagi `(Get-ChildItem ...).FullName` shakli).

**3.5 majburiy.** ATT&CK v19 da raqamlar o'zgargan. Ma'lum misollar:

| Eski (revoked) | Yangi |
|---|---|
| `T1070.001` Clear Windows Event Logs | **`T1685.005`** |
| `T1562.001` Disable or Modify Tools | **`T1685`** |

Eski ID topshirsangiz urinish behuda ketadi.

### 4-faza · Responder

| # | Qadam | Buyruq | Holat |
|---|---|---|---|
| 4.1 | Nishon hostdan joriy snapshot | `collect_windows.ps1 -Out snap.json` | ✅ |
| 4.2 | Triaj (baseline bilan) | `bk resp triage snap.json --baseline base.json --from-logs out\f.json` | ✅ |
| 4.3 | Tuzatish buyruqlarini olish | `bk resp fix snap.json --from-logs out\f.json --os windows` | ✅ |
| 4.4 | Himoyalanadigan ro'yxat | `--protected protected.yaml` | ✅ |
| 4.5 | **Zanjirdan responderga uzatish** | `--from-logs out\f.json` | ⚠️ faqat `logs analyze --json-out` fayli, D bo'limiga qara |
| 4.6 | SLA / xizmat holati | `bk resp sla services.yaml --watch` | ✅ tcp/http/process/service/fayl |
| 4.7 | Xizmat tashxisi | `bk resp doctor snap.json <xizmat>` | ✅ sabab + tuzatish buyrug'i |
| 4.8 | Vazifalar navbati / notification | — | ❌ yo'q |
| 4.9 | Bajarilganini belgilash | web UI **Playbook** tabi (4-faza qadamlari) | ✅ holat saqlanadi |

`--from-logs` ga **`logs analyze --json-out`** fayli beriladi, `ir chain --json` emas.

### 5-faza · Hisobot

| # | Qadam | Buyruq | Holat |
|---|---|---|---|
| 5.1 | IR hisoboti (uz/ru/en) | `bk ir report f1 f2 --lang uz --out report_uz.md` | ✅ |
| 5.2 | Log tahlili hisoboti | `bk logs analyze <f> --out r.html` | ✅ |
| 5.3 | Umumiy hisobot generatori | `bk report` | ✅ |
| 5.4 | Bajarilgan remediatsiya va vaqti | `bk report --resp <triage.json>` | ⚠️ topilmalar kiradi, qo'lda bajarilgan vaqt jurnali — yo'q |
| 5.5 | Topshirilgan ID lar jurnali | `bk answers rank --ledger answers.json` / `bk report --answers` | ✅ |

**5.4 uchun qo'lda jurnal yuriting** — birinchi-tuzatgan ochkosi uchun "qachon
tuzatdik" dalili kerak:

```
vaqt (Toshkent) | host | nima qilindi | buyruq | kim
```

---

## C · Qoidalar (musobaqa boshlanishidan oldin kelishib oling)

**C-1 · Checker IP ni aniqlamaguncha hech narsa bloklanmaydi.**
Tashkilotchilarning ball hisoblovchi boti xizmatlarni tashqaridan tekshiradi. Uni
hujumchi deb bloklasangiz — availability ballingiz nolga tushadi va buni hech kim
aytmaydi. Tool checker larni aniqlaydi: `logs analyze` chiqishidagi `checkers`,
`resp triage` da "checker IP (loglardan)" belgisi. **Bonus:** checker nimani so'rasa,
o'sha baholanadi — uning trafigidan "nimani tirik saqlash kerak" ro'yxatini oling.

**C-2 · Zarardan orqaga yuring, phishingdan oldinga emas.**
Phishing xati logda bo'lmasligi mumkin, zarar esa aniq. Orqaga yurganda har qadamda
tekshirilgan fakt bo'ladi.

**C-3 · Tuzatishdan oldin dalilni oling.**
Responder vazifani o'chiradi — Hunter o'sha vazifa nomi bilan T1053.005 ni isbotlayotgan
edi. Har bir tuzatishdan oldin: nima o'chirilyapti, to'liq yo'li, vaqti — jurnalga.

**C-4 · SLA buzilishi hamma narsani to'xtatadi.**
Ikki soat parallel ketadi: availability (uzluksiz) va tergov (diskret). Qoida
bo'lmasa jamoa har doim tergovni tanlaydi. Availability ni alohida oynada
`bk resp sla services.yaml --watch --interval 30` bilan uzluksiz kuzating.

**C-5 · Urinishlar — valyuta.**
Ishonch bo'yicha kamayish tartibida topshiring. Ota/sub-texnika qoidasini oldindan
so'rang (0-faza). Topshirilgan/qabul qilingan/rad etilgan daftarini yuriting —
aks holda to'rt kishi bir xil ID ni ikki marta topshiradi.

**C-6 · Gipoteza bilan ovlang.**
32 ta hunt ni ketma-ket yurgizmang. 2-3 ta raqobatlashuvchi gipoteza yozing va faqat
ularni **bir-biridan ajratadigan** dalilni qidiring. Hamma gipotezaga mos keladigan
dalil — befoyda dalil.

**C-7 · 15 daqiqa qoidasi.**
Birorta ATT&CK ID yoki harakat bermagan yo'nalish 15 daqiqada tashlanadi yoki boshqa
odamga beriladi.

**C-8 · Eng tez tuzatish — tiklash, tashxis emas.**
Oldindan tayyorlang: xizmat konfiglari, toza `hosts`, normal vazifalar va xizmatlar
ro'yxati. Tuzatish = `diff` + tiklash.

**C-9 · Tuzatgandan keyin o'sha joyni kuzating.**
Tuzatilgan narsa qayta buziladi. Va hujumchi ko'rgan parollarni almashtiring — aks
holda u oddiy login bilan qaytadi va loglarda "normal kirish" bo'lib ko'rinadi.

**C-10 · Da'vo taxtada, og'zaki emas.**
Kim nima ustida ishlayotgani Tracker da turadi. Aks holda to'rt kishi bir ishni qiladi.

### Rollar (`PLAYBOOK.html` dan, bitta qo'shimcha bilan)

| Rol | Vazifa |
|---|---|
| Hunter-1 | Windows / AD loglari |
| Hunter-2 | Linux / Web / Network loglari |
| Responder | tizimga kirib tuzatadi |
| Kapitan | Tracker + ID topshirish + vaqt |

**Qo'shimcha qoida:** Responder tahlil qilmaydi. Availability soati uniki. Ikkala
ishni bir odam qilsa, ikkalasi ham yomon bajariladi.

---

## D · ISHONMANG — bugun buzuq yoki yo'q

| Nima | Holati | Nima qilinadi |
|---|---|---|
| `resp fix/triage --from-logs <ir_chain.json>` | **Jimgina bo'sh natija.** `ir chain` `extracted_iocs`/`attack_chain_timeline` beradi, `logbridge` esa `iocs`/`timeline` kutadi | `logs analyze --json-out` faylini bering |
| Telegram bot | Internet talab qiladi | Offline finalda ishlamaydi |
| Xom `.evtx` / `.pcap` o'qish | Yo'q | Avval Hayabusa / EvtxECmd / TShark (2-faza) |
| Shubhali hostlarni avtomatik reytinglash | Yo'q (2-faza 2.2-2.4) | Qo'lda: 3-fazani bir marta yurgizib `compromised_hosts` ro'yxatini oling |
| Vazifalar navbati / notification | Yo'q | Playbook tabidagi qadam statuslari bilan yuriting |
| Qo'lda bajarilgan tuzatish vaqti jurnali | Hisobotga avtomatik kirmaydi | Ustunlar: vaqt (Toshkent), host, nima qilindi, buyruq, kim — qo'lda yuriting |

**Baseline haqida.** Tashkilotchilar toza host bermasligi mumkin. Bu holda
`--baseline` ga: (1) o'sha hostning T0 snapshoti, (2) bir xil rolli qo'shni host,
(3) uyda toza VM dan olingan etalon — shu tartibda. Hech biri bo'lmasa tool
`bluekit/resp/knowngood.yaml` (OS standart ro'yxati) bilan baselinesiz ham
ishlaydi; batafsil `RESPONDER_QOLLANMA.md` 1.1b.

---

## E · Musobaqagacha checklist

- [x] `.exe` qayta qurildi (Playbook tabi + knowngood + UTF-8 tuzatish bilan),
      `YANGILA.bat` bajarildi, `TEKSHIRUV.bat` 9/9
- [ ] **Toza noutbukda** sinash (Python o'rnatilmagan mashinada)
- [ ] Defender papka istisnosi **har bir noutbukda** + sinovdan o'tkazish
- [ ] Hayabusa / EvtxECmd + .NET runtime offline o'rnatilgan va sinalgan
- [ ] `bk kb info` — KB versiyasi va yo'li to'g'ri
- [ ] Har bir jamoa a'zosi o'z rolidagi buyruqlarni bir marta yurgizib ko'rgan
- [ ] Case papkasi shabloni va nom konvensiyasi kelishilgan
- [ ] Rollar taqsimlangan, C-3 / C-4 / C-10 qoidalari kelishilgan
- [ ] **Sekundomer bilan quruq mashq**: `elasticsearch_export.json` va `dest.csv`
      ustida. O'lchang: birinchi tekshirilgan ATT&CK ID gacha, birinchi tuzatishgacha,
      hisobotgacha qancha vaqt ketdi
- [ ] Tashkilotchilardan 0-fazadagi 5 savolga javob olingan
- [ ] Har bir a'zo web UI dagi **Playbook** tabini ochib ko'rgan va o'z
      fazasining qadamlarini biladi
- [ ] `services.yaml` va `protected.yaml` shablonlari oldindan tayyor
