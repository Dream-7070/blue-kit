# SPEC_NOISE3 — Linux post-exploitation va IDS alert detection (round 3)

## Muammo (o'lchangan, elasticsearch_export.json, round 1 dan keyin)
Shovqin tozalandi (299 777 → 11 detection), lekin endi **false negative** bor:
haqiqiy hujumning 25 ta eventi hech qanday texnika olmayapti.

Aniqlangan: SQLi (T1190), whoami, python reverse shell, cron persistence,
/etc/shadow, useradd, nmap — 11 ta.

**Aniqlanmagan 25 ta event:**
| Vaqt | Buyruq | Kutilgan texnika |
|---|---|---|
| 11:03 | `id` | T1033 |
| 11:06 | `uname -a` | T1082 |
| 11:12 | `/bin/bash -i` | T1059.004 |
| 12:45 | `sudo -l` | T1548.003 |
| 12:49 | `sudo /usr/bin/find . -exec /bin/sh -p \; -quit` | T1548.003 (GTFOBins) |
| 12:57 | `cat /root/.ssh/id_rsa` | T1552.004 |
| 14:38 | `ssh -i /tmp/stolen_id_rsa root@10.0.2.20` | T1021.004 + T1552.004 |
| 14:46, 14:54 | `pg_dump -U postgres -d customer_vault -f /tmp/...` | T1005 + T1074.001 |
| 16:17 | `tar -czf /tmp/vault_backup.tar.gz /tmp/*.sql` | T1560.001 + T1074.001 |
| 16:25–16:53 (15 ta) | `Suricata [Alert 1:2024001:1] High Volume Outbound HTTPS POST to Rare External IP 203.0.113.88` | T1071.001 + T1041 |

Eng og'ir kamchilik: **privilege escalation (GTFOBins) va ma'lumot o'g'irlash (pg_dump/tar)
umuman ko'rinmayapti** — ya'ni hisobotdagi eng muhim ikki bosqich yo'q.
`db-prod-02` "hujum belgisi yo'q" deb chiqyapti, holbuki exfil aynan o'sha yerda.

## O'zgartiriladigan fayl
`bluekit/kb/heuristics.yaml` — yangi qoidalar qo'shiladi (mavjudlari o'zgarmaydi).
Qo'shgandan keyin KB ni qayta build qilish kerak bo'lsa (`bluekit/kb/build.py`
heuristics jadvalini to'ldiradi) — buni ham bajar va qanday buyruq bilan
qayta build qilinganini hisobotda yoz.

## Qo'shiladigan qoidalar
Mavjud format: `- name / pattern / techniques / weight / note`.
Barcha ID lar lokal KB da `active` deb tekshirilgan.

1. **Sudo enumeration** — `(?i)\bsudo\s+-l\b` → `["T1548.003"]`, weight 0.6,
   note: "sudo huquqlarini ro'yxatlash"
2. **GTFOBins sudo abuse** —
   `(?i)sudo\s+(/\S+/)?(find|vim|vi|less|more|awk|nmap|python3?|perl|ruby|tar|zip|man|env|nice|cp|mv)\b.*(-exec|--checkpoint-action|-p\b|/bin/(sh|bash))`
   → `["T1548.003"]`, weight 0.95
3. **SSH private key access** —
   `(?i)(cat|cp|scp|base64|head|tail|less)\s+\S*(/\.ssh/(id_[a-z0-9]+|identity)|/root/\.ssh/\S+|\.pem)\b`
   → `["T1552.004"]`, weight 0.9
4. **SSH with key file** — `(?i)\bssh\s+(-\w+\s+)*-i\s+\S+\s+\S+@\S+`
   → `["T1021.004"]`, weight 0.7. Agar kalit `/tmp/` yoki `/dev/shm/` da bo'lsa
   qo'shimcha `T1552.004` ham qaytsin (alohida qoida sifatida yozish mumkin:
   `(?i)ssh\s+-i\s+/(tmp|dev/shm)/\S+` → `["T1021.004","T1552.004"]`, weight 0.9).
5. **Database dump** —
   `(?i)\b(pg_dump|pg_dumpall|mysqldump|mongodump|sqlite3\s+\S+\s+\.dump)\b`
   → `["T1005"]`, weight 0.85, note: "ma'lumotlar bazasi to'liq dump"
6. **Archive staging** —
   `(?i)\b(tar\s+-?c\w*z?f?|zip\s+-r|7z\s+a|gzip)\s+/(tmp|dev/shm|var/tmp)/\S+`
   → `["T1560.001","T1074.001"]`, weight 0.85
7. **Interactive shell spawn** — `(?i)(^|\s)(/bin/)?(bash|sh|zsh)\s+-i(\s|$)`
   → `["T1059.004"]`, weight 0.6
8. **Linux host discovery** — `(?i)^\s*(id|uname\s+-a|hostname|w|last|groups)\s*$`
   → `["T1082","T1033"]`, weight 0.5
9. **Exfil over alt protocol** —
   `(?i)\b(scp|rsync|sftp)\s+\S+\s+\S+@\S+:` → `["T1048"]`, weight 0.7
10. **IDS/IPS alert — rare external destination** —
    `(?i)(suricata|snort|zeek).*(outbound|beacon|rare external|c2|command and control)`
    → `["T1071.001","T1041"]`, weight 0.85
11. **IDS/IPS alert — umumiy** — `(?i)(suricata|snort)\s*\[?alert`
    → `["T1071.001"]`, weight 0.4, note: "IDS alert — kontekst kerak"
    (10-qoida ishlaganda dedup baribir yuqori confidence ni tanlaydi)

## Diqqat
- 8-qoida (`id`, `uname -a`) faqat **butun matn** shu buyruqdan iborat bo'lganda ishlasin
  (`^...$` anchor) — aks holda har qanday "id=" bor nginx qatoriga tushadi.
- Yangi qoidalar `noise.yaml` bilan to'qnashmasligi kerak: noise `drop` qoidalari
  detect natijasidan keyin ishlaydi, shuning uchun `sshd ... disconnected by user`
  kabi qatorlar baribir tushib ketadi — bu to'g'ri.
- `heuristics.yaml` dagi barcha ID lar `kb.validate()` dan `active` bo'lib o'tishi shart.

## Testlar
```
python bk.py logs analyze "C:\Users\USER\Downloads\AyuGram Desktop\elasticsearch_export.json" --json-out out3.json
```
Kutilgan:
- detectionli eventlar soni **11 → 33 atrofida**;
- `Totals:` da T1548.003, T1552.004, T1021.004, T1005, T1560.001, T1074.001, T1071.001 bo'lsin;
- `db-prod-02` endi "hujum belgisi yo'q" EMAS — exfiltration/collection tactikalari chiqsin;
- tactic coverage 7 dan **10-12** ga ko'tarilsin;
- shovqin qaytmasin: `suppressed_by_noise` ~195 qolsin, umumiy detectionli eventlar 60 dan oshmasin.
- Regressiya: `python bk.py logs analyze dist/data/samples/win_phishing.csv` → 20 high, 5 medium o'zgarmasin.
