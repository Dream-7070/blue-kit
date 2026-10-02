# Отчёт об инциденте CASE-20261002-01

### Паспорт
- **Название:** Initial Access → Execution → Persistence → Lateral Movement → Command and Control (2 ta host)
- **Статус:** confirmed
- **Severity:** HIGH
- **Общая уверенность:** 90%
- **Хосты:** `ACC-PC07`, `FILE-01`
- **Учётные записи:** `corp\a.karimova`
- **Период событий:** 2026-10-05 04:00:00 UTC (Toshkent 09:00:00) – 2026-10-05 06:00:06 UTC (Toshkent 11:00:06)
- **Источник:** `network_connections.csv, security_auth.csv, sysmon_process.csv`
- **Покрытие:** 368 событий; ошибок парсинга — 0, обнаружено звеньев цепи атаки — 7

---

### Резюме
🔴 **ПОДТВЕРЖДЕНО (HIGH):** Выявлена подозрительная активность на 2 хостах. Внешний адрес: **198.51.100[.]31**. Зафиксированные фазы: Initial Access, Execution, Command and Control, Persistence, Lateral Movement. MITRE ATT&CK: T1566.002, T1218.005, T1059.001, T1071.001, T1053.005, T1021.002. Затронутые хосты: `ACC-PC07`, `FILE-01`.

> Данное резюме основано только на проанализированных логах. Неохваченные фазы следует исследовать отдельно.

---

### Цепочка атаки (время как в логах)
**1. [2026-10-05 04:00:00 UTC (Toshkent 09:00:00)]** — 🟢 `[ACC-PC07]` **Initial Access:** msedge.exe hxxps://billing-check.example/invoice `[T1566.002]`
**2. [2026-10-05 04:20:01 UTC (Toshkent 09:20:01)]** — 🟢 `[ACC-PC07]` **Execution:** mshta.exe C:\Users\Public\invoice_1048.hta `[T1218.005]`
**3. [2026-10-05 04:40:02 UTC (Toshkent 09:40:02)]** — 🟢 `[ACC-PC07]` **Execution:** powershell.exe -NoProfile -EncodedCommand [REDACTED] `[T1059.001]`
**4. [2026-10-05 05:00:03 UTC (Toshkent 10:00:03)]** — 🟢 `[ACC-PC07]` **Command and Control:** RAT beacon over 443 `[T1071.001]`
**5. [2026-10-05 05:20:04 UTC (Toshkent 10:20:04)]** — 🟢 `[ACC-PC07]` **Persistence:** schtasks /Create /TN OneDriveHealth /TR %APPDATA%\update.exe `[T1053.005]`
**6. [2026-10-05 05:40:05 UTC (Toshkent 10:40:05)]** — 🟢 `[FILE-01]` **Lateral Movement:** logon type 3 from ACC-PC07 `[T1021.002]`
**7. [2026-10-05 06:00:06 UTC (Toshkent 11:00:06)]** — 🟢 `[FILE-01]` **Lateral Movement:** share access \FILE-01\Finance\payroll_2026.xlsx `[T1021.002]`

---

### MITRE ATT&CK Mapping
- **T1566.002 — Spearphishing Link** — 🟢 ПОДТВЕРЖДЕНО: msedge.exe hxxps://billing-check.example/invoice
- **T1218.005 — Mshta** — 🟢 ПОДТВЕРЖДЕНО: mshta.exe C:\Users\Public\invoice_1048.hta
- **T1059.001 — PowerShell** — 🟢 ПОДТВЕРЖДЕНО: powershell.exe -NoProfile -EncodedCommand [REDACTED]
- **T1071.001 — Web Protocols** — 🟢 ПОДТВЕРЖДЕНО: RAT beacon over 443
- **T1053.005 — Scheduled Task** — 🟢 ПОДТВЕРЖДЕНО: schtasks /Create /TN OneDriveHealth /TR %APPDATA%\update.exe
- **T1021.002 — SMB/Windows Admin Shares** — 🟢 ПОДТВЕРЖДЕНО: logon type 3 from ACC-PC07

---

### IOC и артефакты
- **`198.51.100[.]31`** `[IPv4]` — Attacker / C2: Tashqi manzil — hujumchi/C2 sifatida aniqlangan (dalil: zanjir bosqichlari)
- **`198.51.100.31`** `[dst_ip]` — Initial Access: Observed in T1566.002 (ACC-PC07)
- **`msedge.exe`** `[process]` — Initial Access: Observed in T1566.002 (ACC-PC07)
- **`mshta.exe`** `[process]` — Execution: Observed in T1218.005 (ACC-PC07)
- **`update.exe`** `[process]` — Command and Control: Observed in T1071.001 (ACC-PC07)
- **`FILE-01`** `[host]` — Lateral Movement: Observed in T1021.002 (FILE-01)
- **`10.50.1.27`** `[src_ip]` — Lateral Movement: Observed in T1021.002 (FILE-01)
- **`corp\a.karimova`** `[Account]` — Compromised Account: User account leveraged during attack

---

### Недостающие улики
- Memory (RAM) snapshot of ACC-PC07.
- PCAP / firewall logs for traffic to 198.51.100.31.

---

### Рекомендации
#### Сдерживание (Containment)
- Isolate affected hosts from the network: ACC-PC07, FILE-01.
- Block attacker / C2 IPs on perimeter firewalls: 198.51.100.31.

#### Устранение (Eradication)
- —

#### Восстановление (Recovery)
- Reset credentials of accounts: corp\a.karimova.
- Monitor the listed IOCs for recurrence after recovery.

---

### QA выводов
- Initial Access — **SUPPORTED** (Spearphishing Link)
- Execution — **SUPPORTED** (Mshta, PowerShell)
- Command and Control — **SUPPORTED** (Web Protocols)
- Persistence — **SUPPORTED** (Scheduled Task)
- Lateral Movement — **SUPPORTED** (SMB/Windows Admin Shares)
