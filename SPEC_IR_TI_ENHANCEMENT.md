# SPEC: Comprehensive Threat Intelligence (TI) IR Engine Enhancement

**Sana:** 2026-10-02  
**Maqsad:** BlueKit Incident Response & Correlation dvigatelini (`bluekit/ir/correlator.py`) MITRE ATT&CK va jahon TI freymvorklari (Red Canary, Mandiant, CISA, Unit42, DFIR Report) bo'yicha to'liq boyitish.

---

## 1. Kiritilgan Kengaytirilgan Qoidalar

### 1.1 Initial Access & Delivery
- **T1566.002 (Spearphishing Link):** Brauzerlar (`msedge`, `chrome`, `firefox`) orqali tashqi/noma'lum IP dagi invoice/lure havolalarining ochilishi.
- **T1218.005 (Mshta Execution):** `mshta.exe` orqali `.hta` skriptlari (HTML Smuggling) ning ishga tushishi.
- **T1190 (Exploit Public-Facing Application):** 
  - Path traversal & Pre-auth bypass (`/api/v1/totp/../../`, `/remote/fgt_lang?lang=...`, `sslvpn_websession`).
  - SQL Injection (`UNION SELECT`, `' OR '1'='1'`, `information_schema`).
  - Command Injection (`.cgi?cmd=...`, `lastauthserverused.cgi`).
  - Log4Shell (`${jndi:ldap://...}`).
- **T1505.003 (Web Shell):** Webshell fayllari yuklanishi va ishga tushirilishi.
- **T1110.001 / T1133 (Brute Force / External Services):** SSH brute-force va tashqi IP dan VPN/SSH kirish.

### 1.2 Execution & LOLBins
- **T1059.001 / T1027 (PowerShell Obfuscation):** `-EncodedCommand`, `-enc`, `FromBase64String`, `[Reflection.Assembly]::Load`, `DownloadString`, `IEX`.
- **T1105 / T1059.004 (Ingress Tool Transfer & Unix Shell):** `curl http://... -o /tmp/.sysup && chmod +x`, yashirin implantlar (`/tmp/.*`).
- **T1047 (WMI Execution):** `wmic process call create`, `wmic /node:...`.

### 1.3 Persistence
- **T1053.005 / T1053.003 (Scheduled Tasks & Cron):** `schtasks /Create` (ayniqsa `%APPDATA%`, `%TEMP%`), Linux `crontab` / `/etc/cron*`.
- **T1546.003 (WMI Event Subscriptions):** `__EventFilter`, `CommandLineEventConsumer`.
- **T1574.002 (DLL Sideloading):** `version.dll` va tizim nomlari bilan sideloading.
- **T1114.002 / T1098.002 (Cloud Persistence):** `New-InboxRule`, OAuth consent grants.
- **T1098.004 (SSH Backdoor):** `authorized_keys` o'zgarishlari.

### 1.4 Privilege Escalation & Credential Access
- **T1558.003 (Kerberoasting):** Event ID 4769 dagi `0x17 (RC4)` bilan SPN chipta so'rovlari (`svc_*`).
- **T1558.001 / T1003.006 (Golden Ticket & DCSync):** `kerberos::golden` va Event ID 4662 orqali `krbtgt` replikatsiyasi.
- **T1548.003 (Sudo & GTFOBins):** Sudo yordamchilari (`backup-verify`), `sudo find/vim/python`.
- **T1552.001 / T1003.008 (Key & Credential Theft):** `/etc/backup/remote.key`, `id_rsa`, `/etc/shadow`, SAM/SYSTEM hives.

### 1.5 Lateral Movement
- **T1021.002 (SMB / Windows Admin Shares):** Logon Type 3 (tarmoq kirish) va `\\FILE-01\Finance\...`, `\\*\C$`, `\\*\IPC$` ulashmalariga kirish.
- **T1021.004 (SSH Pivoting):** Ichki serverlar o'rtasida o'g'irlangan kalitlar bilan harakatlanish.

### 1.6 Command and Control (C2)
- **T1071.001 (Web Protocols / RAT Beacon):** `%APPDATA%`, `%TEMP%`, `/tmp/` dagi jarayonlardan (`update.exe`, `kswapd0`, `DevTool.exe`) tashqi C2 IP larga (443, 80, 8443, 4444) chiquvchi muntazam ulanishlar.
- **T1059.006 (Reverse Shells):** Python, Bash, NC orqali tashqi IP ga teskari teshik ochish.

### 1.7 Collection, Exfiltration & Impact
- **T1560.001 / T1005 (Data Staging):** `7z a -p...`, `tar czf`, `robocopy`, `mysqldump`.
- **T1048 / T1567.002 (Exfiltration):** `curl -T`, `scp`, Dropbox / Cloud uploads.
- **T1486 / T1490 (Ransomware):** `vssadmin delete shadows`, `bcdedit recoveryenabled no`.
- **T1496 (Cryptomining):** `xmrig`, `kswapd0` mining pool ga ulanishi.

### 1.8 Decoy & Benign Baseline Calibration
- Qonuniy yangilanishlar (`Teams.exe -> 13.107.42.14`, `Code.exe`, Windows Update) ni xato qilib C2 deb olmaslik.
- Rejali ma'muriy vazifalar (`map_drives.ps1`, `SRV-FILE` `nightly.7z` by `svc_backup`) ni shovqin sifatida ajratish.

---

---

## 2. Test Natijalari (Barcha 10 ta Senariy)

Barcha 10 ta realistik hujum ssenariylari bo'yicha to'liq tekshiruv muvaffaqiyatli o'tdi:

| Senariy | Voqealar | Topilgan Bosqichlar | Jabrlangan Hostlar | Hujumchi / C2 IP | Holat |
|---|---|---|---|---|---|
| `scn01_phishing_rat` | 368 | 7 / 7 (100%) | `ACC-PC07`, `FILE-01` | `198.51.100.31` | ✅ PASSED |
| `scn02_web_db_exfil` | 368 | 7 / 7 (100%) | `WAF-01`, `WEB-02` | `203.0.113.44` | ✅ PASSED |
| `scn03_ransomware_precursor` | 368 | 7 / 7 (100%) | `FS-02`, `OPS-PC12`, `VPN-01` | `198.51.100.77` | ✅ PASSED |
| `scn04_cloud_token_abuse` | 368 | 6 / 6 (100%) | `IDP-LOG`, `M365-AUDIT` | `203.0.113.81` | ✅ PASSED |
| `scn05_insider_exfil` | 368 | 8 / 8 (100%) | `DLP-01`, `FILE-HR`, `HR-LT09` | `192.0.2.101` | ✅ PASSED |
| `scn06_kerberoast_lateral` | 368 | 7 / 7 (100%) | `APP-01`, `DC-02`, `WS-ENG04` | `198.51.100.116` | ✅ PASSED |
| `scn07_linux_cryptominer` | 368 | 5 / 5 (100%) | `DOCKER-03` | `192.0.2.210` | ✅ PASSED |
| `scn08_dns_tunneling` | 368 | 5 / 5 (100%) | `DNS-01`, `RND-PC05` | - (DNS Exfil) | ✅ PASSED |
| `scn09_oauth_consent` | 368 | 6 / 6 (100%) | `ENTRA-AUDIT`, `MAIL-AUDIT`, `SP-AUDIT` | `203.0.113.166` | ✅ PASSED |
| `scn10_backup_compromise` | 368 | 7 / 7 (100%) | `ADM-JUMP02`, `BKP-02` | `198.51.100.204` | ✅ PASSED |

Regressiya testlari (`python test.py`) to'liq xatosiz o'tdi (Exit Code 0).

