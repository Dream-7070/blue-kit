# SPEC: blue-kit RESPONDER KIT — baseline / triage / remediation-generator / SLA-guard

## Context & philosophy
Part of "blue-kit" offline DFIR toolkit. Helps a WEAK responder fix a compromised host FAST and SAFELY while automatic scoring rewards the first team to remediate and penalizes broken services (SLA). Fully OFFLINE, no AI, no network.
CORE SAFETY RULE: the kit NEVER modifies the target automatically. It only (1) COLLECTS state (read-only), (2) FLAGS suspicious items with ATT&CK mapping, (3) GENERATES ready remediation command blocks (backup -> remove -> verify -> rollback) for a human to review and run. A `protected-list` prevents ever suggesting removal of checker/admin/SSH access.

## Architecture (important)
- **Collectors** run ON the target (which may have NO Python): pure PowerShell (`collect_windows.ps1`) and pure bash (`collect_linux.sh`). They are READ-ONLY, output a JSON snapshot to stdout/file, and optionally print an inline human triage. Standalone, no dependencies.
- **Analyzer** runs on the analyst laptop (has Python + the KB): new CLI group `bk resp ...` consumes snapshot JSON, diffs vs baseline, maps to ATT&CK via bluekit.kb.query.KB, generates remediation, and runs SLA checks.

## Where to write (all under D:\Claude Projects\CTF\blue-kit-staging)
```
responder/collect_windows.ps1
responder/collect_linux.sh
responder/protected.example.yaml
responder/sla.example.yaml
bluekit/resp/__init__.py
bluekit/resp/schema.py        # snapshot dataclass/dict helpers + validation
bluekit/resp/triage.py        # diff + suspicious scoring + KB mapping
bluekit/resp/remediate.py     # remediation command-block generator (win+linux)
bluekit/resp/sla.py           # SLA guard checks
bluekit/resp/servicedoctor.py # "service is down" diagnosis
bluekit/resp/fraud.py         # RAT/hosts/1C/bank fraud indicators
bluekit/resp/report.py        # terminal + self-contained HTML triage report
tests/test_resp.py            # unittest, uses data/samples/resp/*
```
Sample snapshots for tests (reviewer will also add real ones): create tiny synthetic `data/samples/resp/baseline_win.json` and `data/samples/resp/current_win.json` where current has injected evil items (a scheduled task to a Temp exe, a new admin user, a Run key, AnyDesk, a hosts-file bank redirect). Do NOT overwrite files the reviewer created there.

## Snapshot JSON schema (BOTH collectors emit this exact shape)
```
{
  "meta": {"os":"windows|linux","hostname":..,"collected_at":ISO8601,"collector_version":".."},
  "users":            [{"name","enabled":bool,"is_admin":bool,"groups":[..],"last_set":?,"uid":?,"shell":?}],
  "services":         [{"name","display","state","start_mode","binary_path","run_as"}],
  "tasks":            [{"name","path","action","trigger","author","enabled"}],   // scheduled tasks / systemd timers
  "cron":             [{"user","line","file"}],                                   // linux
  "autoruns":         [{"location","name","value"}],                             // Run/RunOnce keys, startup folder, systemd units
  "wmi_subscriptions":[{"name","query","consumer"}],                             // windows
  "ssh_authorized_keys":[{"user","file","key_fingerprint_or_line"}],            // linux
  "listening_ports":  [{"proto","addr","port","pid","process"}],
  "connections":      [{"proto","laddr","lport","raddr","rport","pid","process"}],
  "hosts_file":       ["<non-default line>", ..],
  "suid_files":       ["/path", ..],                                             // linux
  "startup_items":    [{"location","name","path"}],
  "remote_access_tools":[{"name","evidence"}],                                    // AnyDesk/TeamViewer/RMS/Ammyy/RustDesk/ScreenConnect
  "defender":         {"realtime":bool,"exclusions":[..]},                        // windows
  "recent_modified":  [{"path","mtime"}],                                         // key dirs, last N hours
  "packages_modified":[..],                                                       // optional: rpm -Va/debsums mismatches
  "errors":           [".."]                                                      // collection errors (non-fatal)
}
```
Collectors must be robust: any single collection step failing appends to `errors` and continues. Never throw. Never write anything on the target except the snapshot file the user names.

## collect_windows.ps1
Params: `-Out <path>` (default .\snapshot_<host>_<ts>.json), `-Baseline` (same as default; snapshot IS the baseline when taken clean), `-Protected <yaml/txt>` (names/IPs to mark protected), `-Quiet` (no inline triage).
Collect (read-only): local users (Get-LocalUser) + group membership + is_admin (Administrators group), services (Get-CimInstance Win32_Service: name, state, startmode, pathname, startname), scheduled tasks (Get-ScheduledTask + actions/triggers/author), Run/RunOnce keys (HKLM+HKCU + Wow6432Node), startup folders, WMI event subscriptions (__EventFilter/CommandLineEventConsumer/__FilterToConsumerBinding), listening ports + owning process (Get-NetTCPListener + process), current connections, hosts file non-default lines, Defender status (Get-MpComputerStatus RealTimeProtectionEnabled) + exclusions (Get-MpPreference), remote-access tools (services/processes/paths matching AnyDesk|TeamViewer|rutserv|rfusclient|Ammyy|RustDesk|ScreenConnect), recently modified files in C:\Windows\Temp, %TEMP%, %APPDATA%, %ProgramData% within last 48h. Output valid JSON (ConvertTo-Json -Depth 6). If not admin, still run and note limited data in errors.
Inline triage (unless -Quiet): print a short colored list of the most suspicious items (see scoring below, replicated simply in PS) so the responder gets value even before copying the file to the laptop.

## collect_linux.sh
POSIX-ish bash. Params: `-o out`, `-p protected`, `-q`. Collect: users from /etc/passwd (uid, shell, uid==0 flagged), sudoers (/etc/sudoers, /etc/sudoers.d/*), services (systemctl list-units --type=service + list-unit-files enabled), systemd timers + cron (crontab -l for each user, /etc/cron*, /var/spool/cron/*), autoruns (/etc/rc.local, systemd units in /etc/systemd, ~/.bashrc ~/.profile /etc/profile.d, ld.so.preload), authorized_keys for each home + root, listening ports (ss -tlnp or netstat), connections (ss -tnp), hosts file non-default, SUID files (find / -perm -4000 -type f, bounded/timeout), remote-access tools, recently modified in /tmp /dev/shm /var/tmp and web roots (/var/www) last 48h, package integrity if debsums/rpm present (best-effort). Emit the same JSON shape (build JSON carefully; escape strings). Never modify anything. `set -o pipefail` but never exit on a single failure — wrap steps.

## bluekit/resp/triage.py
`analyze(kb, current, baseline=None, protected=None)` -> findings list + summary.
Per item across all categories compute a suspicion score (0..1) and reasons:
- NEW vs baseline (item absent in baseline) -> +0.4
- Known-bad / tool name (mimikatz, cobaltstrike, beacon, nc, ncat, socat, rat names, powershell -enc, /tmp path exe, comsvcs MiniDump...) via KB heuristics/search on the item's command/path -> +0.4 and attach the ATT&CK technique(s)
- Suspicious location (Windows: \Temp\, \AppData\, \ProgramData\, public; Linux: /tmp, /dev/shm, /var/tmp, world-writable) -> +0.2
- Recently modified (within window) -> +0.1
- UID 0 non-root user / hidden user / disabled-then-enabled -> +0.3
- Defender realtime OFF or suspicious exclusion path -> high, map T1685 (Disable or Modify Tools)
- authorized_keys entry not in baseline -> +0.4 map T1098.004
Each finding: {category, item(name/path), score, confidence(high>=0.6/med>=0.35/low), techniques:[{id,name}], reasons:[..], protected:bool}. If an item matches the protected-list (name/ip/port), set protected=true and DROP it from remediation (never suggest removing it) but still list it as "protected — teginmang".
Map every technique through KB and translate revoked->active replacement (reuse the same rule as the log analyzer). Sort findings by score desc.

## bluekit/resp/remediate.py
`generate(finding, os)` -> a command block string with 4 clearly-commented stages, for the finding's category and OS:
1. BACKUP/EVIDENCE (export the object: schtasks /query /xml, reg export, copy file to C:\ir\backup or /root/ir-backup, systemctl cat, crontab -l > backup)
2. REMOVE (schtasks /delete /f; sc delete; reg delete; Remove-LocalUser/net user /del; Unregister-ScheduledTask; wmic remove subscription; crontab edit; sed -i to remove authorized_keys line; rm the malware file; kill pid)
3. VERIFY (re-query; expect "not found"/absent)
4. ROLLBACK (re-import the backup) 
Rules: NEVER generate a command touching a protected item. For files, back up before delete. For users, prefer DISABLE first then delete. Include a one-line header: `# FINDING: <item> [<technique ids>]  score=<..>`. Add a top note reminding to snapshot evidence first and to keep checker/SSH access intact. Provide both a "safe" variant (disable/quarantine-move) and a "full" variant (delete) where reasonable.
`generate_all(findings, os)` -> ordered script text (most-suspicious first, protected items skipped, with a summary header).

## bluekit/resp/sla.py
`check(config)` where config (yaml) = list of services: `{name, type: port|http|process|service, target, expect?}`.
- port: TCP connect to host:port (localhost default) -> up/down
- http: GET url (stdlib urllib, short timeout) -> status, expect substring optional
- process: is a process by name running (needs a current snapshot or psutil-free /proc; on the analyst side accept a snapshot)
- service: service state == running (from snapshot)
Return per-service {name, ok, detail}. CLI prints a table and a single OK/DEGRADED verdict. This is meant to be run BEFORE and AFTER each remediation. NOTE: http/port checks do hit the network (localhost/target) — this is the ONLY networked part and only to the target the user chose; keep it opt-in and clearly the user's own target.

## bluekit/resp/servicedoctor.py
`diagnose(snapshot, service_name)` -> ordered probable causes with a fix suggestion each, using snapshot data: service missing/disabled (start_mode), binary_path missing or moved, run_as changed, a cron/task that kills it, its port taken by another pid, a recent config file change (recent_modified near its dir), dependency service down, package integrity mismatch. Output: list of {cause, evidence, suggested_fix_command}. For Day-2 "factory service stopped".

## bluekit/resp/fraud.py
`scan(snapshot)` -> fraud indicators for Day-1: remote_access_tools present (T1219), hosts_file entries redirecting bank/known domains (T1565.001), 1C/bank payment artifacts (paths/names containing 1c, kl_to_1c, to_kl, payment, bank-klient), clipboard-hijack/keylogger autoruns, new admin user + recent logon. Each with technique + suggested check.

## bk.py CLI additions (group `resp`)
- `bk resp triage <current.json> [--baseline b.json] [--protected p.yaml] [--out report.html] [--json]`
- `bk resp fix <current.json> [--baseline b.json] [--protected p.yaml] [--os windows|linux] [--full]`  -> prints remediation script to stdout (or --out file)
- `bk resp sla <sla.yaml>` -> run checks, table + verdict
- `bk resp doctor <current.json> <service_name>` -> diagnosis
- `bk resp fraud <current.json>` -> fraud indicators
All support `--data DIR` / BLUEKIT_DATA for KB. Human-readable default, `--json` where sensible. UTF-8 console.

## Quality & tests
- Never execute remediation or any collected command; generate text only. Collectors are read-only.
- Reuse KB for technique mapping + revoked translation; every emitted technique id must be active.
- tests/test_resp.py (unittest, skip if KB missing): using synthetic baseline_win.json/current_win.json — triage flags the injected evil task/user/runkey/AnyDesk/hosts as high; a protected item (e.g. the checker admin account listed in a protected list) is NOT in the fix output; remediate.generate produces a block containing backup+remove+verify+rollback for a scheduled-task finding; no emitted technique id is revoked; fraud.scan finds the RAT and hosts redirect; servicedoctor returns >=1 cause when a service is disabled. Keep existing tests passing.
- End: print files created + test results.
```
