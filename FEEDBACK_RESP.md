# FEEDBACK — responder kit polish. Core works (triage flags, protected-list excludes checker). Fix these. Work directly, no subagent. Kit stays READ-ONLY / generate-text-only.

## DEFECT 1 — remediation blocks missing for key categories (currently "# REMOVE manually")
remediate.generate must produce full BACKUP->REMOVE->VERIFY->ROLLBACK blocks for ALL categories, not just tasks/users. Add real command blocks (Windows + Linux variants) for:
- **autoruns / Run keys**: BACKUP `reg export "HKCU\...\Run" backup.reg` ; REMOVE `reg delete "HKCU\...\Run" /v <name> /f` ; VERIFY `reg query ...` ; ROLLBACK `reg import backup.reg`. (Linux equivalent for ~/.bashrc, systemd unit, /etc/rc.local: back up file, remove line/unit, verify, restore.)
- **remote_access_tools (AnyDesk/TeamViewer/RMS/etc)**: BACKUP note the install path+service; REMOVE stop+disable service (`sc stop`/`sc config start=disabled` or `Stop-Service`/`Set-Service`), kill process, uninstall or move binary to C:\ir\quarantine; VERIFY service/process gone; ROLLBACK restart service. Prefer DISABLE+quarantine (safe variant) over hard delete unless --full.
- **hosts_file**: BACKUP copy hosts to backup; REMOVE the specific malicious line only (PowerShell: filter out that line and rewrite; Linux: `sed -i` for that exact line or filtered rewrite) — NEVER truncate the whole file; VERIFY line absent; ROLLBACK restore backup.
- **services (malicious)**: sc stop + sc delete (backup `sc qc` first) / systemctl stop+disable+mask; VERIFY; ROLLBACK.
- **cron**: back up `crontab -l`, remove the offending line, verify, restore.
- **ssh_authorized_keys**: back up the file, remove the specific key line, verify, restore.
- **wmi_subscriptions**: back up (Get-WmiObject dump), remove the __EventFilter/Consumer/Binding, verify, note no rollback needed.
- **defender disabled**: REMEDIATE = re-enable (`Set-MpPreference -DisableRealtimeMonitoring $false`) and remove attacker exclusions (`Remove-MpPreference -ExclusionPath ...`); VERIFY `Get-MpComputerStatus`.
Each block keeps the `# FINDING: <item> [<ids>] score=` header. Provide safe (disable/quarantine) and, with --full, destructive (delete) variants. NEVER emit a command for a protected item.

## DEFECT 2 — collectors must support remote/piped execution (target may not allow copying files)
- collect_linux.sh: when `-o -` OR no `-o`, write JSON to STDOUT only (so `ssh host 'bash -s' < collect_linux.sh > snap.json` works). Put inline human triage on STDERR (or suppress with -q) so it never corrupts the JSON on stdout.
- collect_windows.ps1: when `-Out -` OR omitted, emit JSON to stdout only; inline triage to the information/stderr stream. So `Invoke-Command -ComputerName t -FilePath collect_windows.ps1 > snap.json` and pasting into a remote PS session both work. Add a header comment documenting: `powershell -ExecutionPolicy Bypass -File collect_windows.ps1`, the Invoke-Command usage, and the ssh-pipe usage for linux.
- Both: keep them dependency-free and READ-ONLY.

## DEFECT 3 — triage terminal output should be a readable table, and protected flag bug
- `bk resp triage` (non-json) must print an aligned TABLE: Score | Conf | Category | Item | Techniques | Protected | Reasons (use the same print_table). Not Python dict repr.
- Bug: `protected` is sometimes `None` for users; it must always be a bool (True/False). Fix so protected-list matching applies to ALL categories (users, ips, ports, service names, paths).
- Show protected items at the bottom clearly marked "PROTECTED — teginmang" and never in `fix`.

## After
Re-run: `bk resp triage`, `bk resp fix --protected` on data/samples/resp/*, confirm AnyDesk/hosts/run_key now yield full blocks, checker_admin still absent from fix, triage prints a table. `python -m unittest discover -s tests` all pass (add a test: fix output for the AnyDesk finding contains BACKUP+REMOVE+VERIFY, and contains no protected item). Report results.
