# FEEDBACK — collectors are INCOMPLETE. Several schema categories are declared but never populated. This breaks the responder's core value (persistence detection). Fix both collectors. READ-ONLY only. Work directly, no subagent.

Verified on a real Windows machine: it has 15 Run-key values and RATs/WMI/startup data, but the snapshot had autoruns=0, startup_items=0, remote_access_tools=0, and tasks had empty `action`. These categories must actually be collected.

## collect_windows.ps1 — ADD the missing collection blocks (each wrapped in try/catch appending to errors, never throwing)
1. **autoruns (Run/RunOnce keys)** — enumerate values under ALL of:
   HKLM & HKCU `\Software\Microsoft\Windows\CurrentVersion\Run`, `...\RunOnce`, and the WOW6432Node variants under HKLM. For each value: `{location=<full key path>, name=<value name>, value=<value data>}`. (Use Get-Item then iterate `.Property`, Get-ItemProperty to read data.)
2. **startup_items** — files in the common startup `"$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"` and per-user `"$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup"`: `{location, name, path}`.
3. **tasks.action / trigger** — currently empty. Populate action from the task's Actions (Execute + Arguments joined) and trigger from Triggers (type). This is CRITICAL so we can see a task pointing to a Temp exe. Use `(Get-ScheduledTask).Actions` -> Execute + Arguments.
4. **wmi_subscriptions** — Get-WmiObject -Namespace root\subscription -Class __EventFilter (name, Query), CommandLineEventConsumer (name, CommandLineTemplate/ExecutablePath), __FilterToConsumerBinding. Emit `{name, query, consumer}`.
5. **remote_access_tools** — scan services (name/binary_path), running processes (Get-Process path/name), and Program Files dirs for names matching (case-insensitive): anydesk|teamviewer|rutserv|rfusclient|ammyy|rustdesk|screenconnect|connectwise|aeroadmin|radmin|litemanager|ngrok. Emit `{name, evidence=<where found>}`. Dedupe.
6. **listening_ports.process** — resolve the owning process NAME from the pid (Get-Process -Id). Currently empty.
7. **connections** — Get-NetTCPConnection -State Established: `{proto, laddr, lport, raddr, rport, pid, process}`.
8. **recent_modified** — files modified in the last 48h under `$env:windir\Temp`, `$env:TEMP`, `$env:AppData`, `$env:ProgramData` (bounded: skip huge trees, cap ~500 entries): `{path, mtime}`.
Keep `-Out -` stdout behavior and READ-ONLY. Re-verify: on a normal machine autoruns>0, tasks have non-empty action for at least some tasks.

## collect_linux.sh — verify/complete the SAME categories
Ensure these are actually populated (not empty stubs), same JSON shape: users (uid, shell, uid==0 flag), sudoers, services (enabled units), cron (per-user crontab + /etc/cron*), systemd timers, autoruns (rc.local, /etc/profile.d, ~/.bashrc, ~/.profile, ld.so.preload, systemd units in /etc/systemd/system), ssh_authorized_keys (root + each home), listening_ports (ss -tlnp with process), connections (ss -tnp established), hosts_file (non-default), suid_files (find / -perm -4000 -type f, with a timeout, capped), remote_access_tools (process/paths matching the same name list + anydesk/teamviewer for linux), recent_modified (/tmp /dev/shm /var/tmp /var/www last 48h). Every string properly JSON-escaped. READ-ONLY, never modify, never exit on a single failure.

## Sanity self-check inside each collector (optional but helpful)
Before output, if not -Quiet, print to STDERR a one-line count summary (users=N services=N tasks=N autoruns=N rats=N) so the operator sees it collected something.

## After
The reviewer will run collect_windows.ps1 on a real machine and assert autoruns>0, tasks[].action non-empty for some, remote_access_tools works when a RAT is present. Keep existing python tests passing. Do not change the JSON schema keys. Report what you added.
