# FEEDBACK — triage.py is a stub ("Simple logic for now"). Implement real baseline-diff + full-category scoring + better bridge matching. This is the core of the responder. Work directly, no subagent. Kit stays READ-ONLY. Must still work when kb is None (skip KB search, keep baseline/location/known-bad logic).

## BUG 1 (critical) — baseline diff is not implemented
`baseline` param is ignored; every admin is flagged "New admin" (Administrator and checker_admin, which are in baseline, get flagged). Implement real diff:
- Build baseline index per category: user names; tasks by (name, action); autoruns by (name, value); services by name; rat names; hosts lines; ssh authorized_keys lines; listening ports by (port, process); cron lines; wmi subscriptions by name.
- An item is `new` only if absent from the baseline index. `new` adds +0.4 to score and reason "baseline'da yo'q (yangi)".
- An item PRESENT in baseline gets NO "new" bonus and is NOT flagged merely for existing (e.g. baseline admins are not flagged). It is only flagged if independently known-bad (RAT, malware name, Temp path, KB high hit).
- If baseline is None: do NOT invent "new". Flag by independent suspicion only. For admin users with no baseline, list them at MEDIUM confidence with reason "admin akkaunt (baseline yo'q — tekshiring)" so they can still be reviewed/protected (do not mark high, do not call them "new").

## BUG 2 — score by evidence, map techniques via KB (not hardcoded), across ALL categories
Replace the hardcoded per-category technique ids with real scoring. For each item build a suspicion score (0..1, cap 1) from independent signals + the baseline `new` bonus:
- known-bad / tool name or command: run kb.search on the item's command/path/value (task.action, autorun.value, service.binary_path, connection process, etc.) when kb is not None; if top hit confidence high/med, +0.4 and attach that technique (translate revoked->active). When kb is None, use a small built-in known-bad name list (beacon, mimikatz, cobalt, nc, ncat, psexec, comsvcs, procdump, rundll32 ...temp..., .ps1 in temp) for +0.3.
- suspicious location +0.2: Windows \Temp\, \AppData\, \ProgramData\, \Users\Public\; Linux /tmp,/dev/shm,/var/tmp, world-writable.
- recently modified (if recent_modified lists the path) +0.1.
- confidence: high>=0.6, med>=0.35, else low.
Triage these categories (each producing findings): tasks (use `action`), users (baseline diff + admin), autoruns (use `value`), services (new + binary KB), remote_access_tools (T1219), hosts_file (T1565.001), wmi_subscriptions (T1546.003), cron (T1053.003), ssh_authorized_keys (T1098.004 when not in baseline), startup_items, defender (realtime OFF -> T1685 high; attacker exclusion path -> T1685), and **connections/listening_ports** (see BUG 3).
Do NOT dedupe across categories: a task named "Updater" and an autorun named "Updater" are TWO separate findings — keep both.

## BUG 3 — connections/listening_ports are never triaged (C2 missed)
Add findings for network state:
- A `connections` entry whose remote IP (raddr) is public (not private/loopback) -> finding category "connections", item "<raddr>:<rport> (<process>)", technique T1071.001 (or T1571), medium; if the process/basename is known-bad, high.
- If a connection/listener remote or process matches a log IOC IP or file -> log_confirmed (see BUG 4). The sample's beacon.exe -> 45.142.212.61 must become a high, log-confirmed finding.

## BUG 4 — bridge matching: add file-path and IP matching
Extend the correlation (the `if log_artifacts:` block) beyond task/user/runvalue/rat/hosts:
- For tasks/autoruns/services: also match if the item's ACTION/VALUE/BINARY path or its basename is in log_artifacts['files'] or ['filenames'].
- For connections/listening_ports: match if the remote IP is in log_artifacts['ips'] (but NOT checker_ips), or the process basename in ['filenames'].
- Technique intersection: if a finding's technique id is in log_artifacts['techniques'], add a weaker reason "log: shu texnika kuzatilgan" (do not over-boost).
On match: log_confirmed=True, +0.4 (cap 1), confidence high, reason "log korrelyatsiyasi: <artifact> (<evidence>)".

## BUG 5 — unmatched_log_artifacts is noisy
Currently it lists junk like "/n", "health", "t1566.001". Only include MEANINGFUL, TYPED artifacts:
- real file paths (has a drive or leading / AND a file extension) or basenames of such;
- public IPs (exclude private/loopback AND checker_ips);
- task_names, service names, created users, hosts payloads (ip+domain), rat_names.
Exclude: command flags/switches (start with / or - or shorter than 4 chars), technique-id strings (regex ^T\d{4}), pure single words like "health"/"n", and anything already matched. Dedupe. Each entry {artifact, type, evidence}.

## BUG 6 (in the LOG ANALYZER, not resp) — populate `checkers` in JSON output
`bk logs analyze --json-out` currently writes `checkers: null`, so the bridge can't auto-protect checker IPs. Make the analyzer include the checker/beacon candidates it already computes for the terminal summary in the JSON under `checkers` (list of {src, dst, key, interval_seconds, count, first, last}). Then load_log_artifacts must read them into checker_ips (the dst or src that is the periodic pair — include both IPs of each checker candidate as checker_ips candidates, but prefer the one that looks like the checker source).

## After
Rebuild not needed (no KB change). Run:
`bk logs analyze <sample> --json-out logs.json` then
`bk resp triage current_win.json --baseline baseline_win.json --from-logs logs.json`
Expect: Administrator & checker_admin NOT flagged as new (only `admin` is new); the Updater TASK and Updater AUTORUN both appear (2 findings) and both ✔LOG; the beacon.exe->45.142.212.61 connection is a high ✔LOG finding; hosts & AnyDesk ✔LOG; unmatched list contains only real artifacts (no "/n","health","t1566.001"); checker IPs (172.16.9.9) auto-protected and NOT in unmatched. `python -m unittest discover -s tests` all pass (update test_resp expectations if needed, but keep coverage: baseline diff works, protected excluded from fix, revoked-free). Report results.
