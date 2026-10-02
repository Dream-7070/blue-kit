# SPEC: LOG -> RESPONDER bridge. Feed log-analyzer findings into responder triage/fix so remediation is focused and evidence-backed.

## Goal
After `bk logs analyze ... --json-out logs.json`, the responder should CONSUME logs.json so it knows the exact attacker artifacts (files, task names, IPs, users, hosts entries, techniques). Snapshot findings that MATCH the logs get boosted and shown first with the log evidence; log artifacts with no snapshot match are surfaced as "check manually" so nothing is missed. Work directly, no subagent. Kit stays READ-ONLY / generate-text-only.

## Log JSON shape (from the log analyzer; be defensive if keys missing)
- `timeline`: [{index, ts, host, user, process, parent_process, command_line, command_line_full, techniques:[{technique,confidence,...}]}]
- `iocs`: [{type, value, count, first, last}]   // types: ip, win_path, unix_path, etc. (values may be whole command lines — parse them)
- `coverage`: {...}
- `checkers` (or `checker_candidates`): may be null; if present each has a src/dest and interval.

## 1. bluekit/resp/logbridge.py  (new)
`load_log_artifacts(logs_path_or_dict) -> dict` returning typed buckets extracted from BOTH `iocs` and by regex-parsing every timeline `command_line_full`/`command_line` and event fields:
- `ips`: set of IPv4 (from iocs type ip AND regex over commands). Split out `checker_ips` = IPs that appear in `checkers`/checker_candidates (these must be PROTECTED, not remediated).
- `files`: set of full file paths (regex `[A-Za-z]:\\[^\s",]+\.\w+` and `/[^ \t",]+`), plus their basenames in `filenames`.
- `task_names`: from `schtasks .* /tn <name>` and `New-ScheduledTask`/`-TaskName`.
- `run_values`: from `reg add ... /v <name>` under a Run key; also registry Run value names.
- `users`: from `net user <name> /add`, `New-LocalUser`, `useradd <name>`, and log event target usernames on user-creation events.
- `hosts_entries`: lines redirecting via hosts file (from `>> ...\etc\hosts` commands) — capture the "ip domain" payload.
- `services`: from `sc create <name>` / `New-Service`.
- `rat_names`: any of anydesk|teamviewer|rutserv|rfusclient|ammyy|rustdesk|screenconnect|radmin found in commands.
- `techniques`: set of technique ids seen at high/medium confidence in the timeline.
- `hosts_seen`, `users_seen`, time range (first/last ts) for evidence strings.
Robust: skip missing pieces, never throw. Return also a compact `evidence_index`: map from a lowercased artifact string -> a short evidence string like "HR-PC01 09:07 schtasks Updater".

## 2. triage.py — add correlation
`analyze(kb, current, baseline=None, protected=None, log_artifacts=None)`:
- If `log_artifacts` given:
  - Build the protected set UNION with `log_artifacts['checker_ips']` (never remediate the checker) — mark such items protected with reason "checker IP (loglardan)".
  - For each finding, test whether it MATCHES any log artifact (normalized, case-insensitive, substring where sensible):
    * task finding name/action in task_names or its action path/basename in files/filenames
    * autorun/run_value name in run_values OR its value path/basename in files/filenames
    * user finding name in users
    * service finding name/binary in services/files
    * remote_access_tools name in rat_names
    * hosts_file finding matches a hosts_entries payload
    * a listening_ports/connections finding whose remote/why relates to an IP in `ips`
    * any finding whose technique intersects `techniques`
  - On match: `log_confirmed=True`, add +0.4 to score (cap 1.0), bump confidence to at least "high" when a strong artifact (file/task/user/ip) matches, and append reason `"log korrelyatsiyasi: <artifact> (<evidence string>)"`.
- Sort findings: log_confirmed first (desc score), then the rest.
- Return also `unmatched_log_artifacts`: artifacts present in logs but with NO matching snapshot finding (e.g. a file the logs saw that's already gone, a technique with no persistence artifact), each with its evidence — so the operator checks them manually. Exclude checker IPs from this list.

## 3. CLI (bk.py)
- `bk resp triage <snapshot> [--baseline b] [--protected p] [--from-logs logs.json] [--out report.html]`
- `bk resp fix <snapshot> [...] [--from-logs logs.json]`  -> fix prioritizes log_confirmed findings first; still never emits protected/checker items.
- When `--from-logs` used, the terminal/HTML triage must clearly mark log-confirmed findings (e.g. a "✔ LOG" column or tag) and print an "Loglarda bor, snapshotда topilmadi — qo'lda tekshiring" section listing `unmatched_log_artifacts`.

## 4. Web UI (bluekit/web)
- Responder tab: add an optional "Log JSON path" input; pass it to /api/resp/triage and /api/resp/fix as `from_logs`. Server loads it via logbridge. Show the ✔LOG tag and the unmatched-artifacts section. Also show a note when checker IPs were auto-protected.

## 5. Tests (extend tests/test_resp.py)
Create a tiny logs.json (or reuse one generated from the sample) whose artifacts include the evil task name / a file path / a new user / the C2 IP / a checker IP that appear in current_win.json. Assert:
- With `--from-logs`, the matching snapshot findings get `log_confirmed=True` and rank first.
- A checker IP present in the logs' `checkers` is added to protected and NOT present in `fix` output.
- `unmatched_log_artifacts` is a list (may be non-empty) and never includes checker IPs.
- No emitted technique id is revoked. Keep all existing tests passing.

## After
Run: `bk logs analyze <sample> --json-out logs.json` then `bk resp triage current_win.json --baseline baseline_win.json --from-logs logs.json` and `bk resp fix ... --from-logs logs.json`. Show that evil_task/AnyDesk/hosts get ✔LOG and rank first, checker protected. Run unittest. Report results.
