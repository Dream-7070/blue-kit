# SPEC: blue-kit LOG ANALYZER — CSV/JSON logs -> ATT&CK -> timeline + HTML report

## Context
Part of "blue-kit" offline DFIR toolkit. Reuses the already-built KB (bluekit.kb.query.KB). Fully OFFLINE, NO AI/LLM, NO network. Python 3.10+, Windows+Linux. Deps: stdlib + PyYAML only (NO pandas — parse CSV with the csv module so it works everywhere). Never execute any command string from the logs — treat as text.

## Where to write (all under D:\Claude Projects\CTF\blue-kit-staging)
```
bluekit/logs/__init__.py
bluekit/logs/parse.py       # read csv/json, normalize fields
bluekit/logs/fieldmap.yaml  # field aliases (ECS/Winlogbeat/Sysmon/auditd -> canonical)
bluekit/logs/eventmap.yaml  # Windows/Sysmon/Linux event-id -> technique rules
bluekit/logs/detect.py      # per-event technique detection
bluekit/logs/timeline.py    # ordering + chain grouping + IOC extraction
bluekit/logs/report.py      # HTML report + json/csv export
tests/test_logs.py          # unittest, uses data/samples/*
```
Also create sample data: `D:\Claude Projects\CTF\blue-kit\data\samples\win_phishing.csv` already exists (created by reviewer) — DO NOT overwrite it; use it in tests.
New CLI subcommand group in bk.py: `bk logs ...`

## Canonical event fields (normalize every row to this dict)
`ts` (datetime, parsed), `ts_raw` (original string), `host`, `user`, `src_ip`, `dest_ip`, `event_id` (string, e.g. "4688","1"), `channel` (e.g. Security, Sysmon, System, PowerShell, auditd, nginx), `process` (image/exe name), `pid`, `ppid`, `parent_process`, `command_line`, `target` (target user/file/registry as available), `message` (full raw text/other fields joined), `raw` (dict of original row).

## 1. parse.py
- `load(path, mapping=None)` -> list[dict] of canonical events, sorted by ts (rows with unparseable ts kept, sorted last, flagged ts=None).
- Auto-detect format by extension: .csv (csv.DictReader), .json / .ndjson (one JSON object per line OR a top-level list), .log fallback = treat each line as message.
- Field mapping: load fieldmap.yaml = {canonical_field: [list of possible source column names, case-insensitive]}. For each row, fill canonical fields from the first matching source column. Unmapped columns go into `raw` and are also appended to `message`.
- Timestamp parsing: try ISO8601 (with/without Z, ms), "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %I:%M:%S %p", epoch seconds/ms. Keep tz-naive UTC.
- fieldmap.yaml must cover ECS (`@timestamp`, `host.name`, `user.name`, `process.command_line`, `process.name`, `process.parent.name`, `process.pid`, `event.code`, `winlog.channel`, `source.ip`, `destination.ip`, `winlog.event_data.TargetUserName`, `winlog.event_data.SubjectUserName`), classic Winlogbeat/Sysmon (`CommandLine`, `Image`, `ParentImage`, `ParentCommandLine`, `EventID`, `Computer`, `TargetUserName`, `IpAddress`), and common generic names (`timestamp`,`time`,`host`,`hostname`,`user`,`username`,`process`,`cmd`,`command`,`commandline`,`event_id`,`eventid`,`src_ip`,`dst_ip`,`message`,`msg`).

## 2. eventmap.yaml + detect.py
detect.py `detect_event(kb, ev)` -> list of hits, each: {technique, name, confidence('high'|'medium'|'low'), score(float), source('eventmap'|'heuristic'|'sigma-lite'|'fieldmap'), evidence(str)}.
Detection layers (combine, dedupe by technique keeping best):
1. **eventmap.yaml** — rules keyed by (channel/event_id) plus optional field regex. Each rule -> technique(s), base confidence. Cover the important IDs (verify every technique id exists+active in KB at load; warn otherwise):
   - Windows Security: 4688 (process create -> look at command_line via KB), 4624 (logon; type10=RDP T1021.001, type3=network), 4625 (failed logon -> T1110 if many), 4672 (special privs), 4720 (user created T1136.001), 4728/4732/4756 (added to admin group T1098), 4697/7045 (service install T1543.003 / T1569.002), 4698 (scheduled task T1053.005), 1102 (audit log cleared T1685.001? verify -> "Clear Windows Event Logs" family), 4768/4769 (kerberos; RC4 0x17 -> T1558.003), 4662 (possible DCSync T1003.006), 5140/5145 (share access), 4657 (registry).
   - Sysmon: 1 (process -> KB on command_line), 3 (network conn T1071?), 7 (image load), 8 (CreateRemoteThread T1055), 10 (lsass access T1003.001), 11 (file create), 12/13/14 (registry T1112 / T1547.001 if Run key), 22 (DNS), 19/20/21 (WMI subscription T1546.003).
   - System: 7045 (new service).
   - PowerShell: 4104 (scriptblock -> KB on message).
   - Linux auditd/auth: sshd accepted/failed (T1110/T1021.004), sudo, useradd (T1136.001), cron, execve (-> KB on command).
2. **KB command-line detection**: if command_line (or message for 4104) present, call kb.search(text) and take hits with confidence high/medium (skip low). source='heuristic'/'sigma-lite' based on kb evidence.
3. Multi-event correlation done in timeline (e.g. many 4625 then 4624 -> brute force success) — see below.

## 3. timeline.py
- `build(events, hits_by_index)` -> ordered timeline list. Each entry: index, ts, host, user, process/parent, command_line (truncated for display), techniques (list of hits), primary_technique, primary_confidence, channel, event_id.
- **Chains**: group events by host; within a host, link events into chains by (a) process lineage (ppid->pid) when available, else (b) same user within a sliding time window (default 10 min). Each chain: id, host, user, start, end, ordered event indices, set of tactics covered (via KB technique->tactics), techniques in kill-chain order.
- **Correlations** (add synthetic hits): >=5 failed logons (4625) for a user followed by a success (4624) within 10 min -> add T1110 (Brute Force) high on the success event with evidence "N failed then success". RC4 kerberos (4769 ticket enc 0x17) repeated -> T1558.003.
- **IOC extraction**: scan all events for IPs (non-private + private separately), domains, urls, md5/sha1/sha256, file paths in command_line/target, and new usernames created. Dedupe, count occurrences, first/last seen. Reuse bluekit.kb.ioc.classify.
- **Checker/beacon detection**: find (src_ip -> dest_ip:port or URL) connections that repeat at a near-constant interval (>=5 events, low variance). Return as candidates with the interval; label "periodic — checker yoki C2 beacon bo'lishi mumkin" (do NOT auto-classify). This supports the SLA-checker-identification goal.

## 4. report.py + CLI
`bk logs analyze <file> [--map fieldmap.yaml] [--out report.html] [--json out.json] [--from TS] [--to TS] [--host H]`
- Prints a concise terminal summary: #events, timespan, #hosts, top 10 techniques (id, name, count, tactic), #chains, extracted IOC counts, checker/beacon candidates, and a tactic-coverage line (which tactics seen / MISSING).
- Writes a SELF-CONTAINED offline HTML report (no external CDN/JS/CSS; inline everything; must render with file:// and offline). Sections:
  1. Header + summary stats.
  2. ATT&CK coverage: the tactics in kill-chain order, each with the techniques found under it; empty tactics greyed as "MISSING".
  3. Timeline table: ts | host | user | process (parent→child) | command (truncated, full on hover title) | technique(s) | confidence | evidence. Color rows by top confidence. Provide simple client-side filter boxes (plain vanilla JS inlined) for host/technique/text — keep it lightweight.
  4. Chains: each chain as a small ordered list with its kill-chain tactics badge row.
  5. IOCs: table by type with counts and first/last seen.
  6. Checker/beacon candidates.
- `--json` dumps the full structured result (events+hits+chains+iocs+coverage) for the report bot to consume later.
- Also support `bk logs detect "<single command line>"` -> just run detect on one synthetic event (thin wrapper over KB search) for quick use.

## 5. Quality & tests
- Robust to missing columns, empty cells, weird encodings (open files utf-8-sig, errors='replace').
- tests/test_logs.py (unittest, skip if KB or sample missing): load data/samples/win_phishing.csv, assert: parses >0 events; detection finds T1566.001 or T1204.002 somewhere OR at least finds T1053.005/T1003.001 depending on sample; timeline builds >=1 chain; IOC extraction finds the attacker IP present in the sample; tactic coverage marks credential-access or execution as covered. (Reviewer will confirm exact expected ids against the sample.)
- At end print files created and a one-line summary.
- Do not break existing KB code or tests.
