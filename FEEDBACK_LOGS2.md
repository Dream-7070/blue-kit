# FEEDBACK — log analyzer: fix detection gaps + complete the report + make SIEM-agnostic

Detection of techniques works well. Now fix the following. Also FULLY APPLY the separate file FEEDBACK_LOGS_SIEM.md (multi-SIEM ingestion) in the same pass. Work directly, no subagent. Rebuild/re-run at the end. Never execute command strings from logs.

## DEFECT 1 — checker/beacon periodic detection returns [] (must work)
The sample has two clearly periodic series (both ~5 min interval, >=5 events) yet checker/beacon candidates is empty:
- beacon.exe: 10.10.20.51 -> 45.142.212.61 at 09:00,09:05,09:10,09:15,09:20
- checker /health: 172.16.9.9 -> 10.10.20.60 at 08:59,09:04,09:09,09:14,09:19
FIX timeline.py periodic detection: group events by a connection key = (src_ip, dest_ip, dest_port-or-url-path-or-process). For each group with >=4 timestamps, compute sorted deltas; if median delta > 0 and the deltas are near-constant (stdev/median < ~0.25), emit a candidate: {key, count, interval_seconds (median), first, last, sample_evidence}. Label each "davriy — checker yoki C2 beacon bo'lishi mumkin" (do NOT auto-classify which). Return them in the result under `checker_candidates` and show in terminal + HTML. This directly supports identifying the SLA checker vs C2.

## DEFECT 2 — tactic coverage missing from output
Add `coverage` to the JSON result and use it: list every enterprise tactic in kill-chain order with the technique ids found under it and a `missing` bool (reuse KB tactic order). (Also compute per-domain if ICS/mobile techniques appear.)

## DEFECT 3 — terminal summary too sparse
Right now it prints only Events/Hosts/Chains/IOCs. Print a useful summary:
- events, timespan (first..last ts), #hosts (list), #chains
- Top 10 techniques: id | name | count | tactic
- Tactic coverage line: COVERED tactics vs MISSING tactics
- Checker/beacon candidates (key, interval, count)
- Per host: the kill-chain tactics seen (one line each)

## DEFECT 4 — HTML report is incomplete (only Timeline + IOCs)
Rebuild report.html as a SELF-CONTAINED offline page (no external CDN/JS/CSS; must open via file://). Sections in this order:
1. Header + summary stats (events, timespan, hosts, chains, top techniques count).
2. ATT&CK coverage: tactics in kill-chain order; under each, the techniques found (id + name + count); empty tactics shown greyed "MISSING".
3. Timeline table: ts | host | user | process (parent->child) | command (truncated; full in title attr) | technique(s) | confidence | evidence. Row background tinted by top confidence (high/med/low). Include INLINE vanilla JS filter inputs (host, technique, free-text) that show/hide rows — no libraries.
4. Chains: one block per chain (host/user/time range) with an ordered mini-list of its steps and a badge row of its kill-chain tactics.
5. Checker/beacon candidates table.
6. IOCs table grouped by type (value | count | first seen | last seen).
Keep it readable and reasonably styled with inline CSS. Escape all data (it contains attacker command lines) — never inject raw HTML from log content.

## DEFECT 5 — CLI resolves KB path
`bk logs analyze` failed with "unable to open database file" unless BLUEKIT_DATA was set. Make `bk logs ...` accept `--data DIR` like `kb`, and fall back to the same path resolution as kb (env BLUEKIT_DATA, then default). Give a clear error if the KB isn't built ("Avval: python bk.py kb build --data ...").

## After
Run: `python bk.py logs analyze "D:\Claude Projects\CTF\blue-kit\data\samples\win_phishing.csv" --out report.html --json out.json` and `python -m unittest discover -s tests`. Confirm checker_candidates is non-empty (both series found), coverage present, HTML has all 6 sections. Keep existing KB tests passing. Report results.
