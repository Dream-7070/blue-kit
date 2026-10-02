# FEEDBACK — report generator: 3 fixes. Work directly, no subagent. NO AI. STDLIB core.

## BUG 1 (critical) — the ATT&CK techniques table is EMPTY (0 techniques)
The report's MAIN deliverable is the ATT&CK techniques table (the answers), but it shows "0 ATT&CK texnikasi" and no T-ids appear, even though logs.json has 33 events with techniques.
Cause: model.py isn't reading the technique ids. In the log analyzer JSON, each timeline event has `techniques: [{"technique": "T1566.001", "name": ..., "confidence": ..., "tactic"?...}]` — the id key is **"technique"** (not "id"). Also resp triage findings use `techniques: [{"id": "..."}]`.
FIX model.build:
- Collect DISTINCT techniques from logs.timeline[].techniques[] (read the `technique` key; skip low-confidence if you want, but include high+medium) AND from resp findings[].techniques[] (read `id`).
- For each distinct id: look it up in KB for name + tactic (translate revoked->active; drop deprecated). Build rows {id, name, tactic, count, evidence-sample, confidence}. Sort by kill-chain tactic order.
- exec_summary technique count must reflect this distinct count (was 0). 
Required: the sample report shows a populated ATT&CK table incl. T1566.001, T1059.001, T1105, T1003.001, T1053.005, T1547.001, T1110, T1565.001, T1219, T1685.005, etc., and exec_summary count > 0.

## BUG 2 — `resp triage` has no --json (so `bk report --resp` can't get remediation)
Add a `--json` flag to `bk resp triage` that prints the findings + summary (including unmatched_log_artifacts) as JSON to stdout, same shape the web API returns. Then `bk resp triage current.json --from-logs logs.json --json > triage.json` produces a file `bk report --resp triage.json` can read. Verify the full pipeline works and remediation rows appear in the report.

## BUG 3 — report must not block when stdin is not a TTY
`bk report --logs ...` without --answers raised EOFError (it prompted for Title with no TTY). FIX: only prompt interactively when stdin is a TTY AND (--ask given or required meta missing). When NOT a TTY: use answers.yaml if given, else sensible defaults (title "Hodisa hisoboti"/"Incident Report" per lang, date=today, org/team/analyst blank) and continue without blocking. Never raise EOFError.

## After
Run:
`bk logs analyze <sample> --json-out logs.json`
`bk resp triage current_win.json --from-logs logs.json --json > triage.json`
`bk report --logs logs.json --resp triage.json --answers answers.yaml --lang uz --out r_uz.html --md r_uz.md`
`bk report --logs logs.json --lang en --out r_en.html`   (no answers, non-TTY: must NOT block)
Confirm: techniques table populated (count>0, no revoked ids), remediation rows present, both uz and en render, no EOFError. `python -m unittest discover -s tests` all pass (add a test: model.build from the sample logs yields >=8 distinct techniques and no revoked id). Report results.
