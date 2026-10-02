# FEEDBACK — two small fixes. Work directly, no subagent. READ-ONLY kit.

## FIX 1 — the "no generic-KB-hit findings" gate must apply WITH OR WITHOUT baseline
With baseline, legit items (GoogleUpdateTaskMachine, SecurityHealth, Spooler) are correctly dropped. But WITHOUT `--baseline` they reappear as medium "KB match (Txxxx)". The gate must be unconditional.
Rule (both modes): create a finding ONLY IF at least one STRONG signal holds:
- `new` vs baseline (only when baseline provided), OR
- log_confirmed (matches a log artifact), OR
- strong known-bad: a RAT; a known malware/tool NAME (built-in list or a KB *heuristic-level* hit — NOT a plain FTS/bm25 match); a Temp/AppData/ProgramData/public or /tmp,/dev/shm suspicious path; Defender realtime OFF or an attacker Defender exclusion.
A plain kb.search FTS match alone (e.g. "KB match (T1574.001)" on GoogleUpdate, "KB match (T1685)" on Spooler/SecurityHealth) is NOT a strong signal and must NOT create a finding — in EITHER mode. Use KB only to LABEL findings that already qualified.
Required: without baseline, GoogleUpdateTaskMachine / SecurityHealth / Spooler must NOT appear; the log-confirmed items (AnyDesk, hosts, C2 connection, Updater task+autorun) still do; admin users still listed at medium "baseline yo'q — tekshiring".

## FIX 2 — round scores in output
Scores like 0.6000000000000001 appear. Round every displayed/returned score to 3 decimals (CLI table, HTML, JSON).

## After
Run both:
- `bk resp triage current_win.json --baseline baseline_win.json --from-logs logs_out.json`
- `bk resp triage current_win.json --from-logs logs_out.json`   (no baseline)
Confirm legit items absent in BOTH, scores rounded, C2 not protected. `python -m unittest discover -s tests` all pass. Report results.
