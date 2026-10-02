# FEEDBACK — two correctness bugs in the log analyzer. Fix both. Work directly, no subagent. Do NOT execute command strings.

## BUG 1 — revoked technique ids are emitted (wrong submission!)
The 1102 "audit log cleared" event maps to **T1070.001**, which is REVOKED in ATT&CK v19 (replacement T1685.005). An analyst would submit a dead id.
FIX (general, future-proof): after all detection, pass every emitted technique id through the KB; if it is revoked or deprecated and has a replacement (revoked_by), REPLACE it with the active id (keep the evidence/confidence). Apply this to hits from eventmap.yaml AND heuristics AND correlations — everywhere. Do it once in a helper so no revoked id can ever reach the timeline, summary, coverage, chains, or HTML. Verify: after fix, T1070.001 no longer appears; T1685.005 (Clear Windows Event Logs) appears instead for the 1102 event. Also fix the id directly in eventmap.yaml to T1685.005, and at load-time warn on any eventmap id that is revoked/deprecated/unknown in the KB.

## BUG 2 — chain.tactics (and per-host tactics) are over-populated / global
The GW-CHECK chain has ZERO high/medium technique hits (it is just the benign checker doing GET /health), yet its `tactics` list shows 9 tactics (initial-access, credential-access, ...). Every host shows nearly all tactics, which is meaningless.
FIX: a chain's `tactics` must be derived ONLY from the high/medium technique hits of the events that belong to THAT chain (map each such technique -> its tactics via KB, union them). Low-confidence hits do NOT contribute. A benign chain (no high/med hits) must have tactics = [] (or "hujum belgisi yo'q"). Apply the same rule to the per-host tactics line in the terminal summary and to the Chains section in the HTML. Verify: GW-CHECK -> tactics empty; HR-PC01 -> initial-access, execution, credential-access, persistence, discovery, command-and-control (its real ones); DC01 -> credential-access (+ lateral/defense as per its 4625/4624/1102 events); BUX-PC05 -> lateral-movement, impact, defense, persistence, command-and-control.

## After
Run analyze on the sample + `python -m unittest discover -s tests`. Confirm both fixes. Add a test: no result technique id is revoked/deprecated in the KB (iterate timeline hits, assert kb.validate status == 'active'). Keep existing tests passing. Report results.
