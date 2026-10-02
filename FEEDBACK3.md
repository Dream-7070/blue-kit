# FEEDBACK ROUND 3 — scoring & honesty fixes in query.py + missing tests. Then rebuild+retest.

Search now has good recall (17/18 attacker commands map correctly). Remaining issues are about SCORING QUALITY and HONEST CONFIDENCE. Fix in bluekit/kb/query.py (and tests). Work directly, no subagent. Do NOT execute command strings from data.

## DEFECT A — curated heuristic hits must outrank incidental FTS noise
A curated heuristic is high-confidence; a bm25 FTS match on generic words is not. Right now a heuristic hit (e.g. hosts-file => T1565.001, weight 0.8) can rank BELOW incidental FTS matches (e.g. T1685, T1112) that happened to share generic tokens.
FIX search() scoring so a technique that has a HEURISTIC hit is boosted clearly above techniques that only have FTS matches. Concretely: give heuristic contribution a large base (e.g. heuristic_score = 3.0 * rule_weight) added to any FTS component, and compute the final ranking on this combined raw score BEFORE normalization. A curated heuristic (weight>=0.8) should essentially always land in the top results for its pattern.
Verify: search("echo 1.2.3.4 bank.uz >> C:\\Windows\\System32\\drivers\\etc\\hosts") returns T1565.001 in the TOP 1-2.

## DEFECT B — honest confidence (do not show 1.00 for weak/benign input)
Currently `score` is normalized so the top result is always 1.0, even for benign input. Example: search("Get-MpPreference") returns T1190 at score 1.00 — misleading (that is a benign defender command; T1190 is just FTS noise).
FIX: keep the normalized relative `score` (0..1), but ALSO add two honest fields to each result:
- `raw` : the pre-normalization raw score (float, rounded 3).
- `confidence` : "high" if a heuristic matched this technique; else "medium" if raw bm25 is above a sane threshold; else "low".
And add to the search() RESULT payload (or as an attribute the CLI can read) an overall note: if NO heuristic matched AND the top raw score is below threshold, the CLI should print a line like "⚠ past ishonch — bu buyruq aniq bir texnikaga kuchli mos kelmadi" (Uzbek). Pick the bm25 threshold empirically so that clearly-benign inputs ("Get-MpPreference", "ipconfig /all") come out low confidence while real attacker commands come out medium/high.

## DEFECT C — secretsdump -just-dc should rank DCSync higher
search("secretsdump.py -just-dc domain/user@dc") currently ranks T1087.002/T1098 above T1003.006. "-just-dc" / "just-dc-ntlm" is DCSync. Add/strengthen a heuristic: secretsdump with "-just-dc" or "drsuapi" or "DCSync" => T1003.006 (weight 1.0) so T1003.006 ranks in the top 2. Plain "secretsdump" (SAM/LSA) can stay T1003.002/T1003.004.

## DEFECT D — add the tests you skipped in tests/test_kb.py (keep all existing passing)
- search_idx row count > 5000 (regression guard; current build ~7261).
- search "rundll32 comsvcs.dll MiniDump lsass" top-3 contains T1003.001
- search "secretsdump -just-dc" top-2 contains T1003.006
- search "nltest /dclist" top-3 contains T1018
- search "echo x >> C:\\Windows\\System32\\drivers\\etc\\hosts" top-2 contains T1565.001
- validate("T0803") -> status "revoked" and replacement truthy
- a benign-input honesty check: search("Get-MpPreference") -> its top result has confidence != "high" (i.e. no false high-confidence)

## IMPORTANT — do NOT "correct" ids from memory
ATT&CK v19 renumbered many ids. Confirm every id against the built KB (kb.validate). Known examples that are CORRECT in v19: "Disable or Modify Tools" = T1685 (old T1562.001 is REVOKED); "Clear Windows Event Logs" = T1685.005 (old T1070.001 REVOKED). Do not change these back.

## After fixing
Rebuild: `python bk.py kb build --data "D:\Claude Projects\CTF\blue-kit\data"`, then `python -m unittest discover -s tests -v` (BLUEKIT_DATA set). All tests pass. Report test count and results.
