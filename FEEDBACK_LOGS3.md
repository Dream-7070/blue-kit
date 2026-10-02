# FEEDBACK — log analyzer CONFIDENCE noise. The raw-text safety net is drowning the signal.

Detection recall is good and SIEM ingestion + HTML report are done. But the summary is dominated by NOISE. On the sample: 211 "medium" hits vs 21 "high". The Top-10 shows T1685(28), T1190(16), T1112(20) — these are incidental matches, not the real attack. The true findings (T1003.001, T1053.005, T1110, T1566.001, T1565.001) are buried, and T1110 brute-force dropped to 0 high/medium. Fix the confidence model. Work directly, no subagent. Do NOT execute command strings.

## Root cause
The raw-text/blob fallback (kb.search over the whole concatenated row) runs on every event and its matches are being recorded as "medium". A safety net must not outrank real evidence.

## FIX confidence rules in detect.py
Assign confidence by EVIDENCE SOURCE, not just KB score:
- **high**: eventmap field-based rule with a specific event_id (+optional field regex) that maps directly to a technique (e.g. 4720->T1136.001, 7045->T1543.003, 4698->T1053.005, Sysmon10 lsass->T1003.001, 4104/Sysmon1 command_line where kb.search top result is confidence "high"); AND correlation hits (brute force T1110, kerberoast T1558.003).
- **medium**: kb.search on the COMMAND_LINE or PowerShell MESSAGE field (the actual command), where kb confidence is medium.
- **low**: the raw-text/blob fallback (whole-row concatenation). CAP the blob fallback at "low" ALWAYS — it can never be medium or high. It is only there so nothing is missed on unknown schemas.
Dedupe per (event, technique) keeping the highest-confidence source.

## FIX brute-force correlation confidence
The 6x 4625 -> 4624 correlation must emit T1110 at HIGH confidence on the success event. Verify it appears in high counts.

## FIX summary + ranking
- "Top techniques" must rank by high count desc, then medium count desc; EXCLUDE low-only techniques. Display: `id | name | high:X med:Y | tactic`.
- Each timeline event's `primary_technique`/`primary_confidence` = its highest-confidence hit.
- Coverage: a tactic counts as COVERED only if it has at least one high OR medium hit (low-only does not make a tactic "covered").
- HTML: in the timeline, low-confidence hits shown but de-emphasized (smaller/grey) and there must be a "hide low-confidence" filter checkbox (inline JS). Coverage and Top-techniques use high/medium only.

## Acceptance (verify on the sample, print the result)
After fix, the high-confidence Top list must be dominated by the REAL attack, e.g. these should each have >=1 HIGH: T1566.001 (or T1204.002), T1059.001, T1105, T1053.005, T1547.001, T1003.001, T1018, T1110, T1021.001, T1565.001, T1685 (from the actual vssadmin/defender/hosts lines — not from blob noise). T1190 and T1112 must NOT dominate the top (they should drop sharply once blob is low-only). Print "high" and "medium" totals; high should rise, medium should fall well below 211.

## After
Run analyze on the sample + `python -m unittest discover -s tests`. Keep KB tests passing. Report the new confidence totals and Top-10.
