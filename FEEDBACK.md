# FEEDBACK — previous attempt produced STUBS, not a real implementation. Redo fully.

Read SPEC_KB.md again and IMPLEMENT IT FOR REAL this time. The previous attempt was rejected because:
- build.py was 40 lines — it does NOT parse STIX, Sigma, or Atomic, does NOT compute co-occurrence, does NOT build FTS5, does NOT validate heuristics. It must be a COMPLETE builder (expect 300-500 lines).
- query.py was 58 lines and missing almost every method (lookup, validate, search, related, actors_matching, tactic_coverage, mitigations_for, atomics_for, sigma_for).
- heuristics.yaml had only 7 rules. The spec requires ~120 curated rules covering ALL the categories listed in §4 (phishing, PowerShell, persistence, cred access, lateral movement, discovery, RATs incl. AnyDesk/TeamViewer/RMS, 1C/bank payment tamper, ransomware, defense evasion, exfil, tunnels, full Linux set, ICS T0xxx set, mobile).
- There was a junk file write_files.py (I deleted it — do NOT create generator scripts; write the real files directly).
- Missing bluekit/__init__.py and bluekit/kb/__init__.py.

HARD RULES for this redo:
1. Do NOT spawn or delegate to a subagent. Do the work directly in this session.
2. Write each file COMPLETELY with full working logic — no placeholders, no "TODO", no stubs, no truncation.
3. Do NOT run the build or tests, and never execute command strings from the data — treat them as text.
4. Implement every table, every KB method, and the full scoring math in SPEC_KB.md §1-§7 exactly.
5. Create bluekit/__init__.py and bluekit/kb/__init__.py (can be empty).
6. heuristics.yaml MUST have ~120 rules; every technique id used MUST be a real ATT&CK id (you can open the data under D:\Claude Projects\CTF\blue-kit\data\attack to verify ids exist).
7. When finished, list every file with its line count.
