# FEEDBACK ROUND 4 — polish `ioc` and `related`. Then rebuild.

Two commands need polish in bluekit/kb/query.py and the CLI in bk.py. Work directly, no subagent. Do NOT execute command strings from data. Do NOT touch validate/search/tactics (they are good). Do NOT change technique ids from memory — ATT&CK v19 numbers in the KB are correct.

## DEFECT A — `ioc` output is noisy
Currently `kb ioc "hxxp://evil[.]com/a.exe"` dumps ~20 techniques with long unrounded scores like 0.8957939116883481, and a bare URL maps to T1218 at 1.0 which is misleading.
FIX:
1. Round every score to 3 decimals everywhere it is displayed.
2. `techniques_for_ioc` should return at most the top 5 techniques by default; add a `-n` / limit option to `kb ioc`.
3. Only include a candidate technique if its score is meaningful (drop near-zero noise, e.g. score < 0.15).
4. For ioc types that cannot strongly imply a technique on their own (ip, domain, url, hash), mark the returned candidates with confidence "low" and keep the existing note ("... kontekst kerak"). Do not present them as strong hits.
5. For command / path / registry / filename IOCs, reuse kb.search and show its `confidence` field in the ioc table too (columns: ID | Name | Score | Confidence).

## DEFECT B — `related` reasons are too generic and the actors section is missing
Currently reasons are just "T1105 co-occurs". The spec wants informative, Uzbek reasons and a matching-actors section.
FIX in related():
1. Reasons must use the co-occurrence counts. For each observed id s that contributed to candidate T, add a reason string in Uzbek:
   "<s> bilan birga: <both>/<n(s)> aktor" where both = cooc.both(s,T) and n(s) = cooc.n for s (round to integers). List up to the 3 strongest contributing observed ids.
   If the kill-chain bonus was applied, add a reason: "kill-chain: keyingi taktika (<tactic-name>)".
2. `kb related` CLI: after the probability table, print a second section "Mos keladigan aktorlar (guruh/malware):" showing the top 5 from actors_matching(observed): columns Name | Type | Coverage (matched/total observed) | Sample unobserved techniques (up to 3 ids). Use the existing actors_matching method (fix it if needed).
3. Round probabilities to 3 decimals.

## After fixing
Rebuild: `python bk.py kb build --data "D:\Claude Projects\CTF\blue-kit\data"`. Then run `python -m unittest discover -s tests -v` (BLUEKIT_DATA set) — existing tests must still pass. (Do not worry about adding new tests; the reviewer will add those.) Report results.
