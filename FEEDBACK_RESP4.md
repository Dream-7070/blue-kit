# FEEDBACK — SAFETY-CRITICAL fixes in triage/bridge. Baseline diff works now, but new regressions, one dangerous. Work directly, no subagent. READ-ONLY kit.

## BUG 1 (SAFETY-CRITICAL) — the C2 got auto-marked PROTECTED
The beacon.exe -> 45.142.212.61 connection was flagged `protected: True` with reason "checker IP (loglardan)", because the beacon is ALSO periodic (5-min) so it was added to checker_ips. Auto-protecting by periodicity can protect the real C2 — unacceptable (it would be excluded from remediation).
FIX — stop auto-protecting from periodicity:
- Do NOT add checker/beacon candidates to the protected set automatically. Remove that behavior.
- NEVER treat an IP as checker if it is associated with a known-bad process (beacon, mimikatz, etc.), a flagged technique, or is an OUTBOUND connection from a workstation to a PUBLIC IP. Those are C2, not checkers.
- Instead, SURFACE checker candidates as an ADVISORY section only: "Mumkin bo'lgan checker (tekshiring, protected ro'yxatiga QO'LDA qo'shing):" listing each candidate. The operator adds real checker IPs to `--protected` themselves.
- The only auto-protection is the user-supplied `--protected` list. Keep that.
Result required: the beacon.exe->45.142.212.61 connection must be a HIGH, log_confirmed, NOT-protected finding (it is the C2). Verify.

## BUG 2 — baseline (legit) items flagged on generic KB hits
SecurityHealth, GoogleUpdateTaskMachine, Spooler (all in baseline, legit) are being flagged (0.4-0.8) from generic KB FTS matches. A baseline-present item must NOT become a finding from a weak/generic KB hit.
FIX the finding gate:
- Create a finding ONLY IF the item is (a) `new` (not in baseline) OR (b) independently strongly-bad: a RAT, a known-malware/tool NAME (built-in list or KB heuristic-level hit, NOT plain FTS), a Temp/suspicious path, Defender turned OFF, an attacker Defender exclusion, or a log-confirmed match.
- A plain kb.search FTS match on a legit name (SecurityHealth/Spooler/GoogleUpdate) is NOT sufficient to flag. Only use KB technique mapping to LABEL a finding that already qualified — never to CREATE a finding for a baseline item. When kb is None, rely on new-vs-baseline + built-in known-bad names + location.
- Net effect on the sample: SecurityHealth, GoogleUpdateTaskMachine, Spooler must NOT appear as findings.

## BUG 3 — "health" matched "SecurityHealth"; loose substring matching
Bridge/log matching used naive substring so "health" (from "GET /health") matched "SecurityHealth". Tighten:
- Match artifacts on whole-token / exact-ish comparison, not arbitrary substrings. For names (tasks/users/services/autorun names) require case-insensitive EQUALITY or a path-basename equality, not substring-in. For files match on full path or exact basename. For IPs exact. For hosts entries exact payload.
- Drop tokens shorter than 4 chars and generic words ("health","update","system") from artifact matching entirely.

## BUG 4 — reason spam / dedupe
"log: shu texnika kuzatilgan" appears multiple times per finding and on baseline/legit items. Dedupe reasons (no duplicates) and only add the technique-intersection reason to findings that are already log_confirmed or independently suspicious — not to legit baseline items.

## BUG 5 — unmatched list: a matched artifact still listed
91.238.50.10 shows in unmatched even though the hosts finding for "91.238.50.10 ibank.example.uz" was matched. Consider an artifact matched if any finding log_confirmed on it (compare on the same normalized key you match with). Keep the good filtering (real files/IPs only).

## After
Run `bk logs analyze <sample> --json-out logs.json` then `bk resp triage current_win.json --baseline baseline_win.json --from-logs logs.json`. REQUIRED outcome:
- Findings (log_confirmed, high, NOT protected): Updater task, Updater autorun, AnyDesk, hosts 91.238..., and the 45.142.212.61 beacon connection (C2).
- `admin` user = new, medium, not protected.
- SecurityHealth / GoogleUpdateTaskMachine / Spooler = NOT findings.
- No finding is auto-protected (protected only via --protected). With `--protected checker_admin`, checker_admin is protected and absent from `fix`.
- Advisory "possible checker" section lists the periodic candidates without protecting them.
`python -m unittest discover -s tests` all pass (adjust test_resp: checker auto-protect assertion becomes "advisory + not auto-protected"; keep the --protected exclusion test). Report results.
