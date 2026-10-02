# FEEDBACK — per-event technique detection is NOISY / not event-specific. Fix. Work directly, no subagent. No AI. UTF-8 only (no null bytes in any file).

## Problem (verified on data/samples/practice/web_linux.csv)
A BENIGN `GET /health HTTP/1.1 200` timeline event gets **6 high/medium** techniques: T1190, T1112, T1059.001, T1685, T1574.001, T1218 — all false positives (SQLi, PowerShell, Modify-Registry on a Linux web GET). And different events share almost the SAME technique set (the shell.php event also lists T1190, T1112, T1059.001, T1685, T1218, T1574.001). This means detection is NOT specific to each event's own text — noise is attached to every row. It makes the timeline unreadable.

## Root causes to fix in bluekit/logs/detect.py
1. The raw-text/blob fallback must contribute at **LOW confidence ONLY**, and must run on THAT event's own text (command_line, or message for access logs), NOT on a shared/global blob. Verify no blob hit is ever emitted as medium/high.
2. Each event's techniques must come from ITS OWN content:
   - Windows/Linux exec events: from command_line via eventmap + KB search on that command.
   - Access-log (nginx/apache) events: from the `message` (the HTTP request line) ONLY.
3. A plain access-log line with no attack signature (e.g. `GET /health`, `GET /index.html 200`) must yield **NO high/medium technique** (low or none is fine).
4. Web-attack heuristics must be specific:
   - `union select`, `' or '1'='1`, `../`, `sqlmap`, `/etc/passwd` in a URL, error-based/time-based patterns => T1190 (Exploit Public-Facing Application), HIGH.
   - upload of a webshell (`upload.php` + `filename=*.php/.jsp/.aspx`) OR access to a shell (`shell.php?cmd=`, `cmd.jsp`, `c99`, `b374k`) => T1505.003, HIGH.
   - Otherwise a GET/POST alone => nothing.
5. Remove bad generic mappings: nothing should map a Linux web line to T1112 (Modify Registry), T1059.001 (PowerShell), T1574.001, T1218 unless those strings literally appear. Find the over-broad heuristic/eventmap rules causing T1190/T1112/T1059.001/T1218/T1574.001 to appear everywhere and tighten or remove them.

## Also (display, bluekit/web/static/app.js)
The timeline "Techniques" column should show only high/medium techniques per row (drop low). Keep it UTF-8, node --check clean.

## Verify (print results)
After fix, on web_linux.csv:
- `GET /health` events: high/med techniques = NONE (or clearly empty).
- SQLi line (`products.php?id=1 UNION SELECT`): T1190 high.
- `POST /admin/upload.php filename=shell.php` and `GET /uploads/shell.php?cmd=id`: T1505.003 high.
- reverse shell (`bash -i >& /dev/tcp/...`): T1059.004 high, NOT a pile of unrelated ids.
- Each event's technique list should be SHORT and specific (roughly 1-3 high/med), not ~20.
- The summary "Totals: X high, Y medium" should DROP substantially (much less noise).
`python -m unittest discover -s tests` still passes (add/adjust: a benign `GET /health` row yields no high/medium technique; the SQLi row yields T1190). Report the before/after technique counts for the /health and shell rows.
