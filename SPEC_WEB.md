# SPEC: blue-kit LOCAL WEB UI — one offline graphical front for KB + Logs + Responder + Tracker

## Context
Part of "blue-kit". A LOCAL, OFFLINE web app so a team that doesn't like the CLI can use everything in a browser. Fully offline: NO external CDN/fonts/JS — inline everything. Dependencies: Python STDLIB ONLY (http.server / socketserver / json / urllib / html / mimetypes). Do NOT use Flask or any pip package. Reuse existing Python APIs: bluekit.kb.query.KB, bluekit.logs.*, bluekit.resp.*. Python 3.10+, Windows+Linux.

## Safety (hard rules)
- Bind to 127.0.0.1 by DEFAULT. Only bind 0.0.0.0 if `--host 0.0.0.0` is passed, and then print a clear warning "LAN'ga ochildi — 10 jamoa tarmog'ida ehtiyot bo'ling".
- The web UI NEVER executes anything on target systems. Responder "fix" only RETURNS generated command text (same as CLI). No endpoint runs shell/remediation commands.
- The only networked action is the SLA check (port/http) to a target the user explicitly enters — keep it clearly user-initiated.
- No auth needed (localhost), but do not expose arbitrary file read: file paths for logs/snapshots are provided by the local operator; still, restrict served static assets to the app's own files.

## Where to write (all under D:\Claude Projects\CTF\blue-kit-staging)
```
bluekit/web/__init__.py
bluekit/web/server.py       # http.server based app (ThreadingHTTPServer), routing, JSON API, static serving
bluekit/web/static/index.html
bluekit/web/static/app.js   # vanilla JS, no libs
bluekit/web/static/style.css
tests/test_web.py           # unittest: start server on ephemeral port, hit endpoints, assert JSON
```
New CLI: `bk web [--host 127.0.0.1] [--port 8000] [--data DIR] [--workdir DIR]`. On start print the URL and "Ctrl+C to'xtatish".

## Server (bluekit/web/server.py)
- ThreadingHTTPServer + a BaseHTTPRequestHandler subclass.
- Load KB once at startup (fail clearly if not built: "Avval: python bk.py kb build --data ...").
- Serve static files from bluekit/web/static (index.html at `/`). Correct content-types. No path traversal.
- JSON API (all return application/json; catch exceptions -> {"error": msg} with 400/500; never crash the server):
  - GET  /api/info
  - GET  /api/validate?ids=T1059.001,T1070.001
  - GET  /api/search?q=<text>&domain=&n=20
  - GET  /api/id?id=T1003.001
  - GET  /api/related?ids=T1566.001&n=25            (no actors by default; &actors=1 to include, with the "attribution emas" caveat surfaced in UI)
  - GET  /api/ioc?v=<value>&n=5
  - GET  /api/tactics?ids=...&domain=enterprise
  - POST /api/logs/analyze     body {path, preset?, map?}  -> full structured result (events/timeline/coverage/chains/iocs/checker_candidates). (Accept a local file PATH; also accept raw CSV/JSON text in {content, filename} and write to workdir.)
  - POST /api/resp/triage      body {current_path OR current(text), baseline_path?, protected?(list)} -> findings + summary
  - POST /api/resp/fix         body {current..., baseline?, protected?, os, full?} -> {script: text}
  - POST /api/resp/sla         body {services:[...]} -> results + verdict
  - POST /api/resp/doctor      body {current..., service} -> causes
  - POST /api/resp/fraud       body {current...} -> indicators
  - Tracker (persist to <workdir>/tracker.json, create if missing; simple, robust):
    - GET  /api/tracker              -> list of rows
    - POST /api/tracker              body {question, candidates, evidence, status} -> add, returns row id
    - PUT  /api/tracker/<id>         -> update fields (e.g. validated, submitted)
    - DELETE /api/tracker/<id>       -> remove
- `--workdir` default `<data>/../web-work` or a temp dir; holds uploaded files + tracker.json.

## Frontend (static/index.html + app.js + style.css)
Single page, top tab bar: **KB** · **Logs** · **Responder** · **Tracker**. Clean, readable, works at phone width too. Inline/local assets only. Light+dark ok (simple). No external fonts.

### KB tab
- A single big input + a mode selector (Search / Validate / ID / Related / IOC / Tactics) OR separate small cards. Minimum: 
  - "Search" box: paste a command line -> table (ID, Name, Score, Confidence, Evidence). 
  - "Validate" box: paste IDs -> table with status + replacement (revoked highlighted RED with the active replacement shown prominently — this is the attempt-saver).
  - "Related" box: IDs -> probability table (+ optional actors toggle, shown with the "simulyatsiyada nom/IP soxta" caveat).
  - "IOC" box: value -> type + candidates.
  - "Tactics" box: IDs -> kill-chain coverage with MISSING highlighted.
- A prominent "➕ Trackerga qo'sh" button next to results to send a candidate ID into the Tracker.

### Logs tab
- Input: local file path (text field) + "Analyze" button; optional preset dropdown. (Optional: drag-drop upload that posts content.)
- On result: render Summary stats, ATT&CK Coverage (tactics, MISSING greyed), Timeline table with client-side filters (host / technique / free-text / hide-low-confidence checkbox), Chains, Checker/Beacon candidates, IOCs. Reuse the same structure as the HTML report. A "Trackerga qo'sh" on any technique row.

### Responder tab
- Inputs: current snapshot path (+ optional baseline path, + protected list textarea). Buttons: Triage / Fraud / Doctor(service name) / SLA.
- Triage -> findings table (Score, Conf, Category, Item, Techniques, Protected, Reasons); PROTECTED items shown separately marked "teginmang".
- "Fix buyruqlarini yasash" button + OS selector + full checkbox -> shows the generated remediation script in a <pre> with a "📋 Copy" button. Make crystal clear in the UI: "Bu buyruqlarni O'ZINGIZ ko'rib chiqib, targetда ishga tushirasiz. Tool hech narsani bajarmaydi."
- SLA: a small table editor (name, type, target, expect) + "Tekshir" -> OK/DEGRADED verdict; meant to run before/after fixes.

### Tracker tab
- Table: Question | Candidate IDs | Evidence | Status (topildi/validated/submitted) | actions. Add/edit/delete rows. Persists via /api/tracker. This is the team's shared answer log (run one instance on captain laptop + --host to share, or per-person local).
- A "Validate all" button that runs each candidate ID through /api/validate and flags any revoked (so nobody submits a dead ID).

## Tests (tests/test_web.py, unittest; skip if KB missing)
- Start the server on port 0 (ephemeral) in a thread; use urllib to:
  - GET /api/validate?ids=T1070.001 -> json, status revoked, replacement present.
  - GET /api/search?q=vssadmin%20delete%20shadows -> top result T1490.
  - GET / -> 200 and contains "blue-kit".
  - POST /api/resp/fix with the sample current/baseline paths -> script text contains BACKUP/REMOVE and excludes a protected item.
  - Tracker: POST then GET returns the row; DELETE removes it.
  - Shut the server down cleanly.
Keep existing tests passing.

## Quality
- Never block the server thread; handle errors per-request. UTF-8 everywhere. 
- All labels can be Uzbek/English mix as in the rest of the tool.
- At end print files created + how to launch (`python bk.py web`) + test results.
```
