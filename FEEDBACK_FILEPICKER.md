# FEEDBACK — add a FILE PICKER (browse) to the web UI so users don't type paths. Work directly, no subagent.

## CRITICAL ENCODING RULE
Write EVERY edited file (especially bluekit/web/static/app.js and index.html) as **UTF-8, no BOM, no null bytes**. Last time app.js was saved partly as UTF-16 (null bytes between characters) which broke ALL JavaScript (tab switching died). Do NOT do that. After editing, app.js must contain zero 0x00 bytes and pass `node --check`.

## What to add
Browsers cannot read a local file's absolute path from `<input type="file">`, but they CAN read its CONTENT. The server already accepts `{content, filename}` for /api/logs/analyze — use the same pattern everywhere.

### 1. Logs tab (index.html + app.js)
- Add `<input type="file" id="log-file" accept=".csv,.json,.log,.tsv,.ndjson">` next to the existing path textbox. Keep the path textbox as a fallback.
- In app.js `logAnalyze()`: if a file is chosen in #log-file, read it with FileReader.readAsText and POST `{content: <text>, filename: <name>, preset, map}` to /api/logs/analyze. If no file chosen, fall back to the typed path `{path: ...}`.

### 2. Responder tab (index.html + app.js + server.py)
- Add file inputs: `#resp-snap-file` (snapshot JSON), `#resp-logs-file` (logs analyze JSON). Keep the path textboxes as fallback.
- app.js respTriage()/respFix(): if a snapshot file is chosen, read it and send `{current_content, current_filename}`; if a logs file is chosen, send `{from_logs_content, from_logs_filename}`; else use the path fields (`current_path`, `from_logs_path`).
- server.py handle_api_post for /api/resp/triage and /api/resp/fix: if `current_content`+`current_filename` present, save to workdir and use that path; if `from_logs_content`+`from_logs_filename` present, save to workdir and load_log_artifacts from it. Otherwise use the existing path fields. (Mirror exactly how /api/logs/analyze already handles content.)

### 3. Report tab (optional, same pattern)
- Add file inputs for logs.json and resp.json; if chosen, save content to workdir and use; else use the path fields.

## UX
- Small helper text under each picker: "Fayl tanlang yoki yo'lни yozing". 
- If both a file and a path are given, the CHOSEN FILE wins.

## Verify
- `node --check bluekit/web/static/app.js` passes; the file has zero null bytes.
- Start the server, load the page: tab switching still works (KB/Logs/Responder/Tracker/Report), the Logs file picker analyzes data/samples/practice/web_linux.csv when selected, and Responder triage works when snapshot_linux.json + the logs json are selected.
- `python -m unittest discover -s tests` still passes.
Report what you changed.
