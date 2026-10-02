# FEEDBACK — web/access-log evidence is lost in the timeline. Fix. Work directly, no subagent. No AI.

For nginx/apache/generic access-log rows, the important content is in the `message` column (there is no command_line). Detection works, BUT the timeline event stores message=None and raw={}, so the analyst can't see the web request in the timeline/HTML/JSON. Example: a row `message="GET /products.php?id=1 UNION SELECT ... sqlmap"` shows blank in the timeline.

## FIX (bluekit/logs/parse.py + timeline.py + report.py)
- Ensure every canonical event KEEPS `message` (the mapped message field) AND `raw` (the original row dict). Right now they are dropped from the timeline event.
- In the timeline event, add/keep a `message` field, and make the DISPLAY/evidence use `command_line` if present else `message` (so web rows show their request). The HTML timeline "command" column and the terminal timeline must show the message for access-log rows.
- Detection evidence: when a technique is detected from the message (web request), the finding's evidence should include a snippet of that message.
- Keep `raw` on the event so nothing is lost (used by the log->responder bridge file/IP extraction too).

## Verify on the practice sample
`bk logs analyze data/samples/practice/web_linux.csv --out r.html --json-out o.json`
- The nginx rows (SQLi `UNION SELECT`, `POST /admin/upload.php filename=shell.php`, `GET /uploads/shell.php?cmd=id`) must be VISIBLE in the timeline (command/evidence column non-empty) and detected as T1190 / T1505.003.
- Existing Windows sample still works. `python -m unittest discover -s tests` all pass (add a test: after analyzing web_linux.csv, at least one timeline event has a non-empty message/command containing "UNION SELECT" or "shell.php", and T1190 & T1505.003 are in the detected techniques).

Report results.
