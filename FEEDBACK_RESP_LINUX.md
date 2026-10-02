# FEEDBACK — triage crashes on a realistic LINUX snapshot. Make triage handle every schema field shape for BOTH OSes. Work directly, no subagent. READ-ONLY kit.

The triage was only exercised on a minimal Windows snapshot, so it assumes some fields are plain strings. A realistic Linux snapshot (per the documented schema) uses dicts and it crashes:
- `cron.strip()` -> AttributeError: cron entries are dicts `{user, line, file}` (not strings).
- similar risk for `ssh_authorized_keys` (dicts `{user, file, key_fingerprint_or_line}`), `recent_modified` (dicts `{path, mtime}` — partially fixed), `connections` (dicts), `autoruns` (dicts), `services` (dicts), `suid_files` (list of path strings), `users` (dicts with uid/shell).

## FIX
Make triage robust to the FULL snapshot schema for BOTH windows and linux. For each category, extract the right sub-field before string ops, and never call string methods on a dict:
- cron: use entry['line'] (+ show user/file); flag if new vs baseline cron lines; technique T1053.003; suspicious if it contains curl|bash / wget|sh / a /tmp path.
- ssh_authorized_keys: use entry['key_fingerprint_or_line'] and entry['user']; if not in baseline -> T1098.004 high.
- suid_files: list of path strings; flag SUID in suspicious locations (/tmp,/dev/shm,/var/tmp) or not in baseline -> T1548.001.
- connections: entry['raddr']/['rport']/['process']; public remote IP or known-bad process -> finding (T1071.001 / T1571), log-confirm if IP in log ips.
- services (linux + windows): entry['binary_path']/['name']; binary in /tmp or new -> finding.
- autoruns: entry['value']/['name'] (already dict).
- users: entry['name'], entry.get('uid'), entry.get('is_admin'); a NON-root user with uid==0 is a strong finding (T1136.001/T1548) high; admin/new logic as before.
Guard everything: `x['k'] if isinstance(x, dict) else x`. No crash on any field being a dict OR a string OR missing.

## Practice sample to use
`D:\Claude Projects\CTF\blue-kit\data\samples\practice\snapshot_linux.json` (+ its log `web_linux.csv`). Do NOT overwrite them.
After fix, this must work without crashing:
`bk logs analyze practice\web_linux.csv --json-out practice\web_linux.json`
`bk resp triage practice\snapshot_linux.json --from-logs practice\web_linux.json`
and surface (high, not-protected): the cron curl|bash, the root authorized_keys attacker line, /tmp/rootbash SUID, the uid-0 'support' user, the xmrig miner service (/tmp/.x/xmrig), and the connections to 185.220.101.44 (:4444 shell, :3333 miner). The gw-check 172.16.9.9 /health periodic must NOT be auto-protected (advisory only) and the C2 185.220.101.44 must NOT be protected.

## Tests
Add a test loading snapshot_linux.json: analyze() does not crash, returns findings for cron + ssh key + suid + uid0 user + miner service; no revoked technique id; C2 185.220.101.44 not protected. Keep all existing tests passing.

## After
Run both the windows and the linux triage demos + `python -m unittest discover -s tests`. Report results.
