# SPEC: blue-kit knowledge base (KB) — builder + query library + CLI

## Context
Blue-team DFIR competition toolkit ("blue-kit"). Fully OFFLINE, NO AI/LLM, NO network calls at runtime.
Python 3.10+ compatible, runs on Windows and Linux. Dependencies: Python stdlib + PyYAML ONLY.

## Where to write
- Write ALL code ONLY under: `D:\Claude Projects\CTF\blue-kit-staging\`
- Read-only input data (do NOT modify or delete anything there):
  - `D:\Claude Projects\CTF\blue-kit\data\attack\enterprise-attack.json` (ATT&CK v19.2 STIX 2.1 bundle)
  - `D:\Claude Projects\CTF\blue-kit\data\attack\ics-attack.json`
  - `D:\Claude Projects\CTF\blue-kit\data\attack\mobile-attack.json`
  - `D:\Claude Projects\CTF\blue-kit\data\sigma\rules`, `...\sigma\rules-threat-hunting`, `...\sigma\rules-emerging-threats` (SigmaHQ YAML rules)
  - `D:\Claude Projects\CTF\blue-kit\data\atomic\atomics\T*\T*.yaml` (Atomic Red Team; bin/src folders were removed on purpose)
- Do not use the network. Do not install packages.

## Layout to create
```
blue-kit-staging/
  bk.py                      # CLI entry point (argparse)
  bluekit/__init__.py
  bluekit/paths.py           # resolves data dir: env BLUEKIT_DATA or <repo>/data ; kb file: <data>/kb/kb.sqlite
  bluekit/kb/__init__.py
  bluekit/kb/build.py        # build(data_dir, out_path) -> stats dict
  bluekit/kb/query.py        # class KB: read-only API over sqlite
  bluekit/kb/ioc.py          # IOC type detection (regex)
  bluekit/kb/heuristics.yaml # curated pattern -> technique rules (see below)
  tests/test_kb.py           # unittest (NOT pytest), skipped if kb.sqlite missing
  README_KB.md               # short usage doc
```
The default data dir when running from staging must be configurable: `--data <dir>` CLI flag and env `BLUEKIT_DATA`; fallback `<dir of bk.py>/data`.

## 1. Build (`python bk.py kb build [--data DIR]`)
Creates SQLite file `<data>/kb/kb.sqlite` (overwrite atomically: build into temp file then os.replace). Must finish < 3 min. Print progress + final counts.

### STIX parsing rules (apply to all three bundles; domain = enterprise|ics|mobile from file name)
- ATT&CK id = `external_references[]` where `source_name` == "mitre-attack" -> `external_id`; url likewise.
- Objects may have `revoked: true` or `x_mitre_deprecated: true`. Keep them in techniques table with flags, but EXCLUDE them (and relationships touching them, and relationships that are themselves revoked/deprecated) from usage/co-occurrence stats.
- Revocation target: relationship_type `revoked-by` (source=old, target=new) -> store new attack_id in `revoked_by`.
- Sub-techniques: `x_mitre_is_subtechnique`; parent via relationship `subtechnique-of` (source=sub, target=parent), fallback: id prefix before '.'.
- Tactics: `kill_chain_phases[].phase_name` (shortname). Tactic objects `x-mitre-tactic` have `x_mitre_shortname`, name, external_id (TAxxxx). Tactic ORDER = order in `x-mitre-matrix.tactic_refs` (mobile has 2 matrices: concatenate, dedupe, keep first order).
- Actors: types `intrusion-set`, `malware`, `tool`, `campaign`. Relationship `uses` actor -> attack-pattern.
- Mitigations: `course-of-action` with `mitigates` relationship -> technique (keep relationship description).
- Detection (v19 format): `x-mitre-detection-strategy` --`detects`--> attack-pattern; strategy has `x_mitre_analytic_refs` -> `x-mitre-analytic` objects with `description`, `x_mitre_platforms`, `x_mitre_log_source_references[]` ({name, channel}). Store per technique: strategy name + each analytic description + log sources text. Also keep legacy `x_mitre_detection` field if present.
- Same ATT&CK id can exist in more than one domain file (some objects are shared). Primary key for techniques is (attack_id, domain).

### Tables (exact names)
- `meta(key TEXT PRIMARY KEY, value TEXT)` – attack versions per domain (from `x-mitre-collection.x_mitre_version`), build time, counts.
- `tactics(domain, attack_id, shortname, name, ord INTEGER)`
- `techniques(attack_id, domain, stix_id, name, is_sub INTEGER, parent_id, tactics TEXT /*comma shortnames*/, platforms TEXT, description TEXT, detection TEXT, url, deprecated INTEGER, revoked INTEGER, revoked_by TEXT, PRIMARY KEY(attack_id, domain))`
- `actors(stix_id PRIMARY KEY, attack_id, name, type, domain, aliases TEXT)`
- `uses(actor_stix_id, technique_id, domain, description TEXT)` — technique_id is ATT&CK id (sub-technique level as given).
- `mitigations(attack_id, domain, name, description)`
- `mitigates(mitigation_id, technique_id, domain, description)`
- `atomic_tests(technique_id, name, platforms TEXT, executor TEXT, command TEXT, cleanup TEXT)` — from atomic yaml: `attack_technique`, `atomic_tests[].name`, `supported_platforms`, `executor.name`, `executor.command`, `executor.cleanup_command`. Skip unparsable files with a warning count.
- `sigma_rules(rule_id, title, level, status, product, category, service, techniques TEXT /*comma ids uppercased, e.g. T1059.001*/, path TEXT /*relative*/, description TEXT, detection TEXT /*yaml dump of detection section*/, falsepositives TEXT)` — techniques from `tags` matching `attack.t\d{4}(\.\d{3})?` (case-insensitive) -> uppercase `T....`. Sigma files may contain multiple YAML documents: use `yaml.safe_load_all`, take docs having `title`. Skip parse errors with warning count.
- `cooc(t1, t2, level TEXT /*'sub' or 'parent'*/, both REAL, n1 REAL, n2 REAL)` precomputed, see §3. Index on (level, t1).
- FTS5 virtual table `search_idx(attack_id UNINDEXED, domain UNINDEXED, source UNINDEXED, ref UNINDEXED, text)` with tokenizer `unicode61 tokenchars '-_./\\:$'`... if that tokenizer spec fails, fall back to default `unicode61`. Rows:
  - source='technique': text = name + description (+ detection) for every non-revoked non-deprecated technique
  - source='atomic': text = test name + command (ref = test name)
  - source='sigma': text = title + description + detection (ref = relative path) — one row PER technique tag
- Indexes on techniques(attack_id), uses(technique_id), uses(actor_stix_id), atomic_tests(technique_id), mitigates(technique_id).

## 2. Query library (`bluekit/kb/query.py`, class `KB(path=None)`)
All methods return plain dicts/lists (JSON-serializable).
- `version()` -> dict of meta.
- `lookup(attack_id)` -> list of records (one per domain) incl. name, domain, tactics (with names), is_sub, parent (id+name), platforms, url, status: "active" | "deprecated" | "revoked", revoked_by (id+name), short description (first 400 chars), mitigations list, atomic test count, sigma rule count. Accept lowercase and whitespace; accept "t1059.001".
- `validate(ids: list[str])` -> for each: {input, normalized, found: bool, status, domains, name, replacement (revoked_by or None), parent_id, message}. Invalid format -> found False with message.
- `search(text, limit=20, domain=None)` -> ranked techniques. Implementation: FTS5 MATCH over `search_idx` using a SAFE query (quote every token, strip FTS syntax chars, OR-join tokens; if text looks like a command line also try the full phrase); aggregate bm25 scores per (attack_id, domain) across rows with source weights technique=1.0, sigma=1.3, atomic=1.5; PLUS heuristics hits (§4) with high weight. Return: attack_id, name, domain, tactics, score normalized 0..1 (top=1), sources: counts per source, evidence: up to 3 snippets (sigma titles / atomic test names / heuristic names). Exclude revoked/deprecated techniques from results (but if a heuristic points to a revoked id, map to replacement).
- `related(observed: list[str], limit=25, domain=None, level='auto')` -> probable next/associated techniques. See §3.
- `actors_matching(observed: list[str], limit=10)` -> actors ranked by coverage: score = |A∩S| / |S| primarily, tie-break by |A∩S|/|A| ; return name, type, attack_id, matched ids, count of other techniques, top 15 unobserved techniques of that actor (with names, tactics).
- `tactic_coverage(observed: list[str], domain='enterprise')` -> ordered list of tactics of that domain with observed technique ids per tactic and a `missing` flag.
- `mitigations_for(attack_id)`; `atomics_for(attack_id)`; `sigma_for(attack_id)`.

## 3. Co-occurrence & related scoring (no AI, statistics only)
Precompute in build:
- For each non-revoked actor A: set U_sub(A) = technique ids it uses; U_parent(A) = {id.split('.')[0]}.
- Actor weight w(A): campaign 1.0, intrusion-set 1.0, malware 0.8, tool 0.6.
- For level in (sub, parent): for every pair (t1, t2), t1≠t2, both in U(A): both += w(A); n(t) = Σ w(A) over actors using t. Store rows only where both > 0. (Keep it efficient: iterate per actor over its technique set.)
`related(observed)` at query time:
- Normalize observed ids; `level='auto'` → use 'sub' for ids containing '.', 'parent' otherwise; compute both level results and merge taking max per candidate parent/sub id.
- For each candidate T not observed (and not a parent/child of an observed id at same meaning — i.e. exclude T if T == parent(s) or parent(T) == s? NO: keep children of an observed parent as candidates but exclude the parent of an observed sub-technique):
  - P(T|s) = (both(s,T) + 0) / (n(s) + 2)   (mild smoothing)
  - p_cooc = 1 − Π_s (1 − P(T|s))   (noisy-OR)
  - kill-chain bonus: let O = set of tactic orders of observed techniques; for T's tactics, bonus = 0.10 if some tactic order == max(O)+1 or fills a tactic order between min(O) and max(O) not yet covered; else 0.
  - final = min(1, p_cooc * 0.9 + bonus)
- Return top N: attack_id, name, domain, tactics, probability (rounded 3), support = Σ both over s (rounded), reasons: list of strings like "T1566.001 bilan: 38/112 aktor" (use Uzbek word 'aktor'), and "kill-chain: keyingi taktika (lateral-movement)".
- Exclude revoked/deprecated.

## 4. Heuristics (`bluekit/kb/heuristics.yaml`)
YAML list of rules: `{name, pattern /*python regex, case-insensitive*/, techniques: [ids], weight: float 0..1, note}`.
Provide ~120 high-quality rules focused on: phishing/Office/LNK/ISO/archive attachments, PowerShell (encoded, IEX, download cradles), cmd, wscript/cscript/mshta/rundll32/regsvr32/certutil/bitsadmin, schtasks, sc create, Run keys, WMI subscriptions, services, new users/net user/net group add, mimikatz/lsass/procdump/comsvcs MiniDump, reg save SAM/SYSTEM, ntdsutil, DCSync, kerberoast (Rubeus, GetUserSPNs), psexec/wmic /node/winrm/Enter-PSSession/RDP mstsc, nmap/masscan/Advanced IP Scanner/net view/nltest/whoami/ipconfig/systeminfo, AnyDesk/TeamViewer/RMS (rutserv, rfusclient)/Ammyy/ScreenConnect/RustDesk (T1219), clipboard/keylogger/screenshot, 1C and bank payment file tampering (`1c_to_kl.txt`, `kl_to_1c.txt` → T1565.001, T1657), hosts file modification, vssadmin/wbadmin/bcdedit (T1490), wevtutil cl / Clear-EventLog (T1070.001), Defender disable (Set-MpPreference, T1562.001), firewall changes, 7z/rar/zip of data (T1560.001), curl/wget/Invoke-WebRequest/Transfer via cloud (mega, dropbox, transfer.sh T1567.002), DNS tunneling (iodine, dnscat), ngrok/chisel/frp/plink tunnels (T1572), Linux: crontab, /etc/cron*, systemd unit, authorized_keys, useradd, /etc/passwd, sudoers, SUID chmod u+s/+s, ld.so.preload, .bashrc, history -c, rm of logs, nc/ncat/socat reverse shell, bash -i >& /dev/tcp, python pty, webshell names/uploads (T1505.003), sqlmap/union select (T1190), hydra/brute (T1110), miners xmrig/stratum+tcp (T1496), docker.sock / privileged container escape. ICS (domain ics, ids T0xxx): modbus write function codes / "Write Single Coil|Write Multiple Registers" (T0855, T0836), S7 "stop CPU|plc stop" (T0816, T0881?), program download/upload (T0843, T0845), change operating mode (T0858), alarm suppression (T0878), HMI/SCADA service stop (T0881), loss of availability (T0826), default creds (T0812). Mobile: a few (adb install, apk) rules.
IMPORTANT: every technique id you put there MUST exist and be active in the KB. The build step must VALIDATE heuristics against the built KB and print a warning list of unknown/revoked/deprecated ids (for revoked ones print the replacement). Fix heuristics.yaml until the warning list is empty.
Heuristic rows are loaded at build into table `heuristics(name, pattern, techniques, weight, note)`; invalid regex -> warning, skipped.

## 5. IOC typing (`bluekit/kb/ioc.py`)
`classify(s) -> {"type": ..., "value": normalized}` types: ipv4, ipv6, cidr, domain, url, email, md5, sha1, sha256, sha512, win_path, unix_path, registry, filename, command, user, cve, attack_id, unknown. Handle defanged forms (`hxxp`, `[.]`, `(.)`). Private/loopback IPs flagged `private: true`.
`techniques_for_ioc(kb, s)` -> classify + for types command/win_path/unix_path/registry/filename/url/domain run `kb.search` (heuristics first); for attack_id -> validate; for hashes/IPs return empty technique list with note "hash/IP o'zi texnika bermaydi — kontekst kerak" plus generic candidates for ip/domain/url: T1071.001, T1105, T1041 with low score 0.2.

## 6. CLI (`bk.py`)
Subcommands (all support `--json` for machine output; default human-readable aligned text, no colors required, but use ANSI colors only if stdout isatty and not Windows legacy — keep simple):
- `kb build [--data DIR]`
- `kb info`
- `kb id <ID> [ID...]` → lookup details
- `kb validate <ID> [ID...]` → table: input | status | name | replacement
- `kb search "<text>" [--domain enterprise|ics|mobile] [-n 20]`
- `kb ioc "<value>" [...]` → type + candidate techniques
- `kb related <ID> [ID...] [-n 25]` → probability table + reasons, then top 5 matching actors (name, type, coverage)
- `kb tactics <ID> [ID...] [--domain D]` → kill-chain coverage table with MISSING marks
Output text labels may be English; keep reasons in Uzbek as specified. Must work with Windows console (use `sys.stdout.reconfigure(encoding='utf-8', errors='replace')`).

## 7. Tests (`tests/test_kb.py`, unittest)
Skip all if kb.sqlite does not exist. Assert:
- validate("T1003.001") active, name "LSASS Memory"; validate("T0803") in ics -> revoked with non-null replacement; validate("T9999") not found; validate("bad") not found.
- lookup("T0881") domain ics name "Service Stop"; lookup("T1657") name "Financial Theft".
- search("vssadmin delete shadows /all /quiet") top-3 contains T1490.
- search("schtasks /create /sc onlogon /tr evil.exe") top-3 contains T1053.005.
- search("echo ssh-rsa AAAA >> ~/.ssh/authorized_keys") top-3 contains T1098.004.
- related(["T1566.001"]) returns >= 10 rows, probabilities within [0,1], sorted desc, none equal to observed.
- tactic_coverage(["T1566.001","T1003.001"]) marks initial-access and credential-access not missing.
- ioc classify: "hxxp://evil[.]com/a.exe" -> url; "8.8.8.8" ipv4; "10.0.0.5" private; 32-hex -> md5; "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" -> registry; "C:\\Users\\a\\x.exe" -> win_path.
Run build and the tests yourself: `python bk.py kb build --data "D:\Claude Projects\CTF\blue-kit\data"` must work — NOTE the build output path is `<data>/kb/kb.sqlite`; creating that one `kb` folder inside the data dir is the ONLY allowed write outside staging. Then `python -m unittest discover -s tests -v` with env BLUEKIT_DATA set. All tests must pass. Fix code until they pass.

## Quality
- Clear small functions, docstrings short, no dead code, no print debugging left.
- Robust to missing optional fields in STIX/YAML.
- Never execute any command strings from Atomic/Sigma data — treat as text only.
- At the end, print a short summary: files created, build stats (counts per table, build seconds), test results.
