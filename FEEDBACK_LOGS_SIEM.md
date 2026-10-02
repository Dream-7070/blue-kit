# FEEDBACK — make the log analyzer SIEM-AGNOSTIC (we don't know which SIEM the competition uses)

Apply AFTER the base log analyzer works. The analyzer must NOT assume ELK/Kibana. Harden ingestion so ANY SIEM export (CSV/JSON/NDJSON/TSV/plain text) works, and an unknown schema still yields detections.

## 1. Expand fieldmap.yaml with multi-SIEM aliases
For every canonical field, add source-column aliases from these products (case-insensitive, match on exact name AND on the last dotted segment, e.g. both `process.command_line` and `command_line`):
- Elastic ECS + Winlogbeat (already have)
- Splunk CIM: `_time`, `host`, `user`, `dest`, `src`, `process`, `process_name`, `parent_process`, `parent_process_name`, `process_exec`, `CommandLine`, `signature_id`, `EventCode`, `source`, `sourcetype`
- Microsoft Sentinel / Defender (KQL export): `TimeGenerated`, `DeviceName`, `AccountName`, `InitiatingProcessCommandLine`, `ProcessCommandLine`, `InitiatingProcessParentFileName`, `FileName`, `RemoteIP`, `LocalIP`, `EventID`, `ActionType`
- Wazuh: `timestamp`, `agent.name`, `data.win.system.eventID`, `data.win.eventdata.commandLine`, `data.win.eventdata.image`, `data.win.eventdata.parentImage`, `rule.mitre.id`, `full_log`
- QRadar/LEEF & ArcSight/CEF: `devTime`, `src`, `dst`, `usrName`, `cmd`, `proc`, `sev`, `cat`; CEF keys `rt`, `shost`, `suser`, `dhost`, `act`, `deviceEventClassId`
- Graylog/GELF: `timestamp`, `source`, `message`, `_command`, `_process`
- Hayabusa CSV: `Timestamp`, `Computer`, `Channel`, `EventID`, `RuleTitle`, `Details`, `RecordID`
- EvtxECmd (Eric Zimmerman) CSV: `TimeCreated`, `Computer`, `Channel`, `EventId`, `MapDescription`, `PayloadData1..6`, `ExecutableInfo`, `UserName`
- Zeek: `ts`, `id.orig_h`, `id.resp_h`, `id.resp_p`, `uid`, `query` (dns), `host`, `uri` (http)
- Linux auditd/syslog/journalctl: `type`, `exe`, `comm`, `proctitle`, `acct`, `addr`, `SYSCALL`, `__REALTIME_TIMESTAMP`, `MESSAGE`, `_HOSTNAME`, `_COMM`, `_CMDLINE`
Ship these as named presets too: `fieldmap.yaml` should contain a top-level `presets:` section keyed by name (ecs, splunk, sentinel, wazuh, qradar, cef, graylog, hayabusa, evtxecmd, zeek, auditd) each listing that product's mapping, PLUS a merged `default:` used when no preset is chosen. CLI `--preset <name>` selects one.

## 2. Auto column detection + inspector
- `bk logs columns <file>` : print every source column, a sample value, and which canonical field it mapped to (or "UNMAPPED"). Also print which preset best matches (highest number of mapped canonical fields) and a warning if timestamp or command/message could not be located.
- When mapping, if no explicit alias matches a canonical field, use a fuzzy fallback: normalize column names (lowercase, strip non-alnum) and match against a set of keyword stems per canonical field (ts/time/date -> ts; cmd/command/commandline -> command_line; image/process/proc/exe -> process; parent -> parent_process; user/acct/account -> user; host/computer/device/agent -> host; eventid/eventcode/signature -> event_id; channel/source/logsource -> channel; src/source ip/orig -> src_ip; dst/dest/resp/remote -> dest_ip; target/subject -> target; msg/message/details/full_log/payload -> message).
- `--map <file.yaml>` : user override, highest priority (lets us adapt to any unknown SIEM in ~2 min at the competition).

## 3. Raw-text safety net (critical)
Detection must NEVER depend solely on recognized fields. For EVERY row, build a `blob` = concatenation of ALL source cell values (mapped or not) and run kb.search on it in addition to field-based detection (dedupe hits). So even a totally unknown schema still yields technique hits from any command/keyword present. If ts cannot be parsed, still ingest the row (ts=None, sorted last) — never drop rows.

## 4. Formats
Accept .csv, .tsv (auto-detect delimiter via csv.Sniffer, fallback comma/tab), .json / .ndjson (list or one-object-per-line; flatten nested objects with dotted keys so `data.win.eventdata.commandLine` becomes a flat column), and .log/.txt (each line a message; try to regex out a leading timestamp). Open utf-8-sig, errors='replace'.

## 5. Tests
Add tests: a tiny Splunk-style CSV (columns `_time,host,user,EventCode,CommandLine`) and a tiny Sentinel-style CSV (`TimeGenerated,DeviceName,AccountName,ProcessCommandLine`) both containing a `vssadmin delete shadows` line -> analyzer detects T1490 from each despite different schemas. And a JSON/NDJSON sample. Confirm `columns` reports correct mapping. Keep existing tests passing.
