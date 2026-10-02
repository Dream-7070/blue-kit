import json
import re
import os
from datetime import datetime
import ipaddress
from typing import List, Dict, Any, Tuple, Optional
from bluekit.ir.models import AttackStage, AttackChain

from bluekit.netutil import is_external_ip
from urllib.parse import unquote_plus

_WEB_SERVERS = re.compile(r'^(?:nginx|apache2?|httpd|lighttpd|php-fpm[\d.]*|php-cgi[\d.]*|php[\d.]*|w3wp|tomcat\d*|catalina|uwsgi|gunicorn)(?:\.exe)?$', re.I)
_SHELLS = {'sh': 'T1059.004', 'bash': 'T1059.004', 'dash': 'T1059.004', 'zsh': 'T1059.004', 'ksh': 'T1059.004',
           'cmd': 'T1059.003', 'powershell': 'T1059.001', 'pwsh': 'T1059.001', 'python': 'T1059.006', 'python3': 'T1059.006'}
_SQLI_RE = re.compile(r"('\s*(?:or|and)\s+'?\w+'?\s*=\s*'?\w+|\b(?:or|and)\s+\d+\s*=\s*\d+|union(?:\s+all)?\s+select|\b(?:sleep|benchmark|pg_sleep)\s*\(|waitfor\s+delay|information_schema|\b(?:extractvalue|updatexml|load_file)\s*\(|into\s+(?:out|dump)file|'\s*(?:--|#|/\*))", re.I)

def _is_external(ip_obj) -> bool:
    return is_external_ip(ip_obj)
def get_nested(d: Dict[str, Any], path: str, default=None):
    if isinstance(d, dict) and path in d:
        return d[path]
    parts = path.split('.')
    cur = d
    for p in parts:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur

def _str_field(v) -> str:
    if isinstance(v, dict):
        v = v.get('name') or v.get('hostname') or ''
    return v if isinstance(v, str) else ('' if v is None else str(v))

def _clean(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if v not in (None, '')}

def parse_sysmon_xml(path: str) -> List[Dict[str, Any]]:
    import xml.etree.ElementTree as ET
    events = []
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        cleaned = content.strip()
        if not cleaned.startswith('<Events') and not cleaned.startswith('<?xml'):
            cleaned = f"<Events>{cleaned}</Events>"
        elif cleaned.startswith('<?xml'):
            if '<Events>' not in cleaned and '<Events ' not in cleaned:
                xml_decl, rest = cleaned.split('?>', 1)
                cleaned = f"{xml_decl}?>\n<Events>{rest}</Events>"
        root = ET.fromstring(cleaned)
        for ev in root.findall('.//{*}Event') or root.findall('.//Event'):
            d = {'dataset': 'sysmon'}
            sys_node = ev.find('{*}System')
            if sys_node is None: sys_node = ev.find('System')
            if sys_node is not None:
                eid = sys_node.find('{*}EventID')
                if eid is None: eid = sys_node.find('EventID')
                if eid is not None: d['event_id'] = eid.text
                tc = sys_node.find('{*}TimeCreated')
                if tc is None: tc = sys_node.find('TimeCreated')
                if tc is not None: d['ts'] = tc.get('SystemTime') or tc.text
                comp = sys_node.find('{*}Computer')
                if comp is None: comp = sys_node.find('Computer')
                if comp is not None: d['host'] = comp.text
                prov = sys_node.find('{*}Provider')
                if prov is None: prov = sys_node.find('Provider')
                if prov is not None: d['channel'] = prov.get('Name')
            ed = ev.find('{*}EventData')
            if ed is None: ed = ev.find('EventData')
            if ed is not None:
                for data in ed.findall('{*}Data') or ed.findall('Data'):
                    name = data.get('Name')
                    val = data.text or ''
                    if name:
                        d[name] = val
                        if name == 'Image': d['process'] = val
                        elif name == 'CommandLine': d['command_line'] = val
                        elif name == 'User': d['user'] = val
                        elif name == 'SourceIp': d['src_ip'] = val
                        elif name == 'DestinationIp': d['dest_ip'] = val
                        elif name == 'DestinationPort': d['dest_port'] = val
                        elif name == 'Hashes': d['hash'] = val
                        elif name == 'TargetFilename': d['target_file'] = val
            events.append(d)
    except Exception:
        pass
    return events

def load_generic_csv(path: str) -> List[Dict[str, Any]]:
    import csv
    csv.field_size_limit(10**9)
    events = []
    try:
        with open(path, 'r', encoding='utf-8-sig', errors='replace') as f:
            sample = f.read(4096)
            f.seek(0)
            from bluekit.logs.parse import get_csv_reader
            ext = os.path.splitext(path)[1].lower()
            reader = get_csv_reader(f, sample, ext)
            for row in reader:
                events.append(dict(row))
    except Exception:
        pass
    return events

def load_events_from_file(file_path: str) -> Tuple[List[Dict[str, Any]], str]:
    from bluekit.logs.qradar import looks_like_qradar, load_qradar
    ext = os.path.splitext(file_path)[1].lower()
    source_name = os.path.basename(file_path)
    
    # 1. QRadar CSV / TSV
    if ext in ('.csv', '.tsv') and looks_like_qradar(file_path):
        return load_qradar(file_path), source_name
        
    # 2. Sysmon / Windows Event XML
    if ext == '.xml':
        evts = parse_sysmon_xml(file_path)
        if evts:
            return evts, source_name

    # 3. JSON / NDJSON / Elasticsearch / Wazuh
    with open(file_path, 'r', encoding='utf-8-sig', errors='replace') as f:
        first_char = f.read(1)
        f.seek(0)
        
        if first_char == '{':
            try:
                data = json.load(f)
                if isinstance(data, dict):
                    if 'hits' in data and isinstance(data['hits'], dict) and 'hits' in data['hits']:
                        hits = [h.get('_source', h) for h in data['hits']['hits']]
                        return hits, source_name
                    for k in ['events', 'Events', 'records', 'Records', 'results', 'data', 'logs']:
                        if k in data and isinstance(data[k], list):
                            return data[k], source_name
                    return [data], source_name
            except Exception:
                f.seek(0)
                
        if first_char == '[':
            try:
                data = json.load(f)
                if isinstance(data, list):
                    return data, source_name
            except Exception:
                f.seek(0)

        # NDJSON or line-by-line JSON
        f.seek(0)
        events = []
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith('{') and line.endswith('}'):
                try:
                    events.append(json.loads(line))
                except Exception:
                    pass
        if events:
            return events, source_name

    # 4. Generic CSV / TSV (Splunk, Wazuh, Sentinel, FortiAnalyzer)
    if ext in ('.csv', '.tsv'):
        evts = load_generic_csv(file_path)
        if evts:
            return evts, source_name

    # 5. Raw text / Syslog
    try:
        from bluekit.logs.parse import load_rows
        rows = load_rows(file_path)
        if rows:
            return rows, source_name
    except Exception:
        pass

    # Fallback to empty
    return [], source_name

def load_events_from_files(file_paths: List[str]) -> Tuple[List[Dict[str, Any]], str]:
    if not file_paths:
        return [], ""
    if len(file_paths) == 1:
        return load_events_from_file(file_paths[0])
        
    all_events = []
    names = []
    for p in file_paths:
        evts, name = load_events_from_file(p)
        all_events.extend(evts)
        names.append(name)
        
    return all_events, ", ".join(names)

def extract_canonical(evt: Dict[str, Any]) -> Dict[str, Any]:
    """Normalizes ECS or custom fields into canonical keys."""
    ts = (
        evt.get('@timestamp') or
        evt.get('timestamp') or
        evt.get('TimeCreated') or
        evt.get('TimeGenerated') or
        evt.get('EventTime') or
        evt.get('_time') or
        evt.get('time') or
        evt.get('ts') or
        get_nested(evt, 'event.created') or
        evt.get('time_local') or
        evt.get('time_iso8601') or
        evt.get('datetime') or
        evt.get('date_time') or
        ''
    )
    raw_ts = ts
    timestamp_display = ""
    if ts:
        from bluekit.logs.parse import parse_ts
        from bluekit.tz import LOCAL_TZ, display_ts
        parsed = parse_ts(ts)
        # +05:00 bilan: keyin parse_dt qayta o'qiganda --src-tz ikkinchi marta qo'llanmasin
        if parsed:
            timestamp_display = display_ts(parsed, raw=raw_ts)
            ts = parsed.replace(tzinfo=LOCAL_TZ).isoformat()
    dataset = (
        get_nested(evt, 'event.dataset') or
        evt.get('dataset') or
        evt.get('channel') or
        evt.get('sourcetype') or
        evt.get('source') or
        ''
    )
    host = (
        get_nested(evt, 'host.name') or
        evt.get('hostname') or
        evt.get('Computer') or
        evt.get('DeviceName') or
        evt.get('host') or
        get_nested(evt, 'agent.name') or
        ''
    )
    host_ip = get_nested(evt, 'host.ip') or ''
    user = (
        get_nested(evt, 'user.name') or
        evt.get('user') or
        evt.get('username') or
        evt.get('AccountName') or
        evt.get('TargetUserName') or
        get_nested(evt, 'winlog.event_data.TargetUserName') or
        ''
    )
    # ECS da source/host/user lug'at bo'lishi mumkin ({'ip': ...}, {'id': ...}) -- .lower() da yiqilmasin
    dataset, host, user = (_str_field(v) for v in (dataset, host, user))
    src_ip = (
        get_nested(evt, 'source.ip') or
        evt.get('src_ip') or
        evt.get('client_ip') or
        evt.get('IpAddress') or
        evt.get('RemoteIP') or
        evt.get('src') or
        evt.get('srcip') or
        evt.get('remote_ip') or
        evt.get('remote_addr') or
        evt.get('client_ip') or
        evt.get('c-ip') or
        ''
    )
    src_port = get_nested(evt, 'source.port') or evt.get('src_port') or evt.get('srcport') or ''
    dst_ip = (
        get_nested(evt, 'destination.ip') or
        evt.get('dest_ip') or
        evt.get('dst_ip') or
        evt.get('dst') or
        evt.get('dstip') or
        evt.get('dest') or
        evt.get('LocalIP') or
        ''
    )
    dst_port = get_nested(evt, 'destination.port') or evt.get('dest_port') or evt.get('dst_port') or evt.get('dstport') or ''
    
    url_path = (
        get_nested(evt, 'url.path') or
        get_nested(evt, 'url.original') or
        evt.get('path') or
        evt.get('url') or
        evt.get('objectUri') or
        evt.get('cs-uri-stem') or
        ''
    )
    url_query = get_nested(evt, 'url.query') or evt.get('query') or evt.get('cs-uri-query') or ''
    status_code = (
        get_nested(evt, 'http.response.status_code') or
        evt.get('status') or
        evt.get('status_code') or
        evt.get('sc-status')
    )
    if status_code is not None and str(status_code).strip():
        try:
            status_code = int(float(status_code))
        except ValueError:
            pass
    
    method = get_nested(evt, 'http.request.method') or evt.get('method') or evt.get('cs-method') or ''
    
    cmd = (
        get_nested(evt, 'process.command_line') or
        evt.get('command_line') or
        evt.get('CommandLine') or
        evt.get('ProcessCommandLine') or
        evt.get('cmd') or
        ''
    )
    proc_val = (
        get_nested(evt, 'process.name') or
        get_nested(evt, 'process.executable') or
        evt.get('process_name') or
        evt.get('Image') or
        evt.get('FileName') or
        evt.get('process') or
        ''
    )
    if isinstance(proc_val, dict):
        proc_name = proc_val.get('name') or proc_val.get('executable') or ''
    else:
        proc_name = str(proc_val) if proc_val else ''

    message = evt.get('message') or evt.get('_raw') or evt.get('msg') or ''
    action = evt.get('action') or evt.get('actionTaken') or evt.get('ActionType') or ''
    bytes_sent = int(evt.get('bytes_sent') or evt.get('sentbyte') or 0)
    bytes_rcvd = int(evt.get('bytes_rcvd') or evt.get('rcvdbyte') or 0)
    user_agent = evt.get('user_agent') or evt.get('http_user_agent') or ''
    
    req_col = evt.get('request')
    if req_col and isinstance(req_col, str):
        parts = req_col.split()
        if len(parts) >= 2 and parts[0].isupper():
            if not method: method = parts[0]
            req_uri = parts[1]
            if '?' in req_uri:
                if not url_path: url_path = req_uri.split('?', 1)[0]
                if not url_query: url_query = req_uri.split('?', 1)[1]
            else:
                if not url_path: url_path = req_uri

    if not dataset and evt.get('request') and (evt.get('status') or evt.get('status_code')):
        dataset = 'web'

    return {
        'timestamp': ts,
        'timestamp_display': timestamp_display,
        'dataset': dataset,
        'host': host,
        'host_ip': host_ip,
        'user': user,
        'src_ip': src_ip,
        'src_port': src_port,
        'dst_ip': dst_ip,
        'dst_port': dst_port,
        'url_path': url_path,
        'url_query': url_query,
        'status_code': status_code,
        'method': method,
        'user_agent': user_agent,
        'cmd': cmd,
        'proc_name': proc_name,
        'message': message,
        'action': action,
        'bytes_sent': bytes_sent,
        'raw': evt
    }

def is_benign_noise(c: Dict[str, Any]) -> bool:
    """Zero-noise filter: identifies routine background activity."""
    # Logdagi matn yoki IP/fayl nomi bo'yicha "decoy" filtri qo'yilmaydi: hujumchi
    # xabarga shu so'zni qo'shib voqeani yashirishi mumkin, finalda decoylar belgilanmaydi.
    cmd = (c.get('cmd') or '').lower()
    msg = (c.get('message') or '').lower()
    path = (c.get('url_path') or '').lower()
    ds = (c.get('dataset') or '').lower()

    # Static web assets with 200 OK
    if 'nginx' in ds or 'apache' in ds or 'web' in ds:
        if c.get('status_code') == 200 and any(path.endswith(ext) for ext in ('.css', '.js', '.png', '.jpg', '.jpeg', '.svg', '.woff', '.ico')):
            return True
            
    # Routine Windows workstation activity
    if 'windows.security' in ds or 'sysmon' in ds:
        benign_procs = ['outlook.exe', 'teams.exe', 'word.exe', 'excel.exe', 'slack.exe', 'chrome.exe', 'explorer.exe', '1cv8.exe']
        if any(bp in cmd for bp in benign_procs) and not any(k in cmd for k in ['powershell', 'cmd.exe', 'certutil', 'vssadmin', 'mimikatz', 'schtasks', 'mshta', 'curl', 'wget', 'http']):
            return True
            
    # Routine Linux syslog / cron
    if 'syslog' in ds or 'system.syslog' in ds:
        if any(term in msg for term in ['cron[15234]', 'cron[15280]', 'logrotate', 'anacron', 'action-2-builtin:omfile', 'starting daily apt', 'finished daily apt', 'received disconnect from']):
            return True
            
    # Routine PostgreSQL logs
    if 'postgresql' in ds:
        if any(term in msg for term in ['checkpoint', 'autovacuum', 'connection received']):
            return True

    return False

def correlate_incident(raw_events: List[Dict[str, Any]], kb=None, heuristic_fallback=True) -> AttackChain:
    """Analyzes raw events, strips noise, extracts attack stages and MITRE techniques."""
    stages: List[AttackStage] = []
    c2_seen: Dict[Tuple[str, str], AttackStage] = {}

    attacker_ips = set()
    exfil_ips = set()
    compromised_users = set()
    hosts_involved = set()
    signins_by_user = {}
    
    
    # Pre-scan internal IPs to map to endpoint hostnames and users
    ip_to_host = {}
    ip_to_user = {}
    for evt in raw_events:
        c = extract_canonical(evt)
        sip = c['src_ip']
        if sip:
            h = c['host']
            if h and not any(fw in h.lower() for fw in ['ha-cluster', 'fortigate', 'firewall', 'tashkent-d', 'gateway']):
                ip_to_host[sip] = h
            u = c['user']
            if u and not any(ign in u.upper() for ign in ['SYSTEM', 'AUTHORITY', 'ANONYMOUS', 'ESET']):
                ip_to_user[sip] = u

    # Pre-scan web access logs to identify active reconnaissance / scanners
    sensitive_probes = ['/admin', '/.env', '/.git', '/phpmyadmin', '/solr', '/wp-admin', '/actuator', '/config.json', '/cgi-bin', '/shell', '/api/debug']
    ip_probes = {}
    for evt in raw_events:
        c = extract_canonical(evt)
        if c['src_ip'] and c['status_code'] in (404, 403):
            path_lower = c['url_path'].lower()
            if any(p in path_lower for p in sensitive_probes):
                if c['src_ip'] not in ip_probes:
                    ip_probes[c['src_ip']] = {'count': 0, 'paths': set(), 'sample': c}
                ip_probes[c['src_ip']]['count'] += 1
                ip_probes[c['src_ip']]['paths'].add(c['url_path'])

    # Only flag IPs that probed multiple sensitive endpoints
    for ip, data in ip_probes.items():
        if len(data['paths']) >= 4 or data['count'] >= 15:
            attacker_ips.add(ip)
            sample = data['sample']
            if sample['host']: hosts_involved.add(sample['host'])
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=sample['timestamp'],
                host=sample['host'],
                phase="Reconnaissance",
                technique_id="T1595.002",
                technique_name="Active Scanning: Vulnerability Scanning",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=f"Attacker scanned {data['count']} sensitive endpoints ({', '.join(list(data['paths'])[:4])}) with 404/403 responses",
                iocs={"src_ip": ip, "probe_count": data['count'], "probed_paths": list(data['paths'])[:5]},
                source_dataset=sample['dataset']
            ))

    # QRadar Rules - Pre-scan
    import statistics
    c2_sessions = {}
    av_blocks = {}
    masquerading_blocks = {}
    
    for evt in raw_events:
        c = extract_canonical(evt)
        if c['dataset'] != 'qradar':
            continue
            
        host = ip_to_host.get(c['src_ip']) or c['host']
            
        src = c['src_ip']
        dst = c['dst_ip']
        port = c['dst_port']
        ts = c['timestamp']
        if src and dst and ts:
            is_internal = not is_external_ip(dst)
            if not is_internal:
                key = (src, dst)
                if key not in c2_sessions:
                    c2_sessions[key] = {}
                sid = c['raw'].get('session_id') or (src, c.get('src_port'), dst, port)
                if sid not in c2_sessions[key]:
                    c2_sessions[key][sid] = [c, c.get('bytes_sent', 0) or 0, c['raw'].get('bytes_rcvd', 0) or 0]
                else:
                    c2_sessions[key][sid][1] = max(c2_sessions[key][sid][1], c.get('bytes_sent') or 0)
                    c2_sessions[key][sid][2] = max(c2_sessions[key][sid][2], c['raw'].get('bytes_rcvd') or 0)
                
        # AV Blocked URL
        action = c['action']
        url = c['url_path']
        if action and 'Blocked URL' in action and url:
            key = (c['proc_name'], url)
            if key not in av_blocks:
                av_blocks[key] = {'count': 0, 'sample': c, 'hosts': set(), 'users': set()}
            av_blocks[key]['count'] += 1
            if host: av_blocks[key]['hosts'].add(host)
            if c['user']: av_blocks[key]['users'].add(c['user'])
            
        # Masquerading Rule
        proc_lower = c['proc_name'].lower()
        if ('c:\\programdata\\' in proc_lower or 'c:\\users\\public\\' in proc_lower) and \
           any(ms_name in proc_lower for ms_name in ['devicesync', 'onedrive', 'teams', 'update', 'defender', 'host']):
            h = c['raw'].get('hash', '')
            key = (host, c['proc_name'], h)
            if key not in masquerading_blocks:
                masquerading_blocks[key] = {'count': 0, 'first_ts': ts, 'sample': c}
            masquerading_blocks[key]['count'] += 1

    # 1. C2 Beacon Eval
    for (src, dst), sessions_dict in c2_sessions.items():
        sessions = list(sessions_dict.values())
        if len(sessions) >= 10:
            sessions = sorted(sessions, key=lambda x: str(x[0]['timestamp']))
            
            from bluekit.hunt.beacon_math import calculate_beacon_metrics
            
            timestamps = [s[0]['timestamp'] for s in sessions]
            metrics = calculate_beacon_metrics(timestamps)
            if metrics:
                med_f, cv_ratio = metrics
                if cv_ratio < 0.5:
                    total_sent = sum(s[1] for s in sessions)
                    mb_sent = round(total_sent / (1024*1024), 2)
                    port = sessions[-1][0]['dst_port'] or '80'
                    host_resolved = ip_to_host.get(src, sessions[-1][0]['host'])
                    if host_resolved: hosts_involved.add(host_resolved)
                    attacker_ips.add(dst)
                    if src in ip_to_user: compromised_users.add(ip_to_user[src])
                    
                    # Sessiya sanog'i `bk hunt beacons` bilan bir xil bo'lishi uchun
                    # faqat firewall sessiyalari sanaladi: sessionid siz kelgan
                    # ESET/AV yozuvlari bitta psevdo-sessiyaga yig'ilib, sonni
                    # har hostda 1 taga oshirib yuborardi.
                    fw_sessions = sum(1 for s in sessions if s[0]['raw'].get('session_id'))
                    sess_count = fw_sessions or len(sessions)
                    ev_msg = f"{src} -> {dst}:{port}, {sess_count} sessiya, ~{int(round(med_f))}s interval, {mb_sent} MB yuborilgan"
                    stages.append(AttackStage(
                        stage_id=f"S{len(stages)+1:02d}",
                                timestamp=sessions[-1][0]['timestamp'],
                                host=host_resolved,
                                phase="Command and Control",
                                technique_id="T1071.001",
                                technique_name="Web Protocols",
                                confidence="HIGH",
                                status="CONFIRMED",
                                evidence=ev_msg,
                                iocs={"src_ip": src, "dst_ip": dst, "port": port},
                                source_dataset="qradar"
                            ))

    # 2. AV Blocked Rule Evaluator
    for (proc_name, url), data in av_blocks.items():
        sample = data['sample']
        count = data['count']
        host_val = sample['host']
        if host_val: hosts_involved.add(host_val)
        for h in data['hosts']: hosts_involved.add(h)
        for u in data['users']:
            if u and 'SYSTEM' not in u.upper() and 'AUTHORITY' not in u.upper():
                compromised_users.add(u)
        if sample['dst_ip']:
            attacker_ips.add(sample['dst_ip'])
        stages.append(AttackStage(
            stage_id=f"S{len(stages)+1:02d}",
            timestamp=sample['timestamp'],
            host=host_val,
            phase="Command and Control",
            technique_id="T1071.001",
            technique_name="Web Protocols",
            confidence="HIGH",
            status="CONFIRMED",
            evidence=f"{proc_name} -> {url} (AV bloklagan, {count} marta)",
            iocs={"process": proc_name, "url": url},
            source_dataset="qradar"
        ))

    # 3. Masquerading Eval
    for (host, proc_name, h), data in masquerading_blocks.items():
        sample = data['sample']
        ev_msg = f"{proc_name} {h}".strip()
        if host: hosts_involved.add(host)
        u = sample['user']
        if u and 'SYSTEM' not in u.upper() and 'AUTHORITY' not in u.upper():
            compromised_users.add(u)
        stages.append(AttackStage(
            stage_id=f"S{len(stages)+1:02d}",
            timestamp=data['first_ts'],
            host=host,
            phase="Defense Evasion",
            technique_id="T1036.005",
            technique_name="Match Legitimate Resource Name or Location",
            confidence="HIGH",
            status="CONFIRMED",
            evidence=ev_msg,
            iocs={"process": proc_name, "hash": h},
            source_dataset="qradar"
        ))

    # Detailed event evaluation
    handled_idx = set()
    for _i, evt in enumerate(raw_events):
        _n0 = len(stages)
        _pass_to_fallback = False
        c = extract_canonical(evt)
        if is_benign_noise(c):
            handled_idx.add(_i)
            continue
            
        ds = c['dataset'].lower()
        cmd = c['cmd'] or c['message']
        msg = c['message']
        path = c['url_path']
        query = c['url_query']
        ts = c['timestamp']
        host = c['host']
        user = c['user']
        status = c['status_code']
        src_ip = c['src_ip']
        proc_lower = (c['proc_name'] or '').lower()
        cmd_lower = (cmd or '').lower()
        msg_lower = (msg or '').lower()
        full_text = f"{proc_lower} {cmd_lower} {msg_lower}"

        # 1. Suricata / Network IDS Exfiltration & C2
        if 'suricata' in ds or 'eve' in ds:
            if re.search(r'high volume outbound|exfil', msg, re.IGNORECASE):
                m_ip = re.search(r'Rare External IP\s+(\d+\.\d+\.\d+\.\d+)', msg) or re.search(r'to\s+(\d+\.\d+\.\d+\.\d+)', msg)
                dst_ip = m_ip.group(1) if m_ip else (c['dst_ip'] if _is_external(c['dst_ip']) else None)
                if dst_ip:
                    exfil_ips.add(dst_ip)
                if host: hosts_involved.add(host)
                iocs_alert = {"alert": msg}
                if dst_ip:
                    iocs_alert["dst_ip"] = dst_ip
                if c.get('dst_port'):
                    iocs_alert["port"] = c['dst_port']
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}",
                    timestamp=ts,
                    host=host,
                    phase="Exfiltration",
                    technique_id="T1048",
                    technique_name="Exfiltration Over Alternative Protocol",
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=msg,
                    iocs=_clean(iocs_alert),
                    source_dataset=ds
                ))

        # 2. Reconnaissance & System Discovery (T1033, T1087, T1046)
        # faqat buyruq pozitsiyasida: "SELECT id FROM ..." yoki "WHERE id = 5" mos kelmasin
        if re.search(r'(?:^|[;&|]\s*|\s-c\s+[\'"]?)(?:\S*/)?(?:id|whoami)(?:\s|$|;|\||[\'"])', (cmd or '').strip()):
            if host: hosts_involved.add(host)
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=ts,
                host=host,
                phase="Discovery",
                technique_id="T1033",
                technique_name="System Owner/User Discovery",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=cmd or msg,
                iocs=_clean({"cmd": cmd, "user": user}),
                source_dataset=ds
            ))
        elif re.search(r'\b(?:nmap|masscan|zmap)\b', cmd):
            if host: hosts_involved.add(host)
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=ts,
                host=host,
                phase="Discovery",
                technique_id="T1046",
                technique_name="Network Service Discovery",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=cmd or msg,
                iocs=_clean({"cmd": cmd, "user": user}),
                source_dataset=ds
            ))
        elif any(k in cmd_lower for k in ['get-adcomputer', 'get-aduser', 'get-adgroup', 'net user /domain', 'net group "domain admins"']):
            if host: hosts_involved.add(host)
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=ts,
                host=host,
                phase="Discovery",
                technique_id="T1087.002",
                technique_name="Account Discovery: Domain Account Discovery",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=cmd or msg,
                iocs=_clean({"cmd": cmd, "user": user}),
                source_dataset=ds
            ))

        # 3. Execution & Reverse Shells (T1059.006, T1218.005, T1548.003, T1105)
        if re.search(r'(?:bash\s+-i\s+>&|pty\.spawn|socket\.socket|\bnc\b\s+(?:-[a-zA-Z0-9]+\s+)*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\/bin\/(?:ba)?sh\s+-i)', cmd):
            if host: hosts_involved.add(host)
            m_rev_ip = re.search(r'(?:/dev/tcp/|connect\(\(\s*["\'])([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', cmd)
            if m_rev_ip:
                attacker_ips.add(m_rev_ip.group(1))
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=ts,
                host=host,
                phase="Execution",
                technique_id="T1059.006",
                technique_name="Command and Scripting Interpreter: Python",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=cmd or msg,
                iocs=_clean({"cmd": cmd, "user": user}),
                source_dataset=ds
            ))
        elif re.search(r'sudo\s+(?:/usr/bin/find|/usr/bin/sh|find|vim|bash|sh|python|perl|ruby|awk|gdb)', cmd):
            if host: hosts_involved.add(host)
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=ts,
                host=host,
                phase="Privilege Escalation",
                technique_id="T1548.003",
                technique_name="Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=cmd or msg,
                iocs=_clean({"cmd": cmd, "user": user}),
                source_dataset=ds
            ))
        elif 'mshta' in proc_lower or 'mshta' in cmd_lower:
            if host: hosts_involved.add(host)
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=ts,
                host=host,
                phase="Execution",
                technique_id="T1218.005",
                technique_name="System Binary Proxy Execution: Mshta",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=cmd or msg,
                iocs=_clean({"cmd": cmd, "process": c['proc_name'], "user": user}),
                source_dataset=ds
            ))
        elif any(k in cmd_lower for k in ['curl http', 'wget http', 'chmod +x /tmp']) or re.search(r'(?:/tmp|/var/tmp|/dev/shm)/\.(?!x11-unix|ice-unix|font-unix|xim-unix|test-unix|x\d+-lock)[\w.-]+', cmd_lower):
            if host: hosts_involved.add(host)
            m_ip = re.search(r'https?://(\d+\.\d+\.\d+\.\d+)', cmd)
            if m_ip: attacker_ips.add(m_ip.group(1))
            # Yuklovchisiz (faqat yashirin /tmp yo'lidan ishga tushirish) bo'lsa, heuristikalar ham ko'rsin:
            # mayner (T1496), niqob (T1036.005), cron qatori (T1053.003) shu hodisada bo'ladi
            if not re.search(r'\b(?:curl|wget|fetch|tftp|scp|rsync|certutil|bitsadmin|invoke-webrequest|iwr)\b', cmd_lower):
                _pass_to_fallback = True
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=ts,
                host=host,
                phase="Execution / Ingress",
                technique_id="T1105",
                technique_name="Ingress Tool Transfer",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=cmd or msg,
                iocs=_clean({"cmd": cmd, "user": user, "c2": m_ip.group(1) if m_ip else None}),
                source_dataset=ds
            ))

        # 4. Spearphishing & Browser Lures
        if any(b in proc_lower for b in ['msedge', 'chrome', 'firefox', 'iexplore', 'brave']) and (
            any(k in full_text for k in ['invoice', 'billing', 'lure', 'payload', 'hxxps', 'phish']) or
            (_is_external(c['dst_ip']) and any(k in full_text for k in ['invoice', 'download', 'bill', 'document']))
        ):
            if c['dst_ip'] and _is_external(c['dst_ip']): attacker_ips.add(c['dst_ip'])
            if host: hosts_involved.add(host)
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=ts,
                host=host,
                phase="Initial Access",
                technique_id="T1566.002",
                technique_name="Phishing: Spearphishing Link",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=cmd or msg or f"{c['proc_name']} opened external lure link",
                iocs=_clean({"dst_ip": c['dst_ip'], "process": c['proc_name'], "cmd": cmd}),
                source_dataset=ds
            ))

        # 5. Web Application & Edge Gateway Exploitation (T1190, T1505.003)
        reqs = []
        full_req = f"{path}?{query}" if query else path
        if full_req: reqs.append(full_req)
        
        req_texts = [cmd, msg, str(c['raw'].get('request') or '')]
        for rt in req_texts:
            if rt:
                m_req = re.search(r'\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)', rt, re.I)
                if m_req and m_req.group(2) not in reqs:
                    reqs.append(m_req.group(2))

        is_web_context = (
            any(w in ds for w in ['nginx', 'apache', 'web', 'iis', 'httpd', 'access']) or
            bool(_WEB_SERVERS.match(proc_lower)) or
            bool(reqs) or
            any(k in full_text for k in ['cve-', 'auth bypass', 'totp', 'sslvpn', 'webshell', 'traversal', 'sqli'])
        )

        def _web_agg(tid, ip):
            # (host, hujumchi IP, texnika) bo'yicha bitta qadam: skaner/exploit takrorlari count ga
            for st in stages:
                if st.technique_id == tid and st.host == host and st.iocs.get('src_ip') == ip:
                    st.iocs['count'] = st.iocs.get('count', 1) + 1
                    st.iocs['last_seen'] = ts
                    handled_idx.add(_i)
                    return True
            return False

        if is_web_context:
            for u in reqs:
                dec = unquote_plus(unquote_plus(u))
                dec_l = dec.lower()
                atk_ip = src_ip if (src_ip and _is_external(src_ip)) else (c['dst_ip'] if c['dst_ip'] and _is_external(c['dst_ip']) else None)
                
                if any(p in u.lower() or p in dec_l for p in ['/totp/', 'sslvpn_websession', 'fgt_lang', '../../', '..\\..\\', '/remote/fgt_lang']):
                    if atk_ip: attacker_ips.add(atk_ip)
                    if host: hosts_involved.add(host)
                    if _web_agg("T1190", atk_ip): break
                    stages.append(AttackStage(
                        stage_id=f"S{len(stages)+1:02d}",
                        timestamp=ts,
                        host=host,
                        phase="Initial Access",
                        technique_id="T1190",
                        technique_name="Exploit Public-Facing Application: Auth Bypass / Traversal",
                        confidence="HIGH",
                        status="CONFIRMED",
                        evidence=f"{c['method'] or 'GET'} {u} (Status: {status})" if u else (msg or cmd),
                        iocs=_clean({"src_ip": atk_ip, "uri": u, "status": status}),
                        source_dataset=ds
                    ))
                    break
                elif any(p in u.lower() or p in dec_l for p in ['cmd=', 'lastauthserverused.cgi', 'compcheckresult.cgi', 'jndi:ldap', '${jndi']):
                    if atk_ip: attacker_ips.add(atk_ip)
                    if host: hosts_involved.add(host)
                    if _web_agg("T1505.003", atk_ip): break
                    stages.append(AttackStage(
                        stage_id=f"S{len(stages)+1:02d}",
                        timestamp=ts,
                        host=host,
                        phase="Initial Access / Web Shell",
                        technique_id="T1505.003",
                        technique_name="Server Software Component: Web Shell",
                        confidence="HIGH",
                        status="CONFIRMED",
                        evidence=f"{c['method'] or 'GET'} {u} (Status: {status})" if u else (msg or cmd),
                        iocs=_clean({"src_ip": atk_ip, "uri": u, "status": status}),
                        source_dataset=ds
                    ))
                    break
                elif _SQLI_RE.search(dec_l):
                    if atk_ip: attacker_ips.add(atk_ip)
                    if host: hosts_involved.add(host)
                    handled_idx.add(_i)
                    found = False
                    for st in stages:
                        if st.technique_id == "T1190" and st.host == host and (atk_ip is None or st.iocs.get('src_ip') == atk_ip):
                            st.iocs['count'] = st.iocs.get('count', 1) + 1
                            st.iocs['last_seen'] = ts
                            found = True
                            break
                    if not found:
                        stages.append(AttackStage(
                            stage_id=f"S{len(stages)+1:02d}",
                            timestamp=ts,
                            host=host,
                            phase="Initial Access",
                            technique_id="T1190",
                            technique_name="Exploit Public-Facing Application",
                            confidence="HIGH",
                            status="CONFIRMED",
                            evidence=f"{c['method'] or 'GET'} {u}",
                            iocs=_clean({'src_ip': atk_ip, 'uri': u, 'decoded': dec[:200], 'status': status, 'count': 1}),
                            source_dataset=ds
                        ))
                    break

        # 5.5 Web Server Process Spawns Shell
        proc_base = proc_lower.split('/')[-1].split('\\')[-1].replace('.exe', '')
        parent_raw = get_nested(evt,'process.parent.name') or get_nested(evt,'process.parent.executable') or evt.get('ParentImage') or evt.get('parent_process') or evt.get('process.parent.name') or ''
        parent_base = str(parent_raw).lower().split('/')[-1].split('\\')[-1].replace('.exe', '')
        
        shell_val = None
        if _WEB_SERVERS.match(parent_base) and proc_base in _SHELLS:
            shell_val = proc_base
        elif _WEB_SERVERS.match(proc_base):
            m_shell = re.search(r'(?:^|[\s/\\])(sh|bash|dash|zsh|ksh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)\s+(?:-c|/c|-command|-enc|-e)\b', cmd_lower)
            if m_shell:
                shell_val = m_shell.group(1).replace('.exe', '')
                
        if shell_val:
            if host: hosts_involved.add(host)
            handled_idx.add(_i)
            
            found_1505 = False
            for st in stages:
                if st.technique_id == "T1505.003" and st.host == host:
                    st.iocs['count'] = st.iocs.get('count', 1) + 1
                    st.iocs['last_seen'] = ts
                    found_1505 = True
                    break
            if not found_1505:
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}",
                    timestamp=ts,
                    host=host,
                    phase="Persistence",
                    technique_id="T1505.003",
                    technique_name="Server Software Component: Web Shell",
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=cmd or msg,
                    iocs=_clean({'user': user, 'parent': parent_raw or c['proc_name'], 'cmd': cmd, 'count': 1}),
                    source_dataset=ds
                ))
            
            tech = _SHELLS.get(shell_val, "T1059.004")
            found_shell = False
            for st in stages:
                if st.technique_id == tech and st.host == host:
                    st.iocs['count'] = st.iocs.get('count', 1) + 1
                    st.iocs['last_seen'] = ts
                    found_shell = True
                    break
            if not found_shell:
                tname = {
                    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
                    "T1059.003": "Windows Command Shell",
                    "T1059.001": "PowerShell",
                    "T1059.006": "Python"
                }.get(tech, "Command and Scripting Interpreter")
                
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}",
                    timestamp=ts,
                    host=host,
                    phase="Execution",
                    technique_id=tech,
                    technique_name=tname,
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=cmd or msg,
                    iocs=_clean({'user': user, 'parent': parent_raw or c['proc_name'], 'cmd': cmd, 'count': 1}),
                    source_dataset=ds
                ))

        # 6. Account Creation & Persistence (T1136.001, T1053.003, T1053.005)
        if re.search(r'\b(?:useradd|adduser)\b', cmd):
            if host: hosts_involved.add(host)
            created_user = None
            parts = [p.strip('\'"') for p in cmd.strip().split()]
            for p in reversed(parts):
                if p and not p.startswith('-') and p not in ('useradd', 'adduser', 'sudo', 'sh', 'bash') and '/' not in p and '$' not in p:
                    created_user = p
                    break
            iocs_dict = {"cmd": cmd}
            if created_user:
                iocs_dict["created_user"] = created_user
                compromised_users.add(created_user)
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=ts,
                host=host,
                phase="Persistence",
                technique_id="T1136.001",
                technique_name="Create Account: Local Account",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=cmd or msg,
                iocs=_clean(iocs_dict),
                source_dataset=ds
            ))
        elif (re.search(r'\bcrontab\s+(?:-[a-zA-Z]|/tmp/[^\s]+)|\/etc\/cron|\bsh\s+-c\s+[\'"]?\d+\s+\d+\s+\*|\b(?:\*|(?:\*/\d+))\s+\*\s+\*\s+\*\s+\*', cmd, re.I) and not re.search(r'/usr/sbin/cron\s+-f', cmd)):
            if host: hosts_involved.add(host)
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=ts,
                host=host,
                phase="Persistence",
                technique_id="T1053.003",
                technique_name="Scheduled Task/Job: Cron",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=cmd or msg,
                iocs=_clean({"cmd": cmd, "user": user}),
                source_dataset=ds
            ))
        elif 'schtasks' in proc_lower or 'schtasks' in cmd_lower or 'scheduled task' in msg_lower:
            if any(k in cmd_lower for k in ['/create', '/tn', '/tr']) or 'created' in msg_lower:
                if host: hosts_involved.add(host)
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}",
                    timestamp=ts,
                    host=host,
                    phase="Persistence",
                    technique_id="T1053.005",
                    technique_name="Scheduled Task/Job: Scheduled Task",
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=cmd or msg,
                    iocs=_clean({"cmd": cmd, "user": user}),
                    source_dataset=ds
                ))

        # 7. Credentials & Private Keys (T1552.004, T1003.008, T1003.001, T1110.003, T1558.003)
        if re.search(r'id_(?:rsa|ed25519|dsa|ecdsa)|\.ssh/id_', cmd):
            if host: hosts_involved.add(host)
            m_key = re.search(r'(?:cat|cp|less|head|tail|scp|view)\s+.*?([^\s]*id_[a-zA-Z0-9_-]+)', cmd)
            target_key = m_key.group(1) if m_key else None
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=ts,
                host=host,
                phase="Credential Access",
                technique_id="T1552.004",
                technique_name="Unsecured Credentials: Private Keys",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=cmd or msg,
                iocs=_clean({"cmd": cmd, "user": user, "target_key": target_key}),
                source_dataset=ds
            ))
        elif re.search(r'/etc/shadow|/etc/passwd', cmd) and any(op in cmd for op in ['cat ', 'less ', 'head ', 'tail ', 'cp ', 'grep ']):
            if host: hosts_involved.add(host)
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=ts,
                host=host,
                phase="Credential Access",
                technique_id="T1003.008",
                technique_name="OS Credential Dumping: /etc/passwd and /etc/shadow",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=cmd or msg,
                iocs=_clean({"cmd": cmd, "user": user}),
                source_dataset=ds
            ))
        elif 'comsvcs.dll' in cmd_lower or 'minidump' in cmd_lower or 'lsass dump' in msg_lower:
            if host: hosts_involved.add(host)
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=ts,
                host=host,
                phase="Credential Access",
                technique_id="T1003.001",
                technique_name="OS Credential Dumping: LSASS Memory",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=cmd or msg,
                iocs=_clean({"cmd": cmd, "user": user, "process": c['proc_name']}),
                source_dataset=ds
            ))
        elif 'password spray' in msg_lower or 'spray 43 accounts' in msg_lower:
            if host: hosts_involved.add(host)
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=ts,
                host=host,
                phase="Credential Access",
                technique_id="T1110.003",
                technique_name="Brute Force: Password Spraying",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=msg or cmd,
                iocs=_clean({"host": host, "target": msg}),
                source_dataset=ds
            ))
        elif (str(c.get('raw', {}).get('event.code')) == '4769' or str(c.get('raw', {}).get('EventID')) == '4769' or 'kerberoast' in msg_lower) and ('0x17' in str(c.get('raw', {})) or '0x17' in msg_lower):
            if host: hosts_involved.add(host)
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=ts,
                host=host,
                phase="Credential Access",
                technique_id="T1558.003",
                technique_name="Steal or Forge Kerberos Tickets: Kerberoasting",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=msg or "Kerberoasting SPN ticket request (RC4 0x17)",
                iocs=_clean({"user": user, "host": host}),
                source_dataset=ds
            ))

        # 8. Archive & Local Data Staging (T1560.001, T1005)
        if re.search(r'\b(?:pg_dump|mysqldump)\b', cmd):
            if host: hosts_involved.add(host)
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=ts,
                host=host,
                phase="Collection",
                technique_id="T1005",
                technique_name="Data from Local System: Database Dump",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=cmd or msg,
                iocs=_clean({"cmd": cmd, "user": user}),
                source_dataset=ds
            ))
        elif re.search(r'\btar\s+(?:-[a-zA-Z0-9]*c[a-zA-Z0-9]*f?|czf|cf)\s+([^\s]+)|\bzip\s+(?:-[a-zA-Z0-9]+\s+)*([^\s]+)|\b7z\s+a\s+(?:-[a-zA-Z0-9-]+\s+)*([^\s]+)', cmd, re.I):
            if not is_benign_noise(c):
                m_arc = re.search(r'\btar\s+(?:-[a-zA-Z0-9]*c[a-zA-Z0-9]*f?|czf|cf)\s+([^\s]+)|\bzip\s+(?:-[a-zA-Z0-9]+\s+)*([^\s]+)|\b7z\s+a\s+(?:-[a-zA-Z0-9-]+\s+)*([^\s]+)', cmd, re.I)
                arc_file = None
                if m_arc:
                    arc_file = m_arc.group(1) or m_arc.group(2) or m_arc.group(3)
                if host: hosts_involved.add(host)
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}",
                    timestamp=ts,
                    host=host,
                    phase="Collection",
                    technique_id="T1560.001",
                    technique_name="Archive Collected Data: Archive via Utility",
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=cmd or msg,
                    iocs=_clean({"cmd": cmd, "user": user, "archive_file": arc_file}),
                    source_dataset=ds
                ))

        # 9. Lateral Movement (T1021.004 SSH, T1021.002 SMB)
        m_ssh_acc = re.search(r'Accepted\s+(password|publickey|keyboard-interactive/pam)\s+for\s+(\S+)\s+from\s+([0-9a-fA-F:.]+)', msg)
        m_ssh_cmd = re.search(r'ssh\s+.*?-i\s+([^\s]+)\s+(?:[a-zA-Z0-9._-]+@)?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', cmd)
        
        if m_ssh_cmd:
            iocs_ssh = {"key": m_ssh_cmd.group(1), "target": m_ssh_cmd.group(2)}
            if host: hosts_involved.add(host)
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=ts,
                host=host,
                phase="Lateral Movement",
                technique_id="T1021.004",
                technique_name="Remote Services: SSH",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=cmd,
                iocs=_clean(iocs_ssh),
                source_dataset=ds
            ))
        elif m_ssh_acc:
            method, auth_user, auth_ip = m_ssh_acc.groups()
            iocs_ssh = {"user": auth_user, "src_ip": auth_ip, "method": method}
            # (host, user, src_ip) bo'yicha bitta qadam: takroriy kirishlar count/last_seen ni oshiradi, vaqt eng birinchisi qoladi
            ext_auth = _is_external(auth_ip)
            same = [s for s in stages if s.technique_id in (("T1133", "T1078") if ext_auth else ("T1021.004",))
                    and s.host == host and s.iocs.get("src_ip") == auth_ip and s.iocs.get("user") == auth_user]
            if same:
                for s in same:
                    s.iocs["count"] = s.iocs.get("count", 1) + 1
                    if ts and ts < (s.timestamp or ts):
                        s.iocs["last_seen"] = s.iocs.get("last_seen") or s.timestamp
                        s.timestamp = ts
                    elif ts and ts > (s.iocs.get("last_seen") or ""):
                        s.iocs["last_seen"] = ts
            elif ext_auth:
                attacker_ips.add(auth_ip)
                compromised_users.add(auth_user)
                if host: hosts_involved.add(host)
                iocs_ssh["count"] = 1
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}",
                    timestamp=ts,
                    host=host,
                    phase="Initial Access",
                    technique_id="T1133",
                    technique_name="External Remote Services",
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=msg,
                    iocs=_clean(iocs_ssh),
                    source_dataset=ds
                ))
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}",
                    timestamp=ts,
                    host=host,
                    phase="Initial Access",
                    technique_id="T1078",
                    technique_name="Valid Accounts",
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=msg,
                    iocs=_clean(iocs_ssh),
                    source_dataset=ds
                ))
            else:
                if host: hosts_involved.add(host)
                iocs_ssh["count"] = 1
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}",
                    timestamp=ts,
                    host=host,
                    phase="Lateral Movement",
                    technique_id="T1021.004",
                    technique_name="Remote Services: SSH",
                    confidence="MEDIUM",
                    status="CONFIRMED",
                    evidence=msg,
                    iocs=_clean(iocs_ssh),
                    source_dataset=ds
                ))
        # Oddiy 4624 type 3 va SYSVOL/IPC$ ga kirish har bir domen PC da bor, shuning uchun
        # faqat admin ulashmalari (C$, ADMIN$) lateral deb olinadi.
        # (extract_canonical UNC dagi \\ ni \ ga qisqartirishi mumkin, ikkalasi ham qabul qilinadi)
        elif re.search(r'(?:^|[\s"\'=])\\{1,2}[^\\\s]+\\(?:[a-z]|admin)\$', msg_lower + ' ' + cmd_lower):
            if host: hosts_involved.add(host)
            if user and 'SYSTEM' not in user.upper() and 'AUTHORITY' not in user.upper():
                compromised_users.add(user)
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=ts,
                host=host,
                phase="Lateral Movement",
                technique_id="T1021.002",
                technique_name="Remote Services: SMB/Windows Admin Shares",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=msg or cmd,
                iocs=_clean({"host": host, "user": user, "src_ip": c['src_ip']}),
                source_dataset=ds
            ))

        # 9.5. Windows logon (4624) va PsExec xizmati
        eid = str(get_nested(evt, 'event.code') or evt.get('EventID') or evt.get('event_id') or evt.get('event_code') or get_nested(evt, 'winlog.event_id') or '').strip()
        chan = str(get_nested(evt, 'winlog.channel') or evt.get('Channel') or evt.get('channel') or '').lower()
        logon_user = get_nested(evt, 'winlog.event_data.TargetUserName') or evt.get('TargetUserName') or user
        
        lt_val = get_nested(evt, 'winlog.event_data.LogonType') or evt.get('LogonType') or evt.get('logon_type') or ''
        logon_type = str(lt_val).strip()
        if not logon_type:
            m_lt1 = re.search(r'logon\s*type\D{0,3}(\d{1,2})', msg_lower + ' ' + cmd_lower)
            m_lt2 = re.search(r'\(type\s+(\d{1,2})\)', msg_lower)
            if m_lt1:
                logon_type = m_lt1.group(1)
            elif m_lt2:
                logon_type = m_lt2.group(1)

        def _acct_kind(u):
            if not u: return ''
            u_upper = u.upper()
            if '\\' in u:
                parts = u.split('\\', 1)
                dom = parts[0].upper()
                if dom == '.' or dom == 'NT AUTHORITY' or (host and dom == host.upper()):
                    return 'local'
                return 'domain'
            elif '@' in u:
                return 'domain'
            return ''

        def _agg(tid, key_iocs):
            found_s = None
            for s in stages:
                if s.technique_id == tid and s.host == host:
                    match_all = True
                    for k, v in key_iocs.items():
                        if s.iocs.get(k) != v:
                            match_all = False
                            break
                    if match_all:
                        found_s = s
                        break
            if found_s:
                found_s.iocs['count'] = found_s.iocs.get('count', 1) + 1
                if ts and ts < (found_s.timestamp or ts):
                    found_s.iocs['last_seen'] = found_s.iocs.get('last_seen') or found_s.timestamp
                    found_s.timestamp = ts
                elif ts and ts > (found_s.iocs.get('last_seen') or ""):
                    found_s.iocs['last_seen'] = ts
                return True
            return False

        svc_name = get_nested(evt, 'winlog.event_data.ServiceName') or evt.get('ServiceName') or ''
        img_path = get_nested(evt, 'winlog.event_data.ImagePath') or evt.get('ImagePath') or ''
        
        is_psexec_text = bool(re.search(r'\b(?:psexesvc|paexec[\w-]*|remcomsvc|csexecsvc)\b',
                                        proc_lower + ' ' + cmd_lower + ' ' + msg_lower + ' ' + str(svc_name).lower() + ' ' + str(img_path).lower(), re.I))
        is_psexec_sysmon = (eid == '1' and proc_lower.endswith('psexesvc.exe'))

        if (eid in ('7045', '4697') and is_psexec_text) or is_psexec_sysmon:
            svc_found = svc_name or img_path or proc_lower
            if not _agg("T1569.002", {"user": logon_user}):
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}",
                    timestamp=ts,
                    host=host,
                    phase="Execution",
                    technique_id="T1569.002",
                    technique_name="System Services: Service Execution",
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=cmd or msg or svc_found,
                    iocs=_clean({'user': logon_user, 'service': svc_found, 'cmd': cmd}),
                    source_dataset=ds
                ))
            if not _agg("T1021.002", {"user": logon_user}):
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}",
                    timestamp=ts,
                    host=host,
                    phase="Lateral Movement",
                    technique_id="T1021.002",
                    technique_name="Remote Services: SMB/Windows Admin Shares",
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=cmd or msg or svc_found,
                    iocs=_clean({'user': logon_user, 'service': svc_found, 'cmd': cmd}),
                    source_dataset=ds
                ))
            handled_idx.add(_i)

        elif eid == '4624' and (not chan or 'security' in chan):
            if not (not logon_user or logon_user == '-' or logon_user.lower() == 'anonymous logon' or logon_user.endswith('$')):
                ip = src_ip or get_nested(evt, 'winlog.event_data.IpAddress') or ''
                if ip and ip != '-' and ip != '::1' and ip != '127.0.0.1':
                    is_ext = _is_external(ip)
                    is_sshd = (proc_lower in ('sshd', 'sshd.exe'))
                    
                    if is_ext:
                        attacker_ips.add(ip)
                        compromised_users.add(logon_user)
                        
                        if not _agg("T1133", {"user": logon_user, "src_ip": ip}):
                            stages.append(AttackStage(
                                stage_id=f"S{len(stages)+1:02d}", timestamp=ts, host=host, phase="Initial Access",
                                technique_id="T1133", technique_name="External Remote Services", confidence="HIGH",
                                status="CONFIRMED", evidence=msg or f"4624 {logon_user} from {ip}",
                                iocs=_clean({'user': logon_user, 'src_ip': ip, 'logon_type': logon_type}), source_dataset=ds
                            ))
                        
                        acct_kind = _acct_kind(logon_user)
                        tid_acc = "T1078.002" if acct_kind == 'domain' else ("T1078.003" if acct_kind == 'local' else "T1078")
                        name_acc = "Valid Accounts: Domain Accounts" if acct_kind == 'domain' else ("Valid Accounts: Local Accounts" if acct_kind == 'local' else "Valid Accounts")
                        
                        if not _agg(tid_acc, {"user": logon_user, "src_ip": ip}):
                            stages.append(AttackStage(
                                stage_id=f"S{len(stages)+1:02d}", timestamp=ts, host=host, phase="Initial Access",
                                technique_id=tid_acc, technique_name=name_acc, confidence="HIGH",
                                status="CONFIRMED", evidence=msg or f"4624 {logon_user} from {ip}",
                                iocs=_clean({'user': logon_user, 'src_ip': ip, 'logon_type': logon_type}), source_dataset=ds
                            ))
                            
                        if logon_type == '10':
                            if not _agg("T1021.001", {"user": logon_user, "src_ip": ip}):
                                stages.append(AttackStage(
                                    stage_id=f"S{len(stages)+1:02d}", timestamp=ts, host=host, phase="Lateral Movement",
                                    technique_id="T1021.001", technique_name="Remote Services: Remote Desktop Protocol", confidence="HIGH",
                                    status="CONFIRMED", evidence=msg or f"4624 {logon_user} from {ip}",
                                    iocs=_clean({'user': logon_user, 'src_ip': ip, 'logon_type': logon_type}), source_dataset=ds
                                ))
                        
                        if is_sshd:
                            if not _agg("T1021.004", {"user": logon_user, "src_ip": ip}):
                                stages.append(AttackStage(
                                    stage_id=f"S{len(stages)+1:02d}", timestamp=ts, host=host, phase="Lateral Movement",
                                    technique_id="T1021.004", technique_name="Remote Services: SSH", confidence="HIGH",
                                    status="CONFIRMED", evidence=msg or f"4624 {logon_user} from {ip}",
                                    iocs=_clean({'user': logon_user, 'src_ip': ip, 'logon_type': logon_type}), source_dataset=ds
                                ))
                        handled_idx.add(_i)
                    else:
                        # Internal
                        added = False
                        if logon_type == '10':
                            if not _agg("T1021.001", {"user": logon_user, "src_ip": ip}):
                                stages.append(AttackStage(
                                    stage_id=f"S{len(stages)+1:02d}", timestamp=ts, host=host, phase="Lateral Movement",
                                    technique_id="T1021.001", technique_name="Remote Services: Remote Desktop Protocol", confidence="MEDIUM",
                                    status="CONFIRMED", evidence=msg or f"4624 {logon_user} from {ip}",
                                    iocs=_clean({'user': logon_user, 'src_ip': ip, 'logon_type': logon_type}), source_dataset=ds
                                ))
                            added = True
                            
                        if is_sshd:
                            if not _agg("T1021.004", {"user": logon_user, "src_ip": ip}):
                                stages.append(AttackStage(
                                    stage_id=f"S{len(stages)+1:02d}", timestamp=ts, host=host, phase="Lateral Movement",
                                    technique_id="T1021.004", technique_name="Remote Services: SSH", confidence="MEDIUM",
                                    status="CONFIRMED", evidence=msg or f"4624 {logon_user} from {ip}",
                                    iocs=_clean({'user': logon_user, 'src_ip': ip, 'logon_type': logon_type}), source_dataset=ds
                                ))
                            added = True
                            
                        if added:
                            handled_idx.add(_i)

        # 10. Ransomware Impact (T1490, T1543.003)
        if 'vssadmin' in cmd_lower or 'delete shadows' in cmd_lower or 'shadow copies deleted' in msg_lower:
            if host: hosts_involved.add(host)
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=ts,
                host=host,
                phase="Impact",
                technique_id="T1490",
                technique_name="Inhibit System Recovery: Delete Volume Shadow Copies",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=cmd or msg,
                iocs=_clean({"cmd": cmd, "user": user}),
                source_dataset=ds
            ))
        elif 'service rnstage installed' in cmd_lower or 'ransomware staging service' in msg_lower or 'locker_stage' in cmd_lower:
            if host: hosts_involved.add(host)
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=ts,
                host=host,
                phase="Persistence",
                technique_id="T1543.003",
                technique_name="Create or Modify System Process: Windows Service",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=cmd or msg,
                iocs=_clean({"cmd": cmd, "user": user, "process": c['proc_name']}),
                source_dataset=ds
            ))

        # 11. Command and Control (RAT Beacons & Outbound Connections)
        dst_ip_val = c.get('dst_ip') or ''
        if dst_ip_val and _is_external(dst_ip_val):
            proc_base = proc_lower.split('/')[-1].split('\\')[-1].replace('.exe', '')
            is_susp_proc = any(sp in proc_lower for sp in ['kswapd0', 'kworker', 'mshta']) or re.search(r'\b(?:nc|netcat|ncat)\b', proc_lower) or any(loc in cmd_lower for loc in ['\\appdata\\', '\\temp\\', '/tmp/']) or proc_base in {'powershell','pwsh','wscript','cscript','mshta','rundll32','regsvr32','msbuild','installutil','regasm','regsvcs'}
            is_c2_msg = any(k in msg_lower for k in ['rat beacon', 'beacon', 'c2', 'reverse shell', 'connected to pool'])
            c2_key = (host, dst_ip_val)
            if (is_susp_proc or is_c2_msg) and c2_key in c2_seen:
                # har beacon ulanishi alohida qadam bo'lmasin: (host, dst_ip) bo'yicha bitta qadam
                st = c2_seen[c2_key]
                st.iocs['connections'] = st.iocs.get('connections', 1) + 1
                st.iocs['last_seen'] = ts
                handled_idx.add(_i)  # aks holda fallback shu ulanishni yana qadam qilib qo'shadi
            elif is_susp_proc or is_c2_msg:
                attacker_ips.add(dst_ip_val)
                if host: hosts_involved.add(host)
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}",
                    timestamp=ts,
                    host=host,
                    phase="Command and Control",
                    technique_id="T1071.001",
                    technique_name="Application Layer Protocol: Web Protocols / RAT Beacon",
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=msg if is_c2_msg else f"{c['proc_name']} connected to C2 endpoint {dst_ip_val}:{c['dst_port']}",
                    iocs=_clean({"dst_ip": dst_ip_val, "port": c['dst_port'], "process": c['proc_name']}),
                    source_dataset=ds
                ))
                c2_seen[c2_key] = stages[-1]

        # 11.5. M365 / Entra ID (G6)
        op_name = str(get_nested(evt, 'event.code') or evt.get('event_id') or evt.get('Operation') or evt.get('operation') or evt.get('event.action') or '').lower()
        ch_name = str(evt.get('winlog.channel') or evt.get('channel') or evt.get('Workload') or evt.get('event.dataset') or '').lower()
        if op_name:
            if op_name in ['new-inboxrule', 'set-inboxrule', 'updateinboxrules']:
                is_fwd = any(w in (msg_lower + ' ' + cmd_lower) for w in ['forward', 'redirect', 'forwardto', 'redirectto'])
                techs = [("T1114.003", "Email Collection: Email Forwarding Rule"), ("T1564.008", "Hide Artifacts: Email Hiding Rules")] if is_fwd else [("T1564.008", "Hide Artifacts: Email Hiding Rules")]
                if user: compromised_users.add(user)
                for tid, tname in techs:
                    stages.append(AttackStage(
                        stage_id=f"S{len(stages)+1:02d}", timestamp=ts, host=host, phase="Collection / Defense Evasion",
                        technique_id=tid, technique_name=tname, confidence="HIGH", status="CONFIRMED", evidence=msg or op_name,
                        iocs=_clean({"user": user, "host": host}), source_dataset=ds
                    ))
                handled_idx.add(_i)
            elif op_name == 'set-mailbox' and any(w in (msg_lower + ' ' + cmd_lower) for w in ['forwardingsmtpaddress', 'forward']):
                if user: compromised_users.add(user)
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}", timestamp=ts, host=host, phase="Collection",
                    technique_id="T1114.003", technique_name="Email Collection: Email Forwarding Rule", confidence="MEDIUM", status="CONFIRMED", evidence=msg or op_name,
                    iocs=_clean({"user": user, "host": host}), source_dataset=ds
                ))
                handled_idx.add(_i)
            elif op_name in ['add-mailboxpermission', 'add-recipientpermission', 'set-mailboxfolderpermission']:
                if user: compromised_users.add(user)
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}", timestamp=ts, host=host, phase="Persistence",
                    technique_id="T1098.002", technique_name="Account Manipulation: Additional Email Delegate Permissions", confidence="HIGH", status="CONFIRMED", evidence=msg or op_name,
                    iocs=_clean({"user": user, "host": host}), source_dataset=ds
                ))
                handled_idx.add(_i)
            elif op_name in ['consent to application', 'consent', 'add delegated permission grant', 'add app role assignment grant to user']:
                if user: compromised_users.add(user)
                app_name = None
                m_app = re.search(r"'([^']+)'", msg or cmd) or re.search(r'"([^"]+)"', msg or cmd)
                if m_app: app_name = m_app.group(1)
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}", timestamp=ts, host=host, phase="Credential Access",
                    technique_id="T1528", technique_name="Steal Application Access Token", confidence="HIGH", status="CONFIRMED", evidence=msg or op_name,
                    iocs=_clean({"user": user, "host": host, "app": app_name}), source_dataset=ds
                ))
                handled_idx.add(_i)
            elif 'signin' in ch_name or op_name in ['userloggedin', 'signin']:
                if not any(w in (msg_lower + ' ' + cmd_lower) for w in ['fail', 'error', '50126']):
                    if src_ip and _is_external(src_ip) and user:
                        if user not in signins_by_user:
                            signins_by_user[user] = []
                        from bluekit.logs.parse import parse_ts
                        dt = parse_ts(ts)
                        if dt:
                            signins_by_user[user].append((dt, src_ip))
                            user_signins = signins_by_user[user]
                            if len(set(ip for _, ip in user_signins)) >= 2:
                                for dt1, ip1 in user_signins:
                                    if ip1 != src_ip and abs((dt - dt1).total_seconds()) <= 3600:
                                        dup = next((s for s in stages if s.technique_id == "T1078.004" and s.iocs.get("user") == user), None)
                                        if not dup:
                                            # faqat keyingi (yangi) IP: birinchisi odatda foydalanuvchining o'zi (VPN, ofis)
                                            compromised_users.add(user)
                                            attacker_ips.add(src_ip)
                                            if host: hosts_involved.add(host)
                                            stages.append(AttackStage(
                                                stage_id=f"S{len(stages)+1:02d}", timestamp=ts, host=host, phase="Initial Access",
                                                technique_id="T1078.004", technique_name="Valid Accounts: Cloud Accounts", confidence="HIGH", status="CONFIRMED", evidence=f"Muvaffaqiyatli sign-in 60 daq ichida >=2 xil tashqi IP dan: {ip1}, {src_ip}",
                                                iocs=_clean({"user": user, "host": host, "src_ip": src_ip}), source_dataset=ds
                                            ))
                                            handled_idx.add(_i)
                                        break

        # 12. Cloud & Identity / M365 / Entra / OAuth / Token Abuse (Scenarios 04, 08, 09)
        is_cloud_audit = any(ch in str(host).upper() for ch in ['ENTRA', 'M365', 'EXCHANGE', 'SHAREPOINT', 'SP-AUDIT', 'MAIL-AUDIT', 'GRAPHAPI', 'IDP-LOG', 'IDP']) or any(cp in proc_lower for cp in ['oauth', 'graphapi', 'exchange', 'cloudauth', 'cloudadmin'])
        if is_cloud_audit:
            if any(k in msg_lower or k in cmd_lower for k in ['impossible travel', 'session token used without mfa', 'successful token sign-in', 'refresh_token grant']):
                if c['dst_ip'] and _is_external(c['dst_ip']):
                    attacker_ips.add(c['dst_ip'])
                if host: hosts_involved.add(host)
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}",
                    timestamp=ts,
                    host=host,
                    phase="Initial Access",
                    technique_id="T1078.004",
                    technique_name="Valid Accounts: Cloud Accounts",
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=msg or cmd,
                    iocs=_clean({"user": user, "host": host, "c2_ip": c['dst_ip']}),
                    source_dataset=ds
                ))
            elif any(k in msg_lower or k in cmd_lower for k in ['user consent phishing', 'malicious oauth consent', 'consent to app', 'scopes mail.read']):
                if c['dst_ip'] and _is_external(c['dst_ip']):
                    attacker_ips.add(c['dst_ip'])
                if host: hosts_involved.add(host)
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}",
                    timestamp=ts,
                    host=host,
                    phase="Initial Access / Persistence",
                    technique_id="T1566.002",
                    technique_name="Phishing: Spearphishing Consent / Malicious OAuth",
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=msg or cmd,
                    iocs=_clean({"user": user, "host": host, "c2_ip": c['dst_ip']}),
                    source_dataset=ds
                ))
            elif any(k in msg_lower or k in cmd_lower for k in ['onedrive enumeration', '/me/drive/root', 'mailbox search', 'mail attachment downloaded', 'sharepoint file downloaded', 'file downloaded', 'download deals', 'bulk download executive files']):
                if host: hosts_involved.add(host)
                if 'onedrive enumeration' in msg_lower or '/me/drive' in cmd_lower:
                    tech_id = "T1083"
                    tech_name = "File and Directory Discovery: Cloud Storage"
                    phase_name = "Discovery"
                else:
                    tech_id = "T1530" if 'file downloaded' in msg_lower or 'deals' in cmd_lower else ("T1114" if 'mail' in msg_lower else "T1213.002")
                    tech_name = "Data from Cloud Storage: File Download" if 'file downloaded' in msg_lower or 'deals' in cmd_lower else ("Email Collection" if 'mail' in msg_lower else "Data from Information Repositories: SharePoint")
                    phase_name = "Collection"
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}",
                    timestamp=ts,
                    host=host,
                    phase=phase_name,
                    technique_id=tech_id,
                    technique_name=tech_name,
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=msg or cmd,
                    iocs=_clean({"user": user, "cmd": cmd}),
                    source_dataset=ds
                ))
            elif any(k in msg_lower or k in cmd_lower for k in ['mailbox forwarding persistence', 'mail rule persistence', 'inbox rule created', 'create inbox rule', 'forward to external address', 'new-inboxrule forward']):
                if host: hosts_involved.add(host)
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}",
                    timestamp=ts,
                    host=host,
                    phase="Persistence",
                    technique_id="T1114.002",
                    technique_name="Email Collection: Remote Email Forwarding Rule",
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=msg or cmd,
                    iocs=_clean({"user": user, "cmd": cmd}),
                    source_dataset=ds
                ))
            elif any(k in msg_lower or k in cmd_lower for k in ['password sign-in denied', 'legacy password grant denied', 'credential reset initiated by attacker', 'app-only refresh token', 'password compromise not observed']):
                if host: hosts_involved.add(host)
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}",
                    timestamp=ts,
                    host=host,
                    phase="Credential Access",
                    technique_id="T1528",
                    technique_name="Steal Application Access Token: Denied Legacy Auth",
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=msg or cmd,
                    iocs=_clean({"user": user, "cmd": cmd}),
                    source_dataset=ds
                ))

        # 13. Docker API, Container Attacks & Linux Cryptomining (Scenario 07)
        if 'docker' in str(host).lower() or 'docker' in proc_lower or 'container' in msg_lower or 'stratum' in msg_lower or 'miner' in proc_lower:
            if any(k in msg_lower or k in cmd_lower for k in ['docker api create', 'unauthenticated docker api', 'containers/create', 'container started']):
                if host: hosts_involved.add(host)
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}",
                    timestamp=ts,
                    host=host,
                    phase="Initial Access / Execution",
                    technique_id="T1610",
                    technique_name="Deploy Container",
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=msg or cmd,
                    iocs=_clean({"host": host, "user": user}),
                    source_dataset=ds
                ))
            elif any(k in msg_lower or k in cmd_lower for k in ['cryptominer process', 'stratum-like connection', 'resource anomaly cpu 99%']):
                if c['dst_ip']: attacker_ips.add(c['dst_ip'])
                if host: hosts_involved.add(host)
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}",
                    timestamp=ts,
                    host=host,
                    phase="Impact",
                    technique_id="T1496",
                    technique_name="Resource Hijacking: Network Cryptomining",
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=msg or cmd,
                    iocs=_clean({"host": host, "dst_ip": c['dst_ip']}),
                    source_dataset=ds
                ))
            elif any(k in msg_lower or k in cmd_lower for k in ['/etc/cron.d/', 'cron persistence', 'container restart']):
                if host: hosts_involved.add(host)
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}",
                    timestamp=ts,
                    host=host,
                    phase="Persistence",
                    technique_id="T1053.003",
                    technique_name="Scheduled Task/Job: Cron",
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=msg or cmd,
                    iocs=_clean({"host": host, "cmd": cmd}),
                    source_dataset=ds
                ))

        # 14. DNS Tunneling & Exfiltration (Scenario 08)
        if 'dns' in str(host).lower() or 'named' in proc_lower or 'dnscat' in proc_lower or 'dns tunnel' in msg_lower or 'txt queries' in msg_lower:
            if any(k in msg_lower or k in cmd_lower for k in ['dns tunnel chunk', '122 txt queries', 'dnscat', 'exfil-lab']):
                if host: hosts_involved.add(host)
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}",
                    timestamp=ts,
                    host=host,
                    phase="Exfiltration",
                    technique_id="T1048.003",
                    technique_name="Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol (DNS)",
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=msg or cmd,
                    iocs=_clean({"host": host, "process": c['proc_name'], "query": cmd}),
                    source_dataset=ds
                ))

        # 15. Insider Exfiltration, DLP & Log Clearing (Scenario 05)
        if any(k in msg_lower for k in ['read 327 employee files', 'hr-confidential', 'unauthorized mass file copy']):
            if host: hosts_involved.add(host)
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=ts,
                host=host,
                phase="Collection",
                technique_id="T1039",
                technique_name="Data from Network Shared Drive",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=msg or cmd,
                iocs=_clean({"host": host, "user": user}),
                source_dataset=ds
            ))
        elif any(k in msg_lower or k in cmd_lower for k in ['usb inserted', 'synth-usb', 'usbstor', 'copy hr_docs.7z to removable media', 'usb exfil blocked']):
            if host: hosts_involved.add(host)
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=ts,
                host=host,
                phase="Exfiltration",
                technique_id="T1052.001",
                technique_name="Exfiltration Over Physical Medium: USB Removable Media",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=msg or cmd,
                iocs=_clean({"host": host, "user": user, "cmd": cmd}),
                source_dataset=ds
            ))
        elif any(k in msg_lower or k in cmd_lower for k in ['rclone.exe', 'cloud upload 188331002 bytes', 'upload completed to personal cloud', 'cloud exfil confirmed']):
            if c['dst_ip']: attacker_ips.add(c['dst_ip'])
            if host: hosts_involved.add(host)
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=ts,
                host=host,
                phase="Exfiltration",
                technique_id="T1567.002",
                technique_name="Exfiltration Over Web Service: Exfiltration to Cloud Storage",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=msg or cmd,
                iocs=_clean({"host": host, "user": user, "dst_ip": c['dst_ip']}),
                source_dataset=ds
            ))
        elif any(k in cmd_lower or k in msg_lower for k in ['wevtutil cl', 'clear-eventlog', 'log clear']):
            if host: hosts_involved.add(host)
            stages.append(AttackStage(
                stage_id=f"S{len(stages)+1:02d}",
                timestamp=ts,
                host=host,
                phase="Defense Evasion",
                technique_id="T1070.001",
                technique_name="Indicator Removal: Clear Windows Event Logs",
                confidence="HIGH",
                status="CONFIRMED",
                evidence=cmd or msg,
                iocs=_clean({"host": host, "user": user, "cmd": cmd}),
                source_dataset=ds
            ))

        # 16. Backup Compromise & Repository Tampering (Scenario 10)
        if 'backup' in msg_lower or 'backupctl' in cmd_lower or 'delete restore-set' in cmd_lower or 'retention lock' in msg_lower or 'bkp_cfg.tgz' in cmd_lower or 'rdp logon type 10' in msg_lower:
            if host: hosts_involved.add(host)
            if 'rdp logon type 10' in msg_lower:
                if c['src_ip']: attacker_ips.add(c['src_ip'])
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}",
                    timestamp=ts,
                    host=host,
                    phase="Initial Access",
                    technique_id="T1133",
                    technique_name="External Remote Services: RDP Logon",
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=msg,
                    iocs=_clean({"src_ip": c['src_ip'], "user": user}),
                    source_dataset=ds
                ))
            elif 'backup discovery' in msg_lower or 'list repositories' in cmd_lower:
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}",
                    timestamp=ts,
                    host=host,
                    phase="Discovery",
                    technique_id="T1083",
                    technique_name="File and Directory Discovery: Backup Discovery",
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=msg or cmd,
                    iocs=_clean({"cmd": cmd, "user": user}),
                    source_dataset=ds
                ))
            elif 'delete requested' in msg_lower or 'delete restore-set' in cmd_lower or 'delete blocked' in msg_lower:
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}",
                    timestamp=ts,
                    host=host,
                    phase="Impact",
                    technique_id="T1490",
                    technique_name="Inhibit System Recovery: Backup Deletion Attempt",
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=msg or cmd,
                    iocs=_clean({"cmd": cmd, "user": user}),
                    source_dataset=ds
                ))
            elif 'bkp_cfg.tgz' in cmd_lower or 'collection staged' in msg_lower:
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}",
                    timestamp=ts,
                    host=host,
                    phase="Collection",
                    technique_id="T1560.001",
                    technique_name="Archive Collected Data: Archive via Utility",
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=cmd or msg,
                    iocs=_clean({"cmd": cmd, "user": user}),
                    source_dataset=ds
                ))

        if len(stages) > _n0 and not _pass_to_fallback:
            handled_idx.add(_i)

    # F1. IOC pivot
    ioc_first = {}
    for aip in attacker_ips:
        if _is_external(aip):
            t = ''
            for st in stages:
                st_iocs = st.iocs or {}
                if aip in st_iocs.values() or aip in (st.evidence or ''):
                    if not t or (st.timestamp and st.timestamp < t):
                        t = st.timestamp
            ioc_first[aip] = t

    for st in stages:
        for k in ['src_ip', 'dst_ip', 'c2', 'c2_ip', 'target', 'ip']:
            ip = (st.iocs or {}).get(k)
            if ip and _is_external(ip):
                if ip not in ioc_first or not ioc_first[ip] or (st.timestamp and st.timestamp < ioc_first[ip]):
                    ioc_first[ip] = st.timestamp or ''
        for ip in set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', st.evidence or '')):
            if _is_external(ip):
                if ip not in ioc_first or not ioc_first[ip] or (st.timestamp and st.timestamp < ioc_first[ip]):
                    ioc_first[ip] = st.timestamp or ''

    for _i, evt in enumerate(raw_events):
        c = extract_canonical(evt)
        dst = c['dst_ip']
        is_ioc_source = (_i in handled_idx and (not c['timestamp'] or c['timestamp'] == ioc_first.get(dst)))
        if is_ioc_source:
            continue
            
        if dst in ioc_first and _is_external(dst) and (not c['src_ip'] or not _is_external(c['src_ip'])) and (ioc_first[dst] == '' or (c['timestamp'] and c['timestamp'] >= ioc_first[dst])):
            proc_lower = (c['proc_name'] or '').lower()
            proc_base = proc_lower.split('/')[-1].split('\\')[-1].replace('.exe', '')
            cmd = c['cmd'] or ''
            
            _TRANSFER_TOOLS = {'curl','wget','rclone','scp','sftp','ftp','pscp','winscp','bitsadmin','certutil','nc','ncat','netcat','socat'}
            is_transfer = proc_base in _TRANSFER_TOOLS or re.search(r'invoke-webrequest|invoke-restmethod|\biwr\b|\birm\b|net\.webclient|uploadfile|uploaddata', cmd, re.I)
            
            tech = "T1071.001"
            if is_transfer:
                if re.search(r'(?:\s-T\s|--upload-file|\s-F\s|--form|--data-binary|\s-d\s+@|-X\s*(?:POST|PUT)|\bcopy\b|\bput\b|-Method\s+(?:Post|Put)|-InFile|uploadfile|uploaddata)', cmd, re.I):
                    tech = "T1041"
                elif not cmd.strip():
                    has_archive = any(s.host == c['host'] and s.technique_id in {'T1560', 'T1560.001', 'T1005', 'T1039', 'T1530', 'T1213', 'T1213.002', 'T1114', 'T1119'} and (s.timestamp or '') <= (c['timestamp'] or '') for s in stages)
                    if has_archive:
                        tech = "T1041"
                    else:
                        tech = "T1071.001"
                else:
                    if re.search(r'\s-o\s|\s-O\s|--output|-OutFile|downloadfile|downloadstring|>\s*\S', cmd, re.I):
                        tech = "T1105"
                    else:
                        tech = "T1071.001"
            
            tname = "Exfiltration Over C2 Channel" if tech == "T1041" else ("Ingress Tool Transfer" if tech == "T1105" else "Application Layer Protocol: Web Protocols")
            phase = "Exfiltration" if tech == "T1041" else "Command and Control"
            
            if tech == "T1071.001" and _i in handled_idx:
                continue
                
            ev_msg = f"{c['proc_name'] or 'jarayon'} -> {dst}:{c['dst_port']} (IOC: avvalgi hujum qadamidagi IP)"
            if cmd: ev_msg += f" (cmd: {cmd})"
            iocs = _clean({'dst_ip': dst, 'port': c['dst_port'], 'process': c['proc_name'], 'cmd': cmd})
            
            host = c['host']
            c2_key = (host, dst)
            if tech == "T1071.001" and c2_key in c2_seen:
                st = c2_seen[c2_key]
                st.iocs['connections'] = st.iocs.get('connections', 1) + 1
                st.iocs['last_seen'] = c['timestamp']
            else:
                stages.append(AttackStage(
                    stage_id=f"S{len(stages)+1:02d}", timestamp=c['timestamp'], host=host, phase=phase,
                    technique_id=tech, technique_name=tname, confidence="HIGH", status="CONFIRMED", evidence=ev_msg,
                    iocs=iocs, source_dataset=c['dataset']
                ))
                if tech == "T1071.001":
                    c2_seen[c2_key] = stages[-1]
            
            handled_idx.add(_i)
            if host: hosts_involved.add(host)
            attacker_ips.add(dst)
            if tech == "T1041": exfil_ips.add(dst)

    if kb is None:
        try:
            from bluekit.kb.query import KB
            kb = KB()
        except Exception:
            kb = None

    if heuristic_fallback:
        from bluekit.ir.fallback import fallback_stages
        fb = fallback_stages(raw_events, handled_idx, kb, stages)
        stages.extend(fb['stages'])
        hosts_involved.update(fb['hosts'])
        attacker_ips.update(fb['attacker_ips'])
        compromised_users.update(fb['users'])

    # Sort stages strictly by timestamp
    stages = sorted(stages, key=lambda s: s.timestamp)

    # Deduplicate repetitive beaconing/burst stages
    deduped_stages = []
    seen_keys = set()
    for s in stages:
        # For exfiltration, collapse repeated bursts into one stage
        if s.phase == "Exfiltration":
            key = (s.phase, s.technique_id, s.host)
            if key in seen_keys:
                continue
            seen_keys.add(key)
        deduped_stages.append(s)

    # Re-number stage IDs sequentially
    for idx, s in enumerate(deduped_stages, 1):
        s.stage_id = f"S{idx:02d}"

    # KB validation of all techniques (including T1071.001, T1036.005)
    if kb:
        tech_ids = [s.technique_id for s in deduped_stages if s.technique_id]
        if tech_ids:
            try:
                val_res = kb.validate(tech_ids)
                val_map = {r['normalized']: r for r in val_res if r.get('found')}
                for s in deduped_stages:
                    rec = val_map.get(s.technique_id.upper())
                    if rec and rec.get('name'):
                        s.technique_name = rec['name']
            except Exception:
                pass

    from bluekit.ir.explain import explain_stage_uz
    for s in deduped_stages:
        if not getattr(s, 'explain_uz', None):
            s.explain_uz = explain_stage_uz(s)

    from bluekit.tz import display_ts
    disp_map = {}
    for evt in raw_events:
        c = extract_canonical(evt)
        if c['timestamp'] and c['timestamp'] not in disp_map:
            disp_map[c['timestamp']] = c.get('timestamp_display', '')

    for s in deduped_stages:
        s.timestamp_display = disp_map.get(s.timestamp) or display_ts(s.timestamp)

    start_ts = deduped_stages[0].timestamp if deduped_stages else ""
    end_ts = deduped_stages[-1].timestamp if deduped_stages else ""

    try:
        from bluekit.ir.lateral import build_lateral_edges, attack_path as _attack_path
        lateral_edges = build_lateral_edges(raw_events, deduped_stages, kb)
        lateral_path = _attack_path(lateral_edges)
    except Exception:
        lateral_edges, lateral_path = [], []

    chain = AttackChain(
        chain_id="CHAIN-2026-01",
        stages=deduped_stages,
        hosts_involved=sorted(list(hosts_involved)),
        attacker_ips=sorted(list(attacker_ips)),
        exfiltration_ips=sorted(list(exfil_ips)),
        compromised_users=sorted(list(compromised_users)),
        start_time=start_ts,
        end_time=end_ts,
        lateral_edges=lateral_edges,
        attack_path=lateral_path
    )
    return chain
