import ipaddress
import re
from collections import defaultdict
from datetime import datetime, timezone
from bluekit.ir.correlator import extract_canonical, get_nested

def _validate_techniques(kb, ids) -> list:
    if not kb: return ids
    try:
        res = kb.validate(ids)
        new_ids = []
        for r in res:
            if r.get('found'):
                val = r.get('replacement') if r.get('status') in ('revoked', 'deprecated') and r.get('replacement') else r.get('normalized')
                if val and val not in new_ids:
                    new_ids.append(val)
        return new_ids
    except Exception:
        return ids

def _is_valid_ip(ip_str):
    if not ip_str or ip_str == '-': return False
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback or ip.is_unspecified:
            return False
        return True
    except Exception:
        return False

def build_ip_map(raw_events) -> dict:
    ip_host_counts = defaultdict(lambda: defaultdict(int))
    for evt in raw_events:
        if not evt: continue
        try:
            c = extract_canonical(evt)
            raw = c['raw']
            channel = str(get_nested(raw, 'winlog.channel') or raw.get('Channel') or raw.get('channel') or c['dataset'] or '').lower()
            event_id = str(get_nested(raw, 'event.code') or raw.get('EventID') or raw.get('event_id') or get_nested(raw, 'winlog.event_id') or '')
            host = c['host']
            if not host: continue

            own_ips = []
            if c.get('host_ip'):
                if isinstance(c['host_ip'], list): own_ips.extend(c['host_ip'])
                else: own_ips.append(c['host_ip'])
            
            if 'sysmon' in channel and event_id == '3' and c.get('src_ip'):
                own_ips.append(c['src_ip'])
            
            if event_id == '4624' or (c.get('message') and re.search(r'Accepted (publickey|password|keyboard-interactive)', c['message'])):
                if c.get('dst_ip'):
                    own_ips.append(c['dst_ip'])
                    
            for ip_str in own_ips:
                if _is_valid_ip(ip_str):
                    ip_host_counts[ip_str][host] += 1
        except Exception:
            pass
            
    ip_map = {}
    for ip, counts in ip_host_counts.items():
        best_host = sorted(counts.items(), key=lambda x: (-x[1], x[0]))[0][0]
        ip_map[ip] = best_host
    return ip_map

def parse_time(ts):
    if not ts: return None
        
    if isinstance(ts, datetime):
        if ts.tzinfo is None: return ts.replace(tzinfo=timezone.utc)
        return ts
    if isinstance(ts, str):
        try:
            s = ts.replace('Z', '+00:00')
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            pass
    return None

def build_lateral_edges(raw_events, stages, kb=None) -> list:
    ip_map = build_ip_map(raw_events)
    candidates = []
    
    # Store edges for fast lookup for PsExec
    edges_by_dst = defaultdict(list)
    
    for evt in raw_events:
        if not evt: continue
        try:
            c = extract_canonical(evt)
            raw = c['raw']
            channel = str(get_nested(raw, 'winlog.channel') or raw.get('Channel') or raw.get('channel') or c['dataset'] or '').lower()
            event_id = str(get_nested(raw, 'event.code') or raw.get('EventID') or raw.get('event_id') or get_nested(raw, 'winlog.event_id') or '')
            msg = c['message'] or ''
            cmd = c['cmd'] or ''
            host = c['host']
            ts = c['timestamp']
            
            # A. Windows logon
            if event_id == '4624' and _is_valid_ip(c.get('src_ip')):
                # get logon type
                ltype = None
                m1 = re.search(r'(?i)logon type\W{0,8}(\d+)', msg)
                m2 = re.search(r'(?i)\(type (\d+)\)', msg)
                ltd = get_nested(raw, 'winlog.event_data.LogonType') or raw.get('LogonType')
                if m1: ltype = m1.group(1)
                elif m2: ltype = m2.group(1)
                elif ltd: ltype = str(ltd)
                
                if ltype == '10':
                    method = 'RDP'
                    techs = ['T1021.001']
                elif ltype == '3':
                    method = 'Network logon'
                    techs = ['T1078']
                elif ltype is None:
                    method = 'Network logon (type ?)'
                    techs = ['T1078']
                else:
                    continue # ignore 2, 4, 5, 7 etc
                    
                src_ip = c['src_ip']
                src_host = ip_map.get(src_ip, src_ip)
                if src_host == host or ip_map.get(src_ip) == host: continue # local logon
                
                edge = {
                    'src_host': src_host, 'src_ip': src_ip, 'dst_host': host, 'dst_ip': c.get('dst_ip') or '',
                    'user': c['user'] or '', 'method': method, 'techniques': techs,
                    'first_seen': ts, 'last_seen': ts, 'first_seen_display': c.get('timestamp_display', str(ts)),
                    'count': 1, 'evidence': '', 'status': 'SUSPECTED',
                    '_ts': parse_time(ts), '_type3': (ltype == '3')
                }
                candidates.append(edge)
                edges_by_dst[host].append(edge)
                
            # B. PsExec
            if event_id in ('7045', '4697') and re.search(r'(?i)psexesvc|paexec|remcom|csexec', cmd + ' ' + msg):
                svc_name = re.search(r'(?i)Service Name:\s*(\S+)', msg)
                svc = svc_name.group(1) if svc_name else 'PsExec'
                
                evt_ts = parse_time(ts)
                best_edge = None
                if evt_ts:
                    # look for nearest A source type 3 edge 0-300s before
                    valid_edges = []
                    for e in edges_by_dst[host]:
                        if not e['_type3']: continue
                        if not e['_ts']: continue
                        diff = (evt_ts - e['_ts']).total_seconds()
                        if 0 <= diff <= 300:
                            valid_edges.append((diff, e))
                    
                    if valid_edges:
                        # prefer same user
                        same_user = [e for e in valid_edges if e[1]['user'] == c.get('user')]
                        if same_user:
                            best_edge = min(same_user, key=lambda x: x[0])[1]
                        else:
                            best_edge = min(valid_edges, key=lambda x: x[0])[1]
                
                if best_edge:
                    best_edge['method'] = 'SMB/PsExec'
                    best_edge['techniques'] = ['T1021.002', 'T1569.002']
                    if svc not in best_edge['evidence']:
                        best_edge['evidence'] = (best_edge['evidence'] + ' ' + svc).strip()
                    best_edge['_is_b'] = True
                else:
                    edge = {
                        'src_host': '', 'src_ip': '', 'dst_host': host, 'dst_ip': '',
                        'user': c['user'] or '', 'method': 'SMB/PsExec', 'techniques': ['T1021.002', 'T1569.002'],
                        'first_seen': ts, 'last_seen': ts, 'first_seen_display': c.get('timestamp_display', str(ts)),
                        'count': 1, 'evidence': svc, 'status': 'SUSPECTED',
                        '_ts': parse_time(ts), '_is_b': True
                    }
                    candidates.append(edge)
                    
            # C. SSH access
            m_ssh = re.search(r'Accepted (publickey|password|keyboard-interactive) for (\S+) from ([0-9a-fA-F:.]+)', msg)
            if m_ssh:
                user = m_ssh.group(2)
                src_ip = m_ssh.group(3)
                src_host = ip_map.get(src_ip, src_ip)
                if src_host != host:
                    edge = {
                        'src_host': src_host, 'src_ip': src_ip, 'dst_host': host, 'dst_ip': '',
                        'user': user, 'method': 'SSH', 'techniques': ['T1021.004'],
                        'first_seen': ts, 'last_seen': ts, 'first_seen_display': c.get('timestamp_display', str(ts)),
                        'count': 1, 'evidence': '', 'status': 'SUSPECTED',
                        '_ts': parse_time(ts)
                    }
                    candidates.append(edge)
                    
            # D. ssh/scp/rsync cmd
            m_cmd = re.search(r'\b(ssh|scp|rsync)\b', cmd)
            if m_cmd:
                m_ip = re.search(r'(?:(\S+?)@)?(\d{1,3}(?:\.\d{1,3}){3})', cmd)
                if m_ip:
                    cmd_type = m_cmd.group(1)
                    cmd_user = m_ip.group(1) or c['user'] or ''
                    cmd_ip = m_ip.group(2)
                    remote_host = ip_map.get(cmd_ip, cmd_ip)
                    
                    if cmd_type == 'ssh':
                        src_host = host
                        dst_host = remote_host
                        method = 'SSH'
                        techs = ['T1021.004']
                    else: # scp / rsync
                        # find if remote part is before local part
                        # e.g., scp user@ip:/path /local
                        remote_str = m_ip.group(0)
                        remote_idx = cmd.find(remote_str)
                        # primitive check: if remote_idx is in the first half of arguments, it's pull?
                        # better: check if it's the first argument after scp options
                        parts = cmd.split()
                        remote_pos = next((i for i, p in enumerate(parts) if remote_str in p), 999)
                        # the last argument is usually destination
                        if remote_pos < len(parts) - 1:
                            # remote is source, so pull
                            src_host = remote_host
                            dst_host = host
                        else:
                            # remote is destination, push
                            src_host = host
                            dst_host = remote_host
                        method = 'SCP'
                        techs = ['T1570']
                        
                    if src_host != dst_host:
                        edge = {
                            'src_host': src_host, 'src_ip': '', 'dst_host': dst_host, 'dst_ip': cmd_ip if dst_host == remote_host else '',
                            'user': cmd_user, 'method': method, 'techniques': techs,
                            'first_seen': ts, 'last_seen': ts, 'first_seen_display': c.get('timestamp_display', str(ts)),
                            'count': 1, 'evidence': '', 'status': 'SUSPECTED',
                            '_ts': parse_time(ts)
                        }
                        candidates.append(edge)
                        
        except Exception:
            pass

    # L4 Filter
    compromised = {}
    for s in stages:
        if s.confidence in ('HIGH', 'MEDIUM'):
            sts = parse_time(s.timestamp)
            if s.host not in compromised or (sts and sts < compromised[s.host]):
                if sts: compromised[s.host] = sts
                else: compromised[s.host] = datetime.min.replace(tzinfo=timezone.utc)

    filtered = []
    for e in candidates:
        keep = False
        status = 'SUSPECTED'
        
        # 1. src_host in compromised and edge time >= earliest stage time
        if e['src_host'] in compromised:
            if not e['_ts'] or e['_ts'] >= compromised[e['src_host']]:
                keep = True
                status = 'CONFIRMED'
                
        # 2. method SMB/PsExec (B source)
        if e.get('_is_b'):
            keep = True
            status = 'CONFIRMED'
            
        # 3. method SSH or SCP
        if e['method'] in ('SSH', 'SCP'):
            if e['src_host'] in compromised or e['dst_host'] in compromised:
                keep = True
            
        if keep:
            e['status'] = status
            filtered.append(e)

    # L5 Merge
    merged = {}
    for e in filtered:
        key = (e['src_host'], e['dst_host'], e['user'], e['method'])
        if key not in merged:
            merged[key] = e
        else:
            me = merged[key]
            me['count'] += 1
            if parse_time(e['first_seen']) and parse_time(me['first_seen']) and parse_time(e['first_seen']) < parse_time(me['first_seen']):
                me['first_seen'] = e['first_seen']
                me['first_seen_display'] = e['first_seen_display']
            if parse_time(e['last_seen']) and parse_time(me['last_seen']) and parse_time(e['last_seen']) > parse_time(me['last_seen']):
                me['last_seen'] = e['last_seen']
            if not me['evidence'] and e['evidence']:
                me['evidence'] = e['evidence']
            # update techniques safely
            for t in e['techniques']:
                if t not in me['techniques']: me['techniques'].append(t)

    # Validate KB
    res = list(merged.values())
    if kb:
        for e in res:
            try:
                e['techniques'] = _validate_techniques(kb, e['techniques'])
            except Exception:
                continue
                
                
    # cleanup temp keys
    for e in res:
        e.pop('_ts', None)
        e.pop('_type3', None)
        e.pop('_is_b', None)
        
    res.sort(key=lambda x: parse_time(x['first_seen']) or datetime.min.replace(tzinfo=timezone.utc))
    return res

def attack_path(edges) -> list:
    conf = [e for e in edges if e['status'] == 'CONFIRMED' and e['src_host']]
    if not conf: return []
    
    start_edge = conf[0]
    path = [start_edge['src_host']]
    curr = start_edge['dst_host']
    path.append(curr)
    
    last_ts = parse_time(start_edge['first_seen'])
    
    while True:
        next_edges = [e for e in conf if e['src_host'] == curr and e['dst_host'] not in path and (not last_ts or (parse_time(e['first_seen']) and parse_time(e['first_seen']) >= last_ts))]
        if not next_edges:
            break
        next_edge = next_edges[0]
        curr = next_edge['dst_host']
        path.append(curr)
        last_ts = parse_time(next_edge['first_seen'])
        
    return path

def edges_mermaid(edges) -> str:
    if not edges: return ""
    nodes = {}
    lines = ["flowchart LR"]
    for i, e in enumerate(edges, 1):
        sh = e['src_host'] or "?"
        dh = e['dst_host']
        if sh not in nodes: nodes[sh] = f"N{len(nodes)+1}"
        if dh not in nodes: nodes[dh] = f"N{len(nodes)+1}"
        
        user = e['user'].replace('"', "'")
        label = f'#{i} {user} · {e["method"]}'
        arrow = '-->' if e['status'] == 'CONFIRMED' else '-.->'
        lines.append(f'  {nodes[sh]}["{sh}"] {arrow}|"{label}"| {nodes[dh]}["{dh}"]')
        
    return "\n".join(lines)
