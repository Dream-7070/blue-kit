from bluekit.ir.correlator import extract_canonical, get_nested
from bluekit.ir.models import AttackStage
import ipaddress
from typing import Dict, Any, List, Set
import re

from bluekit.netutil import is_external_ip

MAX_ACTORS_PER_HOST_TECH = 3

def _actor(user: str) -> str:
    if not user:
        return ''
    user = user.lower().strip()
    if '\\' in user:
        user = user.split('\\', 1)[-1]
    if '@' in user:
        user = user.split('@', 1)[0]
    sys_users = {'system', 'local service', 'network service', 'anonymous logon', '-', 'n/a', ''}
    if user in sys_users or user.endswith('$'):
        return ''
    return user

def _is_external(ip) -> bool:
    """Ichki (RFC1918/loopback/link-local) bo'lmagan IP. Python is_global dan foydalanilmaydi:
    u TEST-NET (198.51.100.0/24, 203.0.113.0/24) ni global emas deb hisoblaydi, simulyatsiyada esa
    hujumchi IP lari aynan shu diapazonlardan."""
    return is_external_ip(ip)

def fallback_stages(raw_events: List[Dict[str, Any]], handled_idx: Set[int], kb, existing_stages: List[AttackStage]) -> dict:
    stages: List[AttackStage] = []
    hosts: Set[str] = set()
    attacker_ips: Set[str] = set()
    users: Set[str] = set()
    
    if kb is None:
        return {'stages': stages, 'hosts': hosts, 'attacker_ips': attacker_ips, 'users': users}

    from bluekit.logs.detect import detect_event

    probe_ips = set()
    for s in existing_stages:
        if s.technique_id == 'T1595.002' and getattr(s, 'iocs', None) and 'src_ip' in s.iocs:
            probe_ips.add(s.iocs['src_ip'])

    fallback_counts = {}

    for i, evt in enumerate(raw_events):
        if i in handled_idx:
            continue
            
        try:
            c = extract_canonical(evt)
            if c['dataset'].lower() == 'qradar':
                continue
                
            if c['src_ip'] in probe_ips and c['status_code'] in (403, 404):
                continue
                
            # detect_event ev
            raw = c['raw']
            
            # channel
            channel = get_nested(raw, 'winlog.channel') or raw.get('Channel') or raw.get('channel') or c['dataset'] or None
            
            # event_id
            event_id = get_nested(raw, 'event.code') or raw.get('EventID') or raw.get('event_id') or get_nested(raw, 'winlog.event_id') or None
            
            # message
            msg_parts = []
            if c['message']:
                msg_parts.append(c['message'])
            if c['url_path']:
                req = f"{c['method']} {c['url_path']}"
                if c['url_query']:
                    req += f"?{c['url_query']}"
                msg_parts.append(req.strip())
                
            msg = " ".join(filter(None, msg_parts)) if msg_parts else ""
            
            ev = {
                'channel': channel,
                'event_id': event_id,
                'command_line': c['cmd'] or None,
                'message': msg,
                'src_ip': c['src_ip']
            }
            
            if not ev['command_line'] and not ev['message']:
                continue
                
            hits = detect_event(kb, ev, deep=False)
            
            for hit in hits:
                if hit['confidence'] not in ('high', 'medium'):
                    continue
                    
                tech = hit['technique']
                host = c['host']
                cur_actor = _actor(c['user'] or '')
                key = (host, tech, cur_actor)
                
                # Check existing stages and fallback counts
                all_stages = []
                for s in existing_stages:
                    if s.host == host and s.technique_id == tech:
                        s_user = s.iocs.get('user') if hasattr(s, 'iocs') and s.iocs else None
                        all_stages.append((_actor(s_user or ''), s, None, True))
                        
                for k, stg_info in fallback_counts.items():
                    if k[0] == host and k[1] == tech and stg_info['stage'] is not None:
                        all_stages.append((k[2], stg_info['stage'], k, False))
                        
                matched_stage = None
                matched_key = None
                is_existing = False
                
                for act, stg, k, is_ext in all_stages:
                    if is_ext:
                        s_user = stg.iocs.get('user') if hasattr(stg, 'iocs') and stg.iocs else None
                        if not s_user or act == cur_actor:
                            matched_stage = stg
                            is_existing = True
                            break
                    else:
                        if act == cur_actor:
                            matched_stage = stg
                            matched_key = k
                            is_existing = False
                            break
                            
                if not matched_stage and len(all_stages) >= MAX_ACTORS_PER_HOST_TECH:
                    act, stg, k, is_ext = all_stages[-1]
                    matched_stage = stg
                    matched_key = k
                    is_existing = is_ext
                    
                if matched_stage:
                    if is_existing:
                        if key not in fallback_counts:
                            fallback_counts[key] = {'count': 1, 'stage': None}
                        fallback_counts[key]['count'] += 1
                    else:
                        stg_info = fallback_counts[matched_key]
                        stg_info['count'] += 1
                        stg = stg_info['stage']
                        stg.iocs['count'] = stg_info['count']
                        count = stg.iocs['count']
                        
                        new_ts = str(c['timestamp']) if c['timestamp'] else ""
                        cur_first = str(stg.iocs.get('first_seen', ''))
                        cur_last = str(stg.iocs.get('last_seen', ''))
                        
                        ev_text = str(ev['command_line'] or ev['message'])[:200]
                        base_ev = re.sub(r' \(x\d+\)$', '', stg.evidence)
                        
                        if new_ts:
                            if not cur_first or new_ts < cur_first:
                                stg.iocs['first_seen'] = new_ts
                                stg.timestamp = new_ts
                                stg.evidence = f"{ev_text} (x{count})"
                            else:
                                stg.evidence = f"{base_ev} (x{count})"
                                
                            if not cur_last or new_ts > cur_last:
                                stg.iocs['last_seen'] = new_ts
                        else:
                            stg.evidence = f"{base_ev} (x{count})"
                            
                        if c['user']:
                            if 'users' not in stg.iocs:
                                stg.iocs['users'] = []
                                if stg.iocs.get('user'):
                                    stg.iocs['users'].append(stg.iocs['user'])
                            if c['user'] not in stg.iocs['users'] and len(stg.iocs['users']) < 10:
                                stg.iocs['users'].append(c['user'])
                else:
                    try:
                        phase = kb.lookup(tech)[0]['tactics'][0]
                        phase = " ".join(word.capitalize() for word in phase.replace('-', ' ').split())
                    except Exception:
                        phase = "Unknown"
                        
                    ev_text = str(ev['command_line'] or ev['message'])[:200]
                    
                    iocs = {
                        'src_ip': c['src_ip'],
                        'user': c['user'],
                        'count': 1,
                        'first_seen': c['timestamp'],
                        'last_seen': c['timestamp'],
                        'rule_source': hit['source']
                    }
                    if c['user']:
                        iocs['users'] = [c['user']]
                    iocs = {k: v for k, v in iocs.items() if v}
                    
                    raw_id = str(get_nested(raw, 'event.id') or raw.get('_id') or '')
                    
                    new_stage = AttackStage(
                        stage_id="F00",
                        timestamp=str(c['timestamp']),
                        host=host,
                        phase=phase,
                        technique_id=tech,
                        technique_name=hit['name'],
                        confidence="MEDIUM",
                        status="SUSPECTED",
                        evidence=ev_text,
                        iocs=iocs,
                        source_dataset=c['dataset'] or 'text',
                        raw_event_id=raw_id
                    )
                    stages.append(new_stage)
                    fallback_counts[key] = {'count': 1, 'stage': new_stage}
                    
                if host:
                    hosts.add(host)
                    
                if c['src_ip']:
                    try:
                        ip = ipaddress.ip_address(c['src_ip'])
                        if _is_external(ip):
                            attacker_ips.add(c['src_ip'])
                    except Exception:
                        pass
                        
                if c['user']:
                    u = c['user'].upper()
                    if not any(ign in u for ign in ['SYSTEM', 'AUTHORITY', 'ANONYMOUS', 'ESET']):
                        users.add(c['user'])
                        
        except Exception:
            continue

    return {
        'stages': stages,
        'hosts': hosts,
        'attacker_ips': attacker_ips,
        'users': users
    }
