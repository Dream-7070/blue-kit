import os
import sys
import ipaddress
import yaml
import json
from collections import defaultdict
from typing import List, Dict, Any, Tuple
from datetime import datetime
import copy

from bluekit.ir.correlator import load_events_from_files, extract_canonical
from bluekit.hunt.beacon_math import calculate_beacon_metrics, parse_dt
from bluekit.tz import display_ts

from bluekit.netutil import is_internal_ip

def is_private_ip(ip_str: str) -> bool:
    return is_internal_ip(ip_str)

def load_allowlist(yaml_path: str) -> List[ipaddress.IPv4Network]:
    if not yaml_path or not os.path.exists(yaml_path):
        print(f"OGOHLANTIRISH: allowlist fayli topilmadi ({yaml_path}). "
              f"Benign CIDR filtri o'chirilgan -- false positive ko'payadi.", file=sys.stderr)
        return []
    with open(yaml_path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    cidrs = data.get('cidrs', [])
    networks = []
    for c in cidrs:
        try:
            networks.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            pass
    return networks

def ip_in_allowlist(ip_str: str, allowlist: List[ipaddress.IPv4Network]) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        for net in allowlist:
            if ip in net:
                return True
    except ValueError:
        pass
    return False

def format_bytes(b: float) -> str:
    if b < 1024:
        return f"{b:.0f} B"
    elif b < 1024**2:
        return f"{b/1024:.1f} KB"
    else:
        return f"{b/(1024**2):.1f} MB"

def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    else:
        return f"{seconds/3600:.1f} soat"

def hunt_beacons(input_paths: List[str], iocs: List[str], allowlist_path: str, min_sessions: int, max_hosts: int) -> List[Dict]:
    allowlist = load_allowlist(allowlist_path)
    events, _ = load_events_from_files(input_paths)
    
    ip_to_host = {}
    groups = defaultdict(list)
    
    for raw_evt in events:
        evt = extract_canonical(raw_evt)
        src_ip = evt.get('src_ip')
        dst_ip = evt.get('dst_ip')
        dst_port = evt.get('dst_port')
        
        if src_ip and evt.get('host'):
            h = evt.get('host')
            if h and not any(fw in h.lower() for fw in ['ha-cluster', 'fortigate', 'firewall', 'tashkent-d', 'gateway']):
                ip_to_host[src_ip] = h
                
        if not src_ip or not dst_ip:
            continue
            
        if not is_private_ip(src_ip):
            continue
            
        if is_private_ip(dst_ip):
            continue
            
        if ip_in_allowlist(dst_ip, allowlist):
            continue
            
        key = (src_ip, dst_ip)
        groups[key].append(evt)
        
    results = []
    
    dst_host_counter = defaultdict(set)
    for (src, dst) in groups.keys():
        dst_host_counter[dst].add(src)
        
    for (src_ip, dst_ip), evts in groups.items():
        dst_host_count = len(dst_host_counter[dst_ip])
        
        ports = [e.get('dst_port') for e in evts if e.get('dst_port')]
        from collections import Counter
        top_ports = [str(p) for p, c in Counter(ports).most_common(3)]
        dst_port_str = ",".join(top_ports)
        
        has_sid = any(e['raw'].get('session_id') for e in evts)
        
        sessions = defaultdict(list)
        for idx, evt in enumerate(evts):
            session_id = evt['raw'].get('session_id')
            if not has_sid or session_id is None:
                src_port = evt.get('src_port', '')
                dp = evt.get('dst_port', '')
                if not has_sid and not src_port:
                    session_id = ('evt', idx)
                else:
                    session_id = (src_ip, src_port, dst_ip, dp)
            sessions[session_id].append(evt)
            
        fw_sessions = sum(1 for s_evts in sessions.values() if any(e['raw'].get('session_id') for e in s_evts))
        n_sessions = fw_sessions if has_sid else len(sessions)
            
        if dst_host_count > max_hosts:
            continue
            
        total_sent = 0
        max_duration = 0
        night_sessions = 0
        
        session_summaries = []
        first_disp = {}  # sessiya boshlanish vaqti -> logdagi ko'rinishi
        for sid, s_evts in sessions.items():
            bytes_sent = max((int(e.get('bytes_sent') or 0) for e in s_evts), default=0)
            total_sent += bytes_sent
            
            duration = max((float(e.get('duration', e['raw'].get('duration', 0)) or 0) for e in s_evts), default=0)
            if duration > max_duration:
                max_duration = duration
                
            sorted_evts = sorted(s_evts, key=lambda x: str(x.get('timestamp')))
            first_ts = parse_dt(sorted_evts[0].get('timestamp'))
            if isinstance(first_ts, datetime) and first_ts.hour < 6:
                night_sessions += 1
                
            session_summaries.append((first_ts, bytes_sent, duration))
            if first_ts is not None and first_ts not in first_disp:
                first_disp[first_ts] = sorted_evts[0].get('timestamp_display') or display_ts(first_ts)

        session_summaries.sort(key=lambda x: str(x[0]))
        timestamps = [s[0] for s in session_summaries if s[0]]
        
        metrics = None
        if len(timestamps) >= min_sessions:
            metrics = calculate_beacon_metrics(timestamps)
            
        median_interval = 0
        cv_ratio = 1.0
        if metrics:
            median_interval, cv_ratio = metrics
            
        avg_sent = total_sent / n_sessions if n_sessions > 0 else 0
        night_ratio = night_sessions / n_sessions if n_sessions > 0 else 0
        
        score = 0
        reasons = []
        
        if n_sessions >= 20 and 5 <= median_interval <= 3600 and cv_ratio < 0.3:
            score += 30
            reasons.append("Davriylik")
        elif n_sessions >= 20 and 5 <= median_interval <= 3600 and cv_ratio < 0.6:
            score += 15
            reasons.append("Zaif davriylik")
            
        if n_sessions >= 100 and avg_sent < 50000 and (has_sid or total_sent > 0):
            score += 20
            reasons.append("Keepalive hajmi")
            
        if max_duration >= 3600:
            score += 15
            reasons.append("Uzoq sessiya (RAT)")
            
        if dst_host_count <= 5 and score > 0:
            score += 15
            reasons.append("Kam tarqalgan manzil")
            if dst_host_count == 1:
                score += 5
                reasons.append("Juda kam tarqalgan")
                
        if night_ratio >= 0.2 and score > 0:
            score += 10
            reasons.append("Tungi faollik")
            
        if top_ports and not all(p in ('80', '443') for p in top_ports) and score > 0:
            score += 5
            reasons.append("Standart bo'lmagan port")
            
        if score == 0 and n_sessions < min_sessions:
            score = 0
        elif n_sessions < min_sessions:
            score = 0
            
        level = "PAST"
        if score >= 50:
            level = "YUQORI"
        elif score >= 30:
            level = "O'RTA"
            
        if dst_ip in iocs:
            level = "MA'LUM"
            score = 999
            
        # Ko'rsatish logdagi vaqt bo'yicha; tartiblash uchun Toshkent ISO alohida saqlanadi
        if timestamps and isinstance(timestamps[0], datetime):
            earliest = min(timestamps)
            first_seen = first_disp.get(earliest) or display_ts(earliest)
            first_seen_ts = earliest.isoformat()
        else:
            first_seen, first_seen_ts = "", ""
        
        host_name = ip_to_host.get(src_ip, "")
        if not host_name:
            for e in evts:
                if e.get('host'):
                    host_name = e.get('host')
                    break
                
        results.append({
            'score': score,
            'level': level,
            'dst_ip': dst_ip,
            'dst_port': dst_port_str,
            'src_ip': src_ip,
            'host': host_name,
            'dst_host_count': dst_host_count,
            'sessions': n_sessions,
            'median_interval': median_interval,
            'cv_ratio': cv_ratio,
            'avg_sent': avg_sent,
            'max_duration': max_duration,
            'first_seen': first_seen,
            'first_seen_ts': first_seen_ts,
            'reasons': reasons
        })
        
    results.sort(key=lambda x: x['score'], reverse=True)
    return results

def group_by_dst(results: List[Dict], all_results: bool = False) -> List[Dict]:
    """dst_ip bo'yicha jamlangan nomzodlar ro'yxati (CLI jadvali va web UI uchun umumiy)."""
    dst_groups = defaultdict(list)
    for r in results:
        key = r['dst_ip']
        dst_groups[key].append(r)
        
    grouped = []
    for dst_ip, candidates in dst_groups.items():
        best = max(candidates, key=lambda x: x['score'])
        level = best['level']
        
        if not all_results and level not in ("YUQORI", "O'RTA", "MA'LUM"):
            continue
            
        score = best['score']
        median = best['median_interval']
        cv = best['cv_ratio']
        
        total_sess = sum(c['sessions'] for c in candidates)
        avg_sent = sum(c['avg_sent'] * c['sessions'] for c in candidates) / total_sess if total_sess else 0
        max_dur = max(c['max_duration'] for c in candidates)
        
        # Eng erta nomzod Toshkent ISO bo'yicha tanlanadi (ko'rinish satrlari zonasi har xil bo'lishi mumkin)
        dated = [c for c in candidates if c['first_seen']]
        earliest_c = min(dated, key=lambda c: c.get('first_seen_ts') or c['first_seen']) if dated else None
        first_seen = earliest_c['first_seen'] if earliest_c else ""
        
        hosts = []
        sorted_cands = sorted(candidates, key=lambda x: x['sessions'], reverse=True)
        for c in sorted_cands[:10]:
            hosts.append({
                'src_ip': c['src_ip'],
                'host': c['host'],
                'sessions': c['sessions']
            })
            
        grouped.append({
            'dst_ip': dst_ip,
            'dst_port': best['dst_port'],
            'score': score,
            'level': level,
            'dst_host_count': best['dst_host_count'],
            'sessions': total_sess,
            'median_interval': median,
            'cv_ratio': cv,
            'avg_sent': avg_sent,
            'max_duration': max_dur,
            'first_seen': first_seen,
            'reasons': best['reasons'],
            'hosts': hosts
        })
        
    grouped.sort(key=lambda x: x['score'], reverse=True)
    return grouped

def render_table(results: List[Dict], all_results: bool):
    print(f"{'Ball':>4} | {'Daraja':<6} | {'Dst IP':<15} | {'Port':<8} | {'Host':<4} | {'Sessiya':<7} | {'Median':<6} | {'CV':<5} | {'O\'rt.bayt':<9} | {'Maks davom':<10} | {'Birinchi (logdagi)'}")
    print("-" * 115)
    
    grouped = group_by_dst(results, all_results)
    count_high_med = 0
    
    for best in grouped:
        level = best['level']
        
        if level in ("YUQORI", "O'RTA", "MA'LUM"):
            count_high_med += 1
            
        score = best['score']
        score_str = str(score) if score != 999 else "-"
        median = best['median_interval']
        median_str = f"{median:.0f}s" if median else "-"
        cv = best['cv_ratio']
        cv_str = f"{cv:.2f}" if median else "-"
        
        avg_str = format_bytes(best['avg_sent'])
        dur_str = format_duration(best['max_duration'])
        dst_port_str = best['dst_port']
        dst_host_count = best['dst_host_count']
        
        print(f"{score_str:>4} | {level:<6} | {best['dst_ip']:<15} | {dst_port_str:<8} | {dst_host_count:<4} | {best['sessions']:<7} | {median_str:<6} | {cv_str:<5} | {avg_str:<9} | {dur_str:<10} | {best['first_seen']}")
        
        for c in best['hosts']:
            hname_str = f" ({c['host']})" if c['host'] else ""
            if c['sessions'] == 0:
                print(f"       -> {c['src_ip']}{hname_str} (ESET, sessiya yo'q)")
            else:
                print(f"       -> {c['src_ip']}{hname_str} ({c['sessions']} sessiya)")
            
    # For checked count, we need all grouped elements (if all_results was true, we can just filter).
    # To precisely match old behaviour for checked: it checked all dst_groups where max score was in valid_levels.
    # We can just run group_by_dst with all_results=True to get total checked.
    all_grouped = group_by_dst(results, all_results=True)
    valid_levels = ("YUQORI", "O'RTA", "MA'LUM")
    checked = sum(1 for g in all_grouped if g['level'] in valid_levels)
    
    print(f"\n{checked} ta nomzod tekshirildi, {count_high_med} tasi YUQORI/O'RTA.")
    from bluekit.tz import tz_note
    print(tz_note())
    print("CV = intervallar stdev/median nisbati: qancha kichik bo'lsa, davriylik shuncha aniq.")
