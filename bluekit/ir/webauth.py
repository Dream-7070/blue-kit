import re
from collections import defaultdict
from bluekit.ir.models import AttackStage
from bluekit.logs.parse import parse_ts

def web_auth_stages(raw_events, extract_canonical, is_external_ip):
    stages = []
    handled_idx = set()
    
    login_re = re.compile(r'(?i)/(?:api/)?(?:v\d+/)?(?:login|signin|sign-in|auth(?:enticate)?|session|token|oauth/token|wp-login\.php|user/login|admin/login)\b')
    
    parsed = []
    for i, ev in enumerate(raw_events):
        c = extract_canonical(ev)
        method = c['method']
        path = c['url_path']
        status = c['status_code']
        ua = c['user_agent']
        
        msg = c['message'] or c['cmd'] or ''
        if not method or not path or not status:
            m = re.search(r'(GET|POST|PUT|PATCH|DELETE)\s+(\S+)(?:\s+HTTP/[\d.]+)?"?\s+(\d{3})', msg)
            if m:
                if not method: method = m.group(1)
                if not path: path = m.group(2)
                if not status: status = int(m.group(3))
            
        if not ua:
            m_ua = re.search(r'ua:\s*(\S+)', msg, re.IGNORECASE)
            if m_ua:
                ua = m_ua.group(1)
            else:
                m_ua2 = re.search(r'"([^"]+)"$', msg)
                if m_ua2:
                    ua = m_ua2.group(1)
        if not ua:
            ua = ''
        try:
            status = int(status) if status not in (None, '') else None
        except (TypeError, ValueError):
            status = None

        ip = c['src_ip']
        if not ip:
            m_ip = re.match(r'^([0-9a-fA-F:.]+)', msg)
            if m_ip:
                ip = m_ip.group(1)
                
        if not ip or not is_external_ip(ip):
            parsed.append(None)
            continue
            
        ts_str = c['timestamp']
        ts = parse_ts(ts_str) if ts_str else None
        
        is_login = False
        if method == 'POST' and path and login_re.search(path):
            is_login = True
            
        u_str = ''
        if isinstance(ua, dict):
            u_str = ua.get('original') or ua.get('name') or str(ua)
        else:
            u_str = str(ua) if ua is not None else ''
            
        parsed.append({
            'idx': i,
            'ts': ts,
            'raw_ts': ts_str,
            'ip': ip,
            'method': method,
            'path': path,
            'status': status,
            'ua': u_str,
            'host': str(c['host']) if c['host'] is not None else '',
            'is_login': is_login,
            'dataset': c['dataset']
        })
        
    clusters = defaultdict(list)
    for p in parsed:
        if p and p['is_login'] and p['ts']:
            clusters[(p['host'], p['ua'])].append(p)
            
    stuffing_ips = set()
    for key, items in clusters.items():
        items.sort(key=lambda x: x['ts'])
        host, ua = key
        
        n = len(items)
        start_idx = 0
        while start_idx < n:
            start_ts = items[start_idx]['ts']
            end_idx = start_idx
            
            cluster_items = []
            while end_idx < n and (items[end_idx]['ts'] - start_ts).total_seconds() <= 1800:
                cluster_items.append(items[end_idx])
                end_idx += 1
                
            count = len(cluster_items)
            if count >= 20:
                unique_ips = {x['ip'] for x in cluster_items}
                fails = [x for x in cluster_items if x['status'] in (401, 403, 422, 429)]
                fail_rate = len(fails) / count if count > 0 else 0
                
                if len(unique_ips) >= 5 and fail_rate >= 0.6:
                    ip_list = list(unique_ips)[:10]
                    subnets = defaultdict(int)
                    for ip in unique_ips:
                        if ':' not in ip:
                            parts = ip.split('.')
                            if len(parts) == 4:
                                subnets['.'.join(parts[:3]) + '.0/24'] += 1
                    top_subnet = max(subnets.items(), key=lambda x: x[1])[0] if subnets else "N/A"
                    
                    ev_msg = f"{count} ta login urinishi, {len(unique_ips)} noyob IP ({top_subnet}), {len(fails)} ta rad etildi, UA {ua}"
                    
                    st = AttackStage(
                        stage_id="TEMP",
                        timestamp=items[start_idx]['raw_ts'],
                        host=host,
                        phase="Credential Access",
                        technique_id="T1110.004",
                        technique_name="Brute Force: Credential Stuffing",
                        confidence="HIGH",
                        status="CONFIRMED",
                        evidence=ev_msg,
                        iocs={'src_ips': ip_list, 'attempts': count, 'ua': ua, 'successes': count - len(fails)},
                        source_dataset=items[start_idx]['dataset']
                    )
                    stages.append((st, ip_list[0] if ip_list else ''))
                    
                    for x in cluster_items:
                        handled_idx.add(x['idx'])
                        
                    for uip in unique_ips:
                        stuffing_ips.add(uip)
                        
                    success_ips = {}
                    for x in cluster_items:
                        if x['status'] and 200 <= x['status'] < 400:
                            success_ips[x['ip']] = x
                    
                    # Klasterdagi boshqa IP lar: login rad etilgan bo'lsa ham, keyin autentifikatsiya talab qiladigan yo'llarga 2xx bilan kirsa (sessiya boshqa yo'l bilan olingan)
                    auth_area = re.compile(r'(?i)/(?:account|profile|orders?|cards?|payments?|checkout|settings|wallet|billing|me|users?|api/(?:v\d+/)?(?:me|users?|accounts?|orders?|cards?|payments?))\b')
                    anchors = dict(success_ips)
                    for x in cluster_items:
                        anchors.setdefault(x['ip'], x)
                    t1078_count = 0
                    for sip, s_item in anchors.items():
                        if t1078_count >= 5:
                            break
                        is_success_ip = sip in success_ips
                        post_login = [p for p in parsed if p and p['ip'] == sip and p['ts'] and p['ts'] >= s_item['ts'] and p['status'] and 200 <= p['status'] < 400 and p['idx'] > s_item['idx'] and not p['is_login']
                                      and (is_success_ip or (p['path'] and auth_area.search(p['path'])))]
                        if post_login:
                            paths = [p['path'] for p in post_login[:3]]
                            st2 = AttackStage(
                                stage_id="TEMP",
                                timestamp=post_login[0]['raw_ts'],
                                host=host,
                                phase="Initial Access",
                                technique_id="T1078",
                                technique_name="Valid Accounts",
                                confidence="MEDIUM",
                                status="CONFIRMED",
                                evidence=f"{sip}, birinchi muvaffaqiyatli login vaqti {s_item['ts'].isoformat()} va keyingi 3 ta yo'l: {', '.join(paths)}",
                                iocs={'src_ip': sip, 'paths': paths},
                                source_dataset=post_login[0]['dataset']
                            )
                            stages.append((st2, sip))
                            for p in post_login[:3]:
                                handled_idx.add(p['idx'])
                            t1078_count += 1
                    start_idx = end_idx
                    continue
            start_idx += 1

    ip_fails = defaultdict(list)
    for p in parsed:
        if p and p['is_login'] and p['ts'] and p['status'] in (401, 403, 422, 429):
            ip_fails[p['ip']].append(p)
            
    for ip, items in ip_fails.items():
        if ip in stuffing_ips:
            continue
        items.sort(key=lambda x: x['ts'])
        n = len(items)
        start_idx = 0
        while start_idx < n:
            start_ts = items[start_idx]['ts']
            end_idx = start_idx
            cluster_items = []
            while end_idx < n and (items[end_idx]['ts'] - start_ts).total_seconds() <= 600:
                cluster_items.append(items[end_idx])
                end_idx += 1
            if len(cluster_items) >= 20:
                st = AttackStage(
                    stage_id="TEMP",
                    timestamp=items[start_idx]['raw_ts'],
                    host=items[start_idx]['host'],
                    phase="Credential Access",
                    technique_id="T1110.001",
                    technique_name="Brute Force: Password Guessing",
                    confidence="HIGH",
                    status="CONFIRMED",
                    evidence=f"{ip} dan {len(cluster_items)} ta rad etilgan login (10 daqiqa)",
                    iocs={'src_ip': ip, 'attempts': len(cluster_items)},
                    source_dataset=items[start_idx]['dataset']
                )
                stages.append((st, ip))
                for x in cluster_items:
                    handled_idx.add(x['idx'])
                break
            start_idx += 1

    return stages, handled_idx
