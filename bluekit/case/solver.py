import re
import ipaddress
import collections
import hashlib
from datetime import datetime, timedelta, timezone

def P(s):
    s = str(s).strip().replace('Z', '+00:00')
    d = datetime.fromisoformat(s)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)

def parse_baseline(ctx):
    b = ctx['baseline']
    txt = ctx['ops_text'] + ' ' + str(b)
    ranges = []
    for pre, lo, pre2, hi in re.findall(r'\b([A-Z]{2,})-(\d+)\s*\.\.\s*(?:([A-Z]{2,})-)?(\d+)', txt):
        ranges.append((pre, int(lo), int(hi)))
    singles = set(re.findall(r'(?:exercise|drill|approved)[^.\n]*?\b([A-Z]{2,}-\d+)\b', txt, re.I))
    classes = set(b.get('approved_actor_classes', []))
    nets_str = b.get('approved_network', '') + ' ' + ctx['ops_text']
    nets = []
    for n in re.findall(r'\b(\d+\.\d+\.\d+\.\d+/\d+)\b', nets_str):
        try: nets.append(ipaddress.ip_network(n))
        except: pass
    ips = set(re.findall(r'\b(\d+\.\d+\.\d+\.\d+)\b(?!/)', ctx['ops_text']))
    return dict(ranges=ranges, singles=singles, classes=classes, nets=nets, ips=ips)

def ref_ok(v, B):
    m = re.fullmatch(r'([A-Z]{2,})-(\d+)', str(v or ''))
    if not m: return False
    if v in B['singles']: return True
    return any(m.group(1) == p and lo <= int(m.group(2)) <= hi for p, lo, hi in B['ranges'])

def approved(e, B, warnings):
    a = e['attrs']
    prefixes = {p for p, _, _ in B['ranges']} | {x.split('-')[0] for x in B['singles']}
    refs = [str(v) for v in a.values() if isinstance(v, str) and re.fullmatch(r'([A-Z]{2,})-\d+', v) and v.split('-')[0] in prefixes]
    
    if not refs: return False
    if not all(ref_ok(v, B) for v in refs): return False
    
    ac = a.get('actor_class')
    if B['classes'] and ac is not None and ac not in B['classes']: return False
    
    ip_vals = [v for k, v in a.items() if isinstance(v, str) and re.match(r'^\d+\.\d+\.\d+\.\d+$', v)]
    for v in ip_vals:
        try:
            ip = ipaddress.ip_address(v)
            if B['nets'] and not any(ip in net for net in B['nets']) and v not in B['ips']:
                warnings.append(f"baseline ziddiyati: {e['id']}")
        except: pass
            
    return True

TELEMETRY_KEYS = {'host', 'collector_batch', 'result'}
def telemetry(e):
    return set(e['attrs']) <= TELEMETRY_KEYS

GENERIC_VAL = re.compile(r'^(true|false|none|null|success|allow|allowed|deny|denied|blocked|ok|unknown|yes|no|\d{1,4}|-)$', re.I)
def ident_values(e):
    out = set()
    for k, v in e['attrs'].items():
        if isinstance(v, (list, dict)) or v is None or isinstance(v, bool): continue
        s = str(v)
        if GENERIC_VAL.match(s) or len(s) < 3: continue
        if k.lower() in ('bytes', 'count', 'rows', 'items', 'entries', 'tags', 'amount', 'serial'): continue
        out.add(s)
    return out

def outcome(e):
    a = e['attrs']
    s = ' '.join(f'{k}={v}' for k, v in a.items()).lower()
    act = e['action'].lower()
    if re.search(r'result=(blocked|deny|denied|rejected|failure|fail)|applied=false|settled=false|status=(4\d\d|5\d\d)', s) or re.search(r'rejected|denied|held|blocked', act):
        return 'blocked'
    if re.search(r'initiator=soc|revoke|disabled|quarantine', s + ' ' + act):
        return 'response'
    return 'success'

def solve(events, ctx):
    B = parse_baseline(ctx)
    warnings = ctx.get('warnings', [])
    for e in events:
        off = ctx['clocks'].get(e['source'], 0)
        e['utc'] = P(e['raw_time']) - timedelta(seconds=off)
        e['off'] = off
    
    cand, appr_list, tel_list = [], [], []
    for e in events:
        if approved(e, B, warnings):
            appr_list.append(e)
        elif telemetry(e):
            tel_list.append(e)
        else:
            cand.append(e)
        
    idx = {}
    for i, e in enumerate(cand):
        for v in ident_values(e):
            idx.setdefault(v, []).append(i)
            
    par = list(range(len(cand)))
    def f(x):
        while par[x] != x: par[x] = par[par[x]]; x = par[x]
        return x
    for v, l in idx.items():
        for j in l[1:]: par[f(j)] = f(l[0])
            
    g = collections.defaultdict(list)
    for i in range(len(cand)):
        g[f(i)].append(cand[i])
        
    comps = sorted(g.values(), key=len, reverse=True)
    chain_unsorted = comps[0] if comps else []
    orphans = [e for c in comps[1:] for e in c]
    
    for e in chain_unsorted:
        e['ingested_ts'] = P(e['ingested']) if e.get('ingested') else P('1970-01-01T00:00:00Z')
        e['seq_val'] = e['seq'] or 0
        
    chain = sorted(chain_unsorted, key=lambda e: (e['utc'], e['ingested_ts'], e['seq_val']))
    
    for i in range(len(chain)-1):
        a, b = chain[i], chain[i+1]
        u_a = ctx.get('uncertainty', {}).get(a['source'], 1)
        u_b = ctx.get('uncertainty', {}).get(b['source'], 1)
        if (b['utc'] - a['utc']).total_seconds() <= u_a + u_b:
            a['order_uncertain'] = True
            b['order_uncertain'] = True
            
    ids = '|'.join(e['id'] for e in chain)
    flag = 'CTF{%s}' % hashlib.sha256(ids.encode('utf-8')).hexdigest()[:24]
    if not chain:
        flag = ''
        warnings.append("zanjir bo'sh: nomzod hodisa qolmadi (baseline filtri hammasini tasdiqlangan deb oldi yoki ma'lumot yetarli emas), flag hisoblanmadi")
    
    if ctx.get('expected_stages') and len(chain) != ctx['expected_stages']:
        warnings.append('expected_stages bilan zanjir uzunligi farq qildi')
        
    groups = collections.defaultdict(list)
    for e in appr_list:
        a = e['attrs']
        tkt = None
        prefixes = {p for p, _, _ in B['ranges']} | {x.split('-')[0] for x in B['singles']}
        for v in a.values():
            if isinstance(v, str) and re.fullmatch(r'([A-Z]{2,})-\d+', v) and v.split('-')[0] in prefixes:
                tkt = v; break
        if tkt: groups[tkt].append(e)
        
    sorted_groups = sorted(groups.items(), key=lambda x: x[0])
    selected_tkts = []
    covered_classes = set()
    for tkt, grp in sorted_groups:
        ac = grp[0]['attrs'].get('actor_class', '')
        if ac and ac not in covered_classes and len(selected_tkts) < 3:
            selected_tkts.append(tkt)
            covered_classes.add(ac)
    for tkt, grp in sorted_groups:
        if len(selected_tkts) >= 3: break
        if tkt not in selected_tkts:
            selected_tkts.append(tkt)
    selected_tkts.sort()

    lookalike_groups = []
    for tkt in selected_tkts:
        grp = groups[tkt]
        ac = grp[0]['attrs'].get('actor_class', '')
        actions = sorted(set(e['action'] for e in grp))
        nets = []
        for e in grp:
            for v in e['attrs'].values():
                if isinstance(v, str) and re.match(r'^\d+\.\d+\.\d+\.\d+$', v):
                    try:
                        ip = ipaddress.ip_address(v)
                        in_net = bool(B['nets'] and any(ip in n for n in B['nets']) or v in B['ips'])
                        nets.append({"ip": v, "in_approved_network": in_net})
                    except: pass
        nets = [dict(t) for t in sorted({tuple(d.items()) for d in nets})]
        ip_note = ("IP lar approved_network da" if all(n['in_approved_network'] for n in nets) else "DIQQAT: approved_network dan tashqari IP bor") if nets else "IP yo'q"
        reason = f"{tkt} diapazonda, actor_class={ac} tasdiqlangan, {ip_note}"
        lookalike_groups.append({
            'ticket': tkt, 'actor_class': ac, 'events': len(grp),
            'actions': actions, 'networks': nets, 'reason': reason
        })
        
    sub = {}
    tpl = ctx.get('template') or {'timeline': [], 'observed_initial_access': '', 'affected_assets': [], 'successful_actions': [], 'blocked_actions': [], 'benign_exclusions': [], 'detections': [], 'unknowns': [], 'flag': ''}
    
    for k in tpl:
        if k == 'timeline':
            sub[k] = []
            for i, e in enumerate(chain):
                ev_links = []
                for j, x in enumerate(chain):
                    if i != j:
                        for v in ident_values(e):
                            if v in ident_values(x):
                                ev_links.append(f"{j+1}-bosqich bilan umumiy: {v}")
                ev_links = sorted(set(ev_links))
                ev_links.append(f"raw_time={e['raw_time']}, clock_offset_seconds={e['off']} → utc={e['utc'].strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+'Z'}")
                sub[k].append({
                    'stage': i+1, 'utc': e['utc'].strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+'Z',
                    'event_id': e['id'], 'source': e['source'], 'action': e['action'],
                    'evidence': ev_links
                })
        elif k in ('observed_initial_access', 'initial_access'):
            if chain:
                e0 = chain[0]
                iv = ident_values(e0)
                attrs_str = ', '.join(f"{ak}={av}" for ak, av in e0['attrs'].items() if str(av) in iv)
                sub[k] = f"Source: {e0['source']}, Action: {e0['action']}, UTC: {e0['utc'].strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+'Z'}, Attrs: {attrs_str}. Credential qanday olingani — kuzatilmagan, taxmin"
        elif k == 'affected_assets':
            ass = set()
            for e in chain:
                for a_k, a_v in e['attrs'].items():
                    if any(x in a_k.lower() for x in ('host','vm','device','site','table','project','tenant','controller','server','object')):
                        ass.add(str(a_v))
            sub[k] = sorted(ass)
        elif k == 'successful_actions':
            sub[k] = [{'event_id': e['id'], 'utc': e['utc'].strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+'Z', 'action': e['action'], 'outcome': outcome(e)} for e in chain if outcome(e) == 'success']
        elif k == 'blocked_actions':
            sub[k] = [{'event_id': e['id'], 'utc': e['utc'].strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+'Z', 'action': e['action'], 'outcome': outcome(e)} for e in chain if outcome(e) in ('blocked', 'response')]
        elif k == 'attempt_vs_success':
            sub[k] = [{'event_id': e['id'], 'utc': e['utc'].strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+'Z', 'action': e['action'], 'outcome': outcome(e)} for e in chain]
        elif k == 'benign_exclusions':
            sub[k] = lookalike_groups
        elif k == 'detections':
            acts_seen = set()
            sub[k] = []
            ranges_str = ', '.join([f"{p}-{lo}..{hi}" for p, lo, hi in B['ranges']] + sorted(B['singles']))
            cls_str = ', '.join(sorted(B['classes'])) if B['classes'] else "yo'q"
            nets_str = ', '.join(str(n) for n in B['nets']) if B['nets'] else "yo'q"
            fpc = f"diapazon: {ranges_str}, actor_class: {cls_str}, approved_network: {nets_str}"
            for e in chain:
                act = e['action']
                if act not in acts_seen:
                    acts_seen.add(act)
                    sub[k].append({
                        "name": f"Action {act}",
                        "logic": f"action == '{act}' AND NOT (baseline ticket diapazonda AND actor_class tasdiqlangan AND ip approved_network da)",
                        "false_positive_control": fpc,
                        "example_event_id": e['id']
                    })
            if len(sub[k]) < 3:
                for v in sorted(set.union(*[ident_values(e) for e in chain])) if chain else []:
                    srcs = {e['source']: e['id'] for e in chain if v in ident_values(e)}
                    if len(srcs) >= 2:
                        ids2 = list(srcs.values())
                        sub[k].append({
                            "name": "Identifikator ko'p manbada",
                            "logic": f"'{v}' identifikatori baseline ticketsiz >= 2 manbada",
                            "false_positive_control": fpc,
                            "example_event_id": f"{ids2[0]}, {ids2[1]}"
                        })
                        break
            if len(sub[k]) < 3:
                for e in chain:
                    has_out_ip = False
                    for v in e['attrs'].values():
                        if isinstance(v, str) and re.match(r'^\d+\.\d+\.\d+\.\d+$', v):
                            try:
                                ip = ipaddress.ip_address(v)
                                if B['nets'] and not any(ip in net for net in B['nets']) and v not in B['ips']:
                                    has_out_ip = True; break
                            except: pass
                    if has_out_ip:
                        sub[k].append({
                            "name": "Tashqaridagi IP",
                            "logic": "approved_network dan tashqaridagi IP bilan baseline ticketsiz hodisa",
                            "false_positive_control": fpc,
                            "example_event_id": e['id']
                        })
                        break
        elif k == 'unknowns':
            sub[k] = [f"{e['id']} {e['action']}" for e in orphans] + [e['id'] for e in chain if e.get('order_uncertain')] + ["log yo'qligi harakat yo'qligini isbotlamaydi"]
        elif k == 'flag':
            sub[k] = flag
        else:
            sub[k] = tpl[k]
            
    return {
        'chain': chain, 'flag': flag, 'flag_input': ids,
        'counts': {'total': len(events), 'approved': len(appr_list), 'telemetry': len(tel_list), 'candidate': len(cand), 'components': [len(c) for c in comps]},
        'baseline': B, 'orphans': orphans, 'lookalike_groups': lookalike_groups,
        'warnings': warnings, 'submission': sub
    }
