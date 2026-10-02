from collections import defaultdict
from bluekit.kb.ioc import classify
from datetime import timedelta

def translate_all_hits(hits_by_index, kb):
    all_ids = set()
    for hits in hits_by_index.values():
        for h in hits:
            all_ids.add(h['technique'])
            
    if not all_ids: return
    
    val_res = kb.validate(list(all_ids))
    mapping = {}
    for res in val_res:
        if res['found'] and res['status'] in ('revoked', 'deprecated') and res['replacement']:
            mapping[res['input']] = res['replacement']
            mapping[res['normalized']] = res['replacement']
            
    if not mapping: return
    
    conf_rank = {'high': 3, 'medium': 2, 'low': 1, '': 0}
    for i, hits in list(hits_by_index.items()):
        if not hits: continue
        new_hits = []
        changed = False
        for h in hits:
            t = h['technique']
            if t in mapping:
                changed = True
                rep = mapping[t]
                h_new = dict(h)
                h_new['technique'] = rep
                try:
                    tinfo = kb.lookup(rep)[0]
                    h_new['name'] = tinfo['name']
                except:
                    h_new['name'] = ""
                new_hits.append(h_new)
            else:
                new_hits.append(h)
                
        if changed:
            dedup = {}
            for h in new_hits:
                t = h['technique']
                if t not in dedup:
                    dedup[t] = h
                else:
                    rank1 = conf_rank.get(h['confidence'], 0)
                    rank2 = conf_rank.get(dedup[t]['confidence'], 0)
                    if rank1 > rank2:
                        dedup[t] = h
                    elif rank1 == rank2 and h.get('score', 0) > dedup[t].get('score', 0):
                        dedup[t] = h
            hits_by_index[i] = list(dedup.values())

def build(events, hits_by_index, kb):
    from bluekit.tz import display_ts
    disp_of = {}
    for ev in events:
        ts = ev.get('ts')
        if ts and ts not in disp_of:
            disp_of[ts] = ev.get('ts_disp') or display_ts(ts)

    timeline = []
    
    iocs = defaultdict(lambda: {'count': 0, 'first': None, 'last': None, 'sources': set()})
    
    def add_ioc(type_, val, ts, source):
        if not val: return
        iocs[(type_, val)]['count'] += 1
        if ts:
            if not iocs[(type_, val)]['first'] or ts < iocs[(type_, val)]['first']:
                iocs[(type_, val)]['first'] = ts
            if not iocs[(type_, val)]['last'] or ts > iocs[(type_, val)]['last']:
                iocs[(type_, val)]['last'] = ts
        if source:
            iocs[(type_, val)]['sources'].add(source)
                
    failed_logons = defaultdict(list)
    for i, ev in enumerate(events):
        eid = str(ev.get('event_id', ''))
        target_user = ev.get('target') or ev.get('user')
        ts = ev.get('ts')
        if not ts:
            continue
        if eid == '4625' and target_user:
            failed_logons[target_user].append(ts)
        elif eid == '4624' and target_user:
            fails = [t for t in failed_logons.get(target_user, []) if t >= ts - timedelta(minutes=10) and t <= ts]
            if len(fails) >= 5:
                if i not in hits_by_index:
                    hits_by_index[i] = []
                existing = next((h for h in hits_by_index[i] if h['technique'] == 'T1110'), None)
                if existing:
                    existing['confidence'] = 'high'
                    existing['source'] = 'correlation'
                    existing['evidence'] = f"{len(fails)} failed logons then success"
                else:
                    hits_by_index[i].append({
                        'technique': 'T1110',
                        'name': 'Brute Force',
                        'confidence': 'high',
                        'score': 1.0,
                        'source': 'correlation',
                        'evidence': f"{len(fails)} failed logons then success"
                    })
                    
    translate_all_hits(hits_by_index, kb)

    for i, ev in enumerate(events):
        hits = hits_by_index.get(i, [])
        primary_tech = None
        primary_conf = None
        if hits:
            best = max(hits, key=lambda x: {'high':3,'medium':2,'low':1,'':0}.get(x['confidence'],0))
            primary_tech = best['technique']
            primary_conf = best['confidence']
            
        cmd_val = ev.get('command_line') or ev.get('message') or ""
        cmd_trunc = cmd_val[:100] + "..." if cmd_val and len(cmd_val)>100 else cmd_val
        from bluekit.tz import display_ts
        timeline.append({
            'index': i,
            'ts': ev['ts'],
            'ts_disp': ev.get('ts_disp') or display_ts(ev['ts']),
            'host': ev['host'],
            'user': ev['user'],
            'process': ev['process'],
            'parent_process': ev['parent_process'],
            'command_line': cmd_trunc,
            'command_line_full': cmd_val,
            'message': ev.get('message'),
            'raw': ev.get('raw'),
            'techniques': hits,
            'primary_technique': primary_tech,
            'primary_confidence': primary_conf,
            'channel': ev['channel'],
            'event_id': ev['event_id'],
            'source': ev.get('source')
        })
        
        add_ioc('ip', ev['src_ip'], ev['ts'], ev.get('source'))
        add_ioc('ip', ev['dest_ip'], ev['ts'], ev.get('source'))
        
        if ev['command_line']:
            cls = classify(ev['command_line'])
            if cls['type'] != 'unknown':
                add_ioc(cls['type'], cls['value'], ev['ts'], ev.get('source'))
                
        if ev['event_id'] in ('4720', 'useradd') and ev['target']:
            add_ioc('username', ev['target'], ev['ts'], ev.get('source'))

    chains = []
    chain_id = 1
    
    hosts = defaultdict(list)
    for t in timeline:
        if t['host']:
            hosts[t['host']].append(t)
            
    for host, host_events in hosts.items():
        if not host_events: continue
        chain = {
            'id': chain_id,
            'host': host,
            'user': host_events[0]['user'],
            'start': host_events[0]['ts'],
            'end': host_events[-1]['ts'],
            'events': [e['index'] for e in host_events],
            'tactics': [],
            'techniques': []
        }
        for e in host_events:
            for h in e['techniques']:
                if h['technique'] not in chain['techniques']:
                    chain['techniques'].append(h['technique'])
                if h['confidence'] in ('high', 'medium'):
                    try:
                        tinfo = kb.lookup(h['technique'])[0]
                        for tac in tinfo.get('tactics', []):
                            if tac not in chain['tactics']:
                                chain['tactics'].append(tac)
                    except:
                        pass
        chains.append(chain)
        chain_id += 1
        
    formatted_iocs = []
    for (type_, val), data in iocs.items():
        first_ts = data['first']
        last_ts = data['last']
        formatted_iocs.append({
            'type': type_,
            'value': val,
            'count': data['count'],
            'first': first_ts,
            'last': last_ts,
            'first_disp': disp_of.get(first_ts) or display_ts(first_ts) if first_ts else "",
            'last_disp': disp_of.get(last_ts) or display_ts(last_ts) if last_ts else "",
            'sources': sorted(list(data['sources']))
        })
        
    import statistics
    
    conn_groups = defaultdict(list)
    for ev in events:
        if ev['ts'] and ev['src_ip'] and ev['dest_ip']:
            dest_extra = ev['command_line'] or ev['process'] or ""
            key = (ev['src_ip'], ev['dest_ip'], dest_extra)
            conn_groups[key].append(ev['ts'])
            
    checkers = []
    for key, times in conn_groups.items():
        if len(times) >= 4:
            times = sorted(times)
            deltas = [(times[i+1] - times[i]).total_seconds() for i in range(len(times)-1)]
            if deltas:
                median_delta = statistics.median(deltas)
                if median_delta > 0:
                    stdev_delta = statistics.stdev(deltas) if len(deltas) > 1 else 0
                    if (stdev_delta / median_delta) < 0.30:
                        checkers.append({
                            'src': key[0],
                            'dst': key[1],
                            'key': f"{key[0]} -> {key[1]} ({key[2]})",
                            'count': len(times),
                            'interval_seconds': median_delta,
                            'first': times[0],
                            'last': times[-1],
                            'first_disp': disp_of.get(times[0]) or display_ts(times[0]) if times[0] else "",
                            'last_disp': disp_of.get(times[-1]) or display_ts(times[-1]) if times[-1] else "",
                            'sample_evidence': "davriy — checker yoki C2 beacon bo'lishi mumkin"
                        })
                        
    return timeline, chains, formatted_iocs, checkers
