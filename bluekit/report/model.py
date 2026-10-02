import datetime
import itertools

def build(logs=None, resp=None, answers=None):
    if logs is None: logs = {}
    if resp is None: resp = {}
    if answers is None: answers = {}

    model = {}
    
    # meta
    model['meta'] = {
        'title': answers.get('title', 'Incident Report'),
        'org': answers.get('org', 'Unknown Org'),
        'date': answers.get('date', datetime.datetime.now().strftime("%Y-%m-%d")),
        'team': answers.get('team', 'Unknown Team'),
        'analyst': answers.get('analyst', 'Unknown Analyst')
    }

    # Extract info from logs
    log_timeline = logs.get('timeline', [])
    log_iocs = logs.get('iocs', [])
    log_coverage = logs.get('coverage', {})
    
    # Extract info from resp
    resp_findings = resp.get('findings', [])
    resp_extra = resp.get('extra', {})

    # Techniques
    from bluekit.kb.query import KB
    kb = KB()
    
    raw_techniques = {}
    for e in log_timeline:
        for t in e.get('techniques', []):
            t_id = t.get('technique')
            if not t_id: continue
            if t.get('confidence') == 'low': continue
            if t_id not in raw_techniques: raw_techniques[t_id] = {'count': 0, 'evidence': e.get('short_cmd', e.get('command', ''))}
            raw_techniques[t_id]['count'] += 1

    for f in resp_findings:
        for t in f.get('techniques', []):
            t_id = t.get('id')
            if not t_id: continue
            if t_id not in raw_techniques: raw_techniques[t_id] = {'count': 0, 'evidence': f.get('item', '')}
            raw_techniques[t_id]['count'] += 1
            
    techniques_dict = {}
    for t_id, info in raw_techniques.items():
        val = kb.validate([t_id])
        if not val or not val[0]['found']: continue
        v = val[0]
        
        real_id = v['replacement'] if v['status'] == 'revoked' and v.get('replacement') else v['normalized']
        if v['status'] == 'deprecated' or (v['status'] == 'revoked' and not v.get('replacement')):
            continue
            
        lk = kb.lookup(real_id)
        if not lk: continue
        tactic_list = lk[0].get('tactics', [])
        tactic_str = tactic_list[0] if tactic_list else ''
        name = lk[0].get('name', v.get('name', ''))
        
        if real_id not in techniques_dict:
            techniques_dict[real_id] = {
                'id': real_id,
                'name': name,
                'tactic': tactic_str,
                'count': info['count'],
                'evidence-sample': str(info['evidence'])[:100]
            }
        else:
            techniques_dict[real_id]['count'] += info['count']

    model['techniques'] = list(techniques_dict.values())
    
    # Get tactic order from KB
    c = kb.conn.cursor()
    tactic_ord = {r['shortname']: r['ord'] for r in c.execute('SELECT shortname, ord FROM tactics').fetchall()}
    model['techniques'].sort(key=lambda x: (tactic_ord.get(x.get('tactic', ''), 99), x['id']))

    # exec_summary
    if answers.get('exec_summary'):
        model['exec_summary'] = answers['exec_summary']
    else:
        # auto-build factual summary
        h_count = len(set(e.get('host') for e in log_timeline if e.get('host')))
        i_count = len(log_iocs)
        r_count = len(resp_findings)
        
        tactics_map = {}
        for t in model['techniques']:
            tac = t.get('tactic', '')
            if tac not in tactics_map: tactics_map[tac] = []
            tactics_map[tac].append(t['id'])
        
        first_tactic = ""
        impact_t = ""
        if tactics_map:
            for k in ['initial-access', 'execution', 'persistence']:
                for tac in tactics_map.keys():
                    if k in tac.lower():
                        first_tactic = ", ".join(tactics_map[tac])
                        break
                if first_tactic: break
            
            for k in ['impact', 'exfiltration']:
                for tac in tactics_map.keys():
                    if k in tac.lower():
                        impact_t = ", ".join(tactics_map[tac])
                        break
                if impact_t: break
        
        summary = f"Tergov {len(log_timeline)} hodisa, {h_count} host, {len(model['techniques'])} ATT&CK texnikasi aniqladi. "
        if first_tactic: summary += f"Boshlang'ich kirish: {first_tactic}. "
        if impact_t: summary += f"Ta'sir: {impact_t}. "
        summary += f"{i_count} IOC ajratildi. {r_count} remediation amali bajarildi."
        model['exec_summary'] = summary

    # timeline
    capped_timeline = []
    # filter for high/medium conf or just take top
    for e in log_timeline:
        capped_timeline.append({
            'ts': e.get('ts', ''),
            'host': e.get('host', ''),
            'user': e.get('user', ''),
            'technique': e.get('technique', ''),
            'command': e.get('short_cmd', e.get('command', ''))[:100]
        })
    if len(capped_timeline) > 40:
        capped_timeline = capped_timeline[:40]
        model['timeline_truncated'] = True
    else:
        model['timeline_truncated'] = False
    model['timeline'] = capped_timeline

    # iocs
    filtered_iocs = []
    for i in log_iocs:
        # just basic format
        filtered_iocs.append({
            'type': i.get('type', ''),
            'value': i.get('value', ''),
            'count': i.get('count', 1),
            'first': i.get('first', ''),
            'last': i.get('last', '')
        })
    model['iocs'] = filtered_iocs

    # hosts
    hosts_dict = {}
    for e in log_timeline:
        h = e.get('host')
        if not h: continue
        tac = e.get('tactic', '')
        if h not in hosts_dict:
            hosts_dict[h] = set()
        if tac:
            hosts_dict[h].add(tac)
    model['hosts'] = [{'host': k, 'tactics': list(v)} for k, v in hosts_dict.items()]

    # coverage
    model['coverage'] = log_coverage

    # remediation
    rem_done = []
    for f in resp_findings:
        rem_done.append({
            'item': f.get('item', ''),
            'technique': ",".join(t.get('id', '') for t in f.get('techniques', [])),
            'status': f.get('status', "buyruq tayyorlandi"),
            'protected': f.get('protected', False)
        })
    
    rem_manual = []
    for u in resp_extra.get('unmatched_log_artifacts', []):
        rem_manual.append({
            'item': u.get('artifact', ''),
            'technique': '',
            'status': "qo'lda tekshirilsin",
            'protected': False
        })
    
    model['remediation'] = {'done': rem_done, 'manual': rem_manual}
    
    # checker_note
    if logs.get('checkers'):
        model['checker_note'] = "Davriy trafik (checker/SLA) aniqlandi — remediation'da tegilmadi"
    else:
        model['checker_note'] = ""
        
    if answers.get('recommendations'):
        model['recommendations'] = answers['recommendations']
    else:
        model['recommendations'] = ""

    return model
