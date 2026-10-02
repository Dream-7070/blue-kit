import yaml
import os

_eventmap = None
_eventmap_validated = False

def load_eventmap(kb=None):
    global _eventmap, _eventmap_validated
    if _eventmap is None:
        path = os.path.join(os.path.dirname(__file__), 'eventmap.yaml')
        with open(path, 'r', encoding='utf-8') as f:
            _eventmap = yaml.safe_load(f)
            
    if kb and not _eventmap_validated:
        _eventmap_validated = True
        all_ids = set()
        for rule in _eventmap:
            for t in rule.get('techniques', []):
                all_ids.add(t)
                
        if all_ids:
            val_res = kb.validate(list(all_ids))
            for res in val_res:
                if not res['found']:
                    print(f"WARNING: eventmap.yaml contains unknown technique ID: {res['input']}")
                elif res['status'] in ('revoked', 'deprecated'):
                    rep = res.get('replacement')
                    msg = f"WARNING: eventmap.yaml contains {res['status']} technique ID: {res['input']}"
                    if rep: msg += f" (replaced by {rep})"
                    print(msg)
                    
    return _eventmap

_noise_rules = None

def load_noise():
    global _noise_rules
    if _noise_rules is None:
        _noise_rules = []
        path = os.path.join(os.path.dirname(__file__), 'noise.yaml')
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                rules = yaml.safe_load(f) or []
                for rule in rules:
                    try:
                        import re
                        c = re.compile(rule['pattern'], re.I)
                        _noise_rules.append({
                            'name': rule['name'],
                            'pattern': c,
                            'action': rule.get('action', 'drop')
                        })
                    except Exception as e:
                        print(f"WARNING: Invalid regex in noise.yaml for rule {rule.get('name')}: {e}")
    return _noise_rules

from bluekit.netutil import is_external_ip

def _is_external_ip(value):
    return is_external_ip(value)

def detect_event(kb, ev, deep=False, noise=None):
    hits = []
    
    emap = load_eventmap(kb)
    for rule in emap:
        if ev['channel'] and ev['event_id']:
            if rule['channel'].lower() in ev['channel'].lower() and str(ev['event_id']) == str(rule['event_id']):
                # Tashqi (internet) IP dan logon: lateral movement emas, External Remote Services
                external = 'T1021.001' in rule['techniques'] and _is_external_ip(ev.get('src_ip'))
                techs = list(rule['techniques']) + (['T1133'] if external else [])
                for t in techs:
                    try:
                        tinfo = kb.lookup(t)[0]
                        name = tinfo['name']
                    except:
                        name = ""
                    ext_note = f" (tashqi IP {ev.get('src_ip')})" if external else ""
                    hits.append({
                        'technique': t,
                        'name': name,
                        'confidence': 'low' if external and t == 'T1021.001' else rule['confidence'],
                        'score': 1.0,
                        'source': 'eventmap',
                        'evidence': f"Matched {rule['channel']} event {rule['event_id']}{ext_note}"
                    })
                    
    text_to_search = ""
    if ev['command_line']:
        text_to_search = ev['command_line']
    elif ev.get('message'):
        text_to_search = ev['message']
        
    if ev.get('process'):
        import os
        p_base = os.path.basename(ev['process']).strip()
        if p_base and p_base.lower() not in text_to_search.lower():
            text_to_search = (p_base + " " + text_to_search).strip()
        
    if text_to_search:
        res = kb.search(text_to_search) if deep else kb.search_heuristics(text_to_search)
        blob_candidates = []
        
        for r in res:
            is_heuristic = r.get('sources', {}).get('heuristic', 0) > 0
            if is_heuristic:
                snippet = text_to_search[:50] + "..." if len(text_to_search) > 50 else text_to_search
                hits.append({
                    'technique': r['attack_id'],
                    'name': r['name'],
                    'confidence': 'high',
                    'score': r['score'],
                    'source': 'heuristic',
                    'evidence': f"KB search match on: {snippet}"
                })
            elif deep:
                blob_candidates.append(r)
                
        if deep and blob_candidates:
            max_score = max([r['score'] for r in blob_candidates])
            filtered = [r for r in blob_candidates if r['score'] >= 0.35 * max_score]
            filtered.sort(key=lambda x: x['score'], reverse=True)
            for r in filtered[:3]:
                hits.append({
                    'technique': r['attack_id'],
                    'name': r['name'],
                    'confidence': 'low',
                    'score': r['score'],
                    'source': 'blob_search',
                    'evidence': f"KB search match on event text"
                })
                
    if noise is None:
        noise = load_noise()
        
    noise_text = ev.get('command_line') or ev.get('message') or ''
    for rule in noise:
        if rule['pattern'].search(noise_text):
            if rule['action'] == 'drop':
                # Kuchli event-ID signali (7045 xizmat o'rnatish, 4720, 1102 ...) buyruq
                # qatori "toza" ko'rinsa ham tashlanmaydi: PSEXESVC.exe C:\Windows\ ichida.
                keep = [h for h in hits if h.get('source') == 'eventmap' and h['confidence'] == 'high']
                if len(keep) < len(hits): ev['_noise_suppressed'] = True
                if not keep:
                    return []
                hits = keep
            elif rule['action'] == 'downgrade':
                for h in hits:
                    h['confidence'] = 'low'
                    h['noise'] = rule['name']
            
    conf_rank = {'high': 3, 'medium': 2, 'low': 1, '': 0}
    dedup = {}
    for h in hits:
        t = h['technique']
        if t not in dedup:
            dedup[t] = h
        else:
            rank1 = conf_rank.get(h['confidence'], 0)
            rank2 = conf_rank.get(dedup[t]['confidence'], 0)
            if rank1 > rank2:
                dedup[t] = h
            elif rank1 == rank2 and h['score'] > dedup[t]['score']:
                dedup[t] = h
                
    return list(dedup.values())
