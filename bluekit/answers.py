import json
import os
import tempfile
from collections import defaultdict
from datetime import datetime

def collect(paths: list) -> dict:
    collected = defaultdict(lambda: {
        'sources': set(),
        'evidence': [],
        'ir_timeline_steps': 0,
        'ir_occurrences': 0,
        'sigma_strong_rules': set(),
        'sigma_weak_rules': set(),
        'sigma_high_crit_rules': set(),
        'sigma_count': 0,
        'log_high_conf': False,
        'log_low_conf': False,
        'log_blob': False,
        'log_count': 0,
    })

    for path in paths:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            import warnings
            warnings.warn(f"Failed to read/parse {path}: {e}")
            continue

        if 'mitre_attack_techniques' in data or 'attack_chain_timeline' in data:
            # IR Chain
            for tech in data.get('mitre_attack_techniques', []):
                tid = tech.get('technique_id')
                if not tid:
                    continue
                c = collected[tid]
                c['sources'].add('ir_chain')
                occ = tech.get('occurrences', 1)
                c['ir_occurrences'] += occ
                c['evidence'].append(f"IR zanjiri: {tech.get('technique_name', tid)} ({occ} marta)")

            for step in data.get('attack_chain_timeline', []):
                tid = step.get('mitre_id')
                if not tid:
                    continue
                c = collected[tid]
                c['sources'].add('ir_chain')
                c['ir_timeline_steps'] += 1
                c['evidence'].append(f"IR zanjiri {step.get('step', '?')}-qadam: {step.get('evidence', '')}")
                c['ir_occurrences'] += 1

        elif 'hits' in data and 'by_technique' in data:
            # Sigma
            by_tech = data.get('by_technique', {})
            for tid, info in by_tech.items():
                c = collected[tid]
                c['sources'].add('sigma')
                c['sigma_count'] += info.get('count', 1)
                
            for hit in data.get('hits', []):
                for rule in hit.get('rules', []):
                    for tid in rule.get('techniques', []):
                        c = collected[tid]
                        c['sources'].add('sigma')
                        rule_id = rule.get('rule_id', rule.get('title'))
                        if rule.get('weak'):
                            c['sigma_weak_rules'].add(rule_id)
                        else:
                            c['sigma_strong_rules'].add(rule_id)
                        
                        level = rule.get('level', '').lower()
                        if level in ('high', 'critical'):
                            c['sigma_high_crit_rules'].add(rule_id)
                            
                        c['evidence'].append(f"Sigma: {rule.get('title')} ({level})")

        elif 'timeline' in data and isinstance(data.get('timeline'), list):
            # `bk logs analyze --json-out` haqiqiy formati: timeline[].techniques[]
            # har biri {technique, name, confidence, score, source, evidence}.
            def find_techs(obj, path_str=""):
                if isinstance(obj, dict):
                    if 'technique_id' in obj or 'technique' in obj:
                        tid = obj.get('technique_id') or obj.get('technique')
                        conf = str(obj.get('confidence', '')).lower()
                        source = str(obj.get('source', '')).lower()
                        evidence = obj.get('evidence', '') or obj.get('message', '')
                        if tid:
                            c = collected[tid]
                            c['sources'].add('logs')
                            c['log_count'] += 1
                            if conf == 'high':
                                c['log_high_conf'] = True
                            elif conf == 'low':
                                c['log_low_conf'] = True
                            
                            if 'blob' in source:
                                c['log_blob'] = True
                            c['evidence'].append(f"Logs: {evidence}")
                    for k, v in obj.items():
                        find_techs(v, path_str + "." + k)
                elif isinstance(obj, list):
                    for i, v in enumerate(obj):
                        find_techs(v, path_str + f"[{i}]")

            find_techs(data['timeline'])

        else:
            import warnings
            warnings.warn(f"Unrecognized format in {path}, skipping")

    return dict(collected)


def rank(collected: dict, kb=None, submitted=None, prefer_parent=False) -> list:
    results = []
    
    kb_data = {}
    if kb:
        validations = kb.validate(list(collected.keys()))
        for v in validations:
            kb_data[v['input']] = v

    submitted_techs = set()
    if submitted:
        for entry in submitted.get('entries', []):
            if entry.get('result') in ('accepted', 'rejected'):
                submitted_techs.add(entry.get('technique'))

    for tid, c in collected.items():
        score = 0
        
        if c['ir_timeline_steps'] > 0:
            score += 4
        elif c['ir_occurrences'] > 0:
            score += 2
            
        strong_sigma = len(c['sigma_strong_rules'])
        if strong_sigma > 0:
            score += min(6, strong_sigma * 3)
        elif len(c['sigma_weak_rules']) > 0:
            score += 0.5
            
        score += len(c['sigma_high_crit_rules']) * 1
        
        if c['log_high_conf']:
            score += 2
        if c['log_low_conf'] or c['log_blob']:
            score += 0.5
            
        if len(c['sources']) >= 2:
            score += 3
            
        total_occurrences = c['ir_occurrences'] + c['sigma_count'] + c['log_count']
        if total_occurrences > 5:
            score += 1

        if score >= 8:
            confidence = "yuqori"
        elif score >= 4:
            confidence = "o'rta"
        else:
            confidence = "past"
            
        is_submitted = tid in submitted_techs
        
        k = kb_data.get(tid, {})
        kb_status = k.get('status', 'not_found')
        if not k.get('found', False):
            kb_status = 'not_found'
            confidence = "past"
            
        name = k.get('name', 'Unknown')
        replacement = k.get('replacement')
        parent_id = k.get('parent_id')
        
        if not parent_id and '.' in tid:
            parent_id = tid.split('.')[0]
            
        # Deduplicate evidence
        ev = []
        for e in c['evidence']:
            if e not in ev:
                ev.append(e)

        results.append({
            'rank': 0,
            'technique': tid,
            'name': name,
            'score': float(score),
            'confidence': confidence,
            'sources': list(c['sources']),
            'evidence': ev,
            'kb_status': kb_status,
            'replacement': replacement,
            'parent': parent_id,
            'submitted': is_submitted,
            '_total_occ': total_occurrences
        })

    # Ro'yxatdagi qaysi ID lar boshqa bir yozuvning ota-texnikasi sifatida ishlatilgan
    referenced_parents = {r['parent'] for r in results if r['parent']}

    # Sort results
    def sort_key(r):
        sub_penalty = 1 if r['submitted'] else 0
        not_found_penalty = 1 if r['kb_status'] == 'not_found' else 0

        # Parent vs Sub-technique: prefer_parent=False bo'lsa sub yuqori, True bo'lsa ota yuqori
        parent_boost = 0
        if prefer_parent:
            if r['technique'] in referenced_parents:
                parent_boost = 1
        else:
            if r['parent']:
                parent_boost = 1

        return (-sub_penalty, -not_found_penalty, r['score'], parent_boost, r['_total_occ'])

    results.sort(key=sort_key, reverse=True)
    
    for i, r in enumerate(results):
        r['rank'] = i + 1
        del r['_total_occ']
        
    return results


def load_ledger(path) -> dict:
    if not os.path.exists(path):
        return {"entries": []}
    with open(path, 'r', encoding='utf-8') as f:
        try:
            return json.load(f)
        except:
            return {"entries": []}


def record(path, technique, result, note=None) -> dict:
    ledger = load_ledger(path)
    entry = {
        "technique": technique,
        "result": result,
        "at": datetime.now().isoformat(),
        "note": note,
        "by": None
    }
    ledger["entries"].append(entry)
    
    fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(ledger, f, indent=2)
        os.replace(temp_path, path)
    except Exception as e:
        os.unlink(temp_path)
        raise e
        
    return ledger
