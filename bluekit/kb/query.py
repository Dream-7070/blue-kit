import sqlite3
import re
from pathlib import Path
from ..paths import get_kb_path

class KB:
    def __init__(self, path=None):
        self.path = path or get_kb_path()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._heur_compiled = None
        self._tech_status = None
        self._active_techs = None
        
    def version(self):
        c = self.conn.cursor()
        return dict(c.execute("SELECT key, value FROM meta").fetchall())
        
    def lookup(self, attack_id):
        aid = attack_id.upper().strip()
        c = self.conn.cursor()
        rows = c.execute("SELECT * FROM techniques WHERE attack_id=?", (aid,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d['tactics'] = d['tactics'].split(',') if d['tactics'] else []
            d['platforms'] = d['platforms'].split(',') if d['platforms'] else []
            if d['revoked']: d['status'] = 'revoked'
            elif d['deprecated']: d['status'] = 'deprecated'
            else: d['status'] = 'active'
            
            d['short_description'] = (d['description'] or '')[:400]
            
            # Mitigations
            mits = c.execute("SELECT name FROM mitigations JOIN mitigates ON mitigates.mitigation_id=mitigations.attack_id WHERE mitigates.technique_id=? AND mitigates.domain=?", (aid, d['domain'])).fetchall()
            d['mitigations'] = [m[0] for m in mits]
            
            # Atomic
            d['atomic_count'] = c.execute("SELECT count(*) FROM atomic_tests WHERE technique_id=?", (aid,)).fetchone()[0]
            
            # Sigma
            d['sigma_count'] = c.execute("SELECT count(*) FROM sigma_rules WHERE techniques LIKE ?", (f"%{aid}%",)).fetchone()[0]
            
            out.append(d)
        return out
        
    def validate(self, ids):
        c = self.conn.cursor()
        out = []
        for i in ids:
            aid = i.upper().strip()
            rows = c.execute("SELECT name, domain, revoked, deprecated, revoked_by, parent_id FROM techniques WHERE attack_id=?", (aid,)).fetchall()
            if not rows:
                out.append({'input': i, 'normalized': aid, 'found': False, 'message': 'Not found'})
            else:
                domains = [r['domain'] for r in rows]
                r = rows[0]
                status = 'active'
                if r['revoked']: status = 'revoked'
                elif r['deprecated']: status = 'deprecated'
                
                out.append({
                    'input': i, 'normalized': aid, 'found': True, 'status': status, 'domains': domains,
                    'name': r['name'], 'replacement': r['revoked_by'], 'parent_id': r['parent_id'], 'message': ''
                })
        return out
        
    def search(self, text, limit=20, domain=None):
        c = self.conn.cursor()
        # SAFE FTS5 query
        tokens = [f'"{t}"' for t in re.findall(r'\w+', text)]
        if not tokens:
            return []
        q = " OR ".join(tokens)
        
        dom_filter = f"AND domain='{domain}'" if domain else ""
        
        rows = c.execute(f"""
            SELECT attack_id, domain, source, ref, rank FROM search_idx 
            WHERE search_idx MATCH ? {dom_filter}
        """, (q,)).fetchall()
        
        scores = {}
        sources_cnt = {}
        evidences = {}
        
        weights = {'technique': 1.0, 'sigma': 1.3, 'atomic': 1.5, 'heuristic': 100.0}
        for r in rows:
            aid = r['attack_id']
            dom = r['domain']
            src = r['source']
            k = (aid, dom)
            
            scores[k] = scores.get(k, 0) + (-r['rank']) * weights.get(src, 1.0)
            
            if k not in sources_cnt: sources_cnt[k] = {'technique':0, 'sigma':0, 'atomic':0, 'heuristic':0}
            sources_cnt[k][src] += 1
            
            if src in ('sigma', 'atomic') and r['ref']:
                if k not in evidences: evidences[k] = []
                if len(evidences[k]) < 3:
                    evidences[k].append(r['ref'])
                    
        # Heuristics
        heuristics = c.execute("SELECT name, pattern, techniques, weight FROM heuristics").fetchall()
        for h in heuristics:
            try:
                if re.search(h['pattern'], text, re.I):
                    for t in h['techniques'].split(','):
                        t = t.strip()
                        if not t: continue
                        
                        # Handle revoked -> replacement
                        tech = c.execute("SELECT attack_id, domain, revoked, deprecated, revoked_by FROM techniques WHERE attack_id=?", (t,)).fetchone()
                        if tech:
                            if tech['revoked'] and tech['revoked_by']:
                                t = tech['revoked_by']
                            elif tech['revoked'] or tech['deprecated']:
                                continue
                                
                        drows = c.execute("SELECT domain FROM techniques WHERE attack_id=? AND revoked=0 AND deprecated=0", (t,)).fetchall()
                        for dr in drows:
                            k = (t, dr['domain'])
                            scores[k] = scores.get(k, 0) + 3000.0 + (1000.0 * h['weight'])
                            
                            if k not in sources_cnt: sources_cnt[k] = {'technique':0, 'sigma':0, 'atomic':0, 'heuristic':0}
                            sources_cnt[k]['heuristic'] += 1
                            
                            if k not in evidences: evidences[k] = []
                            if len(evidences[k]) < 3:
                                evidences[k].append(h['name'])
            except:
                pass
                
        # Format results
        class SearchResults(list):
            pass
            
        out = SearchResults()
        max_s = max(scores.values()) if scores else 1
        for (aid, dom), s in sorted(scores.items(), key=lambda x: -x[1])[:limit]:
            orig_aid = aid
            tech = c.execute("SELECT name, tactics, revoked, deprecated, revoked_by FROM techniques WHERE attack_id=? AND domain=?", (aid, dom)).fetchone()
            if not tech or tech['revoked'] or tech['deprecated']:
                if tech and tech['revoked'] and tech['revoked_by']:
                    aid = tech['revoked_by']
                    tech = c.execute("SELECT name, tactics, revoked, deprecated FROM techniques WHERE attack_id=? AND domain=?", (aid, dom)).fetchone()
                    if not tech or tech['revoked'] or tech['deprecated']: continue
                else:
                    continue
                    
            sources = {k:v for k,v in sources_cnt.get((orig_aid, dom), {}).items() if v > 0}
            is_heuristic = sources.get('heuristic', 0) > 0
            
            if is_heuristic:
                conf = 'high'
            elif s > 200.0:
                conf = 'medium'
            else:
                conf = 'low'
                    
            out.append({
                'attack_id': aid,
                'name': tech['name'],
                'domain': dom,
                'tactics': tech['tactics'].split(',') if tech['tactics'] else [],
                'score': s / max_s,
                'raw': round(s, 3),
                'confidence': conf,
                'sources': sources,
                'evidence': evidences.get((orig_aid, dom), [])[:3]
            })
            
        if out and not any(r['confidence'] == 'high' for r in out) and out[0]['raw'] < 200.0:
            out.warning = "⚠ past ishonch — bu buyruq aniq bir texnikaga kuchli mos kelmadi"
            
        return out

    def related(self, observed, limit=25, domain=None, level='auto'):
        # Normalization
        obs_clean = [o.upper().strip() for o in observed]
        c = self.conn.cursor()
        
        # Get observed tactics for kill-chain bonus
        obs_tactics = set()
        for aid in obs_clean:
            t_row = c.execute("SELECT tactics, domain FROM techniques WHERE attack_id=?", (aid,)).fetchone()
            if t_row and t_row['tactics']:
                dom = domain or t_row['domain']
                for t in t_row['tactics'].split(','):
                    ord_row = c.execute("SELECT ord FROM tactics WHERE shortname=? AND domain=?", (t, dom)).fetchone()
                    if ord_row: obs_tactics.add(ord_row['ord'])
                    
        max_o = max(obs_tactics) if obs_tactics else -1
        min_o = min(obs_tactics) if obs_tactics else -1
        
        candidates = {}
        for aid in obs_clean:
            is_sub = '.' in aid
            lvl = 'sub' if level == 'auto' and is_sub else ('parent' if level == 'auto' else level)
            
            rows = c.execute("SELECT t2, both, n1, n2 FROM cooc WHERE t1=? AND level=?", (aid, lvl)).fetchall()
            for r in rows:
                t2, both, n1, n2 = r['t2'], r['both'], r['n1'], r['n2']
                if t2 in obs_clean: continue
                p = (both + 0.0) / (n1 + 2.0)
                if t2 not in candidates: candidates[t2] = []
                candidates[t2].append({
                    'p': p, 'aid': aid, 'both': both, 'n1': n1
                })
                
        out = []
        for t, cont in candidates.items():
            tech = c.execute("SELECT name, domain, tactics, revoked, deprecated FROM techniques WHERE attack_id=?", (t,)).fetchone()
            if not tech or tech['revoked'] or tech['deprecated']: continue
            if domain and tech['domain'] != domain: continue
            
            p_cooc = 1.0
            for c_item in cont:
                p_cooc *= (1.0 - c_item['p'])
            p_cooc = 1.0 - p_cooc
            
            # Kill-chain bonus
            kc_bonus = 0.0
            kc_reason = None
            if tech['tactics']:
                t_tactics = tech['tactics'].split(',')
                for tac in t_tactics:
                    ord_row = c.execute("SELECT name, ord FROM tactics WHERE shortname=? AND domain=?", (tac, tech['domain'])).fetchone()
                    if ord_row:
                        t_ord = ord_row['ord']
                        if t_ord == max_o + 1 or (min_o < t_ord < max_o and t_ord not in obs_tactics):
                            kc_bonus = 0.10
                            kc_reason = f"kill-chain: keyingi taktika ({tac})"
                            break
                            
            prob = min(1.0, (p_cooc * 0.9) + kc_bonus)
            
            # Reasons
            top_cont = sorted(cont, key=lambda x: -x['both'])[:3]
            reasons = [f"{c_item['aid']} bilan birga: {round(c_item['both'])}/{round(c_item['n1'])} aktor" for c_item in top_cont]
            if kc_reason:
                reasons.append(kc_reason)
                
            out.append({
                'attack_id': t,
                'name': tech['name'],
                'domain': tech['domain'],
                'tactics': tech['tactics'].split(',') if tech['tactics'] else [],
                'probability': round(prob, 3),
                'support': round(sum(c_item['both'] for c_item in cont)), # Support is sum of 'both'?? SPEC: "support = Σ both over s" - oh, waiting, maybe sum of both. Wait, earlier code had sum(probs)
                'reasons': reasons
            })
            
        return sorted(out, key=lambda x: -x['probability'])[:limit]
        
    def actors_matching(self, observed, limit=10):
        obs_clean = set(o.upper().strip() for o in observed)
        c = self.conn.cursor()
        
        actors = {}
        for r in c.execute("SELECT stix_id, name, type, attack_id FROM actors").fetchall():
            actors[r['stix_id']] = {'name': r['name'], 'type': r['type'], 'attack_id': r['attack_id'], 'uses': set()}
            
        for r in c.execute("SELECT actor_stix_id, technique_id FROM uses").fetchall():
            if r['actor_stix_id'] in actors:
                actors[r['actor_stix_id']]['uses'].add(r['technique_id'])
                
        scored = []
        for aid, a in actors.items():
            inter = a['uses'].intersection(obs_clean)
            if not inter: continue
            score = len(inter) / len(obs_clean)
            tie = len(inter) / len(a['uses'])
            scored.append((score, tie, a, inter))
            
        scored.sort(key=lambda x: (-x[0], -x[1]))
        
        out = []
        for s, tie, a, inter in scored[:limit]:
            unobs = list(a['uses'] - obs_clean)
            out.append({
                'name': a['name'],
                'type': a['type'],
                'attack_id': a['attack_id'],
                'matched_ids': list(inter),
                'other_count': len(unobs),
                'top_unobserved': unobs[:15]
            })
        return out
        
    def tactic_coverage(self, observed, domain='enterprise'):
        obs_clean = set(o.upper().strip() for o in observed)
        c = self.conn.cursor()
        
        tactics = c.execute("SELECT shortname, name, ord FROM tactics WHERE domain=? ORDER BY ord", (domain,)).fetchall()
        out = []
        
        for t in tactics:
            techs = c.execute("SELECT attack_id FROM techniques WHERE domain=? AND tactics LIKE ?", (domain, f"%{t['shortname']}%")).fetchall()
            t_ids = set(x['attack_id'] for x in techs)
            inter = t_ids.intersection(obs_clean)
            out.append({
                'shortname': t['shortname'],
                'name': t['name'],
                'observed': list(inter),
                'missing': len(inter) == 0
            })
        return out
        
    def mitigations_for(self, attack_id):
        c = self.conn.cursor()
        return [dict(x) for x in c.execute("SELECT m.name, m.description FROM mitigations m JOIN mitigates mm ON m.attack_id=mm.mitigation_id WHERE mm.technique_id=?", (attack_id.upper(),)).fetchall()]

    def atomics_for(self, attack_id):
        c = self.conn.cursor()
        return [dict(x) for x in c.execute("SELECT name, platforms, executor, command FROM atomic_tests WHERE technique_id=?", (attack_id.upper(),)).fetchall()]

    def sigma_for(self, attack_id):
        c = self.conn.cursor()
        return [dict(x) for x in c.execute("SELECT title, level, description, path FROM sigma_rules WHERE techniques LIKE ?", (f"%{attack_id.upper()}%",)).fetchall()]

    def search_heuristics(self, text, limit=20):
        c = self.conn.cursor()
        if self._heur_compiled is None:
            self._heur_compiled = []
            for h in c.execute("SELECT name, pattern, techniques, weight FROM heuristics").fetchall():
                try:
                    pat = re.compile(h['pattern'], re.I)
                    techs = [t.strip() for t in h['techniques'].split(',') if t.strip()]
                    self._heur_compiled.append((pat, techs, h['name'], h['weight']))
                except:
                    pass
            self._tech_status = {}
            self._active_techs = {}
            
            for r in c.execute("SELECT attack_id, domain, revoked, deprecated, revoked_by FROM techniques").fetchall():
                aid = r['attack_id']
                if aid not in self._tech_status:
                    self._tech_status[aid] = (r['revoked'], r['deprecated'], r['revoked_by'])
                if not r['revoked'] and not r['deprecated']:
                    if aid not in self._active_techs:
                        self._active_techs[aid] = []
                    self._active_techs[aid].append(r['domain'])
                    
        scores = {}
        sources_cnt = {}
        evidences = {}
        
        for pat, techs, name, weight in self._heur_compiled:
            if pat.search(text):
                for t in techs:
                    tech_status = self._tech_status.get(t)
                    if tech_status:
                        revoked, deprecated, revoked_by = tech_status
                        if revoked and revoked_by:
                            t = revoked_by
                        elif revoked or deprecated:
                            continue
                            
                    domains = self._active_techs.get(t, [])
                    for dom in domains:
                        k = (t, dom)
                        scores[k] = scores.get(k, 0) + 3000.0 + (1000.0 * weight)
                        
                        if k not in sources_cnt: sources_cnt[k] = {'technique':0, 'sigma':0, 'atomic':0, 'heuristic':0}
                        sources_cnt[k]['heuristic'] += 1
                        
                        if k not in evidences: evidences[k] = []
                        if len(evidences[k]) < 3:
                            evidences[k].append(name)
                            
        class SearchResults(list):
            pass
            
        out = SearchResults()
        max_s = max(scores.values()) if scores else 1
        for (aid, dom), s in sorted(scores.items(), key=lambda x: -x[1])[:limit]:
            orig_aid = aid
            tech = c.execute("SELECT name, tactics, revoked, deprecated, revoked_by FROM techniques WHERE attack_id=? AND domain=?", (aid, dom)).fetchone()
            if not tech or tech['revoked'] or tech['deprecated']:
                if tech and tech['revoked'] and tech['revoked_by']:
                    aid = tech['revoked_by']
                    tech = c.execute("SELECT name, tactics, revoked, deprecated FROM techniques WHERE attack_id=? AND domain=?", (aid, dom)).fetchone()
                    if not tech or tech['revoked'] or tech['deprecated']: continue
                else:
                    continue
                    
            sources = {k:v for k,v in sources_cnt.get((orig_aid, dom), {}).items() if v > 0}
            is_heuristic = sources.get('heuristic', 0) > 0
            
            if is_heuristic:
                conf = 'high'
            elif s > 200.0:
                conf = 'medium'
            else:
                conf = 'low'
                    
            out.append({
                'attack_id': aid,
                'name': tech['name'],
                'domain': dom,
                'tactics': tech['tactics'].split(',') if tech['tactics'] else [],
                'score': s / max_s,
                'raw': round(s, 3),
                'confidence': conf,
                'sources': sources,
                'evidence': evidences.get((orig_aid, dom), [])[:3]
            })
            
        if out and not any(r['confidence'] == 'high' for r in out) and out[0]['raw'] < 200.0:
            out.warning = "⚠ past ishonch — bu buyruq aniq bir texnikaga kuchli mos kelmadi"
            
        return out
