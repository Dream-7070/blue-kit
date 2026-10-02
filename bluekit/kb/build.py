import os
import json
import sqlite3
import yaml
import time
import re
from pathlib import Path
from ..paths import get_kb_path

def create_schema(conn):
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE tactics(domain, attack_id, shortname, name, ord INTEGER);
        CREATE TABLE techniques(attack_id, domain, stix_id, name, is_sub INTEGER, parent_id, tactics TEXT, platforms TEXT, description TEXT, detection TEXT, url, deprecated INTEGER, revoked INTEGER, revoked_by TEXT, PRIMARY KEY(attack_id, domain));
        CREATE TABLE actors(stix_id PRIMARY KEY, attack_id, name, type, domain, aliases TEXT);
        CREATE TABLE uses(actor_stix_id, technique_id, domain, description TEXT);
        CREATE TABLE mitigations(attack_id, domain, name, description);
        CREATE TABLE mitigates(mitigation_id, technique_id, domain, description);
        CREATE TABLE atomic_tests(technique_id, name, platforms TEXT, executor TEXT, command TEXT, cleanup TEXT);
        CREATE TABLE sigma_rules(rule_id, title, level, status, product, category, service, techniques TEXT, path TEXT, description TEXT, detection TEXT, falsepositives TEXT);
        CREATE TABLE cooc(t1, t2, level TEXT, both REAL, n1 REAL, n2 REAL);
        CREATE TABLE heuristics(name, pattern, techniques, weight REAL, note);
        CREATE VIRTUAL TABLE search_idx USING fts5(attack_id UNINDEXED, domain UNINDEXED, source UNINDEXED, ref UNINDEXED, text, tokenize='unicode61 tokenchars ''-_./\\:$''');
        
        CREATE INDEX idx_tech_attack_id ON techniques(attack_id);
        CREATE INDEX idx_uses_tech ON uses(technique_id);
        CREATE INDEX idx_uses_actor ON uses(actor_stix_id);
        CREATE INDEX idx_atomic_tech ON atomic_tests(technique_id);
        CREATE INDEX idx_mitigates_tech ON mitigates(technique_id);
        CREATE INDEX idx_cooc_level_t1 ON cooc(level, t1);
    """)
    conn.commit()

def parse_stix(data_dir, conn):
    c = conn.cursor()
    domains = ['enterprise', 'ics', 'mobile']
    attack_ids = {}
    
    for domain in domains:
        p = Path(data_dir) / 'attack' / f"{domain}-attack.json"
        if not p.exists(): continue
        
        with open(p, 'r', encoding='utf-8') as f:
            bundle = json.load(f)
            
        objs = {o.get('id'): o for o in bundle.get('objects', [])}
        
        # Meta version
        for o in bundle.get('objects', []):
            if o.get('type') == 'x-mitre-collection':
                ver = o.get('x_mitre_version', '')
                c.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?,?)", (f"{domain}_attack_version", ver))
                break
                
        # Parse matrices for tactic order
        tactic_order = {}
        for o in bundle.get('objects', []):
            if o.get('type') == 'x-mitre-matrix':
                for ref in o.get('tactic_refs', []):
                    if ref not in tactic_order:
                        tactic_order[ref] = len(tactic_order)
                        
        # Tactics
        for o in bundle.get('objects', []):
            if o.get('type') == 'x-mitre-tactic':
                ext = next((x['external_id'] for x in o.get('external_references', []) if x.get('source_name') == 'mitre-attack'), '')
                shortname = o.get('x_mitre_shortname', '')
                name = o.get('name', '')
                ord = tactic_order.get(o['id'], 999)
                c.execute("INSERT INTO tactics VALUES(?,?,?,?,?)", (domain, ext, shortname, name, ord))
                
        # Techniques
        for o in bundle.get('objects', []):
            if o.get('type') == 'attack-pattern':
                refs = [x for x in o.get('external_references', []) if x.get('source_name') in ('mitre-attack', 'mitre-ics-attack', 'mitre-mobile-attack')]
                if not refs: continue
                ext = refs[0].get('external_id')
                if not ext: continue
                url = refs[0].get('url', '')
                name = o.get('name', '')
                desc = o.get('description', '')
                stix_id = o['id']
                attack_ids[stix_id] = ext
                
                is_sub = 1 if o.get('x_mitre_is_subtechnique') else 0
                tactics = ','.join([p['phase_name'] for p in o.get('kill_chain_phases', [])])
                platforms = ','.join(o.get('x_mitre_platforms', []))
                dep = 1 if o.get('x_mitre_deprecated') else 0
                rev = 1 if o.get('revoked') else 0
                
                # detection
                detection = o.get('x_mitre_detection', '')
                
                c.execute("INSERT OR REPLACE INTO techniques VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                          (ext, domain, stix_id, name, is_sub, None, tactics, platforms, desc, detection, url, dep, rev, None))
                          
        # Actors
        for o in bundle.get('objects', []):
            if o.get('type') in ('intrusion-set', 'malware', 'tool', 'campaign'):
                ext = next((x['external_id'] for x in o.get('external_references', []) if x.get('source_name') in ('mitre-attack','mitre-ics-attack','mitre-mobile-attack')), '')
                c.execute("INSERT OR REPLACE INTO actors VALUES(?,?,?,?,?,?)",
                          (o['id'], ext, o.get('name', ''), o['type'], domain, ','.join(o.get('aliases', []))))
                          
        # Mitigations
        for o in bundle.get('objects', []):
            if o.get('type') == 'course-of-action':
                ext = next((x['external_id'] for x in o.get('external_references', []) if x.get('source_name') in ('mitre-attack','mitre-ics-attack','mitre-mobile-attack')), '')
                c.execute("INSERT OR REPLACE INTO mitigations VALUES(?,?,?,?)",
                          (ext, domain, o.get('name', ''), o.get('description', '')))
                          
        # Relationships
        for o in bundle.get('objects', []):
            if o.get('type') == 'relationship':
                rel = o.get('relationship_type')
                src = o.get('source_ref')
                tgt = o.get('target_ref')
                desc = o.get('description', '')
                if o.get('revoked') or o.get('x_mitre_deprecated'): continue
                
                if rel == 'revoked-by':
                    if src in attack_ids and tgt in attack_ids:
                        c.execute("UPDATE techniques SET revoked_by=? WHERE attack_id=? AND domain=?", (attack_ids[tgt], attack_ids[src], domain))
                elif rel == 'subtechnique-of':
                    if src in attack_ids and tgt in attack_ids:
                        c.execute("UPDATE techniques SET parent_id=? WHERE attack_id=? AND domain=?", (attack_ids[tgt], attack_ids[src], domain))
                elif rel == 'uses':
                    if src in objs and tgt in attack_ids:
                        c.execute("INSERT INTO uses VALUES(?,?,?,?)", (src, attack_ids[tgt], domain, desc))
                elif rel == 'mitigates':
                    if src in objs and tgt in attack_ids:
                        src_ext = next((x['external_id'] for x in objs[src].get('external_references', []) if x.get('source_name') in ('mitre-attack', 'mitre-ics-attack', 'mitre-mobile-attack')), '')
                        if src_ext:
                            c.execute("INSERT INTO mitigates VALUES(?,?,?,?)", (src_ext, attack_ids[tgt], domain, desc))

def parse_atomic(data_dir, conn):
    c = conn.cursor()
    p = Path(data_dir) / 'atomic' / 'atomics'
    if not p.exists(): return
    
    for yaml_file in p.rglob('*.yaml'):
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            tech = data.get('attack_technique')
            if not tech: continue
            for test in data.get('atomic_tests', []):
                name = test.get('name', '')
                plats = ','.join(test.get('supported_platforms', []))
                executor = test.get('executor', {})
                exec_name = executor.get('name', '')
                cmd = executor.get('command', '')
                cleanup = executor.get('cleanup_command', '')
                c.execute("INSERT INTO atomic_tests VALUES(?,?,?,?,?,?)",
                          (tech, name, plats, exec_name, cmd, cleanup))
        except:
            pass

def parse_sigma(data_dir, conn):
    c = conn.cursor()
    p = Path(data_dir) / 'sigma'
    if not p.exists(): return
    
    for yaml_file in p.rglob('*.yml'):
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                docs = list(yaml.safe_load_all(f))
            for data in docs:
                if not data or not isinstance(data, dict) or 'title' not in data: continue
                rule_id = data.get('id', '')
                title = data.get('title', '')
                level = data.get('level', '')
                status = data.get('status', '')
                logsource = data.get('logsource', {})
                prod = logsource.get('product', '')
                cat = logsource.get('category', '')
                svc = logsource.get('service', '')
                desc = data.get('description', '')
                fp = ','.join(data.get('falsepositives', []))
                det_dump = yaml.dump(data.get('detection', {}))
                
                techs = []
                for tag in data.get('tags', []):
                    m = re.match(r'^attack\.t(\d{4}(?:\.\d{3})?)$', tag, re.I)
                    if m:
                        techs.append(f"T{m.group(1)}")
                
                c.execute("INSERT INTO sigma_rules VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                          (rule_id, title, level, status, prod, cat, svc, ','.join(techs), str(yaml_file.relative_to(p)), desc, det_dump, fp))
        except:
            pass

def build_cooc(conn):
    c = conn.cursor()
    actors = c.execute("SELECT stix_id, type FROM actors WHERE stix_id NOT IN (SELECT stix_id FROM actors WHERE type = 'deprecated' OR type='revoked')").fetchall() # type is not revoked but we filter revoked actors if possible, but actually we just filter from uses where tech is active
    
    techs = set(r[0] for r in c.execute("SELECT attack_id FROM techniques WHERE revoked=0 AND deprecated=0").fetchall())
    
    u_sub = {}
    u_parent = {}
    for aid, atype in actors:
        used = c.execute("SELECT technique_id FROM uses WHERE actor_stix_id=?", (aid,)).fetchall()
        used = set(r[0] for r in used if r[0] in techs)
        u_sub[aid] = used
        u_parent[aid] = set(x.split('.')[0] for x in used)
        
    weights = {'campaign':1.0, 'intrusion-set':1.0, 'malware':0.8, 'tool':0.6}
    
    for level in ('sub', 'parent'):
        both_counts = {}
        n_counts = {}
        u_dict = u_sub if level == 'sub' else u_parent
        for aid, atype in actors:
            w = weights.get(atype, 0)
            if w == 0: continue
            
            s = sorted(u_dict[aid])
            for i, t1 in enumerate(s):
                n_counts[t1] = n_counts.get(t1, 0) + w
                # Visit each unordered pair once per actor (avoids doubling `both`).
                for t2 in s[i + 1:]:
                    k = (t1, t2)
                    both_counts[k] = both_counts.get(k, 0) + w
        
        for (t1, t2), both in both_counts.items():
            if both > 0:
                c.execute("INSERT INTO cooc VALUES(?,?,?,?,?,?)", (t1, t2, level, both, n_counts[t1], n_counts[t2]))
                c.execute("INSERT INTO cooc VALUES(?,?,?,?,?,?)", (t2, t1, level, both, n_counts[t2], n_counts[t1]))

def build_fts(conn):
    c = conn.cursor()
    # techniques
    for row in c.execute("SELECT attack_id, domain, name, description, detection FROM techniques WHERE revoked=0 AND deprecated=0").fetchall():
        text = f"{row[2]} {row[3] or ''} {row[4] or ''}"
        c.execute("INSERT INTO search_idx VALUES(?,?,?,?,?)", (row[0], row[1], 'technique', None, text))
    # atomic
    for row in c.execute("SELECT technique_id, name, command FROM atomic_tests").fetchall():
        text = f"{row[1]} {row[2] or ''}"
        doms = c.execute("SELECT domain FROM techniques WHERE attack_id=?", (row[0],)).fetchall()
        for dom in doms:
            c.execute("INSERT INTO search_idx VALUES(?,?,?,?,?)", (row[0], dom[0], 'atomic', row[1], text))
    # sigma
    for row in c.execute("SELECT techniques, title, description, detection, path FROM sigma_rules").fetchall():
        text = f"{row[1]} {row[2] or ''} {row[3] or ''}"
        for t in row[0].split(','):
            if t:
                doms = c.execute("SELECT domain FROM techniques WHERE attack_id=?", (t,)).fetchall()
                for dom in doms:
                    c.execute("INSERT INTO search_idx VALUES(?,?,?,?,?)", (t, dom[0], 'sigma', row[4], text))

def parse_heuristics(conn, data_dir=None):
    c = conn.cursor()
    current_dir = os.path.dirname(os.path.abspath(__file__))
    yaml_file = os.path.join(current_dir, 'heuristics.yaml')
    if not os.path.exists(yaml_file): return
    
    with open(yaml_file, 'r', encoding='utf-8') as f:
        rules = yaml.safe_load(f)
        
    for r in rules:
        c.execute("INSERT INTO heuristics VALUES(?,?,?,?,?)",
                  (r.get('name'), r.get('pattern'), ','.join(r.get('techniques', [])), float(r.get('weight', 0)), r.get('note', '')))

def build(data_dir, out_path=None):
    start = time.time()
    if not out_path:
        out_path = get_kb_path(data_dir)
        
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    temp_path = out_path + ".tmp"
    if os.path.exists(temp_path):
        os.remove(temp_path)
        
    conn = sqlite3.connect(temp_path)
    create_schema(conn)
    
    parse_stix(data_dir, conn)
    parse_atomic(data_dir, conn)
    parse_sigma(data_dir, conn)
    build_cooc(conn)
    build_fts(conn)
    parse_heuristics(conn)
    
    c = conn.cursor()
    # Validate heuristics
    for row in c.execute("SELECT name, techniques FROM heuristics").fetchall():
        for t in row[1].split(','):
            t = t.strip()
            if not t: continue
            tech = c.execute("SELECT attack_id, revoked, deprecated, revoked_by FROM techniques WHERE attack_id=?", (t,)).fetchone()
            if not tech:
                print(f"WARNING: Heuristic '{row[0]}' references unknown technique '{t}'")
            elif tech[1]:
                print(f"WARNING: Heuristic '{row[0]}' references revoked technique '{t}', replaced by {tech[3]}")
            elif tech[2]:
                print(f"WARNING: Heuristic '{row[0]}' references deprecated technique '{t}'")
                
    stats = {
        'techniques': c.execute("SELECT count(*) FROM techniques").fetchone()[0],
        'actors': c.execute("SELECT count(*) FROM actors").fetchone()[0],
        'atomic_tests': c.execute("SELECT count(*) FROM atomic_tests").fetchone()[0],
        'sigma_rules': c.execute("SELECT count(*) FROM sigma_rules").fetchone()[0],
        'search_idx': c.execute("SELECT count(*) FROM search_idx").fetchone()[0],
        'time': time.time() - start
    }
    
    conn.commit()
    conn.close()
    
    if os.path.exists(out_path):
        os.remove(out_path)
    os.rename(temp_path, out_path)
    return stats
