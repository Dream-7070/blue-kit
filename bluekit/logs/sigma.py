import sqlite3
import yaml
import re
import ipaddress
import time
from collections import defaultdict
import os

try:
    from bluekit.paths import get_kb_path
except ImportError:
    def get_kb_path():
        return None

FIELD_MAPPING = {
    'image': 'process',
    'newprocessname': 'process',
    'processname': 'process',
    'process.executable': 'process',
    'parentimage': 'parent_process',
    'parentprocessname': 'parent_process',
    'commandline': 'command_line',
    'processcommandline': 'command_line',
    'eventid': 'event_id',
    'eventcode': 'event_id',
    'user': 'user',
    'subjectusername': 'user',
    'targetusername': 'user',
    'accountname': 'user',
    'computer': 'host',
    'computername': 'host',
    'hostname': 'host',
    'sourceip': 'src_ip',
    'sourceaddress': 'src_ip',
    'ipaddress': 'src_ip',
    'src_ip': 'src_ip',
    'destinationip': 'dest_ip',
    'destinationaddress': 'dest_ip',
    'channel': 'channel'
}

UNSUPPORTED_MODIFIERS = {'base64', 'base64offset', 'utf16', 'wide', 'expand'}

class UnsupportedRule(Exception):
    pass

class SigmaEngine:
    def __init__(self, kb_path=None, products=None, categories=None, min_level=None, max_rules=None):
        if kb_path is None:
            kb_path = get_kb_path()
            
        self.rules = []
        self._stats = {'loaded': 0, 'skipped': 0, 'always_eval': 0, 'indexed_rules': 0, 'by_level': defaultdict(int)}
        self.index = defaultdict(list)
        self.always_eval = []
        
        if not kb_path or not os.path.exists(kb_path):
            return
            
        conn = sqlite3.connect(kb_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = "SELECT * FROM sigma_rules"
        conditions = []
        params = []
        
        if products:
            placeholders = ','.join(['?']*len(products))
            conditions.append(f"product IN ({placeholders})")
            params.extend(products)
            
        if categories:
            placeholders = ','.join(['?']*len(categories))
            conditions.append(f"category IN ({placeholders})")
            params.extend(categories)
            
        if min_level:
            levels = []
            if min_level.lower() == 'high':
                levels = ['high', 'critical']
            elif min_level.lower() == 'medium':
                levels = ['medium', 'high', 'critical']
            elif min_level.lower() == 'low':
                levels = ['low', 'medium', 'high', 'critical']
            elif min_level.lower() == 'informational':
                levels = ['informational', 'low', 'medium', 'high', 'critical']
            
            if levels:
                placeholders = ','.join(['?']*len(levels))
                conditions.append(f"level IN ({placeholders})")
                params.extend(levels)
                
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
            
        if max_rules:
            query += f" LIMIT {max_rules}"
            
        rows = cursor.execute(query, params).fetchall()
        
        for row in rows:
            try:
                rule = self._parse_rule(row)
                self.rules.append(rule)
                self._stats['loaded'] += 1
                self._stats['by_level'][row['level']] += 1
                
                if not rule.get('tokens'):
                    self.always_eval.append(rule)
                    self._stats['always_eval'] += 1
                else:
                    for t in rule['tokens']:
                        self.index[t].append(rule)
                    self._stats['indexed_rules'] += 1
                    
            except UnsupportedRule:
                self._stats['skipped'] += 1
            except Exception as e:
                self._stats['skipped'] += 1
                
        conn.close()

    def stats(self):
        return {
            'loaded': self._stats['loaded'],
            'skipped': self._stats['skipped'],
            'always_eval': self._stats['always_eval'],
            'indexed_rules': self._stats['indexed_rules'],
            'by_level': dict(self._stats['by_level'])
        }
        
    def _parse_rule(self, row):
        detection = yaml.safe_load(row['detection'])
        if not detection:
            raise UnsupportedRule("Empty detection")
            
        condition_str = detection.get('condition')
        if not condition_str:
            raise UnsupportedRule("No condition")
            
        # Extract literals for fast matching
        literals = set()
        tokens = set()
        
        # Parse selections
        selections = {}
        for k, v in detection.items():
            if k == 'condition':
                continue
            if k == 'keywords':
                if isinstance(v, list):
                    selections[k] = v
                    for x in v:
                        if isinstance(x, str):
                            literals.add(x.lower())
                            mt = re.findall(r'[a-z0-9]+', x.lower())
                            if mt: tokens.add(max(mt, key=len))
                else:
                    raise UnsupportedRule("Keywords must be a list")
                continue
                
            # Selection block
            if isinstance(v, dict) or isinstance(v, list):
                selections[k] = v
                self._extract_literals(v, literals)
                for lit in literals:
                    mt = re.findall(r'[a-z0-9]+', lit)
                    if mt: tokens.add(max(mt, key=len))
            else:
                raise UnsupportedRule(f"Unknown block format: {k}")
                
        techniques = []
        if row['techniques']:
            techniques = [t.strip() for t in row['techniques'].split(',')]
            
        rule = {
            'rule_id': row['rule_id'],
            'title': row['title'],
            'level': row['level'],
            'techniques': techniques,
            'selections': selections,
            'literals': list(literals),
            'tokens': list(tokens)
        }
        
        # Precompile condition expression
        available = list(selections.keys())
        # The condition can be a list according to sigma, but the spec says "Qo'llab-quvvatlanishi shart: selection, selection and not filter, ...". So assume string.
        if isinstance(condition_str, list):
            # For simplicity, if it's a list we just OR them (or skip)
            # Spec says: "Boshqa shakl (near, | count() >, agregatsiya) — qoida skipped."
            raise UnsupportedRule("List condition not supported")
            
        cond = str(condition_str).lower()
        if " near " in cond or "|" in cond or " count" in cond:
            raise UnsupportedRule("Aggregation/near not supported")
            
        # Parse condition
        cond = cond.replace("all of them", " and ".join(available))
        if "1 of them" in cond:
            cond = cond.replace("1 of them", "(" + " or ".join(available) + ")")
            
        def repl_all_of(m):
            pat = '^' + m.group(1).replace('*', '.*') + '$'
            matched = [x for x in available if re.match(pat, x, re.IGNORECASE)]
            if not matched: return "False"
            return "(" + " and ".join(matched) + ")"
        cond = re.sub(r'all of ([a-z0-9_*]+)', repl_all_of, cond)
        
        def repl_1_of(m):
            pat = '^' + m.group(1).replace('*', '.*') + '$'
            matched = [x for x in available if re.match(pat, x, re.IGNORECASE)]
            if not matched: return "False"
            return "(" + " or ".join(matched) + ")"
        cond = re.sub(r'1 of ([a-z0-9_*]+)', repl_1_of, cond)
        
        rule['condition_expr'] = cond
        return rule
        
    def _extract_literals(self, block, literals):
        if isinstance(block, dict):
            for k, v in block.items():
                # check modifiers
                parts = k.split('|')
                if len(parts) > 1:
                    mods = set(parts[1:])
                    if mods.intersection(UNSUPPORTED_MODIFIERS):
                        raise UnsupportedRule(f"Unsupported modifier in {k}")
                    if 're' in mods or 'cidr' in mods:
                        continue # can't extract literal easily
                        
                if isinstance(v, str):
                    literals.add(v.lower())
                elif isinstance(v, list):
                    for x in v:
                        if isinstance(x, str):
                            literals.add(x.lower())
                elif isinstance(v, int):
                    literals.add(str(v))
        elif isinstance(block, list):
            for item in block:
                self._extract_literals(item, literals)

    def _eval_condition(self, rule, matched_blocks):
        try:
            return eval(rule['condition_expr'], {"__builtins__": None}, matched_blocks)
        except Exception:
            return False

    def match_event(self, ev):
        blob = ev.get('blob', '')
        if blob:
            blob_lower = blob.lower()
        else:
            # Reconstruct blob if missing (for synthetic test events)
            blob_lower = str(ev).lower()
            
        hits = []
        
        # If rules were manually modified (e.g., in tests), bypass index
        if len(self.rules) != self._stats.get('loaded', 0):
            candidate_rules = self.rules
        else:
            blob_tokens = set(re.findall(r'[a-z0-9]+', blob_lower))
            candidate_rules = self.always_eval.copy()
            
            seen = set(id(r) for r in candidate_rules)
            for t in blob_tokens:
                if t in self.index:
                    for r in self.index[t]:
                        if id(r) not in seen:
                            candidate_rules.append(r)
                            seen.add(id(r))
                    
        for rule in candidate_rules:
            # Prefilter is technically obsolete with index, but we can keep it as a secondary check just in case
            if rule['literals']:
                skip = True
                for lit in rule['literals']:
                    if lit in blob_lower:
                        skip = False
                        break
                if skip:
                    continue
                    
            matched_blocks = {}
            weak = False
            matched_fields_set = set()
            
            for sel_name, sel_block in rule['selections'].items():
                if sel_name == 'keywords':
                    # Keywords match on full text
                    block_match = False
                    for kw in sel_block:
                        if str(kw).lower() in blob_lower:
                            block_match = True
                            weak = True
                            break
                    matched_blocks[sel_name] = block_match
                else:
                    # Evaluate selection block
                    # OR if list of dicts
                    if isinstance(sel_block, list):
                        block_res = False
                        for sub_block in sel_block:
                            if isinstance(sub_block, str):
                                if sub_block.lower() in blob_lower:
                                    block_res = True
                                    weak = True
                                    break
                            elif isinstance(sub_block, dict):
                                sub_res, sub_weak, sub_fields = self._eval_dict_block(sub_block, ev, blob_lower)
                                if sub_res:
                                    block_res = True
                                    weak = weak or sub_weak
                                    matched_fields_set.update(sub_fields)
                                    break
                        matched_blocks[sel_name] = block_res
                    elif isinstance(sel_block, dict):
                        sub_res, sub_weak, sub_fields = self._eval_dict_block(sel_block, ev, blob_lower)
                        matched_blocks[sel_name] = sub_res
                        if sub_res:
                            weak = weak or sub_weak
                            matched_fields_set.update(sub_fields)
            
            # Check if any fields were explicitly matched or keywords were matched
            # "Agar qoidaning birorta ham maydoni topilmasa va keywords ham bo'lmasa — qoida shu hodisa uchun mos kelmadi hisoblansin"
            # Actually, _eval_dict_block returns matched fields. If total matched fields == 0 and keywords not in matched_blocks (or false), maybe false.
            has_explicit_match = bool(matched_fields_set) or matched_blocks.get('keywords', False)
            
            if self._eval_condition(rule, matched_blocks):
                if has_explicit_match or weak: # weak match means blob fallback succeeded
                    hits.append({
                        'rule_id': rule['rule_id'],
                        'title': rule['title'],
                        'level': rule['level'],
                        'techniques': rule['techniques'],
                        'matched_fields': list(matched_fields_set),
                        'weak': weak
                    })
                    
        return hits

    def _eval_dict_block(self, block, ev, blob_lower):
        # Dictionary keys are ANDed
        weak = False
        matched_fields = []
        
        for k, expected_v in block.items():
            parts = k.split('|')
            field = parts[0]
            mods = parts[1:]
            
            # Find field value
            val = None
            raw = ev.get('raw', {})
            field_lower = field.lower()
            
            # 1. exact match in raw
            for rk, rv in raw.items():
                # DictReader ortiqcha ustunlarni None kalit ostiga yig'adi
                if rk is not None and str(rk).lower() == field_lower:
                    val = str(rv)
                    matched_fields.append(field)
                    break
                    
            # 2. canonical mapping
            if val is None:
                canon = FIELD_MAPPING.get(field_lower)
                if canon and canon in ev and ev[canon] is not None:
                    val = str(ev[canon])
                    matched_fields.append(field)
            
            # 3. fallback to blob
            if val is None:
                val = blob_lower
                weak = True
                matched_fields.append(field)
                
            if val is None: # still none? shouldn't happen with blob fallback
                return False, weak, matched_fields
                
            val_lower = val.lower() if val != blob_lower else val
            
            # evaluate value
            is_all = 'all' in mods
            
            vals = expected_v if isinstance(expected_v, list) else [expected_v]
            
            if is_all:
                res = True
                for v in vals:
                    if not self._check_val(str(v), val_lower, mods):
                        res = False
                        break
            else:
                res = False
                for v in vals:
                    if self._check_val(str(v), val_lower, mods):
                        res = True
                        break
                        
            if not res:
                return False, weak, []
                
        return True, weak, matched_fields

    def _check_val(self, expected, actual, mods):
        # actual is already lowercase
        if 're' in mods:
            try:
                # expected is regex
                return re.search(expected, actual, re.IGNORECASE) is not None
            except re.error:
                return False
                
        if 'cidr' in mods:
            try:
                net = ipaddress.ip_network(expected, strict=False)
                addr = ipaddress.ip_address(actual)
                return addr in net
            except ValueError:
                return False
                
        # String match
        exp = expected.lower()
        if 'windash' in mods:
            # equivalent to replacing ^/ with ^- or vice versa, or just check both
            if exp.startswith('-'):
                exp2 = '/' + exp[1:]
            elif exp.startswith('/'):
                exp2 = '-' + exp[1:]
            else:
                exp2 = exp
                
            if 'contains' in mods:
                return exp in actual or exp2 in actual
            elif 'startswith' in mods:
                return actual.startswith(exp) or actual.startswith(exp2)
            elif 'endswith' in mods:
                return actual.endswith(exp) or actual.endswith(exp2)
            else:
                return actual == exp or actual == exp2
                
        if 'contains' in mods:
            return exp in actual
        elif 'startswith' in mods:
            return actual.startswith(exp)
        elif 'endswith' in mods:
            return actual.endswith(exp)
        else:
            return actual == exp

    def match_events(self, events, progress=None):
        start_time = time.time()
        hits = []
        by_technique = {}
        events_with_hits = 0
        total_events = 0
        
        for idx, ev in enumerate(events):
            total_events += 1
            rule_hits = self.match_event(ev)
            if rule_hits:
                events_with_hits += 1
                from bluekit.tz import display_ts
                hit_record = {
                    'index': idx,
                    'ts': ev.get('ts'),
                    'ts_disp': ev.get('ts_disp') or display_ts(ev.get('ts')),
                    'host': ev.get('host'),
                    'rules': rule_hits
                }
                hits.append(hit_record)
                
                for rh in rule_hits:
                    for t in rh.get('techniques', []):
                        if not t: continue
                        if t not in by_technique:
                            by_technique[t] = {'count': 0, 'rules': set(), 'level': rh.get('level')}
                        by_technique[t]['count'] += 1
                        by_technique[t]['rules'].add(rh['rule_id'])
                        
            if progress:
                progress(idx + 1, len(events))
                
        # Format by_technique
        for t, d in by_technique.items():
            d['rules'] = list(d['rules'])
            
        elapsed = time.time() - start_time
        
        return {
            'hits': hits,
            'by_technique': by_technique,
            'stats': {
                'events': total_events,
                'rules_loaded': self._stats['loaded'],
                'rules_skipped': self._stats['skipped'],
                'events_with_hits': events_with_hits,
                'elapsed_sec': elapsed
            }
        }

def drop_weak(res):
    """Ishonchsiz (xom matn orqali topilgan, weak=True) mosliklarni olib tashlaydi va
    by_technique / stats.events_with_hits ni QAYTA hisoblaydi. res ni joyida o'zgartiradi va qaytaradi."""
    for hit in res.get('hits', []):
        hit['rules'] = [r for r in hit.get('rules', []) if not r.get('weak')]
    res['hits'] = [h for h in res['hits'] if h.get('rules')]
    agg = {}
    for hit in res['hits']:
        for r in hit['rules']:
            for tid in r.get('techniques', []):
                slot = agg.setdefault(tid, {'count': 0, 'rules': [], 'level': r.get('level')})
                slot['count'] += 1
                if r.get('rule_id') and r['rule_id'] not in slot['rules']:
                    slot['rules'].append(r['rule_id'])
    res['by_technique'] = agg
    res['stats']['events_with_hits'] = len(res['hits'])
    return res
