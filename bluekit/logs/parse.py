import csv
import json
import yaml
import os
import re
import ipaddress
from datetime import datetime, timedelta, timezone
from bluekit.tz import to_local, from_epoch

_TEXT_FIELD_NAMES = None
def _get_text_field_names():
    global _TEXT_FIELD_NAMES
    if _TEXT_FIELD_NAMES: return _TEXT_FIELD_NAMES
    yaml_path = os.path.join(os.path.dirname(__file__), 'fieldmap.yaml')
    with open(yaml_path, 'r', encoding='utf-8') as f:
        full_map = yaml.safe_load(f)
    def_map = full_map.get('default', {})
    res = {'ts': 'timestamp', 'host': 'host', 'src_ip': 'src_ip', 'dest_ip': 'dest_ip'}
    for canon in res.keys():
        cols = def_map.get(canon, [])
        if res[canon] not in cols and cols:
            res[canon] = cols[0]
    _TEXT_FIELD_NAMES = res
    return res

MONTHS = {'Jan':1, 'Feb':2, 'Mar':3, 'Apr':4, 'May':5, 'Jun':6, 'Jul':7, 'Aug':8, 'Sep':9, 'Oct':10, 'Nov':11, 'Dec':12}

def _parse_text_line(line, mtime):
    fields = _get_text_field_names()
    res = {}
    
    m_apache = re.match(r'^([a-fA-F0-9\.\:]+)\s+.*\[(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-])(\d{2})(\d{2})\]', line)
    m_syslog = re.match(r'^([A-Z][a-z]{2})\s+(\d+)\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)', line)
    
    if m_apache:
        ip_str = m_apache.group(1)
        try:
            ipaddress.ip_address(ip_str)
            res[fields['src_ip']] = ip_str
        except ValueError:
            pass
        
        day = int(m_apache.group(2))
        month_str = m_apache.group(3)
        year = int(m_apache.group(4))
        hour = int(m_apache.group(5))
        minute = int(m_apache.group(6))
        sec = int(m_apache.group(7))
        sign = m_apache.group(8)
        off_h = int(m_apache.group(9))
        off_m = int(m_apache.group(10))
        
        if month_str in MONTHS:
            try:
                dt = datetime(year, MONTHS[month_str], day, hour, minute, sec)
                offset = timedelta(hours=off_h, minutes=off_m)
                if sign == '+':
                    dt = dt.replace(tzinfo=timezone(offset))
                else:
                    dt = dt.replace(tzinfo=timezone(-offset))
                res[fields['ts']] = dt.isoformat()
            except ValueError:
                pass
                
    elif m_syslog:
        month_str = m_syslog.group(1)
        day = int(m_syslog.group(2))
        hour = int(m_syslog.group(3))
        minute = int(m_syslog.group(4))
        sec = int(m_syslog.group(5))
        host = m_syslog.group(6)
        
        res[fields['host']] = host
        
        if month_str in MONTHS:
            mtime_dt = datetime.fromtimestamp(mtime)
            year = mtime_dt.year
            try:
                dt = datetime(year, MONTHS[month_str], day, hour, minute, sec)
                if dt > mtime_dt + timedelta(days=1):
                    dt = dt.replace(year=year-1)
                res[fields['ts']] = dt.isoformat()
            except ValueError:
                pass
                
        m_postfix = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', line)
        if m_postfix:
            ip_str = m_postfix.group(1)
            try:
                ipaddress.ip_address(ip_str)
                res[fields['src_ip']] = ip_str
            except ValueError:
                pass

    m_src = re.search(r'\bSRC=(\S+)', line)
    if m_src:
        try:
            ipaddress.ip_address(m_src.group(1))
            res[fields['src_ip']] = m_src.group(1)
        except ValueError:
            pass
            
    m_dst = re.search(r'\bDST=(\S+)', line)
    if m_dst:
        try:
            ipaddress.ip_address(m_dst.group(1))
            res[fields['dest_ip']] = m_dst.group(1)
        except ValueError:
            pass
            
    return res
from collections import defaultdict

def parse_ts(ts_str):
    if not ts_str: return None
    if isinstance(ts_str, datetime): return to_local(ts_str)
    
    val_str = str(ts_str).strip()
    m_ps = re.search(r'Date\((\d+)(?:[+-]\d{4})?\)', val_str)
    if m_ps:
        val = float(m_ps.group(1))
        if val > 20000000000: val = val / 1000
        if val <= 0: return None
        return from_epoch(val)
        
    try:
        if val_str.replace('.', '', 1).replace('-', '', 1).isdigit():
            val = float(val_str)
            if val > 20000000000: val = val / 1000
            if val <= 0: return None
            return from_epoch(val)
    except: pass
    
    is_utc = False
    if val_str.endswith(' GMT') or val_str.endswith(' UTC'):
        is_utc = True
        val_str = val_str[:-4].strip()
        
    try: 
        dt = datetime.fromisoformat(val_str.replace('Z', '+00:00'))
        if is_utc and dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
        return to_local(dt)
    except: pass
    try: 
        dt = datetime.strptime(val_str, "%Y-%m-%d %H:%M:%S")
        if is_utc and dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
        return to_local(dt)
    except: pass
    try: 
        dt = datetime.strptime(val_str, "%m/%d/%Y %I:%M:%S %p")
        if is_utc and dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
        return to_local(dt)
    except: pass
    
    dt = _parse_ts_extra(val_str)
    if dt:
        if is_utc and dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
        return to_local(dt)
    return None

_MONTHS = {m: i for i, m in enumerate(['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'], 1)}

def _parse_ts_extra(s):
    """Kibana CSV ('Oct 5, 2026 @ 09:14:00.123') va rus Excel ('05.10.2026 09:14:00').
    Oy nomi locale siz xaritalanadi (%b rus Windows da ishonchsiz)."""
    m = re.match(r'^([A-Za-z]{3})[a-z]*\.? (\d{1,2}),? (\d{4})(?: @)? (\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,6}))?)?$', s)
    if m and m.group(1).lower() in _MONTHS:
        mon, d, y = _MONTHS[m.group(1).lower()], m.group(2), m.group(3)
        rest = m.groups()[3:]
    else:
        m = re.match(r'^(\d{1,2})\.(\d{1,2})\.(\d{4})[ T,]+(\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,6}))?)?$', s)
        if not m: return None
        d, mon, y = m.group(1), m.group(2), m.group(3)
        rest = m.groups()[3:]
    hh, mi, ss, frac = rest
    try: return datetime(int(y), int(mon), int(d), int(hh), int(mi), int(ss or 0), int((frac or '0').ljust(6, '0')))
    except ValueError: return None

def flatten_dict(d, parent_key='', sep='.'):
    items = []
    if isinstance(d, dict):
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict): items.extend(flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                if all(not isinstance(x, (dict, list)) for x in v):
                    items.append((new_key, ", ".join(str(x) for x in v)))
                else:
                    for i, el in enumerate(v):
                        if isinstance(el, dict):
                            items.extend(flatten_dict(el, f"{new_key}.{i}", sep=sep).items())
                        else:
                            items.append((f"{new_key}.{i}", el))
            else: items.append((new_key, v))
    return dict(items)

def get_csv_reader(f, sample, ext):
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=',;\t|')
        # Sniffer xabardagi apostrofni (') quotechar deb oladi va qatorlarni buzadi -- eksportlarda doim "
        dialect.quotechar = '"'
        dialect.doublequote = True
        f.seek(0)
        reader = csv.DictReader(f, dialect=dialect)
        fieldnames = reader.fieldnames
        if fieldnames and len(fieldnames) == 1:
            header = fieldnames[0]
            counts = {',': header.count(','), ';': header.count(';'), '\t': header.count('\t')}
            best_delim = max(counts, key=counts.get)
            if counts[best_delim] > 0:
                f.seek(0)
                reader = csv.DictReader(f, delimiter=best_delim)
    except:
        f.seek(0)
        reader = csv.DictReader(f, delimiter=',' if ext=='.csv' else '\t')
    return reader

def load_rows(path):
    from bluekit.logs.qradar import looks_like_qradar, load_qradar
    ext = os.path.splitext(path)[1].lower()
    if ext in ('.csv', '.tsv') and looks_like_qradar(path):
        return load_qradar(path)
        
    rows = []
    with open(path, 'r', encoding='utf-8-sig', errors='replace') as f:
        if ext not in ('.csv', '.tsv', '.json', '.ndjson', '.jsonl', '.journal'):
            # Kengaytma ishonchsiz (secure, auth.log.1, x.txt, docker *-json.log): birinchi qator JSON obyekt bo'lsa -- JSON-lines
            line = f.readline()
            while line and not line.strip():
                line = f.readline()
            try:
                if line.lstrip().startswith('{') and isinstance(json.loads(line), dict):
                    ext = '.jsonl'
            except ValueError:
                pass
            f.seek(0)
        if ext in ('.csv', '.tsv'):
            sample = f.read(4096)
            f.seek(0)
            reader = get_csv_reader(f, sample, ext)
            rows = list(reader)
        elif ext in ('.json', '.ndjson', '.jsonl'):
            content = f.read()
            try:
                data = json.loads(content)
                if isinstance(data, dict):
                    if 'hits' in data and isinstance(data['hits'], dict) and isinstance(data['hits'].get('hits'), list):
                        for h in data['hits']['hits']:
                            row = flatten_dict(h.get('_source', h))
                            if '_index' in h: row['es_index'] = h['_index']
                            if '_id' in h: row['es_id'] = h['_id']
                            rows.append(row)
                    else:
                        found_list = None
                        for k in ['events', 'Events', 'records', 'Records', 'results', 'data', 'logs', 'entries']:
                            if k in data and isinstance(data[k], list):
                                found_list = data[k]
                                break
                        if found_list is not None:
                            for el in found_list:
                                if isinstance(el, dict): rows.append(flatten_dict(el))
                                else: rows.append({"message": str(el)})
                        else:
                            rows.append(flatten_dict(data))
                elif isinstance(data, list):
                    for d in data:
                        if isinstance(d, dict): rows.append(flatten_dict(d))
                        else: rows.append({"message": str(d)})
                else:
                    rows.append({"message": str(data)})
            except:
                f.seek(0)
                for line in f:
                    line = line.strip()
                    if line:
                        try: rows.append(flatten_dict(json.loads(line)))
                        except: pass
        elif ext == '.journal':
            f.seek(0)
            # Check for binary systemd journal magic
            if hasattr(f, 'buffer'):
                magic_check = f.buffer.read(8)
                f.seek(0)
                if magic_check.startswith(b'LPKSHHRH'):
                    return []
            content = f.read()
            if content.startswith('LPKSHHRH'):
                return []
            blocks = content.strip().split('\n\n')
            for b in blocks:
                if not b.strip():
                    continue
                row = {}
                for line in b.strip().split('\n'):
                    if '=' in line:
                        k, v = line.split('=', 1)
                        k_orig = k.strip()
                        k_clean = k_orig.lower()
                        v = v.strip()
                        row[k_orig] = v
                        if k_clean in ('time', '__realtime_timestamp', '_source_realtime_timestamp', 'timestamp'):
                            if 'timestamp' not in row:
                                row['timestamp'] = v
                        elif k_clean == 'event_id':
                            row['event_id'] = v
                        elif k_clean in ('source', '_systemd_unit', 'syslog_identifier'):
                            if 'source' not in row:
                                row['source'] = v
                        elif k_clean in ('message', 'msg'):
                            row['message'] = v
                        elif k_clean in ('_hostname', 'hostname', 'host'):
                            row['host'] = v
                        elif k_clean in ('_comm', 'process', 'comm'):
                            row['process'] = v
                        elif k_clean in ('_pid', 'pid'):
                            row['pid'] = v
                        elif k_clean == 'detail':
                            row['detail'] = v
                            matches = re.findall(r'([A-Za-z0-9_]+)=(.*?)(?=\s+[A-Za-z0-9_]+=|$)', v)
                            for pk, pv in matches:
                                if pk not in ('timestamp', 'source', 'message', 'host', 'process', 'pid', 'event_id'):
                                    row[pk] = pv.strip()
                if row:
                    rows.append(row)
        else:
            try:
                mtime = os.path.getmtime(path)
            except:
                mtime = datetime.now().timestamp()
            for line in f:
                line = line.strip()
                if not line: continue
                # try to extract timestamp
                m = re.match(r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(.*)', line)
                if m:
                    row = {'timestamp': m.group(1), 'message': m.group(2)}
                    # rsyslog RFC3339 (Ubuntu 22.10+, journalctl short-iso): "<ts> host ident[pid]: xabar"
                    m_host = re.match(r'^(\S+)\s+([\w.\-/]+)(?:\[\d+\])?:\s', m.group(2))
                    if 'T' in m.group(1) and m_host:
                        row['host'] = m_host.group(1)
                        row['process'] = m_host.group(2)
                    rows.append(row)
                else:
                    parsed = _parse_text_line(line, mtime)
                    parsed["message"] = line
                    rows.append(parsed)
    return rows

def get_mapping(preset=None, map_path=None):
    if map_path and os.path.exists(map_path):
        with open(map_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
            
    yaml_path = os.path.join(os.path.dirname(__file__), 'fieldmap.yaml')
    with open(yaml_path, 'r', encoding='utf-8') as f:
        full_map = yaml.safe_load(f)
        
    if preset and preset in full_map.get('presets', {}):
        return full_map['presets'][preset]
    return full_map.get('default', {})

def build_col_to_canonical(mapping):
    col_to_canonical = {}
    for canon, cols in mapping.items():
        for c in cols:
            col_to_canonical[c.lower()] = canon
            # Also add exact name and last dotted segment
            col_to_canonical[c.split('.')[-1].lower()] = canon
    return col_to_canonical

def fuzzy_match(col_name):
    col = re.sub(r'[^a-z0-9]', '', col_name.lower())
    stems = {
        'ts': ['ts', 'time', 'date'],
        'command_line': ['cmd', 'command', 'commandline'],
        'process': ['image', 'process', 'proc', 'exe'],
        'parent_process': ['parent'],
        'user': ['user', 'acct', 'account'],
        'host': ['host', 'computer', 'device', 'agent'],
        'event_id': ['eventid', 'eventcode', 'signature'],
        'channel': ['channel', 'source', 'logsource'],
        'src_ip': ['src', 'sourceip', 'orig'],
        'dest_ip': ['dst', 'dest', 'resp', 'remote'],
        'target': ['target', 'subject'],
        'message': ['msg', 'message', 'details', 'fulllog', 'payload']
    }
    for canon, kws in stems.items():
        for kw in kws:
            if kw in col: return canon
    return None

def detect_columns(path, preset=None, map_path=None):
    rows = load_rows(path)
    if not rows:
        print("No rows found.")
        return
        
    columns = set()
    sample_values = {}
    for r in rows:
        for k, v in r.items():
            if k is not None:
                columns.add(k)
                if k not in sample_values and v:
                    sample_values[k] = v
                    
    yaml_path = os.path.join(os.path.dirname(__file__), 'fieldmap.yaml')
    with open(yaml_path, 'r', encoding='utf-8') as f:
        full_map = yaml.safe_load(f)
        
    best_preset = None
    best_count = -1
    
    presets_to_check = full_map.get('presets', {})
    presets_to_check['default'] = full_map.get('default', {})
    
    for p_name, p_map in presets_to_check.items():
        c2c = build_col_to_canonical(p_map)
        count = 0
        for c in columns:
            cl = str(c).lower()
            if cl in c2c or str(c).split('.')[-1].lower() in c2c:
                count += 1
        if count > best_count:
            best_count = count
            best_preset = p_name
            
    print(f"Best matching preset: {best_preset} ({best_count} matched)")
    
    mapping = get_mapping(preset, map_path)
    c2c = build_col_to_canonical(mapping)
    
    has_ts = False
    has_cmd = False
    
    for c in sorted(list(columns)):
        cl = str(c).lower()
        last_seg = str(c).split('.')[-1].lower()
        mapped = "UNMAPPED"
        if cl in c2c:
            mapped = c2c[cl]
        elif last_seg in c2c:
            mapped = c2c[last_seg]
        else:
            fuzzy = fuzzy_match(c)
            if fuzzy: mapped = f"{fuzzy} (fuzzy)"
            
        if "ts" in mapped: has_ts = True
        if "command_line" in mapped or "message" in mapped: has_cmd = True
            
        print(f"{c} -> {mapped} (Sample: {str(sample_values.get(c))[:50]})")
        
    if not has_ts: print("WARNING: No timestamp field detected!")
    if not has_cmd: print("WARNING: No command or message field detected!")


def load(path, preset=None, map_path=None):
    mapping = get_mapping(preset, map_path)
    c2c = build_col_to_canonical(mapping)
    
    rows = load_rows(path)
    events = []
    
    source_name = os.path.basename(path)
    
    for row in rows:
        ev = {
            'ts': None, 'ts_raw': None, 'ts_disp': None, 'host': None, 'user': None,
            'src_ip': None, 'dest_ip': None, 'event_id': None, 'channel': None,
            'process': None, 'pid': None, 'ppid': None, 'parent_process': None,
            'command_line': None, 'target': None, 'message': None, 'raw': row,
            'blob': "", 'source': source_name
        }
        
        blob_vals = []
        unmapped = []
        
        UNMAPPED_SKIP = {"es_index", "es_id", "_score", "took", "timed_out"}
        
        for k, v in row.items():
            if k is None: continue
            
            str_v = str(v)
            if v is not None and str_v.strip():
                blob_vals.append(str_v)
                
            kl = str(k).lower()
            last_seg = str(k).split('.')[-1].lower()
            
            canon = None
            if kl in c2c: canon = c2c[kl]
            elif last_seg in c2c: canon = c2c[last_seg]
            else:
                fuzzy = fuzzy_match(k)
                if fuzzy: canon = fuzzy
                
            if canon:
                if ev[canon] is None: ev[canon] = str(v) if v is not None else None
            elif k not in UNMAPPED_SKIP:
                unmapped.append(f"{k}={v}")
                
        ev['blob'] = " ".join(blob_vals)

        # 4624/4625: user.name bo'sh, hisob TargetUserName da (flat yoki winlog.event_data.*)
        if (ev['user'] or '').strip() in ('', '-'):
            for k, v in row.items():
                if k and str(k).split('.')[-1].lower() == 'targetusername' and str(v or '').strip() not in ('', '-'):
                    ev['user'] = str(v).strip()
                    if not ev['target']: ev['target'] = ev['user']
                    break

        if ev['ts']:
            ev['ts_raw'] = ev['ts']
            ev['ts'] = parse_ts(ev['ts'])
            from bluekit.tz import display_ts
            ev['ts_disp'] = display_ts(ev['ts'], ev['ts_raw'])
            
        if unmapped:
            msg = " ".join(unmapped)
            if ev['message']: ev['message'] = ev['message'] + " " + msg
            else: ev['message'] = msg
                
        events.append(ev)
        
    events_with_ts = [e for e in events if e['ts'] is not None]
    events_no_ts = [e for e in events if e['ts'] is None]
    events_with_ts.sort(key=lambda x: x['ts'])
    
    return events_with_ts + events_no_ts

import sys

def split_preset(spec):
    """'yol@preset' -> (yol, preset). Preset fieldmap.yaml da bo'lmasa '@' yo'lning bir qismi hisoblanadi."""
    if '@' in spec:
        path, _, name = spec.rpartition('@')
        try:
            with open(os.path.join(os.path.dirname(__file__), 'fieldmap.yaml'), 'r', encoding='utf-8') as f:
                known = (yaml.safe_load(f) or {}).get('presets', {})
        except Exception:
            known = {}
        if path and name in known:
            return path, name
    return spec, None

def load_many(items, preset=None, map_path=None):
    all_events = []
    for item in items:
        p = preset
        if isinstance(item, tuple) or isinstance(item, list):
            path = item[0]
            if len(item) > 1 and item[1]:
                p = item[1]
        else:
            path = item
            
        try:
            evs = load(path, preset=p, map_path=map_path)
            if not evs:
                sys.stderr.write(f"[!] {path}: 0 qator o'qildi\n")
            all_events.extend(evs)
        except Exception as e:
            sys.stderr.write(f"[!] {path}: 0 qator o'qildi\n")
            
    for ev in all_events:
        if ev.get('host') is None and ev.get('source'):
            ev['host'] = '[' + ev['source'] + ']'
            
    events_with_ts = [e for e in all_events if e['ts'] is not None]
    events_no_ts = [e for e in all_events if e['ts'] is None]
    events_with_ts.sort(key=lambda x: x['ts'])
    
    return events_with_ts + events_no_ts
