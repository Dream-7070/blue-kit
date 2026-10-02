import json
import os
import glob
import gzip
import base64
import re
import tempfile
import zipfile

def flat(o, pre=''):
    out = {}
    if isinstance(o, dict):
        for k, v in o.items():
            out.update(flat(v, f'{pre}{k}.' if not isinstance(v, dict) else f'{pre}{k}.'))
        return {k.rstrip('.'): v for k, v in out.items()}
    out[pre.rstrip('.')] = o
    return out

def _kv(s):
    return dict(re.findall(r'([\w.]+)=("[^"]*"|\S+)', s or ''))

def load_case(path):
    if path.endswith('.zip'):
        with tempfile.TemporaryDirectory() as d:
            with zipfile.ZipFile(path, 'r') as z:
                z.extractall(d)
            return load_folder(d)
    if os.path.isdir(path):
        return load_folder(path)
    return load_challenge_json(path)

def load_challenge_json(path):
    if not os.path.exists(path):
        raise ValueError(f"File not found: {path}")
    try:
        with open(path, encoding='utf-8') as f:
            d = json.load(f)
    except Exception as e:
        raise ValueError(f"Unknown format: {e}")
        
    ctx = {'clocks': {}, 'uncertainty': {}, 'baseline': d.get('environment', {}).get('baseline', {}), 'ops_text': '',
           'expected_stages': d.get('expected_stages'), 'name': d.get('challenge_id', os.path.basename(path)),
           'template': d.get('submission_template'), 'warnings': []}
    for c in d.get('environment', {}).get('source_clocks', []):
        ctx['clocks'][c['source']] = c.get('clock_offset_seconds', 0)
        ctx['uncertainty'][c['source']] = c.get('uncertainty_seconds', 0)
        
    ev = []
    for r in d.get('records', []):
        attrs = {k.split('.', 1)[-1]: v for k, v in flat(r.get('fields', {})).items()}
        ev.append(dict(id=r.get('event_id'), source=r.get('source'), raw_time=r.get('event_time'), action=r.get('event_type', ''),
                       seq=r.get('source_sequence'), attrs=attrs, ingested=r.get('ingested_at')))
    return ev, ctx

def load_folder(p):
    ctx = {'clocks': {}, 'uncertainty': {}, 'baseline': {}, 'ops_text': '', 'expected_stages': None, 'name': os.path.basename(p.rstrip('/\\')), 'template': None, 'warnings': []}
    ci = glob.glob(os.path.join(p, '**', 'clock_inventory.json'), recursive=True)
    if ci:
        try:
            for c in json.load(open(ci[0], encoding='utf-8')):
                ctx['clocks'][c['source']] = c.get('clock_offset_seconds', 0)
                ctx['uncertainty'][c['source']] = c.get('uncertainty_seconds', 0)
        except: pass
            
    for t in glob.glob(os.path.join(p, '**', 'operations.txt'), recursive=True):
        ctx['ops_text'] += open(t, encoding='utf-8').read() + "\n"
        
    rd = glob.glob(os.path.join(p, '**', 'README*.md'), recursive=True)
    if rd:
        m = re.search(r'Bosqichlar:\s*(\d+)', open(rd[0], encoding='utf-8').read())
        if m: ctx['expected_stages'] = int(m.group(1))
        
    tpl = glob.glob(os.path.join(p, '**', 'submission_template.json'), recursive=True)
    if tpl:
        try: ctx['template'] = json.load(open(tpl[0], encoding='utf-8'))
        except: pass
        
    sums = glob.glob(os.path.join(p, '**', 'SHA256SUMS'), recursive=True)
    if sums:
        import hashlib
        sd = os.path.dirname(sums[0])
        for l in open(sums[0]).read().splitlines():
            if not l.strip(): continue
            h, fn = l.split(None, 1)
            fpath = os.path.join(sd, fn.strip('*'))
            if os.path.exists(fpath):
                if hashlib.sha256(open(fpath, 'rb').read()).hexdigest() != h:
                    ctx['warnings'].append(f"hash mismatch {fn}")
        
    ev = []
    for f in glob.glob(os.path.join(p, '**', '*'), recursive=True):
        f = f.replace('\\', '/')
        if os.path.isdir(f) or 'context/' in f or f.endswith(('.md', 'SHA256SUMS', 'submission_template.json')):
            continue
        op = gzip.open if f.endswith('.gz') else open
        try: txt = op(f, 'rt', encoding='utf-8', errors='replace').read()
        except: continue
            
        base = re.sub(r'\.gz$', '', f)
        if base.endswith('.journal'):
            for b in txt.strip().split('\n\n'):
                r = dict(l.split('=', 1) for l in b.split('\n') if '=' in l)
                if 'EVENT_ID' in r:
                    ev.append(dict(id=r.get('EVENT_ID'), source=r.get('SOURCE'), raw_time=r.get('TIME'), action=r.get('MESSAGE', ''),
                                   seq=None, attrs={k: v.strip('"') for k, v in _kv(r.get('DETAIL')).items()}, ingested=None))
        elif base.endswith('.jsonl'):
            for l in txt.splitlines():
                if l.strip():
                    r = json.loads(l)
                    a = flat(r)
                    ev.append(dict(id=a.pop('id', a.pop('event_id', None)), source=a.pop('source', None), raw_time=a.pop('time', a.pop('timestamp', None)),
                                   action=a.pop('action', a.pop('message', '')), seq=None, attrs=a, ingested=None))
        elif base.endswith('.csv'):
            import csv, io
            for r in csv.DictReader(io.StringIO(txt)):
                a = dict(r)
                if 'detail_b64' in a: a.update(_kv(base64.b64decode(a.pop('detail_b64')).decode('utf-8', 'replace')))
                ev.append(dict(id=a.pop('id', None), source=a.pop('source', None), raw_time=a.pop('time', None), action=a.pop('action', ''), seq=None, attrs=a, ingested=None))
        elif base.endswith('.xml'):
            for m in re.finditer(r'<Event\b.*?</Event>', txt, re.S):
                x = m.group(0); g = lambda t: (re.search(f'<{t}>(.*?)</{t}>', x, re.S) or [None, None])[1]
                a = dict(re.findall(r'<Data Name="([^"]+)">(.*?)</Data>', x))
                ev.append(dict(id=g('EventID') or g('id'), source=g('Provider') or g('source'), raw_time=g('TimeCreated') or g('time'),
                               action=g('Action') or g('action') or '', seq=None, attrs=a, ingested=None))
                               
    for e in ev:
        if e['source'] not in ctx['clocks']:
            ctx['clocks'][e['source']] = 0
            ctx['warnings'].append(f"Clock offset not found for {e['source']}")
            
    if not ev:
        raise ValueError("Unknown format")
    return ev, ctx
