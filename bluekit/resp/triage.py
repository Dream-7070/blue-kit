import os
import re
import ipaddress

_WEBROOT_RE = re.compile(r'(?:^|[\\/])(?:var[\\/]www|srv[\\/]www|usr[\\/]share[\\/]nginx[\\/]html|inetpub[\\/]wwwroot|htdocs|public_html|webapps|wwwroot)(?:[\\/]|$)', re.I)
_WEB_SCRIPT_EXTS = {'.php', '.php5', '.phtml', '.jsp', '.jspx', '.asp', '.aspx', '.ashx', '.asmx', '.cfm', '.cgi'}
def _is_webroot_script(*parts) -> bool:
    joined = '/'.join(str(p) for p in parts if p)
    ext = os.path.splitext(str(parts[-1] if parts else '').lower())[1]
    if not ext:
        ext = os.path.splitext(joined.split('/')[-1])[1].lower()
    return bool(_WEBROOT_RE.search(joined)) and ext in _WEB_SCRIPT_EXTS

def _norm_path_text(text) -> str:
    if not text: return ''
    text = str(text).lower()
    text = re.sub(r'^\\\\\?\\|^\\\?\?\\', '', text)
    text = text.replace('%windir%', 'c:\\windows')
    text = text.replace('%systemroot%', 'c:\\windows')
    text = text.replace('%programfiles%', 'c:\\program files')
    text = text.replace('%programfiles(x86)%', 'c:\\program files (x86)')
    text = text.replace('%programdata%', 'c:\\programdata')
    text = text.replace('%localappdata%', 'c:\\users\\%user%\\appdata\\local')
    text = text.replace('%appdata%', 'c:\\users\\%user%\\appdata\\roaming')
    text = text.replace('%userprofile%', 'c:\\users\\%user%')
    text = text.replace('%public%', 'c:\\users\\public')
    text = text.replace('%temp%', 'c:\\users\\%user%\\appdata\\local\\temp')
    text = text.replace('%tmp%', 'c:\\users\\%user%\\appdata\\local\\temp')
    text = re.sub(r'c:\\users\\[^\\]+\\', lambda m: m.group(0) if m.group(0) == 'c:\\users\\public\\' else 'c:\\users\\%user%\\', text)
    text = re.sub(r'^\\systemroot\\', r'c:\\windows\\', text)
    return text

def _norm_name(name) -> str:
    if not name: return ''
    name = str(name).lower().strip()
    while True:
        prev = name
        name = re.sub(r'[\s_-]*\{[0-9a-f-]{8,}\}$', '', name)
        name = re.sub(r'[\s_-]*s-1-5-21(?:-\d+)+$', '', name)
        name = re.sub(r'[\s_-]+[0-9a-f]{8,}$', '', name)
        if name == prev:
            break
    return name

def _name_in(norm_name, entries) -> bool:
    for e in entries:
        if e.endswith('*'):
            if norm_name.startswith(e[:-1]): return True
        elif norm_name == e:
            return True
    return False

def _match_key(norm_name, mapping) -> list:
    for k, v in mapping.items():
        if _name_in(norm_name, [k]):
            return v
    return []

# tashqi IP ga o'zi ulanmasligi kerak bo'lgan LOLBin lar (high) va shell/script hostlar (med)
CONN_LOLBINS = {'rundll32', 'regsvr32', 'mshta', 'certutil', 'bitsadmin', 'msbuild', 'installutil', 'regasm', 'regsvcs'}
CONN_SHELLS = {'powershell', 'pwsh', 'cmd', 'wscript', 'cscript'}

SUSP_LOCS = ['\\temp\\', '\\appdata\\', '\\programdata\\', '\\users\\public\\', '/tmp', '/dev/shm', '/var/tmp']

def _suspicious_cmd(text) -> tuple | None:
    text = _norm_path_text(text)
    if not text: return None
    if re.search(r'mimikatz|beacon|cobalt|psexec|psexesvc|comsvcs|procdump', text):
        return (None, 'hujum vositasi nomi')
    if re.search(r'(?:^|[\\/\s"\'])(?:nc|nc64|ncat)(?:\.exe)?(?=$|[\s"\'])', text):
        return (None, 'netcat')
    if '\\temp\\' in text or ('temp' in text and text.endswith('.ps1')):
        return (None, 'temp papkasi')
    if 'disable' in text and ('defender' in text or 'mprealtime' in text or 'mpscript' in text):
        return ('T1685', 'Defender o\'chirish')
    if 'exclusion' in text and 'defender' in text:
        return ('T1685', 'Defender o\'chirish')
    if re.search(r'\b(?:powershell|pwsh)(?:\.exe)?\b', text):
        if (re.search(r'(?:^|\s)[-/]e(?:c|nc|ncodedcommand|ncoded)?\s', text) or
            re.search(r'\bbypass\b', text) or
            re.search(r'[-/]w(?:indowstyle)?\s+hidden', text) or
            re.search(r'downloadstring|downloadfile|invoke-webrequest|\biwr\b|\biex\b|invoke-expression|frombase64string|net\.webclient', text)):
            return ('T1059.001', 'PowerShell')
    if re.search(r'\bmshta(?:\.exe)?\b', text):
        if re.search(r'https?://|javascript:|vbscript:|\.hta\b', text):
            return ('T1218.005', 'mshta')
    if re.search(r'\bregsvr32(?:\.exe)?\b', text):
        if re.search(r'/i:|scrobj|https?://', text):
            return ('T1218.010', 'regsvr32')
    if re.search(r'\brundll32(?:\.exe)?\b', text):
        if re.search(r'javascript:|https?://', text) or any(loc in text for loc in SUSP_LOCS):
            return ('T1218.011', 'rundll32')
    if re.search(r'\bcertutil(?:\.exe)?\b', text):
        if re.search(r'[-/]urlcache', text):
            return ('T1105', 'certutil')
        if re.search(r'[-/]decode(?:hex)?\b', text):
            return ('T1140', 'certutil')
    if re.search(r'\bbitsadmin(?:\.exe)?\b', text):
        if re.search(r'/transfer|/addfile|/setnotifycmdline', text):
            return ('T1197', 'bitsadmin')
    if re.search(r'\b(?:wscript|cscript)(?:\.exe)?\b', text):
        if re.search(r'\.(?:vbs|vbe|wsf)\b', text):
            return ('T1059.005', 'wscript/cscript')
        if re.search(r'\.(?:js|jse)\b', text):
            return ('T1059.007', 'wscript/cscript')
    return None

SCRIPT_HOSTS = ('powershell', 'pwsh', 'mshta', 'wscript', 'cscript', 'regsvr32', 'certutil', 'bitsadmin', 'msbuild', 'installutil')

def _is_clean_action(action, allowed_dirs, std_locs=(), allow_bare_exe=False) -> bool:
    t = _norm_path_text(action).strip()
    if not t: return True
    if _suspicious_cmd(t) is not None: return False
    allowed = [_norm_path_text(d) for d in allowed_dirs]
    std = [_norm_path_text(d) for d in std_locs]
    t_clean = t
    for p in allowed + std:
        if p: t_clean = t_clean.replace(p, '<ok>\\')
    if any(loc in t_clean for loc in SUSP_LOCS): return False
    if 'http://' in t or 'https://' in t or re.search(r'(?:^|[\s"\'=])\\\\\w', t): return False
    # Faqat yechilmagan %var% — URL-kodlangan '%20' (Proton%20VPN) emas.
    if re.search(r'%(?!user%)[a-z_][a-z0-9_()]*%', t): return False
    if t.startswith('"'):
        exe_part = t[1:].split('"')[0]
        first_token = f'"{exe_part}"'
    else:
        exe_part = t
        first_token = t.split()[0] if ' ' in t else t
    # Qo'shtirnoqsiz buyruqda exe = birinchi .exe/.com/.bat/.cmd gacha; oxirgi '\'
    # komponenti emas — aks holda 'powershell.exe -file c:\windows\x.ps1' da
    # exe nomi 'x.ps1' bo'lib, script host tekshiruvidan o'tib ketadi.
    m = re.match(r'(.*?\.(?:exe|com|bat|cmd))(?=$|[\s"])', exe_part)
    exe_name = (m.group(1) if m else exe_part.split()[0]).split('\\')[-1]
    for sh in SCRIPT_HOSTS:
        if exe_name == sh or exe_name == f"{sh}.exe":
            return False
    exe_ok = False
    if any(exe_part.startswith(p) for p in allowed if p):
        exe_ok = True
    elif allow_bare_exe and '\\' not in first_token and ':' not in first_token:
        exe_ok = True
    if not exe_ok: return False
    for match in re.finditer(r'[a-z]:\\', t):
        idx = match.start()
        if not any(t[idx:].startswith(p) for p in allowed if p):
            return False
    return True

def _drop_nulls(snap):
    # Real collectors emit JSON null (service without PathName, task without Author);
    # every .get(k, '').lower() below assumes a string.
    if not isinstance(snap, dict):
        return snap
    out = {}
    for k, v in snap.items():
        if isinstance(v, list):
            v = [{f: ('' if x is None else x) for f, x in i.items()} if isinstance(i, dict) else i
                 for i in v if i is not None]
        out[k] = v
    return out


def analyze(kb, current, baseline=None, protected=None, log_artifacts=None):
    current = _drop_nulls(current)
    baseline = _drop_nulls(baseline) if baseline else baseline

    findings = []
    
    import yaml
    from bluekit import paths
    kg_data = {}
    kg_used = False
    kg_path = paths.get_resource_path('bluekit/resp/knowngood.yaml')
    try:
        if os.path.exists(kg_path):
            with open(kg_path, 'r', encoding='utf-8') as f:
                kg_data = yaml.safe_load(f)
            if kg_data:
                kg_used = True
    except Exception:
        pass
        
    os_hint = current.get('meta', {}).get('os')
    kg_suppressed = [0]  # list to allow mutation inside nested functions

    def is_known_good(category, name, value, os_hint, task_path=''):
        if not kg_used: return False
        oses = [os_hint] if os_hint else ['windows', 'linux']
        
        for os_name in oses:
            os_kg = kg_data.get(os_name, {})
            sp = os_kg.get('service_paths', [])
            std = os_kg.get('standard_locations', [])
            vp = os_kg.get('vendor_paths', {}) or {}
            nn = _norm_name(name)
            
            if category == 'tasks':
                tp = os_kg.get('task_prefixes', [])
                if any(task_path.lower().startswith(p.lower()) for p in tp if p) and _is_clean_action(value, sp, std, allow_bare_exe=True):
                    return True
                if _name_in(nn, os_kg.get('tasks', [])) and _is_clean_action(value, sp + _match_key(nn, vp), std, allow_bare_exe=False):
                    return True
                    
            elif category == 'services':
                if str(name).lower() in os_kg.get('services', []):
                    if not value or _is_clean_action(value, sp, std, allow_bare_exe=False):
                        return True
                        
            elif category == 'autoruns':
                if _name_in(nn, os_kg.get('autoruns', [])):
                    if not value or _is_clean_action(value, sp + _match_key(nn, vp), std, allow_bare_exe=False):
                        return True
                        
            elif category == 'users':
                if str(name).lower() in os_kg.get('users', []): return True
                
        return False

    
    prot_set = set(protected or [])

    def is_prot(item):
        if not prot_set: return False
        if item in prot_set: return True
        return any(str(p) in str(item) for p in prot_set)

    def is_checker(item):
        if not log_artifacts: return False
        c_ips = log_artifacts.get('checker_ips', [])
        return item in c_ips or any(str(ip) in str(item) for ip in c_ips)
        
    def quick_log_match(val, target_sets):
        if not log_artifacts: return False
        val_lower = str(val).lower()
        val_base = os.path.basename(val_lower) if '\\' in val_lower or '/' in val_lower else val_lower
        for tset_name in target_sets:
            for x in log_artifacts.get(tset_name, []):
                x_lower = str(x).lower()
                if not x_lower: continue
                # Match artifacts on whole-token / exact-ish comparison
                if val_lower == x_lower or val_base == x_lower:
                    return True
        return False
        
    def add_finding(category, item, score, conf, techs, reasons, extra=None):
        protected_flag = is_prot(item)
        if is_checker(item):
            reasons.append("checker IP (loglardan)")
        f = {'category': category, 'item': item, 'score': score, 'confidence': conf, 'techniques': techs, 'reasons': reasons, 'protected': protected_flag}
        if extra:
            for k, v in extra.items():
                if k not in f:
                    f[k] = v
        findings.append(f)

    # 1. Build Baseline Indexes
    base_users = set()
    base_tasks = set()
    base_autoruns = set()
    base_services = set()
    base_rats = set()
    base_hosts = set()
    base_ssh = set()
    base_cron = set()
    base_wmi = set()
    base_ports = set()
    base_suid = set()
    base_startup = set()
    base_processes = set()
    base_files = set()
    
    if baseline:
        for u in baseline.get('users', []):
            nm = u.get('name', '') if isinstance(u, dict) else u
            base_users.add(str(nm).lower())
        for t in baseline.get('tasks', []):
            if isinstance(t, dict):
                base_tasks.add((t.get('name','').lower(), t.get('action','').lower()))
            else:
                base_tasks.add((str(t).lower(), ''))
        for a in baseline.get('autoruns', []):
            if isinstance(a, dict):
                base_autoruns.add((a.get('name','').lower(), a.get('value','').lower()))
            else:
                base_autoruns.add((str(a).lower(), ''))
        for s in baseline.get('services', []):
            nm = s.get('name', '') if isinstance(s, dict) else s
            base_services.add(str(nm).lower())
        for r in baseline.get('remote_access_tools', []):
            nm = r.get('name', '') if isinstance(r, dict) else r
            base_rats.add(str(nm).lower())
        for h in baseline.get('hosts_file', []):
            base_hosts.add(str(h).strip().lower())
        for s in baseline.get('ssh_authorized_keys', []):
            if isinstance(s, dict):
                base_ssh.add(str(s.get('key_fingerprint_or_line') or s.get('key', '')).strip().lower())
            else:
                base_ssh.add(str(s).strip().lower())
        for c in baseline.get('cron', []):
            if isinstance(c, dict):
                base_cron.add(str(c.get('line') or c.get('job', '')).strip().lower())
            else:
                base_cron.add(str(c).strip().lower())
        for w in baseline.get('wmi_subscriptions', []):
            nm = w.get('name', '') if isinstance(w, dict) else w
            base_wmi.add(str(nm).lower())
        for c in baseline.get('connections', []):
            if isinstance(c, dict):
                base_ports.add((str(c.get('local_port','')), str(c.get('process','')).lower()))
        for c in baseline.get('listening_ports', []):
            if isinstance(c, dict):
                base_ports.add((str(c.get('port','')), str(c.get('process','')).lower()))
        for sf in baseline.get('suid_files', []):
            base_suid.add(str(sf.get('path', '') if isinstance(sf, dict) else sf).strip().lower())
        for si in baseline.get('startup_items', []):
            if isinstance(si, dict):
                base_startup.add(str(si.get('name', '')).strip().lower())
            else:
                base_startup.add(str(si).strip().lower())
        for p in baseline.get('processes', []):
            if isinstance(p, dict):
                base_processes.add((str(p.get('name', '')).lower(), str(p.get('path', '')).lower()))
        for f in baseline.get('suspicious_files', []):
            if isinstance(f, dict) and f.get('path'):
                base_files.add(str(f.get('path', '')).lower())
            elif isinstance(f, str):
                base_files.add(f.lower())

    def get_kb_hit(text):
        if kb is not None and text:
            res = kb.search(text, limit=5)
            for r in res:
                if r['confidence'] == 'high' and r.get('sources', {}).get('heuristic', 0) > 0 and r.get('domain') == 'enterprise':
                    tech = r['attack_id']
                    v = kb.validate([tech])
                    if v and v[0]['status'] in ('revoked', 'deprecated') and v[0]['replacement']:
                        tech = v[0]['replacement']
                    return tech, 'high', None
        
        susp = _suspicious_cmd(text)
        if susp is not None:
            tech, label = susp
            if tech and kb is not None:
                v = kb.validate([tech])
                if v and v[0]['status'] in ('revoked', 'deprecated') and v[0]['replacement']:
                    tech = v[0]['replacement']
            return tech, 'builtin', label
            
        return None, None, None

    def _normalize_tech(tech_id):
        if not tech_id:
            return None
        if kb is not None:
            v = kb.validate([tech_id])
            if v and v[0].get('status') in ('revoked', 'deprecated') and v[0].get('replacement'):
                return v[0]['replacement']
        return tech_id

    def is_staging_path(p: str) -> bool:
        if not p:
            return False
        pl = str(p).lower()
        return pl.startswith('/tmp/') or pl.startswith('/var/tmp/') or pl.startswith('/dev/shm/')

    def _is_public_host(h: str) -> bool:
        if not h:
            return False
        hl = str(h).lower().strip('[]')
        if hl in ('localhost', 'localhost.localdomain'):
            return False
        try:
            ip_obj = ipaddress.ip_address(hl)
            if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_unspecified or ip_obj.is_multicast:
                return False
            if any(ip_obj in net for net in (ipaddress.ip_network('10.0.0.0/8'), ipaddress.ip_network('172.16.0.0/12'), ipaddress.ip_network('192.168.0.0/16'), ipaddress.ip_network('100.64.0.0/10'))):
                return False
            return True
        except ValueError:
            return True

    def calc_score(item_val, search_text, is_new, is_admin=False, is_kg=False):
        score = 0.0
        techs = []
        reasons = []
        has_strong = False
        
        if is_new and baseline is not None:
            score += 0.4
            reasons.append("baseline'da yo'q (yangi)")
            has_strong = True
            
        if baseline is None:
            if not is_kg:
                score += 0.25
                reasons.append("OS standart ro'yxatida yo'q (baseline o'rnida)")
            
        if not is_kg:
            tech, hit_conf, label = get_kb_hit(search_text)
            if hit_conf == 'high':
                score += 0.4
                if tech:
                    techs.append({'id': tech})
                reasons.append(f"KB heuristika ({tech})")
                has_strong = True
            elif hit_conf == 'builtin':
                score += 0.3
                if tech:
                    techs.append({'id': tech})
                reasons.append(f"shubhali nom/buyruq ({label})")
                has_strong = True
                
            t_clean = _norm_path_text(search_text)
            oses = [os_hint] if os_hint else ['windows', 'linux']
            for os_name in oses:
                os_kg = kg_data.get(os_name, {})
                for p in os_kg.get('standard_locations', []):
                    p_norm = _norm_path_text(p)
                    if p_norm: t_clean = t_clean.replace(p_norm, '<ok>\\')
            
            susp_locs = SUSP_LOCS
            if any(loc in t_clean for loc in susp_locs):
                score += 0.2
                reasons.append("shubhali papka")
                has_strong = True
            
        recent = []
        for r in current.get('recent_modified', []):
            p = r.get('path') if isinstance(r, dict) else r
            if p:
                recent.append(str(p).lower())
                
        if search_text:
            search_text_lower = search_text.lower()
            has_slash = '\\' in search_text_lower or '/' in search_text_lower
            if any((has_slash and search_text_lower in rp) or rp in search_text_lower for rp in recent):
                score += 0.1
                reasons.append("yaqinda o'zgartirilgan")
            
        if is_admin:
            if baseline is None:
                if not is_kg:
                    reasons.append("admin akkaunt (baseline yo'q — tekshiring)")
                    score += 0.35
                    has_strong = True
            else:
                reasons.append("admin akkaunt")
                if is_new:
                    # Baselineda bo'lmagan YANGI admin akkaunt — kuchli signal.
                    # Busiz u 0.40 da qolib 'med' bo'lardi va ro'yxatda ko'milib ketardi.
                    score += 0.25
                    reasons.append("yangi admin akkaunt")

        if is_kg and baseline is None and not has_strong:
            score = max(0, score - 0.15)
            reasons.append("OS standart")
            kg_suppressed[0] += 1
            
        score = min(1.0, score)
        if score >= 0.6:
            conf = 'high'
        elif score >= 0.35:
            conf = 'med'
        else:
            conf = 'low'
            
        return score, conf, techs, reasons, has_strong
        
    for t in current.get('tasks', []):
        if isinstance(t, dict):
            name = t.get('name', '')
            action = t.get('action', '')
        else:
            name = str(t)
            action = ''
            
        is_new = (name.lower(), action.lower()) not in base_tasks
        is_kg = is_known_good('tasks', name, action, os_hint, task_path=t.get('path', '') if isinstance(t, dict) else '')
        
        s, c, th, r, has_strong = calc_score(name, action, is_new, is_kg=is_kg)
        
        path_action = ''
        trigger = ''
        if isinstance(t, dict):
            path_action = t.get('path', '') + ' ' + action + ' ' + name + ' ' + t.get('file', '')
            trigger = t.get('trigger', '') or t.get('schedule', '')

        is_cron = False
        if os_hint == 'linux': is_cron = True
        elif '/etc/cron' in path_action or '/var/spool/cron' in path_action: is_cron = True
        elif trigger and re.match(r'^\s*(?:@(?:reboot|yearly|annually|monthly|weekly|daily|hourly)|(?:[\d*/,\-]+\s+){4}[\d*/,\-]+)\s*$', trigger): is_cron = True

        if is_cron and (is_new or baseline is None):
            has_strong = True

        if quick_log_match(name, ['task_names']) or quick_log_match(action, ['files', 'filenames']):
            has_strong = True
            
        if has_strong:
            if is_cron:
                th = [x for x in th if x['id'] != 'T1053.005']
                if not any(x['id'] == 'T1053.003' for x in th):
                    th.append({'id': 'T1053.003'})
            else:
                if not any(x['id'] == 'T1053.005' for x in th):
                    th.append({'id': 'T1053.005'})
            add_finding('tasks', name, s, c, th, r)

    for u in current.get('users', []):
        if isinstance(u, dict):
            name = u.get('name', '')
            is_admin = u.get('is_admin', False)
            uid = u.get('uid')
        else:
            name = str(u)
            is_admin = False
            uid = None
            
        is_new = name.lower() not in base_users
        is_kg = is_known_good('users', name, '', os_hint)
        
        s, c, th, r, has_strong = calc_score(name, name, is_new, is_admin=is_admin, is_kg=is_kg)
        if uid == 0 and name != 'root':
            s = max(s, 0.8)
            c = 'high'
            r.append('NON-root user with uid==0')
            has_strong = True
            if not any(x['id'] == 'T1136.001' for x in th): th.append({'id': 'T1136.001'})
            if not any(x['id'] == 'T1548' for x in th): th.append({'id': 'T1548'})
            
        if quick_log_match(name, ['users']):
            has_strong = True
            
        if has_strong:
            if not any(x['id'] == 'T1078.003' for x in th):
                th.append({'id': 'T1078.003'})
            if is_admin and baseline is None and not is_kg and s < 0.35:
                c = 'med'
            final_s = max(s, 0.35) if (is_admin and baseline is None and not is_kg) else s
            add_finding('users', name, final_s, c, th, r)
                
    for a in current.get('autoruns', []):
        if isinstance(a, dict):
            name = a.get('name', '')
            val = a.get('value', '')
            loc = a.get('location', '')
        else:
            name = str(a)
            val = ''
            loc = ''
            
        is_new = (name.lower(), val.lower()) not in base_autoruns
        is_kg = is_known_good('autoruns', name, val, os_hint)
        
        s, c, th, r, has_strong = calc_score(name, val, is_new, is_kg=is_kg)
        if quick_log_match(name, ['run_values']) or quick_log_match(val, ['files', 'filenames']):
            has_strong = True
            
        is_web = _is_webroot_script(loc, val, name)
        if is_web:
            has_strong = True
            if is_new or baseline is None:
                s = max(s, 0.85)
                c = 'high'
                r.append("web root da skript (web shell ehtimoli)")

        if has_strong:
            if not any(x['id'] == 'T1547.001' for x in th):
                th.append({'id': 'T1547.001'})
            if is_web:
                th = [x for x in th if x['id'] != 'T1547.001']
                v_tid = _normalize_tech('T1505.003')
                if v_tid and not any(x['id'] == v_tid for x in th): th.append({'id': v_tid})
            add_finding('autoruns', name, s, c, th, r, extra={'location': loc, 'raw': val})
                
    for s_obj in current.get('services', []):
        if isinstance(s_obj, dict):
            name = s_obj.get('name', '')
            bp = s_obj.get('binary_path', '')
        else:
            name = str(s_obj)
            bp = ''
            
        is_new = name.lower() not in base_services
        is_kg = is_known_good('services', name, bp, os_hint)
        
        s, c, th, r, has_strong = calc_score(name, bp, is_new, is_kg=is_kg)
        
        bp_lower = bp.lower()
        if '\\temp\\' in bp_lower or '/tmp' in bp_lower or '/dev/shm' in bp_lower or '/var/tmp' in bp_lower or '\\users\\public\\' in bp_lower:
            has_strong = True
            s = max(s, 0.8)
            c = 'high' if c != 'high' else c
            
        if quick_log_match(name, ['services']) or quick_log_match(bp, ['files', 'filenames']):
            has_strong = True
            
        if has_strong:
            if not any(x['id'] == 'T1543.003' for x in th):
                th.append({'id': 'T1543.003'})
            add_finding('services', name, s, c, th, r)
                
    for r in current.get('remote_access_tools', []):
        name = r.get('name', '') if isinstance(r, dict) else str(r)
        is_new = name.lower() not in base_rats
        s, c, th, rs, has_strong = calc_score(name, name, is_new)
        if quick_log_match(name, ['rat_names']):
            has_strong = True
        
        # RATs are inherently strong known-bad
        has_strong = True
        
        if has_strong and (baseline is None or is_new):
            if not any(x['id'] == 'T1219' for x in th):
                th.append({'id': 'T1219'})
            add_finding('remote_access_tools', name, max(s, 0.4 if is_new else 0), 'high' if is_new else c, th, rs)
            
    for h in current.get('hosts_file', []):
        h_val = str(h.get('entry', h) if isinstance(h, dict) else h)
        is_new = h_val.strip().lower() not in base_hosts
        # KB matn qidiruvi hosts yozuviga ishlatilmaydi: u buyruq qatori uchun
        # mo'ljallangan va 'fileserver' kabi oddiy nomlarga tasodifiy texnika
        # moslab qo'yadi. Bu yerda IP qoidasi va log tasdig'i hal qiladi.
        s, c, th, rs, has_strong = calc_score(h_val, '', is_new)
        
        h_ip = h_val.split()[0] if h_val.strip() else ""
        if h_ip and not (h_ip.startswith('127.') or h_ip == '::1' or h_ip == '0.0.0.0'):
            # Ichki IP ga ishora qiluvchi yozuv (192.168.x, 10.x, 172.16-31.x) korporativ
            # muhitda normal — uni 'med' qilamiz. Tashqi (public) IP esa hosts hijacking:
            # aynan 1-kun stsenariysidagi soxta bank domeni shunday ko'rinadi.
            is_public = _is_public_host(h_ip)
            
            if baseline is not None and not is_new and not is_public:
                continue

            has_strong = True
            if is_public:
                s = max(s, 0.6)
                rs.append("hosts faylida TASHQI IP")
            else:
                s = max(s, 0.4)
                rs.append("hosts faylida ichki IP")
            c = 'high' if s >= 0.6 else 'med'

        if quick_log_match(h_val, ['hosts_entries']):
            has_strong = True
            
        if has_strong:
            if not any(x['id'] == 'T1565.001' for x in th):
                th.append({'id': 'T1565.001'})
            # 'high' faqat ikki holatda: tashqi IP (hosts hijacking) yoki haqiqiy
            # baseline diffi. Baselinesiz rejimda hamma yozuv 'yangi' ko'rinadi,
            # shuning uchun unga tayanib bo'lmaydi.
            h_conf = 'high' if (s >= 0.6 or (is_new and baseline is not None)) else c
            add_finding('hosts_file', h_val, s, h_conf, th, rs)
            
    for w in current.get('wmi_subscriptions', []):
        if isinstance(w, dict):
            name = w.get('name', '')
            query = w.get('query', '')
            consumer = w.get('consumer', '')
        else:
            name = str(w)
            query = ''
            consumer = ''
            
        if not name:
            continue
            
        is_new = name.lower() not in base_wmi
        
        if name == 'SCM Event Log Filter' or consumer.startswith('NTEventLogEventConsumer'):
            continue
            
        eval_text = f"{name} {query} {consumer}"
        s, c, th, rs, has_strong = calc_score(name, eval_text, is_new)
        
        c_lower = consumer.lower()
        if _suspicious_cmd(consumer) is not None or re.search(r'\b(?:powershell|pwsh|cmd\.exe|cmd /c|wscript|cscript|mshta|rundll32|regsvr32)\b|https?://', c_lower) or 'activescripteventconsumer' in c_lower:
            has_strong = True
            c = 'high'
            s = max(s, 0.8)
            rs.append("WMI consumer buyruq ishga tushiradi")
        elif not has_strong:
            if baseline is None:
                has_strong = True
                c = 'med'
                s = max(s, 0.5)
            elif is_new:
                has_strong = True
                c = 'high'
            
        if has_strong:
            if not any(x['id'] == 'T1546.003' for x in th):
                th.append({'id': 'T1546.003'})
            add_finding('wmi_subscriptions', name, s, c, th, rs, extra={'raw': consumer, 'query': query})
            
    for cron in current.get('cron', []):
        if isinstance(cron, dict):
            raw = cron.get('job') or cron.get('line', '')
            user = cron.get('user', '')
            fpath = cron.get('file', '')
        else:
            raw = str(cron)
            user = ''
            fpath = ''
            
        if not raw:
            continue
            
        item_str = f"{raw} (user: {user})" if user else raw
        is_new = raw.strip().lower() not in base_cron
        
        # Known-good check
        raw_is_file = raw.startswith('/etc/cron') or raw == '/etc/crontab'
        raw_base = os.path.basename(raw) if raw_is_file else ''
        linux_cron = kg_data.get('linux', {}).get('cron', [])
        is_kg = raw_is_file and raw_base in linux_cron

        if is_kg:
            continue

        s, c, th, rs, has_strong = calc_score(item_str, raw, is_new)
        
        raw_lower = raw.lower()
        if (('curl' in raw_lower or 'wget' in raw_lower) and ('| sh' in raw_lower or '| bash' in raw_lower or '-o- ' in raw_lower + ' | ')) or \
           '/tmp/' in raw_lower or '/dev/shm/' in raw_lower or '/var/tmp/' in raw_lower or \
           'base64 -d' in raw_lower or '/dev/tcp/' in raw_lower or 'nc -e' in raw_lower or 'ncat -e' in raw_lower or \
           ('python -c' in raw_lower and 'socket' in raw_lower) or ('chmod +x' in raw_lower and '/tmp' in raw_lower) or \
           _suspicious_cmd(raw) is not None:
            has_strong = True
            c = 'high'
            s = max(s, 0.8)
            rs.append("shubhali cron buyrug'i")
            
        if not has_strong:
            if is_new and baseline is not None:
                c = 'high'
            elif baseline is None:
                c = 'med'
                s = max(s, 0.45)
                rs.append("OS standart ro'yxatida yo'q (baseline o'rnida)")
            
        if has_strong or is_new:
            if not any(x['id'] == 'T1053.003' for x in th):
                th.append({'id': 'T1053.003'})
            add_finding('cron', item_str, s, c, th, rs, extra={'raw': raw, 'user': user, 'file': fpath})
            
    for ssh in current.get('ssh_authorized_keys', []):
        if isinstance(ssh, dict):
            raw = ssh.get('key') or ssh.get('key_fingerprint_or_line', '')
            user = ssh.get('user', '')
            fpath = ssh.get('file', '')
        else:
            raw = str(ssh)
            user = ''
            fpath = ''
            
        if not raw:
            continue
            
        if not user and fpath:
            if fpath.startswith('/root/'):
                user = 'root'
            else:
                m = re.match(r'^/home/([^/]+)/', fpath)
                if m:
                    user = m.group(1)
                    
        parts = raw.split()
        if len(parts) >= 2 and parts[0].startswith('ssh-'):
            ktype = parts[0]
            kbody = parts[1]
            kcomm = ' '.join(parts[2:]) if len(parts) > 2 else ''
            short_k = kbody[-12:] if len(kbody) >= 12 else kbody
            item_str = f"{ktype} …{short_k}"
            if kcomm: item_str += f" {kcomm}"
            if user: item_str += f" (user: {user})"
        else:
            item_str = raw if len(raw) < 50 else f"…{raw[-40:]}"
            if user: item_str += f" (user: {user})"
            
        is_new = raw.strip().lower() not in base_ssh
        
        if baseline is not None and not is_new:
            continue
            
        s, c, th, rs, has_strong = calc_score(item_str, raw, is_new)
        
        if baseline is not None and is_new:
            has_strong = True
            c = 'high'
            s = max(s, 0.8)
            rs.append("yangi ssh kalit")
        elif baseline is None:
            if user == 'root':
                has_strong = True
                c = 'high'
                s = max(s, 0.65)
                rs.append("root ga ssh kalit")
            else:
                has_strong = True # to force logging it
                if c != 'high':
                    c = 'med'
                s = max(s, 0.5)
                rs.append("baseline yo'q — kalit egasini tekshiring")
                
        if has_strong:
            if not any(x['id'] == 'T1098.004' for x in th):
                th.append({'id': 'T1098.004'})
            add_finding('ssh_authorized_keys', item_str, s, c, th, rs, extra={'raw': raw, 'user': user, 'file': fpath})

    for sf in current.get('suid_files', []):
        if isinstance(sf, dict):
            sf_str = sf.get('path', '')
        else:
            sf_str = str(sf).strip()
            
        if not sf_str:
            continue
            
        is_new = sf_str.lower() not in base_suid
        
        linux_suid = kg_data.get('linux', {}).get('suid', [])
        is_kg = sf_str in linux_suid
        if is_kg:
            continue
            
        s, c, th, rs, has_strong = calc_score(sf_str, sf_str, is_new)
        sf_lower = sf_str.lower()
        sf_base = os.path.basename(sf_lower)
        
        gtfo_bins = {'bash', 'sh', 'dash', 'zsh', 'ksh', 'find', 'vim', 'vi', 'nano', 'python', 'python2', 'python3', 'perl', 'ruby', 'lua', 'php', 'nmap', 'cp', 'mv', 'less', 'more', 'env', 'awk', 'gawk', 'tar', 'zip', 'wget', 'curl', 'socat', 'nc', 'ncat', 'tee', 'dd', 'base64', 'xxd', 'busybox', 'docker'}
        
        if sf_base in gtfo_bins:
            has_strong = True
            c = 'high'
            s = max(s, 0.85)
            rs.append("GTFOBins SUID (root shell)")
        elif '/tmp' in sf_lower or '/dev/shm' in sf_lower or '/var/tmp' in sf_lower or '/home/' in sf_lower or '/run/user/' in sf_lower:
            has_strong = True
            c = 'high'
            s = max(s, 0.8)
            rs.append("shubhali SUID fayl joylashuvi")
        elif is_new and baseline is not None:
            has_strong = True
            c = 'high'
            s = max(s, 0.6)
            rs.append("yangi SUID fayl")
        elif baseline is None:
            has_strong = True
            if c != 'high':
                c = 'med'
            s = max(s, 0.45)
            
        if has_strong:
            if not any(x['id'] == 'T1548.001' for x in th):
                th.append({'id': 'T1548.001'})
            add_finding('suid_files', sf_str, s, c, th, rs, extra={'path': sf_str})

    for si in current.get('startup_items', []):
        if isinstance(si, dict):
            name = si.get('name', '')
            path = si.get('path', '')
            loc = si.get('location', '')
        else:
            name = str(si)
            path = ''
            loc = ''
            
        if not name:
            continue
            
        name_lower = name.strip().lower()
        if name_lower == 'desktop.ini':
            continue
            
        is_new = name_lower not in base_startup
        
        exts = {'.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.bat', '.cmd', '.ps1', '.scr', '.pif', '.exe', '.dll', '.com'}
        ext = os.path.splitext(name_lower)[1]
        
        has_strong = False
        c = 'low'
        s = 0.0
        rs = []
        th = [{'id': 'T1547.001'}]
        
        if ext in exts:
            has_strong = True
            c = 'high'
            s = 0.8
            rs.append("Startup papkasida skript/exe")
        else:
            name_noext = os.path.splitext(name)[0]
            win_autoruns = kg_data.get('windows', {}).get('autoruns', [])
            is_kg = False
            for w_ar in win_autoruns:
                if w_ar.endswith('*') and name_noext.lower().startswith(w_ar[:-1]): is_kg = True
                elif name_noext.lower() == w_ar: is_kg = True
                
            if is_kg:
                continue
                
            if is_new and baseline is not None:
                has_strong = True
                c = 'high'
                s = 0.6
                rs.append("yangi startup item")
            elif baseline is None:
                has_strong = True
                c = 'med'
                s = 0.45
                rs.append("baseline yo'q — startup item")
                
        is_web = _is_webroot_script(loc, path, name)
        if is_web:
            has_strong = True
            if is_new or baseline is None:
                s = max(s, 0.85)
                c = 'high'
                rs.append("web root da skript (web shell ehtimoli)")

        if has_strong:
            if is_web:
                th = [x for x in th if x['id'] != 'T1547.001']
                v_tid = _normalize_tech('T1505.003')
                if v_tid and not any(x['id'] == v_tid for x in th): th.append({'id': v_tid})
            add_finding('startup_items', name, s, c, th, rs, extra={'path': path, 'location': loc})

    if os_hint == 'windows':
        defender = current.get('defender')
        if isinstance(defender, dict):
            defender_warnings = []
            realtime = defender.get('realtime')
            if realtime is False:
                c = 'high'
                s = 0.8
                rs = ["Defender realtime o'chirilgan"]
                if baseline and isinstance(baseline.get('defender'), dict) and baseline['defender'].get('realtime') is False:
                    c = 'med'
                
                tech_id = 'T1685'
                add_finding('defender', 'realtime', s, c, [{'id': tech_id}], rs)
                
            exclusions = defender.get('exclusions')
            if exclusions is None: exclusions = []
            elif isinstance(exclusions, str): exclusions = [exclusions]
            
            base_excl = set()
            if baseline and isinstance(baseline.get('defender'), dict):
                be = baseline['defender'].get('exclusions', [])
                if isinstance(be, str): be = [be]
                elif be is None: be = []
                for x in be: base_excl.add(str(x).strip().lower())
                
            for excl in exclusions:
                excl_str = str(excl).strip()
                if not excl_str: continue
                if excl_str.startswith('N/A'):
                    defender_warnings.append("Defender istisnolari o'qilmadi — kollektorni admin sifatida yurgizing")
                    continue
                    
                excl_lower = excl_str.lower()
                is_new = excl_lower not in base_excl
                
                if baseline is not None and not is_new:
                    continue
                    
                has_strong = False
                c = 'low'
                s = 0.0
                rs = []
                th = [{'id': 'T1685'}]
                
                if '\\users\\public' in excl_lower or '\\appdata\\' in excl_lower or '\\temp' in excl_lower or '\\downloads' in excl_lower or '\\windows\\temp' in excl_lower:
                    has_strong = True
                    c = 'high'
                    s = 0.8
                    rs.append("Defender istisnosi shubhali papkada")
                elif re.match(r'^[a-z]:\\?$', excl_lower):
                    has_strong = True
                    c = 'high'
                    s = 0.8
                    rs.append("Defender istisnosi shubhali papkada")
                elif '\\programdata' in excl_lower:
                    parts = excl_lower.split('\\programdata')
                    if len(parts) > 1 and parts[1].strip('\\').count('\\') == 0:
                        has_strong = True
                        c = 'high'
                        s = 0.8
                        rs.append("Defender istisnosi shubhali papkada")
                        
                if not has_strong:
                    if is_new and baseline is not None:
                        has_strong = True
                        c = 'high'
                        s = 0.6
                        rs.append("yangi Defender istisnosi")
                    elif baseline is None:
                        has_strong = True
                        c = 'med'
                        s = 0.5
                        rs.append("Defender istisnosi (baseline yo'q)")
                        
                if has_strong:
                    add_finding('defender', excl_str, s, c, th, rs, extra={'raw': excl_str})

    def is_public_ip(ip):
        from bluekit.netutil import is_external_ip
        return is_external_ip(ip)

    # hosts/proxy/DNS ga yozilgan tashqi IP ga ulanish — fraud zanjirining bir qismi
    fraud_ips = set()
    for h in current.get('hosts_file', []):
        parts = str(h).split()
        if parts and is_public_ip(parts[0]):
            fraud_ips.add(parts[0])
    proxy = current.get('proxy') or {}
    net_text = ' '.join([str(proxy.get('ProxyServer', '')), str(proxy.get('AutoConfigURL', ''))] +
                        [str(d.get('addresses', '')) for d in current.get('dns_servers', []) if isinstance(d, dict)])
    fraud_ips.update(ip for ip in re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', net_text) if is_public_ip(ip))

    proc_high_findings = {}

    for proc in current.get('processes', []):
        pid = proc.get('pid', 0)
        ppid = proc.get('ppid', 0)
        name = str(proc.get('name', ''))
        path = str(proc.get('path', ''))
        cmdline = str(proc.get('cmdline', ''))
        signed = str(proc.get('signed', 'n/a'))
        sha256 = str(proc.get('sha256', ''))
        exe_deleted = proc.get('exe_deleted', False)
        
        name_lower = name.lower()
        path_lower = path.lower()
        norm_path = _norm_path_text(path_lower)
        cmdline_lower = cmdline.lower()
        
        is_windows = os_hint == 'windows'
        is_linux = os_hint == 'linux'
        
        item_str = f"{name} (pid {pid}) {path}"
        extra = {'pid': pid, 'path': path, 'cmdline': cmdline, 'sha256': sha256, 'os': os_hint}
        
        has_finding = False
        s = 0.0
        c = 'low'
        th = []
        rs = []
        
        in_baseline = False
        if baseline is not None:
            if (name_lower, path_lower) in base_processes:
                in_baseline = True
        
        if is_windows:
            masq_names = {'svchost', 'lsass', 'csrss', 'smss', 'wininit', 'services', 'winlogon', 'spoolsv', 'dllhost', 'conhost', 'taskhostw', 'runtimebroker', 'searchindexer', 'wmiprvse'}
            is_p1 = False
            name_noext = name_lower.replace('.exe', '')
            if path and name_noext in masq_names:
                if not (norm_path.startswith('c:\\windows\\system32\\') or norm_path.startswith('c:\\windows\\syswow64\\')):
                    is_p1 = True
            if path and name_lower == 'explorer.exe':
                if norm_path != 'c:\\windows\\explorer.exe':
                    is_p1 = True
            
            if is_p1:
                has_finding = True
                s = max(s, 0.9)
                c = 'high'
                if not any(x['id'] == 'T1036.005' for x in th): th.append({'id': 'T1036.005'})
                rs.append("tizim jarayoni nomi noto'g'ri papkadan")
            elif name_noext == 'svchost' and path:
                if '-k ' not in cmdline_lower:
                    has_finding = True
                    s = max(s, 0.85)
                    c = 'high'
                    rs.append("svchost -k siz")
                else:
                    pproc = next((p for p in current.get('processes', []) if p.get('pid') == ppid), None)
                    if pproc and str(pproc.get('name', '')).lower() != 'services.exe':
                        has_finding = True
                        s = max(s, 0.85)
                        c = 'high'
                        rs.append("svchost ota jarayoni services.exe emas")
                        
            if ppid > 0:
                pproc = next((p for p in current.get('processes', []) if p.get('pid') == ppid), None)
                if pproc:
                    pname = str(pproc.get('name', '')).lower().replace('.exe', '')
                    cname = name_noext
                    is_p2 = False
                    p2_tech = ''
                    if pname in {'winword', 'excel', 'powerpnt', 'outlook', 'onenote', 'acrord32', 'acrobat'}:
                        if cname in {'cmd', 'powershell', 'pwsh', 'wscript', 'cscript', 'mshta', 'rundll32', 'regsvr32', 'certutil', 'bitsadmin'}:
                            is_p2 = True
                            p2_tech = 'T1204.002'
                    elif pname in {'w3wp', 'httpd', 'nginx', 'sqlservr', 'apache2', 'lighttpd', 'php-fpm', 'uwsgi', 'gunicorn'} or pname.startswith('tomcat') or pname.startswith('php-fpm') or pname == 'php-cgi':
                        if cname in {'cmd', 'powershell', 'pwsh', 'whoami', 'net', 'net1', 'certutil', 'bitsadmin', 'sh', 'bash', 'dash', 'zsh', 'python', 'python3', 'perl', 'id', 'uname', 'nc', 'ncat'}:
                            is_p2 = True
                            p2_tech = 'T1505.003'
                    elif pname == 'wmiprvse':
                        if cname in {'cmd', 'powershell', 'pwsh'}:
                            is_p2 = True
                            p2_tech = 'T1047'
                    elif pname == 'services':
                        if cname in {'cmd', 'powershell'} and ('/c' in cmdline_lower or '-' in cmdline_lower):
                            is_p2 = True
                            p2_tech = 'T1543.003'
                    
                    if is_p2:
                        has_finding = True
                        s = max(s, 0.85)
                        c = 'high'
                        if not any(x['id'] == p2_tech for x in th): th.append({'id': p2_tech})
                        rs.append(f"shubhali ota-bola: {pname} -> {cname}")

            if not in_baseline:
                susp = _suspicious_cmd(cmdline)
                if susp:
                    tech, label = susp
                    has_finding = True
                    s = max(s, 0.8)
                    c = 'high' if s >= 0.6 else c
                    if tech:
                        v_tech = _normalize_tech(tech)
                        if v_tech and not any(x['id'] == v_tech for x in th): th.append({'id': v_tech})
                    rs.append(label)

            if not in_baseline:
                is_p4 = False
                p4_s = 0.0
                p4_c = ''
                if any(norm_path.startswith(x) for x in ['c:\\windows\\temp\\', 'c:\\users\\public\\', 'c:\\programdata\\', 'c:\\$recycle.bin\\', 'c:\\perflogs\\', 'c:\\users\\%user%\\appdata\\local\\temp\\']):
                    if signed != 'valid':
                        is_p4 = True
                        p4_s = 0.8
                        p4_c = 'high'
                elif any(norm_path.startswith(x) for x in ['c:\\users\\%user%\\downloads\\', 'c:\\users\\%user%\\desktop\\', 'c:\\users\\%user%\\appdata\\roaming\\', 'c:\\users\\%user%\\appdata\\local\\']) and not norm_path.startswith('c:\\users\\%user%\\appdata\\local\\temp\\'):
                    if signed in ('unsigned', 'invalid'):
                        is_p4 = True
                        p4_s = 0.55
                        p4_c = 'med'
                
                if signed == 'invalid':
                    has_finding = True
                    s = max(s, 0.8)
                    c = 'high'
                    rs.append("imzo buzilgan / hash mos emas")
                    tech = _normalize_tech('T1036.001')
                    if tech and not any(x['id'] == tech for x in th): th.append({'id': tech})
                elif is_p4:
                    has_finding = True
                    s = max(s, p4_s)
                    c = p4_c if s == p4_s else c
                    rs.append("shubhali joylashuv")
                    
            if not in_baseline:
                conn_pid = next((conn for conn in current.get('connections', []) if (conn.get('pid') if isinstance(conn, dict) else None) == pid), None)
                if conn_pid:
                    raddr = conn_pid.get('raddr', '')
                    if is_public_ip(raddr) and signed != 'valid':
                        is_p5_loc = False
                        if any(norm_path.startswith(x) for x in ['c:\\windows\\temp\\', 'c:\\users\\public\\', 'c:\\programdata\\', 'c:\\$recycle.bin\\', 'c:\\perflogs\\', 'c:\\users\\%user%\\appdata\\local\\temp\\']):
                            is_p5_loc = True
                        elif any(norm_path.startswith(x) for x in ['c:\\users\\%user%\\downloads\\', 'c:\\users\\%user%\\desktop\\', 'c:\\users\\%user%\\appdata\\roaming\\', 'c:\\users\\%user%\\appdata\\local\\']) and not norm_path.startswith('c:\\users\\%user%\\appdata\\local\\temp\\'):
                            is_p5_loc = True
                        
                        if not is_p5_loc and path:
                            if not (norm_path.startswith('c:\\windows\\') or norm_path.startswith('c:\\program files\\') or norm_path.startswith('c:\\program files (x86)\\')):
                                is_p5_loc = True
                        
                        if is_p5_loc or (path and not (norm_path.startswith('c:\\windows\\') or norm_path.startswith('c:\\program files\\') or norm_path.startswith('c:\\program files (x86)\\'))):
                            has_finding = True
                            s = max(s, 0.85)
                            c = 'high'
                            rs.append("imzosiz jarayon tashqi IP ga ulangan")
                            tech = _normalize_tech('T1071')
                            if tech and not any(x['id'] == tech for x in th): th.append({'id': tech})
                            
            if not in_baseline and baseline is None:
                if signed in ('unsigned', 'invalid') and '\\windowsapps\\' not in norm_path and (norm_path.startswith('c:\\program files\\') or norm_path.startswith('c:\\program files (x86)\\') or norm_path.startswith('c:\\windows\\')):
                    has_finding = True
                    s = max(s, 0.45)
                    c = 'med' if c == 'low' else c
                    rs.append("standart joyda imzosiz jarayon")

        elif is_linux:
            if exe_deleted:
                has_finding = True
                s = max(s, 0.85)
                c = 'high'
                rs.append("ijro fayli o'chirilgan, jarayon ishlayapti (fileless)")
                tech = _normalize_tech('T1070.004')
                if tech and not any(x['id'] == tech for x in th): th.append({'id': tech})
                
            if not in_baseline:
                first_token = cmdline.split()[0] if cmdline else ""
                if path.startswith('/tmp/') or path.startswith('/dev/shm/') or path.startswith('/var/tmp/') or path.startswith('/run/user/') or \
                   first_token.startswith('/tmp/') or first_token.startswith('/dev/shm/') or first_token.startswith('/var/tmp/') or first_token.startswith('/run/user/'):
                    has_finding = True
                    s = max(s, 0.85)
                    c = 'high'
                    rs.append("shubhali joydan ishga tushgan")
                elif path.startswith('/home/') or first_token.startswith('/home/'):
                    has_finding = True
                    s = max(s, 0.55)
                    c = 'med' if c == 'low' else c
                    rs.append("/home/ dan ishga tushgan")
                    
            if not in_baseline:
                is_lp3 = False
                if 'bash -i' in cmdline_lower and '/dev/tcp/' in cmdline_lower:
                    is_lp3 = True
                elif any(x in cmdline_lower for x in ['nc ', 'ncat ', 'socat ']) and ('-e' in cmdline_lower or 'exec:' in cmdline_lower):
                    is_lp3 = True
                elif 'python' in cmdline_lower and '-c' in cmdline_lower and 'socket' in cmdline_lower and ('connect' in cmdline_lower or 'pty' in cmdline_lower):
                    is_lp3 = True
                elif 'perl -e' in cmdline_lower and 'socket' in cmdline_lower:
                    is_lp3 = True
                elif ('curl' in cmdline_lower or 'wget' in cmdline_lower) and ('| sh' in cmdline_lower or '| bash' in cmdline_lower):
                    is_lp3 = True
                elif 'base64 -d' in cmdline_lower and ('| sh' in cmdline_lower or '| bash' in cmdline_lower):
                    is_lp3 = True
                
                if is_lp3:
                    has_finding = True
                    s = max(s, 0.8)
                    c = 'high'
                    rs.append("shubhali buyruq (teskari qobiq / dropper)")
                    tech = _normalize_tech('T1059.004')
                    if tech and not any(x['id'] == tech for x in th): th.append({'id': tech})
                    
            # 2a. DB dump buyrug'i
            if re.search(r'\b(?:pg_dump|pg_dumpall|mysqldump|mongodump)\b', cmdline_lower):
                pproc = next((p for p in current.get('processes', []) if p.get('pid') == ppid), None)
                pname = str(pproc.get('name', '')).lower() if pproc else ''
                is_shell_parent = pname in {'bash', 'sh', 'dash', 'zsh', 'ash'}
                has_staging_out = bool(re.search(r'(?:(?:-f|--file|-r)\s*[=\s]?|>\s*)["\']?(?:/tmp/|/var/tmp/|/dev/shm/)[^\s"\']*', cmdline_lower))
                if is_shell_parent or has_staging_out:
                    has_finding = True
                    s = max(s, 0.7)
                    c = 'high'
                    rs.append("DB dump buyrug'i interaktiv qobiqdan / staging papkaga")
                    tech = _normalize_tech('T1005')
                    if tech and not any(x['id'] == tech for x in th): th.append({'id': tech})

            # 2b. Yuklash (upload) buyrug'i
            if re.search(r'\b(?:curl|wget)\b', cmdline_lower):
                # Bayroqlar katta-kichik harfga sezgir: curl -F/-T yuklash, -f/-t esa boshqa (jim rejim, qayta urinish)
                has_upload_flag = bool(re.search(r'(?:^|\s)(?:-F|--form|-T|--upload-file|--post-file)(?:\s+|=)|(?:^|\s)(?:--data-binary|-d|--data)\s*@', cmdline))
                if has_upload_flag:
                    m_url = re.search(r'https?://([^/:\s"\']+)', cmdline)
                    if m_url:
                        target_host = m_url.group(1).strip('[]')
                        if _is_public_host(target_host):
                            has_finding = True
                            s = max(s, 0.75)
                            c = 'high'
                            rs.append("tashqi manzilga fayl yuklash")
                            tech = _normalize_tech('T1041')
                            if tech and not any(x['id'] == tech for x in th): th.append({'id': tech})

            # 2c. Arxivlash buyrug'i
            is_arch_cmd = False
            m_tar = re.search(r'\btar\s+(?:(--create)\b|-{0,2}([a-z]+))', cmdline_lower)
            if m_tar and (m_tar.group(1) or (m_tar.group(2) and 'c' in m_tar.group(2) and not set(m_tar.group(2)) & {'x', 't'})):
                is_arch_cmd = True
            elif re.search(r'\bzip\b', cmdline_lower) or re.search(r'\b7z\s+a\b', cmdline_lower) or re.search(r'\b(?:gzip|xz)\b', cmdline_lower):
                is_arch_cmd = True
                
            if is_arch_cmd and bool(re.search(r'(?:/tmp/|/var/tmp/|/dev/shm/)[^\s"\']+', cmdline_lower)):
                has_finding = True
                s = max(s, 0.6)
                if c == 'low': c = 'med'
                rs.append("staging papkada arxiv yaratish")
                tech = _normalize_tech('T1560.001')
                if tech and not any(x['id'] == tech for x in th): th.append({'id': tech})

            if ppid > 0:
                pproc = next((p for p in current.get('processes', []) if p.get('pid') == ppid), None)
                if pproc:
                    pname = str(pproc.get('name', '')).lower()
                    cname = name_lower
                    if pname in {'apache2', 'httpd', 'nginx', 'java'} or pname.startswith('php-fpm') or pname.startswith('tomcat'):
                        if cname in {'sh', 'bash', 'dash', 'whoami', 'id', 'nc', 'curl', 'wget'}:
                            has_finding = True
                            s = max(s, 0.85)
                            c = 'high'
                            rs.append("shubhali ota-bola")
                            tech = _normalize_tech('T1505.003')
                            if tech and not any(x['id'] == tech for x in th): th.append({'id': tech})
                            
            if not in_baseline:
                conn_pid = next((conn for conn in current.get('connections', []) if (conn.get('pid') if isinstance(conn, dict) else None) == pid), None)
                if conn_pid:
                    raddr = conn_pid.get('raddr', '')
                    if is_public_ip(raddr):
                        first_token = cmdline.split()[0] if cmdline else ""
                        if path.startswith('/tmp/') or path.startswith('/dev/shm/') or path.startswith('/var/tmp/') or path.startswith('/run/user/') or \
                           first_token.startswith('/tmp/') or first_token.startswith('/dev/shm/') or first_token.startswith('/var/tmp/') or first_token.startswith('/run/user/') or \
                           path.startswith('/home/') or first_token.startswith('/home/'):
                            has_finding = True
                            s = max(s, 0.85)
                            c = 'high'
                            rs.append("tashqi IP ga ulangan shubhali joylashuv")
                            tech = _normalize_tech('T1071')
                            if tech and not any(x['id'] == tech for x in th): th.append({'id': tech})
                            
        if has_finding:
            if signed == 'valid' and s < 0.8:
                if not any(r in ['tizim jarayoni nomi noto\'g\'ri papkadan', 'svchost -k siz', 'svchost ota jarayoni services.exe emas', 'shubhali ota-bola', 'shubhali ota-bola: winword -> cmd', 'shubhali ota-bola: winword -> powershell'] for r in rs):
                    pass
                else:
                    add_finding('process', item_str, s, c, th, list(set(rs)), extra=extra)
                    if (c == 'high' or s >= 0.7) and pid:
                        proc_high_findings[pid] = {'score': s, 'conf': c, 'techs': list(th), 'reasons': list(rs)}
            elif signed == 'valid':
                if any(r.startswith('tizim jarayoni') or r.startswith('svchost') or r.startswith('shubhali ota-bola') for r in rs) or any('shubhali buyruq' in r for r in rs) or any(t['id'] in ['T1059.001', 'T1059.005', 'T1059.007', 'T1218.005', 'T1218.010', 'T1218.011', 'T1105', 'T1140', 'T1197', 'T1685', 'T1005', 'T1041', 'T1560.001'] for t in th):
                    add_finding('process', item_str, s, c, th, list(set(rs)), extra=extra)
                    if (c == 'high' or s >= 0.7) and pid:
                        proc_high_findings[pid] = {'score': s, 'conf': c, 'techs': list(th), 'reasons': list(rs)}
            else:
                add_finding('process', item_str, s, c, th, list(set(rs)), extra=extra)
                if (c == 'high' or s >= 0.7) and pid:
                    proc_high_findings[pid] = {'score': s, 'conf': c, 'techs': list(th), 'reasons': list(rs)}

    for conn in current.get('connections', []):
        if isinstance(conn, dict):
            raddr = str(conn.get('raddr', ''))
            rport = str(conn.get('rport', ''))
            proc = str(conn.get('process', ''))
            pid = conn.get('pid')
        else:
            raddr = str(conn)
            rport = ''
            proc = ''
            pid = None
            
        item_str = f"{raddr}:{rport} ({proc})" if proc else f"{raddr}:{rport}"
        
        is_beacon = log_artifacts and raddr in log_artifacts.get('beacon_ips', ())
        
        if pid is not None and pid in proc_high_findings:
            p_info = proc_high_findings[pid]
            s = max(0.7, p_info['score'])
            c = 'high'
            th = [dict(t) for t in p_info['techs']]
            v_tid = _normalize_tech('T1071.001')
            if v_tid and not any(x['id'] == v_tid for x in th):
                th.append({'id': v_tid})
            rs = ["shubhali jarayon ulanishi"]
            if raddr in fraud_ips:
                rs.append("IP hosts/proxy/DNS da ham bor (fraud zanjiri)")
            
            if is_beacon:
                c = 'high'
                s = max(s, 0.9)
                b_info = log_artifacts.get('beacon_info', {}).get(raddr, {})
                rs.append(f"C2 beacon nomzodi (loglardan: {b_info.get('key','')}, ~{b_info.get('interval_seconds',0):.0f}s, {b_info.get('count',0)} ulanish)")
            
            if log_artifacts and raddr in log_artifacts.get('attack_ips', ()):
                c = 'high'
                s = max(s, 0.85)
                rs.append("IP loglardagi hujum qadamida bor")
                if raddr in log_artifacts.get('checker_ips', ()):
                    log_artifacts['checker_ips'].remove(raddr)
                ev = log_artifacts.get('evidence_index', {}).get(raddr)
                if ev:
                    rs.append(f"({ev})")
                    
            add_finding('connections', item_str, s, c, th, rs)
        elif is_public_ip(raddr) or is_beacon:
            s, c, th, rs, has_strong = calc_score(item_str, proc, False)
            
            # Public IP is inherently suspicious if not filtered
            has_strong = True
            if s < 0.35: s = 0.35
            
            if quick_log_match(raddr, ['ips']) or quick_log_match(proc, ['filenames']):
                has_strong = True
                
            if has_strong:
                v_tid = _normalize_tech('T1071.001')
                if v_tid and not any(x['id'] == v_tid for x in th):
                    th.append({'id': v_tid})
                tech, hit_conf, _ = get_kb_hit(proc)
                if hit_conf or _suspicious_cmd(proc) is not None:
                    if log_artifacts and raddr in log_artifacts.get('checker_ips', []):
                        log_artifacts['checker_ips'].remove(raddr)
                if hit_conf:
                    c = 'high'
                    s = max(s, 0.8)
                else:
                    c = 'med' if s < 0.35 else c
                    s = max(s, 0.4)
                proc_l = re.sub(r'\.exe$', '', str(proc).strip().lower())
                if raddr in fraud_ips:
                    c, s = 'high', max(s, 0.85)
                    rs.append("IP hosts/proxy/DNS da ham bor (fraud zanjiri)")
                if proc_l in CONN_LOLBINS:
                    c, s = 'high', max(s, 0.75)
                    rs.append(f"{proc_l} tashqi IP ga ulangan")
                elif proc_l in CONN_SHELLS and c == 'low':
                    c, s = 'med', max(s, 0.5)
                    rs.append(f"{proc_l} tashqi IP ga ulangan")
                
                if is_beacon:
                    c = 'high'
                    s = max(s, 0.9)
                    b_info = log_artifacts.get('beacon_info', {}).get(raddr, {})
                    rs.append(f"C2 beacon nomzodi (loglardan: {b_info.get('key','')}, ~{b_info.get('interval_seconds',0):.0f}s, {b_info.get('count',0)} ulanish)")
                    
                if log_artifacts and raddr in log_artifacts.get('attack_ips', ()):
                    c = 'high'
                    s = max(s, 0.85)
                    rs.append("IP loglardagi hujum qadamida bor")
                    if raddr in log_artifacts.get('checker_ips', ()):
                        log_artifacts['checker_ips'].remove(raddr)
                    ev = log_artifacts.get('evidence_index', {}).get(raddr)
                    if ev:
                        rs.append(f"({ev})")
                        
                add_finding('connections', item_str, s, c, th, rs)


    # RANSOMWARE LOGIC HERE
    ransom_exts = {'lockbit', 'locked', 'encrypted', 'enc', 'crypt', 'crypted', 'cry', 'crypto', 'ryk', 'ryuk', 'conti', 'akira', 'royal', 'babyk', 'phobos', 'hive', 'blackbasta', 'lock', 'wncry', 'wnry', 'cerber', 'locky'}
    doc_exts = {'xlsx', 'xls', 'docx', 'doc', 'pdf', 'txt', 'csv', 'jpg', 'jpeg', 'png', 'sql', 'bak', 'mdb', 'accdb', 'pptx', 'ppt', 'vmdk', 'vhd', 'vhdx', 'zip', 'rar', '7z', 'dwg', 'psd'}
    skip_exts = {'backup', 'orig', 'part', 'partial', 'temp', 'crdownload', 'download', 'old',
                 'webp', 'json', 'html', 'xml', 'lnk', 'sha256', 'sha1', 'md5', 'sig', 'torrent', 'thumb', 'meta', 'info', 'tmp', 'copy'}
    
    ransom_groups = {}
    ransom_notes = []
    
    note_regex = re.compile(r'^(?:how[_ -]?to[_ -]?(?:decrypt|restore|recover|back)|readme[_ -]?(?:to[_ -]?|for[_ -]?)?(?:decrypt|restore|recover)|(?:decrypt|restore|recover)[_ -]?(?:my|your|all)[_ -]?files|.*ransom)[^\\/]*\.(?:txt|hta|html?|rtf)$')
    
    for rm in current.get('recent_modified', []):
        p = rm.get('path') if isinstance(rm, dict) else rm
        mtime = rm.get('mtime') if isinstance(rm, dict) else None
        if not p: continue
        p_str = str(p)
        base = p_str.split('\\')[-1].split('/')[-1]
        base_lower = base.lower()
        
        # Ransom note check
        if note_regex.match(base_lower):
            ransom_notes.append((p_str, mtime))
            continue
            
        # Extension check
        parts = base.split('.')
        if len(parts) >= 2:
            last_ext = parts[-1]
            last_ext_lower = last_ext.lower()
            
            is_encrypted = False
            if last_ext_lower in ransom_exts:
                is_encrypted = True
            elif len(parts) >= 3:
                prev_ext_lower = parts[-2].lower()
                if prev_ext_lower in doc_exts and last_ext_lower not in skip_exts and not re.match(r'^(?:part|vol|r|z)\d+$', last_ext_lower):
                    if 4 <= len(last_ext_lower) <= 12 and last_ext_lower.isalnum():
                        is_encrypted = True
            
            if is_encrypted:
                if last_ext not in ransom_groups:
                    ransom_groups[last_ext] = {'count': 0, 'first_path': p_str, 'earliest_mtime': mtime}
                g = ransom_groups[last_ext]
                g['count'] += 1
                if mtime and g['earliest_mtime'] and mtime < g['earliest_mtime']:
                    g['earliest_mtime'] = mtime
                elif mtime and not g['earliest_mtime']:
                    g['earliest_mtime'] = mtime
                    
    for ext, g in ransom_groups.items():
        rs = [f"shifrlangan kengaytma .{ext}", f"{g['count']} ta fayl", "recent_modified"]
        if g['earliest_mtime']:
            rs.append(f"birinchi: {g['earliest_mtime']}")
        add_finding('ransomware', f"*.{ext} ({g['count']} fayl, masalan {g['first_path']})", 0.95, 'high', [{'id': 'T1486'}], rs)
        
    for p, mtime in ransom_notes:
        rs = ["ransom note nomi"]
        if mtime: rs.append(str(mtime))
        add_finding('ransomware', p, 0.9, 'high', [{'id': 'T1486'}], rs)

    handled_chunk_paths = set()
    if os_hint == 'linux':
        chunk_groups = {}
        for f in current.get('suspicious_files', []):
            if not isinstance(f, dict):
                continue
            fpath = str(f.get('path', ''))
            fsize = f.get('size', 0)
            if not fpath or not is_staging_path(fpath) or fsize < 1_000_000:
                continue
            pdir = os.path.dirname(fpath)
            fname = os.path.basename(fpath)
            m = re.match(r'^(.+?)[._-]?(\d+|[a-z]{2})$', fname, re.IGNORECASE)
            if m:
                stem = m.group(1)
                key = (pdir, stem.lower())
                if key not in chunk_groups:
                    chunk_groups[key] = {'pdir': pdir, 'stem': stem, 'files': []}
                chunk_groups[key]['files'].append(f)
                
        for key, ginfo in chunk_groups.items():
            gfiles = ginfo['files']
            if len(gfiles) >= 3:
                for gf in gfiles:
                    handled_chunk_paths.add(str(gf.get('path', '')).lower())
                tot_size = sum(gf.get('size', 0) for gf in gfiles)
                tot_mb = round(tot_size / (1024 * 1024))
                pdir = ginfo['pdir'].rstrip('/')
                stem = ginfo['stem']
                n_chunks = len(gfiles)
                item_str = f"{pdir}/{stem}* ({n_chunks} ta bo'lak, jami {tot_mb} MB)"
                is_group_in_base = all(str(gf.get('path', '')).lower() in base_files for gf in gfiles) if baseline is not None else False
                c = 'high' if (baseline is not None and not is_group_in_base) else 'med'
                s = 0.8
                th = []
                for tid in ['T1074.001', 'T1030', 'T1560.001']:
                    v_tid = _normalize_tech(tid)
                    if v_tid and not any(x['id'] == v_tid for x in th):
                        th.append({'id': v_tid})
                rs = ["bo'laklangan staging guruhi"]
                add_finding('file', item_str, s, c, th, rs)

    for f in current.get('suspicious_files', []):
        path = str(f.get('path', ''))
        ext = str(f.get('ext', '')).lower()
        size = f.get('size', 0)
        sha256 = str(f.get('sha256', ''))
        signed = str(f.get('signed', 'n/a'))
        exe_magic = f.get('exe_magic', False)
        hidden = f.get('hidden', False)
        head = str(f.get('head', ''))
        webshell_hint = f.get('webshell_hint', False)
        
        path_lower = path.lower()
        if path_lower in handled_chunk_paths:
            continue

        norm_path = _norm_path_text(path_lower)
        
        is_windows = os_hint == 'windows'
        is_linux = os_hint == 'linux'
        
        item_str = path
        if not item_str: continue
        extra = {'path': path, 'sha256': sha256, 'os': os_hint}
        
        has_finding = False
        s = 0.0
        c = 'low'
        th = []
        rs = []
        
        in_baseline = False
        if baseline is not None:
            if path_lower in base_files:
                in_baseline = True
        
        is_f1 = False
        if exe_magic:
            if is_windows:
                if ext not in {'.exe', '.dll', '.sys', '.scr', '.ocx', '.cpl', '.com', '.mui', '.mun', '.node', '.pyd', '.ax', '.drv', '.efi', '.winmd'}:
                    is_f1 = True
            else:
                if ext != '.so' and ext != '':
                    is_f1 = True
        if is_f1:
            has_finding = True
            s = max(s, 0.85)
            c = 'high'
            rs.append("kengaytmasi yashirilgan bajariladigan")
            tech = 'T1036.008'
            v = kb.validate([tech]) if kb else None
            if v and v[0]['status'] in ('revoked', 'deprecated') and v[0]['replacement']:
                tech = v[0]['replacement']
            if not v or v[0]['status'] == 'invalid':
                tech = 'T1036'
            if not any(x['id'] == tech for x in th): th.append({'id': tech})

        if re.search(r'\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|zip)\.(exe|scr|bat|cmd|com|js|jse|vbs|vbe|ps1|hta|lnk)$', path_lower):
            has_finding = True
            s = max(s, 0.85)
            c = 'high'
            rs.append("ikki kengaytma")
            tech = _normalize_tech('T1036.007')
            if tech and not any(x['id'] == tech for x in th): th.append({'id': tech})

        if head and not in_baseline:
            is_f3 = False
            susp = _suspicious_cmd(head)
            f3_tech = None
            if susp:
                is_f3 = True
                f3_tech = susp[0]
            elif is_linux:
                cmdline_lower = head.lower()
                if 'bash -i' in cmdline_lower and '/dev/tcp/' in cmdline_lower:
                    is_f3 = True
                elif any(x in cmdline_lower for x in ['nc ', 'ncat ', 'socat ']) and ('-e' in cmdline_lower or 'exec:' in cmdline_lower):
                    is_f3 = True
                elif 'python' in cmdline_lower and '-c' in cmdline_lower and 'socket' in cmdline_lower and ('connect' in cmdline_lower or 'pty' in cmdline_lower):
                    is_f3 = True
                elif 'perl -e' in cmdline_lower and 'socket' in cmdline_lower:
                    is_f3 = True
                elif ('curl' in cmdline_lower or 'wget' in cmdline_lower) and ('| sh' in cmdline_lower or '| bash' in cmdline_lower):
                    is_f3 = True
                elif 'base64 -d' in cmdline_lower and ('| sh' in cmdline_lower or '| bash' in cmdline_lower):
                    is_f3 = True
                if is_f3 and not f3_tech:
                    f3_tech = 'T1059.004'
            
            if is_f3:
                has_finding = True
                s = max(s, 0.8)
                c = 'high'
                rs.append("skript ichida shubhali buyruq")
                if f3_tech:
                    v_f3 = _normalize_tech(f3_tech)
                    if v_f3 and not any(x['id'] == v_f3 for x in th): th.append({'id': v_f3})

        if webshell_hint:
            has_finding = True
            s = max(s, 0.85)
            c = 'high'
            rs.append("webshell belgisi")
            tech = _normalize_tech('T1505.003')
            if tech and not any(x['id'] == tech for x in th): th.append({'id': tech})
        elif not in_baseline and baseline is None and ext in {'.aspx', '.asp', '.ashx', '.php', '.phtml', '.jsp', '.jspx'}:
            has_finding = True
            s = max(s, 0.5)
            c = 'med' if c == 'low' else c
            rs.append("web papkada yangi skript fayl")
            
        if is_windows and not in_baseline:
            is_exec = ext in {'.exe', '.dll', '.scr', '.com', '.pif', '.sys', '.ocx', '.cpl'}
            is_script = ext in {'.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta'}
            in_high_loc = any(norm_path.startswith(x) for x in ['c:\\windows\\temp\\', 'c:\\users\\public\\', 'c:\\programdata\\', 'c:\\$recycle.bin\\', 'c:\\perflogs\\', 'c:\\users\\%user%\\appdata\\local\\temp\\'])
            in_med_loc = any(norm_path.startswith(x) for x in ['c:\\users\\%user%\\downloads\\', 'c:\\users\\%user%\\desktop\\'])
            
            if is_exec:
                if in_high_loc and signed == 'unknown':
                    # imzo tekshirib bo'lmadi (limit/ruxsat) — imzosiz deb bo'lmaydi, faqat o'rta
                    has_finding = True
                    s = max(s, 0.5)
                    c = 'med' if c == 'low' else c
                    rs.append("shubhali joyda exec, imzo tekshirilmadi")
                elif in_high_loc and signed != 'valid':
                    has_finding = True
                    s = max(s, 0.75)
                    c = 'high' if s >= 0.6 else c
                    rs.append("shubhali joyda imzosiz exec")
                    if ext == '.dll':
                        tech = _normalize_tech('T1574.001')
                        if tech and not any(x['id'] == tech for x in th): th.append({'id': tech})
                elif in_med_loc and signed in ('unsigned', 'invalid'):
                    has_finding = True
                    s = max(s, 0.5)
                    c = 'med' if c == 'low' else c
                    rs.append("shubhali joyda imzosiz exec")
            elif is_script and in_high_loc:
                has_finding = True
                s = max(s, 0.55)
                c = 'med' if c == 'low' else c
                rs.append("shubhali joyda skript")
                
        if is_windows and not in_baseline:
            if norm_path.startswith('c:\\windows\\system32\\') or norm_path.startswith('c:\\windows\\syswow64\\'):
                if signed != 'valid':
                    has_finding = True
                    s = max(s, 0.8)
                    c = 'high'
                    rs.append("System32/SysWOW64 da imzosiz fayl")
                    tech = _normalize_tech('T1574.001')
                    if tech and not any(x['id'] == tech for x in th): th.append({'id': tech})
                    
        if is_linux:
            if exe_magic and (path_lower.startswith('/tmp/') or path_lower.startswith('/dev/shm/') or path_lower.startswith('/var/tmp/')):
                has_finding = True
                s = max(s, 0.8)
                c = 'high'
                rs.append("shubhali joyda exec fayl")
            elif hidden and (exe_magic or ext == '') and (path_lower.startswith('/home/') or path_lower.startswith('/root/') or path_lower.startswith('/tmp/')):
                has_finding = True
                s = max(s, 0.75)
                c = 'high'
                rs.append("yashirin exec fayl")
            elif exe_magic and (path_lower.startswith('/usr/local/bin/') or path_lower.startswith('/opt/')):
                if baseline is None:
                    has_finding = True
                    s = max(s, 0.45)
                    c = 'med' if c == 'low' else c
                    rs.append("standart bo'lmagan joyda ELF")
                elif not in_baseline:
                    has_finding = True
                    s = max(s, 0.6)
                    c = 'high' if s >= 0.6 else c
                    rs.append("standart bo'lmagan joyda yangi ELF")

            # 1a. Staging arxiv
            is_archive_head = (head.startswith('\x1f\x8b') or head.startswith('PK') or 
                               head.startswith('BZh') or head.startswith('7z\xbc\xaf') or 
                               head.startswith('\xfd7zXZ'))
            is_archive_ext = ext.lstrip('.') in {'gz', 'tgz', 'zip', '7z', 'rar', 'bz2', 'xz', 'tar'}
            if is_staging_path(path) and size >= 1_000_000 and (is_archive_head or is_archive_ext):
                has_finding = True
                s = max(s, 0.6)
                if c == 'low': c = 'med'
                rs.append("staging papkada katta arxiv")
                for tid in ['T1560.001', 'T1074.001']:
                    v_tid = _normalize_tech(tid)
                    if v_tid and not any(x['id'] == v_tid for x in th):
                        th.append({'id': v_tid})

            # 1c. Private key fayli
            sys_key_dirs = ('/etc/ssl/private/', '/etc/letsencrypt/', '/etc/pki/', '/etc/ssh/')
            if '-----BEGIN' in head and 'PRIVATE KEY-----' in head and '/.ssh/' not in path_lower and not path_lower.startswith(sys_key_dirs):
                has_finding = True
                s = max(s, 0.75)
                if is_staging_path(path) or (baseline is not None and not in_baseline):
                    c = 'high'
                elif c == 'low':
                    c = 'med'
                rs.append("private key .ssh dan tashqarida")
                v_tid = _normalize_tech('T1552.004')
                if v_tid and not any(x['id'] == v_tid for x in th):
                    th.append({'id': v_tid})

            # 1d. Ma'lumotlar bazasi dampi
            is_db_dump = (head.startswith('PGDMP') or 
                          '-- PostgreSQL database dump' in head or 
                          '-- MySQL dump' in head or 
                          'SQLite format 3' in head or 
                          (ext.lstrip('.') in {'dump', 'sql'} and size >= 100_000))
            if is_staging_path(path) and is_db_dump:
                has_finding = True
                s = max(s, 0.7)
                if baseline is not None and not in_baseline:
                    c = 'high'
                elif c == 'low':
                    c = 'med'
                rs.append("staging papkada DB dampi")
                for tid in ['T1005', 'T1074.001']:
                    v_tid = _normalize_tech(tid)
                    if v_tid and not any(x['id'] == v_tid for x in th):
                        th.append({'id': v_tid})

        if is_windows and norm_path.startswith('c:\\users\\%user%\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\') and ext == '.lnk':
            has_finding = False

        if signed == 'valid':
            if not any(r in ['kengaytmasi yashirilgan bajariladigan', 'ikki kengaytma', 'skript ichida shubhali buyruq', 'webshell belgisi'] for r in rs):
                has_finding = False

        if has_finding:
            add_finding('file', item_str, s, c, th, list(set(rs)), extra=extra)

    # Audit Packages & CVEs, Containers, and Database Exposure
    try:
        from bluekit.kb.cve import audit_packages, audit_containers, audit_database_exposure
        
        base_ports = set()
        base_containers = set()
        base_packages = set()
        if baseline:
            for bp in baseline.get('listening_ports', []):
                base_ports.add((bp.get('ip'), bp.get('port'), bp.get('proto')))
            for bc in baseline.get('containers', []):
                base_containers.add(bc.get('id') or bc.get('name'))
            for bpkg in baseline.get('packages', []):
                base_packages.add((bpkg.get('name'), bpkg.get('version')))
            for bapp in baseline.get('installed_apps', []):
                base_packages.add((bapp.get('name'), bapp.get('version')))

        if not baseline:
            cve_findings = audit_packages(current.get('packages', []), current.get('installed_apps', []))
            for cf in cve_findings:
                th_cve = [{'id': _normalize_tech(t)} for t in cf.get('techniques', []) if _normalize_tech(t)]
                add_finding('vulnerabilities', cf['item'], cf['score'], cf['confidence'], th_cve, cf['reasons'], extra={
                    'cve': cf.get('cve'),
                    'vuln_name': cf.get('vuln_name'),
                    'severity': cf.get('severity'),
                    'suggested_fix_command': cf.get('suggested_fix_command')
                })
            
        cont_findings = audit_containers(current.get('containers', []))
        for ctf in cont_findings:
            if baseline and (ctf.get('container_id') in base_containers or ctf['item'] in base_containers):
                continue
            th_cont = [{'id': _normalize_tech(t)} for t in ctf.get('techniques', []) if _normalize_tech(t)]
            add_finding('containers', ctf['item'], ctf['score'], ctf['confidence'], th_cont, ctf['reasons'], extra={
                'container_id': ctf.get('container_id'),
                'suggested_fix_command': ctf.get('suggested_fix_command')
            })
            
        if not baseline:
            db_findings = audit_database_exposure(current.get('listening_ports', []))
            for dbf in db_findings:
                th_db = [{'id': _normalize_tech(t)} for t in dbf.get('techniques', []) if _normalize_tech(t)]
                add_finding('database_exposure', dbf['item'], dbf['score'], dbf['confidence'], th_db, dbf['reasons'], extra={
                    'suggested_fix_command': dbf.get('suggested_fix_command')
                })
    except ImportError:
        pass

    unmatched_log_artifacts = []

    
    if log_artifacts:
        matched_keys = set()
        for f in findings:
            item_lower = str(f['item']).lower()
            cat = f['category']
            
            match = None
            evidence = ""
            
            def is_valid_token(tok):
                if len(tok) < 4: return False
                if tok in ('health', 'update', 'system'): return False
                return True
                
            def check_match(val, target_sets):
                val_lower = str(val).lower()
                for tset_name in target_sets:
                    for x in log_artifacts.get(tset_name, []):
                        x_lower = str(x).lower()
                        if not x_lower or not is_valid_token(x_lower): continue
                        if x_lower == val_lower:
                            return x, log_artifacts['evidence_index'].get(str(x).lower(), "")
                return None, ""
                
            def check_exact_or_base(val, target_sets):
                val_lower = str(val).lower()
                val_base = os.path.basename(val_lower) if '\\' in val_lower or '/' in val_lower else val_lower
                for tset_name in target_sets:
                    for x in log_artifacts.get(tset_name, []):
                        x_lower = str(x).lower()
                        if not x_lower or not is_valid_token(x_lower): continue
                        x_base = os.path.basename(x_lower) if '\\' in x_lower or '/' in x_lower else x_lower
                        if val_lower == x_lower or val_base == x_base:
                            return x, log_artifacts['evidence_index'].get(x_lower, "")
                return None, ""

            if cat == 'tasks':
                match, evidence = check_match(f['item'], ['task_names'])
                if not match:
                    action = next((t.get('action','') for t in current.get('tasks',[]) if t.get('name') == f['item']), '')
                    match, evidence = check_exact_or_base(action, ['files', 'filenames'])
            elif cat == 'users':
                match, evidence = check_match(f['item'], ['users'])
            elif cat == 'autoruns':
                match, evidence = check_match(f['item'], ['run_values'])
                if not match:
                    val = next((a.get('value','') for a in current.get('autoruns',[]) if a.get('name') == f['item']), '')
                    match, evidence = check_exact_or_base(val, ['files', 'filenames'])
                    if not match and val.split():
                        match, evidence = check_exact_or_base(val.split()[0].strip('"\''), ['files', 'filenames'])
            elif cat == 'services':
                match, evidence = check_match(f['item'], ['services'])
                if not match:
                    bp = next((s.get('binary_path','') for s in current.get('services',[]) if s.get('name') == f['item']), '')
                    match, evidence = check_exact_or_base(bp, ['files', 'filenames'])
            elif cat == 'remote_access_tools':
                match, evidence = check_match(f['item'], ['rat_names'])
            elif cat == 'hosts_file':
                match, evidence = check_match(f['item'], ['hosts_entries'])
            elif cat == 'cron':
                raw = f.get('raw', '')
                n = ' '.join(raw.split()).lower()
                for x in log_artifacts.get('cron_lines', []):
                    if len(x) >= 8 and (x == n or x in n):
                        match = x
                        evidence = log_artifacts['evidence_index'].get(x, "")
                        break
            elif cat == 'suid_files':
                p = f.get('path', '')
                for x in log_artifacts.get('suid_paths', []):
                    if x.lower() == p.lower() or (not x.startswith('/') and os.path.basename(x).lower() == os.path.basename(p).lower()):
                        match = x
                        evidence = log_artifacts['evidence_index'].get(x.lower(), "")
                        break
            elif cat == 'ssh_authorized_keys':
                raw = f.get('raw', '')
                for x in log_artifacts.get('ssh_keys', []):
                    if len(x) >= 8 and x in raw:
                        match = x
                        evidence = log_artifacts['evidence_index'].get(x.lower(), "")
                        break
            elif cat == 'connections' or cat == 'listening_ports':
                raddr = item_lower.split(':')[0] if ':' in item_lower else ""
                raddr = raddr.strip()
                if raddr and raddr in log_artifacts.get('ips', []) and raddr not in log_artifacts.get('checker_ips', []):
                    match = raddr
                    evidence = log_artifacts['evidence_index'].get(raddr, "")
                if not match:
                    proc = ""
                    if '(' in item_lower and ')' in item_lower:
                        proc = item_lower.split('(')[1].split(')')[0]
                    if proc:
                        match, evidence = check_exact_or_base(proc, ['filenames'])
                        
            if match:
                f['log_confirmed'] = True
                f['score'] = min(1.0, f['score'] + 0.4)
                f['confidence'] = 'high'
                f['reasons'].append(f"log korrelyatsiyasi: {match} ({evidence})")
                matched_keys.add(str(match).lower())
                
            if match or f['score'] >= 0.35:
                for tech in f.get('techniques', []):
                    tid = tech.get('id')
                    if tid and tid in log_artifacts.get('techniques', []):
                        f['reasons'].append(f"log: shu texnika kuzatilgan")

            seen_r = set()
            new_r = []
            for r in f['reasons']:
                if r not in seen_r:
                    seen_r.add(r)
                    new_r.append(r)
            f['reasons'] = new_r

        for f in findings:
            f['score'] = round(f['score'], 3)
            
        findings.sort(key=lambda x: (not x.get('log_confirmed', False), -x['score']))
        
        unmatched_dedup = {}
        unmatched_other = []
        
        snap_host = (current.get('meta') or {}).get('hostname') or ''
        snap_host_lower = snap_host.split('.')[0].lower() if snap_host else ''
        
        has_artifact_hosts = log_artifacts and 'artifact_hosts' in log_artifacts and log_artifacts['artifact_hosts']
        legacy_mode = not snap_host_lower or not has_artifact_hosts
        
        def add_unmatched(typ, val):
            val_str = str(val).strip()
            val_lower = val_str.lower()
            
            if not val_str: return
            if any(val_lower == mk or (len(val_lower) >= 4 and len(mk) >= 4 and (val_lower in mk or mk in val_lower)) for mk in matched_keys): return
            if re.match(r'^t\d{4}(?:\.\d{3})?$', val_lower): return
            if val_str.startswith('-') or val_str.startswith('/') or len(val_str) < 4: return
            if re.match(r'^[a-z]+$', val_lower) and typ not in ('user', 'task_name', 'service', 'rat_name'): return
            
            if typ == 'ip':
                if not is_public_ip(val_str) or val_str in log_artifacts.get('checker_ips', []):
                    return
            elif typ == 'file':
                if not (re.match(r'^([a-z]:\\|/).*\.\w+$', val_lower) or re.match(r'^[^/\\]+\.\w+$', val_lower)):
                    return
                    
            if val_lower not in unmatched_dedup:
                item = {
                    'artifact': val_str,
                    'type': typ,
                    'evidence': log_artifacts['evidence_index'].get(val_lower, "")
                }
                
                if legacy_mode:
                    unmatched_dedup[val_lower] = item
                else:
                    suspicious = val_lower in log_artifacts.get('suspicious', set())
                    hosts = log_artifacts.get('artifact_hosts', {}).get(val_lower, set())
                    on_host = any(h.split('.')[0].lower() == snap_host_lower for h in hosts)
                    sys_binary_names = {'svchost.exe', 'explorer.exe', 'services.exe', 'lsass.exe', 'winlogon.exe', 'csrss.exe', 'smss.exe', 'wininit.exe', 'spoolsv.exe', 'taskhostw.exe', 'dllhost.exe', 'conhost.exe', 'runtimebroker.exe', 'searchindexer.exe', 'msedge.exe', 'chrome.exe', 'teams.exe', 'onedrive.exe', 'outlook.exe', 'excel.exe', 'winword.exe'}
                    is_sys_binary = typ == 'file' and ('\\windows\\' in val_lower or val_lower.split('\\')[-1].split('/')[-1] in sys_binary_names)
                    
                    if suspicious or (on_host and typ != 'ip' and not is_sys_binary):
                        item['is_suspicious'] = suspicious
                        unmatched_dedup[val_lower] = item
                    else:
                        item['hosts'] = sorted(list(hosts))
                        unmatched_other.append(item)
                
        for ip in log_artifacts.get('ips', []): add_unmatched('ip', ip)
        for fpath in log_artifacts.get('files', []): add_unmatched('file', fpath)
        for fname in log_artifacts.get('filenames', []): add_unmatched('file', fname)
        for tname in log_artifacts.get('task_names', []): add_unmatched('task_name', tname)
        for sname in log_artifacts.get('services', []): add_unmatched('service', sname)
        for uname in log_artifacts.get('users', []): add_unmatched('user', uname)
        for he in log_artifacts.get('hosts_entries', []): add_unmatched('hosts_entry', he)
        for rat in log_artifacts.get('rat_names', []): add_unmatched('rat_name', rat)
        
        for k, v in unmatched_dedup.items():
            unmatched_log_artifacts.append(v)
            
        if not legacy_mode:
            unmatched_log_artifacts.sort(key=lambda x: not x.get('is_suspicious', False))

            
    else:
        for f in findings:
            f['score'] = round(f['score'], 3)
        findings.sort(key=lambda x: -x['score'])
            

    extra = {'unmatched_log_artifacts': unmatched_log_artifacts}
    if 'unmatched_other' in locals():
        extra['unmatched_other'] = unmatched_other
    else:
        extra['unmatched_other'] = []
    if 'defender_warnings' in locals() and defender_warnings:
        extra['warnings'] = defender_warnings
        
    if kg_used:
        extra['knowngood'] = {'used': True, 'version': kg_data.get('version', 1), 'os': os_hint or 'windows', 'suppressed': kg_suppressed[0]}
    else:
        extra['knowngood'] = "topilmadi"
    if log_artifacts:
        extra['checker_candidates'] = list(log_artifacts.get('checker_ips', []))
        beacon_info = log_artifacts.get('beacon_info', {})
        b_cands = []
        for ip, b in beacon_info.items():
            b['ip'] = ip
            b_cands.append(b)
        b_cands.sort(key=lambda x: -x.get('count', 0))
        extra['beacon_candidates'] = b_cands
    else:
        extra['checker_candidates'] = []
        extra['beacon_candidates'] = []
            
    return findings, extra
