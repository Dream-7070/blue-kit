import re
from collections import defaultdict
from bluekit.ir.models import AttackStage
from bluekit.logs.parse import parse_ts

def get_nested(d, path, default=None):
    if isinstance(d, dict) and path in d:
        return d[path]
    parts = path.split('.')
    cur = d
    for p in parts:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur

_EXE_EXTS = r'(?:exe|scr|msi|js|jse|vbs|hta|bat|cmd|ps1|lnk|com)'

def _exe_path(cmd, pname):
    """Buyruq qatoridan bajariladigan fayl yo'li: tirnoqli ('"C:\\Users\\a b\\x.exe" -k') va bo'shliqli yo'llar bilan ishlaydi."""
    cmd = (cmd or '').strip()
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        return cmd[1:end] if end > 0 else cmd[1:]
    m = re.match(r'^(.*?\.' + _EXE_EXTS + r')(?:\s|$)', cmd, re.I)
    if m:
        return m.group(1)
    return cmd.split()[0] if cmd else str(pname)

def process_tree_stages(raw_events, extract_canonical):
    stages = []
    
    events_by_host = defaultdict(list)
    parsed = []
    
    for i, ev in enumerate(raw_events):
        c = extract_canonical(ev)
        pname = c['proc_name']
        if not pname:
            continue
            
        parent_val = get_nested(ev, 'process.parent.name') or get_nested(ev, 'process.parent.executable') or \
                     ev.get('ParentImage') or ev.get('ParentProcessName') or ev.get('parent_process') or \
                     get_nested(ev, 'winlog.event_data.ParentImage')
        if not parent_val:
            continue
            
        parent = str(parent_val).replace('\\', '/').split('/')[-1].lower()
        if parent.endswith('.exe'):
            parent = parent[:-4]
            
        ts_str = c['timestamp']
        ts = parse_ts(ts_str) if ts_str else None
        
        c_parsed = c.copy()
        c_parsed['parent'] = parent
        c_parsed['idx'] = i
        c_parsed['ts'] = ts
        c_parsed['raw_ts'] = ts_str
        c_parsed['raw_evt'] = ev
        parsed.append(c_parsed)
        if ts and c['host']:
            events_by_host[c['host']].append(c_parsed)
            
    for p in parsed:
        host = p['host']
        cmd = p['cmd']
        parent = p['parent']
        child = str(p['proc_name']).lower()
        child_path = _exe_path(cmd, p['proc_name'])
        
        is_browser = re.match(r'^(chrome|msedge|firefox|iexplore|brave|opera|vivaldi)$', parent)
        if is_browser:
            if re.search(r'(\\|/)(downloads|appdata\\local\\temp|appdata\\roaming|tmp)(\\|/)', child_path, re.I):
                if re.search(r'\.(exe|scr|msi|js|jse|vbs|hta|bat|cmd|ps1|lnk|com)$', child_path, re.I):
                    is_updater = re.search(r'(chrome|msedge|firefox|microsoftedgeupdate|googleupdate|brave|opera)', child, re.I) and not re.search(r'(setup|installer)', child, re.I)
                    if not is_updater:
                        conf = "HIGH"
                        if 'setup' in child.lower() or 'installer' in child.lower():
                            conf = "MEDIUM"
                            
                        st_id = f"T1204.002_{host}_{child_path}"
                        if any(s[0].stage_id == st_id for s in stages):
                            continue
                            
                        st = AttackStage(
                            stage_id=st_id,
                            timestamp=p['raw_ts'],
                            host=host,
                            phase="Execution",
                            technique_id="T1204.002",
                            technique_name="User Execution: Malicious File",
                            confidence=conf,
                            status="CONFIRMED",
                            evidence=f"Brauzer {parent} dan fayl ishga tushdi: {child_path}",
                            iocs={'process': child_path, 'parent': parent},
                            source_dataset=p['dataset']
                        )
                        stages.append((st, ''))
                        
                        if host in events_by_host and p['ts']:
                            for prev in events_by_host[host]:
                                if prev['ts'] and 0 <= (p['ts'] - prev['ts']).total_seconds() <= 600:
                                    if prev['proc_name'] and parent in prev['proc_name'].lower():
                                        if re.search(r'https?://|hxxps?://', prev['cmd'], re.I):
                                            url = re.search(r'(https?://\S+|hxxps?://\S+)', prev['cmd'], re.I).group(1)
                                            st1189 = AttackStage(
                                                stage_id="TEMP",
                                                timestamp=prev['raw_ts'],
                                                host=host,
                                                phase="Initial Access",
                                                technique_id="T1189",
                                                technique_name="Drive-by Compromise",
                                                confidence="MEDIUM",
                                                status="CONFIRMED",
                                                evidence=f"URL: {url} va bola fayl: {child_path}",
                                                iocs={'url': url, 'process': child_path},
                                                source_dataset=prev['dataset']
                                            )
                                            stages.append((st1189, ''))
                                            break
                                            
        is_office = re.match(r'^(winword|excel|powerpnt|outlook|msaccess|mspub|onenote|visio)$', parent)
        if is_office:
            is_script = re.search(r'(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec|curl)\.exe$', child, re.I) or \
                        re.match(r'^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec|curl)$', child.lower().replace('.exe', ''))
            
            if is_script:
                st_id1 = f"T1566.001_{host}_{parent}"
                st_id2 = f"T1204.002_off_{host}_{parent}"
                
                if not any(s[0].stage_id == st_id1 for s in stages):
                    st1 = AttackStage(
                        stage_id=st_id1,
                        timestamp=p['raw_ts'],
                        host=host,
                        phase="Initial Access",
                        technique_id="T1566.001",
                        technique_name="Phishing: Spearphishing Attachment",
                        confidence="MEDIUM",
                        status="CONFIRMED",
                        evidence=f"Office {parent} -> {child}",
                        iocs={'parent': parent, 'process': child},
                        source_dataset=p['dataset']
                    )
                    stages.append((st1, ''))
                    
                    st2 = AttackStage(
                        stage_id=st_id2,
                        timestamp=p['raw_ts'],
                        host=host,
                        phase="Execution",
                        technique_id="T1204.002",
                        technique_name="User Execution: Malicious File",
                        confidence="HIGH",
                        status="CONFIRMED",
                        evidence=f"Office {parent} -> {child}",
                        iocs={'parent': parent, 'process': child},
                        source_dataset=p['dataset']
                    )
                    stages.append((st2, ''))
                    
        # Web account interactive command
        user_raw = str(p.get('user') or '').lower()
        if '\\' in user_raw:
            user_clean = user_raw.split('\\', 1)[-1]
        else:
            user_clean = user_raw
            
        acct_match = False
        if re.match(r'^(iis_iusrs|iusr|apache|www-data|nginx|httpd|tomcat\d*|network service|w3svc)$', user_clean) or \
           re.match(r'^iis apppool\\.*$', user_raw) or re.match(r'^iis apppool\\.*$', user_clean):
            acct_match = True
            
        if acct_match:
            cond_a = bool(re.match(r'^(w3wp|httpd|apache2|nginx|php-fpm|php-cgi|java|tomcat\d*)$', parent, re.I) and \
                          re.match(r'^(cmd|powershell|pwsh|sh|bash|dash|zsh)(?:\.exe)?$', child, re.I))
            cond_b = bool(re.match(r'^(whoami|ipconfig|ifconfig|arp|nslookup|netstat|systeminfo|tasklist|hostname|id|uname|net|net1|ip|route|quser|query)(?:\.exe)?$', child, re.I) and \
                          re.match(r'^(cmd|powershell|pwsh|sh|bash|dash)(?:\.exe)?$', parent, re.I))
                          
            if cond_a or cond_b:
                t1505_id = f"T1505.003_{host}_{user_raw}"
                if not any(s[0].stage_id == t1505_id for s in stages):
                    st1505 = AttackStage(
                        stage_id=t1505_id,
                        timestamp=p['raw_ts'],
                        host=host,
                        phase="Persistence",
                        technique_id="T1505.003",
                        technique_name="Web Shell",
                        confidence="MEDIUM",
                        status="CONFIRMED",
                        evidence=f"veb xizmat hisobi {user_raw} dan interaktiv buyruq: {parent} -> {child}",
                        iocs={'user': user_raw, 'parent': parent, 'process': child},
                        source_dataset=p['dataset']
                    )
                    stages.append((st1505, ''))
                    
                sh_name = child if cond_a else parent
                sh_name = sh_name.lower().replace('.exe', '')
                t_shell = None
                if sh_name == 'cmd':
                    t_shell = "T1059.003"
                elif sh_name in ['powershell', 'pwsh']:
                    t_shell = "T1059.001"
                elif sh_name in ['sh', 'bash', 'dash', 'zsh']:
                    t_shell = "T1059.004"
                    
                if t_shell:
                    tshell_id = f"{t_shell}_{host}_{user_raw}_{sh_name}"
                    if not any(s[0].stage_id == tshell_id for s in stages):
                        st_sh = AttackStage(
                            stage_id=tshell_id,
                            timestamp=p['raw_ts'],
                            host=host,
                            phase="Execution",
                            technique_id=t_shell,
                            technique_name="Command and Scripting Interpreter",
                            confidence="HIGH",
                            status="CONFIRMED",
                            evidence=f"veb xizmat hisobi {user_raw} dan interaktiv buyruq: {parent} -> {child}",
                            iocs={'user': user_raw, 'parent': parent, 'process': child},
                            source_dataset=p['dataset']
                        )
                        stages.append((st_sh, ''))

    for s, _ in stages:
        s.stage_id = "TEMP"
    return stages, set()
