import json
import re
import os
import ipaddress

BEACON_MIN_COUNT = 10  # hunt beacons dagi min_sessions bilan bir xil

def load_log_artifacts(logs_path_or_dict):
    if isinstance(logs_path_or_dict, str):
        try:
            with open(logs_path_or_dict, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception:
            data = {}
    else:
        data = logs_path_or_dict or {}

    artifacts = {
        'ips': set(),
        'checker_ips': set(),
        'attack_ips': set(),
        'beacon_ips': set(),
        'beacon_info': {},
        'artifact_hosts': {},
        'suspicious': set(),
        'files': set(),
        'filenames': set(),
        'task_names': set(),
        'run_values': set(),
        'users': set(),
        'hosts_entries': set(),
        'services': set(),
        'rat_names': set(),
        'techniques': set(),
        'hosts_seen': set(),
        'users_seen': set(),
        'cron_lines': set(),
        'suid_paths': set(),
        'ssh_keys': set(),
        'evidence_index': {},
        'first_ts': None,
        'last_ts': None
    }

    def add_evidence(key, evidence):
        if not key: return key
        key_str = str(key).lower().strip()
        if key_str not in artifacts['evidence_index']:
            artifacts['evidence_index'][key_str] = evidence
        return key_str

    # Extract checkers
    checkers = data.get('checkers') or data.get('checker_candidates') or []
    for chk in checkers:
        if isinstance(chk, dict):
            src = chk.get('src')
            dst = chk.get('dst')
            if not dst:
                if src:
                    artifacts['checker_ips'].add(src)
                continue
            from bluekit.netutil import parse_ip, is_internal_ip
            if parse_ip(dst) is None:
                continue
            is_internal = is_internal_ip(dst)
            
            if is_internal:
                if src:
                    artifacts['checker_ips'].add(src)
            else:
                key = chk.get('key', '')
                count = chk.get('count', 0) or 0
                if count < BEACON_MIN_COUNT:
                    continue  # bir necha tasodifiy tashqi ulanish (CDN/fon) — beacon emas
                artifacts['beacon_ips'].add(dst)
                interval = chk.get('interval_seconds', 0.0)
                existing = artifacts['beacon_info'].get(dst)
                if not existing or count > existing.get('count', -1):
                    artifacts['beacon_info'][dst] = {'src': src, 'key': key, 'count': count, 'interval_seconds': interval}
                add_evidence(dst, f"beacon: {key}, ~{interval:.0f}s, {count} ulanish")

    # Extract IOCs
    for ioc in data.get('iocs', []):
        t = ioc.get('type')
        v = ioc.get('value', '')
        if t == 'ip':
            artifacts['ips'].add(v)
            add_evidence(v, f"IOC: {v}")

    # Process timeline
    timeline = data.get('timeline', [])
    for event in timeline:
        ts = event.get('ts')
        if ts:
            if not artifacts['first_ts'] or ts < artifacts['first_ts']:
                artifacts['first_ts'] = ts
            if not artifacts['last_ts'] or ts > artifacts['last_ts']:
                artifacts['last_ts'] = ts

        host = event.get('host', '')
        if host: artifacts['hosts_seen'].add(host)
        
        user = event.get('user', '')
        if user: artifacts['users_seen'].add(user)

        cmd = event.get('command_line_full') or event.get('command_line') or ''
        
        # Build an evidence string
        ev_str = f"{host} {user} {ts} {cmd[:50]}"
        
        event_keys = set()
        def add_ev(k):
            k_str = add_evidence(k, ev_str)
            if k_str:
                event_keys.add(k_str)
                if host:
                    artifacts['artifact_hosts'].setdefault(k_str, set()).add(host)
                    
        # Extract IPs from raw dict
        raw = event.get('raw')
        if isinstance(raw, dict):
            for k, v in raw.items():
                if isinstance(v, str):
                    for ip in re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', v):
                        ip_str = str(ip).lower().strip()
                        event_keys.add(ip_str)
                        if host:
                            artifacts['artifact_hosts'].setdefault(ip_str, set()).add(host)

        # Parse IPs from cmd
        for ip in re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', cmd):
            artifacts['ips'].add(ip)
            add_ev(ip)

        # Parse files
        for fpath in re.findall(r'[A-Za-z]:\\[^\s",]+\.\w+', cmd):
            artifacts['files'].add(fpath)
            artifacts['filenames'].add(os.path.basename(fpath))
            add_ev(fpath)
            add_ev(os.path.basename(fpath))
            
        for fpath in re.findall(r'/[^ \t",]+', cmd):
            artifacts['files'].add(fpath)
            artifacts['filenames'].add(os.path.basename(fpath))
            add_ev(fpath)
            add_ev(os.path.basename(fpath))

        # Tasks
        task_match = re.search(r'schtasks\s+.*?/tn\s+([^\s"]+)', cmd, re.IGNORECASE)
        if task_match:
            artifacts['task_names'].add(task_match.group(1))
            add_ev(task_match.group(1))
        ps_task = re.search(r'New-ScheduledTask.*?-(?:TaskName|Name)\s+([^\s"]+)', cmd, re.IGNORECASE)
        if ps_task:
            artifacts['task_names'].add(ps_task.group(1))
            add_ev(ps_task.group(1))

        # Run values
        run_match = re.search(r'reg\s+add\s+.*?/v\s+([^\s"]+)', cmd, re.IGNORECASE)
        if run_match and 'run' in cmd.lower():
            artifacts['run_values'].add(run_match.group(1))
            add_ev(run_match.group(1))

        # Users
        user_match = re.search(r'net\s+user\s+([^\s"]+)\s+/add', cmd, re.IGNORECASE)
        if user_match:
            artifacts['users'].add(user_match.group(1))
            add_ev(user_match.group(1))
        ps_user = re.search(r'New-LocalUser.*?-Name\s+([^\s"]+)', cmd, re.IGNORECASE)
        if ps_user:
            artifacts['users'].add(ps_user.group(1))
            add_ev(ps_user.group(1))
        ux_user = re.search(r'useradd\s+([^\s"]+)', cmd, re.IGNORECASE)
        if ux_user:
            artifacts['users'].add(ux_user.group(1))
            add_ev(ux_user.group(1))

        # Services
        sc_match = re.search(r'sc\s+create\s+([^\s"]+)', cmd, re.IGNORECASE)
        if sc_match:
            artifacts['services'].add(sc_match.group(1))
            add_ev(sc_match.group(1))
        ps_svc = re.search(r'New-Service.*?-Name\s+([^\s"]+)', cmd, re.IGNORECASE)
        if ps_svc:
            artifacts['services'].add(ps_svc.group(1))
            add_ev(ps_svc.group(1))

        # RATs
        rat_match = re.search(r'(anydesk|teamviewer|rutserv|rfusclient|ammyy|rustdesk|screenconnect|radmin)', cmd, re.IGNORECASE)
        if rat_match:
            artifacts['rat_names'].add(rat_match.group(1).lower())
            add_ev(rat_match.group(1).lower())

        # Hosts entries
        if 'hosts' in cmd.lower() and ('>>' in cmd or 'Add-Content' in cmd):
            # Try to grab ip domain
            hosts_match = re.search(r'(?:echo|["\'])\s*(\d{1,3}(?:\.\d{1,3}){3}\s+[a-zA-Z0-9.-]+)', cmd)
            if hosts_match:
                artifacts['hosts_entries'].add(hosts_match.group(1))
                add_ev(hosts_match.group(1))

        # Techniques
        has_suspicious = False
        for tech in event.get('techniques', []):
            if tech.get('confidence') in ('high', 'medium'):
                has_suspicious = True
                tid = tech.get('technique')
                if tid:
                    artifacts['techniques'].add(tid)
                    add_ev(tid)
                    
        if has_suspicious:
            for ip in re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', cmd):
                artifacts['attack_ips'].add(ip)
                add_evidence(ip, ev_str)
            if isinstance(raw, dict):
                for k, v in raw.items():
                    if isinstance(v, str):
                        for ip in re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', v):
                            artifacts['attack_ips'].add(ip)
                            add_evidence(ip, ev_str)

        # 1a. cron_lines
        cmd_lower = cmd.lower()
        if any(c in cmd_lower for c in ['crontab', 'cron.d', '/etc/crontab', '/var/spool/cron']):
            # Qo'shtirnoqli bo'laklar; ichma-ich (sh -c "echo '* * * * * x' | crontab -") uchun bir daraja ichkariga ham qaraymiz
            quoted = re.findall(r'"([^"]*)"|\'([^\']*)\'', cmd)
            parts = [a or b for a, b in quoted]
            for part in list(parts):
                parts.extend(a or b for a, b in re.findall(r'"([^"]*)"|\'([^\']*)\'', part))
            for part in parts:
                part_strip = part.strip()
                if re.match(r'^(?:@[a-z]+|(?:[0-9*/,\-]+\s+){5})\S', part_strip):
                    norm = ' '.join(part_strip.split()).lower()
                    artifacts['cron_lines'].add(norm)
                    add_ev(norm)

        # 1b. suid_paths
        if 'chmod' in cmd:
            # Har bir chmod alohida buyruq: && ; | || bilan bo'linadi (bitta chmod +x boshqasining SUID holatiga o'tib ketmasin)
            for seg in re.split(r'&&|\|\||[;|]', cmd):
                tokens = seg.split()
                idx = next((i for i, t in enumerate(tokens) if t == 'chmod' or t.endswith('/chmod')), None)
                if idx is None:
                    continue
                suid_mode = False
                for token in tokens[idx + 1:]:
                    if re.match(r'^[ugoa]*[+=][rwxXt]*s[rwxXt]*$', token) or re.match(r'^[4-7][0-7]{3}$', token):
                        suid_mode = True
                    elif re.match(r'^[0-7]{3,4}$|^[ugoa]*[-+=][rwxXst,]*$', token) or token.startswith('-'):
                        continue
                    elif suid_mode:
                        path = token.strip('"\'()')
                        if path:
                            artifacts['suid_paths'].add(path)
                            add_ev(path)

        # 1c. ssh_keys
        if 'authorized_keys' in cmd or 'ssh-copy-id' in cmd_lower:
            for body in re.findall(r'ssh-[a-z0-9-]+\s+([A-Za-z0-9+/=]{8,})', cmd):
                artifacts['ssh_keys'].add(body)
                add_ev(body)
                
        if has_suspicious:
            artifacts['suspicious'].update(event_keys)
            
    artifacts['suspicious'].update(artifacts['beacon_ips'])
    return artifacts
