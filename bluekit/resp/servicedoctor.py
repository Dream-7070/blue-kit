def diagnose(current, service_name, baseline=None, sla_result=None) -> list:
    meta = current.get('meta', {})
    os_name = meta.get('os', 'windows').lower()
    
    def get_cmd(action, srv_name, arg=None):
        srv_name_q = f'"{srv_name}"' if ' ' in srv_name else srv_name
        if os_name == 'windows':
            if action == 'enable': return f'sc config {srv_name_q} start= auto'
            if action == 'start': return f'sc start {srv_name_q}'
            if action == 'restore_path': return f'sc config {srv_name_q} binPath= "{arg}"'
            if action == 'status': return f'sc qc {srv_name_q}'
        else:
            if action == 'enable': return f'systemctl enable {srv_name}'
            if action == 'start': return f'systemctl start {srv_name}'
            if action == 'restore_path': return f'systemctl edit {srv_name}'
            if action == 'status': return f'systemctl status {srv_name}'
        return ''

    results = []
    
    svc = None
    target_lower = service_name.lower()
    for s in current.get('services', []):
        if s.get('name', '').lower() == target_lower or s.get('display', '').lower() == target_lower:
            svc = s
            break
            
    if not svc:
        results.append({
            'cause': f"Xizmat umuman yo'q",
            'evidence': f"services[] da '{service_name}' topilmadi",
            'confidence': 'yuqori',
            'suggested_fix_command': 'N/A',
            'technique': 'T1489'
        })
        return results

    base_svc = None
    if baseline:
        for s in baseline.get('services', []):
            if s.get('name', '').lower() == target_lower or s.get('display', '').lower() == target_lower:
                base_svc = s
                break

    actual_name = svc.get('name', service_name)
    start_mode = str(svc.get('start_mode', '')).lower()
    state = str(svc.get('state', '')).lower()
    bin_path = str(svc.get('binary_path', ''))
    run_as = str(svc.get('run_as', ''))

    if start_mode == 'disabled':
        results.append({
            'cause': "Xizmat o'chirib qo'yilgan (start_mode=Disabled)",
            'evidence': f"start_mode='{svc.get('start_mode')}'",
            'confidence': 'yuqori',
            'suggested_fix_command': f"{get_cmd('enable', actual_name)} && {get_cmd('start', actual_name)}",
            'technique': 'T1489'
        })
        
    elif state not in ('running', 'active') and start_mode in ('auto', 'automatic', 'enabled', 'static'):
        cause_msg = "Xizmat ishga tushishga urinib yiqilgan" if state == 'failed' else "Xizmat to'xtagan"
        results.append({
            'cause': cause_msg,
            'evidence': f"state='{svc.get('state')}', start_mode='{svc.get('start_mode')}'",
            'confidence': 'yuqori',
            'suggested_fix_command': get_cmd('start', actual_name),
            'technique': 'T1489'
        })

    if base_svc and 'binary_path' in base_svc:
        base_path = str(base_svc.get('binary_path', ''))
        if bin_path != base_path:
            results.append({
                'cause': "Binary yo'li o'zgargan",
                'evidence': f"current='{bin_path}', baseline='{base_path}'",
                'confidence': 'yuqori',
                'suggested_fix_command': get_cmd('restore_path', actual_name, base_path),
                'technique': 'T1543.003'
            })

    suspicious_dirs = ['\\temp\\', '\\appdata\\', '\\programdata\\', '\\users\\', '/tmp/', '/dev/shm/']
    if any(d in bin_path.lower() for d in suspicious_dirs):
        results.append({
            'cause': "Shubhali papkadan ishga tushyapti",
            'evidence': f"binary_path='{bin_path}'",
            'confidence': 'yuqori',
            'suggested_fix_command': get_cmd('status', actual_name),
            'technique': 'T1036.005'
        })

    if os_name == 'windows' and ' ' in bin_path and not bin_path.startswith('"'):
        results.append({
            'cause': "Qo'shtirnoqsiz yo'l (bo'shliq bilan)",
            'evidence': f"binary_path='{bin_path}'",
            'confidence': "o'rta",
            'suggested_fix_command': get_cmd('status', actual_name),
            'technique': 'T1574.009'
        })

    if base_svc and 'run_as' in base_svc:
        base_run_as = str(base_svc.get('run_as', ''))
        if run_as != base_run_as:
            results.append({
                'cause': "Ishga tushirish akkaunti o'zgargan",
                'evidence': f"current='{run_as}', baseline='{base_run_as}'",
                'confidence': 'yuqori',
                'suggested_fix_command': get_cmd('status', actual_name),
                'technique': 'T1543.003'
            })

    stop_cmds = [f'sc stop {actual_name}'.lower(), f'net stop {actual_name}'.lower(), f'systemctl stop {actual_name}'.lower(), f'stop-service {actual_name}'.lower()]
    found_stopper = False
    evidence_stopper = ""
    for t in current.get('tasks', []):
        act = str(t.get('action', '')).lower()
        if any(sc in act for sc in stop_cmds):
            found_stopper = True
            evidence_stopper = f"Task: {t.get('name')} executes '{t.get('action')}'"
            break
    if not found_stopper:
        for a in current.get('autoruns', []):
            val = str(a.get('value', '')).lower()
            if any(sc in val for sc in stop_cmds):
                found_stopper = True
                evidence_stopper = f"Autorun: {a.get('name')} executes '{a.get('value')}'"
                break
    if found_stopper:
        results.append({
            'cause': "Kimdir uni qayta to'xtatyapti",
            'evidence': evidence_stopper,
            'confidence': 'yuqori',
            'suggested_fix_command': get_cmd('start', actual_name),
            'technique': 'T1489'
        })

    found_mod = False
    for r in current.get('recent_modified', []):
        if r.get('path') == bin_path:
            found_mod = True
            break
    if found_mod:
        results.append({
            'cause': "Binary yaqinda o'zgartirilgan",
            'evidence': f"recent_modified ichida {bin_path} topildi",
            'confidence': "o'rta",
            'suggested_fix_command': get_cmd('status', actual_name),
            'technique': 'T1543.003'
        })

    if state in ('running', 'active') and sla_result:
        checks = sla_result.get('checks', [])
        tcp_check = next((c for c in checks if c.get('type') == 'tcp'), None)
        http_check = next((c for c in checks if c.get('type') == 'http'), None)
        
        if tcp_check and not tcp_check.get('ok'):
            detail = tcp_check.get('detail', '')
            results.append({
                'cause': "Ishlayapti, lekin port tinglanmayapti",
                'evidence': f"sla_result tcp=fail ({detail})",
                'confidence': 'yuqori',
                'suggested_fix_command': get_cmd('status', actual_name),
                'technique': None
            })
        elif tcp_check and tcp_check.get('ok') and http_check and not http_check.get('ok'):
            detail = http_check.get('detail', '')
            results.append({
                'cause': "Port ochiq, ilova javob bermayapti",
                'evidence': f"sla_result tcp=ok, http=fail ({detail})",
                'confidence': 'yuqori',
                'suggested_fix_command': get_cmd('status', actual_name),
                'technique': None
            })

    if not results:
        results.append({
            'cause': "sabab aniqlanmadi",
            'evidence': f"Xizmat {actual_name} tekshirildi, barcha parametrlar normal",
            'confidence': 'past',
            'suggested_fix_command': get_cmd('status', actual_name),
            'technique': None
        })

    conf_map = {'yuqori': 0, "o'rta": 1, 'past': 2}
    results.sort(key=lambda x: conf_map.get(x.get('confidence', 'past'), 3))

    return results
