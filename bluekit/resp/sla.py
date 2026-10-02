import socket
import urllib.request
import urllib.error
import hashlib
import subprocess
import time
import ssl
from datetime import datetime

def check_tcp(config):
    target = config.get('target', '')
    timeout = config.get('timeout', 3)
    
    if ':' not in target:
        return False, 0, "Invalid target format (expected host:port)"
        
    host, port_str = target.split(':', 1)
    try:
        port = int(port_str)
    except ValueError:
        return False, 0, "Invalid port"
        
    start_time = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        ms = int((time.time() - start_time) * 1000)
        return True, ms, "ochiq"
    except Exception as e:
        ms = int((time.time() - start_time) * 1000)
        return False, ms, str(e)

def check_http(config):
    url = config.get('url', '')
    expect_status = config.get('expect_status', 200)
    expect_contains = config.get('expect_contains', '')
    timeout = config.get('timeout', 3)
    
    start_time = time.time()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            status = response.getcode()
            body = response.read().decode('utf-8', errors='ignore')
            ms = int((time.time() - start_time) * 1000)
            
            if status != expect_status:
                return False, ms, f"Status {status} != {expect_status}"
            
            if expect_contains and expect_contains not in body:
                return False, ms, f"String '{expect_contains}' not found"
                
            return True, ms, "ok"
    except urllib.error.HTTPError as e:
        ms = int((time.time() - start_time) * 1000)
        if e.code == expect_status:
            if expect_contains:
                body = e.read().decode('utf-8', errors='ignore')
                if expect_contains not in body:
                    return False, ms, f"String '{expect_contains}' not found"
            return True, ms, "ok"
        return False, ms, f"HTTP Error {e.code}"
    except Exception as e:
        ms = int((time.time() - start_time) * 1000)
        return False, ms, str(e)

def check_process(config):
    name = config.get('name', '')
    start_time = time.time()
    try:
        if hasattr(subprocess, 'DEVNULL'):
            # Windows and Linux compatibility roughly, but let's be more specific
            import platform
            if platform.system() == 'Windows':
                output = subprocess.check_output(['tasklist', '/FI', f'IMAGENAME eq {name}'], 
                                                stderr=subprocess.STDOUT, text=True)
                if name.lower() in output.lower():
                    return True, int((time.time() - start_time) * 1000), "ishlayapti"
                return False, int((time.time() - start_time) * 1000), "topilmadi"
            else:
                output = subprocess.check_output(['ps', '-e', '-o', 'comm='], 
                                                stderr=subprocess.STDOUT, text=True)
                if name in [line.strip() for line in output.splitlines()]:
                    return True, int((time.time() - start_time) * 1000), "ishlayapti"
                return False, int((time.time() - start_time) * 1000), "topilmadi"
        return False, int((time.time() - start_time) * 1000), "unsupported"
    except Exception as e:
        return False, int((time.time() - start_time) * 1000), str(e)

def check_service(config):
    name = config.get('name', '')
    expect_state = config.get('expect_state', 'Running')
    start_time = time.time()
    try:
        import platform
        if platform.system() == 'Windows':
            output = subprocess.check_output(['sc', 'query', name], 
                                            stderr=subprocess.STDOUT, text=True)
            if expect_state.upper() in output.upper():
                return True, int((time.time() - start_time) * 1000), "mos"
            return False, int((time.time() - start_time) * 1000), f"holat {expect_state} emas"
        elif platform.system() == 'Linux':
            output = subprocess.check_output(['systemctl', 'is-active', name], 
                                            stderr=subprocess.STDOUT, text=True).strip()
            if output == 'active' and expect_state.lower() == 'running':
                return True, int((time.time() - start_time) * 1000), "mos"
            return False, int((time.time() - start_time) * 1000), f"holat {output}"
        else:
            return False, int((time.time() - start_time) * 1000), "bu platformada qo'llab-quvvatlanmaydi"
    except Exception as e:
        return False, int((time.time() - start_time) * 1000), str(e)

def check_file_hash(config):
    path = config.get('path', '')
    expect_sha256 = config.get('expect_sha256', '')
    start_time = time.time()
    try:
        with open(path, 'rb') as f:
            content = f.read()
            h = hashlib.sha256(content).hexdigest()
            ms = int((time.time() - start_time) * 1000)
            if h.lower() == expect_sha256.lower():
                return True, ms, "mos"
            return False, ms, f"xesh {h}"
    except Exception as e:
        return False, int((time.time() - start_time) * 1000), str(e)

def check_file_absent(config):
    path = config.get('path', '')
    start_time = time.time()
    try:
        import os
        ms = int((time.time() - start_time) * 1000)
        if os.path.exists(path):
            return False, ms, "fayl hali mavjud"
        return True, ms, "yo'q"
    except Exception as e:
        return False, int((time.time() - start_time) * 1000), str(e)

CHECKERS = {
    'tcp': check_tcp,
    'http': check_http,
    'process': check_process,
    'service': check_service,
    'file_hash': check_file_hash,
    'file_absent': check_file_absent
}

DEFAULT_CRITICAL = {
    'tcp': True,
    'http': True,
    'process': True,
    'service': True,
    'file_hash': False,
    'file_absent': False
}

def check(config):
    results = []
    services = config.get('services', [])
    for svc in services:
        svc_name = svc.get('name', 'Unknown')
        board_name = svc.get('board_name', '')
        checks_configs = svc.get('checks', [])
        
        svc_checks = []
        critical_failed = 0
        noncritical_failed = 0
        total_failed = 0
        failed_detail = ""
        
        for c in checks_configs:
            ctype = c.get('type')
            is_critical = c.get('critical', DEFAULT_CRITICAL.get(ctype, True))
            
            if ctype in CHECKERS:
                ok, ms, detail = CHECKERS[ctype](c)
            else:
                ok, ms, detail = False, 0, f"Noma'lum tekshiruv turi: {ctype}"
                
            check_result = {
                'type': ctype,
                'ok': ok,
                'critical': is_critical,
                'ms': ms,
                'detail': detail
            }
            # Add other keys from c
            for k, v in c.items():
                if k not in ['type', 'critical']:
                    check_result[k] = v
                    
            svc_checks.append(check_result)
            
            if not ok:
                total_failed += 1
                if not failed_detail:
                    failed_detail = f"{ctype} {c.get('target') or c.get('url') or c.get('name') or c.get('path') or ''}".strip()
                if is_critical:
                    critical_failed += 1
                else:
                    noncritical_failed += 1
                    
        if total_failed == 0:
            state = 'ok'
            svc_ok = True
            detail = "barcha tekshiruvlar o'tdi"
        elif critical_failed > 0:
            state = 'down'
            svc_ok = False
            detail = f"{total_failed}/{len(checks_configs)} tekshiruv yiqildi: {failed_detail}"
        else:
            state = 'degraded'
            svc_ok = False
            detail = f"{total_failed}/{len(checks_configs)} tekshiruv yiqildi: {failed_detail}"
            
        results.append({
            'name': svc_name,
            'board_name': board_name,
            'state': state,
            'ok': svc_ok,
            'detail': detail,
            'checks': svc_checks,
            'checked_at': datetime.now().isoformat()
        })
        
    return results

def watch(config, interval=30, on_change=None, iterations=None):
    last_states = {}
    iters = 0
    while True:
        if iterations is not None and iters >= iterations:
            break
            
        results = check(config)
        for r in results:
            name = r['name']
            new_state = r['state']
            if name not in last_states or last_states[name] != new_state:
                old_state = last_states.get(name)
                if on_change:
                    on_change(name, old_state, new_state, r)
                else:
                    print(f"[{datetime.now().isoformat()}] {name}: {old_state} -> {new_state} ({r['detail']})")
                last_states[name] = new_state
                
        iters += 1
        if iterations is not None and iters >= iterations:
            break
        time.sleep(interval)
