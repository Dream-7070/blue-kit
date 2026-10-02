import os
from bluekit.resp.logbridge import load_log_artifacts

# Mahsulot -> konfig fayli va unda nimani qidirish kerakligi (o'zbekcha izoh).
_CONFIG_HINTS = {
    'zabbix': "zabbix_agentd.conf -- `UserParameter=` qatorlari tekshiruvlar ro'yxati",
    'nrpe': "nrpe.cfg -- `command[...]=` qatorlari tekshiruvlar ro'yxati",
    'nagios': "nrpe.cfg yoki nsclient.ini -- tekshiruv buyruqlari shu yerda",
    'nsclient': "nsclient.ini -- [/settings/external scripts] bo'limi",
    'node_exporter': "ishga tushirish argumentlari (--collector.*) va textfile papkasi",
    'prometheus': "prometheus.yml -- scrape_configs baholanadigan nishonlarni ko'rsatadi",
    'exporter': "ishga tushirish argumentlari va metrik yo'li (/metrics)",
    'snmp': "snmpd.conf -- qaysi OID lar ochilgani",
    'munin': "munin-node.conf va plugins papkasi",
    'check_mk': "check_mk agenti -- local/ va plugins/ papkalari",
    'winrm': "konfig scorerda, hostda emas -- WinRM orqali qaysi buyruq bajarilganini "
             "Event Log (Microsoft-Windows-WinRM) dan qarang",
}


def _config_hint(product: str) -> str:
    """Agent konfigini qayerdan qidirish kerakligi. O'qing -- lekin o'zgartirmang."""
    p = (product or '').lower()
    for key, hint in _CONFIG_HINTS.items():
        if key in p:
            return hint
    return "agent konfigini toping -- unda baholanadigan tekshiruvlar ro'yxati bor"


def discover(snapshots: list, log_artifacts: dict = None) -> dict:
    if log_artifacts is None:
        log_artifacts = {}
    
    checker_ips_from_logs = log_artifacts.get('checker_ips', set())
    
    ip_info = {}
    
    def is_internal(ip):
        parts = ip.split('.')
        if len(parts) != 4: return False
        if parts[0] == '10': return True
        if parts[0] == '192' and parts[1] == '168': return True
        if parts[0] == '172' and 16 <= int(parts[1]) <= 31: return True
        return False
        
    def _safe_int(v):
        try:
            return int(v)
        except (ValueError, TypeError):
            return None

    agents = []
    
    for snap in snapshots:
        meta = snap.get('meta', {})
        hostname = meta.get('hostname', 'unknown')

        host_listening_ports = set()
        for lp in snap.get('listening_ports', []):
            port = lp.get('port')
            process = lp.get('process', '')
            product = None
            if port == 10050: product = 'Zabbix Agent'
            elif port == 10051: product = 'Zabbix Server'
            elif port == 5666: product = 'NRPE'
            elif port == 9100: product = 'node_exporter'
            elif port == 161: product = 'SNMP'
            elif port in (5985, 5986): product = 'WinRM'
            elif port == 4949: product = 'Munin'
            elif port == 12489: product = 'Nagios NSClient++'
            
            if product:
                agents.append({
                    'host': hostname,
                    'port': port,
                    'process': process,
                    'product': product,
                    'config_hint': _config_hint(product),
                    'service': product
                })
                
            p_int = _safe_int(port)
            if p_int:
                host_listening_ports.add(p_int)
                
        for svc in snap.get('services', []):
            name = (svc.get('name') or '').lower()
            binary = (svc.get('binary_path') or '').lower()
            combined = name + ' ' + binary
            
            product = None
            for kw in ['zabbix', 'nagios', 'nrpe', 'prometheus', 'exporter', 'check_mk', 'munin', 'nsclient']:
                if kw in combined:
                    product = kw
                    break
            
            if product:
                exists = False
                for a in agents:
                    if a['host'] != hostname:
                        continue
                    known = (str(a.get('product', '')) + ' ' +
                             str(a.get('service', '')) + ' ' +
                             str(a.get('process', ''))).lower()
                    if product in known:
                        a['service'] = svc.get('name') or a.get('service')
                        if binary:
                            a['process'] = a.get('process') or binary
                        exists = True
                        break
                if not exists:
                    agents.append({
                        'host': hostname,
                        'port': 0,
                        'process': binary,
                        'product': product.title(),
                        'config_hint': _config_hint(product),
                        'service': svc.get('name')
                    })
        
        for conn in snap.get('connections', []):
            raddr = conn.get('raddr')
            lport = _safe_int(conn.get('lport'))
            rport = _safe_int(conn.get('rport'))
            proto = conn.get('proto')
            
            if not raddr or raddr in ('0.0.0.0', '127.0.0.1', '::', '::1', '*'):
                continue
                
            if raddr not in ip_info:
                ip_info[raddr] = {
                    'inbound_hosts': set(),
                    'inbound_ports': set(),
                    'outbound_hosts': set(),
                    'outbound_targets': set(),
                    'targets': []
                }
            
            info = ip_info[raddr]
            
            # listening_ports bo'lmasa yo'nalishni bilib bo'lmaydi — chiquvchi deb hisoblanadi (checker emas)
            if lport is not None and lport in host_listening_ports:
                info['inbound_hosts'].add(hostname)
                info['inbound_ports'].add((hostname, lport))
                info['targets'].append({'host': hostname, 'port': lport, 'proto': proto})
            else:
                info['outbound_hosts'].add(hostname)
                info['outbound_targets'].add((raddr, rport))
                info['targets'].append({'host': hostname, 'port': lport, 'proto': proto})

    candidates = []
    monitoring_ports = {10051, 5667, 2003, 8086, 9091, 514, 6514, 8125, 4317, 4318}
    admin_ports = {22, 23, 135, 139, 445, 3389, 5900, 5985, 5986}
    
    for ip, info in ip_info.items():
        score = 0
        evidence = []
        model = 'unknown'
        
        in_hosts = len(info['inbound_hosts'])
        in_ports = len(set(p[1] for p in info['inbound_ports']))
        out_hosts = len(info['outbound_hosts'])
        
        in_port_set = set(p[1] for p in info['inbound_ports'])
        if in_hosts > 0 and in_port_set <= admin_ports:
            # faqat boshqaruv portlariga (SSH/RDP/SMB/WinRM) kirish — hujumchi ham shunday kiradi, checker dalili emas
            kind = 'inbound_admin'
            evidence.append(f"faqat boshqaruv portiga kiruvchi ({', '.join(map(str, sorted(in_port_set)))}) — admin yoki hujumchi, checker emas")
        elif in_hosts > 0:
            kind = 'checker_ip'
            if in_hosts > 1:
                score += 10
                evidence.append(f"{in_hosts} ta hostning connections ida uchradi")
            if in_ports > 1:
                score += 10
                model = "to'g'ridan-to'g'ri"
                evidence.append(f"{in_ports} xil tinglanayotgan portga kiruvchi ulanish")
            elif in_hosts == 1 and in_ports == 1:
                score += 5
                p = list(info['inbound_ports'])[0][1]
                evidence.append(f"hostning {p} portiga kiruvchi ulanish")
        else:
            push_target = False
            if out_hosts > 1:
                for target_ip, target_port in info['outbound_targets']:
                    if is_internal(target_ip) or target_port in monitoring_ports:
                        push_target = True
                        break
            
            if push_target:
                kind = "push_target"
                model = "agent (push)"
                score += 10
                evidence.append(f"{out_hosts} ta hostdan bitta portga chiquvchi ulanish")
            else:
                kind = "outbound"
                evidence.append("faqat chiquvchi ulanish (checker emas)")
                if out_hosts > 1 and not is_internal(ip):
                    evidence.append("DIQQAT: bir nechta hostdan tashqi IP ga chiquvchi — C2 bo'lishi mumkin")

        if ip in checker_ips_from_logs:
            score += 5
            evidence.append("loglardan (checker_ips) topildi")
            if kind in ('outbound', 'inbound_admin'):
                kind = 'checker_ip'

        if is_internal(ip) and kind == 'checker_ip':
            score -= 2
            evidence.append("ichki IP (tarmoq ichida)")
            
        confidence = "past"
        if score >= 15:
            confidence = "yuqori"
        elif score >= 5:
            confidence = "o'rta"
            
        candidates.append({
            'value': ip,
            'kind': kind,
            'confidence': confidence,
            'evidence': evidence,
            'model': model,
            'targets': info['targets'],
            'score': score
        })
        
    candidates.sort(key=lambda x: x['score'], reverse=True)
    for c in candidates:
        del c['score']
        
    return {
        'candidates': candidates,
        'agents': agents,
        'warnings': []
    }

def to_sla_config(discovery: dict) -> dict:
    services = []
    for cand in discovery.get('candidates', []):
        if cand['confidence'] == 'yuqori' and cand['model'] == "to'g'ridan-to'g'ri":
            for t in cand.get('targets', []):
                host = t['host']
                port = t['port']
                name = f"{host}:{port}"
                
                checks = []
                checks.append({
                    'type': 'tcp',
                    'target': f"{host}:{port}"
                })
                
                if port in (80, 443, 8080, 8443):
                    scheme = 'https' if port in (443, 8443) else 'http'
                    checks.append({
                        'type': 'http',
                        'url': f"{scheme}://{host}:{port}/",
                        'expect_status': 200
                    })
                    
                services.append({
                    'name': name,
                    'board_name': '',
                    'checks': checks
                })
                
    return {'services': services}

def to_allowlist(discovery: dict) -> dict:
    cidrs = set()
    for cand in discovery.get('candidates', []):
        if cand['kind'] in ('checker_ip', 'push_target') and cand['confidence'] in ('yuqori', "o'rta"):
            cidrs.add(f"{cand['value']}/32")
            
    return {
        'cidrs': list(cidrs),
        'note': "Generated from scoring discovery"
    }

def parse_agent_config(path: str) -> list:
    results = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                # Zabbix
                if line.startswith('UserParameter='):
                    parts = line[14:].split(',', 1)
                    if len(parts) == 2:
                        results.append({
                            'key': parts[0].strip(),
                            'command': parts[1].strip()
                        })
                # NRPE
                elif line.startswith('command['):
                    end_idx = line.find(']=')
                    if end_idx != -1:
                        key = line[8:end_idx].strip()
                        cmd = line[end_idx+2:].strip()
                        results.append({
                            'key': key,
                            'command': cmd
                        })
    except Exception:
        raise ValueError("Format tanilmadi")
        
    if not results:
        raise ValueError("Format tanilmadi")
        
    return results
