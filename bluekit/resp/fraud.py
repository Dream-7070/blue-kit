"""
RAT va hosts endi triage.analyze() orqali shu yerda ham chiqadi, qoidalar bitta joyda (triage) saqlanadi.
"""
import datetime
import ipaddress
import re


from bluekit.netutil import is_external_ip

def _has_public_ip(addrs: str) -> bool:
    for token in re.findall(r'\d{1,3}(?:\.\d{1,3}){3}', addrs):
        if is_external_ip(token):
            return True
    return False

def scan(current, baseline=None, kb=None) -> list:
    res = []
    
    # 1. New root cert & 2. Expired/local cert
    if current.get('root_cas'):
        baseline_cas = {c.get('thumbprint') for c in baseline.get('root_cas', []) if c.get('thumbprint')} if baseline else set()
        for ca in current['root_cas']:
            tb = ca.get('thumbprint')
            if baseline and tb and tb not in baseline_cas:
                res.append({
                    'category': 'root_cas',
                    'item': ca.get('subject', 'Unknown'),
                    'score': 0.8,
                    'confidence': 'high',
                    'techniques': [{'id': 'T1553.004'}],
                    'reasons': ["baseline'da yo'q (yangi)"],
                    'protected': False
                })
            else:
                # check expiration and local names
                notafter = ca.get('notafter', '')
                is_expired = False
                try:
                    if notafter:
                        # naive parse
                        dt = datetime.datetime.fromisoformat(notafter.replace('Z', '+00:00').split('+')[0])
                        if dt > datetime.datetime.utcnow() + datetime.timedelta(days=20*365):
                            is_expired = True
                except:
                    pass
                
                subj = ca.get('subject', '').lower()
                is_local = ('localhost' in subj or '127.0.0.1' in subj)
                
                if is_expired or is_local:
                    reason = "muddati 20 yildan uzoq" if is_expired else "subject da mahalliy nom"
                    res.append({
                        'category': 'root_cas',
                        'item': ca.get('subject', 'Unknown'),
                        'score': 0.8,
                        'confidence': 'high',
                        'techniques': [{'id': 'T1553.004'}],
                        'reasons': [reason],
                        'protected': False
                    })
                    
    # 3. Proxy enabled/changed & 4. PAC file
    proxy = current.get('proxy')
    if proxy and isinstance(proxy, dict):
        base_proxy = baseline.get('proxy', {}) if baseline else {}
        # PAC
        if proxy.get('AutoConfigURL'):
            res.append({
                'category': 'proxy',
                'item': str(proxy.get('AutoConfigURL')),
                'score': 0.9,
                'confidence': 'high',
                'techniques': [{'id': 'T1090'}],
                'reasons': ["PAC fayl o'rnatilgan"],
                'protected': False
            })
        
        # Enabled/changed
        if proxy.get('ProxyEnable') in [1, '1', True, 'true'] and base_proxy.get('ProxyEnable') not in [1, '1', True, 'true']:
            res.append({
                'category': 'proxy',
                'item': 'ProxyEnable',
                'score': 0.7,
                'confidence': 'high' if baseline else 'medium',
                'techniques': [{'id': 'T1090'}],
                'reasons': ["Proxy yoqilgan"],
                'protected': False
            })
        elif baseline and proxy.get('ProxyServer') and proxy.get('ProxyServer') != base_proxy.get('ProxyServer'):
            res.append({
                'category': 'proxy',
                'item': str(proxy.get('ProxyServer')),
                'score': 0.7,
                'confidence': 'high',
                'techniques': [{'id': 'T1090'}],
                'reasons': ["ProxyServer farq qiladi"],
                'protected': False
            })

    # 5. DNS changed
    dns_servers = current.get('dns_servers', [])
    if dns_servers:
        base_dns = baseline.get('dns_servers', []) if baseline else []
        for d in dns_servers:
            addrs = str(d.get('addresses', ''))
            if not addrs:
                continue
            if baseline:
                found = False
                for bd in base_dns:
                    if bd.get('interface') == d.get('interface') and str(bd.get('addresses', '')) == addrs:
                        found = True
                if not found:
                    res.append({
                        'category': 'dns_servers',
                        'item': addrs,
                        'score': 0.7,
                        'confidence': 'high',
                        'techniques': [{'id': 'T1071.004'}],
                        'reasons': ["DNS baselinedan farq qiladi"],
                        'protected': False
                    })
            else:
                if _has_public_ip(addrs):
                    res.append({
                        'category': 'dns_servers',
                        'item': addrs,
                        'score': 0.7,
                        'confidence': 'medium',
                        'techniques': [{'id': 'T1071.004'}],
                        'reasons': ["Tashqi (public) IP"],
                        'protected': False
                    })
                    
    # 6. Portproxy
    portproxy = current.get('portproxy', [])
    if portproxy:
        import re
        # eski Windows snapshotlaridagi netsh sarlavhalari qoida emas; Linux iptables DNAT qatorlari esa saqlanadi
        netsh_header = re.compile(r"^\s*(listen on|address\s+port|-{5,})|:\s*$", re.I)
        base_portproxy = baseline.get('portproxy', []) if baseline else []
        base_rules = [p.get('rule') for p in base_portproxy if p.get('rule') and not netsh_header.search(p.get('rule'))]
        for p in portproxy:
            rule = p.get('rule')
            if rule and not netsh_header.search(rule) and (not baseline or rule not in base_rules):
                res.append({
                    'category': 'portproxy',
                    'item': rule,
                    'score': 0.8,
                    'confidence': 'high' if baseline else 'medium',
                    'techniques': [{'id': 'T1090'}],
                    'reasons': ["Port yo'naltirish qoidasi"],
                    'protected': False
                })
                
    # 7. Firewall off
    fw = current.get('firewall_profiles', [])
    for f in fw:
        st = str(f.get('state', '')).lower()
        if 'off' in st or 'inactive' in st or st == '0' or st == 'false':
            res.append({
                'category': 'firewall_profiles',
                'item': f.get('name', 'Unknown'),
                'score': 0.9,
                'confidence': 'high',
                'techniques': [{'id': 'T1685'}],
                'reasons': ["Firewall o'chirilgan"],
                'protected': False
            })

    try:
        from bluekit.resp.triage import analyze
        findings, _ = analyze(kb, current, baseline)
        for f in findings:
            if f.get('category') in ['remote_access_tools', 'hosts_file']:
                conf = f.get('confidence')
                if conf == 'med':
                    conf = 'medium'
                res.append({
                    'category': f.get('category'),
                    'item': f.get('item'),
                    'score': f.get('score'),
                    'confidence': conf,
                    'techniques': f.get('techniques', []),
                    'reasons': f.get('reasons', []),
                    'protected': f.get('protected', False)
                })
    except Exception as e:
        res.append({
            'category': 'fraud_error',
            'item': f"RAT/hosts tekshiruvi bajarilmadi: {str(e)}",
            'score': 0.0,
            'confidence': 'low',
            'techniques': [],
            'reasons': ["Triage ni alohida yurgizing"],
            'protected': False
        })

    return res
