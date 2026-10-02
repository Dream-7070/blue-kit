import re
import shlex
from typing import List, Dict, Any, Optional

# Version parsing helper without external dependencies
def _clean_version_tuple(v_str: str) -> tuple:
    if not v_str:
        return (0,)
    # Strip epoch if present: 1:2.4.49-1 -> 2.4.49-1
    if ':' in v_str:
        v_str = v_str.split(':', 1)[1]
    # Remove OpenSSH 'p1', 'p2' before splitting digits so 9.7p1 becomes 9.7 (not 9.7.1)
    base_ver = re.sub(r'p\d+', '', v_str.split('-')[0].split('+')[0].split('~')[0])
    clean = re.sub(r'[^0-9\.]', '.', base_ver)
    parts = []
    for chunk in clean.split('.'):
        if chunk.isdigit():
            parts.append(int(chunk))
    return tuple(parts) if parts else (0,)

def _is_patched_backport(pkg_name: str, v_str: str, cve: str) -> bool:
    """Check if the Debian/Ubuntu/RHEL package version contains a backported security fix for the CVE."""
    v_lower = v_str.lower()
    
    # CVE-2024-6387 (OpenSSH regreSSHion):
    if cve == 'CVE-2024-6387':
        if 'ubuntu0.10' in v_lower or 'ubuntu13.3' in v_lower or 'ubuntu3.6' in v_lower:
            return True
        # Debian 12 da tuzatish faqat +deb12u3 dan boshlab (deb12u1/u2 zaif); Debian 11 (8.4p1) umuman ta'sirlanmaydi
        m_deb12 = re.search(r'\+deb12u(\d+)', v_lower)
        if m_deb12 and int(m_deb12.group(1)) >= 3:
            return True
        m_ub = re.search(r'ubuntu0\.(\d+)', v_lower)
        if m_ub and int(m_ub.group(1)) >= 10:
            return True
        m_ub13 = re.search(r'ubuntu13\.(\d+)', v_lower)
        if m_ub13 and int(m_ub13.group(1)) >= 3:
            return True

    # CVE-2021-3156 (Baron Samedit - Sudo):
    if cve == 'CVE-2021-3156':
        m_ub = re.search(r'ubuntu1\.(\d+)', v_lower)
        if m_ub and int(m_ub.group(1)) >= 4:
            return True
        if '+deb10u3' in v_lower or '+deb10u4' in v_lower or '+deb11' in v_lower:
            return True

    # CVE-2021-4034 (PwnKit - Polkit):
    if cve == 'CVE-2021-4034':
        m_ub = re.search(r'ubuntu1\.(\d+)', v_lower)
        if m_ub and int(m_ub.group(1)) >= 2:
            return True
        if 'ubuntu0.18.04.6' in v_lower or '+deb10u1' in v_lower or '+deb11u1' in v_lower:
            return True

    return False

def _version_in_range(pkg_name: str, v_str: str, min_ver: Optional[str], max_ver: Optional[str], exact_list: Optional[list] = None, cve: str = '') -> bool:
    if not v_str:
        return False
    if cve and _is_patched_backport(pkg_name, v_str, cve):
        return False
        
    if exact_list:
        v_clean = v_str.strip()
        for ex in exact_list:
            if ex in v_clean:
                return True
    
    target = _clean_version_tuple(v_str)
    if not target or target == (0,):
        return False
        
    if min_ver:
        min_t = _clean_version_tuple(min_ver)
        max_len = max(len(target), len(min_t))
        t_pad = target + (0,) * (max_len - len(target))
        m_pad = min_t + (0,) * (max_len - len(min_t))
        if t_pad < m_pad:
            return False
            
    if max_ver:
        max_t = _clean_version_tuple(max_ver)
        max_len = max(len(target), len(max_t))
        t_pad = target + (0,) * (max_len - len(target))
        m_pad = max_t + (0,) * (max_len - len(max_t))
        if t_pad > m_pad:
            return False
            
    return True if (min_ver or max_ver) else False


# Known Critical & High Vulnerabilities Catalog
VULNERABILITY_RULES = [
    {
        'cve': 'CVE-2024-6387',
        'name': 'regreSSHion (OpenSSH RCE)',
        'packages': ['openssh-server', 'openssh', 'openssh-client'],
        'min_version': '8.5',
        'max_version': '9.7',
        'severity': 'critical',
        'score': 0.95,
        'technique': 'T1190',
        'description': 'OpenSSH serverda signal handler race condition orqali masofadan root huquqida kod bajarish (regreSSHion)',
        'remediation': 'apt update && apt install --only-upgrade openssh-server'
    },
    {
        'cve': 'CVE-2021-4034',
        'name': 'PwnKit (Polkit pkexec LPE)',
        'packages': ['policykit-1', 'polkit', 'pkexec'],
        'min_version': '0.90',
        'max_version': '0.105',
        'exact_versions': ['0.105-18', '0.105-20', '0.105-26', '0.105-31'],
        'severity': 'critical',
        'score': 0.95,
        'technique': 'T1068',
        'description': 'Polkit pkexec argumentlarini noto\'g\'ri qayta ishlash oqibatida lokal root huquqini qo\'lga kiritish (PwnKit)',
        'remediation': 'apt update && apt install --only-upgrade policykit-1 || chmod 0755 /usr/bin/pkexec'
    },
    {
        'cve': 'CVE-2021-3156',
        'name': 'Baron Samedit (Sudo LPE)',
        'packages': ['sudo', 'sudo-ldap'],
        'min_version': '1.8.2',
        'max_version': '1.9.5',
        'exact_versions': ['1.8.31', '1.9.0', '1.9.5p1'],
        'severity': 'high',
        'score': 0.90,
        'technique': 'T1068',
        'description': 'Sudo parametrlaridagi heap-based buffer overflow orqali parolsiz root huquqini olish (Baron Samedit)',
        'remediation': 'apt update && apt install --only-upgrade sudo'
    },
    {
        'cve': 'CVE-2021-41773',
        'name': 'Apache HTTP Server Path Traversal & RCE',
        'packages': ['apache2', 'httpd'],
        'exact_versions': ['2.4.49'],
        'severity': 'critical',
        'score': 0.95,
        'technique': 'T1190',
        'description': 'Apache 2.4.49 da yo\'l tekshiruvi xatosi orqali ixtiyoriy fayllarni o\'qish va RCE',
        'remediation': 'apt update && apt install --only-upgrade apache2'
    },
    {
        'cve': 'CVE-2021-42013',
        'name': 'Apache HTTP Server RCE (Path Traversal Bypass)',
        'packages': ['apache2', 'httpd'],
        'exact_versions': ['2.4.50'],
        'severity': 'critical',
        'score': 0.95,
        'technique': 'T1190',
        'description': 'Apache 2.4.50 da CVE-2021-41773 tuzatilishini aylanib o\'tish va masofadan kod bajarish',
        'remediation': 'apt update && apt install --only-upgrade apache2'
    },
    {
        'cve': 'CVE-2021-44228',
        'name': 'Log4Shell (Apache Log4j RCE)',
        'packages': ['log4j', 'apache-log4j', 'liblog4j2-java'],
        'min_version': '2.0',
        'max_version': '2.14.1',
        'severity': 'critical',
        'score': 0.95,
        'technique': 'T1190',
        'description': 'Apache Log4j JNDI lookup orqali masofadan kod bajarish (Log4Shell)',
        'remediation': 'apt-get install --only-upgrade liblog4j2-java'
    },
    {
        'cve': 'CVE-2024-1709',
        'name': 'ScreenConnect Authentication Bypass',
        'packages': ['ConnectWise ScreenConnect', 'ScreenConnect', 'screenconnect'],
        'min_version': '1.0',
        'max_version': '23.9.7',
        'severity': 'critical',
        'score': 0.95,
        'technique': 'T1190',
        'description': 'ScreenConnect SetupWizard endpointida autentifikatsiyani aylanib o\'tish va admin hisobini yaratish',
        'remediation': '# ScreenConnect ni zudlik bilan >= 23.9.8 versiyaga yangilang'
    },
    {
        'cve': 'CVE-2022-22965',
        'name': 'Spring4Shell (Spring Framework RCE)',
        'packages': ['libspring-core-java', 'spring-core', 'spring-framework'],
        'min_version': '5.3.0',
        'max_version': '5.3.17',
        'severity': 'critical',
        'score': 0.92,
        'technique': 'T1190',
        'description': 'Spring Framework DataBinder orqali Tomcat class loaderini o\'zgartirish va RCE',
        'remediation': 'apt-get install --only-upgrade libspring-core-java'
    },
    {
        'cve': 'CVE-2021-3560',
        'name': 'Polkit D-Bus LPE',
        'packages': ['polkit', 'policykit-1'],
        'min_version': '0.115',
        'max_version': '0.118',
        'severity': 'high',
        'score': 0.90,
        'technique': 'T1068',
        'description': 'Polkit D-Bus so\'rovini erta uzish orqali parolsiz yangi sudo foydalanuvchi yaratish',
        'remediation': 'apt update && apt install --only-upgrade policykit-1'
    }
]


def audit_packages(packages: List[Dict[str, Any]], installed_apps: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    findings = []
    seen_keys = set()
    all_items = []
    if packages:
        for p in packages:
            all_items.append({'name': str(p.get('name', '')).lower(), 'version': str(p.get('version', '')), 'raw': p})
    if installed_apps:
        for a in installed_apps:
            all_items.append({'name': str(a.get('name', '')).lower(), 'version': str(a.get('version', '')), 'raw': a})
            
    for item in all_items:
        pkg_name = item['name']
        pkg_ver = item['version']
        if not pkg_name or not pkg_ver:
            continue
            
        for rule in VULNERABILITY_RULES:
            match_pkg = any(p.lower() == pkg_name or pkg_name == p.lower() or p.lower() in pkg_name for p in rule['packages'])
            if match_pkg:
                is_vuln = _version_in_range(
                    pkg_name,
                    pkg_ver,
                    rule.get('min_version'),
                    rule.get('max_version'),
                    rule.get('exact_versions'),
                    cve=rule.get('cve', '')
                )
                if is_vuln:
                    dedup_key = (pkg_name, rule['cve'])
                    if dedup_key in seen_keys:
                        continue
                    seen_keys.add(dedup_key)
                    findings.append({
                        'category': 'vulnerabilities',
                        'item': f"{item['raw'].get('name', pkg_name)} {pkg_ver}",
                        'cve': rule['cve'],
                        'vuln_name': rule['name'],
                        'severity': rule['severity'],
                        'score': rule['score'],
                        'techniques': [rule['technique']],
                        'confidence': 'yuqori',
                        'reasons': [
                            f"Zaif paket aniqlandi: {rule['cve']} ({rule['name']})",
                            f"O'rnatilgan versiya: {pkg_ver}",
                            rule['description']
                        ],
                        'suggested_fix_command': rule['remediation']
                    })
    return findings


def audit_containers(containers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []
    if not containers:
        return findings
        
    for c in containers:
        c_name = c.get('name') or c.get('id', 'unknown')
        c_img = c.get('image', 'unknown')
        is_priv = c.get('privileged', False)
        mounts = str(c.get('mount_risks', ''))
        
        reasons = []
        score = 0.0
        techs = []
        
        if is_priv:
            score = max(score, 0.90)
            techs.append('T1611')
            reasons.append("Konteyner --privileged rejimida ishga tushirilgan (Host Escape xavfi yuqori)")
            
        if 'docker.sock' in mounts.lower():
            score = max(score, 0.95)
            techs.append('T1611')
            techs.append('T1078')
            reasons.append("/var/run/docker.sock konteynerga to'g'ridan-to'g'ri ulangan (Host Takeover xavfi)")
            
        if reasons:
            c_target = c.get('id') or c_name
            cid = shlex.quote(str(c_target))
            findings.append({
                'category': 'containers',
                'item': f"Container: {c_name} ({c_img})",
                'score': score,
                'confidence': 'yuqori',
                'techniques': list(set(techs)) if techs else ['T1611'],
                'reasons': reasons,
                'container_id': c.get('id', ''),
                'suggested_fix_command': f"docker stop {cid}"
            })
    return findings


def audit_database_exposure(listening_ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []
    if not listening_ports:
        return findings
        
    db_ports = {
        3306: 'MySQL / MariaDB',
        5432: 'PostgreSQL',
        6379: 'Redis',
        27017: 'MongoDB',
        1433: 'MS SQL',
        9200: 'Elasticsearch',
        11211: 'Memcached'
    }
    
    for lp in listening_ports:
        port_num = lp.get('port') or lp.get('local_port')
        ip_addr = str(lp.get('ip') or lp.get('local_ip') or lp.get('address') or '')
        
        try:
            if not port_num and ':' in ip_addr:
                parts = ip_addr.rsplit(':', 1)
                ip_addr = parts[0]
                port_num = int(parts[1])
            else:
                port_num = int(port_num)
        except Exception:
            continue
            
        if port_num in db_ports:
            is_wildcard = ip_addr in ('0.0.0.0', '::', '*', '') or not ip_addr.startswith(('127.', '::1', 'localhost'))
            if is_wildcard:
                db_name = db_ports[port_num]
                score = 0.85 if port_num in (6379, 11211, 27017) else 0.70
                proto = lp.get('proto', 'tcp')
                findings.append({
                    'category': 'database_exposure',
                    'item': f"{db_name} port {port_num} ({ip_addr})",
                    'score': score,
                    'confidence': 'yuqori' if port_num in (6379, 27017) else "o'rta",
                    'techniques': ['T1190', 'T1046'],
                    'reasons': [
                        f"{db_name} porti ({port_num}) tashqi/umumiy tarmoq interfeysida ochiq turibdi ({ip_addr})",
                        "Parolsiz kirish yoki masofaviy eksployt (RCE/Data Leak) xavfi mavjud"
                    ],
                    'suggested_fix_command': f"# Firewall qoidasi: iptables -A INPUT -p {proto} --dport {port_num} ! -s 127.0.0.1 -j DROP"
                })
    return findings

