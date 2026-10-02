import re
import yaml
import os
import urllib.parse
import zipfile
import io

def levenshtein(s1, s2):
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def defang_url(url):
    return url.replace("http", "hxxp").replace(".", "[.]")

def get_brands():
    brands_path = os.path.join(os.path.dirname(__file__), "brands.yaml")
    with open(brands_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def extract_host(url):
    try:
        p = urllib.parse.urlparse(url)
        return p.hostname or ""
    except:
        return ""

def scan_email(parsed, kb=None):
    brands_data = get_brands()
    brands = brands_data.get("brands", [])
    shorteners = set(brands_data.get("shorteners", []))
    
    brand_domains = set()
    domain_to_brand = {}
    for b in brands:
        for d in b.get("domains", []):
            brand_domains.add(d)
            domain_to_brand[d] = b["name"]
            
    findings = []
    
    def add_finding(check, severity, score, evidence, techniques, izoh):
        findings.append({
            "check": check,
            "severity": severity,
            "score": score,
            "evidence": evidence,
            "techniques": techniques,
            "izoh": izoh
        })

    # Header Checks
    headers = parsed.get("headers", {})
    auth = headers.get("auth_results", "").lower()
    from_domain = headers.get("from_domain", "").lower()
    from_display = headers.get("from_display", "")
    
    if "spf=fail" in auth or "spf=softfail" in auth or "spf fail" in auth:
        add_finding("spf_fail", "medium", 0.25, auth[:100], [], "SPF tekshiruvi muvaffaqiyatsiz bo'ldi, xat soxta bo'lishi mumkin.")
    
    if "dkim=fail" in auth or "dkim=none" in auth or "dkim fail" in auth:
        add_finding("dkim_fail", "medium", 0.2, auth[:100], [], "DKIM imzosi yaroqsiz yoki yo'q.")
        
    if "dmarc=fail" in auth or "dmarc fail" in auth:
        add_finding("dmarc_fail", "medium", 0.3, auth[:100], [], "DMARC siyosati buzildi.")
        
    rp = headers.get("return_path", "").lower()
    rp_domain = rp.split("@")[-1].strip("<>") if "@" in rp else rp.strip("<>")
    if rp and rp_domain and rp_domain != from_domain:
        add_finding("return_path_mismatch", "medium", 0.25, f"From: {from_domain}, Return-Path: {rp_domain}", [], "Return-Path domeni From domenidan farq qiladi.")
        
    rt = headers.get("reply_to", "").lower()
    rt_domain = rt.split("@")[-1].strip("<>") if "@" in rt else rt.strip("<>")
    if rt and rt_domain and rt_domain != from_domain:
        add_finding("reply_to_mismatch", "medium", 0.3, f"From: {from_domain}, Reply-To: {rt_domain}", [], "Reply-To domeni From domenidan farq qiladi.")
        
    # display_name_spoof
    if "@" in from_display or "." in from_display:
        # Check if it looks like an email or domain
        disp_lower = from_display.lower()
        if from_domain and from_domain not in disp_lower:
            add_finding("display_name_spoof", "medium", 0.3, f"Display: {from_display}, From: {from_domain}", ["T1684.001"], "Display name ichida boshqa domen/email ko'rsatilgan.")
            
    # brand_impersonation
    for b in brands:
        if b["name"].lower() in from_display.lower():
            if from_domain not in b["domains"]:
                add_finding("brand_impersonation", "medium", 0.3, f"Brand: {b['name']}, From: {from_domain}", ["T1684.001"], "Xat jo'natuvchisi mashhur brend nomidan foydalangan, lekin domeni uniki emas.")
                break
                
    msg_id = headers.get("message_id", "").lower()
    msg_domain = msg_id.split("@")[-1].strip("<>") if "@" in msg_id else ""
    if msg_id and msg_domain and msg_domain != from_domain:
        add_finding("msgid_mismatch", "low", 0.1, f"From: {from_domain}, MsgID: {msg_domain}", [], "Message-ID domeni From domeniga mos emas.")
        
    # URL Checks
    out_urls = []
    for u in parsed.get("urls", []):
        url = u["url"]
        host = extract_host(url).lower()
        if not host: continue
        reasons = []
        
        if "xn--" in host:
            reasons.append("url_punycode")
            add_finding("url_punycode", "medium", 0.35, host, ["T1566.002"], "URL manzilida Punycode (gomografik hujum) ishlatilgan.")
            
        if re.match(r'^[\d\.]+$', host) or ":" in host and not host.endswith("]"): 
            # simplistic IP check
            reasons.append("url_ip_literal")
            add_finding("url_ip_literal", "medium", 0.3, host, ["T1566.002"], "URL manzilida IP manzil ko'rsatilgan.")
            
        anchor = (u.get("anchor_text") or "").lower()
        if anchor and "." in anchor and not " " in anchor:
            anchor_host = extract_host("http://" + anchor)
            if anchor_host and anchor_host != host:
                reasons.append("url_anchor_mismatch")
                add_finding("url_anchor_mismatch", "high", 0.4, f"Anchor: {anchor_host}, URL: {host}", ["T1566.002", "T1204.001"], "URL matni va asl havola manzili har xil.")
                
        p = urllib.parse.urlparse(url)
        if "@" in p.netloc:
            reasons.append("url_at_trick")
            add_finding("url_at_trick", "medium", 0.3, p.netloc, ["T1566.002"], "URL manzilida @ belgisi ishlatilgan (foydalanuvchini chalg'itish).")
            
        if host in shorteners:
            reasons.append("url_shortener")
            add_finding("url_shortener", "low", 0.2, host, ["T1566.002"], "Qisqartirilgan URL manzilidan foydalanilgan.")
            
        # lookalike
        parts = host.split(".")
        reg_domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
        for bd in brand_domains:
            if reg_domain != bd and 1 <= levenshtein(reg_domain, bd) <= 2:
                reasons.append("url_lookalike")
                add_finding("url_lookalike", "medium", 0.35, f"{reg_domain} ~ {bd}", ["T1684.001"], "Manzil taniqli brend domeniga juda o'xshash (typosquatting).")
                break
                
        # subdomain spoof
        for b in brands:
            if b["name"].lower() in host and reg_domain not in b["domains"]:
                reasons.append("url_subdomain_spoof")
                add_finding("url_subdomain_spoof", "medium", 0.35, host, ["T1684.001"], "Brend nomi subdomenda yashiringan.")
                break
                
        if re.search(r'[a-zA-Z]', host) and re.search(r'[а-яА-Я]', host):
            reasons.append("url_mixed_script")
            add_finding("url_mixed_script", "medium", 0.35, host, ["T1684.001"], "Domen nomida turli alifbolar (lotin+kirill) aralashtirilgan.")
            
        path = p.path.lower()
        if any(x in path for x in ["/login", "/verify", "/secure", "/account", "/owa", "/password"]):
            if reg_domain not in brand_domains:
                reasons.append("url_credential_path")
                add_finding("url_credential_path", "low", 0.15, url[:60], ["T1598.003"], "URL yo'lida avtorizatsiya so'zlari bor, lekin u rasmiy domen emas.")
                
        out_urls.append({
            "url_defanged": defang_url(url),
            "host": host,
            "reasons": reasons
        })
        
    # Attachment Checks
    out_attachments = []
    out_iocs = []
    
    exec_exts = ["exe", "scr", "bat", "cmd", "com", "pif", "ps1", "vbs", "js", "jse", "wsf", "wsh", "hta", "jar", "msi", "lnk"]
    office_macros = ["docm", "xlsm", "pptm", "xlsb"]
    containers = ["iso", "img", "vhd", "vhdx"]
    rtf_xll = ["rtf", "xll", "one"]
    
    magic_map = {
        "pdf": b"%PDF",
        "zip": b"PK",
        "doc": b"\xD0\xCF\x11\xE0",
        "xls": b"\xD0\xCF\x11\xE0",
        "ppt": b"\xD0\xCF\x11\xE0",
        "msg": b"\xD0\xCF\x11\xE0",
        "exe": b"MZ",
        "dll": b"MZ",
        "rtf": b"{\\rtf"
    }
    
    for att in parsed.get("attachments", []):
        fname = att["filename"].lower()
        sha256 = att["sha256"]
        head = att["data_head"]
        payload = att.get("payload", b"")
        size = att["size"]
        
        out_iocs.append({"type": "sha256", "value": sha256})
        
        reasons = []
        suspicious = False
        
        parts = fname.split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        
        if ext in exec_exts:
            reasons.append("attach_executable")
            add_finding("attach_executable", "high", 0.5, fname, ["T1204.002"], "Bajariluvchi (executable) fayl biriktirilgan.")
            suspicious = True
            
        if len(parts) > 2 and parts[-2] in ["pdf", "doc", "jpg", "png", "txt"]:
            reasons.append("attach_double_ext")
            add_finding("attach_double_ext", "high", 0.5, fname, ["T1036.007"], "Faylda ikkilamchi kengaytma bor (masalan .pdf.exe).")
            suspicious = True
        elif "\u202e" in att["filename"]:
            reasons.append("attach_double_ext")
            add_finding("attach_double_ext", "high", 0.5, att["filename"], ["T1036.007"], "Fayl nomida RTL override belgisi bor (kengaytmani yashirish).")
            suspicious = True
            
        if ext in magic_map:
            if not head.startswith(magic_map[ext]):
                reasons.append("attach_magic_mismatch")
                add_finding("attach_magic_mismatch", "high", 0.4, f"Ext: {ext}, Header: {head[:4].hex()}", ["T1036.007"], "Fayl kengaytmasi uning asl formatiga mos emas (magic bytes).")
                suspicious = True
                
        macro_found = False
        if ext in office_macros:
            macro_found = True
        elif ext in ["docx", "xlsx", "pptx", "zip"] or head.startswith(b"PK"):
            # Check zip contents
            try:
                with zipfile.ZipFile(io.BytesIO(payload)) as z:
                    for zinfo in z.infolist():
                        if "vbaProject.bin" in zinfo.filename:
                            macro_found = True
                        if zinfo.flag_bits & 1:
                            reasons.append("attach_encrypted_zip")
                            add_finding("attach_encrypted_zip", "medium", 0.35, fname, ["T1566.001"], "Parollangan arxiv (antivirus tekshiruvini chetlab o'tish uchun).")
                            suspicious = True
            except:
                pass
        elif head.startswith(b"\xD0\xCF\x11\xE0"):
            if b"Macros" in payload or b"VBA" in payload:
                macro_found = True
                
        if macro_found:
            reasons.append("attach_macro_office")
            add_finding("attach_macro_office", "high", 0.45, fname, ["T1566.001"], "Ofis hujjatida makros topildi.")
            suspicious = True
            
        if ext in containers:
            reasons.append("attach_container")
            add_finding("attach_container", "high", 0.4, fname, ["T1566.001"], "Konteyner fayli (ISO/IMG/VHD) biriktirilgan, u orqali zararli kod yashirilishi mumkin.")
            suspicious = True
            
        if ext in rtf_xll:
            reasons.append("attach_rtf_or_xll")
            add_finding("attach_rtf_or_xll", "medium", 0.35, fname, ["T1566.001"], "Xavfli turdagi ofis fayli (RTF/XLL/ONE).")
            suspicious = True
            
        out_attachments.append({
            "filename": att["filename"],
            "sha256": sha256,
            "size": size,
            "suspicious": suspicious,
            "reasons": reasons
        })

    # Body Checks
    body_text = parsed.get("body_text", "")
    body_html = parsed.get("body_html", "")
    
    if "atob(" in body_html or "new Blob(" in body_html:
        if "download=" in body_html or re.search(r'<script>[^<]{1000,}</script>', body_html):
            add_finding("html_smuggling", "high", 0.45, "HTML smuggling pattern", ["T1027.006"], "Xat HTML qismida zararli faylni yashirincha yuklovchi kod bor (HTML Smuggling).")
            
    if re.search(r'<form[^>]+action=["\']http[s]?://', body_html, re.I):
        add_finding("html_form_external", "high", 0.4, "Tashqi domen", ["T1598.003"], "Xat ichida tashqi serverga ma'lumot jo'natuvchi forma bor.")
        
    urgency_kw = {
        "shoshilinch", "hisobingiz bloklanadi", "parolni tasdiqlang", "darhol", "hisobingiz ochiriladi",
        "срочно", "ваш аккаунт заблокирован", "подтвердите пароль", "немедленно",
        "verify your account", "password expires", "urgent", "account suspended", "invoice attached", "wire transfer", "click here immediately"
    }
    
    urg_count = 0
    body_lower = body_text.lower() + body_html.lower()
    for kw in urgency_kw:
        if kw in body_lower:
            urg_count += 1
            
    if urg_count > 0:
        score = min(0.3, urg_count * 0.1)
        add_finding("urgency_keywords", "low", score, f"Kalit so'zlar: {urg_count} marta", ["T1598.003"], "Matnda shoshilinchlik va vahima uyg'otuvchi so'zlar bor.")
        
    if len(body_text.strip()) < 40 and "<img" in body_html.lower():
        add_finding("image_only_body", "low", 0.2, "Matn kam, rasm bor", [], "Xat faqat rasmdan iborat (spam filtrni chetlab o'tish usuli).")
        

    # NEW THREAT CHECKS
    # Threat language
    threat_kw = [
        'kuzatyapman', 'pulni o\'tkaz', 'oilangni', 'sirlaringni', 'fosh qilaman', 'tahdid',
        'слежу за тобой', 'переведи', 'разошлю', 'твои секреты', 'будет хуже', 'я знаю о тебе', 'твоих сотрудников',
        'i have been watching', 'i\'ve been watching', 'been monitoring', 'your enemies', 'pay me', 'i know what you did', 'your secrets', 'or else'
    ]
    threat_count = sum(1 for kw in threat_kw if kw in body_lower)
    if threat_count > 0:
        score = min(0.45, threat_count * 0.15)
        add_finding('threat_language', 'high' if score>=0.4 else 'medium', score, f'Tahdid so\'zlari: {threat_count} marta', ['T1684.001'], 'Matnda tahdid/shantaj kalit so\'zlari topildi.')

    # Crypto Wallets
    btc_match = re.findall(r'\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b', body_text)
    eth_match = re.findall(r'\b0x[a-fA-F0-9]{40}\b', body_text)
    xmr_match = re.findall(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b', body_text)
    tron_match = re.findall(r'\bT[A-Za-z1-9]{33}\b', body_text)
    
    wallets = []
    if btc_match: wallets.extend(btc_match)
    if eth_match: wallets.extend(eth_match)
    if xmr_match: wallets.extend(xmr_match)
    if tron_match: wallets.extend(tron_match)
    
    if wallets:
        add_finding('crypto_wallet', 'high', 0.4, wallets[0], [], 'Matnda kriptovalyuta hamyon manzili topildi.')
        for w in wallets:
            out_iocs.append({'type': 'wallet', 'value': w})

    # Attribution
    attribution = {
        'origin_ip': None,
        'origin_host': None,
        'hops': [],
        'sender_tz': None,
        'server_tz': None,
        'tz_mismatch': False,
        'anonymous_mailer': None,
        'x_mailer': headers.get('x_mailer'),
        'spam_verdict': headers.get('x_spam_status'),
        'notes': []
    }
    
    date_hdr = headers.get('date', '')
    sender_tz_match = re.search(r'([+-]\d{4}|UTC|GMT)', date_hdr)
    if sender_tz_match:
        attribution['sender_tz'] = sender_tz_match.group(1)
        
    for rcv in parsed.get('received', []):
        raw = rcv.get('raw', '')
        ip = rcv.get('ip')
        ts = rcv.get('ts', '')
        
        # Received sintaksisi: "from HELO (rDNS [ip]) by RECV-HOST ..."
        # rDNS qavs ichida bo'lsa u ishonchliroq — HELO ni jo'natuvchi o'zi tanlaydi
        # (masalan "authenticated-user"), rDNS ni esa qabul qiluvchi server yozadi.
        host = ''
        # "Received: by <host> (...)" — lokal topshirish, "from" qismi yo'q.
        # Qavs ichidagi "from userid 1001" ni host deb olmaslik uchun
        # sarlavha "from" bilan boshlanganidagina from-qismi o'qiladi.
        if re.match(r'^\s*from\s', raw, re.I):
            rdns_m = re.search(r'^\s*from\s+\S+\s+\(([^\s()]+)\s*\[', raw, re.I)
            if rdns_m:
                host = rdns_m.group(1)
            else:
                hm = re.match(r'^\s*from\s+([^\s;()]+)', raw, re.I)
                if hm and hm.group(1).lower() not in ('unknown', 'localhost'):
                    host = hm.group(1)
        if not host:
            bm = re.search(r'\bby\s+([^\s;()]+)', raw, re.I)
            if bm: host = bm.group(1)
        
        tz = ''
        tzm = re.search(r'([+-]\d{4}|UTC|GMT)', ts)
        if tzm: tz = tzm.group(1)
        
        attribution['hops'].append({
            'host': host,
            'ip': ip,
            'ts': ts,
            'tz': tz
        })
        
        from bluekit.netutil import is_external_ip
        if ip and is_external_ip(ip):
            if not attribution['origin_ip']:
                attribution['origin_ip'] = ip
                attribution['origin_host'] = host
                
        if tz and not attribution['server_tz']:
            attribution['server_tz'] = tz

    if attribution['sender_tz'] and attribution['server_tz'] and attribution['sender_tz'] != attribution['server_tz']:
        attribution['tz_mismatch'] = True
        attribution['notes'].append(f"Muallif mijozi {attribution['sender_tz']} vaqt mintaqasini e'lon qilgan, qabul qiluvchi server esa {attribution['server_tz']} — jo'natuvchi boshqa mintaqada bo'lishi mumkin.")
        add_finding('tz_mismatch', 'low', 0.1, f"Sender: {attribution['sender_tz']}, Server: {attribution['server_tz']}", [], 'Date offseti birinchi server hop offsetidan farq qiladi.')
        
    if not headers.get('subject'):
        add_finding('no_subject', 'low', 0.1, '', [], 'Subject bo\'sh yoki yo\'q.')
        
    if len(from_display) > 0 and len(from_display) <= 2:
        add_finding('sender_display_minimal', 'low', 0.1, from_display, [], 'Display name juda qisqa.')
        
    anon_mailers = brands_data.get('anonymous_mailers', [])
    anon_found = None
    for am in anon_mailers:
        if am in from_domain.lower() or (attribution['origin_host'] and am in attribution['origin_host'].lower()) or am in body_lower:
            anon_found = am
            break
            
    if anon_found:
        attribution['anonymous_mailer'] = anon_found
        if anon_found in ['protonmail.com', 'tutanota.com']:
            attribution['notes'].append("Maxfiylikka yo'naltirilgan xizmat.")
            add_finding('anonymous_mailer', 'low', 0.15, anon_found, ['T1585.002'], "Maxfiylikka yo'naltirilgan elektron pochta xizmati.")
        else:
            attribution['notes'].append("Xat anonim remailer orqali yuborilgan: haqiqiy jo'natuvchi yashirilgan.")
            add_finding('anonymous_mailer', 'medium', 0.3, anon_found, ['T1585.002'], "Jo'natuvchi domeni yoki origin host anonim/disposable mail xizmati.")
    # Aggregate Score and Verdict
    total_score = round(min(1.0, sum(f["score"] for f in findings)), 2)
    
    is_threat = False
    for f in findings:
        if f['check'] in ['threat_language', 'crypto_wallet']:
            is_threat = True
            break
            
    if is_threat and total_score >= 0.3:
        verdict = "THREAT"
    elif total_score >= 0.6:
        verdict = "PHISHING"
    elif total_score >= 0.3:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

        
    # Severity fixup
    for f in findings:
        if f["score"] >= 0.4:
            f["severity"] = "high"
        elif f["score"] >= 0.2:
            f["severity"] = "medium"
        else:
            f["severity"] = "low"
            
    # Distinct URLs by defanged url string
    dedup_urls = []
    seen = set()
    for u in out_urls:
        if u["url_defanged"] not in seen:
            seen.add(u["url_defanged"])
            dedup_urls.append(u)

    # validate KB if present
    if kb is not None:
        techniques_used = set()
        for f in findings:
            techniques_used.update(f.get("techniques", []))
        if techniques_used:
            try:
                res = kb.validate(list(techniques_used))
                for r in res:
                    if r["status"] != "active":
                        print(f"WARNING: Technique {r['input']} is {r['status']}")
            except:
                pass

    return {
        "file": parsed.get("file", ""),
        "verdict": verdict,
        "score": total_score,
        "headers": headers,
        "findings": findings,
        "urls": dedup_urls,
        "attachments": out_attachments,
        "iocs": out_iocs,
        "attribution": attribution
    }
