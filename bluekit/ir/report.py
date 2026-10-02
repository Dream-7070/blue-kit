import json
from datetime import datetime, timezone
from typing import Dict, Any, List
from bluekit.ir.models import AttackChain, IncidentReportModel
from bluekit.ir.explain import explain_stage_uz
from bluekit.tz import TZ_LABEL, TZ_LABEL_RU, TZ_LABEL_EN


def defang_ip(ip: str) -> str:
    if not ip: return ""
    parts = ip.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}[.]{parts[3]}"
    return ip

def defang_domain(d: str) -> str:
    if not d: return ""
    return d.replace('.', '[.]')

def build_incident_model(chain: AttackChain, source_name: str, total_events: int) -> IncidentReportModel:
    case_id = f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d')}-01"
    
    # Assess severity
    phases = set(s.phase for s in chain.stages)
    if 'Exfiltration' in phases or 'Privilege Escalation' in phases:
        severity = "CRITICAL"
        conf = 98
    elif 'Lateral Movement' in phases or 'Persistence' in phases or 'Command and Control' in phases:
        # Tasdiqlangan C2 kanali — kamida HIGH: hujumchi hostni masofadan boshqara oladi
        severity = "HIGH"
        conf = 90
    else:
        severity = "MEDIUM"
        conf = 80

    # Sarlavha zanjirdagi HAQIQIY fazalardan quriladi (oldin CTF namunasi qattiq yozilgan edi)
    _phase_order = ["Reconnaissance", "Initial Access", "Execution", "Defense Evasion",
                    "Persistence", "Privilege Escalation", "Credential Access",
                    "Discovery", "Lateral Movement", "Collection", "Command and Control",
                    "Exfiltration", "Impact"]
    _seen = []
    for _ph in _phase_order:
        for _st in chain.stages:
            if _ph in (_st.phase or ""):
                if _ph not in _seen:
                    _seen.append(_ph)
                break
    _hostn = len(set(s.host for s in chain.stages if s.host))
    if _seen:
        title = " \u2192 ".join(_seen) + f" ({_hostn} ta host)"
    else:
        title = f"Aniqlangan shubhali faoliyat ({_hostn} ta host)"
    
    for s in chain.stages:
        s.explain_uz = explain_stage_uz(s)
    
    # Build MITRE summary
    mitre_map = {}
    for s in chain.stages:
        t_id = s.technique_id
        if t_id not in mitre_map:
            mitre_map[t_id] = {
                "technique_id": t_id,
                "technique_name": s.technique_name,
                "phase": s.phase,
                "status": s.status,
                "occurrences": 1,
                "sample_evidence": s.evidence,
                "host": s.host
            }
        else:
            mitre_map[t_id]["occurrences"] += 1

    kb = None
    for edge in getattr(chain, 'lateral_edges', []) or []:
        if edge.get('status', 'CONFIRMED') != 'CONFIRMED':
            continue
        src = edge.get('src_host') or '?'
        dst = edge.get('dst_host') or '?'
        meth = edge.get('method')
        usr = edge.get('user')
        ev_parts = []
        if meth: ev_parts.append(meth)
        if usr: ev_parts.append(usr)
        ev_inner = ", ".join(ev_parts)
        ev_str = f"{src} → {dst} ({ev_inner})" if ev_inner else f"{src} → {dst}"
        
        for t in edge.get('techniques') or []:
            if t in mitre_map:
                mitre_map[t]["occurrences"] += 1
            else:
                if kb is None:
                    try:
                        from bluekit.kb.query import KB
                        kb = KB()
                    except Exception:
                        pass
                
                t_name = t
                t_phase = "Lateral Movement"
                if kb:
                    try:
                        res = kb.lookup(t)
                        if res:
                            t_name = res[0].get('name', t)
                            tactics = res[0].get('tactics') or []
                            if tactics:
                                t_phase = " ".join(w.capitalize() for w in tactics[0].split('-'))
                    except Exception:
                        pass
                        
                mitre_map[t] = {
                    "technique_id": t,
                    "technique_name": t_name,
                    "phase": t_phase,
                    "status": "CONFIRMED",
                    "occurrences": 1,
                    "sample_evidence": ev_str,
                    "host": dst
                }

    # Extract all unique IOCs
    iocs_list = []
    seen_iocs = set()
    
    for ip in chain.attacker_ips:
        key = ('ip_attacker', ip)
        if key not in seen_iocs:
            seen_iocs.add(key)
            iocs_list.append({
                "value": defang_ip(ip),
                "raw_value": ip,
                "type": "IPv4",
                "role": "Attacker / C2",
                "description": "Tashqi manzil — hujumchi/C2 sifatida aniqlangan (dalil: zanjir bosqichlari)"
            })
            
    for ip in chain.exfiltration_ips:
        key = ('ip_exfil', ip)
        if key not in seen_iocs:
            seen_iocs.add(key)
            iocs_list.append({
                "value": defang_ip(ip),
                "raw_value": ip,
                "type": "IPv4",
                "role": "Exfiltration Destination",
                "description": "Tashqi manzil — chiquvchi ma'lumot yo'nalishi sifatida aniqlangan"
            })

    for s in chain.stages:
        ioc_dict = s.iocs
        for k, v in ioc_dict.items():
            if v in (None, ''):
                continue
            if k in ('cmd', 'fuzz_count', 'status', 'user', 'query'):
                continue
            val_str = str(v)
            if not val_str or len(val_str) > 120:
                continue
            key = (k, val_str)
            if key not in seen_iocs:
                seen_iocs.add(key)
                iocs_list.append({
                    "value": val_str,
                    "raw_value": val_str,
                    "type": k,
                    "role": s.phase,
                    "description": f"Observed in {s.technique_id} ({s.host})"
                })

    backdoor_users = set(s.iocs.get('created_user') for s in chain.stages if s.technique_id == 'T1136.001' and 'created_user' in s.iocs)
    for u in chain.compromised_users:
        key = ('user', u)
        if key not in seen_iocs:
            seen_iocs.add(key)
            role = "Backdoor Account" if u in backdoor_users else "Compromised Account"
            iocs_list.append({
                "value": u,
                "raw_value": u,
                "type": "Account",
                "role": role,
                "description": f"User account leveraged during attack"
            })

    # Missing evidence checklist
    import re
    missing_evidence = []
    _c2_hosts = sorted(set(s.host for s in chain.stages if s.phase and ('C2' in s.phase or 'Execution' in s.phase)))
    for h in _c2_hosts:
        if h: missing_evidence.append(f"Memory (RAM) snapshot of {h}.")
        
    _pcap_ips = sorted(list(set(chain.attacker_ips + chain.exfiltration_ips)))
    for ip in _pcap_ips:
        missing_evidence.append(f"PCAP / firewall logs for traffic to {ip}.")

    _file_paths = []
    for s in chain.stages:
        for k in ['archive_file', 'target_key', 'key', 'target_file', 'uri', 'path']:
            if k in s.iocs and s.iocs[k]:
                if s.iocs[k] not in _file_paths: _file_paths.append(s.iocs[k])
        matches = re.findall(r"(?:/tmp|/var/tmp|/dev/shm)/[^\s'\";|&>]+", s.evidence)
        for m in matches:
            if m not in _file_paths: _file_paths.append(m)
    if _file_paths:
        missing_evidence.append("Copies of files for hashing: " + ", ".join(_file_paths[:10]))
        
    _t1005_hosts = sorted(set(s.host for s in chain.stages if s.technique_id == 'T1005'))
    for h in _t1005_hosts:
        if h: missing_evidence.append(f"Database / application logs on {h} to measure data exposure.")

    # Incident Response Recommendations
    recommendations = {"containment": [], "eradication": [], "recovery": []}
    
    if chain.hosts_involved:
        recommendations["containment"].append(f"Isolate affected hosts from the network: {', '.join(chain.hosts_involved)}.")
    if chain.attacker_ips:
        recommendations["containment"].append(f"Block attacker / C2 IPs on perimeter firewalls: {', '.join(chain.attacker_ips)}.")
    if chain.exfiltration_ips:
        recommendations["containment"].append(f"Block exfiltration destinations: {', '.join(chain.exfiltration_ips)}.")
        
    for s in chain.stages:
        if s.technique_id and s.technique_id.startswith('T1059') and 'attacker_ip' in s.iocs:
            a_ip = s.iocs['attacker_ip']
            pt = f":{s.iocs['port']}" if s.iocs.get('port') else ""
            recommendations["containment"].append(f"Kill the process holding a connection to {a_ip}{pt} on {s.host}.")
            
    _erad = []
    for s in chain.stages:
        tid = s.technique_id
        h = s.host
        if tid == 'T1505.003':
            v = s.iocs.get('uri') or s.iocs.get('path')
            _erad.append(f"Remove web shell {v} on {h}." if v else f"Remove web shell on {h}.")
        elif tid == 'T1053.003':
            ev = s.evidence[:100]
            _erad.append(f"Review and clean crontab / cron files on {h} (evidence: {ev}).")
        elif tid == 'T1136.001' and 'created_user' in s.iocs:
            _erad.append(f"Delete unauthorized account '{s.iocs['created_user']}' on {h}.")
        elif tid in ('T1552.004', 'T1021.004'):
            k = s.iocs.get('target_key') or s.iocs.get('key')
            kp = f" ({k})" if k else ""
            _erad.append(f"Rotate SSH keys used on {h}{kp}.")
        elif tid == 'T1190':
            p = s.iocs.get('path')
            if p:
                _erad.append(f"Patch the exploited endpoint {p} on {h}.")
            else:
                _erad.append(f"Patch the exploited endpoint on {h}.")
        elif tid == 'T1003.008':
            _erad.append(f"Reset passwords of all local accounts on {h} (/etc/shadow was read).")
            
    for x in _erad:
        if x not in recommendations["eradication"]: recommendations["eradication"].append(x)
        
    if chain.compromised_users:
        recommendations["recovery"].append(f"Reset credentials of accounts: {', '.join(chain.compromised_users)}.")
    
    _rec_hosts = sorted(set(s.host for s in chain.stages if s.technique_id in ('T1005', 'T1560.001')))
    for h in _rec_hosts:
        if h: recommendations["recovery"].append(f"Verify integrity of data on {h} against a known-good backup.")
        
    recommendations["recovery"].append("Monitor the listed IOCs for recurrence after recovery.")

    return IncidentReportModel(
        case_id=case_id,
        title=title,
        severity=severity,
        confidence_pct=conf,
        status="confirmed",
        hosts=chain.hosts_involved,
        accounts=chain.compromised_users,
        period_start=chain.start_time,
        period_end=chain.end_time,
        period_start_display=chain.stages[0].timestamp_display if chain.stages else "",
        period_end_display=chain.stages[-1].timestamp_display if chain.stages else "",
        source_name=source_name,
        total_events_processed=total_events,
        chain=chain,
        mitre_summary=list(mitre_map.values()),
        all_iocs=iocs_list,
        missing_evidence=missing_evidence,
        recommendations=recommendations
    )

def render_scoring_json(model: IncidentReportModel) -> str:
    """Produces clean machine-readable JSON for competition automated scoring."""
    scoring_data = {
        "case_id": model.case_id,
        "title": model.title,
        "verdict": "CONFIRMED_BREACH",
        "severity": model.severity,
        "confidence_score": f"{model.confidence_pct}%",
        "time_window": {
            "start": model.period_start,
            "end": model.period_end
        },
        "attacker_ips": model.chain.attacker_ips,
        "exfiltration_ips": model.chain.exfiltration_ips,
        "compromised_hosts": model.hosts,
        "compromised_accounts": model.accounts,
        "mitre_attack_techniques": [
            {
                "technique_id": m["technique_id"],
                "technique_name": m["technique_name"],
                "phase": m["phase"],
                "status": m["status"],
                "occurrences": m["occurrences"]
            }
            for m in model.mitre_summary
        ],
        "attack_chain_timeline": [
            {
                "step": idx,
                "timestamp": s.timestamp,
                "host": s.host,
                "phase": s.phase,
                "mitre_id": s.technique_id,
                "mitre_name": s.technique_name,
                "evidence": s.evidence,
                "explain_uz": getattr(s, 'explain_uz', ''),
                "iocs": s.iocs
            }
            for idx, s in enumerate(model.chain.stages, 1)
        ],
        "extracted_iocs": model.all_iocs,
        "lateral_movement": [
            {
                k: v for k, v in edge.items() 
                if k in ("src_host","dst_host","user","method","techniques","first_seen","status")
            }
            for edge in getattr(model.chain, 'lateral_edges', [])
        ],
        "attack_path": getattr(model.chain, 'attack_path', []),
        "scoring_hash_metadata": {
            "source_file": model.source_name,
            "total_events_analyzed": model.total_events_processed,
            "stages_count": len(model.chain.stages)
        }
    }
    return json.dumps(scoring_data, indent=2)

def _lateral_md(model: IncidentReportModel, lang: str) -> str:
    try:
        from bluekit.ir.lateral import edges_mermaid
        mermaid_fn = edges_mermaid
    except Exception:
        mermaid_fn = lambda x: ""
        
    edges = getattr(model.chain, 'lateral_edges', [])
    path = getattr(model.chain, 'attack_path', [])
    
    if lang == 'uz':
        title = "### Hostdan hostga o'tish (Lateral Movement)"
        path_prefix = "**Hujum yo'li:**"
        empty_msg = "Hostdan hostga o'tish aniqlanmadi."
        headers = ["#", "Vaqt", "Dan", "Ga", "Akkaunt", "Usul", "MITRE", "Holat"]
    elif lang == 'ru':
        title = "### Перемещение между хостами (Lateral Movement)"
        path_prefix = "**Путь атаки:**"
        empty_msg = "Перемещение между хостами не обнаружено."
        headers = ["#", "Время", "Откуда", "Куда", "Аккаунт", "Метод", "MITRE", "Статус"]
    else:
        title = "### Lateral Movement (host to host)"
        path_prefix = "**Attack path:**"
        empty_msg = "No host-to-host movement detected."
        headers = ["#", "Time", "From", "To", "Account", "Method", "MITRE", "Status"]

    if not edges:
        return f"{title}\n{empty_msg}\n\n"
        
    md = [title]
    if path:
        md.append(f"{path_prefix} {' → '.join(path)}\n")
        
    md.append("| " + " | ".join(headers) + " |")
    md.append("| " + " | ".join(["---"] * len(headers)) + " |")
    
    for idx, e in enumerate(edges, 1):
        ts = e.get('first_seen_display') or e.get('first_seen', '')[:19]
        src = e.get('src_host') or '?'
        dst = e.get('dst_host') or '?'
        usr = e.get('user') or ''
        meth = e.get('method') or ''
        if e.get('count', 1) > 1:
            meth = f"{meth} (x{e['count']})"
        techs = ", ".join(e.get('techniques', []))
        status = e.get('status') or ''
        row = [str(idx), ts, src, dst, usr, meth, techs, status]
        row = [str(x).replace('|', r'\|') for x in row]
        md.append("| " + " | ".join(row) + " |")
        
    md.append("\n```mermaid\n" + mermaid_fn(edges) + "\n```\n")
    return "\n".join(md)

def render_markdown_report(model: IncidentReportModel, lang: str = "ru") -> str:
    """Produces the formal Incident Response report in standard template format."""
    if lang == "ru":
        return _render_ru(model)
    elif lang == "uz":
        return _render_uz(model)
    return _render_en(model)

def _render_ru(model: IncidentReportModel) -> str:
    hosts_str = ", ".join(f"`{h}`" for h in model.hosts)
    accounts_str = ", ".join(f"`{a}`" for a in model.accounts)
    
    _phases = []
    for _st in model.chain.stages:
        if _st.phase and _st.phase not in _phases:
            _phases.append(_st.phase)
    _techs = []
    for _st in model.chain.stages:
        _t = f"{_st.technique_id}"
        if _t not in _techs:
            _techs.append(_t)
    _hosts_s = ", ".join(f"`{h}`" for h in model.hosts) if model.hosts else "неизвестно"
    _c2 = defang_ip(model.chain.attacker_ips[0]) if model.chain.attacker_ips else None
    
    _parts = []
    _parts.append(f"\U0001F534 **ПОДТВЕРЖДЕНО ({model.severity}):** Выявлена подозрительная активность на {len(model.hosts)} хостах.")
    if _c2:
        _parts.append(f"Внешний адрес: **{_c2}**.")
    _parts.append("Зафиксированные фазы: " + ", ".join(_phases) + ".")
    _parts.append("MITRE ATT&CK: " + ", ".join(_techs) + ".")
    _parts.append(f"Затронутые хосты: {_hosts_s}.")
    _parts.append("")
    _parts.append("> Данное резюме основано только на проанализированных логах. Неохваченные фазы следует исследовать отдельно.")
    ru_summary = " ".join(_parts[:-2]) + "\n\n" + _parts[-1]

    qa_map = {}
    for _st in model.chain.stages:
        if _st.phase:
            if _st.phase not in qa_map:
                qa_map[_st.phase] = set()
            qa_map[_st.phase].add(_st.technique_name)
    qa_md = "\n".join(f"- {_ph} — **SUPPORTED** ({', '.join(sorted(qa_map[_ph]))})" for _ph in _phases)
    if not qa_md:
        qa_md = "- —"

    stages_md = []
    for idx, s in enumerate(model.chain.stages, 1):
        ts = s.timestamp_display or s.timestamp[:19].replace('T', ' ')
        stages_md.append(f"**{idx}. [{ts}]** — 🟢 `[{s.host}]` **{s.phase}:** {s.evidence} `[{s.technique_id}]`")

    mitre_md = []
    for m in model.mitre_summary:
        icon = "🟢 ПОДТВЕРЖДЕНО" if m["status"] == "CONFIRMED" else "🟡 ВЕРОЯТНО"
        mitre_md.append(f"- **{m['technique_id']} — {m['technique_name']}** — {icon}: {m['sample_evidence'][:110]}")

    iocs_md = []
    for i in model.all_iocs:
        iocs_md.append(f"- **`{i['value']}`** `[{i['type']}]` — {i['role']}: {i['description']}")

    missing_md = "\n".join(f"- {item}" for item in model.missing_evidence) or "- —"
    cont_md = "\n".join(f"- {item}" for item in model.recommendations["containment"]) or "- —"
    erad_md = "\n".join(f"- {item}" for item in model.recommendations["eradication"]) or "- —"
    recov_md = "\n".join(f"- {item}" for item in model.recommendations["recovery"]) or "- —"
    
    p_start = model.period_start_display or model.period_start[:19].replace('T', ' ')
    p_end = model.period_end_display or model.period_end[:19].replace('T', ' ')

    return f"""# Отчёт об инциденте {model.case_id}

### Паспорт
- **Название:** {model.title}
- **Статус:** {model.status}
- **Severity:** {model.severity}
- **Общая уверенность:** {model.confidence_pct}%
- **Хосты:** {hosts_str}
- **Учётные записи:** {accounts_str}
- **Период событий:** {p_start} – {p_end}
- **Источник:** `{model.source_name}`
- **Покрытие:** {model.total_events_processed} событий; ошибок парсинга — 0, обнаружено звеньев цепи атаки — {len(model.chain.stages)}

---

### Резюме
{ru_summary}

---

### Цепочка атаки (время как в логах)
{chr(10).join(stages_md)}

---

{_lateral_md(model, 'ru')}
---

### MITRE ATT&CK Mapping
{chr(10).join(mitre_md)}

---

### IOC и артефакты
{chr(10).join(iocs_md)}

---

### Недостающие улики
{missing_md}

---

### Рекомендации
#### Сдерживание (Containment)
{cont_md}

#### Устранение (Eradication)
{erad_md}

#### Восстановление (Recovery)
{recov_md}

---

### QA выводов
{qa_md}
"""

def _render_uz(model: IncidentReportModel) -> str:
    hosts_str = ", ".join(f"`{h}`" for h in model.hosts)
    accounts_str = ", ".join(f"`{a}`" for a in model.accounts)
    
    # --- Executive summary faktlardan quriladi ---
    _phases = []
    for _st in model.chain.stages:
        if _st.phase and _st.phase not in _phases:
            _phases.append(_st.phase)
    _techs = []
    for _st in model.chain.stages:
        _t = f"{_st.technique_id}"
        if _t not in _techs:
            _techs.append(_t)
    _hosts_s = ", ".join(f"`{h}`" for h in model.hosts) if model.hosts else "aniqlanmagan"
    _c2 = defang_ip(model.chain.attacker_ips[0]) if model.chain.attacker_ips else None
    _dom = None
    for _i in model.all_iocs:
        if _i.get("type") in ("domain", "url") and not _dom:
            _dom = str(_i.get("value", ""))
    _parts = []
    _parts.append(f"🔴 **TASDIQLANGAN ({model.severity}):** {len(model.hosts)} ta host bo'yicha shubhali faoliyat aniqlandi.")
    if _c2:
        _parts.append(f"Tashqi manzil: **{_c2}**" + (f" ({_dom})" if _dom else "") + ".")
    _parts.append("Kuzatilgan bosqichlar: " + ", ".join(_phases) + ".")
    _parts.append("MITRE ATT&CK: " + ", ".join(_techs) + ".")
    _parts.append(f"Jabrlangan hostlar: {_hosts_s}.")
    _parts.append("")
    _parts.append("> Ushbu xulosa faqat tahlil qilingan loglardagi dalillarga asoslanadi. "
                  "Loglar qamrab olmagan bosqichlar (dastlabki kirish yo'li, persistensiya mexanizmi, "
                  "ma'lumot sizishi hajmi) alohida tekshirilishi kerak.")
    uz_summary = " ".join(_parts[:-2]) + "\n\n" + _parts[-1]

    stages_md = []
    for idx, s in enumerate(model.chain.stages, 1):
        ts = s.timestamp_display or s.timestamp[:19].replace('T', ' ')
        stages_md.append(f"**{idx}. [{ts}]** — 🟢 `[{s.host}]` **{s.phase}:** {s.evidence} `[{s.technique_id}]`\n   > *{s.explain_uz}*")

    mitre_md = []
    for m in model.mitre_summary:
        icon = "🟢 TASDIQLANGAN" if m["status"] == "CONFIRMED" else "🟡 EHTIMOLI YUQORI"
        mitre_md.append(f"- **{m['technique_id']} — {m['technique_name']}** — {icon}: {m['sample_evidence'][:110]}")

    iocs_md = []
    for i in model.all_iocs:
        iocs_md.append(f"- **`{i['value']}`** `[{i['type']}]` — {i['role']}: {i['description']}")

    p_start = model.period_start_display or model.period_start[:19].replace('T', ' ')
    p_end = model.period_end_display or model.period_end[:19].replace('T', ' ')

    return f"""# Hodisa Hisoboti {model.case_id}

### Pasport
- **Nomi:** {model.title}
- **Holati:** {model.status}
- **Xavflilik darajasi (Severity):** {model.severity}
- **Ishonchlilik darajasi:** {model.confidence_pct}%
- **Jabrlangan hostlar:** {hosts_str}
- **Foydalanuvchi hisoblari:** {accounts_str}
- **Vaqt oralig'i:** {p_start} – {p_end}
- **Manba:** `{model.source_name}`
- **Tahlil qilingan loglar soni:** {model.total_events_processed} ta, aniqlangan hujum zanjiri qadamlari: {len(model.chain.stages)} ta

---

### Qisqacha Xulosa (Executive Summary)
{uz_summary}

---

### Hujum Zanjiri (vaqtlar logdagi kabi)
{chr(10).join(stages_md)}

---

{_lateral_md(model, 'uz')}
---

### MITRE ATT&CK Xaritasi
{chr(10).join(mitre_md)}

---

### IOC va Artefaktlar
{chr(10).join(iocs_md)}
"""

def _render_en(model: IncidentReportModel) -> str:
    hosts_str = ", ".join(f"`{h}`" for h in model.hosts)
    accounts_str = ", ".join(f"`{a}`" for a in model.accounts)
    
    _phases = []
    for _st in model.chain.stages:
        if _st.phase and _st.phase not in _phases:
            _phases.append(_st.phase)
    _techs = []
    for _st in model.chain.stages:
        _t = f"{_st.technique_id}"
        if _t not in _techs:
            _techs.append(_t)
    _hosts_s = ", ".join(f"`{h}`" for h in model.hosts) if model.hosts else "unknown"
    _c2 = defang_ip(model.chain.attacker_ips[0]) if model.chain.attacker_ips else None
    
    _parts = []
    _parts.append(f"\U0001F534 **CONFIRMED ({model.severity}):** Suspicious activity detected across {len(model.hosts)} hosts.")
    if _c2:
        _parts.append(f"External address: **{_c2}**.")
    _parts.append("Observed phases: " + ", ".join(_phases) + ".")
    _parts.append("MITRE ATT&CK: " + ", ".join(_techs) + ".")
    _parts.append(f"Affected hosts: {_hosts_s}.")
    _parts.append("")
    _parts.append("> This summary is based only on analyzed logs. Uncovered phases should be investigated separately.")
    en_summary = " ".join(_parts[:-2]) + "\n\n" + _parts[-1]

    stages_md = []
    for idx, s in enumerate(model.chain.stages, 1):
        ts = s.timestamp_display or s.timestamp[:19].replace('T', ' ')
        stages_md.append(f"**{idx}. [{ts}]** — 🟢 `[{s.host}]` **{s.phase}:** {s.evidence} `[{s.technique_id}]`")

    mitre_md = []
    for m in model.mitre_summary:
        mitre_md.append(f"- **{m['technique_id']} — {m['technique_name']}** — CONFIRMED: {m['sample_evidence'][:110]}")

    iocs_md = []
    for i in model.all_iocs:
        iocs_md.append(f"- **`{i['value']}`** `[{i['type']}]` — {i['role']}: {i['description']}")

    missing_md = "\n".join(f"- {item}" for item in model.missing_evidence) or "- —"
    cont_md = "\n".join(f"- {item}" for item in model.recommendations["containment"]) or "- —"
    erad_md = "\n".join(f"- {item}" for item in model.recommendations["eradication"]) or "- —"
    recov_md = "\n".join(f"- {item}" for item in model.recommendations["recovery"]) or "- —"

    p_start = model.period_start_display or model.period_start[:19].replace('T', ' ')
    p_end = model.period_end_display or model.period_end[:19].replace('T', ' ')

    return f"""# Incident Report {model.case_id}

### Passport
- **Title:** {model.title}
- **Status:** {model.status}
- **Severity:** {model.severity}
- **Confidence:** {model.confidence_pct}%
- **Hosts:** {hosts_str}
- **Accounts:** {accounts_str}
- **Time Window:** {p_start} – {p_end}
- **Source:** `{model.source_name}`
- **Events Processed:** {model.total_events_processed} events, Attack Chain Stages: {len(model.chain.stages)}

---

### Executive Summary
{en_summary}

---

### Attack Chain (times as in logs)
{chr(10).join(stages_md)}

---

{_lateral_md(model, 'en')}
---

### MITRE ATT&CK Mapping
{chr(10).join(mitre_md)}

---

### IOCs and Artifacts
{chr(10).join(iocs_md)}

---

### Missing Evidence
{missing_md}

---

### Recommendations
#### Containment
{cont_md}

#### Eradication
{erad_md}

#### Recovery
{recov_md}
"""
