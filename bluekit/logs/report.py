import json
import os
import html
from datetime import datetime

def generate_report(events, timeline, chains, iocs, checkers, kb, coverage, out_path):
    html_str = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>blue-kit Report</title>
<style>
body {{ font-family: sans-serif; margin: 20px; color: #333; }}
table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; font-size: 14px; }}
th, td {{ border: 1px solid #ccc; padding: 6px 8px; text-align: left; }}
th {{ background-color: #f5f5f5; }}
.high {{ background-color: #ffcccc; }}
.medium {{ background-color: #ffffcc; }}
.low {{ background-color: #e6f2ff; font-size: 12px; color: #666; }}
.missing {{ color: #999; text-decoration: line-through; }}
.tactic-block {{ margin-bottom: 10px; }}
.chain-block {{ border: 1px solid #ddd; padding: 10px; margin-bottom: 15px; background: #fafafa; }}
.badge {{ display: inline-block; padding: 3px 6px; margin: 2px; border-radius: 3px; font-size: 12px; background: #e0e0e0; }}
input[type=text] {{ padding: 5px; margin-bottom: 10px; width: 200px; }}
</style>
<script>
function filterTimeline() {{
    var host = document.getElementById("filterHost").value.toLowerCase();
    var tech = document.getElementById("filterTech").value.toLowerCase();
    var free = document.getElementById("filterFree").value.toLowerCase();
    var hideLow = document.getElementById("hideLow").checked;
    var trs = document.getElementById("timelineTbl").getElementsByTagName("tr");
    for (var i = 1; i < trs.length; i++) {{
        var row = trs[i];
        var text = row.textContent.toLowerCase();
        var cHost = row.cells[1].textContent.toLowerCase();
        var cTech = row.cells[5].textContent.toLowerCase();
        var cConf = row.cells[6].textContent.toLowerCase();
        var isLow = (cConf === 'low');
        if (cHost.includes(host) && cTech.includes(tech) && text.includes(free) && !(hideLow && isLow)) {{
            row.style.display = "";
        }} else {{
            row.style.display = "none";
        }}
    }}
}}
</script>
</head>
<body>
<h1>blue-kit LOG ANALYZER Report</h1>

<h2>1. Summary</h2>
<ul>
    <li>Events: {len(events)}</li>
    <li>Timespan: {timeline[0]['ts'] if timeline else ''} to {timeline[-1]['ts'] if timeline else ''}</li>
    <li>Hosts: {len(set(e['host'] for e in events if e['host']))}</li>
    <li>Chains: {len(chains)}</li>
</ul>

<h2>2. ATT&CK Coverage</h2>
"""
    for cov in coverage:
        if cov['missing']:
            html_str += f"<div class='tactic-block missing'><b>{html.escape(cov['name'])}</b>: MISSING</div>\n"
        else:
            tech_html = []
            for t in cov['observed']:
                t_info = kb.lookup(t)
                name = t_info[0]['name'] if t_info else ''
                tech_html.append(f"{html.escape(t)} ({html.escape(name)})")
            html_str += f"<div class='tactic-block'><b>{html.escape(cov['name'])}</b>: {', '.join(tech_html)}</div>\n"

    html_str += """
<h2>3. Timeline</h2>
<input type="text" id="filterHost" placeholder="Filter Host..." onkeyup="filterTimeline()">
<input type="text" id="filterTech" placeholder="Filter Technique..." onkeyup="filterTimeline()">
<input type="text" id="filterFree" placeholder="Free text search..." onkeyup="filterTimeline()">
<label><input type="checkbox" id="hideLow" onclick="filterTimeline()"> Hide Low-Confidence</label>
<table id="timelineTbl">
<tr><th>TS</th><th>Host</th><th>User</th><th>Process (Parent &rarr; Child)</th><th>Command</th><th>Technique(s)</th><th>Confidence</th><th>Evidence</th></tr>
"""
    for t in timeline:
        ts_iso = t['ts'].isoformat() if t['ts'] else ''
        ts_disp = t.get('ts_disp') or ts_iso
        cmd = t['command_line'] or ''
        cmd_full = t['command_line_full'] or ''
        proc_str = f"{t['parent_process'] or '?'} &rarr; {t['process'] or '?'}"
        tech = t['primary_technique'] or ''
        conf = t['primary_confidence'] or ''
        cls = conf if conf in ('high', 'medium', 'low') else ''
        
        all_techs = ", ".join(h['technique'] for h in t['techniques'])
        evidence = "<br>".join(html.escape(h.get('evidence','')) for h in t['techniques'])
        
        html_str += f"<tr class='{cls}'><td title='{html.escape(str(ts_iso))}'>{html.escape(str(ts_disp))}</td><td>{html.escape(str(t['host']))}</td><td>{html.escape(str(t['user']))}</td><td>{proc_str}</td><td title='{html.escape(str(cmd_full))}'>{html.escape(str(cmd))}</td><td>{html.escape(all_techs)}</td><td>{html.escape(str(conf))}</td><td>{evidence}</td></tr>\n"
        
    html_str += "</table>\n<h2>4. Chains</h2>\n"
    
    for c in chains:
        html_str += f"<div class='chain-block'><h3>Chain {c['id']} ({html.escape(str(c['host']))} / {html.escape(str(c['user']))})</h3>"
        html_str += f"<p>{c['start']} to {c['end']}</p>"
        html_str += "<div>"
        if not c['tactics']:
            html_str += "<span class='badge'>hujum belgisi yo'q</span>"
        else:
            for tac in c['tactics']:
                html_str += f"<span class='badge'>{html.escape(tac)}</span>"
        html_str += "</div><ul>"
        for idx in c['events']:
            ev = next((t for t in timeline if t['index'] == idx), None)
            if ev:
                html_str += f"<li>{html.escape(str(ev['ts']))} - {html.escape(str(ev['command_line']))} [{ev['primary_technique']}]</li>"
        html_str += "</ul></div>\n"
        
    html_str += "<h2>5. Checker/Beacon Candidates</h2>\n<table><tr><th>Key</th><th>Interval (s)</th><th>Count</th><th>First</th><th>Last</th><th>Evidence</th></tr>\n"
    for chk in checkers:
        f_disp = chk.get('first_disp') or str(chk['first'])
        l_disp = chk.get('last_disp') or str(chk['last'])
        html_str += f"<tr><td>{html.escape(str(chk['key']))}</td><td>{chk['interval_seconds']:.1f}</td><td>{chk['count']}</td><td>{html.escape(f_disp)}</td><td>{html.escape(l_disp)}</td><td>{html.escape(chk['sample_evidence'])}</td></tr>\n"
        
    html_str += "</table>\n<h2>6. IOCs</h2>\n<table><tr><th>Type</th><th>Value</th><th>Count</th><th>First Seen</th><th>Last Seen</th></tr>\n"
    
    grouped_iocs = {}
    for ioc in iocs:
        grouped_iocs.setdefault(ioc['type'], []).append(ioc)
        
    for typ, items in grouped_iocs.items():
        for ioc in items:
            f_disp = ioc.get('first_disp') or str(ioc['first'])
            l_disp = ioc.get('last_disp') or str(ioc['last'])
            html_str += f"<tr><td>{html.escape(typ)}</td><td>{html.escape(str(ioc['value']))}</td><td>{ioc['count']}</td><td>{html.escape(f_disp)}</td><td>{html.escape(l_disp)}</td></tr>\n"
            
    html_str += "</table></body></html>"
    
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(html_str)

def analyze_logs(file_path, kb, preset=None, map_path=None, json_path=None, html_path=None, deep=False, from_dt=None, to_dt=None, host=None):
    from bluekit.logs.parse import load, load_many
    from bluekit.logs.detect import detect_event
    from bluekit.logs.timeline import build
    from bluekit.logs.filter import filter_events, describe
    
    is_list = isinstance(file_path, list)
    if is_list:
        events = load_many(file_path, preset=preset, map_path=map_path)
    else:
        events = load(file_path, preset=preset, map_path=map_path)
        
    loaded_count = len(events)
    filt = describe(from_dt, to_dt, host)
    if filt:
        events = filter_events(events, from_dt, to_dt, host)
        
    hits_by_index = {}
    
    suppressed_by_noise = 0
    events_with_hits = 0
    
    source_stats = {}
    
    for i, ev in enumerate(events):
        hits = detect_event(kb, ev, deep=deep)
        src = ev.get('source')
        if src and src not in source_stats:
            source_stats[src] = {'events': 0, 'events_with_hits': 0}
        if src:
            source_stats[src]['events'] += 1
            
        if hits:
            hits_by_index[i] = hits
            events_with_hits += 1
            if src:
                source_stats[src]['events_with_hits'] += 1
                
        if ev.get('_noise_suppressed'):
            suppressed_by_noise += 1
                
    from bluekit.logs.bruteforce import correlate_bruteforce
    bruteforce = correlate_bruteforce(events, hits_by_index)
    
    timeline, chains, iocs, checkers = build(events, hits_by_index, kb)
    
    all_techs = set()
    tech_counts = {}
    for t_item in timeline:
        for h in t_item['techniques']:
            tech = h['technique']
            conf = h['confidence']
            if tech not in tech_counts:
                tech_counts[tech] = {'high': 0, 'medium': 0, 'low': 0}
            tech_counts[tech][conf] = tech_counts[tech].get(conf, 0) + 1
            if conf in ('high', 'medium'):
                all_techs.add(tech)
    
    coverage = kb.tactic_coverage(list(all_techs), domain='enterprise')
    
    if json_path:
        with open(json_path, 'w', encoding='utf-8') as f:
            def default(o):
                if isinstance(o, datetime): return o.isoformat()
                return str(o)
            import bluekit.tz
            
            # Helper: timedelta to +HH:MM
            def td_to_str(td):
                return bluekit.tz.fmt_offset(td)

            out_data = {
                'timeline': timeline, 'chains': chains, 'iocs': iocs,
                'coverage': coverage, 'checkers': checkers,
                'bruteforce': bruteforce,
                'stats': {
                    'events': len(events),
                    'events_with_hits': events_with_hits,
                    'suppressed_by_noise': suppressed_by_noise,
                    'deep': deep,
                    'tz': "+05:00",
                    'src_tz': td_to_str(bluekit.tz.get_naive_tz())
                }
            }
            if filt:
                out_data['stats']['filter'] = {
                    'from': from_dt.isoformat() if from_dt else None,
                    'to': to_dt.isoformat() if to_dt else None,
                    'host': host if host else None,
                    'loaded': loaded_count
                }
            if is_list:
                out_data['stats']['sources'] = source_stats
            json.dump(out_data, f, default=default, indent=2)
            
    if html_path:
        generate_report(events, timeline, chains, iocs, checkers, kb, coverage, html_path)
        
    hosts = list(set([e['host'] for e in events if e['host']]))
    first_ts = timeline[0].get('ts_disp') if timeline and timeline[0].get('ts_disp') else (timeline[0]['ts'] if timeline and timeline[0]['ts'] else 'N/A')
    last_ts = timeline[-1].get('ts_disp') if timeline and timeline[-1].get('ts_disp') else (timeline[-1]['ts'] if timeline and timeline[-1]['ts'] else 'N/A')
    
    if filt:
        has_time = from_dt is not None or to_dt is not None
        print(f"Filtr: {filt}{' (Toshkent)' if has_time else ''} -> {len(events)}/{loaded_count} hodisa")
        if len(events) == 0:
            if has_time:
                print("Diqqat: filtrdan keyin hodisa qolmadi. --from/--to vaqtlari Toshkent (UTC+5) da; --src-tz ni tekshiring.")
            else:
                print("Diqqat: filtrdan keyin hodisa qolmadi. --host nomi logdagi bilan aynan mos bo'lishi kerak (katta-kichik harf farqi yo'q).")
            
    print(f"Events: {len(events)} | Timespan: {first_ts} .. {last_ts} | Hosts: {len(hosts)} ({', '.join(hosts)}) | Chains: {len(chains)}")
    
    if is_list:
        for src, st in sorted(source_stats.items()):
            print(f"  Source {src}: {st['events']} events, {st['events_with_hits']} with hits")
            
    if suppressed_by_noise > 0:
        print(f"Noise suppressed: {suppressed_by_noise} events")
    
    total_high = sum(counts.get('high', 0) for counts in tech_counts.values())
    total_med = sum(counts.get('medium', 0) for counts in tech_counts.values())
    print(f"\nTotals: {total_high} high, {total_med} medium")
    
    print("\nTop 15 techniques:")
    valid_techs = [(t, counts) for t, counts in tech_counts.items() if counts.get('high', 0) > 0 or counts.get('medium', 0) > 0]
    sorted_techs = sorted(valid_techs, key=lambda x: (x[1].get('high', 0), x[1].get('medium', 0), x[0]), reverse=True)[:15]
    for t, counts in sorted_techs:
        tinfo = kb.lookup(t)
        name = tinfo[0]['name'] if tinfo else ''
        tactic = ','.join(tinfo[0].get('tactics',[])) if tinfo else ''
        print(f"  {t} | {name} | high:{counts.get('high', 0)} med:{counts.get('medium', 0)} | {tactic}")
        
    if bruteforce:
        print("\nBrute-force (4625 agregatsiyasi):")
        for b in bruteforce:
            t_first = b.get('first_disp') or (b['first'].strftime('%m-%d %H:%M:%S') if isinstance(b['first'], datetime) else str(b['first']))
            t_last = b.get('last_disp') or (b['last'].strftime('%m-%d %H:%M:%S') if isinstance(b['last'], datetime) else str(b['last']))
            accs = b['accounts']
            if len(accs) > 3:
                acc_str = f"[{', '.join(accs[:3])} +{len(accs)-3}]"
            else:
                acc_str = f"[{', '.join(accs)}]"
            if b['success']:
                s_time = b.get('success_disp') or (b['success_ts'].strftime('%m-%d %H:%M:%S') if isinstance(b['success_ts'], datetime) else str(b['success_ts']))
                s_str = f"MUVAFFAQIYATLI {s_time} ({b['success_account']})"
            else:
                s_str = "muvaffaqiyat yo'q"
            print(f"  {b['source']} -> {b['host']} {acc_str}: {b['failures']} ta 4625 ({t_first} .. {t_last}) {b['technique']} {b['name']} | {s_str}")
            
    covered = sum(1 for c in coverage if not c['missing'])
    print(f"\nTactic coverage: {covered} COVERED vs {len(coverage) - covered} MISSING")
    
    if is_list:
        cross_iocs = [ioc for ioc in iocs if 'sources' in ioc and len(ioc['sources']) >= 2]
        if cross_iocs:
            print("\nCross-source IOCs:")
            cross_iocs.sort(key=lambda x: len(x['sources']), reverse=True)
            for ioc in cross_iocs[:10]:
                print(f"  {ioc['value']} | {ioc['type']} | {len(ioc['sources'])} sources: {', '.join(ioc['sources'])}")

    if checkers:
        print("\nChecker/beacon candidates:")
        for c in checkers:
            print(f"  {c['key']} | interval: {c['interval_seconds']:.1f}s | count: {c['count']}")
            
    print("\nPer host tactics:")
    for chain in chains:
        tacs = ', '.join(chain['tactics']) if chain['tactics'] else "hujum belgisi yo'q"
        print(f"  {chain['host']}: {tacs}")

    from bluekit.tz import tz_note
    print("\n" + tz_note())

    return events, timeline, chains, iocs, checkers
