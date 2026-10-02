import os
import yaml
import html

def load_strings():
    p = os.path.join(os.path.dirname(__file__), 'strings.yaml')
    with open(p, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def render_html(model, lang='uz'):
    s = load_strings().get(lang, load_strings()['uz'])
    
    def esc(text):
        return html.escape(str(text)) if text is not None else ""
        
    css = """
    body { font-family: Arial, sans-serif; margin: 40px auto; max-width: 900px; line-height: 1.6; color: #333; }
    h1, h2, h3 { color: #2c3e50; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background-color: #f2f2f2; }
    .meta { background: #f9f9f9; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
    .warning { color: #d35400; font-weight: bold; }
    @media print { body { margin: 0; } }
    """
    
    out = [f"<!DOCTYPE html><html><head><meta charset='utf-8'><title>{esc(s['title'])}</title><style>{css}</style></head><body>"]
    out.append(f"<h1>{esc(s['title'])}: {esc(model['meta']['title'])}</h1>")
    
    out.append("<div class='meta'>")
    out.append(f"<b>{esc(s['org'])}:</b> {esc(model['meta']['org'])} | ")
    out.append(f"<b>{esc(s['date'])}:</b> {esc(model['meta']['date'])} | ")
    out.append(f"<b>{esc(s['team'])}:</b> {esc(model['meta']['team'])} | ")
    out.append(f"<b>{esc(s['analyst'])}:</b> {esc(model['meta']['analyst'])}")
    out.append("</div>")
    
    out.append(f"<h2>{esc(s['exec_summary'])}</h2>")
    out.append(f"<p>{esc(model['exec_summary'])}</p>")
    
    if model.get('checker_note'):
        out.append(f"<p class='warning'>{esc(model['checker_note'])}</p>")
    
    if model.get('techniques'):
        out.append(f"<h2>{esc(s['techniques'])}</h2>")
        out.append("<table><tr>")
        out.append(f"<th>{esc(s['id'])}</th><th>{esc(s['name'])}</th><th>{esc(s['tactic'])}</th><th>{esc(s['count'])}</th><th>{esc(s['evidence'])}</th>")
        out.append("</tr>")
        for t in model['techniques']:
            out.append(f"<tr><td>{esc(t['id'])}</td><td>{esc(t['name'])}</td><td>{esc(t['tactic'])}</td><td>{esc(t['count'])}</td><td>{esc(t['evidence-sample'])}</td></tr>")
        out.append("</table>")

    if model.get('iocs'):
        out.append(f"<h2>{esc(s['iocs'])}</h2>")
        out.append("<table><tr>")
        out.append(f"<th>{esc(s['type'])}</th><th>{esc(s['value'])}</th><th>{esc(s['count'])}</th><th>{esc(s['first'])}</th><th>{esc(s['last'])}</th>")
        out.append("</tr>")
        for i in model['iocs']:
            out.append(f"<tr><td>{esc(i['type'])}</td><td>{esc(i['value'])}</td><td>{esc(i['count'])}</td><td>{esc(i['first'])}</td><td>{esc(i['last'])}</td></tr>")
        out.append("</table>")
        
    if model.get('timeline'):
        out.append(f"<h2>{esc(s['timeline'])}</h2>")
        if model.get('timeline_truncated'):
            out.append("<p><i>Timeline truncated for readability.</i></p>")
        out.append("<table><tr>")
        out.append(f"<th>{esc(s['ts'])}</th><th>{esc(s['host'])}</th><th>{esc(s['user'])}</th><th>ATT&CK</th><th>{esc(s['command'])}</th>")
        out.append("</tr>")
        for t in model['timeline']:
            out.append(f"<tr><td>{esc(t['ts'])}</td><td>{esc(t['host'])}</td><td>{esc(t['user'])}</td><td>{esc(t['technique'])}</td><td>{esc(t['command'])}</td></tr>")
        out.append("</table>")

    if model.get('remediation', {}).get('done') or model.get('remediation', {}).get('manual'):
        out.append(f"<h2>{esc(s['remediation'])}</h2>")
        out.append("<table><tr>")
        out.append(f"<th>{esc(s['item'])}</th><th>ATT&CK</th><th>{esc(s['status'])}</th>")
        out.append("</tr>")
        for r in model['remediation'].get('done', []):
            out.append(f"<tr><td>{esc(r['item'])}</td><td>{esc(r['technique'])}</td><td>{esc(r['status'])}</td></tr>")
        for r in model['remediation'].get('manual', []):
            out.append(f"<tr><td>{esc(r['item'])}</td><td>{esc(r['technique'])}</td><td>{esc(r['status'])}</td></tr>")
        out.append("</table>")
        
    if model.get('recommendations'):
        out.append(f"<h2>{esc(s['recommendations'])}</h2>")
        out.append(f"<p>{esc(model['recommendations'])}</p>")

    out.append("</body></html>")
    return "\n".join(out)

def render_markdown(model, lang='uz'):
    s = load_strings().get(lang, load_strings()['uz'])
    out = []
    
    out.append(f"# {s['title']}: {model['meta']['title']}")
    out.append(f"**{s['org']}**: {model['meta']['org']} | **{s['date']}**: {model['meta']['date']} | **{s['team']}**: {model['meta']['team']} | **{s['analyst']}**: {model['meta']['analyst']}")
    out.append("")
    
    out.append(f"## {s['exec_summary']}")
    out.append(model['exec_summary'])
    out.append("")
    
    if model.get('checker_note'):
        out.append(f"> **WARNING**: {model['checker_note']}")
        out.append("")
        
    if model.get('techniques'):
        out.append(f"## {s['techniques']}")
        out.append(f"| {s['id']} | {s['name']} | {s['tactic']} | {s['count']} | {s['evidence']} |")
        out.append("|---|---|---|---|---|")
        for t in model['techniques']:
            out.append(f"| {t['id']} | {t['name']} | {t['tactic']} | {t['count']} | {t['evidence-sample']} |")
        out.append("")

    if model.get('iocs'):
        out.append(f"## {s['iocs']}")
        out.append(f"| {s['type']} | {s['value']} | {s['count']} | {s['first']} | {s['last']} |")
        out.append("|---|---|---|---|---|")
        for i in model['iocs']:
            out.append(f"| {i['type']} | {i['value']} | {i['count']} | {i['first']} | {i['last']} |")
        out.append("")
        
    if model.get('timeline'):
        out.append(f"## {s['timeline']}")
        if model.get('timeline_truncated'):
            out.append("*Timeline truncated for readability.*")
        out.append(f"| {s['ts']} | {s['host']} | {s['user']} | ATT&CK | {s['command']} |")
        out.append("|---|---|---|---|---|")
        for t in model['timeline']:
            out.append(f"| {t['ts']} | {t['host']} | {t['user']} | {t['technique']} | {t['command']} |")
        out.append("")

    if model.get('remediation', {}).get('done') or model.get('remediation', {}).get('manual'):
        out.append(f"## {s['remediation']}")
        out.append(f"| {s['item']} | ATT&CK | {s['status']} |")
        out.append("|---|---|---|")
        for r in model['remediation'].get('done', []):
            out.append(f"| {r['item']} | {r['technique']} | {r['status']} |")
        for r in model['remediation'].get('manual', []):
            out.append(f"| {r['item']} | {r['technique']} | {r['status']} |")
        out.append("")
        
    if model.get('recommendations'):
        out.append(f"## {s['recommendations']}")
        out.append(model['recommendations'])
        out.append("")

    return "\n".join(out)

def render_docx(model, lang, path):
    try:
        import docx
    except ImportError:
        raise ImportError("python-docx yo'q")
    
    s = load_strings().get(lang, load_strings()['uz'])
    doc = docx.Document()
    
    doc.add_heading(f"{s['title']}: {model['meta']['title']}", 0)
    doc.add_paragraph(f"{s['org']}: {model['meta']['org']} | {s['date']}: {model['meta']['date']} | {s['team']}: {model['meta']['team']} | {s['analyst']}: {model['meta']['analyst']}")
    
    doc.add_heading(s['exec_summary'], level=1)
    doc.add_paragraph(model['exec_summary'])
    
    if model.get('checker_note'):
        doc.add_paragraph(model['checker_note'], style='Intense Quote')
        
    if model.get('techniques'):
        doc.add_heading(s['techniques'], level=1)
        t = doc.add_table(rows=1, cols=5)
        t.style = 'Table Grid'
        cells = t.rows[0].cells
        cells[0].text, cells[1].text, cells[2].text, cells[3].text, cells[4].text = s['id'], s['name'], s['tactic'], s['count'], s['evidence']
        for tech in model['techniques']:
            row_cells = t.add_row().cells
            row_cells[0].text = str(tech['id'])
            row_cells[1].text = str(tech['name'])
            row_cells[2].text = str(tech['tactic'])
            row_cells[3].text = str(tech['count'])
            row_cells[4].text = str(tech['evidence-sample'])

    # simplified - skipping full table rendering for other sections to save space unless requested
    # but let's add them just to be complete
    if model.get('iocs'):
        doc.add_heading(s['iocs'], level=1)
        t = doc.add_table(rows=1, cols=5)
        t.style = 'Table Grid'
        cells = t.rows[0].cells
        cells[0].text, cells[1].text, cells[2].text, cells[3].text, cells[4].text = s['type'], s['value'], s['count'], s['first'], s['last']
        for i in model['iocs']:
            row_cells = t.add_row().cells
            row_cells[0].text = str(i['type'])
            row_cells[1].text = str(i['value'])
            row_cells[2].text = str(i['count'])
            row_cells[3].text = str(i['first'])
            row_cells[4].text = str(i['last'])
            
    doc.save(path)
