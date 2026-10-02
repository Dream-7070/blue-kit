import html

def generate_html(findings, out_path, extra=None, meta=None) -> None:
    meta = meta or {}
    hostname = html.escape(meta.get('hostname', "Noma'lum"))
    collected_at = html.escape(meta.get('collected_at', "Noma'lum"))
    
    total = len(findings)
    high = sum(1 for f in findings if f.get('confidence') == 'high')
    # triage 'med', fraud esa 'medium' qaytaradi -- ikkalasi ham hisoblansin
    med = sum(1 for f in findings if f.get('confidence') in ('med', 'medium'))
    low = sum(1 for f in findings if f.get('confidence') == 'low')
    protected_cnt = sum(1 for f in findings if f.get('protected'))
    
    rows = []
    for f in sorted(findings, key=lambda x: x.get('score', 0), reverse=True):
        score = f.get('score', 0)
        conf = f.get('confidence', '')
        cat = html.escape(f.get('category', ''))
        item = html.escape(f.get('item', ''))
        protected = f.get('protected', False)
        
        techs = ", ".join(t.get('id', '') for t in f.get('techniques', []))
        reasons = "<br>".join(html.escape(r) for r in f.get('reasons', []))
        
        if conf == 'high': bg = '#ffcccc'
        elif conf in ('med', 'medium'): bg = '#ffffcc'
        elif conf == 'low': bg = '#f0f0f0'
        else: bg = '#ffffff'
        
        prot_html = ' <span class="prot">(himoyalangan — tegmang)</span>' if protected else ''
        
        rows.append(f"""
        <tr style="background-color: {bg}">
            <td>{score}</td>
            <td>{html.escape(conf)}</td>
            <td>{cat}</td>
            <td>{item}{prot_html}</td>
            <td>{html.escape(techs)}</td>
            <td>{reasons}</td>
        </tr>
        """)
        
    rows_html = "\\n".join(rows)
    if not findings:
        rows_html = "<tr><td colspan='6'>Topilma yo'q</td></tr>"
        
    extra_html = ""
    if extra and extra.get('beacon_candidates'):
        b_lines = []
        for b in extra['beacon_candidates']:
            b_lines.append(f"{html.escape(str(b.get('ip')))} — {html.escape(str(b.get('key')))}, ~{b.get('interval_seconds', 0):.0f}s, {b.get('count', 0)} ulanish")
        b_cands = "<br>".join(b_lines)
        extra_html += f"""
        <div class="extra-block" style="border-color: red; background-color: #ffe6e6;">
            <h3>C2 beacon nomzodlari (tashqi, davriy) — tekshirib BLOKLANG</h3>
            <p>{b_cands}</p>
        </div>
        """
        
    if extra and 'checker_candidates' in extra:
        cands = "<br>".join(html.escape(str(c)) for c in extra['checker_candidates'])
        extra_html += f"""
        <div class="extra-block">
            <h3>Mumkin bo'lgan checker IP lari — BULARNI BLOKLAMANG</h3>
            <p>{cands}</p>
        </div>
        """
        
    html_content = f"""<!DOCTYPE html>
<html lang="uz">
<head>
    <meta charset="utf-8">
    <title>Triage Report - {hostname}</title>
    <style>
        body {{ font-family: sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
        th {{ background-color: #e0e0e0; }}
        .prot {{ color: red; font-weight: bold; }}
        .extra-block {{ margin-top: 20px; padding: 15px; border: 2px solid green; background-color: #e6ffe6; }}
    </style>
</head>
<body>
    <h1>Triage Report ({hostname}, {collected_at})</h1>
    <div>
        <p>Jami topilma: {total} | High: {high}, Medium: {med}, Low: {low} | Himoyalangan: {protected_cnt}</p>
    </div>
    <table>
        <thead>
            <tr>
                <th>Ball</th>
                <th>Ishonch</th>
                <th>Kategoriya</th>
                <th>Element</th>
                <th>ATT&CK</th>
                <th>Sabablar</th>
            </tr>
        </thead>
        <tbody>
            {rows_html}
        </tbody>
    </table>
    {extra_html}
</body>
</html>
"""
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
