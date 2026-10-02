import argparse
import sys
import json
from bluekit.kb.build import build
from bluekit.kb.query import KB
from bluekit.kb.ioc import classify, techniques_for_ioc

def print_table(headers, rows):
    if not rows:
        print("No results.")
        return
    cols = len(headers)
    widths = [len(str(h)) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(str(c)))
    fmt = " | ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print("-+-".join("-" * w for w in widths))
    for r in rows:
        print(fmt.format(*[str(c) for c in r]))

def check_input_format(path):
    """Xom EVTX/PCAP bo'lsa tushunarsiz xato o'rniga konvertatsiya buyrug'ini beradi."""
    try:
        from bluekit.logs.formats import identify
        res = identify(path)
    except Exception:
        return True
    if res.get('supported', True):
        return True
    print("Bu fayl to'g'ridan-to'g'ri o'qilmaydi: %s (%s)" % (path, res.get('format')))
    if res.get('hint'):
        print(res['hint'])
    return False


def main():
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

    # `bk siem ...` ning o'z argparse i bor -- argumentlarni to'g'ridan-to'g'ri uzatamiz.
    if len(sys.argv) > 1 and sys.argv[1] == 'siem':
        from bluekit.siem.cli import main as siem_main
        sys.exit(siem_main(sys.argv[2:]))

    parser = argparse.ArgumentParser(prog='bk')
    parser.add_argument('--json', action='store_true', help='Output JSON')
    sub = parser.add_subparsers(dest='cmd', required=True)

    sub.add_parser('siem', help="SIEM uchun tayyor qidiruv so'rovlari "
                                "(bk siem list | hunts | show | query | pack)")

    sg_parser = sub.add_parser('sigma', help="Sigma qoidalari bilan loglarni tekshirish (3700+ qoida)")
    sgsub = sg_parser.add_subparsers(dest='sigmacmd', required=True)
    sg_scan = sgsub.add_parser('scan', help="Faylni Sigma qoidalari bo'yicha tekshirish")
    sg_scan.add_argument('file')
    sg_scan.add_argument('--preset', default=None)
    sg_scan.add_argument('--map', default=None)
    sg_scan.add_argument('--level', default=None,
                         choices=['informational', 'low', 'medium', 'high', 'critical'],
                         help="Shu darajadan pastini tashlab ketish")
    sg_scan.add_argument('--product', action='append', default=None,
                         help="windows / linux / ... (bir necha marta berish mumkin)")
    sg_scan.add_argument('--weak', action='store_true',
                         help="Xom matn orqali topilgan (ishonchsiz) mosliklarni ham ko'rsatish")
    sg_scan.add_argument('-n', type=int, default=25, help="Nechta texnika ko'rsatilsin")
    sg_scan.add_argument('--json', action='store_true')
    sg_scan.add_argument('--out', default=None)
    sgsub.add_parser('info', help="Nechta qoida yuklanadi")

    ans_parser = sub.add_parser('answers', help="Topilgan ATT&CK ID larni reytinglash va topshirish daftari")
    anssub = ans_parser.add_subparsers(dest='answerscmd', required=True)
    ans_rank = anssub.add_parser('rank', help="ir chain/sigma scan/logs analyze JSON chiqishlaridan reyting")
    ans_rank.add_argument('files', nargs='+', help="--json/--json-out bilan saqlangan fayllar")
    ans_rank.add_argument('--ledger', default='answers.json', help="Topshirish daftari yo'li")
    ans_rank.add_argument('--prefer-parent', action='store_true', dest='prefer_parent')
    ans_rank.add_argument('-n', type=int, default=15)
    ans_rank.add_argument('--json', action='store_true')
    ans_submit = anssub.add_parser('submit', help="Topshirilgan javobni daftarga yozish")
    ans_submit.add_argument('technique')
    ans_submit.add_argument('result', choices=['accepted', 'rejected', 'pending'])
    ans_submit.add_argument('--note', default=None)
    ans_submit.add_argument('--ledger', default='answers.json')
    ans_submit.add_argument('--question', help="tracker savoli matni")
    ans_submit.add_argument('--max', type=int, help="max_attempts")
    ans_submit.add_argument('--tracker', default='web-work/tracker.json')
    ans_submit.add_argument('--force', action='store_true', help="ogohlantirishlarga qaramay yozish")

    dec_p = sub.add_parser('decode', help="Obfuskatsiyani ochish (base64, -enc, hex, url, gzip...)")
    dec_p.add_argument('text', nargs='?', help="Ochiladigan matn (yoki --file)")
    dec_p.add_argument('--file', help="Fayl: har qatordagi kodlangan bo'laklar ochiladi")
    dec_p.add_argument('--max-lines', dest='max_lines', type=int, default=200)
    dec_p.add_argument('--detect', action='store_true',
                       help="Natijadan ATT&CK texnikasini aniqlash")
    dec_p.add_argument('--json', action='store_true')
    dec_p.add_argument('--data', default=None)

    doctor_p = sub.add_parser('doctor', help="Kit shu mashinada ishlayaptimi -- o'z-o'zini tekshirish")
    doctor_p.add_argument('--quick', action='store_true', help="Faqat tez tekshiruvlar")
    doctor_p.add_argument('--data', default=None)
    doctor_p.add_argument('--json', action='store_true')

    kb_parser = sub.add_parser('kb')
    kbsub = kb_parser.add_subparsers(dest='kbcmd', required=True)
    
    b_p = kbsub.add_parser('build')
    b_p.add_argument('--data', required=True)
    
    kbsub.add_parser('info')
    
    id_p = kbsub.add_parser('id')
    id_p.add_argument('ids', nargs='+')
    
    v_p = kbsub.add_parser('validate')
    v_p.add_argument('ids', nargs='+')
    
    s_p = kbsub.add_parser('search')
    s_p.add_argument('text')
    s_p.add_argument('--domain', default=None)
    s_p.add_argument('-n', type=int, default=20)
    
    ioc_p = kbsub.add_parser('ioc')
    ioc_p.add_argument('values', nargs='+')
    ioc_p.add_argument('-n', type=int, default=5)
    
    r_p = kbsub.add_parser('related')
    r_p.add_argument('ids', nargs='+')
    r_p.add_argument('-n', type=int, default=25)
    r_p.add_argument('--actors', action='store_true',
                     help='Show similar-TTP actors (off by default; simulated CTF scenarios use fake names/IPs, so attribution misleads)')
    
    t_p = kbsub.add_parser('tactics')
    t_p.add_argument('ids', nargs='+')
    t_p.add_argument('--domain', default='enterprise')
    
    logs_parser = sub.add_parser('logs')
    logssub = logs_parser.add_subparsers(dest='logscmd', required=True)
    
    a_p = logssub.add_parser('analyze')
    a_p.add_argument('file', nargs='+', help="Log fayl(lar); har biri 'yol' yoki 'yol@preset' (masalan siem.json@ecs)")
    a_p.add_argument('--map', default=None)
    a_p.add_argument('--preset', default=None)
    a_p.add_argument('--out', default=None)
    a_p.add_argument('--json-out', default=None)
    a_p.add_argument('--from', dest='from_ts', default=None)
    a_p.add_argument('--to', dest='to_ts', default=None)
    a_p.add_argument('--host', default=None)
    a_p.add_argument('--data', default=None)
    a_p.add_argument('--deep', action='store_true', help="KB full-text qidiruvini yoqish (ko'p low-confidence natija beradi)")
    
    c_p = logssub.add_parser('columns')
    c_p.add_argument('file')
    c_p.add_argument('--map', default=None)
    c_p.add_argument('--preset', default=None)
    
    d_p = logssub.add_parser('detect')
    d_p.add_argument('command')
    
    
    resp_parser = sub.add_parser('resp')
    respsub = resp_parser.add_subparsers(dest='respcmd', required=True)

    triage_p = respsub.add_parser('triage')
    triage_p.add_argument('current')
    triage_p.add_argument('--baseline')
    triage_p.add_argument('--protected')
    triage_p.add_argument('--from-logs')
    triage_p.add_argument('--out')
    triage_p.add_argument('--json', action='store_true')
    triage_p.add_argument('--data', default=None)

    fix_p = respsub.add_parser('fix')
    fix_p.add_argument('current')
    fix_p.add_argument('--baseline')
    fix_p.add_argument('--protected')
    fix_p.add_argument('--from-logs')
    fix_p.add_argument('--os', choices=['windows', 'linux'])
    fix_p.add_argument('--full', action='store_true')
    fix_p.add_argument('--out')
    fix_p.add_argument('--data', default=None)

    sla_p = respsub.add_parser('sla', help="Xizmatlar holati: yashil / sariq / qizil")
    sla_p.add_argument('config')
    sla_p.add_argument('--watch', action='store_true',
                       help="Uzluksiz kuzatish, holat o'zgarganda xabar beradi")
    sla_p.add_argument('--interval', type=int, default=30, help="Kuzatuv oralig'i (soniya)")
    sla_p.add_argument('--json', action='store_true')

    disc_p = respsub.add_parser('discover',
                                help="Ball hisoblovchi checker va monitoring agentlarini topish")
    disc_p.add_argument('snapshots', nargs='+', help="collect_*.ps1/sh chiqishi (JSON)")
    disc_p.add_argument('--from-logs', dest='from_logs',
                        help="logs analyze --json-out fayli (checker IP larini boyitadi)")
    disc_p.add_argument('--sla-out', dest='sla_out', help="Topilgan nishonlardan tekshiruv konfigi")
    disc_p.add_argument('--allowlist-out', dest='allowlist_out', help="'Tegmang' ro'yxati")
    disc_p.add_argument('--json', action='store_true')
    
    doc_p = respsub.add_parser('doctor', help="Xizmat nega ishlamayapti -- sabab va tuzatish buyrug'i")
    doc_p.add_argument('current')
    doc_p.add_argument('service')
    doc_p.add_argument('--baseline', help="Toza snapshot: yo'l/akkaunt o'zgarganini aniqlaydi")
    doc_p.add_argument('--json', action='store_true')

    fraud_p = respsub.add_parser('fraud')
    fraud_p.add_argument('current')
    fraud_p.add_argument('--baseline')

    
    mail_parser = sub.add_parser('mail')
    mailsub = mail_parser.add_subparsers(dest='mailcmd', required=True)
    scan_p = mailsub.add_parser('scan')
    scan_p.add_argument('target')
    scan_p.add_argument('--out', default=None)
    # --json is already in main parser as global flag

    web_parser = sub.add_parser('web')
    web_parser.add_argument('--host', default='127.0.0.1')
    web_parser.add_argument('--port', type=int, default=8000)
    web_parser.add_argument('--data', default=None)
    web_parser.add_argument('--workdir', default=None)

    report_parser = sub.add_parser('report')
    report_parser.add_argument('--logs', default=None)
    report_parser.add_argument('--resp', default=None)
    report_parser.add_argument('--answers', default=None)
    report_parser.add_argument('--lang', default='uz')
    report_parser.add_argument('--out', default='report.html')
    report_parser.add_argument('--md', default=None)
    report_parser.add_argument('--docx', default=None)
    report_parser.add_argument('--ask', action='store_true')

    reportbot_parser = sub.add_parser('report-bot')
    reportbot_parser.add_argument('--token', default=None)

    hunt_parser = sub.add_parser('hunt')
    huntsub = hunt_parser.add_subparsers(dest='huntcmd', required=True)
    hb_p = huntsub.add_parser('beacons')
    hb_p.add_argument('path', help='Log file or folder')
    hb_p.add_argument('--json', dest='json_out', default=None, help='Output JSON file')
    hb_p.add_argument('--out', default=None, help='HTML output file')
    hb_p.add_argument('--min-sessions', type=int, default=10)
    hb_p.add_argument('--max-hosts', type=int, default=100)
    hb_p.add_argument('--all', action='store_true', help='Show all levels')
    hb_p.add_argument('--ioc', default=None, help='Known IOCs file')
    hb_p.add_argument('--allowlist', default=None, help="Allowlist YAML fayli (default: paket ichidagi bluekit/hunt/allowlist.yaml)")

    ir_parser = sub.add_parser('ir', help='Incident Response & Attack Chain Engine')
    irsub = ir_parser.add_subparsers(dest='ircmd', required=True)

    chain_p = irsub.add_parser('chain', help='Reconstruct end-to-end multi-stage attack chain')
    chain_p.add_argument('file', nargs='+', help='Log file path(s) (ELK JSON, NDJSON, CSV, Syslog, XML)')
    chain_p.add_argument('--json', action='store_true', help='Output machine-readable scoring JSON')
    chain_p.add_argument('--out', default=None, help='Write output to file')
    chain_p.add_argument('--lang', choices=['ru', 'uz', 'en'], default='ru', help='Language for output')

    rep_p = irsub.add_parser('report', help='Generate formal Incident Response report')
    rep_p.add_argument('file', nargs='+', help='Log file path(s)')
    rep_p.add_argument('--out', default='incident_report.md', help='Output report file')
    rep_p.add_argument('--lang', choices=['ru', 'uz', 'en'], default='ru', help='Language of report')
    rep_p.add_argument('--json-out', default=None, help='Also output scoring JSON')

    from bluekit.case import cli as _case_cli
    case_parser = sub.add_parser('case', help="Ko'p manbali forensic topshiriq: soat siljishi, tasdiqlangan faoliyat, zanjir, flag")
    casesub = case_parser.add_subparsers(dest='casecmd', required=True)
    _case_cli.add_arguments(casesub.add_parser('solve', help='Challenge JSON / papka / zip -> zanjir, flag, submission'))

    parser.add_argument('--src-tz', dest='src_tz', default=None,
                        help="Zonasi yozilmagan log vaqtlari qaysi zonada: local (sukut, Toshkent +05:00), utc, yoki +HH:MM")
    args = parser.parse_args()

    import bluekit.tz
    try:
        bluekit.tz.set_naive_tz(args.src_tz)
    except ValueError as e:
        sys.stderr.write(str(e) + "\n")
        sys.exit(2)

    if getattr(args, 'cmd', None) == 'logs' and getattr(args, 'logscmd', None) == 'analyze':
        from bluekit.logs.filter import parse_bound
        try:
            args.from_dt = parse_bound(args.from_ts) if getattr(args, 'from_ts', None) is not None else None
            args.to_dt = parse_bound(args.to_ts, end=True) if getattr(args, 'to_ts', None) is not None else None
        except ValueError as e:
            sys.stderr.write(str(e) + "\n"); sys.exit(2)
        if getattr(args, 'from_dt', None) and getattr(args, 'to_dt', None) and args.from_dt > args.to_dt:
            sys.stderr.write("--from vaqti --to dan keyin bo'lmasligi kerak\n"); sys.exit(2)
        if getattr(args, 'host', None) is not None and not args.host.strip():
            sys.stderr.write("--host bo'sh bo'lmasligi kerak\n"); sys.exit(2)

    if args.cmd == 'sigma':
        from bluekit.logs.sigma import SigmaEngine, drop_weak
        import json as _json
        import os
        if args.sigmacmd == 'info':
            print(_json.dumps(SigmaEngine().stats(), ensure_ascii=False, indent=2))
            sys.exit(0)
        if not check_input_format(args.file):
            sys.exit(1)
        from bluekit.logs.parse import load as _load
        events = _load(args.file, preset=args.preset, map_path=args.map)
        eng = SigmaEngine(products=args.product, min_level=args.level)
        res = eng.match_events(events)
        if not args.weak:
            drop_weak(res)
        if args.json or args.out:
            text = _json.dumps(res, ensure_ascii=False, indent=2, default=str)
            if args.out:
                with open(args.out, 'w', encoding='utf-8') as f:
                    f.write(text)
                print("Saqlandi: %s" % args.out)
            else:
                print(text)
            sys.exit(0)
        st = res['stats']
        print("Hodisalar: %d | moslik topilgan: %d | qoidalar: %d yuklandi, %d skip | %.1fs"
              % (st.get('events', 0), st.get('events_with_hits', 0),
                 st.get('rules_loaded', 0), st.get('rules_skipped', 0),
                 st.get('elapsed_sec', 0)))
        by_t = res.get('by_technique', {})
        # qoida id -> sarlavha (UUID o'rniga o'qiladigan nom ko'rsatish uchun)
        titles = {}
        for hit in res.get('hits', []):
            for r in hit.get('rules', []):
                if r.get('rule_id'):
                    titles[r['rule_id']] = r.get('title', r['rule_id'])
        rows = []
        for tid, info in sorted(by_t.items(), key=lambda kv: -kv[1].get('count', 0))[:args.n]:
            names = [titles.get(r, r) for r in info.get('rules', [])[:2]]
            rows.append([tid, info.get('count', 0), info.get('level', '-'),
                         '; '.join(names)[:58]])
        print()
        print_table(['ATT&CK', 'Soni', 'Daraja', 'Qoidalar'], rows)
        if by_t:
            print("\nID larni topshirishdan oldin tekshiring:")
            print("  python bk.py kb validate %s" % ' '.join(list(by_t)[:6]))
        sys.exit(0)

    if args.cmd == 'answers':
        from bluekit.answers import collect, rank, load_ledger, record
        import json as _json
        if args.answerscmd == 'submit':
            import os as _os
            import sys as _sys
            from bluekit import tracker as _trk
            
            if getattr(args, 'question', None):
                def do_submit(rows):
                    row = _trk.find_by_question(rows, args.question)
                    if not row:
                        row = _trk.add_row(rows, {"question": args.question, "candidates": args.technique, "max_attempts": args.max})
                    elif getattr(args, 'max', None) is not None:
                        row['max_attempts'] = _trk.parse_max_attempts(args.max)
                    
                    check = _trk.add_attempt(row, args.technique, args.result, force=args.force)
                    return row, check

                tracker_dir = _os.path.dirname(args.tracker)
                if tracker_dir and not _os.path.exists(tracker_dir):
                    _os.makedirs(tracker_dir, exist_ok=True)
                
                try:
                    row, check = _trk.mutate(args.tracker, do_submit)
                except _trk.AttemptNeedsConfirm as e:
                    for w in e.check.get('warnings', []):
                        print("OGOHLANTIRISH: " + w)
                    print("Baribir yozish uchun --force qo'shing.")
                    _sys.exit(2)
                except _trk.TrackerError as e:
                    print(str(e))
                    _sys.exit(1)
                
                ledger = record(args.ledger, row['attempts'][-1]['answer'], args.result,
                                note=args.note or args.question)
                rem = "?" if row.get("max_attempts") is None else row.get("max_attempts")
                used = check['used'] + 1
                print("Yozildi: %s -> %s | savol: %s | urinish %d/%s" % (args.technique, args.result, args.question, used, rem))
                
                if args.result == 'rejected' and check['remaining'] is not None and check['remaining'] <= 1:
                    print("Bu savolga urinishlar tugadi.")
                _sys.exit(0)
            else:
                ledger = record(args.ledger, args.technique, args.result, note=args.note)
                print("Yozildi: %s -> %s (%d ta yozuv)" % (args.technique, args.result, len(ledger['entries'])))
                _sys.exit(0)
        ledger = load_ledger(args.ledger)
        collected = collect(args.files)
        rows = rank(collected, kb=KB(), submitted=ledger, prefer_parent=args.prefer_parent)
        if args.json:
            print(_json.dumps(rows, ensure_ascii=False, indent=2))
            sys.exit(0)
        print("Reyting (%d ta texnika, daftar: %s)\n" % (len(rows), args.ledger))
        for r in rows[:args.n]:
            flag = ' [TOPSHIRILGAN]' if r['submitted'] else ''
            kb_note = ''
            if r['kb_status'] == 'revoked':
                kb_note = '  <- REVOKED, o\'rniga: %s' % r['replacement']
            elif r['kb_status'] == 'not_found':
                kb_note = '  <- KB da topilmadi'
            print("%2d. %-14s %-32s ball=%-5.1f %-6s%s%s" % (
                r['rank'], r['technique'], (r['name'] or '')[:32], r['score'],
                r['confidence'], kb_note, flag))
            for e in r['evidence'][:2]:
                print("      - %s" % e[:90])
        sys.exit(0)

    if args.cmd == 'decode':
        from bluekit.decode import decode as _decode, decode_file
        import json as _json
        import os
        if args.file:
            rows = decode_file(args.file, max_lines=args.max_lines)
            if args.json:
                print(_json.dumps(rows, ensure_ascii=False, indent=2))
            else:
                if not rows:
                    print("Kodlangan bo'lak topilmadi.")
                for row in rows:
                    print("--- %s-qator ---" % row.get('line_no'))
                    print(row.get('output', ''))
                print("\nJami: %d ta qatorda kodlangan bo'lak ochildi." % len(rows))
            sys.exit(0)
        if not args.text:
            print("Matn yoki --file kerak.")
            sys.exit(1)
        res = _decode(args.text)
        if args.json:
            print(_json.dumps(res, ensure_ascii=False, indent=2))
            sys.exit(0)
        if not res['layers']:
            print("Kodlangan qatlam topilmadi -- matn o'z holicha.")
        else:
            for lay in res['layers']:
                print("%d. %s -- %s" % (lay['step'], lay['method'], lay.get('note', '')))
            print("\nNatija:\n%s" % res['output'])
        if res.get('iocs'):
            print("\nIOC lar:")
            for i in res['iocs']:
                print("  %-8s %s" % (i.get('type'), i.get('value')))
        if args.detect:
            from bluekit.paths import get_kb_path
            from bluekit.kb.query import KB as _KB
            from bluekit.logs.detect import detect_event
            kbp = get_kb_path(args.data)
            if os.path.exists(kbp):
                ev = {'channel': '', 'event_id': '', 'command_line': res['output'],
                      'message': ''}
                hits = detect_event(_KB(kbp), ev)
                print("\nATT&CK:")
                for h in hits:
                    print("  [%s] %s (%s)" % (h['technique'], h['name'], h['confidence']))
                if not hits:
                    print("  texnika aniqlanmadi")
            else:
                print("\n(KB topilmadi -- --detect ishlamadi)")
        sys.exit(0)

    if args.cmd == 'doctor':
        from bluekit.doctor import run_checks, summary
        import json as _json
        results = run_checks(data_dir=args.data, quick=args.quick)
        s = summary(results)
        if args.json:
            print(_json.dumps({'results': results, 'summary': s},
                              ensure_ascii=False, indent=2))
        else:
            rows = []
            for r in results:
                belgi = 'OK' if r['ok'] else ('XATO' if r.get('critical') else 'OGOH')
                rows.append([belgi, r['name'], r.get('detail', '')])
            print_table(['', 'Tekshiruv', 'Natija'], rows)
            for r in results:
                if not r['ok'] and r.get('fix'):
                    print("\n  %s -> %s" % (r['name'], r['fix']))
            print("\n%s  (%d/%d)" % (s['verdict'], s['ok'], s['total']))
        sys.exit(0 if s['failed'] == 0 else 1)

    if getattr(args, 'kbcmd', None) == 'build':
        from bluekit.kb.build import build
        stats = build(args.data)
        if args.json:
            print(json.dumps(stats, indent=2))
        else:
            print("Build complete.")
            for k, v in stats.items():
                print(f"{k}: {v}")
        return
        
    from bluekit.paths import get_kb_path
    import os
    
    # Only need KB for commands that use it
    kb_required = not (getattr(args, 'logscmd', None) == 'columns') and getattr(args, 'respcmd', None) not in ('sla', 'doctor', 'fraud', 'discover') and getattr(args, 'cmd', None) != 'ir'
    kb = None
    if kb_required or getattr(args, 'cmd', None) == 'ir':
        kb_path = get_kb_path(getattr(args, 'data', None))
        if os.path.exists(kb_path):
            kb = KB(kb_path)
        elif kb_required:
            print("Avval: python bk.py kb build --data ...")
            sys.exit(1)

    
    if getattr(args, 'kbcmd', None) == 'info':
        res = kb.version()
        if args.json: print(json.dumps(res, indent=2))
        else:
            for k, v in res.items(): print(f"{k}: {v}")
    elif getattr(args, 'kbcmd', None) == 'id':
        res = []
        for i in args.ids:
            res.extend(kb.lookup(i))
        if args.json: print(json.dumps(res, indent=2))
        else:
            for r in res:
                print(f"\n[{r['attack_id']}] {r['name']} ({r['status']})")
                print(f"Domain: {r['domain']}")
                print(f"Tactics: {', '.join(r['tactics'])}")
                print(f"Desc: {r['short_description']}")
    elif getattr(args, 'kbcmd', None) == 'validate':
        res = kb.validate(args.ids)
        if args.json: print(json.dumps(res, indent=2))
        else:
            rows = [[r['input'], r['status'], r.get('name', ''), r.get('replacement', '')] for r in res]
            print_table(["Input", "Status", "Name", "Replacement"], rows)
    elif getattr(args, 'kbcmd', None) == 'search':
        res = kb.search(args.text, limit=args.n, domain=args.domain)
        if args.json: print(json.dumps(res, indent=2))
        else:
            if hasattr(res, 'warning'):
                print(res.warning)
            rows = [[r['attack_id'], r['name'], round(r['score'],3), r['confidence'], str(r['sources'])] for r in res]
            print_table(["ID", "Name", "Score", "Confidence", "Sources"], rows)
    elif getattr(args, 'kbcmd', None) == 'ioc':
        res = [techniques_for_ioc(kb, v, limit=args.n) for v in args.values]
        if args.json: print(json.dumps(res, indent=2))
        else:
            for r in res:
                c = r['classification']
                print(f"\nIOC: {c['value']} [{c['type']}]")
                if 'note' in r: print(f"Note: {r['note']}")
                rows = [[t['attack_id'], t.get('name',''), round(t.get('score', 0), 3), t.get('confidence', '')] for t in r.get('techniques', [])]
                if rows: print_table(["ID", "Name", "Score", "Confidence"], rows)
    elif getattr(args, 'kbcmd', None) == 'related':
        res = kb.related(args.ids, limit=args.n)
        if args.json:
            out_json = {"techniques": res}
            if args.actors:
                out_json["actors"] = kb.actors_matching(args.ids, limit=5)
            print(json.dumps(out_json, indent=2))
        else:
            rows = [[r['attack_id'], r['name'], r['probability'], r['support'], " | ".join(r['reasons'])] for r in res]
            print_table(["ID", "Name", "Prob", "Support", "Reasons"], rows)

            if args.actors:
                print("\nO'xshash TTP profilli aktorlar (DIQQAT: attributsiya emas — simulyatsiyada nom/IP soxta):")
                actors = kb.actors_matching(args.ids, limit=5)
                actor_rows = []
                for a in actors:
                    coverage = f"{len(a['matched_ids'])}/{len(args.ids)}"
                    sample_unobs = ", ".join(a['top_unobserved'][:3])
                    actor_rows.append([a['name'], a['type'], coverage, sample_unobs])
                print_table(["Name", "Type", "Coverage", "Sample unobserved"], actor_rows)
    elif getattr(args, 'kbcmd', None) == 'tactics':
        res = kb.tactic_coverage(args.ids, domain=args.domain)
        if args.json: print(json.dumps(res, indent=2))
        else:
            rows = [[r['shortname'], r['name'], 'MISSING' if r['missing'] else 'COVERED', ','.join(r['observed'])] for r in res]
            print_table(["Tactic", "Name", "Status", "Observed"], rows)

    if args.cmd == 'logs':
        if args.logscmd == 'analyze':
            from bluekit.logs.report import analyze_logs
            from bluekit.logs.parse import split_preset
            items = [split_preset(f) for f in args.file]
            for _p, _pr in items:
                if not check_input_format(_p):
                    sys.exit(1)
            if len(items) == 1 and not items[0][1]:
                target = items[0][0]
            else:
                target = items
            analyze_logs(target, kb, preset=args.preset, map_path=args.map, json_path=args.json_out, html_path=args.out, deep=args.deep, from_dt=args.from_dt, to_dt=args.to_dt, host=args.host)
        elif args.logscmd == 'columns':
            if not check_input_format(args.file):
                sys.exit(1)
            from bluekit.logs.parse import detect_columns
            detect_columns(args.file, preset=args.preset, map_path=args.map)
        elif args.logscmd == 'detect':
            from bluekit.logs.detect import detect_event
            ev = {'channel': '', 'event_id': '', 'command_line': args.command, 'message': ''}
            hits = detect_event(kb, ev)
            if args.json:
                print(json.dumps(hits, indent=2))
            else:
                for h in hits:
                    print(f"[{h['technique']}] {h['name']} - Confidence: {h['confidence']} - Source: {h['source']}")


    if args.cmd == 'resp':
        import yaml
        if args.respcmd == 'triage':
            from bluekit.resp.triage import analyze
            from bluekit.resp.logbridge import load_log_artifacts
            with open(args.current, encoding='utf-8-sig') as f: cur = json.load(f)
            bas = None
            if args.baseline:
                with open(args.baseline, encoding='utf-8-sig') as f: bas = json.load(f)
            prot = None
            if args.protected:
                with open(args.protected, encoding='utf-8') as f: prot = yaml.safe_load(f).get('items', [])
            
            log_artifacts = None
            if getattr(args, 'from_logs', None):
                log_artifacts = load_log_artifacts(args.from_logs)
                
            findings, extra = analyze(kb, cur, bas, prot, log_artifacts=log_artifacts)
            if args.json:
                print(json.dumps({'findings': findings, 'extra': extra}, indent=2))
            else:
                rows = []
                prot_rows = []
                for f in findings:
                    t_ids = ",".join([t['id'] for t in f.get('techniques', [])])
                    log_tag = "✔ LOG" if f.get('log_confirmed') else ""
                    row = [f.get('score',''), f.get('confidence',''), f.get('category',''), f.get('item',''), t_ids, f.get('protected', False), log_tag, ",".join(f.get('reasons', []))]
                    if f.get('protected'):
                        prot_rows.append(row)
                    else:
                        rows.append(row)
                if rows:
                    print_table(["Score", "Conf", "Category", "Item", "Techniques", "Protected", "Log", "Reasons"], rows)
                if prot_rows:
                    print("\nPROTECTED — teginmang")
                    print_table(["Score", "Conf", "Category", "Item", "Techniques", "Protected", "Log", "Reasons"], prot_rows)
                    
                unmatched = extra.get('unmatched_log_artifacts', [])
                if unmatched:
                    print("\nLoglarda bor, snapshotda topilmadi — qo'lda tekshiring:")
                    for u in unmatched:
                        print(f"- {u['artifact']} (Evidence: {u['evidence']})")
                other = extra.get('unmatched_other', [])
                if other:
                    print(f"  (+{len(other)} ta boshqa host / fon artefakti yashirildi — to'liq ro'yxat: --json, 'unmatched_other')")

                beacons_adv = extra.get('beacon_candidates', [])
                if beacons_adv:
                    print("\nC2 beacon nomzodlari (tashqi, davriy) — tekshirib BLOKLANG:")
                    for b in beacons_adv:
                        print(f"- {b.get('ip')} | {b.get('key')} | ~{b.get('interval_seconds') or 0:.0f}s | {b.get('count')} ulanish")

                checkers_adv = extra.get('checker_candidates', [])
                if checkers_adv:
                    print("\nMumkin bo'lgan checker (tekshiring, protected ro'yxatiga QO'LDA qo'shing):")
                    for c_ip in checkers_adv:
                        print(f"- {c_ip}")
                        
            if args.out:
                from bluekit.resp.report import generate_html
                generate_html(findings, args.out)
        elif args.respcmd == 'fix':
            from bluekit.resp.triage import analyze
            from bluekit.resp.remediate import generate_all
            from bluekit.resp.logbridge import load_log_artifacts
            with open(args.current, encoding='utf-8-sig') as f: cur = json.load(f)
            bas = None
            if args.baseline:
                with open(args.baseline, encoding='utf-8-sig') as f: bas = json.load(f)
            prot = None
            if args.protected:
                with open(args.protected, encoding='utf-8') as f: prot = yaml.safe_load(f).get('items', [])
                
            log_artifacts = None
            if getattr(args, 'from_logs', None):
                log_artifacts = load_log_artifacts(args.from_logs)
                
            findings, _ = analyze(kb, cur, bas, prot, log_artifacts=log_artifacts)
            res = generate_all(findings, args.os, getattr(args, 'full', False))
            if args.out:
                with open(args.out, 'w') as f: f.write(res)
            else:
                print(res)
        elif args.respcmd == 'sla':
            from bluekit.resp.sla import check, watch
            with open(args.config, encoding='utf-8') as f: conf = yaml.safe_load(f)

            RANG = {'ok': 'YASHIL', 'degraded': 'SARIQ', 'down': 'QIZIL'}

            def show(res):
                rows = []
                for r in res:
                    yiqilgan = [c for c in r.get('checks', []) if not c.get('ok')]
                    rows.append([RANG.get(r.get('state'), r.get('state')),
                                 r.get('name'), r.get('board_name') or '-',
                                 '%d/%d' % (len(r.get('checks', [])) - len(yiqilgan),
                                            len(r.get('checks', []))),
                                 r.get('detail', '')])
                print_table(['Holat', 'Xizmat', 'Scoreboard', 'Tekshiruv', 'Tafsilot'], rows)

            if getattr(args, 'watch', False):
                print("Kuzatuv boshlandi (interval %ds). To'xtatish: Ctrl+C" % args.interval)
                show(check(conf))

                def on_change(name, old, new, r):
                    from datetime import datetime
                    print("[%s] %s: %s -> %s | %s"
                          % (datetime.now().strftime('%H:%M:%S'), name,
                             RANG.get(old, old), RANG.get(new, new), r.get('detail', '')))
                try:
                    watch(conf, interval=args.interval, on_change=on_change)
                except KeyboardInterrupt:
                    print("\nKuzatuv to'xtatildi.")
            elif args.json:
                print(json.dumps(check(conf), ensure_ascii=False, indent=2))
            else:
                show(check(conf))
        elif args.respcmd == 'discover':
            from bluekit.resp.scoring import discover, to_sla_config, to_allowlist
            from bluekit.resp.logbridge import load_log_artifacts
            snaps = []
            for p in args.snapshots:
                with open(p, encoding='utf-8-sig') as f: snaps.append(json.load(f))
            arts = load_log_artifacts(args.from_logs) if args.from_logs else None
            res = discover(snaps, arts)
            if args.json:
                print(json.dumps(res, ensure_ascii=False, indent=2, default=list))
            else:
                rows = [[c['value'], c['kind'], c['confidence'], c.get('model', '-'),
                         len(c.get('targets', [])), '; '.join(c.get('evidence', []))[:60]]
                        for c in res.get('candidates', [])]
                print_table(['Qiymat', 'Turi', 'Ishonch', 'Model', 'Nishon', 'Dalil'], rows)
                if res.get('agents'):
                    print("\nMonitoring agentlari (BULARGA TEGMANG):")
                    for a in res['agents']:
                        print("  %s:%s  %s  -> %s" % (a['host'], a['port'] or '?',
                                                      a['product'], a['config_hint']))
                for w in res.get('warnings', []):
                    print("  ! %s" % w)
            if getattr(args, 'sla_out', None):
                with open(args.sla_out, 'w', encoding='utf-8') as f:
                    yaml.safe_dump(to_sla_config(res), f, allow_unicode=True, sort_keys=False)
                print("\nTekshiruv konfigi: %s" % args.sla_out)
            if getattr(args, 'allowlist_out', None):
                with open(args.allowlist_out, 'w', encoding='utf-8') as f:
                    yaml.safe_dump(to_allowlist(res), f, allow_unicode=True, sort_keys=False)
                print("Allowlist: %s" % args.allowlist_out)
        elif args.respcmd == 'doctor':
            from bluekit.resp.servicedoctor import diagnose
            with open(args.current, encoding='utf-8-sig') as f: cur = json.load(f)
            base = None
            if getattr(args, 'baseline', None):
                with open(args.baseline, encoding='utf-8-sig') as f: base = json.load(f)
            res = diagnose(cur, args.service, baseline=base)
            if args.json:
                print(json.dumps(res, ensure_ascii=False, indent=2))
            else:
                print("Xizmat: %s\n" % args.service)
                for i, r in enumerate(res, 1):
                    print("%d. %s   [%s]%s" % (i, r.get('cause'), r.get('confidence', '-'),
                                               "  " + r['technique'] if r.get('technique') else ""))
                    print("   Dalil : %s" % r.get('evidence', ''))
                    if r.get('suggested_fix_command'):
                        print("   Buyruq: %s" % r['suggested_fix_command'])
                    if r.get('risk'):
                        print("   Xavf  : %s" % r['risk'])
                    print()
                print("Buyruqlar faqat taklif -- bajarishdan oldin tekshiring.")
        elif args.respcmd == 'fraud':
            from bluekit.resp.fraud import scan
            with open(args.current, encoding='utf-8-sig') as f: cur = json.load(f)
            bas = None
            if args.baseline:
                with open(args.baseline, encoding='utf-8-sig') as f: bas = json.load(f)
            res = scan(cur, bas, kb)
            if args.json:
                print(json.dumps(res))
            else:
                if not res:
                    print("Fraud: shubhali narsa topilmadi.")
                else:
                    for r in res:
                        techs = ",".join([t.get('id', '') for t in r.get('techniques', [])])
                        reasons = "; ".join(r.get('reasons', []))
                        print(f"{r.get('confidence', ''):<6} | {r.get('category', ''):<20} | {r.get('item', '')} | {techs} | {reasons}")

    
    if args.cmd == 'mail':
        from bluekit.mail.parse import load_eml
        from bluekit.mail.scan import scan_email
        import os
        import glob
        
        targets = []
        if os.path.isdir(args.target):
            targets = glob.glob(os.path.join(args.target, "**/*.eml"), recursive=True)
        else:
            targets = [args.target]
            
        results = []
        for t in targets:
            parsed = load_eml(t)
            res = scan_email(parsed, kb)
            results.append(res)
            
        if args.json:
            print(json.dumps(results if len(results) > 1 else results[0], indent=2))
        else:
            for r in results:
                print(f"\n--- Fayl: {r['file']} ---")
                print(f"Verdikt: {r['verdict']} | Ball: {r['score']}")
                if r['findings']:
                    rows = [[f['check'], f['severity'], str(f['evidence'])[:40], ",".join(f['techniques'])] for f in r['findings']]
                    print_table(["Check", "Severity", "Dalil", "Texnika"], rows)
                if r['urls']:
                    u_rows = [[u['url_defanged'][:50], u['host'], ",".join(u['reasons'])] for u in r['urls']]
                    print_table(["URL", "Host", "Sabab"], u_rows)
                if r['attachments']:
                    a_rows = [[a['filename'], a['size'], 'SUSP' if a['suspicious'] else 'OK', ",".join(a['reasons'])] for a in r['attachments']]
                    print_table(["Fayl", "Hajm", "Shubha", "Sabab"], a_rows)
                
                if 'attribution' in r:
                    attr = r['attribution']
                    print("\nJO'NATUVCHI TAHLILI (Attribution)")
                    print(f"  Origin IP    : {attr.get('origin_ip', '-')} ({attr.get('origin_host', '-')})")
                    print(f"  Anonim mailer: {attr.get('anonymous_mailer') or '-'}")
                    sm = "MOS EMAS" if attr.get('tz_mismatch') else "MOS"
                    print(f"  Vaqt mintaqasi: muallif {attr.get('sender_tz') or '-'} / server {attr.get('server_tz') or '-'}  -> {sm}")
                    print(f"  Spam verdikt : {attr.get('spam_verdict', '-')}")
                    print("\n  Hop zanjiri:")
                    for idx, hop in enumerate(attr.get('hops', []), 1):
                        print(f"    {idx}. {hop.get('host') or '-'}  {hop.get('ip') or '-'}   {hop.get('ts') or '-'}")
                    if attr.get('notes'):
                        print("\n  Xulosa:")
                        for n in attr.get('notes', []):
                            print(f"    - {n}")

                print("\nIZOHLAR:")
                for f in r['findings']:
                    print(f"- {f['check']}: {f['izoh']}")

            if len(results) > 1:
                print("\n--- UMUMIY NATIJA ---")
                sum_rows = [[r['file'], r['verdict'], r['score'], len(r['findings'])] for r in results]
                print_table(["Fayl", "Verdikt", "Ball", "Findings soni"], sum_rows)
                
        if getattr(args, 'out', None):
            if args.out.lower().endswith('.json'):
                text = json.dumps(results if len(results) > 1 else results[0], ensure_ascii=False, indent=2, default=str)
            else:
                from html import escape as _e
                def _tbl(head, rows):
                    return "<table border='1' cellpadding='4'><tr>" + "".join(f"<th>{_e(h)}</th>" for h in head) + "</tr>" + \
                        "".join("<tr>" + "".join(f"<td>{_e(str(c))}</td>" for c in row) + "</tr>" for row in rows) + "</table>"
                text = "<html><head><meta charset='utf-8'><title>Mail scan</title></head><body>"
                for r in results:
                    text += f"<h2>{_e(r['file'])}</h2><p><b>Verdikt: {_e(r['verdict'])}</b> | Ball: {r['score']}</p>"
                    text += _tbl(["Check", "Severity", "Dalil", "Texnika", "Izoh"], [[f['check'], f['severity'], f['evidence'], ",".join(f['techniques']), f['izoh']] for f in r['findings']])
                    text += "<h3>URL</h3>" + _tbl(["URL", "Host", "Sabab"], [[u['url_defanged'], u['host'], ",".join(u['reasons'])] for u in r['urls']])
                    text += "<h3>Ilovalar</h3>" + _tbl(["Fayl", "SHA256", "Hajm", "Sabab"], [[a['filename'], a['sha256'], a['size'], ",".join(a['reasons'])] for a in r['attachments']])
                    text += "<h3>IOC</h3>" + _tbl(["Tur", "Qiymat"], [[i['type'], i['value']] for i in r['iocs']])
                text += "</body></html>"
            with open(args.out, 'w', encoding='utf-8') as f:
                f.write(text)
            print(f"\nSaqlandi: {args.out}")

    if args.cmd == 'web':
        from bluekit.web.server import run_server
        run_server(args.host, args.port, args.data, args.workdir)

    if args.cmd == 'report':
        from bluekit.report.model import build
        from bluekit.report.render import render_html, render_markdown, render_docx
        import yaml
        
        logs_data = {}
        if args.logs:
            with open(args.logs, 'r', encoding='utf-8') as f:
                logs_data = json.load(f)
                
        resp_data = {}
        if args.resp:
            with open(args.resp, 'r', encoding='utf-8') as f:
                resp_data = json.load(f)
                
        answers = {}
        if args.answers:
            with open(args.answers, 'r', encoding='utf-8') as f:
                answers = yaml.safe_load(f) or {}
                
        is_tty = sys.stdin.isatty()
        req_missing = not (answers.get('title') and answers.get('org') and answers.get('team') and answers.get('analyst'))
        
        if is_tty and (args.ask or req_missing):
            try:
                print(f"[{args.lang}] Iltimos, hisobot ma'lumotlarini kiriting (bo'sh qoldirsa default):")
                if not answers.get('title'): answers['title'] = input("Title: ") or ""
                if not answers.get('org'): answers['org'] = input("Org: ") or ""
                if not answers.get('date'):
                    d = input("Date (leave empty for today): ")
                    if d: answers['date'] = d
                if not answers.get('team'): answers['team'] = input("Team: ") or ""
                if not answers.get('analyst'): answers['analyst'] = input("Analyst: ") or ""
            except EOFError:
                # No interactive input available (piped/no stdin) — fall back to defaults below.
                pass
            
        import datetime
        if not answers.get('title'):
            answers['title'] = "Hodisa hisoboti" if args.lang == 'uz' else "Incident Report"
        if not answers.get('date'):
            answers['date'] = datetime.datetime.now().strftime("%Y-%m-%d")
        if not answers.get('org'): answers['org'] = ""
        if not answers.get('team'): answers['team'] = ""
        if not answers.get('analyst'): answers['analyst'] = ""
            
        model = build(logs_data, resp_data, answers)
        
        h = render_html(model, args.lang)
        with open(args.out, 'w', encoding='utf-8') as f:
            f.write(h)
        print(f"HTML hisobot yaratildi: {args.out}")
        
        if args.md:
            m = render_markdown(model, args.lang)
            with open(args.md, 'w', encoding='utf-8') as f:
                f.write(m)
            print(f"Markdown hisobot yaratildi: {args.md}")
            
        if args.docx:
            try:
                render_docx(model, args.lang, args.docx)
                print(f"DOCX hisobot yaratildi: {args.docx}")
            except ImportError:
                print("python-docx yo'q — HTML'ni PDF'ga chop eting")

    if args.cmd == 'report-bot':
        import os
        token = args.token or os.environ.get('BLUEKIT_TG_TOKEN')
        if not token:
            print("Token kiritilmagan. --token yoki BLUEKIT_TG_TOKEN ni ishlating.")
            sys.exit(1)
        try:
            from bluekit.report.telegram_bot import run_bot
            run_bot(token)
        except ImportError:
            print("python-telegram-bot o'rnatilmagan — bu ixtiyoriy. Offline: bk report yoki web UI ishlating.")

    if args.cmd == 'hunt':
        import os
        from bluekit.hunt.beacons import hunt_beacons, render_table
        
        paths = []
        if os.path.isdir(args.path):
            for root, _, files in os.walk(args.path):
                for f in files:
                    paths.append(os.path.join(root, f))
        else:
            paths.append(args.path)
            
        iocs = []
        if args.ioc and os.path.exists(args.ioc):
            with open(args.ioc, 'r') as f:
                iocs = [line.strip() for line in f if line.strip()]
                
        from bluekit.paths import get_resource_path
        allowlist_path = args.allowlist or get_resource_path('bluekit/hunt/allowlist.yaml')
        results = hunt_beacons(paths, iocs, allowlist_path, args.min_sessions, args.max_hosts)
        
        if args.json_out:
            with open(args.json_out, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2)
                
        # the main --json global argument should print to stdout if given, or maybe not, SPEC says --json out.json
        if getattr(args, 'json', False):
            print(json.dumps(results, indent=2))
        else:
            render_table(results, args.all)
            
        if args.out:
            # HTML export is optional based on spec, but flag is there. Simple implementation:
            html = "<html><body><h1>C2 Beacons</h1><table border='1'><tr><th>IP</th><th>Port</th><th>Score</th></tr>"
            for r in results:
                html += f"<tr><td>{r['dst_ip']}</td><td>{r['dst_port']}</td><td>{r['score']}</td></tr>"
            html += "</table></body></html>"
            with open(args.out, 'w', encoding='utf-8') as f:
                f.write(html)

    if args.cmd == 'case':
        sys.exit(_case_cli.run(args))

    if args.cmd == 'ir':
        from bluekit.ir.correlator import load_events_from_files, correlate_incident
        from bluekit.ir.report import build_incident_model, render_scoring_json, render_markdown_report
        
        file_list = args.file if isinstance(args.file, list) else [args.file]
        for _p in file_list:
            if os.path.isfile(_p) and not check_input_format(_p):
                sys.exit(1)
        events, source_name = load_events_from_files(file_list)
        if not events:
            print(f"Xato: '{args.file}' faylidan hodisalar topilmadi yoki o'qib bo'lmadi.")
            sys.exit(1)

        chain = correlate_incident(events, kb)
        model = build_incident_model(chain, source_name, len(events))

        if args.ircmd == 'chain':
            if args.json:
                res = render_scoring_json(model)
                if getattr(args, 'out', None):
                    with open(args.out, 'w', encoding='utf-8') as f:
                        f.write(res)
                    print(f"Scoring JSON saqlandi: {args.out}")
                else:
                    print(res)
            else:
                rows = []
                for idx, s in enumerate(chain.stages, 1):
                    ts = s.timestamp_display or s.timestamp[:19].replace('T', ' ')
                    t_str = f"{s.technique_id} ({s.technique_name[:28]})"
                    rows.append([f"#{idx}", ts, s.host, s.phase, t_str, s.evidence[:65]])
                print(f"\n[IR ATTACK CHAIN] Jami hodisalar: {len(events)} | Zanjir qadamlari: {len(chain.stages)} | Hostlar: {', '.join(chain.hosts_involved)}")
                print_table(["#", "Vaqt (logdagi)", "Host", "Phase", "MITRE ATT&CK", "Evidence"], rows)
                
                print("\nIZOHLAR:")
                for idx, s in enumerate(chain.stages, 1):
                    print(f"  #{idx}  {getattr(s, 'explain_uz', '')}")
                
                lat_path = getattr(chain, 'attack_path', [])
                if lat_path:
                    print(f"\n[LATERAL MOVEMENT] Hujum yo'li: {' → '.join(lat_path)}")
                    lat_rows = []
                    for idx, edge in enumerate(getattr(chain, 'lateral_edges', []), 1):
                        ts = edge.get('first_seen_display') or edge.get('first_seen', '')[:19]
                        src = edge.get('src_host') or '?'
                        dst = edge.get('dst_host')
                        usr = edge.get('user')
                        meth = edge.get('method')
                        if edge.get('count', 1) > 1:
                            meth = f"{meth} (x{edge['count']})"
                        techs = ", ".join(edge.get('techniques', []))
                        status = edge.get('status')
                        lat_rows.append([f"#{idx}", ts, src, dst, usr, meth, techs, status])
                    print_table(["#", "Vaqt (logdagi)", "Dan", "Ga", "Akkaunt", "Usul", "MITRE", "Holat"], lat_rows)
                else:
                    print(f"\n[LATERAL MOVEMENT] hostdan hostga o'tish topilmadi")

                print("\n[EXTRACTED IOCs]")
                ioc_rows = [[i['value'], i['type'], i['role'], i['description'][:50]] for i in model.all_iocs]
                print_table(["IOC Value", "Type", "Role", "Description"], ioc_rows)

                from bluekit.tz import tz_note
                print("\n" + tz_note())

                if getattr(args, 'out', None):
                    rep = render_markdown_report(model, args.lang)
                    with open(args.out, 'w', encoding='utf-8') as f:
                        f.write(rep)
                    print(f"\nHisobot saqlandi: {args.out}")

        elif args.ircmd == 'report':
            md_content = render_markdown_report(model, args.lang)
            with open(args.out, 'w', encoding='utf-8') as f:
                f.write(md_content)
            print(f"\n[+] Incident Response hisoboti saqlandi: {args.out} (Til: {args.lang})")

            if getattr(args, 'json_out', None):
                json_str = render_scoring_json(model)
                with open(args.json_out, 'w', encoding='utf-8') as f:
                    f.write(json_str)
                print(f"[+] Scoring JSON saqlandi: {args.json_out}")

if __name__ == '__main__':
    main()
