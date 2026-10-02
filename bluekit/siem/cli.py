"""`bk siem` buyruqlari — SIEM so'rovlarini ro'yxatlash va yaratish."""

import sys
import argparse
import json

from .builder import build_query, list_dialects, list_hunts, get_hunt
from .catalog import CATEGORIES


def _table(headers, rows):
    if not rows:
        return "Natija yo'q."
    widths = [len(str(h)) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(str(c)))
    fmt = " | ".join("{:<%d}" % w for w in widths)
    out = [fmt.format(*headers), "-+-".join("-" * w for w in widths)]
    for r in rows:
        out.append(fmt.format(*[str(c) for c in r]))
    return "\n".join(out)


def format_query(res):
    """Terminalga chiqadigan matn. So'rovning o'zi bezaksiz — ko'chirishga tayyor."""
    lines = [
        "=== %s — %s ===" % (res['hunt_id'], res['hunt_name']),
        "SIEM: %s (%s)   |   ATT&CK: %s" % (res['siem_name'], res['language'],
                                            ', '.join(res['attack'])),
        "Parametrlar: %s" % ', '.join('%s=%s' % (k, v)
                                      for k, v in sorted(res['params'].items())),
        "",
        res['query'],
        "",
    ]
    if res['notes']:
        lines.append("Eslatmalar:")
        for n in res['notes']:
            lines.append("  - %s" % n)
    if res['tuning']:
        lines.append("Sozlash: %s" % res['tuning'])
    lines.append("")
    lines.append("Eksport qilgandan keyin:")
    for step in res['next_steps']:
        lines.append("  %s" % step)
    return "\n".join(lines)


def format_show(hunt):
    lines = [
        "=== %s — %s ===" % (hunt['id'], hunt['name']),
        "Kategoriya: %s (%s)" % (CATEGORIES[hunt['category']], hunt['category']),
        "Log manbasi: %s" % hunt.get('logsource', 'any'),
        "ATT&CK: %s" % ', '.join(hunt['attack']),
        "",
        hunt['description'],
        "",
        "Chiqariladigan ustunlar: %s" % ', '.join(hunt.get('select', [])),
        "Parametrlar (default): %s" % ', '.join(
            '%s=%s' % (k, v) for k, v in sorted(hunt.get('params', {}).items())),
        "",
        "Sozlash: %s" % hunt.get('tuning', ''),
        "",
        "So'rov olish: python bk.py siem query %s --siem <siem>" % hunt['id'],
    ]
    return "\n".join(lines)


def _emit(text, out_path):
    if out_path:
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(text + "\n")
        print("Yozildi: %s" % out_path)
    else:
        print(text)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except AttributeError:
        pass

    parser = argparse.ArgumentParser(
        prog='bk siem', description="SIEM uchun tayyor qidiruv so'rovlari generatori")
    sub = parser.add_subparsers(dest='command', required=True)

    p = sub.add_parser('list', help="Qo'llab-quvvatlanadigan SIEM lar")
    p.add_argument('--json', action='store_true')

    p = sub.add_parser('hunts', help="Nima qidirish mumkin — hunt lar ro'yxati")
    p.add_argument('--category', help="Kategoriya: %s" % ', '.join(sorted(CATEGORIES)))
    p.add_argument('--search', help="Nom, tavsif yoki ATT&CK ID bo'yicha qidirish")
    p.add_argument('--siem')
    p.add_argument('--json', action='store_true')

    p = sub.add_parser('show', help="Bitta hunt haqida batafsil")
    p.add_argument('hunt_id')
    p.add_argument('--json', action='store_true')

    p = sub.add_parser('query', help="So'rov yaratish")
    p.add_argument('hunt_id')
    p.add_argument('--siem', required=True, help="SIEM id yoki 'all'")
    p.add_argument('--days', type=int)
    p.add_argument('--threshold', type=int)
    p.add_argument('--limit', type=int)
    p.add_argument('--host')
    p.add_argument('--user')
    p.add_argument('--ip')
    p.add_argument('--out')
    p.add_argument('--json', action='store_true')

    p = sub.add_parser('pack', help="Bir nechta so'rovni bitta faylga")
    p.add_argument('--siem', required=True)
    p.add_argument('--category')
    p.add_argument('--search')
    p.add_argument('--days', type=int)
    p.add_argument('--out')
    p.add_argument('--json', action='store_true')

    args = parser.parse_args(argv)

    try:
        return _run(args)
    except ValueError as e:
        print("Xato: %s" % e)
        return 1


def _params(args):
    out = {}
    for key in ('days', 'threshold', 'limit', 'host', 'user', 'ip'):
        val = getattr(args, key, None)
        if val is not None:
            out[key] = val
    return out


def _run(args):
    if args.command == 'list':
        dialects = list_dialects()
        if args.json:
            print(json.dumps(dialects, indent=2, ensure_ascii=False))
            return 0
        rows = [(k, v['name'], v['language'], v['bk_preset'] or '-', v['where'])
                for k, v in dialects.items()]
        print(_table(['ID', 'SIEM', 'Til', 'bk preset', 'Qayerga qo\'yiladi'], rows))
        print("\nSo'rov olish: python bk.py siem query <hunt-id> --siem <ID>")
        return 0

    if args.command == 'hunts':
        hunts = list_hunts(args.category, args.search, args.siem)
        if args.json:
            print(json.dumps(hunts, indent=2, ensure_ascii=False))
            return 0
        rows = [(h['id'], h['name'], CATEGORIES[h['category']], ', '.join(h['attack']))
                for h in hunts]
        print(_table(['ID', 'Nomi', 'Kategoriya', 'ATT&CK'], rows))
        print("\nJami: %d ta. Batafsil: python bk.py siem show <hunt-id>" % len(rows))
        return 0

    if args.command == 'show':
        hunt = get_hunt(args.hunt_id)
        if args.json:
            print(json.dumps(hunt, indent=2, ensure_ascii=False))
            return 0
        print(format_show(hunt))
        return 0

    if args.command == 'query':
        siems = list(list_dialects()) if args.siem == 'all' else [args.siem]
        results = [build_query(args.hunt_id, s, _params(args)) for s in siems]
        if args.json:
            payload = results[0] if len(results) == 1 else results
            text = json.dumps(payload, indent=2, ensure_ascii=False)
        else:
            text = "\n\n".join(format_query(r) for r in results)
        _emit(text, args.out)
        return 0

    if args.command == 'pack':
        hunts = list_hunts(args.category, args.search, args.siem)
        if not hunts:
            print("Bu shartlarga mos hunt topilmadi.")
            return 1
        params = _params(args)
        results = [build_query(h['id'], args.siem, params) for h in hunts]
        if args.json:
            text = json.dumps(results, indent=2, ensure_ascii=False)
        else:
            header = "%s uchun %d ta so'rov" % (results[0]['siem_name'], len(results))
            text = "\n\n".join([header, "=" * len(header)] +
                               [format_query(r) for r in results])
        _emit(text, args.out)
        return 0

    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
