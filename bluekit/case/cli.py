import argparse
import sys
import json
from datetime import datetime
from .loaders import load_case
from .solver import solve, outcome, ident_values

def add_arguments(parser):
    parser.add_argument("path", help="Path to challenge JSON or folder")
    parser.add_argument("--json", action="store_true", help="Output JSON result")
    parser.add_argument("--out", help="Write submission JSON to file")

def run(args):
    try:
        events, ctx = load_case(args.path)
        res = solve(events, ctx)
    except Exception as e:
        print(f"Error: {e}")
        return 1

    if args.json:
        def default(o):
            if isinstance(o, datetime): return o.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+'Z'
            if isinstance(o, set): return sorted(list(o))
            if hasattr(o, '__str__'): return str(o)
            raise TypeError
        print(json.dumps(res, default=default, indent=2))
    else:
        c = res['counts']
        print(f"Counts: total={c['total']} approved={c['approved']} telemetry={c['telemetry']} candidate={c['candidate']} components={c['components']}")
        print(f"Baseline: ranges={res['baseline']['ranges']} singles={res['baseline']['singles']} classes={res['baseline']['classes']} nets={[str(n) for n in res['baseline']['nets']]}")
        for i, e in enumerate(res['chain']):
            warn = "⚠ noaniq tartib" if e.get('order_uncertain') else ""
            outc = outcome(e)
            links = []
            for j in range(i):
                common = ident_values(e) & ident_values(res['chain'][j])
                if common: links.append(f"bosqich {j+1} bilan umumiy: {','.join(common)}")
            links_str = "; ".join(links)
            utc_str = e['utc'].strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+'Z'
            print(f"{utc_str} (raw {e['raw_time']} off={e['off']}) {e['source']} {e['action']} {e['id']} {outc} {links_str} {warn}")
        if res['orphans']:
            print(f"Orphans: {[e['id'] for e in res['orphans']]}")
        if res['warnings']:
            print(f"Warnings: {res['warnings']}")
        print(f"FLAG: {res['flag']}")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as out_f:
            json.dumps(res['submission']) # Check serialize
            out_f.write(json.dumps(res['submission'], indent=2))

    return 0

def main(argv=None):
    try: sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except: pass
    parser = argparse.ArgumentParser()
    parser.add_argument("command", nargs="?")
    add_arguments(parser)
    args = parser.parse_args(argv)
    sys.exit(run(args))

if __name__ == '__main__':
    main()
