import os
import uuid
import base64
from bluekit.case.loaders import load_case
from bluekit.case.solver import solve, outcome, ident_values

def handle_case_solve(handler, data):
    try:
        if 'filename' in data:
            if 'content' not in data and 'content_b64' not in data:
                handler.end_error("Kontent berilmagan", 400)
                return
                
            if '..' in data['filename'] or '/' in data['filename'] or '\\' in data['filename']:
                handler.end_error("Yaroqsiz fayl nomi", 400)
                return
            fname = os.path.basename(data['filename'])
            if not fname or fname in ('.', '..'):
                handler.end_error("Noto'g'ri fayl nomi", 400)
                return
                
            case_id = f"case_{uuid.uuid4().hex}"
            case_dir = os.path.join(handler.server.workdir, case_id)
            os.makedirs(case_dir, exist_ok=True)
            path = os.path.join(case_dir, fname)
            
            if 'content_b64' in data:
                b = base64.b64decode(data['content_b64'])
                with open(path, 'wb') as f:
                    f.write(b)
            else:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(data['content'])
        elif 'path' in data:
            path = handler._resolve_path(data['path'])
            if not path or not os.path.exists(path):
                handler.end_error("Fayl topilmadi", 400)
                return
        else:
            handler.end_error("Yo'l yoki kontent berilmagan", 400)
            return
            
        events, ctx = load_case(path)
        res = solve(events, ctx)
        
        chain = []
        for i, e in enumerate(res['chain']):
            links = []
            for j in range(i):
                common = sorted(list(ident_values(e) & ident_values(res['chain'][j])))
                if common:
                    links.append({"stage": j + 1, "values": common})
                    
            item = {
                "id": e["id"],
                "source": e["source"],
                "action": e["action"],
                "raw_time": e["raw_time"],
                "utc": e["utc"].strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
                "off": e["off"],
                "outcome": outcome(e),
                "order_uncertain": bool(e.get("order_uncertain")),
                "links": links,
                "attrs": e["attrs"]
            }
            chain.append(item)
            
        orphans = [{"id": o["id"], "source": o["source"], "action": o["action"]} for o in res.get("orphans", [])]
        
        b = res.get("baseline", {})
        baseline = {
            "ranges": [f"{p}-{lo}..{hi}" for p, lo, hi in b.get("ranges", [])],
            "singles": sorted(list(b.get("singles", []))),
            "classes": sorted(list(b.get("classes", []))),
            "nets": [str(n) for n in b.get("nets", [])],
            "ips": sorted(list(b.get("ips", [])))
        }
        
        new_res = {
            "chain": chain,
            "orphans": orphans,
            "baseline": baseline,
            "flag": res["flag"],
            "flag_input": res["flag_input"],
            "counts": res["counts"],
            "lookalike_groups": res["lookalike_groups"],
            "warnings": res["warnings"],
            "submission": res["submission"]
        }
        
        handler.end_json(new_res)
    except ValueError as e:
        handler.end_error(str(e), 400)
    except FileNotFoundError as e:
        handler.end_error(str(e), 400)
    except Exception as e:
        handler.end_error("Ichki xato", 500)
