import os
import json
import urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import mimetypes
import uuid
import sys
import contextlib

from bluekit.paths import get_kb_path, get_resource_path
from bluekit.kb.query import KB
from bluekit.kb.ioc import techniques_for_ioc
from bluekit.logs.report import analyze_logs
from bluekit.resp.triage import analyze as resp_analyze
from bluekit.resp.remediate import generate_all
from bluekit.resp.sla import check as resp_sla_check
from bluekit.resp.servicedoctor import diagnose as resp_doctor
from bluekit.resp.fraud import scan as resp_fraud
from bluekit import playbook
from bluekit import tracker as trk
from bluekit import answers
from bluekit.logs.sigma import SigmaEngine, drop_weak

HITS_LIMIT = 500

def get_static_dir():
    if os.environ.get('BLUEKIT_STATIC') and os.path.isdir(os.environ['BLUEKIT_STATIC']):
        return os.environ['BLUEKIT_STATIC']
    # Frozen (exe) holatda diskdagi eski 'static' nusxasi exe ichidagi yangi UI ni
    # to'sib qo'ygan edi — shuning uchun exe har doim o'zinikini ishlatadi.
    # Diskdagi nusxani ataylab ishlatish kerak bo'lsa: BLUEKIT_STATIC=<papka>
    if getattr(sys, 'frozen', False):
        return os.path.join(os.path.dirname(__file__), 'static')
    cwd_static = os.path.join(os.getcwd(), 'static')
    if os.path.isdir(cwd_static):
        return cwd_static
    exe_dir_static = os.path.join(os.path.dirname(sys.executable), 'static')
    if os.path.isdir(exe_dir_static):
        return exe_dir_static
    return os.path.join(os.path.dirname(__file__), 'static')

STATIC_DIR = get_static_dir()

class WebKitServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, kb, workdir):
        super().__init__(server_address, RequestHandlerClass)
        self.kb = kb
        self.workdir = workdir
        os.makedirs(workdir, exist_ok=True)
        self.tracker_file = os.path.join(workdir, 'tracker.json')
        self.ledger_file = os.path.join(workdir, 'answers.json')
        if not os.path.exists(self.tracker_file):
            with open(self.tracker_file, 'w', encoding='utf-8') as f:
                json.dump([], f)
        self.playbook_file = os.path.join(workdir, 'playbook.json')
        if not os.path.exists(self.playbook_file):
            with open(self.playbook_file, 'w', encoding='utf-8') as f:
                json.dump(playbook.default_state(), f, ensure_ascii=False)

class WebKitHandler(BaseHTTPRequestHandler):
    def end_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    @contextlib.contextmanager
    def _naive_tz(self, payload):
        import bluekit.tz
        old_tz = bluekit.tz.get_naive_tz()
        try:
            if 'src_tz' in payload:
                bluekit.tz.set_naive_tz(payload['src_tz'])
            yield
        finally:
            if 'src_tz' in payload:
                bluekit.tz.set_naive_tz(old_tz)

    def end_error(self, msg, status=400):
        self.end_json({"error": msg}, status=status)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path.startswith('/api/'):
            try:
                self.handle_api_get(path, qs)
            except Exception as e:
                import traceback
                traceback.print_exc()
                self.end_error(str(e), 500)
            return

        if path == '/':
            path = '/index.html'
        
        safe_path = os.path.normpath(path).lstrip('\\/')
        static_dir = get_static_dir()
        file_path = os.path.join(static_dir, safe_path)
        if not os.path.abspath(file_path).startswith(os.path.abspath(static_dir)):
            self.send_error(403, "Forbidden")
            return
        
        if os.path.isfile(file_path):
            ctype, _ = mimetypes.guess_type(file_path)
            self.send_response(200)
            self.send_header('Content-Type', ctype or 'application/octet-stream')
            self.end_headers()
            with open(file_path, 'rb') as f:
                self.wfile.write(f.read())
        else:
            self.send_error(404, "Not Found")

    def handle_api_get(self, path, qs):
        kb = self.server.kb
        if path == '/api/info':
            self.end_json(kb.version())
        elif path == '/api/validate':
            ids = qs.get('ids', [''])[0].split(',')
            self.end_json(kb.validate(ids))
        elif path == '/api/search':
            q = qs.get('q', [''])[0]
            domain = qs.get('domain', [None])[0]
            n = int(qs.get('n', [20])[0])
            self.end_json(kb.search(q, limit=n, domain=domain))
        elif path == '/api/id':
            id_val = qs.get('id', [''])[0]
            self.end_json(kb.lookup(id_val))
        elif path == '/api/related':
            ids = qs.get('ids', [''])[0].split(',')
            n = int(qs.get('n', [25])[0])
            actors = qs.get('actors', ['0'])[0] == '1'
            res = {"techniques": kb.related(ids, limit=n)}
            if actors:
                res["actors"] = kb.actors_matching(ids, limit=5)
            self.end_json(res)
        elif path == '/api/ioc':
            v = qs.get('v', [''])[0]
            n = int(qs.get('n', [5])[0])
            self.end_json(techniques_for_ioc(kb, v, limit=n))
        elif path == '/api/tactics':
            ids = qs.get('ids', [''])[0].split(',')
            domain = qs.get('domain', ['enterprise'])[0]
            self.end_json(kb.tactic_coverage(ids, domain=domain))
        elif path == '/api/siem/dialects':
            from bluekit.siem.builder import list_dialects
            self.end_json(list_dialects())
        elif path == '/api/siem/hunts':
            from bluekit.siem.builder import list_hunts
            from bluekit.siem.catalog import CATEGORIES
            category = qs.get('category', [''])[0]
            search = qs.get('search', [''])[0]
            # None to match default params if empty
            if not category: category = None
            if not search: search = None
            self.end_json({"hunts": list_hunts(category, search), "categories": CATEGORIES})
        elif path == '/api/tracker':
            try:
                rows = trk.load(self.server.tracker_file)
                self.end_json([trk.public_row(r) for r in rows])
            except trk.TrackerError as e:
                self.end_error(str(e), 400)
            except Exception as e:
                self.end_error(str(e), 500)
        elif path == '/api/playbook':
            warn = None
            try:
                with open(self.server.playbook_file, 'r', encoding='utf-8') as f:
                    state = json.load(f)
                state = playbook.validate_state(state)
            except Exception:
                state = playbook.default_state()
                warn = "playbook.json o'qilmadi, holat tiklandi"
            res = {
                "phases": playbook.PHASES,
                "kill_chain": playbook.KILL_CHAIN,
                "rules": playbook.RULES,
                "state": state,
                "progress": playbook.progress(state)
            }
            if warn:
                res["warning"] = warn
            self.end_json(res)
        elif path == '/api/sigma/info':
            import bluekit.logs.parse as logs_parse
            if not hasattr(self.server, '_sigma_info'):
                try:
                    import yaml
                    fieldmap_path = os.path.join(os.path.dirname(logs_parse.__file__), 'fieldmap.yaml')
                    with open(fieldmap_path, 'r', encoding='utf-8') as f:
                        fm = yaml.safe_load(f)
                    presets = list(fm.get('presets', {}).keys())
                except Exception:
                    presets = []
                eng = SigmaEngine(kb_path=self.server.kb.path)
                self.server._sigma_info = {
                    "presets": presets,
                    "levels": ["informational", "low", "medium", "high", "critical"],
                    "rules": eng.stats()
                }
            self.end_json(self.server._sigma_info)
        else:
            self.end_error("Not Found", 404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        
        if path.startswith('/api/'):
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length)
                if body:
                    data = json.loads(body.decode('utf-8'))
                else:
                    data = {}
                self.handle_api_post(path, data)
            except (ValueError, FileNotFoundError) as e:
                self.end_error(str(e), 400)
            except Exception as e:
                import traceback
                traceback.print_exc()
                self.end_error(str(e), 500)
            return
        
        self.send_error(404, "Not Found")

    def handle_api_post(self, path, data):
        kb = self.server.kb
        if path == '/api/logs/analyze':
            preset = data.get('preset')
            map_path = data.get('map')
            
            json_out = os.path.join(self.server.workdir, f"out_{uuid.uuid4().hex}.json")
            
            try:
                with self._naive_tz(data):
                    file_path = self._logs_input_paths(data)
                    
                    from bluekit.logs.filter import parse_bound
                    
                    from_s = data.get('from')
                    to_s = data.get('to')
                    host = data.get('host')
                    
                    for k, v in [('from', from_s), ('to', to_s), ('host', host)]:
                        if v is not None and not isinstance(v, str):
                            raise ValueError(f"'{k}' satr bo'lishi kerak")
                            
                    from_s = from_s.strip() if from_s else None
                    to_s = to_s.strip() if to_s else None
                    host = host.strip() if host else None
                    
                    from_dt = parse_bound(from_s) if from_s else None
                    to_dt = parse_bound(to_s, end=True) if to_s else None
                    
                    if from_dt and to_dt and from_dt > to_dt:
                        raise ValueError("'Dan' vaqti 'Gacha' dan keyin bo'lmasligi kerak")
                        
                    analyze_logs(file_path, kb, preset=preset, map_path=map_path, json_path=json_out, html_path=None, deep=data.get('deep', False), from_dt=from_dt, to_dt=to_dt, host=host)
                    with open(json_out, 'r', encoding='utf-8') as f:
                        self.end_json(json.load(f))
            except ValueError as e:
                self.end_error(str(e), 400)
                
        elif path == '/api/sigma/scan':
            import bluekit.logs.parse as logs_parse
            import yaml
            
            preset = data.get('preset')
            level = data.get('level')
            products = data.get('products')
            weak = data.get('weak', False)
            
            if preset:
                try:
                    fieldmap_path = os.path.join(os.path.dirname(logs_parse.__file__), 'fieldmap.yaml')
                    with open(fieldmap_path, 'r', encoding='utf-8') as f:
                        fm = yaml.safe_load(f)
                    presets = list(fm.get('presets', {}).keys())
                    if preset not in presets:
                        self.end_error(f"Noma'lum preset. Ruxsat etilganlar: {', '.join(presets)}", 400)
                        return
                except Exception:
                    pass
            
            if level and level not in ["informational", "low", "medium", "high", "critical"]:
                self.end_error("Noma'lum daraja", 400)
                return
                
            if 'products' in data and products is not None:
                if not isinstance(products, list) or not all(isinstance(p, str) and p.strip() for p in products):
                    self.end_error("Mahsulotlar ro'yxati (products) noto'g'ri", 400)
                    return
            
            if not data.get('files') and not data.get('content') and not data.get('path'):
                self.end_error("Kirish fayllari kiritilmadi", 400)
                return
            
            try:
                paths = self._logs_input_paths(data)
                if not paths:
                    self.end_error("Fayl topilmadi", 400)
                    return
                if isinstance(paths, list):
                    for p in paths:
                        if not os.path.exists(p):
                            self.end_error(f"Fayl nomi topilmadi: {p}", 400)
                            return
                else:
                    if not os.path.exists(paths):
                        self.end_error(f"Fayl nomi topilmadi: {paths}", 400)
                        return
            except Exception as e:
                self.end_error(str(e), 400)
                return
                
            with self._naive_tz(data):
                if isinstance(paths, list):
                    events = logs_parse.load_many(paths, preset=preset or None)
                else:
                    events = logs_parse.load(paths, preset=preset or None)
                
                if not events:
                    self.end_error("0 ta hodisa o'qildi — format yoki presetni tekshiring", 400)
                    return
                    
                eng = SigmaEngine(kb_path=self.server.kb.path, products=products or None, min_level=level or None)
                res = eng.match_events(events)
                
                if not weak:
                    drop_weak(res)
                    
                rule_titles = {}
                for h in res.get('hits', []):
                    for r in h.get('rules', []):
                        if r.get('rule_id'):
                            rule_titles[r['rule_id']] = r.get('title', r['rule_id'])
                            
                hits_total = len(res.get('hits', []))
                hits = res.get('hits', [])
                
                def hit_sort_key(h):
                    has_non_weak = any(not r.get('weak', False) for r in h.get('rules', []))
                    levels_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1, None: 0}
                    max_level_val = max((levels_order.get(r.get('level'), 0) for r in h.get('rules', [])), default=0)
                    return (-int(has_non_weak), -max_level_val, h.get('index', 0))
                
                hits.sort(key=hit_sort_key)
                
                hits_truncated = False
                if len(hits) > HITS_LIMIT:
                    hits = hits[:HITS_LIMIT]
                    hits_truncated = True
                    
                techniques = []
                for tid, tdata in res.get('by_technique', {}).items():
                    new_rules = []
                    for rid in tdata.get('rules', []):
                        new_rules.append({"rule_id": rid, "title": rule_titles.get(rid, rid)})
                    techniques.append({
                        "technique": tid,
                        "count": tdata.get('count', 0),
                        "level": tdata.get('level'),
                        "rules": new_rules
                    })
                techniques.sort(key=lambda x: (-x['count'], x['technique']))
                
                # Remove sets or invalid types from by_technique
                safe_by_technique = {}
                for tid, tdata in res.get('by_technique', {}).items():
                    safe_by_technique[tid] = {
                        "count": tdata.get('count', 0),
                        "level": tdata.get('level'),
                        "rules": list(tdata.get('rules', []))
                    }
                
                for h in hits:
                    if h.get('ts'):
                        h['ts'] = str(h['ts'])
                
                out = {
                    "hits": hits,
                    "by_technique": safe_by_technique,
                    "stats": res.get('stats', {}),
                    "techniques": techniques,
                    "hits_total": hits_total,
                    "hits_truncated": hits_truncated,
                    "params": {"preset": preset or None, "level": level or None, "products": products or [], "weak": weak}
                }
                self.end_json(out)
        
        elif path == '/api/resp/triage':
            cur, bas, prot = self._load_resp_args(data)
            log_artifacts = self._load_resp_logs(data)
            findings, extra = resp_analyze(kb, cur, bas, prot, log_artifacts=log_artifacts)
            self.end_json({'findings': findings, 'extra': extra})
            
        elif path == '/api/resp/fix':
            cur, bas, prot = self._load_resp_args(data)
            log_artifacts = self._load_resp_logs(data)
            findings, _ = resp_analyze(kb, cur, bas, prot, log_artifacts=log_artifacts)
            os_val = data.get('os', 'windows')
            full = data.get('full', False)
            script = generate_all(findings, os_val, full)
            self.end_json({"script": script})
            
        elif path == '/api/resp/sla':
            import yaml
            services = []
            if 'services_yaml' in data:
                try:
                    parsed = yaml.safe_load(data['services_yaml'])
                    if isinstance(parsed, dict) and 'services' in parsed:
                        services = parsed['services']
                    elif isinstance(parsed, list):
                        services = parsed
                except yaml.YAMLError as e:
                    self.end_error(f"YAML parsing error: {e}", 400)
                    return
            else:
                services = data.get('services', [])
                
            if not services:
                self.end_error("Xizmatlar ro'yxati bo'sh — services.yaml kiriting (namuna: responder/sla.example.yaml)", 400)
                return
                
            res = resp_sla_check({"services": services})
            self.end_json(res)
            
        elif path == '/api/resp/doctor':
            cur, bas, _ = self._load_resp_args(data)
            service = data.get('service')
            res = resp_doctor(cur, service, bas)
            self.end_json(res)
            
        elif path == '/api/resp/fraud':
            cur, bas, _ = self._load_resp_args(data)
            res = resp_fraud(cur, bas, kb)
            self.end_json(res)
            
        elif path == '/api/ir/chain':
            from bluekit.ir.correlator import load_events_from_files, correlate_incident
            from bluekit.ir.report import build_incident_model, render_scoring_json, render_markdown_report
            
            file_paths = []
            if 'files' in data and isinstance(data['files'], list):
                for f_item in data['files']:
                    if 'content' in f_item and 'filename' in f_item:
                        fp = os.path.join(self.server.workdir, os.path.basename(f_item['filename']))
                        with open(fp, 'w', encoding='utf-8') as f:
                            f.write(f_item['content'])
                        file_paths.append(fp)
                    elif 'path' in f_item:
                        fp = f_item['path']
                        if not os.path.isabs(fp):
                            if os.path.exists(os.path.join(os.getcwd(), fp)):
                                fp = os.path.join(os.getcwd(), fp)
                            elif os.path.exists(os.path.join(self.server.workdir, fp)):
                                fp = os.path.join(self.server.workdir, fp)
                        file_paths.append(fp)
            elif 'content' in data and 'filename' in data:
                file_path = os.path.join(self.server.workdir, os.path.basename(data['filename']))
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(data['content'])
                file_paths.append(file_path)
            else:
                file_path = data.get('path')
                if not file_path:
                    raise ValueError("Fayl yo'li yoki content ko'rsatilmadi.")
                if not os.path.isabs(file_path):
                    if os.path.exists(os.path.join(os.getcwd(), file_path)):
                        file_path = os.path.join(os.getcwd(), file_path)
                    elif os.path.exists(os.path.join(self.server.workdir, file_path)):
                        file_path = os.path.join(self.server.workdir, file_path)
                file_paths.append(file_path)
                        
            with self._naive_tz(data):
                events, source_name = load_events_from_files(file_paths)
                if not events:
                    raise ValueError(f"Fayldan hodisalar o'qib bo'lmadi: {file_paths}")
                    
                chain = correlate_incident(events, kb)
                model = build_incident_model(chain, source_name, len(events))
                
                lang = data.get('lang', 'ru')
                report_md = render_markdown_report(model, lang)
                scoring_json = json.loads(render_scoring_json(model))
                
                self.end_json({
                    "model": model.to_dict(),
                    "scoring_json": scoring_json,
                    "report_md": report_md
                })

        elif path == '/api/hunt/beacons':
            from bluekit.hunt.beacons import hunt_beacons, group_by_dst

            file_paths = self._collect_input_files(data)
            expanded = []
            for fp in file_paths:
                if os.path.isdir(fp):
                    for root, _, files in os.walk(fp):
                        for name in files:
                            expanded.append(os.path.join(root, name))
                else:
                    expanded.append(fp)

            iocs = data.get('iocs') or []
            if isinstance(iocs, str):
                iocs = [ln.strip() for ln in iocs.splitlines() if ln.strip()]

            allowlist_path = data.get('allowlist') or get_resource_path('bluekit/hunt/allowlist.yaml')
            from bluekit.tz import tz_note
            with self._naive_tz(data):
                results = hunt_beacons(expanded, iocs,
                                       allowlist_path,
                                       int(data.get('min_sessions', 10)),
                                       int(data.get('max_hosts', 100)))

                shown = group_by_dst(results, all_results=bool(data.get('all', False)))
                valid_levels = ("YUQORI", "O'RTA", "MA'LUM")
                all_grouped = group_by_dst(results, all_results=True)

                self.end_json({
                    "candidates": shown,
                    "summary": {
                        "checked": sum(1 for g in all_grouped if g['level'] in valid_levels),
                        "high_medium": sum(1 for g in shown if g['level'] in valid_levels),
                        "total_groups": len(all_grouped),
                        "tz_note": tz_note()
                    }
                })

        elif path == '/api/siem/query':
            from bluekit.siem.builder import build_query
            hunt_id = data.get('hunt_id')
            siem = data.get('siem')
            kwargs = {}
            for k in ['days', 'threshold', 'limit', 'host', 'user', 'ip']:
                if k in data and data[k] not in (None, ''):
                    kwargs[k] = data[k]
                    if k in ['days', 'threshold', 'limit'] and isinstance(kwargs[k], str):
                        kwargs[k] = int(kwargs[k])

            try:
                if siem == 'all':
                    from bluekit.siem.builder import list_dialects
                    results = []
                    for key in list_dialects().keys():
                        try:
                            results.append(build_query(hunt_id, key, params=kwargs))
                        except Exception:
                            pass
                    self.end_json({"results": results})
                else:
                    self.end_json({"results": [build_query(hunt_id, siem, params=kwargs)]})
            except ValueError as e:
                self.end_error(str(e), 400)

        elif path.startswith('/api/tracker'):
            try:
                parts = path.split('/')
                if path == '/api/tracker':
                    def do_add(rows):
                        return trk.add_row(rows, data)
                    new_row = trk.mutate(self.server.tracker_file, do_add)
                    self.end_json({"id": new_row["id"], "row": trk.public_row(new_row)})
                elif len(parts) >= 5 and parts[4] == 'check':
                    row_id = parts[3]
                    rows = trk.load(self.server.tracker_file)
                    row = trk.find_row(rows, row_id)
                    ans = data.get('answer', '')
                    check = trk.check_attempt(row, ans)
                    self.end_json(check)
                elif len(parts) >= 5 and parts[4] == 'attempts':
                    row_id = parts[3]
                    ans = data.get('answer', '')
                    res = data.get('result', 'pending')
                    force = data.get('force') is True
                    
                    check_res = {}
                    updated_row = {}
                    def do_add_att(rows):
                        nonlocal check_res, updated_row
                        row = trk.find_row(rows, row_id)
                        check_res = trk.add_attempt(row, ans, res, force=force)
                        updated_row = dict(row)
                        return row
                    
                    try:
                        trk.mutate(self.server.tracker_file, do_add_att)
                    except trk.AttemptNeedsConfirm as e:
                        self.end_json({"error": "; ".join(e.check["warnings"]), "needs_confirm": True, "check": e.check}, status=409)
                        return
                        
                    out = {"row": trk.public_row(updated_row), "check": check_res}
                    
                    if trk.is_attack_id(ans):
                        try:
                            answers.record(self.server.ledger_file, ans.upper(), res, note=updated_row.get("question"))
                        except Exception as e:
                            out["ledger_warning"] = str(e)
                    
                    self.end_json(out)
                else:
                    self.end_error("Not Found", 404)
            except trk.RowNotFound:
                self.end_error("Not Found", 404)
            except trk.TrackerError as e:
                self.end_error(str(e), 400)
            except Exception as e:
                self.end_error(str(e), 500)

        elif path == '/api/playbook/step':
            from datetime import datetime, timezone
            try:
                with open(self.server.playbook_file, 'r', encoding='utf-8') as f:
                    state = json.load(f)
                state = playbook.validate_state(state)
            except Exception:
                state = playbook.default_state()
            
            step_id = data.get("id")
            valid_ids = [s["id"] for p in playbook.PHASES for s in p["steps"]]
            if step_id not in valid_ids:
                self.end_error("Step not found", 400)
                return
                
            if "steps" not in state: state["steps"] = {}
            if step_id not in state["steps"]: state["steps"][step_id] = {}
            state["steps"][step_id]["status"] = data.get("status", "todo")
            if "note" in data:
                state["steps"][step_id]["note"] = data["note"]
            state["steps"][step_id]["ts"] = datetime.now(timezone.utc).isoformat()
            
            state = playbook.validate_state(state)
            
            tmp = self.server.playbook_file + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(state, f, ensure_ascii=False)
            os.replace(tmp, self.server.playbook_file)
            
            self.end_json({"ok": True, "state": state, "progress": playbook.progress(state)})

        elif path == '/api/playbook/kc':
            from datetime import datetime, timezone
            try:
                with open(self.server.playbook_file, 'r', encoding='utf-8') as f:
                    state = json.load(f)
                state = playbook.validate_state(state)
            except Exception:
                state = playbook.default_state()
                
            kc_key = data.get("key")
            valid_keys = [kc["key"] for kc in playbook.KILL_CHAIN]
            if kc_key not in valid_keys:
                self.end_error("KC not found", 400)
                return
                
            if "kc" not in state: state["kc"] = {}
            if kc_key not in state["kc"]: state["kc"][kc_key] = {}
            state["kc"][kc_key]["status"] = data.get("status", "unknown")
            if "evidence" in data:
                state["kc"][kc_key]["evidence"] = data["evidence"]
            state["kc"][kc_key]["ts"] = datetime.now(timezone.utc).isoformat()
            
            state = playbook.validate_state(state)
            
            tmp = self.server.playbook_file + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(state, f, ensure_ascii=False)
            os.replace(tmp, self.server.playbook_file)
            
            self.end_json({"ok": True, "state": state, "progress": playbook.progress(state)})

        elif path == '/api/playbook/reset':
            state = playbook.default_state()
            tmp = self.server.playbook_file + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(state, f, ensure_ascii=False)
            os.replace(tmp, self.server.playbook_file)
            self.end_json({"ok": True, "state": state, "progress": playbook.progress(state)})

        elif path == '/api/report':
            from bluekit.report.model import build
            from bluekit.report.render import render_html
            
            if 'logs_content' in data and 'logs_filename' in data:
                l_path = os.path.join(self.server.workdir, os.path.basename(data['logs_filename']))
                with open(l_path, 'w', encoding='utf-8') as f:
                    f.write(data['logs_content'])
                data['logs_path'] = l_path
                
            if 'resp_content' in data and 'resp_filename' in data:
                r_path = os.path.join(self.server.workdir, os.path.basename(data['resp_filename']))
                with open(r_path, 'w', encoding='utf-8') as f:
                    f.write(data['resp_content'])
                data['resp_path'] = r_path

            logs_path = data.get('logs_path')
            resp_path = data.get('resp_path')
            meta = data.get('meta', {})
            lang = data.get('lang', 'uz')
            
            logs_data = {}
            if logs_path and os.path.exists(logs_path):
                with open(logs_path, 'r', encoding='utf-8') as f:
                    logs_data = json.load(f)
                    
            resp_data = {}
            if resp_path and os.path.exists(resp_path):
                with open(resp_path, 'r', encoding='utf-8') as f:
                    resp_data = json.load(f)
                    
            model = build(logs_data, resp_data, meta)
            html_content = render_html(model, lang)
            
            out_filename = f"report_{uuid.uuid4().hex[:8]}.html"
            out_path = os.path.join(self.server.workdir, out_filename)
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            self.end_json({"html": html_content, "path": out_path})
        else:
            self.end_error("Not Found", 404)

    def do_PUT(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path.startswith('/api/tracker/'):
            try:
                parts = path.split('/')
                length = int(self.headers.get('Content-Length', 0))
                data = json.loads(self.rfile.read(length).decode('utf-8'))
                
                if len(parts) == 4:
                    row_id = parts[3]
                    def do_update(rows):
                        return trk.update_row(rows, row_id, data)
                    new_row = trk.mutate(self.server.tracker_file, do_update)
                    self.end_json({"success": True, "row": trk.public_row(new_row)})
                elif len(parts) >= 6 and parts[4] == 'attempts':
                    row_id = parts[3]
                    try:
                        att_idx = int(parts[5])
                    except ValueError:
                        self.end_error("Not Found", 404)
                        return
                    res = data.get('result')
                    ans = None
                    def do_update_att(rows):
                        nonlocal ans
                        r = trk.find_row(rows, row_id)
                        if att_idx >= 0 and att_idx < len(r.get("attempts", [])):
                            ans = r["attempts"][att_idx]["answer"]
                        return trk.set_attempt_result(r, att_idx, res)
                    new_row = trk.mutate(self.server.tracker_file, do_update_att)
                    
                    out = {"row": trk.public_row(new_row)}
                    if ans and trk.is_attack_id(ans):
                        try:
                            answers.record(self.server.ledger_file, ans.upper(), res, note=new_row.get("question"))
                        except Exception as e:
                            out["ledger_warning"] = str(e)
                    self.end_json(out)
                else:
                    self.send_error(404, "Not Found")
            except trk.RowNotFound:
                self.end_error("Not Found", 404)
            except trk.TrackerError as e:
                self.end_error(str(e), 400)
            except Exception as e:
                self.end_error(str(e), 500)
        else:
            self.send_error(404, "Not Found")

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path.startswith('/api/tracker/'):
            try:
                parts = path.split('/')
                if len(parts) == 4:
                    row_id = parts[3]
                    def do_del(rows):
                        trk.delete_row(rows, row_id)
                    trk.mutate(self.server.tracker_file, do_del)
                    self.end_json({"success": True})
                elif len(parts) >= 6 and parts[4] == 'attempts':
                    row_id = parts[3]
                    try:
                        att_idx = int(parts[5])
                    except ValueError:
                        self.end_error("Not Found", 404)
                        return
                    def do_del_att(rows):
                        r = trk.find_row(rows, row_id)
                        trk.delete_attempt(r, att_idx)
                        return r
                    new_row = trk.mutate(self.server.tracker_file, do_del_att)
                    self.end_json({"row": trk.public_row(new_row)})
                else:
                    self.send_error(404, "Not Found")
            except trk.RowNotFound:
                self.end_error("Not Found", 404)
            except Exception as e:
                self.end_error(str(e), 500)
        else:
            self.send_error(404, "Not Found")

    def _resolve_path(self, p):
        if not os.path.isabs(p):
            if os.path.exists(os.path.join(os.getcwd(), p)):
                return os.path.join(os.getcwd(), p)
            if os.path.exists(os.path.join(self.server.workdir, p)):
                return os.path.join(self.server.workdir, p)
        return p

    def _logs_input_paths(self, data):
        if isinstance(data.get('files'), list):
            if not data['files']:
                raise ValueError("Fayl tanlanmadi...")
            file_path = []
            for n, f_item in enumerate(data['files']):
                if 'content' in f_item and 'filename' in f_item:
                    sub = os.path.join(self.server.workdir, "multi_%d" % n)
                    os.makedirs(sub, exist_ok=True)
                    fp = os.path.join(sub, os.path.basename(f_item['filename']))
                    with open(fp, 'w', encoding='utf-8') as f:
                        f.write(f_item['content'])
                    if f_item.get('mtime'):
                        os.utime(fp, (f_item['mtime'] / 1000.0, f_item['mtime'] / 1000.0))
                    file_path.append(fp)
                elif f_item.get('path'):
                    file_path.append(self._resolve_path(f_item['path']))
            if len(file_path) == 1:
                return file_path[0]
            if not file_path:
                raise ValueError("Fayl tanlanmadi...")
            return file_path
        elif 'content' in data and 'filename' in data:
            file_path = os.path.join(self.server.workdir, os.path.basename(data['filename']))
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(data['content'])
            return file_path
        else:
            file_path = data.get('path')
            if file_path:
                return self._resolve_path(file_path)
            raise ValueError("Fayl tanlanmadi...")

    def _collect_input_files(self, data):
        """`files` ro'yxati / bitta `content` / `path` -- uchala ko'rinishni ham qabul qiladi."""
        paths = []
        items = data['files'] if isinstance(data.get('files'), list) else [data]
        for item in items:
            if item.get('content') is not None and item.get('filename'):
                fp = os.path.join(self.server.workdir, os.path.basename(item['filename']))
                with open(fp, 'w', encoding='utf-8') as f:
                    f.write(item['content'])
                paths.append(fp)
            elif item.get('path'):
                paths.append(self._resolve_path(item['path']))
        if not paths:
            raise ValueError("Fayl yo'li yoki content ko'rsatilmadi.")
        return paths

    def _load_resp_logs(self, data):
        from bluekit.resp.logbridge import load_log_artifacts
        l_path = None
        if 'from_logs_content' in data and 'from_logs_filename' in data:
            l_path = os.path.join(self.server.workdir, os.path.basename(data['from_logs_filename']))
            with open(l_path, 'w', encoding='utf-8') as f:
                f.write(data['from_logs_content'])
        elif data.get('from_logs_path'):
            l_path = self._resolve_path(data['from_logs_path'].strip().strip('"'))
            
        if not l_path:
            return None
            
        if not os.path.exists(l_path):
            raise FileNotFoundError(f"Log analiz fayli topilmadi: {l_path}")
            
        try:
            with open(l_path, 'r', encoding='utf-8-sig') as f:
                d = json.load(f)
                if not isinstance(d, dict):
                    raise ValueError(f"Log analiz fayli JSON emas (bk logs analyze --json-out natijasi kerak): {os.path.basename(l_path)}")
        except Exception as e:
            if isinstance(e, ValueError) and "Log analiz fayli JSON emas" in str(e):
                raise
            raise ValueError(f"Log analiz fayli JSON emas (bk logs analyze --json-out natijasi kerak): {os.path.basename(l_path)}")
            
        return load_log_artifacts(d)

    def _load_resp_args(self, data):
        if 'current_content' in data and 'current_filename' in data:
            c_path = os.path.join(self.server.workdir, os.path.basename(data['current_filename']))
            with open(c_path, 'w', encoding='utf-8') as f:
                f.write(data['current_content'])
            data['current_path'] = c_path

        cur = None
        if 'current' in data and data['current']:
            if isinstance(data['current'], dict):
                cur = data['current']
            else:
                try:
                    cur = json.loads(data['current'])
                except Exception as e:
                    raise ValueError(f"Joriy snapshot JSON formati xato: {e}")
        elif data.get('current_path'):
            cp = self._resolve_path(data['current_path'].strip().strip('"'))
            if os.path.exists(cp):
                with open(cp, 'r', encoding='utf-8-sig') as f:
                    cur = json.load(f)
            else:
                raise FileNotFoundError(f"Snapshot fayli topilmadi: {cp}")
        else:
            raise ValueError("Joriy snapshot ko'rsatilmadi (current_path yoki snapshot JSON kerak)")
        
        bas = None
        if 'baseline' in data and data['baseline']:
            if isinstance(data['baseline'], dict):
                bas = data['baseline']
            else:
                try:
                    bas = json.loads(data['baseline'])
                except Exception as e:
                    raise ValueError(f"Baseline snapshot JSON formati xato: {e}")
        elif data.get('baseline_path'):
            bp = data['baseline_path'].strip().strip('"')
            if bp:
                bp = self._resolve_path(bp)
                if os.path.exists(bp):
                    with open(bp, 'r', encoding='utf-8-sig') as f:
                        bas = json.load(f)
                else:
                    raise FileNotFoundError(f"Baseline fayli topilmadi: {bp}")
                
        prot = data.get('protected', [])
        return cur, bas, prot

def run_server(host, port, data_dir, workdir):
    if host == '0.0.0.0':
        print("WARNING: LAN'ga ochildi — 10 jamoa tarmog'ida ehtiyot bo'ling")

    kb_path = get_kb_path(data_dir)
    if not os.path.exists(kb_path):
        print("Avval: python bk.py kb build --data ...")
        sys.exit(1)
    
    kb = KB(kb_path)
    
    if not workdir:
        if data_dir:
            workdir = os.path.join(os.path.dirname(data_dir), 'web-work')
        else:
            workdir = 'web-work'
            
    server = WebKitServer((host, port), WebKitHandler, kb, workdir)
    print(f"Server started at http://{host}:{port}")
    print("Ctrl+C to'xtatish")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
