import os
import sys
import time
import socket
import tempfile
import yaml
import importlib
import sqlite3
import shutil
from datetime import datetime

from bluekit import paths

def run_checks(data_dir=None, quick=False) -> list:
    results = []

    def add_check(id, name, critical, check_fn):
        t0 = time.time()
        ok = False
        detail = ""
        fix = None
        override_critical = critical
        try:
            res = check_fn()
            if isinstance(res, tuple):
                ok, detail = res[0], res[1]
                if len(res) > 2:
                    override_critical = res[2]
            else:
                ok = res
                detail = "OK"
        except Exception as e:
            ok = False
            detail = f"Xato: {type(e).__name__} - {e}"
        t1 = time.time()
        ms = int((t1 - t0) * 1000)
        results.append({
            'id': id,
            'name': name,
            'ok': ok,
            'detail': detail,
            'fix': fix,
            'critical': override_critical,
            'ms': ms
        })

    # A. Muhit
    def check_python():
        frozen = "frozen (exe)" if getattr(sys, "frozen", False) else "manba (source)"
        return True, f"Python {sys.version.split()[0]}, {frozen}"
    add_check('python', 'Python muhiti', True, check_python)

    def check_data_dir():
        d = data_dir or paths.get_data_dir()
        if os.path.isdir(d):
            return True, d
        return False, f"Topilmadi: {d}"
    add_check('data_dir', 'Data papkasi', True, check_data_dir)

    def check_workdir():
        try:
            fd, p = tempfile.mkstemp(dir=".")
            os.close(fd)
            os.remove(p)
            return True, "Yozish mumkin"
        except Exception as e:
            return False, f"Yozib bo'lmadi: {e}"
    add_check('workdir', 'Joriy papkaga yozish', True, check_workdir)

    def check_encoding():
        if sys.stdout.encoding.lower() in ('utf-8', 'utf8'):
            return True, "UTF-8"
        return False, f"UTF-8 emas: {sys.stdout.encoding}"
    add_check('encoding', 'Matn kodlanishi', False, check_encoding)

    # B. Ma'lumot
    def check_kb():
        d = data_dir or paths.get_data_dir()
        db_path = paths.get_kb_path(d)
        if not os.path.exists(db_path):
            return False, "kb.sqlite topilmadi"
        with sqlite3.connect(db_path) as conn:
            c = conn.cursor()
            c.execute("SELECT key, value FROM meta")
            meta = dict(c.fetchall())
            c.execute("SELECT domain, count(*) FROM techniques GROUP BY domain")
            by_domain = dict(c.fetchall())
        ver = meta.get('enterprise_attack_version', '?')
        parts = ", ".join("%s %d" % (k, v) for k, v in sorted(by_domain.items()))
        return ver != '?', f"ATT&CK v{ver} | {parts}"
    add_check('kb', 'KB bazasi', True, check_kb)

    def check_kb_ics():
        d = data_dir or paths.get_data_dir()
        db_path = paths.get_kb_path(d)
        if not os.path.exists(db_path):
            return False, "kb.sqlite topilmadi"
        with sqlite3.connect(db_path) as conn:
            c = conn.cursor()
            c.execute("SELECT count(*) FROM techniques WHERE domain='ics'")
            count = c.fetchone()[0]
        return count > 0, f"{count} ta ICS texnikasi (domain='ics')"
    add_check('kb_ics', 'KB da ICS', False, check_kb_ics)

    def check_kb_v19():
        d = data_dir or paths.get_data_dir()
        db_path = paths.get_kb_path(d)
        if not os.path.exists(db_path):
            return False, "kb.sqlite topilmadi"
        with sqlite3.connect(db_path) as conn:
            c = conn.cursor()
            c.execute("SELECT revoked, revoked_by FROM techniques WHERE attack_id = 'T1070.001'")
            row = c.fetchone()
            if not row:
                return False, "T1070.001 topilmadi"
            if row[0] and row[1] == 'T1685.005':
                return True, "T1070.001 revoked va replacement tasdiqlandi"
            return False, f"Noto'g'ri holat: revoked={row[0]}, replacement={row[1]}"
    add_check('kb_v19', 'KB v19 ekanligi', True, check_kb_v19)

    def check_sigma():
        d = data_dir or paths.get_data_dir()
        db_path = paths.get_kb_path(d)
        if not os.path.exists(db_path):
            return False, "kb.sqlite topilmadi"
        with sqlite3.connect(db_path) as conn:
            c = conn.cursor()
            try:
                c.execute("SELECT count(*) FROM sigma_rules")
                count = c.fetchone()[0]
                return count > 0, f"{count} ta Sigma qoidasi"
            except sqlite3.OperationalError:
                return False, "sigma_rules jadvali yo'q"
    add_check('sigma', 'Sigma qoidalari', False, check_sigma)

    def check_atomic():
        d = data_dir or paths.get_data_dir()
        db_path = paths.get_kb_path(d)
        if not os.path.exists(db_path):
            return False, "kb.sqlite topilmadi"
        with sqlite3.connect(db_path) as conn:
            c = conn.cursor()
            try:
                c.execute("SELECT count(*) FROM atomic_tests")
                count = c.fetchone()[0]
                return count > 0, f"{count} ta Atomic test"
            except sqlite3.OperationalError:
                return False, "atomic_tests jadvali yo'q"
    add_check('atomic', 'Atomic testlar', False, check_atomic)

    def check_samples():
        d = data_dir or paths.get_data_dir()
        samples_dir = os.path.join(d, "samples")
        if os.path.isdir(samples_dir):
            files = [os.path.join(r, f)
                     for r, _dirs, fs in os.walk(samples_dir) for f in fs]
            if files:
                return True, f"{len(files)} ta namuna fayli"
        return False, "Namunalar topilmadi"
    add_check('samples', 'Namunaviy fayllar', False, check_samples)

    # C. Paket ichidagi resurslar
    resources = [
        ('res_fieldmap', 'bluekit/logs/fieldmap.yaml', True),
        ('res_eventmap', 'bluekit/logs/eventmap.yaml', True),
        ('res_noise', 'bluekit/logs/noise.yaml', True),
        ('res_heuristics', 'bluekit/kb/heuristics.yaml', True),
        ('res_brands', 'bluekit/mail/brands.yaml', True),
        ('res_strings', 'bluekit/report/strings.yaml', True),
        ('res_allowlist', 'bluekit/hunt/allowlist.yaml', True),
        ('res_knowngood', 'bluekit/resp/knowngood.yaml', True),
        ('res_static', 'bluekit/web/static/index.html', False)
    ]

    for rid, rel_path, critical in resources:
        def make_check_res(path=rel_path):
            def check():
                full_path = paths.get_resource_path(path)
                if not os.path.exists(full_path):
                    return False, "Topilmadi"
                if path.endswith('.yaml'):
                    with open(full_path, 'r', encoding='utf-8') as f:
                        data = yaml.safe_load(f)
                    if data is not None:
                        return True, "YAML yuklandi"
                    return False, "Bo'sh YAML"
                else:
                    with open(full_path, 'r', encoding='utf-8') as f:
                        f.read(1)
                    return True, "Fayl ochildi"
            return check
        add_check(rid, os.path.basename(rel_path), critical, make_check_res())

    # D. Modullar yuklanishi
    modules = [
        'bluekit.siem.builder', 'bluekit.siem.cli', 'bluekit.ir.correlator',
        'bluekit.ir.report', 'bluekit.hunt.beacons', 'bluekit.logs.parse',
        'bluekit.logs.qradar', 'bluekit.resp.triage', 'bluekit.resp.sla',
        'bluekit.resp.scoring', 'bluekit.resp.servicedoctor', 'bluekit.mail.scan',
        'bluekit.report.render', 'bluekit.web.server'
    ]

    for mod_name in modules:
        rid = f"mod_{mod_name.split('.')[-1]}"
        def make_check_mod(m=mod_name):
            def check():
                importlib.import_module(m)
                return True, "Yuklandi"
            return check
        add_check(rid, f"Modul {mod_name}", True, make_check_mod())

    # E. Funksional sinov
    if not quick:
        def check_fn_siem():
            from bluekit.siem.builder import build_query
            query = build_query('net-port-scan', 'sentinel')
            if 'SourceIP' in query.get('query', ''):
                return True, "Query to'g'ri qurildi"
            return False, "Query da SourceIP yo'q"
        add_check('fn_siem', 'SIEM Builder', True, check_fn_siem)
        
        def check_fn_kb():
            from bluekit.kb.ioc import KB
            d = data_dir or paths.get_data_dir()
            db_path = paths.get_kb_path(d)
            kb = KB(path=db_path)
            res = kb.validate(['T1059.001'])
            for r in res:
                if r.get('input') == 'T1059.001' and r.get('found') and r.get('status') == 'active':
                    return True, "T1059.001 topildi va faol"
            return False, "T1059.001 faol emas yoki topilmadi"
        add_check('fn_kb', 'KB Validate', True, check_fn_kb)

        def check_fn_logs():
            d = data_dir or paths.get_data_dir()
            sample = os.path.join(d, "samples", "win_phishing.csv")
            if not os.path.exists(sample):
                return True, "Namuna topilmadi", False
            from bluekit.logs.parse import load
            events = list(load(sample))
            if len(events) > 0:
                return True, f"{len(events)} hodisa"
            return False, "Hodisalar 0"
        add_check('fn_logs', 'Logs Parse', True, check_fn_logs)
        
        def check_fn_noise():
            d = data_dir or paths.get_data_dir()
            sample = os.path.join(d, "samples", "noise_check.log")
            if not os.path.exists(sample):
                return True, "Namuna topilmadi", False
            
            from bluekit.logs.detect import load_noise
            rules = load_noise()
            if rules:
                return True, "Shovqin filtri ishladi (qoidalar yuklandi)"
            return False, "Shovqin filtri ishlamadi (qoidalar yo'q)"
        add_check('fn_noise', 'Noise Detect', True, check_fn_noise)
        
        def check_fn_mail():
            d = data_dir or paths.get_data_dir()
            sample = os.path.join(d, "samples", "mail", "phish_sample.eml")
            if not os.path.exists(sample):
                return True, "Namuna topilmadi", False
            from bluekit.mail.parse import load_eml
            from bluekit.mail.scan import scan_email
            parsed = load_eml(sample)
            res = scan_email(parsed)
            if res.get("verdict", "").lower() == "phishing":
                return True, "Phishing belgisi topildi"
            return False, "Phishing topilmadi"
        add_check('fn_mail', 'Mail Scan', True, check_fn_mail)
        
        def check_fn_resp():
            d = data_dir or paths.get_data_dir()
            import json as _json
            from bluekit.resp.triage import analyze
            from bluekit.kb.query import KB
            sample = os.path.join(d, "samples", "resp", "current_win.json")
            baseline = os.path.join(d, "samples", "resp", "baseline_win.json")
            if not os.path.exists(sample):
                return True, "Namuna topilmadi", False
            try:
                with open(sample, encoding='utf-8') as f:
                    current = _json.load(f)
                base = None
                if os.path.exists(baseline):
                    with open(baseline, encoding='utf-8') as f:
                        base = _json.load(f)
                kb_path = paths.get_kb_path(d)
                kb = KB(kb_path) if os.path.exists(kb_path) else None
                findings, _extra = analyze(kb, current, base)
                if findings:
                    return True, f"{len(findings)} ta topilma"
                return False, "Topilma 0 -- triage ishlamayapti"
            except Exception as e:
                return False, f"Xato: {e}"
        add_check('fn_resp', 'Resp Triage', True, check_fn_resp)
        
        def check_fn_sla():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
            s.close()
            
            from bluekit.resp.sla import check
            conf = {
                'services': [
                    {
                        'name': 'test',
                        'checks': [{'type': 'tcp', 'host': '127.0.0.1', 'port': port}]
                    }
                ]
            }
            res = check(conf)
            if res and res[0].get('state') == 'down':
                return True, "yopiq port down qaytardi"
            return False, f"port holati: {res[0].get('state') if res else 'None'}"
        add_check('fn_sla', 'SLA Check', True, check_fn_sla)

        def check_fn_ir():
            d = data_dir or paths.get_data_dir()
            sample = os.path.join(d, "samples", "win_phishing.csv")
            if not os.path.exists(sample):
                return True, "Namuna topilmadi", False
            from bluekit.ir.correlator import load_events_from_files
            events = load_events_from_files([sample])
            return True, f"{len(events)} hodisa (istisnosiz)"
        add_check('fn_ir', 'IR Correlator', True, check_fn_ir)

    # F. Ogohlantirishlar
    def check_write_temp():
        try:
            fd, p = tempfile.mkstemp()
            os.close(fd)
            os.remove(p)
            return True, "Yozish mumkin"
        except Exception as e:
            return False, f"Yozib bo'lmadi: {e}"
    add_check('write_temp', 'Vaqtinchalik papkaga yozish', False, check_write_temp)

    def check_tz():
        now = datetime.now()
        import datetime as dt
        utc = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
        diff = (now - utc).total_seconds()
        hours = diff / 3600.0
        return True, f"Farq: {hours:.1f} soat"
    add_check('tz', 'Vaqt zonasi farqi', False, check_tz)

    def check_disk():
        d = data_dir or paths.get_data_dir()
        if not os.path.exists(d):
            return False, "Data papkasi yo'q"
        stat = shutil.disk_usage(d)
        mb = stat.free / (1024 * 1024)
        if mb > 200:
            return True, f"{mb:.1f} MB bo'sh"
        return False, f"{mb:.1f} MB bo'sh (kam)"
    add_check('disk', 'Diskda joy', False, check_disk)

    return results

def summary(results) -> dict:
    total = len(results)
    ok = sum(1 for r in results if r['ok'])
    failed = sum(1 for r in results if r['critical'] and not r['ok'])
    warnings = sum(1 for r in results if not r['critical'] and not r['ok'])
    
    if failed > 0:
        verdict = 'XATOLAR BOR'
    elif warnings > 0:
        verdict = 'OGOHLANTIRISH BOR'
    else:
        verdict = 'HAMMASI JOYIDA'
        
    return {
        'total': total,
        'ok': ok,
        'failed': failed,
        'warnings': warnings,
        'verdict': verdict
    }

if __name__ == '__main__':
    res = run_checks()
    sum_data = summary(res)
    print(f"Total: {sum_data['total']}, OK: {sum_data['ok']}, Failed: {sum_data['failed']}, Warnings: {sum_data['warnings']}")
    for r in res:
        crit = "[CRITICAL]" if r['critical'] else "[WARNING]"
        status = "OK" if r['ok'] else "FAIL"
        print(f"{status} {crit} {r['id']} - {r['name']}: {r['detail']}")
    
    if sum_data['failed'] > 0:
        sys.exit(1)
