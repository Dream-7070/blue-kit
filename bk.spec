# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['bk.py'],
    pathex=[],
    binaries=[],
    datas=[('bluekit/kb/heuristics.yaml', 'bluekit/kb'), ('bluekit/logs/eventmap.yaml', 'bluekit/logs'), ('bluekit/logs/fieldmap.yaml', 'bluekit/logs'), ('bluekit/logs/noise.yaml', 'bluekit/logs'), ('bluekit/mail/brands.yaml', 'bluekit/mail'), ('bluekit/report/strings.yaml', 'bluekit/report'), ('bluekit/hunt/allowlist.yaml', 'bluekit/hunt'), ('bluekit/resp/knowngood.yaml', 'bluekit/resp'), ('bluekit/web/static', 'bluekit/web/static')],
    hiddenimports=['bluekit.logs.qradar', 'bluekit.logs.parse', 'bluekit.logs.sigma', 'bluekit.logs.formats', 'bluekit.ir.explain', 'bluekit.ir.correlator', 'bluekit.ir.models', 'bluekit.ir.report', 'bluekit.ir.lateral', 'bluekit.ir.fallback', 'bluekit.hunt.beacons', 'bluekit.hunt.beacon_math', 'bluekit.paths', 'bluekit.siem.cli', 'bluekit.siem.builder', 'bluekit.siem.catalog', 'bluekit.siem.dialects', 'bluekit.siem.fields', 'bluekit.resp.sla', 'bluekit.resp.scoring', 'bluekit.resp.servicedoctor', 'bluekit.resp.fraud', 'bluekit.decode', 'bluekit.doctor', 'bluekit.answers', 'bluekit.playbook', 'bluekit.tracker', 'bluekit.tz', 'bluekit.logs.filter', 'bluekit.logs.bruteforce', 'bluekit.kb.cve', 'bluekit.case', 'bluekit.case.loaders', 'bluekit.case.solver', 'bluekit.case.cli'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['telegram', 'httpx', 'httpcore', 'h2', 'hpack', 'anyio', 'sniffio', 'certifi'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='bk',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
