import os

MAGIC_MAP = {
    b'ElfFile\x00': 'evtx',
    b'\xd4\xc3\xb2\xa1': 'pcap',
    b'\xa1\xb2\xc3\xd4': 'pcap',
    b'\x0a\x0d\x0d\x0a': 'pcapng',
    b'EVF\x09': 'ewf',
    b'PAGEDU64': 'memdump',
    b'PAGEDUMP': 'memdump',
    b'PK\x03\x04': 'zip',
    b'LPKSHHRH': 'journal_bin',
    b'\x1f\x8b': 'gzip'
}

EXPECTED_EXTS = {
    'evtx': {'.evtx'},
    'pcap': {'.pcap', '.cap'},
    'pcapng': {'.pcapng'},
    'etl': {'.etl'},
    'ewf': {'.e01'},
    'memdump': {'.dmp', '.vmem', '.raw'},
    'zip': {'.zip', '.7z'},
    'journal_bin': {'.journal'},
    'gzip': {'.gz', '.tgz'}
}

SUPPORTED_EXTS = {'.csv', '.json', '.log', '.journal'}

def _is_text(path: str) -> bool:
    try:
        with open(path, 'rb') as f:
            head = f.read(4096)
    except Exception:
        return False
    # Bo'sh fayl ham matn: 0 qator beradi, butun ishni to'xtatmaydi
    return b'\x00' not in head

def identify(path: str) -> dict:
    if not os.path.exists(path):
        return {'path': path, 'format': 'unknown', 'supported': False, 'hint': "Fayl topilmadi."}

    ext = os.path.splitext(path)[1].lower()
    magic = b''
    try:
        with open(path, 'rb') as f:
            magic = f.read(16)
    except Exception as e:
        return {'path': path, 'format': 'unknown', 'supported': False, 'hint': f"Faylni o'qishda xato: {e}"}

    format_id = 'unknown'
    magic_matched = False
    for m, fmt in MAGIC_MAP.items():
        if magic.startswith(m):
            format_id = fmt
            magic_matched = True
            break

    # PowerShell 5.1 `>` / Out-File UTF-16 yozadi -- utf-8 o'quvchi uni jim buzadi
    if magic.startswith((b'\xff\xfe', b'\xfe\xff')):
        return {'path': path, 'format': 'utf16', 'supported': False,
                'hint': ("UTF-16 matn (PowerShell '>' yoki Out-File). Avval UTF-8 ga o'giring:\n"
                         "  Get-Content <fayl> | Set-Content -Encoding utf8 <yangi.log>")}

    if format_id == 'unknown':
        if ext == '.etl':
            format_id = 'etl'
        elif ext == '.evtx':
            format_id = 'evtx'
        elif ext in ['.pcap', '.cap']:
            format_id = 'pcap'
        elif ext == '.pcapng':
            format_id = 'pcapng'
        elif ext == '.e01':
            format_id = 'ewf'
        elif ext in ['.dmp', '.vmem', '.raw']:
            format_id = 'memdump'
        elif ext in ['.zip', '.7z']:
            format_id = 'zip'
        elif ext in ['.gz', '.tgz']:
            format_id = 'gzip'

    # Kengaytma ahamiyatsiz: matn fayl (boshida NUL bayt yo'q) o'qiladi -- secure, messages, auth.log.1, x.jsonl, x.txt
    if format_id == 'unknown' and (ext in SUPPORTED_EXTS or _is_text(path)):
        return {'path': path, 'format': 'supported', 'supported': True, 'hint': None}

    hint = ""
    if format_id == 'evtx':
        hint = ("Xom EVTX o'qilmaydi. Avval CSV ga aylantiring:\n"
                "  hayabusa.exe csv-timeline -d <papka> -o hb.csv\n"
                "  keyin: bk logs analyze hb.csv --preset hayabusa")
    elif format_id in ['pcap', 'pcapng']:
        hint = ("tshark -r x.pcap -T fields -E header=y -E separator=, -e frame.time -e ip.src -e ip.dst -e tcp.dstport -e http.request.full_uri > out.csv\n"
                "yoki Zeek (zeek -r x.pcap)")
    elif format_id == 'etl':
        hint = "netsh trace convert orqali aylantiring."
    elif format_id in ['ewf', 'memdump']:
        hint = "bu kit uchun emas, alohida vosita kerak (Volatility / Autopsy)"
    elif format_id == 'zip':
        hint = "avval oching"
    elif format_id == 'gzip':
        hint = "Siqilgan (gzip). Avval oching: gzip -d auth.log.2.gz yoki 7-Zip, keyin ochilgan faylni bering."
    elif format_id == 'journal_bin':
        hint = ("Binar systemd journal formati. Uni eksport qilish uchun:\n"
                "  journalctl --file <fayl> -o json > logs.json\n"
                "  yoki: journalctl --file <fayl> > logs.log")

    if format_id == 'unknown':
        hint = "Noma'lum format"

    # Check for magic/extension mismatch
    if format_id != 'unknown':
        if magic_matched:
            if ext and ext not in EXPECTED_EXTS.get(format_id, set()):
                hint += f"\nEslatma: chalkashlik, sehrli baytlar {format_id} ni ko'rsatmoqda, lekin kengaytma {ext}"
        else:
            if ext in EXPECTED_EXTS.get(format_id, set()):
                hint += f"\nEslatma: chalkashlik, kengaytma {ext} lekin sehrli baytlar mos emas"

    return {
        'path': path,
        'format': format_id,
        'supported': False,
        'hint': hint.strip()
    }
