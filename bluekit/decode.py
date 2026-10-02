import base64
import binascii
import urllib.parse
import html
import gzip
import zlib
import re
import codecs

MEANINGFUL_KEYWORDS = ['http', 'powershell', 'cmd', 'iex', 'invoke', 'download', '\\\\', '.exe', 'select', '/bin/', 'base64']

def is_printable(text: str) -> bool:
    if not text:
        return False
    # Count unprintable characters
    unprintable = sum(1 for c in text if ord(c) < 32 and c not in '\r\n\t')
    if unprintable > len(text) * 0.2: # more than 20% unprintable
        return False
    if text.count('\x00') > 0: # Still has null bytes after decoding
        return False
    return True

def has_meaningful(text: str) -> bool:
    low = text.lower()
    return any(k in low for k in MEANINGFUL_KEYWORDS)

def try_decode_step(text: str):
    if len(text) > 1024 * 1024:
        return None

    # 1. powershell_enc
    m = re.search(r'(?i)-(?:enc|e|encodedcommand|ec)\s+([A-Za-z0-9+/=]+)', text)
    if m:
        return ('powershell_enc', m.group(1), "-enc argumentidan base64 ajratildi")
        
    # 2. frombase64string
    m = re.search(r'(?i)FromBase64String\([\'"]([A-Za-z0-9+/=]+)[\'"]\)', text)
    if m:
        return ('frombase64string', m.group(1), "FromBase64String ichidan base64 ajratildi")

    # 3. caret
    if '^' in text:
        dec = re.sub(r'\^', '', text)
        if dec != text:
             return ('caret', dec, "Caret (^) escape olib tashlandi")

    # 4. backtick
    if '`' in text:
        dec = re.sub(r'`', '', text)
        if dec != text:
             return ('backtick', dec, "Backtick (`) escape olib tashlandi")
             
    # 5. base64 checks
    # Check if text looks like base64
    b64_pattern = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')
    if len(text) >= 4 and len(text) % 4 == 0 and b64_pattern.match(text):
        try:
            raw = base64.b64decode(text)
            if raw:
                # check gzip
                if raw.startswith(b'\x1f\x8b'):
                    try:
                        dec = gzip.decompress(raw).decode('utf-8', errors='ignore')
                        if is_printable(dec):
                            return ('base64+gzip', dec, "base64 va gzip dekodlandi")
                    except:
                        pass
                # check utf16le
                if b'\x00' in raw:
                    try:
                        dec = raw.decode('utf-16le')
                        if is_printable(dec):
                            return ('base64+utf16le', dec, "base64 dekodlandi, UTF-16LE matn")
                    except:
                        pass
                # check plain utf8
                try:
                    dec = raw.decode('utf-8')
                    if is_printable(dec) and dec != text:
                        return ('base64', dec, "base64 dekodlandi")
                except:
                    pass
        except:
            pass

    # 6. html_entity
    if '&#' in text:
        dec = html.unescape(text)
        if dec != text:
            return ('html_entity', dec, "HTML entity dekodlandi")

    # 7. url
    if text.count('%') >= 2:
        dec = urllib.parse.unquote(text)
        if dec != text:
            return ('url', dec, "URL dekodlandi")

    # 8. hex
    # Match patterns like \x41\x42, 0x41,0x42, 414243
    hex_clean = text
    if r'\x' in hex_clean:
        hex_clean = hex_clean.replace(r'\x', '')
    elif '0x' in hex_clean:
        hex_clean = hex_clean.replace('0x', '').replace(',', '')
    
    if re.match(r'^[0-9a-fA-F]+$', hex_clean) and len(hex_clean) % 2 == 0 and len(hex_clean) > 0:
        try:
            raw = binascii.unhexlify(hex_clean)
            dec = raw.decode('utf-8')
            if is_printable(dec) and dec != text:
                return ('hex', dec, "Hex dekodlandi")
        except:
            pass

    # 9. concat
    if '+' in text or '.' in text:
        # e.g., 'po'+'wer' or "po"."wer"
        # simplified check
        dec = re.sub(r'[\'"]\s*[\+\.]\s*[\'"]', '', text)
        if dec != text and has_meaningful(dec):
            return ('concat', dec, "String concat birlashtirildi")

    # 10. char_array
    # [char]72+[char]69 or chr(72).chr(69)
    if 'char' in text.lower() or 'chr' in text.lower():
        chars = re.findall(r'(?:\[char\]|chr\()(\d+)\)?', text, re.IGNORECASE)
        if chars:
            try:
                dec = ''.join(chr(int(c)) for c in chars)
                if has_meaningful(dec):
                    return ('char_array', dec, "Char array dekodlandi")
            except:
                pass

    # 11. reverse
    if len(text) > 3:
        dec = text[::-1]
        if has_meaningful(dec):
            return ('reverse', dec, "Matn teskarisiga o'girildi")

    return None

def extract_encoded(text: str) -> list:
    results = []
    # Base64 in log lines
    b64_matches = re.finditer(r'(?i)(?:-enc|e|encodedcommand|ec)\s+([A-Za-z0-9+/=]+)', text)
    for m in b64_matches:
        results.append({
            'value': m.group(1),
            'offset': m.start(1),
            'kind': 'base64'
        })
    
    # Maybe standalone base64
    b64_standalone = re.finditer(r'\b[A-Za-z0-9+/]{32,}={0,2}\b', text)
    for m in b64_standalone:
        results.append({
            'value': m.group(0),
            'offset': m.start(0),
            'kind': 'base64'
        })
        
    return results

def decode(text: str, max_depth: int = 6) -> dict:
    if len(text) > 1024 * 1024:
        return {'input': text, 'layers': [], 'output': text, 'depth': 0, 'iocs': [], 'truncated': True}
        
    original_text = text
    layers = []
    current_text = text
    depth = 0
    
    while depth < max_depth:
        step_res = None
        try:
            step_res = try_decode_step(current_text)
        except:
            pass
            
        if not step_res:
            break
            
        method, new_text, note = step_res
        if new_text == current_text:
            break
            
        depth += 1
        layers.append({
            'step': depth,
            'method': method,
            'note': note,
            'output': new_text
        })
        current_text = new_text

    # Basic IOC extraction (URLs)
    urls = re.findall(r'(?i)https?://[^\s\'"<>()]+', current_text)
    iocs = [{'type': 'url', 'value': u} for u in urls]
    
    return {
        'input': original_text,
        'layers': layers,
        'output': current_text,
        'depth': depth,
        'iocs': iocs,
        'truncated': False
    }

def decode_file(path: str, max_lines: int = 200) -> list:
    results = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                
                line = line.strip()
                extracted = extract_encoded(line)
                for ext in extracted:
                    dec = decode(ext['value'])
                    if dec['layers']:
                        results.append({
                            'line_no': i + 1,
                            'input': ext['value'],
                            'output': dec['output'],
                            'layers': dec['layers']
                        })
    except:
        pass
    return results
