import email
from email import policy
import hashlib
import re
from html.parser import HTMLParser

class AnchorParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []
        self.current_a_href = None
        self.current_a_text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            for name, value in attrs:
                if name == "href":
                    self.current_a_href = value
                    self.current_a_text = []

    def handle_endtag(self, tag):
        if tag == "a" and self.current_a_href is not None:
            text = "".join(self.current_a_text).strip()
            self.urls.append({"url": self.current_a_href, "anchor_text": text if text else None, "source": "html"})
            self.current_a_href = None
            self.current_a_text = []

    def handle_data(self, data):
        if self.current_a_href is not None:
            self.current_a_text.append(data)


def decode_part_text(part):
    """Matnli qismni dekodlaydi. E'lon qilingan charset yolg'on bo'lishi mumkin
    (spam/phishda keng tarqalgan) — U+FFFD chiqsa, muqobil kodlashlar sinaladi."""
    raw = part.get_payload(decode=True)
    if raw is None:
        try:
            return part.get_content()
        except Exception:
            return ""

    declared = (part.get_content_charset() or 'utf-8').lower()
    candidates = [declared]
    for enc in ('utf-8', 'cp1251', 'koi8-r', 'cp1252', 'iso-8859-1'):
        if enc not in candidates:
            candidates.append(enc)

    best_text = None
    best_bad = None
    for enc in candidates:
        try:
            text = raw.decode(enc, errors='replace')
        except (LookupError, UnicodeDecodeError):
            continue
        bad = text.count('�')
        if bad == 0:
            return text
        if best_bad is None or bad < best_bad:
            best_text, best_bad = text, bad

    return best_text if best_text is not None else raw.decode('utf-8', errors='replace')


def load_eml(path):
    result = {
        "file": "",
        "size": 0,
        "headers": {},
        "received": [],
        "body_text": "",
        "body_html": "",
        "urls": [],
        "attachments": [],
        "errors": []
    }
    
    import os
    result["file"] = os.path.basename(path)
    try:
        result["size"] = os.path.getsize(path)
    except Exception as e:
        result["errors"].append(str(e))
        return result

    try:
        with open(path, "rb") as f:
            header_bytes = f.read(8)
            if header_bytes.startswith(b"\xD0\xCF\x11\xE0"):
                try:
                    import extract_msg
                except ImportError:
                    result["errors"].append(".msg uchun extract_msg kerak \u2014 yoki Outlook'da 'Save as .eml' qiling")
                    print(".msg uchun extract_msg kerak \u2014 yoki Outlook'da 'Save as .eml' qiling")
                    return result
            f.seek(0)
            msg = email.message_from_binary_file(f, policy=policy.default)
    except Exception as e:
        result["errors"].append(f"Failed to parse eml: {e}")
        return result

    headers_to_extract = ["from", "to", "subject", "date", "return-path", "reply-to", "message-id", "x-mailer", "authentication-results", "x-spam-status"]
    
    for h in headers_to_extract:
        val = msg.get(h)
        if val:
            key = h.replace("-", "_")
            if key == "authentication_results":
                key = "auth_results"
            result["headers"][key] = str(val).replace("\n", " ").replace("\r", " ").strip()

    from_header = msg.get("from")
    if from_header:
        from_header_str = str(from_header)
        # Extract display name, addr, domain
        m = re.match(r'(.*)<(.*@(.*))>', from_header_str)
        if m:
            disp = m.group(1).strip(" \"'")
            addr = m.group(2).strip()
            domain = m.group(3).strip()
        else:
            disp = ""
            addr = from_header_str.strip()
            domain = addr.split("@")[-1] if "@" in addr else ""
        
        result["headers"]["from_display"] = disp
        result["headers"]["from_addr"] = addr
        result["headers"]["from_domain"] = domain
        
        if "from" in result["headers"]:
            del result["headers"]["from"]

    for rcv in msg.get_all("Received", []):
        raw_rcv = str(rcv).replace("\n", " ").replace("\r", " ").strip()
        ip_m = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', raw_rcv)
        ip = ip_m.group(1) if ip_m else None
        
        parts = raw_rcv.split(";")
        ts = parts[-1].strip() if len(parts) > 1 else None
        
        result["received"].append({
            "raw": raw_rcv,
            "ip": ip,
            "ts": ts
        })
    result["received"].reverse()

    def process_part(part):
        if part.is_multipart():
            for subpart in part.iter_parts():
                process_part(subpart)
        else:
            content_type = part.get_content_type()
            disp = part.get_content_disposition()
            
            if disp in ["attachment", "inline"] or part.get_filename():
                fname = part.get_filename() or "unknown"
                payload = part.get_content()
                if isinstance(payload, str):
                    payload = payload.encode("utf-8")
                
                size = len(payload)
                sha256 = hashlib.sha256(payload).hexdigest()
                data_head = payload[:64]
                
                result["attachments"].append({
                    "filename": fname,
                    "content_type": content_type,
                    "size": size,
                    "sha256": sha256,
                    "data_head": data_head,
                    "payload": payload
                })
            elif content_type == "text/plain":
                try:
                    result["body_text"] += decode_part_text(part) + "\n"
                except:
                    pass
            elif content_type == "text/html":
                try:
                    result["body_html"] += decode_part_text(part) + "\n"
                except:
                    pass

    process_part(msg)

    # Extract URLs from HTML
    if result["body_html"]:
        parser = AnchorParser()
        try:
            parser.feed(result["body_html"])
            result["urls"].extend(parser.urls)
        except:
            pass

    # Extract URLs from text
    if result["body_text"]:
        # Simple regex for URLs
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', result["body_text"])
        for u in urls:
            result["urls"].append({"url": u, "anchor_text": None, "source": "text"})

    return result
