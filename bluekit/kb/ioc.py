import re
from .query import KB

def classify(s: str) -> dict:
    s = s.strip()
    # defanged normalization
    val = s.replace('hxxp', 'http').replace('[.]', '.').replace('(.)', '.')
    
    if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', val):
        parts = [int(x) for x in val.split('.')]
        is_priv = False
        if parts[0] == 10 or (parts[0] == 172 and 16 <= parts[1] <= 31) or (parts[0] == 192 and parts[1] == 168) or parts[0] == 127:
            is_priv = True
        return {"type": "ipv4", "value": val, "private": is_priv}
        
    if re.match(r'^T\d{4}(\.\d{3})?$', val, re.I):
        return {"type": "attack_id", "value": val.upper()}
        
    if re.match(r'^[a-fA-F0-9]{32}$', val): return {"type": "md5", "value": val.lower()}
    if re.match(r'^[a-fA-F0-9]{40}$', val): return {"type": "sha1", "value": val.lower()}
    if re.match(r'^[a-fA-F0-9]{64}$', val): return {"type": "sha256", "value": val.lower()}
    
    if val.startswith('http://') or val.startswith('https://'): return {"type": "url", "value": val}
    
    if re.match(r'^HK[A-Z]{1,2}\\', val, re.I): return {"type": "registry", "value": val}
    if re.match(r'^[A-Za-z]:\\', val) or '\\\\' in val: return {"type": "win_path", "value": val}
    if '/' in val and not val.startswith('http'): return {"type": "unix_path", "value": val}
    
    return {"type": "unknown", "value": val}

def techniques_for_ioc(kb: KB, s: str, limit: int = 5):
    cls = classify(s)
    val = cls["value"]
    typ = cls["type"]
    
    if typ == "attack_id":
        return {"classification": cls, "techniques": kb.validate([val])}
        
    if typ in ("md5", "sha1", "sha256", "ipv4"):
        # return empty with note
        return {
            "classification": cls, 
            "note": "hash/IP o'zi texnika bermaydi — kontekst kerak",
            "techniques": [
                {"attack_id": "T1071.001", "score": 0.2, "name": "Web Protocols", "confidence": "low"},
                {"attack_id": "T1105", "score": 0.2, "name": "Ingress Tool Transfer", "confidence": "low"},
                {"attack_id": "T1041", "score": 0.2, "name": "Exfiltration Over C2 Channel", "confidence": "low"}
            ][:limit]
        }
        
    if typ in ("command", "win_path", "unix_path", "registry", "filename", "url", "domain"):
        res = kb.search(val)
        filtered = []
        for t in res:
            if t.get('score', 0) >= 0.15:
                # Add low confidence for url/domain if they don't have it
                if typ in ("url", "domain"):
                    t["confidence"] = "low"
                filtered.append(t)
        
        ret = {"classification": cls, "techniques": filtered[:limit]}
        if typ in ("url", "domain"):
            ret["note"] = "URL/domain o'zi texnika bermaydi — kontekst kerak"
        return ret
        
    return {"classification": cls, "techniques": []}
