import re
from datetime import datetime, timedelta
import bluekit.tz

def parse_bound(value: str, end: bool = False) -> datetime:
    value = value.strip()
    if not value:
        raise ValueError("Vaqt bo'sh bo'lmasligi kerak")
    
    s = re.sub(r'\s*\(Toshkent[^)]*\)\s*$', '', value)
    s = re.sub(r'(?i)\s+(utc|gmt)$', '+00:00', s)
    s = re.sub(r'\s+([+-]\d{2}:?\d{2})$', r'\1', s)
    
    s = s.replace('Z', '+00:00').replace('z', '+00:00')
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        raise ValueError(f"Noto'g'ri vaqt: '{value}'. Misol: 2026-10-05 14:20, 2026-10-05T09:20:00Z, 2026-10-05T14:20:00+05:00")
        
    dt_local = bluekit.tz.to_local(dt)
    
    if re.fullmatch(r'\d{4}-\d{2}-\d{2}', s):
        if end:
            dt_local = dt_local + timedelta(days=1) - timedelta(microseconds=1)
    
    return dt_local

def filter_events(events, from_dt=None, to_dt=None, host=None) -> list:
    if from_dt is None and to_dt is None and host is None:
        return list(events)
        
    out = []
    host_filter = host.strip().lower() if host else None
    
    for ev in events:
        if from_dt is not None or to_dt is not None:
            ts = ev.get('ts')
            if ts is None:
                continue
            if from_dt is not None and ts < from_dt:
                continue
            if to_dt is not None and ts > to_dt:
                continue
                
        if host_filter is not None:
            ev_host = (ev.get('host') or '').strip().lower()
            if ev_host != host_filter:
                continue
                
        out.append(ev)
        
    return out

def describe(from_dt, to_dt, host) -> str | None:
    if from_dt is None and to_dt is None and host is None:
        return None
        
    parts = []
    if host:
        parts.append(f"host={host}")
        
    if from_dt or to_dt:
        f_str = from_dt.strftime('%Y-%m-%d %H:%M:%S') if from_dt else "..."
        t_str = to_dt.strftime('%Y-%m-%d %H:%M:%S') if to_dt else "..."
        parts.append(f"{f_str} .. {t_str}")
        
    return ", ".join(parts)
