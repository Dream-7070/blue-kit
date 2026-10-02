import os
from datetime import datetime, timedelta, timezone

LOCAL_OFFSET = timedelta(hours=5)
LOCAL_TZ = timezone(LOCAL_OFFSET)
TZ_LABEL = "Toshkent (UTC+5)"      # B-spec yorliqlarda ishlatadi
TZ_LABEL_RU = "Ташкент (UTC+5)"
TZ_LABEL_EN = "Tashkent (UTC+5)"

_naive_tz = LOCAL_OFFSET

def parse_offset(s: str) -> timedelta | None:
    s = s.lower().strip()
    if s in ("utc", "z", "gmt"):
        return timedelta(0)
    if s in ("local", "tashkent"):
        return LOCAL_OFFSET
    
    import re
    m = re.match(r'^([+-])(\d{2}):?(\d{2})?$', s)
    if not m:
        return None
    
    sign = 1 if m.group(1) == '+' else -1
    hours = int(m.group(2))
    mins = int(m.group(3)) if m.group(3) else 0
    
    if hours > 14 or (hours == 14 and mins > 0):
        return None
        
    return timedelta(hours=sign * hours, minutes=sign * mins)

def set_naive_tz(spec):
    global _naive_tz
    if not spec:
        _naive_tz = LOCAL_OFFSET
        return
    if isinstance(spec, timedelta):
        _naive_tz = spec
        return
    parsed = parse_offset(spec)
    if parsed is None:
        raise ValueError(f"Noto'g'ri vaqt zonasi: '{spec}'. Misol: utc, +05:00, -03:00")
    _naive_tz = parsed

def get_naive_tz() -> timedelta:
    return _naive_tz

def to_local(dt: datetime) -> datetime:
    if dt.tzinfo is not None:
        return dt.astimezone(LOCAL_TZ).replace(tzinfo=None)
    else:
        return dt - get_naive_tz() + LOCAL_OFFSET

def from_utc_naive(dt: datetime) -> datetime:
    return dt + LOCAL_OFFSET

def from_epoch(val: float) -> datetime:
    dt = datetime.fromtimestamp(val, timezone.utc)
    return to_local(dt)

def fmt_offset(td: timedelta) -> str:
    tot = int(td.total_seconds())
    sign = '+' if tot >= 0 else '-'
    tot = abs(tot)
    hh, rem = divmod(tot, 3600)
    mm = rem // 60
    return f"{sign}{hh:02d}:{mm:02d}"

def display_ts(local_dt, raw=None, src_offset=None) -> str:
    import re
    if local_dt is None or local_dt == "":
        return ""
    if isinstance(local_dt, str):
        try:
            local_dt = datetime.fromisoformat(local_dt)
        except ValueError:
            return ""
            
    if local_dt.tzinfo is not None:
        local_naive = local_dt.astimezone(LOCAL_TZ).replace(tzinfo=None)
    else:
        local_naive = local_dt
        
    explicit = False
    off = None

    if src_offset is not None:
        off = src_offset
        explicit = True
    elif raw is None or raw == "":
        off = LOCAL_OFFSET
        explicit = False
    elif isinstance(raw, datetime):
        if raw.tzinfo is not None:
            off = raw.utcoffset()
            explicit = True
        else:
            off = get_naive_tz()
            explicit = False
    elif isinstance(raw, (int, float)):
        off = timedelta(0)
        explicit = True
    elif isinstance(raw, str):
        raw = raw.strip()
        if raw.replace('.', '', 1).isdigit():
            off = timedelta(0)
            explicit = True
        elif 'Date(' in raw:
            off = timedelta(0)
            explicit = True
        elif raw.endswith('Z') or raw.lower().endswith(' gmt') or raw.lower().endswith(' utc'):
            off = timedelta(0)
            explicit = True
        else:
            m = re.search(r'\d{1,2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?\s*([+-])(\d{2}):?(\d{2})?$', raw)
            if m:
                sign = 1 if m.group(1) == '+' else -1
                h = int(m.group(2))
                mins = int(m.group(3)) if m.group(3) else 0
                off = timedelta(hours=sign * h, minutes=sign * mins)
                explicit = True
            else:
                off = get_naive_tz()
                explicit = False
    else:
        off = get_naive_tz()
        explicit = False

    src_local = local_naive - LOCAL_OFFSET + off
    res = src_local.strftime('%Y-%m-%d %H:%M:%S')

    if explicit:
        if off == timedelta(0):
            res += " UTC"
        else:
            res += " " + fmt_offset(off)
            
    if off != LOCAL_OFFSET:
        if src_local.date() == local_naive.date():
            res += f" (Toshkent {local_naive.strftime('%H:%M:%S')})"
        else:
            res += f" (Toshkent {local_naive.strftime('%m-%d %H:%M:%S')})"
            
    return res

def tz_note() -> str:
    tz = get_naive_tz()
    if tz.total_seconds() == 0:
        src = "+00:00 (UTC)"
    else:
        src = fmt_offset(tz)
    return f"Vaqtlar logdagi kabi ko'rsatiladi; boshqa zonadagilar yonida (Toshkent ...) berilgan. Zonasiz log vaqtlari {src} deb olindi (o'zgartirish: --src-tz). --from/--to filtri: {TZ_LABEL}."


initial_tz = os.environ.get("BK_NAIVE_TZ")
if initial_tz:
    try:
        set_naive_tz(initial_tz)
    except ValueError:
        pass
