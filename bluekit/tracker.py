import json
import os
import uuid
import threading
import time
import tempfile
import re
from datetime import datetime, timezone

RESULTS = ('accepted', 'rejected', 'pending')

class TrackerError(ValueError):
    pass

class RowNotFound(KeyError):
    pass

class AttemptNeedsConfirm(Exception):
    def __init__(self, check: dict):
        self.check = check

def parse_max_attempts(value) -> int | None:
    if value is None or str(value).strip() == "":
        return None
    try:
        val = str(value).strip()
        num = int(val)
        if num < 1 or str(num) != val:
            raise ValueError
        return num
    except ValueError:
        raise TrackerError("max_attempts musbat butun son bo'lishi kerak")

def normalize_row(row: dict) -> dict:
    new_row = dict(row)
    if not new_row.get("id"):
        new_row["id"] = uuid.uuid4().hex
    
    new_row["question"] = str(new_row.get("question", "")) if new_row.get("question") is not None else ""
    new_row["candidates"] = str(new_row.get("candidates", "")) if new_row.get("candidates") is not None else ""
    new_row["evidence"] = str(new_row.get("evidence", "")) if new_row.get("evidence") is not None else ""
    new_row["status"] = str(new_row.get("status", "")) if new_row.get("status") is not None else ""
    
    try:
        new_row["max_attempts"] = parse_max_attempts(new_row.get("max_attempts"))
    except TrackerError:
        new_row["max_attempts"] = None
        
    attempts = new_row.get("attempts", [])
    if not isinstance(attempts, list):
        attempts = []
        
    valid_attempts = []
    for att in attempts:
        if isinstance(att, dict) and isinstance(att.get("answer"), str):
            res = att.get("result")
            if res not in RESULTS:
                res = "pending"
            at = att.get("at")
            if not isinstance(at, str):
                at = ""
            if not att["answer"].strip():
                continue
            valid_attempts.append({"answer": att["answer"], "result": res, "at": at})
            
    new_row["attempts"] = valid_attempts
    return new_row

def load(path) -> list:
    # Windows: boshqa oqim faylni o'qib turganda os.replace PermissionError beradi —
    # shuning uchun o'qish ham yozish bilan bitta (RLock) qulf ostida.
    with _tracker_lock:
        return _load_unlocked(path)

def _load_unlocked(path) -> list:
    if not os.path.exists(path):
        return []
    if os.path.getsize(path) == 0:
        return []
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        raise TrackerError(f"tracker.json o'qilmadi: {e}")
        
    if not isinstance(data, list):
        raise TrackerError("tracker.json o'qilmadi: list kutilgan")
        
    rows = []
    changed_id = False
    for item in data:
        if isinstance(item, dict):
            old_id = item.get("id")
            norm = normalize_row(item)
            if old_id != norm["id"]:
                changed_id = True
            rows.append(norm)
            
    if changed_id:
        save(path, rows)
        
    return rows

def save(path, rows) -> None:
    fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(path) if os.path.dirname(path) else '.')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(rows, f, ensure_ascii=False, indent=1)
        # Boshqa JARAYON (CLI, antivirus) faylni ochib turgan bo'lsa qisqa kutib qayta urinamiz
        for i in range(20):
            try:
                os.replace(temp_path, path)
                break
            except PermissionError:
                if i == 19:
                    raise
                time.sleep(0.05)
    except Exception:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        raise

_tracker_lock = threading.RLock()

def mutate(path, fn):
    with _tracker_lock:
        rows = load(path)
        result = fn(rows)
        save(path, rows)
        return result

def find_row(rows, row_id) -> dict:
    for r in rows:
        if r.get("id") == row_id:
            return r
    raise RowNotFound(row_id)

def _text(value) -> str:
    """JSON null -> "" (aks holda str(None) "None" matnini yozib qo'yardi)."""
    return "" if value is None else str(value).strip()

def add_row(rows, data: dict) -> dict:
    q = data.get("question", "")
    if q is not None:
        q = str(q).strip()
    if not q:
        raise TrackerError("Savol matni bo'sh")
        
    new_row = {
        "id": uuid.uuid4().hex,
        "question": q,
        "candidates": _text(data.get("candidates")),
        "evidence": _text(data.get("evidence")),
        "status": _text(data.get("status")) or "tekshirilmoqda",
        "max_attempts": parse_max_attempts(data.get("max_attempts")),
        "attempts": []
    }
    rows.append(new_row)
    return new_row

EDITABLE = ('question', 'candidates', 'evidence', 'status', 'max_attempts')

def update_row(rows, row_id, data: dict) -> dict:
    row = find_row(rows, row_id)
    if 'question' in data:
        q = _text(data['question'])
        if not q:
            raise TrackerError("Savol matni bo'sh")
        row['question'] = q

    if 'candidates' in data:
        row['candidates'] = _text(data['candidates'])
    if 'evidence' in data:
        row['evidence'] = _text(data['evidence'])
    if 'status' in data:
        row['status'] = _text(data['status'])
    if 'max_attempts' in data:
        row['max_attempts'] = parse_max_attempts(data['max_attempts'])
        
    return row

def delete_row(rows, row_id) -> None:
    for i, r in enumerate(rows):
        if r.get("id") == row_id:
            del rows[i]
            return
    raise RowNotFound(row_id)

def norm_answer(answer) -> str:
    return " ".join(str(answer).split()).upper()

def check_attempt(row, answer) -> dict:
    attempts = row.get("attempts", [])
    used = len(attempts)
    max_att = row.get("max_attempts")
    remaining = max_att - used if max_att is not None else None
    if remaining is not None and remaining < 0:
        remaining = 0
        
    norm_ans = norm_answer(answer)
    duplicate = False
    duplicate_of = None
    already_accepted = False
    
    for att in attempts:
        if norm_answer(att["answer"]) == norm_ans:
            duplicate = True
            duplicate_of = att
        if att.get("result") == "accepted":
            already_accepted = True
            
    over_limit = False
    last_attempt = False
    if max_att is not None:
        if used >= max_att:
            over_limit = True
        elif used == max_att - 1:
            last_attempt = True
            
    warnings = []
    if duplicate:
        warnings.append(f"'{duplicate_of['answer']}' bu savolga allaqachon topshirilgan ({duplicate_of['result']}, {duplicate_of['at']})")
    if over_limit:
        warnings.append(f"Urinishlar tugagan: {used}/{max_att} ishlatilgan — yana topshirsangiz limitdan oshadi")
    if last_attempt:
        warnings.append(f"Diqqat: bu OXIRGI urinish ({used}/{max_att} ishlatilgan)")
    if already_accepted:
        warnings.append("Bu savolga javob allaqachon qabul qilingan")
        
    return {
        "answer": str(answer).strip(),
        "used": used,
        "max": max_att,
        "remaining": remaining,
        "duplicate": duplicate,
        "duplicate_of": duplicate_of,
        "over_limit": over_limit,
        "last_attempt": last_attempt,
        "already_accepted": already_accepted,
        "warnings": warnings,
        "ok": len(warnings) == 0
    }

def add_attempt(row, answer, result='pending', force=False, now=None) -> dict:
    ans_str = str(answer).strip()
    if is_attack_id(ans_str):
        ans_str = ans_str.upper()   # t1566.001 -> T1566.001 (ledger ham katta harf yozadi)
    if not ans_str:
        raise TrackerError("Bo'sh javob")
    if result not in RESULTS:
        raise TrackerError("Noto'g'ri natija")
        
    check = check_attempt(row, answer)
    if not check['ok'] and not force:
        raise AttemptNeedsConfirm(check)
        
    if now is None:
        now = datetime.now(timezone.utc)
    at_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    
    if "attempts" not in row or not isinstance(row["attempts"], list):
        row["attempts"] = []
    row["attempts"].append({
        "answer": ans_str,
        "result": result,
        "at": at_str
    })
    return check

def set_attempt_result(row, index: int, result) -> dict:
    if result not in RESULTS:
        raise TrackerError("Noto'g'ri natija")
    attempts = row.get("attempts", [])
    if index < 0 or index >= len(attempts):
        raise RowNotFound(index)
    attempts[index]["result"] = result
    return row

def delete_attempt(row, index: int) -> None:
    attempts = row.get("attempts", [])
    if index < 0 or index >= len(attempts):
        raise RowNotFound(index)
    del attempts[index]

def public_row(row) -> dict:
    pub = dict(row)
    attempts = pub.get("attempts", [])
    used = len(attempts)
    max_att = pub.get("max_attempts")
    
    pub["used"] = used
    if max_att is not None:
        rem = max_att - used
        pub["remaining"] = rem if rem >= 0 else 0
    else:
        pub["remaining"] = None
        
    pub["solved"] = any(att.get("result") == "accepted" for att in attempts)
    pub["exhausted"] = (max_att is not None and used >= max_att and not pub["solved"])
    return pub

ATTACK_ID_RE = re.compile(r'^T\d{4}(\.\d{3})?$', re.I)
def is_attack_id(answer) -> bool:
    return bool(ATTACK_ID_RE.match(str(answer).strip()))

def find_by_question(rows, question) -> dict | None:
    q_norm = " ".join(str(question).split()).casefold()
    for r in rows:
        if " ".join(str(r.get("question", "")).split()).casefold() == q_norm:
            return r
    return None
