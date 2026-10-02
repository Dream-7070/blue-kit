# SPEC: Synthetic Journal Log Format Support (.journal)

**Sana:** 2026-10-02  
**Maqsad:** BlueKit log analizatoriga `.journal` ko'p qatorli kalit-qiymat (Key-Value block) formatidagi sintetik loglarni to'g'ridan-to'g'ri o'qish imkoniyatini qo'shish.

---

## 1. Kontekst va Muammo
`05_clockwork_vault` va shunga o'xshash CTF/Scenario mashg'ulotlarida loglar `.journal` kengaytmasi bilan quyidagi ko'p qatorli bloklar formatida saqlangan:

```text
TIME=2026-09-21T06:00:04+00:00
EVENT_ID=05-Nauth-0310
SOURCE=auth
MESSAGE=object read
DETAIL=actor=maintenance-2 src=10.24.1.77 result=denied ticket=OPS-129
```

Oldin `bluekit/logs/formats.py` faqat `.csv`, `.json`, `.log` formatlarini qo'llab-quvvatlagan va `.journal` fayllari uchun `unknown` (Noma'lum format) xatoligi qaytarilgan.

---

## 2. Kiritilgan o'zgartirishlar (Diff)

### Fayl 1: `bluekit/logs/formats.py`
`SUPPORTED_EXTS` ro'yxatiga `.journal` qo'shildi:
```python
# Oldingi:
SUPPORTED_EXTS = {'.csv', '.json', '.log'}

# Yangilangan:
SUPPORTED_EXTS = {'.csv', '.json', '.log', '.journal'}
```

### Fayl 2: `bluekit/logs/parse.py`
`load_rows(path)` funksiyasiga `.journal` bloklarini parslash mantiqi qo'shildi:
```python
        elif ext == '.journal':
            content = f.read()
            blocks = content.strip().split('\n\n')
            for b in blocks:
                if not b.strip():
                    continue
                row = {}
                for line in b.strip().split('\n'):
                    if '=' in line:
                        k, v = line.split('=', 1)
                        k = k.strip().lower()
                        v = v.strip()
                        if k == 'time':
                            row['timestamp'] = v
                        elif k == 'event_id':
                            row['event_id'] = v
                        elif k == 'source':
                            row['source'] = v
                        elif k == 'message':
                            row['message'] = v
                        elif k == 'detail':
                            row['detail'] = v
                            for part in v.split():
                                if '=' in part:
                                    pk, pv = part.split('=', 1)
                                    row[pk] = pv
                if row:
                    rows.append(row)
```

---

## 3. Qanday ishlaydi?
1. Bo'sh qator (`\n\n`) bilan ajratilgan har bir log yozuvi bitta voqea sifatida olinadi.
2. `TIME` ustuni `timestamp` ga o'tkaziladi (BlueKit standart vaqt tahlili uchun).
3. `DETAIL` dagi `key=value` juftliklari (`actor`, `src`, `host`, `user`, `result`, `ticket` va boshqalar) avtomatik ravishda alohida ustunlarga (`row[pk] = pv`) yoyiladi.
4. Bu orqali `fieldmap.yaml` dagi `src -> src_ip`, `host -> host` qoidalari to'g'ridan-to'g'ri ishlaydi.

---

## 4. Tekshiruv va Test natijalari
- `python bk.py logs analyze test/05_clockwork_vault/evidence/auth.journal` muvaffaqiyatli bajarildi (657 ta voqea yuklandi).
- Regressiya testlari (`python test.py`) to'liq o'tdi (Exit Code 0).
