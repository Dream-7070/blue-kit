# SPEC_DOCTOR — xizmat tashxisi va triage hisoboti

Loyiha: `D:\Claude Projects\CTF\blue-kit-staging`

Ikkita stub haqiqiy kodga almashtiriladi. Ikkalasi ham snapshotdagi mavjud
ma'lumot bilan ishlaydi — kollektorlarni o'zgartirish **kerak emas**.

## Nega

**1. `bluekit/resp/servicedoctor.py` — 2 qator, kirishga qaramasdan bir xil javob:**

```python
def diagnose(snapshot, service_name):
    return [{"cause": "disabled", "evidence": "start_mode is disabled",
             "suggested_fix_command": "sc config service start= auto"}]
```

Qaysi xizmat so'ralishidan qat'i nazar "disabled" deydi va buyruqda xizmat nomi
o'rniga `service` so'zi turadi. `bk resp doctor` va `/api/resp/doctor` shunga ulangan.

**2. `bluekit/resp/report.py` — bo'sh HTML yozadi:**

```python
def generate_html(findings, out_path):
    with open(out_path, 'w') as f:
        f.write("<html><body><h1>Triage Report</h1></body></html>")
```

`bk.py:357` da `bk resp triage ... --out r.html` aynan shuni chaqiradi — ya'ni
foydalanuvchi hisobot so'raydi, bo'sh sahifa oladi va buni sezmaydi.

## TEGMANG

`bk.py`, `bluekit/web/**`, `bluekit/siem/**`, `bluekit/hunt/**`, `bluekit/ir/**`,
`bluekit/logs/**`, `bluekit/resp/triage.py`, `bluekit/resp/remediate.py`,
`bluekit/resp/logbridge.py`, `bluekit/resp/sla.py`, `bluekit/resp/scoring.py`,
mavjud `tests/test_*.py`, `responder/collect_*.{ps1,sh}`.

`bluekit/resp/fraud.py` ham stub, lekin **bu ishda emas** — unga kerakli ma'lumot
(proxy, DNS, sertifikatlar) hozir snapshotda yo'q, u alohida ish.

**O'zgartiriladigan:** `bluekit/resp/servicedoctor.py`, `bluekit/resp/report.py`.
**Yangi:** `tests/test_doctor.py`.

## Mavjud chaqiruvchilar buzilmasin

```python
# bk.py va bluekit/web/server.py
from bluekit.resp.servicedoctor import diagnose
diagnose(cur, args.service)          # ikkita pozitsion argument

from bluekit.resp.report import generate_html
generate_html(findings, args.out)    # ikkita pozitsion argument
```

Nomlar va birinchi ikkita argument **saqlansin**. Yangi argumentlar faqat
ixtiyoriy (default bilan) qo'shilsin.

---

## 1-qism · `servicedoctor.py`

```python
def diagnose(current, service_name, baseline=None, sla_result=None) -> list:
```

`current` / `baseline` — `responder/collect_*.{ps1,sh}` chiqishi. Sxema
`bluekit/resp/schema.py` da. Ishlatiladigan maydonlar:

- `meta`: `{os: 'windows'|'linux', hostname}`
- `services`: `[{name, display, state, start_mode, binary_path, run_as}]`
- `tasks`: `[{name, path, action, trigger, author}]`
- `autoruns`: `[{location, name, value}]`
- `listening_ports`: `[{proto, addr, port, pid, process}]`
- `recent_modified`: `[{path, mtime}]` (bo'lmasligi mumkin)

`sla_result` — ixtiyoriy, `bluekit.resp.sla.check()` qaytargan bitta xizmat lug'ati.
Berilsa, qaysi tekshiruv yiqilgani tashxisni aniqlashtiradi.

### Tekshiriladigan sabablar

Har biri topilganda ro'yxatga qo'shiladi. **Topilmasa — qo'shilmaydi.** Hech narsa
topilmasa bo'sh ro'yxat emas, bitta `cause: "sabab aniqlanmadi"` elementi qaytsin,
ichida nima tekshirilgani `evidence` da sanalsin.

| # | Sabab | Shart | ATT&CK |
|---|---|---|---|
| 1 | Xizmat umuman yo'q | `services` da nom topilmadi | T1489 |
| 2 | O'chirib qo'yilgan | `start_mode` = `Disabled`/`disabled` | T1489 |
| 3 | To'xtagan | `state` != `Running`/`active`, `start_mode` = `Auto` | T1489 |
| 4 | Binary yo'li o'zgargan | `baseline` dagi `binary_path` bilan farq | T1543.003 |
| 5 | Shubhali papkadan ishga tushyapti | yo'lda `\Temp\`, `\AppData\`, `\ProgramData\`, `\Users\`, `/tmp/`, `/dev/shm/` | T1036.005 |
| 6 | Qo'shtirnoqsiz yo'l (bo'shliq bilan) | Windows, `binary_path` da bo'shliq bor va `"` bilan boshlanmaydi | T1574.009 |
| 7 | Ishga tushirish akkaunti o'zgargan | `baseline` dagi `run_as` bilan farq | T1543.003 |
| 8 | Kimdir uni qayta to'xtatyapti | `tasks[].action` yoki `autoruns[].value` ichida `sc stop <nom>`, `net stop <nom>`, `systemctl stop <nom>`, `Stop-Service <nom>` | T1489 |
| 9 | Binary yaqinda o'zgartirilgan | `recent_modified` ichida shu `binary_path` | T1543.003 |
| 10 | Ishlayapti, lekin port tinglanmayapti | `state` = Running, lekin `sla_result` dagi `tcp` tekshiruvi yiqilgan | — |
| 11 | Port ochiq, ilova javob bermayapti | `sla_result` da `tcp` ok, `http` yiqilgan | — |

Xizmat nomi taqqoslashda katta-kichik harf hisobga olinmasin; `display` nomi bilan
ham qidirilsin.

### Qaytariladigan format

```python
[
  {
    'cause': "Xizmat o'chirib qo'yilgan (start_mode=Disabled)",   # o'zbekcha
    'evidence': "services[]: name='W3SVC', state='Stopped', start_mode='Disabled'",
    'confidence': 'yuqori',              # yuqori | o'rta | past
    'suggested_fix_command': 'sc config "W3SVC" start= auto && sc start "W3SVC"',
    'technique': 'T1489',                # bo'lmasa None
    'risk': "Buyruqni bajarishdan oldin binary_path ni tekshiring",  # ixtiyoriy
  },
]
```

`cause`, `evidence`, `suggested_fix_command` kalitlari **majburiy** (eski
chaqiruvchilar shularni kutadi). Ro'yxat ishonch bo'yicha kamayish tartibida.

### Buyruqlar platformaga qarab

`meta.os` bo'yicha:

| Holat | Windows | Linux |
|---|---|---|
| Yoqish | `sc config "<nom>" start= auto` | `systemctl enable <nom>` |
| Ishga tushirish | `sc start "<nom>"` | `systemctl start <nom>` |
| Yo'lni tiklash | `sc config "<nom>" binPath= "<baseline yo'li>"` | `systemctl edit <nom>` (qo'lda) |
| Holatni ko'rish | `sc qc "<nom>"` | `systemctl status <nom>` |

**Buyruqlar faqat ko'rsatiladi, bajarilmaydi** — loyihaning qoidasi shunday.
Xizmat nomi buyruqqa qo'shtirnoq ichida qo'yilsin (bo'shliqli nomlar uchun).

---

## 2-qism · `report.py`

```python
def generate_html(findings, out_path, extra=None, meta=None) -> None:
```

`findings` — `bluekit.resp.triage.analyze()` qaytargan **birinchi** element.
Uning shakli (namuna):

```python
{'category': 'tasks', 'item': 'Updater', 'score': 0.6, 'confidence': 'high',
 'techniques': [{'id': 'T1053.005'}], 'reasons': ["baseline'da yo'q (yangi)",
 "shubhali papka"], 'protected': False}
```

`extra` — `analyze()` ning ikkinchi elementi (ichida `checker_candidates` bo'lishi
mumkin). `meta` — snapshot `meta` si (hostname, collected_at).

### HTML talablari

- **To'liq oflayn**: CDN yo'q, tashqi shrift yo'q, rasm yo'q. Hamma CSS `<style>`
  ichida. `<meta charset="utf-8">` majburiy.
- Sarlavha: hostname va snapshot vaqti (`meta` berilgan bo'lsa).
- Yuqorida jamlanma: jami topilma, ishonch bo'yicha soni (high/medium/low),
  `protected` belgilanganlari soni.
- Asosiy jadval, ball bo'yicha kamayish tartibida:
  `Ball | Ishonch | Kategoriya | Element | ATT&CK | Sabablar`
- Ishonch ranglari: high — qizil, medium — sariq, low — kulrang.
  `protected: true` bo'lganlar alohida belgilansin ("himoyalangan — tegmang").
- ATT&CK ustunida ID lar vergul bilan.
- `extra['checker_candidates']` bo'lsa — jadval ostida alohida blok:
  "Mumkin bo'lgan checker IP lari — BULARNI BLOKLAMANG".
- Matnlar o'zbekcha.
- **HTML escape majburiy**: `item` va `reasons` ichida `<`, `>`, `&`, `"` bo'lishi
  mumkin (fayl yo'llari, buyruq qatorlari). `html.escape` ishlating.
- `findings` bo'sh bo'lsa ham to'g'ri sahifa chiqsin ("topilma yo'q").

---

## 3-qism · Testlar (`tests/test_doctor.py`, YANGI fayl)

Stub bilan **o'tmaydigan** testlar. 1 va 2 eng muhimi.

1. **Har xil sabab — har xil javob:** `Disabled` xizmat uchun va `Stopped`+`Auto`
   xizmat uchun `diagnose()` **turli** `cause` qaytarsin. *(Eski stub ikkalasiga
   bir xil javob berardi — maqsad shu.)*
2. **Buyruqda haqiqiy xizmat nomi:** `diagnose(snap, 'W3SVC')` natijasidagi
   `suggested_fix_command` ichida `W3SVC` bo'lsin. *(Eski stubda `service` so'zi
   turardi.)*
3. **Xizmat topilmadi** — `services` bo'sh snapshotda `cause` "yo'q" holatini
   ko'rsatsin.
4. **Baseline bilan farq:** `binary_path` baselineda `C:\Windows\System32\a.exe`,
   currentda `C:\Users\x\AppData\Local\Temp\a.exe` → yo'l o'zgargani **va**
   shubhali papka aniqlansin, ikkalasi ham natijada bo'lsin.
5. **Qo'shtirnoqsiz yo'l:** `C:\Program Files\App\svc.exe` (qo'shtirnoqsiz,
   bo'shliqli) → T1574.009 sababi chiqsin.
6. **Qayta to'xtatuvchi vazifa:** `tasks` da `action` = `sc stop W3SVC` bo'lsa,
   shu sabab topilsin.
7. **Linux:** `meta.os = 'linux'` bo'lsa buyruqlarda `systemctl` bo'lsin, `sc`
   bo'lmasin.
8. **`sla_result` bilan:** `tcp` ok + `http` yiqilgan → "ilova javob bermayapti"
   sababi chiqsin.
9. **Hech narsa topilmasa** — bo'sh ro'yxat emas, tushuntirishli bitta element.
10. **Orqaga moslik:** `diagnose(cur, 'X')` ikki argument bilan ishlaydi va har
    elementda `cause`, `evidence`, `suggested_fix_command` bor.
11. **ATT&CK ID lari KB da active** (`bluekit.kb.query.KB().validate`), KB yo'q
    bo'lsa `skipUnless`. **T1562 ni ishlatmang — u v19 da revoked (T1685).**
12. **HTML hisobot:** `generate_html(findings, tmp)` yozgan fayl ichida topilma
    `item` matni bor, `<meta charset` bor, va `<script src=` yoki `http://` ga
    tashqi havola **yo'q** (oflayn).
13. **HTML escape:** `item` qiymati `<img src=x onerror=1>` bo'lsa, faylda xom
    `<img` bo'lmasin (escape qilingan bo'lsin).
14. **Bo'sh findings** bilan ham istisnosiz fayl yozilsin.

## 4-qism · Qabul

```
python -m unittest discover -s tests -p "test_*.py" -q
python bk.py resp doctor data\samples\resp\current_win.json Spooler
python bk.py resp triage data\samples\resp\current_win.json --baseline data\samples\resp\baseline_win.json --out r_test.html
```

Hozir **86 ta test** yashil — hammasi yashil qolsin, ustiga yangilari qo'shilsin.

Hisobotda **ko'chirib** keltiring:
- `bk resp doctor ... Spooler` chiqishi
- yozilgan `r_test.html` ning birinchi 20 qatori
- `unittest` chiqishining oxirgi 3 qatori

Bajara olmagan qismni ochiq yozing. Bir xil javob qaytaradigan ikkinchi versiya
kerak emas.
