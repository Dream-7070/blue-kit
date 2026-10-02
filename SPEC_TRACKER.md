# SPEC_TRACKER — CTF Tracker: urinishlar limiti, tahrirlash, bo'sh nomzod (BACKEND)

Loyiha: `D:\Claude Projects\CTF\blue-kit-staging`

## Muammo

Musobaqada har bir savolga javob urinishlari cheklangan (masalan 3 ta). Web UI dagi
CTF Tracker esa har bir qatorni faqat `{id, question, candidates, evidence, status}`
erkin matn sifatida saqlaydi:

- urinishlar hisoblagichi va limit yo'q — jamoa bir xil ID ni ikki marta topshirib
  yoki limitdan oshib ketib, ball yo'qotishi mumkin;
- `PUT /api/tracker/<id>` har qanday kalitni (hatto `id` ni) qatorga yozib yuboradi va
  mavjud bo'lmagan `id` ga ham `{"success": true}` qaytaradi;
- `POST /api/tracker` bo'sh savolni ham qabul qiladi;
- fayl `json.dump` bilan to'g'ridan-to'g'ri (atomik emas) va qulfsiz yoziladi,
  holbuki server `ThreadingHTTPServer`.

CLI dagi `bk answers submit <ID> accepted|rejected|pending --ledger answers.json`
ham savol bo'yicha limitni bilmaydi.

Bu topshiriq — FAQAT backend (Python). Frontend (`app.js`, `index.html`) ni alohida
topshiriq qiladi — ularga TEGMANG.

## 0. Asosiy qoidalar

**O'zgartiriladigan:**
- `bluekit/web/server.py` — FAQAT tracker shoxlari (`/api/tracker...`) va
  `WebKitServer.__init__` dagi tracker fayl yaratish qismi;
- `bk.py` — FAQAT `answers submit` parseri va `if args.cmd == 'answers':` bloki
  ichidagi `submit` shoxi;
- `bk.spec` — `hiddenimports` ro'yxatiga `'bluekit.tracker'` qo'shish;
- `RELEASE.md` — hiddenimports ro'yxatiga `bluekit.tracker` qo'shish;
- `tests/test_web.py` — FAQAT yangi test metodlari QO'SHISH mumkin (mavjudlarini
  o'zgartirmang).

**Yangi:** `bluekit/tracker.py`, `tests/test_tracker.py`.

**TEGMANG:** `bluekit/answers.py` (faqat `record` ni chaqiring), `bluekit/web/static/**`,
`bluekit/playbook.py`, `bluekit/siem/**`, `bluekit/logs/**`, `bluekit/resp/**`,
`bluekit/ir/**`, boshqa barcha `tests/test_*.py`.

Fayllar faqat **O'SISHI** kerak. Hozir: `server.py` 666 qator, `bk.py` ~900+ qator.
Mavjud funksiyalarni (`run_server`, `do_PUT`, `do_DELETE`, `_load_resp_args`,
`/api/report`, `/api/playbook...` va h.k.) qayta yozish, qisqartirish yoki
"tozalash" TAQIQLANADI. `server.py` ni butunlay qayta yozmang — faqat kerakli
joylarni tahrirlang.

**bk.py scoping tuzog'i:** `bk.py` dagi `main()` bitta ulkan funksiya. Modul
darajasida allaqachon import qilingan nomni (`json`, `os`, `sys`, `KB`) `main()`
ichida QAYTA `import` qilmang — bu Python ga butun `main()` da uni lokal deb
belgilatadi va boshqa shoxlarni `UnboundLocalError` bilan buzadi. Kerak bo'lsa
`import json as _json` kabi taxallus bilan import qiling (mavjud kod shunday qiladi).

**Unicode:** fayllarni UTF-8 da saqlang, mavjud o'zbekcha/emoji matnni buzmang.
Stub, `pass`, `TODO`, "placeholder" yozmang — har bir funksiya to'liq ishlashi shart.

## 1. `bluekit/tracker.py` (yangi modul, sof mantiq, faqat stdlib)

### Ma'lumot shakli (tracker.json — qatorlar ro'yxati)

```json
[
  {
    "id": "32-belgili hex",
    "question": "3-savol: dastlabki kirish texnikasi?",
    "candidates": "T1566.001, T1204.002",
    "evidence": "Proxy log 08:45",
    "status": "tekshirilmoqda",
    "max_attempts": 3,
    "attempts": [
      {"answer": "T1566.001", "result": "rejected", "at": "2026-10-05T08:51:02Z"},
      {"answer": "T1566.002", "result": "pending",  "at": "2026-10-05T08:55:40Z"}
    ]
  }
]
```

- `max_attempts`: `int >= 1` yoki `null` (limit noma'lum / cheklanmagan).
- `attempts[].result`: faqat `accepted` | `rejected` | `pending` (`RESULTS` konstantasi).
- `attempts[].at`: UTC, format `%Y-%m-%dT%H:%M:%SZ`.

**Orqaga moslik:** eski fayllarda faqat `{id, question, candidates, evidence, status}`
bor (masalan `D:\Tools\blue-kit-dist\web-work\tracker.json` da:
`[{"id": "186ac9...", "question": " dsdsd", "candidates": "wsed", "evidence": "sd", "status": "sd"}]`).
Ular xatosiz yuklanishi, yo'q maydonlar standart qiymat olishi va qatorning
**noma'lum qo'shimcha kalitlari saqlanib qolishi** shart.

### Funksiyalar (aniq shu nomlar va imzolar)

```python
RESULTS = ('accepted', 'rejected', 'pending')

class TrackerError(ValueError): ...          # 400 — noto'g'ri kirish
class RowNotFound(KeyError): ...             # 404
class AttemptNeedsConfirm(Exception):        # 409 — ogohlantirish, force kerak
    def __init__(self, check: dict): self.check = check

def normalize_row(row: dict) -> dict
```
Nusxa qaytaradi (kirishni o'zgartirmaydi). `id` yo'q/bo'sh → `uuid.uuid4().hex`;
`question`, `candidates`, `evidence`, `status` → `str` (None → `""`); `max_attempts`
→ `parse_max_attempts` orqali, lekin eski/buzuq qiymatda xato ko'tarmay `None` qiladi;
`attempts` → ro'yxat bo'lmasa `[]`, har bir element dict bo'lishi va `answer`
(str) bo'lishi kerak, aks holda tashlab yuboriladi; `result` `RESULTS` da bo'lmasa
`"pending"`; `at` yo'q bo'lsa `""`. Boshqa kalitlar o'zgarishsiz qoladi.

```python
def parse_max_attempts(value) -> int | None
```
`None`, `""`, faqat bo'shliq → `None`. `int` yoki raqamli string (`"3"`, `" 3 "`)
→ `int`. `< 1`, kasr, `bool`, raqam bo'lmagan string → `TrackerError`
(o'zbekcha xabar: `"max_attempts musbat butun son bo'lishi kerak"`).

```python
def load(path) -> list
```
Fayl yo'q → `[]`. Bo'sh fayl → `[]`. JSON buzuq yoki ro'yxat emas → `TrackerError`
(`"tracker.json o'qilmadi: ..."`) — **faylni hech qachon ustidan yozmang/tozalamang**,
jamoa ma'lumoti yo'qolmasin. Har bir element `normalize_row` dan o'tadi (dict
bo'lmagan elementlar tashlab yuboriladi). Agar normalizatsiya natijasida biror
qatorga yangi `id` berilgan bo'lsa — faylni darhol `save` qiling (aks holda har
GET da id o'zgarib, UI dagi tugmalar ishlamay qoladi).

```python
def save(path, rows) -> None
```
Atomik: shu papkada `tempfile.mkstemp` → `json.dump(rows, f, ensure_ascii=False, indent=1)`
UTF-8 → `os.replace`. Xatoda vaqtinchalik faylni o'chiring va xatoni qayta ko'taring.

```python
def mutate(path, fn):
```
Modul darajasidagi `threading.Lock()` ostida: `rows = load(path)`; `result = fn(rows)`;
`save(path, rows)`; `return result`. Agar `fn` xato ko'tarsa — saqlamang, xatoni
o'tkazib yuboring. Server BARCHA yozuvchi amallarni shu orqali qiladi.

```python
def find_row(rows, row_id) -> dict            # yo'q bo'lsa RowNotFound
def add_row(rows, data: dict) -> dict
```
`question` `.strip()` dan keyin bo'sh bo'lsa → `TrackerError("Savol matni bo'sh")`.
`candidates` **ixtiyoriy** (bo'sh bo'lishi mumkin — nomzod hali topilmagan savolni
oldindan kiritish uchun). `status` bo'sh bo'lsa → `"tekshirilmoqda"`.
`max_attempts` → `parse_max_attempts`. `attempts = []`. Yangi `id`. Qatorni
`rows` ga qo'shib, uni qaytaradi. Barcha matn maydonlari `.strip()` qilinadi.

```python
EDITABLE = ('question', 'candidates', 'evidence', 'status', 'max_attempts')
def update_row(rows, row_id, data: dict) -> dict
```
FAQAT `EDITABLE` dagi kalitlar qo'llanadi; `id`, `attempts` va boshqa kalitlar
**jimgina e'tiborsiz qoldiriladi**. `question` bo'sh qilib yuborilsa → `TrackerError`.
`max_attempts` → `parse_max_attempts` (bu yerda `""`/`None` limitni olib tashlaydi).
Yangilangan qatorni qaytaradi.

```python
def delete_row(rows, row_id) -> None          # yo'q bo'lsa RowNotFound
def norm_answer(answer) -> str
```
`" ".join(str(answer).split()).upper()` — dublikatni aniqlash uchun
(`t1566.001` == `T1566.001 `).

```python
def check_attempt(row, answer) -> dict
```
Hech narsani o'zgartirmaydi. Qaytaradi:
```python
{
  "answer": "<strip qilingan answer>",
  "used": <len(attempts)>,          # pending ham urinish hisoblanadi
  "max": <max_attempts yoki None>,
  "remaining": <max-used, 0 dan kichik emas> yoki None,
  "duplicate": bool,                 # shu savolda norm_answer bir xil urinish bor
  "duplicate_of": {...} yoki None,   # o'sha oldingi urinish (answer/result/at)
  "over_limit": bool,                # max bor va used >= max
  "last_attempt": bool,              # max bor va used == max-1
  "already_accepted": bool,          # shu savolda accepted urinish bor
  "warnings": [ ...o'zbekcha matnlar... ],
  "ok": bool                         # warnings bo'sh bo'lsa True
}
```
Warning matnlari (aynan shu mazmunda, raqamlar bilan):
- duplicate: `"'T1566.001' bu savolga allaqachon topshirilgan (rejected, 2026-10-05T08:51:02Z)"`
- over_limit: `"Urinishlar tugagan: 3/3 ishlatilgan — yana topshirsangiz limitdan oshadi"`
- last_attempt: `"Diqqat: bu OXIRGI urinish (2/3 ishlatilgan)"`
- already_accepted: `"Bu savolga javob allaqachon qabul qilingan"`

```python
def add_attempt(row, answer, result='pending', force=False, now=None) -> dict
```
`answer` strip dan keyin bo'sh → `TrackerError`. `result` `RESULTS` da emas →
`TrackerError`. `check = check_attempt(row, answer)`; agar `not check['ok'] and not force`
→ `raise AttemptNeedsConfirm(check)` (qator O'ZGARMAYDI). Aks holda
`{"answer", "result", "at"}` qo'shadi (`now` — test uchun `datetime`, bo'lmasa
`datetime.now(timezone.utc)`), va `check` ni qaytaradi (qo'shilgandan OLDINGI holat).

```python
def set_attempt_result(row, index: int, result) -> dict   # indeks noto'g'ri → RowNotFound; result noto'g'ri → TrackerError
def delete_attempt(row, index: int) -> None                 # indeks noto'g'ri → RowNotFound
```
(Manfiy indeks ham noto'g'ri hisoblanadi.)

```python
def public_row(row) -> dict
```
Qator nusxasi + hisoblangan (faylga YOZILMAYDIGAN) maydonlar:
`used`, `remaining`, `solved` (accepted urinish bormi), `exhausted`
(`max` bor va `used >= max` va `not solved`).

```python
ATTACK_ID_RE = re.compile(r'^T\d{4}(\.\d{3})?$', re.I)
def is_attack_id(answer) -> bool
```

```python
def find_by_question(rows, question) -> dict | None
```
`" ".join(q.split()).casefold()` bo'yicha to'liq tenglik (CLI uchun).

## 2. `bluekit/web/server.py`

`from bluekit import tracker as trk` (modul boshida).

`WebKitServer.__init__`: tracker faylini yaratish mantig'i qolsin (yo'q bo'lsa `[]`);
qo'shimcha `self.ledger_file = os.path.join(workdir, 'answers.json')`.

Endpointlar (javob har doim JSON; xatolar `{"error": "..."}`):

| Metod | Yo'l | Tana | Javob |
|---|---|---|---|
| GET | `/api/tracker` | — | `[public_row(r) ...]` (ro'yxat — eski shakl saqlanadi) |
| POST | `/api/tracker` | `{question, candidates?, evidence?, status?, max_attempts?}` | 200 `{"id": ..., "row": public_row}` ; 400 `TrackerError` |
| PUT | `/api/tracker/<id>` | EDITABLE kalitlardan istalgani | 200 `{"success": true, "row": public_row}` ; 404 ; 400 |
| DELETE | `/api/tracker/<id>` | — | 200 `{"success": true}` ; 404 |
| POST | `/api/tracker/<id>/check` | `{answer}` | 200 `check` dict (hech narsa yozilmaydi) ; 404 |
| POST | `/api/tracker/<id>/attempts` | `{answer, result?, force?}` | 200 `{"row": public_row, "check": check}` ; **409** `{"error": "; ".join(warnings), "needs_confirm": true, "check": check}` ; 404 ; 400 |
| PUT | `/api/tracker/<id>/attempts/<n>` | `{result}` | 200 `{"row": public_row}` ; 404 ; 400 |
| DELETE | `/api/tracker/<id>/attempts/<n>` | — | 200 `{"row": public_row}` ; 404 |

- Barcha yozuvchi amallar `trk.mutate(self.server.tracker_file, fn)` orqali.
- Xato xaritasi: `AttemptNeedsConfirm` → 409, `RowNotFound` → 404, `TrackerError` → 400,
  qolgani → 500. Diqqat: `TrackerError` `ValueError` dan meros, `RowNotFound` esa
  `KeyError` dan — `do_POST` ning mavjud umumiy `except (ValueError, FileNotFoundError)`
  bloki 404/409 ni buzmasligi uchun tracker shoxlari O'Z `try/except` iga ega bo'lsin
  (umumiy blokka yetib bormasin).
- `/api/tracker/<id>/attempts...` yo'llarni `/api/tracker/<id>` bilan chalkashtirmang:
  `path.split('/')` ni to'g'ri tahlil qiling (`['', 'api', 'tracker', id, 'attempts', n]`).
  `n` raqam bo'lmasa → 404.
- `force` — faqat `True`/`true` bo'lganda kuchga kiradi (`data.get('force') is True`).
- **Ledger bilan bog'lash:** urinish muvaffaqiyatli qo'shilganda VA natijasi
  `PUT .../attempts/<n>` bilan o'zgarganda, agar `trk.is_attack_id(answer)` bo'lsa,
  `bluekit.answers.record(self.server.ledger_file, answer.upper(), result, note=question)`
  chaqiring (tracker qulfidan TASHQARIDA, mutate tugagandan keyin). Ledger yozuvi
  xato bersa — tracker javobi baribir 200, faqat javobga `"ledger_warning": str(e)`
  qo'shing. Urinish o'chirilganda ledger ga tegmang (u append-only).
  Shu tufayli `bk answers rank ... --ledger web-work/answers.json` web da
  topshirilgan ID larni "[TOPSHIRILGAN]" deb ko'rsatadi.

## 3. `bk.py` — `bk answers submit`

Yangi ixtiyoriy argumentlar:
- `--question TEXT` — tracker savoli matni;
- `--max N` (int) — shu savol uchun `max_attempts` (yangi qator yaratilganda yoki
  mavjudini yangilash uchun);
- `--tracker PATH` — default `web-work/tracker.json`;
- `--force` — ogohlantirishlarga qaramay yozish.

`--question` BERILMASA — xatti-harakat 100% avvalgidek (faqat ledger).

`--question` berilsa:
1. `trk.mutate(args.tracker, fn)`: `find_by_question`; topilmasa `add_row` (candidates
   = technique, max_attempts = `--max`); topilsa va `--max` berilgan bo'lsa
   `max_attempts` yangilanadi; so'ng `add_attempt(row, technique, result, force=args.force)`.
   Tracker papkasi yo'q bo'lsa yarating.
2. `AttemptNeedsConfirm` bo'lsa: har bir warning ni `"OGOHLANTIRISH: ..."` deb chiqaring,
   `"Baribir yozish uchun --force qo'shing."` va `sys.exit(2)` — ledger ga ham
   YOZMANG (va tracker o'zgarmasligi kerak — mutate `fn` xato bersa saqlamaydi).
3. Muvaffaqiyatda: ledger ga `record(...)` (avvalgidek), va chiqish:
   `"Yozildi: T1566.001 -> rejected | savol: <q> | urinish 2/3"` (max yo'q bo'lsa `2/?`).
   Agar natija `rejected` bo'lsa va urinishlar tugagan bo'lsa qo'shimcha qator:
   `"Bu savolga urinishlar tugadi."`
4. `TrackerError` → xabarni chiqarib `sys.exit(1)`.

## 4. Testlar

### `tests/test_tracker.py` (yangi, `tempfile` papkada, KB talab qilmaydi)
Kamida quyidagilar — har biri alohida test metodi:
1. `test_legacy_row_loads` — faylga aynan
   `[{"id": "186ac90e6f6a49e8b6f8177a3dea527b", "question": " dsdsd", "candidates": "wsed", "evidence": "sd", "status": "sd", "extra_key": 5}]`
   yozing → `load` 1 qator, `max_attempts is None`, `attempts == []`, `id` o'zgarmagan,
   `extra_key == 5` saqlangan; `mutate` bilan bir urinish qo'shib qayta yuklang —
   `extra_key` hali ham bor.
2. `test_missing_id_persisted` — id siz qator: ikki marta `load` → bir xil id.
3. `test_corrupt_file_not_overwritten` — faylga `"{buzuq"` yozing → `load`
   `TrackerError`; `mutate` ham xato beradi; fayl mazmuni `"{buzuq"` bo'lib QOLADI.
4. `test_add_row_empty_candidates` — `candidates` siz qator qo'shiladi; bo'sh
   `question` (`"   "`) → `TrackerError`.
5. `test_parse_max_attempts` — `"3"`→3, `" 2 "`→2, `""`→None, `None`→None;
   `0`, `-1`, `"abc"`, `2.5`, `True` → `TrackerError`.
6. `test_update_row_ignores_protected` — `update_row(..., {"candidates": "T1", "id": "x", "attempts": [], "foo": 1})`
   → candidates yangilangan, id o'zgarmagan, attempts o'zgarmagan, `foo` yo'q.
   Mavjud bo'lmagan id → `RowNotFound`.
7. `test_attempt_limit_flow` — max=3, har safar turli answer (T1001, T1002, ...):
   1-urinish (`used==0`) → ok; 2-urinish (`used==1`) → ok, `remaining==2`;
   3-urinish (`used==2`) → `last_attempt True` → `AttemptNeedsConfirm`, qator
   o'zgarmagan (len==2), warning da `"2/3"`; `force=True` bilan o'tadi (len==3);
   4-urinish (`used==3`) → `over_limit True`, `last_attempt False`,
   `AttemptNeedsConfirm`, warning da `"3/3"`, `remaining == 0`.
8. `test_duplicate_case_insensitive` — `T1566.001` topshirilgan, keyin `" t1566.001 "`
   → `duplicate True`, `duplicate_of['answer'] == 'T1566.001'`, warning da `rejected`
   yoki mos natija; boshqa savolda xuddi shu ID dublikat EMAS.
9. `test_already_accepted` — accepted urinishdan keyin yangi urinish → `already_accepted`.
10. `test_no_limit` — `max_attempts=None`: 5 ta turli urinish `force` siz o'tadi,
    `remaining is None`.
11. `test_set_and_delete_attempt` — pending → accepted; noto'g'ri result → `TrackerError`;
    indeks 5 va -1 → `RowNotFound`; o'chirgandan keyin `used` kamayadi.
12. `test_public_row` — `used/remaining/solved/exhausted` to'g'ri; `save` qilingan
    faylda bu hisoblangan kalitlar YO'Q.
13. `test_timestamp_utc` — `now=datetime(2026,10,5,8,51,2,tzinfo=timezone.utc)` →
    `at == "2026-10-05T08:51:02Z"`.
14. `test_atomic_save_unicode` — `"Savol: o'g'irlangan ma'lumot — qayerga?"` saqlanib,
    fayl baytlarida UTF-8 (ensure_ascii=False) holda qaytadan o'qiladi.
15. `test_cli_submit_with_question` — `subprocess` bilan
    `[sys.executable, 'bk.py', 'answers', 'submit', 'T1566.001', 'rejected', '--question', 'Q1', '--max', '2', '--tracker', <tmp>/t.json, '--ledger', <tmp>/a.json]`
    (cwd = loyiha ildizi) → exit 0, tracker da 1 urinish, ledger da 1 yozuv; ikkinchi
    marta xuddi shu ID → exit 2, tracker da hali 1 urinish, ledger da hali 1 yozuv;
    `--force` bilan → exit 0, 2 urinish. `--question` siz eski chaqiruv → exit 0 va
    tracker fayli YARATILMAYDI.

### `tests/test_web.py` ga yangi metodlar (mavjudlariga tegmang)
`_put` yordamchisini qo'shing (`method='PUT'`). HTTP xato kodlarini
`urllib.error.HTTPError` orqali tekshiring (`e.code`, `json.loads(e.read())`).
1. `test_tracker_attempts_api` — `max_attempts: 2` bilan qator; `POST .../attempts`
   `{answer: "T1566.001", result: "rejected"}` → 200, `row.used == 1`; xuddi shu
   answer → **409**, `needs_confirm True`, `check.duplicate True`; `force: true` → 200;
   `GET /api/tracker` dagi shu qator `used == 2`, `exhausted True`;
   `PUT .../attempts/0 {result: "accepted"}` → 200, `solved True`;
   `DELETE .../attempts/1` → 200, `used == 1`; `POST .../check {answer: "T1204.002"}`
   → 200 va `used` o'zgarmagan.
2. `test_tracker_put_and_errors` — bo'sh candidates bilan qator yaratish 200;
   `PUT {candidates: "T1204.002", evidence: "e", status: "s", id: "hack"}` → qator id
   o'zgarmagan, maydonlar yangilangan; `PUT /api/tracker/yoqid` → 404;
   `POST /api/tracker {question: ""}` → 400; `PUT {max_attempts: "abc"}` → 400;
   `POST /api/tracker/yoqid/attempts` → 404.
3. `test_tracker_ledger_link` — T-ID urinishidan keyin `workdir/answers.json` da shu
   ID li yozuv, `note` = savol matni; IP (`198.51.100.45`) urinishidan keyin ledger
   ga yangi yozuv QO'SHILMAYDI.
Testlar oxirida o'zlari yaratgan qatorlarni o'chirsin.

## 5. Qabul mezonlari

- `python -m unittest discover -s tests` — HAMMASI yashil (hozir ~190+ test), yangi
  testlar `skip` bo'lmasin (KB kerak bo'lgan `test_web.py` bundan mustasno — u KB
  qurilgan bo'lsa ishlaydi, hozir qurilgan).
- `python bk.py answers submit T1003 pending --ledger <tmp>` (eski shakl) ishlaydi.
- `python bk.py ir chain --help` va `python bk.py logs analyze --help` ishlaydi
  (scoping tuzog'i tekshiruvi).
- `server.py` va `bk.py` qator soni faqat oshgan; `run_server`, `do_PUT`, `do_DELETE`,
  `_load_resp_args`, `/api/report` joyida.
- Hisobotda: har bir faylning oldin/keyin qator soni.
