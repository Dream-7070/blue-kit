# SPEC_SIEM_WEB — `bk siem` ni web UI ga qo'shish

Loyiha: `D:\Claude Projects\CTF\blue-kit-staging`

CLI da `bk siem` allaqachon to'liq ishlaydi (`bluekit/siem/`, 12 SIEM × 32 hunt,
`tests/test_siem.py` da 32 ta test). Endi xuddi shu narsa offline web UI da ham
bo'lishi kerak: analitik SIEM turini va nima qidirishni **dropdown dan tanlaydi**,
tayyor so'rovni "Nusxalash" bilan oladi va SIEM ga qo'yadi.

Hozir UI da tablar: KB / Logs / IR / C2 Hunt / Responder / Tracker / Report.
SIEM tabi yo'q.

## 0. Asosiy qoidalar

**Mantiqni takrorlamang.** `bluekit/siem/builder.py` dagi `build_query`,
`list_hunts`, `list_dialects`, `get_hunt` — faqat CHAQIRILADI. Hunt lar ro'yxati,
SIEM lar ro'yxati, so'rov matni yoki ATT&CK ID lari **JS ichiga ko'chirilmasin** —
ular API dan olinadi. (Buni test tekshiradi: `app.js` va `index.html` ichida
`auth-bruteforce` degan satr BO'LMASLIGI shart.)

**TEGMANG:** `bluekit/siem/**` (faqat o'qing va chaqiring), `bk.py`,
`bluekit/hunt/**`, `bluekit/ir/**`, `bluekit/logs/**`, mavjud `tests/test_*.py`.

**O'zgartiriladigan fayllar:** `bluekit/web/server.py` (faqat qo'shimcha),
`bluekit/web/static/index.html`, `bluekit/web/static/app.js`,
`bluekit/web/static/style.css` (kerak bo'lsa). **Yangi:** `tests/test_siem_web.py`.

**DIQQAT — o'tgan safar shu yerda xato bo'lgan:** `server.py` dagi mavjud
funksiyalar va endpointlar o'chib ketmasin. Fayl hozir 499 qator va unda
`get_static_dir`, `WebKitServer`, `end_json`, `end_error`, `do_GET`,
`handle_api_get`, `do_POST`, `handle_api_post`, `do_PUT`, `do_DELETE`,
`_resolve_path`, `_collect_input_files`, `_load_resp_args`, `run_server` bor.
Faylni qayta yozmang — faqat yangi `elif` shoxlarini qo'shing.

## 1. API (`bluekit/web/server.py`)

Uchta endpoint. Fayl qabul qilish YO'Q — bu tab fayl bilan ishlamaydi.

### `GET /api/siem/dialects`

`handle_api_get` ichiga (`/api/tactics` shoxidan keyin) qo'shing. Javob —
`list_dialects()` natijasi o'zgartirilmagan holda (12 ta yozuv: `name`, `syntax`,
`language`, `bk_preset`, `where`).

### `GET /api/siem/hunts?category=&search=`

`list_hunts(category, search)` natijasi. Ikkala parametr ham ixtiyoriy, mavjud
`qs.get('q', [''])[0]` uslubida o'qiladi. Qo'shimcha ravishda javobga
`categories` (ya'ni `bluekit.siem.catalog.CATEGORIES`) ham qo'shing:

```json
{"hunts": [...], "categories": {"auth": "Kirish / autentifikatsiya", ...}}
```

### `POST /api/siem/query`

`handle_api_post` ichiga (`/api/hunt/beacons` shoxidan keyin). Kiruvchi:

```json
{"hunt_id": "auth-bruteforce", "siem": "qradar",
 "days": 7, "threshold": 20, "limit": 200,
 "host": null, "user": null, "ip": null}
```

`siem` qiymati `"all"` bo'lsa — barcha 12 dialekt uchun. Javob:

```json
{"results": [ ...build_query() natijasi... ]}
```

Bitta SIEM uchun ham `results` ro'yxat bo'lsin (JS da bitta yo'l bo'lishi uchun).
`days/threshold/limit/host/user/ip` dan `null` yoki bo'sh bo'lganlari
`build_query` ga **umuman uzatilmasin** (hunt ning o'z defaulti ishlasin).

`build_query` `ValueError` tashlasa → `self.end_error(str(e), 400)`. Boshqa
xatolarni `do_POST` allaqachon 500 bilan ushlaydi.

## 2. UI (`index.html`)

- **Tugma:** `index.html:36` dagi `🛰 C2 Hunt` tugmasidan keyin:
  `<button class="tab-btn" onclick="showTab('siem')">🔍 SIEM So'rov</button>`
- **Blok:** `<div id="hunt" class="tab-content">` yopilgandan keyin (RESPONDER
  izohidan oldin) `<div id="siem" class="tab-content">`.
- Tuzilishi C2 Hunt tabidan (`index.html:320-382`) ko'chirilsin: `section-title`,
  `card card-hud`, `card-title`, `helper-text`, `brand-badge`. Dropzone KERAK EMAS.

Sarlavha: `SIEM So'rov Generatori — SIEM turini va nima qidirishni tanlang`.

**Tanlash paneli** (bitta `card card-hud` ichida, grid bilan):

| element | id | izoh |
|---|---|---|
| SIEM select | `siem-dialect` | API dan; oxirida `<option value="all">Barcha SIEM lar</option>` |
| Kategoriya select | `siem-category` | `Hammasi` + `categories` dan; hunt ro'yxatini filtrlaydi |
| Qidiruv input | `siem-search` | yozilganda hunt ro'yxatini filtrlaydi (debounce 250ms, `triggerFilterDebounced` uslubida) |
| Hunt select | `siem-hunt` | `<optgroup label="<kategoriya nomi>">` bilan guruhlangan |
| days | `siem-days` | number, bo'sh qoldirilsa default |
| threshold | `siem-threshold` | number, bo'sh qoldirilsa default |
| limit | `siem-limit` | number |
| host / user / ip | `siem-host`, `siem-user`, `siem-ip` | ixtiyoriy matn, "qo'shimcha filtr" |
| tugma | `siem-btn` | `🔍 So'rov yaratish`, `onclick="runSiemQuery()"` |

Hunt tanlanganda uning `description` i tanlash panelining ostida `helper-text`
sifatida darhol ko'rsatilsin (so'rov yaratmasdan oldin ham).

**Natija** (`siem-result`, boshida `display:none`): har bir so'rov uchun alohida
`card card-hud`:

1. Sarlavha: `<hunt nomi> — <SIEM nomi> (<til>)`.
2. ATT&CK badge lari — har biri bosiladigan:
   `onclick="showMitreModal('T1110', event)"` (mavjud funksiya, yangi yozmang).
3. So'rov `<pre class="siem-query">` ichida, o'zgartirilmagan holda (bezaksiz,
   HTML escape qilingan — `escapeHtml` mavjud). Yonida ikkita tugma:
   - `📋 Nusxalash` → mavjud `copyText(text, event)`
   - `📥 Yuklab olish` → mavjud `downloadBlob(content, filename, mimeType)`,
     fayl nomi `<hunt_id>_<siem>.txt`
4. `Eslatmalar:` — `notes` ro'yxati `<ul>` bo'lib. `DIQQAT` so'zi bilan boshlangan
   eslatma `var(--cyber-red)` rangida bo'lsin (ular haqiqiy ogohlantirish).
5. `Sozlash:` — `tuning`.
6. `Eksport qilgandan keyin:` — `next_steps` har biri alohida qatorda, `<code>`
   ichida, yonida kichik `📋` tugmasi bilan.

Xato uchun `siem-error` kartasi — C2 Hunt dagi `hunt-error` naqshida.

Tab birinchi marta ochilganda dropdownlar API dan to'ldirilsin (`showTab` da
`if (id === 'tracker') loadTracker();` naqshi bor — shunga `siem` ni qo'shing,
lekin ikkinchi marta qayta yuklamasin).

## 3. `app.js`

Yangi funksiyalar: `loadSiemMeta()`, `renderSiemHuntOptions()`, `runSiemQuery()`,
`renderSiemResults(results)`. Spinner, `btn.disabled`, toast va xato kartasi —
`runHuntBeacons()` (1727-qator) naqshini takrorlang. Tarmoq chaqiruvi mavjud
`api(path, method, body)` orqali.

Global holat: `let siemMeta = null;` va `let lastSiemResults = null;` (mavjud
`lastHuntData` uslubida).

## 4. `style.css`

Kerak bo'lsa faqat `.siem-query` uchun: `white-space: pre; overflow-x: auto;
font-family` mavjud monospace o'zgaruvchisi, fon `var(--bg-panel)` yoki shunga
o'xshash **mavjud** o'zgaruvchilar. Yangi rang o'zgaruvchisi kiritmang.

## 5. Testlar (`tests/test_siem_web.py`, YANGI fayl)

`tests/test_web.py` dagi `setUpClass` naqshi (lokal `WebKitServer`, `_get`,
`_post`). Mavjud test fayllariga tegmang.

1. `GET /api/siem/dialects` → 200, 12 ta yozuv, `qradar` bor, uning
   `bk_preset` i `qradar`.
2. `GET /api/siem/hunts` → 200, 32 ta hunt, `categories` da 8 ta kategoriya.
3. `GET /api/siem/hunts?category=auth` → faqat auth (9 ta), `web-attack-patterns` yo'q.
4. `GET /api/siem/hunts?search=T1110` → natijada `auth-bruteforce` bor.
5. `POST /api/siem/query` `{hunt_id: auth-bruteforce, siem: qradar}` → 200,
   `results` uzunligi 1, `results[0]['query']` ichida `4625` va `LAST 7 DAYS` bor.
6. `POST` da `{days: 30}` → so'rovda `LAST 30 DAYS`.
7. `POST` da `{siem: "all"}` → `results` uzunligi 12.
8. `POST` da noma'lum `hunt_id` → 400 (`urllib.error.HTTPError` ni ushlang).
9. `POST` da bo'sh `days`/`threshold` (`null`) yuborilganda hunt defaulti
   ishlaydi (`LAST 7 DAYS`, `>= 20`).
10. **Katalog JS ga ko'chirilmaganini tekshirish:** `index.html` va `app.js`
    fayllarini o'qib, ularda `auth-bruteforce` va `T1110` satrlari YO'Qligini
    tasdiqlang.
11. **Regressiya — server.py butunligi:** `bluekit/web/server.py` manbasini o'qib,
    quyidagilarning hammasi hali ham borligini tasdiqlang:
    `def run_server`, `def do_PUT`, `def do_DELETE`, `def _load_resp_args`,
    `def _collect_input_files`, va endpointlar: `/api/logs/analyze`,
    `/api/resp/triage`, `/api/resp/fix`, `/api/resp/sla`, `/api/resp/doctor`,
    `/api/resp/fraud`, `/api/ir/chain`, `/api/hunt/beacons`, `/api/tracker`,
    `/api/report`, `/api/info`, `/api/validate`, `/api/search`, `/api/id`,
    `/api/related`, `/api/ioc`, `/api/tactics`.

## 6. Qabul mezonlari — O'ZINGIZ yugurtiring

```
python -m unittest discover -s tests -p "test_*.py" -q
```

Hozir **65 ta test** bor va hammasi yashil — siz qo'shgandan keyin ham 65 tasi
yashil qolishi, ustiga yangilari qo'shilishi kerak. Bitta ham eski test yiqilmasin.

```
python bk.py siem query auth-bruteforce --siem qradar
python bk.py ir chain "D:\Claude Projects\CTF\elasticsearch_export.json"
python bk.py hunt beacons "D:\Claude Projects\CTF\dest.csv"
```

Uchalasi ham hozirgidek ishlashi shart (siz ularga tegmaysiz, lekin `server.py` ni
buzsangiz test yiqiladi).

Web ni qo'lda ham tekshiring: `python bk.py web` → brauzerda SIEM tabini oching,
QRadar + `auth-bruteforce` tanlang, so'rov chiqishini va "Nusxalash" ishlashini
ko'ring, keyin "Barcha SIEM lar" bilan 12 ta blok chiqishini tasdiqlang.

Hisobotda quyidagilarni **ko'chirib** keltiring:
- `unittest` chiqishining oxirgi 3 qatori
- `git diff --stat` yoki o'zgargan har bir faylning eski/yangi qator soni
- `POST /api/siem/query` javobining `results[0]['query']` qiymati

Stub, `TODO`, bo'sh test qoldirmang. Biror talabni bajara olmasangiz — hisobotda
ochiq yozing, "hammasi tayyor" deb yozib ichida placeholder qoldirmang.
