# SPEC_HUNT_WEB — `hunt beacons` ni asosiy web UI ga qo'shish

Loyiha: `D:\Claude Projects\CTF\blue-kit-staging`

CLI da `bk hunt beacons` allaqachon ishlaydi (`bluekit/hunt/beacons.py`). Endi xuddi shu
funksiya offline web UI da ham bo'lishi kerak — hozir UI da KB / Logs / IR / Responder /
Tracker / Report tablari bor, C2 Hunt yo'q.

**Muhim:** `bluekit/hunt/beacons.py` dagi `hunt_beacons()` ni QAYTA YOZMANG va logikasini
takrorlamang — faqat chaqiring. `bk.py`, `bluekit/ir/correlator.py`, `bluekit/logs/qradar.py`
fayllariga TEGMANG (ular boshqa ish ostida).

## 1. Umumiy agregatsiya funksiyasi (yangi, `bluekit/hunt/beacons.py` ichida)

Hozir `render_table()` natijalarni `dst_ip` bo'yicha o'zi guruhlaydi (239–281-qatorlar).
Web UI ham aynan shu agregatsiyani talab qiladi — ikkinchi nusxa yozilmasligi uchun shuni
ajratib oling:

```python
def group_by_dst(results: List[Dict], all_results: bool = False) -> List[Dict]:
    """dst_ip bo'yicha jamlangan nomzodlar ro'yxati (CLI jadvali va web UI uchun umumiy)."""
```

Har element:
```python
{
  'dst_ip': '46.30.190.150',
  'dst_port': '80',              # eng ko'p uchragan portlar, ","
  'score': 90,                   # 999 bo'lsa CLI da "-" deb chiqadi
  'level': "YUQORI",             # YUQORI / O'RTA / PAST / MA'LUM
  'dst_host_count': 5,
  'sessions': 1793,              # barcha ichki hostlar bo'yicha yig'indi
  'median_interval': 30.0,
  'cv_ratio': 0.10,
  'avg_sent': 7100.0,
  'max_duration': 15983.0,
  'first_seen': '09-20 20:46',
  'reasons': ["Davriylik", ...], # eng yuqori ballli nomzodniki
  'hosts': [                     # sessiya bo'yicha kamayish tartibida, maksimal 10 ta
     {'src_ip': '192.168.19.224', 'host': 'asultonov.digital.local', 'sessions': 940},
     ...
  ]
}
```
`all_results=False` bo'lsa faqat `YUQORI` / `O'RTA` / `MA'LUM` darajalilar qaytadi.

`render_table()` shundan keyin faqat shu funksiya natijasini chop etsin — chiqish matni
**hozirgidek bir xil** qolishi shart (ustunlar, `->` bilan host ro'yxati, oxiridagi
"N ta nomzod tekshirildi...", "Vaqtlar UTC da...", "CV = ..." qatorlari).

## 2. API: `POST /api/hunt/beacons` (`bluekit/web/server.py`)

`handle_api_post` ichiga `elif path == '/api/hunt/beacons':` qo'shing. Fayl qabul qilish
mantig'i `'/api/ir/chain'` (215–265-qatorlar) bilan **bir xil** bo'lsin:
`data['files']` ro'yxati (`{filename, content}` yoki `{path}`), yoki bitta
`{filename, content}`, yoki `{path}`. Nisbiy yo'l `os.getcwd()` va `self.server.workdir`
bo'yicha qidiriladi. Papka berilsa — ichidagi barcha fayllar (CLI dagidek `os.walk`).

So'rov maydonlari (hammasi ixtiyoriy, defaultlari CLI bilan bir xil):
`min_sessions` (10), `max_hosts` (100), `all` (false), `iocs` (IP/domen ro'yxati yoki
qator-qator matn), `allowlist` (fayl yo'li; berilmasa
`bluekit.paths.get_resource_path('bluekit/hunt/allowlist.yaml')`).

Javob:
```json
{
  "candidates": [ ...group_by_dst natijasi... ],
  "summary": {"checked": 1, "high_medium": 1, "total_groups": 4, "tz_note": "Vaqtlar UTC da. Mahalliy vaqt uchun +5 soat qo'shing."}
}
```
Xato bo'lsa mavjud `end_error` / `try-except` uslubida (`do_POST` allaqachon 500 ni ushlaydi).

## 3. UI: yangi tab (`bluekit/web/static/index.html` + `app.js` + `style.css`)

- `index.html:35` dagi IR tugmasidan keyin: `<button class="tab-btn" onclick="showTab('hunt')">🛰 C2 Hunt</button>`
- `<div id="ir" class="tab-content">` blokidan keyin `<div id="hunt" class="tab-content">`.
  Tuzilishi IR tabidan ko'chirilsin (hud-ribbon + card-hud + dropzone + file/path input +
  tugma), lekin matnlar hunt uchun: "Noma'lum C2 nomzodlarini xulq-atvor bo'yicha saralash".
- Qo'shimcha inputlar: `hunt-min-sessions` (number, 10), `hunt-max-hosts` (number, 100),
  `hunt-all` (checkbox: "PAST darajalarni ham ko'rsatish"), `hunt-ioc` (textarea:
  "Ma'lum IOC lar, har qatorda bittadan").
- `app.js` da: `runHuntBeacons()`, `renderHuntResults(data)`, `huntClearFiles()` va
  drag-and-drop — `runIRChainAnalysis` / `irClearFiles` naqshini takrorlang
  (spinner, toast, xato kartasi, `btn.disabled`).
- Jadval ustunlari: `Ball | Daraja | Dst IP | Port | Host | Sessiya | Median | CV |
  O'rt.bayt | Maks davom | Birinchi (UTC)`. Har qator ostida (yoki ochiladigan qismda)
  ichki hostlar: `192.168.19.224 (asultonov.digital.local) — 940 sessiya`,
  sessiyasi 0 bo'lsa `(ESET, sessiya yo'q)`.
- Daraja ranglari mavjud CSS o'zgaruvchilari bilan: YUQORI → `var(--crimson)`,
  O'RTA → `var(--amber)`, MA'LUM → `var(--neon-cyan)`, PAST → `var(--text-muted)`.
- Jadval ostida ikki izoh qatori: "Vaqtlar UTC da. Mahalliy vaqt uchun +5 soat qo'shing."
  va "CV = intervallar stdev/median nisbati: qancha kichik bo'lsa, davriylik shuncha aniq."
- "📥 JSON yuklab olish" tugmasi — mavjud `downloadFile`/`copyToClipboard` yordamchilaridan
  foydalaning, yangi yozmang.
- Bayt/davomiylik formatlari CLI dagidek: `7.1 KB`, `4.4 soat`, `30s`.

## 4. Test (`tests/test_hunt.py`, yangi fayl)

`tests/test_web.py` naqshi bo'yicha `unittest` + lokal `WebKitServer`:
1. Kichik sun'iy QRadar/FortiGate CSV yarating (bitta ichki host → bitta tashqi IP,
   ~40 ta sessiya, 30s intervalda, `sessionid` va `duration` maydonlari bilan).
2. `POST /api/hunt/beacons` → 200, `candidates` bo'sh emas, birinchi nomzodning
   `dst_ip` to'g'ri, `level` `YUQORI` yoki `O'RTA`, `hosts` ro'yxati bo'sh emas.
3. `min_sessions` ni 1000 qilib yuborilganda nomzod chiqmasligini tekshiring.
4. `group_by_dst` ning o'zi uchun bitta to'g'ridan-to'g'ri test.

## 5. Qabul mezonlari (o'zingiz yugurtirib tekshiring)

```
python -m unittest discover -s tests -p "test_*.py" -q        # hammasi OK (hozir 30 ta test)
python bk.py hunt beacons "D:\Claude Projects\CTF\dest.csv"   # chiqish AYNAN hozirgidek
python bk.py ir chain "D:\Claude Projects\CTF\elasticsearch_export.json"   # 22 qadam
```
`bk hunt beacons` chiqishi hozir quyidagicha (bitta belgi ham o'zgarmasin):
```
  90 | YUQORI | 46.30.190.150   | 80       | 5    | 1793    | 30s    | 0.10  | 7.1 KB    | 4.4 soat   | 09-20 20:46
       -> 192.168.19.224 (asultonov.digital.local) (940 sessiya)
```

Ishni O'ZING bajar, subagentga topshirma. Stub qoldirma, "TODO" yozma.
