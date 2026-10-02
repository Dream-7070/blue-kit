# SPEC_IR_FALLBACK — `ir chain` da qo'lda yozilgan qoidalar topmagan hodisalar uchun KB heuristikalari

Loyiha: `D:\Claude Projects\CTF\blue-kit-staging`

## Muammo (o'lchangan)

`bluekit/ir/correlator.py::correlate_incident` faqat qo'lda yozilgan qoidalarga tayanadi:
`event.dataset` ichida `nginx/apache/web`, `auditd/process/exec`, `suricata/eve`,
`auth/sshd`, `qradar` bo'lsa va `url.path`, HTTP status, `process.command_line` kabi
tuzilmali maydonlar bo'lsa. Natija:

| Kirish | Hozirgi natija |
|---|---|
| `windows.security` + `powershell -enc SQBFAFgA...` | **0 qadam** (Windows uchun hujum qoidasi umuman yo'q) |
| xom nginx/firewall/pochta qatorlari (dataset yo'q) | **0 qadam** |
| ECS nginx (`dataset=nginx.access`, `url.path`) | 2 qadam (`T1190`, `T1505.003`) — bu ishlaydi |

Bir vaqtning o'zida `bk logs analyze` (KB heuristikalari, `bluekit/logs/detect.py::detect_event`)
shu hodisalarning hammasida hujumni topadi. Maqsad: `ir chain` ham qo'lda qoidalar
**topmagan** hodisalarni `detect_event` orqali tekshirib, ularni qo'shimcha bosqich
sifatida zanjirga qo'shsin. Mavjud qoidalar va ularning natijasi **o'zgarmaydi**.

## 0. Qoidalar

**Mavjud xulq buzilmaydi:** `correlate_incident` ning hozirgi bosqichlari (qo'lda qoidalar)
aynan avvalgidek chiqadi; fallback faqat **qo'shimcha** bosqichlar qo'shadi.
Mavjud testlar (`tests/test_ir.py` dagi `len(chain.stages) == 4` va `>= 10` ni ham
qo'shib) **o'zgartirilmasdan** o'tishi shart. Agar fallback ularni buzsa — testni
o'zgartirmang, sababini hisobotda yozing va fallbackni toraytiring.

**TEGMANG:** `bk.py`, `bluekit/web/**`, `bluekit/logs/**`, `bluekit/kb/**`,
`bluekit/siem/**`, `bluekit/resp/**`, `bluekit/ir/report.py`, `bluekit/ir/explain.py`,
`bluekit/ir/models.py`, mavjud `tests/test_*.py`.

**O'zgartiriladigan:** `bluekit/ir/correlator.py` (faqat kichik qo'shimchalar, qayta
yozmang — u 880 qator). **Yangi:** `bluekit/ir/fallback.py`, `tests/test_ir_fallback.py`.

UTF-8, satr oxiri (LF/CRLF) va mavjud Unicode belgilar o'zgarmasin. Stub/placeholder/
`pass`/TODO yo'q. Faqat stdlib + mavjud kutubxonalar.

## 1. `correlator.py` — kichik o'zgarishlar

### 1.1 `get_nested` — yassi kalit

`get_nested(d, path)` avval `path` ni **yassi kalit** sifatida tekshirsin:
`if isinstance(d, dict) and path in d: return d[path]`, keyin mavjud ichma-ich yurish.
Sabab: `bluekit/logs/parse.py::load_rows` xom qatorlarga `source.ip`, `dst`, `host`,
`timestamp` kabi YASSI kalitlar yozadi va `extract_canonical` `get_nested(evt,'source.ip')`
ni topa olmayapti.

### 1.2 Qayta ishlangan hodisalarni belgilash

"Detailed event evaluation" sikli (`for evt in raw_events:` — `# Detailed event
evaluation` izohidan keyin) `for _i, evt in enumerate(raw_events):` ga aylansin.
`handled_idx = set()` sikldan oldin yaratiladi. Sikl tanasida:
- `is_benign_noise(c)` true bo'lib `continue` qilinsa — `handled_idx.add(_i)` avval;
- tananing oxirida (barcha qoidalardan keyin) `len(stages)` sikl boshidagidan katta
  bo'lsa `handled_idx.add(_i)`. Buning uchun sikl boshida `_n0 = len(stages)`.
Siklning boshqa hech narsasi o'zgarmaydi.

### 1.3 Fallbackni chaqirish

`# Sort stages strictly by timestamp` qatoridan **oldin**:

```python
if heuristic_fallback:
    from bluekit.ir.fallback import fallback_stages
    fb = fallback_stages(raw_events, handled_idx, kb, stages)
    stages.extend(fb['stages'])
    hosts_involved.update(fb['hosts'])
    attacker_ips.update(fb['attacker_ips'])
    compromised_users.update(fb['users'])
```

Imzo: `correlate_incident(raw_events, kb=None, heuristic_fallback=True)` — yangi
kalit-argument **oxirida**, default `True`. `kb is None` bo'lsa fallbackdan oldin
mavjud kodning KB yaratish bloki (`if kb is None: ... KB()`) hozir fallbackdan KEYIN
turibdi; uni fallbackdan **oldinga** ko'chiring (faqat joyini, mantiqini emas), aks
holda `kb=None` da fallback ishlamaydi.

`is_benign_noise` va `qradar` hodisalari: `dataset == 'qradar'` hodisalari fallbackga
kirmaydi (ular oldindan skanerlanadi) — buni `fallback_stages` o'zi tekshiradi.

## 2. `bluekit/ir/fallback.py` — yangi modul

```python
def fallback_stages(raw_events, handled_idx, kb, existing_stages) -> dict:
    """{'stages': [AttackStage], 'hosts': set, 'attacker_ips': set, 'users': set}"""
```

Har `i, evt in enumerate(raw_events)` uchun (`i in handled_idx` bo'lsa o'tkazing):

1. `c = extract_canonical(evt)` (`bluekit.ir.correlator` dan import qiling — funksiya ichida,
   sirkulyar import bo'lmasin). `c['dataset'].lower() == 'qradar'` bo'lsa o'tkazing.
2. Ilgari `T1595.002` skaner bosqichi hosil qilgan IP lardan kelgan 403/404 hodisalarni
   o'tkazing: `existing_stages` da `technique_id == 'T1595.002'` bo'lgan bosqichlarning
   `iocs['src_ip']` to'plami `probe_ips`; `c['src_ip'] in probe_ips and c['status_code'] in (403, 404)` -> o'tkazing.
3. `detect_event` uchun hodisa lug'ati yasang (`bluekit.logs.detect.detect_event`):
   ```python
   ev = {'channel': <a>, 'event_id': <b>, 'command_line': c['cmd'] or None, 'message': <m>}
   ```
   - `<a>` = birinchi bo'sh bo'lmagan: `get_nested(raw,'winlog.channel')`, `raw.get('Channel')`,
     `raw.get('channel')`, `c['dataset']` (eventmap kanal nomlari `Security`, `Sysmon`, `auth`,
     `PowerShell`, `System` — `detect_event` ularni **substring** bilan solishtiradi, shuning uchun
     `windows.security` -> `Security` mos keladi); bo'lmasa `None`.
   - `<b>` = birinchi bo'sh bo'lmagan: `get_nested(raw,'event.code')`, `raw.get('EventID')`,
     `raw.get('event_id')`, `get_nested(raw,'winlog.event_id')`; bo'lmasa `None`.
   - `<m>` = `c['message']` va (agar `c['url_path']` bor bo'lsa)
     `f"{c['method']} {c['url_path']}" + (f"?{c['url_query']}" if c['url_query'] else "")`
     larning bo'sh bo'lmaganlarini bitta bo'shliq bilan birlashtirilgani; `None` emas, bo'sh satr bo'lishi mumkin.
   `ev['command_line']` ham, `ev['message']` ham bo'sh bo'lsa hodisani o'tkazing.
4. `hits = detect_event(kb, ev)` (`deep=False`). Faqat `confidence in ('high','medium')` bo'lgan
   hitlarni oling (`low` — `noise.yaml` downgrade — tashlanadi).
5. Har hit uchun kalit `(c['host'], hit['technique'])`. Kalit `existing_stages` dagi bosqich
   `(host, technique_id)` juftligi bilan yoki oldin shu funksiya qo'shgan bosqich bilan
   mos kelsa: yangi bosqich **qo'shilmaydi**, faqat mavjud fallback bosqichning hisoblagichi
   oshadi (pastga qarang). Aks holda yangi `AttackStage`:
   - `stage_id`: vaqtinchalik `"F00"` (correlator qayta raqamlaydi);
   - `timestamp = c['timestamp']` (str);
   - `host = c['host']`;
   - `phase` = KB dan texnikaning **birinchi taktikasi** (`kb.lookup(tid)[0]['tactics'][0]`)
     shortname ni Title Case ga: `initial-access` -> `Initial Access`, `stealth` -> `Stealth`
     (`-` ni bo'shliqqa, har so'z bosh harf). KB da topilmasa `"Unknown"`;
   - `technique_id = hit['technique']`, `technique_name = hit['name']`;
   - `confidence = "MEDIUM"`, `status = "SUSPECTED"`;
   - `evidence` = hodisa matnining birinchi 200 belgisi (`ev['command_line'] or ev['message']`);
   - `iocs = {'src_ip': c['src_ip'], 'user': c['user'], 'count': 1, 'first_seen': ts, 'last_seen': ts, 'rule_source': hit['source']}`
     (bo'sh qiymatli kalitlarni **tushirib qoldiring**);
   - `source_dataset = c['dataset'] or 'text'`;
   - `raw_event_id = str(get_nested(raw,'event.id') or raw.get('_id') or '')`.
6. Takrorlanish: shu `(host, technique)` kalitiga keyingi hodisada `iocs['count'] += 1`,
   `iocs['last_seen'] = ts` yangilanadi; `count > 1` bo'lsa `evidence` oxiriga
   `f" (x{count})"` qo'shiladi (avvalgisini qayta yozing, ketma-ket "(x2) (x3)" bo'lmasin).
   Bosqich soni shu tariqa `(host × texnika)` bilan chegaralanadi.
7. Yig'iladigan to'plamlar:
   - `hosts` — bosqich hosti bo'sh bo'lmasa;
   - `attacker_ips` — `c['src_ip']` **ommaviy** IP bo'lsa (`ipaddress.ip_address(x).is_global`;
     xato bo'lsa tashlang) va hit yangi bosqich yoki takror bo'lishidan qat'i nazar;
   - `users` — `c['user']` bo'sh emas va `SYSTEM/AUTHORITY/ANONYMOUS/ESET` (katta-kichik harfsiz)
     so'zlarini o'z ichiga olmasa.

`extract_canonical` maydonlar mavjud emasligida `KeyError` bermasligi kerak (u lug'at
qaytaradi — bo'sh satrlar). `kb is None` bo'lsa `{'stages': [], ...}` qaytaring.
Butun funksiya bitta buzuq hodisada yiqilmasin: har hodisa `try/except Exception` ichida
(hodisani o'tkazib yuboring).

## 3. Testlar — `tests/test_ir_fallback.py` (`unittest`)

`KB` ni `tests/test_ir.py` qanday yaratsa shunday yarating (o'sha faylni o'qing).

Haqiqiy kirishlar (har biri `correlate_incident(events, kb)`):
1. Windows: `{'@timestamp':'2026-10-05T09:01:10Z','event':{'dataset':'windows.security','code':4688},'host':{'name':'hr-pc-01'},'user':{'name':'hr.anna'},'process':{'name':'powershell.exe','command_line':'powershell -enc SQBFAFgA...'}}`
   -> kamida 1 bosqich, `T1059.001` bor, `host=='hr-pc-01'`, `status=='SUSPECTED'`, `'hr.anna'` `compromised_users` da.
   (Oldin `git stash` mantiqida emas — shu testning o'zi `heuristic_fallback=False` bilan **0 bosqich**ni ham tasdiqlasin.)
2. Xom nginx qatori `load_events_from_files([tmp .log fayl])` orqali (haqiqiy fayl yarating):
   `198.51.100.45 - - [05/Oct/2026:09:10:40 +0000] "GET /uploads/shell.php?cmd=whoami HTTP/1.1" 200 20 "-" "curl/7.68"` ->
   `T1505.003` yoki `T1033` (heuristika qaysini bersa, `bluekit.logs.detect` ni shu qator bilan
   to'g'ridan-to'g'ri chaqirib **avval qaysi texnika chiqishini o'zingiz aniqlang** va testda o'sha ID ni kuting — taxmin qilmang);
   `198.51.100.45` `attacker_ips` da (`get_nested` yassi-kalit tuzatishi shuni ta'minlaydi).
3. Dedup: 5 ta bir xil hodisa (bir host, bir texnika, turli ts) -> aynan 1 bosqich, `iocs['count']==5`,
   `evidence` `" (x5)"` bilan tugaydi (bitta marta).
4. Qo'lda qoida ustuvorligi: ECS nginx UNION SELECT hodisasi (`dataset='nginx.access'`) — natija
   `heuristic_fallback=True` va `False` da **bir xil** `T1190` bosqichini beradi (fallback uni
   ikkinchi marta qo'shmaydi: `(host, T1190)` allaqachon bor).
5. Regressiya: `heuristic_fallback=False` da chiqish hozirgi bilan aynan bir xil — buning uchun
   `tests/test_ir.py` dagi mock hodisalarni (`len(chain.stages)==4`) o'sha faylning o'zidan
   nusxalab, ikkala rejimda ham 4 ekanini tasdiqlang; agar `True` rejimda 4 dan ko'p chiqsa,
   sababini aniqlang (qaysi hodisa/texnika) va hisobotga yozing.
6. `heuristic_fallback=True` da `kb=None` — yiqilmaydi.
7. Teskari tartib: bir xil hodisalarni `reversed` bering — bosqichlar soni va texnikalar
   to'plami bir xil.
8. `get_nested({'source.ip':'1.2.3.4'}, 'source.ip') == '1.2.3.4'` va ichma-ich shakl ham ishlaydi.

Dummy/hardcode bilan o'tadigan test yozmang.

## 4. Tugagach

`python -m unittest discover -s tests` — hammasi (217+) yashil. Hisobotda o'zgargan
fayllar, qator sonlari va test_ir.py bilan bog'liq kuzatuvlarni yozing.
