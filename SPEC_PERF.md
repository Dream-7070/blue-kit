# SPEC_PERF — `logs analyze` ni katta eksportlar uchun tezlashtirish

Loyiha: `D:\Claude Projects\CTF\blue-kit-staging`

## Muammo (o'lchangan)

`bk logs analyze` hodisaga **~12 ms** sarflaydi. Musobaqada eksport 15 000 emas,
100 000+ qator bo'lishi mumkin:

| Hodisa | Hozirgi vaqt |
|---|---|
| 15 000 | 3 daq 15 s |
| 100 000 | ~20 daqiqa |
| 500 000 | ~1 soat 40 daqiqa |

`cProfile` (500 hodisa, jami 7.7 s):

```
7.109 s  bluekit/kb/query.py:65(search)        <- 92%
4.481 s  sqlite3.Cursor.fetchall (1039 chaqiruv)
1.081 s  sqlite3.Cursor.execute (11041 chaqiruv)
0.218 s  re.search (60000 chaqiruv)            <- atigi 3%
```

Ya'ni regexlar arzon, **butun vaqt SQLite ga ketyapti**. Ikki sabab:

1. `query.py:102` — `SELECT ... FROM heuristics` **har bir `search()` chaqiruvida**
   qayta o'qiladi (120 qator × har hodisa uchun), regexlar har safar qayta
   kompilyatsiya qilinadi.
2. `query.py:75` — FTS5 `MATCH` so'rovi log qatoridagi **hamma so'zni `OR`** qilib
   yuboradi (`"198" OR "51" OR "100" OR "45" OR "GET" OR ...`), bu 7261 qatorli
   indeksdan ulkan natija qaytaradi. **Ammo `detect.py` bu natijani `deep`
   bo'lmasa butunlay tashlab yuboradi** (`if is_heuristic:` shoxi) — ya'ni ish
   behuda bajariladi.

**Prototip o'lchovi (2000 hodisa):** heuristikalarni bir marta o'qib kompilyatsiya
qilish + FTS ni o'tkazib yuborish → **15.81 s dan 0.31 s ga, 50x tezlanish,
natija aynan bir xil** (ikkalasida ham 15 ta heuristika-hit).

## 0. Asosiy qoidalar

**MAVJUD `search()` METODIGA TEGMANG.** Uni web UI (`/api/search`), `bk kb search`,
`bluekit/resp/triage.py` va `bluekit/logs/detect.py` ning `--deep` yo'li
ishlatadi. Uning imzosi, xulqi va qaytaradigan strukturasi **o'zgarmaydi**.
Yangi metod qo'shiladi, eskisi joyida qoladi.

**TEGMANG:** `bluekit/resp/**`, `bluekit/siem/**`, `bluekit/ir/**`,
`bluekit/web/**`, `bk.py`, `bluekit/kb/build.py`, mavjud `tests/test_*.py`.

**O'zgartiriladigan:** `bluekit/kb/query.py` (faqat qo'shimcha),
`bluekit/logs/detect.py` (bitta shox). **Yangi:** `tests/test_perf.py`.

Fayllar faqat o'sadi. `query.py` hozir 300+ qator — qayta yozish TAQIQLANADI.

## 1. `bluekit/kb/query.py` — yangi kesh va metod

### 1.1 Lazy kesh

`KB.__init__` ga uchta bo'sh kesh maydoni qo'shing (SQL ishlatmang, faqat `None`):

```python
self._heur_compiled = None    # [(compiled_regex, [tech_id,...], name, weight), ...]
self._tech_status = None      # {attack_id: (revoked, deprecated, revoked_by)}
self._active_techs = None     # {attack_id, ...} revoked=0 va deprecated=0
```

KB ishga tushganda emas, **birinchi kerak bo'lganda** to'ldiriladi (lazy),
chunki `bk kb info` kabi buyruqlar uchun bu ortiqcha.

Kompilyatsiya qilib bo'lmaydigan regex (`re.error`) **jimgina tashlab ketiladi**
— bugungi `try/except` xulqi shunday, saqlang.

### 1.2 `search_heuristics(self, text)`

Yangi metod. Faqat heuristika qoidalarini ishlatadi, **FTS5 ga umuman
murojaat qilmaydi**.

Qaytaradi: `search()` bilan **bir xil shakldagi** ro'yxat, ya'ni har element:

```python
{
    'attack_id': 'T1041',
    'name': 'Exfiltration Over C2 Channel',
    'domain': 'enterprise',
    'score': <float>,
    'confidence': 'high',
    'sources': {'technique': 0, 'sigma': 0, 'atomic': 0, 'heuristic': <n>},
    'evidence': [<qoida nomlari>, ...]
}
```

Ballash **bugungi bilan bir xil bo'lishi shart**: `3000.0 + 1000.0 * weight`
(query.py:121). Revoked/deprecated bilan ishlash ham bugungidek:
- `revoked` va `revoked_by` bor → `revoked_by` ga almashtiriladi;
- `revoked` yoki `deprecated`, almashtiruv yo'q → **o'tkazib yuboriladi**;
- texnika har bir domeni uchun alohida yozuv (bugungi `drows` sikli shunday).

`name` va `confidence` qanday hisoblanishini `search()` ning oxiridagi
(query.py:140-160) koddan **o'qib oling va aynan takrorlang** — taxmin qilmang.

Natija `score` bo'yicha kamayish tartibida qaytariladi.

### 1.3 Nima QILMAYDI

`search_heuristics` `cooc`, `search_idx`, `sigma_rules`, `atomic_tests`
jadvallariga tegmaydi.

## 2. `bluekit/logs/detect.py` — bitta shox

Hozir (detect.py:84):

```python
if text_to_search:
    res = kb.search(text_to_search)
```

Bo'lsin:

```python
if text_to_search:
    res = kb.search(text_to_search) if deep else kb.search_heuristics(text_to_search)
```

Qolgan mantiq (`is_heuristic` tekshiruvi, `blob_candidates`, evidence matni)
**o'zgarmaydi**. `--deep` yo'li bugungidek ishlashda davom etadi.

## 3. Testlar — `tests/test_perf.py`

### 3.1 Bir xillik testi (eng muhim)

Kamida **20 ta** turli matn ustida (Windows buyruq qatorlari, nginx log
qatorlari, Linux buyruqlari — namunalarni
`data/samples/` dagi fayllardan yoki `tests/test_logs.py` dagilardan oling):

```python
a = sorted({r['attack_id'] for r in kb.search(t) if r['sources']['heuristic'] > 0})
b = sorted({r['attack_id'] for r in kb.search_heuristics(t)})
self.assertEqual(a, b, f"farq: {t}")
```

Shuningdek ballar ham mos kelsin (bir xil `attack_id` uchun `score` teng).

### 3.2 Kesh testi

`search_heuristics` ikki marta chaqirilganda ikkinchisida SQLite ga yangi
so'rov ketmasligini tekshiring (masalan `kb.conn.set_trace_callback` bilan
so'rovlarni sanang, yoki `kb._heur_compiled is not None` ekanini tasdiqlang
va sanоqni solishtiring).

### 3.3 Revoked test

Heuristikalar ichida revoked ID ga ishora qiluvchi qoida bo'lsa, natijada
almashtiruv ID chiqishini tekshiring (masalan `T1070.001` → `T1685.005`).
Agar bunday qoida yo'q bo'lsa, testni `kb._tech_status` orqali sun'iy
holatda tekshiring — lekin KB ni O'ZGARTIRMANG.

### 3.4 Tezlik testi (yumshoq)

2000 ta matnda `search_heuristics` **10 soniyadan kam** ishlashi kerak
(mashinaga bog'liqlikni hisobga olib keng chegara). Bu regressiya qo'riqchisi.

Mavjud **200 ta test ham yashil qolishi shart.**

## 4. Qabul mezonlari

- [ ] `python -m unittest discover -s tests` — 200 + yangi, hammasi yashil.
- [ ] Quyidagi ikki buyruq **bir xil texnikalar ro'yxatini** beradi
      (faqat vaqt farq qiladi):
      `bk logs analyze <15k fayl> --preset ecs --json-out a.json`
      va shu faylning `--deep` siz eski versiyasi bilan olingan natija.
      Tekshirish: `timeline[].techniques[].technique` to'plamlari teng.
- [ ] 15 000 hodisali `elasticsearch_export.json` **1 daqiqadan kam** ishlaydi
      (hozir 3 daq 15 s).
- [ ] `bk kb search "<matn>"` va web UI dagi KB qidiruvi bugungidek ishlaydi
      (ular `search()` ni ishlatadi, unga tegilmagan).
- [ ] Hisobotda: o'lchangan yangi vaqt va har bir fayl uchun oldingi/keyingi
      qator soni.
