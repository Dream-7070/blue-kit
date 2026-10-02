# SPEC_DOCTOR_SELFTEST — `bk doctor` (kit o'zini tekshiradi)

Loyiha: `D:\Claude Projects\CTF\blue-kit-staging`

## Nega

Musobaqa kuni birinchi savol: "bu kit shu noutbukda umuman ishlayaptimi?"
Hozir buni bilish uchun 6-7 buyruqni qo'lda yurgizish kerak. `TEKSHIRUV.bat` bor,
lekin u faqat tarqatilgan papkada ishlaydi va `.bat` ichida qotib qolgan.

Kerak: **bitta buyruq**, ham manbada, ham `.exe` ichida ishlaydigan.

## TEGMANG

`bk.py` (CLI ni men ulayman), `bluekit/web/**`, `bluekit/siem/**`,
`bluekit/hunt/**`, `bluekit/ir/**`, `bluekit/logs/**`, `bluekit/resp/**`,
`bluekit/kb/**`, `bluekit/mail/**`, `bluekit/report/**`, `responder/**`,
mavjud `tests/test_*.py`, `bk.spec`, `TEKSHIRUV.bat`.

**Yangi fayllar:** `bluekit/doctor.py`, `tests/test_selftest.py`.

Boshqa modullarni faqat **chaqiring**, o'zgartirmang.

## 1. API

```python
def run_checks(data_dir=None, quick=False) -> list
def summary(results) -> dict
```

`run_checks` har bir tekshiruv uchun lug'at qaytaradi:

```python
{
  'id': 'kb',
  'name': 'KB bazasi',                  # o'zbekcha
  'ok': True,
  'detail': 'enterprise 19.2, 858 texnika',
  'fix': None,                          # xato bo'lsa -- nima qilish kerakligi
  'critical': True,                     # False bo'lsa ogohlantirish, xato emas
  'ms': 42,
}
```

`summary(results)` → `{'total': n, 'ok': n, 'failed': n, 'warnings': n,
'verdict': 'HAMMASI JOYIDA' | 'OGOHLANTIRISH BOR' | 'XATOLAR BOR'}`.

`quick=True` — faqat tez tekshiruvlar (namunali funksional sinovlarsiz).

Hech bir tekshiruv **istisno tashlamasin**. Har biri `try/except` ichida, xato
bo'lsa `ok: False` va `detail` da sabab.

## 2. Tekshiruvlar

### A. Muhit

| id | Tekshiradi | critical |
|---|---|---|
| `python` | Python versiyasi, frozen (exe) yoki manba rejimi | ha |
| `data_dir` | `bluekit.paths.get_data_dir()` mavjudmi, yo'li | ha |
| `workdir` | joriy papkaga yozish mumkinmi (vaqtinchalik fayl yaratib o'chiring) | ha |
| `encoding` | `sys.stdout` UTF-8 ni ko'taradimi (o'zbekcha matn buzilmasligi) | yo'q |

### B. Ma'lumot

| id | Tekshiradi | critical |
|---|---|---|
| `kb` | `kb.sqlite` ochiladimi, `meta` dagi versiyalar, texnikalar soni | ha |
| `kb_ics` | KB da ICS (T0xxx) texnikalari bormi va nechta | yo'q |
| `kb_v19` | `T1070.001` **revoked** va `replacement` = `T1685.005` ekanini tasdiqlang | ha |
| `sigma` | `sigma_rules` jadvalidagi qoidalar soni | yo'q |
| `atomic` | `atomic_tests` soni | yo'q |
| `samples` | `data/samples` dagi namunaviy fayllar bormi | yo'q |

`kb_v19` eng muhimi: u KB haqiqatan v19 ekanini isbotlaydi. Agar eski KB bo'lsa,
butun javoblar noto'g'ri ID bilan chiqadi.

### C. Paket ichidagi resurslar

`bluekit.paths.get_resource_path()` orqali har biri **ochilib o'qilsin** (shunchaki
mavjudligini tekshirish yetarli emas — exe ichida yo'l boshqacha):

`bluekit/logs/fieldmap.yaml`, `bluekit/logs/eventmap.yaml`, `bluekit/logs/noise.yaml`,
`bluekit/kb/heuristics.yaml`, `bluekit/mail/brands.yaml`,
`bluekit/report/strings.yaml`, `bluekit/hunt/allowlist.yaml`.

YAML sifatida `yaml.safe_load` bilan yuklansin. Har biri alohida tekshiruv
(`id` = `res_fieldmap` va h.k.), hammasi `critical: True`.

Alohida: `bluekit/web/static/index.html` mavjudmi (`id: res_static`, critical: yo'q).

### D. Modullar yuklanishi

Har biri `importlib.import_module` bilan (exe da hiddenimports tushib qolsa shu
yerda chiqadi). `id: mod_<nom>`, hammasi critical:

`bluekit.siem.builder`, `bluekit.siem.cli`, `bluekit.ir.correlator`,
`bluekit.ir.report`, `bluekit.hunt.beacons`, `bluekit.logs.parse`,
`bluekit.logs.qradar`, `bluekit.resp.triage`, `bluekit.resp.sla`,
`bluekit.resp.scoring`, `bluekit.resp.servicedoctor`, `bluekit.mail.scan`,
`bluekit.report.render`, `bluekit.web.server`.

### E. Funksional sinov (`quick=False` da)

Haqiqiy chaqiruv, natija tekshiriladi:

| id | Nima qilinadi | O'tgan hisoblanadi |
|---|---|---|
| `fn_siem` | `build_query('net-port-scan', 'sentinel')` | `query` da `SourceIP` bor |
| `fn_kb` | `KB().validate(['T1059.001'])` | `found` va `active` |
| `fn_logs` | `data/samples/win_phishing.csv` ni `logs.report.analyze_logs` yoki `logs.parse.load` bilan | hodisalar soni > 0 |
| `fn_noise` | `data/samples/noise_check.log` tahlili | shovqin filtri ishladi |
| `fn_mail` | `data/samples/mail/phish_sample.eml` skani | natijada phishing belgisi |
| `fn_resp` | `resp.triage.analyze` namunaviy snapshot + baseline bilan | topilmalar soni > 0 |
| `fn_sla` | **yopiq** portga (`127.0.0.1` da band bo'lmagan port) `sla.check` | `state == 'down'` |
| `fn_ir` | `ir.correlator.load_events_from_files` namunaviy CSV bilan | istisno yo'q |

Namuna fayli topilmasa — `ok: False` emas, `critical: False` bilan
"namuna topilmadi" deb belgilansin (kitda namunalar bo'lmasligi mumkin).

`fn_sla` bo'sh port tanlashda: `socket` bilan portni band qiling, `getsockname`
bilan raqamini oling, keyin **yoping** va o'sha raqamni tekshiring.

### F. Ogohlantirishlar (critical: False)

| id | Tekshiradi |
|---|---|
| `write_temp` | vaqtinchalik papkaga yozish |
| `tz` | tizim vaqt zonasi va UTC farqi (tool UTC da ishlaydi) |
| `disk` | `data_dir` joylashgan diskda kamida 200 MB bo'sh joy |

## 3. Chiqish (men `bk.py` da formatlayman)

Modul faqat ma'lumot qaytarsin, chop etmasin. Faqat bitta istisno: modul
`python -m bluekit.doctor` bilan ham ishga tushsin (`if __name__ == '__main__'`),
u holda oddiy jadval chiqarib, xato bo'lsa `sys.exit(1)` qilsin.

## 4. Testlar (`tests/test_selftest.py`)

1. `run_checks()` istisnosiz ishlaydi va ro'yxat qaytaradi.
2. Har bir element majburiy kalitlarga ega: `id`, `name`, `ok`, `detail`,
   `critical`.
3. `id` lar takrorlanmaydi.
4. `summary()` sonlari `results` bilan mos (`ok + failed == total`).
5. **Bu muhitda `critical` tekshiruvlarning hammasi o'tishi kerak** —
   ya'ni test `[r for r in run_checks() if r['critical'] and not r['ok']]`
   bo'sh ekanini tasdiqlasin. (KB yo'q bo'lsa `skipUnless` bilan o'tkazib
   yuborilsin.)
6. `quick=True` da tekshiruvlar soni kamroq va tezroq.
7. `fn_sla` tekshiruvi **haqiqatan** yopiq portni sinaydi: uni `run_checks`
   natijasidan topib, `ok: True` ekanini tasdiqlang (ya'ni "yopiq port down
   qaytardi" degani).
8. Nomavjud `data_dir` berilganda ham istisno tashlamaydi, shunchaki tegishli
   tekshiruvlar `ok: False` bo'ladi.

## 5. Qabul

```
python -m unittest discover -s tests -p "test_*.py" -q
python -m bluekit.doctor
```

Hozir **102 ta test** yashil — hammasi yashil qolsin.

Hisobotda `python -m bluekit.doctor` ning **to'liq chiqishini** ko'chirib
keltiring va nechta tekshiruv borligini ayting.

Stub qoldirmang: har bir tekshiruv haqiqatan biror narsani tekshirsin.
"Hammasi OK" qaytaradigan ro'yxat kerak emas — bu kit haqiqatan ishlayotganini
isbotlashi kerak.
