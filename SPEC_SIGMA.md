# SPEC_SIGMA — Sigma qoidalari bilan hodisalarni tekshirish

Loyiha: `D:\Claude Projects\CTF\blue-kit-staging`

## Nega

KB da **3757 ta Sigma qoidasi** bor va ularning **3289 tasi ATT&CK ID bilan
bog'langan**. Hozir tahlil dvigateli ulardan **bittasini ham ishlatmaydi** —
`eventmap.yaml` da atigi 21 ta texnika, `heuristics.yaml` da 96 ta naqsh.

Eng muhimi: `sigma_rules.detection` ustunida qoidaning **to'liq mantig'i** YAML
matn ko'rinishida saqlangan. Ya'ni yangi ma'lumot yuklash shart emas — hammasi
diskda yotibdi.

Stsenariy noma'lum bo'lgani uchun bu eng foydali sarmoya: Sigma qamrovi qaysi
hikoya bo'lishidan qat'i nazar ishlaydi.

## TEGMANG

`bk.py` (CLI ni men ulayman), `bluekit/web/**`, `bluekit/siem/**`,
`bluekit/hunt/**`, `bluekit/ir/**`, `bluekit/resp/**`, `bluekit/kb/**`,
`bluekit/decode.py`, `bluekit/doctor.py`, mavjud `tests/test_*.py`.

`bluekit/logs/` ichidagi **mavjud** fayllarga tegmang (`parse.py`, `detect.py`,
`qradar.py`, `report.py`, `timeline.py`, `formats.py`, yaml lar). `parse.load()`
ni faqat **chaqiring**.

**Yangi fayllar:** `bluekit/logs/sigma.py`, `tests/test_sigma.py`.

Faqat stdlib + `yaml` (allaqachon bog'liqlikda).

---

## 1. Ma'lumot manbai

```sql
CREATE TABLE sigma_rules(rule_id, title, level, status, product, category,
                         service, techniques TEXT, path TEXT, description TEXT,
                         detection TEXT, falsepositives TEXT)
```

`detection` — Sigma qoidasining `detection:` bloki YAML matn sifatida. Namuna:

```
condition: keywords
keywords:
- SuspiciousOperation
- DisallowedHost
```

`techniques` — vergul bilan ajratilgan ID lar (`T1190` yoki `T1059.001,T1027`).
`product` — `windows`, `linux`, `django`, ... `category` — `process_creation`,
`application`, `network_connection`, ...

KB yo'lini `bluekit.paths.get_kb_path()` dan oling.

---

## 2. Qo'llab-quvvatlanadigan Sigma sintaksisi

To'liq Sigma spetsifikatsiyasini bajarish **shart emas**. Quyidagi to'plam
qoidalarning katta qismini qoplaydi. Qo'llab-quvvatlanmaydigan qoida
**tashlab yuborilsin** (`skipped` hisobiga qo'shilsin), xato bermasin.

### Selection bloklari

```yaml
selection:
  EventID: 4688
  Image|endswith: '\powershell.exe'
  CommandLine|contains:
    - '-enc'
    - 'FromBase64String'
```

- Lug'at kalitlari **AND** bilan bog'lanadi
- Kalit qiymati ro'yxat bo'lsa — **OR**
- Ro'yxat ichidagi lug'atlar (`selection: [ {...}, {...} ]`) — OR

### Modifikatorlar

Majburiy: `contains`, `startswith`, `endswith`, `all`, `re`, `cidr`, `windash`.
`base64`, `base64offset`, `utf16`, `wide` — qo'llab-quvvatlanmasa, qoida
`skipped` bo'lsin (xato emas).

`|all` — ro'yxatdagi **hamma** qiymat bo'lishi kerak (OR emas, AND).
`|re` — regex (`re.IGNORECASE`, xato regex bo'lsa qoida skip).
`|windash` — `-param` va `/param` variantlarini tenglashtiradi.

### Keywords

```yaml
keywords:
  - 'SuspiciousOperation'
```

Ro'yxat — hodisaning **butun matni** bo'yicha OR qidiruv.

### Condition

Qo'llab-quvvatlanishi shart:

- `selection`
- `selection and not filter`
- `sel1 or sel2`, `sel1 and sel2`
- `all of them`, `1 of them`
- `all of selection*`, `1 of selection*`, `not 1 of filter*`
- qavslar: `(a or b) and not c`

Boshqa shakl (`near`, `| count() >`, agregatsiya) — qoida `skipped`.

Taqqoslash **katta-kichik harfsiz** (Sigma standarti shunday).

---

## 3. Maydonlarni moslashtirish

Hodisa `bluekit.logs.parse.load()` dan keladi. Uning kalitlari:

`ts, host, user, src_ip, dest_ip, event_id, channel, process, pid, ppid,
parent_process, command_line, target, message, raw, blob`

`raw` — asl qator (lug'at), `blob` — barcha qiymatlarning birlashtirilgan matni.

Sigma maydonini qidirish tartibi (birinchi topilgani ishlatiladi):

1. `ev['raw']` ichida **aynan shu nom** bilan (katta-kichik harfsiz)
2. quyidagi xarita bo'yicha kanonik maydon:

| Sigma maydoni | Kanonik |
|---|---|
| `Image`, `NewProcessName`, `ProcessName`, `process.executable` | `process` |
| `ParentImage`, `ParentProcessName` | `parent_process` |
| `CommandLine`, `ProcessCommandLine` | `command_line` |
| `EventID`, `EventCode` | `event_id` |
| `User`, `SubjectUserName`, `TargetUserName`, `AccountName` | `user` |
| `Computer`, `ComputerName`, `Hostname` | `host` |
| `SourceIp`, `SourceAddress`, `IpAddress`, `src_ip` | `src_ip` |
| `DestinationIp`, `DestinationAddress` | `dest_ip` |
| `Channel` | `channel` |
| `TargetFilename`, `TargetObject`, `ImageLoaded`, `ServiceName`, `ServiceFileName` | yo'q -> 3-qadam |

3. Topilmasa — `ev['blob']` bo'yicha **matn ichidan** qidirish, va bunday moslik
   `weak: True` deb belgilansin (aniq maydon emas, butun matn).

Agar qoidaning **birorta ham** maydoni topilmasa va `keywords` ham bo'lmasa —
qoida shu hodisa uchun mos kelmadi hisoblansin (majburan `blob` ga tushmasin).

---

## 4. API

```python
class SigmaEngine:
    def __init__(self, kb_path=None, products=None, categories=None,
                 min_level=None, max_rules=None):
        """products: ['windows','linux'] kabi filtr. min_level: 'high' bo'lsa
        faqat high va critical. Yuklanganda qoidalar bir marta parse qilinadi."""

    def stats(self) -> dict          # {'loaded': n, 'skipped': n, 'by_level': {...}}
    def match_event(self, ev) -> list
    def match_events(self, events, progress=None) -> dict
```

`match_event` qaytaradi:

```python
[{'rule_id': '...', 'title': 'Encoded PowerShell', 'level': 'high',
  'techniques': ['T1059.001'], 'matched_fields': ['CommandLine'],
  'weak': False}]
```

`match_events` qaytaradi:

```python
{
  'hits': [{'index': 12, 'ts': ..., 'host': ..., 'rules': [...]}],
  'by_technique': {'T1059.001': {'count': 3, 'rules': ['...'], 'level': 'high'}},
  'stats': {'events': 1000, 'rules_loaded': 900, 'rules_skipped': 120,
            'events_with_hits': 7, 'elapsed_sec': 4.2},
}
```

### Tezlik — majburiy talab

3757 qoidani har bir hodisaga qo'llash sekin. Ikki bosqichli filtr:

1. **Yuklashda**: har bir qoidadan **literal satrlar** (modifikatorsiz va
   `contains`/`endswith`/`startswith` qiymatlari) ajratilsin. Qoidada hech
   bo'lmasa bitta literal bo'lsa — u "prefilter" ro'yxatiga kirsin.
2. **Tekshirishda**: hodisaning `blob` ida o'sha literallardan **birortasi ham
   yo'q** bo'lsa, qoida to'liq baholanmasin.

Maqsad: 5000 hodisa × yuklangan qoidalar **30 soniyadan kam**.
`match_events` da `progress` callback (`progress(done, total)`) ixtiyoriy.

---

## 5. Testlar (`tests/test_sigma.py`)

KB kerak bo'lgan testlarga `skipUnless(os.path.exists(get_kb_path()))`.

1. **Yuklash:** `SigmaEngine()` istisnosiz, `stats()['loaded'] > 500`.
   `skipped` soni `loaded` dan kichik bo'lsin (ya'ni ko'pchiligi tushuniladi).
2. **Sun'iy qoida — contains:** engine ni chetlab, ichki baholovchini to'g'ridan-
   to'g'ri sinang: `{'selection': {'CommandLine|contains': '-enc'}, 'condition': 'selection'}`
   → `command_line` da `-enc` bor hodisaga mos, yo'q hodisaga mos emas.
3. **endswith va katta-kichik harf:** `Image|endswith: '\POWERSHELL.EXE'` →
   `process` = `C:\...\powershell.exe` ga mos.
4. **`and not`:** `selection and not filter` — filter mos kelganda natija yo'q.
5. **`1 of selection*`** va **`all of them`** ishlaydi.
6. **`|all`:** ikkala qiymat ham bo'lsa mos, bittasi bo'lsa mos emas.
7. **`|re`:** regex ishlaydi; buzuq regex qoida **skipped** bo'ladi, istisno emas.
8. **keywords:** butun matn bo'yicha topadi.
9. **Maydon topilmasa:** qoidada `TargetFilename` bo'lsa va hodisada u yo'q —
   `blob` orqali topilsa `weak: True` bo'lsin.
10. **Haqiqiy KB qoidasi bilan:** KB dan `title` ichida `PowerShell` bo'lgan va
    `techniques` da `T1059.001` bo'lgan qoidani toping, unga mos keladigan
    sun'iy hodisa yasang va `match_event` o'sha texnikani qaytarishini
    tasdiqlang. *(Bu test sun'iy emas, haqiqiy ma'lumot bilan ishlaydi.)*
11. **`by_technique` jamlanmasi** to'g'ri sanaydi.
12. **Tezlik:** 2000 ta sun'iy hodisa `match_events` dan **20 soniyadan kam**
    vaqtda o'tsin (`unittest` ichida vaqtni o'lchang va `assertLess`).
13. **Istisno tashlamaslik:** bo'sh hodisa `{}`, `None` qiymatli maydonlar,
    juda uzun matn — hammasi istisnosiz.
14. **Texnika ID lari formati:** `by_technique` kalitlari `T` bilan boshlanadi
    va bo'shliqsiz (KB dagi `techniques` ustuni vergul bilan ajratilgan matn —
    uni to'g'ri bo'ling).

## 6. Qabul

```
python -m unittest discover -s tests -p "test_*.py" -q
python -c "from bluekit.logs.sigma import SigmaEngine; e=SigmaEngine(); print(e.stats())"
python -c "from bluekit.logs.sigma import SigmaEngine; from bluekit.logs.parse import load; e=SigmaEngine(products=['windows']); r=e.match_events(load('data/samples/win_phishing.csv')); print(r['stats']); print(list(r['by_technique'].items())[:5])"
```

Hozir **125 ta test** yashil — hammasi yashil qolsin.

Hisobotda yuqoridagi uchala buyruqning chiqishini **ko'chirib** keltiring,
va nechta qoida yuklangani / nechtasi skip bo'lganini ayting.

Skip bo'lgan qoidalar soni `loaded` dan katta bo'lsa — bu muvaffaqiyatsizlik,
sababini hisobotda tushuntiring.
