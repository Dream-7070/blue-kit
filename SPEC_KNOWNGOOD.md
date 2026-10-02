# SPEC_KNOWNGOOD — baselinesiz ishlash uchun "OS standart" ro'yxati

Loyiha: `D:\Claude Projects\CTF\blue-kit-staging`

## Muammo (o'lchangan, taxmin emas)

Musobaqada tashkilotchilar **toza host bermasligi** aniq bo'ldi — ya'ni
`bk resp triage` ko'p hollarda `--baseline` siz ishlaydi. Bugungi holat
(`data/samples/resp/current_win.json` ustida o'lchangan):

| Rejim | Topilma | `high` | Hujumchi artefaktlari qayerda |
|---|---|---|---|
| Toza baseline bilan | 6 | 4 | `Updater` vazifa/autorun `high` |
| Baseline yo'q | 7 | 2 | `Updater` faqat `med` (0.50) |

Sabab: `calc_score()` da `has_strong` va +0.40 ball **faqat** `is_new and
baseline is not None` shartidan keladi. Baseline bo'lmasa hujumchi qo'shgan
narsa "yangi" ekanini hech narsa aytmaydi, shuning uchun u `med` da qolib,
42 qatorli ro'yxat ichida ko'milib ketadi.

Yechim: baseline o'rnini qisman bosadigan **"OS standart" (known-good)**
ro'yxatini kit ichiga qo'yish. Mantiq: `Spooler`, `wuauserv`,
`\Microsoft\Windows\...` vazifalari — bular har qanday Windows da bor, demak
ular hujumchi izi emas. Ro'yxatda **yo'q** element esa "baseline'da yo'q (yangi)"
signalining zaifroq variantini oladi.

## 0. Asosiy qoidalar

**TEGMANG:** `bk.py`, `bluekit/siem/**`, `bluekit/logs/**`, `bluekit/ir/**`,
`bluekit/web/**`, `bluekit/kb/**`, mavjud `tests/test_*.py`.

**O'zgartiriladigan:** `bluekit/resp/triage.py` (faqat qo'shimcha mantiq),
`bluekit/doctor.py` (resurslar ro'yxatiga 1 qator), `bk.spec` (`datas` ga 1 yozuv).
**Yangi:** `bluekit/resp/knowngood.yaml`, `tests/test_knowngood.py`.

`triage.py` hozir 571 qator. Mavjud funksiyalarni qayta yozish, qisqartirish yoki
"tozalash" TAQIQLANADI — fayl faqat o'sishi kerak. `analyze()` ning imzosi
(`analyze(kb, current, baseline=None, protected=None, log_artifacts=None)`)
va qaytaradigan `(findings, extra)` strukturasi **o'zgarmaydi** — uni web UI va
`bk.py` chaqiradi.

**DIQQAT:** oldingi topshiriqlarda soxta ma'lumot bilan "tayyor" deb hisobot
berilgan. Bu yerda 5-bo'limdagi testlar aynan shuni ushlash uchun yozilgan —
ro'yxatni sikl bilan generatsiya qilib bo'lmaydi, unda haqiqiy Windows/Linux
nomlari bo'lishi kerak.

## 1. `bluekit/resp/knowngood.yaml`

Struktura:

```yaml
version: 1
windows:
  services:           # xizmat NOMLARI (name maydoni), kichik harfga keltirib solishtiriladi
    - wuauserv
    - spooler
    - windefend
    # ...
  service_paths:      # standart xizmat binarylari shu papkalarda bo'ladi
    - 'c:\windows\system32\'
    - 'c:\windows\syswow64\'
    - 'c:\program files\'
    - 'c:\program files (x86)\'
  task_prefixes:      # Microsoft yetkazadigan vazifalar shu yo'l ostida yashaydi
    - '\microsoft\windows\'
    - '\microsoft\xblgamesave\'
  tasks:              # ildizda turadigan mashhur uchinchi tomon vazifalari
    - googleupdatetaskmachine
    # ...
  autoruns:           # standart Run kaliti yozuvlari
    - securityhealth
    - onedrive
    # ...
  users:              # OS o'zi yaratadigan akkauntlar
    - administrator
    - guest
    - defaultaccount
    - wdagutilityaccount
    - krbtgt
    # ...
  ports: [135, 139, 445, 3389, 5985, 47001]
linux:
  services:
    - sshd
    - cron
    # ...
  service_paths:
    - '/usr/sbin/'
    - '/usr/bin/'
    - '/lib/systemd/'
  cron:
    - apt-daily
    # ...
  users:
    - root
    - daemon
    - nobody
    # ...
  ports: [22, 25, 53, 111, 631]
```

**Hajm talablari (test tekshiradi):** `windows.services` ≥ **120** ta,
`windows.users` ≥ **12**, `windows.autoruns` ≥ **15**, `linux.services` ≥ **40**,
`linux.users` ≥ **20**. Hamma yozuv kichik harfda, takrorlanmaydigan, va
`name-1`, `service-2` kabi generatsiya qilingan naqsh BO'LMASLIGI kerak
(test regex bilan tekshiradi).

Ro'yxatga albatta kirishi shart bo'lgan nomlar (test shularni aniq qidiradi):
`wuauserv`, `windefend`, `bits`, `lanmanserver`, `lanmanworkstation`, `dnscache`,
`eventlog`, `schedule`, `termservice`, `winrm`, `w32time`, `spooler`, `msiserver`,
`trustedinstaller`, `sysmain`, `wscsvc`, `dhcp`, `netlogon`, `samss`, `rpcss`;
linux: `sshd`, `cron`, `systemd-journald`, `systemd-logind`, `dbus`, `rsyslog`,
`networkd-dispatcher`, `unattended-upgrades`, `polkit`, `udisks2`.

YAML `bluekit/paths.py` dagi `get_resource_path('bluekit/resp/knowngood.yaml')`
orqali o'qiladi (PyInstaller uchun shu shart). Fayl topilmasa `analyze()`
**qulamaydi** — jimgina eski (bugungi) xulq bilan ishlaydi va `extra` ga
`knowngood: "topilmadi"` deb yozadi.

## 2. `triage.py` ga integratsiya

### 2.1 Moslik tekshiruvi

`is_known_good(category, name, path_or_value, os_hint)` yordamchisi:

- `name` kichik harfga keltirilib ro'yxat bilan **aniq** solishtiriladi
  (substring EMAS — `admin` `administrator` ga moslashmasligi kerak).
- `tasks` uchun: vazifa `path` maydoni `task_prefixes` dan biri bilan boshlansa —
  known-good, nomidan qat'i nazar.
- **Masquerade himoyasi (eng muhim shart):** `services` va `autoruns` uchun nom
  ro'yxatda bo'lsa ham, `binary_path`/`value` `service_paths` dagi papkalardan
  birida turmasa — **known-good EMAS**. Ya'ni `Spooler` nomli, lekin
  `C:\Users\Public\spoolsv.exe` da turgan xizmat baribir shubhali.
- Bundan tashqari: `calc_score()` ichida `has_strong` yoqilgan bo'lsa
  (KB match, `builtin` shubhali nom yoki shubhali papka) — known-good
  **hech qachon** bostirmaydi.

`os_hint`: `current.get('meta', {}).get('os')` dan olinadi (`windows` / `linux`).
Bo'lmasa ikkala ro'yxat ham tekshiriladi.

### 2.2 Ballga ta'siri

`calc_score()` ga yangi ixtiyoriy argument qo'shing (mavjud chaqiruvlar
buzilmasin), mantiq:

| Holat | Bugun | Bundan keyin |
|---|---|---|
| `baseline` BOR, element yangi | +0.40, `has_strong=True` | **o'zgarmaydi** |
| `baseline` BOR, element known-good | — | o'zgarmaydi (baseline aniqroq, ikki marta hisoblamang) |
| `baseline` YO'Q, element known-good da YO'Q | hech narsa | **+0.25**, sabab: `"OS standart ro'yxatida yo'q (baseline o'rnida)"`, `has_strong` **O'ZGARMAYDI** (False qoladi) |
| `baseline` YO'Q, element known-good | hech narsa | ball 0.15 ga **kamaytiriladi** (`score = max(0, score - 0.15)`), sabab: `"OS standart"` |

`has_strong = True` qilib qo'ymaslik ataylab: bu signal o'zi yolg'iz
`high` bermasligi kerak, aks holda tashkilot o'zining oddiy dasturlari bilan
ro'yxat to'lib ketadi. U faqat boshqa signal bilan birga chegaradan o'tkazadi
(0.35 + 0.25 = 0.60 → `high`).

Shuningdek `baseline is None` bo'lganda `admin akkaunt (baseline yo'q —
tekshiring)` sababi known-good users da turgan akkauntlar uchun
(`administrator`, `krbtgt` …) **qo'shilmasin** — hozir u har bir admin akkauntni
`med` qilib ro'yxatni ifloslantiradi.

### 2.3 `extra` ga qo'shimcha

`analyze()` qaytaradigan `extra` lug'atiga:
```python
extra['knowngood'] = {'used': True/False, 'version': 1, 'os': 'windows',
                      'suppressed': <bostirilgan elementlar soni>}
```
Mavjud `extra` kalitlarini (`unmatched_log_artifacts` va h.k.) O'CHIRMANG.

## 3. `doctor.py` va `bk.spec`

- `bluekit/doctor.py` dagi `resources` ro'yxatiga:
  `('res_knowngood', 'bluekit/resp/knowngood.yaml', True)` qo'shing.
- `bk.spec` dagi `datas` ga `('bluekit/resp/knowngood.yaml', 'bluekit/resp')`
  qo'shing. **Bu yodda tuting** — qo'shilmasa exe da fayl yo'qoladi va
  xususiyat jimgina o'chadi.

## 4. Til

Sabablar (`reasons`) o'zbekcha, mavjud uslubda: `"OS standart"`,
`"OS standart ro'yxatida yo'q (baseline o'rnida)"`.

## 5. Testlar — `tests/test_knowngood.py`

`tests/test_resp.py` uslubida. **Hammasi haqiqiy namuna fayllar ustida:**

### 5.1 Xulq testlari (asosiy)

`cur = data/samples/resp/current_win.json`, `analyze(kb, cur, baseline=None)`:

`high` bo'lishi SHART:
- `tasks` / `Updater`
- `autoruns` / `Updater`
- `users` / `admin`
- `connections` ichidagi `45.142.212.61` yozuvi

`high` bo'lMASLIGI shart:
- `users` / `Administrator`
- `users` / `checker_admin`
- `services` / `Spooler`
- `tasks` / `GoogleUpdateTaskMachine`
- `autoruns` / `SecurityHealth`

### 5.2 Masquerade testi (bu bo'lmasa topshiriq qabul qilinmaydi)

Namunani nusxalab, unga quyidagini qo'shing:
```python
cur['services'].append({"name": "Spooler", "display": "Print Spooler",
    "state": "Running", "start_mode": "Auto",
    "binary_path": "C:\\Users\\Public\\spoolsv.exe", "run_as": "LocalSystem"})
```
Bu yozuv `baseline=None` da **`high`** bo'lishi shart — nomi known-good bo'lsa ham,
yo'li standart papkada emas. Xuddi shu testni `autoruns` uchun ham yozing
(`SecurityHealth` nomi + `C:\Users\hr.olim\AppData\Local\Temp\x.exe` qiymati).

### 5.3 Regressiya testi

`analyze(kb, cur, baseline=<baseline_win.json>)` natijasi **bugungi bilan bir xil**
qolsin: `Updater` vazifa va autorun `high`, jami `high` soni ≥ 4. Ya'ni
known-good haqiqiy baselinening natijasini yomonlashtirmasligi kerak.

### 5.4 Ma'lumot sifati testlari

- YAML yuklanadi, `version` bor.
- 1-bo'limdagi hajm chegaralari (≥120, ≥12, ≥15, ≥40, ≥20).
- 1-bo'limda aniq sanab o'tilgan 30 ta nom ro'yxatda bor.
- Har bir ro'yxatda takror yo'q (`len(x) == len(set(x))`).
- Hech bir yozuv `^(item|name|service|task|user|entry)[-_]?\d+$` regexiga
  mos kelmaydi (generatsiya qilingan soxta ma'lumotga qarshi).
- Hamma yozuv kichik harfda (`x == x.lower()`).

### 5.5 Chidamlilik

- YAML fayli yo'q bo'lsa (`get_resource_path` ni vaqtincha mavjud bo'lmagan
  yo'lga o'zgartirib) `analyze()` **istisno tashlamaydi** va natija beradi.

## 6. Qabul mezonlari

- [ ] `python -m unittest discover -s tests` — **189 + yangi testlar**, hammasi yashil.
      Mavjud 189 tadan birortasi ham buzilmasin.
- [ ] Quyidagi buyruq baselinesiz `high` sonini **2 dan 4 ga** ko'taradi:
      `python bk.py resp triage data/samples/resp/current_win.json --json`
- [ ] `python bk.py doctor` da `res_knowngood` yashil.
- [ ] Hisobotda: `knowngood.yaml` dagi har bir bo'lim uchun **aniq yozuvlar soni**
      va `triage.py` ning oldingi/keyingi qator soni.
