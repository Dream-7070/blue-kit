# SPEC_ICS — ICS/OT qamrovi (arzon sug'urta versiyasi)

Loyiha: `D:\Claude Projects\CTF\blue-kit-staging`

## Nega

O'tgan yilgi finalning 2-kuni zavod xizmati ishdan chiqarilgan edi va javoblar
ATT&CK **for ICS** (T0xxx) bo'yicha topshirilgan. Stsenariy takrorlanishi shart
emas — bu **garov**, shuning uchun arzon versiyasi qilinadi.

Hozirgi holat:

| Komponent | ICS qamrovi |
|---|---|
| KB | **118 ta** T0xxx texnika bor ✅ |
| `bluekit/kb/heuristics.yaml` | atigi **8 ta** ICS qoidasi |
| `bluekit/logs/eventmap.yaml` | **0** |
| `bluekit/siem/catalog.py` | **0** |
| `bluekit/logs/fieldmap.yaml` | ICS preseti yo'q |

Ya'ni `bk kb id T0836` ishlaydi, lekin loglardan T0836 ni **topib bera olmaydi**.

**Modbus/S7 parseri yozilmaydi** — bu qimmat va ehtimoli past. Faqat naqsh va
so'rovlar qo'shiladi.

## TEGMANG

`bluekit/logs/parse.py`, `detect.py`, `qradar.py`, `report.py`, `timeline.py`,
`sigma.py`, `formats.py`, `bluekit/ir/**`, `bluekit/resp/**`, `bluekit/web/**`,
`bluekit/decode.py`, `bluekit/doctor.py`, `bk.py`, mavjud `tests/test_*.py`.

**O'zgartiriladigan (faqat qo'shimcha, o'chirish yo'q):**
`bluekit/kb/heuristics.yaml`, `bluekit/logs/eventmap.yaml`,
`bluekit/logs/fieldmap.yaml`, `bluekit/siem/catalog.py`,
`bluekit/siem/dialects.py` (faqat `SOURCE_MAPS` ga `ics` qatori).

**Yangi:** `tests/test_ics.py`.

## 0. Majburiy birinchi qadam — ID larni tekshirish

Quyida ishlatiladigan **har bir** T0xxx ID ni avval KB da tasdiqlang:

```
python bk.py kb validate T0803 T0816 T0821 T0831 T0836 T0843 T0845 T0855 T0856 T0858 T0878 T0881 T0889
```

`revoked` yoki `not found` chiqsa — **o'sha ID ni ishlatmang**, KB dagi
to'g'risini toping (`bk kb search <matn>`). Hisobotda qaysi ID lar tasdiqlangani
va qaysilari almashtirilgani yozilsin. Quyidagi jadvallardagi ID lar **taklif**,
KB ustun.

## 1. `heuristics.yaml` — ICS naqshlarini kengaytirish

Hozir 8 ta. Format mavjud fayldan ko'chirilsin (`name`, `pattern`, `techniques`,
`weight`, `note`). **Mavjud yozuvlarga tegmang**, faqat qo'shing — maqsad ~25 ta.

Qamrab olinishi kerak bo'lgan mavzular:

| Mavzu | Naqsh misollari (regex) | Texnika (tasdiqlang) |
|---|---|---|
| PLC to'xtatish / ishga tushirish | `stop\s*cpu`, `plc\s*stop`, `cpu\s*halt`, `run/stop` | T0816, T0881 |
| Modbus yozish funksiyalari | `function\s*code\s*(5|6|15|16)`, `write\s*(single|multiple)\s*(coil|register)` | T0836, T0855 |
| Setpoint / parametr o'zgarishi | `setpoint\s*chang`, `parameter\s*(write|modif)`, `tag\s*write` | T0836 |
| Dastur yuklash (program download) | `program\s*download`, `ladder\s*logic`, `project\s*download`, `firmware\s*(update|upload)` | T0821, T0843 |
| Injenerlik stansiyasi vositalari | `tia\s*portal`, `step\s*7`, `rslogix`, `studio\s*5000`, `unity\s*pro`, `codesys` | T0858 (tasdiqlang) |
| HMI/SCADA xizmati to'xtashi | `hmi.*stop`, `scada.*stop`, `wincc.*(stop|fail)`, `ignition.*stop` | T0881 |
| Protokol nomlari | `modbus`, `s7comm`, `dnp3`, `enip`, `cip`, `iec-?104`, `bacnet`, `profinet` | T0885 / T0830 (tasdiqlang) |
| Nazoratni yo'qotish belgilari | `loss\s*of\s*(view|control)`, `communication\s*(loss|fail)` | T0829, T0827 (tasdiqlang) |

Regexlar **katta-kichik harfsiz** (`(?i)`) va mavjud fayldagi uslubda bo'lsin.
`weight` mavjud ICS yozuvlaridagi kabi.

**Muhim:** naqsh juda keng bo'lmasin. `modbus` so'zi oddiy tarmoq logida ham
uchraydi — shuning uchun protokol nomlari uchun `weight` past bo'lsin, yozish
buyruqlari uchun yuqori.

## 2. `eventmap.yaml` — ICS uchun Windows hodisalari

ICS muhitidagi injenerlik stansiyalari **Windows** da ishlaydi. Shuning uchun
eventmap ga bir nechta yozuv qo'shish mumkin:

- `System` / 7045 + xizmat nomida `wincc|step7|rslinx|codesys` → T0858
- `Security` / 4688 + jarayon nomi injenerlik vositasi → T0858
- ICS mahsulotining o'z jurnali (`channel` da `WinCC`, `FactoryTalk`) → T0885

Agar mavjud `eventmap.yaml` sxemasi (`channel` + `event_id` + `techniques`)
buni ko'tarmasa — **sxemani o'zgartirmang**, shu ishni faqat `heuristics.yaml`
da qiling va hisobotda sababini yozing.

## 3. `fieldmap.yaml` — `ics` preseti

Zeek ning ICS loglari va umumiy ICS eksportlari uchun:

```yaml
  ics:
    ts: [ts, timestamp, Timestamp]
    src_ip: [id.orig_h, src_ip, source]
    dest_ip: [id.resp_h, dst_ip, destination]
    dest_port: [id.resp_p, dst_port]
    host: [host, device, station, plc]
    user: [user, operator]
    event_id: [func, function_code, funcode, service]
    command_line: [request, command, tag, point]
    message: [message, info, detail]
```

Mavjud presetlarga **tegmang**, faqat yangi blok qo'shing. `default` bloki
`create_maps.py` bilan yangilanadi — uni **qayta yurgizmang**, qo'lda ham
yangilamang (boshqa presetlar buzilmasin).

## 4. `siem/catalog.py` — 5 ta ICS hunt

Mavjud 32 ta hunt ga **tegmang**, 5 tasini qo'shing. `logsource: 'ics'`.

| id | name (uz) | shart | ATT&CK |
|---|---|---|---|
| `ics-plc-stop` | PLC yoki CPU to'xtatildi | `message contains_any ['stop cpu','plc stop','cpu halt']` | T0816, T0881 |
| `ics-write-command` | Kontrollerga yozish buyrug'i | `event_id in [5,6,15,16]` yoki `message contains_any ['write single coil','write multiple registers']` | T0836 |
| `ics-program-download` | Kontrollerga dastur yuklandi | `message contains_any ['program download','ladder logic','project download']` | T0821 |
| `ics-engineering-tool` | Injenerlik vositasi ishga tushdi | `process endswith_any ['\\Step7.exe','\\RSLogix.exe','\\CodeSys.exe']` | T0858 |
| `ics-hmi-service-stop` | HMI/SCADA xizmati to'xtadi | `message contains_any ['hmi stop','scada stop','wincc']` | T0881 |

Har biri to'liq bo'lsin: `description` va `tuning` mazmunli o'zbekcha matn
(nomdan nusxa emas), `select` maydonlari, `params`.

`dialects.py` ning `SOURCE_MAPS` iga har bir dialekt uchun `'ics'` qatori
qo'shilsin (masalan `splunk: 'index=ics'`, `sentinel: 'CommonSecurityLog'`,
`elastic: 'FROM logs-ics.*'`, `qradar: 'events'`). Mavjud qatorlarga tegmang.

## 5. Testlar (`tests/test_ics.py`)

1. **Barcha ICS ID lari KB da `active`** — `heuristics.yaml`, `catalog.py` va
   (agar qo'shilgan bo'lsa) `eventmap.yaml` dagi hamma T0xxx. `skipUnless` KB.
2. **Heuristika soni oshgan:** `heuristics.yaml` da T0xxx li yozuvlar >= 20.
3. **Naqshlar kompilyatsiya bo'ladi:** har bir yangi `pattern` `re.compile`
   dan istisnosiz o'tsin.
4. **Naqsh ishlaydi:** `"PLC STOP command sent to station 3"` matni kamida
   bitta ICS heuristikasiga mos kelsin.
5. **Naqsh juda keng emas:** `"user logged in successfully"` va
   `"GET /index.html 200"` matnlari **hech qaysi** ICS heuristikasiga mos
   kelmasin. *(Shovqin testi — eng muhimi.)*
6. **5 ta hunt qo'shilgan:** `HUNTS` da `ics-` bilan boshlanadigan 5 ta id bor,
   umumiy soni 37.
7. **Har bir ICS hunt 12 dialektda render bo'ladi** va `TODO`/bo'sh chiqmaydi.
8. **`ics` logsource har bir dialektning `SOURCE_MAPS` ida bor.**
9. **`fieldmap.yaml` da `ics` preseti** yuklanadi va `ts`, `src_ip`, `dest_ip`
   kalitlari bor. Mavjud presetlar soni kamaymagan.
10. **Regressiya:** mavjud 32 hunt va ularning snapshot testlari o'zgarmagan.

## 6. Qabul

```
python -m unittest discover -s tests -p "test_*.py" -q
python bk.py kb validate <ishlatilgan barcha T0 ID lar>
python bk.py siem hunts --search ics
python bk.py siem query ics-plc-stop --siem qradar
python bk.py kb build --data <data papkasi>      # heuristics.yaml o'zgargani uchun KB qayta quriladi
```

**`heuristics.yaml` o'zgargandan keyin KB qayta qurilishi shart** — aks holda
yangi naqshlar `sqlite` ga tushmaydi va hech narsa o'zgarmaydi. Buni bajaring va
hisobotda tasdiqlang.

Barcha mavjud testlar yashil qolsin. Hisobotda: tasdiqlangan/almashtirilgan
T0 ID lar ro'yxati, qo'shilgan heuristika soni, 5-testning natijasi.
