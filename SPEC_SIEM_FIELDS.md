# SPEC_SIEM_FIELDS — maydon xaritasini log manbasiga bog'lash

Loyiha: `D:\Claude Projects\CTF\blue-kit-staging`

`REVIEW_SIEM_RESULT.md` dagi 1-topilma (YUQORI) tasdiqlandi. Shuni tuzatamiz —
**faqat shuni**.

## Muammo (tasdiqlangan)

Hozir har bir dialekt uchun bitta maydon xaritasi bor. Lekin Sentinel da har bir
jadvalning o'z ustunlari bor, va biz jadvalni `logsource` bo'yicha tanlaymiz.
Natijada:

```
python bk.py siem query net-port-scan --siem sentinel
  CommonSecurityLog
  | summarize dest_port_count = dcount(DestinationPort) by IpAddress    <-- XATO
```

`IpAddress` — `SecurityEvent` ustuni. `CommonSecurityLog` da u `SourceIP`.
So'rov sintaktik jihatdan to'g'ri, lekin **jimgina bo'sh natija** qaytaradi —
musobaqada eng yomon nosozlik turi.

`auth-bruteforce` (SecurityEvent) esa to'g'ri ishlaydi — ya'ni xarita SecurityEvent
uchun to'g'ri, boshqa jadvallar uchun noto'g'ri.

## TEGMANG

`bk.py`, `bluekit/web/**`, `bluekit/hunt/**`, `bluekit/ir/**`, `bluekit/logs/**`,
`static/**`, `dist/**`. `bluekit/siem/catalog.py` dagi hunt lar ham o'zgarmaydi —
muammo katalogda emas, xaritada.

**Quyidagilarni O'ZGARTIRMANG** (men tekshirdim, ular ataylab shunday):

- `FIELD_MAPS['wazuh']` dagi kichik harfli nomlar (`data.win.eventdata.commandLine`,
  `parentImage`, `targetUserName`). Wazuh Windows eventdata maydonlarining birinchi
  harfini kichik qiladi. Review da buni CamelCase qilish taklif qilingan — **bu
  noto'g'ri, qilmang.**
- `CqlRenderer` dagi `count(field=..., distinct=true, as=...)` va `sort(field=...)`.
- `UdmRenderer` dagi `net.ip_in_range_cidr(...)` va regex literallari.
- `FIELD_MAPS['splunk']` dagi `New_Process_Name` / `Process_Command_Line`.

## 1. `FIELD_OVERRIDES` (`bluekit/siem/dialects.py`)

`FIELD_MAPS` dan keyin yangi lug'at: `{siem: {logsource: {kanonik: native}}}`.
Bu **qo'shimcha qatlam** — `FIELD_MAPS` asos bo'lib qoladi, override faqat
farq qiladigan maydonlarni almashtiradi.

```python
FIELD_OVERRIDES = {
    'sentinel': {
        'firewall': { ... },   # CommonSecurityLog
        'proxy':    { ... },   # CommonSecurityLog
        ...
    },
}
```

Sentinel jadvallari va ustunlari (shularni ishlating):

| logsource | jadval | ustunlar |
|---|---|---|
| `firewall`, `proxy` | `CommonSecurityLog` | `SourceIP`, `DestinationIP`, `SourcePort`, `DestinationPort`, `DeviceAction`, `SentBytes`, `ReceivedBytes`, `Protocol`, `RequestURL`, `SourceUserName`, `DeviceName`, `Activity` |
| `dns` | `DnsEvents` | `Computer`, `ClientIP`, `Name` (so'ralgan domen), `QueryType`, `IPAddresses` |
| `web` | `W3CIISLog` | `Computer`, `cIP`, `csUriStem`, `csUriQuery`, `scStatus`, `csMethod`, `csUserAgent`, `sSiteName` |
| `vpn` | `SigninLogs` | `UserPrincipalName`, `IPAddress`, `AppDisplayName`, `ResultType`, `Location` |
| `mail` | `OfficeActivity` | `UserId`, `ClientIP`, `Operation` |

`windows-*` logsource lari `SecurityEvent` / `Event` da qoladi — ular uchun override
KERAK EMAS (hozirgi `FIELD_MAPS['sentinel']` to'g'ri).

Agar shu ustun nomlaridan birortasiga qo'shilmasangiz — o'zgartirmang, hisobotda
ayting.

## 2. Boshqa dialektlarni ham tekshiring

Xuddi shu muammo boshqa joyda ham bo'lishi mumkin — jadval `logsource` ga qarab
o'zgaradigan har qanday dialektda. Ayniqsa:

- **`defender`**: `DeviceNetworkEvents` (`LocalIP`/`RemoteIP`/`RemoteUrl`),
  `DeviceLogonEvents` (`AccountName`, `RemoteIP`, `LogonType`),
  `EmailEvents` (`SenderFromAddress`, `RecipientEmailAddress`, `Subject` — bular
  faqat shu jadvalda bor), `DeviceProcessEvents`, `DeviceRegistryEvents`.
- Qolgan 10 ta dialektni ham ko'zdan kechiring.

Haqiqatan mos kelmayotgan joy topsangiz — override qo'shing. Topmasangiz —
**o'ylab topib qo'shmang**, hisobotda "tekshirildi, muammo yo'q" deb yozing.

## 3. Builder ni ulash (`bluekit/siem/builder.py`) — eng muhim qism

Hozir maydonlar **bir necha joyda** `self.fmap.get(...)` orqali olinadi:
`field()`, `metric_native()`, `select_natives()`, `group_natives()`,
`user_filters()` (ichidagi `ip` shoxi), `AqlRenderer.metric_sql()` va boshqa
renderer larning `metric_*` metodlari.

**Hammasi bitta joydan o'tishi shart.** Aks holda so'rovning yarmi to'g'ri,
yarmi noto'g'ri nom bilan chiqadi — hozirgidan ham battar.

`Renderer.__init__` da yig'ilgan xarita tayyorlansin:

```python
base = dict(FIELD_MAPS.get(siem, {}))
base.update(FIELD_OVERRIDES.get(siem, {}).get(hunt.get('logsource', 'any'), {}))
self.fmap = base
```

Shunda qolgan kod o'zgarmaydi. Agar shu yo'lni tanlasangiz — `self.fmap` ga
to'g'ridan-to'g'ri murojaat qiladigan **barcha** joylar shu yig'ilgan xaritadan
foydalanayotganini tekshiring.

## 4. Testlar (`tests/test_siem.py` ga QO'SHING)

Mavjud 32 ta testni **o'chirmang va o'zgartirmang**. Yangilari:

1. `net-port-scan` / `sentinel` → so'rovda `SourceIP` bor, `IpAddress` **yo'q**.
2. `exfil-large-upload` / `sentinel` → `SourceIP` bor, `IpAddress` yo'q.
3. `c2-dns-tunnel` / `sentinel` → `DnsEvents` va `Name` (yoki tanlagan ustuningiz).
4. `web-attack-patterns` / `sentinel` → `W3CIISLog` va `csUriStem`.
5. **Regressiya:** `auth-bruteforce` / `sentinel` → hamon `SecurityEvent` va
   `IpAddress` (override windows-logon ga tegmaganini isbotlaydi).
6. `FIELD_OVERRIDES` dagi har bir `(siem, logsource)` juftligi haqiqiy: `siem`
   `DIALECTS` da bor, `logsource` esa o'sha dialektning `SOURCE_MAPS` ida bor.
7. `FIELD_OVERRIDES` dagi har bir kanonik nom `fields.CANONICAL_FIELDS` da bor.
8. Har bir hunt × har bir dialekt uchun so'rovda kanonik nom **qolib ketmaganini**
   tekshiring: masalan `by src_ip` yoki `sum(bytes_sent)` kabi — agregatsiya
   maydoni xaritada yo'q bo'lsa kanonik nom qoladi va bu ogohlantirish bilan
   kelishi kerak (`metric_native` buni allaqachon qiladi). Test: kanonik nom
   qolgan bo'lsa, `notes` da o'sha maydon haqida eslatma bor.

## 5. Qabul

```
python -m unittest discover -s tests -p "test_*.py" -q
python bk.py siem query net-port-scan --siem sentinel
python bk.py siem query auth-bruteforce --siem sentinel
python bk.py siem query exfil-large-upload --siem defender
python bk.py siem query auth-bruteforce --siem all
```

Hozir **65 ta test** yashil. Siz qo'shgandan keyin ham hammasi yashil bo'lsin,
ustiga yangilari qo'shilsin. Uchta snapshot testi (`test_qradar_bruteforce`,
`test_splunk_encoded_powershell`, `test_sentinel_bruteforce`) **o'zgarmasdan**
o'tishi shart — agar ulardan biri yiqilsa, siz SecurityEvent xaritasini
buzgansiz.

Hisobotda **ko'chirib** keltiring:
- `python bk.py siem query net-port-scan --siem sentinel` ning to'liq chiqishi
- `python bk.py siem query auth-bruteforce --siem sentinel` ning to'liq chiqishi
- `unittest` chiqishining oxirgi 3 qatori
- 2-bo'lim bo'yicha: qaysi dialektlarni tekshirdingiz va nima topdingiz

Ishonchingiz komil bo'lmagan ustun nomini yozmang — hisobotda "tekshirish kerak"
deb belgilang. Bo'sh natija qaytaradigan so'rov — sintaktik xatodan ham yomon,
chunki uni sezish qiyin.
