# SPEC_FRAUD — yaxlitlik tekshiruvlari va kollektorlarni kengaytirish

Loyiha: `D:\Claude Projects\CTF\blue-kit-staging`

## Nega

`bluekit/resp/fraud.py` — 7 qator, ikkita `if`:

```python
def scan(snapshot):
    res = []
    if snapshot.get('remote_access_tools'): res.append({'technique': 'T1219', ...})
    if snapshot.get('hosts_file'): res.append({'technique': 'T1565.001', ...})
    return res
```

Ikkala tekshiruvni ham `bluekit/resp/triage.py` **allaqachon** yaxshiroq
qiladi — baseline bilan solishtirib, ball berib, KB bilan bog'lab. Ya'ni bu
modul foyda qo'shmaydi.

Haqiqiy qiymat beradigan tekshiruvlar uchun **ma'lumot yig'ilmayapti**: proxy
sozlamalari, DNS serverlari, o'rnatilgan ildiz sertifikatlari, port-proxy
qoidalari. Shuning uchun ish kollektorlardan boshlanadi.

Bu "bank o'tkazmasi" stsenariysiga bog'lanmagan — **ma'lumot yaxlitligining
buzilishi** har qanday hikoyada uchraydi.

## TEGMANG

`bluekit/resp/triage.py`, `remediate.py`, `logbridge.py`, `sla.py`,
`scoring.py`, `servicedoctor.py`, `report.py`, `bluekit/logs/**`,
`bluekit/siem/**`, `bluekit/ir/**`, `bluekit/hunt/**`, `bluekit/web/**`,
`bluekit/decode.py`, `bluekit/doctor.py`, `bk.py`, mavjud `tests/test_*.py`.

**O'zgartiriladigan:** `responder/collect_windows.ps1`,
`responder/collect_linux.sh`, `bluekit/resp/schema.py` (faqat yangi maydonlar),
`bluekit/resp/fraud.py` (to'liq qayta yoziladi).
**Yangi:** `tests/test_fraud.py`.

## 0. Kollektorlar uchun qattiq qoidalar

Bu fayllar musobaqa kunida begona mashinalarda ishlaydi. Shuning uchun:

- **PowerShell 5.1 mos** bo'lsin: `??`, `?.`, ternar operator, `-AsHashtable`
  **ishlatilmaydi**. `&&` va `||` ham yo'q.
- Tashqi modul o'rnatilmaydi, internet yo'q.
- **Admin bo'lmasa ham ishlashi kerak** — har bir yangi blok `try/catch` ichida,
  xato bo'lsa `$snapshot.errors += "<nom>: $_"` va davom etadi.
- Mavjud maydonlar va JSON tuzilmasi **o'zgarmaydi** — faqat yangi kalitlar
  qo'shiladi (eski snapshotlar bilan moslik saqlanadi).
- Linux skripti `bash` da, `jq` yoki boshqa tashqi vositaga tayanmasin.
- Chiqish hajmi cheklansin: sertifikatlar ro'yxati 200 tadan, port-proxy 100
  tadan oshmasin.

## 1. Kollektorlarga qo'shiladigan ma'lumot

### Windows (`collect_windows.ps1`)

| Kalit | Nima yig'iladi | Qanday |
|---|---|---|
| `proxy` | Tizim va foydalanuvchi proxy sozlamalari | `HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings` (`ProxyEnable`, `ProxyServer`, `AutoConfigURL`), `netsh winhttp show proxy` |
| `dns_servers` | Har bir interfeys uchun DNS | `Get-DnsClientServerAddress` (yo'q bo'lsa `ipconfig /all` matnidan) |
| `root_cas` | Ildiz sertifikatlari | `Get-ChildItem Cert:\LocalMachine\Root` -> `{subject, thumbprint, notafter, issuer}` |
| `portproxy` | Port yo'naltirish qoidalari | `netsh interface portproxy show all` |
| `firewall_profiles` | Profil holati (on/off) | `Get-NetFirewallProfile` yoki `netsh advfirewall show allprofiles` |

### Linux (`collect_linux.sh`)

| Kalit | Manba |
|---|---|
| `proxy` | `/etc/environment`, `http_proxy`/`https_proxy` muhit o'zgaruvchilari, `/etc/apt/apt.conf.d/*proxy*` |
| `dns_servers` | `/etc/resolv.conf`, `resolvectl status` (bo'lsa) |
| `root_cas` | `/etc/ssl/certs/ca-certificates.crt` dagi soni + `/usr/local/share/ca-certificates/` dagi fayllar ro'yxati |
| `portproxy` | `iptables -t nat -L -n` yoki `nft list ruleset` (mavjud bo'lsa) |
| `firewall_profiles` | `ufw status` yoki `firewall-cmd --state` |

Har bir kalit **ro'yxat yoki lug'at** bo'lsin, olinmasa **bo'sh** (yo'q emas).

## 2. `schema.py`

`Snapshot` dataclass ga yangi maydonlar qo'shilsin (hammasi
`field(default_factory=...)` bilan, eski snapshotlar buzilmasin):

```python
proxy: Dict[str, Any] = field(default_factory=dict)
dns_servers: List[Dict[str, Any]] = field(default_factory=list)
root_cas: List[Dict[str, Any]] = field(default_factory=list)
portproxy: List[Dict[str, Any]] = field(default_factory=list)
firewall_profiles: List[Dict[str, Any]] = field(default_factory=list)
```

`from_dict` allaqachon noma'lum kalitlarni tashlab ketadi — unga tegmang.

## 3. `fraud.py` — yaxlitlik tekshiruvlari

```python
def scan(current, baseline=None, kb=None) -> list
```

Birinchi argument nomi va pozitsiyasi **saqlansin** — `bk.py` va
`/api/resp/fraud` uni `scan(cur)` deb chaqiradi.

### Tekshiruvlar

| # | Nima | Shart | ATT&CK (tasdiqlang) |
|---|---|---|---|
| 1 | Yangi ildiz sertifikati | `root_cas` da baselineda yo'q thumbprint | T1553.004 |
| 2 | Muddati g'alati sertifikat | `notafter` 20 yildan uzoq yoki `subject` da mahalliy nom | T1553.004 |
| 3 | Proxy yoqilgan/o'zgargan | `proxy.ProxyEnable` = 1 va baselineda 0, yoki `ProxyServer` farq qiladi | T1090 |
| 4 | PAC fayl o'rnatilgan | `proxy.AutoConfigURL` bo'sh emas | T1090 |
| 5 | DNS o'zgargan | `dns_servers` baselinedan farq qiladi yoki tashqi (public) IP | T1071.004 |
| 6 | Port yo'naltirish | `portproxy` bo'sh emas yoki baselineda yo'q yozuv bor | T1090 |
| 7 | Firewall o'chirilgan | `firewall_profiles` da biror profil `off` | T1562 -> **KB da tasdiqlang, v19 da T1685 bo'lishi mumkin** |

Baseline berilmasa — 1, 3, 5 kabi "farq" tekshiruvlari o'rniga **mutlaq**
mezonlar ishlatilsin (masalan: PAC bor, portproxy bor, firewall off, DNS public
IP) va `confidence` pasaytirilsin.

### Qaytariladigan format

`triage.py` dagi topilma formatiga **mos** bo'lsin (bir xil ko'rinishda
ko'rsatish uchun):

```python
{'category': 'root_cas', 'item': 'CN=Fake Root CA (a1b2c3...)',
 'score': 0.8, 'confidence': 'high',
 'techniques': [{'id': 'T1553.004'}],
 'reasons': ["baseline'da yo'q (yangi)", "muddati 30 yil"],
 'protected': False}
```

`hosts_file` va `remote_access_tools` ni **takrorlamang** — ular triage da bor.
Agar shu ikkisi ham kerak bo'lsa, `scan()` hujjatida "bular triage da" deb
yozib qo'ying.

## 4. Testlar (`tests/test_fraud.py`)

1. **Yangi sertifikat:** baselineda 2 ta CA, currentda 3 ta → uchinchisi
   topilsin, `T1553.004` bilan.
2. **O'zgarmagan sertifikatlar** → topilma yo'q (shovqin yo'q).
3. **PAC:** `AutoConfigURL` bo'lsa topilsin, bo'sh bo'lsa yo'q.
4. **Proxy o'zgarishi:** baseline `ProxyEnable: 0`, current `1` → topilsin.
5. **DNS:** baselineda ichki DNS, currentda `8.8.8.8` → topilsin.
6. **Portproxy** bo'sh bo'lmasa topilsin.
7. **Firewall off** topilsin.
8. **Baselinesiz rejim:** `scan(current)` istisnosiz ishlaydi va mutlaq
   mezonlar bo'yicha topilma beradi.
9. **Eski snapshot:** yangi kalitlarsiz (faqat `users`, `services`) snapshot
   berilganda istisno emas, bo'sh natija.
10. **Format mosligi:** har bir topilmada `category`, `item`, `score`,
    `confidence`, `techniques`, `reasons` kalitlari bor.
11. **ATT&CK ID lari KB da `active`** (`skipUnless` KB).
12. **Orqaga moslik:** `scan(cur)` bitta argument bilan ishlaydi.

Kollektorlar uchun (skript sintaksisi):

13. `collect_windows.ps1` **PowerShell 5.1 da parse bo'ladi**:
    `[System.Management.Automation.Language.Parser]::ParseFile()` bilan
    tekshiring, xatolar bo'lmasin. (Skriptni **ishga tushirmang**, faqat parse.)
14. `collect_linux.sh` `bash -n` bilan sintaksis tekshiruvidan o'tsin
    (Windows da `bash` bo'lmasa `skipUnless`).

## 5. Qabul

```
python -m unittest discover -s tests -p "test_*.py" -q
powershell -ExecutionPolicy Bypass -File responder\collect_windows.ps1 -Out snap_test.json
python -c "import json; d=json.load(open('snap_test.json',encoding='utf-8')); print({k: (len(v) if isinstance(v,(list,dict)) else v) for k,v in d.items()})"
python bk.py resp fraud snap_test.json
```

Kollektorni **haqiqatan ishga tushiring** va chiqishdagi yangi kalitlarni
hisobotda ko'rsating. Agar biror ma'lumot admin huquqisiz olinmasa — buni
`errors` da ko'rsating va hisobotda ayting, jim qolmang.

Barcha mavjud testlar yashil qolsin.
