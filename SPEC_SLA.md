# SPEC_SLA — haqiqiy xizmat monitoringi va ball infratuzilmasini topish

Loyiha: `D:\Claude Projects\CTF\blue-kit-staging`

## Nega

Hozir `bluekit/resp/sla.py` **butunlay soxta** — ikki qator:

```python
def check(config):
    return [{"name": s['name'], "ok": True, "detail": "simulated"} for s in config['services']]
```

`localhost:80` yopiq bo'lsa ham `ok: True` qaytaradi. U CLI (`bk resp sla`) va web UI
(`/api/resp/sla`) ga ulangan — ya'ni ekranda yashil "ok" ko'rinadi, xizmat esa o'lik
bo'lishi mumkin. Musobaqada availability avtomatik baholanadi, shuning uchun bu eng
xavfli nuqta.

Ikkinchi vazifa: musobaqada scoreboard xizmatlarni **topishmoq nomlari** bilan
ko'rsatadi ("Poseidon qizil"), qaysi host va port ekani aytilmaydi. Ball hisoblovchi
infratuzilmani topish va uni o'z tekshiruv ro'yxatimizga aylantirish kerak.

## TEGMANG

`bk.py` (CLI ulashni men qilaman), `bluekit/web/**`, `bluekit/siem/**`,
`bluekit/hunt/**`, `bluekit/ir/**`, `bluekit/logs/**`, `bluekit/resp/triage.py`,
`bluekit/resp/remediate.py`, `bluekit/resp/logbridge.py`, mavjud `tests/test_*.py`.

`bluekit/resp/servicedoctor.py`, `fraud.py`, `report.py` ham stub, lekin **bu ishda
emas** — ularga tegmang.

**O'zgartiriladigan:** `bluekit/resp/sla.py` (to'liq qayta yoziladi),
`responder/sla.example.yaml`. **Yangi:** `bluekit/resp/scoring.py`,
`tests/test_sla.py`.

## Muhim: mavjud chaqiruvchilar buzilmasin

`bk.py` va `bluekit/web/server.py` shunday chaqiradi:

```python
from bluekit.resp.sla import check as resp_sla_check
resp_sla_check(config)      # config = yuklangan YAML (dict)
```

`check(config)` nomi va imzosi **saqlanib qolsin**, ro'yxat qaytarsin. Ichidagi
lug'atlar boyitiladi (pastda), lekin `name` kaliti qolsin.

---

## 1-qism · `bluekit/resp/sla.py` — haqiqiy tekshiruv

### Konfiguratsiya formati

`responder/sla.example.yaml` ni shu formatga yangilang:

```yaml
services:
  - name: web-prod-01 HTTP        # bizning nomimiz
    board_name: "Poseidon"        # scoreboard dagi topishmoq nomi (ixtiyoriy)
    checks:
      - type: tcp
        target: 10.10.20.11:80
      - type: http
        url: http://10.10.20.11/
        expect_status: 200
        expect_contains: "Welcome"
        timeout: 3
      - type: process
        name: nginx
      - type: service             # windows xizmati
        name: W3SVC
        expect_state: Running
      - type: file_hash
        path: C:\inetpub\wwwroot\index.html
        expect_sha256: "abc123..."
        critical: false
      - type: file_absent
        path: C:\inetpub\wwwroot\shell.aspx
        critical: false
```

Tekshiruv turlari: `tcp`, `http`, `process`, `service`, `file_hash`, `file_absent`.
Har birida ixtiyoriy `critical` (default pastdagi jadval bo'yicha) va `timeout`
(default 3 soniya).

### Uch holat — scoreboard ranglariga mos

| Holat | Qachon | Scoreboard |
|---|---|---|
| `ok` | hamma tekshiruv o'tdi | yashil |
| `degraded` | kritik tekshiruvlar o'tdi, kritik bo'lmagani yiqildi | sariq |
| `down` | kamida bitta **kritik** tekshiruv yiqildi | qizil |

Default `critical`: `tcp`, `http`, `process`, `service` → **true** (mavjudlik);
`file_hash`, `file_absent` → **false** (yaxlitlik).

Mantiq shu: xizmat ishlayapti, lekin webshell hali o'chirilmagan → **sariq**.

### `check(config)` qaytaradigan qiymat

```python
[
  {
    'name': 'web-prod-01 HTTP',
    'board_name': 'Poseidon',
    'state': 'degraded',              # ok | degraded | down
    'ok': False,                      # eski chaqiruvchilar uchun: state == 'ok'
    'detail': "1/5 tekshiruv yiqildi: file_absent shell.aspx",
    'checks': [
      {'type': 'tcp', 'target': '10.10.20.11:80', 'ok': True,
       'critical': True, 'ms': 12, 'detail': 'ochiq'},
      {'type': 'file_absent', 'path': '...', 'ok': False,
       'critical': False, 'detail': 'fayl hali mavjud'},
    ],
    'checked_at': '2026-10-05T09:40:00',
  },
]
```

### Talablar

- **Faqat stdlib**: `socket`, `urllib.request`, `hashlib`, `subprocess`, `time`.
  Tashqi kutubxona yo'q (offline exe).
- Har bir tekshiruv `timeout` bilan cheklansin va **hech qachon istisno tashlamasin** —
  xato bo'lsa `ok: False` va `detail` da sabab. Bitta xizmat yiqilishi butun
  tekshiruvni to'xtatmasin.
- `ms` — javob vaqti millisekundda. Bu keyin sekinlashuvni ko'rsatadi.
- `process` tekshiruvi: Windows da `tasklist`, Linux da `/proc` yoki `ps`.
  `service`: Windows `sc query`, Linux `systemctl is-active`. Platforma
  aniqlanmasa — `ok: False`, `detail: "bu platformada qo'llab-quvvatlanmaydi"`.
- `http`: faqat `http://` va `https://`. Sertifikat xatosi = `ok: False`, lekin
  istisno emas.

### Kuzatish rejimi

```python
def watch(config, interval=30, on_change=None, iterations=None):
    """Har `interval` soniyada tekshiradi. Holat o'zgarganda on_change chaqiriladi."""
```

- `on_change(service_name, old_state, new_state, result)` — callback.
- `iterations` berilsa — shuncha marta aylanib to'xtaydi (test uchun shart).
- Har aylanishda holat o'zgarganlarni qaytarsin; o'zgarmaganini takrorlamasin.
- CLI chiqishida holat o'zgarishi ko'rinadigan bo'lsin: vaqt, xizmat, eski → yangi.

---

## 2-qism · `bluekit/resp/scoring.py` — ball infratuzilmasini topish

Musobaqada scorer to'rt xil ishlashi mumkin. Har birining izi boshqacha:

| Model | Izi |
|---|---|
| To'g'ridan-to'g'ri | bitta tashqi IP → **ko'p ichki port** |
| Agent (so'rov) | bitta tashqi IP → **bitta g'alati port** (10050, 5666, 9100, 161) |
| Agent (push) | **hostdan tashqariga** davriy chiquvchi ulanish |
| Kredensial | takrorlanuvchi autentifikatsiya (5985/5986, 22) |

### Kirish

Snapshot(lar) — `responder/collect_windows.ps1` / `collect_linux.sh` chiqishi.
Sxema `bluekit/resp/schema.py` da, foydalaniladigan maydonlar:

- `meta`: `{os, hostname, collected_at}`
- `listening_ports`: `[{proto, addr, port, pid, process}]`
- `connections`: `[{proto, laddr, lport, raddr, rport, pid, process}]`
- `services`: `[{name, display, state, start_mode, binary_path, run_as}]`

Ixtiyoriy: `logs analyze --json-out` fayli (`logbridge.load_log_artifacts` dan
`checker_ips` olinadi — o'sha funksiyani **qayta yozmang, chaqiring**).

### API

```python
def discover(snapshots: list, log_artifacts: dict = None) -> dict
```

Bir nechta snapshot berilishi muhim: **scorer ko'p hostga tegadi, C2 odatda kamiga.**

Qaytadi:

```python
{
  'candidates': [
    {
      'value': '10.10.0.5',
      'kind': 'checker_ip',            # checker_ip | agent_port | agent_service | push_target
      'confidence': 'yuqori',          # yuqori | o'rta | past
      'evidence': ["3 ta hostning connections ida uchradi",
                   "7 xil ichki port bilan gaplashgan"],
      'model': 'to\'g\'ridan-to\'g\'ri',
      'targets': [{'host': 'web-prod-01', 'port': 80, 'proto': 'tcp'}, ...],
    },
  ],
  'agents': [
    {'host': 'web-prod-01', 'port': 10050, 'process': 'zabbix_agentd.exe',
     'product': 'Zabbix Agent',
     'config_hint': 'zabbix_agentd.conf — UserParameter= qatorlari tekshiruvlar ro\'yxati',
     'service': 'Zabbix Agent'},
  ],
  'warnings': ["..."],   # o'zbekcha ogohlantirishlar
}
```

### Aniqlash qoidalari (ball beriladi, eng yuqorisi birinchi)

1. Bitta tashqi IP bir nechta **snapshotda** uchrasa → `yuqori` (scorer ko'p hostga tegadi)
2. O'sha IP ko'p xil ichki portga ulangan bo'lsa → `yuqori`, model `to'g'ridan-to'g'ri`,
   `targets` to'ldiriladi — **bu baholanadigan xizmatlar ro'yxati**
3. Ma'lum monitoring porti tinglanayotgan bo'lsa → `agents` ga:
   `10050 Zabbix`, `10051 Zabbix server`, `5666 NRPE`, `9100 node_exporter`,
   `161 SNMP`, `5985/5986 WinRM`, `4949 Munin`, `12489 Nagios NSClient++`
4. Xizmat nomi/binary da `zabbix|nagios|nrpe|prometheus|exporter|check_mk|munin|nsclient`
   uchrasa → `agents`
5. Bir nechta hostdan **bitta** tashqi IP ga chiquvchi ulanish → `push_target`
6. `log_artifacts['checker_ips']` da bo'lsa → ishonch bir pog'ona oshadi

Ichki IP lar (10/8, 172.16/12, 192.168/16) "tashqi" hisoblanmaydi, lekin scorer ichki
tarmoqda ham bo'lishi mumkin — shuning uchun **ichki IP ni ham ko'rib chiqing**,
faqat ishonchini pasaytiring va `evidence` da ayting.

### Tekshiruv konfigini yasash

```python
def to_sla_config(discovery: dict) -> dict
```

`candidates[*].targets` dan 1-qismdagi YAML tuzilmasini yasaydi: har bir
`(host, port)` uchun `tcp` tekshiruvi, 80/443 bo'lsa qo'shimcha `http`.
`name` avtomatik (`<host>:<port>`), `board_name` bo'sh — uni analitik qo'lda to'ldiradi.

### Allowlist chiqishi

```python
def to_allowlist(discovery: dict) -> dict
```

Topilgan checker IP lari, agent portlari va xizmat nomlari — "BULARGA TEGMANG"
ro'yxati. `bluekit/hunt/allowlist.yaml` formatiga mos bo'lsin (uni o'qib formatini
ko'ring, **o'zgartirmang**).

Bu muhim: push-agent chiquvchi davriy ulanish qiladi va `bk hunt beacons` uni C2
sifatida YUQORI ball bilan chiqaradi. Uni o'chirgan jamoa o'z ballini o'ldiradi.

### Agent konfigini o'qish (ixtiyoriy kirish)

```python
def parse_agent_config(path: str) -> list
```

Faqat ikki format: **Zabbix** (`UserParameter=<kalit>,<buyruq>`) va
**NRPE** (`command[<nom>]=<buyruq>`). Har biridan `{'key': ..., 'command': ...}`
chiqadi — bu scorer aynan nimani tekshirayotganini ko'rsatadi.

Boshqa formatlarni **taxmin qilmang** — `ValueError` yoki bo'sh ro'yxat va
`warnings` da "format tanilmadi".

---

## 3-qism · Testlar (`tests/test_sla.py`, YANGI fayl)

Stub bilan **o'tmaydigan** testlar kerak. Eng muhimi 2-test.

1. **Ochiq port** — test ichida `socket` bilan lokal tinglovchi oching (port 0 =
   ixtiyoriy), `tcp` tekshiruvi `ok: True` qaytarsin.
2. **Yopiq port** — tinglovchini yoping, o'sha portga `tcp` tekshiruvi
   **`ok: False`** qaytarsin. *(Eski stub bu testda yiqiladi — maqsad shu.)*
3. **HTTP** — `http.server` bilan lokal server ko'taring: `expect_status: 200` o'tsin,
   `expect_status: 404` yiqilsin, `expect_contains` ishlasin.
4. **Uch holat:** kritik o'tgan + kritik bo'lmagan yiqilgan → `degraded`;
   kritik yiqilgan → `down`; hammasi o'tgan → `ok`.
5. **`file_hash` / `file_absent`** — vaqtinchalik fayl bilan (`tempfile`).
6. **Istisno tashlamaslik** — mavjud bo'lmagan host (`10.255.255.1:1`),
   noto'g'ri URL, bo'lmagan fayl: hammasi `ok: False` qaytarsin, exception emas.
7. **Orqaga moslik** — `check(config)` ro'yxat qaytaradi va har elementda `name`
   hamda `ok` bor (eski chaqiruvchilar buzilmaydi).
8. **`watch(..., iterations=2)`** — ikki aylanishda to'xtaydi; holat o'zgarganda
   `on_change` chaqiriladi (tinglovchini o'rtada yopib tekshiring).
9. **Discovery — to'g'ridan-to'g'ri model:** uchta sun'iy snapshot yasang, ularning
   `connections` ida bitta tashqi IP (masalan `203.0.113.7`) har xil ichki portlarga
   ulangan bo'lsin → `candidates[0]['value']` o'sha IP, `confidence` `yuqori`,
   `targets` uzunligi to'g'ri.
10. **Discovery — agent:** snapshotda `listening_ports` da 10050 va
    `services` da `zabbix_agentd` bo'lsin → `agents` bo'sh emas, `product` `Zabbix`.
11. **Discovery — C2 ni checker deb belgilamasin:** bitta hostdan bitta tashqi IP ga
    bitta ulanish (C2 ga o'xshash) → u `yuqori` ishonch olmasin.
12. **`to_sla_config`** — discovery natijasidan yasalган konfig 1-qismdagi
    `check()` ga berilganda istisnosiz ishlasin.
13. **`parse_agent_config`** — vaqtinchalik Zabbix va NRPE konfig fayllari bilan.

## 4-qism · Qabul

```
python -m unittest discover -s tests -p "test_*.py" -q
python -c "from bluekit.resp.sla import check; import yaml; print(check(yaml.safe_load(open('responder/sla.example.yaml'))))"
```

Hozir **73 ta test** yashil — hammasi yashil qolsin, ustiga yangilari qo'shilsin.

`bk.py` ga tegmaysiz, shuning uchun CLI ni men ulayman. Lekin modul mustaqil
sinaladigan bo'lsin: `python -c "..."` bilan yuqoridagidek chaqirib ko'ring va
**chiqishini hisobotga ko'chiring**.

Hisobotda yana:
- 1 va 2-testlarning (ochiq/yopiq port) natijasi
- `unittest` chiqishining oxirgi 3 qatori
- Yangi fayllarning qator soni

Bajara olmagan qismni ochiq yozing. Bu modul musobaqada ball keltiradi —
"simulated" qaytaradigan ikkinchi versiya kerak emas.
