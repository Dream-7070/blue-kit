# FEEDBACK_KNOWNGOOD — tuzatish kerak bo'lgan 7 ta nuqta

Asosiy natija yaxshi: baselinesiz `high` soni 2 dan 5 ga ko'tarildi va ro'yxat
haqiqiy nomlardan tuzilgan. Quyidagilar tuzatilsa topshiriq yopiladi.

`SPEC_KNOWNGOOD.md` dagi barcha cheklovlar kuchda qoladi (mavjud funksiyalarni
qayta yozmaslik, `analyze()` imzosi o'zgarmasligi, 189 ta eski test yashil qolishi).

---

## 1. `checker_admin` — soxta ma'lumot, olib tashlang

`bluekit/resp/knowngood.yaml` ning `windows.users` bo'limiga `checker_admin`
qo'shilgan. Bu **noto'g'ri**: `checker_admin` OS standart akkaunti emas, u shu
musobaqaning o'ziga xos nomi. Faylning ma'nosi "har qanday Windows da bor
akkauntlar" — unga musobaqaga xos nom qo'shilsa, ro'yxat ishonchini yo'qotadi va
hujumchi shu nomni qo'yib yashirinishi mumkin bo'ladi.

**Qiling:** `checker_admin` ni `knowngood.yaml` dan o'chiring.

Test (`test_behavior_baseline_none`) dagi `assertNotIn('checker_admin', high_items)`
shartini haqiqiy mexanizm bilan ta'minlang — checker akkaunti `protected` ro'yxati
orqali himoyalanadi (musobaqada ham shunday: `bk resp discover --allowlist-out`):

```python
f, ex = analyze(self.kb, self.cur, baseline=None, protected=['checker_admin'])
...
ch = [x for x in f if x['item'] == 'checker_admin']
self.assertTrue(all(x['protected'] for x in ch))   # PROTECTED belgisi bor
self.assertNotIn('checker_admin', high_items)
```

## 2. Windows xizmat nomlaridan 11 tasini olib tashlang

Quyidagilar haqiqiy Windows xizmat nomlari EMAS (ular display name, qisqartma yoki
xato yozilgan). Ro'yxatda turishi xavfli: shu nomdagi zararli xizmat jimgina
ishonchli deb hisoblanadi.

O'chiring: `smb`, `rpc`, `wmi`, `wmic`, `spool`, `workstation`, `sntp`,
`eventmanager`, `sysmonlog`, `pnroesvc`, `wcspluginstervice`

Sabablari: xizmat nomi `LanmanServer` (`smb` emas), `RpcSs`/`RpcEptMapper`
(`rpc` emas), `Winmgmt` (`wmi` emas), `Spooler` (`spool` emas),
`LanmanWorkstation` (`workstation` emas). `sysmonlog` eski XP/2003 xizmati va
`Sysmon` ga o'xshab ketadi — ayniqsa xavfli.

Qo'shing: `winmgmt`, `rpceptmapper`, `wcsplugInservice` (to'g'ri yozilishi:
`wcspluginservice`), `pnrpautoreg`

Yakuniy son baribir ≥ 120 bo'lib qoladi (132 − 11 + 4 = 125).

## 3. `susp_locs` vaznini 0.2 ga qaytaring

`calc_score()` da shubhali papka balli `0.2` dan `0.35` ga ko'tarilgan
(izoh: `# boost to ensure 0.35 + 0.25 = 0.60 -> high`). Bu **mavjud detektorning
sozlamasini** o'zgartiradi va baseline BOR rejimga ham ta'sir qiladi — ya'ni
testni o'tkazish uchun butun tizim qayta sozlangan.

Bu kerak emas: `Updater` baribir `0.25 (kg yo'q) + 0.3 (shubhali nom) + 0.2
(shubhali papka) = 0.75` bilan `high` bo'ladi. Vaznni `0.2` ga qaytaring va
testlar baribir o'tishini tasdiqlang.

## 4. Known-good akkauntlar sababsiz `med` bo'lib chiqyapti

Hozir baselinesiz natijada:

```
0.35 med  users  Administrator   []      <- reasons BO'SH
0.35 med  users  checker_admin   []      <- reasons BO'SH
```

Sababi: `is_admin` shoxidagi `else: has_strong = True` ("old tests uchun") va
chaqiruv joyidagi `max(s, 0.35 if (is_admin and baseline is None) else 0)`.
Natijada analitik ro'yxatda sababsiz qatorni ko'radi va nima uchun turganini
tushunmaydi — bu aynan biz kamaytirmoqchi bo'lgan shovqin.

**Qiling:** known-good akkaunt (`is_kg=True`) baselinesiz rejimda `max(..., 0.35)`
ni olmasin va `med` bo'lmasin. Agar boshqa hech qanday signal yo'q bo'lsa,
u umuman topilmalar ro'yxatiga tushmasin. Tushgan taqdirda ham sababi bo'lsin:
`"OS standart akkaunt"`.

## 5. `hosts_file` baselinesiz umuman ko'rinmayapti — bu 1-kun stsenariysining asosiy artefakti

Namunadagi soxta bank yozuvi:

```
91.238.50.10 ibank.example.uz
```

- toza baseline bilan: `0.40 high` ✅
- baselinesiz: **topilmalar ro'yxatida umuman yo'q** ❌

Sababi: `for h in current.get('hosts_file', ...)` sikli `if has_strong:` bilan
himoyalangan, `has_strong` esa faqat `is_new and baseline is not None` dan keladi.
Sizning `+0.25` shoxingiz (to'g'ri qaror bilan) `has_strong` ni yoqmaydi, shuning
uchun baselinesiz butun kategoriya tushib qoladi.

Bu 1-kun stsenariysida (phishing → buxgalter → soxta bank o'tkazmasi) eng muhim
dalil, shuning uchun alohida qoida kerak:

**`hosts_file` yozuvi loopback BO'LMAGAN IP ga ishora qilsa** (ya'ni `127.`,
`::1`, `0.0.0.0` emas) — `has_strong = True`, sabab `"hosts faylida tashqi IP"`,
ball kamida `0.4`, va `T1565.001` texnikasi qo'shiladi (bu allaqachon bor).
Bu baseline bor-yo'qligidan qat'i nazar ishlasin.

Test qo'shing: `analyze(kb, cur, baseline=None)` natijasida `91.238.50.10`
yozuvi bor va `high`.

Xuddi shu mantiqni `cron`, `wmi_subscriptions`, `ssh_authorized_keys` uchun
takrorlash SHART EMAS — faqat `hosts_file` ni tuzating.

## 6. `paths` o'zgaruvchisi modul nomini soyalaydi

`is_known_good()` ichida:

```python
paths = os_kg.get('service_paths', [])
```

`paths` — bu `from bluekit import paths` bilan import qilingan MODUL nomi.
Hozir tasodifan ishlayapti (funksiya ichida modul ishlatilmaydi), lekin keyin
o'sha funksiyaga `paths.get_resource_path(...)` qo'shilsa `UnboundLocalError`
bilan quladi. **`kg_paths` deb nomlang** (ikkala joyda: services va autoruns).

Shu bilan birga `except:` ni `except Exception:` qiling.

## 7. Testlar haqiqiy KB bilan ham yurgizilsin

`tests/test_knowngood.py` da `self.kb = None`. Haqiqiy CLI esa doim KB uzatadi va
`get_kb_hit()` ning xulqi KB bor/yo'qligiga qarab farq qiladi — ya'ni hozirgi
testlar ishlab turgan yo'lni tekshirmayapti.

`tests/test_web.py` dagidek KB ni yuklang (yo'q bo'lsa `skipTest`) va
**kamida `test_behavior_baseline_none` ni haqiqiy KB bilan** ham yurgizing:

```python
from bluekit.paths import get_kb_path
from bluekit.kb.query import KB
kb_path = get_kb_path()
if not os.path.exists(kb_path):
    raise unittest.SkipTest("KB not built")
self.kb = KB(kb_path)
```

Haqiqiy KB bilan kutilayotgan natija (o'lchangan): `high` ≥ 5 va ichida
`Updater` (tasks), `Updater` (autoruns), `admin` (users), `45.142.212.61`
(connections), `91.238.50.10 ibank.example.uz` (hosts_file, 5-punktdan keyin).

---

## Qabul mezonlari

- [ ] `python -m unittest discover -s tests` — hammasi yashil.
- [ ] `knowngood.yaml` da `checker_admin` yo'q; `windows.services` ≥ 120 va
      2-punktdagi 11 ta nom yo'q.
- [ ] `susp_locs` balli `0.2`.
- [ ] Baselinesiz natijada sababsiz (`reasons == []`) topilma yo'q.
- [ ] Baselinesiz natijada `91.238.50.10 ibank.example.uz` bor va `high`.
- [ ] Hisobotda: o'chirilgan/qo'shilgan nomlar ro'yxati va har bir fayl uchun
      oldingi/keyingi qator soni.
