# SPEC_PLAYBOOK_WEB — Playbook tabi (web UI)

Loyiha: `D:\Claude Projects\CTF\blue-kit-staging`

Backend **allaqachon tayyor va ishlaydi**: `bluekit/playbook.py` (6 faza, 42 qadam,
7 kill-chain bosqichi, 10 qoida) va `bluekit/web/server.py` dagi 4 ta endpoint.
Frontendda esa Playbook tabi **umuman yo'q** — `app.js` va `index.html` ichida
`playbook` so'zi bitta marta ham uchramaydi. Shuni yasash kerak.

Maqsad: musobaqa paytida jamoa web UI ni ochganda birinchi ko'radigan ekran —
"hozir qaysi qadamdamiz, nimasi bajarildi, nimasi yo'q, hujum kill-chain ning
qaysi bosqichigacha isbotlangan".

## 0. Asosiy qoidalar

**Mantiq va MA'LUMOTNI TAKRORLAMANG.** Fazalar, qadamlar, buyruqlar, kill-chain
bosqichlari, texnika ID lari, qoidalar matni — hammasi `GET /api/playbook` dan
keladi. Bularning birortasi ham `app.js` yoki `index.html` ichiga **ko'chirilmasin**.
Buni test tekshiradi: `app.js` va `index.html` ichida `Razvedka`, `T1566.001`,
`exfil-large-upload`, `Checker IP ni aniqlamaguncha` satrlari BO'LMASLIGI shart.

**TEGMANG (faqat o'qing):** `bluekit/playbook.py`, `bk.py`, `bluekit/siem/**`,
`bluekit/resp/**`, `bluekit/logs/**`, `bluekit/ir/**`, mavjud `tests/test_*.py`.

**O'zgartiriladigan fayllar:** `bluekit/web/static/index.html`,
`bluekit/web/static/app.js`, `bluekit/web/static/style.css`.
**Yangi fayl:** `tests/test_playbook_web.py`.

`bluekit/web/server.py` ga **tegish shart emas** — endpointlar bor. Agar biror
zarurat chiqsa, faqat qo'shimcha `elif` shoxi qo'shing, mavjud kodni qayta yozmang.

**DIQQAT — oldingi topshiriqlarda aynan shu yerda xato bo'lgan:**

1. Fayllar faqat **O'SISHI** kerak. Hozir: `app.js` 92414 bayt / 2010+ qator,
   `index.html` 42539 bayt, `style.css` 32659 bayt. Birorta mavjud funksiya,
   tab yoki CSS klassi o'chib ketsa — topshiriq bajarilmagan hisoblanadi.
   Mavjud funksiyalarni "tozalash"/"qisqartirish"/"refaktor qilish" TAQIQLANADI.
2. **Javob strukturasini TAXMIN QILMANG.** Quyida 1-bo'limda har bir endpointning
   aniq JSON shakli yozilgan — o'sha maydon nomlarini ishlating. Ishonchingiz
   komil bo'lmasa `python -c "from bluekit import playbook; ..."` bilan chiqishni
   o'zingiz chop etib ko'ring. (O'tgan safar SIEM tabida frontend `r.hunt.mitre`
   kabi ichma-ich strukturani kutgan, backend esa tekis javob bergan — barcha
   Python testlari yashil bo'lgani holda brauzerda tab ishlamagan.)
3. Ishni tugatishdan oldin `python bk.py web` ni ishga tushirib, brauzerda
   **haqiqatan bosib ko'ring**: status tugmasi, KC tanlagich, filtr, reset.

## 1. API — javoblarning ANIQ shakli

### `GET /api/playbook`

```json
{
  "phases": [
    {
      "id": "0",
      "title_uz": "Tayyorgarlik (musobaqa boshlanishidan oldin)",
      "goal_uz": "Bir marta qilinadi. ...",
      "steps": [
        {"id": "0.1", "title_uz": "...", "cmd": null, "kc": [], "must": true, "note": "..."},
        {"id": "1.1", "title_uz": "...", "cmd": "bk siem query ...", "kc": ["actions"], "must": true, "note": null}
      ]
    }
  ],
  "kill_chain": [
    {
      "key": "recon", "num": 1,
      "name_en": "Reconnaissance", "name_uz": "Razvedka",
      "desc": "...",
      "tactics": ["Reconnaissance", "Discovery"],
      "techniques": ["T1595", "T1590"],
      "hunts": ["net-port-scan"],
      "tools": ["bk siem query net-port-scan"],
      "evidence": "..."
    }
  ],
  "rules": [{"id": "C-1", "title_uz": "...", "body_uz": "..."}],
  "state": {
    "steps": {"0.2": {"status": "done", "note": "", "ts": "2026-09-24T07:00:00+00:00"}},
    "kc": {"c2": {"status": "confirmed", "evidence": "matn", "ts": "..."}},
    "updated": null
  },
  "progress": {
    "phases": [{"id": "0", "title_uz": "...", "total": 7, "done": 1, "skip": 0,
                "doing": 0, "blocked": 0, "todo": 6, "must_total": 6,
                "must_done": 1, "percent": 14}],
    "overall": {"total": 42, "done": 1, "percent": 2, "must_total": 30, "must_done": 1},
    "kill_chain": [{"key": "c2", "num": 6, "name_uz": "...", "name_en": "...",
                    "status": "confirmed", "evidence": "...", "steps_total": 7,
                    "steps_done": 0, "covered": false}],
    "next": [{"id": "0.1", "phase": "0", "title_uz": "...", "cmd": null, "must": true}]
  },
  "warning": "playbook.json o'qilmadi, holat tiklandi"     // ixtiyoriy, bo'lmasligi mumkin
}
```

Raqamlar bugun: **6 faza, 42 qadam, 7 kill-chain bosqichi, 10 qoida, 30 majburiy
qadam**. Bularni JS ichiga konstanta qilib yozmang — massiv uzunligidan oling.

**Ikki xil `note` bor, ularni ARALASHTIRMANG:**
- `phases[].steps[].note` — playbook ichidagi **maslahat/ogohlantirish** (faqat
  o'qiladi, o'zgartirilmaydi). UI da "Eslatma" deb ko'rsating.
- `state.steps[<id>].note` — **analitik o'zi yozadigan izoh** (saqlanadi).
  UI da "Izoh" deb ko'rsating.

### `POST /api/playbook/step`

So'rov: `{"id": "1.1", "status": "done", "note": "ixtiyoriy matn"}`
`status` ∈ `todo | doing | done | skip | blocked`. Noto'g'ri `id` → HTTP 400.
Javob: `{"ok": true, "state": {...}, "progress": {...}}` — `progress` xuddi
yuqoridagidek to'liq. Ya'ni **qayta `GET /api/playbook` qilish shart emas**,
javobdan progressni to'g'ridan-to'g'ri yangilang.

### `POST /api/playbook/kc`

So'rov: `{"key": "c2", "status": "confirmed", "evidence": "matn"}`
`status` ∈ `unknown | suspected | confirmed | ruled_out`. Noto'g'ri `key` → 400.
Javob step dagidek.

### `POST /api/playbook/reset`

So'rov: `{}`. Hamma holatni tozalaydi. Javob step dagidek.

Holat `<workdir>/playbook.json` da saqlanadi va server qayta ishga tushsa ham
qoladi.

## 2. Tab va navigatsiya (`index.html`)

Hozirgi nav:
```
📖 KB (ATT&CK) | 📊 Logs Analyzer | ⚡ IR Attack Chain | 🛰 C2 Hunt |
🔍 SIEM So'rov | 🛡 Responder | 🎯 CTF Tracker | 📑 Report Generator
```

**Playbook tabi eng BIRINCHI bo'ladi va sahifa ochilganda o'sha aktiv bo'ladi**
(musobaqada birinchi ko'rinadigan ekran — "endi nima qilaman"):

```html
<button class="tab-btn active" onclick="showTab('playbook')">📋 Playbook</button>
<button class="tab-btn" onclick="showTab('kb')">📖 KB (ATT&amp;CK)</button>
...
```

Ya'ni KB tugmasidan `active` klassini olib tashlang va `<div id="kb"
class="tab-content active">` dan ham `active` ni olib tashlab, yangi
`<div id="playbook" class="tab-content active">` ga bering. Boshqa tablarga
tegmang.

`app.js` dagi `showTab(id)` funksiyasiga bitta qator qo'shing (mavjud
`if (id === 'tracker') loadTracker();` yonига):
```js
if (id === 'playbook') loadPlaybook();
```
Sahifa yuklanganda ham bir marta `loadPlaybook()` chaqirilsin (mavjud
`DOMContentLoaded` bloki ichida, `initClock()` yonida).

## 3. Playbook tabining tarkibi

Mavjud CSS klasslarini ishlating: `hud-ribbon`, `hud-tile`, `card`, `card-hud`,
`card-title`, `section-title`, `helper-text`, `field-label`, `btn`,
`btn-primary`, `btn-secondary`, `btn-sm`, `brand-badge`, `badge`,
`table-responsive`. Yangi klass faqat zarur bo'lganda qo'shing va
`style.css` ning OXIRIGA `/* ===== PLAYBOOK ===== */` bloki sifatida yozing.

Tab ichi 5 ta blokdan iborat, shu tartibda:

### 3.1 Yuqori HUD lenta — umumiy progress

`hud-ribbon` ichida 4 ta `hud-tile`:
1. **Umumiy**: `overall.done`/`overall.total` va `overall.percent`% (katta raqam).
2. **Majburiy**: `overall.must_done`/`overall.must_total` — agar teng bo'lmasa
   sariq/qizil rangda (bu ballga to'g'ridan-to'g'ri ta'sir qiladigan qadamlar).
3. **Kill-chain**: `confirmed` statusli bosqichlar soni / 7.
4. **Oxirgi yangilanish**: `state.updated` yoki holatdagi eng oxirgi `ts`,
   lokal vaqt formatida; bo'sh bo'lsa `—`.

Lentaning tagida gorizontal progress bar (`overall.percent`).

### 3.2 "Keyingi qadamlar" kartasi

`progress.next` (maksimum 3 ta) — backend majburiy qadamlarni oldin qaytaradi.
Har biri uchun: `id`, `title_uz`, `must` bo'lsa **MAJBURIY** badge, `cmd` bo'lsa
`<code>` + nusxalash tugmasi (mavjud `copyText(text, event)`), va darhol
`done` / `doing` qilib qo'yadigan ikkita kichik tugma.

Agar `progress.next` bo'sh bo'lsa: "Barcha qadamlar yopilgan" degan matn.

### 3.3 Cyber Kill Chain paneli

7 ta bosqich, `num` bo'yicha tartibda, gorizontal (kichik ekranda wrap bo'ladi).
Har bir bosqich kartasi:

- Sarlavha: `num`. `name_uz` va kichikroq shriftda `name_en`.
- **Status tanlagich** — 4 ta tugma (yoki `<select>`): `unknown` / `suspected` /
  `confirmed` / `ruled_out`, uzbekcha yorliqlar bilan:
  `Noma'lum` / `Shubha bor` / `Tasdiqlandi` / `Rad etildi`.
  Ranglar: unknown = kulrang, suspected = sariq, confirmed = qizil
  (bu bosqich haqiqatan sodir bo'lgan!), ruled_out = yashil.
- `steps_done`/`steps_total` — shu bosqichga bog'langan qadamlar.
  `covered === true` bo'lsa ✔ belgisi.
- `desc` matni.
- `evidence` uchun bitta qatorli input: analitik dalilni yozadi
  (masalan "4698 vazifa, host WS-07"). `change`/`blur` da saqlanadi.
  Saqlanganda `showToast()` bilan tasdiq.
- `techniques` chiplari: har biri bosilganda mavjud
  `showMitreModal(attackId, event)` chaqiriladi (KB modalini ochadi).
- `hunts` chiplari: bosilganda `bk siem query <hunt-id> --siem qradar --days 7`
  buyrug'i clipboardga ko'chiriladi (`copyText`) va toast chiqadi.
- `tools` ro'yxati `<code>` ko'rinishida, har birida nusxalash tugmasi.
- `evidence` (statik, `kill_chain[].evidence`) — "Nimaga qarash kerak" matni.
  Buni analitikning `state.kc[].evidence` inputi bilan ARALASHTIRMANG:
  statik matn "Qayerdan qidiriladi" deb, input esa "Bizning dalilimiz" deb
  belgilansin.

**Bosqich kartasini bosish → filtr:** o'sha bosqichga bog'langan qadamlar
(`steps[].kc` ichida shu `key` bor qadamlar) qolgan qismda ajratib ko'rsatiladi,
boshqalari yashiriladi. Karta ustida "Filtr yoqilgan" belgisi va yuqorida
"✕ Filtrni tozalash" tugmasi chiqadi. Qayta bosilsa filtr o'chadi.

### 3.4 Fazalar va qadamlar

6 ta faza ketma-ket. Har bir faza sarlavhasi: `id` + `title_uz`, o'ng tomonda
`progress.phases[]` dan `done`/`total`, `percent`% mini-bar va
`must_done`/`must_total`. Faza ochiladi/yopiladi (`<details>` yoki tugma bilan);
boshlang'ich holatda **hammasi ochiq**.

Har bir qadam qatori:

| Nima | Qayerdan |
|---|---|
| `id` (masalan `4.2`) | `steps[].id` |
| Sarlavha | `steps[].title_uz` |
| **MAJBURIY** badge | `steps[].must === true` |
| Kill-chain chiplari | `steps[].kc` — har biri `num` + `name_uz`, bosilsa 3.3 dagi filtr yoqiladi |
| Buyruq | `steps[].cmd` — `<code>` + nusxalash tugmasi; `null` bo'lsa "qo'lda bajariladi" |
| Eslatma | `steps[].note` (statik maslahat), bo'lsa kichik kursiv matn |
| Status | `state.steps[id].status`, default `todo` |
| Izoh | `state.steps[id].note` — input, `blur` da saqlanadi |
| Vaqt | `state.steps[id].ts` — lokal vaqtda, `done`/`skip` bo'lganda ko'rsatiladi |

Status uchun 5 ta tugma: `Boshlanmagan` (todo) / `Jarayonda` (doing) /
`Bajarildi` (done) / `O'tkazildi` (skip) / `Bloklangan` (blocked).
Aktiv status tugmasi ajralib turadi. Ranglar: todo kulrang, doing ko'k,
done yashil, skip so'nik, blocked qizil.

Bosilganda darhol `POST /api/playbook/step` yuboriladi va javobdagi `progress`
bilan **butun ekran qayta chiziladi** (HUD, keyingi qadamlar, kill-chain
hisoblari, faza barlari) — sahifa yangilanmasdan.

Faza ustida filtr tugmalari: `Hammasi` / `Faqat majburiy` / `Faqat bajarilmagan`
(todo + doing + blocked). Bu 3.3 dagi kill-chain filtri bilan birga ishlaydi
(ikkalasi ham yoqilsa — kesishma).

### 3.5 Qoidalar paneli

`rules` (10 ta, `C-1`..`C-10`) — yopiladigan (`<details>`) ro'yxat,
`id` + `title_uz` sarlavha, `body_uz` ichida. Boshlang'ich holatda **yopiq**.

Eng pastda: **"🗑 Holatni tozalash"** tugmasi. Bosilganda `confirm()` so'raydi
("Barcha belgilangan qadamlar va kill-chain holati o'chiriladi. Davom etasizmi?"),
tasdiqlansa `POST /api/playbook/reset`.

## 4. Xatolar va chegaraviy holatlar

- Fetch xato bersa yoki javobda `error` bo'lsa — tab ichida qizil xabar
  ("Playbook yuklanmadi: <sabab>") va "Qayta urinish" tugmasi. Sahifa
  oq ekran bo'lib qolmasin.
- `warning` maydoni kelsa — sariq banner sifatida ko'rsating.
- Matnlar `escapeHtml()` dan o'tkazilsin (izoh va dalil inputlari
  foydalanuvchi kiritadigan matn).
- Hech qanday tashqi kutubxona, CDN, font yoki ikonka yuklanmasin — musobaqa
  **offline**. Faqat vanilla JS.
- Ikki marta tez bosilganda ikkita so'rov ketmasin — oddiy "yuborilyapti" flagi
  yetarli.

## 5. Testlar — `tests/test_playbook_web.py`

`tests/test_web.py` dagi uslubni ishlating (`WebKitServer` ni thread da ko'tarish,
`urllib`). Kamida:

1. `GET /api/playbook` → 200, `phases` 6 ta, jami qadamlar 42, `kill_chain` 7 ta,
   `rules` 10 ta, `progress.overall.total == 42`.
2. `POST /api/playbook/step` `{"id":"1.1","status":"done"}` → `ok`, javobdagi
   `progress.overall.done == 1`, va keyingi `GET` da ham `done` qolgan
   (fayl saqlanishini tekshiradi).
3. `POST /api/playbook/step` noto'g'ri id (`"9.9"`) → HTTP 400.
4. `POST /api/playbook/kc` `{"key":"c2","status":"confirmed"}` → `progress.kill_chain`
   ichida `c2` ning statusi `confirmed`.
5. `POST /api/playbook/kc` noto'g'ri key (`"yoq"`) → HTTP 400.
6. `POST /api/playbook/reset` → `overall.done == 0`.
7. **Statik fayl testi:** `index.html` ichida `showTab('playbook')` va
   `id="playbook"` bor; `app.js` ichida `loadPlaybook` va `/api/playbook/step`
   bor.
8. **Takrorlanmaslik testi:** `app.js` va `index.html` ichida `Razvedka`,
   `T1566.001`, `exfil-large-upload`, `Checker IP ni aniqlamaguncha` satrlari
   YO'Q (ma'lumot faqat API dan keladi).

Barcha mavjud testlar ham yashil qolishi kerak:
```
python -m unittest discover -s tests -v
```

## 6. Qabul mezonlari

- [ ] `python -m unittest discover -s tests` — hammasi yashil (avvalgi 181 + yangi).
- [ ] `python bk.py web` → brauzerda Playbook tabi birinchi va ochiq turadi.
- [ ] Qadam statusini bosganda yuqoridagi foiz va "Keyingi qadamlar" darhol
      o'zgaradi, sahifa yangilanmaydi.
- [ ] Serverni o'chirib qayta yoqqanda belgilangan statuslar joyida.
- [ ] Kill-chain bosqichini `confirmed` qilganda HUD dagi hisob o'zgaradi.
- [ ] Bosqich kartasini bosganda faqat o'sha bosqichga tegishli qadamlar qoladi.
- [ ] `app.js`, `index.html`, `style.css` faqat kattalashgan; birorta mavjud
      funksiya yoki tab yo'qolmagan.
- [ ] Hisobotda har bir fayl uchun **oldingi va keyingi qator sonini** yozing.
