# SPEC_TRACKER_WEB — CTF Tracker tabi: urinishlar, limit, tahrirlash (FRONTEND)

Loyiha: `D:\Claude Projects\CTF\blue-kit-staging`

Backend (`bluekit/tracker.py`, `server.py` endpointlari) ALOHIDA topshiriqda
qilinmoqda — uning API shakli quyida ANIQ berilgan. Python fayllarga TEGMANG.

## 0. Asosiy qoidalar

**O'zgartiriladigan:** `bluekit/web/static/app.js` — FAQAT
`// ==================== Tracker Functions ====================` bo'limi
(`loadTracker`, `trkAdd`, `trkDel`, `trkValidateAll`) va unga yangi funksiyalar;
`bluekit/web/static/index.html` — FAQAT `<div id="tracker" class="tab-content">`
ichidagi forma; `bluekit/web/static/style.css` — faqat oxiriga yangi `.trk-*` klasslar.

**TEGMANG:** barcha `.py` fayllar, `app.js` dagi boshqa bo'limlar (jumladan
`addToTrackerForm`, `trackerBtn`, `api`, `renderTable`, `escapeHtml`, `showTab`),
`index.html` dagi boshqa tablar.

Fayllar faqat **O'SISHI** kerak. Hozir: `app.js` 2598 qator, `index.html` 827,
`style.css` 1563. Faylni qayta yozmang — faqat tracker bo'limini tahrirlang.

**Unicode:** UTF-8, LF qator oxiri saqlansin. O'tgan topshiriqlarda mavjud emoji
(`🔗`, `◀`, `🗺`, `📋`, `✔`) jimgina `-`, `?`, `??` ga aylangan edi — bu QABUL
QILINMAYDI. Topshirishdan oldin `app.js` va `index.html` da `??` qidirib ko'ring.

**Xavfsizlik / escaping:** foydalanuvchi matni (savol, nomzod, dalil, javob)
`innerHTML` ga FAQAT `escapeHtml()` orqali tushadi. Foydalanuvchi matnini
`onclick="f('${...}')"` ichiga QO'YMANG (apostrof va `\` JS ni buzadi — `escapeHtml`
`'` ni `&#039;` qiladi, brauzer uni atributda qayta `'` ga aylantiradi). Buning
o'rniga: `data-*` atribut (`data-v="${escapeHtml(x)}"`) + `onclick="f(this.dataset.v)"`,
yoki qator `id` si (32-belgili hex — xavfsiz) + indeks orqali ma'lumotni
`window.trkRows` dan olish. Mavjud `showMitreModal('${escapeHtml(r.candidates)}')`
chaqiruvi ham shu usulga o'tkazilsin.

## 1. API (backend tayyorlaydi — aynan shu shakl)

`GET /api/tracker` → qatorlar ro'yxati:
```json
[{
  "id": "hex", "question": "...", "candidates": "T1566.001, T1204.002",
  "evidence": "...", "status": "tekshirilmoqda",
  "max_attempts": 3,               // yoki null
  "attempts": [{"answer": "T1566.001", "result": "rejected", "at": "2026-10-05T08:51:02Z"}],
  "used": 1, "remaining": 2,       // remaining: max null bo'lsa null
  "solved": false,                 // accepted urinish bormi
  "exhausted": false               // max bor, used>=max va solved emas
}]
```
Xato bo'lsa `{"error": "..."}` (masalan tracker.json buzilgan).

- `POST /api/tracker` `{question, candidates, evidence, status, max_attempts}` →
  200 `{id, row}` | 400 `{error}` (bo'sh savol, noto'g'ri max).
- `PUT /api/tracker/<id>` — istalgan `{question, candidates, evidence, status, max_attempts}`
  (`max_attempts: ""` → limitni olib tashlaydi) → 200 `{success, row}` | 400 | 404.
- `DELETE /api/tracker/<id>` → 200.
- `POST /api/tracker/<id>/check` `{answer}` → 200 `check` (hech narsa yozmaydi).
- `POST /api/tracker/<id>/attempts` `{answer, result, force}` →
  200 `{row, check, ledger_warning?}` |
  **409** `{error, needs_confirm: true, check}` |
  400/404 `{error}`.
- `PUT /api/tracker/<id>/attempts/<n>` `{result}` → 200 `{row}`.
- `DELETE /api/tracker/<id>/attempts/<n>` → 200 `{row}`.

`check` shakli:
```json
{"answer": "T1566.001", "used": 2, "max": 3, "remaining": 1,
 "duplicate": false, "duplicate_of": null, "over_limit": false,
 "last_attempt": true, "already_accepted": false,
 "warnings": ["Diqqat: bu OXIRGI urinish (2/3 ishlatilgan)"], "ok": false}
```
`result` qiymatlari: `accepted` | `rejected` | `pending`.

**Muhim:** mavjud `api()` yordamchisi HTTP status kodini qaytarmaydi — u faqat
`JSON.parse(text)` natijasini qaytaradi. Shuning uchun 409 ni status bo'yicha emas,
javobdagi `res.needs_confirm === true` bo'yicha aniqlang. `api()` ni o'zgartirmang.

## 2. Forma (`index.html`, tracker tabi)

Mavjud 4 ta input qoladi (id lar o'zgarmaydi: `trk-q`, `trk-c`, `trk-e`, `trk-s`).
Qo'shiladi: `<input type="number" id="trk-max" min="1" placeholder="Maks. urinish (masalan 3, bo'sh = noma'lum)">`.
`trk-c` placeholderiga "(ixtiyoriy)" so'zini qo'shing.

`trkAdd()`: faqat `question` majburiy (bo'sh bo'lsa `alert("Savol matnini kiriting!")`).
`candidates` bo'sh bo'lishi mumkin. `max_attempts` = `trk-max` qiymati (bo'sh → `""`).
Javobda `res.error` bo'lsa — `alert(res.error)` va maydonlarni TOZALAMANG.
Muvaffaqiyatda maydonlarni (jumladan `trk-max`) tozalang.

## 3. Jadval (`loadTracker`)

`window.trkRows = res` saqlansin. Ustunlar:
`Savol` | `Nomzodlar` | `Dalil` | `Status` | `Urinishlar` | `Amallar`.

- **Nomzodlar:** vergul/bo'shliq bilan ajratilgan har bir nomzod alohida `tech-tag`
  (bosilganda `showMitreModal(<o'sha bitta ID>)` — `data-*` orqali). Bo'sh bo'lsa
  `<span style="color:var(--text-dim)">— hali yo'q</span>`.
- **Status:** `solved` bo'lsa `✅ Qabul qilindi` (yashil badge) + status matni;
  `exhausted` bo'lsa `⛔ Urinishlar tugadi` (qizil badge); aks holda status matni.
- **Urinishlar:** katta `used/max` yorlig'i (`max` null bo'lsa `used/?`).
  Rang: `solved` → yashil; `exhausted` yoki `remaining === 0` → qizil;
  `remaining === 1` → sariq; aks holda neytral. Ostida urinishlar ro'yxati:
  har biri `#1 T1566.001` + natija badge (`accepted` yashil, `rejected` qizil,
  `pending` sariq) + vaqt (`at`, `T`/`Z` ni olib `2026-10-05 08:51 UTC` ko'rinishida)
  + kichik `<select>` (accepted/rejected/pending, joriy tanlangan; o'zgarganda
  `trkSetResult(id, n, value)`) + `✕` tugmasi (`trkDelAttempt(id, n)`, `confirm()` bilan).
- **Amallar:** `✏️ Tahrirlash`, `🎯 Topshirish`, `📋 Nusxa` (candidates ni nusxalaydi,
  bo'sh bo'lsa tugma ko'rinmaydi), `O'chirish` (`confirm("Savolni o'chirasizmi?")` bilan —
  hozir tasdiqsiz o'chiradi, urinishlar tarixi yo'qolmasin).

Jadvalni `renderTable` bilan chizish shart emas (u `'revoked'` kabi qiymatlarga
maxsus ishlov beradi) — o'zingiz `<table>` yozishingiz mumkin, lekin mavjud CSS
klasslarini (`table-responsive`, `badge`, `badge-success`, `badge-high`, `tech-tag`,
`action-btn`, `btn-sm`) ishlating.

## 4. Joyida tahrirlash (`trkEdit(id)`)

`✏️ Tahrirlash` bosilganda shu qatorning Savol/Nomzodlar/Dalil/Status katakchalari
va max_attempts `<input>` larga aylanadi (joriy qiymatlar bilan, `value` atributi
`escapeHtml` orqali), Amallar ustunida `💾 Saqlash` va `Bekor`.
- `💾 Saqlash` → `trkSave(id)`: `PUT /api/tracker/<id>` ga
  `{question, candidates, evidence, status, max_attempts}` (max bo'sh → `""`).
  `res.error` → `alert` va tahrir rejimida qoladi. Muvaffaqiyatda `showToast("✓ Saqlandi")`
  va `loadTracker()`.
- `Bekor` → `loadTracker()`.
- Tahrir rejimida `Enter` → Saqlash, `Escape` → Bekor.
Bir vaqtning o'zida bitta qator tahrirlanadi (holat `trkEditingId` o'zgaruvchisida).

## 5. Urinish topshirish (`trkAttemptForm(id)`, `trkSubmitAttempt(id, force)`)

`🎯 Topshirish` shu qator ostida (yoki Urinishlar katakchasida) kichik forma ochadi:
- `<input>` javob (default qiymat — candidates dagi birinchi nomzod),
  `<select>` natija (`pending` default, `rejected`, `accepted`),
  `✔ Yozish` va `Bekor` tugmalari;
- javob inputi o'zgarganda (debounce ~250 ms) `POST .../check` chaqirib,
  forma ostida `check.warnings` ni sariq/qizil matnda JONLI ko'rsatadi
  (`ok` bo'lsa: `"Qolgan urinish: N"` yoki max yo'q bo'lsa `"Limit kiritilmagan"`).

`✔ Yozish` → `POST .../attempts` `{answer, result, force: false}`:
- `res.needs_confirm` → `confirm("⚠ " + res.check.warnings.join("\n") + "\n\nBaribir yozilsinmi?")`;
  OK bo'lsa `force: true` bilan qayta yuboring; Cancel → hech narsa yozilmaydi,
  forma ochiq qoladi.
- `res.error` (needs_confirm siz) → `alert(res.error)`.
- muvaffaqiyat → `showToast("✓ Urinish yozildi: " + used/max)`; `res.ledger_warning`
  bo'lsa uni ham toast da ko'rsating; `loadTracker()`.

`trkSetResult(id, n, result)` → `PUT .../attempts/<n>`; `trkDelAttempt(id, n)` →
`DELETE .../attempts/<n>`; ikkalasi `loadTracker()`.

## 6. Qolganlari

- `trkValidateAll()` ishlashda davom etsin (bo'sh candidates ni o'tkazib yuboradi;
  PUT faqat `{candidates}` yuboradi — backend buni qo'llab-quvvatlaydi). Nomzodlarni
  `,` bo'yicha ajratib, har birini `trim` qilib validate ga yuboring (hozir
  `"T1566.001, T1204.002"` dagi bo'shliq muammo tug'dirishi mumkin).
- `loadTracker` dagi `res.error` holatida xabarni qizil kartada ko'rsating (masalan
  "tracker.json o'qilmadi: ..."), `innerText` bilan.
- HUD dagi uchinchi plitka (`Export & Sync`) o'rniga: `Urinishlar Limiti` /
  `Dublikat va limit ogohlantirishi` deb yozing (mavjud emoji 📋 ni saqlang yoki 🔢).

## 7. Tekshirish (majburiy)

`node --check bluekit/web/static/app.js` xatosiz. Keyin qo'lda: `python bk.py web`
→ brauzerda Tracker tabi → nomzodsiz savol qo'shish (max 2), tahrirlash, 2 ta
urinish, dublikat ogohlantirishi. Hisobotda har bir faylning oldin/keyin qator soni.
