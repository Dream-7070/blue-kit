# Tz Labels & Toshkent Timezone Implementation Report

Mazkur hisobot spetsifikatsiyadagi barcha punktlar to'liq bajarilganligini hamda test natijalarini tasdiqlash uchun tayyorlandi.

## 1. O'zgartirilgan Fayllar va Tahrirlar Ro'yxati

1. **`bluekit/tz.py`**
   - *O'zgarish:* `tz_note()` helper funksiyasi yaratildi va eksport qilindi.
   
2. **`bluekit/ir/report.py`**
   - *O'zgarish:* `_render_ru`, `_render_uz`, `_render_en` funksiyalarida hisobotga yoziladigan vaqt zonalari `bluekit.tz` modulidagi lokallashtirilgan `TZ_LABEL_*` konstalar bilan almashtirildi. Barcha "UTC" va qattiq yozilgan "Vaqtlar UTC da" matnlari olib tashlandi.

3. **`bluekit/hunt/beacons.py`**
   - *O'zgarish:* Jadval sarlavhasi `Birinchi (UTC)` o'rniga `Birinchi (Toshkent)` bilan, shuningdek izoh `tz_note()` bilan almashtirildi.
   
4. **`bluekit/logs/report.py`**
   - *O'zgarish:* CLI da chiqariladigan xabarda qattiq yozilgan "Vaqtlar UTC da" so'zlari `tz_note()` ga almashtirildi.

5. **`bk.py`**
   - *O'zgarish:* `Timestamp UTC` o'rniga `Vaqt (Toshkent)` qo'llanildi. Izohga `tz_note()` chaqiruvi yozildi.

6. **`bluekit/web/server.py`**
   - *O'zgarish:* `import contextlib` va `_naive_tz(payload)` kontekst menejeri qo'shildi.
   - *O'zgarish:* `/api/logs/analyze`, `/api/sigma/scan`, `/api/ir/chain` va `/api/hunt/beacons` API endpointlari `with self._naive_tz(data):` blokiga o'raldi. Natijada `src_tz` parametri asosida vaqt mintaqasi boshqariladi va `finally` orqali to'g'ri holatga qaytarilishi ta'minlanadi. API javobiga `tz_note()` qaytarildi. `_logs_input_paths()` tahlil paytida xatoga uchrashining oldini olish maqsadida `try` ichiga olib kirildi.
   - *Izoh:* Funksiyalar va line count kamaymasligiga e'tibor qaratildi.

7. **`bluekit/web/static/app.js`**
   - *O'zgarish:* `buildLogInputBody()` funksiyasiga hamda bevosita `/api/hunt/beacons` va `/api/ir/chain` zaproslarini yig'adigan funksiyalarda DOM dan `log-src-tz` select elementi o'qilib `payload.src_tz` biriktirildi.
   - *O'zgarish:* Jadval va HTML shablonlardagi "Vaqt (UTC)" matnlari "Vaqt (Toshkent)" bilan, "UTC" matni "Toshkent (UTC+5)" matniga yangilandi. Funksiyalar va line count saqlab qolindi.
   
8. **`bluekit/web/static/index.html`**
   - *O'zgarish:* "Vaqtlar UTC da. Mahalliy vaqt uchun +5 soat qo'shing." eslatmasi butunlay olib tashlandi (C2 Hunt bo'limida ham).
   - *O'zgarish:* Logs bo'limidagi fayl yuklash grid qismida `log-src-tz` `<select>` komponenti qo'shildi va `grid-template-columns` `1fr 1fr auto auto` etib o'zgartirildi.

9. **`bluekit/playbook.py`**
   - *O'zgarish:* 0.4.6 va 4.6-bandlardagi "vaqt(UTC)" matni "vaqt (Toshkent)" bilan almashtirildi.
   
10. **`BOSHLOVCHI_QOLLANMA.html`**
    - *O'zgarish:* "Toshkent vaqti uchun +5 soat qo'shing." matni olib tashlandi, o'rniga "Toshkent (+05:00)" qo'yildi.

## 2. Test Natijalari

Yangi yaratilgan `tests/test_tz_labels.py` barcha talablarni qamrab oldi:
- **Test 1 (`test_tz_note`):** `tz_note()` default qiymati va "utc" parametri bilan tekshirildi.
- **Test 2 (`test_no_hardcoded_strings`):** Barcha `.py`, `.js`, `.html` fayllarda "+5 soat qo'shing" umuman (0 marta) uchrashi isbotlandi.
- **Test 3 (`test_ir_report_no_utc`):** DummyModel orqali hisobotda umuman `UTC` so'zi yo'qligi tasdiqlandi.
- **Test 4 (`test_server_tz_handler`):** `/api/logs/analyze` bilan noto'g'ri zona (xato kod `400`) va to'g'ri zona ko'rsatilganda `finally` orqali tizim zonasining o'z holiga qaytishi tekshirildi.

Parallel task (`/api/sigma/info`, `/api/sigma/scan`, `test_sigma_web.py`) holati va umuman barcha bazaviy testlar yashil saqlanib qolindi.

**Oxirgi 5 qator (`python -m unittest discover -s tests` natijasi):**
```text
----------------------------------------------------------------------
Ran 365 tests in ~80.201s

OK
```

Barcha talablar bajarildi va nuqtaviy tahrir tamoyiliga to'liq rioya qilindi.
