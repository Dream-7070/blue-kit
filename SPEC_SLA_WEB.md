# SPEC_SLA_WEB — web UI dagi SLA tabini haqiqiy ishlaydigan qilish

Loyiha: `D:\Claude Projects\CTF\blue-kit-staging`

## Muammo

Responder tabidagi **⏱ SLA Holati** tugmasi hozir **hech narsani tekshirmaydi**:

- `app.js` dagi `respSla()` serverga `args.services = []` (bo'sh ro'yxat) yuboradi;
- `server.py` `/api/resp/sla` shoxi `resp_sla_check({"services": []})` chaqiradi;
- `bluekit/resp/sla.py` dagi `check()` bo'sh ro'yxatga `[]` qaytaradi;
- `app.js` esa buni ko'rib `"Snapshotda faol servislar ro'yxati tahlil qilindi"`
  deb yozadi.

Ya'ni foydalanuvchi "hammasi joyida" degan taassurot oladi, aslida bitta ham
tekshiruv bajarilmagan. Musobaqada availability balli shu tugmaga ishonib
yo'qotilishi mumkin.

Ikkinchi nuqson: `respSla()` avval `getRespArgs()` chaqirib, **snapshot yo'q
bo'lsa** "Joriy Snapshot Kiritilmadi" ogohlantirishini ko'rsatadi. SLA ning
snapshotga umuman aloqasi yo'q — u tarmoq orqali tirik xizmatlarni tekshiradi.

## 0. Asosiy qoidalar

**TEGMANG:** `bluekit/resp/sla.py` (faqat chaqiring — mantiq tayyor va testlari bor),
`bk.py`, `bluekit/resp/triage.py`, `bluekit/resp/fraud.py`, `bluekit/playbook.py`,
`bluekit/siem/**`, `bluekit/logs/**`, `bluekit/ir/**`, mavjud `tests/test_*.py`.

**O'zgartiriladigan:** `bluekit/web/server.py` (faqat `/api/resp/sla` shoxi),
`bluekit/web/static/index.html`, `bluekit/web/static/app.js`,
`bluekit/web/static/style.css` (kerak bo'lsa).
**Yangi:** `tests/test_sla_web.py`.

Fayllar faqat **O'SISHI** kerak. Hozir: `app.js` 2480 qator, `index.html` 820,
`style.css` 1563, `server.py` 631. Mavjud funksiyalarni qayta yozish, qisqartirish
yoki "tozalash" TAQIQLANADI.

**Unicode:** fayllarni UTF-8 da saqlang. O'tgan topshiriqda emoji belgilar `??`
va `-` ga aylanib ketgan edi — bu qabul qilinmaydi.

## 1. Backend: `/api/resp/sla`

Hozirgi shox:
```python
elif path == '/api/resp/sla':
    services = data.get('services', [])
    res = resp_sla_check({"services": services})
    self.end_json(res)
```

Yangi xulq (mavjud `services` kalitiga moslik saqlanadi):

1. Agar `data` da `services_yaml` (matn) bo'lsa — `yaml.safe_load` bilan
   o'qing. Natija `{'services': [...]}` ko'rinishida bo'lishi kutiladi;
   ro'yxat to'g'ridan-to'g'ri berilgan bo'lsa (`- name: ...`) uni ham qabul qiling.
2. Aks holda `data.get('services')` ishlatiladi (eski xulq).
3. **Agar oxirida xizmatlar ro'yxati bo'sh bo'lsa** — `[]` qaytarmang.
   HTTP 400 va aniq xabar bering:
   `{"error": "Xizmatlar ro'yxati bo'sh — services.yaml kiriting (namuna: responder/sla.example.yaml)"}`
4. YAML sintaksis xatosi bo'lsa — HTTP 400 va xato matni.

`resp_sla_check` qaytaradigan struktura (O'ZGARTIRMANG, shunchaki uzating):

```json
[{"name": "web-prod-01 HTTP", "board_name": "Poseidon",
  "state": "ok|degraded|down", "ok": true,
  "detail": "barcha tekshiruvlar o'tdi",
  "checks": [{"type": "tcp", "ok": true, "critical": true, "ms": 12,
              "detail": "ochiq", "target": "10.10.20.11:80"}],
  "checked_at": "2026-10-05T09:14:00"}]
```

`state` uch xil bo'lishi mumkin — `ok`, `degraded` (faqat nokritik tekshiruv
yiqilgan), `down` (kritik tekshiruv yiqilgan). Buni frontend ajratib ko'rsatishi shart.

## 2. Frontend: kirish maydoni

Responder tabining chap kartasida, "Himoyalangan elementlar (Protected YAML)"
maydonidan keyin yangi blok:

- `<label class="field-label">SLA konfigi (services.yaml):</label>`
- `<textarea id="resp-sla-yaml">` — placeholder sifatida qisqa namuna
  (`services:` / `  - name: web` / `    checks:` / `      - type: tcp` /
  `        target: 10.10.20.11:80`)
- Yonida `<input type="file" id="resp-sla-file" accept=".yaml,.yml">` —
  tanlangan fayl matni textarea ga o'qiladi (`FileReader`, `app.js` dagi
  mavjud fayl o'qish uslubida).
- Kichik yordam matni: `responder/sla.example.yaml` dan nusxa oling yoki
  `bk resp discover base_*.json --sla-out services.yaml` bilan yasang.

## 3. Frontend: `respSla()` ni tuzatish

1. **`getRespArgs()` ga bog'liqlikni olib tashlang** — SLA snapshot talab qilmaydi.
   `renderSnapshotMissingWarning()` chaqirilmasin.
2. Textarea bo'sh bo'lsa serverga umuman bormasdan sariq ogohlantirish
   ko'rsating: "SLA konfigi kiritilmagan — services.yaml ni yuklang".
3. So'rov: `POST /api/resp/sla` body `{"services_yaml": "<textarea matni>"}`.
4. Javobdagi `error` bo'lsa — qizil kartada ko'rsating.

### Natijani chizish

Har bir xizmat uchun karta (jadval emas — tekshiruvlar ichma-ich):

- Sarlavha: `name`, `board_name` bo'lsa qavs ichida.
- Holat badge: `ok` → yashil `TIRIK`, `degraded` → sariq `QISMAN`,
  `down` → qizil `O'LGAN`. Faqat `ok: true/false` emas, **uchala holat** ajratilsin.
- `detail` matni.
- `checks` ro'yxati: har biri `type`, `ok`, `critical` (kritik bo'lsa belgisi),
  `ms` (javob vaqti), `detail`. Yiqilganlari tepada tursin.
- `checked_at` — lokal vaqtda.

Yuqorida umumiy lenta: nechta `TIRIK` / `QISMAN` / `O'LGAN`.

## 4. Avtomatik yangilash

Availability uzluksiz baholanadi, shuning uchun bitta bosish yetarli emas.

- Natija ustida checkbox: `Avto-yangilash` + interval `<select>` (15 / 30 / 60 soniya,
  default 30).
- Yoqilganda `setInterval` bilan so'rov takrorlanadi; o'chirilganda yoki
  boshqa tabga o'tilganda `clearInterval` qilinadi (taymer oqib ketmasin).
- Holat **o'zgarganda** (masalan `ok` → `down`) `showToast()` bilan xabar bering:
  `"<xizmat nomi>: TIRIK -> O'LGAN"`. Bu musobaqada eng muhim signal.
- Oxirgi yangilanish vaqti ko'rsatilsin.

## 5. Testlar — `tests/test_sla_web.py`

`tests/test_web.py` uslubida (server thread da, `urllib`):

1. `POST /api/resp/sla` bo'sh body `{}` → **HTTP 400**, javobda `error` bor
   va unda `services.yaml` so'zi uchraydi. (Bugungi jimgina `[]` qaytarish
   qaytib kelmasligi uchun.)
2. `{"services": []}` → ham **HTTP 400**.
3. Noto'g'ri YAML (`"services: [": "`) → **HTTP 400**.
4. To'g'ri `services_yaml` bilan: yopiq portga `tcp` tekshiruvi
   (`127.0.0.1:1` kabi ishlatilmaydigan port) → HTTP 200, natijada bitta
   xizmat, `state == 'down'`, `ok == False`, `checks[0]['type'] == 'tcp'`.
5. Ikkita tekshiruvli xizmat: biri kritik emas (`critical: false`) va yiqiladi,
   ikkinchisi o'tadi → `state == 'degraded'`.
   (Tekshiruv o'tishi uchun test serverining o'z portiga `tcp` tekshiruvi
   qo'ying — u albatta ochiq.)
6. Statik fayl testi: `index.html` da `resp-sla-yaml` bor;
   `app.js` da `services_yaml` bor va `renderSnapshotMissingWarning` endi
   `respSla` ichida chaqirilmaydi (`respSla` funksiyasi matnida yo'q).

Mavjud **194 ta test ham yashil qolishi shart**.

## 6. Qabul mezonlari

- [ ] `python -m unittest discover -s tests` — 194 + yangi, hammasi yashil.
- [ ] `python bk.py web` → brauzerda: konfig kiritmasdan SLA bosilsa aniq
      ogohlantirish chiqadi, "hammasi joyida" degan yolg'on natija YO'Q.
- [ ] `responder/sla.example.yaml` ni textarea ga qo'yib bosganda haqiqiy
      tekshiruv natijasi (`down` bo'lsa ham) chiqadi.
- [ ] Avto-yangilash yoqilsa natija o'zi yangilanadi, boshqa tabga o'tilsa to'xtaydi.
- [ ] Hisobotda har bir fayl uchun oldingi/keyingi qator soni.
