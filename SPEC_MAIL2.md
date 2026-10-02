# SPEC_MAIL2 — Sender attribution + tahdid/ekstorsiya tekshiruvlari (mail round 2)

## Muammo (haqiqiy namunada o'lchangan)
`bk mail scan` ni eski CTF taskidagi haqiqiy xatga (`threat.eml`) qo'llab ko'rdim:

```
Verdikt: CLEAN | Ball: 0
```

Xat esa — tahdid xati (shantaj/qo'rqitish). Sabab: mavjud tekshiruvlarning hammasi
**phishing mexanikasi** ga qaraydi (soxta link, attachment, auth fail). Bu xatda esa:
- SPF **pass**, DKIM **pass** (haqiqiy anonim remailer orqali yuborilgan)
- URL **yo'q**, attachment **yo'q**
- Zarar — faqat matnda va **jo'natuvchi kimligida**

Bunday taskda savol "phishingmi?" emas, balki **"kim yubordi va qayerdan?"**.
Hozir kit bu savolga umuman javob bermaydi.

Shu bitta xatdagi dalillar (kit ko'rsatishi kerak bo'lgan narsalar):
| Dalil | Qiymat |
|---|---|
| Birinchi tashqi Received hop | `uzmail.inboxpress.net [139.28.47.223]` |
| Jo'natuvchi domeni | `anonymousemail.eu` — anonim remailer |
| Body izi | "Powered by Anonymousemail" |
| **Timezone sizishi** | `Date: ... 08:31:45 +0200`, server esa `+0000 UTC` — muallif mijozi **UTC+2** deb e'lon qilgan, Toshkent (+05) emas |
| SpamAssassin | `X-Spam-Status: No, score=-1.9 ... SPF_PASS, DKIM_VALID` |

## O'zgartiriladigan fayllar
1. `bluekit/mail/scan.py` — yangi tekshiruvlar + attribution bloki
2. `bluekit/mail/brands.yaml` — `anonymous_mailers` ro'yxati
3. `bk.py` — chiqishga yangi bo'lim

---

## 1. Yangi bo'lim: `attribution`

`scan_email()` natijasiga yangi kalit:
```python
"attribution": {
  "origin_ip": str|None,          # birinchi tashqi (public) Received hop IP si
  "origin_host": str|None,
  "hops": [ {"host","ip","ts","tz"} ],   # eng eskisidan yangisiga
  "sender_tz": str|None,          # Date sarlavhasidagi offset, masalan "+0200"
  "server_tz": str|None,          # birinchi server hopidagi offset
  "tz_mismatch": bool,            # sender_tz != server_tz
  "anonymous_mailer": str|None,   # topilgan xizmat nomi
  "x_mailer": str|None,
  "spam_verdict": str|None,       # X-Spam-Status dan
  "notes": [str]                  # o'zbekcha qisqa xulosalar
}
```

Mantiq:
- **origin_ip**: `received` ro'yxatidagi eng eski hopdan boshlab birinchi **public**
  IP (RFC1918/loopback emas). Yo'q bo'lsa `None`.
- **sender_tz**: `Date` sarlavhasidagi offset (`+0200`).
- **server_tz**: birinchi server hopining offseti.
- **tz_mismatch**: ikkisi farq qilsa `True` va `notes` ga:
  "Muallif mijozi UTC+2 vaqt mintaqasini e'lon qilgan, qabul qiluvchi server esa UTC —
  jo'natuvchi boshqa mintaqada bo'lishi mumkin."
- **anonymous_mailer**: `from_domain`, `origin_host` yoki body matni
  `brands.yaml` dagi `anonymous_mailers` ro'yxatidagi xizmatga mos kelsa, nomi.

`notes` — har biri bitta o'zbekcha jumla, hakamga tayyor dalil sifatida.

## 2. Yangi tekshiruvlar (findings ga qo'shiladi)

| check | shart | score | technique |
|---|---|---|---|
| `anonymous_mailer` | jo'natuvchi domeni yoki origin host anonim/disposable mail xizmati | 0.3 | `T1585.002` |
| `threat_language` | tahdid/shantaj kalit so'zlari (pastga qarang), har biri 0.15, jami max 0.45 | <=0.45 | `T1684.001` |
| `crypto_wallet` | matnda BTC/ETH/XMR/TRON hamyon manzili | 0.4 | — |
| `tz_mismatch` | `Date` offseti birinchi server hop offsetidan farq qiladi | 0.1 | — |
| `no_subject` | `Subject` bo'sh yoki yo'q | 0.1 | — |
| `sender_display_minimal` | display name 1-2 belgi (`zz` kabi) | 0.1 | — |

Hamyon regexlari:
- BTC: `\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b`
- ETH: `\b0x[a-fA-F0-9]{40}\b`
- XMR: `\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b`
- TRON: `\bT[A-Za-z1-9]{33}\b`

Topilgan hamyon `iocs` ga `{"type": "wallet", "value": ...}` bo'lib qo'shiladi.

Tahdid kalit so'zlari (katta-kichik harf farqsiz):
- uz: `kuzatyapman`, `pulni o'tkaz`, `oilangni`, `sirlaringni`, `fosh qilaman`, `tahdid`
- ru: `слежу за тобой`, `переведи`, `разошлю`, `твои секреты`, `будет хуже`, `я знаю о тебе`, `твоих сотрудников`
- en: `i have been watching`, `i've been watching`, `been monitoring`, `your enemies`, `pay me`, `i know what you did`, `your secrets`, `or else`

## 3. Verdikt shkalasi

Hozir verdikt faqat phishing mexanikasini o'lchaydi. Yangi holat qo'shilsin:

- `threat_language` YOKI `crypto_wallet` ishga tushsa va umumiy ball >= 0.3 →
  verdikt **`THREAT`** (PHISHING emas).
- Qolgani avvalgidek: >=0.6 `PHISHING`, >=0.3 `SUSPICIOUS`, aks holda `CLEAN`.

`CLEAN` verdikt chiqqanda, agar `attribution.anonymous_mailer` topilgan bo'lsa,
chiqishda ogohlantirish bo'lsin: "Phishing belgisi yo'q, lekin xat anonim
remailer orqali yuborilgan — jo'natuvchini qo'lda tekshiring."

## 4. brands.yaml ga qo'shiladi
```yaml
anonymous_mailers:
  - anonymousemail.eu
  - guerrillamail.com
  - mailinator.com
  - 10minutemail.com
  - temp-mail.org
  - yopmail.com
  - protonmail.com
  - tutanota.com
  - emkei.cz
  - anonymouse.org
  - sendanonymousemail.net
```
(protonmail/tutanota — o'zi zararli emas, shuning uchun `notes` da
"maxfiylikka yo'naltirilgan xizmat" deb belgilansin, ball 0.3 emas 0.15 bo'lsin.)

## 5. CLI chiqishi
`findings` jadvalidan keyin yangi bo'lim:
```
JO'NATUVCHI TAHLILI (Attribution)
  Origin IP    : 139.28.47.223 (uzmail.inboxpress.net)
  Anonim mailer: anonymousemail.eu
  Vaqt mintaqasi: muallif +0200 / server +0000  -> MOS EMAS
  Spam verdikt : No (score=-1.9, SPF_PASS, DKIM_VALID)

  Hop zanjiri:
    1. uzmail.inboxpress.net  139.28.47.223   2026-09-14 06:31:45 +0000
    2. mx1.umail.uz           -               2026-09-14 11:31:49 +0500

  Xulosa:
    - Muallif mijozi UTC+2 ni e'lon qilgan, server UTC — jo'natuvchi Toshkentda bo'lmasligi mumkin.
    - Xat anonim remailer orqali yuborilgan: haqiqiy jo'natuvchi yashirilgan.
```
`--json` da `attribution` kaliti sifatida.

## 6. Testlar
```
python bk.py mail scan "C:\Users\USER\Downloads\threat.eml"
python -m unittest tests.test_mail -v
```
Kutilgan:
- `threat.eml` → verdikt **`THREAT`** (CLEAN emas);
- `attribution.origin_ip` = `139.28.47.223`, `anonymous_mailer` = `anonymousemail.eu`,
  `tz_mismatch` = `True`;
- `threat_language` findingi kamida 2 ta kalit so'z bilan ishga tushgan;
- mavjud 2 ta test (`phish_sample`, `clean_sample`) **avvalgidek o'tadi** —
  `clean_sample` hamon `CLEAN`.

`tests/test_mail.py` ga uchinchi test qo'shing: `threat.eml` o'rniga
`data/samples/mail/threat_sample.eml` yarating (haqiqiy xat maxfiy bo'lgani uchun
faqat kerakli sarlavhalar bilan soddalashtirilgan nusxa: anonim domen,
`Date` +0200, server hop +0000, tahdid matni).

Stub qoldirmang. Ishni o'zingiz bajaring, subagentga topshirmang.
