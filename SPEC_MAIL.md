# SPEC_MAIL — Email / phishing skaner (`bk mail scan`)

## Maqsad
Kitda email faylini tahlil qilish qobiliyati umuman yo'q. `.eml` faylini oflayn
(tarmoqsiz, DNS so'rovsiz) statik tahlil qilib, phishing belgilarini topadigan
modul kerak. Natija mavjud findings formatiga mos bo'lsin — IR hisobotiga va
`submission.json` ga tushadi.

**Qattiq cheklovlar:**
- Tarmoq YO'Q (DNS, WHOIS, VT — hech biri). Faqat statik tahlil.
- Yangi majburiy kutubxona YO'Q. Hammasi stdlib (`email`, `hashlib`, `zipfile`,
  `re`, `html.parser`, `quopri`, `base64`).
- Attachmentlar HECH QACHON diskka yozilmaydi va ochilmaydi — faqat baytlari o'qiladi.

## Yangi fayllar
```
bluekit/mail/__init__.py
bluekit/mail/parse.py     # .eml -> normalized dict
bluekit/mail/scan.py      # tekshiruvlar + ball
bluekit/mail/brands.yaml  # brend / shortener / homoglyph ro'yxati
```

## 1. parse.py

`load_eml(path)` -> dict:
```python
{
  "file": "<basename>", "size": int,
  "headers": {"from","from_display","from_addr","from_domain","to","subject","date",
              "return_path","reply_to","message_id","x_mailer","auth_results"},
  "received": [ {"raw": str, "ip": str|None, "ts": str|None} ],   # eng eskisi birinchi
  "body_text": str, "body_html": str,
  "urls": [ {"url": str, "anchor_text": str|None, "source": "html"|"text"} ],
  "attachments": [ {"filename","content_type","size","sha256","data_head"} ],
  "errors": [str]
}
```
- `email.message_from_binary_file` + `policy.default`.
- Multipart xatlarda `text/plain` va `text/html` alohida yig'iladi.
- HTML dan URL va anchor matnini `html.parser.HTMLParser` bilan oling —
  `<a href=...>matn</a>` juftligi SHART (anchor/href mosligini tekshirish uchun).
- Har bir attachment uchun sha256 hisoblanadi, `data_head` — birinchi 64 bayt.
- `.msg` (OLE, magic `D0CF11E0`) berilsa: `extract_msg` ni import qilib ko'ring;
  bo'lmasa aniq xabar chiqsin: ".msg uchun extract_msg kerak — yoki Outlook'da
  'Save as .eml' qiling". Crash BO'LMASIN.

## 2. scan.py

`scan_email(parsed, kb=None)` -> dict:
```python
{
  "file": str, "verdict": "PHISHING"|"SUSPICIOUS"|"CLEAN", "score": float,
  "headers": {...},
  "findings": [ {"check","severity","score","evidence","techniques":[str],"izoh"} ],
  "urls": [ {"url_defanged","host","reasons":[str]} ],
  "attachments": [ {"filename","sha256","size","suspicious":bool,"reasons":[str]} ],
  "iocs": [ {"type","value"} ]
}
```
Ball: barcha `findings[].score` yig'indisi, `min(1.0, ...)`.
Verdikt: `>=0.6` PHISHING, `>=0.3` SUSPICIOUS, aks holda CLEAN.
`severity`: score >= 0.4 → `high`, >= 0.2 → `medium`, aks holda `low`.
Har bir finding da `izoh` — bitta o'zbekcha jumla: nima topildi va nega yomon.

### MAJBURIY tekshiruvlar — Header
| check | shart | score | technique |
|---|---|---|---|
| `spf_fail` | `auth_results` da `spf=fail` yoki `softfail` | 0.25 | — |
| `dkim_fail` | `dkim=fail` yoki `dkim=none` | 0.2 | — |
| `dmarc_fail` | `dmarc=fail` | 0.3 | — |
| `return_path_mismatch` | `return_path` domeni != `from_domain` | 0.25 | — |
| `reply_to_mismatch` | `reply_to` domeni != `from_domain` | 0.3 | — |
| `display_name_spoof` | `from_display` ichida email yoki domen bor va u `from_domain` dan farq qiladi | 0.3 | `T1684.001` |
| `brand_impersonation` | `from_display` da brands.yaml dagi brend nomi bor, lekin `from_domain` o'sha brendniki emas | 0.3 | `T1684.001` |
| `msgid_mismatch` | `message_id` domeni != `from_domain` | 0.1 | — |

### MAJBURIY tekshiruvlar — URL
Har bir URL uchun; sabablar `urls[].reasons` ga ham yoziladi.

| check | shart | score | technique |
|---|---|---|---|
| `url_punycode` | hostda `xn--` | 0.35 | `T1566.002` |
| `url_ip_literal` | host IPv4/IPv6 literal | 0.3 | `T1566.002` |
| `url_anchor_mismatch` | anchor matni domenga o'xshaydi, lekin href domeni boshqa | 0.4 | `T1566.002`, `T1204.001` |
| `url_at_trick` | URL authority qismida `@` | 0.3 | `T1566.002` |
| `url_shortener` | host brands.yaml dagi `shorteners` ro'yxatida | 0.2 | `T1566.002` |
| `url_lookalike` | host brend domeniga Levenshtein masofasi 1-2 | 0.35 | `T1684.001` |
| `url_subdomain_spoof` | brend nomi subdomenda, registrable domen boshqa (`paypal.com.evil.ru`) | 0.35 | `T1684.001` |
| `url_mixed_script` | hostda lotin + kirill harflari aralash | 0.35 | `T1684.001` |
| `url_credential_path` | yo'lda `/login`, `/verify`, `/secure`, `/account`, `/owa`, `/password` va host brend emas | 0.15 | `T1598.003` |

Levenshtein funksiyasini o'zingiz yozing — kutubxona qo'shmang.
URL lar hisobotda defang qilinadi (`http` -> `hxxp`, `.` -> `[.]`).

### MAJBURIY tekshiruvlar — Attachment
Arxiv ichidagilarga ham 1 daraja chuqurlikda qo'llanadi.

| check | shart | score | technique |
|---|---|---|---|
| `attach_executable` | kengaytma: exe scr bat cmd com pif ps1 vbs js jse wsf wsh hta jar msi lnk | 0.5 | `T1204.002` |
| `attach_double_ext` | ikkilamchi kengaytma (`.pdf.exe`, `.doc.lnk`) yoki RTL override belgisi | 0.5 | `T1036.007` |
| `attach_magic_mismatch` | magic baytlar kengaytmaga mos emas (PDF `%PDF`, ZIP `PK`, OLE `D0CF11E0`, PE `MZ`, RTF `{\rtf`) | 0.4 | `T1036.007` |
| `attach_macro_office` | kengaytma docm/xlsm/pptm/xlsb, YOKI ZIP ichida `vbaProject.bin`, YOKI OLE ichida `Macros`/`VBA` | 0.45 | `T1566.001` |
| `attach_container` | iso img vhd vhdx | 0.4 | `T1566.001` |
| `attach_encrypted_zip` | ZIP local header flag bit 0 = 1 (parol bilan) | 0.35 | `T1566.001` |
| `attach_rtf_or_xll` | rtf, xll, one | 0.35 | `T1566.001` |

Har bir attachment sha256 → `iocs` ro'yxatiga.

### MAJBURIY tekshiruvlar — Body
| check | shart | score | technique |
|---|---|---|---|
| `html_smuggling` | HTML da `atob(` YOKI `new Blob(` + `download=` YOKI `<script>` ichida 1000+ belgili base64 blob | 0.45 | `T1027.006` |
| `html_form_external` | `<form action="http...">` tashqi domenga | 0.4 | `T1598.003` |
| `urgency_keywords` | uz/ru/en kalit so'zlar, har biri 0.1, jami maksimum 0.3 | <=0.3 | `T1598.003` |
| `image_only_body` | matn 40 belgidan kam, lekin 1+ inline rasm bor | 0.2 | — |

Kalit so'zlar (katta-kichik harf farqsiz, kamida shular):
- uz: `shoshilinch`, `hisobingiz bloklanadi`, `parolni tasdiqlang`, `darhol`, `hisobingiz ochiriladi`
- ru: `срочно`, `ваш аккаунт заблокирован`, `подтвердите пароль`, `немедленно`
- en: `verify your account`, `password expires`, `urgent`, `account suspended`, `invoice attached`, `wire transfer`, `click here immediately`

### brands.yaml
```yaml
brands:
  - {name: "Microsoft", domains: ["microsoft.com", "outlook.com", "office.com", "live.com"]}
  - {name: "Google", domains: ["google.com", "gmail.com"]}
  # + Apple, Amazon, PayPal, DHL, FedEx, Telegram, Facebook, Instagram, LinkedIn,
  #   Binance, Uzcard, Humo, Click, Payme, Beeline, Ucell, Uzum
shorteners: ["bit.ly","tinyurl.com","t.co","goo.gl","is.gd","cutt.ly","rb.gy","shorturl.at","ow.ly","buff.ly"]
corporate_domains: []   # foydalanuvchi o'z domenini qo'shadi; lookalike shu bo'yicha ham tekshiriladi
```

## 3. CLI (`bk.py`)
Yangi guruh:
```
bk mail scan <file.eml|papka> [--json] [--out report.html]
```
- Papka berilsa `*.eml` fayllari rekursiv topiladi, har biriga alohida natija.
- Oddiy rejim: fayl boshida verdikt + ball, keyin `findings` jadvali
  (`Check | Severity | Dalil | Texnika`), keyin URL jadvali, keyin attachment jadvali,
  oxirida `IZOHLAR:` ro'yxati (IR tabdagi uslubda).
- `--json`: to'liq dict.
- Bir nechta fayl bo'lsa oxirida umumiy jadval: `Fayl | Verdikt | Ball | Findings soni`.

## 4. Texnika ID lari
Faqat quyidagilar, hammasi KB da `active` deb tekshirilgan:
`T1566.001`, `T1566.002`, `T1598.003`, `T1204.001`, `T1204.002`, `T1036.007`,
`T1027.006`, `T1684.001`.

**DIQQAT:** `T1656` (Impersonation) bu KB da **revoked** — o'rniga `T1684.001`.
Modul yuklanganda barcha ID lar `kb.validate()` dan o'tkazilsin; `active` bo'lmagani
topilsa `WARNING:` chop etilsin (eventmap.yaml uslubida).

## 5. Testlar
`tests/test_mail.py` (unittest) va ikkita namuna fayl yarating:

`data/samples/mail/phish_sample.eml` — ichida kamida: SPF fail header,
boshqa domenli `Reply-To`, display name'da "Microsoft",
`<a href="http://xn--micrsoft-9db.com/login">microsoft.com</a>`,
va `invoice.pdf.exe` nomli kichik attachment.

Kutilgan natija: verdikt `PHISHING`, kamida 5 ta finding, ro'yxatda `T1036.007`
va `T1566.002` bor.

`data/samples/mail/clean_sample.eml` — oddiy ichki xat → verdikt `CLEAN`, 0-1 finding.

Kod uslubi: mavjud fayllar uslubi (4 space, yaml.safe_load, modul darajasida cache).
Stub qoldirmang — har bir tekshiruv haqiqatan implement qilinishi shart.
