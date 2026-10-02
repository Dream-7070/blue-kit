# SPEC_ANSWERS — javob reytingi va topshirish daftari

Loyiha: `D:\Claude Projects\CTF\blue-kit-staging`

## Nega

Musobaqada javoblar ATT&CK ID sifatida topshiriladi va **urinishlar soni
cheklangan**. Hozir tool ID larni topadi (`ir chain`, `sigma scan`,
`logs analyze`), lekin ularni **tartiblab bermaydi**: qaysi birini birinchi
topshirish kerakligini analitik o'zi taxmin qiladi.

Yana bir muammo: to'rt kishi ishlaganda kim qaysi ID ni topshirganini hech kim
bilmaydi — bir xil javob ikki marta ketadi.

## TEGMANG

`bluekit/logs/**`, `bluekit/siem/**`, `bluekit/ir/**`, `bluekit/hunt/**`,
`bluekit/resp/**`, `bluekit/kb/**`, `bluekit/decode.py`, `bluekit/doctor.py`,
`bluekit/web/**`, `bk.py` (CLI ni loyiha egasi ulaydi), mavjud `tests/test_*.py`.

**Yangi fayllar:** `bluekit/answers.py`, `tests/test_answers.py`.

Mavjud modullarni faqat **chaqiring**.

## 1. Kirish ma'lumotlari

Uchta manbadan JSON qabul qilinadi. Har biri ixtiyoriy, kamida bittasi kerak.

| Manba | Qanday olinadi | Ichida nima bor |
|---|---|---|
| IR zanjiri | `bk ir chain <f> --json --out chain.json` | `mitre_attack_techniques` (`technique_id`, `technique_name`, `phase`, `status`, `occurrences`), `attack_chain_timeline` (`step`, `mitre_id`, `evidence`) |
| Sigma | `bk sigma scan <f> --json --out sigma.json` | `by_technique` (`count`, `rules`, `level`), `hits` (`rules[].title`, `weak`) |
| Log tahlili | `bk logs analyze <f> --json-out logs.json` | ichida texnikalar va dalillar (formatini **o'zingiz fayldan o'qib aniqlang**, taxmin qilmang) |

Format tanilmasa — istisno emas, `warnings` ga yozilsin va o'sha fayl tashlab
ketilsin.

## 2. API

```python
def collect(paths: list) -> dict          # fayllarni o'qib, texnikalarni yig'adi
def rank(collected: dict, kb=None, submitted=None) -> list
def load_ledger(path) -> dict
def record(path, technique, result, note=None) -> dict
```

### `rank()` qaytaradigan element

```python
{
  'rank': 1,
  'technique': 'T1059.001',
  'name': 'PowerShell',              # KB dan
  'score': 8.4,
  'confidence': 'yuqori',            # yuqori | o'rta | past
  'sources': ['ir_chain', 'sigma'],
  'evidence': [
      "IR zanjiri 4-qadam: powershell -enc ... (Execution)",
      "Sigma: Suspicious PowerShell Download and Execute Pattern (high) x3",
  ],
  'kb_status': 'active',             # active | revoked | deprecated | not_found
  'replacement': None,               # revoked bo'lsa -- yangi ID
  'parent': 'T1059',                 # sub-texnika bo'lsa
  'submitted': False,
}
```

### Ball hisoblash

Ball **manbaning ishonchliligiga** qarab yig'iladi:

| Belgi | Ball |
|---|---|
| IR zanjirida bor (`attack_chain_timeline` da qadam sifatida) | +4 |
| IR `mitre_attack_techniques` da, lekin zanjirda qadam emas | +2 |
| Sigma `weak: False` moslik | +3 (har xil qoida uchun, maksimal +6) |
| Sigma faqat `weak: True` moslik | +0.5 |
| Sigma qoidasi darajasi `critical`/`high` | +1 |
| Log tahlili `confidence: high` | +2 |
| Log tahlili `confidence: low` yoki `blob_search` manbasi | +0.5 |
| Ikki va undan ortiq mustaqil manbada uchrashi | +3 |
| Takrorlanish soni 5 dan ko'p | +1 |

**Ko'p manbada uchrashi eng kuchli belgi** — shuning uchun +3. Bitta manbadagi
katta son emas, turli manbalarning bir-birini tasdiqlashi muhim.

`confidence`: ball >= 8 → `yuqori`, >= 4 → `o'rta`, aks holda `past`.

### KB tekshiruvi — majburiy

Har bir ID `bluekit.kb.query.KB().validate()` dan o'tsin:

- `revoked` bo'lsa — `kb_status: 'revoked'`, `replacement` to'ldirilsin va
  ro'yxatda **almashtiruvchi ID** ko'rsatilsin (eskisi emas)
- `not_found` bo'lsa — ro'yxat oxiriga tushsin va `confidence: 'past'`

Bu ATT&CK v19 tuzog'i uchun: `T1070.001` → `T1685.005`, `T1562.001` → `T1685`.

### Ota / sub-texnika

`T1059.001` bor bo'lsa, `parent: 'T1059'` to'ldirilsin. Agar ro'yxatda ham ota,
ham sub bo'lsa — ikkalasi ham qolsin, lekin sub yuqoriroq tursin (aniqroq javob).
`rank()` ga `prefer_parent=True` berilsa — teskarisi.

## 3. Topshirish daftari

Oddiy JSON fayl (default: joriy papkada `answers.json`):

```json
{"entries": [
  {"technique": "T1059.001", "result": "accepted", "at": "2026-10-05T10:12:00",
   "note": "3-savol", "by": null}
]}
```

`result`: `accepted` | `rejected` | `pending`.

`rank(..., submitted=ledger)` — daftarda `accepted` yoki `rejected` bo'lgan
ID lar ro'yxatdan **chiqarilsin** (`submitted: True` bilan alohida qaytarilsin,
lekin reytingda birinchi o'rinlarni egallamasin).

`record()` atomik yozsin (avval vaqtinchalik faylga, keyin `os.replace`) —
musobaqada fayl buzilib qolmasin.

## 4. Testlar (`tests/test_answers.py`)

1. **Ko'p manba ustunligi:** bitta texnika faqat Sigma da (5 marta), ikkinchisi
   ham IR zanjirida, ham Sigma da (1 martadan) → **ikkinchisi yuqori turishi**
   shart. *(Bu ball formulasining asosiy g'oyasi.)*
2. **Zanjir qadami eng og'ir:** faqat `attack_chain_timeline` da bo'lgan texnika
   faqat `weak` Sigma moslikdan yuqori.
3. **Revoked ID:** kirishda `T1070.001` bo'lsa, natijada `kb_status: 'revoked'`
   va `replacement: 'T1685.005'` bo'lsin (KB bo'lsa; aks holda `skipUnless`).
4. **Ota/sub:** `T1059` va `T1059.001` ikkalasi ham bo'lsa, sub yuqori;
   `prefer_parent=True` bilan teskari.
5. **Daftar:** `record()` dan keyin `rank(submitted=...)` o'sha ID ni birinchi
   o'rinlardan chiqarib tashlasin.
6. **Atomik yozuv:** `record()` ni 50 marta chaqirib, fayl har safar to'g'ri
   JSON bo'lib qolishini tekshiring.
7. **Buzuq kirish:** bo'sh fayl, noto'g'ri JSON, kutilmagan struktura →
   istisno emas, `warnings` da xabar.
8. **Reyting o'zgaruvchan:** kirish o'zgarsa tartib ham o'zgarsin (bir xil
   ro'yxat qaytaradigan stub bu testda yiqiladi).
9. **Haqiqiy fayl bilan:** `bk ir chain data/samples/win_phishing.csv --json`
   chiqishini vaqtinchalik faylga yozib, `collect()` uni o'qiy olishini
   tasdiqlang.

## 5. Qabul

```
python -m unittest discover -s tests -p "test_*.py" -q
python -c "import json,tempfile,os; from bluekit.answers import collect, rank; print(rank(collect([])))"
```

Barcha mavjud testlar yashil qolsin.

Hisobotda: haqiqiy `ir chain` + `sigma scan` chiqishlaridan yasalgan reytingning
birinchi 10 qatorini **ko'chirib** keltiring.

Stub qoldirmang. Har doim bir xil tartib qaytaradigan funksiya kerak emas.
