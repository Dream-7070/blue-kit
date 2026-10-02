# FEEDBACK_SIGMA — ikkita nuqson

Ish asosan yaxshi. Ishlayotgan va **qayta yozilmasligi kerak** bo'lgan qismlar:

- 3757 qoidadan **3740** yuklanadi, atigi 17 skip — parser kuchli
- Kodlangan PowerShell hodisasida `T1059.001` to'g'ri topildi (8 qoida)
- `certutil -urlcache` da `T1105`, `T1218` topildi
- `weak` bayrog'i to'g'ri ishlaydi (blob orqali topilgan moslik belgilanadi)
- Bo'sh/buzuq hodisalarda istisno yo'q
- Namunaviy faylda 28 ta texnika topildi (`eventmap.yaml` da atigi 21 ta, ulardan
  10 tasi butunlay yangi) — qamrov haqiqatan oshdi

Quyidagi ikkitasini tuzating, boshqasiga tegmang.

## 1-nuqson (YUQORI) — `not 1 of <prefiks>*` ishlamayapti

Bu eng muhimi: **614 ta qoida** shu shaklni ishlatadi va ular aynan noto'g'ri
musbatni chiqarib tashlash uchun yozilgan. Hozir ular o'chmayapti.

### Dalil

KB dagi haqiqiy qoida:

```yaml
condition: selection and not 1 of filter_main_*
filter_main_img_location:
  Image:
  - C:\Windows\System32\svchost.exe
  - C:\Windows\SysWOW64\svchost.exe
filter_main_ofn:
  OriginalFileName: svchost.exe
selection:
  Image|endswith: \svchost.exe
```

Sinov hodisasi (mutlaqo qonuniy):

```python
{'process': r'C:\Windows\System32\svchost.exe',
 'command_line': r'C:\Windows\System32\svchost.exe -k netsvcs',
 'event_id': '4688',
 'raw': {'Image': r'C:\Windows\System32\svchost.exe', ...}}
```

`filter_main_img_location` ning `Image` ro'yxatidagi birinchi qiymat aynan mos
keladi → `1 of filter_main_*` = True → `not (...)` = False → **qoida ishga
tushmasligi kerak**.

Natija: `match_event` uni **topilma sifatida qaytardi**
(`Suspicious Process Masquerading As SvcHost.EXE`, `weak=False`).

Xuddi shu xato ikkinchi qoidada ham:

```yaml
condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
filter_main_generic:
  Image|startswith:
  - C:\Windows\System32\
  ...
```

`C:\Windows\System32\svchost.exe` shu `startswith` ga mos → qoida o'chishi kerak
edi, lekin `System File Execution Location Anomaly` ham topilma bo'lib qaytdi.

### Nima tekshirish kerak

Baholovchi quyidagilarni **alohida-alohida** to'g'ri bajarishi shart:

| Shakl | Qoidalar soni | Ma'nosi |
|---|---|---|
| `not 1 of filter_*` | 614 | prefiksga mos **birorta** blok mos kelsa — False |
| `and not <nom>` | 803 | aniq nomli blok mos kelsa — False |
| `1 of sel*` | 947 | birorta mos kelsa — True |
| `all of sel*` | 823 | hammasi mos kelsa — True |

Ehtimoliy sabab: `not` ni `1 of ...*` konstruksiyasiga emas, undan keyingi
birinchi so'zga qo'llayapsiz, yoki `*` bo'yicha bloklar to'plami noto'g'ri
yig'ilyapti. Prefiks bo'yicha tanlashda `filter_main_*` → `filter_main_img_location`
va `filter_main_ofn` ikkalasi ham kirishi kerak.

**Muhim:** blok nomi `filter` bilan boshlanishi hech narsani anglatmaydi — mantiq
faqat `condition` dagi `not` dan kelib chiqadi. Nomga qarab filtr deb hisoblamang.

### Testlar

Yuqoridagi ikkala haqiqiy qoidani KB dan `title` bo'yicha oling va sinang:

1. `C:\Windows\System32\svchost.exe` → **topilma YO'Q**
2. `C:\Users\x\AppData\Local\Temp\svchost.exe` → **topilma BOR** (filtrga tushmaydi)

Bu ikki test juftligi negatsiya ishlayotganini isbotlaydi. Sun'iy qoida bilan ham
sinang: `condition: selection and not 1 of filter_*` ikkita `filter_a`, `filter_b`
bloki bilan — har biri alohida-alohida o'chirishi kerak.

## 2-nuqson (O'RTA) — tezlik talabdan 2.7 barobar sekin

O'lchovim: **2000 ta hodisa → 54 soniya** (talab: 20 dan kam). Hodisalar bir xil,
har biri 8 ta qoidaga mos keladigan "og'ir" holat.

Namunaviy faylda 33 hodisa 0.5 soniya = ~15 ms/hodisa. Haqiqiy log
(`D:\Claude Projects\CTF\dest.csv`, 38 MB) yuz minglab qatordan iborat — hozirgi
tezlikda bu soatlab davom etadi, ya'ni musobaqada ishlatib bo'lmaydi.

### Taklif: teskari indeks

Hozir har bir hodisa uchun **barcha** qoidalarning literallari tekshirilyapti.
Buni teskari indeksga almashtiring:

1. **Yuklashda**: har bir qoidaning har bir literalidan bitta *ajratuvchi token*
   oling — literal ichidagi eng uzun harf-raqam ketma-ketligi, kichik harfda.
   `\powershell.exe` → `powershell`, `-enc` → `enc`,
   `FromBase64String` → `frombase64string`. Indeks: `token -> [rule_id, ...]`.
2. **Tekshirishda**: hodisaning `blob` idan harf-raqam tokenlarini bir marta
   ajrating (kichik harfda, `set`). Nomzod qoidalar = shu tokenlar bo'yicha
   indeksdan olingan birlashma.
3. Indekslanmaydigan qoidalar (literali yo'q, masalan faqat regex yoki faqat
   raqamli maydon) alohida kichik ro'yxatda qolsin va har doim baholansin —
   ularning soni kam bo'lishi kerak, sonini `stats()` ga qo'shing
   (`always_eval`).

Qo'shimcha: regexlarni yuklashda bir marta `re.compile` qiling, hodisa
maydonlarini qoida boshiga bir marta yeching (har bir blok uchun qayta emas).

**Maqsad:** yuqoridagi 2000 ta og'ir hodisa **20 soniyadan kam**. `stats()` ga
`always_eval` va `indexed_rules` sonlarini qo'shing.

Mavjud tezlik testini shu og'ir holat bilan almashtiring: 2000 ta hodisa, har
biri `Image`, `CommandLine`, `ParentImage`, `EventID` to'ldirilgan va kamida
bitta qoidaga mos keladigan.

## Qabul

```
python -m unittest discover -s tests -p "test_*.py" -q
```

Hozir **139 ta test** yashil — hammasi yashil qolsin.

Hisobotda:
- yuqoridagi ikkita svchost testining natijasi (topilma bor/yo'q)
- 2000 og'ir hodisa uchun o'lchangan vaqt
- yangi `stats()` chiqishi

`bk.py`, web va boshqa modullarga tegmang — ish faqat
`bluekit/logs/sigma.py` va `tests/test_sigma.py` da.
