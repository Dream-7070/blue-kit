# RELEASE — exe qurish va tarqatilgan kitni yangilash

Bu spec emas, **protsedura**. Har safar shu tartibda bajariladi.

Uchta papka, uch vazifa:

```
D:\Claude Projects\CTF\blue-kit-staging\      manba kod (bu yerda yoziladi)
        |  PyInstaller
D:\Claude Projects\CTF\blue-kit-staging\dist\ qurilgan exe
        |  YANGILA.bat
D:\Tools\blue-kit-dist\                       ishlatiladigan nusxa (musobaqaga boradi)
```

## 1. Qurishdan oldin

**a) `bk.spec` dagi `hiddenimports` ni tekshiring.**

PyInstaller bu loyihada modullarni o'zi to'liq topa olmaydi — ro'yxat qo'lda
yuritiladi. Har bir **yangi** `bluekit.<paket>.<modul>` shu ro'yxatga
qo'shilishi shart, aks holda exe muammosiz quriladi, lekin buyruq ishlamaydi.

Hozirgi ro'yxatda bo'lishi kerak (yangi modul qo'shilgan bo'lsa — qo'shing):

```
bluekit.logs.qradar, bluekit.logs.parse, bluekit.logs.sigma, bluekit.logs.formats,
bluekit.ir.explain, bluekit.ir.correlator, bluekit.ir.models, bluekit.ir.report, bluekit.ir.lateral, bluekit.ir.fallback,
bluekit.hunt.beacons, bluekit.hunt.beacon_math, bluekit.paths,
bluekit.siem.cli, bluekit.siem.builder, bluekit.siem.catalog,
bluekit.siem.dialects, bluekit.siem.fields,
bluekit.resp.sla, bluekit.resp.scoring, bluekit.resp.servicedoctor,
bluekit.resp.fraud, bluekit.decode, bluekit.doctor, bluekit.answers, bluekit.tracker, bluekit.tz, bluekit.logs.filter, bluekit.logs.bruteforce, bluekit.kb.cve,
bluekit.case, bluekit.case.loaders, bluekit.case.solver, bluekit.case.cli, bluekit.ir.webauth, bluekit.ir.proctree, bluekit.ir.cloudtrail, bluekit.netutil, bluekit.web.case_api
```

**b) Yangi YAML/resurs fayl qo'shilgan bo'lsa** — `bk.spec` ning `datas`
ro'yxatiga ham qo'shing (masalan yangi `hunts.local.yaml`).

**c) Testlar yashil bo'lsin:**

```
python -m unittest discover -s tests -p "test_*.py" -q
```

**d) Selftest o'tsin:**

```
python bk.py doctor
```

## 2. Qurish

```
python -m PyInstaller bk.spec --noconfirm --distpath dist --workpath dist_build
```

Log `build_exe<N>.log` ga yozilsa yaxshi (mavjud raqamdan keyingisi).

## 3. Qurilgan exe ni tekshirish

```
dist\bk.exe doctor
dist\bk.exe siem query net-port-scan --siem sentinel
dist\bk.exe kb info
```

`bk.exe doctor` **exe ichida** ishlashi muhim: u paket ichidagi YAML resurslar va
`hiddenimports` to'g'ri kirganini tekshiradi. Manbada o'tib, exe da yiqilsa —
sabab deyarli har doim 1-a yoki 1-b qadami.

## 4. Tarqatilgan nusxani yangilash

**Avval `bk.exe` jarayonlarini to'xtating.** Brauzerni yopish yetarli emas —
`WEB-UI.bat` serverni alohida jarayonda qoldiradi:

```powershell
Get-Process bk -ErrorAction SilentlyContinue | Stop-Process -Force
```

Keyin:

```
D:\Tools\blue-kit-dist\YANGILA.bat
```

U to'rt narsani ko'chiradi: `bk.exe`, `static\`, `data\samples\`, hujjatlar
(`PLAYBOOK_FLOW.md`, `PLAYBOOK.html`, `CHEATSHEET.html`) va `TEKSHIRUV.bat`.

## 5. Yakuniy tekshiruv

```
D:\Tools\blue-kit-dist\TEKSHIRUV.bat
```

9 ta tekshiruv o'tishi kerak. Keyin qo'lda:

```
D:\Tools\blue-kit-dist\WEB-UI.bat
```

Brauzerda **Ctrl+F5** (eski static kesh qolmasin), keyin har bir tab ochilishini
va SIEM tabida "So'rov yaratish" tugmasi **haqiqatan** ishlashini ko'ring.

> Web UI ni faqat `unittest` bilan tekshirish yetarli emas. 23-sent-2026 da
> 150/150 test yashil bo'lgan holda brauzerda `Cannot read properties of
> undefined` xatosi chiqqan edi — Python testlari frontend-backend mos
> kelmasligini ushlamaydi.

## 6. Musobaqadan oldin (bir marta, har bir noutbukda)

- [ ] Defender papka istisnosi qo'yilgan va **sinovdan o'tgan**
- [ ] `TEKSHIRUV.bat` toza noutbukda 9/9 bergan
- [ ] `bk.exe doctor` o'sha mashinada o'tgan
- [ ] Hayabusa / EvtxECmd + .NET runtime o'rnatilgan va sinalgan
- [ ] Har bir jamoa a'zosi o'z rolidagi buyruqlarni bir marta yurgizib ko'rgan
