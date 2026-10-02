# FEEDBACK_DOCTOR — ikkita nuqson

Ish umuman yaxshi bajarilgan. 12 ta mustaqil tekshiruvimdan 10 tasi o'tdi:
sabablar bir-biridan farq qiladi, buyruqlarda haqiqiy xizmat nomi bor, baseline
farqi va shubhali papka topiladi, T1574.009 ishlaydi, qayta to'xtatuvchi vazifa
aniqlanadi, HTML hisobot oflayn va escape qilingan.

**Ishlayotgan qismlarni qayta yozmang.** Faqat quyidagi ikkitasini tuzating.

## 1-nuqson (YUQORI) — `sla_result` shakli o'ylab topilgan

`bluekit/resp/servicedoctor.py:149-152`:

```python
if state in ('running', 'active') and sla_result:
    tcp_ok = sla_result.get('tcp') == 'ok'
    http_ok = sla_result.get('http') == 'ok'
```

Bunday tuzilma hech qaerda yo'q. `bluekit/resp/sla.py` dagi `check()` **aslida**
shuni qaytaradi (bitta xizmat uchun):

```python
{
  'name': 'web-prod-01 HTTP',
  'board_name': 'Poseidon',
  'state': 'down',
  'ok': False,
  'detail': '...',
  'checks': [
     {'type': 'tcp',  'ok': True,  'critical': True,  'ms': 12, 'detail': 'ochiq',
      'target': '10.10.20.11:80'},
     {'type': 'http', 'ok': False, 'critical': True,  'ms': 3020, 'detail': '500',
      'url': 'http://10.10.20.11/'},
  ],
  'checked_at': '...',
}
```

Ya'ni tur `checks` ro'yxatida `type` maydonida, natija esa `ok` (bool) da.
Hozirgi kod hech qachon ishlamaydi — mening sinovimda `tcp` ok + `http` yiqilgan
holatda `"sabab aniqlanmadi"` qaytardi.

**Kerakli xulq** (SPEC_DOCTOR.md ning 10 va 11-qatorlari):

| Holat | Sabab |
|---|---|
| `state` Running, `checks` da `type=tcp` bor va `ok=False` | "Xizmat ishlayapti, lekin port tinglanmayapti" |
| `checks` da `type=tcp` `ok=True`, `type=http` `ok=False` | "Port ochiq, ilova javob bermayapti" |

`sla_result` berilmasa — hozirgidek, bu sabablar umuman qo'shilmasin.

`checks` ichidagi `detail` ni `evidence` ga qo'shing (masalan HTTP kodi) — u
analitikka nima bo'lganini aytadi.

## 2-nuqson (O'RTA) — Linux holat lug'ati to'liq emas

```
snapshot: {'os': 'linux', services: [{'name':'nginx', 'state':'inactive',
                                      'start_mode':'enabled', ...}]}
diagnose(...) -> [{'cause': 'sabab aniqlanmadi', ...,
                   'suggested_fix_command': 'systemctl status nginx'}]
```

Bu xizmat **to'xtagan va yoqilgan** — ya'ni "Xizmat to'xtagan" sababi chiqishi va
`systemctl start nginx` taklif qilinishi kerak edi. Sabab: "to'xtagan" qoidasi
faqat `start_mode == 'Auto'` ni qaraydi, Linux esa `enabled` deydi.

`start_mode` = `disabled` holati **to'g'ri ishlaydi** — unga tegmang.

Qabul qilinishi kerak bo'lgan qiymatlar (katta-kichik harfsiz):

| Ma'no | Qiymatlar |
|---|---|
| Ishlayapti | `running`, `active` |
| To'xtagan | `stopped`, `inactive`, `dead`, `failed`, `exited` |
| Avtomatik yoqilgan | `auto`, `automatic`, `enabled`, `static` |
| O'chirilgan | `disabled`, `masked` |

`failed` holati uchun alohida sabab qo'shsangiz yaxshi bo'lardi ("Xizmat ishga
tushishga urinib yiqilgan") — lekin bu majburiy emas.

## Testlar

`tests/test_doctor.py` ga qo'shing (mavjudlarini o'chirmang):

1. `sla_result` = yuqoridagi haqiqiy shakl (`checks` ro'yxati bilan), `tcp` ok +
   `http` ok=False → natijada "ilova javob bermayapti" ma'nosidagi sabab bor va
   `cause` `"sabab aniqlanmadi"` **emas**.
2. `tcp` ok=False → "port tinglanmayapti" ma'nosidagi sabab.
3. Linux: `state='inactive'`, `start_mode='enabled'` → "to'xtagan" sababi va
   `suggested_fix_command` ichida `systemctl start`.
4. Linux: `state='failed'` → sabab aniqlanadi (`"sabab aniqlanmadi"` emas).

## Qabul

```
python -m unittest discover -s tests -p "test_*.py" -q
```

Hozir **98 ta test** yashil — hammasi yashil qolsin.

Hisobotda `sla_result` bilan va Linux `inactive` holatidagi `diagnose()`
chiqishini **ko'chirib** keltiring.

`bk.py`, web, `resp/sla.py`, `resp/triage.py`, `resp/report.py` va boshqa
modullarga **tegmang** — nuqson faqat `servicedoctor.py` da.
