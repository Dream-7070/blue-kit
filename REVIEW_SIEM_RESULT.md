# SIEM Generator Kodini Tekshirish Natijalari

Umumiy holat: Asosiy mantiq to'g'ri shakllantirilgan, lekin Sentinel maydonlar xaritasida va LogScale (CQL) sintaksisida jiddiy xatolar mavjud. Boshqa SIEM'lar (Splunk, QRadar, ES|QL, KQL, DQL) katta ehtimol bilan to'g'ri ishlaydi.

## Xatolar jadvali

| Jiddiylik | Fayl:qator | Muammo | To'g'ri variant |
|---|---|---|---|
| **YUQORI** | luekit/siem/dialects.py:90-100 | **Sentinel maydonlar kelishmovchiligi:** SecurityEvent jadvali (IpAddress) va CommonSecurityLog jadvali (DestinationIP, SentBytes) maydonlari bitta xaritada aralashib ketgan. Natijada xavfsizlik devori so'rovlari (masalan, 
et-port-scan) IpAddress maydonini izlaydi va natija bermaydi, chunki tarmoq jurnallarida SourceIP ishlatiladi. | Maydonlarni jadvalga qarab dinamik hal qilish (yoki coalesce orqali coalesce(SourceIP, IpAddress)) tavsiya etiladi. Minimal tuzatish: tarmoq jurnallari uchun src_ip
i SourceIPga o'zgartirish. |
| **YUQORI** | luekit/siem/builder.py:870-876 | **LogScale (CQL) agregatsiya sintaksisida xato:** count(field=X, distinct=true, as=Y) va sum(field=bytes_sent) kabi yozilgan. CQL'da count() funksiyasi distinct=true yoki ield parametrlarini qabul qilmaydi. sum() funksiyasi esa sum(bytes_sent, as=...) shaklida argument oladi. | sum uchun: sum(%s, as=%s). Distinct count uchun CQL maxsus groupBy (masalan groupBy([src_ip, dest_port])) talab qiladi, to'g'ridan-to'g'ri aggregate ichida qilib bo'lmaydi. Uni to'g'rilash kerak. |
| **O'RTA** | luekit/siem/dialects.py:137-154 | **Wazuh case sensitivity (katta-kichik harf):** data.win.eventdata.commandLine va boshqa eventdata maydonlari kichik harf bilan yozilgan. Elasticsearch va Wazuh agentlari Windows voqealarini XML'dan olganda asl nomini (CamelCase) saqlaydi, masalan CommandLine. | data.win.eventdata.CommandLine, data.win.eventdata.TargetUserName, data.win.eventdata.Image shaklida bosh harflar bilan yozilishi kerak. |
| **O'RTA** | luekit/siem/builder.py:711 | **Chronicle (UDM Search) CIDR sintaksisi:** 
et.ip_in_range_cidr(native, block) bu YARA-L funksiyasi. UDM Search qidiruv qatorida (Chronicle UI) garchi funksiya qabul qilinsa-da, u oddiy so'rovlarda to'g'ridan to'g'ri operator talab qiladi. | UDM Search'ning to'g'ridan to'g'ri imkoniyati: %s = "%s" (masalan, principal.ip = "10.0.0.0/8"). |
| **O'RTA** | luekit/siem/dialects.py:75-87 | **Splunk CIM standartlaridan chetlanish:** New_Process_Name, Process_Command_Line kabi maydonlar faqat TA-Windows orqali ishlaydi va Splunk CIM'ga to'la mos emas. | Splunk CIM standartidagi maydonlar ishlatilgani ma'qul: process_name, parent_process_name, process. |
| **PAST** | luekit/siem/builder.py:890 | **LogScale (CQL) sort:** sort(field=%s, order=desc) kodi LogScale'da qo'shimcha parametr nomsiz qabul qilinadi. | sort(%s, order=desc, limit=%d) yoki sort([%s], order=desc) shakli to'g'riroq (garchi hozirgisi ishlasa ham, idiomatik emas). |

## Boshqa tekshirilgan va TO'G'RI deb topilgan jihatlar:

- **Chronicle (UDM Search) Regex:** 
ocase modifikatori va /.../ sintaksisi haqiqatan UDM Search'da qabul qilinadi (YARA-L qoidalari).
- **Sumo Logic:** !isPrivateIP(dest_ip), count_distinct(x) kabi barcha funksiyalar to'g'ri formatda.
- **ArcSight Logger:** deviceEventClassId="4624" AND msg CONTAINS "10" ArcSight CEF qidiruvi uchun to'liq mos keladi.
- **QRadar AQL:** INCIDR('10.0.0.0/8', sourceip) (argumentlar ketma-ketligi to'g'ri), "Command Line" atrofida qo'shtirnoq, va LIMIT ... LAST 7 DAYS tartibi AQL uchun mutlaqo to'g'ri.
- **ES\|QL:** NOW() - 7 days, CIDR_MATCH, COUNT_DISTINCT, KEEP komandalari to'g'ri va o'z joyida yozilgan.
- **DQL / Lucene:** _LUCENE_SPECIAL orqali belgilarni, shu jumladan bo'shliqlarni (space) qochirish \  amaliyoti Lucene, Kibana KQL va Graylog uchun to'g'ri sintaksisni ta'minlaydi. 
- **Hunt logikasi (catalog.py):** Windows hodisalari (4624, 4625, 4720, 7045 va h.k.) hamda Sysmon (10, 12, 13, 19-21) to'g'ri keltirilgan. Defender uchun EVENT_ID_TRANSLATION ham to'g'ri (local guruh qo'shilishlari UserAccountAddedToLocalGroup sifatida DeviceEvents jadvalida ko'rinadi).
- **Xavfsizlik / Qochirish (builder.py):** escape_inner har bir dialekt uchun o'ziga xos (AQL uchun '', KQL uchun "", KQL/DQL uchun \) amalga oshirilgani, AQL va boshqa qidiruv tizimlarida injection hujumlarining oldini oladi.

### Xulosa

- **QRadar (AQL), Splunk (SPL), Defender/Sentinel (KQL), ES|QL, Sumo Logic, ArcSight** va **Lucene (DQL)** dialektlariga to'liq ishonsa bo'ladi (ular aniq sintaktik qoidalarga mos).
- **LogScale (CQL)** va **Sentinel (KQL)** ustida ishlash (maydonlar xaritasi aralashuvi va aggregatsiya) qayta ko'rib chiqilishi shart, ularsiz ayrim so'rovlar ishdan chiqadi (qulaydi).
- **Wazuh** muhiti uchun harflar registri to'g'rilanishi lozim, aks holda voqealar topilmaydi.
