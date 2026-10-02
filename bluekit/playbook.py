# bluekit/playbook.py
import datetime

KILL_CHAIN = [
    {
        "key": "recon", "num": 1, "name_en": "Reconnaissance", "name_uz": "Razvedka",
        "desc": "Hujumchi nishonni o'rganadi: portlar, xizmatlar, xodimlar, ochiq web.",
        "tactics": ["Reconnaissance", "Discovery"],
        "techniques": ["T1595", "T1595.002", "T1590", "T1046", "T1087"],
        "hunts": ["net-port-scan", "web-attack-patterns"],
        "tools": ["bk siem query net-port-scan", "bk logs analyze <firewall.csv>"],
        "evidence": "Bitta manbadan ko'p portga qisqa ulanishlar; 404/400 to'lqini; skaner User-Agent."
    },
    {
        "key": "weaponization", "num": 2, "name_en": "Weaponization", "name_uz": "Qurollantirish",
        "desc": "Zararli hujjat/yuklama tayyorlanadi. Bu bosqich nishon loglarida deyarli KO'RINMAYDI.",
        "tactics": ["Resource Development"],
        "techniques": ["T1588", "T1587.001", "T1608"],
        "hunts": [],
        "tools": ["bk mail scan <xat.eml>", "bk decode --file <fayl>"],
        "evidence": "Faqat qo'lga tushgan ilova/makro orqali: makro, obfuskatsiya, yuklab oluvchi URL."
    },
    {
        "key": "delivery", "num": 3, "name_en": "Delivery", "name_uz": "Yetkazish",
        "desc": "Yuklama qurbonga yetkaziladi: phishing xat, ilova, havola, ochiq xizmat.",
        "tactics": ["Initial Access"],
        "techniques": ["T1566.001", "T1566.002", "T1189", "T1190", "T1078", "T1133"],
        "hunts": ["web-attack-patterns", "auth-external-rdp"],
        "tools": ["bk mail scan <xat.eml>", "bk siem query web-attack-patterns", "bk siem query auth-external-rdp"],
        "evidence": "SMTP/proxy logi, mail gateway, birinchi tashqi IP, birinchi shubhali ilova."
    },
    {
        "key": "exploitation", "num": 4, "name_en": "Exploitation", "name_uz": "Ekspluatatsiya",
        "desc": "Yuklama ishga tushadi: makro bosiladi, zaiflik ishlatiladi, kod bajariladi.",
        "tactics": ["Execution", "Privilege Escalation"],
        "techniques": ["T1204.002", "T1203", "T1059.001", "T1059.003", "T1047", "T1548.002", "T1190"],
        "hunts": ["exec-office-child", "exec-encoded-powershell", "exec-lolbin", "exec-wmi-remote", "exec-uac-bypass", "auth-bruteforce", "auth-password-spray"],
        "tools": ["bk siem query exec-office-child", "bk decode --detect", "bk sigma scan <fayl>"],
        "evidence": "WINWORD.EXE -> powershell.exe ota-bola zanjiri; -enc bazasi; 4688/Sysmon 1."
    },
    {
        "key": "installation", "num": 5, "name_en": "Installation", "name_uz": "O'rnashish",
        "desc": "Hujumchi qayta yuklashdan keyin ham qolishni ta'minlaydi.",
        "tactics": ["Persistence", "Defense Evasion"],
        "techniques": ["T1543.003", "T1053.005", "T1547.001", "T1546.003", "T1136.001", "T1098", "T1505.003"],
        "hunts": ["persist-service-install", "persist-scheduled-task", "persist-run-key", "persist-wmi-subscription", "persist-new-user", "persist-admin-group"],
        "tools": ["bk siem hunts --category persistence", "bk resp triage <snap.json> --baseline <base.json>"],
        "evidence": "7045 yangi xizmat; 4698 vazifa; Run kaliti; 4720/4732; webshell fayli."
    },
    {
        "key": "c2", "num": 6, "name_en": "Command & Control", "name_uz": "Boshqaruv kanali (C2)",
        "desc": "Zararlangan host tashqaridagi boshqaruv serveri bilan gaplashadi.",
        "tactics": ["Command and Control"],
        "techniques": ["T1071.001", "T1071.004", "T1571", "T1572", "T1105", "T1008"],
        "hunts": ["c2-rare-port", "c2-dns-tunnel", "exec-lolbin"],
        "tools": ["bk siem query c2-rare-port", "bk siem query c2-dns-tunnel", "bk hunt beacons <firewall.csv>"],
        "evidence": "Davriy (jitterli) ulanishlar; noyob subdomenlar oqimi; noodatiy port; LOLBin yuklab olish."
    },
    {
        "key": "actions", "num": 7, "name_en": "Actions on Objectives", "name_uz": "Maqsadga erishish",
        "desc": "Asl maqsad: o'g'irlash, pul o'tkazish, yon harakat, ishdan chiqarish, izni yo'qotish.",
        "tactics": ["Credential Access", "Lateral Movement", "Collection", "Exfiltration", "Impact", "Inhibit Response Function"],
        "techniques": ["T1003.001", "T1003.003", "T1558.003", "T1021.001", "T1021.002", "T1570", "T1041", "T1048", "T1567", "T1490", "T1685", "T1685.005", "T1657", "T1565.001", "T0816", "T0821", "T0836", "T0858", "T0881"],
        "hunts": ["cred-lsass-access", "cred-ntds", "auth-kerberoast", "lateral-admin-share", "lateral-remote-service", "exfil-large-upload", "evasion-log-cleared", "evasion-av-disabled", "evasion-recovery-inhibit", "ics-plc-stop", "ics-write-command", "ics-program-download", "ics-engineering-tool", "ics-hmi-service-stop"],
        "tools": ["bk siem query exfil-large-upload", "bk resp fraud <snap.json>", "bk siem hunts --search ics"],
        "evidence": "Katta chiquvchi hajm; 5140/5145; LSASS o'qish; 1102 jurnal tozalandi; PLC STOP; bank o'tkazmasi."
    }
]

PHASES = [
    {
        "id": "0", "title_uz": "Tayyorgarlik (musobaqa boshlanishidan oldin)", "goal_uz": "Bir marta qilinadi. Bu yerdagi 30 soniyani tejab, keyin bir soat yo'qotasiz.",
        "steps": [
            {"id": "0.1", "title_uz": "Tashkilotchilardan qoidalarni aniqlash (ota/sub-texnika, urinishlar soni, ATT&CK versiyasi, qaysi xizmatlar baholanadi, hostlarga kirish usuli)", "cmd": None, "kc": [], "must": True, "note": "Javoblar strategiyani o'zgartiradi. PLAYBOOK_FLOW.md 0-faza ro'yxatiga qarang. Kirish usuli: RDP / SSH / WinRM / faqat SIEM — 0.4 qaysi yo'l bilan qilinishini shu belgilaydi."},
            {"id": "0.1.1", "title_uz": "↳ Javoblarning qisqa xulosasini shu qadamning izohiga yozish", "cmd": None, "kc": [], "must": True, "note": "Namuna: sub-texnika majburiy | 3 urinish/savol | ATT&CK v19 | SLA: WEB01:443 DB01:5432 | checker IP berilmagan | kirish: RDP+SSH"},
            {"id": "0.1.2", "title_uz": "↳ To'liq jadvalni case\\<sana>\\jurnal.md ga yozish: Savol | Javob | Strategiyaga ta'siri", "cmd": None, "kc": [], "must": False, "note": "Masalan: 'faqat sub-texnika' -> answers rank da --prefer-parent ISHLATILMAYDI; ATT&CK v18 yoki eski -> kb validate ko'rsatgan yangi ID emas, eski (revoked) ID topshiriladi."},
            {"id": "0.1.3", "title_uz": "↳ Savollarni CTF Tracker ga kiritish (nomzod '?', Status '0/<limit>')", "cmd": None, "kc": [], "must": False, "note": "Tracker da urinish limiti yo'q — hisob Status maydonida va 'bk answers submit <ID> <natija> --note \"Q3 urinish-1\" --ledger case\\<sana>\\answers.json' da yuritiladi."},
            {"id": "0.2", "title_uz": "Kit shu noutbukda ishlayaptimi", "cmd": "bk doctor", "kc": [], "must": True, "note": "Avval kit papkasiga o'ting (CLI-oyna.bat yoki cd D:\\Tools\\blue-kit-dist). '.\\bk.exe не распознано / not recognized' = noto'g'ri papka, doctor xatosi EMAS. Oxirgi qator: HAMMASI JOYIDA / OGOHLANTIRISH BOR / XATOLAR BOR; birinchi ustunda XATO yoki OGOH qatorlarini qidiring."},
            {"id": "0.3", "title_uz": "KB versiyasi va yo'li to'g'rimi", "cmd": "bk kb info", "kc": [], "must": True, "note": "Versiyani 0.1 dagi tashkilotchi versiyasi bilan solishtiring va shu yerga yozing (masalan: kit 19.2 = tashkilotchi v19)."},
            {"id": "0.4", "title_uz": "HAR BIR nishon hostdan T0 (birinchi) snapshot — toza bo'lmasa ham", "cmd": "powershell -ExecutionPolicy Bypass -File responder\\collect_windows.ps1 -Out case\\<sana>\\base_<HOST>.json", "kc": [], "must": True, "note": "Tashkilotchilar TOZA host bermasligi mumkin — baribir oling. T0 snapshot 'toza' emas, 'boshlang’ich' nuqta: 2 kun davomida hujumchi QO'SHGAN har bir narsa keyingi snapshot bilan solishtirganda high ishonch bilan chiqadi. Toza baseline bo'lmasa 4.2 dagi zaxira usullarga qarang. <HOST> o'rniga host nomi, qavslarsiz (base_WEB01.json). Qaysi usul — 0.4.1-0.4.3; tartib: avval baholanadigan serverlar, keyin ish stansiyalari."},
            {"id": "0.4.1", "title_uz": "↳ Windows, RDP: skriptni Ctrl+C/Ctrl+V bilan hostning C:\\Windows\\Temp ga ko'chirib, ADMIN PowerShell da yurgizish; JSON ni xuddi shunday case\\<sana>\\ ga qaytarish", "cmd": "powershell -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\collect_windows.ps1 -Out C:\\Windows\\Temp\\base_$env:COMPUTERNAME.json", "kc": [], "must": False, "note": "RDP disk ulashni (Local Resources -> Drives) ISHLATMANG: buzilgan hostdagi hujumchi sessiya davomida noutbuk diskini ko'radi."},
            {"id": "0.4.2", "title_uz": "↳ Windows, WinRM: noutbukdan to'g'ridan-to'g'ri (RDP siz)", "cmd": "$c = Get-Credential; $j = Invoke-Command -ComputerName <HOST> -Credential $c -FilePath responder\\collect_windows.ps1; [IO.File]::WriteAllText(\"$PWD\\case\\<sana>\\base_<HOST>.json\", ($j -join \"`n\"))", "kc": [], "must": False, "note": "Out-File -Encoding utf8 ISHLATMANG — PowerShell 5.1 BOM yozadi. Noutbuk domenda bo'lmasa oldin (o'zingiz): Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value '<HOST>' -Force"},
            {"id": "0.4.3", "title_uz": "↳ Linux, SSH: skriptni ko'chirish, sudo bilan yurgizish, JSON ni qaytarish (sudo siz root cron va .ssh ko'rinmaydi)", "cmd": "scp responder\\collect_linux.sh user@<HOST>:/tmp/ ; ssh -t user@<HOST> \"sudo bash /tmp/collect_linux.sh -o /tmp/base_<HOST>.json && sudo chmod 644 /tmp/base_<HOST>.json\" ; scp user@<HOST>:/tmp/base_<HOST>.json case\\<sana>\\", "kc": [], "must": False, "note": "Hostning o'zida bo'lsangiz: sudo bash collect_linux.sh -o base_$(hostname).json"},
            {"id": "0.4.4", "title_uz": "↳ Fayl chala emasligini tekshirish: sonlar 0 emas, errors bo'sh", "cmd": "$s = Get-Content case\\<sana>\\base_<HOST>.json -Raw -Encoding utf8 | ConvertFrom-Json; \"users=$($s.users.Count) services=$($s.services.Count) tasks=$($s.tasks.Count) autoruns=$($s.autoruns.Count) errors=$($s.errors.Count)\"; $s.errors", "kc": [], "must": True, "note": "errors da 'Access denied' -> admin/sudo siz yig'ilgan, qayta oling. JSON ni hech kimga yopishtirmang — akkaunt va host nomlari bor."},
            {"id": "0.4.5", "title_uz": "↳ T0 ni faqat o'qiladigan qilish (adashib ustiga yozilmasin)", "cmd": "attrib +r case\\<sana>\\base_*.json", "kc": [], "must": True, "note": "T0 qayta olinmaydi. 2-kunda yangi papka ochiladi, lekin T0 1-kun papkasida qoladi: --baseline case\\<1-kun>\\base_<HOST>.json"},
            {"id": "0.4.6", "title_uz": "↳ Jurnalga vaqtni yozish: vaqt (Toshkent) | HOST | T0 snapshot | usul | kim", "cmd": None, "kc": [], "must": True, "note": "Kollektor o'zi 4688 / PowerShell 4104 / SSH login izi qoldiradi — keyin SIEM da o'z izingizni hujum deb o'ylamaslik uchun."},
            {"id": "0.5", "title_uz": "Checker/monitoring IP larini topish va SLA konfigini yasash", "cmd": "bk resp discover (Get-ChildItem case\\<sana>\\base_*.json).FullName --sla-out services.yaml --allowlist-out protected.yaml", "kc": [], "must": True, "note": "C-1: checker IP ni bloklasangiz availability ballingiz nolga tushadi. PowerShell da base_*.json ni bk o'zi ochmaydi — (Get-ChildItem ...).FullName shakli shart."},
            {"id": "0.6", "title_uz": "Case papkasi va nom konvensiyasi", "cmd": None, "kc": [], "must": False, "note": "case\\<sana>\\<scope>_<hunt-id>_<vaqt>.csv"},
            {"id": "0.7", "title_uz": "Rollarni taqsimlash: Hunter-1 (Windows/AD), Hunter-2 (Linux/Web/Net), Responder, Kapitan", "cmd": None, "kc": [], "must": True, "note": None}
        ]
    },
    {
        "id": "1", "title_uz": "SIEM dan loglarni olish", "goal_uz": "Zarardan orqaga yuring, phishingdan oldinga emas (C-2).",
        "steps": [
            {"id": "1.1", "title_uz": "Zarar: tashqariga nima chiqdi / nima ishdan chiqdi", "cmd": "bk siem query exfil-large-upload --siem qradar --days 7", "kc": ["actions"], "must": True, "note": None},
            {"id": "1.2", "title_uz": "Boshqaruv kanali bormi", "cmd": "bk siem query c2-rare-port --siem qradar --days 7", "kc": ["c2"], "must": True, "note": None},
            {"id": "1.3", "title_uz": "DNS tunnel bormi", "cmd": "bk siem query c2-dns-tunnel --siem qradar --days 7", "kc": ["c2"], "must": False, "note": None},
            {"id": "1.4", "title_uz": "Qayoqqa tarqalgan (yon harakat)", "cmd": "bk siem query lateral-admin-share --siem qradar --days 7", "kc": ["actions"], "must": True, "note": None},
            {"id": "1.5", "title_uz": "Qayerga o'rnashgan", "cmd": "bk siem pack --siem qradar --category persistence --out q_persist.txt", "kc": ["installation"], "must": True, "note": None},
            {"id": "1.6", "title_uz": "Qanday bajarilgan", "cmd": "bk siem query exec-encoded-powershell --siem qradar --days 7", "kc": ["exploitation"], "must": True, "note": None},
            {"id": "1.7", "title_uz": "Qanday kirgan", "cmd": "bk siem pack --siem qradar --category auth --out q_auth.txt", "kc": ["delivery", "exploitation"], "must": True, "note": None},
            {"id": "1.8", "title_uz": "Izni yo'qotish urinishi bormi", "cmd": "bk siem query evasion-log-cleared --siem qradar --days 7", "kc": ["actions"], "must": False, "note": None},
            {"id": "1.9", "title_uz": "ICS/OT (2-kun): PLC va HMI", "cmd": "bk siem hunts --search ics", "kc": ["actions"], "must": False, "note": None},
            {"id": "1.10", "title_uz": "Eksport o'qiladimi (ustunlar taniladimi)", "cmd": "bk logs columns case\\<sana>\\f.csv", "kc": [], "must": True, "note": None}
        ]
    },
    {
        "id": "2", "title_uz": "Loglarni tahlil qilish", "goal_uz": "Har bir eksportdan ATT&CK texnikasi va IOC chiqarish.",
        "steps": [
            {"id": "2.1", "title_uz": "Eksportni tahlil qilish", "cmd": "bk logs analyze case\\<sana>\\f.csv --preset qradar --json-out out\\f.json", "kc": ["exploitation", "installation", "c2", "actions"], "must": True, "note": None},
            {"id": "2.2", "title_uz": "Sigma qoidalari bilan qoplash (3700+ qoida)", "cmd": "bk sigma scan case\\<sana>\\f.csv --preset qradar --json --out out\\sigma.json", "kc": ["exploitation", "installation", "actions"], "must": False, "note": None},
            {"id": "2.3", "title_uz": "Obfuskatsiyani ochish (base64 / -enc / hex / gzip)", "cmd": "bk decode --file case\\<sana>\\f.csv --detect", "kc": ["exploitation", "weaponization"], "must": False, "note": None},
            {"id": "2.4", "title_uz": "Phishing xatini tahlil qilish", "cmd": "bk mail scan <xat.eml>", "kc": ["delivery", "weaponization"], "must": False, "note": "Xat topilmasa bu qadamni 'o'tkazib yuborildi' qiling — C-2 bo'yicha bu normal."},
            {"id": "2.5", "title_uz": "Beacon davriyligi (C2 ni matematik tasdiqlash)", "cmd": "bk hunt beacons case\\<sana>\\firewall.csv", "kc": ["c2"], "must": False, "note": None}
        ]
    },
    {
        "id": "3", "title_uz": "Attack chain va javoblar", "goal_uz": "Ajralgan topilmalarni bitta zanjirga ulash va ATT&CK ID larini topshirish.",
        "steps": [
            {"id": "3.1", "title_uz": "Hamma fayllarni bitta zanjirga", "cmd": "bk ir chain (Get-ChildItem case\\<sana>\\*.csv).FullName --lang uz", "kc": ["recon", "delivery", "exploitation", "installation", "c2", "actions"], "must": True, "note": "PowerShell da *.csv ni bk o'zi ochmaydi — (Get-ChildItem ...).FullName shaklini ishlating."},
            {"id": "3.2", "title_uz": "Mashina o'qiydigan chiqish", "cmd": "bk ir chain (Get-ChildItem case\\<sana>\\*.csv).FullName --json --out out\\chain.json", "kc": [], "must": True, "note": None},
            {"id": "3.3", "title_uz": "Javoblarni ishonch bo'yicha reytinglash", "cmd": "bk answers rank out\\chain.json out\\f.json --ledger answers.json", "kc": [], "must": True, "note": None},
            {"id": "3.4", "title_uz": "ID ni topshirishdan OLDIN tekshirish (v19 da raqamlar o'zgargan)", "cmd": "bk kb validate T1059.001 T1053.005", "kc": [], "must": True, "note": "T1070.001 -> T1685.005, T1562.001 -> T1685. Eski ID topshirsangiz urinish behuda ketadi."},
            {"id": "3.5", "title_uz": "Topshirilgan javobni daftarga yozish", "cmd": "bk answers submit T1059.001 accepted --ledger answers.json", "kc": [], "must": True, "note": "C-5: urinishlar valyuta. Daftarsiz to'rt kishi bir ID ni ikki marta topshiradi."}
        ]
    },
    {
        "id": "4", "title_uz": "Responder (tuzatish va availability)", "goal_uz": "Birinchi tuzatgan ochko oladi. Lekin dalil olinmaguncha hech narsa o'chirilmaydi (C-3).",
        "steps": [
            {"id": "4.1", "title_uz": "Nishon hostdan JORIY snapshot", "cmd": "powershell -ExecutionPolicy Bypass -File responder\\collect_windows.ps1 -Out snap_<host>.json", "kc": [], "must": True, "note": None},
            {"id": "4.2", "title_uz": "Triaj: baseline + loglar bilan solishtirish", "cmd": "bk resp triage snap_<host>.json --baseline base_<host>.json --from-logs out\\f.json", "kc": ["installation", "c2", "actions"], "must": True, "note": "--from-logs ga 'logs analyze --json-out' fayli beriladi, 'ir chain --json' EMAS. TOZA BASELINE BO'LMASA (o'lchangan: baselinesiz high topilmalar 4 tadan 1 taga tushadi) zaxira tartibi: (1) --baseline ga o'sha hostning T0 snapshotini bering — musobaqa davomida qo'shilgani chiqadi; (2) --baseline ga BIR XIL ROLLI qo'shni hostni bering (bir xil obrazdan) — lekin ikkalasi aynan bir xil zararlangan bo'lsa hujum butunlay ko'rinmay qoladi, shuning uchun bu ikkinchi fikr, asosiy manba emas; (3) uyda toza VM dan olingan etalon baseline; (4) baseline umuman bo'lmasa --from-logs dagi ✔ LOG ustuni asosiy ishonch manbaiga aylanadi."},
            {"id": "4.3", "title_uz": "Moliyaviy firibgarlik izlari (1-kun stsenariysi)", "cmd": "bk resp fraud snap_<host>.json", "kc": ["actions"], "must": False, "note": None},
            {"id": "4.4", "title_uz": "Tozalash buyruqlarini yasash (avtomatik BAJARILMAYDI)", "cmd": "bk resp fix snap_<host>.json --from-logs out\\f.json --os windows --protected protected.yaml", "kc": ["installation", "c2", "actions"], "must": True, "note": None},
            {"id": "4.5", "title_uz": "Dalil olinganini tasdiqlash: nima o'chirilyapti, to'liq yo'li, vaqti — jurnalga", "cmd": None, "kc": [], "must": True, "note": "C-3: Responder vazifani o'chiradi — Hunter o'sha vazifa nomi bilan T1053.005 ni isbotlayotgan edi."},
            {"id": "4.6", "title_uz": "Buyruqlarni qo'lda bajarish va vaqtini yozib qo'yish", "cmd": None, "kc": [], "must": True, "note": "Jurnal ustunlari: vaqt (Toshkent) | host | nima qilindi | buyruq | kim"},
            {"id": "4.7", "title_uz": "Xizmatlar holati (availability)", "cmd": "bk resp sla services.yaml --watch --interval 30", "kc": [], "must": True, "note": None},
            {"id": "4.8", "title_uz": "To'xtagan xizmatning sababi va tuzatish buyrug'i", "cmd": "bk resp doctor snap_<host>.json nginx --baseline base_<host>.json", "kc": [], "must": False, "note": None},
            {"id": "4.9", "title_uz": "Hujumchi ko'rgan parollarni almashtirish", "cmd": None, "kc": [], "must": True, "note": "C-9: aks holda u oddiy login bilan qaytadi va loglarda 'normal kirish' bo'lib ko'rinadi."},
            {"id": "4.10", "title_uz": "Tuzatilgan joyni qayta tekshirish (qayta buziladi)", "cmd": "bk resp triage snap_<host>.json --baseline base_<host>.json", "kc": [], "must": True, "note": None}
        ]
    },
    {
        "id": "5", "title_uz": "Hisobot", "goal_uz": "Ball dalil bilan beriladi. Tuzatish vaqti ham dalil.",
        "steps": [
            {"id": "5.1", "title_uz": "IR hisoboti (uz/ru/en)", "cmd": "bk ir report (Get-ChildItem case\\<sana>\\*.csv).FullName --lang uz --out report_uz.md", "kc": [], "must": True, "note": None},
            {"id": "5.2", "title_uz": "Log tahlili HTML hisoboti", "cmd": "bk logs analyze case\\<sana>\\f.csv --preset qradar --out r.html", "kc": [], "must": False, "note": None},
            {"id": "5.3", "title_uz": "Umumiy hisobot generatori", "cmd": "bk report", "kc": [], "must": False, "note": None},
            {"id": "5.4", "title_uz": "Remediatsiya jurnalini hisobotga qo'shish", "cmd": None, "kc": [], "must": True, "note": None},
            {"id": "5.5", "title_uz": "Topshirilgan ID lar daftarini yakunlash", "cmd": "bk answers rank out\\chain.json --ledger answers.json", "kc": [], "must": True, "note": None}
        ]
    }
]

RULES = [
    {"id": "C-1", "title_uz": "Checker IP ni aniqlamaguncha hech narsa bloklanmaydi.", "body_uz": "Tashkilotchilarning ball hisoblovchi boti xizmatlarni tashqaridan tekshiradi. Uni hujumchi deb bloklasangiz — availability ballingiz nolga tushadi va buni hech kim aytmaydi."},
    {"id": "C-2", "title_uz": "Zarardan orqaga yuring, phishingdan oldinga emas.", "body_uz": "Phishing xati logda bo'lmasligi mumkin, zarar esa aniq. Orqaga yurganda har qadamda tekshirilgan fakt bo'ladi."},
    {"id": "C-3", "title_uz": "Tuzatishdan oldin dalilni oling.", "body_uz": "Responder vazifani o'chiradi — Hunter o'sha vazifa nomi bilan T1053.005 ni isbotlayotgan edi. Har bir tuzatishdan oldin: nima o'chirilyapti, to'liq yo'li, vaqti — jurnalga."},
    {"id": "C-4", "title_uz": "SLA buzilishi hamma narsani to'xtatadi.", "body_uz": "Ikki soat parallel ketadi: availability (uzluksiz) va tergov (diskret). Qoida bo'lmasa jamoa har doim tergovni tanlaydi."},
    {"id": "C-5", "title_uz": "Urinishlar — valyuta.", "body_uz": "Ishonch bo'yicha kamayish tartibida topshiring. Ota/sub-texnika qoidasini oldindan so'rang (0-faza). Topshirilgan/qabul qilingan/rad etilgan daftarini yuriting — aks holda to'rt kishi bir xil ID ni ikki marta topshiradi."},
    {"id": "C-6", "title_uz": "Gipoteza bilan ovlang.", "body_uz": "32 ta hunt ni ketma-ket yurgizmang. 2-3 ta raqobatlashuvchi gipoteza yozing va faqat ularni bir-biridan ajratadigan dalilni qidiring. Hamma gipotezaga mos keladigan dalil — befoyda dalil."},
    {"id": "C-7", "title_uz": "15 daqiqa qoidasi.", "body_uz": "Birorta ATT&CK ID yoki harakat bermagan yo'nalish 15 daqiqada tashlanadi yoki boshqa odamga beriladi."},
    {"id": "C-8", "title_uz": "Eng tez tuzatish — tiklash, tashxis emas.", "body_uz": "Oldindan tayyorlang: xizmat konfiglari, toza hosts, normal vazifalar va xizmatlar ro'yxati. Tuzatish = diff + tiklash."},
    {"id": "C-9", "title_uz": "Tuzatgandan keyin o'sha joyni kuzating.", "body_uz": "Tuzatilgan narsa qayta buziladi. Va hujumchi ko'rgan parollarni almashtiring — aks holda u oddiy login bilan qaytadi va loglarda \"normal kirish\" bo'lib ko'rinadi."},
    {"id": "C-10", "title_uz": "Da'vo taxtada, og'zaki emas.", "body_uz": "Kim nima ustida ishlayotgani Tracker da turadi. Aks holda to'rt kishi bir ishni qiladi."}
]

def default_state() -> dict:
    return {"steps": {}, "kc": {}, "updated": None}

def validate_state(state: dict) -> dict:
    if not isinstance(state, dict):
        return default_state()
        
    out = default_state()
    
    if "steps" in state and isinstance(state["steps"], dict):
        valid_step_ids = set()
        for p in PHASES:
            for s in p["steps"]:
                valid_step_ids.add(s["id"])
                
        for k, v in state["steps"].items():
            if k in valid_step_ids and isinstance(v, dict):
                s = v.get("status", "todo")
                if s not in ("todo", "doing", "done", "skip", "blocked"):
                    s = "todo"
                out["steps"][k] = {
                    "status": s,
                    "note": str(v.get("note", "")) if v.get("note") is not None else "",
                    "ts": v.get("ts") if isinstance(v.get("ts"), str) else None
                }
                
    if "kc" in state and isinstance(state["kc"], dict):
        valid_kc_keys = {kc["key"] for kc in KILL_CHAIN}
        for k, v in state["kc"].items():
            if k in valid_kc_keys and isinstance(v, dict):
                s = v.get("status", "unknown")
                if s not in ("unknown", "suspected", "confirmed", "ruled_out"):
                    s = "unknown"
                out["kc"][k] = {
                    "status": s,
                    "evidence": str(v.get("evidence", "")) if v.get("evidence") is not None else "",
                    "ts": v.get("ts") if isinstance(v.get("ts"), str) else None
                }
                
    out["updated"] = state.get("updated") if isinstance(state.get("updated"), str) else None
    return out

def progress(state: dict) -> dict:
    out = {
        "phases": [],
        "overall": {"total": 0, "done": 0, "percent": 0, "must_total": 0, "must_done": 0},
        "kill_chain": [],
        "next": []
    }
    
    steps_state = state.get("steps", {})
    kc_state = state.get("kc", {})
    
    overall_total = 0
    overall_done = 0
    overall_skip = 0
    overall_must_total = 0
    overall_must_done = 0
    
    next_candidates = []
    next_must_candidates = []
    
    for p in PHASES:
        p_total = len(p["steps"])
        p_done = 0
        p_skip = 0
        p_doing = 0
        p_blocked = 0
        p_todo = 0
        p_must_total = 0
        p_must_done = 0
        
        for s in p["steps"]:
            s_id = s["id"]
            st = steps_state.get(s_id, {}).get("status", "todo")
            if st == "done": p_done += 1
            elif st == "skip": p_skip += 1
            elif st == "doing": p_doing += 1
            elif st == "blocked": p_blocked += 1
            else: p_todo += 1
            
            if s["must"]:
                p_must_total += 1
                if st == "done":
                    p_must_done += 1
            
            if st in ("todo", "doing"):
                cand = {"id": s_id, "phase": p["id"], "title_uz": s["title_uz"], "cmd": s["cmd"], "must": s["must"]}
                if s["must"]:
                    next_must_candidates.append(cand)
                else:
                    next_candidates.append(cand)
                    
        denom = p_total - p_skip
        p_percent = round(100 * p_done / denom) if denom > 0 else 100
        
        out["phases"].append({
            "id": p["id"],
            "title_uz": p["title_uz"],
            "total": p_total,
            "done": p_done,
            "skip": p_skip,
            "doing": p_doing,
            "blocked": p_blocked,
            "todo": p_todo,
            "must_total": p_must_total,
            "must_done": p_must_done,
            "percent": p_percent
        })
        
        overall_total += p_total
        overall_done += p_done
        overall_skip += p_skip
        overall_must_total += p_must_total
        overall_must_done += p_must_done

    denom_overall = overall_total - overall_skip
    overall_percent = round(100 * overall_done / denom_overall) if denom_overall > 0 else 100
    
    out["overall"] = {
        "total": overall_total,
        "done": overall_done,
        "percent": overall_percent,
        "must_total": overall_must_total,
        "must_done": overall_must_done
    }
    
    for kc in KILL_CHAIN:
        key = kc["key"]
        kcs = kc_state.get(key, {})
        steps_total = 0
        steps_done = 0
        for p in PHASES:
            for s in p["steps"]:
                if key in s["kc"]:
                    steps_total += 1
                    if steps_state.get(s["id"], {}).get("status", "todo") == "done":
                        steps_done += 1
                        
        out["kill_chain"].append({
            "key": key,
            "num": kc["num"],
            "name_uz": kc["name_uz"],
            "name_en": kc["name_en"],
            "status": kcs.get("status", "unknown"),
            "evidence": kcs.get("evidence", ""),
            "steps_total": steps_total,
            "steps_done": steps_done,
            "covered": steps_total > 0 and steps_total == steps_done
        })
        
    out["next"] = next_must_candidates[:3]
    if len(out["next"]) < 3:
        out["next"].extend(next_candidates[:3 - len(out["next"])])
        
    return out
