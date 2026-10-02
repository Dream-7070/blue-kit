EXPLAIN_UZ = {
    "T1595.002": "Hujumchi saytni avtomatik skanerlagan: admin panel, config va backup fayllarini qidirib ko'plab 404/403 javob olgan. Bu razvedka bosqichi — hali kirish yo'q, lekin nishon tanlanmoqda.",
    "T1190": "Veb-ilova parametriga SQL in'ektsiya yuborilgan va baza tuzilmasi, foydalanuvchi jadvali o'qib olingan. Bu — hujumchining tizimga birinchi kirish nuqtasi.",
    "T1505.003": "Serverga web-shell (brauzer orqali buyruq bajaradigan fayl) yuklangan va unga murojaat qilingan. Endi hujumchi veb-server huquqida istalgan buyruqni bajara oladi.",
    "T1033": "Hujumchi web-shell orqali `whoami`/`id` kabi buyruqlar bilan qaysi huquqda ishlayotganini aniqlagan. Bu — muhitni o'rganish, keyingi qadamni rejalashtirish.",
    "T1059.006": "Python orqali teskari qobiq (reverse shell) ochilgan: server o'zi hujumchining IP siga ulanib, to'liq interaktiv terminal bergan. Ulanish chiquvchi bo'lgani uchun oddiy firewall uni to'smaydi.",
    "T1053.003": "Cron jadvaliga har 15 daqiqada tashqi skriptni yuklab ishga tushiruvchi yozuv qo'shilgan. Bu — qayta ishga tushgandan keyin ham kirishni saqlash usuli; cron yozuvi o'chirilmasa, server qayta zararlanadi.",
    "T1548.003": "`sudo` huquqlari ro'yxatlangan va ruxsat etilgan dastur orqali (GTFOBins usuli) root qobig'i olingan. Shu daqiqadan boshlab hujumchi serverda to'liq nazoratga ega.",
    "T1003.008": "`/etc/shadow` fayli o'qilgan — barcha lokal parol hashlari hujumchi qo'lida. Parollarni oflayn buzish mumkin, shuning uchun barcha akkaunt parollarini almashtirish shart.",
    "T1552.004": "Root foydalanuvchining SSH shaxsiy kaliti o'g'irlangan. Bu kalit bilan parolsiz, boshqa serverlarga ham kirish mumkin — kalitni darhol bekor qilib, yangisini generatsiya qiling.",
    "T1136.001": "Yangi lokal foydalanuvchi yaratilgan, nomi tizim akkauntiga o'xshatib tanlangan. Bu — yashirin zaxira kirish yo'li; akkauntni o'chiring va boshqa hostlarda ham shunga o'xshash akkaunt bor-yo'qligini tekshiring.",
    "T1046": "Ichki tarmoq skanerlangan (SSH, MySQL, PostgreSQL portlari). Hujumchi qo'shni serverlarga o'tish uchun nishon tanlamoqda — demak hujum bitta host bilan tugamaydi.",
    "T1021.004": "O'g'irlangan SSH kaliti bilan ichki tarmoqdagi boshqa serverga kirilgan. Bu — lateral movement (yon harakat): buzilgan perimetr endi ichki infratuzilmaga tarqalgan.",
    "T1005": "Ma'lumotlar bazasi to'liq dump qilingan (mijoz va to'lov jadvallari). Bu hodisaning eng og'ir qismi — shaxsiy ma'lumotlar sizib chiqqan, huquqiy bildirish talab etilishi mumkin.",
    "T1560.001": "O'g'irlangan fayllar bitta arxivga yig'ilgan (staging). Bu odatda tashqariga jo'natishdan oldingi oxirgi tayyorgarlik qadami.",
    "T1048": "Ma'lumotlar tashqi IP ga HTTPS orqali davriy ravishda jo'natilgan. Bu — eksfiltratsiya/C2 kanali: shu IP ni firewallda bloklang va jo'natilgan hajmni aniqlang.",
    "T1071.001": "Tashqi C2 (boshqaruv) serveriga veb-protokol (HTTP/HTTPS) orqali davriy ulanish va buyruq almashish kanali o'rnatilgan (C2 beaconing / callback).",
    "T1036.005": "Zararli fayl sezilmaslik uchun qonuniy tizim dasturi nomi (masalan, Microsoft DeviceSync) va papkasidan foydalanib yashiringan (Masquerading).",
    "T1105": "Tashqi manbadan qo'shimcha zararli modullar yoki buyruqlar yuklab olingan (Ingress Tool Transfer).",
    "T1027": "Buyruq yoki fayl yashirilgan (masalan, base64 bilan kodlangan PowerShell `-enc`), shunda antivirus va qidiruv uni oddiy matn sifatida topa olmaydi. Kodni dekodlab, ichida nima bajarilganini tekshiring (`bk decode`).",
    "T1059.001": "PowerShell orqali buyruq bajarilgan. Odatda phishing hujjati ochilgach zararli skript yuklab ishga tushirish uchun ishlatiladi — buyruq matnini va uni ishga tushirgan jarayonni (parent) tekshiring.",
    "T1059.005": "Makro/Visual Basic skripti bajarilgan (masalan, Word hujjatidagi makro). Bu phishing xatidagi ilova ochilgani va foydalanuvchi makroni yoqqanining belgisi.",
    "T1566.001": "Zararli ilova (masalan, `.docm` hujjat) bilan phishing xati yuborilgan yoki ochilgan. Bu — tizimga birinchi kirish yo'li: xat yuboruvchisini, qabul qiluvchilarni va ilovani ochgan foydalanuvchini aniqlang."
}

EXPLAIN_PHASE = {
    "Reconnaissance": "Razvedka bosqichi — hujumchi nishon haqida ma'lumot yig'moqda.",
    "Initial Access": "Tizimga birinchi kirish bosqichi.",
    "Execution": "Hujumchi nishon tizimda buyruq bajargan.",
    "Persistence": "Hujumchi kirishini doimiy saqlash uchun tizimga o'zgartirish kiritgan.",
    "Privilege Escalation": "Huquqlar ko'tarilgan — hujumchi yuqoriroq (odatda root/SYSTEM) darajaga chiqqan.",
    "Defense Evasion": "Himoyani chetlab o'tish — hujumchi o'z izlarini va jarayonlarini yashirmoqda.",
    "Stealth": "Yashirinish (ATT&CK v19 da avvalgi Defense Evasion) — hujumchi o'z izlarini va jarayonlarini yashirmoqda.",
    "Defense Impairment": "Himoya vositalari (antivirus, log, firewall) o'chirilgan yoki buzilgan.",
    "Resource Development": "Hujumchi hujum uchun infratuzilma va vositalarni tayyorlagan.",
    "Impact": "Tizim yoki ma'lumotga zarar yetkazilgan (shifrlash, o'chirish, uzilish).",
    "Credential Access": "Parol yoki kalit kabi maxfiy ma'lumotlar qo'lga kiritilgan.",
    "Discovery": "Muhit o'rganilmoqda — tizim, foydalanuvchi yoki tarmoq haqida ma'lumot yig'ilgan.",
    "Lateral Movement": "Hujum boshqa hostga tarqalgan.",
    "Collection": "Qimmatli ma'lumot yig'ilgan va jo'natishga tayyorlanmoqda.",
    "Command and Control": "Boshqaruv kanali — tashqi tajovuzkor serveri bilan aloqa o'rnatilgan.",
    "Exfiltration": "Ma'lumot tashqariga chiqarilgan."
}

def explain_stage_uz(stage):
    """AttackStage uchun o'zbekcha izoh qaytaradi (topilmasa — faza bo'yicha zaxira matn)."""
    if stage.technique_id in EXPLAIN_UZ:
        return EXPLAIN_UZ[stage.technique_id]
    
    stage_phase = (stage.phase or "").lower()
    for phase, explanation in EXPLAIN_PHASE.items():
        if phase.lower() in stage_phase:
            return explanation

    if stage.technique_name:
        return "%s bosqichida %s (%s) aniqlangan." % (stage.phase or "Noma'lum", stage.technique_name, stage.technique_id)
    return ""
