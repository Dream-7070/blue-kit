"""Hunt katalogi — nima qidirilishi SIEM dan qat'i nazar bir marta ta'riflanadi.

Shart (`where`) strukturaviy daraxt: builder uni har bir SIEM tiliga o'zi render qiladi.
ATT&CK ID lari KB v19.2 bo'yicha tekshirilgan (tests/test_siem.py buni har safar
qayta tekshiradi).
"""

CATEGORIES = {
    'auth': 'Kirish / autentifikatsiya',
    'persistence': 'Mustahkamlanish',
    'execution': 'Ishga tushirish',
    'evasion': 'Yashirinish',
    'credential': 'Hisob ma\'lumotlari',
    'lateral': 'Yon harakat',
    'network': 'Tarmoq / C2',
    'web': 'Web hujumlar',
}


def _all(*items):
    return {'op': 'all', 'items': list(items)}


def _any(*items):
    return {'op': 'any', 'items': list(items)}


def _in(field, *values):
    return {'field': field, 'op': 'in', 'value': list(values)}


def _eq(field, value):
    return {'field': field, 'op': 'eq', 'value': value}


def _not_in(field, *values):
    return {'field': field, 'op': 'not_in', 'value': list(values)}


def _has(field, *values):
    return {'field': field, 'op': 'contains_any', 'value': list(values)}


def _ends(field, *values):
    return {'field': field, 'op': 'endswith_any', 'value': list(values)}


def _public(field):
    return {'field': field, 'op': 'is_public'}


def _exists(field):
    return {'field': field, 'op': 'exists'}


def _count(*group_by, threshold_default=20):
    return {'group_by': list(group_by), 'metric': 'count',
            'having': {'op': 'gte', 'param': 'threshold'}}


def _distinct(field, *group_by):
    return {'group_by': list(group_by), 'metric': 'distinct_count:' + field,
            'having': {'op': 'gte', 'param': 'threshold'}}


def _sum(field, *group_by):
    return {'group_by': list(group_by), 'metric': 'sum:' + field,
            'having': {'op': 'gte', 'param': 'threshold'}}


WIN_PROC_SELECT = ['ts', 'host', 'user', 'parent_process', 'process', 'command_line']
WIN_AUTH_SELECT = ['ts', 'host', 'user', 'src_ip', 'event_id', 'logon_type']

_HUNTS = [
    # ------------------------------------------------------------------ auth
    {
        'id': 'auth-bruteforce',
        'name': 'Parolni saralash (brute force)',
        'category': 'auth',
        'description': "Bitta manba IP dan qisqa vaqt ichida ko'p marta muvaffaqiyatsiz "
                       "kirish urinishi (4625). Parol topilgunicha davom etadigan hujum.",
        'logsource': 'windows-logon',
        'attack': ['T1110', 'T1110.001'],
        'where': _in('event_id', 4625),
        'aggregate': _count('src_ip', 'user', 'host'),
        'select': WIN_AUTH_SELECT,
        'params': {'days': 7, 'threshold': 20, 'limit': 200},
        'tuning': "Xizmat akkauntlari, eskirgan parol saqlagan ilovalar va vuln-skaner "
                  "IP lari doimiy 4625 beradi — ularni allowlist qiling.",
    },
    {
        'id': 'auth-password-spray',
        'name': 'Password spray (bitta parol, ko\'p akkaunt)',
        'category': 'auth',
        'description': "Bitta manbadan ko'p turli akkauntga kam urinish. Lockout ga "
                       "tushmaslik uchun ataylab sekin qilinadi — shuning uchun urinishlar "
                       "soni emas, noyob akkauntlar soni sanaladi.",
        'logsource': 'windows-logon',
        'attack': ['T1110.003'],
        'where': _in('event_id', 4625),
        'aggregate': _distinct('user', 'src_ip'),
        'select': WIN_AUTH_SELECT,
        'params': {'days': 7, 'threshold': 10, 'limit': 200},
        'tuning': "Threshold ni domendagi akkauntlar soniga qarab tanlang. Exchange/ADFS "
                  "proksi orqasida hamma urinish bitta IP dan ko'rinishi mumkin.",
    },
    {
        'id': 'auth-success-after-fail',
        'name': "Muvaffaqiyatsiz urinishlardan keyin muvaffaqiyatli kirish",
        'category': 'auth',
        'description': "Bir xil manba/akkaunt juftligida ham 4625, ham 4624 bo'lsa — "
                       "parol topilgan bo'lishi mumkin. Brute force natijasini aniqlaydi.",
        'logsource': 'windows-logon',
        'attack': ['T1110', 'T1078'],
        'where': _in('event_id', 4625, 4624),
        'aggregate': _distinct('event_id', 'src_ip', 'user'),
        'select': WIN_AUTH_SELECT,
        'params': {'days': 7, 'threshold': 2, 'limit': 200},
        'tuning': "threshold=2 — ya'ni ikkala hodisa turi ham uchragan. Natijani vaqt "
                  "bo'yicha ko'ring: 4624 aynan 4625 seriyasidan keyin kelganmi?",
    },
    {
        'id': 'auth-external-rdp',
        'name': 'Tashqi IP dan RDP kirish',
        'category': 'auth',
        'description': "Internetdagi (public) manzildan muvaffaqiyatli RDP sessiyasi "
                       "(4624, LogonType 10). Ko'pincha ilk kirish nuqtasi.",
        'logsource': 'windows-logon',
        'attack': ['T1021.001', 'T1078'],
        'where': _all(_in('event_id', 4624), _eq('logon_type', 10), _public('src_ip')),
        'select': WIN_AUTH_SELECT,
        'params': {'days': 7, 'limit': 200},
        'tuning': "Qonuniy masofaviy ishchilar va VPN chiqish IP lari bo'lsa, ularni "
                  "chiqarib tashlang. LogonType 10 = RemoteInteractive.",
    },
    {
        'id': 'auth-admin-privileges',
        'name': "Maxsus imtiyozlar bilan kirish (4672)",
        'category': 'auth',
        'description': "Sessiyaga administrator darajasidagi imtiyozlar berilgani. "
                       "Yangi yoki kutilmagan akkauntda paydo bo'lishi muhim signal.",
        'logsource': 'windows-logon',
        'attack': ['T1078.002'],
        'where': _in('event_id', 4672),
        'aggregate': _count('user', 'host'),
        'select': ['ts', 'host', 'user', 'event_id'],
        'params': {'days': 7, 'threshold': 1, 'limit': 200},
        'tuning': "4672 juda shovqinli — DC larda har bir admin kirishida chiqadi. "
                  "Ma'lum admin akkauntlarni ro'yxatdan chiqarib, yangilariga qarang.",
    },
    {
        'id': 'auth-kerberoast',
        'name': 'Kerberoasting (RC4 xizmat chiptasi)',
        'category': 'auth',
        'description': "4769 — xizmat chiptasi so'ralishi; shifr turi 0x17 (RC4) bo'lsa "
                       "chipta oflayn parol buzishga qulay bo'ladi.",
        'logsource': 'windows-logon',
        'attack': ['T1558.003'],
        'where': _all(_in('event_id', 4769), _has('ticket_encryption', '0x17')),
        'select': ['ts', 'host', 'user', 'src_ip', 'event_id', 'target'],
        'params': {'days': 7, 'limit': 200},
        'tuning': "Eski ilovalar ham RC4 so'raydi. Bitta akkaunt qisqa vaqtda ko'p "
                  "turli SPN so'ragan bo'lsa — shubha kuchayadi.",
    },
    {
        'id': 'auth-explicit-cred',
        'name': "Boshqa akkaunt ma'lumoti bilan ishga tushirish (4648)",
        'category': 'auth',
        'description': "Foydalanuvchi o'z sessiyasidan boshqa akkaunt parolini kiritib "
                       "jarayon ishga tushirgan — runas va yon harakatning tipik izi.",
        'logsource': 'windows-logon',
        'attack': ['T1078'],
        'where': _in('event_id', 4648),
        'select': ['ts', 'host', 'user', 'target', 'process', 'src_ip'],
        'params': {'days': 7, 'limit': 200},
        'tuning': "Admin larning kundalik runas ishlatishi ko'p FP beradi — akkaunt "
                  "juftliklarini (kim -> kim) baseline qiling.",
    },
    {
        'id': 'auth-lockout',
        'name': 'Akkaunt bloklanishi (4740)',
        'category': 'auth',
        'description': "Akkauntlarning ketma-ket bloklanishi brute force yoki spray ning "
                       "yon ta'siri bo'ladi.",
        'logsource': 'windows-account',
        'attack': ['T1110'],
        'where': _in('event_id', 4740),
        'aggregate': _count('user', 'host'),
        'select': ['ts', 'host', 'user', 'src_ip', 'event_id'],
        'params': {'days': 7, 'threshold': 1, 'limit': 200},
        'tuning': "Telefondagi eski parol ham lockout beradi. Ko'p turli akkaunt bir "
                  "vaqtda bloklansa — bu hujum.",
    },
    {
        'id': 'auth-linux-ssh-bruteforce',
        'name': 'Linux SSH brute force',
        'category': 'auth',
        'description': "sshd ning muvaffaqiyatsiz autentifikatsiya xabarlari bitta "
                       "manbadan ko'p takrorlansa.",
        'logsource': 'linux-auth',
        'attack': ['T1110', 'T1110.001'],
        'where': _has('message', 'Failed password', 'authentication failure', 'Invalid user'),
        'aggregate': _count('src_ip', 'host'),
        'select': ['ts', 'host', 'user', 'src_ip', 'message'],
        'params': {'days': 7, 'threshold': 20, 'limit': 200},
        'tuning': "Internetga ochiq SSH da bu fon shovqini — threshold ni oshiring va "
                  "muvaffaqiyatli 'Accepted password' bor-yo'qligini alohida qarang.",
    },

    # ----------------------------------------------------------- persistence
    {
        'id': 'persist-new-user',
        'name': 'Yangi foydalanuvchi yaratildi (4720)',
        'category': 'persistence',
        'description': "Hujumchi o'ziga doimiy kirish uchun yangi akkaunt ochadi. "
                       "Ish vaqtidan tashqari yaratilganlari alohida shubhali.",
        'logsource': 'windows-account',
        'attack': ['T1136.001'],
        'where': _in('event_id', 4720),
        'select': ['ts', 'host', 'user', 'target', 'event_id'],
        'params': {'days': 7, 'limit': 200},
        'tuning': "HR/IT jarayoni orqali yaratilgan akkauntlarni ticket bilan solishtiring.",
    },
    {
        'id': 'persist-admin-group',
        'name': "Administratorlar guruhiga qo'shish",
        'category': 'persistence',
        'description': "4728/4732/4756 — akkauntni lokal yoki domen admin guruhiga "
                       "qo'shish. Imtiyozni oshirishning eng ko'p uchraydigan izi.",
        'logsource': 'windows-account',
        'attack': ['T1098'],
        'where': _in('event_id', 4728, 4732, 4756),
        'select': ['ts', 'host', 'user', 'target', 'event_id'],
        'params': {'days': 7, 'limit': 200},
        'tuning': "Guruh nomiga qarang: Domain Admins / Enterprise Admins eng muhimi.",
    },
    {
        'id': 'persist-service-install',
        'name': "Yangi xizmat o'rnatildi (7045)",
        'category': 'persistence',
        'description': "Yangi Windows xizmati o'rnatilishi — ham mustahkamlanish, ham "
                       "masofaviy ishga tushirish vositasi (PsExec kabi).",
        'logsource': 'windows-service',
        'attack': ['T1543.003'],
        'where': _in('event_id', 7045, 4697),
        'select': ['ts', 'host', 'user', 'service_name', 'file_path', 'event_id'],
        'params': {'days': 7, 'limit': 200},
        'tuning': "Qonuniy dasturlar ham xizmat o'rnatadi — xizmat nomi tasodifiy "
                  "harflardan iborat bo'lsa yoki binar yo'li Temp da bo'lsa shubhali.",
    },
    {
        'id': 'persist-scheduled-task',
        'name': "Rejalashtirilgan vazifa yaratildi",
        'category': 'persistence',
        'description': "4698/4702 hodisasi yoki schtasks / Register-ScheduledTask buyrug'i — "
                       "qayta yuklashdan keyin ham qaytib keladigan mustahkamlanish.",
        'logsource': 'windows-security',
        'attack': ['T1053.005'],
        'where': _any(_in('event_id', 4698, 4702),
                      _has('command_line', 'schtasks', 'Register-ScheduledTask')),
        'select': WIN_PROC_SELECT + ['event_id'],
        'params': {'days': 7, 'limit': 200},
        'tuning': "Vazifa nomi va ishga tushirilayotgan buyruqqa qarang: powershell, "
                  "mshta yoki Temp dagi fayl bo'lsa — tekshiring.",
    },
    {
        'id': 'persist-run-key',
        'name': "Avtoyuklash reestr kaliti o'zgartirildi",
        'category': 'persistence',
        'description': "Run / RunOnce kalitiga yozuv qo'shilishi (Sysmon 12/13) — "
                       "foydalanuvchi kirganda dastur avtomatik ishga tushadi.",
        'logsource': 'windows-registry',
        'attack': ['T1547.001', 'T1112'],
        'where': _all(_in('event_id', 13, 12),
                      _has('registry_path', '\\CurrentVersion\\Run',
                           '\\CurrentVersion\\RunOnce', '\\Explorer\\Shell Folders')),
        'select': ['ts', 'host', 'user', 'process', 'registry_path', 'event_id'],
        'params': {'days': 7, 'limit': 200},
        'tuning': "Yangilanish va o'rnatuvchilar ham Run kalitiga yozadi — yozayotgan "
                  "jarayon (process) kim ekaniga qarang.",
    },
    {
        'id': 'persist-wmi-subscription',
        'name': 'WMI hodisa obunasi',
        'category': 'persistence',
        'description': "Sysmon 19/20/21 — WMI filter/consumer/binding yaratilishi. "
                       "Faylsiz (fileless) mustahkamlanishning klassik usuli.",
        'logsource': 'windows-sysmon',
        'attack': ['T1546.003'],
        'where': _in('event_id', 19, 20, 21),
        'select': ['ts', 'host', 'user', 'process', 'message', 'event_id'],
        'params': {'days': 7, 'limit': 200},
        'tuning': "Normal muhitda WMI obunasi deyarli yaratilmaydi — har bir natijani "
                  "qo'lda ko'rib chiqing. SCCM istisno bo'lishi mumkin.",
    },

    # ------------------------------------------------------------- execution
    {
        'id': 'exec-encoded-powershell',
        'name': "Kodlangan PowerShell buyrug'i",
        'category': 'execution',
        'description': "Base64 ga o'ralgan yoki yashirin rejimda ishga tushirilgan "
                       "PowerShell — yuklovchi (loader) skriptlarning asosiy belgisi.",
        'logsource': 'windows-process',
        'attack': ['T1059.001', 'T1027'],
        'where': _all(_in('event_id', 4688),
                      _has('command_line', '-enc', '-EncodedCommand',
                           'FromBase64String', '-nop -w hidden')),
        'select': WIN_PROC_SELECT,
        'params': {'days': 7, 'limit': 200},
        'tuning': "Ba'zi boshqaruv tizimlari (SCCM, RMM) ham -enc ishlatadi — ota "
                  "jarayonga qarab ularni chiqarib tashlang.",
    },
    {
        'id': 'exec-office-child',
        'name': "Office hujjatidan jarayon ishga tushdi",
        'category': 'execution',
        'description': "Word/Excel/Outlook dan cmd, powershell, wscript yoki mshta "
                       "ishga tushsa — makro orqali kirish (phishing) ehtimoli yuqori.",
        'logsource': 'windows-process',
        'attack': ['T1566.001', 'T1204.002'],
        'where': _all(_in('event_id', 4688),
                      _ends('parent_process', '\\winword.exe', '\\excel.exe',
                            '\\powerpnt.exe', '\\outlook.exe'),
                      _ends('process', '\\cmd.exe', '\\powershell.exe', '\\wscript.exe',
                            '\\cscript.exe', '\\mshta.exe', '\\rundll32.exe')),
        'select': WIN_PROC_SELECT,
        'params': {'days': 7, 'limit': 200},
        'tuning': "Deyarli har doim haqiqiy hodisa. Natija chiqsa, o'sha hostdan "
                  "boshlab IR zanjirini yig'ing.",
    },
    {
        'id': 'exec-lolbin',
        'name': "LOLBin orqali fayl yuklab olish",
        'category': 'execution',
        'description': "certutil, bitsadmin, mshta, regsvr32, rundll32 kabi tizim "
                       "binarlari tashqi manzildan fayl tortib olish uchun ishlatilgan.",
        'logsource': 'windows-process',
        'attack': ['T1218', 'T1105'],
        'where': _all(_in('event_id', 4688),
                      _ends('process', '\\certutil.exe', '\\bitsadmin.exe', '\\mshta.exe',
                            '\\regsvr32.exe', '\\rundll32.exe', '\\msiexec.exe',
                            '\\curl.exe', '\\wget.exe'),
                      _has('command_line', 'http://', 'https://', '-urlcache',
                           '-decode', '/transfer', 'scrobj.dll')),
        'select': WIN_PROC_SELECT,
        'params': {'days': 7, 'limit': 200},
        'tuning': "certutil -urlcache va bitsadmin /transfer eng ishonchli belgilar. "
                  "msiexec ning qonuniy http o'rnatishlari FP bo'lishi mumkin.",
    },
    {
        'id': 'exec-wmi-remote',
        'name': "WMI orqali masofaviy buyruq",
        'category': 'execution',
        'description': "WmiPrvSE.exe dan jarayon tug'ilishi yoki wmic /node: — "
                       "masofadan buyruq bajarishning keng tarqalgan usuli.",
        'logsource': 'windows-process',
        'attack': ['T1047'],
        'where': _any(_ends('parent_process', '\\wmiprvse.exe'),
                      _has('command_line', '/node:', 'Invoke-WmiMethod', 'Invoke-CimMethod')),
        'select': WIN_PROC_SELECT,
        'params': {'days': 7, 'limit': 200},
        'tuning': "Inventarizatsiya tizimlari WMI ni doim ishlatadi — ota jarayoni "
                  "WmiPrvSE bo'lgan cmd/powershell ga e'tibor bering.",
    },
    {
        'id': 'exec-uac-bypass',
        'name': 'UAC chetlab o\'tish',
        'category': 'execution',
        'description': "fodhelper, eventvwr, sdclt, computerdefaults dan farzand jarayon "
                       "tug'ilishi — UAC so'ramasdan imtiyoz oshirishning tipik zanjiri.",
        'logsource': 'windows-process',
        'attack': ['T1548.002'],
        'where': _all(_in('event_id', 4688),
                      _ends('parent_process', '\\fodhelper.exe', '\\eventvwr.exe',
                            '\\sdclt.exe', '\\computerdefaults.exe')),
        'select': WIN_PROC_SELECT,
        'params': {'days': 7, 'limit': 200},
        'tuning': "Bu jarayonlarning normal farzandi deyarli bo'lmaydi — FP kam.",
    },

    # --------------------------------------------------------------- evasion
    {
        'id': 'evasion-log-cleared',
        'name': 'Hodisalar jurnali tozalandi',
        'category': 'evasion',
        'description': "1102/104 hodisasi yoki wevtutil cl buyrug'i — izni yo'qotish "
                       "urinishi. Deyarli har doim tekshirishga arziydi.",
        'logsource': 'windows-security',
        'attack': ['T1685.005'],
        'where': _any(_in('event_id', 1102, 104),
                      _has('command_line', 'wevtutil cl', 'Clear-EventLog')),
        'select': ['ts', 'host', 'user', 'command_line', 'event_id'],
        'params': {'days': 7, 'limit': 200},
        'tuning': "Jurnal tozalangan vaqtdan oldingi oynaga alohida qarang — o'sha yerda "
                  "yashirilmoqchi bo'lgan harakat bor.",
    },
    {
        'id': 'evasion-av-disabled',
        'name': "Antivirus himoyasi o'chirildi",
        'category': 'evasion',
        'description': "Defender ning real-time himoyasini o'chirish, istisno papka "
                       "qo'shish yoki xizmatni to'xtatish urinishlari.",
        'logsource': 'windows-security',
        'attack': ['T1685'],
        'where': _any(_in('event_id', 5001, 5007),
                      _has('command_line', 'Set-MpPreference -Disable',
                           'DisableRealtimeMonitoring', 'Add-MpPreference -ExclusionPath',
                           'sc stop WinDefend')),
        'select': ['ts', 'host', 'user', 'command_line', 'event_id'],
        'params': {'days': 7, 'limit': 200},
        'tuning': "IT xodimlari ham istisno qo'shadi — kim qo'shganini va qaysi papkani "
                  "istisno qilganini tekshiring.",
    },
    {
        'id': 'evasion-recovery-inhibit',
        'name': "Tiklash imkoniyatini yo'q qilish",
        'category': 'evasion',
        'description': "Soya nusxalarni o'chirish, zaxira katalogini tozalash yoki "
                       "bcdedit bilan tiklashni o'chirish — shifrlashdan oldingi qadam.",
        'logsource': 'windows-process',
        'attack': ['T1490'],
        'where': _has('command_line', 'delete shadows', 'shadowcopy delete',
                      'wbadmin delete catalog', 'recoveryenabled no',
                      'bcdedit /set', 'resize shadowstorage'),
        'select': WIN_PROC_SELECT,
        'params': {'days': 7, 'limit': 200},
        'tuning': "FP deyarli yo'q. Natija chiqsa — shifrlash boshlanishidan oldin "
                  "hostni darhol izolyatsiya qiling.",
    },

    # ------------------------------------------------------------ credential
    {
        'id': 'cred-lsass-access',
        'name': "LSASS xotirasiga murojaat (Sysmon 10)",
        'category': 'credential',
        'description': "lsass.exe ga boshqa jarayon ochiq kirish so'ragani — parol va "
                       "xesh o'g'irlashning asosiy usuli.",
        'logsource': 'windows-sysmon',
        'attack': ['T1003.001'],
        'where': _all(_in('event_id', 10), _has('target', 'lsass.exe')),
        'select': ['ts', 'host', 'user', 'process', 'target', 'event_id'],
        'params': {'days': 7, 'limit': 200},
        'tuning': "Antivirus va monitoring agentlari ham lsass ga murojaat qiladi — "
                  "ularning yo'llarini allowlist qiling, qolganini tekshiring.",
    },
    {
        'id': 'cred-ntds',
        'name': "Domen parol bazasini (NTDS.dit) nusxalash",
        'category': 'credential',
        'description': "ntdsutil yoki ntds.dit faylining nusxasi — butun domen "
                       "parollarini bir yo'la olib chiqish urinishi.",
        'logsource': 'windows-process',
        'attack': ['T1003.003'],
        'where': _has('command_line', 'ntdsutil', 'ntds.dit', 'create full', 'IFM'),
        'select': WIN_PROC_SELECT,
        'params': {'days': 7, 'limit': 200},
        'tuning': "Faqat DC larda kutiladi. Qonuniy zaxira jarayoni bo'lsa, uning "
                  "jadvali bilan solishtiring — mos kelmasa insident.",
    },

    # --------------------------------------------------------------- lateral
    {
        'id': 'lateral-admin-share',
        'name': "Administrativ papkaga tarmoq orqali kirish",
        'category': 'lateral',
        'description': "5140/5145 — ADMIN$, C$ yoki IPC$ ga tarmoqdan murojaat. "
                       "PsExec va shunga o'xshash vositalarning izi.",
        'logsource': 'windows-security',
        'attack': ['T1021.002'],
        'where': _all(_in('event_id', 5140, 5145), _has('target', 'ADMIN$', 'C$', 'IPC$')),
        'select': ['ts', 'host', 'user', 'src_ip', 'target', 'event_id'],
        'params': {'days': 7, 'limit': 200},
        'tuning': "Boshqaruv serverlari (SCCM, zaxira) doimiy ADMIN$ ishlatadi — "
                  "ularning IP larini chiqarib tashlang.",
    },
    {
        'id': 'lateral-remote-service',
        'name': "Masofaviy xizmat orqali buyruq bajarish",
        'category': 'lateral',
        'description': "Yangi xizmat (7045) ning ishga tushirish yo'lida cmd, powershell "
                       "yoki nomli kanal bo'lsa — PsExec uslubidagi yon harakat.",
        'logsource': 'windows-service',
        'attack': ['T1570', 'T1021.002'],
        'where': _all(_in('event_id', 7045),
                      _any(_has('file_path', 'cmd.exe', 'powershell', '%COMSPEC%', '\\\\'),
                           _has('service_name', 'PSEXESVC', 'PAExec', 'RemCom'))),
        'select': ['ts', 'host', 'user', 'service_name', 'file_path', 'src_ip'],
        'params': {'days': 7, 'limit': 200},
        'tuning': "Xizmat nomi tasodifiy 8 ta harf bo'lsa — deyarli har doim hujum "
                  "vositasi. Qaysi hostdan kelganini src_ip bo'yicha toping.",
    },

    # --------------------------------------------------------------- network
    {
        'id': 'c2-rare-port',
        'name': "Noodatiy portga chiquvchi ulanish",
        'category': 'network',
        'description': "Tashqi manzilga standart bo'lmagan portda ko'p ulanish — "
                       "C2 kanali standart portlardan qochishga urinadi.",
        'logsource': 'firewall',
        'attack': ['T1571'],
        'where': _all(_public('dest_ip'),
                      _not_in('dest_port', 80, 443, 53, 123, 22, 25, 389, 445,
                              587, 993, 995, 3389)),
        'aggregate': _count('src_ip', 'dest_ip', 'dest_port'),
        'select': ['ts', 'host', 'src_ip', 'dest_ip', 'dest_port', 'bytes_sent'],
        'params': {'days': 7, 'threshold': 50, 'limit': 200},
        'tuning': "O'z muhitingizdagi qonuniy yuqori portlarni (yangilanish, VoIP, "
                  "monitoring) allowlist qiling.",
    },
    {
        'id': 'c2-dns-tunnel',
        'name': 'DNS tunnel (juda ko\'p noyob subdomen)',
        'category': 'network',
        'description': "Bitta host qisqa vaqtda juda ko'p noyob DNS nomi so'rasa — "
                       "ma'lumot DNS so'rovlari ichiga yashirilgan bo'lishi mumkin.",
        'logsource': 'dns',
        'attack': ['T1071.004', 'T1572'],
        'where': _exists('dns_query'),
        'aggregate': _distinct('dns_query', 'host'),
        'select': ['ts', 'host', 'src_ip', 'dns_query'],
        'params': {'days': 1, 'threshold': 200, 'limit': 200},
        'tuning': "CDN va antivirus reputatsiya xizmatlari ham ko'p noyob nom so'raydi — "
                  "natijadagi domenning ona qismiga qarang.",
    },
    {
        'id': 'exfil-large-upload',
        'name': "Tashqariga katta hajmli yuklash",
        'category': 'network',
        'description': "Ichki hostdan tashqi manzilga katta hajmdagi ma'lumot ketgan — "
                       "ma'lumot o'g'irlash (exfiltration) belgisi.",
        'logsource': 'firewall',
        'attack': ['T1041', 'T1048', 'T1567'],
        'where': _public('dest_ip'),
        'aggregate': _sum('bytes_sent', 'src_ip', 'dest_ip'),
        'select': ['ts', 'host', 'src_ip', 'dest_ip', 'dest_port', 'bytes_sent'],
        'params': {'days': 1, 'threshold': 104857600, 'limit': 200},
        'tuning': "threshold baytda (default 100 MB). Zaxira va bulut sinxronizatsiyasi "
                  "(OneDrive, Dropbox) qonuniy katta trafik beradi.",
    },
    {
        'id': 'net-port-scan',
        'name': 'Port skanerlash',
        'category': 'network',
        'description': "Bitta manbadan ko'p turli portga rad etilgan ulanish — "
                       "tarmoqni o'rganish (discovery) bosqichi.",
        'logsource': 'firewall',
        'attack': ['T1046'],
        'where': _has('action', 'deny', 'drop', 'block', 'reject'),
        'aggregate': _distinct('dest_port', 'src_ip'),
        'select': ['ts', 'src_ip', 'dest_ip', 'dest_port', 'action'],
        'params': {'days': 1, 'threshold': 100, 'limit': 200},
        'tuning': "Zaiflik skanerlari (Nessus, Qualys) ham shunday ko'rinadi — "
                  "ularning IP larini bilib qo'ying.",
    },

    # ------------------------------------------------------------------- web
    {
        'id': 'web-attack-patterns',
        'name': "Web hujum naqshlari (SQLi / traversal / webshell / skaner)",
        'category': 'web',
        'description': "URL ichidagi SQL in'ektsiya, katalogdan chiqish, webshell "
                       "belgilari yoki mashhur skanerlarning User-Agent i.",
        'logsource': 'web',
        'attack': ['T1190', 'T1505.003', 'T1595'],
        'where': _any(
            _has('url', 'union select', "' or 1=1", 'or 1=1--', 'sleep(',
                 '../', '..%2f', '/etc/passwd', '<script', 'cmd.exe'),
            _has('url', 'shell.php', 'cmd.aspx', 'c99.php', '?cmd=', '?exec='),
            _has('user_agent', 'sqlmap', 'nikto', 'nmap', 'masscan',
                 'dirbuster', 'python-requests', 'curl/'),
        ),
        'select': ['ts', 'host', 'src_ip', 'url', 'http_method', 'http_status', 'user_agent'],
        'params': {'days': 7, 'limit': 200},
        'tuning': "python-requests va curl qonuniy integratsiyalarda ham uchraydi. "
                  "http_status 200 bo'lgan natijalar eng muhimi — hujum ishlagan bo'lishi mumkin.",
    },
    {
        'id': 'ics-plc-stop',
        'name': 'PLC yoki CPU to\'xtatildi',
        'category': 'execution',
        'description': "Kontroller (PLC) yoki CPU ni to'xtatish buyrug'i berildi. "
                       "Bu kutilmaganda sodir bo'lsa, xizmat ko'rsatishni to'xtatish (DoS) "
                       "hujumi bo'lishi mumkin.",
        'logsource': 'ics',
        'attack': ['T0816', 'T0881'],
        'where': _has('message', 'stop cpu', 'plc stop', 'cpu halt'),
        'select': ['ts', 'host', 'src_ip', 'message', 'event_id'],
        'params': {'days': 7, 'limit': 200},
        'tuning': "Texnik xizmat vaqtida bo'lishi mumkin.",
    },
    {
        'id': 'ics-write-command',
        'name': 'Kontrollerga yozish buyrug\'i',
        'category': 'execution',
        'description': "Kontrollerga (Modbus yoki boshqa protokol) qiymat yozish buyrug'i. "
                       "Teglar yoki parametrlar o'zgartirilishi mumkin.",
        'logsource': 'ics',
        'attack': ['T0836'],
        'where': _any(_in('event_id', 5, 6, 15, 16), _has('message', 'write single coil', 'write multiple registers')),
        'select': ['ts', 'host', 'src_ip', 'message', 'event_id'],
        'params': {'days': 7, 'limit': 200},
        'tuning': "Avtomatlashtirilgan jarayonlarda shovqinli bo'lishi mumkin.",
    },
    {
        'id': 'ics-program-download',
        'name': 'Kontrollerga dastur yuklandi',
        'category': 'execution',
        'description': "PLC ga yangi logika yoki dastur yuklandi. "
                       "Bu tizimning ishlash mantiqini o'zgartirishini anglatadi.",
        'logsource': 'ics',
        'attack': ['T0821'],
        'where': _has('message', 'program download', 'ladder logic', 'project download'),
        'select': ['ts', 'host', 'src_ip', 'message', 'event_id'],
        'params': {'days': 7, 'limit': 200},
        'tuning': "Faqat litsenziyali injenerlik stansiyalaridan kutiladi.",
    },
    {
        'id': 'ics-engineering-tool',
        'name': 'Injenerlik vositasi ishga tushdi',
        'category': 'execution',
        'description': "Step7, RSLogix, CodeSys kabi vositalarning ishga tushishi. "
                       "Hujumchilar ulardan foydalanib kontrollerga kirishadi.",
        'logsource': 'ics',
        'attack': ['T0858'],
        'where': _ends('process', '\\Step7.exe', '\\RSLogix.exe', '\\CodeSys.exe'),
        'select': ['ts', 'host', 'user', 'process', 'command_line'],
        'params': {'days': 7, 'limit': 200},
        'tuning': "Ruxsat etilmagan foydalanuvchilarni qidiring.",
    },
    {
        'id': 'ics-hmi-service-stop',
        'name': 'HMI/SCADA xizmati to\'xtadi',
        'category': 'execution',
        'description': "Operatsion stansiya yoki HMI da WinCC, SCADA to'xtadi. "
                       "Ko'rinishni yo'qotishga sabab bo'ladi.",
        'logsource': 'ics',
        'attack': ['T0881'],
        'where': _has('message', 'hmi stop', 'scada stop', 'wincc'),
        'select': ['ts', 'host', 'user', 'message'],
        'params': {'days': 7, 'limit': 200},
        'tuning': "Xizmat ko'rsatish darchasidan tashqarida izlang.",
    },
]

HUNTS = {h['id']: h for h in _HUNTS}
