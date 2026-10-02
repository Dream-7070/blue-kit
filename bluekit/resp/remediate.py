import re
import shlex

def _ps_quote(s):
    if not s: return "''"
    return "'" + str(s).replace("'", "''") + "'"

def _safe_name(s):
    # zaxira fayl nomi uchun: skriptga qo'shtirnoqsiz tushadi, shuning uchun faqat oq ro'yxat
    # (; $ ` & ( ) qolsa "x;reboot" nomli xizmat buyruq bo'lib bajarilardi)
    return re.sub(r'[^A-Za-z0-9._-]+', '_', str(s)).strip('_') or 'item'

def generate(finding, os_name, full=False):
    item = finding.get('item', '')
    t_ids = ",".join([t['id'] for t in finding.get('techniques', [])])
    one_line = re.sub(r'[\r\n]+', ' ', str(item))
    header = f"# FINDING: {one_line} [{t_ids}]  score={finding.get('score', 0)}"
    if finding.get('protected'): return ""
    
    cat = finding.get('category')
    raw = finding.get('raw')
    path = finding.get('path')
    
    sn = _safe_name(item)
    ci = str(item).replace('"', '')
    li = shlex.quote(str(item))
    lu = shlex.quote('/etc/systemd/system/' + str(item) + '.service')

    if cat == 'tasks':
        ti = str(item).replace('"', '')
        return f"{header}\n# BACKUP\nschtasks /query /tn \"{ti}\" /xml > C:\\ir\\backup\\{sn}.xml\n# REMOVE\nschtasks /delete /tn \"{ti}\" /f\n# VERIFY\nschtasks /query /tn \"{ti}\"\n# ROLLBACK\nschtasks /create /tn \"{ti}\" /xml C:\\ir\\backup\\{sn}.xml"

    if cat == 'users':
        if os_name == 'windows':
            qu = _ps_quote(item)
            return f"{header}\n# BACKUP\nnet user {qu}\n# REMOVE\nDisable-LocalUser -Name {qu}\n# VERIFY\nnet user {qu}\n# ROLLBACK\nEnable-LocalUser -Name {qu}"
        else:
            qu = shlex.quote(str(item))
            return f"{header}\n# BACKUP\nmkdir -p /tmp/ir_backup && getent passwd {qu} > /tmp/ir_backup/user_{sn}.passwd\nchage -l {qu} 2>/dev/null\n# REMOVE\nusermod -L -e 1 {qu} 2>/dev/null || passwd -l {qu}\n# faol sessiyalarni uzish (ixtiyoriy): pkill -KILL -u {qu}\n# VERIFY\npasswd -S {qu}\n# ROLLBACK\nusermod -U -e '' {qu} 2>/dev/null || passwd -u {qu}"
    
    if cat == 'autoruns':
        if os_name == 'windows':
            loc = finding.get('location')
            if not loc:
                loc = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
            loc = loc.replace('HKLM:\\', 'HKLM\\').replace('HKCU:\\', 'HKCU\\')
            return f"{header}\n# BACKUP\nreg export \"{loc}\" C:\\ir\\backup\\run_backup.reg\n# REMOVE\nreg delete \"{loc}\" /v \"{item}\" /f\n# VERIFY\nreg query \"{loc}\" /v \"{item}\"\n# ROLLBACK\nreg import C:\\ir\\backup\\run_backup.reg"
        else:
            # Linux kollektori faqat fayl/unit yo'lini beradi (value='exists') — qatorni avtomatik o'chirib bo'lmaydi
            loc = finding.get('location')
            if not loc: return f"{header}\n# REMOVE manually (xom qiymat yo'q)"
            ql = shlex.quote(loc)
            return f"{header}\n# BACKUP\nmkdir -p /tmp/ir_backup && cp -a {ql} /tmp/ir_backup/\n# REMOVE manually: faylni ko'rib chiqing, begona qatorni qo'lda o'chiring\nless {ql}\n# VERIFY\ncat {ql}\n# ROLLBACK\ncp -a /tmp/ir_backup/$(basename {ql}) {ql}"
    
    if cat == 'startup_items':
        if not path: return f"{header}\n# REMOVE manually (xom qiymat yo'q)"
        loc = finding.get('location', '')
        return f"{header}\n# BACKUP\nCopy-Item {_ps_quote(path)} C:\\ir\\backup\\\n# REMOVE\nRemove-Item {_ps_quote(path)} -Force\n# VERIFY\nTest-Path {_ps_quote(path)}\n# ROLLBACK\nCopy-Item C:\\ir\\backup\\{item} {_ps_quote(loc)}"
        
    if cat == 'remote_access_tools':
        if os_name == 'windows':
            remove_cmd = f"sc stop \"{ci}\"\nsc config \"{ci}\" start=disabled"
            if full: remove_cmd += f"\nsc delete \"{ci}\""
            return f"{header}\n# BACKUP\nsc qc \"{ci}\" > C:\\ir\\backup\\{sn}_qc.txt\n# REMOVE\n{remove_cmd}\n# VERIFY\nsc query \"{ci}\"\n# ROLLBACK\nsc config \"{ci}\" start=demand"
        else:
            oi = shlex.quote(re.sub(r'\.service$', '', str(item)))
            base_path = shlex.quote('/etc/init.d/' + re.sub(r'\.service$', '', str(item)))
            rm_rat_sysd = f"\n  rm -f {lu}" if full else ""
            backup_sh = (f"if command -v systemctl >/dev/null 2>&1; then\n  systemctl cat {li} > /tmp/ir_backup/{sn}.backup\n"
                         f"elif command -v rc-service >/dev/null 2>&1; then\n  cp -a {base_path} /tmp/ir_backup/ 2>/dev/null\n"
                         f"else\n  cp -a {base_path} /tmp/ir_backup/ 2>/dev/null\nfi")
            remove_sh = (f"if command -v systemctl >/dev/null 2>&1; then\n  systemctl stop {li}\n  systemctl disable {li}{rm_rat_sysd}\n"
                         f"elif command -v rc-service >/dev/null 2>&1; then\n  rc-service {oi} stop\n  rc-update del {oi}\n"
                         f"else\n  service {oi} stop\n  update-rc.d {oi} disable 2>/dev/null || chkconfig {oi} off\nfi")
            verify_sh = (f"if command -v systemctl >/dev/null 2>&1; then\n  systemctl status {li}\n"
                         f"elif command -v rc-service >/dev/null 2>&1; then\n  rc-service {oi} status\n"
                         f"else\n  service {oi} status\nfi")
            rollback_sh = (f"if command -v systemctl >/dev/null 2>&1; then\n  systemctl enable {li}\n"
                           f"elif command -v rc-service >/dev/null 2>&1; then\n  rc-update add {oi} default\n"
                           f"else\n  update-rc.d {oi} enable 2>/dev/null || chkconfig {oi} on\nfi")
            return f"{header}\n# BACKUP\n{backup_sh}\n# REMOVE\n{remove_sh}\n# VERIFY\n{verify_sh}\n# ROLLBACK\n{rollback_sh}"
            
    if cat == 'hosts_file':
        if os_name == 'windows':
            pat = f"([regex]::Escape({_ps_quote(item)}))"
            return f"{header}\n# BACKUP\nCopy-Item C:\\Windows\\System32\\drivers\\etc\\hosts C:\\ir\\backup\\hosts.bak\n# REMOVE\n(Get-Content C:\\Windows\\System32\\drivers\\etc\\hosts) | Where-Object {{ $_ -notmatch {pat} }} | Set-Content C:\\Windows\\System32\\drivers\\etc\\hosts\n# VERIFY\nSelect-String -Path C:\\Windows\\System32\\drivers\\etc\\hosts -Pattern {pat}\n# ROLLBACK\nCopy-Item C:\\ir\\backup\\hosts.bak C:\\Windows\\System32\\drivers\\etc\\hosts -Force"
        else:
            qi = shlex.quote(item)
            return f"{header}\n# BACKUP\ncp /etc/hosts /tmp/hosts.bak\n# REMOVE\ngrep -vF -- {qi} /etc/hosts > /tmp/hosts.ir.new && cat /tmp/hosts.ir.new > /etc/hosts\n# VERIFY\ngrep -F -- {qi} /etc/hosts\n# ROLLBACK\ncp /tmp/hosts.bak /etc/hosts"
            
    if cat == 'services':
        if os_name == 'windows':
            remove_cmd = f"sc stop \"{ci}\"\nsc config \"{ci}\" start=disabled"
            if full: remove_cmd += f"\nsc delete \"{ci}\""
            return f"{header}\n# BACKUP\nsc qc \"{ci}\" > C:\\ir\\backup\\{sn}_qc.txt\n# REMOVE\n{remove_cmd}\n# VERIFY\nsc query \"{ci}\"\n# ROLLBACK\nsc config \"{ci}\" start=demand"
        else:
            oi = shlex.quote(re.sub(r'\.service$', '', str(item)))
            base_path = shlex.quote('/etc/init.d/' + re.sub(r'\.service$', '', str(item)))
            rm_sys_sysd = f"\n  rm -f {lu}" if full else ""
            backup_sh = (f"if command -v systemctl >/dev/null 2>&1; then\n  systemctl cat {li} > /tmp/ir_backup/{sn}.backup\n"
                         f"elif command -v rc-service >/dev/null 2>&1; then\n  cp -a {base_path} /tmp/ir_backup/ 2>/dev/null\n"
                         f"else\n  cp -a {base_path} /tmp/ir_backup/ 2>/dev/null\nfi")
            remove_sh = (f"if command -v systemctl >/dev/null 2>&1; then\n  systemctl stop {li}\n  systemctl disable {li}\n  systemctl mask {li}{rm_sys_sysd}\n"
                         f"elif command -v rc-service >/dev/null 2>&1; then\n  rc-service {oi} stop\n  rc-update del {oi}\n"
                         f"else\n  service {oi} stop\n  update-rc.d {oi} disable 2>/dev/null || chkconfig {oi} off\nfi")
            verify_sh = (f"if command -v systemctl >/dev/null 2>&1; then\n  systemctl status {li}\n"
                         f"elif command -v rc-service >/dev/null 2>&1; then\n  rc-service {oi} status\n"
                         f"else\n  service {oi} status\nfi")
            rollback_sh = (f"if command -v systemctl >/dev/null 2>&1; then\n  systemctl unmask {li}\n  systemctl enable {li}\n"
                           f"elif command -v rc-service >/dev/null 2>&1; then\n  rc-update add {oi} default\n"
                           f"else\n  update-rc.d {oi} enable 2>/dev/null || chkconfig {oi} on\nfi")
            return f"{header}\n# BACKUP\n{backup_sh}\n# REMOVE\n{remove_sh}\n# VERIFY\n{verify_sh}\n# ROLLBACK\n{rollback_sh}"
            
    if cat == 'cron':
        if not raw: return f"{header}\n# REMOVE manually (xom qiymat yo'q)"
        if raw.startswith('/'):
            # It's a file
            f_q = shlex.quote(raw)
            rem = f"rm -f {f_q}" if full else f"chmod -x {f_q}"
            return f"{header}\n# BACKUP\nmkdir -p /tmp/ir_backup && cp -a {f_q} /tmp/ir_backup/\n# REMOVE\n{rem}\n# VERIFY\nls -l {f_q}\n# ROLLBACK\ncp /tmp/ir_backup/$(basename {f_q}) {f_q}"
        else:
            qraw = shlex.quote(raw)
            user = finding.get('user', '')
            uflag = f"-u {shlex.quote(user)} " if user else ""
            uname = user if user else "root"
            return f"{header}\n# BACKUP\nmkdir -p /tmp/ir_backup && crontab {uflag}-l > /tmp/ir_backup/cron_{uname}.bak\n# REMOVE\ncrontab {uflag}-l | grep -vF -- {qraw} | crontab {uflag}-\n# VERIFY\ncrontab {uflag}-l | grep -F -- {qraw}\n# ROLLBACK\ncrontab {uflag}/tmp/ir_backup/cron_{uname}.bak"
            
    if cat == 'ssh_authorized_keys':
        if not raw: return f"{header}\n# REMOVE manually (xom qiymat yo'q)"
        fpath = finding.get('file', '')
        # '~' qo'shtirnoq ichida ochilmaydi — $HOME ishlatiladi
        qfile = shlex.quote(fpath) if fpath else '"$HOME/.ssh/authorized_keys"'
        qraw = shlex.quote(raw)
        return f"{header}\n# BACKUP\ncp {qfile} {qfile}.ir.bak\n# REMOVE\ngrep -vF -- {qraw} {qfile} > {qfile}.ir.new && cat {qfile}.ir.new > {qfile}\n# VERIFY\ngrep -cF -- {qraw} {qfile}\n# ROLLBACK\ncp {qfile}.ir.bak {qfile}"
        
    if cat == 'suid_files':
        if not path: return f"{header}\n# REMOVE manually (xom qiymat yo'q)"
        qpath = shlex.quote(path)
        return f"{header}\n# BACKUP\nstat {qpath}\n# REMOVE\nchmod u-s {qpath}\n# VERIFY\nls -l {qpath}\n# ROLLBACK\nchmod u+s {qpath}"
        
    if cat == 'wmi_subscriptions':
        qitem = _ps_quote(item)
        return f"{header}\n# BACKUP\nGet-WmiObject -Namespace root\\subscription -Class __EventFilter > C:\\ir\\backup\\wmi.txt\n# REMOVE\nGet-WmiObject -Namespace root\\subscription -Class __EventFilter -Filter \"Name={qitem}\" | Remove-WmiObject\n# VERIFY\nGet-WmiObject -Namespace root\\subscription -Class __EventFilter -Filter \"Name={qitem}\"\n# ROLLBACK\n# No rollback provided"
        
    if cat == 'process':
        try:
            pid = int(finding.get('pid'))
        except (TypeError, ValueError):
            pid = 0
        if not pid or not path: return f"{header}\n# REMOVE manually (xom qiymat yo'q)"
        if os_name == 'windows':
            qp = _ps_quote(path)
            base = path.replace('/', '\\').split('\\')[-1]
            rm = f"\nRemove-Item -LiteralPath {qp} -Force" if full else "\n# fayl saqlanadi"
            return (f"{header}\n# BACKUP\nNew-Item -ItemType Directory C:\\ir\\backup -Force; Get-FileHash -LiteralPath {qp}; "
                    f"Copy-Item -LiteralPath {qp} C:\\ir\\backup\\ -Force\n"
                    f"Get-CimInstance Win32_Process -Filter \"ProcessId={pid}\" | Select-Object CommandLine,ParentProcessId\n"
                    f"# REMOVE\nStop-Process -Id {pid} -Force{rm}\n# VERIFY\nGet-Process -Id {pid}\n"
                    f"# ROLLBACK\n# jarayonni qaytarib bo'lmaydi; fayl: Copy-Item {_ps_quote('C:\\ir\\backup\\' + base)} {qp}")
        qpath = shlex.quote(path)
        chm = f"\nchmod -x {qpath}" if full else ""
        return (f"{header}\n# BACKUP\nmkdir -p /tmp/ir_backup; cp /proc/{pid}/exe /tmp/ir_backup/{pid}.bin\n"
                f"tr '\\0' ' ' < /proc/{pid}/cmdline; echo\n# REMOVE\nkill -9 {pid}{chm}\n# VERIFY\nps -p {pid}\n"
                f"# ROLLBACK\n# jarayonni qaytarib bo'lmaydi")

    if cat == 'file':
        if not path: return f"{header}\n# REMOVE manually (xom qiymat yo'q)"
        if os_name == 'windows':
            qp = _ps_quote(path)
            name = path.replace('/', '\\').split('\\')[-1]
            qq = _ps_quote(name + '.ir.quarantine')
            rm = f"Remove-Item -LiteralPath {qp} -Force" if full else f"Rename-Item -LiteralPath {qp} -NewName {qq}"
            return (f"{header}\n# BACKUP\nNew-Item -ItemType Directory C:\\ir\\quarantine -Force; "
                    f"Copy-Item -LiteralPath {qp} C:\\ir\\quarantine\\ -Force\n# REMOVE\n{rm}\n"
                    f"# VERIFY\nTest-Path -LiteralPath {qp}\n# ROLLBACK\nCopy-Item {_ps_quote('C:\\ir\\quarantine\\' + name)} {qp}")
        qpath = shlex.quote(path)
        qq = shlex.quote(path + '.ir.quarantine')
        return (f"{header}\n# BACKUP\nmkdir -p /tmp/ir_backup && cp -p {qpath} /tmp/ir_backup/\n"
                f"# REMOVE\nchmod -x {qpath} && mv {qpath} {qq}\n# VERIFY\nls -l {qpath} {qq}\n# ROLLBACK\nmv {qq} {qpath}")

    if cat == 'defender':
        if item == 'realtime':
            return f"{header}\n# BACKUP\nGet-MpPreference > C:\\ir\\backup\\defender.txt\n# REMOVE\nSet-MpPreference -DisableRealtimeMonitoring $false  # himoyani QAYTA YOQADI\n# VERIFY\nGet-MpComputerStatus\n# ROLLBACK\nSet-MpPreference -DisableRealtimeMonitoring $true"
        else:
            ex_path = raw or item
            if not ex_path or ex_path == 'exclusion': return f"{header}\n# REMOVE manually (xom qiymat yo'q)"
            qraw = _ps_quote(ex_path)
            return f"{header}\n# BACKUP\nGet-MpPreference > C:\\ir\\backup\\defender.txt\n# REMOVE\nRemove-MpPreference -ExclusionPath {qraw}\n# VERIFY\nGet-MpPreference | Select-Object -ExpandProperty ExclusionPath\n# ROLLBACK\nAdd-MpPreference -ExclusionPath {qraw}"

    if cat in ('vulnerabilities', 'containers', 'database_exposure'):
        fix_cmd = finding.get('suggested_fix_command', '')
        if fix_cmd:
            return f"{header}\n# REMEDIATE / PATCH\n{fix_cmd}"
        return f"{header}\n# REMOVE manually"

    return f"{header}\n# REMOVE manually"

def generate_all(findings, os_name, full=False):
    res = []
    for f in findings:
        gen = generate(f, os_name, full)
        if gen: res.append(gen)
    if not res: return ""
    if os_name == 'windows':
        pre = "# PREP\nNew-Item -ItemType Directory C:\\ir\\backup -Force | Out-Null"
    else:
        pre = "# PREP\nmkdir -p /tmp/ir_backup"
    return pre + "\n\n" + "\n\n".join(res)
