#!/bin/bash
# USAGE: bash collect_linux.sh [-o out.json] [-q]
# Remote/piped execution: ssh user@host 'bash -s' < collect_linux.sh > snap.json

if [ -z "${BASH_VERSION:-}" ]; then
  echo "[!] collect_linux.sh bash talab qiladi: sudo bash collect_linux.sh -o snap.json" >&2
  exit 2
fi
out="-"
quiet=0
DAYS_BACK=30
events_days=7
events_csv=""
events_skip=0
events_max=20000
log_root=""
events_only=0
utc_offset=""

while getopts "o:qd:D:E:NM:R:OZ:H:" opt; do
  case $opt in
    o) out="$OPTARG" ;;
    q) quiet=1 ;;
    d) DAYS_BACK="$OPTARG" ;;
    D) events_days="$OPTARG" ;;
    E) events_csv="$OPTARG" ;;
    N) events_skip=1 ;;
    M) events_max="$OPTARG" ;;
    R) log_root="$OPTARG" ;;
    O) events_only=1 ;;
    Z) utc_offset="$OPTARG" ;;
    H) opt_H="$OPTARG" ;;
  esac
done





meta_events_json='{"skipped":"not run"}'

escape() {
  local s="$1"
  s=$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037')
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

collect_events() {
  if [ "$events_skip" -eq 1 ]; then
    meta_events_json='{"skipped":"NoEvents"}'
    if [ $quiet -eq 0 ]; then echo "[*] Events skipped: NoEvents" >&2; fi
    return 0
  fi
  
  local csv_path=""
  if [ -n "$events_csv" ]; then
    csv_path="$events_csv"
  elif [ -n "$out" ] && [ "$out" != "-" ]; then
    if [[ "$out" == *.json ]]; then
      csv_path="${out%.json}_events.csv"
    else
      csv_path="${out}_events.csv"
    fi
  else
    meta_events_json='{"skipped":"stdout"}'
    if [ $events_only -eq 1 ]; then
      echo "[!] -O uchun -E yoki -o kerak" >&2
      exit 2
    fi
    if [ $quiet -eq 0 ]; then echo "[*] Events skipped: stdout" >&2; fi
    return 0
  fi
  
  local meta_out="$csv_path"
  local meta_days="$events_days"
  local meta_max="$events_max"
  local meta_total=0
  local meta_journal=0
  local meta_files=0
  local meta_auditd=0
  local meta_bash=0
  local syslog_source="none"
  local meta_skipped=""
  local meta_errors=""
  local meta_archive=""
  
  if [ "$(id -u)" -ne 0 ] && [ -z "$log_root" ]; then
    meta_errors="\"root emas - auth.log/audit.log o'qilmasligi mumkin (ruxsat)\""
    echo "[!] root emas - auth.log/audit.log o'qilmasligi mumkin" >&2
  fi
  
  # Vaqtinchalik papka YO'Q (kollektorda hech qanday o'chirish bo'lmasin): CSV to'g'ridan-to'g'ri yoziladi,
  # journal va `last` chiqishi CSV yonida dalil fayli sifatida qoladi.
  local tmp_csv="$csv_path"
  local journal_txt="${csv_path%.csv}_journal.log"
  local last_txt="${csv_path%.csv}_last.txt"
  
  echo "TimeCreated,Computer,Channel,EventID,user,process,parent_process,CommandLine,src,dst,message" > "$tmp_csv"

  # Find actual local tz if needed
  local tz="$utc_offset"
  if [ -z "$tz" ]; then
    tz=$(date +%z)
    tz="${tz:0:3}:${tz:3:2}"
  fi
  
  local awk_syslog='

function civil_from_days(z,    era, doe, yoe, y, doy, mp, d, m) {
    z = z + 719468
    era = (z >= 0 ? z : z - 146096)
    era = int(era / 146097)
    doe = z - era * 146097
    yoe = int((doe - int(doe/1460) + int(doe/36524) - int(doe/146096)) / 365)
    y = yoe + era * 400
    doy = doe - (365 * yoe + int(yoe/4) - int(yoe/100))
    mp = int((5 * doy + 2) / 153)
    d = doy - int((153 * mp + 2) / 5) + 1
    m = mp + (mp < 10 ? 3 : -9)
    y = y + (m <= 2 ? 1 : 0)
    return sprintf("%04d-%02d-%02d", y, m, d)
}
function format_epoch(epoch,    s, ms, z, h, min, sec, days) {
    s = int(epoch)
    ms = int((epoch - s) * 1000 + 0.5)
    z = int(s / 86400)
    if (s < 0 && s % 86400 != 0) z -= 1
    sec = s % 86400
    if (sec < 0) sec += 86400
    h = int(sec / 3600)
    min = int((sec % 3600) / 60)
    sec = sec % 60
    if (ms > 0) return sprintf("%sT%02d:%02d:%02d.%03dZ", civil_from_days(z), h, min, sec, ms)
    return sprintf("%sT%02d:%02d:%02dZ", civil_from_days(z), h, min, sec)
}
function escape_csv(s) {
    gsub(/[[:cntrl:]]/, " ", s)
    gsub(/"/, "\"\"", s)
    return "\"" s "\""
}

BEGIN {
    # Months map
    mmap["Jan"]="01"; mmap["Feb"]="02"; mmap["Mar"]="03"; mmap["Apr"]="04"; mmap["May"]="05"; mmap["Jun"]="06"
    mmap["Jul"]="07"; mmap["Aug"]="08"; mmap["Sep"]="09"; mmap["Oct"]="10"; mmap["Nov"]="11"; mmap["Dec"]="12"
}
{
    tc = ""
    host = ""
    ident = ""
    msg = ""
    # 1. ISO: 2026-09-30T10:00:01.123456+05:00 web01 sshd[1234]: xabar
    if ($1 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T/) {
        tc = $1
        # fix offset +0500 -> +05:00
        if (tc ~ /[+-][0-9][0-9][0-9][0-9]$/) {
            tc = substr(tc, 1, length(tc)-2) ":" substr(tc, length(tc)-1)
        }
        host = $2
        ident_raw = $3
        msg = $0
        sub(/^[^ ]+ +[^ ]+ +[^ ]+ /, "", msg)
    }
    # 2. RFC3164: Sep 30 10:00:01 web01 sshd[1234]: xabar
    else if ($1 in mmap) {
        day = $2
        time_part = $3
        host = $4
        ident_raw = $5
        msg = $0
        # regex for stripping first 5 parts is tricky because of double space in day
        # Sep  3 09:05:00 web01 sshd[99]: msg
        # Just use match
        match($0, /^[A-Z][a-z][a-z] +[0-9]+ +[0-9:]+ +[^ ]+ +[^ ]+ /)
        if (RSTART > 0) {
            msg = substr($0, RLENGTH + 1)
        }
        
        m_num = mmap[$1]
        y = rfc_year
        if (m_num > rfc_month) {
            y = y - 1
        }
        tc = sprintf("%04d-%s-%02dT%s%s", y, m_num, day, time_part, tz)
    } else {
        next
    }
    
    if (tc == "") next
    
    if (host == "") host = fallback_host
    
    # parse ident
    # remove trailing colon
    sub(/:$/, "", ident_raw)
    # remove [pid]
    sub(/\[[0-9]+\]$/, "", ident_raw)
    ident = ident_raw
    
    channel = "syslog"
    chan_lower = tolower(ident)
    if (chan_lower ~ /^(sshd|sudo|su|useradd|usermod|userdel|groupadd|groupmod|gpasswd|passwd|chpasswd|chage|login|systemd-logind)$/ || chan_lower ~ /^pam/) {
        channel = "auth"
    } else if (chan_lower ~ /^cron/) {
        channel = "cron"
    }
    
    event_id = chan_lower
    process = ident
    
    # trim message to 2000 chars
    if (length(msg) > 2000) {
        msg = substr(msg, 1, 2000)
    }
    
    user = ""
    src = ""
    cmd = ""
    
    # Regexes
    # Accepted/Failed \S+ for (invalid user )?(\S+) from (\S+)
    if (match(msg, /(Accepted|Failed) [^ ]+ for (invalid user )?([^ ]+) from ([^ ]+)/)) {
        s = substr(msg, RSTART, RLENGTH)
        split(s, arr, " ")
        if (arr[4] == "invalid" && arr[5] == "user") {
            user = arr[6]
            src = arr[8]
        } else {
            user = arr[4]
            src = arr[6]
        }
    } else if (match(msg, /Invalid user ([^ ]+) from ([^ ]+)/)) {
        s = substr(msg, RSTART, RLENGTH)
        split(s, arr, " ")
        user = arr[3]
        src = arr[5]
    } else if (chan_lower == "sudo" && match(msg, /^[ \t]*([^ ]+) : .*COMMAND=(.*)$/)) {
        s = msg
        sub(/^[ \t]*/, "", s)
        user = substr(s, 1, index(s, " ")-1)
        match(s, /COMMAND=.*$/)
        cmd = substr(s, RSTART + 8, RLENGTH - 8)
    } else if (match(msg, /session opened for user ([^ ]+)/)) {
        s = substr(msg, RSTART, RLENGTH)
        split(s, arr, " ")
        user = arr[5]
        sub(/\(uid=[0-9]+\)$/, "", user)
    } else if (match(msg, /new user: name=([^,]+)/)) {
        s = substr(msg, RSTART, RLENGTH)
        sub(/.*name=/, "", s)
        user = s
    } else if (match(msg, /new group: name=([^,]+)/)) {
        s = substr(msg, RSTART, RLENGTH)
        sub(/.*name=/, "", s)
        user = s
    } else if (chan_lower ~ /^cron/ && match(msg, /\(([^)]+)\) CMD \((.*)\)$/)) {
        # find user and cmd.
        match(msg, /\(([^)]+)\) CMD \(/)
        user = substr(msg, RSTART+1, RLENGTH - 8)
        match(msg, /CMD \((.*)\)$/)
        cmd = substr(msg, RSTART+5, RLENGTH - 6)
    }
    
    printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n", escape_csv(tc), escape_csv(host), escape_csv(channel), escape_csv(event_id), escape_csv(user), escape_csv(process), escape_csv(""), escape_csv(cmd), escape_csv(src), escape_csv(""), escape_csv(msg)
}'

  # Source 1: Syslog/journal
  local fallback_host="unknown"
  if [ -n "$opt_H" ]; then
      fallback_host="$opt_H"
  elif [ -z "$log_root" ]; then
      fallback_host=$(hostname 2>/dev/null || echo "unknown")
  else
      fallback_host=""
  fi
  if [ -z "$log_root" ] && command -v journalctl >/dev/null 2>&1; then
     # Try precise
     journalctl -q --no-pager -o short-iso-precise --since "$events_days days ago" | tail -n "$events_max" > "$journal_txt" 2>/dev/null
     if [ $? -ne 0 ] || [ ! -s "$journal_txt" ]; then
         journalctl -q --no-pager -o short-iso --since "$events_days days ago" | tail -n "$events_max" > "$journal_txt" 2>/dev/null
     fi
     
     if [ -s "$journal_txt" ]; then
         syslog_source="journal"
         meta_journal=$(awk -v fallback_host="$fallback_host" "$awk_syslog" "$journal_txt" | tee -a "$tmp_csv" | wc -l)
     fi
  fi
  
  if [ "$syslog_source" = "none" ]; then
      syslog_source="files"
      for f in "$log_root"/var/log/auth.log* "$log_root"/var/log/secure* "$log_root"/var/log/syslog* "$log_root"/var/log/messages*; do
          if [ -f "$f" ]; then
              if [ ! -r "$f" ]; then
                  if [ -z "$meta_errors" ]; then meta_errors='"'"$(basename "$f")"'"'; else meta_errors="$meta_errors, "'"'"$(basename "$f")"'"'; fi
                  continue
              fi
              local mtime=$(date -r "$f" +%Y-%m 2>/dev/null || echo "1970-01")
              local rfc_year="${mtime%%-*}"
              local rfc_month="${mtime##*-}"
              local read_cmd="cat"
              if [[ "$f" == *.gz ]]; then read_cmd="gzip -dc"; fi
              
              local cnt=$($read_cmd "$f" 2>/dev/null | tail -n "$events_max" | awk -v fallback_host="$fallback_host" -v rfc_year="$rfc_year" -v rfc_month="$rfc_month" -v tz="$tz" "$awk_syslog" | tee -a "$tmp_csv" | wc -l)
              meta_files=$((meta_files + cnt))
          fi
      done
  fi

  if [ -z "$fallback_host" ]; then
      local first_host=$(head -n 2 "$tmp_csv" | tail -n 1 | cut -d, -f2 | tr -d '"')
      if [ -n "$first_host" ] && [ "$first_host" != "Computer" ]; then
          fallback_host="$first_host"
      else
          fallback_host="unknown"
      fi
  fi
  
  # Auditd
  local awk_audit='

function civil_from_days(z,    era, doe, yoe, y, doy, mp, d, m) {
    z = z + 719468
    era = (z >= 0 ? z : z - 146096)
    era = int(era / 146097)
    doe = z - era * 146097
    yoe = int((doe - int(doe/1460) + int(doe/36524) - int(doe/146096)) / 365)
    y = yoe + era * 400
    doy = doe - (365 * yoe + int(yoe/4) - int(yoe/100))
    mp = int((5 * doy + 2) / 153)
    d = doy - int((153 * mp + 2) / 5) + 1
    m = mp + (mp < 10 ? 3 : -9)
    y = y + (m <= 2 ? 1 : 0)
    return sprintf("%04d-%02d-%02d", y, m, d)
}
function format_epoch(epoch,    s, ms, z, h, min, sec, days) {
    s = int(epoch)
    ms = int((epoch - s) * 1000 + 0.5)
    z = int(s / 86400)
    if (s < 0 && s % 86400 != 0) z -= 1
    sec = s % 86400
    if (sec < 0) sec += 86400
    h = int(sec / 3600)
    min = int((sec % 3600) / 60)
    sec = sec % 60
    if (ms > 0) return sprintf("%sT%02d:%02d:%02d.%03dZ", civil_from_days(z), h, min, sec, ms)
    return sprintf("%sT%02d:%02d:%02dZ", civil_from_days(z), h, min, sec)
}
function escape_csv(s) {
    gsub(/[[:cntrl:]]/, " ", s)
    gsub(/"/, "\"\"", s)
    return "\"" s "\""
}

function hex2dec(h,   i, d, n, c) {
    d = 0; n = length(h)
    for(i=1; i<=n; i++) {
        c = tolower(substr(h, i, 1))
        d = d * 16 + (index("0123456789abcdef", c) - 1)
    }
    return d
}
function parse_args(s,    res, i, arr, p) {
    res = ""
    while (match(s, / a[0-9]+=/)) {
        p = substr(s, RSTART + RLENGTH)
        # Check if quoted
        if (substr(p, 1, 1) == "\"") {
            match(p, /^"[^"]*"/)
            arg = substr(p, 2, RLENGTH - 2)
            s = substr(p, RLENGTH + 1)
        } else {
            # unquoted, might be hex
            match(p, /^[^ ]+/)
            arg = substr(p, 1, RLENGTH)
            s = substr(p, RLENGTH + 1)
            # convert hex
            if (arg ~ /^[0-9A-Fa-f]+$/ && length(arg) % 2 == 0) {
                # Hex string
                tmp = ""
                for(i=1; i<=length(arg); i+=2) {
                    hex_pair = substr(arg, i, 2)
                    c = hex2dec(hex_pair)
                    if (c == 0) c = 32
                    tmp = tmp sprintf("%c", c)
                }
                arg = tmp
            }
        }
        if (res == "") res = arg
        else res = res " " arg
    }
    return res
}

BEGIN {
    # No arrays for caching lines across different files, but since its one file its ok.
    # We will use serials
}
{
    type = ""
    if (match($0, /type=[^ ]+/)) type = substr($0, RSTART+5, RLENGTH-5)
    
    if (type !~ /^(SYSCALL|EXECVE|USER_LOGIN|USER_AUTH|ADD_USER|DEL_USER|ADD_GROUP|USER_CMD)$/) next
    
    # msg=audit(1790744401.123:456)
    if (!match($0, /msg=audit\([^\)]+\)/)) next
    
    audit_str = substr($0, RSTART+10, RLENGTH-11)
    split(audit_str, a, ":")
    epoch = a[1]
    serial = a[2]
    
    tc = format_epoch(epoch)
    
    if (type == "SYSCALL") {
        # get auid, uid, exe, ppid
        auid = ""; uid = ""; exe = ""; ppid = ""
        if (match($0, / auid=[^ ]+/)) auid = substr($0, RSTART+6, RLENGTH-6)
        if (match($0, / uid=[^ ]+/)) uid = substr($0, RSTART+5, RLENGTH-5)
        if (match($0, / exe="[^"]+"/)) exe = substr($0, RSTART+6, RLENGTH-7)
        if (match($0, / ppid=[^ ]+/)) ppid = substr($0, RSTART+6, RLENGTH-6)
        
        sys_auid[serial] = auid
        sys_uid[serial] = uid
        sys_exe[serial] = exe
        sys_ppid[serial] = ppid
        next
    }
    
    host = fallback_host
    if (match($0, / node=[^ ]+/)) host = substr($0, RSTART+6, RLENGTH-6)
    
    channel = "auditd"
    event_id = type
    
    user = ""
    process = ""
    parent_process = ""
    cmd = ""
    src = ""
    msg = ""
    
    if (type == "EXECVE") {
        # get a0, a1, ...
        # match argc
        if (match($0, / argc=[0-9]+/)) {
            cmd = parse_args($0)
        }
        
        # process = exe from SYSCALL
        if (serial in sys_exe) process = sys_exe[serial]
        else {
            if (match($0, / a0="[^"]+"/)) process = substr($0, RSTART+5, RLENGTH-6)
            else if (match($0, / a0=[^ ]+/)) process = substr($0, RSTART+4, RLENGTH-4)
        }
        
        if (serial in sys_auid) {
            user = sys_auid[serial]
            if (user == "4294967295" || user == "unset") user = sys_uid[serial]
        }
        
        if (serial in sys_ppid) parent_process = sys_ppid[serial]
        msg = "ppid=" parent_process " serial=" serial
        
    } else {
        if (match($0, /msg=audit\([^\)]+\): /)) {
            msg = substr($0, RSTART + RLENGTH)
        }
        if (match($0, / acct="[^"]+"/)) user = substr($0, RSTART+7, RLENGTH-8)
        else if (match($0, / acct=[^ ]+/)) user = substr($0, RSTART+6, RLENGTH-6)
        
        if (match($0, / addr="[^"]+"/)) src = substr($0, RSTART+7, RLENGTH-8)
        else if (match($0, / addr=[^ ]+/)) src = substr($0, RSTART+6, RLENGTH-6)
        if (src == "?") src = ""
    }
    
    printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n", escape_csv(tc), escape_csv(host), escape_csv(channel), escape_csv(event_id), escape_csv(user), escape_csv(process), escape_csv(parent_process), escape_csv(cmd), escape_csv(src), escape_csv(""), escape_csv(msg)
}'

  for f in "$log_root"/var/log/audit/audit.log*; do
    if [ -f "$f" ]; then
      if [ ! -r "$f" ]; then
          if [ -z "$meta_errors" ]; then meta_errors='"'"$(basename "$f")"'"'; else meta_errors="$meta_errors, "'"'"$(basename "$f")"'"'; fi
          continue
      fi
      local read_cmd="cat"
      if [[ "$f" == *.gz ]]; then read_cmd="gzip -dc"; fi
      
      local cnt=$($read_cmd "$f" 2>/dev/null | tail -n "$events_max" | awk -v fallback_host="$fallback_host" "$awk_audit" | tee -a "$tmp_csv" | wc -l)
      meta_auditd=$((meta_auditd + cnt))
    fi
  done

  # Bash history
  local awk_bash='

function civil_from_days(z,    era, doe, yoe, y, doy, mp, d, m) {
    z = z + 719468
    era = (z >= 0 ? z : z - 146096)
    era = int(era / 146097)
    doe = z - era * 146097
    yoe = int((doe - int(doe/1460) + int(doe/36524) - int(doe/146096)) / 365)
    y = yoe + era * 400
    doy = doe - (365 * yoe + int(yoe/4) - int(yoe/100))
    mp = int((5 * doy + 2) / 153)
    d = doy - int((153 * mp + 2) / 5) + 1
    m = mp + (mp < 10 ? 3 : -9)
    y = y + (m <= 2 ? 1 : 0)
    return sprintf("%04d-%02d-%02d", y, m, d)
}
function format_epoch(epoch,    s, ms, z, h, min, sec, days) {
    s = int(epoch)
    ms = int((epoch - s) * 1000 + 0.5)
    z = int(s / 86400)
    if (s < 0 && s % 86400 != 0) z -= 1
    sec = s % 86400
    if (sec < 0) sec += 86400
    h = int(sec / 3600)
    min = int((sec % 3600) / 60)
    sec = sec % 60
    if (ms > 0) return sprintf("%sT%02d:%02d:%02d.%03dZ", civil_from_days(z), h, min, sec, ms)
    return sprintf("%sT%02d:%02d:%02dZ", civil_from_days(z), h, min, sec)
}
function escape_csv(s) {
    gsub(/[[:cntrl:]]/, " ", s)
    gsub(/"/, "\"\"", s)
    return "\"" s "\""
}

BEGIN {
    # default untimed
    tc = ""
}
{
    if ($0 ~ /^#[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]+$/) {
        tc = format_epoch(substr($0, 2))
        next
    }
    cmd = $0
    host = fallback_host
    channel = "bash_history"
    process = "bash"
    
    if (tc == "") {
        event_id = "history_untimed"
        msg = "vaqt yoq - fayl mtime korsatilgan"
        tc_final = file_mtime
    } else {
        event_id = "history"
        msg = ""
        tc_final = tc
    }
    
    printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n", escape_csv(tc_final), escape_csv(host), escape_csv(channel), escape_csv(event_id), escape_csv(user), escape_csv(process), escape_csv(""), escape_csv(cmd), escape_csv(""), escape_csv(""), escape_csv(msg)
    
    tc = ""
}'
  
  for f in "$log_root"/root/.bash_history "$log_root"/home/*/.bash_history "$log_root"/Users/*/.bash_history; do
      if [ -f "$f" ]; then
          if [ ! -r "$f" ]; then
              if [ -z "$meta_errors" ]; then meta_errors='"'"$(basename "$f")"'"'; else meta_errors="$meta_errors, "'"'"$(basename "$f")"'"'; fi
              continue
          fi
          
          local user="root"
          if [[ "$f" == */home/* ]]; then
              user=$(basename "$(dirname "$f")")
          fi
          
          local file_mtime=$(date -u -r "$f" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "1970-01-01T00:00:00Z")
          
          local cnt=$(cat "$f" 2>/dev/null | tail -n "$events_max" | awk -v fallback_host="$fallback_host" -v file_mtime="$file_mtime" -v user="$user" "$awk_bash" | tee -a "$tmp_csv" | wc -l)
          meta_bash=$((meta_bash + cnt))
      fi
  done

  # Zsh history
  local awk_zsh='
function civil_from_days(z,    era, doe, yoe, y, doy, mp, d, m) {
    z = z + 719468
    era = (z >= 0 ? z : z - 146096)
    era = int(era / 146097)
    doe = z - era * 146097
    yoe = int((doe - int(doe/1460) + int(doe/36524) - int(doe/146096)) / 365)
    y = yoe + era * 400
    doy = doe - (365 * yoe + int(yoe/4) - int(yoe/100))
    mp = int((5 * doy + 2) / 153)
    d = doy - int((153 * mp + 2) / 5) + 1
    m = mp + (mp < 10 ? 3 : -9)
    y = y + (m <= 2 ? 1 : 0)
    return sprintf("%04d-%02d-%02d", y, m, d)
}
function format_epoch(epoch,    s, ms, z, h, min, sec, days) {
    s = int(epoch)
    ms = int((epoch - s) * 1000 + 0.5)
    z = int(s / 86400)
    if (s < 0 && s % 86400 != 0) z -= 1
    sec = s % 86400
    if (sec < 0) sec += 86400
    h = int(sec / 3600)
    min = int((sec % 3600) / 60)
    sec = sec % 60
    if (ms > 0) return sprintf("%sT%02d:%02d:%02d.%03dZ", civil_from_days(z), h, min, sec, ms)
    return sprintf("%sT%02d:%02d:%02dZ", civil_from_days(z), h, min, sec)
}
function escape_csv(s) {
    gsub(/[[:cntrl:]]/, " ", s)
    gsub(/"/, """", s)
    return "\"" s "\""
}

{
    host = fallback_host
    channel = "zsh_history"
    process = "zsh"
    
    if (match($0, /^: [0-9][0-9]*:[0-9][0-9]*;/)) {
        match_str = substr($0, 1, RLENGTH)
        split(match_str, a, ":")
        epoch = a[2]
        cmd = substr($0, RLENGTH + 1)
        event_id = "history"
        msg = ""
        tc_final = format_epoch(epoch)
    } else {
        cmd = $0
        event_id = "history_untimed"
        msg = "vaqt yoq - fayl mtime korsatilgan"
        tc_final = file_mtime
    }
    
    printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n", escape_csv(tc_final), escape_csv(host), escape_csv(channel), escape_csv(event_id), escape_csv(user), escape_csv(process), escape_csv(""), escape_csv(cmd), escape_csv(""), escape_csv(""), escape_csv(msg)
}'

  local meta_zsh=0
  for f in "$log_root"/root/.zsh_history "$log_root"/home/*/.zsh_history "$log_root"/Users/*/.zsh_history; do
      if [ -f "$f" ]; then
          if [ ! -r "$f" ]; then
              local escaped_f; escaped_f=$(escape "$(basename "$f")"); if [ -z "$meta_errors" ]; then meta_errors="\"$escaped_f: o'qib bo'lmadi (ruxsat)\""; else meta_errors="$meta_errors, \"$escaped_f: o'qib bo'lmadi (ruxsat)\""; fi
              continue
          fi
          
          local user="root"
          if [[ "$f" == */home/* ]] || [[ "$f" == */Users/* ]]; then
              user=$(basename "$(dirname "$f")")
          fi
          
          local file_mtime=$(date -u -r "$f" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "1970-01-01T00:00:00Z")
          
          local cnt=$(cat "$f" 2>/dev/null | tail -n "$events_max" | awk -v fallback_host="$fallback_host" -v file_mtime="$file_mtime" -v user="$user" "$awk_zsh" | tee -a "$tmp_csv" | wc -l)
          meta_zsh=$((meta_zsh + cnt))
      fi
  done

  # Archive
  if [ -z "$log_root" ]; then
      local tgz_path="${csv_path%_events.csv}_logs.tgz"
      local tar_files=()
      while IFS= read -r -d $'\0' f; do
          tar_files+=("$f")
      done < <(find /var/log/auth.log* /var/log/secure* /var/log/syslog* /var/log/messages* /var/log/cron* /var/log/kern.log* /var/log/audit/ /var/log/nginx/ /var/log/apache2/ /var/log/httpd/ /root/.bash_history /home/*/.bash_history /root/.zsh_history /home/*/.zsh_history -size -200M 2>/dev/null | tr '\n' '\0')
      
      if [ ${#tar_files[@]} -gt 0 ]; then
          if command -v last >/dev/null 2>&1; then
              last -Fw > "$last_txt" 2>/dev/null
              tar_files+=("$last_txt")
          fi
          tar czf "$tgz_path" "${tar_files[@]}" 2>/dev/null
          if [ $? -eq 0 ]; then
              meta_archive="$tgz_path"
          else
              if [ -z "$meta_errors" ]; then meta_errors='"tar failed"'; else meta_errors="$meta_errors, \"tar failed\""; fi
          fi
      fi
  fi
  
  meta_total=$((meta_journal + meta_files + meta_auditd + meta_bash + meta_zsh))
  
  meta_events_json="{\"out\":\"$(escape "$csv_path")\",\"days\":$meta_days,\"max_per_source\":$meta_max,\"total\":$meta_total,\"per_source\":{\"journal\":$meta_journal,\"files\":$meta_files,\"auditd\":$meta_auditd,\"bash_history\":$meta_bash,\"zsh_history\":$meta_zsh},\"syslog_source\":\"$syslog_source\",\"skipped\":\"$meta_skipped\",\"errors\":[$meta_errors],\"archive\":\"$(escape "$meta_archive")\"}"
  
  if [ $quiet -eq 0 ]; then
      echo "[*] Events: $meta_total -> $csv_path" >&2
  fi
}

if [ $events_only -eq 1 ]; then
  collect_events
  exit 0
fi
if [ $quiet -eq 0 ] && [ $events_only -eq 0 ]; then
  echo "[*] Collecting Linux snapshot..." >&2
fi



users="[]"
services="[]"
cron="[]"
tasks="[]"
autoruns="[]"
ssh_authorized_keys="[]"
listening_ports="[]"
connections="[]"
hosts_file="[]"
suid_files="[]"
remote_access_tools="[]"
recent_modified="[]"
proxy="{}"
dns_servers="[]"
root_cas="[]"
portproxy="[]"
firewall_profiles="[]"
packages="[]"
containers="[]"
errors="[]"
processes="[]"
suspicious_files="[]"

append_json() {
  local var_name=$1
  local obj=$2
  local current
  eval "current=\$$var_name"
  if [ "$current" = "[]" ]; then
    eval "$var_name=\"[\$obj]\""
  else
    local inner="${current%\]}"
    eval "$var_name=\"\$inner, \$obj]\""
  fi
}

while IFS=: read -r user pass uid gid gecos home shell; do
  [ -z "$uid" ] || ! [[ "$uid" =~ ^[0-9]+$ ]] && uid=-1
  is_admin="false"
  if [ "$uid" -eq 0 ]; then
    is_admin="true"
  else
    for g in sudo wheel admin; do
      g_gid=$(getent group $g 2>/dev/null | cut -d: -f3)
      if [ -n "$g_gid" ] && [ "$gid" = "$g_gid" ]; then
        is_admin="true"
        break
      fi
    done
    if [ "$is_admin" = "false" ]; then
      for g in sudo wheel admin; do
        if getent group $g 2>/dev/null | cut -d: -f4 | tr ',' '\n' | grep -qx "$user"; then
          is_admin="true"
          break
        fi
      done
    fi
  fi
  enabled="true"
  if [[ "$shell" == *nologin ]] || [[ "$shell" == */bin/false ]]; then enabled="false"; fi
  groups_json="[]"
  grps=$(id -nG "$user" 2>/dev/null)
  if [ -n "$grps" ]; then
    groups_json="["
    first_g=1
    for g in $grps; do
      if [ $first_g -eq 1 ]; then groups_json="${groups_json}\"$(escape "$g")\""; first_g=0; else groups_json="${groups_json},\"$(escape "$g")\""; fi
    done
    groups_json="${groups_json}]"
  fi
  append_json users "{\"name\":\"$(escape "$user")\",\"enabled\":$enabled,\"is_admin\":$is_admin,\"uid\":$uid,\"shell\":\"$(escape "$shell")\",\"groups\":$groups_json}"
done < /etc/passwd

if command -v systemctl >/dev/null 2>&1; then
  while read -r unit state rest; do
    [ -n "$unit" ] && append_json services "{\"name\":\"$(escape "$unit")\",\"display\":\"$(escape "$unit")\",\"state\":\"$(escape "$state")\",\"start_mode\":\"auto\",\"binary_path\":\"\",\"run_as\":\"\"}"
  done < <(systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null)
fi

for u in $(cut -f1 -d: /etc/passwd); do
  if crontab -u "$u" -l >/dev/null 2>&1; then
    while read -r line; do
      [ -z "$line" ] && continue
      append_json cron "{\"user\":\"$(escape "$u")\",\"job\":\"$(escape "$line")\"}"
    done < <(crontab -u "$u" -l 2>/dev/null | grep -v '^#')
  fi
done
for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly; do
  if [ -d "$d" ]; then
    for f in "$d"/*; do
      [ -f "$f" ] && append_json cron "{\"user\":\"root\",\"job\":\"$(escape "$f")\"}"
    done
  fi
done
[ -f /etc/crontab ] && append_json cron "{\"user\":\"root\",\"job\":\"/etc/crontab\"}"

if command -v systemctl >/dev/null 2>&1; then
  # NEXT/LAST ustunlari bir necha so'zdan iborat — UNIT va ACTIVATES doim oxirgi ikki maydon
  while read -r unit activ; do
    [ -n "$unit" ] && append_json tasks "{\"name\":\"$(escape "$unit")\",\"path\":\"/etc/systemd/system\",\"enabled\":true,\"author\":\"system\",\"action\":\"$(escape "$activ")\",\"trigger\":\"timer\"}"
  done < <(systemctl list-timers --all --no-legend 2>/dev/null | awk 'NF>=2 {print $(NF-1), $NF}')
fi

for f in /etc/rc.local /etc/profile.d/* ~/.bashrc ~/.profile /etc/ld.so.preload; do
  if [ -f "$f" ]; then
    append_json autoruns "{\"location\":\"$(escape "$f")\",\"name\":\"file\",\"value\":\"exists\"}"
  fi
done
if [ -d /etc/systemd/system ]; then
  for f in /etc/systemd/system/*.service; do
    [ -f "$f" ] && append_json autoruns "{\"location\":\"$(escape "$f")\",\"name\":\"systemd\",\"value\":\"service\"}"
  done
fi

for d in /root /home/*; do
  if [ -f "$d/.ssh/authorized_keys" ]; then
    while read -r key; do
      [ -z "$key" ] || [ "${key:0:1}" = "#" ] && continue
      append_json ssh_authorized_keys "{\"file\":\"$(escape "$d/.ssh/authorized_keys")\",\"key\":\"$(escape "$key")\"}"
    done < "$d/.ssh/authorized_keys"
  fi
done

split_hostport() {
  local x="$1"
  local port="${x##*:}"
  local addr="${x%:*}"
  addr="${addr%\%*}"
  addr="${addr//[\[\]]/}"
  if ! [[ "$port" =~ ^[0-9]+$ ]]; then port=0; fi
  echo "$addr $port"
}

get_pid() {
  local proc="$1"
  local pid=$(echo "$proc" | grep -oP '(?<=pid=)[0-9]+' | head -n1)
  if [ -z "$pid" ]; then pid=0; fi
  echo "$pid"
}

if command -v ss >/dev/null 2>&1; then
  while read -r state recv send local peer process rest; do
    proc_name=$(echo "$process" | grep -o 'users:(("[^"]*' | cut -d'"' -f2 | head -n1)
    pid=$(get_pid "$process")
    read -r addr port < <(split_hostport "$local")
    append_json listening_ports "{\"proto\":\"tcp\",\"addr\":\"$(escape "$addr")\",\"port\":$port,\"pid\":$pid,\"process\":\"$(escape "$proc_name")\"}"
  done < <(ss -tlnp 2>/dev/null | tail -n +2)
  while read -r recv send local peer process rest; do
    proc_name=$(echo "$process" | grep -o 'users:(("[^"]*' | cut -d'"' -f2 | head -n1)
    pid=$(get_pid "$process")
    read -r laddr lport < <(split_hostport "$local")
    read -r raddr rport < <(split_hostport "$peer")
    append_json connections "{\"proto\":\"tcp\",\"laddr\":\"$(escape "$laddr")\",\"lport\":$lport,\"raddr\":\"$(escape "$raddr")\",\"rport\":$rport,\"pid\":$pid,\"process\":\"$(escape "$proc_name")\"}"
  done < <(ss -tnp state established 2>/dev/null | tail -n +2)
elif command -v netstat >/dev/null 2>&1; then
  while read -r proto recv send local peer state process rest; do
    proc_name="${process#*/}"
    pid="${process%%/*}"
    if ! [[ "$pid" =~ ^[0-9]+$ ]]; then pid=0; proc_name=""; fi
    read -r addr port < <(split_hostport "$local")
    append_json listening_ports "{\"proto\":\"tcp\",\"addr\":\"$(escape "$addr")\",\"port\":$port,\"pid\":$pid,\"process\":\"$(escape "$proc_name")\"}"
  done < <(netstat -tlnp 2>/dev/null | tail -n +2 | grep '^tcp')
  while read -r proto recv send local peer state process rest; do
    proc_name="${process#*/}"
    pid="${process%%/*}"
    if ! [[ "$pid" =~ ^[0-9]+$ ]]; then pid=0; proc_name=""; fi
    read -r laddr lport < <(split_hostport "$local")
    read -r raddr rport < <(split_hostport "$peer")
    append_json connections "{\"proto\":\"tcp\",\"laddr\":\"$(escape "$laddr")\",\"lport\":$lport,\"raddr\":\"$(escape "$raddr")\",\"rport\":$rport,\"pid\":$pid,\"process\":\"$(escape "$proc_name")\"}"
  done < <(netstat -tnp 2>/dev/null | tail -n +2 | grep '^tcp' | grep 'ESTABLISHED')
else
  append_json errors '"ports: ss/netstat topilmadi"'
fi

if [ -f /etc/hosts ]; then
  while read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    append_json hosts_file "\"$(escape "$line")\""
  done < /etc/hosts
fi

while read -r f; do
  append_json suid_files "{\"path\":\"$(escape "$f")\"}"
done < <(timeout 10 find / -xdev -type f -perm -4000 2>/dev/null | head -n 100)

while read -r comm args; do
  append_json remote_access_tools "{\"name\":\"$(escape "$comm")\",\"evidence\":\"process\"}"
done < <(ps -eo comm,args 2>/dev/null | grep -iE 'anydesk|teamviewer|rutserv|rfusclient|ammyy|rustdesk|screenconnect|connectwise|aeroadmin|radmin|litemanager|ngrok' | grep -v grep)


proxy_env=$(grep -i "proxy" /etc/environment 2>/dev/null | tr '\n' ';' | sed 's/"/\"/g')
proxy_apt=$(cat /etc/apt/apt.conf.d/*proxy* 2>/dev/null | tr '\n' ';' | sed 's/"/\"/g')
proxy_pkg=$(cat /etc/dnf/dnf.conf /etc/yum.conf /etc/zypp/zypp.conf /etc/sysconfig/proxy 2>/dev/null | grep -i "proxy" | grep -v '^[[:space:]]*#' | tr '\n' ';' | sed 's/"/\"/g')
proxy="{\"environment\":\"$(escape "$proxy_env")\",\"apt\":\"$(escape "$proxy_apt")\",\"http_proxy\":\"$(escape "$http_proxy")\",\"pkg\":\"$(escape "$proxy_pkg")\"}"

if [ -f /etc/resolv.conf ]; then
  dns_ips=$(grep '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ',' | sed 's/,$//')
  append_json dns_servers "{\"interface\":\"resolv.conf\",\"addresses\":\"$(escape "$dns_ips")\"}"
fi
if command -v resolvectl >/dev/null 2>&1; then
  res_dns=$(resolvectl status 2>/dev/null | grep 'DNS Servers' | awk -F': ' '{print $2}' | tr '\n' ',' | sed 's/,$//')
  [ -n "$res_dns" ] && append_json dns_servers "{\"interface\":\"resolvectl\",\"addresses\":\"$(escape "$res_dns")\"}"
fi

ca_bundle=""
for b in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/ssl/ca-bundle.pem; do
  if [ -f "$b" ]; then
    ca_bundle="$b"
    break
  fi
done
ca_count=0
if [ -n "$ca_bundle" ]; then
  ca_count=$(grep -c 'BEGIN CERTIFICATE' "$ca_bundle" 2>/dev/null)
fi
[ -z "$ca_count" ] && ca_count=0
local_cas=""
for d in /usr/local/share/ca-certificates/ /etc/pki/ca-trust/source/anchors/ /etc/pki/trust/anchors/; do
  if [ -d "$d" ]; then
    d_name=$(basename "$d")
    while IFS= read -r f; do
      [ -z "$f" ] && continue
      if [ -z "$local_cas" ]; then local_cas="${d_name}/${f}"; else local_cas="${local_cas},${d_name}/${f}"; fi
    done < <(ls -1 "$d" 2>/dev/null)
  fi
done
append_json root_cas "{\"ca_certificates_crt_count\":$ca_count,\"local_share\":\"$(escape "$local_cas")\",\"bundle_path\":\"$(escape "$ca_bundle")\"}"

if command -v iptables >/dev/null 2>&1; then
  while read -r line; do
    append_json portproxy "{\"rule\":\"$(escape "$line")\"}"
  done < <(iptables -t nat -L -n 2>/dev/null | grep -i '^dnat' | head -n 100)
elif command -v nft >/dev/null 2>&1; then
  while read -r line; do
    append_json portproxy "{\"rule\":\"$(escape "$line")\"}"
  done < <(nft list ruleset 2>/dev/null | grep -i dnat | head -n 100)
fi

if command -v ufw >/dev/null 2>&1; then
  ufw_st=$(ufw status 2>/dev/null | head -n1)
  append_json firewall_profiles "{\"name\":\"ufw\",\"state\":\"$(escape "$ufw_st")\"}"
elif command -v firewall-cmd >/dev/null 2>&1; then
  fw_st=$(firewall-cmd --state 2>/dev/null)
  append_json firewall_profiles "{\"name\":\"firewalld\",\"state\":\"$(escape "$fw_st")\"}"
fi

# --- Packages (dpkg / rpm / apk) ---
if command -v dpkg-query >/dev/null 2>&1; then
  while IFS=$'\t' read -r pkg_name pkg_ver pkg_arch; do
    [ -z "$pkg_name" ] && continue
    append_json packages "{\"name\":\"$(escape "$pkg_name")\",\"version\":\"$(escape "$pkg_ver")\",\"arch\":\"$(escape "$pkg_arch")\",\"manager\":\"dpkg\"}"
  done < <(dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' 2>/dev/null)
elif command -v rpm >/dev/null 2>&1; then
  while IFS=$'\t' read -r pkg_name pkg_ver pkg_arch; do
    [ -z "$pkg_name" ] && continue
    append_json packages "{\"name\":\"$(escape "$pkg_name")\",\"version\":\"$(escape "$pkg_ver")\",\"arch\":\"$(escape "$pkg_arch")\",\"manager\":\"rpm\"}"
  done < <(rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n' 2>/dev/null)
elif command -v apk >/dev/null 2>&1; then
  while read -r line; do
    [ -z "$line" ] && continue
    pkg_name=$(echo "$line" | sed 's/-[0-9].*//')
    pkg_ver=$(echo "$line" | sed "s/^${pkg_name}-//")
    append_json packages "{\"name\":\"$(escape "$pkg_name")\",\"version\":\"$(escape "$pkg_ver")\",\"arch\":\"\",\"manager\":\"apk\"}"
  done < <(apk info -v 2>/dev/null)
fi

# --- Containers (Docker / Podman) ---
if command -v docker >/dev/null 2>&1; then
  while IFS=$'\t' read -r c_id c_img c_names; do
    [ -z "$c_id" ] && continue
    is_priv="false"
    mounts=""
    insp=$(docker inspect "$c_id" 2>/dev/null)
    if echo "$insp" | grep -q '"Privileged": true'; then
      is_priv="true"
    fi
    if echo "$insp" | grep -q 'docker.sock'; then
      mounts="docker.sock"
    fi
    append_json containers "{\"id\":\"$(escape "$c_id")\",\"image\":\"$(escape "$c_img")\",\"name\":\"$(escape "$c_names")\",\"privileged\":$is_priv,\"mount_risks\":\"$(escape "$mounts")\"}"
  done < <(docker ps -a --no-trunc --format '{{.ID}}\t{{.Image}}\t{{.Names}}' 2>/dev/null)
elif command -v podman >/dev/null 2>&1; then
  while IFS=$'\t' read -r c_id c_img c_names; do
    [ -z "$c_id" ] && continue
    append_json containers "{\"id\":\"$(escape "$c_id")\",\"image\":\"$(escape "$c_img")\",\"name\":\"$(escape "$c_names")\",\"privileged\":false,\"mount_risks\":\"\"}"
  done < <(podman ps -a --no-trunc --format '{{.ID}}\t{{.Image}}\t{{.Names}}' 2>/dev/null)
fi

while read -r f; do
  append_json recent_modified "{\"path\":\"$(escape "$f")\",\"mtime\":\"recent\"}"
done < <(timeout 10 find /tmp /dev/shm /var/tmp /var/www -type f -mtime -2 2>/dev/null | head -n 125)

# --- deep processes ---
proc_count=0
sha256_count=0
if [ -d /proc ]; then
  for pdir in /proc/[0-9]*; do
    [ -d "$pdir" ] || continue
    pid="${pdir#/proc/}"
    
    cmdline=$(head -c 1000 "$pdir/cmdline" 2>/dev/null | tr '\0' ' ')
    path=$(readlink "$pdir/exe" 2>/dev/null)
    
    if [ -z "$cmdline" ] && [ -z "$path" ]; then
      continue
    fi
    
    proc_count=$((proc_count+1))
    if [ $proc_count -gt 1500 ]; then
      break
    fi
    
    name=$(cat "$pdir/comm" 2>/dev/null)
    
    stat_file=$(cat "$pdir/stat" 2>/dev/null)
    ppid=0
    if [ -n "$stat_file" ]; then
      rest="${stat_file##*)}"
      ppid=$(echo "$rest" | awk '{print $2}')
    fi
    
    exe_deleted="false"
    if [[ "$path" == *" (deleted)" ]]; then
      path="${path% (deleted)}"
      exe_deleted="true"
    fi
    
    user=$(stat -c %U "$pdir" 2>/dev/null || echo "")
    
    sha256=""
    if [ "$exe_deleted" = "true" ] || [[ "$path" == /tmp/* ]] || [[ "$path" == /dev/shm/* ]] || [[ "$path" == /var/tmp/* ]] || [[ "$path" == /home/* ]] || [[ "$path" == /run/user/* ]] || [[ "$path" == /root/* ]]; then
      if [ $sha256_count -lt 100 ]; then
        if [ "$exe_deleted" = "true" ]; then
          sha_out=$(sha256sum "$pdir/exe" 2>/dev/null | cut -d' ' -f1)
        else
          sha_out=$(sha256sum "$path" 2>/dev/null | cut -d' ' -f1)
        fi
        if [ -n "$sha_out" ]; then
          sha256="$sha_out"
          sha256_count=$((sha256_count+1))
        fi
      fi
    fi
    
    append_json processes "{\"pid\":$pid,\"ppid\":$ppid,\"name\":\"$(escape "$name")\",\"path\":\"$(escape "$path")\",\"cmdline\":\"$(escape "$cmdline")\",\"user\":\"$(escape "$user")\",\"start_time\":\"\",\"signed\":\"n/a\",\"sha256\":\"$(escape "$sha256")\",\"exe_deleted\":$exe_deleted}"
  done
fi
# --- deep processes end ---

find_printf="false"
find_mode="stat"
if find / -maxdepth 0 -printf '' >/dev/null 2>&1; then
  find_printf="true"
  find_mode="printf"
fi

_list_recent_files() {
  if [ "$find_printf" = "true" ]; then
    find "${dirs[@]}" -xdev -type f -mtime "-$DAYS_BACK" -printf '%p\t%s\t%T@\t%C@\t%m\n' 2>/dev/null | sort -k3 -n -r
  else
    find "${dirs[@]}" -xdev -type f -mtime "-$DAYS_BACK" 2>/dev/null | while IFS= read -r p; do
      stat -c '%s %Y %Z %a' "$p" 2>/dev/null | {
        read -r s m c a
        if [ -n "$s" ]; then
          printf '%s\t%s\t%s\t%s\t%s\n' "$p" "$s" "$m" "$c" "$a"
        fi
      }
    done | sort -k3 -n -r
  fi
}

# --- deep suspicious_files ---
files_scanned=0
files_emitted=0
files_truncated="false"
timed_out="false"
start_time=$SECONDS

dirs=()
for d in /tmp /var/tmp /dev/shm /home /root /opt /srv /var/www /usr/share/nginx /var/lib/tomcat*/webapps /usr/local/bin /usr/local/sbin; do
  if [ -d "$d" ]; then
    dirs+=("$d")
  fi
done

if [ ${#dirs[@]} -gt 0 ]; then
  while IFS=$'\t' read -r path size mtime_raw ctime_raw mode; do
    if [ -z "$path" ]; then continue; fi
    if [ $((SECONDS - start_time)) -gt 60 ]; then
      timed_out="true"
      break
    fi
    
    if [ $files_emitted -ge 400 ]; then
      files_truncated="true"
      break
    fi
    
    files_scanned=$((files_scanned+1))
    
    ext=""
    if [[ "$path" == *.* ]]; then
      ext=".${path##*.}"
      ext=$(echo "$ext" | tr '[:upper:]' '[:lower:]')
    fi
    
    is_script="false"
    if [[ "$ext" == ".sh" ]] || [[ "$ext" == ".py" ]] || [[ "$ext" == ".pl" ]] || [[ "$ext" == ".php" ]] || [[ "$ext" == ".bat" ]] || [[ "$ext" == ".cmd" ]] || [[ "$ext" == ".ps1" ]] || [[ "$ext" == ".vbs" ]] || [[ "$ext" == ".vbe" ]] || [[ "$ext" == ".js" ]] || [[ "$ext" == ".jse" ]] || [[ "$ext" == ".wsf" ]] || [[ "$ext" == ".hta" ]]; then
        is_script="true"
    fi
    
    is_web="false"
    if [[ "$ext" == ".php" ]] || [[ "$ext" == ".phtml" ]] || [[ "$ext" == ".jsp" ]] || [[ "$ext" == ".jspx" ]] || [[ "$ext" == ".asp" ]] || [[ "$ext" == ".aspx" ]] || [[ "$ext" == ".ashx" ]]; then
        is_web="true"
    fi
    
    exe_magic="false"
    magic=$(head -c 4 "$path" 2>/dev/null | od -An -tx1 | tr -d ' \n')
    if [ "$magic" = "7f454c46" ]; then
      exe_magic="true"
    fi
    
    emit="false"
    
    is_exec="false"
    octal_mode="${mode: -3}"
    if [ ${#octal_mode} -eq 3 ]; then
      u="${octal_mode:0:1}"
      g="${octal_mode:1:1}"
      o="${octal_mode:2:1}"
      if [[ "$u" =~ [1357] ]] || [[ "$g" =~ [1357] ]] || [[ "$o" =~ [1357] ]]; then
        is_exec="true"
      fi
    fi
    
    if [ "$is_exec" = "true" ]; then
      if [ "$exe_magic" = "true" ] || [ "$is_script" = "true" ]; then
        if [[ "$path" == /usr/local/bin/* ]] || [[ "$path" == /opt/* ]]; then
           if [ "$exe_magic" = "true" ]; then
               emit="true"
           fi
        else
           emit="true"
        fi
      fi
    fi
    
    if [[ "$path" == /tmp/* ]] || [[ "$path" == /var/tmp/* ]] || [[ "$path" == /dev/shm/* ]]; then
      if [ "$exe_magic" = "true" ] || [ "$is_script" = "true" ]; then
        emit="true"
      fi
    fi
    
    if [[ "$path" == /var/www/* ]] || [[ "$path" == /srv/* ]] || [[ "$path" == /usr/share/nginx/* ]] || [[ "$path" == /var/lib/tomcat* ]]; then
      if [[ "$ext" == ".php" ]] || [[ "$ext" == ".phtml" ]] || [[ "$ext" == ".jsp" ]] || [[ "$ext" == ".jspx" ]] || [[ "$ext" == ".asp" ]] || [[ "$ext" == ".aspx" ]]; then
        emit="true"
      fi
    fi
    
    if [ "$emit" = "false" ]; then
      continue
    fi
    
    hidden="false"
    if [[ "$path" == */.* ]]; then
      hidden="true"
    fi
    
    mtime=$(date -u -d @"${mtime_raw%%.*}" +%FT%TZ 2>/dev/null || echo "")
    ctime=$(date -u -d @"${ctime_raw%%.*}" +%FT%TZ 2>/dev/null || echo "")
    
    sha256=""
    if [ "$exe_magic" = "true" ] || [ "$is_script" = "true" ]; then
        if [ "$size" -le 104857600 ]; then
            sha256=$(sha256sum "$path" 2>/dev/null | cut -d' ' -f1)
        fi
    fi
    
    head_content=""
    if [ "$is_script" = "true" ] && [ "$size" -le 65536 ]; then
       head_content=$(head -c 400 "$path" 2>/dev/null | tr '\000-\010\013\014\016-\037' ' ')
    fi
    
    webshell_hint="false"
    if [ "$is_web" = "true" ]; then
       if head -c 65536 "$path" 2>/dev/null | grep -Ei 'eval\s*\(|Request(\.|\[)(Form|QueryString|Params)|cmd\.exe|Runtime\.getRuntime\(\)\.exec|\b(system|passthru|shell_exec|proc_open|popen)\s*\(|base64_decode\s*\(|ProcessStartInfo|\$_(GET|POST|REQUEST)\[' >/dev/null; then
           webshell_hint="true"
       fi
    fi
    
    append_json suspicious_files "{\"path\":\"$(escape "$path")\",\"ext\":\"$(escape "$ext")\",\"size\":$size,\"mtime\":\"$(escape "$mtime")\",\"ctime\":\"$(escape "$ctime")\",\"sha256\":\"$(escape "$sha256")\",\"signed\":\"n/a\",\"exe_magic\":$exe_magic,\"hidden\":$hidden,\"head\":\"$(escape "$head_content")\",\"webshell_hint\":$webshell_hint}"
    
    files_emitted=$((files_emitted+1))
    
  done < <(_list_recent_files)
fi
# --- deep suspicious_files end ---

if [ $events_only -eq 0 ]; then
  collect_events
fi

if [ $quiet -eq 0 ]; then
  events_count=$(echo "$meta_events_json" | grep -o '"total":[0-9]*' | cut -d: -f2 | head -n1)
if [ -z "$events_count" ]; then events_count=0; fi
echo "users=$(echo "$users" | grep -o '{' | wc -l) services=$(echo "$services" | grep -o '{' | wc -l) tasks=$(echo "$tasks" | grep -o '{' | wc -l) autoruns=$(echo "$autoruns" | grep -o '{' | wc -l) rats=$(echo "$remote_access_tools" | grep -o '{' | wc -l) events=$events_count" >&2
fi

os_id=""
os_ver=""
os_name=""
os_file="/etc/os-release"
[ ! -f "$os_file" ] && os_file="/usr/lib/os-release"
if [ -f "$os_file" ]; then
  os_id=$(grep '^ID=' "$os_file" 2>/dev/null | cut -d= -f2- | sed "s/^\"//;s/\"\$//;s/^'//;s/'\$//")
  os_ver=$(grep '^VERSION_ID=' "$os_file" 2>/dev/null | cut -d= -f2- | sed "s/^\"//;s/\"\$//;s/^'//;s/'\$//")
  os_name=$(grep '^PRETTY_NAME=' "$os_file" 2>/dev/null | cut -d= -f2- | sed "s/^\"//;s/\"\$//;s/^'//;s/'\$//")
fi
cap_journal="false"; command -v journalctl >/dev/null 2>&1 && cap_journal="true"
cap_audit="false"; [ -r /var/log/audit/audit.log ] && cap_audit="true"
cap_ss="false"; command -v ss >/dev/null 2>&1 && cap_ss="true"
cap_netstat="false"; command -v netstat >/dev/null 2>&1 && cap_netstat="true"
cap_systemctl="false"; command -v systemctl >/dev/null 2>&1 && cap_systemctl="true"
cap_root="false"; [ "$(id -u)" = 0 ] && cap_root="true"
cap_json="{\"journalctl\":$cap_journal,\"auditd_log\":$cap_audit,\"ss\":$cap_ss,\"netstat\":$cap_netstat,\"systemctl\":$cap_systemctl,\"find_printf\":$find_printf,\"is_root\":$cap_root}"
distro_json="{\"id\":\"$(escape "$os_id")\",\"version_id\":\"$(escape "$os_ver")\",\"pretty_name\":\"$(escape "$os_name")\"}"

JSON_PAYLOAD=$(cat << EOF
{
  "meta": {"os":"linux", "hostname":"$(escape "$(hostname 2>/dev/null || echo "unknown")")", "events": $meta_events_json, "collected_at":"$(date -Iseconds)", "collector_version":"1.1", "collector_rev":"distro-1", "distro": $distro_json, "capabilities": $cap_json, "deep": {"processes": $proc_count, "files_scanned": $files_scanned, "files_emitted": $files_emitted, "files_truncated": $files_truncated, "timed_out": $timed_out, "find_mode": "$(escape "$find_mode")"}},
  "processes": $processes,
  "suspicious_files": $suspicious_files,
  "users": $users,
  "services": $services,
  "tasks": $tasks,
  "cron": $cron,
  "autoruns": $autoruns,
  "wmi_subscriptions": [],
  "ssh_authorized_keys": $ssh_authorized_keys,
  "listening_ports": $listening_ports,
  "connections": $connections,
  "hosts_file": $hosts_file,
  "suid_files": $suid_files,
  "startup_items": [],
  "remote_access_tools": $remote_access_tools,
  "proxy": $proxy,
  "dns_servers": $dns_servers,
  "root_cas": $root_cas,
  "portproxy": $portproxy,
  "firewall_profiles": $firewall_profiles,
  "defender": {},
  "recent_modified": $recent_modified,
  "packages_modified": [],
  "packages": $packages,
  "containers": $containers,
  "errors": $errors
}
EOF
)

if [ "$out" = "-" ]; then
  echo "$JSON_PAYLOAD"
else
  echo "$JSON_PAYLOAD" > "$out"
fi

if [ $quiet -eq 0 ]; then
  if [ "$out" = "-" ]; then
    echo "Snapshot JSON printed to STDOUT" >&2
  else
    echo "Snapshot saved to $out" >&2
  fi
fi
