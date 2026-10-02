import os

def update_bash_script():
    with open("responder/collect_linux.sh", "r", newline="\n") as f:
        content = f.read()

    awk_functions = r"""
function civil_from_days(z,    era, doe, yoe, y, doy, mp, d, m) {
    z = z + 719468
    era = (z >= 0 ? z : z - 146096)
    era = int(era / 146097)
    doe = z - era * 146097
    yoe = int((doe - doe/1460 + doe/36524 - doe/146096) / 365)
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
    gsub(/\r|\t|[\x00-\x1F]/, " ", s)
    gsub(/"/, "\"\"", s)
    return "\"" s "\""
}
"""

    collect_events = r"""
meta_events_json='{"skipped":"not run"}'

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
    meta_errors='"root emas - auth.log/audit.log oqilmasligi mumkin"'
    echo "[!] root emas - auth.log/audit.log o'qilmasligi mumkin" >&2
  fi
  
  local tmp_dir=$(mktemp -d 2>/dev/null || mktemp -d -t 'bk_events_XXXXXX')
  trap 'rm -rf "$tmp_dir"' EXIT
  local tmp_csv="$tmp_dir/events.csv"
  
  echo "TimeCreated,Computer,Channel,EventID,user,process,parent_process,CommandLine,src,dst,message" > "$tmp_csv"

  # Find actual local tz if needed
  local tz="$utc_offset"
  if [ -z "$tz" ]; then
    tz=$(date +%z)
    tz="${tz:0:3}:${tz:3:2}"
  fi
  
  local awk_syslog='
__AWK_FUNCTIONS__
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
    if ($1 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T/) {
        tc = $1
        # fix offset +0500 -> +05:00
        if (tc ~ /[+-][0-9]{4}$/) {
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
        match($0, /^[A-Z][a-z]{2} +[0-9]+ +[0-9:]+ +[^ ]+ +[^ ]+ /)
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
  local fallback_host=$(hostname 2>/dev/null || echo "unknown")
  if [ -z "$log_root" ] && command -v journalctl >/dev/null 2>&1; then
     # Try precise
     journalctl -q --no-pager -o short-iso-precise --since "$events_days days ago" | tail -n "$events_max" > "$tmp_dir/j.log" 2>/dev/null
     if [ $? -ne 0 ] || [ ! -s "$tmp_dir/j.log" ]; then
         journalctl -q --no-pager -o short-iso --since "$events_days days ago" | tail -n "$events_max" > "$tmp_dir/j.log" 2>/dev/null
     fi
     
     if [ -s "$tmp_dir/j.log" ]; then
         syslog_source="journal"
         meta_journal=$(awk -v fallback_host="$fallback_host" "$awk_syslog" "$tmp_dir/j.log" | tee -a "$tmp_csv" | wc -l)
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

  # Auditd
  local awk_audit='
__AWK_FUNCTIONS__
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
__AWK_FUNCTIONS__
BEGIN {
    # default untimed
    tc = ""
}
{
    if ($0 ~ /^#[0-9]{10,}$/) {
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
  
  for f in "$log_root"/root/.bash_history "$log_root"/home/*/.bash_history; do
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
  
  # Archive
  if [ -z "$log_root" ]; then
      local tgz_path="${csv_path%_events.csv}_logs.tgz"
      local tar_files=()
      while IFS= read -r -d $'\0' f; do
          tar_files+=("$f")
      done < <(find /var/log/auth.log* /var/log/secure* /var/log/syslog* /var/log/messages* /var/log/cron* /var/log/kern.log* /var/log/audit/ /var/log/nginx/ /var/log/apache2/ /var/log/httpd/ /root/.bash_history /home/*/.bash_history -size -200M 2>/dev/null | tr '\n' '\0')
      
      if [ ${#tar_files[@]} -gt 0 ]; then
          if command -v last >/dev/null 2>&1; then
              last -Fw > "$tmp_dir/last.txt" 2>/dev/null
              tar_files+=("$tmp_dir/last.txt")
          fi
          tar czf "$tgz_path" "${tar_files[@]}" 2>/dev/null
          if [ $? -eq 0 ]; then
              meta_archive="$tgz_path"
          else
              if [ -z "$meta_errors" ]; then meta_errors='"tar failed"'; else meta_errors="$meta_errors, \"tar failed\""; fi
          fi
      fi
  fi
  
  cp "$tmp_csv" "$csv_path"
  meta_total=$((meta_journal + meta_files + meta_auditd + meta_bash))
  
  meta_events_json="{\"out\":\"$(escape "$csv_path")\",\"days\":$meta_days,\"max_per_source\":$meta_max,\"total\":$meta_total,\"per_source\":{\"journal\":$meta_journal,\"files\":$meta_files,\"auditd\":$meta_auditd,\"bash_history\":$meta_bash},\"syslog_source\":\"$syslog_source\",\"skipped\":\"$meta_skipped\",\"errors\":[$meta_errors],\"archive\":\"$(escape "$meta_archive")\"}"
  
  if [ $quiet -eq 0 ]; then
      echo "[*] Events: $meta_total -> $csv_path" >&2
  fi
}
"""

    collect_events = collect_events.replace("__AWK_FUNCTIONS__", awk_functions)

    if "collect_events()" in content:
        start_idx = content.find("meta_events_json='{\"skipped\":\"not run\"}'")
        end_idx = content.find("\nif [ $events_only -eq 1 ]; then")
        
        if start_idx != -1 and end_idx != -1:
            content = content[:start_idx] + collect_events + content[end_idx:]
    
    with open("responder/collect_linux.sh", "w", newline="\n") as f:
        f.write(content)

update_bash_script()
