#!/bin/sh

escape() {
  if [ -z "$1" ]; then
    return
  fi
  printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037' | awk '
  BEGIN { ORS="" }
  {
    gsub(/\\/, "\\\\");
    gsub(/"/, "\\\"");
    gsub(/\t/, "\\t");
    gsub(/\r/, "\\r");
    if (NR > 1) print "\\n";
    print $0
  }'
}

if [ "$COLLECT_POSIX_SELFTEST" = "1" ]; then
  escape "$1"
  exit 0
fi


num() {
  if printf "%s\n" "$1" | grep -q '^[0-9][0-9]*$'; then
    echo "$1"
  else
    echo "0"
  fi
}

append_json() {
  local var_name=$1
  local obj=$2
  local current
  eval "current=\$$var_name"
  if [ "$current" = "[]" ]; then
    eval "$var_name='['\$obj']'"
  else
    local inner="${current%]}"
    eval "$var_name=''\$inner', '\$obj']'"
  fi
}

OUT_FILE="-"
QUIET=0
LOG_DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    -o) OUT_FILE="$2"; shift 2;;
    -q) QUIET=1; shift;;
    -L) LOG_DIR="$2"; shift 2;;
    *) shift;;
  esac
done

TMP_DIR=""
cleanup() {
  if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT HUP INT TERM

TMP_DIR=$(mktemp -d 2>/dev/null)
if [ -z "$TMP_DIR" ] || [ ! -d "$TMP_DIR" ]; then
  TMP_DIR="/tmp/collect_posix_$$"
  mkdir -p "$TMP_DIR" 2>/dev/null
fi

errors="[]"
log_error() {
  append_json errors "\"$(escape "$1")\""
}

info_msg() {
  if [ "$QUIET" -eq 0 ]; then
    echo "INFO: $1" >&2
  fi
}

# --- JSON Variables ---
meta="{}"
users="[]"
services="[]"
cron="[]"
autoruns="[]"
ssh_authorized_keys="[]"
listening_ports="[]"
connections="[]"
hosts_file="[]"
suid_files="[]"
processes="[]"
recent_modified="[]"
dns_servers="[]"

# --- 1. Meta ---
info_msg "Collecting meta..."
hostname=$(hostname 2>/dev/null || cat "${COLLECT_POSIX_ROOT}/etc/hostname" 2>/dev/null || echo "unknown")
# For POSIX we can use date -u +%Y-%m-%dT%H:%M:%SZ
collected_at=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "1970-01-01T00:00:00Z")
is_root="false"
if [ "$(id -u 2>/dev/null || echo 1)" = "0" ]; then is_root="true"; fi

distro_id="unknown"
distro_version_id=""
distro_pretty_name=""
if [ -f "${COLLECT_POSIX_ROOT}/etc/os-release" ]; then
  while IFS='=' read -r key val; do
    # Remove quotes
    val=$(echo "$val" | sed 's/^"//;s/"$//;s/^\x27//;s/\x27$//')
    case "$key" in
      ID) distro_id="$val" ;;
      VERSION_ID) distro_version_id="$val" ;;
      PRETTY_NAME) distro_pretty_name="$val" ;;
    esac
  done < "${COLLECT_POSIX_ROOT}/etc/os-release"
fi

caps="[]"
for cmd in ss netstat systemctl rc-status journalctl find awk sed; do
  if command -v "$cmd" >/dev/null 2>&1; then
    append_json caps "\"$(escape "$cmd")\""
  fi
done
find_printf_check=$(find /etc -maxdepth 0 -printf "%p" 2>/dev/null)
if [ -n "$find_printf_check" ]; then append_json caps "\"find_printf\""; fi

meta="{\"os\":\"linux\",\"hostname\":\"$(escape "$hostname")\",\"collected_at\":\"$collected_at\",\"collector_version\":\"posix-1\",\"is_root\":$is_root,\"distro\":{\"ID\":\"$(escape "$distro_id")\",\"VERSION_ID\":\"$(escape "$distro_version_id")\",\"PRETTY_NAME\":\"$(escape "$distro_pretty_name")\"},\"capabilities\":$caps}"

# --- 2. Users ---
info_msg "Collecting users..."
if [ -f "${COLLECT_POSIX_ROOT}/etc/passwd" ]; then
  while IFS=: read -r user pass uid gid gecos home shell; do
    [ -z "$user" ] && continue
    uid_num=$(num "$uid")
    # Simple check if uid is number
    
    
    is_admin="false"
    if [ "$uid_num" = "0" ]; then
      is_admin="true"
    else
      for g in sudo wheel admin; do
        if grep -E "^$g:.*:.*[:,]$user([,:]|$)" "${COLLECT_POSIX_ROOT}/etc/group" >/dev/null 2>&1; then is_admin="true"; break; fi
        if grep -E "^$g:.*:$uid_num$" "${COLLECT_POSIX_ROOT}/etc/group" >/dev/null 2>&1; then is_admin="true"; break; fi
      done
    fi
    
    enabled="true"
    case "$shell" in
      *nologin|*/bin/false) enabled="false" ;;
    esac
    
    groups_json="[]"
    # To get groups in POSIX, id -nG is usually available. If not, use grep on "${COLLECT_POSIX_ROOT}/etc/group"
    grps=$(id -nG "$user" 2>/dev/null)
    if [ -n "$grps" ]; then
      for g in $grps; do
        append_json groups_json "\"$(escape "$g")\""
      done
    fi
    
    append_json users "{\"name\":\"$(escape "$user")\",\"enabled\":$enabled,\"is_admin\":$is_admin,\"uid\":$uid_num,\"shell\":\"$(escape "$shell")\",\"groups\":$groups_json}"
  done < "${COLLECT_POSIX_ROOT}/etc/passwd"
else
  log_error ""${COLLECT_POSIX_ROOT}/etc/passwd" not found"
fi

# --- 3. Services ---
info_msg "Collecting services..."
if command -v systemctl >/dev/null 2>&1; then
  systemctl list-unit-files --type=service --state=enabled 2>/dev/null > "$TMP_DIR/sysctl.out"
  while read -r unit state rest; do
    if [ -n "$unit" ] && [ "$unit" != "UNIT" ] && [ "$unit" != "0" ] && echo "$unit" | grep -q '\.service$'; then
      append_json services "{\"name\":\"$(escape "$unit")\",\"display\":\"$(escape "$unit")\",\"state\":\"$(escape "$state")\",\"start_mode\":\"auto\",\"binary_path\":\"\",\"run_as\":\"\"}"
    fi
  done < "$TMP_DIR/sysctl.out"
elif command -v rc-status >/dev/null 2>&1; then
  rc-status -a 2>/dev/null | awk '/^\[.*\]$/ {runlevel=$1} /^ / {print $1}' > "$TMP_DIR/rc.out"
  while read -r unit; do
    [ -n "$unit" ] && append_json services "{\"name\":\"$(escape "$unit")\",\"display\":\"$(escape "$unit")\",\"state\":\"enabled\",\"start_mode\":\"auto\",\"binary_path\":\"\",\"run_as\":\"\"}"
  done < "$TMP_DIR/rc.out"
elif [ -d "${COLLECT_POSIX_ROOT}/etc/init.d" ]; then
  for f in "${COLLECT_POSIX_ROOT}/etc/init.d"/*; do
    if [ -f "$f" ]; then
      unit=$(basename "$f")
      append_json services "{\"name\":\"$(escape "$unit")\",\"display\":\"$(escape "$unit")\",\"state\":\"enabled\",\"start_mode\":\"auto\",\"binary_path\":\"\",\"run_as\":\"\"}"
    fi
  done
fi

# --- 4. Cron ---
info_msg "Collecting cron..."
if [ -f "${COLLECT_POSIX_ROOT}/etc/passwd" ]; then
  while IFS=: read -r user rest; do
    crontab_out=$(crontab -u "$user" -l 2>/dev/null)
    if [ -n "$crontab_out" ]; then
      echo "$crontab_out" > "$TMP_DIR/cron.out"
      while IFS= read -r line; do
        if ! echo "$line" | grep -q '^#' && [ -n "$line" ]; then
          append_json cron "{\"user\":\"$(escape "$user")\",\"job\":\"$(escape "$line")\"}"
        fi
      done < "$TMP_DIR/cron.out"
    fi
  done < "${COLLECT_POSIX_ROOT}/etc/passwd"
fi

for d in "${COLLECT_POSIX_ROOT}/var/spool/cron/crontabs" "${COLLECT_POSIX_ROOT}/var/spool/cron" "${COLLECT_POSIX_ROOT}/etc/crontabs"; do
  if [ -d "$d" ]; then
    for f in "$d"/*; do
      if [ -f "$f" ]; then
        user=$(basename "$f")
        while IFS= read -r line; do
          if ! echo "$line" | grep -q '^#' && [ -n "$line" ]; then
            append_json cron "{\"user\":\"$(escape "$user")\",\"job\":\"$(escape "$line")\"}"
          fi
        done < "$f"
      fi
    done
  fi
done

for d in "${COLLECT_POSIX_ROOT}/etc/crontab" "${COLLECT_POSIX_ROOT}/etc/cron.d"; do
  if [ -d "$d" ]; then
    for f in "$d"/*; do
      if [ -f "$f" ]; then
        while IFS= read -r line; do
          if ! echo "$line" | grep -q '^#' && [ -n "$line" ] && ! echo "$line" | grep -q '^[A-Za-z_][A-Za-z0-9_]*='; then
            user=$(echo "$line" | awk '{print $6}')
            append_json cron "{\"user\":\"$(escape "$user")\",\"job\":\"$(escape "$line")\"}"
          fi
        done < "$f"
      fi
    done
  elif [ -f "$d" ]; then
    while IFS= read -r line; do
      if ! echo "$line" | grep -q '^#' && [ -n "$line" ] && ! echo "$line" | grep -q '^[A-Za-z_][A-Za-z0-9_]*='; then
        user=$(echo "$line" | awk '{print $6}')
        append_json cron "{\"user\":\"$(escape "$user")\",\"job\":\"$(escape "$line")\"}"
      fi
    done < "$d"
  fi
done

for d in "${COLLECT_POSIX_ROOT}/etc/cron.daily" "${COLLECT_POSIX_ROOT}/etc/cron.hourly" "${COLLECT_POSIX_ROOT}/etc/cron.monthly" "${COLLECT_POSIX_ROOT}/etc/cron.weekly"; do
  if [ -d "$d" ]; then
    for f in "$d"/*; do
      if [ -f "$f" ]; then
        real_f="${f#$COLLECT_POSIX_ROOT}"
        append_json cron "{\"user\":\"root\",\"job\":\"$(escape "$real_f")\"}"
      fi
    done
  fi
done

# --- 5. Autoruns ---
info_msg "Collecting autoruns..."
for f in "${COLLECT_POSIX_ROOT}/etc/rc.local" "${COLLECT_POSIX_ROOT}/etc/rc.d/rc.local" "${COLLECT_POSIX_ROOT}/etc/profile" "${COLLECT_POSIX_ROOT}/etc/bash.bashrc" "${COLLECT_POSIX_ROOT}/etc/environment"; do
  if [ -f "$f" ]; then
    real_f="${f#$COLLECT_POSIX_ROOT}"
        append_json autoruns "{\"location\":\"$(escape "$real_f")\",\"name\":\"file\",\"value\":\"exists\"}"
  fi
done
for d in "${COLLECT_POSIX_ROOT}/etc/profile.d" "${COLLECT_POSIX_ROOT}/etc/local.d"; do
  if [ -d "$d" ]; then
    for f in "$d"/*; do
      if [ -f "$f" ]; then
        real_f="${f#$COLLECT_POSIX_ROOT}"
        append_json autoruns "{\"location\":\"$(escape "$real_f")\",\"name\":\"file\",\"value\":\"exists\"}"
      fi
    done
  fi
done
if [ -d "${COLLECT_POSIX_ROOT}/etc/systemd/system" ]; then
  for f in "${COLLECT_POSIX_ROOT}/etc/systemd/system"/*.service; do
    if [ -f "$f" ]; then
      real_f="${f#$COLLECT_POSIX_ROOT}"
        append_json autoruns "{\"location\":\"$(escape "$real_f")\",\"name\":\"file\",\"value\":\"exists\"}"
    fi
  done
fi

# --- 6. SSH Authorized Keys ---
info_msg "Collecting ssh keys..."
for k in "${COLLECT_POSIX_ROOT}/root/.ssh/authorized_keys"*; do
  if [ -f "$k" ]; then
    real_k="${k#$COLLECT_POSIX_ROOT}"
    while IFS= read -r line; do
      [ -n "$line" ] && append_json ssh_authorized_keys "{\"file\":\"$(escape "$real_k")\",\"key\":\"$(escape "$line")\"}"
    done < "$k"
  fi
done
if [ -d "${COLLECT_POSIX_ROOT}/home" ]; then
  for d in "${COLLECT_POSIX_ROOT}/home"/*; do
    for k in "$d"/.ssh/authorized_keys*; do
      if [ -f "$k" ]; then
        real_k="${k#$COLLECT_POSIX_ROOT}"
        while IFS= read -r line; do
          [ -n "$line" ] && append_json ssh_authorized_keys "{\"file\":\"$(escape "$real_k")\",\"key\":\"$(escape "$line")\"}"
        done < "$k"
      fi
    done
  done
fi

# --- 7. Listening Ports & Connections ---
info_msg "Collecting network..."
parse_hex_ip() {
  local hex=$1
  if [ -z "$hex" ] || [ "${#hex}" -ne 8 ]; then echo "$hex"; return; fi
  awk -v h="$hex" 'BEGIN {
    for(i=1;i<=4;i++) {
      s = substr(h, i*2-1, 2)
      v = (index("0123456789ABCDEF", toupper(substr(s,1,1)))-1)*16 + (index("0123456789ABCDEF", toupper(substr(s,2,1)))-1)
      b[i] = v
    }
    printf "%d.%d.%d.%d", b[4], b[3], b[2], b[1]
  }' 2>/dev/null || echo "$hex"
}
parse_hex_port() {
  awk -v h="$1" 'BEGIN {
    n=0;
    for(i=1;i<=4;i++){
      c=substr(h,i,1);
      v=index("0123456789ABCDEF", toupper(c))-1;
      n=n*16+v;
    }
    print n
  }' 2>/dev/null || echo "$1"
}

if command -v ss >/dev/null 2>&1; then
  ss -tunap 2>/dev/null > "$TMP_DIR/ss.out"
  awk 'NR>1 {print $1, $2, $5, $6, $7}' "$TMP_DIR/ss.out" > "$TMP_DIR/ss.awk"
  while read -r proto state local_addr remote_addr pinfo; do
    [ -z "$proto" ] && continue
    laddr="${local_addr%:*}"
    laddr="$(echo "$laddr" | tr -d '[]')"
    lport="${local_addr##*:}"
    raddr="${remote_addr%:*}"
    raddr="$(echo "$raddr" | tr -d '[]')"
    rport="${remote_addr##*:}"
    pid=""
    pname=""
    if [ -n "$pinfo" ] && [ "$pinfo" != "-" ]; then
      pid=$(echo "$pinfo" | awk -F'pid=' '{print $2}' | cut -d, -f1)
      pname=$(echo "$pinfo" | awk -F'"' '{print $2}')
    fi
    pid=$(num "$pid")
    lport=$(num "$lport")
    rport=$(num "$rport")
    
    if [ "$state" = "LISTEN" ] || [ "$state" = "UNCONN" ]; then
      append_json listening_ports "{\"proto\":\"$(escape "$proto")\",\"addr\":\"$(escape "$laddr")\",\"port\":$lport,\"pid\":$pid,\"process\":\"$(escape "$pname")\"}"
    elif [ "$state" = "ESTAB" ] || [ "$state" = "ESTABLISHED" ]; then
      append_json connections "{\"proto\":\"$(escape "$proto")\",\"local_addr\":\"$(escape "$laddr")\",\"local_port\":$lport,\"remote_addr\":\"$(escape "$raddr")\",\"remote_port\":$rport,\"state\":\"$(escape "$state")\",\"pid\":$pid,\"process\":\"$(escape "$pname")\"}"
    fi
  done < "$TMP_DIR/ss.awk" 
elif command -v netstat >/dev/null 2>&1; then
  netstat -tunap 2>/dev/null > "$TMP_DIR/netstat.out"
  awk 'NR>2 {print $0}' "$TMP_DIR/netstat.out" > "$TMP_DIR/netstat.awk"
  while read -r proto q1 q2 local_addr remote_addr p5 p6 p7; do
    [ -z "$proto" ] && continue
    if [ "$proto" = "Proto" ] || [ "$proto" = "Active" ]; then continue; fi
    if echo "$proto" | grep -q '^udp'; then
      state="UNCONN"
      pinfo="$p5"
    else
      state="$p5"
      pinfo="$p6"
    fi
    laddr="${local_addr%:*}"
    laddr="$(echo "$laddr" | tr -d '[]')"
    lport="${local_addr##*:}"
    raddr="${remote_addr%:*}"
    raddr="$(echo "$raddr" | tr -d '[]')"
    rport="${remote_addr##*:}"
    pid=""
    pname=""
    if [ -n "$pinfo" ] && [ "$pinfo" != "-" ]; then
      pid=$(echo "$pinfo" | cut -d/ -f1)
      pname=$(echo "$pinfo" | cut -d/ -f2)
    fi
    pid=$(num "$pid")
    lport=$(num "$lport")
    rport=$(num "$rport")
    
    if [ "$state" = "LISTEN" ] || [ "$state" = "UNCONN" ]; then
      append_json listening_ports "{\"proto\":\"$(escape "$proto")\",\"addr\":\"$(escape "$laddr")\",\"port\":$lport,\"pid\":$pid,\"process\":\"$(escape "$pname")\"}"
    elif [ "$state" = "ESTABLISHED" ]; then
      append_json connections "{\"proto\":\"$(escape "$proto")\",\"local_addr\":\"$(escape "$laddr")\",\"local_port\":$lport,\"remote_addr\":\"$(escape "$raddr")\",\"remote_port\":$rport,\"state\":\"$(escape "$state")\",\"pid\":$pid,\"process\":\"$(escape "$pname")\"}"
    fi
  done < "$TMP_DIR/netstat.awk" 
else
  # /proc/net fallback
  find_pid_by_inode() {
    local inode=$1
    if [ -z "$inode" ] || [ "$inode" = "0" ]; then echo 0; return; fi
    find /proc/[0-9]*/fd -type l -exec ls -l {} + 2>/dev/null | awk -v inod="socket:[$inode]" 'index($0, inod) > 0 {split($9, a, "/"); print a[3]; exit}' || echo 0
  }
  for proto in tcp tcp6 udp; do
    if [ -f "/proc/net/$proto" ]; then
      awk 'NR>1 {print $2, $3, $4, $10}' "/proc/net/$proto" > "$TMP_DIR/proc_$proto.out"
      while read -r l_hex r_hex state inode; do
        l_ip="${l_hex%:*}"
        l_pt="${l_hex##*:}"
        r_ip="${r_hex%:*}"
        r_pt="${r_hex##*:}"
        
        laddr=$(parse_hex_ip "$l_ip")
        lport=$(parse_hex_port "$l_pt")
        raddr=$(parse_hex_ip "$r_ip")
        rport=$(parse_hex_port "$r_pt")
        laddr="$(echo "$laddr" | tr -d '[]')"
        raddr="$(echo "$raddr" | tr -d '[]')"
        pid=$(find_pid_by_inode "$inode")
        pid=$(num "$pid")
        lport=$(num "$lport")
        rport=$(num "$rport")
        
        pr="tcp"
        if [ "$proto" = "udp" ]; then pr="udp"; fi
        
        if [ "$state" = "0A" ] || ( [ "$proto" = "udp" ] && [ "$state" = "07" ] ); then
          append_json listening_ports "{\"proto\":\"$pr\",\"addr\":\"$(escape "$laddr")\",\"port\":$lport,\"pid\":$pid,\"process\":\"\"}"
        elif [ "$state" = "01" ]; then
          append_json connections "{\"proto\":\"$pr\",\"local_addr\":\"$(escape "$laddr")\",\"local_port\":$lport,\"remote_addr\":\"$(escape "$raddr")\",\"remote_port\":$rport,\"state\":\"ESTABLISHED\",\"pid\":$pid,\"process\":\"\"}"
        fi
      done < "$TMP_DIR/proc_$proto.out"
    fi
  done
fi

# --- 8. Hosts ---
info_msg "Collecting hosts..."
if [ -f "${COLLECT_POSIX_ROOT}/etc/hosts" ]; then
  while read -r line; do
    if ! echo "$line" | grep -q '^#'; then
      [ -n "$line" ] && append_json hosts_file "\"$(escape "$line")\""
    fi
  done < "${COLLECT_POSIX_ROOT}/etc/hosts"
fi

# --- 9. SUID Files ---
info_msg "Collecting suid..."
suid_dir="/"
[ -n "$COLLECT_POSIX_ROOT" ] && suid_dir="$COLLECT_POSIX_ROOT"
# buyruqni satrga yig'ib $cmd qilib yurgizish qo'shtirnoqni argumentga qo'shib yuboradi -- to'g'ridan-to'g'ri chaqiriladi
# eski BusyBox (<1.30) da "timeout 60" ishlamaydi ("-t 60" kerak), shuning uchun avval sinab ko'riladi
if timeout 1 true >/dev/null 2>&1; then
  timeout 60 find "$suid_dir" -xdev -type f -perm -4000 2>/dev/null > "$TMP_DIR/suid.out"
else
  find "$suid_dir" -xdev -type f -perm -4000 2>/dev/null > "$TMP_DIR/suid.out"
fi
while read -r p; do
  if [ -n "$p" ]; then
    real_p="${p#$COLLECT_POSIX_ROOT}"
    [ -z "$real_p" ] && real_p="/"
    append_json suid_files "{\"path\":\"$(escape "$real_p")\"}"
  fi
done < "$TMP_DIR/suid.out" 

# --- 10. Processes ---
info_msg "Collecting processes..."
if [ -d /proc ]; then
  for pdir in /proc/[0-9]*; do
    if [ -d "$pdir" ]; then
      pid="${pdir#/proc/}"
      cmdline=$(head -c 1000 "$pdir/cmdline" 2>/dev/null | tr '\0' ' ')
      path=""
      if command -v readlink >/dev/null 2>&1; then path=$(readlink "$pdir/exe" 2>/dev/null); else path=$(ls -l "$pdir/exe" 2>/dev/null | awk '{print $NF}'); fi
      
      if [ -z "$cmdline" ] && [ -z "$path" ]; then continue; fi
      
      name=$(cat "$pdir/comm" 2>/dev/null)
      ppid=0
      stat_file=$(cat "$pdir/stat" 2>/dev/null)
      if [ -n "$stat_file" ]; then
        ppid=$(echo "$stat_file" | awk -F') ' '{print $2}' | awk '{print $2}')
        [ -z "$ppid" ] && ppid=0
      fi
      
      exe_deleted="false"
      case "$path" in
        *" (deleted)")
          path="${path% (deleted)}"
          exe_deleted="true"
          ;;
      esac
      
      user=""
      if command -v stat >/dev/null 2>&1; then
        user=$(stat -c %U "$pdir" 2>/dev/null)
      else
        user=$(ls -ld "$pdir" 2>/dev/null | awk '{print $3}')
      fi
      
      sha256=""
      # Omit hashing to save time since bash version only hashes some files, and POSIX can skip it or just set empty
      
      pid=$(num "$pid")
      ppid=$(num "$ppid")
      append_json processes "{\"pid\":$pid,\"ppid\":$ppid,\"name\":\"$(escape "$name")\",\"path\":\"$(escape "$path")\",\"cmdline\":\"$(escape "$cmdline")\",\"user\":\"$(escape "$user")\",\"start_time\":\"\",\"signed\":\"n/a\",\"sha256\":\"\",\"exe_deleted\":$exe_deleted}"
    fi
  done
fi

# --- 11. Recent Modified ---
info_msg "Collecting recent modified..."
recent_cmd="find ${COLLECT_POSIX_ROOT}/tmp ${COLLECT_POSIX_ROOT}/var/tmp ${COLLECT_POSIX_ROOT}/dev/shm ${COLLECT_POSIX_ROOT}/etc ${COLLECT_POSIX_ROOT}/var/www ${COLLECT_POSIX_ROOT}/root ${COLLECT_POSIX_ROOT}/home -maxdepth 5 -type f -mtime -7"
if timeout 1 true >/dev/null 2>&1; then
  recent_cmd="timeout 30 $recent_cmd"
fi
count=0
$recent_cmd 2>/dev/null > "$TMP_DIR/recent.out"
while read -r p; do
  [ $count -ge 500 ] && break
  if [ -n "$p" ]; then
    size=0
    mtime=""
    if command -v stat >/dev/null 2>&1; then
      size=$(stat -c %s "$p" 2>/dev/null || echo 0)
      mtime=$(stat -c %Y "$p" 2>/dev/null || echo "")
    else
      size=$(ls -l "$p" 2>/dev/null | awk '{print $5}' || echo 0)
    fi
    size=$(num "$size")
    real_p="${p#$COLLECT_POSIX_ROOT}"
    [ -z "$real_p" ] && real_p="/"
    append_json recent_modified "{\"path\":\"$(escape "$real_p")\",\"size\":$size,\"mtime\":\"$(escape "$mtime")\"}"
    count=$((count+1))
  fi
done < "$TMP_DIR/recent.out" 

# --- 12. DNS Servers ---
info_msg "Collecting dns..."
if [ -f "${COLLECT_POSIX_ROOT}/etc/resolv.conf" ]; then
  awk '/^nameserver/ {print $2}' "${COLLECT_POSIX_ROOT}/etc/resolv.conf" 2>/dev/null > "$TMP_DIR/resolv.out"
  while read -r ns; do
    [ -n "$ns" ] && append_json dns_servers "{\"interface\":\"resolv.conf\",\"addresses\":\"$(escape "$ns")\"}"
  done < "$TMP_DIR/resolv.out"
fi

# --- Log Copy ---
if [ -n "$LOG_DIR" ] && [ -d "$LOG_DIR" ]; then
  info_msg "Copying logs to $LOG_DIR..."
  for lf in "${COLLECT_POSIX_ROOT}/var/log/auth.log" "${COLLECT_POSIX_ROOT}/var/log/secure" "${COLLECT_POSIX_ROOT}/var/log/messages" "${COLLECT_POSIX_ROOT}/var/log/syslog" "${COLLECT_POSIX_ROOT}/var/log/audit/audit.log" "${COLLECT_POSIX_ROOT}/var/log/nginx/access.log" "${COLLECT_POSIX_ROOT}/var/log/apache2/access.log" "${COLLECT_POSIX_ROOT}/var/log/httpd/access_log"; do
    if [ -f "$lf" ]; then
      bname=$(basename "$lf")
      tail -n 20000 "$lf" > "$LOG_DIR/$bname" 2>/dev/null
    fi
  done
  for hf in "${COLLECT_POSIX_ROOT}/root/.ash_history" "${COLLECT_POSIX_ROOT}/root/.bash_history"; do
    if [ -f "$hf" ]; then
      bname=$(basename "$hf")
      tail -n 20000 "$hf" > "$LOG_DIR/history_root_$bname" 2>/dev/null
    fi
  done
  if [ -d "${COLLECT_POSIX_ROOT}/home" ]; then
    for hd in "${COLLECT_POSIX_ROOT}/home"/*; do
      if [ -d "$hd" ]; then
        u=$(basename "$hd")
        for hf in "$hd"/.ash_history "$hd"/.bash_history; do
          if [ -f "$hf" ]; then
            bname=$(basename "$hf")
            tail -n 20000 "$hf" > "$LOG_DIR/history_${u}_${bname}" 2>/dev/null
          fi
        done
      fi
    done
  fi
fi

# --- Final JSON Output ---
info_msg "Writing JSON..."
if [ "$OUT_FILE" = "-" ]; then
  exec 3>&1
else
  exec 3> "$OUT_FILE"
fi

cat >&3 <<EOF
{
  "meta": $meta,
  "users": $users,
  "services": $services,
  "tasks": [],
  "cron": $cron,
  "autoruns": $autoruns,
  "wmi_subscriptions": [],
  "ssh_authorized_keys": $ssh_authorized_keys,
  "listening_ports": $listening_ports,
  "connections": $connections,
  "hosts_file": $hosts_file,
  "suid_files": $suid_files,
  "startup_items": [],
  "remote_access_tools": [],
  "defender": {},
  "recent_modified": $recent_modified,
  "packages_modified": [],
  "proxy": {},
  "dns_servers": $dns_servers,
  "root_cas": [],
  "portproxy": [],
  "firewall_profiles": [],
  "packages": [],
  "installed_apps": [],
  "containers": [],
  "processes": $processes,
  "errors": $errors
}
EOF

# Clean up done by trap
exit 0
