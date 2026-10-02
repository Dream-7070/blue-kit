#!/bin/bash
# USAGE: bash collect_linux.sh [-o out.json] [-q]
# Remote/piped execution: ssh user@host 'bash -s' < collect_linux.sh > snap.json

out="-"
quiet=0
while getopts "o:q" opt; do
  case $opt in
    o) out="$OPTARG" ;;
    q) quiet=1 ;;
  esac
done

if [ $quiet -eq 0 ]; then
  echo "[*] Collecting Linux snapshot..." >&2
fi

escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

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
  is_root="false"
  if [ "$uid" -eq 0 ]; then is_root="true"; fi
  append_json users "{\"name\":\"$(escape "$user")\",\"enabled\":true,\"is_admin\":$is_root,\"uid\":$uid,\"shell\":\"$(escape "$shell")\"}"
done < /etc/passwd

if command -v systemctl >/dev/null 2>&1; then
  systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | while read -r unit state rest; do
    [ -n "$unit" ] && append_json services "{\"name\":\"$(escape "$unit")\",\"display\":\"$(escape "$unit")\",\"state\":\"$(escape "$state")\",\"start_mode\":\"auto\",\"binary_path\":\"\",\"run_as\":\"\"}"
  done
fi

for u in $(cut -f1 -d: /etc/passwd); do
  if crontab -u "$u" -l >/dev/null 2>&1; then
    crontab -u "$u" -l 2>/dev/null | grep -v '^#' | while read -r line; do
      [ -z "$line" ] && continue
      append_json cron "{\"user\":\"$(escape "$u")\",\"job\":\"$(escape "$line")\"}"
    done
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
  systemctl list-timers --all --no-legend 2>/dev/null | while read -r next left last passed unit activ rest; do
    [ -n "$unit" ] && append_json tasks "{\"name\":\"$(escape "$unit")\",\"path\":\"/etc/systemd/system\",\"enabled\":true,\"author\":\"system\",\"action\":\"\",\"trigger\":\"$(escape "$next")\"}"
  done
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

if command -v ss >/dev/null 2>&1; then
  ss -tlnp 2>/dev/null | tail -n +2 | while read -r state recv send local peer process rest; do
    proc_name=$(echo "$process" | grep -o 'users:(("[^"]*' | cut -d'"' -f3 | head -n1)
    [ -z "$proc_name" ] && proc_name=$(echo "$process" | grep -oP '(?<=pid=)\d+' | head -n1)
    append_json listening_ports "{\"proto\":\"tcp\",\"addr\":\"$(escape "$local")\",\"port\":0,\"pid\":0,\"process\":\"$(escape "$proc_name")\"}"
  done
  ss -tnp state established 2>/dev/null | tail -n +2 | while read -r recv send local peer process rest; do
    proc_name=$(echo "$process" | grep -o 'users:(("[^"]*' | cut -d'"' -f3 | head -n1)
    append_json connections "{\"proto\":\"tcp\",\"laddr\":\"$(escape "$local")\",\"lport\":0,\"raddr\":\"$(escape "$peer")\",\"rport\":0,\"pid\":0,\"process\":\"$(escape "$proc_name")\"}"
  done
fi

if [ -f /etc/hosts ]; then
  while read -r line; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    append_json hosts_file "\"$(escape "$line")\""
  done < /etc/hosts
fi

timeout 10 find / -xdev -type f -perm -4000 2>/dev/null | head -n 100 | while read -r f; do
  append_json suid_files "{\"path\":\"$(escape "$f")\"}"
done

ps -eo comm,args 2>/dev/null | grep -iE 'anydesk|teamviewer|rutserv|rfusclient|ammyy|rustdesk|screenconnect|connectwise|aeroadmin|radmin|litemanager|ngrok' | grep -v grep | while read -r comm args; do
  append_json remote_access_tools "{\"name\":\"$(escape "$comm")\",\"evidence\":\"process\"}"
done

timeout 10 find /tmp /dev/shm /var/tmp /var/www -type f -mtime -2 2>/dev/null | head -n 125 | while read -r f; do
  append_json recent_modified "{\"path\":\"$(escape "$f")\",\"mtime\":\"recent\"}"
done

if [ $quiet -eq 0 ]; then
  echo "users=$(echo "$users" | grep -o '{' | wc -l) services=$(echo "$services" | grep -o '{' | wc -l) tasks=$(echo "$tasks" | grep -o '{' | wc -l) autoruns=$(echo "$autoruns" | grep -o '{' | wc -l) rats=$(echo "$remote_access_tools" | grep -o '{' | wc -l)" >&2
fi

JSON_PAYLOAD=$(cat << EOF
{
  "meta": {"os":"linux", "hostname":"$(escape "$(hostname 2>/dev/null || echo "unknown")")", "collected_at":"$(date -Iseconds)", "collector_version":"1.0"},
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
  "defender": {"realtime":false,"exclusions":[]},
  "recent_modified": $recent_modified,
  "packages_modified": [],
  "errors": []
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
