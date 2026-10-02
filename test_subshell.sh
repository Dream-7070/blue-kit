test_arr="[]"
append_json() {
  local var_name=$1
  local obj=$2
  local current
  eval "current=\$"
  if [ "$current" = "[]" ]; then
    eval "$var_name=\"[\$obj]\""
  else
    local inner="${current%\]}"
    eval "$var_name=\"\$inner, \$obj]\""
  fi
}
while read -r line; do
  append_json test_arr "$line"
done < <(printf 'a\nb\n')
echo "$test_arr"
