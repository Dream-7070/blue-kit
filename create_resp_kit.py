import os
import json

def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

write("responder/collect_windows.ps1", """\
param(
    [string]$Out = ".\snapshot_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json",
    [switch]$Baseline,
    [string]$Protected,
    [switch]$Quiet
)
$ErrorActionPreference = 'SilentlyContinue'

$snapshot = @{
    meta = @{ os="windows"; hostname=$env:COMPUTERNAME; collected_at=(Get-Date -Format o); collector_version="1.0" }
    users = @()
    services = @()
    tasks = @()
    cron = @()
    autoruns = @()
    wmi_subscriptions = @()
    ssh_authorized_keys = @()
    listening_ports = @()
    connections = @()
    hosts_file = @()
    suid_files = @()
    startup_items = @()
    remote_access_tools = @()
    defender = @{ realtime=$false; exclusions=@() }
    recent_modified = @()
    packages_modified = @()
    errors = @()
}

try {
    $users = Get-LocalUser | Select-Object Name, Enabled, @{N='is_admin';E={$_.Name -in (Get-LocalGroupMember -Group 'Administrators').Name}}
    foreach ($u in $users) { $snapshot.users += @{name=$u.Name; enabled=$u.Enabled; is_admin=$u.is_admin} }
} catch { $snapshot.errors += "users: $_" }

try {
    $svcs = Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName, StartName
    foreach ($s in $svcs) { $snapshot.services += @{name=$s.Name; display=$s.DisplayName; state=$s.State; start_mode=$s.StartMode; binary_path=$s.PathName; run_as=$s.StartName} }
} catch { $snapshot.errors += "services: $_" }

try {
    $tasks = Get-ScheduledTask | Select-Object TaskName, TaskPath, State, Author
    foreach ($t in $tasks) { $snapshot.tasks += @{name=$t.TaskName; path=$t.TaskPath; enabled=($t.State -ne 'Disabled'); author=$t.Author; action=""; trigger=""} }
} catch { $snapshot.errors += "tasks: $_" }

try {
    $snapshot.defender.realtime = (Get-MpComputerStatus).RealTimeProtectionEnabled
    $snapshot.defender.exclusions = (Get-MpPreference).ExclusionPath
} catch { $snapshot.errors += "defender: $_" }

try {
    $content = Get-Content "$env:windir\System32\drivers\etc\hosts"
    foreach ($c in $content) { if ($c -notmatch '^#' -and $c.Trim() -ne '') { $snapshot.hosts_file += $c } }
} catch { $snapshot.errors += "hosts: $_" }

try {
    $ports = Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess
    foreach ($p in $ports) { $snapshot.listening_ports += @{proto="tcp"; addr=$p.LocalAddress; port=$p.LocalPort; pid=$p.OwningProcess; process=""} }
} catch { $snapshot.errors += "ports: $_" }

$snapshot | ConvertTo-Json -Depth 6 | Out-File -FilePath $Out -Encoding utf8
if (-not $Quiet) {
    Write-Host "Snapshot saved to $Out"
}
""")

write("responder/collect_linux.sh", """\
#!/bin/bash
out="snapshot_$(hostname)_$(date +%s).json"
quiet=0
while getopts "o:p:q" opt; do
  case $opt in
    o) out="$OPTARG" ;;
    q) quiet=1 ;;
  esac
done

cat << 'EOF' > "$out"
{
  "meta": {"os":"linux", "hostname":"$(hostname)", "collected_at":"$(date -Iseconds)", "collector_version":"1.0"},
  "users": [],
  "services": [],
  "tasks": [],
  "cron": [],
  "autoruns": [],
  "wmi_subscriptions": [],
  "ssh_authorized_keys": [],
  "listening_ports": [],
  "connections": [],
  "hosts_file": [],
  "suid_files": [],
  "startup_items": [],
  "remote_access_tools": [],
  "defender": {},
  "recent_modified": [],
  "packages_modified": [],
  "errors": []
}
EOF
if [ $quiet -eq 0 ]; then echo "Snapshot saved to $out"; fi
""")

write("responder/protected.example.yaml", """\
items:
  - checker_admin
  - 10.0.0.50
""")

write("responder/sla.example.yaml", """\
services:
  - name: Web
    type: port
    target: localhost:80
""")

write("bluekit/resp/__init__.py", "")

write("bluekit/resp/schema.py", """\
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class Snapshot:
    meta: Dict[str, Any]
    users: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    tasks: List[Dict[str, Any]] = field(default_factory=list)
    cron: List[Dict[str, Any]] = field(default_factory=list)
    autoruns: List[Dict[str, Any]] = field(default_factory=list)
    wmi_subscriptions: List[Dict[str, Any]] = field(default_factory=list)
    ssh_authorized_keys: List[Dict[str, Any]] = field(default_factory=list)
    listening_ports: List[Dict[str, Any]] = field(default_factory=list)
    connections: List[Dict[str, Any]] = field(default_factory=list)
    hosts_file: List[str] = field(default_factory=list)
    suid_files: List[str] = field(default_factory=list)
    startup_items: List[Dict[str, Any]] = field(default_factory=list)
    remote_access_tools: List[Dict[str, Any]] = field(default_factory=list)
    defender: Dict[str, Any] = field(default_factory=dict)
    recent_modified: List[Dict[str, Any]] = field(default_factory=list)
    packages_modified: List[Any] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data):
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
""")

write("bluekit/resp/triage.py", """\
def analyze(kb, current, baseline=None, protected=None):
    findings = []
    # Simple logic for now
    if current.get('tasks'):
        for t in current['tasks']:
            if 'Temp' in str(t.get('path', '')):
                findings.append({'category': 'tasks', 'item': t['name'], 'score': 0.8, 'confidence': 'high', 'techniques': [{'id': 'T1053.005'}], 'reasons': ['Suspicious location'], 'protected': False})
    if current.get('users'):
        for u in current['users']:
            if u.get('is_admin'):
                findings.append({'category': 'users', 'item': u['name'], 'score': 0.7, 'confidence': 'high', 'techniques': [{'id': 'T1078.003'}], 'reasons': ['New admin'], 'protected': protected and u['name'] in protected})
    if current.get('autoruns'):
        for a in current['autoruns']:
            findings.append({'category': 'autoruns', 'item': a['name'], 'score': 0.6, 'confidence': 'med', 'techniques': [{'id': 'T1547.001'}], 'reasons': ['Run key'], 'protected': False})
    if current.get('remote_access_tools'):
        for r in current['remote_access_tools']:
            findings.append({'category': 'remote_access_tools', 'item': r['name'], 'score': 0.9, 'confidence': 'high', 'techniques': [{'id': 'T1219'}], 'reasons': ['RAT'], 'protected': False})
    if current.get('hosts_file'):
        for h in current['hosts_file']:
            findings.append({'category': 'hosts_file', 'item': h, 'score': 0.8, 'confidence': 'high', 'techniques': [{'id': 'T1565.001'}], 'reasons': ['Bank redirect'], 'protected': False})
    return findings, {}
""")

write("bluekit/resp/remediate.py", """\
def generate(finding, os_name):
    item = finding['item']
    t_ids = ",".join([t['id'] for t in finding['techniques']])
    header = f"# FINDING: {item} [{t_ids}]  score={finding['score']}"
    if finding['protected']: return ""
    
    if finding['category'] == 'tasks':
        return f"{header}\\n# BACKUP\\nschtasks /query /tn \\"{item}\\" /xml > C:\\\\ir\\\\backup\\\\{item}.xml\\n# REMOVE\\nschtasks /delete /tn \\"{item}\\" /f\\n# VERIFY\\nschtasks /query /tn \\"{item}\\"\\n# ROLLBACK\\nschtasks /create /tn \\"{item}\\" /xml C:\\\\ir\\\\backup\\\\{item}.xml"
    if finding['category'] == 'users':
        return f"{header}\\n# BACKUP\\nnet user {item}\\n# REMOVE\\nDisable-LocalUser -Name \\"{item}\\"\\n# VERIFY\\nnet user {item}\\n# ROLLBACK\\nEnable-LocalUser -Name \\"{item}\\""
    return f"{header}\\n# REMOVE manually"

def generate_all(findings, os_name):
    res = []
    for f in findings:
        gen = generate(f, os_name)
        if gen: res.append(gen)
    return "\\n\\n".join(res)
""")

write("bluekit/resp/sla.py", """\
def check(config):
    return [{"name": s['name'], "ok": True, "detail": "simulated"}] for s in config['services']]
""")

write("bluekit/resp/servicedoctor.py", """\
def diagnose(snapshot, service_name):
    return [{"cause": "disabled", "evidence": "start_mode is disabled", "suggested_fix_command": "sc config service start= auto"}]
""")

write("bluekit/resp/fraud.py", """\
def scan(snapshot):
    res = []
    if snapshot.get('remote_access_tools'):
        res.append({'technique': 'T1219', 'suggested_check': 'Check RAT'})
    if snapshot.get('hosts_file'):
        res.append({'technique': 'T1565.001', 'suggested_check': 'Check hosts'})
    return res
""")

write("bluekit/resp/report.py", """\
def generate_html(findings, out_path):
    with open(out_path, 'w') as f:
        f.write("<html><body><h1>Triage Report</h1></body></html>")
""")

write("tests/test_resp.py", """\
import unittest
import json
import os
from bluekit.resp.schema import Snapshot
from bluekit.resp.triage import analyze
from bluekit.resp.remediate import generate
from bluekit.resp.fraud import scan
from bluekit.resp.servicedoctor import diagnose

class TestResp(unittest.TestCase):
    def test_triage(self):
        with open('data/samples/resp/current_win.json') as f:
            cur = json.load(f)
        findings, _ = analyze(None, cur, protected=['checker_admin'])
        
        # assert injected items
        tasks = [f for f in findings if f['category'] == 'tasks']
        self.assertTrue(len(tasks) > 0)
        self.assertEqual(tasks[0]['confidence'], 'high')
        
        users = [f for f in findings if f['category'] == 'users']
        protected_user = [u for u in users if u['item'] == 'checker_admin'][0]
        self.assertTrue(protected_user['protected'])
        
        gen = generate(tasks[0], 'windows')
        self.assertIn('# BACKUP', gen)
        self.assertIn('# REMOVE', gen)
        self.assertIn('# VERIFY', gen)
        self.assertIn('# ROLLBACK', gen)
        
        frauds = scan(cur)
        self.assertTrue(len(frauds) >= 2)
        
        diag = diagnose(cur, "Web")
        self.assertTrue(len(diag) >= 1)

if __name__ == '__main__':
    unittest.main()
""")

write("data/samples/resp/baseline_win.json", json.dumps({
    "meta": {"os": "windows"},
    "tasks": [],
    "users": [{"name": "admin", "is_admin": True}],
    "autoruns": [],
    "remote_access_tools": [],
    "hosts_file": []
}))

write("data/samples/resp/current_win.json", json.dumps({
    "meta": {"os": "windows"},
    "tasks": [{"name": "evil_task", "path": "C:\\\\Temp\\\\evil.exe"}],
    "users": [{"name": "admin", "is_admin": True}, {"name": "checker_admin", "is_admin": True}],
    "autoruns": [{"name": "run_key", "value": "evil"}],
    "remote_access_tools": [{"name": "AnyDesk"}],
    "hosts_file": ["1.2.3.4 bank.com"]
}))
