<#
.SYNOPSIS
Windows Responder Collector

.DESCRIPTION
Usage:
  powershell -ExecutionPolicy Bypass -File collect_windows.ps1
  Invoke-Command -ComputerName target -FilePath collect_windows.ps1 > snap.json
  Linux ssh-pipe: ssh user@host 'bash -s' < collect_linux.sh > snap.json
#>
param(
    [string]$Out = "-",
    [switch]$Baseline,
    [string]$Protected,
    [switch]$Quiet
)
$ErrorActionPreference = 'SilentlyContinue'

if (-not $Quiet) {
    [Console]::Error.WriteLine("[*] Collecting Windows snapshot...")
}

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
    $tasks = Get-ScheduledTask | Select-Object TaskName, TaskPath, State, Author, Actions, Triggers
    foreach ($t in $tasks) { 
        $action = ""
        if ($t.Actions) {
            $acts = @()
            foreach ($a in $t.Actions) {
                if ($a.Execute) { $acts += "$($a.Execute) $($a.Arguments)".Trim() }
            }
            $action = $acts -join "; "
        }
        $trigger = ""
        if ($t.Triggers) {
            $trigger = ($t.Triggers | ForEach-Object { if ($_.CimClass) { $_.CimClass.CimClassName } else { $_.GetType().Name } }) -join "; "
        }
        $snapshot.tasks += @{name=$t.TaskName; path=$t.TaskPath; enabled=($t.State -ne 'Disabled'); author=$t.Author; action=$action; trigger=$trigger} 
    }
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
    foreach ($p in $ports) { 
        $procName = ""
        if ($p.OwningProcess) {
            $proc = Get-Process -Id $p.OwningProcess -ErrorAction SilentlyContinue
            if ($proc) { $procName = $proc.Name }
        }
        $snapshot.listening_ports += @{proto="tcp"; addr=$p.LocalAddress; port=$p.LocalPort; pid=$p.OwningProcess; process=$procName} 
    }
} catch { $snapshot.errors += "ports: $_" }

try {
    $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
    foreach ($c in $conns) {
        $procName = ""
        if ($c.OwningProcess) {
            $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
            if ($proc) { $procName = $proc.Name }
        }
        $snapshot.connections += @{proto="tcp"; laddr=$c.LocalAddress; lport=$c.LocalPort; raddr=$c.RemoteAddress; rport=$c.RemotePort; pid=$c.OwningProcess; process=$procName}
    }
} catch { $snapshot.errors += "connections: $_" }

try {
    $keys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($k in $keys) {
        if (Test-Path $k) {
            $item = Get-Item $k -ErrorAction SilentlyContinue
            if ($item) {
                foreach ($val in $item.Property) {
                    $valData = (Get-ItemProperty -Path $k -Name $val -ErrorAction SilentlyContinue).$val
                    $snapshot.autoruns += @{location=$k; name=$val; value=$valData}
                }
            }
        }
    }
} catch { $snapshot.errors += "autoruns: $_" }

try {
    $paths = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($p in $paths) {
        if (Test-Path $p) {
            Get-ChildItem $p -File -ErrorAction SilentlyContinue | ForEach-Object {
                $snapshot.startup_items += @{location=$p; name=$_.Name; path=$_.FullName}
            }
        }
    }
} catch { $snapshot.errors += "startup_items: $_" }

try {
    $filters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
    $consumers = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue
    $bindings = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
    
    foreach ($b in $bindings) {
        $filterPath = $b.Filter
        $consumerPath = $b.Consumer
        
        $f = $filters | Where-Object { $_.__RELPATH -eq $filterPath }
        $c = $consumers | Where-Object { $_.__RELPATH -eq $consumerPath }
        
        $q = if ($f) { $f.Query } else { $filterPath }
        $cons = if ($c) { "$($c.CommandLineTemplate) $($c.ExecutablePath)".Trim() } else { $consumerPath }
        $name = if ($f) { $f.Name } else { "Unknown" }
        
        $snapshot.wmi_subscriptions += @{name=$name; query=$q; consumer=$cons}
    }
} catch { $snapshot.errors += "wmi_subscriptions: $_" }

try {
    $rats = @()
    $pattern = "(?i)(anydesk|teamviewer|rutserv|rfusclient|ammyy|rustdesk|screenconnect|connectwise|aeroadmin|radmin|litemanager|ngrok)"
    
    foreach ($s in $snapshot.services) {
        if ($s.name -match $pattern -or $s.binary_path -match $pattern) {
            $rats += @{name=$s.name; evidence="service: $($s.binary_path)"}
        }
    }
    
    $procs = Get-Process | Select-Object Name, Path -ErrorAction SilentlyContinue
    foreach ($p in $procs) {
        if ($p.Name -match $pattern -or $p.Path -match $pattern) {
            $rats += @{name=$p.Name; evidence="process: $($p.Path)"}
        }
    }
    
    foreach ($r in $rats | Sort-Object -Property name,evidence -Unique) {
        $snapshot.remote_access_tools += $r
    }
} catch { $snapshot.errors += "remote_access_tools: $_" }

try {
    $limitTime = (Get-Date).AddDays(-2)
    $recentFiles = @()
    $searchPaths = @(
        "$env:windir\Temp",
        "$env:TEMP",
        "$env:AppData",
        "$env:ProgramData"
    )
    foreach ($sp in $searchPaths) {
        if (Test-Path $sp) {
            $files = Get-ChildItem -Path $sp -Recurse -File -ErrorAction SilentlyContinue | 
                     Where-Object { $_.LastWriteTime -ge $limitTime } | 
                     Select-Object -First 125
            foreach ($f in $files) {
                $recentFiles += @{path=$f.FullName; mtime=$f.LastWriteTime.ToString("o")}
            }
        }
    }
    $snapshot.recent_modified = $recentFiles
} catch { $snapshot.errors += "recent_modified: $_" }

$json = $snapshot | ConvertTo-Json -Depth 6

if (-not $Quiet) {
    [Console]::Error.WriteLine("users=$($snapshot.users.Count) services=$($snapshot.services.Count) tasks=$($snapshot.tasks.Count) autoruns=$($snapshot.autoruns.Count) rats=$($snapshot.remote_access_tools.Count)")
}

if ($Out -eq "-") {
    Write-Output $json
    if (-not $Quiet) {
        [Console]::Error.WriteLine("Snapshot JSON printed to STDOUT")
    }
} else {
    $json | Out-File -FilePath $Out -Encoding utf8
    if (-not $Quiet) {
        [Console]::Error.WriteLine("Snapshot saved to $Out")
    }
}
