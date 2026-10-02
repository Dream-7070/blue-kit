<#
.SYNOPSIS
Windows Responder Collector

.DESCRIPTION
Usage:
  powershell -ExecutionPolicy Bypass -File collect_windows.ps1
  Invoke-Command -ComputerName target -FilePath collect_windows.ps1 > snap.json
  Linux ssh-pipe: ssh user@host 'bash -s' < collect_linux.sh > snap.json
  -EventsDays 7 -EventsMax 10000 -EventsOut x.csv -NoEvents (event log CSV)
#>
param(
    [string]$Out = "-",
    [switch]$Baseline,
    [string]$Protected,
    [switch]$Quiet,
    [switch]$NoDeep,
    [int]$DaysBack = 30,
    [int]$DeepTimeoutSec = 90,
    [string]$EventsOut = "",
    [int]$EventsDays = 7,
    [int]$EventsMax = 10000,
    [switch]$NoEvents
)
$ErrorActionPreference = 'SilentlyContinue'

if (-not $Quiet) {
    [Console]::Error.WriteLine("[*] Collecting Windows snapshot...")
}

$snapshot = @{
    meta = @{ os="windows"; hostname=$env:COMPUTERNAME; collected_at=(Get-Date -Format o); collector_version="1.1"; deep=@{ processes=0; files_scanned=0; files_emitted=0; files_truncated=$false; timed_out=$false } }
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
    proxy = @{}
    dns_servers = @()
    root_cas = @()
    portproxy = @()
    firewall_profiles = @()
    packages = @()
    installed_apps = @()
    containers = @()
    recent_modified = @()
    packages_modified = @()
    errors = @()
    processes = @()
    suspicious_files = @()
}

try {
    $adminSIDs = @()
    $adminNames = @()
    $adminGroupMethod = "sid"
    try {
        $admins = Get-LocalGroupMember -SID S-1-5-32-544 -ErrorAction Stop
        foreach ($a in $admins) {
            if ($a.SID) {
                $adminSIDs += $a.SID.Value
            }
        }
    } catch {
        $adminGroupMethod = "name"
        try {
            $groupName = (Get-LocalGroup -SID S-1-5-32-544 -ErrorAction Stop).Name
            $netOut = net localgroup "`"$groupName`"" 2>$null
            $parsing = $false
            foreach ($line in $netOut) {
                if ($line -match "^----------------") { $parsing = $true; continue }
                if ($line -match "The command completed successfully") { $parsing = $false; continue }
                if ($parsing -and $line.Trim() -ne "") {
                    $name = $line.Trim()
                    if ($name -match "\\(.*)") {
                        $name = $matches[1]
                    }
                    $adminNames += $name.ToLower()
                }
            }
        } catch {
            $adminGroupMethod = "fail"
            $snapshot.errors += "users: is_admin aniqlanmadi: $_"
        }
    }

    $users = Get-LocalUser
    foreach ($u in $users) {
        $isAdmin = $false
        if ($adminGroupMethod -eq "sid") {
            if ($u.SID.Value -in $adminSIDs) { $isAdmin = $true }
        } elseif ($adminGroupMethod -eq "name") {
            if ($u.Name.ToLower() -in $adminNames) { $isAdmin = $true }
        }
        $grp = @()
        if ($isAdmin) { $grp = @('Administrators') }
        $snapshot.users += @{name=$u.Name; enabled=$u.Enabled; is_admin=$isAdmin; groups=$grp}
    }
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
    foreach ($c in $content) { if ($c -notmatch '^#' -and $c.Trim() -ne '') { $snapshot.hosts_file += [string]$c } }
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
    $proxyData = @{}
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    if (Test-Path $regPath) {
        $props = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        if ($null -ne $props.ProxyEnable) { $proxyData.ProxyEnable = $props.ProxyEnable }
        if ($null -ne $props.ProxyServer) { $proxyData.ProxyServer = $props.ProxyServer }
        if ($null -ne $props.AutoConfigURL) { $proxyData.AutoConfigURL = $props.AutoConfigURL }
    }
    $nsh = netsh winhttp show proxy 2>$null
    if ($nsh) { $proxyData.netsh = ($nsh -join " ").Trim() }
    $snapshot.proxy = $proxyData
} catch { $snapshot.errors += "proxy: $_" }

try {
    $dns = Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, ServerAddresses
    if ($dns) {
        foreach ($d in $dns) {
            if ($d.ServerAddresses) {
                $addrs = $d.ServerAddresses -join ", "
                $snapshot.dns_servers += @{interface=$d.InterfaceAlias; addresses=$addrs}
            }
        }
    } else {
        $ipc = (ipconfig /all) -join " "
        $snapshot.dns_servers += @{interface="ipconfig"; addresses=$ipc}
    }
} catch { $snapshot.errors += "dns_servers: $_" }

try {
    $cas = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Select-Object -First 200 Subject, Thumbprint, NotAfter, Issuer
    if ($cas) {
        foreach ($c in $cas) {
            $snapshot.root_cas += @{subject=$c.Subject; thumbprint=$c.Thumbprint; notafter=$c.NotAfter.ToString("o"); issuer=$c.Issuer}
        }
    }
} catch { $snapshot.errors += "root_cas: $_" }

try {
    $pports = netsh interface portproxy show all 2>$null
    if ($pports) {
        $lines = $pports -split "`r?`n" | Where-Object { $_.Trim() -ne "" } | Select-Object -First 100
        foreach ($l in $lines) {
            # netsh sarlavhalari ("Listen on ipv4:", "Address Port", "-----") qoida emas
            if ($l -match '^\s*(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s*$') {
                $snapshot.portproxy += @{rule=$l.Trim(); listen_addr=$matches[1]; listen_port=[int]$matches[2]; connect_addr=$matches[3]; connect_port=[int]$matches[4]}
            }
        }
    }
} catch { $snapshot.errors += "portproxy: $_" }

try {
    $fws = Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name, Enabled
    if ($fws) {
        foreach ($fw in $fws) {
            $st = "off"
            if ($fw.Enabled -eq 1 -or $fw.Enabled -eq 'True') { $st = "on" }
            $snapshot.firewall_profiles += @{name=$fw.Name; state=$st}
        }
    } else {
        $nshFw = netsh advfirewall show allprofiles state 2>$null
        if ($nshFw) {
            $lines = $nshFw -split "`r?`n" | Where-Object { $_.Trim() -ne "" }
            foreach ($l in $lines) {
                $snapshot.firewall_profiles += @{name="netsh"; state=$l.Trim()}
            }
        }
    }
} catch { $snapshot.errors += "firewall_profiles: $_" }

try {
    $regPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    foreach ($rp in $regPaths) {
        Get-ItemProperty $rp -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
            $app = @{
                name = [string]$_.DisplayName
                version = [string]$_.DisplayVersion
                publisher = [string]$_.Publisher
                install_date = [string]$_.InstallDate
            }
            $snapshot.installed_apps += $app
            $snapshot.packages += @{
                name = [string]$_.DisplayName
                version = [string]$_.DisplayVersion
                manager = "windows_registry"
            }
        }
    }
} catch { $snapshot.errors += "installed_apps: $_" }

try {
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        $dockPs = docker ps -a --no-trunc --format '{{.ID}}\t{{.Image}}\t{{.Names}}' 2>$null
        if ($dockPs) {
            foreach ($line in $dockPs) {
                if ($line) {
                    $parts = $line -split "`t"
                    if ($parts.Count -ge 2) {
                        $snapshot.containers += @{
                            id = [string]$parts[0]
                            image = [string]$parts[1]
                            name = if ($parts.Count -ge 3) { [string]$parts[2] } else { "" }
                            privileged = $false
                            mount_risks = ""
                        }
                    }
                }
            }
        }
    }
} catch { $snapshot.errors += "containers: $_" }

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

try {
    $snapshot.processes = @()
    $signCache = @{}
    $signCount = 0
    $hashCount = 0

    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Sort-Object ProcessId
    foreach ($p in $procs) {
        $path = $p.ExecutablePath
        if ($null -eq $path) { $path = "" }
        $cmd = $p.CommandLine
        if ($null -eq $cmd) { $cmd = "" }
        if ($cmd.Length -gt 1000) { $cmd = $cmd.Substring(0, 1000) }
        
        $user = ""
        try {
            $owner = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
            if ($owner.User) {
                if ($owner.Domain) { $user = "$($owner.Domain)\$($owner.User)" }
                else { $user = $owner.User }
            }
        } catch { }

        $signed = "unknown"
        if ($path -ne "" -and (Test-Path -LiteralPath $path -PathType Leaf)) {
            if (-not $signCache.ContainsKey($path)) {
                if ($signCount -lt 300) {
                    $sig = Get-AuthenticodeSignature -LiteralPath $path
                    $st = $sig.Status
                    if ($st -eq 'Valid') { $signCache[$path] = "valid" }
                    elseif ($st -eq 'NotSigned') { $signCache[$path] = "unsigned" }
                    elseif ($st -eq 'HashMismatch' -or $st -eq 'NotTrusted') { $signCache[$path] = "invalid" }
                    else { $signCache[$path] = "unknown" }
                    $signCount++
                } else {
                    $signCache[$path] = "unknown"
                }
            }
            $signed = $signCache[$path]
        }

        $sha256 = ""
        if ($signed -ne "valid" -and $path -ne "" -and (Test-Path -LiteralPath $path -PathType Leaf) -and $hashCount -lt 200) {
            $fi = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
            if ($fi -and $fi.Length -le 104857600) {
                $hashCount++
                $h = Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction SilentlyContinue
                if ($h) { $sha256 = $h.Hash.ToLower() }
            }
        }

        $stTime = ""
        if ($p.CreationDate) {
            $stTime = $p.CreationDate.ToString("o")
        }

        $snapshot.processes += @{
            pid = [int]$p.ProcessId
            ppid = [int]$p.ParentProcessId
            name = if ($p.Name) { $p.Name } else { "" }
            path = $path
            cmdline = $cmd
            user = $user
            start_time = $stTime
            signed = $signed
            sha256 = $sha256
            exe_deleted = $false
        }
    }
    $snapshot.meta.deep.processes = $snapshot.processes.Count
} catch { $snapshot.errors += "processes: $_" }

try {
    $snapshot.meta.events = @{ out=""; days=$EventsDays; max_per_log=$EventsMax; total=0; per_log=@{}; truncated=@(); errors=@(); skipped=""; seconds=0; missing=@() }
    $eventsBlockSw = [Diagnostics.Stopwatch]::StartNew()
    $snapshot.meta.events.is_admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if ($NoEvents) {
        $snapshot.meta.events.skipped = "NoEvents"
        if (-not $Quiet) { [Console]::Error.WriteLine("[*] Events skipped: NoEvents") }
    } elseif ($EventsOut -eq "" -and $Out -eq "-") {
        $snapshot.meta.events.skipped = "stdout"
        if (-not $Quiet) { [Console]::Error.WriteLine("[*] Events skipped: stdout") }
    } else {
        $csvPath = $EventsOut
        if ($csvPath -eq "") {
            $dir = [System.IO.Path]::GetDirectoryName($Out)
            if ($dir -eq "") { $dir = "." }
            $fn = [System.IO.Path]::GetFileNameWithoutExtension($Out)
            $csvPath = Join-Path $dir "$fn`_events.csv"
        }
        $csvPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($csvPath)
        $snapshot.meta.events.out = $csvPath
        
        $logMap = @(
            @{ LogName="Security"; Id=@(1102, 4624, 4625, 4648, 4657, 4672, 4688, 4697, 4698, 4702, 4720, 4722, 4724, 4728, 4732, 4738, 4756, 4768, 4769, 4771, 4776, 5140, 5145) },
            @{ LogName="System"; Id=@(104, 7040, 7045) },
            @{ LogName="Microsoft-Windows-PowerShell/Operational"; Id=@(4103, 4104) },
            @{ LogName="Windows PowerShell"; Id=@(400) },
            @{ LogName="Microsoft-Windows-Sysmon/Operational"; Id=@(1, 3, 7, 8, 10, 11, 12, 13, 22) },
            @{ LogName="Microsoft-Windows-TaskScheduler/Operational"; Id=@(106, 140, 141) },
            @{ LogName="Microsoft-Windows-Windows Defender/Operational"; Id=@(1116, 1117, 5001, 5007) },
            @{ LogName="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"; Id=@(21, 24, 25) },
            @{ LogName="Microsoft-Windows-WMI-Activity/Operational"; Id=@(5861) }
        )

        $allEvents = New-Object 'System.Collections.Generic.List[object]'
        $startTime = (Get-Date).AddDays(-$EventsDays)

        $known = @{}
        foreach ($n in [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.GetLogNames()) { $known[$n.ToLower()] = $true }

        foreach ($lm in $logMap) {
            $ln = $lm.LogName
            $ids = $lm.Id
            
            if ($ln -eq 'Security' -and -not $snapshot.meta.events.is_admin) {
                $msg = "Security: admin emas - o'qilmadi (kollektorni admin sifatida qayta yurgizing)"
                $snapshot.meta.events.errors += $msg
                if (-not $Quiet) { [Console]::Error.WriteLine("[!] $msg") }
                continue
            }
            if (-not $known.ContainsKey($ln.ToLower())) {
                $snapshot.meta.events.per_log[$ln] = 0
                $snapshot.meta.events.missing += $ln
                continue
            }

            try {
                $evts = Get-WinEvent -FilterHashtable @{LogName=$ln; Id=$ids; StartTime=$startTime} -MaxEvents $EventsMax -ErrorAction Stop
                $cnt = 0
                if ($evts) {
                    $cnt = @($evts).Count
                    $allEvents.AddRange(@($evts))
                }
                $snapshot.meta.events.per_log[$ln] = $cnt
                if ($cnt -ge $EventsMax) {
                    $snapshot.meta.events.truncated += $ln
                }
            } catch {
                $errId = $_.FullyQualifiedErrorId
                $errMsg = $_.Exception.Message
                if ($errId -like '*NoMatchingEventsFound*') {
                    $snapshot.meta.events.per_log[$ln] = 0
                } else {
                    $snapshot.meta.events.errors += "$($ln): $errMsg"
                    if (-not $Quiet) { [Console]::Error.WriteLine("[!] $($ln): $errMsg") }
                }
            }
        }

        $csvRows = New-Object 'System.Collections.Generic.List[object]'
        foreach ($e in $allEvents | Sort-Object TimeCreated) {
            $x = [xml]$e.ToXml()
            $d = @{}
            
            $ed = $x.Event.EventData.Data
            if ($null -eq $ed -or $ed.Count -eq 0) {
                $ud = $x.Event.UserData.ChildNodes[0].ChildNodes
                if ($null -ne $ud) {
                    foreach ($node in $ud) {
                        if ($node.LocalName) { $d[$node.LocalName] = $node.InnerText }
                    }
                }
            } else {
                $idx = 0
                foreach ($node in $ed) {
                    if ($node.Name) {
                        $d[$node.Name] = $node.InnerText
                    } else {
                        $d["Data$idx"] = $node.InnerText
                        $idx++
                    }
                }
            }

            foreach ($k in @($d.Keys)) {
                if ($d[$k] -eq "-") { $d[$k] = "" }
            }

            $user = ""
            if ($d.TargetUserName) { $user = $d.TargetUserName }
            elseif ($d.SubjectUserName) { $user = $d.SubjectUserName }
            elseif ($d.User) { $user = $d.User }
            elseif ($d.AccountName) { $user = $d.AccountName }
            elseif ($d.UserName) { $user = $d.UserName }
            if ($e.Id -eq 4688 -and $d.TargetUserName -eq "") {
                $user = $d.SubjectUserName
            }

            $proc = ""
            if ($d.NewProcessName) { $proc = $d.NewProcessName }
            elseif ($d.Image) { $proc = $d.Image }
            elseif ($d.ProcessName) { $proc = $d.ProcessName }

            $pproc = ""
            if ($d.ParentProcessName) { $pproc = $d.ParentProcessName }
            elseif ($d.ParentImage) { $pproc = $d.ParentImage }

            $cmdLine = ""
            if ($d.CommandLine) { $cmdLine = $d.CommandLine }
            elseif ($d.ScriptBlockText) {
                $cmdLine = $d.ScriptBlockText
                if ($cmdLine.Length -gt 4000) { $cmdLine = $cmdLine.Substring(0, 4000) }
            }
            elseif ($d.ImagePath) { $cmdLine = $d.ImagePath }
            elseif ($d.ServiceFileName) { $cmdLine = $d.ServiceFileName }
            elseif ($d.TaskContent) {
                $tc = $d.TaskContent
                $c = ""; $a = ""
                if ($tc -match '<Command>(.*?)</Command>') { $c = $matches[1] }
                if ($tc -match '<Arguments>(.*?)</Arguments>') { $a = $matches[1] }
                $cmdLine = "$c $a".Trim()
            }
            elseif ($e.LogName -eq 'Windows PowerShell' -and $e.Id -eq 400) {
                foreach ($v in $d.Values) {
                    if ($v -match 'HostApplication=(.*)') {
                        $cmdLine = $matches[1]
                        break
                    }
                }
            }
            elseif ($d.Payload) {
                $cmdLine = $d.Payload
                if ($cmdLine.Length -gt 2000) { $cmdLine = $cmdLine.Substring(0, 2000) }
            }

            $src = ""
            if ($d.IpAddress) { $src = $d.IpAddress }
            elseif ($d.SourceIp) { $src = $d.SourceIp }
            elseif ($d.SourceAddress) { $src = $d.SourceAddress }
            elseif ($d.Address) { $src = $d.Address }
            elseif ($d.ClientAddress) { $src = $d.ClientAddress }

            $dst = ""
            if ($d.DestinationIp) { $dst = $d.DestinationIp }

            $msgParts = @()
            if ($e.Id -in @(4624,4625) -and $d.LogonType) {
                $msgParts += "Logon Type $($d.LogonType)"
            }
            if ($e.Id -in @(1116,1117)) {
                if ($d.'Threat Name') { $msgParts += "Threat Name=$($d.'Threat Name')" }
                if ($d.Path) { $msgParts += "Path=$($d.Path)" }
                if ($d.'Process Name') { $msgParts += "Process Name=$($d.'Process Name')" }
                if ($d.'Action Name') { $msgParts += "Action Name=$($d.'Action Name')" }
            }

            $excludeKeys = @('CommandLine','ScriptBlockText','TaskContent','Payload','ImagePath','ServiceFileName','NewProcessName','Image','ParentImage','ParentProcessName','IpAddress','SourceIp','DestinationIp')
            foreach ($k in $d.Keys) {
                if ($k -in $excludeKeys) { continue }
                if ($k -like '*Sid' -or $k -like '*Guid' -or $k -like '*LogonId' -or $k -eq 'KeyLength' -or $k -eq 'LmPackageName' -or $k -eq 'TransmittedServices' -or $k -eq 'ImpersonationLevel' -or $k -eq 'RestrictedAdminMode' -or $k -eq 'VirtualAccount' -or $k -eq 'ElevatedToken' -or $k -eq 'TargetOutboundUserName' -or $k -eq 'TargetOutboundDomainName' -or $k -eq 'ScriptBlockId' -or ($e.Id -eq 4104 -and $k -eq 'Path') -or $k -eq 'MessageNumber' -or $k -eq 'MessageTotal' -or $k -eq 'Hashes') { continue }
                
                $val = $d[$k]
                if ($val -ne "") {
                    if ($val.Length -gt 300) { $val = $val.Substring(0, 300) }
                    if ($e.Id -in @(1116,1117) -and $k -in @('Threat Name','Path','Process Name','Action Name')) { continue }
                    if ($e.Id -in @(4624,4625) -and $k -eq 'LogonType') { continue }
                    $msgParts += "$k=$val"
                }
            }
            $msg = $msgParts -join " | "
            if ($msg.Length -gt 2000) { $msg = $msg.Substring(0, 2000) }

            $row = [ordered]@{
                TimeCreated = $e.TimeCreated.ToString("o")
                Computer = $e.MachineName
                Channel = $e.LogName
                EventID = $e.Id
                user = $user
                process = $proc
                parent_process = $pproc
                CommandLine = $cmdLine
                src = $src
                dst = $dst
                message = $msg
            }

            foreach ($k in @($row.Keys)) {
                if ($row[$k] -ne $null) {
                    $row[$k] = $row[$k] -replace '[\x00-\x1F]', ' '
                }
            }
            $csvRows.Add([pscustomobject]$row)
        }
        
        $snapshot.meta.events.total = $csvRows.Count
        if ($csvRows.Count -eq 0) {
            $lines = @('"TimeCreated","Computer","Channel","EventID","user","process","parent_process","CommandLine","src","dst","message"')
        } else {
            $lines = ($csvRows | ConvertTo-Csv -NoTypeInformation)
        }
        
        $utf8NoBom = New-Object System.Text.UTF8Encoding $False
        [System.IO.File]::WriteAllLines($csvPath, $lines, $utf8NoBom)
        
        if (-not $Quiet) {
            [Console]::Error.WriteLine("[*] Events: $($snapshot.meta.events.total) -> $csvPath")
        }
    }
    $eventsBlockSw.Stop()
    $snapshot.meta.events.seconds = [int][Math]::Floor($eventsBlockSw.Elapsed.TotalSeconds)
} catch {
    $snapshot.meta.events.errors += "main: $_"
}

if (-not $NoDeep) {
    try {
        $snapshot.suspicious_files = @()
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $emitted = @()
        $scannedCount = 0

        $limitTime = (Get-Date).AddDays(-$DaysBack)
        
        $signCacheFiles = @{}
        $signCountFiles = 0

        $execExts = @('.exe','.dll','.sys','.scr','.ocx','.cpl','.com','.pif','.bat','.cmd','.ps1','.vbs','.vbe','.js','.jse','.wsf','.wsh','.hta','.jar','.msi','.lnk')
        $signExts = @('.exe','.dll','.sys','.scr','.ocx','.cpl')
        $webExts = @('.aspx','.asp','.ashx','.php','.phtml','.jsp','.jspx')
        
        $searchPaths = @("$env:windir\Temp", "$env:windir\Tasks", "C:\PerfLogs", $env:ProgramData)
        $usersDir = "C:\Users"
        if (Test-Path $usersDir) {
            Get-ChildItem $usersDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $up = $_.FullName
                if ($_.Name -eq "Public") {
                    $searchPaths += $up
                } else {
                    $searchPaths += "$up\Downloads", "$up\Desktop", "$up\AppData\Roaming", "$up\AppData\LocalLow", "$up\AppData\Local"
                }
            }
        }
        $webRoots = @("C:\inetpub\wwwroot", "C:\xampp\htdocs")
        if (Test-Path "C:\") {
            Get-ChildItem "C:\" -Directory -Filter "wamp*" -ErrorAction SilentlyContinue | ForEach-Object { $webRoots += "$($_.FullName)\www" }
        }
        foreach ($wr in $webRoots) { if (Test-Path $wr) { $searchPaths += $wr } }

        $sysPaths = @("$env:windir\System32", "$env:windir\SysWOW64")

        function Process-SusFile {
            param([System.IO.FileInfo]$f, [bool]$isSys, [bool]$isRoot, [bool]$isWeb)
            
            if ($sw.Elapsed.TotalSeconds -gt $DeepTimeoutSec) {
                $snapshot.meta.deep.timed_out = $true
                return
            }
            $script:scannedCount++
            
            $ext = $f.Extension.ToLower()
            $isExecScript = ($ext -in $execExts)
            
            $mt = $f.LastWriteTime
            $ct = $f.CreationTime
            if ($mt -lt $limitTime -and $ct -lt $limitTime) { return }
            
            $size = $f.Length
            $magicMZ = $false
            if (-not $isExecScript -and $size -ge 4096 -and $size -le 52428800) {
                try {
                    $fs = [System.IO.File]::OpenRead($f.FullName)
                    $b1 = $fs.ReadByte()
                    $b2 = $fs.ReadByte()
                    $fs.Close()
                    if ($b1 -eq 77 -and $b2 -eq 90) { $magicMZ = $true }
                } catch { }
            }
            
            $isWebExt = ($ext -in $webExts)
            
            $shouldEmit = $false
            if ($isSys) {
                if ($ext -in $signExts) { $shouldEmit = $true }
            } elseif ($isWeb) {
                if ($isWebExt) { $shouldEmit = $true }
            } else {
                if ($isExecScript -or $magicMZ) { $shouldEmit = $true }
                elseif ($isRoot -and $isExecScript) { $shouldEmit = $true }
            }
            
            if (-not $shouldEmit) { return }
            
            $signed = "n/a"
            if ($ext -in $signExts -or $magicMZ) {
                if ($ext -eq ".lnk") {
                    $signed = "n/a"
                } else {
                    $p = $f.FullName
                    if (-not $script:signCacheFiles.ContainsKey($p)) {
                        if ($script:signCountFiles -lt 300) {
                            $sig = Get-AuthenticodeSignature -LiteralPath $p
                            $st = $sig.Status
                            if ($st -eq 'Valid') { $script:signCacheFiles[$p] = "valid" }
                            elseif ($st -eq 'NotSigned') { $script:signCacheFiles[$p] = "unsigned" }
                            elseif ($st -eq 'HashMismatch' -or $st -eq 'NotTrusted') { $script:signCacheFiles[$p] = "invalid" }
                            else { $script:signCacheFiles[$p] = "unknown" }
                            $script:signCountFiles++
                        } else {
                            $script:signCacheFiles[$p] = "unknown"
                        }
                    }
                    $signed = $script:signCacheFiles[$p]
                }
            }
            
            if ($isSys -and $signed -eq "valid") { return }
            
            $sha256 = ""
            if ($ext -ne ".lnk" -and ($isExecScript -or $magicMZ -or $isWebExt) -and $size -le 104857600) {
                $h = Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
                if ($h) { $sha256 = $h.Hash.ToLower() }
            }
            
            $head = ""
            $scriptExts = @('.bat','.cmd','.ps1','.vbs','.vbe','.js','.jse','.wsf','.hta','.sh','.py','.pl','.php')
            if ($ext -in $scriptExts -and $size -le 65536) {
                try {
                    $txt = [System.IO.File]::ReadAllText($f.FullName)
                    if ($txt.Length -gt 400) { $txt = $txt.Substring(0, 400) }
                    $txt = $txt -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ' '
                    $head = $txt
                } catch { }
            }
            
            $webshell = $false
            if ($isWebExt -and $size -le 65536) {
                try {
                    $txt = [System.IO.File]::ReadAllText($f.FullName)
                    $pat = '(?i)(eval\s*\(|Request(\.|\[)(Form|QueryString|Params)|cmd\.exe|Runtime\.getRuntime\(\)\.exec|\b(system|passthru|shell_exec|proc_open|popen)\s*\(|base64_decode\s*\(|ProcessStartInfo|\$_(GET|POST|REQUEST)\[)'
                    if ($txt -match $pat) { $webshell = $true }
                } catch { }
            }
            
            $hidden = (($f.Attributes -band [System.IO.FileAttributes]::Hidden) -eq [System.IO.FileAttributes]::Hidden)
            
            $rec = @{
                path = $f.FullName
                ext = if ($ext -eq $null) { "" } else { $ext }
                size = $size
                mtime = $mt.ToString("o")
                ctime = $ct.ToString("o")
                sha256 = $sha256
                signed = $signed
                exe_magic = $magicMZ
                hidden = $hidden
                head = $head
                webshell_hint = $webshell
            }
            $script:emitted += $rec
        }

        # Brauzer kengaytmalari, paket keshlari va Store ilovalari shovqin: ularni o'tkazib yuboramiz
        $noiseRx = '(?i)\\(google\\chrome\\user data|microsoft\\edge\\user data|mozilla\\firefox\\profiles|brave-browser\\user data|node_modules|npm-cache|\.vscode\\extensions|microsoft\\windowsapps|inetcache|packages\\[^\\]+\\localcache|microsoft\\windows\\recent|microsoft\\windows\\start menu|programdata\\microsoft\\windows defender|programdata\\package cache|programdata\\microsoft\\windows\\apprepository|microsoft\\windows\\wer)\\'
        $seenFiles = @{}
        foreach ($sp in $sysPaths) {
            if (Test-Path $sp) {
                Get-ChildItem -Path $sp -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    if ($snapshot.meta.deep.timed_out) { return }
                    if (-not $seenFiles.ContainsKey($_.FullName)) {
                        $seenFiles[$_.FullName] = $true
                        Process-SusFile -f $_ -isSys $true -isRoot $false -isWeb $false
                    }
                }
            }
        }
        if (Test-Path "C:\") {
            Get-ChildItem -Path "C:\" -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
                if ($snapshot.meta.deep.timed_out) { return }
                if (-not $seenFiles.ContainsKey($_.FullName)) {
                    $seenFiles[$_.FullName] = $true
                    Process-SusFile -f $_ -isSys $false -isRoot $true -isWeb $false
                }
            }
        }
        
        foreach ($sp in $searchPaths) {
            if (Test-Path $sp) {
                Get-ChildItem -Path $sp -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    if ($snapshot.meta.deep.timed_out) { return }
                    if ($_.FullName -match $noiseRx) { return }
                    if (-not $seenFiles.ContainsKey($_.FullName)) {
                        $seenFiles[$_.FullName] = $true
                        $isWeb = ($sp -in $webRoots -or $sp.StartsWith("C:\inetpub") -or $sp.StartsWith("C:\xampp") -or $sp.StartsWith("C:\wamp"))
                        Process-SusFile -f $_ -isSys $false -isRoot $false -isWeb $isWeb
                    }
                }
            }
        }
        $emitted = $emitted | Sort-Object -Property mtime -Descending
        if ($emitted.Count -gt 600) {
            $emitted = $emitted | Select-Object -First 600
            $snapshot.meta.deep.files_truncated = $true
        }
        $snapshot.suspicious_files = $emitted
        $snapshot.meta.deep.files_scanned = $scannedCount
        $snapshot.meta.deep.files_emitted = $emitted.Count
    } catch {
        $snapshot.errors += "suspicious_files: $_"
    }
}

$json = $snapshot | ConvertTo-Json -Depth 6

if (-not $Quiet) {
    [Console]::Error.WriteLine("users=$($snapshot.users.Count) services=$($snapshot.services.Count) tasks=$($snapshot.tasks.Count) autoruns=$($snapshot.autoruns.Count) rats=$($snapshot.remote_access_tools.Count) procs=$($snapshot.processes.Count) files=$($snapshot.suspicious_files.Count) events=$($snapshot.meta.events.total)")
}

if ($Out -eq "-") {
    Write-Output $json
    if (-not $Quiet) {
        [Console]::Error.WriteLine("Snapshot JSON printed to STDOUT")
    }
} else {
    $utf8NoBom = New-Object System.Text.UTF8Encoding $False
    [System.IO.File]::WriteAllText($Out, $json, $utf8NoBom)
    if (-not $Quiet) {
        [Console]::Error.WriteLine("Snapshot saved to $Out")
    }
}
