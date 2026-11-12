<#
 Auto Adjust NOC agent for Windows (PowerShell 5.1+). Reads real metrics from Windows performance counters / CIM and posts them to
 POST $SPARK_URL/api/soc/noc/telemetry using an ORGANIZATION key (aa_live_...). Read-only: it changes nothing on the host.
 STATUS: written to the same payload contract as the Linux agent, which IS tested. This script (telemetry AND the optional -Executor mode) has NOT been executed on a Windows host yet
 (no Windows available in the build environment) - run the "Test" steps in docs/ORG-KEYS-MIGRATION.md before relying on it.
 Usage:  $env:SPARK_URL='https://autoadjust.net'; $env:SPARK_INGEST_TOKEN='aa_live_xxx'; .\Auto-Adjust-Windows-Agent.ps1            # loop
         .\Auto-Adjust-Windows-Agent.ps1 -Once            # one sample      .\Auto-Adjust-Windows-Agent.ps1 -DryRun   # print JSON, send nothing
 Optional: -IntervalSec 60  -DeviceName X  -ProbeTargets '10.0.0.1','10.0.0.2:443'  (host = ICMP, host:port = TCP connect)
#>
param([int]$IntervalSec = 60, [string]$DeviceName = $env:COMPUTERNAME, [string[]]$ProbeTargets = @(), [switch]$Once, [switch]$DryRun, [switch]$Executor, [int]$ExecPollSec = 10, [string]$PolicyFile = "$env:ProgramData\AutoAdjust\executor-policy.conf", [string]$StateDir = "$env:ProgramData\AutoAdjust\state", [switch]$AllowAdmin)
$ErrorActionPreference = 'Stop'
$Url = $env:SPARK_URL; $Token = $env:SPARK_INGEST_TOKEN
if (-not $DryRun -and ([string]::IsNullOrWhiteSpace($Url) -or [string]::IsNullOrWhiteSpace($Token))) { Write-Error 'SPARK_URL and SPARK_INGEST_TOKEN are required'; exit 2 }
if ($Token -and $Token -notmatch '^aa_live_') { Write-Warning 'SPARK_INGEST_TOKEN is not an organization key (aa_live_...). Legacy shared tokens are being retired.' }
$Id = ($DeviceName.ToLower() -replace '[^a-z0-9._-]', '-')

function Get-Sample {
  $cpu = (Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 2 -MaxSamples 1).CounterSamples[0].CookedValue
  $os = Get-CimInstance Win32_OperatingSystem
  $mem = 100 * (1 - ($os.FreePhysicalMemory / $os.TotalVisibleMemorySize))
  $sys = (Get-Item Env:SystemDrive).Value; $d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$sys'"
  $disk = 100 * (1 - ($d.FreeSpace / $d.Size))
  $nic = Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface | Where-Object { $_.Name -notmatch 'Loopback|isatap|Teredo' } | Sort-Object BytesTotalPersec -Descending | Select-Object -First 1
  $cap = $null; if ($nic -and $nic.CurrentBandwidth -gt 0) { $cap = [math]::Round($nic.CurrentBandwidth / 1e6, 1) }
  $m = [ordered]@{ cpu = [math]::Round($cpu, 1); mem = [math]::Round($mem, 1); disk = [math]::Round($disk, 1) }
  if ($nic) { $m.bwInMbps = [math]::Round($nic.BytesReceivedPersec * 8 / 1e6, 3); $m.bwOutMbps = [math]::Round($nic.BytesSentPersec * 8 / 1e6, 3) }
  if ($cap) { $m.bwCapMbps = $cap }
  $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notmatch '^(127|169\.254)\.' } | Select-Object -First 1).IPAddress
  [ordered]@{ id = $Id; name = $DeviceName; type = 'server'; ip = $ip; up = $true; metrics = $m
    config = [ordered]@{ os = $os.Caption; build = $os.BuildNumber; uptimeSec = [int]((Get-Date) - $os.LastBootUpTime).TotalSeconds; agent = 'windows-1.0' } }
}
function Get-Probe([string]$t) {
  $pid2 = 'probe-' + ($t -replace '[^a-zA-Z0-9._-]', '-')
  if ($t -match '^(.+):(\d+)$') {
    $h = $Matches[1]; $p = [int]$Matches[2]; $sw = [Diagnostics.Stopwatch]::StartNew(); $c = New-Object Net.Sockets.TcpClient
    try { $ok = $c.ConnectAsync($h, $p).Wait(3000) } catch { $ok = $false } finally { $c.Close() }
    if ($ok) { return [ordered]@{ id = $pid2; name = $t; type = 'server'; ip = $h; up = $true; metrics = @{ latencyMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 1); lossPct = 0 } } }
    return [ordered]@{ id = $pid2; name = $t; type = 'server'; ip = $h; up = $false; metrics = @{ lossPct = 100 } }
  }
  $r = @(Test-Connection -ComputerName $t -Count 3 -ErrorAction SilentlyContinue)
  if ($r.Count -eq 0) { return [ordered]@{ id = $pid2; name = $t; type = 'server'; ip = $t; up = $false; metrics = @{ lossPct = 100 } } }
  $lat = ($r | ForEach-Object { if ($_.ResponseTime -ne $null) { $_.ResponseTime } else { $_.Latency } } | Measure-Object -Average).Average
  [ordered]@{ id = $pid2; name = $t; type = 'server'; ip = $t; up = $true; metrics = @{ latencyMs = [math]::Round($lat, 1); lossPct = [math]::Round(100 * (3 - $r.Count) / 3, 1) } }
}
function Send-Once {
  $devs = @(Get-Sample); foreach ($t in $ProbeTargets) { $devs += Get-Probe $t }
  $body = @{ source = "windows-agent:$Id"; devices = $devs } | ConvertTo-Json -Depth 6 -Compress
  if ($DryRun) { $body; return }
  try {
    $r = Invoke-RestMethod -Method Post -Uri "$Url/api/soc/noc/telemetry" -Headers @{ Authorization = "Bearer $Token" } -ContentType 'application/json' -Body $body -TimeoutSec 20
    Write-Host ("{0} sent, server stored {1} device(s)" -f (Get-Date).ToUniversalTime().ToString('s'), $r.received)
  } catch { Write-Warning ("send failed: " + $_.Exception.Message); if ($Once) { exit 1 } }
}

# ===================== EXECUTOR (optional, -Executor): read-only diagnostics approved by people in Auto Adjust =====================
# Same safety model as the Linux executor: outbound HTTPS only; HMAC-signed, host-bound, single-use, short-lived jobs; the command text lives HERE (fixed PowerShell
# text that reads parameters from AA_P_* environment variables - parameters are never pasted into command text); host-local policy file, fail closed; clean child
# environment (your API key is not visible to commands); timeout kill; output caps; secret redaction; refuses to run elevated unless -AllowAdmin.
# Policy file, one rule per line:  template <id> | service <name> | target <exact host name or IPv4; no wildcards>        (log.tail on Windows only allows the Application and System logs)
# !! NOT YET EXECUTED ON WINDOWS. The Linux executor is covered by tests/live/executor-e2e.ts; run the same checks here before relying on this. !!
$XT = @{
 'sys.uptime'  = @{ t=10; l=20;  b=4096;  ps="Get-CimInstance Win32_OperatingSystem | Select-Object @{n='LastBoot';e={`$_.LastBootUpTime}},@{n='UptimeHours';e={[math]::Round(((Get-Date)-`$_.LastBootUpTime).TotalHours,1)}} | Format-List" }
 'sys.cpu_top' = @{ t=10; l=16;  b=4096;  ps="Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 Id,ProcessName,CPU,WorkingSet | Format-Table -AutoSize" }
 'sys.mem'     = @{ t=10; l=20;  b=4096;  ps="Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory | Format-List" }
 'sys.disk'    = @{ t=15; l=40;  b=8192;  ps="Get-PSDrive -PSProvider FileSystem | Select-Object Name,Used,Free | Format-Table -AutoSize" }
 'sys.load'    = @{ t=5;  l=5;   b=1024;  ps="(Get-Counter '\System\Processor Queue Length').CounterSamples | Select-Object Path,CookedValue | Format-List" }
 'svc.status'  = @{ t=10; l=20;  b=4096;  ps='Get-Service -Name $env:AA_P_UNIT | Select-Object Name,Status,StartType | Format-List' }
 'net.listen'  = @{ t=10; l=120; b=12288; ps="Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Select-Object LocalAddress,LocalPort | Format-Table -AutoSize" }
 'net.reach'   = @{ t=5;  l=5;   b=1024;  ps=$null }
 'net.ping'    = @{ t=15; l=20;  b=2048;  ps='Test-Connection -ComputerName $env:AA_P_HOST -Count 3 | Format-Table -AutoSize' }
 'dns.lookup'  = @{ t=10; l=10;  b=2048;  ps='Resolve-DnsName -Name $env:AA_P_NAME -Type A | Format-Table -AutoSize' }
 'log.tail'    = @{ t=20; l=200; b=16384; ps='Get-WinEvent -LogName $env:AA_P_LOG -MaxEvents ([int]$env:AA_P_N) | ForEach-Object { ''{0:o} [{1}] {2} {3}'' -f $_.TimeCreated,$_.LevelDisplayName,$_.ProviderName,(($_.Message -split "`n")[0]) }' }
}
$RE_UNIT = '^[A-Za-z0-9][A-Za-z0-9@._-]{0,63}$'
$RE_HOSTNAME = '^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$'
$RE_IPV4 = '^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$'
function Test-Policy([string]$kind, [string]$val) { if (-not (Test-Path $PolicyFile)) { return $false }; return [bool](Select-String -Path $PolicyFile -SimpleMatch -Pattern "$kind $val" -Quiet) -and ((Get-Content $PolicyFile) -contains "$kind $val") }
function Test-PolicyTargets { if (-not (Test-Path $PolicyFile)) { return $false }; foreach ($l in (Get-Content $PolicyFile)) { if ($l -like 'target *') { $v = $l.Substring(7); if (-not ($v -match $RE_IPV4 -or $v -match $RE_HOSTNAME)) { return $false } } }; return $true }
function Test-ForbiddenTarget([string]$h) { return ($h -match '^127\.' -or $h -match '^0\.' -or $h -match '^169\.254\.' -or $h -match '^(22[4-9]|2[3-5]\d)\.' -or $h -ieq 'localhost' -or $h -like '*.localhost') }
function Hide-Secrets([string]$t) {
  foreach ($r in @(@('aa_live_[A-Za-z0-9_-]{8,}','[REDACTED API KEY]'), @('eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}','[REDACTED JWT]'), @('(?i)(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}','$1 [REDACTED]'),
      @('\b(AKIA|ASIA)[A-Z0-9]{16}\b','[REDACTED AWS KEY]'), @('(?i)((pass(word|wd)?|pwd|secret|token|api[_-]?key|apikey|auth|credential|private[_-]?key|access[_-]?key)[A-Za-z0-9_.-]*\s*[=:]\s*)("[^"]*"|''[^'']*''|[^\s,;&]+)','$1[REDACTED]'),
      @('(//[^/\s:@]+:)[^@\s/]+@','$1[REDACTED]@'), @('(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*','[REDACTED PRIVATE KEY]'))) { $t = [regex]::Replace($t, $r[0], $r[1]) }
  return $t
}
function Get-HmacHex([string]$key, [string]$text) { $h = New-Object Security.Cryptography.HMACSHA256 (,[Text.Encoding]::UTF8.GetBytes($key)); return ([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($text))) -replace '-','').ToLower() }
function Get-Sha256Hex([string]$text) { $s = [Security.Cryptography.SHA256]::Create(); return ([BitConverter]::ToString($s.ComputeHash([Text.Encoding]::UTF8.GetBytes($text))) -replace '-','').ToLower() }
function Test-JobParams([string]$t, $p) {
  $names = @($p.Keys)
  switch ($t) {
    { $_ -in 'sys.uptime','sys.cpu_top','sys.mem','sys.disk','sys.load','net.listen' } { if ($names.Count -ne 0) { return 'unexpected parameters' } }
    'svc.status' { if ($names.Count -ne 1 -or $p['unit'] -notmatch $RE_UNIT) { return 'bad unit' }; if (-not (Test-Policy 'service' $p['unit'])) { return 'unit not in local policy (service)' } }
    'log.tail'   { if ($names.Count -ne 2 -or $p['log'] -notin 'Application','System' -or $p['n'] -notmatch '^\d{1,3}$' -or [int]$p['n'] -lt 1 -or [int]$p['n'] -gt 200) { return 'bad log or n' } }
    'net.reach'  { if ($names.Count -ne 2 -or -not ($p['host'] -match $RE_IPV4 -or $p['host'] -match $RE_HOSTNAME) -or $p['port'] -notmatch '^\d{1,5}$' -or [int]$p['port'] -lt 1 -or [int]$p['port'] -gt 65535) { return 'bad host or port' }; if (Test-ForbiddenTarget $p['host']) { return 'forbidden target' }; if (-not (Test-PolicyTargets)) { return 'host policy has an invalid or wildcard target rule' }; if (-not (Test-Policy 'target' $p['host'])) { return 'target not in local policy' } }
    'net.ping'   { if ($names.Count -ne 1 -or -not ($p['host'] -match $RE_IPV4 -or $p['host'] -match $RE_HOSTNAME)) { return 'bad host' }; if (Test-ForbiddenTarget $p['host']) { return 'forbidden target' }; if (-not (Test-PolicyTargets)) { return 'host policy has an invalid or wildcard target rule' }; if (-not (Test-Policy 'target' $p['host'])) { return 'target not in local policy' } }
    'dns.lookup' { if ($names.Count -ne 1 -or $p['name'] -notmatch $RE_HOSTNAME) { return 'bad name' } }
    default { return 'unknown template' }
  }
  if (-not (Test-Policy 'template' $t)) { return 'template not enabled in local policy' }
  return $null
}
function Invoke-Job([string]$t, $p) {
  $d = $XT[$t]; $out = ''; $rc = 0; $tmo = $false
  if ($t -eq 'net.reach') { $c = New-Object Net.Sockets.TcpClient; try { $sw = [Diagnostics.Stopwatch]::StartNew(); if ($c.ConnectAsync($p['host'], [int]$p['port']).Wait($d.t * 1000)) { $out = "CONNECTED $($p['host']):$($p['port']) in $([int]$sw.ElapsedMilliseconds) ms" } else { $out = "FAILED to connect to $($p['host']):$($p['port'])"; $rc = 1 } } catch { $out = "FAILED to connect to $($p['host']):$($p['port'])"; $rc = 1 } finally { $c.Close() } }
  elseif ($d.ps -and -not (Get-Command (($d.ps -split "[\s|(]+" | Where-Object { $_ -match '^[A-Z][a-z]+-[A-Za-z]+$' } | Select-Object -First 1)) -ErrorAction SilentlyContinue)) { $out = "UNSUPPORTED: a required PowerShell command is not available on this host. Nothing was run."; $rc = 127 }
  else {
    $psi = New-Object Diagnostics.ProcessStartInfo; $psi.FileName = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"; $psi.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Restrict -Command "' + ($d.ps -replace '"','\"') + '"'
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
    $psi.EnvironmentVariables.Clear(); foreach ($k in 'SystemRoot','SystemDrive','windir','Path','PSModulePath','TEMP','TMP') { $v = [Environment]::GetEnvironmentVariable($k); if ($v) { $psi.EnvironmentVariables[$k] = $v } }   # clean environment: no SPARK_* secrets
    foreach ($k in $p.Keys) { $psi.EnvironmentVariables['AA_P_' + $k.ToUpper()] = [string]$p[$k] }
    $pr = [Diagnostics.Process]::Start($psi); $o = $pr.StandardOutput.ReadToEndAsync(); $e = $pr.StandardError.ReadToEndAsync()
    if (-not $pr.WaitForExit($d.t * 1000)) { try { $pr.Kill() } catch {}; $tmo = $true; $rc = 124 } else { $rc = $pr.ExitCode }
    $out = ($o.Result + $e.Result)
  }
  $trunc = $false; $lines = $out -split "`r?`n"; if ($lines.Count -gt $d.l) { $out = ($lines[0..($d.l - 1)] -join "`n"); $trunc = $true }
  if ([Text.Encoding]::UTF8.GetByteCount($out) -gt $d.b) { $out = $out.Substring(0, [math]::Min($out.Length, $d.b)); $trunc = $true }
  $out = Hide-Secrets (($out.ToCharArray() | Where-Object { $_ -ge ' ' -or $_ -eq "`n" -or $_ -eq "`t" }) -join '')
  return @{ rc = $rc; timedOut = $tmo; output = $out; truncated = $trunc }
}
function Send-Result($job, $keyHash, $res, [string]$started) {
  $sig = Get-HmacHex $keyHash ("v1result|$($job.id)|$($job.leaseId)|$($res.rc)|$([int]$res.timedOut)|$(Get-Sha256Hex $res.output)")
  $body = @{ leaseId = $job.leaseId; exitCode = $res.rc; timedOut = [bool]$res.timedOut; output = $res.output; sig = $sig; startedAt = $started; truncated = [bool]$res.truncated } | ConvertTo-Json -Compress
  try { Invoke-RestMethod -Method Post -Uri "$Url/api/soc/noc/executor/jobs/$($job.id)/result" -Headers @{ Authorization = "Bearer $Token" } -ContentType 'application/json' -Body $body -TimeoutSec 20 | Out-Null; "reported" } catch { "report failed: $($_.Exception.Message)" }
}
function Invoke-ExecutorPoll {
  if (-not $AllowAdmin -and ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Warning 'Executor refuses to run elevated (use a standard account; -AllowAdmin overrides).'; return }
  New-Item -ItemType Directory -Force -Path $StateDir | Out-Null; $keyHash = Get-Sha256Hex ("aa-key:" + $Token)
  try { $r = Invoke-RestMethod -Uri "$Url/api/soc/noc/executor/jobs?host=$Id" -Headers @{ Authorization = "Bearer $Token" } -TimeoutSec 20 } catch { Write-Warning "executor poll failed: $($_.Exception.Message)"; return }
  if (-not $r.jobs -or @($r.jobs).Count -ne 1) { return }; $j = @($r.jobs)[0]
  $pp = @{}; foreach ($pr in $j.params.PSObject.Properties) { $pp[$pr.Name] = [string]$pr.Value }
  $canon = 'v1|{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}' -f $j.id, $j.orgId, $j.hostId, $j.template, (($pp.Keys | Sort-Object { $_ } | ForEach-Object { "$_=$($pp[$_])" }) -join '&'), $j.expiresAt, $j.nonce, $j.leaseId
  if ((Get-HmacHex $keyHash $canon) -ne $j.sig) { Write-Warning "job $($j.id) IGNORED: bad signature"; return }
  $refuse = { param($why) Write-Warning "job $($j.id) REFUSED: $why"; Send-Result $j $keyHash @{ rc = 126; timedOut = $false; output = "Refused by the executor: $why"; truncated = $false } (Get-Date).ToUniversalTime().ToString('o') | Out-Null }
  if ($j.hostId -ne $Id) { & $refuse 'job is for another host'; return }
  if ([datetime]::Parse($j.expiresAt).ToUniversalTime() -lt (Get-Date).ToUniversalTime().AddSeconds(-60)) { & $refuse 'job expired'; return }
  $seen = Join-Path $StateDir "seen-$($j.id)"; if (Test-Path $seen) { Write-Warning "job $($j.id) IGNORED: already seen (replay)"; return }; New-Item -ItemType File -Path $seen | Out-Null    # recorded BEFORE running
  $why = Test-JobParams $j.template $pp; if ($why) { & $refuse $why; return }
  $started = (Get-Date).ToUniversalTime().ToString('o'); $res = Invoke-Job $j.template $pp
  Write-Host ("{0} job {1} {2} rc={3} timeout={4} -> {5}" -f $started, $j.id, $j.template, $res.rc, $res.timedOut, (Send-Result $j $keyHash $res $started))
}

if ($Executor -and $DryRun) { Write-Host 'Executor is not started in -DryRun.' }
$last = [datetime]::MinValue
do {
  if (((Get-Date) - $last).TotalSeconds -ge $IntervalSec) { Send-Once; $last = Get-Date }
  if ($Executor -and -not $DryRun) { Invoke-ExecutorPoll; if (-not $Once) { Start-Sleep -Seconds $ExecPollSec } } elseif (-not $Once) { Start-Sleep -Seconds $IntervalSec }
} while (-not $Once)
