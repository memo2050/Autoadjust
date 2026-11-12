<#
.SYNOPSIS
  Read-only collector: sends recent Windows Security, System and Defender events to your Spark SOC server.

.DESCRIPTION
  Run it on a Windows computer that you own or are authorized to monitor, in an elevated PowerShell (reading the Security log needs admin rights).
  It only READS event logs and POSTs them over HTTPS to your server. It changes nothing on the machine.
  It remembers the last record it sent per log in a small state file, so each run sends only new events.
  NOTE: this script was written without access to a Windows machine and has not been run by its author. Test it with -DryRun first.

.PARAMETER Url      Base URL of your Spark site, e.g. https://soc.example.com
.PARAMETER Token    The value of SOC_INGEST_TOKEN configured on the server.
.PARAMETER Hours    First run only: how many hours back to read (default 24).
.PARAMETER Loop     Keep running and send new events every -IntervalSeconds seconds.
.PARAMETER DryRun   Collect and show counts but send nothing.

.EXAMPLE
  .\Send-SecurityEvents.ps1 -Url https://soc.example.com -Token $env:SOC_INGEST_TOKEN -DryRun
  .\Send-SecurityEvents.ps1 -Url https://soc.example.com -Token $env:SOC_INGEST_TOKEN -Loop
#>
param(
  [Parameter(Mandatory = $true)][string]$Url,
  [Parameter(Mandatory = $true)][string]$Token,
  [int]$Hours = 24,
  [switch]$Loop,
  [int]$IntervalSeconds = 120,
  [switch]$DryRun,
  [string]$StateFile = (Join-Path $env:ProgramData 'SparkSoc\state.json')
)
$ErrorActionPreference = 'Stop'
if ($Url -notmatch '^https://' -and $Url -notmatch '^http://(localhost|127\.0\.0\.1)') { throw 'Use an https:// URL (plain http is only allowed for localhost testing).' }
$endpoint = $Url.TrimEnd('/') + '/api/soc/ingest/windows'

# Which events to read. Security needs auditing enabled (Logon, Process Creation with command line, Account Management, Policy Change).
$sources = @(
  @{ Log = 'Security'; Ids = 4624,4625,4648,4672,4688,4698,4719,4720,4722,4728,4732,4740,4756,1102 },
  @{ Log = 'System'; Ids = 7045,104 },
  @{ Log = 'Microsoft-Windows-Windows Defender/Operational'; Ids = 1116,1117,5001 },
  @{ Log = 'Application'; Ids = 1000,1002,1026 },
  # Sysmon is optional. If it is not installed this source is skipped. Install it with a reviewed config (for example SwiftOnSecurity's).
  @{ Log = 'Microsoft-Windows-Sysmon/Operational'; Ids = 1,3,8,10,11,13,22; Max = 5000 }
)
$CollectorVersion = '2.0'

function Get-State { if (Test-Path $StateFile) { try { return Get-Content $StateFile -Raw | ConvertFrom-Json -AsHashtable } catch {} }; return @{} }
function Save-State($s) { $d = Split-Path $StateFile; if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }; $s | ConvertTo-Json | Set-Content -Path $StateFile -Encoding UTF8 }

function Convert-Event($e) {
  $xml = [xml]$e.ToXml()
  $data = @{}
  foreach ($d in $xml.Event.EventData.Data) { if ($d.Name) { $data[$d.Name] = [string]$d.'#text' } }
  [ordered]@{
    Id = [int]$e.Id; RecordId = [long]$e.RecordId; TimeCreated = $e.TimeCreated.ToUniversalTime().ToString('o')
    ProviderName = $e.ProviderName; LogName = $e.LogName; MachineName = $e.MachineName; LevelDisplayName = $e.LevelDisplayName; Data = $data
  }
}

function Send-Once {
  $state = Get-State
  $batch = New-Object System.Collections.Generic.List[object]
  $maxSeen = @{}
  foreach ($src in $sources) {
    $log = $src.Log
    $last = if ($state.ContainsKey($log)) { [long]$state[$log] } else { 0 }
    $filter = @{ LogName = $log; Id = $src.Ids }
    if ($last -eq 0) { $filter.StartTime = (Get-Date).AddHours(-$Hours) }
    try {
      if ($src.Max) { $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $src.Max -ErrorAction Stop } else { $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop }
    } catch {
      if ($_.Exception.Message -match 'No events were found') { $events = @() }
      elseif ($_.Exception.Message -match 'not an event log|could not be found') { Write-Host "Log not present on this computer, skipping: $log"; continue }
      else { Write-Warning "Cannot read ${log}: $($_.Exception.Message)"; continue }
    }
    foreach ($e in ($events | Sort-Object RecordId)) {
      if ($e.RecordId -le $last) { continue }
      $batch.Add((Convert-Event $e)); if (-not $maxSeen.ContainsKey($log) -or $e.RecordId -gt $maxSeen[$log]) { $maxSeen[$log] = [long]$e.RecordId }
    }
  }
  Write-Host ("{0} new events collected" -f $batch.Count)
  if ($DryRun) { return }
  if ($batch.Count -eq 0) {
    # Heartbeat: tell the server this computer is alive even though nothing new happened.
    $hb = @{ host = $env:COMPUTERNAME; collector = 'Send-SecurityEvents.ps1'; version = $CollectorVersion; events = @() } | ConvertTo-Json -Depth 4 -Compress
    Invoke-RestMethod -Method Post -Uri $endpoint -Headers @{ Authorization = "Bearer $Token" } -ContentType 'application/json; charset=utf-8' -Body ([System.Text.Encoding]::UTF8.GetBytes($hb)) | Out-Null
    Write-Host 'heartbeat sent'
    return
  }
  $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | ForEach-Object { $_.IPAddress })
  $os = (Get-CimInstance Win32_OperatingSystem).Caption
  for ($i = 0; $i -lt $batch.Count; $i += 1000) {
    $chunk = $batch.GetRange($i, [Math]::Min(1000, $batch.Count - $i))
    $body = @{ host = $env:COMPUTERNAME; ips = $ips; os = $os; collector = 'Send-SecurityEvents.ps1'; version = $CollectorVersion; events = $chunk } | ConvertTo-Json -Depth 8 -Compress
    $r = Invoke-RestMethod -Method Post -Uri $endpoint -Headers @{ Authorization = "Bearer $Token" } -ContentType 'application/json; charset=utf-8' -Body ([System.Text.Encoding]::UTF8.GetBytes($body))
    Write-Host ("sent {0}: accepted {1}, rejected {2}, new alerts {3}" -f $chunk.Count, $r.accepted, $r.rejected.Count, $r.newAlerts)
  }
  # Only advance the bookmark after every batch was accepted by the server.
  foreach ($k in $maxSeen.Keys) { $state[$k] = $maxSeen[$k] }
  Save-State $state
}

do {
  try { Send-Once } catch { Write-Warning $_.Exception.Message }
  if ($Loop) { Start-Sleep -Seconds $IntervalSeconds }
} while ($Loop)
