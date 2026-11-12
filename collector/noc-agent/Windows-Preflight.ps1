# Auto Adjust - Windows VM PREFLIGHT (development VM only). Automates the checks that need no server: environment record, script hash, W-01 syntax, W-03 dry-run.
# Writes preflight-result.txt next to this script. Sends nothing anywhere. NOT YET RUN BY ANYONE (no PowerShell in the build sandbox): if it errors, that is itself a finding - send the file.
# Usage (standard, non-admin PowerShell):  powershell -NoProfile -ExecutionPolicy Bypass -File .\Windows-Preflight.ps1
$ErrorActionPreference = 'Continue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path; $agent = Join-Path $dir 'Auto-Adjust-Windows-Agent.ps1'; $out = Join-Path $dir 'preflight-result.txt'
$L = New-Object System.Collections.Generic.List[string]; function Log($s) { $L.Add($s); Write-Host $s }
Log "Auto Adjust Windows preflight - $((Get-Date).ToUniversalTime().ToString('o'))"
Log "Windows: $((Get-CimInstance Win32_OperatingSystem).Caption) build $((Get-CimInstance Win32_OperatingSystem).BuildNumber)"
Log "PowerShell: $($PSVersionTable.PSVersion)"
$elev = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Log "Elevated: $elev   (the real test must run NON-elevated; elevated is only for W-04)"
if (-not (Test-Path $agent)) { Log "FAIL: $agent not found"; $L | Set-Content $out; exit 1 }
Log "Agent SHA256: $((Get-FileHash $agent -Algorithm SHA256).Hash)   (compare with the hash in the delivery notes)"
$errs = $null; [void][System.Management.Automation.Language.Parser]::ParseFile($agent, [ref]$null, [ref]$errs)
if ($errs -and $errs.Count) { Log "W-01 FAIL: $($errs.Count) syntax error(s):"; $errs | ForEach-Object { Log "   line $($_.Extent.StartLineNumber): $($_.Message)" } } else { Log "W-01 PASS: no syntax errors" }
$env:SPARK_URL = ''; $env:SPARK_INGEST_TOKEN = ''
try { $o = & powershell -NoProfile -ExecutionPolicy Bypass -File $agent -Once -DryRun -DeviceName PREFLIGHT01 2>&1 | Out-String; $rc = $LASTEXITCODE
  Log "W-03 dry-run exit code: $rc"; Log "W-03 dry-run output (first 40 lines):"; ($o -split "`r?`n" | Select-Object -First 40) | ForEach-Object { Log "   $_" }
  Log "W-03 judgement: PASS only if it printed a payload, exit code 0, and it contacted no server (no URL was configured) - judge from the output above." } catch { Log "W-03 FAIL: $($_.Exception.Message)" }
$L | Set-Content $out -Encoding UTF8; Log "Saved: $out"
