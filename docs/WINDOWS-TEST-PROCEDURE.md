# Auto Adjust – Windows agent & executor: real-host test procedure

**Status today: NOT TESTED.** The PowerShell agent (`Auto-Adjust-Windows-Agent.ps1`, telemetry and `-Executor`) has never been run on Windows, and has not even been syntax-checked (no PowerShell was available in the build environment). Do not describe it as Windows-compatible until every REQUIRED row below is PASS on a real host and the sheet is filed.

## 0. Rules for this test
- Use a **disposable Windows VM you own** (Windows 10/11 or Server 2019+, PowerShell 5.1 as shipped). Not a customer host, not production.
- Point it at the **development** Auto Adjust server only. No network scanning. `net.reach`/`net.ping` only to registered devices of the test org.
- Run the executor as a **standard (non-admin) user**. Do not use `-AllowAdmin` except in test W-12.
- Record each row as **PASS**, **FAIL** or **NOT TESTED**. Anything not run stays NOT TESTED. Never edit a FAIL into a PASS; fix, then re-run and note the date.

## 1. Setup (screenshots of each step, please)
1. Create a test org in the dev server; as owner create an API key (name `win-test`). Keep it out of screenshots.
2. On the VM, sign in as a standard user `aatest`. Copy `Auto-Adjust-Windows-Agent.ps1` and confirm its hash equals the one in the delivered zip: `Get-FileHash .\Auto-Adjust-Windows-Agent.ps1 -Algorithm SHA256`.
3. Syntax check first (no execution): `powershell -NoProfile -Command "$e=$null;[void][System.Management.Automation.Language.Parser]::ParseFile('.\Auto-Adjust-Windows-Agent.ps1',[ref]$null,[ref]$e);$e"` → must print nothing.
4. Create the policy file `C:\ProgramData\AutoAdjust\executor-policy.conf` (readable by `aatest`, writable only by Administrators) with exactly:
```
template sys.uptime
template sys.mem
template sys.disk
template sys.cpu_top
template sys.load
template svc.status
template net.listen
template net.reach
template net.ping
template dns.lookup
template log.tail
service Spooler
target <exact IP or host name of a second test device you registered>   # exact values only: wildcards/ranges are not supported and make net.* refuse
```
5. Set `SPARK_URL` and `SPARK_INGEST_TOKEN` (the key) in the aatest session and start: `.\Auto-Adjust-Windows-Agent.ps1 -Once -Executor -DeviceName WINTEST01`.
6. In the dashboard (`/agents.html`) register the executor: host `WINTEST01`, OS `windows`, bound to the key; owner switches execution ON.

## 2. Test sheet
| ID | Required | Step | Expected | Result | Evidence |
|---|---|---|---|---|---|
| W-01 | REQ | Syntax check (step 3) | No parse errors | NOT TESTED | |
| W-02 | REQ | Telemetry: run agent `-Once` (no `-Executor`) | Device `WINTEST01` appears in NOC with CPU/mem/disk; HTTP 200 | NOT TESTED | |
| W-03 | REQ | Run `-Once -DryRun` | Prints payload, sends nothing; no job polling | NOT TESTED | |
| W-04 | REQ | Executor refuses elevated | Start from an elevated prompt without `-AllowAdmin` → warning "refuses to run elevated", nothing polled | NOT TESTED | |
| W-05 | REQ | Request `sys.uptime` from dashboard, run agent `-Once -Executor` | Job `succeeded`; output shows boot time; requester recorded | NOT TESTED | |
| W-06 | REQ | Each of `sys.mem`, `sys.disk`, `sys.cpu_top`, `sys.load`, `net.listen`, `dns.lookup` | `succeeded` with real output, or `unsupported`/`failed` **honestly** (never succeeded with empty/garbage output) | NOT TESTED | |
| W-07 | REQ | `svc.status` for `Spooler`; then for a service **not** in policy | First: real state. Second: refused ("not in local policy") | NOT TESTED | |
| W-08 | REQ | `log.tail` log=`System` n=20, then `Application` n=20 | `succeeded` with event lines | NOT TESTED | |
| W-09 | REQ | `log.tail` log=`Security` (via API/curl, UI does not offer it) | Rejected by the server (400). Also craft a *signed* job with log=Security in a test stub: executor refuses | NOT TESTED | |
| W-10 | REQ | `net.reach` / `net.ping` to the registered test device; then to an unregistered IP; then `*` | First works; unregistered IP and `*` rejected by the server; with a stub, a policy file containing `target *` or `10.0.0.0/24` makes net.reach/net.ping refuse | NOT TESTED | |
| W-11 | REQ | Replay: run agent twice for the same job; keep state dir | Second run: "already seen (replay)", nothing executed | NOT TESTED | |
| W-12 | REQ | Tamper: edit job params in a stub server and send with old signature | "IGNORED: bad signature"; nothing executed | NOT TESTED | |
| W-13 | REQ | Timeout: temporarily set a template `t=2` and a long command (test copy of the script only) | Process killed, status `timed_out` | NOT TESTED | |
| W-14 | REQ | Output cap: force >16 KB output in the test copy | Output truncated, `truncated=true` | NOT TESTED | |
| W-15 | REQ | Redaction: command output containing `password=abc123` and `Bearer eyJ...` (test copy) | Both redacted before leaving the host | NOT TESTED | |
| W-16 | REQ | Clean environment: command prints env (test copy) | `SPARK_INGEST_TOKEN` not visible | NOT TESTED | |
| W-17 | REQ | Missing policy file / empty policy | Nothing runs; jobs refused ("not enabled in local policy") | NOT TESTED | |
| W-18 | REQ | Server-side kill switch (owner turns execution OFF) | Next poll returns no jobs | NOT TESTED | |
| W-19 | REQ | Cross-org: use a key of another org against this host id | No job delivered / registration refused | NOT TESTED | |
| W-20 | OPT | Run as a Windows service / scheduled task under a low-privilege account; reboot; confirm it resumes | Works without admin | NOT TESTED | |
| W-21 | OPT | PowerShell 7 and Windows Server Core | Documented behaviour | NOT TESTED | |

## 3. Known risks to watch for (not yet verified; I expect to need fixes)
- The `Test-Policy` helper uses `Select-String -SimpleMatch` plus an exact line compare; verify it does not match substrings (policy `service Spooler` must not allow `Spool`).
- `ParseFile`/execution of the `$XT` table: the here-string/backtick escaping of the Windows command texts has never been parsed.
- `Get-Counter '\System\Processor Queue Length'` and `Get-NetTCPConnection` availability on Server Core; the agent should report `unsupported`, not fail silently.
- Localized Windows: the Windows `UNSUPPORTED:` detection uses `Get-Command`; confirm on a non-English OS.
- Argument quoting in `ProcessStartInfo.Arguments` (double quotes escaped with backslash) for the `log.tail` command containing quotes.

## 4. Sign-off
Windows compatibility may be claimed only when W-01…W-19 are PASS. Attach the filled sheet, screenshots, script hash and the Windows build number. Until then the product documentation must say: *"Windows executor: not yet validated."*
