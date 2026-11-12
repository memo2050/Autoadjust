# Auto Adjust – Windows executor: DEVELOPMENT VM checklist (fill-in sheet)

**Windows support status: NOT TESTED.** Windows compatibility may be claimed only when all 19 REQUIRED rows are PASS and this sheet is filed. Detailed steps and expected results: `docs/WINDOWS-TEST-PROCEDURE.md`.

## Hard rules
- [ ] A **dedicated development VM** that you own and can delete (snapshot taken before the test). Not a production, customer, or shared host.
- [ ] Development Auto Adjust server and a **test organization** only. No production data.
- [ ] No network scanning. `net.reach`/`net.ping` only to **one registered test device** (exact IP/host name) of the same test organization.
- [ ] Executor runs as a **standard user** (not Administrator). Elevated run is only test W-04.
- [ ] API key created for this test only; revoke it afterwards. Never paste it in chat, screenshots, tickets or Git.
- [ ] Test copies of the script (for timeout / cap / redaction / environment tests) are separate files and are deleted afterwards.

## Environment record
| Item | Value |
|---|---|
| Date / tester | |
| Windows edition + build (`winver`) | |
| PowerShell version (`$PSVersionTable.PSVersion`) | |
| Script SHA256 (must equal the delivered file) | |
| Dev server URL / test org name | |
| VM snapshot name | |

## Required checks (all 19 must be PASS)
Result = PASS / FAIL / NOT TESTED. Evidence = screenshot or log file name (secrets removed).

| ID | Check | Result | Evidence | Notes |
|---|---|---|---|---|
| W-01 | Script parses with no syntax errors | | | |
| W-02 | Telemetry sample reaches the NOC (HTTP 200, device visible) | | | |
| W-03 | `-DryRun` sends nothing, polls no jobs | | | |
| W-04 | Executor refuses to run elevated (without `-AllowAdmin`) | | | |
| W-05 | `sys.uptime` succeeds end-to-end; requester recorded | | | |
| W-06 | `sys.mem`, `sys.disk`, `sys.cpu_top`, `sys.load`, `net.listen`, `dns.lookup`: real output or honest `unsupported`/`failed` | | | |
| W-07 | `svc.status`: allowed service works; non-allow-listed service refused | | | |
| W-08 | `log.tail` System and Application work | | | |
| W-09 | `log.tail` Security is rejected (server) and refused (host, with a signed test job) | | | |
| W-10 | `net.reach`/`net.ping`: registered target works; unregistered and `*` rejected; policy with wildcard/range makes net.* refuse | | | |
| W-11 | Replay: same job twice → second ignored | | | |
| W-12 | Tampered job / bad signature ignored | | | |
| W-13 | Timeout kills the process → `timed_out` | | | |
| W-14 | Output cap → truncated flag | | | |
| W-15 | Secrets redacted before leaving the host | | | |
| W-16 | Child process cannot see the API key (clean environment) | | | |
| W-17 | Missing / empty policy file → nothing runs | | | |
| W-18 | Server kill switch stops job delivery | | | |
| W-19 | Another organization's key cannot receive or register this host's jobs | | | |

## Optional (not required for sign-off)
| ID | Check | Result | Evidence |
|---|---|---|---|
| W-20 | Runs as a low-privilege scheduled task / service and survives reboot | | |
| W-21 | PowerShell 7 and Server Core behaviour documented | | |

## Sign-off
- Required rows PASS: ___ / 19 &nbsp;&nbsp; FAIL: ___ &nbsp;&nbsp; NOT TESTED: ___
- Any FAIL → fix → re-run that row and the whole sheet's dependent rows; record the date. Never change a FAIL to PASS without a re-run.
- Cleanup done: key revoked ☐ &nbsp; VM reverted/deleted ☐ &nbsp; test copies deleted ☐
- Tester signature / date: ______________________
