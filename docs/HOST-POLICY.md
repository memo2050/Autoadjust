# Auto Adjust executor – host-local policy (v1.2)

The host owner, not the server, decides what may run on a host. **Fail closed:** no policy file (or an empty one) means nothing runs. The server's catalog and the host policy must BOTH allow a job.

Location: Linux `EXECUTOR_POLICY` (default `/etc/auto-adjust/executor-policy.conf`); Windows `-PolicyFile` (default `%ProgramData%\AutoAdjust\executor-policy.conf`). Make it writable only by root/Administrators.

## Rules (one per line, exact match, no comments inside a rule line)
| Rule | Meaning |
|---|---|
| `template <id>` | Allow this catalog template on this host (e.g. `template sys.uptime`). |
| `service <unit>` | Allow `svc.status` for this exact service/unit. |
| `logunit <unit>` | Allow Linux `log.tail` for this exact unit. (Windows `log.tail` is fixed to Application and System.) |
| `target <exact IPv4 or host name>` | Allow `net.reach` / `net.ping` to exactly this target. |

## There are no wildcards
`target *`, `target 10.0.0.*`, ranges, CIDR (`10.0.0.0/24`) and patterns are **not supported**. If the policy file contains any `target` rule that is not an exact IPv4 address or host name, **every net.\* job is refused** ("host policy has an invalid or wildcard target rule") so the mistake is visible. (Removed in v1.2; covered by `tests/live/executor-e2e.ts` for `*`, `10.0.0.*`, CIDR, `*.example.com`, `?`.)

## Targets must be registered devices of the same organization
Three independent checks, all required:
1. **Server:** the target IP/name must belong to a device registered in the authenticated organization (other organizations' devices, unregistered addresses, loopback, 0.0.0.0, link-local/cloud-metadata 169.254/16 and multicast/reserved are refused and audited).
2. **Signature/host binding:** the job is signed for this organization's key and this host only.
3. **Host policy:** the exact target must be listed above.

## Example
```
template sys.uptime
template sys.mem
template net.ping
template net.reach
template svc.status
service nginx.service
target 10.0.0.6
target db01.corp.example
```
