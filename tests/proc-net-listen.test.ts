// net.listen fallback (/proc/net parser used when `ss` is not installed). Tests the REAL bash function extracted from the agent script, against fixtures
// and against the real /proc/net of this machine with an independent Python parser as the cross-check.
import test from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync, execFileSync } from "node:child_process";

const SH = readFileSync(new URL("../collector/noc-agent/auto-adjust-linux-agent.sh", import.meta.url), "utf8");
const FN = SH.slice(SH.indexOf("# BEGIN proc_listen"), SH.indexOf("# END proc_listen"));
const tmp = mkdtempSync(join(tmpdir(), "aa-pl-")); const FNFILE = join(tmp, "fn.sh"); writeFileSync(FNFILE, FN);
const run = (dir: string, env: Record<string, string> = { PATH: process.env.PATH! }) => { const r = spawnSync("bash", ["-c", `set -u; source ${FNFILE}; proc_listen "$1"`, "x", dir], { encoding: "utf8", env }); return { rc: r.status, out: r.stdout, err: r.stderr }; };
// Real kernels label the remote column "rem_address" in tcp/udp but "remote_address" in tcp6/udp6 (found on a GitHub runner, kernel 7.0; the sandbox has no IPv6 proc files).
const HDR6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
const HDR4 = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
const row = (i: number, la: string, st: string, ra = "00000000:0000") => `  ${i}: ${la} ${ra} ${st} 00000000:00000000 00:00000000 00000000     0        0 ${1000 + i} 1 0000000000000000 100 0 0 10 0\n`;
const mk = (files: Record<string, string>) => { const d = mkdtempSync(join(tmp, "p-")); for (const [k, v] of Object.entries(files)) writeFileSync(join(d, k), v); return d; };
const row6 = (i: number, la: string, st: string) => row(i, la, st, "0".repeat(32) + ":0000");
const rows = (out: string) => out.split("\n").filter((l) => /^(tcp|udp) /.test(l));
const unsupportedOnly = (r: { rc: number | null; out: string }, why: RegExp) => { assert.equal(r.rc, 127); assert.match(r.out, /^UNSUPPORTED: /); assert.match(r.out, why); assert.equal(r.out.trim().split("\n").length, 1, "no partial rows are ever printed with an UNSUPPORTED result"); };

test("normal IPv4: TCP LISTEN and UDP unconnected only; other states are excluded; port is big-endian hex, address little-endian", () => {
  const d = mk({ tcp: HDR4 + row(0, "00000000:0016", "0A") + row(1, "0100007F:1F90", "0A") + row(2, "0500000A:C350", "01", "0600000A:01BB") + row(3, "0100007F:0035", "0a"), udp: HDR4 + row(0, "00000000:0044", "07") + row(1, "0100007F:E123", "01", "08080808:0035") });
  const r = run(d); assert.equal(r.rc, 0); assert.deepEqual(rows(r.out), ["tcp LISTEN 0.0.0.0:22", "tcp LISTEN 127.0.0.1:8080", "tcp LISTEN 127.0.0.1:53", "udp UNCONN 0.0.0.0:68"]);
  assert.match(r.out, /^# origin: \/proc\/net fallback \(ss is not installed\).*ipv6 files: absent/); assert.match(r.out, /\nNetid State Local-Address:Port\n/);
});
test("IPv6: :: and ::1 and a global address decode correctly; v4-mapped is shown in documented uncompressed form", () => {
  const H6 = HDR6, z = "00000000000000000000000000000000";
  const d = mk({ tcp: HDR4, udp: HDR4 + row(0, "00000000:0044", "07"), tcp6: H6 + row6(0, z + ":0016", "0A") + row6(1, "00000000000000000000000001000000:0277", "0A") + row6(2, "B80D01200000000000000000" + "01000000:01BB", "0A") + row6(3, "0000000000000000FFFF00000100000A:1F90", "0A"), udp6: H6 + row6(0, z + ":0035", "07") });
  const r = run(d); assert.equal(r.rc, 0, r.out); assert.deepEqual(rows(r.out), ["udp UNCONN 0.0.0.0:68", "tcp LISTEN [::]:22", "tcp LISTEN [::1]:631", "tcp LISTEN [2001:db8:0:0:0:0:0:1]:443", "tcp LISTEN [0:0:0:0:0:ffff:a00:1]:8080", "udp UNCONN [::]:53"]);
  assert.match(r.out, /ipv6 files: present/);
});
test("no listeners but other sockets exist: reported plainly as none found (reliable), not as an error", () => {
  const r = run(mk({ tcp: HDR4 + row(0, "0500000A:C350", "01", "0600000A:01BB"), udp: HDR4 })); assert.equal(r.rc, 0); assert.deepEqual(rows(r.out), []); assert.match(r.out, /no listening sockets found; 1 sockets in other states were seen/);
});
test("UNSUPPORTED (never success) when the result could be incomplete or ambiguous", () => {
  const ok4 = HDR4 + row(0, "00000000:0016", "0A");
  unsupportedOnly(run(mk({ udp: ok4 })), /tcp does not exist/); unsupportedOnly(run(mk({ tcp: ok4 })), /udp does not exist/);
  unsupportedOnly(run(mk({ tcp: HDR4, udp: HDR4 })), /no sockets visible/);                                   // zero sockets of any state: ambiguous
  unsupportedOnly(run(mk({ tcp: "garbage header\n" + row(0, "00000000:0016", "0A"), udp: ok4 })), /unexpected header/);
  unsupportedOnly(run(mk({ tcp: "", udp: ok4 })), /empty/);
  const d6 = mk({ tcp: ok4, udp: ok4 }); mkdirSync(join(d6, "tcp6")); unsupportedOnly(run(d6), /empty|cannot read/);   // IPv6 file present but unreadable as a file
  for (const [name, bad] of [["short address", row(1, "0000000:0016", "0A")], ["non-hex address", row(1, "0000000G:0016", "0A")], ["bad port", row(1, "00000000:00G6", "0A")], ["bad state", row(1, "00000000:0016", "ZZ")], ["no index", "  x 00000000:0016 00000000:0000 0A 0 0 0\n"], ["truncated row", "  1: 00000000:0016\n"], ["v6 address in v4 file", row(1, "00000000000000000000000000000000:0016", "0A")]] as const)
    unsupportedOnly(run(mk({ tcp: ok4 + bad + row(2, "0100007F:0050", "0A"), udp: ok4 })), /malformed|unexpected/);   // valid rows before AND after the bad one: still nothing partial
  unsupportedOnly(run(mk({ tcp: ok4, udp: ok4, tcp6: HDR4 + row(1, "0100007F:0050", "0A"), udp6: HDR4 })), /malformed address/);   // 8-hex address in a tcp6 file
  unsupportedOnly(run(mk({ tcp: ok4, udp: ok4, tcp6: HDR4 })), /only one of tcp6\/udp6/);   // inconsistent IPv6 state   // 8-hex address in a tcp6 file
});
test("the fallback is pure bash builtins: it runs with an EMPTY PATH (no external program) and contains no eval / command substitution / backticks", () => {
  const d = mk({ tcp: HDR4 + row(0, "00000000:0016", "0A"), udp: HDR4 + row(0, "00000000:0044", "07") });
  const r = spawnSync("/bin/bash", ["-c", `set -u; source ${FNFILE}; proc_listen "$1"`, "x", d], { encoding: "utf8", env: { PATH: "" } }); assert.equal(r.status, 0, r.stderr + r.stdout); assert.ok(rows(r.stdout).length === 2);
  const code = FN.split("\n").filter((l) => !l.trim().startsWith("#")).join("\n"); assert.ok(!/\beval\b|`|\$\(\s*[a-z]|\bsource\b|\bexec\b|\bsh -c\b|\bcurl\b/.test(code.replace(/\$\(\(/g, "")), "no eval, backticks, command substitution or external call");
});
test("real /proc/net with a real listener: output equals an INDEPENDENT Python parse and contains the listener's port", async () => {
  const srv = net.createServer(); await new Promise<void>((r) => srv.listen(0, "0.0.0.0", r)); const port = (srv.address() as any).port;
  try {
    const r = run("/proc/net"); assert.equal(r.rc, 0, r.out); const mine = new Set(rows(r.out));
    const py = `
import socket,struct
def v4(h): return socket.inet_ntoa(struct.pack("<I",int(h,16)))
out=set()
for f,net,want in (("tcp","tcp","0A"),("udp","udp","07")):
    for l in open("/proc/net/"+f).read().splitlines()[1:]:
        p=l.split()
        a,pt=p[1].split(":")
        if p[3].upper()==want: out.add(("tcp LISTEN " if net=="tcp" else "udp UNCONN ")+v4(a)+":"+str(int(pt,16)))
print("\\n".join(sorted(out)))`;
    const theirs = new Set(execFileSync("python3", ["-I", "-c", py], { encoding: "utf8" }).split("\n").filter(Boolean));
    const v4mine = new Set([...mine].filter((x) => !x.includes("["))); assert.deepEqual([...v4mine].sort(), [...theirs].sort());
    assert.ok(mine.has(`tcp LISTEN 0.0.0.0:${port}`), "the real listener is listed");
  } finally { srv.close(); }
});

test("real-kernel IPv6 header (remote_address) is accepted; an unknown column name is still refused", () => {
  const z = "0".repeat(32), ok4 = HDR4 + row(0, "00000000:0016", "0A");
  const good = run(mk({ tcp: ok4, udp: HDR4 + row(0, "00000000:0044", "07"), tcp6: HDR6 + row6(0, z + ":0016", "0A"), udp6: HDR6 })); assert.equal(good.rc, 0, good.out); assert.ok(rows(good.out).some((r) => r.includes("[::]:22")), good.out);
  unsupportedOnly(run(mk({ tcp: ok4, udp: ok4, tcp6: HDR6.replace("remote_address", "peer_address"), udp6: HDR6 })), /unexpected header/);
});
