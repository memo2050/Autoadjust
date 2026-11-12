// Server-side request forgery (SSRF) guard for every URL a customer types and OUR server then calls (Wazuh, Zabbix, automation webhooks).
// Rules: https only (http only when the operator opts in), no credentials in the URL, every resolved address must be public
// (loopback, link-local / cloud metadata, multicast are never allowed; private networks only with WAZUH_ALLOW_PRIVATE_TARGETS=1).
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { HttpError } from "../soc/pipeline";

/** True for addresses a customer-supplied URL must never make our server contact. */
export function blockedAddress(ip: string, allowPrivate: boolean): string | null {
  const v = ip.toLowerCase().replace(/^::ffff:/, "");
  if (isIP(v) === 4) {
    const [a, b] = v.split(".").map(Number);
    if (a === 127 || a === 0) return "loopback or unspecified address";
    if (a === 169 && b === 254) return "link-local / cloud metadata address";
    if (a >= 224) return "multicast or reserved address";
    if (!allowPrivate && (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127))) return "private network address";
    return null;
  }
  if (isIP(v) === 6) {
    if (v === "::1" || v === "::") return "loopback address";
    if (v.startsWith("fe80:")) return "link-local address";
    if (!allowPrivate && (v.startsWith("fc") || v.startsWith("fd"))) return "private network address";
    return null;
  }
  return "not an IP address";
}
export type Resolver = (host: string) => Promise<string[]>;
let defaultResolver: Resolver = async (h) => (await lookup(h, { all: true })).map((x) => x.address);
/** Tests only: replace DNS so fake host names resolve to a chosen address. */
export function __setResolverForTests(r: Resolver | null) { defaultResolver = r ?? (async (h) => (await lookup(h, { all: true })).map((x) => x.address)); }
export async function assertSafeTarget(raw: string, what: string, env: Record<string, string | undefined> = process.env, resolver: Resolver = defaultResolver, opt: { allowPath?: boolean; httpEnv?: string } = {}): Promise<string> {
  let u: URL; try { u = new URL(raw); } catch { throw new HttpError(400, `${what} is not a valid URL.`); }
  if (u.username || u.password) throw new HttpError(400, `${what} must not contain a user name or password; enter credentials in their own fields.`);
  if (u.protocol !== "https:" && !(u.protocol === "http:" && (env.WAZUH_ALLOW_HTTP === "1" || (!!opt.httpEnv && env[opt.httpEnv] === "1")))) throw new HttpError(400, `${what} must use https.`);
  if (u.search || (!opt.allowPath && u.pathname !== "/" && u.pathname !== "")) throw new HttpError(400, `${what} must be only the server address, for example https://wazuh.example.com:55000`);
  const host = u.hostname.replace(/^\[|\]$/g, ""), allowPrivate = env.WAZUH_ALLOW_PRIVATE_TARGETS === "1";
  const addrs = isIP(host) ? [host] : await resolver(host).catch(() => { throw new HttpError(400, `${what}: the host name ${host} cannot be resolved.`); });
  if (!addrs.length) throw new HttpError(400, `${what}: the host name ${host} has no address.`);
  for (const a of addrs) { const why = blockedAddress(a, allowPrivate); if (why) throw new HttpError(400, `${what} points to a ${why}, which this platform will not contact. ${why === "private network address" ? "A Wazuh server on a private network cannot be reached from the internet: run the bridge next to it (push mode) instead." : ""}`.trim()); }
  return opt.allowPath ? u.toString().replace(/\/+$/, "") : u.origin;
}

