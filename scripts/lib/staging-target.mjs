// Single place that decides which addresses the staging smoke test and load test may touch.
// Policy: localhost/127.0.0.1 (self-tests) or an EXACT hostname from the list below over HTTPS. Nothing else; no wildcards, no suffix or substring matching.
// To approve another staging host, add its full hostname here in a reviewed change.
export const APPROVED_STAGING_HOSTS = Object.freeze(["stellar-purple-horse-66.hostingersite.com"]);
const LOCAL = new Set(["localhost", "127.0.0.1"]);
/** @returns {{ ok: true, base: string, host: string } | { ok: false, reason: string }} */
export function checkStagingUrl(raw) {
  const s = String(raw ?? "").trim();
  if (!s) return { ok: false, reason: "STAGING_URL is empty" };
  let u; try { u = new URL(s); } catch { return { ok: false, reason: "STAGING_URL is not a valid URL" }; }
  if (u.username || u.password) return { ok: false, reason: "STAGING_URL must not contain credentials" };
  if (u.search || u.hash || (u.pathname && u.pathname !== "/")) return { ok: false, reason: "STAGING_URL must be an origin only (no path, query or fragment)" };
  const host = u.hostname.toLowerCase();
  if (LOCAL.has(host)) return u.protocol === "http:" || u.protocol === "https:" ? { ok: true, base: u.origin, host } : { ok: false, reason: "unsupported protocol" };
  if (APPROVED_STAGING_HOSTS.includes(host)) return u.protocol === "https:" && !u.port ? { ok: true, base: u.origin, host } : { ok: false, reason: "approved staging host must use HTTPS on the default port" };
  return { ok: false, reason: "hostname is not an approved staging host" };
}
