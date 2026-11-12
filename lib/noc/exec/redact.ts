// Removes secrets from anything that is logged, audited or stored from host output. Applied on the host (executor) AND again on the server.
const RULES: [RegExp, string][] = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g, "[REDACTED PRIVATE KEY]"],
  [/aa_live_[A-Za-z0-9_-]{8,}/g, "[REDACTED API KEY]"],
  [/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, "[REDACTED JWT]"],
  [/\b(Bearer|Basic)\s+[A-Za-z0-9._~+\/=-]{8,}/gi, "$1 [REDACTED]"],
  [/\b(AKIA|ASIA)[A-Z0-9]{16}\b/g, "[REDACTED AWS KEY]"],
  [/\b(gh[pousr]_[A-Za-z0-9]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,})\b/g, "[REDACTED TOKEN]"],
  [/((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|auth|credential|private[_-]?key|access[_-]?key)[A-Za-z0-9_.-]*\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s,;&]+)/gi, "$1[REDACTED]"],
  [/(\/\/[^\/\s:@]+:)[^@\s\/]+@/g, "$1[REDACTED]@"],
];
export function redact(s: string): string { let o = String(s ?? ""); for (const [re, to] of RULES) o = o.replace(re, to); return o; }
export function redactDeep<T>(v: T, depth = 0): T {
  if (typeof v === "string") return redact(v) as any;
  if (depth > 6 || v == null || typeof v !== "object") return v;
  if (Array.isArray(v)) return v.map((x) => redactDeep(x, depth + 1)) as any;
  return Object.fromEntries(Object.entries(v as any).map(([k, x]) => [k, /^(pass(word)?|passwd|secret|token|api_?key|credential|authorization|private_?key)$/i.test(k) && typeof x === "string" ? "[REDACTED]" : redactDeep(x, depth + 1)])) as any;
}
