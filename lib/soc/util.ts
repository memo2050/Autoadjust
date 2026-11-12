import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export const nowIso = () => new Date().toISOString();
export const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");
export const rid = (prefix: string) => `${prefix}_${randomBytes(8).toString("hex")}`;
export const hid = (prefix: string, s: string) => `${prefix}_${sha256(s).slice(0, 16)}`;
export const slug = (s: string) => s.trim().toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80) || "unknown";
export const ms = (iso: string) => Date.parse(iso);

/** Constant-time string equality (hashes both sides first so lengths never leak). */
export function safeEqual(a: string, b: string): boolean {
  return timingSafeEqual(createHash("sha256").update(a).digest(), createHash("sha256").update(b).digest());
}

export function newToken(): string { return "socs_" + randomBytes(32).toString("base64url"); }

export const clip = (s: unknown, n: number) => { const t = String(s ?? ""); return t.length > n ? t.slice(0, n) + "…" : t; };

export function isPrivateIp(ip: string): boolean {
  const v = ip.trim().toLowerCase();
  if (!v || v === "-" || v === "::1" || v === "127.0.0.1" || v === "::") return true;
  if (v.startsWith("fe80:") || v.startsWith("fc") || v.startsWith("fd")) return true;
  const m = v.replace(/^::ffff:/, "").match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
}

export const uniq = <T,>(xs: T[]) => Array.from(new Set(xs));

export class ApiError extends Error {
  constructor(public status: number, message: string, public extra?: Record<string, unknown>) { super(message); }
}
