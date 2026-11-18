export type DemoRequest = { name: string; email: string; company: string; message: string };
const EMAIL = /^[^\s@<>]{1,64}@[^\s@<>]{1,190}\.[^\s@<>]{2,}$/;
const clean = (v: unknown, max: number) => (typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, max) : "");
/** Validates the public "Request a Demo" form. Returns the cleaned request or an error string. Honeypot field `website` must be empty. */
export function parseDemoRequest(b: unknown): { ok: true; value: DemoRequest } | { ok: false; error: string } {
  if (!b || typeof b !== "object") return { ok: false, error: "Invalid request." };
  const o = b as Record<string, unknown>;
  if (typeof o.website === "string" && o.website.length > 0) return { ok: false, error: "Invalid request." };
  const name = clean(o.name, 120), email = clean(o.email, 200).toLowerCase(), company = clean(o.company, 160), message = clean(o.message, 2000);
  if (!name) return { ok: false, error: "Please enter your name." };
  if (!EMAIL.test(email)) return { ok: false, error: "Please enter a valid email address." };
  return { ok: true, value: { name, email, company, message } };
}
