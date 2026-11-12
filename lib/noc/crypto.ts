// Credential encryption at rest. AES-256-GCM; the key comes from the NOC_SECRET_KEY environment variable and is never stored.
// If the key is missing, credentials are REFUSED (never stored in clear text).
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

export const cryptoConfigured = () => (process.env.NOC_SECRET_KEY ?? "").length >= 32;
const key = () => {
  const k = process.env.NOC_SECRET_KEY ?? "";
  if (k.length < 32) throw new Error("NOC_SECRET_KEY must be set (32+ characters) to store monitoring credentials.");
  return createHash("sha256").update(k).digest();
};
export function encryptJson(o: unknown): string {
  const iv = randomBytes(12), c = createCipheriv("aes-256-gcm", key(), iv), ct = Buffer.concat([c.update(JSON.stringify(o), "utf8"), c.final()]);
  return ["v1", iv.toString("base64"), c.getAuthTag().toString("base64"), ct.toString("base64")].join(".");
}
export function decryptJson<T = any>(s: string): T {
  const [v, iv, tag, ct] = s.split("."); if (v !== "v1") throw new Error("Unknown credential format");
  const d = createDecipheriv("aes-256-gcm", key(), Buffer.from(iv, "base64")); d.setAuthTag(Buffer.from(tag, "base64"));
  return JSON.parse(Buffer.concat([d.update(Buffer.from(ct, "base64")), d.final()]).toString("utf8"));
}
