// Per-organization Wazuh connection (Phase 2). Until now the Wazuh settings came ONLY from server-wide environment variables, so in a multi-organization
// deployment every organization's "Sync" would have pulled the platform operator's Wazuh data into its own workspace. Now:
//   * each organization stores its own connection in its own (org-namespaced) soc_meta row; passwords are AES-256-GCM encrypted (NOC_SECRET_KEY) and never returned;
//   * the server-wide environment settings are used only by the Default organization (the platform operator's own workspace);
//   * a URL typed by a customer is fetched BY OUR SERVER, so it is checked against server-side request forgery (SSRF): https only, no credentials in the URL,
//     no loopback / link-local / cloud-metadata addresses, and private networks only when the operator explicitly allows them.
import type { Store } from "./store";
import { T } from "./store";
import { audit, HttpError, type Actor } from "./pipeline";
import { decryptJson, encryptJson, cryptoConfigured } from "../noc/crypto";
import { nowIso } from "./util";
import { DEFAULT_ORG_ID } from "../tenant/scoped-store";
import { wazuhEnv, type WazuhCfg } from "./wazuh";

const ID = "wazuh-config";
export interface StoredWazuh { id: typeof ID; data: { apiUrl: string; apiUser: string; indexerUrl: string; indexerUser: string; index: string; minLevel: number; agentManager: string; enc: string; updatedAt: string; updatedBy: string } }

const isDefaultOrg = (s: Store) => !("orgId" in s) || (s as any).orgId === DEFAULT_ORG_ID;

export { blockedAddress, assertSafeTarget } from "../tenant/ssrf";
import { assertSafeTarget } from "../tenant/ssrf";

export async function saveWazuhConfig(store: Store, actor: Actor, b: any, env = process.env, resolver?: import("../tenant/ssrf").Resolver) {
  if (!cryptoConfigured()) throw new HttpError(409, "NOC_SECRET_KEY (32+ characters) is not set on the server, so credentials cannot be stored safely. Nothing was saved.");
  const s = (k: string, max = 200) => { const v = typeof b?.[k] === "string" ? b[k].trim() : ""; if (v.length > max) throw new HttpError(400, `${k} is too long`); return v; };
  const old = await store.get<StoredWazuh>(T.meta, ID); const prev = old ? safeDecrypt(old.data.enc) : null;
  const apiUser = s("apiUser", 100), indexerUser = s("indexerUser", 100), apiPassword = s("apiPassword", 300) || prev?.apiPassword || "", indexerPassword = s("indexerPassword", 300) || prev?.indexerPassword || "";
  if (!apiUser || !indexerUser || !apiPassword || !indexerPassword) throw new HttpError(400, "apiUser, apiPassword, indexerUser and indexerPassword are required.");
  const apiUrl = await assertSafeTarget(s("apiUrl"), "Manager API URL", env, resolver), indexerUrl = await assertSafeTarget(s("indexerUrl"), "Indexer URL", env, resolver);
  const min = Number(b?.minLevel ?? 7); if (!Number.isFinite(min) || min < 1 || min > 15) throw new HttpError(400, "minLevel must be between 1 and 15");
  const index = s("index", 80) || "wazuh-alerts-*"; if (!/^[A-Za-z0-9._*,-]+$/.test(index)) throw new HttpError(400, "index contains characters that are not allowed");
  const agentManager = s("agentManager", 255); if (agentManager && !/^[A-Za-z0-9.-]+$/.test(agentManager)) throw new HttpError(400, "agentManager must be a host name or IP address");
  await store.upsert(T.meta, [{ id: ID, data: { apiUrl, apiUser, indexerUrl, indexerUser, index, minLevel: min, agentManager, enc: encryptJson({ apiPassword, indexerPassword }), updatedAt: nowIso(), updatedBy: actor.name } } as StoredWazuh]);
  await audit(store, actor, "wazuh.config.save", "wazuh", { apiUrl, indexerUrl, index, minLevel: min, passwordsChanged: !!(s("apiPassword") || s("indexerPassword")) });
  return publicConfig((await store.get<StoredWazuh>(T.meta, ID))!);
}
function safeDecrypt(enc: string): { apiPassword: string; indexerPassword: string } | null { try { return decryptJson(enc); } catch { return null; } }
const publicConfig = (r: StoredWazuh) => ({ configured: true, apiUrl: r.data.apiUrl, apiUser: r.data.apiUser, indexerUrl: r.data.indexerUrl, indexerUser: r.data.indexerUser, index: r.data.index, minLevel: r.data.minLevel, agentManager: r.data.agentManager, passwordsStored: true, updatedAt: r.data.updatedAt, updatedBy: r.data.updatedBy, origin: "organization" as const });
export async function getWazuhConfigPublic(store: Store) {
  const r = await store.get<StoredWazuh>(T.meta, ID); if (r) return publicConfig(r);
  let env = false; try { env = isDefaultOrg(store) && !!wazuhEnv(); } catch { env = isDefaultOrg(store); }
  return { configured: env, origin: env ? ("server-environment" as const) : null };
}
export async function deleteWazuhConfig(store: Store, actor: Actor) { await store.remove(T.meta, { id: ID }); await audit(store, actor, "wazuh.config.delete", "wazuh", {}); return { removed: true }; }

/** The connection this organization may use: its own, or (Default organization only) the server environment. Never another organization's. */
export async function resolveWazuhCfg(store: Store, env: Record<string, string | undefined> = process.env, resolver?: import("../tenant/ssrf").Resolver): Promise<WazuhCfg | null> {
  const r = await store.get<StoredWazuh>(T.meta, ID);
  if (r) {
    // Re-check on every use: a host name that resolved to a public address when saved may resolve to an internal one later (DNS rebinding).
    await assertSafeTarget(r.data.apiUrl, "Manager API URL", env, resolver); await assertSafeTarget(r.data.indexerUrl, "Indexer URL", env, resolver); const sec = safeDecrypt(r.data.enc); if (!sec) throw new HttpError(500, "The stored Wazuh credentials cannot be decrypted (NOC_SECRET_KEY changed?). Save the connection again."); const d = r.data; return { apiUrl: d.apiUrl, apiUser: d.apiUser, apiPassword: sec.apiPassword, indexerUrl: d.indexerUrl, indexerUser: d.indexerUser, indexerPassword: sec.indexerPassword, index: d.index, minLevel: d.minLevel }; }
  return isDefaultOrg(store) ? wazuhEnv() : null;
}
export async function minLevelFor(store: Store): Promise<number> { const r = await store.get<StoredWazuh>(T.meta, ID); return r ? r.data.minLevel : Number(process.env.WAZUH_MIN_LEVEL ?? 7) || 7; }

// ---- agent enrollment (official Wazuh agent packages; Spark never installs anything itself) ----
export function enrollment(os: string, manager: string, version: string, agentName?: string) {
  if (!/^[A-Za-z0-9.-]+$/.test(manager)) throw new HttpError(400, "Set the agent connection address (agentManager) in the Wazuh connection first.");
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw new HttpError(400, "version must look like 4.9.2 and should match your Wazuh manager version.");
  const name = (agentName ?? "").replace(/[^A-Za-z0-9._-]/g, "").slice(0, 64), v = version, nm = name ? ` WAZUH_AGENT_NAME='${name}'` : "";
  const note = "Run on a computer you own or are authorized to monitor. The agent is the official package from packages.wazuh.com. Use the same major version as your manager (an agent must not be newer than the manager). If your manager requires a registration password, set WAZUH_REGISTRATION_PASSWORD yourself; Auto Adjust never stores it.";
  if (os === "windows") return { os, note, steps: [{ title: "Install (PowerShell as Administrator)", code: `Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-${v}-1.msi -OutFile $env:tmp\\wazuh-agent.msi\nmsiexec.exe /i $env:tmp\\wazuh-agent.msi /q WAZUH_MANAGER='${manager}' WAZUH_REGISTRATION_SERVER='${manager}'${nm}` }, { title: "Start", code: "NET START WazuhSvc" }, { title: "Optional: Windows Event Collector / Send-SecurityEvents.ps1", code: "The Wazuh agent already reads the Security, System and Sysmon event channels. The existing Send-SecurityEvents.ps1 collector stays available for computers without a Wazuh agent; give it an organization API key from the Account page as -Token." }] };
  if (os === "linux-deb") return { os, note, steps: [{ title: "Install (Debian/Ubuntu)", code: `curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${v}-1_amd64.deb && sudo WAZUH_MANAGER='${manager}'${nm} dpkg -i ./wazuh-agent.deb` }, { title: "Start", code: "sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent" }] };
  if (os === "linux-rpm") return { os, note, steps: [{ title: "Install (RHEL/Rocky/Alma/Amazon Linux)", code: `curl -o wazuh-agent.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-${v}-1.x86_64.rpm && sudo WAZUH_MANAGER='${manager}'${nm} rpm -ihv wazuh-agent.rpm` }, { title: "Start", code: "sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent" }] };
  throw new HttpError(400, "os must be windows, linux-deb or linux-rpm");
}
