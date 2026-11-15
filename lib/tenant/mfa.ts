import type { Store } from "../soc/store";
import type { Principal } from "./auth";
import { AuthError } from "./auth";

/** MFA is enforced by the API (not only by the sign-in page). Off unless MFA_ENFORCE=on, so existing deployments are unchanged until the owner turns it on.
 *  When on, a signed-in user must hold an aal2 session (Supabase TOTP verified) to change anything if they are an owner/it_admin, a platform admin,
 *  or a member of an organization that turned on "require MFA for everyone". Reads are not blocked, so the dashboard still loads and can show the enrolment prompt. */
export const mfaEnforced = (env: NodeJS.ProcessEnv) => (env.MFA_ENFORCE ?? "off").toLowerCase() === "on";
export const PRIVILEGED = ["owner", "it_admin"];

export async function orgRequiresMfa(raw: Store, orgId: string): Promise<boolean> {
  const [o] = await raw.select<{ settings?: Record<string, unknown> }>("organizations", { where: { id: orgId }, limit: 1 });
  return o?.settings?.requireMfa === true;
}
export async function mfaStatus(raw: Store, pr: Principal, env: NodeJS.ProcessEnv) {
  const orgWide = await orgRequiresMfa(raw, pr.orgId);
  const privileged = pr.kind === "user" && (PRIVILEGED.includes(pr.orgRole ?? "") || pr.platformAdmin);
  const required = pr.kind === "user" && (privileged || orgWide);
  return { enforced: mfaEnforced(env), verified: pr.aal === "aal2", required, orgRequiresMfa: orgWide, privileged };
}
export async function enforceMfa(raw: Store, pr: Principal, method: string, env: NodeJS.ProcessEnv): Promise<void> {
  if (!mfaEnforced(env) || pr.kind !== "user" || ["GET", "HEAD", "OPTIONS"].includes(method) || pr.aal === "aal2") return;
  const st = await mfaStatus(raw, pr, env);
  if (st.required) throw new AuthError(403, "Multi-factor authentication is required for this action. Add or verify an authenticator app on your account page, then sign in again.", { code: "mfa_required" });
}
export async function setOrgMfaPolicy(raw: Store, orgId: string, requireMfa: boolean) {
  const [o] = await raw.select<{ settings?: Record<string, unknown> }>("organizations", { where: { id: orgId }, limit: 1 });
  await raw.upsert("organizations", [{ id: orgId, settings: { ...(o?.settings ?? {}), requireMfa } } as any]);
}
