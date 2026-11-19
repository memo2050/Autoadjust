// SOAR: response PLANS built from an alert. Nothing here executes anything. Every disruptive step is a proposal that must go through the existing action + approval flow (human approves).
import type { ActionType, Alert } from "./types";
import { DISRUPTIVE } from "./types";
export interface Proposal { type: ActionType; target: string; description: string; rationale: string; requiresApproval: boolean; autoExecute: false }
export interface SoarPlan { alertId: string; ruleId: string; playbook: string; proposals: Proposal[]; note: string }
export interface PlaybookDef { id: string; name: string; match: (ruleId: string) => boolean; build: (a: Pick<Alert, "host" | "entities" | "title">) => Omit<Proposal, "requiresApproval" | "autoExecute">[] }
const inv = (a: Pick<Alert, "host">, why: string) => ({ type: "investigate" as ActionType, target: a.host, description: `Investigate ${a.host}: review the cited events and recent activity`, rationale: why });
export const PLAYBOOKS: PlaybookDef[] = [
  { id: "credential-attack", name: "Credential attack (brute force, spraying, stolen credentials)", match: (r) => r.startsWith("WIN-AUTH") || r === "UEBA-002" || r === "WIN-BEHAV-001",
    build: (a) => [inv(a, "Confirm whether the activity is the real user."), ...a.entities.ips.slice(0, 3).map((ip) => ({ type: "block_ip" as ActionType, target: ip, description: `Block ${ip} at the perimeter firewall`, rationale: "Source of the suspicious authentication activity." })), ...a.entities.users.slice(0, 3).map((u) => ({ type: "reset_password" as ActionType, target: u, description: `Reset the password of ${u} and revoke sessions`, rationale: "The account may be compromised." }))] },
  { id: "persistence-privilege", name: "Persistence or privilege change", match: (r) => r.startsWith("WIN-PRIV") || r.startsWith("WIN-ACCT") || r.startsWith("WIN-PERSIST"),
    build: (a) => [inv(a, "Verify the change was authorised."), ...a.entities.users.slice(0, 2).map((u) => ({ type: "disable_account" as ActionType, target: u, description: `Disable ${u} until the change is verified`, rationale: "New or elevated account may be attacker-created." }))] },
  { id: "malware-ransomware", name: "Malware or ransomware precursor", match: (r) => r.startsWith("WIN-MAL") || r === "WIN-IMPACT-001" || r.startsWith("SYS-RANSOM") || r === "SYS-CRED-001" || r === "WIN-EXEC-001",
    build: (a) => [inv(a, "Preserve evidence before acting."), { type: "isolate_host", target: a.host, description: `Isolate ${a.host} from the network`, rationale: "Limits spread; do only after a human confirms and evidence is captured." }, { type: "request_scan", target: a.host, description: `Run a full endpoint-protection scan on ${a.host}`, rationale: "Confirm and clean the detection." }] },
  { id: "network-behaviour", name: "Suspicious network behaviour (beaconing, scanning, C2)", match: (r) => r.startsWith("NDR-") || r === "SYS-NET-001",
    build: (a) => [inv(a, "Identify the process and destination; confirm it is not an approved tool."), ...a.entities.ips.slice(0, 3).map((ip) => ({ type: "block_ip" as ActionType, target: ip, description: `Block outbound traffic to ${ip}`, rationale: "Possible command-and-control destination." }))] },
  { id: "defense-evasion", name: "Defense evasion (log clearing, protection disabled)", match: (r) => r.startsWith("WIN-EVASION"),
    build: (a) => [inv(a, "Find out who changed the logging or protection and why."), { type: "request_scan", target: a.host, description: `Scan ${a.host} for malware after protection was changed`, rationale: "Attackers disable defences before acting." }] },
];
export const playbookCatalog = () => PLAYBOOKS.map((p) => ({ id: p.id, name: p.name }));
export function soarPlan(a: Pick<Alert, "id" | "ruleId" | "host" | "entities" | "title">): SoarPlan {
  const pb = PLAYBOOKS.find((p) => p.match(a.ruleId));
  if (!pb) return { alertId: a.id, ruleId: a.ruleId, playbook: "none", proposals: [inv(a, "No automated playbook exists for this rule.") as any].map((p) => ({ ...p, requiresApproval: false, autoExecute: false as const })), note: "No playbook matches this rule; investigation only." };
  return { alertId: a.id, ruleId: a.ruleId, playbook: pb.id, proposals: pb.build(a).map((p) => ({ ...p, requiresApproval: DISRUPTIVE.includes(p.type), autoExecute: false as const })), note: "Plan only. Nothing is executed automatically; disruptive steps need human approval through the Actions workflow." };
}
