// Shared types for the Spark SOC module. Pure TypeScript, no framework imports.

/** Where a row came from. Shown as a badge everywhere in the UI. */
export type DataSource = "live" | "imported" | "demo";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
export const sevRank = (s: Severity) => 4 - SEVERITIES.indexOf(s); // critical=4 ... info=0

export type Role = "admin" | "analyst" | "viewer" | "collector";

export interface Asset {
  id: string;               // slug of hostname
  hostname: string;
  ips: string[];
  os?: string;
  criticality: number;      // 1 (low) .. 5 (crown jewel); set by a human
  authorized: boolean;      // owner has attested that testing/scan results for this asset are allowed
  authorizedBy?: string;
  authorizedAt?: string;
  authorizationNote?: string;
  source: DataSource;
  firstSeen: string;
  lastSeen: string;
  lastEventAt?: string;
  lastContactAt?: string;   // last time the collector talked to the server, even with no new events
  collector?: string;
  collectorVersion?: string;
  lastBatch?: number;       // events accepted in the last request
  agentId?: string; agentStatus?: "active" | "disconnected" | "pending" | "never_connected"; agentVersion?: string; agentSyncedAt?: string; wazuhGroups?: string[]; // set for endpoints reported by a Wazuh Manager
}

export interface SocEvent {
  id: string;
  source: DataSource;
  collector: string;
  assetId: string;
  host: string;
  time: string;             // ISO
  channel: string;
  provider: string;
  eventId: number;
  recordId?: number;
  level?: string;
  user?: string;
  targetUser?: string;
  domain?: string;
  srcIp?: string;
  srcHost?: string;
  logonType?: number;
  process?: string;
  parentProcess?: string;
  commandLine?: string;
  severity?: Severity;      // per-event severity derived from the Windows level and event id (not a detection verdict)
  summary: string;
  data: Record<string, string>;
  fingerprint: string;
  ingestedAt: string;
}

export interface MitreRef { id: string; name: string; tactic: string }

export interface Alert {
  id: string;
  source: DataSource;
  ruleId: string;
  key: string;              // dedupe key
  title: string;
  severity: Severity;
  confidence: number;       // 0..1, set by the rule, not by AI
  mitre: MitreRef[];
  assetId: string;
  host: string;
  eventIds: string[];
  firstSeen: string;
  lastSeen: string;
  reasoning: string;
  entities: { users: string[]; ips: string[] };
  incidentId?: string;
  createdAt: string;
}

export type IncidentStatus = "open" | "investigating" | "contained" | "remediated" | "closed";
export const INCIDENT_STATUSES: IncidentStatus[] = ["open", "investigating", "contained", "remediated", "closed"];

export interface Incident {
  id: string;
  source: DataSource;
  title: string;
  severity: Severity;
  confidence: number;
  status: IncidentStatus;
  assetId: string;
  host: string;
  alertIds: string[];
  tactics: string[];
  firstSeen: string;
  lastSeen: string;
  reasoning: string;
  owner?: string;           // who owns the incident (set by a human)
  statusChangedAt: string;
  remediatedAt?: string;
  verification?: Verification;
  closedWithoutVerification?: boolean;
  recurrenceOf?: string;
  createdAt: string;
  updatedAt: string;
}

export interface Verification {
  status: "passed" | "failed" | "inconclusive";
  checkedAt: string;
  details: string[];
}

export type VulnStatus = "open" | "in_remediation" | "accepted_risk" | "fixed_verified" | "reappeared";

export interface Vuln {
  id: string;
  source: DataSource;       // imported or demo
  assetId: string;
  host: string;
  port: string;             // "443/tcp" or "general/tcp"
  oid: string;
  name: string;
  cvss: number;
  severity: Severity;
  cves: string[];
  qod: number;              // quality of detection 0..100 from the scanner
  summary: string;
  solution: string;
  solutionType: string;
  status: VulnStatus;
  firstSeen: string;
  lastSeen: string;
  scanId: string;
  priority: number;         // 0..100
  priorityReasons: string[];
  kev: boolean;
  note?: string;
  fixedAt?: string;
  updatedAt: string;
}

export interface ScanImport {
  id: string;
  source: DataSource;
  format: "xml" | "csv";
  filename?: string;
  scanTime: string;
  importedAt: string;
  importedBy: string;
  hosts: string[];
  findings: number;
  logResultsSkipped: number;
  newFindings: number;
  fixedVerified: number;
  reappeared: number;
}

export interface AgentRun {
  id: string;
  agent: AgentId;
  target: string;
  actor: string;
  model: string;
  promptHash: string;
  evidenceIds: string[];
  status: "ok" | "unavailable" | "error";
  summary: string;
  output: AgentOutput | null;
  invalidEvidenceIds: string[];
  error?: string;
  usage?: { inputTokens?: number; outputTokens?: number };
  createdAt: string;
  source: DataSource;
}

export const AGENT_IDS: AgentId[] = ["soc_analyst", "vuln_analyst", "threat_hunter", "incident_responder", "security_advisor", "siem_specialist"];
export type AgentId = "soc_analyst" | "vuln_analyst" | "threat_hunter" | "incident_responder" | "security_advisor" | "siem_specialist";

export interface AgentFinding { claim: string; evidenceIds: string[]; confidence: "low" | "medium" | "high"; supported: boolean; hypothesis: true }
export interface AgentRecommendation {
  action: string; priority: "P1" | "P2" | "P3"; disruptive: boolean;
  actionType: ActionType; target: string; rationale: string; evidenceIds: string[];
}
export interface AgentOutput { summary: string; analysis: string; report?: string; findings: AgentFinding[]; recommendations: AgentRecommendation[]; limitations: string[] }

export type ActionType = "isolate_host" | "disable_account" | "block_ip" | "request_scan" | "reset_password" | "patch" | "investigate" | "other";
export const DISRUPTIVE: ActionType[] = ["isolate_host", "disable_account", "block_ip", "request_scan", "reset_password"];

export interface SocAction {
  id: string;
  source: DataSource;
  incidentId?: string;
  type: ActionType;
  target: string;
  description: string;
  rationale: string;
  proposedBy: string;       // "agent:soc_analyst" or user label
  status: "proposed" | "approved" | "rejected" | "done";
  requiresApproval: boolean;
  decidedBy?: string;
  decidedAt?: string;
  decisionNote?: string;
  createdAt: string;
}

export interface AuditEntry {
  id: string;
  time: string;
  actor: string;
  role: string;
  action: string;
  target: string;
  detail: Record<string, unknown>;
  seq?: number;             // position in the audit hash chain (1, 2, 3, ...)
  prevHash?: string;        // hash chain: each record commits to the one before it
  hash?: string;
}

export interface ApiKey {
  id: string;
  label: string;
  role: Role;
  prefix: string;
  hash: string;
  createdBy: string;
  createdAt: string;
  lastUsedAt?: string;
  revokedAt?: string;
}

export interface TimelineEntry {
  time: string;
  kind: "event" | "alert" | "agent" | "status" | "action" | "note" | "verification";
  title: string;
  detail?: string;
  ref?: string;
  source?: DataSource;
}
