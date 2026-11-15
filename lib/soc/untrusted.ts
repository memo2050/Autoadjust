// T8: protection against prompt injection through log/alert text. Everything collected from systems is attacker-influenced DATA.
// Layers (none relies on the model "behaving"): (1) clean + escape so data cannot close the evidence block or hide characters,
// (2) detect and record instruction-like text, (3) after the model answers, never accept a disruptive proposal whose target is not in the evidence.
export const INJECTION_PATTERNS: [string, RegExp][] = [
  ["ignore-instructions", /\b(ignore|disregard|forget|override|bypass|skip)\b.{0,40}\b(previous|prior|above|earlier|all|any|your|the|system)\b.{0,30}\b(instruction|prompt|rule|guideline|direction|constraint|polic)/],
  ["new-instructions", /\b(new|updated|revised|real|actual|additional)\s+(instruction|directive|task|order|prompt|rule)s?\b/],
  ["role-reassign", /\b(you are now|from now on you|act as|pretend (to be|you)|you must now|your new role|role ?play as|behave as)\b/],
  ["system-prompt", /\b(system|developer|hidden|initial)\s*(prompt|message|instruction)s?\b/],
  ["reveal-prompt", /\b(reveal|print|show|repeat|output|leak|display)\b.{0,30}\b(prompt|instruction|secret|api key|credential|password|token)s?\b/],
  ["role-marker", /(^|\n)\s*(system|assistant|developer|human|user)\s*:/],
  ["chat-template", /<\|[a-z_]{2,20}\|>|\[\/?inst\]|<<\/?sys>>|###\s*(system|instruction)/],
  ["tag-spoof", /<\/?\s*(evidence|system|instructions?|assistant|prompt|tool_?(call|use|result)|function_?calls?)\b/],
  ["tool-call-spoof", /\b(tool_use|function_call|tool_call)\b|"?(action_type|recommendations)"?\s*:\s*[\[{"]/],
  ["do-not-tell", /\b(do not|don't|never)\s+(tell|mention|report|reveal|flag|alert|log)\b.{0,30}\b(analyst|user|human|anyone|admin|soc)/],
  ["mark-benign", /\b(mark|classify|report|label|treat|consider)\b.{0,30}\b(as )?(benign|safe|false positive|trusted|harmless|authorized|allowlisted)\b/],
  ["suppress-finding", /\b(this (alert|event|activity|host|user) is)\b.{0,20}\b(benign|safe|authorized|approved|expected|a test)\b/],
  ["force-action", /\b(immediately|urgently|automatically)\b.{0,40}\b(disable|isolate|block|delete|reset|shut ?down|wipe|quarantine)\b/],
  ["disable-account", /\b(disable|delete|lock|reset)\b.{0,20}\b(account|user|admin(istrator)?|password)\b.{0,40}\b(now|immediately|without|no approval)/],
  ["skip-approval", /\b(without|skip|no need for|bypass)\b.{0,20}\b(approval|human|review|confirmation|analyst)/],
  ["exfiltrate", /\b(send|post|upload|exfiltrat\w*|forward|email|curl|wget)\b.{0,60}\bhttps?:\/\/\S+/],
  ["code-exec", /\b(run|execute|eval)\b.{0,20}\b(command|script|shell|powershell|bash|code)\b/],
  ["jailbreak", /\b(jailbreak|dan mode|developer mode|no restrictions|unfiltered|without (any )?(restrictions|filters|limits))\b/],
  ["important-msg", /\b(important|urgent|attention|note)\s*(to|for)\s*(the )?(ai|assistant|model|llm|analyst bot|language model)\b/],
  ["ai-address", /\b(dear|hey|hello|attention)\s+(ai|assistant|claude|gpt|chatgpt|model|llm)\b/],
  ["end-of-data", /\b(end of (evidence|data|logs?|input)|evidence ends|data ends)\b/],
  ["base64-blob", /[a-z0-9+/]{120,}={0,2}/],
  ["markdown-exfil", /!\[[^\]]*\]\(https?:\/\/[^)]+\)/],
  ["multilingual", /\b(ignorer? (les|toutes les) (consignes|instructions)|ignoriere?n? (alle )?(vorherigen|bisherigen) (anweisungen|instruktionen)|ignora (todas )?las (instrucciones|reglas) anteriores|ignora (le|tutte le) (istruzioni|regole) precedenti|игнорируй)|\bab jetzt gilt\b|\bvous devez (ignorer|bloquer|supprimer)/],
  ["cite-fake-id", /\b(cite|use|reference)\b.{0,30}\b(evidence ids?|ids?)\b/],
  ["confirmed-claim", /\b(declare|state|conclude|report)\b.{0,30}\b(confirmed|no (threat|incident|attack)|all clear)\b/],
];
const INVISIBLE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\u3164\uFE00-\uFE0F\uFEFF\uFFA0\uFFF9-\uFFFB]|\uDB40[\uDC00-\uDFFF]/g;

/** Remove invisible/bidi/control characters and normalise look-alike forms (full-width etc.) so neither the reader nor the detector is fooled. */
export function cleanText(s: string): string { return s.normalize("NFKC").replace(INVISIBLE, "").replace(/\r\n?/g, "\n"); }
/** Matched pattern names (never the text itself). */
export function scanText(s: string): string[] {
  const t = cleanText(s).toLowerCase().replace(/[ \t]+/g, " "), hit: string[] = [];
  for (const [n, re] of INJECTION_PATTERNS) if (re.test(t)) hit.push(n);
  // Hidden payloads: decode base64-looking runs and scan what they contain.
  for (const m of s.match(/[A-Za-z0-9+/]{24,}={0,2}/g) ?? []) { try { const d = Buffer.from(m, "base64").toString("utf8"); if (/^[\x09\x0a\x0d\x20-\x7e]{12,}$/.test(d) && INJECTION_PATTERNS.some(([n, re]) => n !== "base64-blob" && re.test(d.toLowerCase()))) { hit.push("encoded-instruction"); break; } } catch { /* not base64 */ } }
  return hit;
}
export interface Suspicion { path: string; patterns: string[] }
/** Fields that name a machine, account or address. Only these (and only when not flagged as instruction-like) can justify a proposed target. */
const IDENTITY_KEY = /^(host|hostname|assetid|ips?|srcip|dstip|sourceip|destip|ipaddress|user|users|username|account|targetusername|subjectusername|workstationname|computer)$/i;
/** Deep-clean a packet and report where instruction-like text was found. Only strings are touched; keys, numbers and ids are left as they are.
 *  `identities` = hosts/accounts/addresses that appear in identity fields, for checking a model-proposed target later. */
export function sanitizePacket<T>(packet: T, maxString = 2000): { packet: T; suspicions: Suspicion[]; identities: Set<string> } {
  const suspicions: Suspicion[] = [], identities = new Set<string>();
  const walk = (v: unknown, path: string, idKey: boolean): unknown => {
    if (typeof v === "string") { const c = cleanText(v).slice(0, maxString), p = scanText(c); if (p.length) suspicions.push({ path, patterns: p }); else if (idKey && c.length <= 200) identities.add(c.trim().toLowerCase()); return c; }
    if (Array.isArray(v)) return v.slice(0, 2000).map((x, i) => walk(x, `${path}[${i}]`, idKey));
    if (v && typeof v === "object") return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, walk(x, path ? `${path}.${k}` : k, IDENTITY_KEY.test(k))]));
    return v;
  };
  return { packet: walk(packet, "", false) as T, suspicions, identities };
}
/** JSON for the prompt in which < and > can never appear, so no text inside the data can open or close a tag such as </evidence>. Still valid JSON. */
export const safeJson = (v: unknown) => JSON.stringify(v).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
/** Is a proposed target a host, account or address that appears in an identity field of the evidence (and that field was not itself instruction-like)? Free text cannot justify a target. */
export function targetInEvidence(target: string, identities: Set<string>): boolean {
  const t = cleanText(String(target ?? "")).trim().toLowerCase(); if (t.length < 2 || t.length > 200) return false;
  if (identities.has(t)) return true; const bare = t.includes("\\") ? t.slice(t.lastIndexOf("\\") + 1) : t; return bare.length >= 2 && (identities.has(bare) || [...identities].some((x) => x.endsWith("\\" + bare)));
}
