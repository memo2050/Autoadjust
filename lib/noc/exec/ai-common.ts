// Shared rules for the AI analysts: confidence labels, evidence-id validation of any model-written narrative, and the "not executed" contract.
import type { ModelFn } from "../../soc/agents";
export type Confidence = "low" | "medium" | "high";
export const conf = (points: number): Confidence => (points >= 3 ? "high" : points >= 2 ? "medium" : "low");
export interface Recommendation { id: string; kind: "recommendation"; priority: "urgent" | "high" | "medium" | "low"; action: string; rationale: string; evidenceIds: string[]; confidence: Confidence; requiresHuman: true; status: "not_executed"; changesSystem: boolean }
export interface SuggestedDiagnostic { template: string; hostId: string; params?: Record<string, string | number>; why: string; status: "suggested_not_requested" | "proposed_awaiting_human"; jobId?: string }
export const ID_TOKEN = /\b(?:soc_|noc_)?(?:inc|alt|evt|nev|nmt|njb|aud|ast|vul|act)_[a-f0-9]{6,}\b|\b[a-z]+:[a-z0-9._-]+:[a-z]+:\d{4}-\d{2}-\d{2}T[\d:.]+Z\b/gi;
/** Asks the model for a narrative ONLY about the already-computed findings. The text is kept only if every evidence id it mentions exists in the evidence set. */
export async function narrate(model: ModelFn | null | undefined, system: string, payload: unknown, allowed: Set<string>): Promise<{ text?: string; model?: string; discarded?: string }> {
  if (!model) return {};
  try {
    const r = await model(system + "\nWrite 3-6 short sentences. Mention only facts present in the JSON. Cite evidence ids exactly as given. Do not propose running commands. Do not claim anything was done or fixed.", JSON.stringify(payload).slice(0, 60000));
    const cited = r.text.match(ID_TOKEN) ?? [], unknown = cited.filter((x) => !allowed.has(x));
    if (unknown.length) return { discarded: `The AI narrative cited ${unknown.length} evidence id(s) that do not exist in this organization's data, so it was discarded (${unknown.slice(0, 3).join(", ")}).` };
    if (/\b(i have|i've|has been|was successfully)\s+(restarted|fixed|resolved|blocked|isolated|disabled|deleted|executed|applied)\b/i.test(r.text)) return { discarded: "The AI narrative claimed an action had been performed. Auto Adjust analysis never performs actions, so the text was discarded." };
    return { text: r.text.slice(0, 2500), model: r.model };
  } catch (e: any) { return { discarded: "AI service unavailable: " + String(e?.message ?? e).slice(0, 120) }; }
}
