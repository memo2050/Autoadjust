// Plan limits for monitoring: device admission and metric retention. Both are inert unless billing enforcement is on (BILLING_ENFORCE=1),
// so existing organizations are unaffected until the owner deliberately enables it. Nothing here ever deletes a device or any data on its own.
import type { Store } from "../soc/store";
import { NOC_TABLE } from "../soc/noc";
import { NT } from "./types";

/** Which of the given device ids may be stored. Existing devices are ALWAYS admitted (updates never blocked); only NEW ids beyond the room left are skipped. */
export async function admitDevices(store: Store, ids: string[], max: number | null | undefined): Promise<{ allowed: Set<string>; skipped: string[]; limit: number | null }> {
  const uniq = [...new Set(ids)];
  if (max == null) return { allowed: new Set(uniq), skipped: [], limit: null };
  const have = new Set((await store.select<{ id: string }>(NOC_TABLE, { limit: 100000 })).map((d) => d.id));
  const allowed = new Set<string>(), skipped: string[] = []; let room = Math.max(0, max - have.size);
  for (const id of uniq) { if (have.has(id)) allowed.add(id); else if (room > 0) { allowed.add(id); room--; } else skipped.push(id); }
  return { allowed, skipped, limit: max };
}

const ts = (t: unknown) => (typeof t === "number" ? t : Date.parse(String(t)));
/** Metric samples older than `days`. Dry run by default; only `apply` deletes, only noc_metrics rows (never audit log, events, incidents or evidence), at most `cap` rows per call. */
export async function pruneMetrics(store: Store, days: number | null, o: { apply?: boolean; now?: number; cap?: number } = {}) {
  if (days == null) return { retentionDays: null, applied: false, eligible: 0, deleted: 0, note: "No retention limit applies (billing enforcement is off or the plan has none). Nothing is eligible." };
  const now = o.now ?? Date.now(), cutoff = now - days * 86400000, cap = o.cap ?? 5000;
  const rows = await store.select<{ id: string; t?: unknown }>(NT.metrics, { limit: 200000 });
  const old = rows.filter((r) => { const x = ts(r.t); return Number.isFinite(x) && x < cutoff; });
  let deleted = 0;
  if (o.apply) for (const r of old.slice(0, cap)) { await store.remove(NT.metrics, { id: r.id }); deleted++; }
  return { retentionDays: days, cutoff: new Date(cutoff).toISOString(), applied: !!o.apply, totalSamples: rows.length, eligible: old.length, deleted, remaining: old.length - deleted };
}
