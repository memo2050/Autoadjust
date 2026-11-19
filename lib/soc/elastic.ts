// Elastic integration (READ-ONLY, ingest side). Maps Winlogbeat / Elastic Agent Windows documents (ECS `winlog.*`) into the raw Windows event shape the existing normalizer already accepts,
// so every existing rule (Windows, Sysmon, UEBA, NDR) works on Elastic data. The query builder only builds a _search body; it never writes or deletes in Elasticsearch.
import type { RawWinEvent } from "./windows";
const get = (o: any, path: string) => path.split(".").reduce((x, k) => (x == null ? undefined : x[k]), o);
const first = (o: any, ...paths: string[]) => { for (const p of paths) { const v = get(o, p) ?? o?.[p]; if (v != null && v !== "") return v; } return undefined; };
/** `hit` is an Elasticsearch search hit ({_source}) or a bare document. Returns null if it is not a Windows event. */
export function elasticToRaw(hit: any): RawWinEvent | null {
  const d = hit?._source ?? hit; if (!d || typeof d !== "object") return null;
  const id = first(d, "winlog.event_id", "event.code"); if (id == null) return null;
  const ed = { ...(get(d, "winlog.event_data") ?? {}) } as Record<string, unknown>;
  const uf = get(d, "winlog.event_data.TargetUserName") ?? get(d, "user.name"); if (ed.TargetUserName == null && uf != null) ed.TargetUserName = uf;
  const src = get(d, "source.ip"); if (ed.IpAddress == null && src != null) ed.IpAddress = src;
  return { Id: Number(id), RecordId: first(d, "winlog.record_id"), TimeCreated: first(d, "@timestamp"), MachineName: first(d, "winlog.computer_name", "host.name", "host.hostname"), LogName: first(d, "winlog.channel") ?? "Unknown", ProviderName: first(d, "winlog.provider_name") ?? "Unknown", LevelDisplayName: first(d, "log.level"), EventData: ed };
}
export interface ElasticQuery { index: string; body: Record<string, unknown> }
/** Search body for Windows events newer than `sinceIso`, oldest first, capped. */
export function elasticQuery(o: { index?: string; sinceIso?: string; size?: number } = {}): ElasticQuery {
  const size = Math.max(1, Math.min(1000, Math.floor(o.size ?? 500)));
  return { index: o.index ?? "winlogbeat-*", body: { size, sort: [{ "@timestamp": "asc" }], query: { bool: { filter: [{ exists: { field: "winlog.event_id" } }, ...(o.sinceIso ? [{ range: { "@timestamp": { gt: o.sinceIso } } }] : [])] } } } };
}
export function elasticHitsToRaw(hits: unknown[]): { events: RawWinEvent[]; skipped: number } {
  const events: RawWinEvent[] = []; let skipped = 0; for (const h of hits.slice(0, 1000)) { const r = elasticToRaw(h); if (r) events.push(r); else skipped++; } return { events, skipped };
}
