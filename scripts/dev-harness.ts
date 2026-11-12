// Local test harness (NOT shipped to production): serves public/ and /api/soc/* with an in-memory store and a mock AI model.
import { createServer } from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { extname, join } from "node:path";
import { handleSoc } from "../lib/soc/api";
import { MemoryStore } from "../lib/soc/store";
import type { ModelFn } from "../lib/soc/agents";

Object.assign(process.env, { SOC_ADMIN_TOKEN: "admin-token-1234567890", SOC_INGEST_TOKEN: "ingest-token-1234567890", SOC_ANALYST_TOKEN: "analyst-token-1234567890", SOC_VIEWER_TOKEN: "viewer-token-1234567890", NOC_SECRET_KEY: "k".repeat(40) });
const store = new MemoryStore();
const mock: ModelFn | null = process.env.NO_MODEL ? null : async (_s, user) => {
  const ev = JSON.parse(user.replace(/^<evidence>\n|\n<\/evidence>$/g, ""));
  const first = (ev.events?.[0]?.id ?? ev.event?.id ?? ev.topAlerts?.[0]?.id) as string;
  return { model: "mock-model", text: JSON.stringify({ summary: "MOCK: repeated failures followed by a successful logon.", analysis: "## Assessment\n- (mock model) hypothesis based on cited evidence\n## Next checks\n- Confirm with the account owner", findings: [{ claim: "A successful logon followed repeated failures from one IP.", evidence_ids: [first, "evt_doesnotexist"], confidence: "medium" }],
    recommendations: [{ action: "Disable the administrator account until verified", priority: "P1", action_type: "disable_account", target: "administrator", rationale: "possible compromise", evidence_ids: [first] }, { action: "Review logon history", priority: "P2", action_type: "investigate", target: "ws01", rationale: "context", evidence_ids: [first] }], limitations: ["Mock model used in the test harness"] }) };
};
const root = process.argv[2], port = Number(process.argv[3] ?? 8802);
const mime: Record<string, string> = { ".html": "text/html", ".jpg": "image/jpeg", ".png": "image/png", ".mp4": "video/mp4" };
createServer(async (req, res) => {
  const url = new URL(req.url!, "http://x");
  if (url.pathname.startsWith("/api/soc/")) {
    const chunks: Buffer[] = []; for await (const c of req) chunks.push(c as Buffer);
    const r = await handleSoc(new Request(url, { method: req.method, headers: req.headers as any, body: ["GET", "HEAD"].includes(req.method!) ? undefined : Buffer.concat(chunks) }), url.pathname.slice(9).split("/"), { store, model: mock });
    const hdrs: Record<string, string> = {}; r.headers.forEach((v, k) => { hdrs[k] = v; }); res.writeHead(r.status, hdrs); res.end(Buffer.from(await r.arrayBuffer())); return;
  }
  const f = join(root, url.pathname === "/" ? "landing.html" : url.pathname);
  if (existsSync(f)) { res.writeHead(200, { "content-type": mime[extname(f)] ?? "application/octet-stream" }); res.end(readFileSync(f)); } else { res.writeHead(404, { "content-type": "text/html" }); res.end("<h1>404</h1>"); }
}).listen(port, () => console.log("harness on", port));
