// A MOCK of the Wazuh Manager API (:55000) and Wazuh Indexer (:9200) that speaks real HTTP. It is NOT Wazuh: it exists so the integration code
// (login, JWT, pagination, cursor, read-only calls, error handling) is exercised over a real network socket. It records every request.
import http from "node:http";
import type { AddressInfo } from "node:net";
export interface MockWazuh { port: number; requests: string[]; alerts: any[]; agents: any[]; user: string; pass: string; version: string; roles: string[]; close(): Promise<void> }
export async function startMockWazuh(o: { user?: string; pass?: string; alerts?: any[]; agents?: any[]; version?: string; roles?: string[] } = {}): Promise<MockWazuh> {
  const st: MockWazuh = { port: 0, requests: [], alerts: o.alerts ?? [], agents: o.agents ?? [], user: o.user ?? "wazuh-ro", pass: o.pass ?? "mock-pass-123", version: o.version ?? "v4.9.2", roles: o.roles ?? ["readonly"], close: async () => {} };
  const srv = http.createServer((req, res) => {
    const url = new URL(req.url!, "http://x"); st.requests.push(`${req.method} ${url.pathname}`);
    const send = (code: number, body: unknown, text = false) => { res.writeHead(code, { "content-type": text ? "text/plain" : "application/json" }); res.end(text ? String(body) : JSON.stringify(body)); };
    const basic = "Basic " + Buffer.from(`${st.user}:${st.pass}`).toString("base64");
    let body = ""; req.on("data", (c) => (body += c)); req.on("end", () => {
      if (url.pathname === "/security/user/authenticate") return req.headers.authorization === basic ? send(200, "mock.jwt.token", true) : send(401, { title: "Unauthorized" });
      if (url.pathname.startsWith("/_cluster") || url.pathname.endsWith("/_search")) {
        if (req.headers.authorization !== basic) return send(401, {});
        if (url.pathname === "/_cluster/health") return send(200, { status: "green", number_of_nodes: 1 });
        const q = body ? JSON.parse(body) : {}, gte = q?.query?.range?.["@timestamp"]?.gte as string | undefined;
        let rows = st.alerts.slice(); if (gte && !gte.startsWith("now")) rows = rows.filter((a) => a["@timestamp"] >= gte); else if (gte) rows = rows.filter((a) => Date.parse(a["@timestamp"]) >= Date.now() - 3600_000 * 24);
        rows.sort((a, b) => (a["@timestamp"] < b["@timestamp"] ? (q.sort?.[0]?.["@timestamp"] === "desc" ? 1 : -1) : q.sort?.[0]?.["@timestamp"] === "desc" ? -1 : 1));
        return send(200, { hits: { hits: rows.slice(0, q.size ?? 10).map((a) => ({ _id: a.id, _source: a })) } });
      }
      if (req.headers.authorization !== "Bearer mock.jwt.token") return send(401, { title: "Unauthorized" });
      if (url.pathname === "/manager/info") return send(200, { data: { affected_items: [{ version: st.version, name: "wazuh-mock" }] } });
      if (url.pathname === "/security/users/me") return send(200, { data: { affected_items: [{ username: st.user, roles: st.roles }] } });
      if (url.pathname === "/agents") { const off = Number(url.searchParams.get("offset") ?? 0), lim = Number(url.searchParams.get("limit") ?? 500); return send(200, { data: { affected_items: st.agents.slice(off, off + lim) } }); }
      return send(404, {});
    });
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r)); st.port = (srv.address() as AddressInfo).port;
  st.close = () => new Promise((r) => { srv.closeAllConnections(); srv.close(() => r()); });
  return st;
}
/** fetch that sends requests for the pretend public host names to the mock servers on loopback (the real HTTP stack is used). */
export const routeFetch = (map: Record<string, number>): typeof fetch => (async (input: any, init?: any) => {
  const u = new URL(typeof input === "string" ? input : input.url), port = map[u.hostname]; if (!port) throw new Error("unexpected host " + u.hostname);
  return fetch(`http://127.0.0.1:${port}${u.pathname}${u.search}`, init);
}) as any;
