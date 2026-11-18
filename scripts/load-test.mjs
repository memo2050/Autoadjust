#!/usr/bin/env node
// Basic load test. STAGING/LOCALHOST ONLY: refuses any other address. No secrets printed. Uses synthetic requests only.
// Env: STAGING_URL (required), LOAD_TOKEN (optional access token of a TEST user: adds authenticated GETs), LOAD_CONCURRENCY (default 10), LOAD_SECONDS (default 20), LOAD_MAX_RPS (default 200: hard cap),
//      LOAD_P95_MS (default 1500) and LOAD_MAX_ERROR_PCT (default 1) = pass thresholds. Exit: 0 pass, 1 threshold missed, 2 refused/bad config.
const base = (process.env.STAGING_URL ?? "").replace(/\/$/, ""); let host = ""; try { host = new URL(base).hostname; } catch {}
if (!base || !/staging|^localhost$|^127\.0\.0\.1$/.test(host) || /prod/.test(host)) { console.error("Refusing to run: STAGING_URL must be a staging/localhost address."); process.exit(2); }
const num = (k, d) => { const n = Number(process.env[k] ?? d); return Number.isFinite(n) && n > 0 ? n : d; };
const conc = Math.min(num("LOAD_CONCURRENCY", 10), 50), secs = Math.min(num("LOAD_SECONDS", 20), 120), maxRps = num("LOAD_MAX_RPS", 200), p95Max = num("LOAD_P95_MS", 1500), errMax = num("LOAD_MAX_ERROR_PCT", 1);
const tok = process.env.LOAD_TOKEN;
const targets = [{ name: "landing", path: "/" }, { name: "status-unauth", path: "/api/soc/status", expect: [401, 403, 200] }, ...(tok ? [{ name: "alerts-auth", path: "/api/soc/alerts", auth: true }, { name: "org-mine", path: "/api/soc/org/mine", auth: true }] : [])];
const lat = {}, codes = {}; let total = 0, errors = 0, limited = 0; const end = Date.now() + secs * 1000, gap = (1000 * conc) / maxRps;
async function worker(i) {
  let k = i;
  while (Date.now() < end) {
    const t = targets[k++ % targets.length], t0 = performance.now();
    try { const r = await fetch(base + t.path, { headers: t.auth ? { authorization: "Bearer " + tok } : {}, redirect: "manual" }); await r.arrayBuffer();
      const ok = r.status < 500 && (r.status !== 429) && (!t.expect || t.expect.includes(r.status) || r.status < 400); if (r.status === 429) limited++; if (!ok && r.status !== 429) errors++;
      (codes[r.status] ??= 0), codes[r.status]++; } catch { errors++; (codes.neterr ??= 0), codes.neterr++; }
    (lat[t.name] ??= []).push(performance.now() - t0); total++;
    const spent = performance.now() - t0; if (spent < gap) await new Promise((r) => setTimeout(r, gap - spent));
  }
}
await Promise.all(Array.from({ length: conc }, (_, i) => worker(i)));
const q = (a, p) => { const s = [...a].sort((x, y) => x - y); return Math.round(s[Math.min(s.length - 1, Math.floor(s.length * p))] ?? 0); };
const all = Object.values(lat).flat(); const res = { target: host, concurrency: conc, seconds: secs, requests: total, rps: Math.round(total / secs), errors, errorPct: +(100 * errors / Math.max(total, 1)).toFixed(2), rateLimited429: limited, statusCodes: codes, p50: q(all, 0.5), p95: q(all, 0.95), p99: q(all, 0.99), perEndpoint: Object.fromEntries(Object.entries(lat).map(([k, v]) => [k, { n: v.length, p95: q(v, 0.95) }])) };
const pass = res.p95 <= p95Max && res.errorPct <= errMax && total > 0; console.log(JSON.stringify(res, null, 1)); console.log(pass ? "LOAD TEST PASS" : "LOAD TEST FAIL (thresholds: p95<=" + p95Max + "ms, errors<=" + errMax + "%)"); process.exit(pass ? 0 : 1);
