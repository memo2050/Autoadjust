import { writeFileSync } from "fs";
import { TIERS, ADDONS, FEATURES, ANNUAL_DISCOUNT, PRICING_NOTES, annualUsd, annualPerMonthUsd, perEndpointUsd, includes } from "../lib/billing/pricing";
const esc = (s: string) => s.replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" } as any)[c]);
const usd = (n: number) => "$" + n.toLocaleString("en-US", { minimumFractionDigits: Number.isInteger(n) ? 0 : 2, maximumFractionDigits: 2 });
const n = (v: number | null) => v == null ? "Custom" : v.toLocaleString("en-US");
const cards = TIERS.map(t => `<article class="card${t.id === "professional" ? " pop" : ""}"><h3>${esc(t.name)}</h3><p class="bl">${esc(t.blurb)}</p>` + (t.monthlyUsd == null
  ? `<div class="pr"><span class="amt">Custom</span></div><div class="sub">Contact us for a quote</div>`
  : `<div class="pr" data-m="${t.monthlyUsd}" data-a="${annualPerMonthUsd(t.monthlyUsd)}" data-y="${annualUsd(t.monthlyUsd)}"><span class="amt">${usd(t.monthlyUsd)}</span><span class="per">/mo</span></div><div class="sub" data-sub>billed monthly</div>`)
  + `<ul><li>${n(t.endpoints)} endpoints</li><li>${n(t.devices)} network devices</li><li>${n(t.users)} users</li><li>${t.retentionDays ? t.retentionDays + " days log retention" : "Extended retention"}</li><li>${esc(t.support)} support</li></ul><a class="btn" href="/demo?request=1">Request a Demo</a></article>`).join("");
const head = `<tr><th></th>${TIERS.map(t => `<th>${esc(t.name)}</th>`).join("")}</tr>`;
const row = (l: string, f: (t: typeof TIERS[number]) => string) => `<tr><th scope="row">${l}</th>${TIERS.map(t => `<td>${esc(f(t))}</td>`).join("")}</tr>`;
const limits = head + row("Monthly price", t => t.monthlyUsd == null ? "Custom" : usd(t.monthlyUsd)) + row("Annual price (15% off)", t => t.monthlyUsd == null ? "Custom" : usd(annualUsd(t.monthlyUsd)) + "/yr") + row("Endpoints", t => n(t.endpoints)) + row("Network devices", t => n(t.devices)) + row("Users", t => n(t.users)) + row("Log retention", t => t.retentionDays ? t.retentionDays + " days" : "Extended") + row("Price per endpoint", t => { const p = perEndpointUsd(t); return p == null ? "—" : "$" + p.toFixed(2); }) + row("Support", t => t.support) + row("Free trial", t => t.trial === "Pilot" ? "Pilot" : t.trial + " (coming soon)");
const lab = { available: "", soon: " — Coming soon", planned: " — Planned" } as const;
const feats = head + FEATURES.map(f => `<tr><th scope="row">${esc(f.name)}${lab[f.status]}${f.note ? `<small> ${esc(f.note)}</small>` : ""}</th>${TIERS.map(t => `<td>${f.status === "available" ? (includes(t.id, f) ? "✓" : "—") : (includes(t.id, f) ? "Soon" : "—")}</td>`).join("")}</tr>`).join("");
const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pricing — Auto Adjust</title><meta name="description" content="Auto Adjust launch pricing proposal. Online payment is not enabled."><style>
:root{--bg:#050608;--fg:#e9edf5;--mut:#aab3c5;--card:#0a0d14;--bd:#1b2233;--ac:#4d8dff;--onac:#050608}
@media(prefers-color-scheme:light){:root:not([data-theme="dark"]){--bg:#f6f8fc;--fg:#0b1220;--mut:#4a5568;--card:#fff;--bd:#d6dcea;--ac:#2f5bd8;--onac:#fff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}main{max-width:1200px;margin:0 auto;padding:24px 16px 64px}
header.top{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;max-width:1200px;margin:0 auto;padding:16px}a{color:var(--ac)}.logo{font-weight:700;color:var(--fg);text-decoration:none;font-size:20px}
h1{font-size:clamp(28px,5vw,44px);margin:8px 0}.lead{color:var(--mut);max-width:720px}.banner{border:1px solid var(--ac);border-radius:10px;padding:12px 14px;margin:16px 0;background:var(--card)}
.tog{display:inline-flex;border:1px solid var(--bd);border-radius:999px;margin:12px 0;overflow:hidden}.tog button{background:none;border:0;color:var(--fg);padding:9px 18px;cursor:pointer;font:inherit}.tog button[aria-pressed=true]{background:var(--ac);color:var(--onac)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px}.card{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:18px;display:flex;flex-direction:column}.card.pop{border-color:var(--ac)}.card h3{margin:0}.bl{color:var(--mut);font-size:14px;min-height:42px}
.amt{font-size:34px;font-weight:700}.per{color:var(--mut)}.sub{color:var(--mut);font-size:13px;min-height:20px}.card ul{padding-left:18px;margin:12px 0;flex:1}
.btn{display:inline-block;text-align:center;background:var(--ac);color:var(--onac);padding:10px 14px;border-radius:8px;text-decoration:none;font-weight:600}.btn.ghost{background:none;color:var(--ac);border:1px solid var(--ac)}
h2{margin:40px 0 10px}.tw{overflow-x:auto;border:1px solid var(--bd);border-radius:12px}table{border-collapse:collapse;width:100%;min-width:720px;background:var(--card)}th,td{padding:9px 12px;border-bottom:1px solid var(--bd);text-align:left;font-size:14px}thead th,tr:first-child th{background:var(--card)}tbody th{font-weight:500}small{color:var(--mut)}
ul.n{color:var(--mut)}:focus-visible{outline:2px solid var(--ac);outline-offset:2px}
</style></head><body><header class="top"><a class="logo" href="/">Auto Adjust.</a><nav><a href="/demo">Live Demo</a> · <a href="/account.html">Sign In</a></nav></header><main>
<h1>Simple pricing for security and network monitoring</h1><p class="lead">One flat price per tier covering SOC and NOC, with AI assistance, for small and mid-size teams.</p>
<div class="banner" role="note"><strong>Payments are not enabled.</strong> This is a launch pricing proposal. You cannot subscribe or be charged online yet — request a demo and we will get in touch.</div>
<div class="tog" role="group" aria-label="Billing period"><button type="button" id="bm" aria-pressed="true">Monthly</button><button type="button" id="by" aria-pressed="false">Annual (save ${Math.round(ANNUAL_DISCOUNT * 100)}%)</button></div>
<section class="grid" aria-label="Plans">${cards}</section>
<h2>Limits and price</h2><div class="tw"><table>${limits}</table></div>
<h2>Feature availability</h2><p class="lead">Only features that are available today are sold. Items marked Soon are built but still being validated; Planned items are not built.</p><div class="tw"><table>${feats}</table></div>
<h2>Add-on packs (monthly)</h2><div class="tw"><table><tr><th>Add-on</th><th>Price</th></tr>${ADDONS.map(a => `<tr><td>${esc(a.name)}</td><td>${usd(a.monthlyUsd)}/mo</td></tr>`).join("")}</table></div>
<h2>Notes</h2><ul class="n">${PRICING_NOTES.map(x => `<li>${esc(x)}</li>`).join("")}<li>Upgrades will be prorated; downgrades apply at the next renewal.</li></ul>
<p><a class="btn" href="/demo?request=1">Request a Demo</a> <a class="btn ghost" href="/account.html">Create Account</a></p></main>
<script>(function(){var y=false;function s(v){y=v;document.getElementById("bm").setAttribute("aria-pressed",String(!v));document.getElementById("by").setAttribute("aria-pressed",String(v));document.querySelectorAll(".pr[data-m]").forEach(function(p){var a=p.querySelector(".amt");var f=function(n){return "$"+(Number.isInteger(n)?n:n.toFixed(2))};a.textContent=f(+p.getAttribute(v?"data-a":"data-m"));p.nextElementSibling.textContent=v?"$"+(+p.getAttribute("data-y")).toLocaleString("en-US",{minimumFractionDigits:2})+" billed yearly":"billed monthly"})}document.getElementById("bm").onclick=function(){s(false)};document.getElementById("by").onclick=function(){s(true)}})();</script><script src="/support-widget.js" defer></script></body></html>`;
writeFileSync("public/pricing.html", html);
console.log("wrote public/pricing.html", html.length);
