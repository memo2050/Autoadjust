/* Auto Adjust public demo layer. Active ONLY on /demo . Nothing here talks to a backend:
   - fetch() to /api/soc/* is answered locally with a non-JSON 404 so the page's built-in SAMPLE modes activate.
   - fetch() to /api/analyze is answered by the scripted, clearly-labelled SIMULATED responder below (no real AI call, no quota, no keys).
   - the only network calls allowed out are POST /api/demo-request (the Request a Demo form) and POST /api/support/chat (read-only FAQ answers; tickets are not available in demo). Every other /api/* call is blocked.
   All data on screen is simulated. */
(function () {
  "use strict";
  var on = /^\/demo\/?$/.test(location.pathname); // exact /demo route only: no query-string or hash switch
  if (!on) return;
  window.__AA_DEMO__ = true;
  var blocked = [];
  window.__AA_DEMO_BLOCKED__ = blocked;

  /* ---------- fetch shim ---------- */
  var realFetch = window.fetch ? window.fetch.bind(window) : null;
  function path(u) { try { return new URL(typeof u === "string" ? u : u.url, location.href).pathname; } catch (e) { return ""; } }
  function bodyOf(init) { try { return init && typeof init.body === "string" ? JSON.parse(init.body) : {}; } catch (e) { return {}; } }
  window.fetch = function (u, init) {
    var p = path(u);
    if (p.indexOf("/api/") !== 0) return realFetch ? realFetch(u, init) : Promise.reject(new Error("no fetch"));
    if (p.indexOf("/api/soc") === 0) { blocked.push(p); return Promise.resolve(new Response("<!doctype html><title>demo</title>No backend in demo mode.", { status: 404, headers: { "Content-Type": "text/html" } })); }
    if (p === "/api/analyze") {
      var b = bodyOf(init), out = respond(String(b.text || ""), b.mode);
      return new Promise(function (ok) { setTimeout(function () { ok(new Response(out, { status: 200, headers: { "Content-Type": "text/plain; charset=utf-8" } })); }, 700 + Math.random() * 600); });
    }
    if (p === "/api/demo-request" || p === "/api/support/chat") return realFetch(u, init);
    blocked.push(p);
    return Promise.resolve(new Response("Blocked in demo mode", { status: 403 }));
  };
  if (navigator.sendBeacon) navigator.sendBeacon = function () { return false; };

  /* ---------- scripted AI ---------- */
  var TAG = "[SIMULATED AI RESPONSE - scripted for the public demo; no real model was called and no real system was analysed]\n\n";
  function respond(text, mode) {
    var m = /QUESTION:\s*([\s\S]*)$/.exec(text), q = (m ? m[1] : text.split("\n\nSAMPLE DATA")[0].split("\n\nTELEMETRY")[0]).toLowerCase();
    if (/telemetry/i.test(text)) return TAG + nocAnswer(text, q).replace(/^## /gm, "");
    return TAG + socAnswer(q, text);
  }
  function nocAnswer(text, q) {
    var bad = [], t = /TELEMETRY:\n([\s\S]*?)\n\nQUESTION:/.exec(text);
    try { var arr = JSON.parse(t[1]); arr.forEach(function (d) { if (d.status && d.status !== "healthy") bad.push(d); }); } catch (e) {}
    var list = bad.slice(0, 5).map(function (d) { return "- " + d.name + " (" + d.type + "): " + d.status + (d.why && d.why.length ? " - " + [].concat(d.why).slice(0, 2).join("; ") : ""); }).join("\n");
    var h = "## Assessment (hypothesis, based on the simulated telemetry shown)\n";
    var core = bad.length ? "Devices needing attention:\n" + list + "\n" : "No device in the simulated telemetry is outside its thresholds.\n";
    var steps;
    if (/cpu|load|slow|performance/.test(q)) steps = "## Likely causes\n- Sustained CPU above 85% usually points to a runaway process, a backup/AV scan window or a traffic spike.\n## Recommended checks\n- Compare the CPU trend with the interface throughput on the same host.\n- List the top processes and any scheduled jobs that start at that time.\n- If the load follows a deployment, roll back the change before adding capacity.";
    else if (/disk|storage|space/.test(q)) steps = "## Likely causes\n- Log growth, an unrotated backup folder or database files expanding.\n## Recommended checks\n- Identify the largest directories; confirm log rotation is running.\n- Alert on 80% and act at 90% to leave room for the weekend.";
    else if (/latency|packet|loss|link|network|wan|switch|router|down|offline|unreach/.test(q)) steps = "## Likely causes\n- Packet loss with high latency often indicates a saturated or flapping uplink, a duplex mismatch or a failing optic.\n## Recommended checks\n- Check interface error counters (CRC, drops) on both ends of the affected link.\n- Look for a recent config change or STP topology change in the device log.\n- Fail traffic over to the redundant path if one exists, then replace the suspect cable/optic.";
    else steps = "## Recommended next steps\n- Start with the devices listed above, highest severity first.\n- Correlate their alerts in time: simultaneous alerts on several devices usually share one upstream cause.\n- Confirm with a second data source (logs, ping/traceroute) before acting.";
    return h + core + "\n" + steps + "\n\nRisk: " + (bad.length > 2 ? "MEDIUM-HIGH (several devices affected)" : bad.length ? "MEDIUM (limited scope)" : "LOW") + ". All figures here are simulated demo data.";
  }
  function socAnswer(q, full) {
    if (/report/.test(q)) return "## Security report (simulated demo data)\n- Posture score: 37/100 (poor) - 2 critical incidents open on DEMO-WS01 and DEMO-SRV02.\n- 9 alerts in the last 24 h; 6 vulnerability findings (1 critical, 2 high, 3 medium).\n## Top risks\n- Possible compromised administrator account after repeated failed logons from 203.0.113.45.\n- Malware detection (Trojan:Win32/Sample.Demo) on DEMO-SRV02.\n## Recommended actions\n- Reset the administrator credentials and require MFA.\n- Isolate DEMO-SRV02 and run a full scan.\n- Patch the critical vulnerability within 72 hours.";
    if (/brute|failed log|logon|password|credential|account|admin/.test(q)) return "## Assessment (hypothesis)\nA burst of failed logons followed by a successful one from the same external address is a classic brute-force or password-spray pattern (MITRE T1110). Combined with persistence and defense-evasion alerts on the same host, a compromised administrator account is likely.\n## Confidence\n- Medium-high; confirm with the source IP reputation and the account's usual logon times.\n## Recommended actions\n- Disable or reset the account and revoke active sessions.\n- Block the source address at the firewall.\n- Review scheduled tasks and new services created after the successful logon.\n- Enforce MFA and account lockout.";
    if (/malware|trojan|virus|ransom|backdoor|defender|infect/.test(q)) return "## Assessment (hypothesis)\nDefender acted on a trojan dropper in a public folder. Because the file ran from C:\\Users\\Public, it may have executed before being quarantined.\n## Recommended actions\n- Isolate the host from the network while you check for a second-stage payload.\n- Search other hosts for the same file hash and for outbound connections to unusual destinations.\n- Review autoruns and scheduled tasks for persistence.\n- Restore from a clean backup if integrity cannot be confirmed.\n(Disruptive steps like isolation need human approval.)";
    if (/vuln|patch|cve|cvss|scan/.test(q)) return "## Prioritisation (hypothesis)\n- Fix first: the critical finding on an internet-facing or domain-joined server, then high findings with known exploits.\n- Medium findings can follow the normal patch cycle.\n## Recommended actions\n- Patch or apply the vendor mitigation, then re-scan to confirm.\n- Track the exception if a patch must be delayed, with an owner and date.";
    if (/event|4625|4624|4688|log/.test(q)) return "## Event analysis (hypothesis)\nThis normalized Windows event is consistent with the surrounding alert: look at the account, source address and logon type, and compare with the host's baseline. On its own it is low-confidence; in sequence with the neighbouring events it supports the incident narrative.\n## Next steps\n- Pivot on the account and source IP across all hosts for the last 24 h.";
    if (/investigat|alert|incident|triage/.test(q) || /Investigate/i.test(full.slice(0, 200))) return "## Investigation summary (hypothesis)\nSeven related alerts on DEMO-WS01 were grouped into one incident: failed logons, a successful logon from an external address, new persistence, then evasion activity - a plausible intrusion chain (Initial Access -> Execution -> Persistence -> Defense Evasion).\n## Severity: CRITICAL (confidence 0.9)\n## Recommended actions\n- Contain: isolate the workstation (needs approval).\n- Eradicate: remove the persistence entries and reset the account.\n- Recover: restore from a known-good image if tampering is confirmed.\n- Document the timeline and indicators for the post-incident review.";
    return "## Answer (general guidance, simulated)\nThis demo has a scripted analyst. Try questions about brute-force logons, malware, vulnerabilities, a specific alert, or ask for a security report. In the full product the AI SOC Analyst answers from your own events and cites evidence for every claim.\n- Tip: use the Investigate Alert, Analyze Event and Generate Security Report buttons.";
  }

  /* ---------- chrome: banner, tabs, CTAs, request-a-demo form ---------- */
  var css = "#aa-demo{position:sticky;top:0;z-index:2000;display:flex;flex-wrap:wrap;align-items:center;gap:8px 14px;padding:8px 14px;background:#7a4b00;color:#fff;font:600 13px/1.3 system-ui,sans-serif;border-bottom:1px solid #ffb74d}" +
    "#aa-demo b{background:#ffb74d;color:#3a2400;padding:2px 8px;border-radius:99px;letter-spacing:.04em}#aa-demo .sp{flex:1 1 120px}" +
    "#aa-demo a,#aa-demo button{color:#fff;background:rgba(255,255,255,.14);border:1px solid rgba(255,255,255,.35);border-radius:8px;padding:5px 11px;font:600 13px system-ui,sans-serif;text-decoration:none;cursor:pointer}" +
    "#aa-demo a:hover,#aa-demo button:hover{background:rgba(255,255,255,.28)}#aa-demo .pri{background:#4d8dff;border-color:#4d8dff}" +
    "nav.nv{top:var(--aa-h,44px)!important}#socws{top:var(--aa-h,44px)!important;inset:var(--aa-h,44px) 0 0 0!important}" +
    "#aa-modal{position:fixed;inset:0;z-index:3000;background:rgba(0,0,0,.7);display:none;align-items:center;justify-content:center;padding:16px}#aa-modal.open{display:flex}" +
    "#aa-modal form{background:#0e1626;color:#e8eefc;border:1px solid #2b3d63;border-radius:14px;padding:22px;width:100%;max-width:440px;font:14px system-ui,sans-serif;max-height:92vh;overflow:auto}" +
    "#aa-modal h2{margin:0 0 4px;font-size:20px}#aa-modal p{margin:0 0 12px;color:#9fb2d8}#aa-modal label{display:block;margin:10px 0 4px;font-weight:600}" +
    "#aa-modal input,#aa-modal textarea{width:100%;box-sizing:border-box;background:#0a1120;color:#fff;border:1px solid #2b3d63;border-radius:8px;padding:9px;font:inherit}" +
    "#aa-modal .row{display:flex;gap:8px;margin-top:14px}#aa-modal .row button{flex:1;padding:10px;border-radius:8px;border:0;font:700 14px system-ui;cursor:pointer;background:#4d8dff;color:#fff}#aa-modal .row .x{background:#243252}" +
    "#aa-modal .hp{position:absolute;left:-9999px}#aa-modal .msg{margin-top:10px;min-height:18px}#aa-modal .msg.er{color:#ff8a80}#aa-modal .msg.ok{color:#7be495}" +
    "@media(max-width:600px){#aa-demo{font-size:12px}#aa-demo .hide-s{display:none}}";
  var st = document.createElement("style"); st.textContent = css; document.head.appendChild(st);

  function build() {
    var bar = document.createElement("div"); bar.id = "aa-demo"; bar.setAttribute("role", "region"); bar.setAttribute("aria-label", "Demo controls");
    bar.innerHTML = '<b>DEMO DATA</b><span class="hide-s">Simulated environment. Not connected to any real system, customer or production data.</span><span class="sp"></span>' +
      '<a href="/#/home">&larr; Back to Website</a><a href="#/soc" id="aa-soc">SOC demo</a><a href="#/noc" id="aa-noc">NOC demo</a>' +
      '<button type="button" id="aa-req">Request a Demo</button><a class="pri" href="/account.html">Create Account</a>';
    document.body.insertBefore(bar, document.body.firstChild);
    document.documentElement.style.setProperty("--aa-h", bar.offsetHeight + "px");
    window.addEventListener("resize", function () { document.documentElement.style.setProperty("--aa-h", bar.offsetHeight + "px"); });
    var md = document.createElement("div"); md.id = "aa-modal"; md.setAttribute("role", "dialog"); md.setAttribute("aria-modal", "true"); md.setAttribute("aria-labelledby", "aa-mt");
    md.innerHTML = '<form novalidate><h2 id="aa-mt">Request a Demo</h2><p>Tell us a little about you and we will arrange a walkthrough with your own data.</p>' +
      '<label for="aa-n">Name</label><input id="aa-n" name="name" autocomplete="name" maxlength="120" required>' +
      '<label for="aa-e">Work email</label><input id="aa-e" name="email" type="email" autocomplete="email" maxlength="200" required>' +
      '<label for="aa-c">Company</label><input id="aa-c" name="company" autocomplete="organization" maxlength="160">' +
      '<label for="aa-m">What would you like to see?</label><textarea id="aa-m" name="message" rows="3" maxlength="2000"></textarea>' +
      '<input class="hp" name="website" tabindex="-1" autocomplete="off" aria-hidden="true">' +
      '<div class="msg" role="status" aria-live="polite"></div><div class="row"><button type="submit">Send request</button><button type="button" class="x">Close</button></div></form>';
    document.body.appendChild(md);
    var f = md.querySelector("form"), msg = md.querySelector(".msg");
    function open() { md.classList.add("open"); msg.textContent = ""; msg.className = "msg"; setTimeout(function () { f.name.focus(); }, 30); }
    function close() { md.classList.remove("open"); }
    document.getElementById("aa-req").addEventListener("click", open);
    md.querySelector(".x").addEventListener("click", close);
    md.addEventListener("click", function (e) { if (e.target === md) close(); });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape") close(); });
    window.aaOpenRequest = open;
    f.addEventListener("submit", function (e) {
      e.preventDefault(); msg.className = "msg"; msg.textContent = "Sending...";
      var d = { name: f.name.value, email: f.email.value, company: f.company.value, message: f.message.value, website: f.website.value };
      window.fetch("/api/demo-request", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(d) })
        .then(function (r) { return r.text().then(function (t) { var j = {}; try { j = JSON.parse(t); } catch (x) {} if (!r.ok) throw new Error(j.error || "Could not send your request right now."); }); })
        .then(function () { msg.className = "msg ok"; msg.textContent = "Thank you. We have received your request."; f.reset(); })
        .catch(function (er) { msg.className = "msg er"; msg.textContent = er.message || "Could not send your request."; });
    });
    /* nav buttons on the page itself */
    var nr = document.querySelector("nav.nv .nr");
    if (nr) nr.innerHTML = '<a class="btn" href="/account.html">Sign In</a><a class="btn" href="/account.html">Create Account</a><a class="btn" href="#" id="aa-nreq">Request a Demo</a>';
    var nq = document.getElementById("aa-nreq"); if (nq) nq.addEventListener("click", function (e) { e.preventDefault(); open(); });
    if (/[?&]request=1\b/.test(location.search)) setTimeout(open, 400);
    function openSoc() { var b = document.querySelector('.soc-hot[data-role="analyst"]'); if (b) b.click(); }
    document.getElementById("aa-soc").addEventListener("click", function () { setTimeout(openSoc, 250); });
    if (!location.hash || /^#\/?(home|top)?$/.test(location.hash)) location.hash = "#/soc";
    if (/^#\/?(soc|doc)$/.test(location.hash) && !/[?&]request=1\b/.test(location.search)) setTimeout(openSoc, 700);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", build); else build();
})();
