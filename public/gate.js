/* Auth gate for the SOC/NOC dashboards on the public page.
   Client-side gate = UX only. The real protection is server-side: every /api/soc/* call needs a valid Supabase JWT (401 otherwise).
   Unauthenticated visitors (no token, or a token the server rejects) never see the SOC workspace or the NOC dashboard: they are sent to the sign-in page.
   The simulated public demo lives at /demo and is exempt (it has no backend and uses only built-in sample data). */
(function () {
  "use strict";
  if (/^\/demo\/?$/.test(location.pathname)) return; // exact /demo only
  var KEYS = ["socToken", "aaSession"], ok = false, pending = null, bypass = false, needOrg = false;
  var st = document.createElement("style");
  st.textContent = 'html:not(.aa-ok) body[data-view="soc"] [data-page="soc"],html:not(.aa-ok) body[data-view="noc"] [data-page="noc"],html:not(.aa-ok) #socws{display:none!important}';
  document.head.appendChild(st);
  function tok() { try { return sessionStorage.getItem("socToken") || ""; } catch (e) { return ""; } }
  function clear() { KEYS.forEach(function (k) { try { sessionStorage.removeItem(k); } catch (e) {} }); }
  function setOk(v) { ok = v; document.documentElement.classList.toggle("aa-ok", v); var b = document.getElementById("aaSignout"); if (b) b.style.display = v ? "" : "none"; }
  function toLogin() { location.replace("/account.html?" + (needOrg ? "need=org&" : "") + "next=" + encodeURIComponent(location.pathname + (location.hash || "#/soc"))); }
  function authed() {
    var t = tok(); if (!t) return Promise.resolve(false);
    if (pending) return pending;
    window.__aaChecking = true;
    pending = fetch("/api/soc/me", { headers: { Authorization: "Bearer " + t }, cache: "no-store" }).then(function (r) {
      var ct = r.headers.get("content-type") || "";
      if (r.ok && ct.indexOf("json") >= 0) return true;
      // 401 = the server rejected the token: sign-in is invalid, forget it.
      // 403/409 = the token is VALID but the user has no organization (or must choose one): keep the session and send them to the account page to fix that.
      if (r.status === 401) clear(); else if (r.status === 403 || r.status === 409) needOrg = true;
      return false;
    }).catch(function () { return false; }).then(function (v) { pending = null; window.__aaChecking = false; setOk(v); return v; });
    return pending;
  }
  function view() { return document.body && document.body.getAttribute("data-view"); }
  function guard() { var v = view(); if (v !== "soc" && v !== "noc") return; if (ok) return; authed().then(function (a) { if (!a) toLogin(); }); }
  document.addEventListener("click", function (e) {
    if (bypass) return;
    var el = e.target.closest && e.target.closest(".soc-hot,#noc-opensoc,[data-open-soc]"); if (!el) return;
    if (ok) return;
    e.preventDefault(); e.stopImmediatePropagation();
    authed().then(function (a) { if (!a) return toLogin(); bypass = true; try { el.click(); } finally { bypass = false; } });
  }, true);
  function init() {
    var nr = document.querySelector("nav.nv .nr");
    if (nr && !document.getElementById("aaSignout")) {
      var a = document.createElement("a"); a.className = "btn"; a.id = "aaSignout"; a.href = "#"; a.textContent = "Sign out"; a.style.display = "none"; a.style.marginLeft = "8px";
      a.addEventListener("click", function (ev) {
        ev.preventDefault(); var t = tok(); clear(); setOk(false);
        var done = function () { if (view() === "soc" || view() === "noc") location.replace("/#/home"); location.reload(); };
        if (!t) return done();
        fetch("/api/auth/config").then(function (r) { return r.json(); }).then(function (c) { return c.configured ? fetch(c.url + "/auth/v1/logout", { method: "POST", headers: { apikey: c.anonKey, Authorization: "Bearer " + t } }) : null; }).then(done, done);
      });
      nr.appendChild(a);
    }
    authed().then(function () { guard(); });
  }
  document.addEventListener("sparkview", guard);
  window.addEventListener("hashchange", function () { setTimeout(guard, 0); });
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
})();
