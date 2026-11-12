#!/usr/bin/env python3
"""Idempotent. Adds the NOC page and the page router (home / SOC / NOC) to Spark landing page copies.
usage: apply-noc.py page.html [page2.html ...]   (run apply-theme-night.py first)"""
import re, sys, os
D = os.path.dirname(os.path.abspath(__file__))
rd = lambda n: open(os.path.join(D, n), encoding="utf-8").read()
NAV = ('<nav class="nv" id="top"><a class="logo" href="#/home">Spark<span>.</span></a>'
 '<div class="nl"><a class="l" data-nav="home" href="#/home">Home Page</a><a class="l" data-nav="soc" href="#/soc">SOC AI Agents</a><a class="l" data-nav="noc" href="#/noc">NOC AI Agents</a>'
 '<a class="l" href="#features">Portfolio</a><a class="l" href="#how">Process</a><a class="l" href="#pricing">Pricing</a><a class="l" href="#contact">Contact us</a></div>'
 '<div class="nr"><a href="/studio">Ask AI</a><a class="btn" href="#builder">Try it</a></div></nav>')
PAGES_CSS = '''<style id="pages-css">
body[data-view="home"] [data-page]:not([data-page="home"]),body[data-view="soc"] [data-page]:not([data-page="soc"]),body[data-view="noc"] [data-page]:not([data-page="noc"]){display:none!important}
nav.nv{grid-template-columns:auto 1fr auto}nav.nv .nr,nav.nv .nr a{white-space:nowrap}nav.nv .nl{gap:28px}nav.nv .nl a[aria-current="page"]{color:#fff;text-shadow:0 0 16px rgba(77,141,255,.9);box-shadow:0 2px 0 0 #4d8dff}
@media(max-width:1100px){nav.nv .nl{gap:18px}nav.nv .nl a{font-size:15px}}@media(max-width:980px){nav.nv{grid-template-columns:1fr auto}nav.nv .nl{gap:22px}}
</style>'''
ROUTER_EARLY = '<script id="router-early">(function(){var h=(location.hash||"").replace(/^#\\/?/,""),p=(location.pathname||"").replace(/\\/+$/,"").split("/").pop(),v=h==="soc"||h==="doc"?"soc":h==="noc"?"noc":h==="home"||h==="top"?"home":h?"home":p==="soc"?"soc":p==="noc"?"noc":"home";document.body.setAttribute("data-view",v)})();</script>'
ROUTER = '''<script id="router">(function(){
var T0=document.title,TT={soc:"SOC AI Agents | Spark",noc:"NOC AI Agents | Spark"};
function parse(){var h=(location.hash||"").replace(/^#\\/?/,""),p=(location.pathname||"").replace(/\\/+$/,"").split("/").pop(),def=p==="soc"?"soc":p==="noc"?"noc":"home";
 if(h==="soc"||h==="doc")return"soc";if(h==="noc")return"noc";if(h==="home"||h==="top")return"home";if(!h)return def;
 var el=document.getElementById(h);if(!el)return def==="home"?(document.body.getAttribute("data-view")||"home"):def;var pg=el.closest("[data-page]");return pg?pg.getAttribute("data-page"):(document.body.getAttribute("data-view")||def)}
function apply(first){var v=parse(),old=document.body.getAttribute("data-view");document.body.setAttribute("data-view",v);document.title=TT[v]||T0;
 var as=document.querySelectorAll("nav.nv a[data-nav]");for(var i=0;i<as.length;i++){if(as[i].getAttribute("data-nav")===v)as[i].setAttribute("aria-current","page");else as[i].removeAttribute("aria-current")}
 var h=(location.hash||"").replace(/^#\\/?/,""),el=h&&document.getElementById(h);
 if(v!==old||first){if(el&&el.closest("[data-page]")&&h!=="soc"&&h!=="noc"&&h!=="doc"){setTimeout(function(){el.scrollIntoView()},30)}else window.scrollTo(0,0)}
 try{document.dispatchEvent(new Event("sparkview"))}catch(e){}}
window.addEventListener("hashchange",function(){apply(false)});
if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",function(){apply(true)});else apply(true);
})();</script>'''
for p in sys.argv[1:]:
    s = open(p, encoding="utf-8").read()
    # 1. nav
    s, n = re.subn(r'<nav class="nv".*?</nav>', lambda m: NAV, s, count=1, flags=re.S); assert n == 1, "themed nav not found (run apply-theme-night.py first): " + p
    # 2. data-page attributes
    def tag(pat, page):
        global s
        s = re.sub(pat, lambda m: m.group(1) + ' data-page="' + page + '"' if 'data-page=' not in m.group(0) else m.group(0), s, count=1)
    tag(r'(<header class="hero")(?![^>]*data-page)', "home")
    for i, pg in [("builder", "home"), ("trust", "home"), ("features", "home"), ("how", "home"), ("pricing", "home"), ("doc", "soc"), ("soc", "soc")]:
        tag(r'(<section id="%s")(?![^>]*data-page)' % i, pg)
    s = re.sub(r'<section><div class="final">', '<section data-page="home"><div class="final">', s, count=1)
    # 3. body attr + early router
    if 'id="router-early"' not in s:
        s = re.sub(r'<body([^>]*)>', lambda m: '<body' + re.sub(r'\sdata-view="[^"]*"', '', m.group(1)) + ' data-view="home">' + ROUTER_EARLY, s, count=1)
    # 4. CSS (pages + noc)
    s = re.sub(r'<style id="pages-css">.*?</style>', '', s, flags=re.S); s = re.sub(r'<style id="noc-css">.*?</style>', '', s, flags=re.S)
    s = s.replace("</head>", PAGES_CSS + '<style id="noc-css">' + rd("noc.css") + rd("topo.css") + "</style></head>", 1)
    # 5. NOC section + script, then router
    s = re.sub(r'<!--NOC-BEGIN-->.*?<!--NOC-END-->', '', s, flags=re.S); s = re.sub(r'<script id="router">.*?</script>', '', s, flags=re.S)
    part = rd("noc.part.html").replace("/*NOC_JS*/", rd("noc.js").replace("</script", "<\\/script")).replace("/*TOPO_JS*/", rd("topo.js").replace("</script", "<\\/script"))
    assert '<section id="how"' in s, "how section not found"
    s = s.replace('<section id="how"', part + '<section id="how"', 1)
    s = s.replace("</body>", ROUTER + "</body>", 1)
    open(p, "w", encoding="utf-8").write(s); print(p, "ok", len(s))
