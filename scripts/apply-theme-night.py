#!/usr/bin/env python3
"""Idempotent: restyle the Spark landing page to the near-black / navy-glow look with a centered pill-less top nav.
usage: apply-theme-night.py page.html [page2.html ...]"""
import re, sys
TOK = [("#1a1217","#050608"),("#261a1f","#0a0d14"),("#3f2b30","#1b2233"),("#f6ece4","#e9edf5"),("#b79a8f","#aab3c5"),
       ("#ed9157","#4d8dff"),("#c8694b","#2f5bd8"),("237,145,87","77,141,255"),("166,93,69","24,52,130"),("26,18,23","5,6,8")]
FONT = '<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">'
CSS = '''<style id="theme-night">
body{font-family:"Inter",system-ui,-apple-system,"Segoe UI",sans-serif;
background-color:var(--bg);
background-image:radial-gradient(ellipse 55% 75% at 100% 0%,rgba(22,48,120,.62),rgba(12,26,70,.28) 45%,transparent 72%),repeating-linear-gradient(90deg,rgba(255,255,255,.028) 0,rgba(255,255,255,.028) 1px,transparent 1px,transparent 46px);
background-attachment:fixed}
nav.nv{position:sticky;top:0;z-index:60;display:grid;grid-template-columns:1fr auto 1fr;align-items:center;gap:16px;padding:18px 20px;margin:0 -20px}
nav.nv::before{content:"";position:absolute;z-index:-1;top:0;bottom:0;left:50%;width:100vw;transform:translateX(-50%);background:linear-gradient(180deg,rgba(5,6,8,.78),rgba(5,6,8,.35));-webkit-backdrop-filter:blur(10px);backdrop-filter:blur(10px)}
nav.nv .logo{font-weight:800;font-size:22px;color:var(--fg);text-decoration:none;margin:0;justify-self:start}
nav.nv .nl{display:flex;gap:42px;justify-content:center}
nav.nv .nl a{margin:0;color:#cdd3df;font-size:16px;font-weight:500;text-decoration:none;white-space:nowrap;transition:color .2s,text-shadow .2s}
nav.nv .nl a:hover,nav.nv .nl a:focus-visible{color:#fff;text-shadow:0 0 18px rgba(77,141,255,.8);outline:none}
nav.nv .nr{display:flex;gap:14px;align-items:center;justify-self:end}
nav.nv .nr a{margin:0;font-size:15px;color:#cdd3df;text-decoration:none}
nav.nv .nr a.btn{color:var(--onac);padding:9px 18px;font-size:14px}
@media(max-width:980px){nav.nv{grid-template-columns:1fr auto}nav.nv .nl{grid-column:1/-1;grid-row:2;gap:26px;justify-content:flex-start;overflow-x:auto;padding-bottom:4px;scrollbar-width:none}nav.nv .nl::-webkit-scrollbar{display:none}}
@media(max-width:560px){nav a.l{display:inline}nav.nv .nr a:not(.btn){display:none}nav.nv .nl a{font-size:15px}}
html{scroll-behavior:smooth}section[id],footer[id],header[id]{scroll-margin-top:84px}
</style>'''
NAV = ('<nav class="nv" id="top"><a class="logo" href="#top">Spark<span>.</span></a>'
 '<div class="nl"><a class="l" href="#top">Home Page</a><a class="l" href="#soc">AI Agents</a><a class="l" href="#features">Portfolio</a>'
 '<a class="l" href="#how">Process</a><a class="l" href="#pricing">Pricing</a><a class="l" href="#contact">Contact us</a></div>'
 '<div class="nr"><a href="/studio">Ask AI</a><a class="btn" href="#builder">Try it</a></div></nav>')
for p in sys.argv[1:]:
    s = open(p, encoding="utf-8").read()
    for a, b in TOK: s = s.replace(a, b)
    if 'id="theme-night"' not in s:
        s = s.replace("</head>", FONT + CSS + "</head>", 1)
    if 'class="nv"' not in s:
        s, n = re.subn(r"<nav>.*?</nav>", lambda m: NAV, s, count=1, flags=re.S); assert n == 1, "nav not found in " + p
    s = s.replace("<footer>Copyright", '<footer id="contact">Copyright', 1) if '<footer id="contact"' not in s else s
    open(p, "w", encoding="utf-8").write(s); print(p, "ok", len(s))
