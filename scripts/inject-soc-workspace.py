#!/usr/bin/env python3
"""Injects the SOC Analyst workspace (scripts/soc-workspace.part.html) and the clickable pill into a landing page.
Usage: python3 scripts/inject-soc-workspace.py sample.json page.html [page2.html ...]
Idempotent: re-running replaces the previous injection."""
import re, sys, json
sample = open(sys.argv[1]).read().strip()
json.loads(sample)
here = __file__.rsplit('/', 1)[0] if '/' in __file__ else '.'
rd = lambda n: open(here + '/' + n).read()
part = rd('soc-workspace.part.html').replace('/*SOCWS_SAMPLE*/null', sample.replace('</', '<\\/'))
js = lambda t: t.replace('</script', '<\\/script')
collector = json.dumps(rd('../collector/windows/Send-SecurityEvents.ps1')).replace('</', '<\\/')
part = part.replace('/*SOCWS_ROLESJS*/', rd('soc-roles.js').replace('/*SOCWS_COLLECTOR*/""', collector)).replace('/*SOCWS_CONSOLE*/', rd('soc-console.js')).replace('/*SOCWS_ORCH*/', rd('soc-orch.js')).replace('/*SOCWS_ROLES_INIT_JS*/', rd('soc-roles-init.js')).replace('/*SOCWS_ENGINE*/', js(rd('engine.browser.js')))
WALLDIV = '<!--SWD--><div class="soc-wall" id="socWall" aria-hidden="true"><div class="sw-live">LIVE SIMULATION · demo data</div><div class="sw-p sw-1"><div><h4 class="sw-h">Threat Monitoring</h4><div class="sw-l"></div></div><div class="sw-mapw"><canvas></canvas></div></div><div class="sw-p"><h4 class="sw-h">Live Security Events</h4><div class="sw-ev"></div></div><div class="sw-p"><h4 class="sw-h">Network Traffic</h4><div class="sw-tr"><canvas></canvas></div><div class="sw-g"></div></div><div class="sw-p red sw-4"><div><h4 class="sw-h">Threat Intelligence</h4><div class="sw-map" style="height:100%"><canvas style="height:100%"></canvas></div></div><div class="sw-l"></div></div><div class="sw-p"><h4 class="sw-h">System Status</h4><div class="sw-st"></div></div></div><!--/SWD-->'
wallpart = rd('soc-wall.part.html')
ROLES = [("analyst", "SOC Analyst"), ("engineer", "Security Engineer"), ("hunter", "Threat Hunter"), ("responder", "Incident Responder"), ("siem", "SIEM Specialist"), ("ciso", "CISO")]
HOT = ''.join('<button type="button" class="soc-hot" %sdata-role="%s" aria-haspopup="dialog" aria-label="Open the %s AI workspace"><span class="tip" aria-hidden="true">Open %s workspace</span><span class="sts" aria-hidden="true">Idle</span></button>' % ('id="socHot" ' if k == 'analyst' else '', k, n, n) for k, n in ROLES) + ''.join('<span class="soc-robot" data-role="%s" aria-hidden="true"></span>' % k for k, n in ROLES)
BTN = '<ul class="soc-stl" id="socStl" role="status" aria-label="AI agent status"></ul><p class="dnote" id="socOpenRow"><button type="button" class="soc-open2" id="socHot2" aria-haspopup="dialog">Open the SOC Analyst AI workspace &rarr;</button> <button type="button" class="soc-open2 soc-open3" id="socHot3" data-role="team" aria-haspopup="dialog">Open the AI Agent Collaboration Center &rarr;</button></p>'
for p in sys.argv[2:]:
    h = open(p).read()
    h = re.sub(r'<!--SOCWS-START-->.*?<!--SOCWS-END-->', '', h, flags=re.S)
    h = re.sub(r'<button type="button" class="soc-hot".*?</button>', '', h, flags=re.S)
    h = re.sub(r'<!--SOCWALL-START-->.*?<!--SOCWALL-END-->', '', h, flags=re.S)
    h = re.sub(r'<!--SWD-->.*?<!--/SWD-->', '', h, flags=re.S)
    h = re.sub(r'<span class="soc-robot"[^>]*></span>', '', h)
    h = re.sub(r'<ul class="soc-stl".*?</ul>', '', h, flags=re.S)
    h = re.sub(r'<p class="dnote" id="socOpenRow">.*?</p>', '', h, flags=re.S)
    m = re.search(r'<div class="ds" id="soct" style="[^"]*">(<img [^>]*>)</div>', h)
    assert m, 'soct block not found in ' + p
    h = h.replace(m.group(0), '<div class="ds" id="soct" style="aspect-ratio:3/2">' + m.group(1) + WALLDIV + HOT + '</div>', 1)
    h = h.replace('<p class="dnote">AI-generated illustration of an AI security team.</p>', '<p class="dnote">AI-generated illustration of an AI security team.</p>' + BTN, 1)
    i = h.rindex('</body>')
    h = h[:i] + part + wallpart + h[i:]
    open(p, 'w').write(h)
    print(p, 'ok', len(h))
