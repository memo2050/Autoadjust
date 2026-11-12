/* ---------- Agent investigation consoles (one per SOC role) ----------
   Each agent runs its OWN analysis over the data in view (sample or connected) using the Spark rule engine.
   The run is paced so the person can watch it. It is a rule-based analysis, not a live scan of any system,
   and it never carries out a response action: containment items are only recorded as requests for approval. */
var STG=["User request","AI agent","Security analysis","Threat detection","Investigation","Report"];
var SRANK={critical:4,high:3,medium:2,low:1,info:0};
var AG={},AGSEQ=0;
var CON={
 analyst:{title:"SOC ANALYST \u2014 AI SECURITY INVESTIGATION",def:"Investigate suspicious login attempts.",chips:["Investigate suspicious login attempts.","Check for malware activity","Look for phishing indicators","Review all recent alerts"],caps:["Alert triage","Brute-force and password spraying","Malware","Phishing indicators","Event correlation","Severity rating","Investigation report"],run:"Investigating",tool:"Windows Security events, rule alerts"},
 engineer:{title:"SECURITY ENGINEER \u2014 CONFIGURATION AND HARDENING REVIEW",def:"Review infrastructure security configuration and prepare a remediation plan.",chips:["Review infrastructure security configuration and prepare a remediation plan.","Review exposed services and firewall risk","Hardening recommendations"],caps:["Vulnerabilities","Misconfigurations","Exposed services","Firewall risk review","Hardening","Remediation plan"],run:"Investigating",tool:"scan findings, rule alerts"},
 hunter:{title:"THREAT HUNTER \u2014 PROACTIVE HUNT",def:"Hunt for hidden threats, lateral movement and indicators of compromise.",chips:["Hunt for hidden threats, lateral movement and indicators of compromise.","Hunt for lateral movement","Extract indicators of compromise"],caps:["Hypothesis hunts","IOC extraction","Lateral movement","Suspicious authentication","Intrusion-chain view","Hunting report"],run:"Investigating",tool:"normalized events"},
 responder:{title:"INCIDENT RESPONDER \u2014 INCIDENT RESPONSE",def:"Respond to the highest-severity active incident.",chips:["Respond to the highest-severity active incident.","Build the response timeline","Prepare containment options"],caps:["Response timeline","Severity and priority","Containment options","Eradication and recovery","Approval-gated actions","Incident report"],run:"Investigating",tool:"incident, alerts, timeline"},
 siem:{title:"SIEM SPECIALIST \u2014 LOG ANALYSIS AND QUERIES",def:"Find repeated failed logons (event 4625) and generate SIEM queries.",chips:["Find repeated failed logons (event 4625) and generate SIEM queries.","Show successful logons (4624) for user alice","Search events from IP 198.51.100.23","Check Linux, firewall and network log coverage"],caps:["Windows log search","Correlation","Query generation","Failed-logon detection","Source coverage","Query results"],run:"Investigating",tool:"stored events"},
 ciso:{title:"CISO \u2014 EXECUTIVE SECURITY INTELLIGENCE",def:"Prepare an executive briefing on current security posture and risks.",chips:["Prepare an executive briefing on current security posture and risks.","What decisions do I need to make this week?","Summarize risk and KPIs"],caps:["Security posture","Top risks","KPIs","Decisions needed","Strategic priorities","Executive report"],run:"Reviewing",tool:"posture, incidents, vulnerabilities"}
};
function agState(r){return AG[r]||(AG[r]={status:"Idle",progress:0,stage:-1,steps:[],done:0,log:[],reveal:0,res:null,tok:0,timer:null,running:false,task:"",err:"",note:"",pend:null})}
function fT(iso){var d=new Date(iso);return isFinite(d)?d.toLocaleTimeString([],{hour12:false}):"?"}
function fDT(iso){var d=new Date(iso);return isFinite(d)?d.toLocaleDateString([],{month:"short",day:"numeric"})+" "+d.toLocaleTimeString([],{hour12:false}):"?"}
function maxSev(a){var m="low";a.forEach(function(x){if((SRANK[x.sev]||0)>(SRANK[m]||0))m=x.sev});return m}
function uniqA(a){var o=[];a.forEach(function(x){if(x&&o.indexOf(x)<0)o.push(x)});return o}
function dataLabel(){var ev=evs(),demo=ev.filter(function(e){return e.source==="demo"}).length;
 if(S.mode!=="connected")return{kind:"sample",text:"SIMULATED: sample data. Nothing real was scanned, collected or protected."};
 if(demo&&demo===ev.length)return{kind:"sample",text:"SIMULATED: the backend holds only sample events."};
 if(demo)return{kind:"mixed",text:"CONNECTED data mixed with "+demo+" sample event(s) (marked SAMPLE)."};
 return{kind:"live",text:"Computed from data stored in your SOC backend. Only systems that send data to it are covered."}}
function evSec(){return evs().filter(function(e){return/security/i.test(e.channel||"")})}
function isPub(ip){return!!ip&&!/^(10\.|192\.168\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|::1|fe80)/i.test(ip)}
function mk(){return{head:"",sev:"low",L:{1:[],2:[],3:[],4:[]},findings:[],table:null,extra:[],recs:[],limits:[],md:"",stages:null}}
/* ---- analyst ---- */
function bAnalyst(task,ctx){var R=mk(),t=task.toLowerCase(),focus=/phish|e-?mail|mail\b/.test(t)?"phishing":/malware|virus|trojan|ransom|defender|payload/.test(t)?"malware":/login|logon|password|brute|spray|credential|auth|sign.?in/.test(t)?"login":/alert/.test(t)?"alerts":"login";
 var ev=evs(),sec=evSec(),alerts=(S.data&&S.data.recentAlerts)||[];
 R.L[1].push("SOC Analyst accepted the task. Focus: "+focus+".","Plan: group events by source and account, correlate with rule alerts, rate severity, write the report.");
 R.L[2].push("Loaded "+ev.length+" normalized events ("+sec.length+" from the Security log) and "+alerts.length+" rule alerts.");
 var fails=sec.filter(function(e){return e.eventId===4625}),oks=sec.filter(function(e){return e.eventId===4624}),lock=sec.filter(function(e){return e.eventId===4740});
 if(focus==="login"||focus==="alerts"){
  var by={};fails.forEach(function(e){var k=e.srcIp||"(local / no address)";(by[k]=by[k]||[]).push(e)});
  R.L[2].push("Found "+fails.length+" failed logons (4625), "+oks.length+" successful (4624) and "+lock.length+" lockouts (4740).","Grouped failed logons by source address: "+Object.keys(by).length+" source(s).");
  var rows=Object.keys(by).map(function(ip){var g=by[ip],us=uniqA(g.map(function(e){return e.targetUser||e.user})),ts=g.map(function(e){return Date.parse(e.time)}),f=Math.min.apply(null,ts),l=Math.max.apply(null,ts);
   var after=oks.filter(function(o){return o.srcIp===ip&&Date.parse(o.time)>=f});var sv=after.length&&g.length>=3?"critical":g.length>=10||us.length>=5?"high":g.length>=5?"high":g.length>=3?"medium":"low";
   return{ip:ip,n:g.length,us:us,f:f,l:l,after:after,sev:sv,ids:g.slice(0,3).map(function(e){return e.id})}}).sort(function(a,b){return SRANK[b.sev]-SRANK[a.sev]||b.n-a.n});
  if(ctx&&ctx.ips&&ctx.ips.length){rows.sort(function(a,b){return(ctx.ips.indexOf(b.ip)>=0)-(ctx.ips.indexOf(a.ip)>=0)});R.L[2].push("Using the SIEM Specialist's handoff: checking "+ctx.ips.slice(0,3).join(", ")+" first instead of re-counting every source.")}
  R.table={title:"Suspicious sources (failed logons)",cols:["Source IP","Failed","Accounts","First seen","Last seen","Logon after failures","Severity"],rows:rows.slice(0,12).map(function(r){return[r.ip+(isPub(r.ip)?" (public)":""),r.n,r.us.slice(0,4).join(", ")+(r.us.length>4?" +"+(r.us.length-4):""),fDT(new Date(r.f).toISOString()),fDT(new Date(r.l).toISOString()),r.after.length?"YES ("+r.after.length+")":"no",sev(r.sev)]}),raw:true};
  rows.filter(function(r){return r.sev!=="low"}).forEach(function(r){var ac=r.us.length>1?"password spraying across "+r.us.length+" accounts":"repeated guessing against "+(r.us[0]||"an account");
   R.findings.push({sev:r.sev,t:r.n+" failed logons from "+r.ip+": "+ac+(r.after.length?". A SUCCESSFUL logon followed from the same address, so the account may be compromised.":"."),ev:r.ids})});
  R.L[4].push(rows.some(function(r){return r.after.length&&r.n>=3})?"Checked for success after failure: a successful logon followed failures, which raises severity.":"Checked for success after failure: none found.");
  R.L[4].push("Mapped to MITRE ATT&CK T1110 (Brute Force / Password Spraying).");
  rows.filter(function(r){return r.sev==="critical"||r.sev==="high"}).slice(0,3).forEach(function(r){
   if(r.ip.indexOf("(")<0)R.recs.push({p:"P1",t:"Block "+r.ip+" at the firewall after confirming it is not a legitimate user or scanner.",type:"block_ip",target:r.ip,dis:true});
   (r.after.slice(0,1)).forEach(function(o){var u=o.targetUser||o.user;if(u)R.recs.push({p:"P1",t:"Reset the password of "+u+" and review the logon that followed the failures.",type:"reset_password",target:u,dis:true})})});
 }
 if(focus==="malware"||focus==="alerts"){
  var def=ev.filter(function(e){return e.eventId===1116||e.eventId===1117}),cmd=ev.filter(function(e){return e.eventId===4688&&/\\(users\\public|appdata|temp)\\/i.test((e.process||"")+" "+(e.commandLine||""))});
  R.L[2].push("Checked endpoint-protection events: "+def.length+" Defender detection(s); "+cmd.length+" process(es) started from user-writable folders.");
  def.slice(0,4).forEach(function(e){var d=e.data||{};R.findings.push({sev:/severe|high/i.test(d["Severity Name"]||"")?"critical":"high",t:"Defender: "+(d["Threat Name"]||e.summary)+" on "+e.host+(d.Path?" ("+d.Path+")":"")+". "+(e.eventId===1117?"Action was taken; confirm the file was removed and find how it arrived.":"Detection only; confirm it was blocked."),ev:[e.id]})});
  cmd.slice(0,3).forEach(function(e){R.findings.push({sev:"medium",t:"Process started from a user-writable folder on "+e.host+": "+(e.process||e.commandLine||"").slice(0,90),ev:[e.id]})});
  R.L[4].push("Malware triage: compared detections against process starts on the same hosts.");
  var hosts=uniqA(def.map(function(e){return e.host}));hosts.slice(0,2).forEach(function(h){R.recs.push({p:"P1",t:"Isolate "+h+" from the network until a full scan and review are complete.",type:"isolate_host",target:h,dis:true})});
  if(!R.table&&def.length)R.table={title:"Endpoint protection detections",cols:["Time","Host","Threat","Path","Event"],rows:def.slice(0,10).map(function(e){return[fDT(e.time),e.host,(e.data||{})["Threat Name"]||e.summary,(e.data||{}).Path||"",e.eventId]})};
 }
 if(focus==="phishing"){
  var off=ev.filter(function(e){return e.eventId===4688&&/(winword|excel|outlook|powerpnt|onenote|acrord32)/i.test(e.parentProcess||"")&&/(powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32)/i.test((e.process||"")+" "+(e.commandLine||""))});
  R.L[2].push("No mail gateway or user-reported-phish source is connected to Spark, so mail content cannot be examined.","Checked endpoint process chains instead: "+off.length+" case(s) of Office or mail clients launching script hosts.");
  off.slice(0,4).forEach(function(e){R.findings.push({sev:"high",t:(e.parentProcess||"Office")+" launched "+(e.process||"a script host")+" on "+e.host+". This is a common result of opening a malicious attachment.",ev:[e.id]})});
  R.limits.push("Phishing email itself cannot be analyzed: no mail source is connected.");
  R.L[4].push("Mapped to ATT&CK T1566 (Phishing) / T1204 (User Execution) as hypotheses.");
  R.table={title:"Office / mail client process chains",cols:["Time","Host","Parent","Child"],rows:off.slice(0,10).map(function(e){return[fDT(e.time),e.host,e.parentProcess||"",e.process||""]})};
 }
 var al=alerts.filter(function(a){return focus==="alerts"||(focus==="login"&&/^WIN-AUTH/.test(a.ruleId))||(focus==="malware"&&/^WIN-(MAL|EXEC)/.test(a.ruleId))});
 R.L[2].push("Correlated with "+al.length+" rule alert(s) for this focus.");
 al.slice(0,5).forEach(function(a){R.findings.push({sev:a.severity,t:"Rule "+a.ruleId+": "+a.title+" on "+a.host+" ("+Math.round(a.confidence*100)+"% rule confidence).",ev:(a.eventIds||[]).slice(0,3)})});
 R.findings.sort(function(a,b){return SRANK[b.sev]-SRANK[a.sev]});R.findings=R.findings.slice(0,10);R.L[3].push(R.findings.length?"Threat detection found "+R.findings.length+" item(s) of interest.":"Threat detection found nothing above low severity.");
 R.sev=R.findings.length?maxSev(R.findings):"low";R.L[4].push("Severity assigned: "+R.sev.toUpperCase()+" (highest finding).");
 R.head=R.findings.length?R.findings.length+" finding(s), overall severity "+R.sev.toUpperCase()+".":"No suspicious activity above low severity in "+ev.length+" events.";
 if(!R.recs.length)R.recs.push({p:"P3",t:R.findings.length?"Review the cited events and decide whether a response is needed.":"Keep monitoring; widen the search window or add log sources if you expect activity.",dis:false});
 R.limits.push("Evidence is limited to events in view ("+ev.length+"). Absence of findings is not proof of safety.");R.mdTitle="SOC Analyst investigation report";return R}
/* ---- engineer ---- */
function bEngineer(task,ctx){var R=mk(),t=task.toLowerCase(),V=vulnsAll(),al=(S.data&&S.data.recentAlerts)||[];
 var plan=E.remediationPlan(V,(S.data&&S.data.assets)||[]);
 R.L[1].push("Security Engineer accepted the task.","Plan: rank open findings, classify misconfigurations, review exposed services, build the hardening list.");
 R.L[2].push("Loaded "+V.length+" scan finding(s) across "+plan.totals.hosts+" host(s) with open work.","Open: "+plan.totals.critical+" critical, "+plan.totals.high+" high, "+plan.totals.kev+" known-exploited.");
 var top=V.filter(function(v){return v.status!=="fixed_verified"&&v.status!=="accepted_risk"}).sort(function(a,b){return b.priority-a.priority});
 if(ctx&&ctx.hosts&&ctx.hosts.length){var hl=ctx.hosts.map(function(h){return String(h).toLowerCase()});top.sort(function(a,b){return(hl.indexOf(String(b.host).toLowerCase())>=0)-(hl.indexOf(String(a.host).toLowerCase())>=0)||b.priority-a.priority});R.L[2].push("Prioritizing hosts named by earlier agents: "+ctx.hosts.slice(0,4).join(", ")+".")}
 top.slice(0,6).forEach(function(v){R.findings.push({sev:v.severity,t:v.name+" on "+v.host+" ("+v.port+"), CVSS "+v.cvss+", priority "+v.priority+"/100"+(v.kev?", known exploited":"")+". Fix: "+(v.solution||"none given in the scan").slice(0,110),ev:[]})});
 var cat={"Legacy / insecure protocol":/smbv1|telnet|ftp\b|sslv|tls ?1\.0|ntlmv1|rc4|cleartext|http\b/i,"Weak or default credentials":/default|weak|password|anonymous|blank/i,"Missing signing / encryption":/signing|unencrypted|cipher|certificate|ssl|tls/i,"Exposed remote access":/rdp|remote desktop|vnc|ssh|winrm/i};
 var cats=Object.keys(cat).map(function(k){var m=V.filter(function(v){return cat[k].test(v.name+" "+v.summary)});return[k,m.length,uniqA(m.map(function(v){return v.host})).join(", ")]}).filter(function(c){return c[1]});
 cats.forEach(function(c){R.L[2].push("Misconfiguration class \u201c"+c[0]+"\u201d: "+c[1]+" finding(s) on "+c[2]+".")});
 var risky={21:"FTP",23:"Telnet",135:"RPC",139:"NetBIOS",445:"SMB",1433:"SQL Server",3306:"MySQL",3389:"RDP",5900:"VNC",5985:"WinRM"},seen={};
 V.forEach(function(v){var p=parseInt(v.port,10);if(risky[p]){var k=v.host+"|"+p;seen[k]=seen[k]||{h:v.host,p:p,n:risky[p],c:0};seen[k].c++}});
 var exp=Object.keys(seen).map(function(k){return seen[k]});
 R.L[3].push("Exposed-service review: "+exp.length+" high-risk service(s) seen by the scan.");
 exp.forEach(function(x){if(x.p===445||x.p===3389||x.p===23||x.p===21)R.findings.push({sev:"high",t:x.n+" ("+x.p+"/tcp) is reachable on "+x.h+" according to the scan. Restrict it by firewall rule or disable it if unused.",ev:[]})});
 if(/firewall|port|exposed/.test(t))R.table={title:"High-risk services seen by the scan (firewall review)",cols:["Host","Port","Service","Findings on port"],rows:exp.map(function(x){return[x.h,x.p+"/tcp",x.n,x.c]})};
 else R.table={title:"Remediation order",cols:["#","Host","Priority","Fix (grouped)"],rows:plan.items.slice(0,8).map(function(i,n){return[n+1,i.host,i.topPriority,i.steps.slice(0,2).map(function(s){return s.solution.slice(0,90)}).join(" | ")]})};
 var hd=E.hardeningFor(al);hd.slice(0,4).forEach(function(h){R.extra.push({title:"Hardening for "+h.title,text:h.advice.map(function(a){return"- "+a}).join("\n")})});
 R.L[4].push("Built the remediation plan: "+plan.items.length+" host group(s), ordered by priority.","Prepared "+hd.length+" hardening checklist(s) from alert rules.");
 plan.items.slice(0,3).forEach(function(i){R.recs.push({p:i.topPriority>=80?"P1":"P2",t:"Patch / fix "+i.host+": "+i.steps[0].solution.slice(0,120),type:"patch",target:i.host,dis:true})});
 exp.filter(function(x){return x.p===445||x.p===3389}).slice(0,2).forEach(function(x){R.recs.push({p:"P2",t:"Change the firewall rule that exposes "+x.n+" on "+x.h+" (restrict to management addresses).",type:"other",target:x.h,dis:true})});
 R.sev=R.findings.length?maxSev(R.findings):"low";R.head=plan.totals.findings+" open finding(s) on "+plan.totals.hosts+" host(s); top severity "+R.sev.toUpperCase()+".";
 R.limits.push("No firewall or device configuration was read. The service list comes only from scan findings.","Configuration changes are listed as requests; Spark does not apply them.");
 R.mdTitle="Security configuration and remediation report";return R}
/* ---- hunter ---- */
function bHunter(task,ctx){var R=mk(),ev=evs(),t=task.toLowerCase();
 R.L[1].push("Threat Hunter accepted the task.","Plan: test "+E.HUNTS.length+" hypotheses, extract indicators, look for lateral movement, score the intrusion chain.");
 R.L[2].push("Searching "+ev.length+" events across "+uniqA(ev.map(function(e){return e.host})).length+" host(s).");
 var res=E.HUNTS.map(function(h){var r=h.run(ev);return{h:h,r:r}}),hit=res.filter(function(x){return x.r.matches.length});
 var SV={"failed-sources":"medium","encoded-cmd":"high","persistence":"medium","log-tamper":"high","public-rdp":"high","av-detect":"medium","recovery-inhibit":"critical"};
 res.forEach(function(x){R.L[2].push("Hunt \u201c"+x.h.name+"\u201d: "+x.r.matches.length+" match(es).")});
 hit.forEach(function(x){R.findings.push({sev:SV[x.h.id]||"medium",t:x.h.name+" \u2014 "+x.r.note+" Hypothesis: "+x.h.hypothesis+" ("+x.h.mitre+")",ev:x.r.matches.slice(0,3).map(function(e){return e.id})})});
 var iocs=[],add=function(type,v,e){if(!v)return;var k=type+"|"+v,f=iocs.filter(function(i){return i.k===k})[0];if(f){f.n++}else iocs.push({k:k,type:type,v:v,n:1,t:e.time})};
 ev.forEach(function(e){if(e.srcIp&&isPub(e.srcIp))add("Public IP",e.srcIp,e);var d=e.data||{};if(d["Threat Name"])add("Malware name",d["Threat Name"],e);if(d.Path&&/\.(exe|dll|ps1|bat|vbs|js)$/i.test(d.Path))add("File path",d.Path,e);
  var m=(e.commandLine||"").match(/https?:\/\/[^\s"']+/g);(m||[]).forEach(function(u){add("URL",u.slice(0,100),e)});if(e.eventId===4720||e.eventId===4732)add("Account changed",d.TargetUserName||d.MemberName||"",e)});
 if(ctx&&ctx.ips&&ctx.ips.length)ctx.ips.slice(0,3).forEach(function(ip){var rel=E.huntEvents(ev,{ip:ip},300),hs=uniqA(rel.rows.map(function(e){return e.host})),ids=uniqA(rel.rows.map(function(e){return e.eventId}));R.L[2].push("Pivot from the analyst's lead "+ip+": "+rel.total+" related event(s) on "+hs.length+" host(s).");if(rel.total)R.findings.unshift({sev:hs.length>1?"high":"medium",t:"Related activity for "+ip+": "+rel.total+" event(s) (ids "+ids.join(", ")+") across "+hs.join(", ")+".",ev:rel.rows.slice(0,3).map(function(e){return e.id})});add("Public IP",ip,{time:(rel.rows[0]||{}).time})})
 R.L[3].push("Extracted "+iocs.length+" indicator(s) of compromise.");
 var lat={},ips={};ev.filter(function(e){return(e.eventId===4624&&(e.logonType===3||e.logonType===10))||e.eventId===4648}).forEach(function(e){var u=e.targetUser||e.user;if(u)(lat[u]=lat[u]||{})[e.host]=1;if(e.srcIp)(ips[e.srcIp]=ips[e.srcIp]||{})[e.host]=1});
 var lu=Object.keys(lat).filter(function(u){return Object.keys(lat[u]).length>=2}),li=Object.keys(ips).filter(function(i){return Object.keys(ips[i]).length>=2});
 R.L[2].push("Lateral movement check: "+lu.length+" account(s) and "+li.length+" source address(es) touched 2 or more hosts.");
 lu.forEach(function(u){R.findings.push({sev:"high",t:"Account "+u+" logged on over the network to "+Object.keys(lat[u]).length+" hosts ("+Object.keys(lat[u]).join(", ")+"). Verify this is expected administration.",ev:[]})});
 li.forEach(function(i){R.findings.push({sev:isPub(i)?"high":"medium",t:"Address "+i+" authenticated to "+Object.keys(ips[i]).length+" hosts. "+(isPub(i)?"It is public.":"It is internal; check for a jump host or compromised workstation."),ev:[]})});
 var stage={"Initial access (failed then successful logon)":hit.some(function(x){return x.h.id==="failed-sources"})&&ev.some(function(e){return e.eventId===4624}),"Execution":hit.some(function(x){return x.h.id==="encoded-cmd"||x.h.id==="av-detect"}),"Persistence":hit.some(function(x){return x.h.id==="persistence"}),"Defense evasion":hit.some(function(x){return x.h.id==="log-tamper"}),"Lateral movement":lu.length+li.length>0,"Impact preparation":hit.some(function(x){return x.h.id==="recovery-inhibit"})},k=Object.keys(stage).filter(function(s){return stage[s]}).length;
 R.L[4].push("Intrusion-chain view: "+k+" of 6 stages show activity ("+Object.keys(stage).filter(function(s){return stage[s]}).join(", ")+").");
 if(k>=3)R.findings.unshift({sev:"high",t:k+" of 6 intrusion-chain stages show activity in this data. That pattern is consistent with a multi-step intrusion. It is a hypothesis and is NOT attribution to any named APT group.",ev:[]});
 R.table=iocs.length?{title:"Indicators of compromise (extracted)",cols:["Type","Indicator","Seen","First seen"],rows:iocs.sort(function(a,b){return b.n-a.n}).slice(0,14).map(function(i){return[i.type,i.v,i.n,fDT(i.t)]})}:{title:"Hunt results",cols:["Hunt","Matches"],rows:res.map(function(x){return[x.h.name,x.r.matches.length]})};
 R.findings.sort(function(a,b){return SRANK[b.sev]-SRANK[a.sev]});R.findings=R.findings.slice(0,10);R.sev=R.findings.length?maxSev(R.findings):"low";
 R.L[3].push(R.findings.length?R.findings.length+" hunting lead(s) to follow up.":"No leads in this data.");
 if(hit[0])R.recs.push({p:"P2",t:"Pivot on \u201c"+hit[0].h.name+"\u201d in the Threat Hunter tab and read the matching raw events.",dis:false});
 if(k>=3)uniqA(ev.filter(function(e){return e.eventId===4688&&e.commandLine}).map(function(e){return e.host})).slice(0,1).forEach(function(h){R.recs.push({p:"P1",t:"Consider isolating "+h+" while the chain is verified.",type:"isolate_host",target:h,dis:true})});
 R.recs.push({p:"P3",t:"Enable process command-line auditing (4688) and PowerShell script-block logging so future hunts see more.",dis:false});
 R.head=R.findings.length?R.findings.length+" lead(s); "+k+" of 6 chain stages active; top severity "+R.sev.toUpperCase()+".":"No hunting leads in "+ev.length+" events.";
 R.limits.push("Hunts only see the events provided; hunting is a hypothesis test, not a clearance.","No threat-intelligence feed is connected, so indicators are not checked against reputation sources.");R.mdTitle="Threat hunting report";return R}
/* ---- responder ---- */
async function bResponder(task,ctx){var R=mk(),inc=(S.data&&S.data.activeIncidents)||[],t=task.toLowerCase(),pick=inc.filter(function(i){return t.indexOf(i.id.toLowerCase())>=0||t.indexOf(String(i.host).toLowerCase())>=0})[0]||(ctx&&ctx.hosts?inc.filter(function(i){return ctx.hosts.map(function(h){return String(h).toLowerCase()}).indexOf(String(i.host).toLowerCase())>=0})[0]:null)||inc[0];
 R.L[1].push("Incident Responder accepted the task.");
 if(!pick){R.L[2].push("Looked for active incidents: none.");R.head="There are no active incidents to respond to.";R.limits.push("Incidents are created when related alerts are correlated. None exist in the data in view.");R.mdTitle="Incident response report";R.md="# Incident response report\n\nNo active incidents in the data in view.";R.noInc=true;return R}
 R.L[1].push("Selected incident: "+pick.title+" on "+pick.host+".");
 var d=await rDetail(pick.id),i=d.incident,al=d.alerts||[];S.rsel=pick.id;
 var st=S.mode==="connected"?i.status:(L.istat[i.id]||i.status),names=["Detection","Investigation","Containment","Eradication","Recovery"],cur={open:1,investigating:1,contained:3,remediated:4,closed:5}[st];if(cur==null)cur=1;
 R.stages=names.map(function(n,x){return{n:n,s:x<cur?"done":x===cur?"active":"todo"}});
 var pr={critical:"P1",high:"P2",medium:"P3",low:"P4"}[i.severity]||"P3";
 R.L[2].push("Loaded the incident with "+al.length+" alert(s) and "+(d.timeline||[]).length+" timeline entries. Status: "+st+".","Priority "+pr+" from severity "+i.severity+".");
 R.findings.push({sev:i.severity,t:i.title+" \u2014 "+i.reasoning,ev:[]});al.slice(0,5).forEach(function(a){R.findings.push({sev:a.severity,t:a.title+" ("+a.ruleId+") on "+a.host+".",ev:[]})});
 R.L[4].push("Built the response timeline ("+(d.timeline||[]).length+" entries).","Response stage now: "+names[Math.min(cur,4)]+(cur>=5?" (all complete)":"")+".");
 R.table={title:"Response timeline",cols:["Time","Event","Detail"],rows:(d.timeline||[]).slice(0,14).map(function(x){return[fDT(x.time),x.title,(x.detail||"").slice(0,100)]})};
 var pb=E.playbookFor(i,al.map(function(a){return a.ruleId}));
 pb.forEach(function(ph){ph.steps.forEach(function(s){var a=s.needsApproval?actFor(s.id,i,al):null;R.recs.push({p:/Contain/.test(ph.phase)?"P1":/Eradicate/.test(ph.phase)?"P2":"P3",t:"["+ph.phase.replace(/^\d \u00b7 /,"")+"] "+s.text,type:a?a.type:(s.needsApproval?"other":""),target:a?a.target:(s.needsApproval?i.host:""),dis:!!s.needsApproval,desc:a?a.description:s.text,inc:i.id})})});
 R.sev=i.severity;R.head="Incident "+i.id.slice(0,12)+": "+i.severity.toUpperCase()+" / "+pr+", stage "+names[Math.min(cur,4)]+".";
 R.limits.push("Containment steps are suggestions. Spark does not isolate hosts, block addresses, reset passwords or change firewalls.");R.mdTitle="Incident response report";
 R.md=E.incidentReportMd({incident:Object.assign({},i,{status:st}),timeline:d.timeline,actions:(d.actions||[]).concat(L.drafts.filter(function(x){return x.incidentId===i.id})),notes:(L.notes[i.id]||[]).map(function(n){return new Date(n.t).toISOString()+" "+n.text})});return R}
/* ---- siem ---- */
function bSiem(task,ctx){var R=mk(),ev=evs(),sec=evSec(),t=task;
 var KNOWN=[104,1102,1116,1117,4624,4625,4634,4648,4672,4688,4697,4698,4719,4720,4728,4732,4740,4756,5001,7045];
 var q={ids:uniqA((t.match(/\b(\d{3,5})\b/g)||[]).map(Number).filter(function(n){return KNOWN.indexOf(n)>=0})),ip:(t.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/)||[])[0],user:(/\buser(?:name)?\s+([\w.\\$-]+)/i.exec(t)||[])[1],host:(/\bhost\s+([\w-]+)/i.exec(t)||[])[1]};
 if(/failed|repeated|brute|spray/i.test(t)&&q.ids.indexOf(4625)<0)q.ids.push(4625);if(/login|logon/i.test(t)&&!q.ids.length)q.ids=[4624,4625];
 var lx=/linux|ssh|syslog/i.test(t),fw=/firewall|fortigate|pfsense|palo/i.test(t),nw=/network|netflow|dns|proxy/i.test(t);
 R.L[1].push("SIEM Specialist accepted the task.","Parsed filters \u2192 event ids: "+(q.ids.join(", ")||"any")+"; ip: "+(q.ip||"any")+"; user: "+(q.user||"any")+"; host: "+(q.host||"any")+".");
 var r=E.huntEvents(ev,{eventIds:q.ids,ip:q.ip,user:q.user,host:q.host},500);
 R.L[2].push("Searched "+ev.length+" stored events ("+sec.length+" Security): "+r.total+" match(es).");
 var f=r.rows.filter(function(e){return e.eventId===4625}),by={};f.forEach(function(e){var k=(e.srcIp||"-")+"|"+(e.targetUser||e.user||"-");(by[k]=by[k]||[]).push(e)});
 var rep=Object.keys(by).filter(function(k){return by[k].length>=3}).sort(function(a,b){return by[b].length-by[a].length});
 R.L[3].push("Repeated-failure check: "+rep.length+" source/account pair(s) with 3 or more failures.");
 rep.slice(0,5).forEach(function(k){var g=by[k],p=k.split("|");R.findings.push({sev:g.length>=10?"high":"medium",t:g.length+" failed logons from "+p[0]+" against "+p[1]+" between "+fT(g[g.length-1].time)+" and "+fT(g[0].time)+".",ev:g.slice(0,3).map(function(e){return e.id})})});
 var sus=r.rows.filter(function(e){return e.eventId===4624&&e.logonType===10&&isPub(e.srcIp)});
 sus.slice(0,3).forEach(function(e){R.findings.push({sev:"high",t:"RDP logon from public address "+e.srcIp+" for "+(e.targetUser||e.user)+" on "+e.host+".",ev:[e.id]})});
 R.table={title:"Query results (newest first)",cols:["Time","Host","Event","User","Source IP","Summary"],rows:r.rows.slice(0,12).map(function(e){return[fDT(e.time),e.host,e.eventId,e.targetUser||e.user||"",e.srcIp||"",String(e.summary).slice(0,70)]})};
 var ids=q.ids.length?q.ids:[4625],cond=function(a,b,c){return[q.ip?a(q.ip):"",q.user?b(q.user):"",q.host?c(q.host):""].filter(Boolean)};
 var spl='index=wineventlog source="WinEventLog:Security" ('+ids.map(function(i){return"EventCode="+i}).join(" OR ")+")"+cond(function(x){return' (Source_Network_Address="'+x+'" OR IpAddress="'+x+'")'},function(x){return' (Account_Name="'+x+'" OR TargetUserName="'+x+'")'},function(x){return' host="'+x+'"'}).join("")+" | stats count min(_time) as first max(_time) as last values(Account_Name) as accounts by Source_Network_Address | where count>=3 | sort - count";
 var kql="SecurityEvent\n| where EventID in ("+ids.join(", ")+")"+cond(function(x){return'\n| where IpAddress == "'+x+'"'},function(x){return'\n| where TargetUserName == "'+x+'"'},function(x){return'\n| where Computer =~ "'+x+'"'}).join("")+"\n| summarize Count=count(), First=min(TimeGenerated), Last=max(TimeGenerated), Accounts=make_set(TargetUserName) by IpAddress\n| where Count >= 3\n| order by Count desc";
 var ps="Get-WinEvent -FilterHashtable @{LogName='Security'; Id="+ids.join(",")+"; StartTime=(Get-Date).AddHours(-24)} |\n  Group-Object { $_.Properties[19].Value } | Where-Object Count -ge 3 | Sort-Object Count -Descending";
 var es='event.code:('+ids.join(" or ")+")"+cond(function(x){return' and source.ip:"'+x+'"'},function(x){return' and user.name:"'+x+'"'},function(x){return' and host.name:"'+x+'"'}).join("");
 R.extra.push({title:"Generated queries (NOT executed; test in your SIEM first)",code:"# Splunk SPL\n"+spl+"\n\n# Microsoft Sentinel / Log Analytics KQL\n"+kql+"\n\n# PowerShell on a Windows host\n"+ps+"\n\n# Elastic (KQL)\n"+es});
 if(lx||fw||nw)R.extra.push({title:"Starter queries for sources Spark does not collect (NOT executed)",code:(lx?'# Linux sshd (Splunk)\nindex=linux sourcetype=linux_secure "Failed password" | rex "from (?<src>\\d+\\.\\d+\\.\\d+\\.\\d+)" | stats count by src, user | where count>=5\n\n':"")+(fw?'# Firewall denies (Splunk, generic)\nindex=firewall action=blocked | stats count by src_ip, dest_port | sort - count | head 20\n\n':"")+(nw?'# DNS / network (KQL, generic)\nDnsEvents | summarize Count=count() by ClientIP, Name | top 20 by Count':"")});
 var ig=S.integ||[],on=ig.filter(function(x){return/healthy|connected|imported/.test(x.status)});
 R.L[4].push("Source coverage: "+on.length+" of "+ig.length+" integration(s) report data.",lx||fw||nw?"Linux, firewall and network logs: no collector in Spark, so only generated queries are provided.":"Windows Security log is the only parsed source.");
 R.findings.push({sev:"low",t:"Log source coverage: "+(ig.length?ig.map(function(x){return x.name+" ("+x.status+")"}).join(", "):"integration list unavailable")+". Linux, firewall and network logs have no collector.",ev:[]});
 R.findings.sort(function(a,b){return SRANK[b.sev]-SRANK[a.sev]});R.sev=maxSev(R.findings);
 R.recs.push({p:"P3",t:"Run the generated query in your SIEM to confirm the result on the full dataset.",dis:false},{p:"P3",t:"Add a detection rule for 5+ failed logons per source in 10 minutes, and enable 4688 command-line auditing.",dis:false});
 R.head=r.total+" matching event(s); "+rep.length+" repeated-failure pair(s).";
 R.limits.push("Results come from events stored in Spark, not from your SIEM. Queries are generated text and were not run anywhere.");R.mdTitle="SIEM log analysis report";return R}
/* ---- ciso ---- */
function bCiso(task,ctx){var R=mk(),d=S.data,ei=execInput(),risks=E.topRisks(ei,5),act=d.activeIncidents,crit=act.filter(function(i){return i.severity==="critical"}).length,vc=d.vulnCounts||{},hi=(vc.critical||0)+(vc.high||0);
 R.L[1].push("CISO advisor accepted the task.","Plan: summarize posture, rank business risks, list KPIs and the decisions leadership must make.");
 R.L[2].push("Reviewed posture score "+(d.posture==null?"n/a":d.posture+"/100")+", "+act.length+" active incident(s), "+hi+" critical or high vulnerabilities.");
 risks.forEach(function(r){R.findings.push({sev:/CRITICAL/.test(r.risk)?"critical":/HIGH|critical|known-exploited/.test(r.risk+r.why)?"high":"medium",t:r.risk+". "+r.why,ev:[]})});
 if(ctx&&ctx.results){var rs=Object.keys(ctx.results);R.L[2].push("Read the shared investigation memory: "+rs.length+" agent report(s) ("+rs.map(function(k){return ROLES[k].n}).join(", ")+"). Their findings are reused, not re-analyzed.");rs.forEach(function(k){var f=ctx.results[k].findings[0];if(f)R.findings.unshift({sev:f.sev,t:ROLES[k].n+" reported: "+f.t.slice(0,160),ev:[]})})}
 R.L[3].push(risks.length?"Ranked "+risks.length+" top risk(s) by severity, status and exploitation.":"No open risks in the data.");
 var pend=actsList().filter(function(a){return a.status==="proposed"}).length,kev=ei.kevVulns||0,lowA=(d.assets||[]).filter(function(a){return a.score<50}).length;
 R.table={title:"Security KPIs (from the data in view)",cols:["KPI","Value","Note"],rows:[["Security posture",d.posture==null?"n/a":d.posture+"/100","100 minus average asset risk; a simple score, not an audit"],["Active incidents",act.length+" ("+crit+" critical)","not yet closed"],["Critical + high vulnerabilities",hi,"open findings"],["Known-exploited vulnerabilities",kev,"on the CISA KEV list"],["Response actions awaiting approval",pend,"decisions for an approver"],["Hosts with risk score below 50",lowA,"of "+(d.assets||[]).length],["Mean time to respond","not available","no history is stored yet"]]};
 R.L[4].push("Compiled KPIs and strategic priorities.");
 if(crit)R.recs.push({p:"P1",t:"Assign an accountable owner and a containment decision for the "+crit+" critical incident(s) today.",dis:false});
 if(kev)R.recs.push({p:"P1",t:"Approve emergency patching for "+kev+" known-exploited vulnerability(ies).",dis:false});
 if(pend)R.recs.push({p:"P2",t:"Approve or reject "+pend+" pending response action(s) so containment is not stalled.",dis:false});
 if(hi)R.recs.push({p:"P2",t:"Fund and schedule remediation of "+hi+" critical/high findings with a deadline per host owner.",dis:false});
 R.recs.push({p:"P3",t:"Strategic: extend log coverage (Linux, firewall, network), baseline MFA on remote access, test restores of offline backups.",dis:false});
 R.sev=R.findings.length?maxSev(R.findings):"low";R.head="Posture "+(d.posture==null?"n/a":d.posture+"/100")+"; "+act.length+" active incident(s); "+risks.length+" top risk(s).";
 R.limits.push("Counts cover only systems connected to Spark. There is no trend data, no financial impact estimate and no compliance mapping.");R.mdTitle="Executive security briefing";R.md=E.execSummaryMd(ei);return R}
var BUILD={analyst:bAnalyst,engineer:bEngineer,hunter:bHunter,responder:bResponder,siem:bSiem,ciso:bCiso};
function mdOf(role,a){var R=a.res,P=ROLES[role],o=["# "+R.mdTitle,"",a.dl.text,"","- **Agent:** "+P.n,"- **Task:** "+a.task,"- **Result:** "+R.head,"- **Severity:** "+R.sev,"- **Run at:** "+new Date(a.at).toISOString(),""];
 if(R.md&&role!=="analyst"&&role!=="engineer"){o.push(R.md,"")}
 o.push("## Findings","",R.findings.length?R.findings.map(function(f,i){return(i+1)+". ["+f.sev.toUpperCase()+"] "+f.t+((f.ev||[]).length?" (events: "+f.ev.join(", ")+")":"")}).join("\n"):"No findings.","");
 if(R.table){o.push("## "+R.table.title,"","| "+R.table.cols.join(" | ")+" |","|"+R.table.cols.map(function(){return" --- |"}).join(""));R.table.rows.forEach(function(r){o.push("| "+r.map(function(c){return String(c).replace(/<[^>]+>/g,"").replace(/\|/g,"/")}).join(" | ")+" |")});o.push("")}
 R.extra.forEach(function(x){o.push("## "+x.title,"",x.code?x.code:x.text,"")});
 o.push("## Recommended next steps (none executed)","",R.recs.map(function(r){return"- ["+r.p+"] "+r.t+(r.dis?" (needs explicit approval)":"")}).join("\n"),"","## Limits","",R.limits.map(function(l){return"- "+l}).join("\n"),"","---","Rule-based analysis by Spark over the data in view; findings are hypotheses for a human to verify. "+a.dl.text);return o.join("\n")}
/* ---- runner ---- */
function stepsOf(role,task,R){var s=[{s:0,t:"Request received: \u201c"+task+"\u201d"}];[1,2].forEach(function(k){R.L[k].forEach(function(t){s.push({s:k,t:t})})});
 if(R.L[3].length)s.push({s:3,t:R.L[3][0]});R.findings.forEach(function(f,i){s.push({s:3,t:(f.sev==="critical"||f.sev==="high"?"ALERT ":"")+"Finding: "+f.t.slice(0,150),find:i,al:f.sev==="critical"||f.sev==="high"})});R.L[3].slice(1).forEach(function(t){s.push({s:3,t:t})});
 R.L[4].forEach(function(t){s.push({s:4,t:t})});s.push({s:5,t:"Report generated ("+R.findings.length+" finding(s), severity "+R.sev.toUpperCase()+")"});return s}
function setStatus(role,st){var a=agState(role);a.status=st;syncDash()}
async function startAgent(role){var a=agState(role);if(a.running)return;var inp=$("con-in-"+role),task=(inp.value||"").trim()||CON[role].def;inp.value=task;
 if(!E){a.err="The analysis engine did not load, so this agent cannot run.";paintCon(role);return}
 if(typeof INV!=="undefined"&&INV&&INV.running&&INV.agents.indexOf(role)>=0){a.err="This agent is busy in the running investigation. Pause or cancel it in the Collaboration Center first.";paintCon(role);return}
 if(typeof OST!=="undefined")OST[role]=null;
 if(S.mode==="connected"&&canWrite())return startAgentServer(role,task);
 var my=++a.tok;a.running=true;a.server=false;a.err="";a.note="";a.task=task;a.res=null;a.log=[];a.reveal=0;a.stage=0;a.progress=0;a.done=0;a.steps=[];a.pend=null;setStatus(role,"Analyzing");paintCon(role);
 var R;try{R=await BUILD[role](task)}catch(e){if(my!==a.tok)return;a.running=false;a.err="The agent could not complete: "+(e.message||e);a.stage=-1;setStatus(role,"Idle");paintCon(role);return}
 if(my!==a.tok)return;a.res=R;a.dl=dataLabel();a.steps=stepsOf(role,task,R);
 var stepper=function(){if(my!==a.tok)return;if(a.done>=a.steps.length){finish(role,my);return}
  var s=a.steps[a.done++];a.stage=s.s;a.log.push({t:Date.now(),s:s.s,text:s.t,al:s.al});if(s.find!=null)a.reveal=s.find+1;a.progress=Math.round(a.done/a.steps.length*100);
  setStatus(role,s.s>=4?CON[role].run:"Analyzing");paintCon(role);a.timer=setTimeout(stepper,380+Math.random()*320)};
 a.timer=setTimeout(stepper,350)}
function finish(role,my){var a=agState(role);if(my!==a.tok)return;a.running=false;a.stage=5;a.progress=100;a.reveal=a.res.findings.length;a.at=Date.now();a.timer=null;
 a.res.md=mdOf(role,a);var h=(L.ah=L.ah||{});var arr=(h[role]=h[role]||[]);arr.unshift({at:a.at,task:a.task,head:a.res.head,sev:a.res.sev,dl:a.dl,res:trimRes(a.res)});h[role]=arr.slice(0,6);lsSave();setStatus(role,"Completed");paintCon(role);
 var ni=$("con-live-"+role);if(ni)ni.textContent=ROLES[role].n+" finished: "+a.res.head}
function trimRes(R){var c=JSON.parse(JSON.stringify(R));c.findings=c.findings.slice(0,10);if(c.table)c.table.rows=c.table.rows.slice(0,14);c.recs=c.recs.slice(0,12);c.extra=c.extra.map(function(x){return{title:x.title,text:x.text&&x.text.slice(0,3000),code:x.code&&x.code.slice(0,3000)}});c.md=(c.md||"").slice(0,20000);return c}
function stopAgent(role){var a=agState(role);if(!a.running)return;if(a.server&&a.runId)api("POST","/tasks/"+a.runId+"/cancel").catch(function(){});a.tok++;clearTimeout(a.timer);a.running=false;a.note="Stopped before completion. Partial output is shown; no report was written.";setStatus(role,"Stopped");paintCon(role)}
function resetAgent(role){var a=agState(role);if(a.running&&a.server&&a.runId)api("POST","/tasks/"+a.runId+"/cancel").catch(function(){});a.tok++;clearTimeout(a.timer);AG[role]=null;agState(role);$("con-in-"+role).value="";syncDash();paintCon(role)}
function viewHist(role,i){var a=agState(role);if(a.running)return;if(S.mode==="connected"&&a.sh)return viewSrv(role,i);var e=L.ah[role][i];if(!e)return;a.tok++;a.res=e.res;a.dl=e.dl;a.task=e.task;a.at=e.at;a.stage=5;a.progress=100;a.reveal=e.res.findings.length;a.steps=[];a.log=[{t:e.at,s:5,text:"Showing saved run from "+fDT(new Date(e.at).toISOString())+" (kept in this browser)."}];a.note="Viewing a saved run. Press Start to run the agent again on current data.";$("con-in-"+role).value=e.task;setStatus(role,"Completed");paintCon(role)}
/* ---- server-side runs: every step is executed by the backend, progress = completed steps / total steps ---- */
var MDT={analyst:"SOC Analyst investigation report",engineer:"Security configuration and remediation report",hunter:"Threat hunting report",responder:"Incident response report",siem:"SIEM log analysis report",ciso:"Executive security briefing"};
function srvR(role,run){var o=run.result;return{head:o.head,sev:o.severity,L:{1:[],2:[],3:[],4:[]},findings:o.findings.map(function(f){return{sev:f.sev,t:f.t,ev:f.ev||[]}}),table:o.table?{title:o.table.title,cols:o.table.cols,rows:o.table.rows.map(function(r){return r.map(function(c){return/^\d{4}-\d{2}-\d{2}T\d/.test(String(c))?fDT(c):c})})}:null,extra:(o.extra||[]).map(function(x){return{title:x.title,code:x.code}}),recs:o.recs.map(function(r){return{p:r.p,t:r.t,type:r.type,target:r.target,dis:r.dis,inc:r.incidentId,srv:!!(r.dis&&r.type&&r.target)}}),limits:o.limits,md:"",stages:o.stages||null,mdTitle:MDT[role],handoff:o.handoff,pivots:o.pivots,noInc:/no active incident/i.test(o.head)}}
function stageAt(run,i){var n=run.stepsTotal||1,r=(i+1)/n;return r<=.34?2:r<=.67?3:4}
function applyRun(role,run){var a=agState(role);a.runId=run.id;a.stepsDone=run.stepsDone;a.stepsTotal=run.stepsTotal;a.progress=run.progress;a.server=true;
 a.stage=run.status==="completed"?5:Math.max(1,stageAt(run,Math.max(0,run.stepsDone)));
 a.log=[{t:Date.parse(run.createdAt),s:0,text:"Task created on the server: \u201c"+run.task+"\u201d ("+run.stepsTotal+" steps)"}].concat(run.steps.map(function(s,i){return s}).filter(function(s){return s.status==="done"||s.status==="failed"}).map(function(s){var i=run.steps.indexOf(s);return{t:Date.parse(s.endedAt),s:stageAt(run,i),text:s.name+" \u2014 "+(s.detail||s.error||"")+" ["+s.durationMs+" ms]",al:s.status==="failed"}}));
 var st=run.status==="completed"?"Completed":run.status==="failed"?"Failed":run.status==="cancelled"?"Stopped":run.stepsDone/run.stepsTotal<.5?"Analyzing":CON[role].run;setStatus(role,st);paintCon(role)}
async function startAgentServer(role,task){var a=agState(role),my=++a.tok;a.running=true;a.server=true;a.err="";a.note="";a.task=task;a.res=null;a.log=[];a.reveal=0;a.stage=1;a.progress=0;a.stepsDone=0;a.stepsTotal=0;a.canRetry=false;a.dl=dataLabel();a.pend=null;setStatus(role,"Analyzing");paintCon(role);
 try{var run=await api("POST","/tasks",{role:role,task:task});a.runId=run.id;applyRun(role,run);await driveRun(role,run,my)}catch(e){if(my!==a.tok)return;a.running=false;a.err=e.message||"Request failed";setStatus(role,"Failed");paintCon(role)}}
async function driveRun(role,run,my){var a=agState(role);
 while(run.status==="running"&&my===a.tok){run=await api("POST","/tasks/"+run.id+"/next");if(my!==a.tok)return;applyRun(role,run)}
 if(my!==a.tok)return;a.running=false;
 if(run.status==="completed"){a.res=srvR(role,run);a.dl=dataLabel();a.reveal=a.res.findings.length;a.stage=5;a.at=Date.now();a.res.md=mdOf(role,a);setStatus(role,"Completed");try{S.actions=await api("GET","/actions");if(typeof paintApprovals==="function")paintApprovals()}catch(e){}loadHist(role)}
 else if(run.status==="failed"){a.err=run.error||"The run failed.";a.canRetry=true;setStatus(role,"Failed")}
 paintCon(role)}
async function retryAgent(role){var a=agState(role);if(!a.runId||a.running)return;var my=++a.tok;a.running=true;a.err="";a.canRetry=false;setStatus(role,"Analyzing");paintCon(role);
 try{var run=await api("POST","/tasks/"+a.runId+"/retry");applyRun(role,run);await driveRun(role,run,my)}catch(e){if(my!==a.tok)return;a.running=false;a.err=e.message||"Retry failed";a.canRetry=true;setStatus(role,"Failed");paintCon(role)}}
async function loadHist(role){if(S.mode!=="connected")return;try{agState(role).sh=await api("GET","/tasks?role="+role+"&limit=8");paintCon(role)}catch(e){}}
function viewSrv(role,i){var a=agState(role);if(a.running)return;var run=a.sh&&a.sh[i];if(!run)return;a.tok++;applyRun(role,run);a.running=false;a.task=run.task;a.at=Date.parse(run.createdAt);$("con-in-"+role).value=run.task;
 if(run.status==="completed"){a.res=srvR(role,run);a.dl=dataLabel();a.reveal=a.res.findings.length;a.res.md=mdOf(role,a);a.note="Viewing a saved server run from "+fDT(run.createdAt)+" (its steps and timings are the recorded ones).";setStatus(role,"Completed")}else{a.res=null;a.err=run.error||("Run "+run.status+".");a.canRetry=run.status==="failed"}
 paintCon(role)}
/* ---- dashboard sync ---- */
var STS_CLS={Idle:"i",Analyzing:"a",Investigating:"v",Hunting:"v",Reviewing:"v",Completed:"c",Stopped:"s"};
function stsCls(st){return/Process|Analyz|Assigned/.test(st)?"a":/Communicat|Investigat|Review/.test(st)?"v":/Complet/.test(st)?"c":/Stopped|Paused/.test(st)?"s":/Waiting/.test(st)?"w":/Failed/.test(st)?"f":"i"}
function dashStatus(r){var a=agState(r),o=typeof OST!=="undefined"?OST[r]:null;if(o&&o.status&&o.status!=="Idle"){var pr=o.progress!=null&&!/Waiting|Idle/.test(o.status)?o.progress:null;return{st:o.status,pr:pr,work:/Processing|Communicating/.test(o.status)}}return{st:a.status,pr:null,work:a.running}}
function syncDash(){var items=[];ORDER.forEach(function(r){if(!CON[r])return;var d=dashStatus(r),st=d.st,txt=st+(d.pr!=null?" "+d.pr+"%":""),cl=stsCls(st);
 document.querySelectorAll('#soct .soc-hot[data-role="'+r+'"]').forEach(function(b){b.setAttribute("data-sts",cl);var c=b.querySelector(".sts");if(c)c.textContent=txt;b.setAttribute("aria-label","Open the "+ROLES[r].n+" AI workspace. Status: "+txt)});
 document.querySelectorAll('#soct .soc-robot[data-role="'+r+'"]').forEach(function(b){b.classList.toggle("work",!!d.work)});
 var t=$("tab-"+r);if(t){t.setAttribute("data-sts",cl);t.title=ROLES[r].n+" \u2014 "+txt}
 items.push('<li data-role="'+r+'" data-sts="'+cl+'"><i></i><b>'+esc(ROLES[r].n)+"</b> \u2014 "+esc(st)+(d.pr!=null?" \u2014 "+d.pr+"%":"")+"</li>")});
 var l=$("socStl");if(l)l.innerHTML=items.join("")}
/* ---- rendering ---- */
function conHtml(role){var C=CON[role],P=ROLES[role];
 return'<div class="con-top"><div><h3 class="con-h">'+C.title+'</h3><p class="sub" style="margin:2px 0 0">'+esc(P.s)+'. Reads: '+esc(C.tool)+'.</p></div><span class="con-st" id="con-st-'+role+'" role="status" aria-live="polite"><i></i><b>Idle</b></span></div>'
 +'<div class="chips" style="margin:8px 0">'+C.caps.map(function(c){return'<span class="chip">'+esc(c)+"</span>"}).join("")+"</div>"
 +'<div class="con-lab" id="con-lab-'+role+'"></div>'
 +'<form class="con-form" data-conform="'+role+'"><label class="sub" for="con-in-'+role+'" style="margin:0">Task for the '+esc(P.n)+'</label><div class="con-row"><input type="text" id="con-in-'+role+'" maxlength="300" placeholder="'+esc(C.def)+'" autocomplete="off">'
 +'<button type="submit" class="abtn con-go" id="con-go-'+role+'">&#9654; Start</button><button type="button" class="abtn con-sec" data-constop="'+role+'" id="con-stop-'+role+'" disabled>&#9632; Stop</button><button type="button" class="abtn con-sec" data-conreset="'+role+'">&#8635; Reset</button></div>'
 +'<div class="con-presets">'+C.chips.map(function(c){return'<button type="button" class="mini" data-conpre="'+role+'" data-t="'+esc(c)+'">'+esc(c.length>46?c.slice(0,44)+"\u2026":c)+"</button>"}).join("")+"</div></form>"
 +'<div id="con-err-'+role+'"></div>'
 +'<div class="con-flow" id="con-flow-'+role+'" aria-label="Agent workflow"></div>'
 +'<div class="con-bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0" id="con-bar-'+role+'"><span></span><em>0%</em></div>'
 +'<div class="con-cols"><div><h4 class="con-sub">Live task timeline</h4><div class="con-log" id="con-log-'+role+'" aria-live="off"></div></div><div><h4 class="con-sub">Security alerts raised <span class="chip" id="con-ac-'+role+'">0</span></h4><div id="con-fd-'+role+'" class="con-fd"></div></div></div>'
 +'<div id="con-out-'+role+'"></div><div id="con-hist-'+role+'"></div><div class="sr-only" id="con-live-'+role+'" aria-live="polite" style="position:absolute;left:-9999px"></div>'}
function mountConsole(role){var pane=$("rp-"+role);if(!pane||$("con-"+role))return;var s=document.createElement("section");s.className="pn con";s.id="con-"+role;s.setAttribute("data-role",role);s.setAttribute("aria-label",ROLES[role].n+" investigation console");s.innerHTML=conHtml(role);pane.insertBefore(s,pane.firstChild);paintCon(role)}
function paintCon(role){var root=$("con-"+role);if(!root)return;var a=agState(role),R=a.res,C=CON[role],st=a.status;
 var sb=$("con-st-"+role);sb.setAttribute("data-sts",stsCls(st));sb.querySelector("b").textContent=st;
 $("con-go-"+role).disabled=a.running;$("con-stop-"+role).disabled=!a.running;
 var dl=a.dl||dataLabel();var meas=a.server||(S.mode==="connected"&&canWrite());$("con-lab-"+role).innerHTML='<span class="badge '+(dl.kind==="live"?"b-live":"b-demo")+'">'+(dl.kind==="live"?"CONNECTED DATA":dl.kind==="mixed"?"CONNECTED + SAMPLE":"SIMULATED DATA")+'</span> <span>'+esc(dl.text)+(meas?" MEASURED RUN: the server executes each step; progress is completed steps divided by total steps. The analysis is rule-based, not an AI verdict.":" SAMPLE PLAYBACK: steps are replayed with a short pause so you can watch; progress is NOT measured. The analysis is rule-based, not an AI verdict.")+"</span>";
 $("con-err-"+role).innerHTML=a.err?'<div class="banner bad">'+esc(a.err)+(a.canRetry&&canWrite()?' <button type="button" class="mini" data-conretry="'+role+'">Retry failed step</button>':"")+"</div>":a.note?'<div class="banner info">'+esc(a.note)+"</div>":"";
 var cur=a.running?a.stage:(st==="Completed"?6:a.stage),fl="";
 STG.forEach(function(n,i){var cls=cur>i||(!a.running&&st==="Completed")?"done":cur===i&&a.running?"act":"";fl+='<div class="con-n '+cls+'"><span class="con-d">'+(i+1)+"</span><b>"+esc(n)+"</b></div>"+(i<5?'<div class="con-c '+(cls==="done"?"done":cur===i+1&&a.running?"flow":"")+'" aria-hidden="true"><s></s><s></s><s></s></div>':"")});
 $("con-flow-"+role).innerHTML=fl;$("con-flow-"+role).classList.toggle("run",a.running);
 var bar=$("con-bar-"+role);bar.setAttribute("aria-valuenow",a.progress);bar.firstChild.style.width=a.progress+"%";bar.lastChild.textContent=(a.server?a.stepsDone+"/"+a.stepsTotal+" steps \u00b7 ":"")+a.progress+"%";
 $("con-log-"+role).innerHTML=a.log.length?a.log.map(function(l){return'<div class="con-l'+(l.al?" al":"")+'"><time>'+fT(new Date(l.t).toISOString())+"</time><span class=\"con-k k"+l.s+'">'+esc(STG[l.s])+"</span> "+esc(l.text)+"</div>"}).join(""):'<div class="empty">Nothing running. Enter a task and press Start.</div>';
 var lg=$("con-log-"+role);lg.scrollTop=lg.scrollHeight;
 var shown=R?R.findings.slice(0,a.reveal):[],ac=shown.filter(function(f){return f.sev==="critical"||f.sev==="high"});$("con-ac-"+role).textContent=ac.length;
 $("con-fd-"+role).innerHTML=shown.length?shown.map(function(f){return'<div class="con-f f-'+f.sev+'">'+sev(f.sev)+" <span>"+esc(f.t)+"</span>"+((f.ev||[]).length?'<small>events '+f.ev.map(function(x){return esc(x.slice(0,12))}).join(", ")+"</small>":"")+"</div>"}).join(""):'<div class="empty">Findings appear here as the agent detects them.</div>';
 var o="";
 if(R&&a.stage>=4){
  if(R.stages)o+='<div class="con-stg">'+R.stages.map(function(x){return'<span class="'+x.s+'"><i></i>'+esc(x.n)+"</span>"}).join('<em></em>')+"</div>";
  if(R.table)o+='<h4 class="con-sub">'+esc(R.table.title)+'</h4><div class="con-tw"><table><thead><tr>'+R.table.cols.map(function(c){return"<th>"+esc(c)+"</th>"}).join("")+"</tr></thead><tbody>"+(R.table.rows.length?R.table.rows.map(function(r){return"<tr>"+r.map(function(c){return"<td>"+(R.table.raw&&/^<span class="sev/.test(String(c))?c:esc(c))+"</td>"}).join("")+"</tr>"}).join(""):'<tr><td colspan="'+R.table.cols.length+'">No rows.</td></tr>')+"</tbody></table></div>"}
 if(R&&a.stage===5&&!a.running){
  o+='<div class="con-done"><h4 class="con-sub">Result: '+esc(R.head)+" "+sev(R.sev)+"</h4>";
  R.extra.forEach(function(x){o+='<h4 class="con-sub">'+esc(x.title)+"</h4>"+(x.code?'<pre class="con-code">'+esc(x.code)+"</pre>":"<pre class=\"con-code\">"+esc(x.text)+"</pre>")});
  o+='<h4 class="con-sub">Recommended next steps <span class="chip">none executed</span></h4>';
  o+=R.recs.map(function(r,i){var p=a.pend,req=a.reqd&&a.reqd[i];return'<div class="con-r"><span class="chip p'+r.p+'">'+esc(r.p)+"</span><span>"+esc(r.t)+(r.dis?' <small class="warn">needs explicit approval</small>':"")+"</span>"+(r.srv?'<span class="badge b-live">PROPOSED \u2014 awaiting approval (Pending Approvals)</span>':r.dis&&r.type?(req?'<span class="badge b-live">'+esc(req)+"</span>":p===i?'<span class="con-ask">Send this as a request for approval? Spark will NOT carry it out.<button type="button" class="mini" data-conyes="'+role+'" data-i="'+i+'">Yes, send request</button><button type="button" class="mini" data-conno="'+role+'">Cancel</button></span>':'<button type="button" class="mini" data-conreq="'+role+'" data-i="'+i+'">Request approval</button>'):"")+"</div>"}).join("");
  o+='<h4 class="con-sub">Limits</h4><ul class="con-lim">'+R.limits.map(function(l){return"<li>"+esc(l)+"</li>"}).join("")+"</ul>";
  o+='<div class="ctl"><button type="button" class="mini" data-conrep="'+role+'">View report</button><button type="button" class="mini" data-condl="'+role+'">Download report (.md)</button><button type="button" class="mini" data-concopy="'+role+'">Copy report</button><button type="button" class="mini" data-conai="'+role+'">Ask AI to comment</button><span class="st" id="con-msg-'+role+'" role="status"></span></div><div id="con-rep-'+role+'"></div><div id="con-aic-'+role+'" class="res" hidden></div></div>'}
 $("con-out-"+role).innerHTML=o;
 var H=(S.mode==="connected"&&a.sh)?a.sh.map(function(r){return{at:Date.parse(r.createdAt),task:r.task,head:r.result?r.result.head:(r.error||r.status),sev:r.result?r.result.severity:"low"}}):((L.ah&&L.ah[role])||[]);$("con-hist-"+role).innerHTML=H.length?'<h4 class="con-sub">Activity history <span class="chip">'+(S.mode==="connected"&&a.sh?"recorded on the server":"this browser only")+'</span></h4>'+H.map(function(e,i){return'<div class="con-h2"><time>'+esc(fDT(new Date(e.at).toISOString()))+"</time>"+sev(e.sev)+"<span>"+esc(e.task.slice(0,70))+" \u2014 "+esc(e.head)+'</span><button type="button" class="mini" data-conview="'+role+'" data-i="'+i+'"'+(a.running?" disabled":"")+">View</button></div>"}).join(""):""}
async function sendReq(role,i){var a=agState(role),r=a.res.recs[i],msg=$("con-msg-"+role),desc=r.desc||r.t,b={incidentId:r.inc||undefined,type:r.type,target:r.target||"unspecified",description:desc,rationale:"Requested from the "+ROLES[role].n+" console. Recommendation from a rule-based analysis; a human must approve and perform it."};
 a.pend=null;a.reqd=a.reqd||{};
 if(S.mode==="connected"&&canWrite()){try{await api("POST","/actions",b);S.actions=await api("GET","/actions");a.reqd[i]="REQUEST SENT \u2014 awaiting approver";if(msg)msg.textContent="";if(S.role==="responder"||S.role==="ciso")try{paintActs();paintKpis()}catch(e){}}catch(e){a.err=e.message||"Request failed";}}
 else{var why=S.mode==="connected"?"Your role cannot propose actions.":"";if(S.mode==="connected"){a.err=why}else{L.drafts.unshift({id:"draft_"+Date.now(),draft:true,status:"proposed",requiresApproval:true,proposedBy:"you (draft)",incidentId:b.incidentId,type:b.type,target:b.target,description:b.description,rationale:b.rationale});lsSave();a.reqd[i]="DRAFT (sample, this browser only)";try{paintActs();paintKpis()}catch(e){}}}
 paintCon(role)}
document.addEventListener("click",function(e){var t=e.target;if(!t.closest||!t.closest("#socws"))return;var c;
 if(c=t.closest("[data-conpre]")){var r=c.dataset.conpre;$("con-in-"+r).value=c.dataset.t;$("con-in-"+r).focus();return}
 if(c=t.closest("[data-constop]")){stopAgent(c.dataset.constop);return}
 if(c=t.closest("[data-conreset]")){resetAgent(c.dataset.conreset);return}
 if(c=t.closest("[data-conretry]")){retryAgent(c.dataset.conretry);return}
 if(c=t.closest("[data-conview]")){viewHist(c.dataset.conview,Number(c.dataset.i));return}
 if(c=t.closest("[data-conreq]")){agState(c.dataset.conreq).pend=Number(c.dataset.i);paintCon(c.dataset.conreq);return}
 if(c=t.closest("[data-conno]")){agState(c.dataset.conno).pend=null;paintCon(c.dataset.conno);return}
 if(c=t.closest("[data-conyes]")){sendReq(c.dataset.conyes,Number(c.dataset.i));return}
 if(c=t.closest("[data-conrep]")){var r2=c.dataset.conrep,box=$("con-rep-"+r2);box.innerHTML=box.innerHTML?"":'<div class="res">'+render(agState(r2).res.md)+"</div>";return}
 if(c=t.closest("[data-condl]")){var r3=c.dataset.condl;download("report-"+r3+"-"+new Date().toISOString().slice(0,10)+".md",agState(r3).res.md,"text/markdown");return}
 if(c=t.closest("[data-concopy]")){var r4=c.dataset.concopy,m=$("con-msg-"+r4),tx=agState(r4).res.md;if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(tx).then(function(){m.textContent="Copied."},function(){m.textContent="Use Download instead."});else m.textContent="Use Download instead.";return}
 if(c=t.closest("[data-conai]")){var r5=c.dataset.conai,a5=agState(r5),box5=$("con-aic-"+r5);run(c,"",ROLES[r5].a,"",ROLES[r5].p+"\n\nComment on this finished investigation and say what to verify first:\n"+a5.res.md.slice(0,6000),"Comment on this finished SAMPLE investigation and say what to verify first. Remember it is simulated:\n"+a5.res.md.slice(0,6000),{},r5).then(function(){var rs=$(r5==="analyst"?"socws-res":"res-"+r5);if(rs&&!rs.hidden){box5.hidden=false;box5.innerHTML=rs.innerHTML;rs.hidden=true}});return}});
document.addEventListener("submit",function(e){var t=e.target;if(!t.closest||!t.closest("#socws"))return;var r=t.dataset&&t.dataset.conform;if(r){e.preventDefault();startAgent(r)}});
