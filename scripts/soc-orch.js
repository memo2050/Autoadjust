/* ---------- AI Agent Collaboration Center: orchestrator, agent-to-agent messages, shared investigation memory ----------
   The orchestrator picks agents for a request, runs them in order, passes each one the findings gathered so far,
   shows every hand-off message, and writes one unified report. Each agent's analysis is the same rule-based
   analysis as its own console, run over the data in view. Messages are composed from those results; they are not
   free-form model chat. Nothing is executed: disruptive steps can only be sent as requests for human approval. */
ROLES.team={n:"Collaboration Center",a:"security_advisor",s:"Six agents working one investigation together",p:"Your role today: security operations lead. Summarize this unified investigation for an executive: what happened, how sure we are, what to decide."};
ORDER.push("team");
ICO.team='<circle cx="12" cy="5" r="2.2"/><circle cx="5" cy="18" r="2.2"/><circle cx="19" cy="18" r="2.2"/><path d="M12 7.2v4.3M10.5 12.5L6.6 16.3M13.5 12.5l3.9 3.8"/><circle cx="12" cy="12.5" r="1.3"/>';
var SIX=["analyst","engineer","hunter","responder","siem","ciso"],PIPE=["siem","analyst","hunter","engineer","responder","ciso"];
var OST={},INV=null,OSEL={auto:true,set:[]},OPOS={};
PIPE.forEach(function(r,i){var an=(-90+i*60)*Math.PI/180;OPOS[r]={x:50+37*Math.cos(an),y:50+35*Math.sin(an)}});OPOS.orch={x:50,y:50};
var VERB={siem:"is analyzing authentication logs",analyst:"is investigating suspicious activity",hunter:"is searching for related threats and indicators",engineer:"is evaluating vulnerabilities and security weaknesses",responder:"is preparing containment and recovery recommendations",ciso:"is reviewing all findings"};
function sleep(ms){return new Promise(function(r){setTimeout(r,ms)})}
function audit(what,who){L.audit=L.audit||[];L.audit.unshift({t:Date.now(),who:who||"you",what:what});L.audit=L.audit.slice(0,120);lsSave()}
function autoAgents(req){var t=req.toLowerCase(),has=function(re){return re.test(t)},s;
 if(has(/posture|compliance|maturity|overall|review our|security review/))s=["siem","engineer","ciso"];
 else if(has(/login|logon|brute|attack|breach|intrusion|compromise|credential/))s=PIPE;
 else if(has(/\b\d{1,3}(\.\d{1,3}){3}\b|\bip\b|address/))s=["siem","analyst","hunter"];
 else if(has(/malware|ransom|virus|trojan|phish/))s=["analyst","hunter","engineer","responder","ciso"];
 else if(has(/vulnerab|patch|misconfig|firewall|harden|cve/))s=["engineer","ciso"];
 else if(has(/incident|contain|respond|recover/))s=["analyst","responder","ciso"];
 else if(has(/\blogs?\b|query|siem|search|splunk|sentinel/))s=["siem","analyst"];
 else if(has(/executive|board|briefing|ciso|summary/))s=["siem","ciso"];
 else s=PIPE;
 return PIPE.filter(function(r){return s.indexOf(r)>=0})}
function chosen(req){return OSEL.auto?autoAgents(req):PIPE.filter(function(r){return OSEL.set.indexOf(r)>=0})}
function taskFor(role,req){var ip=(req.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/)||[])[0];
 if(role==="siem")return ip?"Search events from IP "+ip+" and find repeated failed logons (event 4625).":/login|logon|brute|attack|auth|credential/i.test(req)?"Find repeated failed logons (event 4625) and generate SIEM queries.":"Summarize recent Windows security events and repeated failed logons.";
 if(role==="ciso")return "Prepare an executive briefing on current security posture and risks.";
 return req}
/* shared pivots derived from the event data (mirrors the SIEM repeated-failure logic) */
function pivots(req){var ev=evSec(),by={},us={},hs={},ip0=(req.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/)||[])[0];
 ev.filter(function(e){return e.eventId===4625&&e.srcIp}).forEach(function(e){var g=by[e.srcIp]=by[e.srcIp]||{n:0,users:{},hosts:{}};g.n++;g.users[e.targetUser||e.user||"?"]=1;g.hosts[e.host]=1});
 var ips=Object.keys(by).filter(function(k){return by[k].n>=3}).sort(function(a,b){return by[b].n-by[a].n});
 var alerts=((S.data&&S.data.recentAlerts)||[]).filter(function(a){return/^WIN-AUTH/.test(a.ruleId)});
 alerts.forEach(function(a){((a.entities||{}).ips||[]).forEach(function(i){if(ips.indexOf(i)<0)ips.push(i)})});
 if(ip0){ips=ips.filter(function(i){return i!==ip0});ips.unshift(ip0)}
 ips.forEach(function(i){var g=by[i];if(g){Object.keys(g.users).forEach(function(u){us[u]=1});Object.keys(g.hosts).forEach(function(h){hs[h]=1})}});
 alerts.forEach(function(a){hs[a.host]=1;((a.entities||{}).users||[]).forEach(function(u){us[u]=1})});
 ((S.data&&S.data.activeIncidents)||[]).forEach(function(i){hs[i.host]=1});
 return{ips:ips.slice(0,6),hosts:Object.keys(hs).slice(0,8),users:Object.keys(us).slice(0,10),counts:by}}
function otl(text,kind){if(!INV)return;INV.tl.push({t:Date.now(),text:text,kind:kind||"sys"});paintOrch()}
function ostSet(r,st,pr){OST[r]={status:st,progress:pr==null?(OST[r]&&OST[r].progress)||0:pr};syncDash();paintNodes()}
function posOf(r){return OPOS[r]||OPOS.orch}
function fly(from,to,label){var net=$("orch-net");INV&&(INV.snd=from==="orch"?null:from,INV.rcv=to==="orch"?null:to);paintNodes();
 var calm=window.matchMedia&&matchMedia("(prefers-reduced-motion:reduce)").matches;
 if(net&&!calm&&net.animate){var a=posOf(from),b=posOf(to),svg=net.querySelector(".orch-ov");var ln=document.createElementNS("http://www.w3.org/2000/svg","line");ln.setAttribute("x1",a.x);ln.setAttribute("y1",a.y);ln.setAttribute("x2",b.x);ln.setAttribute("y2",b.y);ln.setAttribute("class","orch-msgln");svg.appendChild(ln);setTimeout(function(){ln.remove()},1500);
  for(var k=0;k<4;k++){var d=document.createElement("i");d.className="orch-pt";d.style.left=a.x+"%";d.style.top=a.y+"%";net.appendChild(d);(function(d,k){var an=d.animate([{left:a.x+"%",top:a.y+"%",opacity:0,transform:"translate(-50%,-50%) scale(.6)"},{opacity:1,offset:.15},{opacity:1,offset:.85},{left:b.x+"%",top:b.y+"%",opacity:0,transform:"translate(-50%,-50%) scale(1.2)"}],{duration:1100,delay:k*130,easing:"ease-in-out",fill:"both"});an.onfinish=function(){d.remove()}})(d,k)}}
 return sleep(calm?250:1250).then(function(){if(INV){INV.snd=null;INV.rcv=null}paintNodes()})}
function pause(){return new Promise(function(res){(function w(){if(!INV||!INV.paused)res();else setTimeout(w,150)})()})}
function msgFor(from,to,R){var c=INV.ctx,ev=evSec(),top=function(){return R.findings[0]?R.findings[0].t.slice(0,150):R.head};
 if(from==="siem"){if(c.ips.length){var g=c.counts[c.ips[0]],n=g?g.n:null,u=g?Object.keys(g.users).length:0;return n?"Detected "+n+" failed login attempts from suspicious IP "+c.ips[0]+(u>1?" against "+u+" accounts":"")+".":"Authentication alerts reference suspicious IP "+c.ips[0]+"."}return"Searched "+ev.length+" security events: "+R.head+" No repeated failed-logon source found."}
 if(from==="analyst")return c.ips.length?"Severity "+R.sev.toUpperCase()+". Investigate whether "+c.ips[0]+" is associated with additional suspicious activity. "+R.head:"Severity "+R.sev.toUpperCase()+". "+R.head;
 if(from==="hunter")return R.findings.length?"Hunt result: "+top():"Hunt result: "+R.head;
 if(from==="engineer")return"Weaknesses found: "+R.head;
 if(from==="responder")return R.noInc?"No active incident to respond to. "+R.head:R.head+" Containment steps need explicit approval; nothing was executed.";
 return R.head}
function addMem(role,R){var m=INV.mem;m.results[role]=R;R.findings.forEach(function(f){m.findings.push({agent:role,sev:f.sev,t:f.t,ev:f.ev||[]});(f.t.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g)||[]).forEach(function(ip){iocAdd("IP address",ip,role)})});
 R.recs.forEach(function(r){if(!m.recs.some(function(x){return x.t===r.t}))m.recs.push(Object.assign({by:role},r))});
 if(R.table&&/^Indicators/.test(R.table.title))R.table.rows.forEach(function(r){iocAdd(r[0],String(r[1]),role)});
 var c=INV.ctx;if(role==="hunter"||role==="analyst"){R.findings.forEach(function(f){(f.t.match(/\bon ([A-Z][\w-]{2,})\b/g)||[]).forEach(function(x){var h=x.slice(3);if(c.hosts.indexOf(h)<0&&/^[A-Z0-9-]+$/.test(h))c.hosts.push(h)})})}}
function iocAdd(type,v,by){var m=INV.mem.iocs,f=m.filter(function(i){return i.type===type&&i.v===v})[0];if(f){if(f.by.indexOf(by)<0)f.by.push(by)}else m.push({type:type,v:v,by:[by]})}
function riskOf(){var f=INV.mem.findings,w={critical:80,high:60,medium:35,low:10},m=0,hi=0;f.forEach(function(x){m=Math.max(m,w[x.sev]||0);if(x.sev==="critical"||x.sev==="high")hi++});var s=f.length?Math.min(100,m+Math.min(20,hi*4)):0;
 return{score:s,label:s>=80?"CRITICAL":s>=60?"HIGH":s>=35?"MEDIUM":s>0?"LOW":"NONE",hi:hi,n:f.length}}
function confOf(){var k=INV.dl.kind,ag=Object.keys(INV.mem.results).length,why=[];var lv=k==="sample"?0:1;why.push(k==="sample"?"Data is simulated, so confidence in any real-world conclusion is low.":"Based on data stored in your backend.");
 var cross=INV.mem.iocs.filter(function(i){return i.by.length>=2}).length;if(cross&&k!=="sample"){lv++;why.push(cross+" indicator(s) were independently reported by 2 or more agents.")}else if(cross)why.push(cross+" indicator(s) appear in 2 or more agents' results (same simulated data).");
 why.push(ag+" of "+INV.agents.length+" assigned agent(s) completed.");why.push("All analysis is rule-based; there is no external threat-intelligence check.");return{label:["LOW","MEDIUM","HIGH"][Math.min(lv,2)],why:why}}
async function runAgent(role,idx){var my=INV.tok,R,task=taskFor(role,INV.req);INV.cur=role;
 ostSet(role,"Processing",0);if(idx+1<INV.agents.length&&OST[INV.agents[idx+1]]&&OST[INV.agents[idx+1]].status==="Waiting for Agent")ostSet(INV.agents[idx+1],"Assigned",0);
 otl(ROLES[role].n+" "+VERB[role]+".","agent");
 var srv=S.mode==="connected"&&canWrite(),srvRun=null;
 try{if(INV.fail&&INV.fail[role]){delete INV.fail[role];throw new Error("Simulated agent failure (test hook)")}
  if(srv){var ctx={ips:INV.ctx.ips||[],hosts:INV.ctx.hosts||[],users:INV.ctx.users||[]};var prev=INV.agents[idx-1];if(prev&&INV.msgs.length)ctx.message=INV.msgs[INV.msgs.length-1].text,ctx.from=prev;
   srvRun=INV.runs[role]&&INV.runs[role].status==="failed"?await api("POST","/tasks/"+INV.runs[role].id+"/retry"):await api("POST","/tasks",{role:role,task:task,context:ctx,investigationId:INV.id});INV.runs[role]=srvRun;
   while(srvRun.status==="running"){if(my!==INV.tok)return false;await pause();ostSet(role,"Processing",srvRun.progress);srvRun=await api("POST","/tasks/"+srvRun.id+"/next");INV.runs[role]=srvRun;
    var st=srvRun.steps.filter(function(x){return x.status==="done"}).slice(-1)[0];if(st&&INV.seenStep[srvRun.id+st.id]!==1){INV.seenStep[srvRun.id+st.id]=1;otl(ROLES[role].n+" step "+srvRun.stepsDone+"/"+srvRun.stepsTotal+": "+st.name+" ("+st.durationMs+" ms)","agent")}}
   if(srvRun.status!=="completed")throw new Error(srvRun.error||("run "+srvRun.status));R=srvR(role,srvRun)}
  else R=await BUILD[role](task,INV.ctx)}catch(e){if(my!==INV.tok)return false;ostSet(role,"Failed",OST[role].progress);INV.failed=role;INV.err=ROLES[role].n+" failed: "+(e.message||e);otl(INV.err,"alert");audit("Agent failed: "+role,"orchestrator");return false}
 if(my!==INV.tok)return false;INV.dl=dataLabel();
 var steps=srv?[]:stepsOf(role,task,R),said=0;
 if(srv){R.findings.slice(0,3).forEach(function(f){otl(ROLES[role].n+" identified: "+f.t.slice(0,140),f.sev==="critical"||f.sev==="high"?"alert":"agent")})}
 for(var k=0;k<steps.length;k++){await pause();if(my!==INV.tok)return false;var s=steps[k];ostSet(role,"Processing",Math.min(90,Math.round((k+1)/steps.length*90)));
  if(s.find!=null&&said<3){said++;otl(ROLES[role].n+" identified: "+s.t.replace(/^ALERT /,"").slice(0,140),s.al?"alert":"agent")}
  await sleep(260+Math.random()*240)}
 addMem(role,R);INV.res[role]=R;
 if(role==="siem"||!INV.pv){var pv=pivots(INV.req);INV.ctx.ips=pv.ips;INV.ctx.hosts=uniqA(INV.ctx.hosts.concat(pv.hosts));INV.ctx.users=pv.users;INV.ctx.counts=pv.counts;INV.pv=true;pv.ips.forEach(function(i){iocAdd("IP address",i,role==="siem"?"siem":"orchestrator")});INV.ctx.results=INV.mem.results}
 otl(ROLES[role].n+" finished: "+R.head,"agent");
 var nxt=INV.agents[idx+1];ostSet(role,"Communicating",95);
 var text=nxt?msgFor(role,nxt,R):null;if(nxt){INV.msgs.push({t:Date.now(),from:role,to:nxt,text:text});otl(ROLES[role].n+" → "+ROLES[nxt].n+": “"+text+"”","msg");await fly(role,nxt)}
 if(my!==INV.tok)return false;ostSet(role,"Completed",100);return true}
async function runPipeline(from){var my=INV.tok;INV.running=true;INV.failed=null;INV.err="";INV.status="Running";paintOrch();
 for(var i=from;i<INV.agents.length;i++){var r=INV.agents[i];if(INV.done[r])continue;await pause();if(my!==INV.tok)return;var ok=await runAgent(r,i);if(my!==INV.tok)return;if(!ok){INV.running=false;INV.status="Needs attention";paintOrch();return}INV.done[r]=1;
  if(i+2<INV.agents.length&&OST[INV.agents[i+2]]&&OST[INV.agents[i+2]].status==="Waiting for Agent")ostSet(INV.agents[i+2],"Assigned",0)}
 finishInv(my)}
async function finishInv(my){var rk=riskOf(),last=INV.agents[INV.agents.length-1];INV.running=false;var t="Investigation completed. "+(rk.label==="NONE"?"No risk indicators were found in the data in view":rk.label+"-risk incident identified")+" (risk score "+rk.score+"/100).";
 INV.msgs.push({t:Date.now(),from:last,to:"user",text:t});otl(ROLES[last].n+" → User: “"+t+"”","msg");await fly(last,"orch");if(my!==INV.tok)return;
 makeReport(false);INV.status="Completed";otl("Final report generated.","sys");audit("Investigation completed: "+INV.id,"orchestrator");saveInv();paintOrch()}
function makeReport(partial){var rk=riskOf(),cf=confOf(),m=INV.mem,P=function(r){return ROLES[r].n},o=[];var ids=Object.keys(INV.res),lab=INV.dl.text;
 var top=m.findings.slice().sort(function(a,b){return SRANK[b.sev]-SRANK[a.sev]});
 o.push("# Unified Security Intelligence Report","","- **Investigation ID:** "+INV.id,"- **Request:** "+INV.req,"- **Generated:** "+new Date().toISOString()+(partial?" (PARTIAL: "+ids.length+" of "+INV.agents.length+" agents had finished)":""),"- **Data:** "+lab,"");
 o.push("## Executive Summary","",(rk.n?"Risk score "+rk.score+"/100 ("+rk.label+"). "+rk.n+" finding(s) from "+ids.length+" agent(s), "+rk.hi+" at high or critical severity. ":"No findings were produced. ")+(top[0]?"Most important: "+top[0].t:""),"");
 o.push("## Incident Description","",INV.req,"",INV.res.responder&&!INV.res.responder.noInc?INV.res.responder.head:INV.res.analyst?INV.res.analyst.head:"No incident record was produced by the assigned agents.","");
 o.push("## Threat Severity","","**"+rk.label+"** (heuristic score "+rk.score+"/100: strongest finding plus 4 points per high or critical finding; not a calibrated measure).","");
 o.push("## Technical Findings","");PIPE.forEach(function(r){var R=INV.res[r];if(!R)return;o.push("### "+P(r),"",R.head,"");R.findings.slice(0,6).forEach(function(f){o.push("- ["+f.sev.toUpperCase()+"] "+f.t)});o.push("")});
 o.push("## Agent Contributions","");INV.agents.forEach(function(r){var R=INV.res[r];o.push("- **"+P(r)+":** "+(R?R.findings.length+" finding(s); "+R.head:(OST[r]&&OST[r].status==="Failed"?"failed":"did not finish"))+(INV.msgs.filter(function(x){return x.from===r}).length?" Sent "+INV.msgs.filter(function(x){return x.from===r}).length+" message(s).":""))});o.push("");
 o.push("## Indicators of Compromise","");o.push(...(m.iocs.length?m.iocs.map(function(i){return"- "+i.type+": `"+i.v+"` (reported by "+i.by.map(P).join(", ")+")"}):["None extracted."]),"");
 o.push("## Risk Assessment","","Risk score **"+rk.score+"/100 ("+rk.label+")**.");(INV.res.ciso?INV.res.ciso.findings.slice(0,4).map(function(f){return"- "+f.t}):[]).forEach(function(x){o.push(x)});o.push("");
 o.push("## Recommended Actions (none executed)","");o.push(...(m.recs.length?m.recs.slice(0,16).map(function(r){return"- ["+r.p+"] "+r.t+(r.dis?" (needs explicit approval)":"")+" — "+P(r.by)}):["None."]),"");
 o.push("## Incident Response Plan","");var rp=INV.res.responder;o.push(...(rp&&rp.recs.length?rp.recs.slice(0,14).map(function(r){return"- ["+r.p+"] "+r.t}):["The Incident Responder was not assigned or found no active incident. Use the Recommended Actions above."]),"");
 o.push("## Confidence Level","","**"+cf.label+"**");cf.why.forEach(function(w){o.push("- "+w)});o.push("");
 o.push("## Agent Communication","");o.push(...(INV.msgs.length?INV.msgs.map(function(x){return"- "+fT(new Date(x.t).toISOString())+" "+(x.from==="user"?"User":P(x.from))+" → "+(x.to==="user"?"User":P(x.to))+": "+x.text}):["No messages."]),"");
 o.push("## Investigation Timeline","");o.push(...INV.tl.map(function(x){return"- "+fT(new Date(x.t).toISOString())+" — "+x.text}),"");
 o.push("## Limits","","- "+lab,"- Findings are hypotheses from a rule-based analysis of the data in view; they are not verified real-world findings unless the data came from your connected backend.","- Nothing was scanned, blocked, disabled or changed. Disruptive steps can only be sent as requests for a human to approve.","- No external intelligence (VirusTotal, Sentinel, Splunk, Wazuh) was queried.");
 INV.report=o.join("\n");INV.partial=partial;audit((partial?"Partial report":"Final report")+" generated: "+INV.id)}
function saveInv(){var h=(L.inv=L.inv||[]);h.unshift({id:INV.id,at:Date.now(),req:INV.req,agents:INV.agents,risk:riskOf(),report:INV.report.slice(0,40000),dl:INV.dl.kind});L.inv=h.slice(0,10);lsSave()}
function orchStart(){if(INV&&INV.running)return;var inp=$("orch-in"),req=(inp.value||"").trim();if(!req){req="Investigate a suspicious login attack.";inp.value=req}
 if(!E){$("orch-err").innerHTML='<div class="banner bad">The analysis engine did not load.</div>';return}
 var sel=chosen(req);if(!sel.length){$("orch-err").innerHTML='<div class="banner bad">Select at least one agent.</div>';return}
 if(INV)INV.tok++;var d=new Date(),id="INV-"+d.getFullYear()+String(d.getMonth()+1).padStart(2,"0")+String(d.getDate()).padStart(2,"0")+"-"+Math.random().toString(36).slice(2,6).toUpperCase();
 INV={id:id,req:req,agents:sel,manual:!OSEL.auto,tok:(INV?INV.tok:0)+1,running:true,paused:false,status:"Running",tl:[],msgs:[],mem:{findings:[],iocs:[],recs:[],results:{}},ctx:{ips:[],hosts:[],users:[],counts:{},results:null},res:{},done:{},runs:{},seenStep:{},dl:dataLabel(),report:null,err:"",pend:null,reqd:{},snd:null,rcv:null,started:Date.now(),fail:Object.assign({},window.__orchFail||{})};INV.ctx.results=INV.mem.results;
 ["analyst","engineer","hunter","responder","siem","ciso"].forEach(function(r){var i=sel.indexOf(r);OST[r]=i<0?{status:"Idle",progress:0}:{status:i===0?"Assigned":i===1?"Assigned":"Waiting for Agent",progress:0}});syncDash();
 audit("Investigation started: "+id+" ("+sel.length+" agents)");otl("Investigation "+id+" started. Agents: "+sel.map(function(r){return ROLES[r].n}).join(", ")+(OSEL.auto?" (auto-selected)":" (manual)")+".","sys");
 var pv=pivots(req);INV.ctx.ips=sel.indexOf("siem")<0?pv.ips:[];INV.ctx.hosts=sel.indexOf("siem")<0?pv.hosts:[];INV.ctx.users=sel.indexOf("siem")<0?pv.users:[];INV.ctx.counts=pv.counts;INV.pv=sel.indexOf("siem")>=0?false:true;if(INV.pv)INV.pv=true;
 if(sel.indexOf("siem")<0&&pv.ips.length)otl("SIEM Specialist is not assigned, so the orchestrator derived pivot data (IPs, hosts) directly from the event data.","sys");
 var my=INV.tok;(async function(){for(var i=0;i<sel.length;i++){fly("orch",sel[i]);await sleep(160);if(my!==INV.tok)return}await sleep(700);if(my!==INV.tok)return;runPipeline(0)})();paintOrch()}
function orchPause(){if(!INV||!INV.running||INV.paused)return;INV.paused=true;INV.status="Paused";otl("Investigation paused.","sys");audit("Investigation paused");paintOrch()}
function orchResume(){if(!INV||!INV.paused)return;INV.paused=false;INV.status="Running";otl("Investigation resumed.","sys");audit("Investigation resumed");paintOrch()}
function orchCancel(){if(!INV||(!INV.running&&INV.status!=="Needs attention"))return;INV.tok++;INV.running=false;INV.paused=false;INV.status="Cancelled";INV.agents.forEach(function(r){if(!INV.done[r])OST[r]={status:"Idle",progress:0}});INV.snd=INV.rcv=null;otl("Investigation cancelled by user.","sys");audit("Investigation cancelled");syncDash();paintOrch()}
function orchRetry(){if(!INV||!INV.failed)return;var r=INV.failed,i=INV.agents.indexOf(r);otl("Retrying "+ROLES[r].n+".","sys");audit("Retry failed agent: "+r);INV.err="";runPipeline(i)}
function orchReport(){if(!INV||!Object.keys(INV.res).length)return;var partial=INV.running||INV.status!=="Completed";makeReport(partial);otl("Report generated"+(partial?" (partial)":"")+".","sys");paintOrch();var b=$("orch-rep");if(b)try{b.scrollIntoView({behavior:"smooth",block:"nearest"})}catch(e){}}
function orchReset(){if(INV)INV.tok++;INV=null;["analyst","engineer","hunter","responder","siem","ciso"].forEach(function(r){OST[r]=null});syncDash();paintOrch()}
async function orchPost(b){if(S.mode==="connected"){if(!canWrite())throw new Error("Your role cannot propose actions.");await api("POST","/actions",b);S.actions=await api("GET","/actions");return"REQUEST SENT — awaiting approver"}
 L.drafts.unshift({id:"draft_"+Date.now(),draft:true,status:"proposed",requiresApproval:true,proposedBy:"you (draft)",incidentId:b.incidentId,type:b.type,target:b.target,description:b.description,rationale:b.rationale});lsSave();return"DRAFT (sample, this browser only)"}
async function orchReq(i){var r=INV.mem.recs[i];INV.pend=null;try{INV.reqd[i]=await orchPost({incidentId:r.inc||undefined,type:r.type,target:r.target||"unspecified",description:r.desc||r.t,rationale:"Requested from the Collaboration Center investigation "+INV.id+" (rule-based recommendation by "+ROLES[r.by].n+"). A human must approve and perform it."});audit("Approval requested: "+r.type+" "+r.target);try{paintActs();paintKpis()}catch(e){}}catch(e){INV.err=e.message||"Request failed"}paintOrch()}
/* ---------- UI ---------- */
SK.team=function(){return'<section class="pn con orch" id="orch" data-role="team"><div class="con-top"><div><h3 class="con-h">AI AGENT COLLABORATION CENTER</h3><p class="sub" style="margin:2px 0 0">An orchestrator assigns work to the six agents, passes findings between them and writes one report.</p></div><span class="con-st" id="orch-st" role="status" aria-live="polite"><i></i><b>Idle</b></span></div>'
 +'<div class="con-lab" id="orch-lab"></div>'
 +'<form id="orch-form" class="con-form"><label class="sub" for="orch-in" style="margin:0">Your request to the SOC team</label><div class="con-row"><input type="text" id="orch-in" maxlength="300" placeholder="Investigate a suspicious login attack." autocomplete="off"><button type="submit" class="abtn con-go" id="orch-go">&#9654; Start Investigation</button></div>'
 +'<div class="con-presets">'+["Investigate a suspicious login attack.","Analyze this suspicious IP address 203.0.113.45","Review our cybersecurity posture.","Investigate possible malware on a server."].map(function(c){return'<button type="button" class="mini" data-opre="'+esc(c)+'">'+esc(c.length>40?c.slice(0,38)+"…":c)+"</button>"}).join("")+"</div>"
 +'<div class="orch-sel" id="orch-sel"></div>'
 +'<div class="con-presets" id="orch-ctl"><button type="button" class="abtn con-sec" data-octl="pause">&#10073;&#10073; Pause</button><button type="button" class="abtn con-sec" data-octl="resume">&#9654; Resume</button><button type="button" class="abtn con-sec" data-octl="cancel">&#9632; Cancel</button><button type="button" class="abtn con-sec" data-octl="retry">&#8635; Retry Failed Agent</button><button type="button" class="abtn con-sec" data-octl="report">Generate Final Report</button><button type="button" class="abtn con-sec" data-octl="reset">Reset</button></div></form><div id="orch-err"></div>'
 +'<div class="orch-net" id="orch-net"><svg class="orch-ov" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true"></svg><div class="orch-core" id="orch-core"><b>ORCHESTRATOR</b><small id="orch-core-s">Waiting for a request</small></div></div>'
 +'<div class="con-cols orch-cols"><div><h4 class="con-sub">Agent-to-agent communication</h4><div class="con-log orch-feed" id="orch-feed" aria-live="polite"></div></div><div><h4 class="con-sub">Investigation timeline</h4><div class="con-log" id="orch-tl"></div></div></div>'
 +'<div id="orch-ws"></div><div id="orch-rep"></div><div id="orch-aic" class="res" hidden></div><div id="st-team" class="st" role="status"></div><div id="res-team" class="res" hidden></div><div id="orch-hist"></div></section>'};
function paintNodes(){var net=$("orch-net");if(!net)return;var h="";
 PIPE.forEach(function(r){var o=OST[r]||{status:"Idle",progress:0},cl=stsCls(o.status),inA=INV&&INV.agents.indexOf(r)>=0,sh=o.status!=="Idle"&&!/Waiting/.test(o.status)&&o.status!=="Failed";
  h+='<button type="button" class="orch-n'+(INV&&INV.snd===r?" snd":"")+(INV&&INV.rcv===r?" rcv":"")+(INV&&INV.cur===r&&INV.running?" cur":"")+'" data-role="'+r+'" data-sts="'+cl+'" data-onode="'+r+'" style="left:'+OPOS[r].x+"%;top:"+OPOS[r].y+'%" aria-label="'+esc(ROLES[r].n+": "+o.status)+'"><span class="orch-ic">'+svg(r,22)+'</span><b>'+esc(ROLES[r].n)+'</b><em>'+esc(o.status)+(sh||o.status==="Failed"?" · "+(o.progress||0)+"%":"")+'</em><span class="orch-pb"><s style="width:'+(o.progress||0)+'%"></s></span></button>'});
 [].forEach.call(net.querySelectorAll(".orch-n"),function(n){n.remove()});net.insertAdjacentHTML("beforeend",h);
 var sv=net.querySelector(".orch-ov");if(!sv.dataset.b){var s="";PIPE.forEach(function(r,i){s+='<line class="sp" x1="50" y1="50" x2="'+OPOS[r].x+'" y2="'+OPOS[r].y+'"/>';var q=PIPE[(i+1)%6];s+='<line class="rg" x1="'+OPOS[r].x+'" y1="'+OPOS[r].y+'" x2="'+OPOS[q].x+'" y2="'+OPOS[q].y+'"/>'});sv.innerHTML=s;sv.dataset.b="1"}}
function paintOrch(){var root=$("orch");if(!root)return;var I=INV,st=I?I.status:"Idle",run=I&&I.running,rk=I?riskOf():null;
 $("orch-st").querySelector("b").textContent=st;$("orch-st").setAttribute("data-sts",stsCls(st==="Running"?"Processing":st==="Needs attention"?"Failed":st));
 var dl=I?I.dl:dataLabel();$("orch-lab").innerHTML='<span class="badge '+(dl.kind==="live"?"b-live":"b-demo")+'">'+(dl.kind==="live"?"CONNECTED DATA":dl.kind==="mixed"?"CONNECTED + SAMPLE":"SIMULATED DATA")+"</span> "+esc(dl.text)+" Agents use the rule-based analysis of their own consoles. Messages are generated from their results. No system is scanned and nothing is executed."+(I?' <b class="orch-id">'+esc(I.id)+"</b>":"");
 var req=($("orch-in").value||"").trim()||"Investigate a suspicious login attack.",pre=OSEL.auto?autoAgents(req):OSEL.set;
 $("orch-sel").innerHTML='<span class="sub" style="margin:0">Agents:</span><button type="button" class="mini'+(OSEL.auto?" on":"")+'" data-oauto="1">Auto-select</button>'+PIPE.map(function(r){var on=I&&run?I.agents.indexOf(r)>=0:pre.indexOf(r)>=0;return'<button type="button" role="checkbox" aria-checked="'+on+'" class="orch-chip'+(on?" on":"")+'" data-role="'+r+'" data-oag="'+r+'"'+(run?" disabled":"")+">"+esc(ROLES[r].n)+"</button>"}).join("")+'<span class="sub" style="margin:0">'+(OSEL.auto?"chosen by the orchestrator from your request":"chosen by you")+"</span>";
 var q=function(a){return $("orch-ctl").querySelector('[data-octl="'+a+'"]')};q("pause").disabled=!(run&&!I.paused);q("resume").disabled=!(I&&I.paused);q("cancel").disabled=!(I&&(run||I.status==="Needs attention"));q("retry").disabled=!(I&&I.failed&&!run);q("report").disabled=!(I&&Object.keys(I.res).length);q("reset").disabled=!!run&&!I.paused;
 $("orch-go").disabled=!!run;$("orch-err").innerHTML=I&&I.err?'<div class="banner bad">'+esc(I.err)+" Use <b>Retry Failed Agent</b>.</div>":"";
 $("orch-core-s").textContent=!I?"Waiting for a request":I.status==="Completed"?"Done · risk "+rk.score+"/100":I.status+(I.cur&&run?" · "+ROLES[I.cur].n:"");$("orch-core").classList.toggle("run",!!run&&!I.paused);
 paintNodes();
 var fd=$("orch-feed"),tl=$("orch-tl");fd.innerHTML=I&&I.msgs.length?I.msgs.map(function(m){return'<div class="con-l orch-m"><time>'+fT(new Date(m.t).toISOString())+'</time><b data-role="'+(m.from==="user"?"ciso":m.from)+'" class="orch-who">'+esc(m.from==="user"?"User":ROLES[m.from].n)+'</b> → <b data-role="'+(m.to==="user"?"ciso":m.to)+'" class="orch-who">'+esc(m.to==="user"?"User":ROLES[m.to].n)+"</b><br>“"+esc(m.text)+"”</div>"}).join(""):'<div class="empty">Messages between agents appear here while the investigation runs.</div>';fd.scrollTop=fd.scrollHeight;
 tl.innerHTML=I&&I.tl.length?I.tl.map(function(x){return'<div class="con-l'+(x.kind==="alert"?" al":"")+'"><time>'+fT(new Date(x.t).toISOString())+"</time>"+esc(x.text)+"</div>"}).join(""):'<div class="empty">Real timestamps are recorded as the investigation runs.</div>';tl.scrollTop=tl.scrollHeight;
 var w="";if(I){var m=I.mem,cf=confOf(),alr=((S.data&&S.data.recentAlerts)||[]).filter(function(a){return I.ctx.hosts.indexOf(a.host)>=0||((a.entities||{}).ips||[]).some(function(x){return I.ctx.ips.indexOf(x)>=0})}),allA=false;if(!alr.length){alr=((S.data&&S.data.recentAlerts)||[]).slice(0,5);allA=true}
  w+='<h4 class="con-sub">Shared investigation workspace <span class="chip">'+esc(I.id)+'</span></h4><div class="orch-grid"><div class="card2"><b>Risk score</b><div class="orch-risk"><span>'+rk.score+'</span>/100 '+sev(rk.label==="NONE"?"low":rk.label.toLowerCase())+'</div><small class="sub">heuristic: strongest finding + 4 per high/critical</small><div class="con-bar" style="margin:8px 0 4px"><span style="width:'+rk.score+'%"></span></div><small class="sub">Confidence: <b>'+cf.label+"</b></small></div>"
   +'<div class="card2"><b>Request</b><p style="margin:4px 0;font-size:13px">'+esc(I.req)+'</p><small class="sub">Assigned: '+I.agents.map(function(r){return esc(ROLES[r].n)}).join(", ")+"</small></div>"
   +'<div class="card2"><b>Indicators of compromise</b> <span class="chip">'+m.iocs.length+"</span>"+(m.iocs.length?'<ul class="con-lim" style="margin-top:4px">'+m.iocs.slice(0,8).map(function(i){return"<li>"+esc(i.type)+": <code>"+esc(i.v)+"</code> <small>("+i.by.map(function(b){return esc(ROLES[b]?ROLES[b].n:b)}).join(", ")+")</small></li>"}).join("")+"</ul>":'<p class="empty">None yet.</p>')+"</div>"
   +'<div class="card2"><b>Related alerts</b> <span class="chip">'+alr.length+"</span>"+(alr.length?'<ul class="con-lim" style="margin-top:4px">'+alr.slice(0,5).map(function(a){return"<li>"+sev(a.severity)+" "+esc(a.title.slice(0,70))+" <small>"+esc(a.host)+"</small></li>"}).join("")+"</ul>"+(allA?'<small class="sub">No alert matched the pivots, so the latest alerts are shown.</small>':""):'<p class="empty">No alerts in the data.</p>')+"</div></div>";
  w+='<h4 class="con-sub">Findings by agent</h4>'+(m.findings.length?m.findings.slice().sort(function(a,b){return SRANK[b.sev]-SRANK[a.sev]}).slice(0,10).map(function(f){return'<div class="con-f f-'+f.sev+'">'+sev(f.sev)+' <b data-role="'+f.agent+'" class="orch-who">'+esc(ROLES[f.agent].n)+"</b> "+esc(f.t)+"</div>"}).join(""):'<div class="empty">Findings are added to shared memory as each agent finishes.</div>');
  if(m.recs.length)w+='<h4 class="con-sub">Recommended actions <span class="chip">none executed</span></h4>'+m.recs.slice(0,12).map(function(r,i){var rq=I.reqd[i];return'<div class="con-r"><span class="chip p'+r.p+'">'+esc(r.p)+"</span><span>"+esc(r.t)+' <small class="sub">— '+esc(ROLES[r.by].n)+"</small>"+(r.dis?' <small class="warn">needs explicit approval</small>':"")+"</span>"+(r.srv?'<span class="badge b-live">PROPOSED \u2014 awaiting approval (Pending Approvals)</span>':r.dis&&r.type?(rq?'<span class="badge b-live">'+esc(rq)+"</span>":I.pend===i?'<span class="con-ask">Send as a request for approval? Spark will NOT carry it out.<button type="button" class="mini" data-oqy="'+i+'">Yes, send request</button><button type="button" class="mini" data-oqn="1">Cancel</button></span>':'<button type="button" class="mini" data-oq="'+i+'">Request approval</button>'):"")+"</div>"}).join("")}
 $("orch-ws").innerHTML=w;
 var rp="";if(I&&I.report)rp='<h4 class="con-sub">Unified Security Intelligence Report'+(I.partial?' <span class="chip">partial</span>':"")+'</h4><div class="ctl"><button type="button" class="mini" data-orv="1">View report</button><button type="button" class="mini" data-orc="1">Copy</button><button type="button" class="mini" data-ord="md">Export (.md)</button><button type="button" class="mini" data-ord="html">Export (web page / print to PDF)</button><button type="button" class="mini" data-ord="json">Export investigation (.json)</button><button type="button" class="mini" data-oai="1">AI summary</button><span class="st" id="orch-msg" role="status"></span></div><div id="orch-view">'+(I.view?'<div class="res">'+render(I.report)+"</div>":"")+"</div>";
 $("orch-rep").innerHTML=rp;
 var H=L.inv||[],AU=L.audit||[];$("orch-hist").innerHTML=(H.length?'<h4 class="con-sub">Investigation history <span class="chip">this browser only</span></h4>'+H.map(function(e,i){return'<div class="con-h2"><time>'+esc(fDT(new Date(e.at).toISOString()))+"</time><b>"+esc(e.id)+"</b>"+sev(e.risk.label==="NONE"?"low":e.risk.label.toLowerCase())+"<span>"+esc(e.req.slice(0,70))+'</span><button type="button" class="mini" data-ohv="'+i+'">View</button></div>'}).join(""):"")+(AU.length?'<details class="guide"><summary>Audit log ('+AU.length+')</summary>'+AU.slice(0,40).map(function(a){return'<div class="con-l"><time>'+esc(fDT(new Date(a.t).toISOString()))+"</time>"+esc(a.who)+": "+esc(a.what)+"</div>"}).join("")+"</details>":"")}
document.addEventListener("click",function(e){var t=e.target;if(!t.closest||!t.closest("#socws"))return;var c;
 if(c=t.closest("[data-opre]")){$("orch-in").value=c.dataset.opre;paintOrch();return}
 if(c=t.closest("[data-oauto]")){OSEL.auto=true;paintOrch();return}
 if(c=t.closest("[data-oag]")){var r=c.dataset.oag;if(OSEL.auto){OSEL.set=autoAgents(($("orch-in").value||"Investigate a suspicious login attack.").trim());OSEL.auto=false}var i=OSEL.set.indexOf(r);if(i>=0)OSEL.set.splice(i,1);else OSEL.set.push(r);paintOrch();return}
 if(c=t.closest("[data-octl]")){var a=c.dataset.octl;({pause:orchPause,resume:orchResume,cancel:orchCancel,retry:orchRetry,report:orchReport,reset:orchReset})[a]();return}
 if(c=t.closest("[data-onode]")){var n=c.dataset.onode;setRole(n);return}
 if(c=t.closest("[data-oq]")){INV.pend=Number(c.dataset.oq);paintOrch();return}if(t.closest("[data-oqn]")){INV.pend=null;paintOrch();return}
 if(c=t.closest("[data-oqy]")){orchReq(Number(c.dataset.oqy));return}
 if(t.closest("[data-orv]")){INV.view=!INV.view;paintOrch();return}
 if(t.closest("[data-orc]")){var m=$("orch-msg");if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(INV.report).then(function(){m.textContent="Copied."},function(){m.textContent="Use Export instead."});else m.textContent="Use Export instead.";return}
 if(c=t.closest("[data-ord]")){var k=c.dataset.ord,nm="investigation-"+INV.id;audit("Report exported ("+k+")");if(k==="md")download(nm+".md",INV.report,"text/markdown");else if(k==="json")download(nm+".json",JSON.stringify({id:INV.id,request:INV.req,agents:INV.agents,data:INV.dl,risk:riskOf(),messages:INV.msgs,timeline:INV.tl,iocs:INV.mem.iocs,findings:INV.mem.findings,recommendations:INV.mem.recs.map(function(r){return{priority:r.p,text:r.t,by:r.by,needsApproval:!!r.dis}}),report:INV.report},null,1),"application/json");else download(nm+".html",'<!doctype html><meta charset="utf-8"><title>'+esc(INV.id)+'</title><style>body{font:15px/1.55 system-ui,sans-serif;max-width:820px;margin:30px auto;padding:0 16px;color:#111}h4{margin:16px 0 4px}</style>'+render(INV.report),"text/html");return}
 if(c=t.closest("[data-ohv]")){var e2=L.inv[Number(c.dataset.ohv)];if(INV&&INV.running)return;INV={id:e2.id,req:e2.req,agents:e2.agents,tok:(INV?INV.tok:0)+1,running:false,paused:false,status:"Completed",tl:[],msgs:[],mem:{findings:[],iocs:[],recs:[],results:{}},ctx:{ips:[],hosts:[],users:[],counts:{}},res:{},done:{},dl:{kind:e2.dl,text:e2.dl==="sample"?"SIMULATED: saved run from sample data.":"Saved run."},report:e2.report,view:true,reqd:{},err:""};paintOrch();return}
 if(t.closest("[data-oai]")){var b=t.closest("[data-oai]");run(b,"","security_advisor","","Write a short executive summary of this unified investigation, and say what to verify first:\n"+INV.report.slice(0,6000),"Write a short executive summary of this unified SIMULATED investigation, and say what to verify first. It is simulated data:\n"+INV.report.slice(0,6000),{},"team").then(function(){var rs=$("res-team"),bx=$("orch-aic");if(rs&&!rs.hidden){bx.hidden=false;bx.innerHTML=rs.innerHTML;rs.hidden=true}});return}});
document.addEventListener("submit",function(e){var t=e.target;if(t&&t.id==="orch-form"){e.preventDefault();orchStart()}});
document.addEventListener("input",function(e){if(e.target&&e.target.id==="orch-in")paintOrch()});
setTimeout(function(){try{paintOrch()}catch(x){}},0);
