
/* handlers for the role panels */
async function respStatus(){var id=S.rsel,st=$("rst").value,note=$("rnote").value,msg=$("rst-msg");msg.className="st";
 if(S.mode==="connected"){try{await api("PATCH","/incidents/"+encodeURIComponent(id),{status:st,note:note,force:!!note.trim()&&st==="closed"});S.data=await api("GET","/overview?scope=all");paint()}catch(e){msg.textContent=e.message;msg.className="st er"}}
 else{L.istat[id]=st;lsSave();await paintResponder();paintKpis();$("rst-msg").textContent="Status changed in this browser only (sample data)."}}
async function respVerify(){var id=S.rsel,msg=$("rst-msg");try{await api("POST","/incidents/"+encodeURIComponent(id)+"/verify");S.data=await api("GET","/overview?scope=all");paint()}catch(e){msg.textContent=e.message;msg.className="st er"}}
function respNote(){var id=S.rsel,v=$("rn-in").value.trim();if(!v)return;(L.notes[id]=L.notes[id]||[]).push({t:Date.now(),text:v});lsSave();openResp(id)}
function respReport(){var r=S.rdet,id=S.rsel,st=S.mode==="connected"?r.incident.status:(L.istat[id]||r.incident.status),md=E.incidentReportMd({incident:Object.assign({},r.incident,{status:st}),timeline:r.timeline,actions:(r.actions||[]).concat(L.drafts.filter(function(d){return d.incidentId===id})),notes:(L.notes[id]||[]).map(function(n){return new Date(n.t).toISOString()+" "+n.text})});showExport("responder","Incident report","incident-report-"+id.slice(0,12)+".md",md,"text/markdown")}
async function sendAction(){var msg=$("af-msg"),b={incidentId:S.rsel,type:$("af-type").value,target:$("af-target").value.trim(),description:$("af-desc").value.trim(),rationale:"Requested from the Incident Responder workspace"};msg.className="st";
 if(S.mode==="connected"){try{await api("POST","/actions",b);S.actions=await api("GET","/actions");msg.textContent="Sent. An admin must approve it, and Spark will not carry it out itself.";paintActs();paintKpis();$("af-target").value="";$("af-desc").value=""}catch(e){msg.textContent=e.message;msg.className="st er"}}
 else{L.drafts.unshift(Object.assign({id:"draft_"+Date.now(),draft:true,status:"proposed",requiresApproval:true,proposedBy:"you (draft)"},b));lsSave();msg.textContent="Drafted in this browser only. Connect a SOC backend to send requests for approval.";paintActs();paintKpis()}}
function runPreset(id){var h=E.HUNTS.filter(function(x){return x.id===id})[0],r=h.run(evs());S.hunt={rows:r.matches.slice(0,200),total:r.matches.length,searched:evs().length,label:"Hunt \u201c"+h.name+"\u201d"};hSum(r.note);try{$("hunt-sum").scrollIntoView({behavior:"smooth",block:"nearest"})}catch(e){}}
function hardMd(){return"# Hardening checklist\n\n"+(S.hard||[]).map(function(x){return"## "+x.title+" ("+x.ruleId+") on "+x.hosts.join(", ")+"\n"+x.advice.map(function(a){return"- [ ] "+a}).join("\n")}).join("\n\n")}
document.addEventListener("click",function(e){var t=e.target;if(!t.closest||!t.closest("#socws"))return;var c;
 if(c=t.closest("[data-tab]")){setRole(c.dataset.tab);return}
 if(c=t.closest("[data-dl]")){var o=S.out[c.dataset.dl];download(o.file,o.text,o.mime);return}
 if(c=t.closest("[data-dlh]")){webPage(c.dataset.dlh);return}
 if(c=t.closest("[data-cp]")){copyText(c.dataset.cp);return}
 if(c=t.closest("[data-xx]")){$("out-"+c.dataset.xx).hidden=true;return}
 if(c=t.closest("[data-q][data-role-of]")){roleAI(c.dataset.roleOf,c.dataset.q);return}
 if(c=t.closest("[data-ask]")){roleAsk(c.dataset.ask);return}
 if(c=t.closest("[data-hunt]")){runPreset(c.dataset.hunt);return}
 if(c=t.closest("[data-hev]")){hDetail(Number(c.dataset.hev));return}
 if(c=t.closest("[data-pivot]")){var p=c.dataset.pivot.split("|"),m={user:"huser",ip:"hip",host:"hhost"};$(m[p[0]]).value=p.slice(1).join("|");runHunt();return}
 if(c=t.closest("[data-nbdel]")){L.hunt.splice(Number(c.dataset.nbdel),1);lsSave();paintHunter();paintKpis();return}
 if(c=t.closest("[data-rinc]")){openResp(c.dataset.rinc);return}
 if(c=t.closest("[data-prep]")){var a=actFor(c.dataset.prep,S.rdet.incident,S.rdet.alerts||[]);if(a){$("af-type").value=a.type;$("af-target").value=a.target;$("af-desc").value=a.description;$("af-target").focus();try{$("act-form").scrollIntoView({behavior:"smooth",block:"nearest"})}catch(x){}}return}
 if(c=t.closest("[data-aact]")){decide(c.dataset.id,c.dataset.aact);return}
 if(c=t.closest("[data-draftdel]")){L.drafts=L.drafts.filter(function(d){return d.id!==c.dataset.draftdel});lsSave();paintActs();paintKpis();if(S.role==="ciso")paintCiso();return}
 var b=t.closest("button"),id=b&&b.id;if(!id)return;
 if(id==="eng-csv"){showExport("engineer","Remediation plan (CSV)","remediation-plan.csv",E.planToCsv(S.plan),"text/csv")}
 else if(id==="eng-hmd"){showExport("engineer","Hardening checklist","hardening-checklist.md",hardMd(),"text/markdown")}
 else if(id==="hunt-clr"){["hq","heid","hhost","huser","hip"].forEach(function(i){$(i).value=""});$("hwin").value="0";runHunt()}
 else if(id==="hunt-csv"){if(!S.hunt||!S.hunt.rows.length){$("hunt-sum").textContent="Nothing to export. Run a hunt that returns events first.";return}showExport("hunter","Hunt results (CSV)","hunt-results.csv",evCsv(S.hunt.rows),"text/csv")}
 else if(id==="nb-add"){var v=$("nb-in").value.trim();if(!v)return;L.hunt.unshift({t:Date.now(),text:v});lsSave();$("nb-in").value="";paintHunter();paintKpis()}
 else if(id==="lg-go"){runLogs()}
 else if(id==="lg-ex"){$("lg-in").value=exampleLogs();runLogs()}
 else if(id==="lg-clr"){$("lg-in").value="";$("lg-out").innerHTML="";LGSTATE=null}
 else if(id==="lg-exp"){showExport("siem","Normalized events (JSON)","normalized-events.json",JSON.stringify(LGSTATE.a.accepted,null,1),"application/json")}
 else if(id==="lg-send"){sendLogs()}
 else if(id==="si-ps"){if(COLLECTOR)showExport("siem","Windows collector script (PowerShell)","Send-SecurityEvents.ps1",COLLECTOR,"text/plain");else{var g=$("socws-guide");g.open=true}}
 else if(id==="ciso-gen"){genSummary()}
 else if(id==="rgo"){respStatus()}else if(id==="rver"){respVerify()}else if(id==="rn-add"){respNote()}else if(id==="rrep"){respReport()}});
document.addEventListener("change",function(e){var t=e.target;if(!t.closest||!t.closest("#socws"))return;
 if(t.matches("[data-vs]"))setVuln(t.dataset.vs,t.value);
 else if(t.matches("[data-pbs]")){pbState(S.rsel)[t.dataset.pbs]=t.checked;lsSave()}
 else if(t.id==="lg-file"&&t.files&&t.files[0]){var f=t.files[0];if(f.size>6e6){$("lg-out").innerHTML='<div class="banner bad" style="margin-top:10px">That file is larger than 6 MB.</div>';return}f.text().then(function(x){$("lg-in").value=x;runLogs()});t.value=""}});
document.addEventListener("submit",function(e){var t=e.target;if(!t.closest||!t.closest("#socws"))return;if(t.id==="hunt-form"){e.preventDefault();runHunt()}else if(t.id==="act-form"){e.preventDefault();sendAction()}});
$("socws-roles").innerHTML=ORDER.map(function(k){return'<button type="button" role="tab" id="tab-'+k+'" data-tab="'+k+'" data-role="'+k+'" aria-selected="'+(k==="analyst")+'" aria-controls="rp-'+k+'" tabindex="'+(k==="analyst"?0:-1)+'">'+svg(k,18)+ROLES[k].n+"</button>"}).join("");
$("socws-ic").innerHTML=svg("analyst");
$("socws-roles").addEventListener("keydown",function(e){var i=ORDER.indexOf(S.role),n;if(e.key==="ArrowRight")n=(i+1)%ORDER.length;else if(e.key==="ArrowLeft")n=(i+ORDER.length-1)%ORDER.length;else if(e.key==="Home")n=0;else if(e.key==="End")n=ORDER.length-1;else return;e.preventDefault();setRole(ORDER[n],true)});
document.querySelectorAll("#soct .soc-hot").forEach(function(b){["mouseenter","focus"].forEach(function(v){b.addEventListener(v,function(){hov(b,true)})});["mouseleave","blur"].forEach(function(v){b.addEventListener(v,function(){hov(b,false)})})});
var hm=/^#soc-(\w+)$/.exec(location.hash);if(hm&&ROLES[hm[1]])setTimeout(function(){open(document.querySelector('.soc-hot[data-role="'+hm[1]+'"]')||$("socHot"),hm[1])},300);

mountConsole("analyst");syncDash();
