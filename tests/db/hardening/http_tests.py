import hmac,hashlib,base64,json,time,urllib.request,urllib.error,sys
S=open('/tmp/pgrst/secret.txt').read().strip().encode(); B="http://127.0.0.1:3399"
b=lambda x:base64.urlsafe_b64encode(x).rstrip(b'=')
def jwt(role,sub=None):
    h=b(json.dumps({"alg":"HS256","typ":"JWT"}).encode()); p={"role":role,"exp":int(time.time())+600,"aud":"authenticated"}
    if sub:p["sub"]=sub
    p=b(json.dumps(p).encode()); return (h+b'.'+p+b'.'+b(hmac.new(S,h+b'.'+p,hashlib.sha256).digest())).decode()
UA="aaaaaaaa-0000-4000-8000-00000000000a"; UB="bbbbbbbb-0000-4000-8000-00000000000b"
PA="11111111-1111-4111-8111-111111111111"; PB="22222222-2222-4222-8222-222222222222"
tok={"anon":jwt("anon"),"A":jwt("authenticated",UA),"B":jwt("authenticated",UB),"svc":jwt("service_role")}
def call(who,method,path,body=None,extra=None):
    h={"Authorization":"Bearer "+tok[who],"Content-Type":"application/json","Prefer":"return=representation"}
    if extra:h.update(extra)
    r=urllib.request.Request(B+path,data=json.dumps(body).encode() if body is not None else None,method=method,headers=h)
    try:
        with urllib.request.urlopen(r) as x: return x.status,x.read().decode()
    except urllib.error.HTTPError as e: return e.code,e.read().decode()
res=[]
def t(name,who,method,path,body,want_status,pred=None,extra=None):
    st,tx=call(who,method,path,body,extra); ok=(st==want_status) and (pred(tx) if pred else True)
    res.append(ok); print(("PASS" if ok else "FAIL"),name,"| HTTP",st,"want",want_status,"|",tx[:90].replace("\n"," "))
n=lambda tx:len(json.loads(tx)) if tx.startswith('[') else -1
# increment_usage
t("anon calls increment_usage","anon","POST","/rpc/increment_usage",{"uid":UA},401)
t("A calls increment_usage (self)","A","POST","/rpc/increment_usage",{"uid":UA},403)
t("A calls increment_usage (user B)","A","POST","/rpc/increment_usage",{"uid":UB},403)
t("service_role calls increment_usage","svc","POST","/rpc/increment_usage",{"uid":UA},204)
# backend-only tables
for tb in ("app_records","soc_kev","soc_meta"):
    t(f"anon reads {tb}","anon","GET",f"/{tb}",None,401)
    t(f"A reads {tb}","A","GET",f"/{tb}",None,403)
t("service_role reads app_records","svc","GET","/app_records",None,200,lambda x:n(x)==1)
t("anon writes app_records","anon","POST","/app_records",{"app_id":"x","collection":"z","data":{}},401)
t("A writes app_records","A","POST","/app_records",{"app_id":"x","collection":"z","data":{}},403)
t("service_role writes app_records","svc","POST","/app_records",{"app_id":"x","collection":"z","data":{}},201)
# builder tables
for tb in ("projects","versions","usage"):
    t(f"anon reads {tb}","anon","GET",f"/{tb}",None,401)
t("A sees only own projects","A","GET","/projects?select=id,name",None,200,lambda x:n(x)==1 and PA in x and PB not in x)
t("B sees only own projects","B","GET","/projects?select=id,name",None,200,lambda x:n(x)==1 and PB in x and PA not in x)
t("A reads B's project by id","A","GET",f"/projects?id=eq.{PB}",None,200,lambda x:n(x)==0)
t("A updates B's project","A","PATCH",f"/projects?id=eq.{PB}",{"name":"evil"},200,lambda x:n(x)==0)
t("A updates own project","A","PATCH",f"/projects?id=eq.{PA}",{"name":"A2"},200,lambda x:n(x)==1)
t("A creates project as B","A","POST","/projects",{"user_id":UB,"name":"evil"},403)
t("A creates own project","A","POST","/projects",{"user_id":UA,"name":"A3"},201)
t("A reads own versions only","A","GET","/versions?select=project_id",None,200,lambda x:PA in x and PB not in x)
t("A adds version to B's project","A","POST","/versions",{"project_id":PB,"prompt":"p","html":"x"},403)
t("A adds version to own project","A","POST","/versions",{"project_id":PA,"prompt":"p","html":"x"},201)
t("A reads own usage only","A","GET","/usage?select=user_id",None,200,lambda x:UA in x and UB not in x)
t("A writes usage directly","A","POST","/usage",{"user_id":UA,"day":"2030-01-01"},403)
# published sites
t("anon serves site (app's /serve query)","anon","GET","/sites?select=html&slug=eq.site-a",None,200,lambda x:'<p>A</p>' in x)
t("anon serves by custom domain","anon","GET","/sites?select=html&custom_domain=eq.a.example.test",None,200,lambda x:'<p>A</p>' in x)
t("anon reads project_id of sites","anon","GET","/sites?select=project_id",None,401)
t("anon select=* on sites","anon","GET","/sites?select=*",None,401)
t("anon edits a site","anon","PATCH","/sites?slug=eq.site-a",{"html":"defaced"},401)
t("anon deletes a site","anon","DELETE","/sites?slug=eq.site-a",None,401)
t("anon inserts a site","anon","POST","/sites",{"slug":"evil-site","project_id":PA,"html":"x"},401)
t("A sees only own sites","A","GET","/sites?select=slug",None,200,lambda x:'site-a' in x and 'site-b' not in x)
t("A publishes own project (upsert like /api/publish)","A","POST","/sites?on_conflict=project_id",{"project_id":PA,"slug":"site-a2","html":"<p>A2</p>"},200,None,{"Prefer":"resolution=merge-duplicates,return=representation"})
t("A takes a name used by B","A","POST","/sites?on_conflict=project_id",{"project_id":PA,"slug":"site-b","html":"x"},409,None,{"Prefer":"resolution=merge-duplicates,return=representation"})
t("A defaces B's site","A","PATCH","/sites?slug=eq.site-b",{"html":"defaced"},200,lambda x:n(x)==0)
t("A deletes B's site","A","DELETE","/sites?slug=eq.site-b",None,200,lambda x:n(x)==0)
t("service_role reads all sites","svc","GET","/sites?select=slug",None,200,lambda x:n(x)>=2)
# tenant tables still locked to anon
for tb in ("organizations","org_members","net_devices","agent_enrollment_tokens"):
    t(f"anon reads {tb}","anon","GET",f"/{tb}?limit=1",None,401)
t("anon creates organization","anon","POST","/rpc/create_organization",{"p_name":"x","p_slug":"xx-org"},401)
print(f"\nHTTP_TESTS total={len(res)} pass={sum(res)} fail={len(res)-sum(res)}")
