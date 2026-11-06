/*
 ============================================================
  SmartAttend  -  QR attendance system  (ONE FILE = whole website)
 ============================================================
  You do NOT need to edit anything in this file.
  Everything (design + server + database code) is inside it.

  Part 1: Server and database      (the code right below)
  Part 2: The website design/page  (PAGE_CSS and PAGE_HTML, at the bottom)

  Settings are given from the hosting website (Render), not here:
    DATABASE_URL  -> link of your free Neon database (keeps data forever)
    TEACHER_CODE  -> optional secret code that teachers need to register
 ============================================================
*/
const express=require('express'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=process.env.PORT||3000,STEP=20000,TCODE=process.env.TEACHER_CODE||'';
const DBF=path.join(process.env.DATA_DIR||__dirname,'data.json'),DBURL=process.env.DATABASE_URL;
let db,pool=null,timer;
async function load(){
  let d=null;
  if(DBURL){const {Pool}=require('pg');pool=new Pool({connectionString:DBURL,ssl:process.env.PGSSL==='off'?false:{rejectUnauthorized:false}});
    await pool.query('create table if not exists kv(k text primary key,v jsonb not null)');
    const r=await pool.query("select v from kv where k='db'");d=r.rows[0]&&r.rows[0].v}
  else try{d=JSON.parse(fs.readFileSync(DBF))}catch(e){}
  db=Object.assign({sessions:[],users:[],logins:{},roster:[],settings:{college:'',dept:'',subject:'',radius:200}},d||{});
}
async function flush(){try{await pool.query("insert into kv(k,v) values('db',$1) on conflict (k) do update set v=excluded.v",[JSON.stringify(db)])}catch(e){console.error('save failed:',e.message)}}
function save(){if(!pool)return fs.writeFileSync(DBF,JSON.stringify(db));clearTimeout(timer);timer=setTimeout(flush,200)}
const app=express();app.set('trust proxy',1);app.use(express.json({limit:'1mb'}));app.get('/',(q,s)=>s.type('html').send(PAGE_HTML));
app.get('/style.css',(q,s)=>s.type('css').send(PAGE_CSS));
const fails={},rnd=()=>String(crypto.randomInt(100000,1000000));
const last=()=>db.sessions[db.sessions.length-1]||null,live=()=>{const s=last();return s&&s.active?s:null};
const rotate=s=>{if(Date.now()-s.tokenAt>=STEP){s.prev=s.token;s.token=rnd();s.tokenAt=Date.now();save()}};
const tok=r=>((r.headers.cookie||'').match(/sid=([a-f0-9]+)/)||[])[1];
const me=r=>{const id=db.logins[tok(r)];return (id&&db.users.find(u=>u.id===id))||null};
const auth=(q,s,n)=>{const u=me(q);if(u&&u.role==='teacher')return n();s.status(401).json({error:'Teacher login required'})};
const hash=(p,s)=>crypto.scryptSync(String(p),s,32).toString('hex');
const eq=(a,b)=>{a=Buffer.from(String(a));b=Buffer.from(String(b));return a.length===b.length&&crypto.timingSafeEqual(a,b)};
const hav=(a,b,c,d)=>{const R=6371000,t=x=>x*Math.PI/180,p=t(c-a),q=t(d-b),h=Math.sin(p/2)**2+Math.cos(t(a))*Math.cos(t(c))*Math.sin(q/2)**2;return 2*R*Math.asin(Math.sqrt(h))};
const begin=(q,s,u)=>{const t=crypto.randomBytes(24).toString('hex');db.logins[t]=u.id;save();s.setHeader('Set-Cookie',`sid=${t}; HttpOnly; Path=/; SameSite=Strict; Max-Age=2592000${q.secure?'; Secure':''}`)};
const hasT=()=>db.users.some(u=>u.role==='teacher');
const clean=(s,n)=>String(s||'').trim().slice(0,n);

app.get('/api/public',(q,s)=>{const a=live();s.json({settings:db.settings,active:!!a,geo:!!(a&&a.geo),setup:!hasT(),needCode:!!TCODE})});
app.post('/api/signup',(q,s)=>{
  const {role,password,code}=q.body||{};const id=clean(q.body.id,30).toUpperCase();
  if(!/^[A-Z0-9_.-]{3,30}$/.test(id))return s.status(400).json({error:'ID must be 3–30 letters or numbers (no spaces).'});
  if(String(password||'').length<6)return s.status(400).json({error:'Password must be at least 6 characters.'});
  if(db.users.some(u=>u.id===id))return s.status(409).json({error:'An account with this ID already exists. Please sign in.'});
  let u;
  if(role==='student'){
    const st=db.roster.find(x=>x[0].toUpperCase()===id);
    if(!st)return s.status(400).json({error:db.roster.length?'This roll number is not in the class list. Ask your teacher to add you.':'Your teacher has not added the class list yet.'});
    u={id,role:'student',roll:st[0],name:st[1]};
  }else if(role==='teacher'){
    if(TCODE?!eq(code||'',TCODE):hasT())return s.status(403).json({error:TCODE?'Invalid teacher registration code.':'A teacher account already exists.'});
    const nm=clean(q.body.name,60);if(!nm)return s.status(400).json({error:'Please enter your name.'});
    u={id,role:'teacher',name:nm};
  }else return s.status(400).json({error:'Choose Student or Teacher.'});
  u.salt=crypto.randomBytes(16).toString('hex');u.hash=hash(password,u.salt);db.users.push(u);begin(q,s,u);s.json({ok:true,role:u.role});
});
app.post('/api/login',(q,s)=>{
  const f=fails[q.ip]||{n:0,t:Date.now()};if(Date.now()-f.t>600000){f.n=0;f.t=Date.now()}
  if(f.n>=8)return s.status(429).json({error:'Too many attempts. Try again in a few minutes.'});
  const u=db.users.find(x=>x.id===clean(q.body.id,30).toUpperCase());
  if(!u||!eq(hash(q.body.password||'',u.salt),u.hash)){f.n++;fails[q.ip]=f;return s.status(401).json({error:'Incorrect ID or password.'})}
  delete fails[q.ip];begin(q,s,u);s.json({ok:true,role:u.role});
});
app.post('/api/logout',(q,s)=>{delete db.logins[tok(q)];save();s.setHeader('Set-Cookie','sid=; Path=/; Max-Age=0');s.json({ok:true})});
app.get('/api/me',(q,s)=>{const u=me(q);s.json({user:u&&{role:u.role,name:u.name,roll:u.roll||null}})});

app.post('/api/teacher/settings',auth,(q,s)=>{const b=q.body,r=Math.round(+b.radius);
  db.settings={college:clean(b.college,80),dept:clean(b.dept,60),subject:clean(b.subject,60),radius:r>=20&&r<=2000?r:200};save();s.json({ok:true,settings:db.settings})});
app.post('/api/teacher/students',auth,(q,s)=>{
  let add=0,skip=0;
  String(q.body.text||'').split(/\r?\n/).forEach(line=>{
    const m=line.trim().match(/^([^,;\t]+)[,;\t]\s*(.+)$/);if(!m)return;
    const roll=m[1].trim().toUpperCase(),name=m[2].trim().slice(0,60);
    if(!/^[A-Z0-9_.-]{3,30}$/.test(roll)||db.roster.some(x=>x[0].toUpperCase()===roll)){skip++;return}
    db.roster.push([roll,name]);add++;
  });save();s.json({added:add,skipped:skip});
});
app.delete('/api/teacher/students/:roll',auth,(q,s)=>{const r=q.params.roll.toUpperCase();
  db.roster=db.roster.filter(x=>x[0].toUpperCase()!==r);db.users=db.users.filter(u=>!(u.role==='student'&&u.id===r));save();s.json({ok:true})});
app.post('/api/class/start',auth,(q,s)=>{
  if(!db.settings.subject||!db.roster.length)return s.status(400).json({error:'Add your subject (Settings) and at least one student first.'});
  const o=live();if(o){o.active=false;o.ended=Date.now()}
  const {geo,lat,lng}=q.body;if(geo&&!(isFinite(lat)&&isFinite(lng)&&lat!==null))return s.status(400).json({error:'Location is required for the location check.'});
  db.sessions.push({id:'s'+Date.now(),subject:db.settings.subject,radius:db.settings.radius,active:true,started:Date.now(),geo:!!geo,lat:geo?+lat:null,lng:geo?+lng:null,token:rnd(),prev:'',tokenAt:Date.now(),marks:[]});
  save();s.json({ok:true});
});
app.post('/api/class/end',auth,(q,s)=>{const a=live();if(a){a.active=false;a.ended=Date.now();save()}s.json({ok:true})});
app.get('/api/teacher/state',auth,(q,s)=>{
  const a=last();if(a&&a.active)rotate(a);
  const reg=new Set(db.users.filter(u=>u.role==='student').map(u=>u.id));
  s.json({now:Date.now(),step:STEP,settings:db.settings,roster:db.roster.map(([r,n])=>[r,n,reg.has(r.toUpperCase())]),
    session:a&&{id:a.id,active:a.active,started:a.started,geo:a.geo,token:a.token,tokenAt:a.tokenAt,marks:a.marks.map(({device,...m})=>m)},
    history:db.sessions.slice(-30).reverse().map(x=>({id:x.id,subject:x.subject,started:x.started,present:x.marks.length}))});
});
app.get('/api/class/export.csv',auth,(q,s)=>{
  const x=db.sessions.find(z=>z.id===q.query.sid)||last(),by={};(x?x.marks:[]).forEach(m=>by[m.roll]=m);
  const rows=[['Roll','Name','Status','Time','Distance (m)']].concat(db.roster.map(([r,n])=>[r,n,by[r]?'Present':'Absent',by[r]?new Date(by[r].at).toLocaleString():'',by[r]&&by[r].dist!=null?by[r].dist:'']));
  s.type('text/csv').attachment('attendance.csv').send(rows.map(r=>r.map(v=>`"${String(v).replace(/"/g,'""')}"`).join(',')).join('\n'));
});
app.post('/api/mark',(q,s)=>{
  const u=me(q);if(!u||u.role!=='student')return s.status(401).json({error:'Please sign in as a student.'});
  const {code,lat,lng,device}=q.body||{},roll=u.roll,a=live();
  if(!a)return s.status(400).json({error:'No class is currently active.'});
  rotate(a);let c=String(code||'').trim();
  if(c.startsWith('ATT:')){const p=c.split(':');if(p[1]!==a.id)return s.status(400).json({error:'This QR belongs to an earlier class.'});c=p[2]}
  if(c!==a.token&&c!==a.prev)return s.status(400).json({error:'This code has expired or is incorrect. Scan the current code.'});
  if(a.marks.some(m=>m.roll===roll))return s.json({ok:true,already:true,name:u.name});
  if(!device||a.marks.some(m=>m.device===device))return s.status(403).json({error:'Attendance was already marked from this device for another student.'});
  let d=null;
  if(a.geo){
    if(!(isFinite(lat)&&isFinite(lng)&&lat!==null))return s.status(403).json({error:'Location access is required to confirm you are in the classroom.'});
    d=Math.round(hav(a.lat,a.lng,+lat,+lng));
    if(d>a.radius)return s.status(403).json({error:`You are about ${d} m from the classroom. Attendance not recorded.`});
  }
  a.marks.push({roll,name:u.name,at:Date.now(),dist:d,device});save();s.json({ok:true,name:u.name});
});
load().then(()=>app.listen(PORT,()=>console.log('SmartAttend running on port '+PORT))).catch(e=>{console.error('Startup failed:',e.message);process.exit(1)});

/* ================= PART 2: WEBSITE PAGE (HTML + CSS) ================= */
const PAGE_CSS = String.raw`:root{--bg:#f3f5fa;--card:#fff;--tx:#14192b;--mu:#64708a;--ac:#2446d6;--ok:#0e9f6e;--er:#d92d3a;--bd:#e2e6f0;--sh:0 1px 2px rgba(20,25,43,.05),0 8px 24px rgba(20,25,43,.06)}
@media (prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#0e1118;--card:#171b25;--tx:#eef1f8;--mu:#93a0ba;--ac:#6f8bff;--ok:#34d399;--er:#ff6b77;--bd:#262c3b;--sh:none}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header{background:linear-gradient(120deg,#13226b,#2446d6 60%,#4f6cf0);color:#fff}
.hi{max-width:1000px;margin:0 auto;padding:18px 20px 26px}.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:19px}.logo{width:34px;height:34px;border-radius:9px;background:rgba(255,255,255,.18);display:grid;place-items:center}
.live{display:flex;align-items:center;gap:8px;background:rgba(255,255,255,.14);padding:6px 12px;border-radius:99px;font-size:13px}
.dot{width:8px;height:8px;border-radius:50%;background:#9aa7d6}.dot.on{background:#4ade80;box-shadow:0 0 0 4px rgba(74,222,128,.25)}
h1{font-size:26px;margin:22px 0 4px}.hs{opacity:.85;font-size:14px}.chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}.chip{background:rgba(255,255,255,.14);padding:4px 12px;border-radius:99px;font-size:12.5px}
main{max-width:1000px;margin:-14px auto 40px;padding:0 20px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:16px;padding:20px;margin-top:16px;box-shadow:var(--sh)}.card h2{font-size:16px;margin:0 0 4px}.sub{color:var(--mu);font-size:13px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:16px}@media(max-width:700px){.stats{grid-template-columns:repeat(2,1fr)}}
.st{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:14px 16px;box-shadow:var(--sh)}.st b{display:block;font-size:26px;line-height:1.2}.st span{font-size:12.5px;color:var(--mu)}
button,select,input{font:inherit;color:var(--tx)}.btn{border:1px solid var(--bd);background:var(--card);padding:10px 16px;border-radius:10px;cursor:pointer;font-weight:600}
.btn.p{background:var(--ac);border-color:var(--ac);color:#fff}.btn.d{color:var(--er);border-color:var(--er)}.btn:disabled{opacity:.5}
select,input[type=text],input[type=password]{width:100%;padding:11px 12px;border:1px solid var(--bd);border-radius:10px;background:var(--bg)}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:14px}
.g{display:grid;grid-template-columns:auto 1fr;gap:28px;align-items:center}@media(max-width:640px){.g{grid-template-columns:1fr;justify-items:center;text-align:center}}
#qr{background:#fff;padding:12px;border-radius:14px;width:208px;height:208px;border:1px solid var(--bd)}
.code{font-size:38px;font-weight:800;letter-spacing:8px;font-variant-numeric:tabular-nums}
.bar{height:6px;background:var(--bd);border-radius:6px;overflow:hidden;margin-top:8px;max-width:320px}.bar i{display:block;height:100%;background:var(--ac);width:100%;transition:width .25s linear}
table{width:100%;border-collapse:collapse;margin-top:10px}th{font-size:12px;text-transform:uppercase;color:var(--mu)}td,th{padding:10px 8px;border-bottom:1px solid var(--bd);text-align:left;font-size:14px}.tw{overflow-x:auto}
.pill{padding:3px 11px;border-radius:99px;font-size:12px;font-weight:700}.pr{background:color-mix(in srgb,var(--ok) 16%,transparent);color:var(--ok)}.ab{background:color-mix(in srgb,var(--er) 13%,transparent);color:var(--er)}
.msg{margin-top:14px;padding:11px 14px;border-radius:10px;font-size:14px}.msg.ok{background:color-mix(in srgb,var(--ok) 14%,transparent);color:var(--ok)}.msg.er{background:color-mix(in srgb,var(--er) 12%,transparent);color:var(--er)}.msg.in{background:var(--bg);color:var(--mu)}
video{width:100%;max-width:360px;border-radius:12px;background:#000;margin-top:12px}.hide{display:none}label.c{display:flex;gap:7px;align-items:center;font-size:14px}
footer{text-align:center;color:var(--mu);font-size:12.5px;padding:0 20px 28px}
.seg{display:flex;background:var(--bg);border:1px solid var(--bd);border-radius:12px;padding:4px;gap:4px}.seg button{flex:1;border:0;background:none;padding:9px 14px;border-radius:9px;font-weight:600;color:var(--mu);cursor:pointer;white-space:nowrap}.seg button.on{background:var(--ac);color:#fff}
label.f{display:block;margin-top:14px;font-size:13px;color:var(--mu)}label.f input,label.f textarea{margin-top:5px}
textarea{width:100%;padding:11px 12px;border:1px solid var(--bd);border-radius:10px;background:var(--bg);font:inherit;color:var(--tx);min-height:130px}
.lk{background:none;border:0;color:var(--ac);font-weight:600;cursor:pointer;padding:0;font:inherit}.x{background:none;border:0;color:var(--er);cursor:pointer;font-size:13px}
input[type=number]{width:100%;padding:11px 12px;border:1px solid var(--bd);border-radius:10px;background:var(--bg)}
.w{max-width:440px;margin:16px auto 0}.two{display:grid;grid-template-columns:1fr 1fr;gap:14px}@media(max-width:640px){.two{grid-template-columns:1fr}}
.tabsx{margin-top:0}.tabsx .seg{overflow-x:auto}
#bcw{background:#fff;padding:16px 20px;border-radius:14px;border:1px solid var(--bd);max-width:100%;overflow:hidden}#bc{display:block;max-width:100%;height:auto}
`;

const PAGE_HTML = String.raw`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SmartAttend — QR Attendance</title><link rel="stylesheet" href="style.css"></head><body>
<header><div class="hi"><div class="top"><div class="brand"><div class="logo">📋</div><span id="col">SmartAttend</span></div><div class="live"><span class="dot" id="dot"></span><span id="lt">Checking…</span></div></div>
<h1 id="h1">Secure QR Attendance</h1><div class="hs" id="hs">Sign in to continue.</div><div class="chips" id="chips"></div></div></header>
<main>
<!-- AUTH -->
<section id="vA" class="hide"><div class="card w">
<div class="seg"><button id="rS" class="on">Student</button><button id="rT">Teacher</button></div>
<h2 id="ttl" style="margin-top:18px">Sign in</h2>
<label class="f" id="nmW" hidden>Full name<input type="text" id="nm"></label>
<label class="f"><span id="idL">Roll number</span><input type="text" id="id" autocapitalize="characters" autocomplete="username"></label>
<label class="f">Password<input type="password" id="pw"></label>
<label class="f" id="cdW" hidden>Teacher registration code<input type="password" id="cd"></label>
<div class="sub" id="note" style="margin-top:10px"></div>
<div class="row"><button class="btn p" id="go" style="width:100%">Sign in</button></div><div id="am" class="msg er hide"></div>
<div class="sub" style="margin-top:16px;text-align:center"><span id="alt">New here?</span> <button class="lk" id="sw">Create an account</button></div></div></section>
<!-- STUDENT -->
<section id="vS" class="hide"><div class="card w" style="max-width:520px"><h2>Mark your attendance</h2><div class="sub" id="who"></div>
<div class="row"><button class="btn p" id="scan">Scan barcode</button><button class="btn hide" id="stop">Stop camera</button><button class="btn" id="outS" style="margin-left:auto">Sign out</button></div>
<video id="vid" class="hide" playsinline muted></video><canvas id="cv" class="hide"></canvas>
<div class="sub" style="margin-top:18px">Camera not working? Enter the 6-digit code from the teacher’s screen.</div>
<div class="row" style="margin-top:8px"><input type="text" id="man" inputmode="numeric" maxlength="6" placeholder="000000" style="max-width:170px"><button class="btn" id="sub">Submit</button></div>
<div id="smsg" class="msg in hide"></div></div></section>
<!-- TEACHER -->
<section id="vT" class="hide">
<div class="row" style="margin-top:0;justify-content:space-between"><div class="seg" style="max-width:100%"><button id="tL" class="on">Live class</button><button id="tR">Students</button><button id="tH">History</button><button id="tG">Settings</button></div><button class="btn" id="outT">Sign out</button></div>
<div id="pL">
<div class="stats"><div class="st"><b id="np">0</b><span>Present</span></div><div class="st"><b id="na">0</b><span>Absent</span></div><div class="st"><b id="nt">0</b><span>Total students</span></div><div class="st"><b id="pc">0%</b><span>Attendance rate</span></div></div>
<div class="card"><h2>Class session</h2><div class="sub">The barcode changes every 20 seconds, so a forwarded photo becomes useless.</div>
<div class="row"><button class="btn p" id="start">Start class</button><button class="btn d hide" id="end">End class</button><label class="c"><input type="checkbox" id="geo" checked> Students must be near this laptop</label></div>
<div id="emsg" class="msg er hide"></div>
<div class="hide" id="qcard" style="margin-top:20px"><div class="seg" style="max-width:260px;margin-bottom:14px"><button id="mB" class="on">Barcode</button><button id="mQ">QR code</button></div><div class="g"><div><div id="bcw"><svg id="bc"></svg></div><div id="qr" class="hide"></div></div><div><div class="sub">Scan this barcode or enter the number</div><div class="code" id="code">······</div><div class="bar"><i id="fill"></i></div><div class="sub" id="cnt" style="margin-top:6px"></div></div></div></div></div>
<div class="card"><div class="row" style="margin-top:0;justify-content:space-between"><div><h2>Attendance sheet</h2><div class="sub" id="sinfo">No session yet</div></div><a class="btn" id="csv" href="/api/class/export.csv" style="text-decoration:none;color:inherit">Export CSV</a></div>
<div class="tw"><table><thead><tr><th>Roll no.</th><th>Name</th><th>Status</th><th>Time</th><th>Distance</th></tr></thead><tbody id="tb"></tbody></table></div></div></div>
<div id="pR" class="hide"><div class="card"><h2>Add students</h2><div class="sub">One per line as <b>Roll number, Full name</b>. You can paste a whole class list.</div>
<label class="f" style="margin-top:8px"><textarea id="lst" placeholder="CS101, Student Name&#10;CS102, Student Name"></textarea></label>
<div class="row"><button class="btn p" id="addS">Add students</button></div><div id="rm" class="msg in hide"></div></div>
<div class="card"><h2>Class list</h2><div class="sub" id="rinfo"></div><div class="tw"><table><thead><tr><th>Roll no.</th><th>Name</th><th>Account</th><th></th></tr></thead><tbody id="rb"></tbody></table></div></div></div>
<div id="pH" class="hide"><div class="card"><h2>Past classes</h2><div class="tw"><table><thead><tr><th>Date</th><th>Subject</th><th>Present</th><th></th></tr></thead><tbody id="hb"></tbody></table></div></div></div>
<div id="pG" class="hide"><div class="card" style="max-width:560px"><h2>Class details</h2><div class="sub">These appear on the website header for everyone.</div>
<label class="f">College / school name<input type="text" id="sCol"></label><div class="two"><label class="f">Department<input type="text" id="sDep"></label><label class="f">Subject<input type="text" id="sSub"></label></div>
<label class="f">Allowed distance from teacher (metres)<input type="number" id="sRad" min="20" max="2000"></label>
<div class="row"><button class="btn p" id="saveG">Save details</button></div><div id="gm" class="msg ok hide"></div></div></div>
</section>
</main><footer>SmartAttend · Rotating QR · Location check · One device per student</footer>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jsbarcode/3.11.6/JsBarcode.all.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/@zxing/library@0.21.3/umd/index.min.js"></script>
<script>
const $=i=>document.getElementById(i);let pub={},role='student',mode='in',st=null,off=0,poller=null,qrObj=null,lastTok='',stream=null,raf=null,busy=false;
const tm=t=>new Date(t).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}),dt=t=>new Date(t).toLocaleString([], {day:'numeric',month:'short',hour:'2-digit',minute:'2-digit'});
let dev;try{dev=localStorage.getItem('dev');if(!dev){dev=Math.random().toString(36).slice(2,14)+Date.now().toString(36);localStorage.setItem('dev',dev)}}catch(e){dev=Math.random().toString(36).slice(2,14)}
async function api(p,b,m){const r=await fetch(p,{method:m||(b?'POST':'GET'),headers:{'Content-Type':'application/json'},body:b?JSON.stringify(b):undefined});if(r.status===401&&!p.includes('login')&&!p.includes('mark')){boot();throw new Error('auth')}const d=await r.json();if(!r.ok)throw new Error(d.error||'Something went wrong');return d}
function cell(tr,x){const td=document.createElement('td');td.textContent=x;tr.appendChild(td);return td}
function show(v){['vA','vS','vT'].forEach(x=>$(x).classList.toggle('hide',x!==v))}
function header(){const s=pub.settings||{};$('col').textContent=s.college||'SmartAttend';const c=$('chips');c.textContent='';[s.dept&&'Department: '+s.dept,s.subject&&'Subject: '+s.subject].filter(Boolean).forEach(t=>{const e=document.createElement('span');e.className='chip';e.textContent=t;c.appendChild(e)});$('dot').classList.toggle('on',!!pub.active);$('lt').textContent=pub.active?'Class in session':'No active class'}
async function boot(){
  clearInterval(poller);poller=null;stopCam();
  try{pub=await api('/api/public');const {user}=await api('/api/me');header();
    if(!user){$('h1').textContent='Secure QR Attendance';$('hs').textContent='Sign in to mark or manage attendance.';authUi();return show('vA')}
    if(user.role==='teacher'){$('h1').textContent='Welcome, '+user.name;$('hs').textContent='Manage your class, students and attendance.';show('vT');tabT('L');poll();poller=setInterval(poll,2000)}
    else{$('h1').textContent='Welcome, '+user.name;$('hs').textContent='Scan the barcode on the teacher’s screen.';$('who').textContent='Roll no. '+user.roll;show('vS');poller=setInterval(async()=>{try{pub=await api('/api/public');header()}catch(e){}},5000)}
  }catch(e){if(e.message!=='auth'){$('lt').textContent='Offline'}}
}
/* auth */
function authUi(){const t=role==='teacher',up=mode==='up';$('rS').classList.toggle('on',!t);$('rT').classList.toggle('on',t);
  $('idL').textContent=t?'Username':'Roll number';$('nmW').hidden=!(t&&up);$('cdW').hidden=!(t&&up&&pub.needCode);
  $('ttl').textContent=up?'Create '+(t?'teacher':'student')+' account':'Sign in';$('go').textContent=up?'Create account':'Sign in';
  $('alt').textContent=up?'Already registered?':'New here?';$('sw').textContent=up?'Sign in':'Create an account';$('am').classList.add('hide');
  $('note').textContent=up&&t&&!pub.needCode?'The first teacher to register becomes the admin. Later teacher sign-ups are disabled.':up&&!t?'Use the roll number your teacher added for you.':''}
$('rS').onclick=()=>{role='student';authUi()};$('rT').onclick=()=>{role='teacher';authUi()};$('sw').onclick=()=>{mode=mode==='in'?'up':'in';authUi()};
async function doAuth(){$('go').disabled=true;$('am').classList.add('hide');
  try{await api(mode==='up'?'/api/signup':'/api/login',{role,id:$('id').value,password:$('pw').value,name:$('nm').value,code:$('cd').value});$('pw').value='';await boot()}
  catch(e){$('am').textContent=e.message;$('am').classList.remove('hide')}finally{$('go').disabled=false}}
$('go').onclick=doAuth;['id','pw','nm','cd'].forEach(i=>$(i).onkeydown=e=>{if(e.key==='Enter')doAuth()});
const out=async()=>{await fetch('/api/logout',{method:'POST'});boot()};$('outS').onclick=out;$('outT').onclick=out;
/* student */
function sm(t,k){const s=$('smsg');s.textContent=t;s.className='msg '+k}
const pos=()=>new Promise((res,rej)=>navigator.geolocation?navigator.geolocation.getCurrentPosition(p=>res(p.coords),rej,{enableHighAccuracy:true,timeout:12000,maximumAge:0}):rej());
async function mark(code){if(busy)return;busy=true;
  try{pub=await api('/api/public');header();let lat=null,lng=null;
    if(pub.geo){sm('Verifying your location…','in');try{const c=await pos();lat=c.latitude;lng=c.longitude}catch(e){return sm('Location access is required to confirm you are in the classroom.','er')}}
    const d=await api('/api/mark',{code,lat,lng,device:dev});stopCam();sm(d.already?d.name+', your attendance is already recorded.':'Success — attendance recorded for '+d.name+'.','ok')
  }catch(e){if(e.message!=='auth')sm(e.message,'er')}finally{busy=false}}
$('sub').onclick=()=>{const v=$('man').value.trim();if(v)mark(v)};
async function startCam(){if(!navigator.mediaDevices)return sm('Camera needs a secure (https) connection. Enter the code manually.','er');
  try{stream=await navigator.mediaDevices.getUserMedia({video:{facingMode:'environment'}});const v=$('vid');v.srcObject=stream;v.classList.remove('hide');await v.play();$('scan').classList.add('hide');$('stop').classList.remove('hide');
    const cv=$('cv'),cx=cv.getContext('2d',{willReadFrequently:true});
    const hints=new Map();hints.set(ZXing.DecodeHintType.POSSIBLE_FORMATS,[ZXing.BarcodeFormat.CODE_128,ZXing.BarcodeFormat.QR_CODE]);hints.set(ZXing.DecodeHintType.TRY_HARDER,true);
    const zr=new ZXing.MultiFormatReader();zr.setHints(hints);let lastT=0;
    const loop=()=>{if(!stream)return;const now=Date.now();
      if(v.readyState===v.HAVE_ENOUGH_DATA&&now-lastT>120&&!busy){lastT=now;const sc=Math.min(1,800/v.videoWidth),w=Math.round(v.videoWidth*sc),h=Math.round(v.videoHeight*sc);cv.width=w;cv.height=h;cx.drawImage(v,0,0,w,h);
        const d=cx.getImageData(0,0,w,h).data,lum=new Uint8ClampedArray(w*h);for(let i=0,j=0;i<lum.length;i++,j+=4)lum[i]=(d[j]*306+d[j+1]*601+d[j+2]*117)>>10;
        try{const t=zr.decode(new ZXing.BinaryBitmap(new ZXing.HybridBinarizer(new ZXing.RGBLuminanceSource(lum,w,h)))).getText();if(/^(ATT:.+|\d{6})$/.test(t))mark(t)}catch(e){}}
      raf=requestAnimationFrame(loop)};loop();
  }catch(e){sm('Camera could not be opened. Enter the code manually below.','er')}}
function stopCam(){if(stream){stream.getTracks().forEach(t=>t.stop());stream=null}cancelAnimationFrame(raf);$('vid').classList.add('hide');$('scan').classList.remove('hide');$('stop').classList.add('hide')}
$('scan').onclick=startCam;$('stop').onclick=stopCam;
/* teacher */
function tabT(t){['L','R','H','G'].forEach(x=>{$('p'+x).classList.toggle('hide',x!==t);$('t'+x).classList.toggle('on',x===t)});if(t==='G'&&st){const s=st.settings;$('sCol').value=s.college;$('sDep').value=s.dept;$('sSub').value=s.subject;$('sRad').value=s.radius}}
['L','R','H','G'].forEach(x=>$('t'+x).onclick=()=>tabT(x));
function bm(m){$('bcw').classList.toggle('hide',m!=='B');$('qr').classList.toggle('hide',m==='B');$('mB').classList.toggle('on',m==='B');$('mQ').classList.toggle('on',m!=='B')}
$('mB').onclick=()=>bm('B');$('mQ').onclick=()=>bm('Q');
function err(t){const e=$('emsg');e.textContent=t||'';e.classList.toggle('hide',!t)}
$('end').onclick=async()=>{try{await api('/api/class/end',{});poll()}catch(e){}};
$('start').onclick=async()=>{err('');$('start').disabled=true;const b={geo:$('geo').checked};
  try{if(b.geo){try{const c=await pos();b.lat=c.latitude;b.lng=c.longitude}catch(e){throw new Error('Location unavailable. Allow location access or untick the box.')}}
    await api('/api/class/start',b);lastTok='';poll()}catch(e){if(e.message!=='auth')err(e.message)}finally{$('start').disabled=false}};
$('addS').onclick=async()=>{const m=$('rm');try{const d=await api('/api/teacher/students',{text:$('lst').value});m.textContent=d.added+' added'+(d.skipped?', '+d.skipped+' skipped (duplicate or invalid line)':'')+'.';m.className='msg '+(d.added?'ok':'er');if(d.added)$('lst').value='';poll()}catch(e){m.textContent=e.message;m.className='msg er'}};
$('saveG').onclick=async()=>{try{const d=await api('/api/teacher/settings',{college:$('sCol').value,dept:$('sDep').value,subject:$('sSub').value,radius:$('sRad').value});pub.settings=d.settings;header();$('gm').textContent='Saved.';$('gm').classList.remove('hide');poll()}catch(e){}};
async function poll(){try{st=await api('/api/teacher/state');off=st.now-Date.now();pub.settings=st.settings;pub.active=!!(st.session&&st.session.active);header();render()}catch(e){}}
function render(){
  const s=st.session,a=s&&s.active,R=st.roster,by={};(s?s.marks:[]).forEach(m=>by[m.roll]=m);const n=R.length,p=R.filter(r=>by[r[0]]).length;
  $('np').textContent=p;$('na').textContent=n-p;$('nt').textContent=n;$('pc').textContent=(n?Math.round(p/n*100):0)+'%';
  $('start').classList.toggle('hide',!!a);$('end').classList.toggle('hide',!a);$('qcard').classList.toggle('hide',!a);
  $('sinfo').textContent=s?'Started '+dt(s.started)+(a?' · Live':' · Ended'):'No session yet';$('csv').href='/api/class/export.csv'+(s?'?sid='+s.id:'');
  if(a&&s.token!==lastTok){lastTok=s.token;$('code').textContent=s.token;try{JsBarcode('#bc',s.token,{format:'CODE128',width:4,height:120,displayValue:false,margin:0})}catch(e){}const t='ATT:'+s.id+':'+s.token;if(!qrObj)qrObj=new QRCode($('qr'),{text:t,width:184,height:184,correctLevel:QRCode.CorrectLevel.M});else{qrObj.clear();qrObj.makeCode(t)}}
  const tb=$('tb');tb.textContent='';if(!n){const tr=document.createElement('tr');cell(tr,'Add your students in the Students tab to begin.').colSpan=5;tb.appendChild(tr)}
  R.forEach(([r,nm])=>{const m=by[r],tr=document.createElement('tr');cell(tr,r);cell(tr,nm);const c=cell(tr,''),pl=document.createElement('span');pl.className='pill '+(m?'pr':'ab');pl.textContent=m?'Present':'Absent';c.appendChild(pl);cell(tr,m?tm(m.at):'—');cell(tr,m&&m.dist!=null?m.dist+' m':'—');tb.appendChild(tr)});
  $('rinfo').textContent=n+' students · '+R.filter(r=>r[2]).length+' have created an account';
  const rb=$('rb');rb.textContent='';R.forEach(([r,nm,reg])=>{const tr=document.createElement('tr');cell(tr,r);cell(tr,nm);const c=cell(tr,''),pl=document.createElement('span');pl.className='pill '+(reg?'pr':'ab');pl.textContent=reg?'Registered':'Not yet';c.appendChild(pl);
    const d=cell(tr,''),b=document.createElement('button');b.className='x';b.textContent='Remove';b.onclick=async()=>{if(confirm('Remove '+nm+' and their account?')){await api('/api/teacher/students/'+encodeURIComponent(r),null,'DELETE');poll()}};d.appendChild(b);rb.appendChild(tr)});
  const hb=$('hb');hb.textContent='';if(!st.history.length){const tr=document.createElement('tr');cell(tr,'No classes yet.').colSpan=4;hb.appendChild(tr)}
  st.history.forEach(h=>{const tr=document.createElement('tr');cell(tr,dt(h.started));cell(tr,h.subject);cell(tr,h.present+' / '+n);const c=cell(tr,''),l=document.createElement('a');l.href='/api/class/export.csv?sid='+h.id;l.textContent='CSV';l.style.color='var(--ac)';c.appendChild(l);hb.appendChild(tr)});
}
setInterval(()=>{if(!st||!st.session||!st.session.active)return;const l=Math.max(0,st.step-(Date.now()+off-st.session.tokenAt));$('fill').style.width=(l/st.step*100)+'%';$('cnt').textContent='New code in '+Math.ceil(l/1000)+'s'},250);
boot();
</script></body></html>
`;
