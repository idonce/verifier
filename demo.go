package main

const demoHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="idonce Verifier — Try human verification live. Scan the QR code with the idonce app.">
<title>idonce — Verify</title>
<style>
@font-face{font-family:'Space Grotesk';font-style:normal;font-weight:700;font-display:swap;src:local('Space Grotesk Bold')}
@font-face{font-family:'Inter';font-style:normal;font-weight:400;font-display:swap;src:local('Inter')}
@font-face{font-family:'Inter';font-style:normal;font-weight:500;font-display:swap;src:local('Inter Medium')}
:root{--black:#0a0a0a;--white:#fafaf9;--purple:#7c3aed;--purple-light:#ede9fe;--purple-muted:#c4b5fd;--grey:#a8a29e;--grey-light:#e7e5e4;--green:#22c55e;--green-light:#dcfce7;--font-display:'Space Grotesk',system-ui,sans-serif;--font-body:'Inter',system-ui,sans-serif}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--font-body);color:var(--black);background:var(--white);-webkit-font-smoothing:antialiased;min-height:100vh;display:flex;align-items:center;justify-content:center}
a{color:var(--purple);text-decoration:none}
.wrap{max-width:460px;padding:48px 28px;text-align:center}
.logo{font-family:var(--font-display);font-size:24px;font-weight:700;letter-spacing:-1px;margin-bottom:4px}
.logo span{color:var(--purple)}
.sub{color:var(--grey);font-size:13px;margin-bottom:40px}
h2{font-family:var(--font-display);font-size:20px;font-weight:700;text-transform:uppercase;letter-spacing:-0.5px;margin-bottom:4px}
.txt-sm{color:var(--grey);font-size:14px;line-height:1.6}
.btn{display:inline-flex;align-items:center;gap:8px;font-family:var(--font-body);font-weight:500;font-size:15px;border:none;cursor:pointer;transition:all 0.2s;text-decoration:none;border-radius:50px}
.btn-p{background:var(--black);color:var(--white);padding:14px 28px}.btn-p:hover{background:var(--purple)}
.btn-s{background:none;color:var(--black);padding:14px 28px;border:1.5px solid var(--grey-light)}.btn-s:hover{border-color:var(--black)}
.demo-box{padding:40px;border:1.5px solid var(--grey-light);border-radius:20px;margin-bottom:24px}
.qr-wrap{background:#fff;border-radius:12px;padding:16px;display:inline-block;margin:20px 0 12px;border:1px solid var(--grey-light)}
.qr-wrap canvas{display:block}
.pulse{display:inline-block;width:8px;height:8px;background:var(--purple);border-radius:50%;margin-right:8px;animation:pulse 1.5s ease infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.v-icon{width:64px;height:64px;background:var(--green-light);border-radius:50%;display:inline-flex;align-items:center;justify-content:center;margin-bottom:16px}
.v-icon svg{width:32px;height:32px;color:var(--green)}
.claim{display:inline-block;background:var(--green-light);color:var(--green);font-size:12px;font-weight:600;padding:4px 12px;border-radius:50px;margin:3px}
.footer{color:var(--grey);font-size:12px;margin-top:8px}
.footer a{color:var(--grey)}
.footer a:hover{color:var(--black)}
</style>
</head>
<body>
<div class="wrap">

<div class="logo">id<span>once</span></div>
<p class="sub">Human Verification</p>

<div class="demo-box">
  <div id="d-idle">
    <h2>Verify you're human</h2>
    <p class="txt-sm" style="margin-bottom:20px">One scan. One confirmation. No passwords.</p>
    <button class="btn btn-p" onclick="startDemo()" style="width:100%">Start Verification</button>
  </div>
  <div id="d-pending" style="display:none">
    <p style="font-weight:600;font-size:15px">Scan with idonce App</p>
    <div class="qr-wrap"><canvas id="qr"></canvas></div>
    <div><button class="btn btn-s" onclick="copyQR()" style="font-size:13px;padding:8px 18px"><span id="cp">Copy QR Data</span></button></div>
    <p style="margin-top:12px;font-size:13px;color:var(--grey)"><span class="pulse"></span>Waiting for verification...</p>
    <p class="txt-sm" id="timer"></p>
  </div>
  <div id="d-ok" style="display:none">
    <div class="v-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M20 6L9 17l-5-5"/></svg></div>
    <div style="font-family:var(--font-display);font-size:24px;font-weight:700;text-transform:uppercase;color:var(--green)">Verified</div>
    <p class="txt-sm">A real person confirmed their presence</p>
    <div id="claims" style="margin-top:12px"></div>
    <button class="btn btn-s" onclick="resetDemo()" style="margin-top:20px;width:100%">Verify Again</button>
  </div>
  <div id="d-err" style="display:none">
    <p style="color:#ef4444;font-weight:600">Verification expired</p>
    <button class="btn btn-p" onclick="resetDemo()" style="margin-top:16px;width:100%">Try Again</button>
  </div>
</div>

<p class="footer"><a href="https://www.idonce.com">idonce.com</a> &middot; <a href="https://www.idonce.com/developers">Docs</a> &middot; <a href="https://github.com/idonce">GitHub</a></p>

</div>

<script src="/static/qrcode.min.js"></script>
<script>
const API=location.origin;let sid,pid,tid,exp,qrd;
function show(id){['d-idle','d-pending','d-ok','d-err'].forEach(x=>document.getElementById(x).style.display='none');document.getElementById('d-'+id).style.display='block'}
async function startDemo(){
  const r=await fetch(API+'/vp/sessions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_id:'idonce-verifier'})});
  const d=await r.json();sid=d.session_id;qrd=d.qr_data;exp=new Date(d.expires_at);
  const q=qrcode(0,'M');q.addData(d.qr_data);q.make();
  const c=document.getElementById('qr'),n=q.getModuleCount(),s=Math.floor(180/n);
  c.width=s*n;c.height=s*n;const ctx=c.getContext('2d');
  ctx.fillStyle='#fff';ctx.fillRect(0,0,c.width,c.height);ctx.fillStyle='#000';
  for(let r=0;r<n;r++)for(let cl=0;cl<n;cl++)if(q.isDark(r,cl))ctx.fillRect(cl*s,r*s,s,s);
  show('pending');
  pid=setInterval(async()=>{const r=await fetch(API+'/vp/sessions/'+sid);const d=await r.json();
    if(d.status==='presented'){stop();showOk(d)}else if(d.status==='expired'){stop();show('err')}},1500);
  tid=setInterval(()=>{const d=Math.max(0,Math.floor((exp-new Date())/1000));
    document.getElementById('timer').textContent=Math.floor(d/60)+':'+(d%60).toString().padStart(2,'0');
    if(d<=0){stop();show('err')}},1000);
}
function stop(){if(pid){clearInterval(pid);pid=null}if(tid){clearInterval(tid);tid=null}}
function showOk(data){
  const el=document.getElementById('claims');el.innerHTML='';
  Object.entries(data.disclosed_claims||{}).forEach(([k,v])=>{if(v===true){
    const b=document.createElement('span');b.className='claim';b.textContent=k.replace(/([A-Z])/g,' $1').trim();el.appendChild(b)}});show('ok')}
function resetDemo(){stop();sid=null;show('idle')}
function copyQR(){if(!qrd)return;navigator.clipboard.writeText(qrd).then(()=>{const l=document.getElementById('cp');l.textContent='Copied!';setTimeout(()=>l.textContent='Copy QR Data',1500)})}
</script>
</body>
</html>`
