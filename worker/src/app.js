// Fort Card — THE WALLET APP (the operational PWA). The standalone app AND, byte-for-byte, the
// plugin: Fort Core embeds this same page in an iframe (`?embed=1` trims the chrome), and because
// the iframe IS the wallet's origin, the session cookie + passkey ceremony work natively. The Core
// is glass — it never holds a key and never becomes a second approver (DESIGN §0).
//
// Routes:
//   GET /app                      the PWA (login → enroll passkey → cards/approvals/secrets/agents)
//   GET /app/manifest.webmanifest installable manifest
//   GET /app/sw.js                tiny offline shell
//
// The page is just HTML+JS that calls the worker's own API (same origin) with the session cookie.
// Every sensitive act runs the passkey step-up in the browser and passes the one-shot token as
// X-Fort-Action — the server enforces it (webauthn.js). Public HTML (nothing secret is inlined).

function appHeaders(env) {
  // Allow Fort Core (and self) to frame the app so it can host the plugin; default self-only.
  const ancestors = env.CORE_ORIGIN ? `'self' ${env.CORE_ORIGIN}` : "'self'";
  return {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Security-Policy": `frame-ancestors ${ancestors}`,
  };
}

export function handleApp(env, request, url, path) {
  if (path === "/app/manifest.webmanifest") {
    return new Response(
      JSON.stringify({
        name: "Fort Wallet",
        short_name: "Wallet",
        start_url: "/app",
        display: "standalone",
        background_color: "#14110e",
        theme_color: "#14110e",
        icons: [{ src: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%23b87333'/%3E%3Ctext x='32' y='44' font-size='34' text-anchor='middle' fill='%2314110e' font-family='sans-serif'%3E%E2%97%88%3C/text%3E%3C/svg%3E", sizes: "any", type: "image/svg+xml" }],
      }),
      { headers: { "Content-Type": "application/manifest+json" } },
    );
  }
  if (path === "/app/sw.js") {
    return new Response(
      `self.addEventListener('install',e=>self.skipWaiting());self.addEventListener('activate',e=>self.clients.claim());self.addEventListener('fetch',()=>{});`,
      { headers: { "Content-Type": "application/javascript" } },
    );
  }
  if (path === "/app") return new Response(PAGE, { headers: appHeaders(env) });
  return null;
}

const PAGE = `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Fort Wallet</title><link rel="manifest" href="/app/manifest.webmanifest"><meta name="theme-color" content="#14110e">
<style>
:root{color-scheme:dark}*{box-sizing:border-box;margin:0;padding:0}
body{font:16px/1.55 -apple-system,system-ui,Segoe UI,Roboto,sans-serif;background:#14110e;color:#efe7da;-webkit-font-smoothing:antialiased;padding:env(safe-area-inset-top) 0 40px}
.wrap{max-width:680px;margin:0 auto;padding:0 16px}
a{color:#d9943f}
.bar{display:flex;align-items:center;justify-content:space-between;padding:16px 0;gap:12px}
.bar .id{font-size:14px;color:#cdc2af;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar .id b{color:#efe7da}
h2{font-size:12px;letter-spacing:.13em;text-transform:uppercase;color:#b8ad99;margin:26px 0 12px}
.card{background:#1d1812;border:1px solid #2c251c;border-radius:14px;padding:16px;margin-bottom:12px}
.card.pending{border-color:#b87333}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.muted{color:#9a8f7d;font-size:13px}
.pill{font-size:11px;letter-spacing:.08em;text-transform:uppercase;padding:3px 8px;border-radius:999px;border:1px solid #3a342b;color:#cdc2af}
.pill.warn{border-color:#b87333;color:#e7a85a}
.pill.dead{opacity:.55}
.btn{display:inline-block;padding:11px 15px;border-radius:10px;font-weight:600;cursor:pointer;border:1px solid #3a342b;background:#14110e;color:#e8dcc8;font-size:14px}
.btn.p{background:#b87333;color:#14110e;border-color:#b87333}
.btn.sm{padding:7px 11px;font-size:13px}
.btn:disabled{opacity:.5;cursor:not-allowed}
.btns{display:flex;gap:8px;flex-wrap:wrap}
input,select{width:100%;padding:11px;border-radius:10px;border:1px solid #3a342b;background:#14110e;color:#efe7da;font-size:15px;margin-top:8px}
label{font-size:13px;color:#cdc2af;display:block;margin-top:10px}
.hero{padding:30px 0 8px}.hero h1{font-size:28px;letter-spacing:-.02em;margin-bottom:8px}.hero h1 .c{color:#d9943f}
.token{font-family:ui-monospace,Menlo,monospace;font-size:13px;word-break:break-all;background:#0f0c09;border:1px solid #2c251c;border-radius:10px;padding:11px;margin-top:8px;color:#e7a85a}
.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);background:#2c251c;border:1px solid #3a342b;color:#efe7da;padding:11px 16px;border-radius:10px;max-width:90vw;opacity:0;transition:opacity .2s;pointer-events:none;z-index:9}
.toast.show{opacity:1}
.hide{display:none!important}
.embed .hero,.embed .bar .sub{display:none}
</style></head><body>
<div class="wrap" id="root">
  <div id="signin" class="hide" style="padding:60px 0;text-align:center">
    <div class="hero" style="text-align:left"><h1>Fort <span class="c">Wallet</span></h1><p class="muted">Credentials issued like cards, not keys. Sign in to your space.</p></div>
    <a class="btn p" href="/login" style="margin-top:20px;display:inline-block">Sign in with GitHub</a>
  </div>
  <div id="app" class="hide">
    <div class="bar"><div class="id">space <b id="who">…</b></div><a class="btn sm" href="/logout">Sign out</a></div>

    <h2>This device</h2>
    <div class="card"><div class="row">
      <div><div id="pkstate" class="muted">Checking passkey…</div><div class="muted">A fingerprint is required for every sensitive act.</div></div>
      <button class="btn" id="enroll">Add passkey</button>
    </div></div>

    <h2>Pending approvals</h2>
    <div id="pending"><div class="muted">None.</div></div>

    <h2>Cards</h2>
    <div id="cards"><div class="muted">Loading…</div></div>
    <details class="card"><summary style="cursor:pointer">Issue a card</summary>
      <label>Name<input id="c_name" placeholder="openai for the drafter"></label>
      <label>Vault secret it draws on<input id="c_secret" placeholder="openai-key"></label>
      <label>Allowed hosts (comma-separated)<input id="c_hosts" placeholder="api.openai.com"></label>
      <label>Use limit (blank = unlimited)<input id="c_limit" type="number" inputmode="numeric"></label>
      <button class="btn p" id="issue" style="margin-top:14px">Issue (tap to confirm)</button>
    </details>

    <h2>Secrets</h2>
    <details class="card"><summary style="cursor:pointer">Store a secret</summary>
      <label>Name<input id="s_name" placeholder="openai-key"></label>
      <label>Value<input id="s_val" placeholder="sk-…" autocomplete="off"></label>
      <button class="btn p" id="store" style="margin-top:14px">Store (tap to confirm)</button>
    </details>

    <h2>Agent bearers</h2>
    <div id="agents"><div class="muted">Loading…</div></div>
    <details class="card"><summary style="cursor:pointer">Mint an agent bearer</summary>
      <label>Label<input id="a_label" placeholder="ci-bot"></label>
      <label>Expires in days (blank = never)<input id="a_ttl" type="number" inputmode="numeric"></label>
      <button class="btn p" id="mint" style="margin-top:14px">Mint (tap to confirm)</button>
    </details>

    <h2>Statement</h2>
    <div id="events" class="card"><div class="muted">Loading…</div></div>
  </div>
</div>
<div class="toast" id="toast"></div>
<script>
const $=s=>document.querySelector(s), api=(p,o)=>fetch(p,{credentials:'same-origin',...o});
if(new URLSearchParams(location.search).get('embed'))document.body.classList.add('embed');
const toast=(m)=>{const t=$('#toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2600)};
const b2b=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
const s2b=s=>{s=s.replace(/-/g,'+').replace(/_/g,'/');return Uint8Array.from(atob(s+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0))};
async function jget(p,o){const r=await api(p,o);let j={};try{j=await r.json()}catch{}if(!r.ok)throw new Error(j.error||('HTTP '+r.status));return j}

function pkmsg(html){$('#pkstate').innerHTML=html}
async function enroll(){
  try{
    pkmsg('Starting…');
    const {publicKey:o}=await jget('/passkey/register/begin',{method:'POST'});
    o.challenge=s2b(o.challenge);o.user.id=s2b(o.user.id);
    o.excludeCredentials=(o.excludeCredentials||[]).map(c=>({...c,id:s2b(c.id)}));
    pkmsg('Waiting for your fingerprint…');
    let c;
    try{c=await navigator.credentials.create({publicKey:o})}
    catch(err){
      // The authenticator already holds a passkey for this space — it's added, just re-read it.
      if(err&&(err.name==='InvalidStateError'||err.name==='NotAllowedError')){await load();return}
      throw err;
    }
    pkmsg('Saving…');
    await jget('/passkey/register/finish',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({clientDataJSON:b2b(c.response.clientDataJSON),attestationObject:b2b(c.response.attestationObject),label:'device'})});
    await load();
  }catch(e){pkmsg('<b style="color:#e7857a">Add passkey failed: '+(e.message||e.name||'unknown')+'</b>')}
}
// the banking-app tap: prove the human for ONE action, get a one-shot token
async function stepUp(action){
  const {publicKey:o}=await jget('/passkey/assert/begin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action})});
  o.challenge=s2b(o.challenge);o.allowCredentials=(o.allowCredentials||[]).map(c=>({...c,id:s2b(c.id)}));
  const c=await navigator.credentials.get({publicKey:o});
  const r=await jget('/passkey/assert/finish',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:c.id,clientDataJSON:b2b(c.response.clientDataJSON),authenticatorData:b2b(c.response.authenticatorData),signature:b2b(c.response.signature)})});
  return r.action_token;
}
async function withTap(action,fn){try{const t=await stepUp(action);await fn(t);load()}catch(e){toast(e.message||'cancelled')}}

function cardView(c,pending){
  const lim=c.limit==null?'∞':((c.remaining??0)+'/'+c.limit);
  const el=document.createElement('div');el.className='card'+(pending?' pending':'');
  el.innerHTML='<div class="row"><div><b>'+c.name+'</b><div class="muted">'+(c.allowed_hosts||[]).join(', ')+' · uses '+lim+'</div></div>'+
    '<span class="pill '+(pending?'warn':c.frozen?'dead':'')+'">'+(pending?'pending':c.frozen?'frozen':'active')+'</span></div>'+
    '<div class="btns" style="margin-top:12px"></div>';
  const b=el.querySelector('.btns');
  if(pending){const a=mkbtn('Approve (tap)','p');a.onclick=()=>withTap('card.approve',t=>jget('/cards/'+c.id+'/freeze',{method:'POST',headers:{'Content-Type':'application/json','X-Fort-Action':t},body:JSON.stringify({frozen:false})}));b.append(a);}
  else{const f=mkbtn(c.frozen?'Unfreeze (tap)':'Freeze');
    if(c.frozen)f.onclick=()=>withTap('card.approve',t=>jget('/cards/'+c.id+'/freeze',{method:'POST',headers:{'Content-Type':'application/json','X-Fort-Action':t},body:JSON.stringify({frozen:false})}));
    else f.onclick=()=>jget('/cards/'+c.id+'/freeze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({frozen:true})}).then(load);
    b.append(f);}
  const rv=mkbtn('Revoke');rv.onclick=()=>{if(confirm('Revoke '+c.name+'?'))jget('/cards/'+c.id,{method:'DELETE'}).then(load)};b.append(rv);
  return el;
}
const mkbtn=(t,cls)=>{const b=document.createElement('button');b.className='btn sm'+(cls?' '+cls:'');b.textContent=t;return b};

async function load(){
  try{
    const cards=(await jget('/cards')).cards||[];
    const pend=cards.filter(c=>c.pending),live=cards.filter(c=>!c.pending);
    const pe=$('#pending');pe.innerHTML='';if(!pend.length)pe.innerHTML='<div class="muted">None.</div>';else pend.forEach(c=>pe.append(cardView(c,true)));
    const ce=$('#cards');ce.innerHTML='';if(!live.length)ce.innerHTML='<div class="muted">No cards yet.</div>';else live.forEach(c=>ce.append(cardView(c,false)));
  }catch(e){$('#cards').innerHTML='<div class="muted">'+e.message+'</div>'}
  try{
    const pk=(await jget('/passkey/list')).passkeys||[];
    $('#pkstate').innerHTML=pk.length?('<b style="color:#7fae6d">✓ '+pk.length+' passkey'+(pk.length>1?'s':'')+' on file</b>'):'<b style="color:#e7a85a">No passkey — add one</b>';
    $('#enroll').textContent=pk.length?'Add another':'Add passkey';
  }catch(e){$('#pkstate').innerHTML='<b style="color:#e7857a">Couldn\\'t read passkeys: '+(e.message||'error')+'</b>'}
  try{
    const ag=(await jget('/agents')).agents||[];const ae=$('#agents');ae.innerHTML='';
    if(!ag.length)ae.innerHTML='<div class="muted">None.</div>';
    ag.filter(a=>!a.revoked).forEach(a=>{const el=document.createElement('div');el.className='card';el.innerHTML='<div class="row"><div><b>'+a.label+'</b><div class="muted">'+a.id+(a.expires_at?' · expires '+a.expires_at.slice(0,10):'')+'</div></div></div><div class="btns" style="margin-top:10px"></div>';const rv=mkbtn('Revoke');rv.onclick=()=>{if(confirm('Revoke '+a.label+'?'))withTap('agent.revoke',t=>jget('/agents/'+a.id,{method:'DELETE',headers:{'X-Fort-Action':t}}))};el.querySelector('.btns').append(rv);ae.append(el)});
  }catch(e){$('#agents').innerHTML='<div class="muted">'+e.message+'</div>'}
  try{
    const ev=(await jget('/events?limit=12')).events||[];
    $('#events').innerHTML=ev.length?ev.map(e=>'<div class="row" style="border-top:1px solid #2c251c;padding:7px 0"><span>'+e.type+'</span><span class="muted">'+(e.ts||'').slice(5,16).replace('T',' ')+'</span></div>').join(''):'<div class="muted">No activity.</div>';
  }catch{}
}

$('#enroll').onclick=enroll;
$('#issue').onclick=()=>{const hosts=$('#c_hosts').value.split(',').map(s=>s.trim()).filter(Boolean);const lim=$('#c_limit').value;withTap('card.issue',t=>jget('/cards',{method:'POST',headers:{'Content-Type':'application/json','X-Fort-Action':t},body:JSON.stringify({name:$('#c_name').value,secret:$('#c_secret').value,allowed_hosts:hosts,limit:lim?+lim:undefined})}))};
$('#store').onclick=()=>withTap('secret.store',t=>jget('/secrets',{method:'POST',headers:{'Content-Type':'application/json','X-Fort-Action':t},body:JSON.stringify({name:$('#s_name').value,value:$('#s_val').value})}));
$('#mint').onclick=async()=>{try{const t=await stepUp('agent.mint');const ttl=$('#a_ttl').value;const r=await jget('/agents',{method:'POST',headers:{'Content-Type':'application/json','X-Fort-Action':t},body:JSON.stringify({label:$('#a_label').value||'agent',ttl_days:ttl?+ttl:undefined})});alert('Bearer (shown ONCE — copy it now):\\n\\n'+r.token);load()}catch(e){toast(e.message||'cancelled')}};

(async()=>{
  try{const w=await jget('/whoami');$('#who').textContent=(w.login?w.login+' · ':'')+w.space;$('#app').classList.remove('hide');load();}
  catch{$('#signin').classList.remove('hide');}
  if('serviceWorker'in navigator)navigator.serviceWorker.register('/app/sw.js').catch(()=>{});
})();
</script></body></html>`;
