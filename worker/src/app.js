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

const b64bytes = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
// Generated PNG app icons (dark bg, copper rounded square) — required for the install prompt.
const ICON192 = "iVBORw0KGgoAAAANSUhEUgAAAMAAAADACAYAAABS3GwHAAACSElEQVR42u3TQQ3CAAAEwVNA0gQnSKu5ugMLhAeP7jzWwOVmz+PxlqrNCAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAAuC7rvOlHwPA6XVjDHN6lTHM+VVGMMdXGcKcX2UEc36VEcz5VUYw51cZwZxfZQQACADnVxXBnF9lBAAIAAAEgPMriAAAAQCAAHB+BREAIAAAEAAACAAABAAAAgAAAQCAAABAAAAgAAAQAAAIAAAEAAACAAABAIAAAEAAACAAABAAAAgAAAQAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAIAAAEAAACAAABAAAAgAAAQAAAIAAAEAgAAAQAAAIAAAEAAACAAABAAAAgAAAQCAAABAAAAgAAAQAAAIAAAEAAACAAABAIAAAEAAACAAABAAAAgAAAQAAAIAAAEAgAAAQAAAIAAAEAAACAAABAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIHB+AAAAAAAAAAAAAucHAAAAAAAAAAAgcH4AIHB+ABwLgDYACJw/DwAC588DgMD58wAgcP48AAicPw8ABMcHAALnBwAGpwcABqcHQAJAAkACQAJAAkACQAJAAkACQABIAEgASABIAEgASABIAEgASABIAEgASABIAEgASABIAEgASABIAEgASABIAEgASABIAEgASABIf+8Dbth9Sg/3KIgAAAAASUVORK5CYII=";
const ICON512 = "iVBORw0KGgoAAAANSUhEUgAAAgAAAAIACAYAAAD0eNT6AAAKR0lEQVR42u3WMQ0AIAxFwSogIakTpGEOd+CgKyHccAY69L/I3jYA8JdwBAAQAACAAAAABAAAIAAAAAEAAAgAAEAAAAACAAAQAACAAAAABAAAIAAAAAEAAAgAAEAAAAACAAAQAAAgAAAAAQAACAAAQAAAAAIAABAAAIAAAAAEAAAgAAAAAQAACAAAQAAAAAIAABAAAIAAAAAEAAAgAABAAAAAAgAAEAAAgAAAAAQAACAAAAABAAAIAABAAAAAAgAAEAAAgAAAAAQAACAAAAABAAAIAABAAACAAAAABAAAIAAAAAEAAAgAAEAAAAACAAAQAACAAAAABAAAIAAAAAEAAAgAAEAAAAACAAAQAACAAAAAAeAQACAAAAABAAAIAABAAAAAAgAAEAAAgAAAAAQAACAAAAABAAAIAABAAAAAAgAAEAAAgAAAAAQAAAgARwAAAQAACAAAQAAAAAIAABAAAIAAAAAEAAAgAAAAAQAACAAAQAAAAAIAABAAAIAAAAAEAAAgALhrzQEU/AkEAIYeEAYIAIw+IAYQABh9QAwgADD6gP+EAMDwgxAAAYDhByEAAgDDD0IAAeAIGH4QAggADD8gBBAAGH9ABCAAMPyAEEAAYPwBEYAAwPgDIgABgPEHRAACAMMPCAEEAMYfEAEIAIw/IAIQABh/QAQgADD+gAhAAGD8ARGAAEAAAAIAAYBnBYgABIDxBxABCADjDyACEADGH0AECAAEAIAAEAAYfwARIAAw/gAiQAAgAAAB4A8LAIw/IAIQAAgAQAAgADD+gAhAACAAAAGAAMD4AyIAAYAAAAQAAgDjD4gABIAAABAACADjDyACEAACAEAAIAAEAIAAQAAYfwARgAAQAAACQAAgAAAEgADA+AOIAAGAAAAQAAIAAQAgAAQAxh9ABAgABACAABAACABAACAAEACAAEAAIAAAAYAAQAAAAgABYPwBRAACQAAACAAEgAAAEAAIAAEAIAAQAAIAQAAgAAQAgABAAAgAAAEgABAAAAJAACAAAASAAEAAAAgAAYAAABAAAgABACAABAACAEAACAAEACAAEAAIAEAAIAAQAIAAQAAgAAABgAAQAB4HIAAQAAIAQAAgAAQAgABAAAgAAAGAABAAAAIAASAAAAQAAkAAAAgAAeAQAgBAAAgABACAABAACAAAASAAEAAAAkAAIAAABIAAQAAACAABgAAABIB/LgAQAIAAQAAgAAABgABAAAACAAGAxwEIAASAAAAQAAgAAQAgABAAAgBAACAABACAAEAACAAAAYAAEAAAAkAAOIIAABAAAgABACAABAACAEAACAAEAIAAEAAIAAABIAAQAAACQAAgAAAEgABAAAACAAGAAAAEAAIAAQAIAAQAAgAQAAgAAQAgABAAAgBAACAABACAAEAACAAAAYAAEAAAAgABIAAABAACQAAACAABgAAAEAACAAEAIAAEAAIAQAAIAAQAgAAQAAgAAAEgABAAAAJAACAAAAGAAEAAAAIAAYAAAAQAAgABAAgABIAAABAACAABACAAEAACAEAAIAAEAIAAQAAIAAABgAAQAAACAAEgAAAEgABAAAAIAAGAAAAQAAIAAQAgAAQAAgBAAAgABACAABAACAAAASAAEACAAEAAIAAAAYAAQAAAAgABgAAABAACQAAACAAEgAAAEAAIAAEAIAAQAAIAQAAgAAQAgABAAAgAAAGAABAAAAJAACAAAASAAEAAAAgAAYAAABAAAgABACAABAACAEAACAAEAIAAEAAIAEAAIAAQAIAAQAAgAAABgABAAAACAAEgADwOQAAgAAQAgABAAAgAAAGAABAAAAIAASAAAAQAAkAAAAgABIAAABAAAsAhBACAABAACAAAASAAEAAAAkAAIAAABIAAQAAACAABgAAAEAACAAEACAD/XAAgAAABgABAAAACAAGAAAAEAAIAjwMQAAgAAQAgABAAAgBAACAABACAAEAACAAAAYAAEAAAAgABIAAABIAAcAQBACAABAACAEAACAAEAIAAEAAIAAABIAAQAAACQAAgAAAEgABAAAAIAAGAAAAEAAIAAQAIAAQAAgAQAAgABAAgABAAAgBAACAABACAAEAACAAAAYAAEAAAAgABIAAABAACQAAACAAEgAAAEAACAAEAIAAEAAIAQAAIAAQAgAAQAAgAAAEgABAAAAJAACAAAASAAEAAAAIAAYAAAAQAAgABAAgABAACABAACAABACAAEAACAEAAIAAEAIAAQAAIAAABgAAQAAACAAEgAAAEAAJAAAAIAAGAAAAQAAIAAQAgAAQAAgBAAAgABACAABAACAAAASAAEAAAAkAAIAAAAYAAQAAAAgABgAAABAACAAEACAAEgAAAEAAIAAEAIAAQAAIAQAAgAAQAgABAAAgAAAGAABAAAAIAASAAAASAAEAAAAgAAYAAABAAAgABACAABAACAEAACAAEAIAAEAAIAAABIAAQAIAAQAAgAAABgABAAAACAAGAAAAEAAJAAHgcgABAAAgAAAGAABAAAAIAASAAAAQAAkAAAAgABIAAABAACAABACAABIBDCAAAASAAEAAAAkAAIAAABIAAQAAACAABgAAAEAACABEAYPwFAAIAEAAIAAQAIAAQAAgAQAAgABAAgABAACAAAAGAABABAMYfASAAAAQAAkAAAAgABIAIADD+CAABACAAEAACAEAACABHEAEAxl8AIAAABIAAQAAACAABgAgAMP4CAAEAIAAEACIAMP4IAAQAIAAQAIgAwPgjABAAgABAACACAOOPAEAAAAIAAYAIAIw/AgABAAgABIAI8IQA448AEAEAxh8BIAAABAACQAQAGH8EgAgAMP4CABEAYPwFACIAwPgLAAQAIAAQAIgAwPgjABABgPFHACACAOOPAEAEAMYfAYAIAIw/AgAhABh+BAAiADD+CABEAGD8EQCIAMD4IwAQAoDhRwAgAgDjjwBACACGHwGAEADDDwIAIQCGHwEAQgAMPwIAhAAYfgQAiAEw+ggAEANg9BEAIAbA6CMAQBiAoUcAAAACAAAQAACAAAAABAAAIAAAAAEAAAgAAEAAAAACAAAQAAAgAAAAAQAACAAAQAAAAAIAABAAAIAAAAAEAAAgAAAAAQAACAAAQAAAAAIAABAAAIAAAAAEAAAgAABAADgEAAgAAEAAAAACAAAQAACAAAAABAAAIAAAAAEAAAgAAEAAAAACAAAQAACAAAAABAAAIAAAAAEAAALAEQBAAAAAAgAAEAAAgAAAAAQAACAAAAABAAAIAABAAAAAAgAAEAAAgAAAAAQAACAAAAABAAAIAABAAACAAAAABAAAIAAAAAEAAAgAAEAAAAACAAAQAACAAAAABAAAIAAAAAEAAAgAAEAAAAACAAAQAACAAAAAAQAACAAAQAAAAAIAABAAAIAAAAAEAAAgAAAAAQAACAAAQAAAAAIAABAAAIAAAAAEAAAgAAAAAQAAAgAAEAAAgAAAAAQAACAAAIDXHAmDz8VcGDOWAAAAAElFTkSuQmCC";
export function handleApp(env, request, url, path) {
  if (path === "/app/manifest.webmanifest") {
    return new Response(
      JSON.stringify({
        name: "Fort Wallet",
        short_name: "Wallet",
        start_url: "/app",
        scope: "/app",
        display: "standalone",
        background_color: "#14110e",
        theme_color: "#14110e",
        icons: [
          { src: "/app/icon-192.png", sizes: "192x192", type: "image/png", purpose: "any maskable" },
          { src: "/app/icon-512.png", sizes: "512x512", type: "image/png", purpose: "any maskable" },
        ],
      }),
      { headers: { "Content-Type": "application/manifest+json" } },
    );
  }
  if (path === "/app/icon-192.png") return new Response(b64bytes(ICON192), { headers: { "Content-Type": "image/png", "Cache-Control": "public, max-age=86400" } });
  if (path === "/app/icon-512.png") return new Response(b64bytes(ICON512), { headers: { "Content-Type": "image/png", "Cache-Control": "public, max-age=86400" } });
  if (path === "/app/sw.js") {
    return new Response(
      `self.addEventListener('install',e=>self.skipWaiting());
self.addEventListener('activate',e=>self.clients.claim());
self.addEventListener('fetch',()=>{});
self.addEventListener('push',e=>{let d={};try{d=e.data?e.data.json():{}}catch(_){d={}}e.waitUntil(self.registration.showNotification(d.title||'Fort Wallet',{body:d.body||'',data:{url:d.url||'/app'},badge:undefined}))});
self.addEventListener('notificationclick',e=>{e.notification.close();const u=(e.notification.data&&e.notification.data.url)||'/app';e.waitUntil(self.clients.matchAll({type:'window',includeUncontrolled:true}).then(ws=>{for(const w of ws){if(w.url.indexOf('/app')>=0){return w.focus()}}return self.clients.openWindow(u)}))});`,
      { headers: { "Content-Type": "application/javascript", "Service-Worker-Allowed": "/app" } },
    );
  }
  if (path === "/app") return new Response(PAGE, { headers: appHeaders(env) });
  return null;
}

const PAGE = `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Fort Wallet</title><link rel="manifest" href="/app/manifest.webmanifest"><meta name="theme-color" content="#14110e">
<meta name="mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-status-bar-style" content="black-translucent"><meta name="apple-mobile-web-app-title" content="Fort Wallet">
<link rel="apple-touch-icon" href="/app/icon-192.png"><link rel="icon" type="image/png" href="/app/icon-192.png">
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
.tiles{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
.tile{display:flex;flex-direction:column;align-items:flex-start;gap:2px;text-align:left;background:#1d1812;border:1px solid #2c251c;border-radius:14px;padding:16px;cursor:pointer;color:#efe7da;font:inherit}
.tile:hover{border-color:#b87333}
.tile b{font-size:16px}
.tile .ic{font-size:22px;margin-bottom:6px}
@media(max-width:480px){.tiles{grid-template-columns:1fr}}
.back{margin:4px 0 18px}
.ev{border-top:1px solid #2c251c;padding:9px 0}
.ev:first-child{border-top:0}
.ev .evtype{font-weight:600}
.ev .evd{margin-top:2px;word-break:break-word}
</style></head><body>
<div class="wrap" id="root">
  <div id="installbar" class="hide" style="background:#1d1812;border:1px solid #b87333;border-radius:12px;padding:12px 14px;margin:14px 0;display:flex;align-items:center;justify-content:space-between;gap:12px">
    <span>📲 Install Fort Wallet on your phone</span><button class="btn p sm" id="installbtn">Install</button>
  </div>
  <div id="notifbar" class="hide" style="background:#1d1812;border:1px solid #b87333;border-radius:12px;padding:12px 14px;margin:14px 0;display:flex;align-items:center;justify-content:space-between;gap:12px">
    <span>🔔 Turn on approval alerts</span><button class="btn p sm" id="notifbtn">Enable</button>
  </div>
  <div id="signin" class="hide" style="padding:60px 0;text-align:center">
    <div class="hero" style="text-align:left"><h1>Fort <span class="c">Wallet</span></h1><p class="muted">Credentials issued like cards, not keys. Sign in to your space.</p></div>
    <a class="btn p" href="/login" style="margin-top:20px;display:inline-block">Sign in with GitHub</a>
  </div>
  <div id="lock" class="hide" style="padding:48px 0;text-align:center">
    <div class="hero" style="text-align:left"><h1>Fort <span class="c">Wallet</span></h1></div>
    <p class="muted" style="margin-bottom:18px">Signed in as <b id="lockwho">…</b></p>
    <button class="btn p" id="unlock" style="font-size:16px;padding:14px 22px">Unlock with your passkey</button>
    <p id="lockmsg" class="muted" style="margin-top:14px"></p>
    <p class="muted" style="margin:26px auto 0;max-width:460px">Your passkey guards this device and stays on it. GitHub is your sign-in and your recovery: lose this device, sign back in anywhere, re-enable it, and your keys are right there — so a lost device doesn't lock you out.</p>
    <a class="muted" href="/logout" style="display:inline-block;margin-top:16px">Sign out</a>
  </div>
  <div id="gate" class="hide" style="padding:40px 0">
    <div class="hero" style="text-align:left"><h1>Fort <span class="c">Wallet</span></h1><p class="muted">Signed in as <b id="gatewho">…</b></p></div>
    <div class="card" style="margin-top:18px">
      <div class="row"><b style="font-size:18px">Subscription</b><span class="pill warn" id="gateprice">$8 / month</span></div>
      <p class="muted" style="margin-top:10px">Your own lockbox: store keys on your own Cloudflare, issue capped cards, approve agent requests from your phone. One price, everything in. Cancel anytime.</p>
      <button class="btn p" id="subbtn" style="margin-top:16px;width:100%;font-size:16px;padding:14px">Subscribe</button>
      <p class="muted" style="margin-top:10px">You'll review and accept the terms on the secure checkout page.</p>
      <p id="gatemsg" class="muted" style="margin-top:12px"></p>
    </div>
    <a class="muted" href="/logout" style="display:inline-block;margin-top:16px">Sign out</a>
  </div>
  <div id="app" class="hide">
    <div class="bar"><div class="id">space <b id="who">…</b></div><a class="btn sm" href="/logout">Sign out</a></div>

    <!-- HOME: approve agent requests, see cards, jump to Lockbox / Log -->
    <div id="view-home">
      <h2>This device</h2>
      <div class="card"><div class="row">
        <div><div id="pkstate" class="muted">Checking passkey…</div><div class="muted">Enable your passkey to guard your secrets — it stays on this device. GitHub stays your recovery, so a lost device doesn't lock you out.</div></div>
        <button class="btn" id="enroll">Add passkey</button>
      </div></div>
      <div class="card hide" id="pushcard"><div class="row">
        <div><b>Notifications</b><div class="muted">Get a push when an agent requests a card — approve right from your phone.</div><div id="pushstatus" class="muted" style="margin-top:6px"></div></div>
        <button class="btn" id="pushbtn">Enable</button>
      </div></div>

      <h2>Pending approvals</h2>
      <div id="pending"><div class="muted">None.</div></div>

      <h2>Cards</h2>
      <div id="cards"><div class="muted">Loading…</div></div>

      <h2>Manage</h2>
      <div class="tiles">
        <button class="tile" id="tile-vault"><span class="ic">🔑</span><b>Lockbox</b><span class="muted">Add &amp; roll your keys</span></button>
        <button class="tile" id="tile-log"><span class="ic">📜</span><b>Log</b><span class="muted">What your agents did</span></button>
        <button class="tile" id="tile-data"><span class="ic">🛡️</span><b>Data &amp; privacy</b><span class="muted">Export or delete it all</span></button>
      </div>

      <footer id="subfoot" class="hide" style="margin:36px 0 14px;padding-top:18px;border-top:1px solid #2c251c;text-align:center">
        <div id="subline" class="muted" style="margin-bottom:10px"></div>
        <button class="btn sm" id="cancelsub" style="display:none">Cancel subscription</button>
        <button class="btn p sm" id="resumesub" style="display:none">Resume subscription</button>
        <!-- Two-step confirm: a stray scroll-tap on "Cancel" only OPENS this; the prominent choice is
             "Keep", and cancelling needs a second, deliberate tap on the quieter "Yes, cancel". -->
        <div id="cancelconfirm" class="hide">
          <div id="cancelconfirmmsg" class="muted" style="margin-bottom:12px"></div>
          <button class="btn p sm" id="cancelkeep">Keep my subscription</button>
          <button class="btn sm" id="canceldo" style="margin-left:10px;color:#e7857a;border-color:#5a3a36">Yes, cancel</button>
        </div>
      </footer>
    </div>

    <!-- LOCKBOX: your keys — add and roll over in place -->
    <div id="view-vault" class="hide">
      <button class="btn sm back" data-back>← Back</button>
      <h2>Lockbox — your keys</h2>
      <p class="muted" style="margin-bottom:14px">The keys your cards draw on, sealed in your own lockbox. Add a key, or roll one over in place — every card pointing at it picks up the new value automatically, no re-issuing.</p>
      <div class="card" id="lmcard">
        <div id="lmstatus" class="muted">Checking your lockbox…</div>
        <div id="lmpending" class="hide" style="margin-top:10px">
          <div class="muted" style="margin-bottom:6px">A lockbox phoned home and is waiting for your approval:</div>
          <div id="lmpendingurl" class="muted" style="word-break:break-all;margin-bottom:8px"></div>
          <button class="btn p" id="lmapprovebtn">Approve this lockbox (tap to confirm)</button>
          <button class="btn" id="lmrejectbtn" style="margin-top:8px">Reject</button>
        </div>
        <div id="lmconnect" class="hide">
          <div class="muted" style="margin-bottom:6px">Connect your lockbox in one tap — we set it up on your own Cloudflare for you:</div>
          <button class="btn p" id="lmcfbtn">⚡ Connect Cloudflare</button>
          <div class="muted" style="margin-top:8px">You approve once on Cloudflare. We create the lockbox in <em>your</em> account — nothing to copy, nothing to paste.</div>
          <details style="margin-top:14px">
            <summary class="muted" style="cursor:pointer">Other ways to connect</summary>
            <div class="muted" style="margin:10px 0 6px"><b>Setup code:</b> deploy it yourself, type one code:</div>
            <button class="btn" id="lmsetupbtn">Get a setup code</button>
            <div id="lmclaim" class="hide" style="margin-top:10px">
              <div class="muted" style="margin:4px 0">Setup code: <b id="lmclaimcode" style="font-family:monospace;letter-spacing:1px"></b></div>
              <div class="muted" style="margin:4px 0;word-break:break-all">Control plane: <b id="lmclaimcp"></b></div>
              <a class="btn" href="https://deploy.workers.cloudflare.com/?url=https://github.com/TheFortThatHolds/fort-card-lockbox" target="_blank" rel="noopener" style="margin-top:8px">⚡ Deploy to Cloudflare</a>
              <div class="muted" style="margin-top:8px">Paste both on Cloudflare's deploy screen. The lockbox phones home and appears above to approve. Code expires in ~30 min.</div>
            </div>
            <div class="muted" style="margin:16px 0 6px"><b>Paste the URL:</b> deploy, then paste the worker URL:</div>
            <a class="btn" href="https://deploy.workers.cloudflare.com/?url=https://github.com/TheFortThatHolds/fort-card-lockbox" target="_blank" rel="noopener">⚡ Deploy to Cloudflare</a>
            <label style="margin-top:14px">Worker URL<input id="lm_url" placeholder="https://fort-card-lockbox.you.workers.dev"></label>
            <button class="btn" id="lmconnectbtn" style="margin-top:12px">Connect my lockbox (tap to confirm)</button>
            <div class="muted" style="margin-top:8px">We claim the link for you — no tokens to copy. Your key seals inside <em>your</em> worker; we only ever hold ciphertext.</div>
          </details>
        </div>
      </div>
      <div id="secrets"><div class="muted">Loading…</div></div>
      <details class="card"><summary style="cursor:pointer">Add a key</summary>
        <label>Name<input id="s_name" placeholder="openai-key"></label>
        <label>Value<input id="s_val" placeholder="sk-…" autocomplete="off"></label>
        <button class="btn p" id="store" style="margin-top:14px">Store (tap to confirm)</button>
      </details>
    </div>

    <!-- LOG: the full statement, newest first, with detail -->
    <div id="view-log" class="hide">
      <button class="btn sm back" data-back>← Back</button>
      <h2>Log — agent activity</h2>
      <p class="muted" style="margin-bottom:14px">The last 10 acts in your space, newest first: requests, approvals, charges, declines, freezes, key rolls. Export pulls the full history.</p>
      <a class="btn sm" id="logexport" href="/events/export" download style="display:inline-block;margin-bottom:14px">⬇ Export full log</a>
      <div id="events" class="card"><div class="muted">Loading…</div></div>
    </div>

    <!-- DATA & PRIVACY: download everything, or erase it all (GDPR / CCPA data rights) -->
    <div id="view-data" class="hide">
      <button class="btn sm back" data-back>← Back</button>
      <h2>Your data &amp; privacy</h2>
      <p class="muted" style="margin-bottom:14px">Download everything we hold for your space, or erase it permanently. Secret values are never exported — the wallet can't read them.</p>
      <button class="btn sm" id="exportdata">Download my data (JSON)</button>
      <button class="btn sm" id="erasedata" style="margin-left:10px;color:#e7857a;border-color:#5a3a36">Delete everything</button>
      <!-- Two-step confirm: "Delete everything" only OPENS this; "Keep my data" is the prominent way out. -->
      <div id="eraseconfirm" class="hide" style="margin-top:14px">
        <div class="muted" style="margin-bottom:12px">This permanently deletes your secrets, cards, bearers, and statement — and cancels your subscription. It cannot be undone.</div>
        <button class="btn p sm" id="erasekeep">Keep my data</button>
        <button class="btn sm" id="erasedo" style="margin-left:10px;color:#e7857a;border-color:#5a3a36">Yes, delete everything</button>
      </div>
    </div>
  </div>
</div>
<div class="toast" id="toast"></div>
<script>
const $=s=>document.querySelector(s), api=(p,o)=>fetch(p,{credentials:'same-origin',...o});
if(new URLSearchParams(location.search).get('embed'))document.body.classList.add('embed');
const toast=(m)=>{const t=$('#toast');t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2600)};
const b2b=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
const s2b=s=>{s=s.replace(/-/g,'+').replace(/_/g,'/');return Uint8Array.from(atob(s+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0))};
// Idempotent GETs auto-retry on a transient 5xx / network blip (Cloudflare KV can be slow + flaky)
// with a short backoff, so one hiccup doesn't surface as a dead "HTTP 500" section. 4xx never retries
// (it's a real answer), and anything with a method (mutations) runs exactly once — never replayed.
async function jget(p,o){const isGet=!o||!o.method||o.method==='GET';let last;for(let i=0,n=isGet?3:1;i<n;i++){if(i)await new Promise(r=>setTimeout(r,300*i));let r;try{r=await api(p,o)}catch(e){last=e;continue}let j={};try{j=await r.json()}catch{}if(r.ok)return j;last=new Error(j.error||('HTTP '+r.status));if(r.status<500)break}throw last}

let me='',hasPk=false,__bill=null;
function pkmsg(html){$('#pkstate').innerHTML=html}
function regSW(){if('serviceWorker'in navigator)navigator.serviceWorker.register('/app/sw.js',{scope:'/app'}).catch(()=>{})}
function showApp(){$('#signin').classList.add('hide');$('#lock').classList.add('hide');$('#app').classList.remove('hide');load();maybeNudge()}
const standalone=()=>matchMedia('(display-mode: standalone)').matches||navigator.standalone===true;
let deferredPrompt=null;
addEventListener('beforeinstallprompt',e=>{e.preventDefault();deferredPrompt=e;if(!standalone())$('#installbar').classList.remove('hide')});
addEventListener('appinstalled',()=>{deferredPrompt=null;$('#installbar').classList.add('hide')});
function maybeNudge(){if(standalone()&&'Notification'in window&&Notification.permission==='default')$('#notifbar').classList.remove('hide')}
function showLock(who){$('#lockwho').textContent=who||me;$('#signin').classList.add('hide');$('#app').classList.add('hide');$('#lock').classList.remove('hide');if(standalone())setTimeout(tryAutoUnlock,200)}
// In the installed PWA, the launch gives us activation — so pop the fingerprint on open, no button
// tap first. If the browser declines (needs an explicit tap), the Unlock button is right there.
async function tryAutoUnlock(){try{$('#lockmsg').textContent='Confirm on your device…';await passkeyAssert();showApp()}catch(_){$('#lockmsg').textContent=''}}

async function enroll(){
  try{
    pkmsg('Starting…');
    const {publicKey:o}=await jget('/passkey/register/begin',{method:'POST'});
    o.challenge=s2b(o.challenge);o.user.id=s2b(o.user.id);
    o.excludeCredentials=(o.excludeCredentials||[]).map(c=>({...c,id:s2b(c.id)}));
    pkmsg('Confirm on your device…');
    let c;
    try{c=await navigator.credentials.create({publicKey:o})}
    catch(err){if(err&&(err.name==='InvalidStateError'||err.name==='NotAllowedError')){await load();return}throw err}
    pkmsg('Saving…');
    await jget('/passkey/register/finish',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({clientDataJSON:b2b(c.response.clientDataJSON),attestationObject:b2b(c.response.attestationObject),label:'device'})});
    await load();
  }catch(e){pkmsg('<b style="color:#e7857a">Add passkey failed: '+(e.message||e.name||'unknown')+'</b>')}
}

// one fingerprint tap proves presence and unlocks the wallet for this session (GitHub stays underneath)
async function passkeyAssert(){
  const {publicKey:o}=await jget('/passkey/assert/begin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'unlock'})});
  o.challenge=s2b(o.challenge);o.allowCredentials=(o.allowCredentials||[]).map(c=>({...c,id:s2b(c.id)}));
  const c=await navigator.credentials.get({publicKey:o});
  await jget('/passkey/assert/finish',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:c.id,clientDataJSON:b2b(c.response.clientDataJSON),authenticatorData:b2b(c.response.authenticatorData),signature:b2b(c.response.signature)})});
}
async function unlock(){const m=$('#lockmsg');try{m.textContent='Confirm on your device…';await passkeyAssert();showApp()}catch(e){m.innerHTML='<b style="color:#e7857a">'+(e.message||e.name||'cancelled')+'</b>'}}

// Per-action step-up: a FRESH fingerprint/Face ID tap that yields a one-shot token for exactly this
// action (the banking-app gate). Sent as the X-Fort-Action header; the server burns it after one use.
async function stepUp(action){
  const {publicKey:o}=await jget('/passkey/assert/begin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action})});
  o.challenge=s2b(o.challenge);o.allowCredentials=(o.allowCredentials||[]).map(c=>({...c,id:s2b(c.id)}));
  const c=await navigator.credentials.get({publicKey:o});
  const r=await jget('/passkey/assert/finish',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:c.id,clientDataJSON:b2b(c.response.clientDataJSON),authenticatorData:b2b(c.response.authenticatorData),signature:b2b(c.response.signature)})});
  return r.action_token;
}

// run a sensitive action; the unlock session authorizes it. if it's locked, drop back to the tap.
async function act(fn,okMsg){try{await fn();if(okMsg)toast(okMsg);load()}catch(e){const msg=e.message||'';if(msg.indexOf('lock')>=0){if(hasPk){toast('Locked — tap to unlock');showLock(me)}else toast('Enable your passkey first — tap Add passkey')}else toast(msg||e.name||'failed')}}

const mkbtn=(t,cls)=>{const b=document.createElement('button');b.className='btn sm'+(cls?' '+cls:'');b.textContent=t;return b};
function cardView(c,pending){
  const lim=c.limit==null?'∞':((c.remaining??0)+'/'+c.limit);
  const el=document.createElement('div');el.className='card'+(pending?' pending':'');
  el.innerHTML='<div class="row"><div><b>'+c.name+'</b><div class="muted">'+(c.allowed_hosts||[]).join(', ')+' · uses '+lim+'</div></div><span class="pill '+(pending?'warn':c.frozen?'dead':'')+'">'+(pending?'pending':c.frozen?'frozen':'active')+'</span></div><div class="btns" style="margin-top:12px"></div>';
  const b=el.querySelector('.btns');
  if(pending){const a=mkbtn('Approve','p');a.onclick=()=>act(()=>jget('/cards/'+c.id+'/freeze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({frozen:false})}));b.append(a)}
  else{const f=mkbtn(c.frozen?'Unfreeze':'Freeze');f.onclick=()=>act(()=>jget('/cards/'+c.id+'/freeze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({frozen:!c.frozen})}));b.append(f)}
  const rv=mkbtn('Revoke');rv.onclick=()=>{if(confirm('Revoke '+c.name+'?'))act(()=>jget('/cards/'+c.id,{method:'DELETE'}))};b.append(rv);
  return el;
}

async function load(){
  // Run the independent sections concurrently — on a slow worker, four serial round-trips stack into
  // a long wait (and a longer window to time out). Each still owns its own try/catch so one failing
  // section degrades alone instead of taking the others down.
  await Promise.all([
    (async()=>{try{
      const cards=(await jget('/cards')).cards||[];
      const pend=cards.filter(c=>c.pending),live=cards.filter(c=>!c.pending);
      const pe=$('#pending');pe.innerHTML='';if(!pend.length)pe.innerHTML='<div class="muted">None.</div>';else pend.forEach(c=>pe.append(cardView(c,true)));
      const ce=$('#cards');ce.innerHTML='';if(!live.length)ce.innerHTML='<div class="muted">No cards yet.</div>';else live.forEach(c=>ce.append(cardView(c,false)));
    }catch(e){$('#cards').innerHTML='<div class="muted">'+e.message+'</div>'}})(),
    (async()=>{try{
      const pk=(await jget('/passkey/list')).passkeys||[];hasPk=pk.length>0;
      $('#pkstate').innerHTML=hasPk?('<b style="color:#7fae6d">✓ '+pk.length+' passkey'+(pk.length>1?'s':'')+' on file</b>'):'<b style="color:#e7a85a">No passkey on this device — add one</b>';
      $('#enroll').textContent=hasPk?'Add another':'Add passkey';
    }catch(e){$('#pkstate').innerHTML='<b style="color:#e7857a">Couldn\\'t read passkeys: '+(e.message||'error')+'</b>'}})(),
    (async()=>{try{
      const ss=(await jget('/secrets')).secrets||[];
      const se=$('#secrets');se.innerHTML='';
      if(!ss.length){se.innerHTML='<div class="muted">No secrets stored yet.</div>'}
      else ss.forEach(n=>{const el=document.createElement('div');el.className='card';el.innerHTML='<div class="row"><div><b>'+n+'</b><div class="muted">stored · the key a card draws on</div></div><div class="btns"></div></div>';const b=mkbtn('Roll over');b.onclick=()=>rollover(n);el.querySelector('.btns').append(b);se.append(el)});
    }catch(e){$('#secrets').innerHTML='<div class="muted">'+e.message+'</div>'}})(),
  ]);
  refreshPushState();
}
// Store a key. The plaintext goes browser → the customer's OWN lockbox to be sealed there, and the
// control plane only ever receives ciphertext — it never touches a plaintext key. (The non-lockbox
// branch only fires on a self-host worker that carries its own MASTER_KEY.)
async function storeKey(name,value){
  value=String(value).trim(); // strip paste whitespace/newlines — a stray \n gets sealed INTO the token and rejected upstream as invalid
  let st={connected:false};try{st=await jget('/lastmile/status')}catch(_){}
  if(st.connected){
    const t=await jget('/lastmile/seal-ticket',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
    const r=await fetch(t.url.replace(/\\/+$/,'')+'/seal',{method:'POST',mode:'cors',headers:{'Content-Type':'application/json','X-Seal-Ticket':t.ticket},body:JSON.stringify({plaintext:value,dek:t.dek})});
    let j={};try{j=await r.json()}catch(_){}
    if(!r.ok||!j.sealed)throw new Error('seal failed at your lockbox'+(r.status?' ('+r.status+')':''));
    await jget('/secrets',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,sealed:j.sealed})});
  }else{
    await jget('/secrets',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,value})});
  }
}
// Lockbox connection state: is this space sealing on the customer's own lockbox, or not yet?
async function refreshLastmile(){
  const el=$('#lmstatus');if(!el)return;
  try{
    const st=await jget('/lastmile/status');
    const pend=$('#lmpending');
    if(st.pending && !st.connected){
      const pu=$('#lmpendingurl');if(pu)pu.textContent=st.pending;
      pend&&pend.classList.remove('hide');
    }else{ pend&&pend.classList.add('hide'); }
    if(st.connected){
      el.innerHTML='<b style="color:#7fae6d">✓ Your lockbox is connected</b> — keys seal in your own worker.<div class="muted" style="margin-top:4px;word-break:break-all">'+st.url+'</div>';
      $('#lmconnect').classList.add('hide');
    }else{
      el.innerHTML='<b style="color:#e7a85a">No lockbox connected yet.</b> Connect your lockbox so your keys seal on your own Cloudflare — until then there\\'s nowhere to store them.';
      $('#lmconnect').classList.remove('hide');
    }
  }catch(_){el.textContent=''}
}
// roll a key over: fingerprint pops, paste the new value, it overwrites in place. The old value is
// gone; cards pointing at this name now draw on the new key. No re-issuing cards needed.
async function rollover(name){
  try{
    await passkeyAssert();
    const v=prompt('Paste the NEW value for "'+name+'"');
    if(!v)return;
    await storeKey(name,v);
    toast('Rolled over ✓');load();
  }catch(e){toast(e.message||e.name||'cancelled')}
}

function urlB64(b){const pad='='.repeat((4-b.length%4)%4);const s=(b+pad).replace(/-/g,'+').replace(/_/g,'/');const r=atob(s);const u=new Uint8Array(r.length);for(let i=0;i<r.length;i++)u[i]=r.charCodeAt(i);return u}
async function enablePush(){
  const st=(m,c)=>{const e=$('#pushstatus');if(e){e.textContent=m;e.style.color=c||'#9a8f7d'}};
  try{
    if(!('serviceWorker'in navigator)){st('no service worker support','#e7857a');return}
    if(!('PushManager'in window)){st('no PushManager (is it the installed app?)','#e7857a');return}
    st('requesting permission…');
    const perm=await Notification.requestPermission();
    if(perm!=='granted'){st('permission: '+perm,'#e7857a');return}
    st('registering worker…');
    const reg=await navigator.serviceWorker.register('/app/sw.js',{scope:'/app'});
    // don't wait on navigator.serviceWorker.ready (that needs page CONTROL and can hang) — just
    // wait for this registration to have an ACTIVE worker, which is all subscribe needs.
    if(!reg.active){await new Promise(res=>{const w=reg.installing||reg.waiting;if(!w){res();return}const h=()=>{if(w.state==='activated'){w.removeEventListener('statechange',h);res()}};w.addEventListener('statechange',h);setTimeout(res,8000)})}
    st('fetching key…');
    const {key}=await jget('/push/key');
    if(!key){st('server returned no VAPID key','#e7857a');return}
    st('subscribing…');
    const old=await reg.pushManager.getSubscription();if(old){await old.unsubscribe().catch(()=>{})}
    const sub=await reg.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:urlB64(key)});
    st('saving to server…');
    const r=await jget('/push/subscribe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({subscription:sub.toJSON()})});
    st('✓ subscribed ('+(r.id||'ok')+')','#7fae6d');await refreshPushState()
  }catch(e){st('FAIL: '+(e.name||'')+' — '+(e.message||e),'#e7857a')}
}
// Quiet once subscribed: show the control only when there's no subscription; if there is one,
// make sure the server has it (self-heal) and hide. Shows again if the subscription ever drops.
async function refreshPushState(){
  try{
    const card=$('#pushcard');const bar=$('#notifbar');
    const supported=('Notification'in window)&&('serviceWorker'in navigator)&&('PushManager'in window);
    if(!supported||Notification.permission==='denied'){if(card)card.classList.add('hide');if(bar)bar.classList.add('hide');return}
    const reg=await navigator.serviceWorker.getRegistration('/app').catch(()=>null)||await navigator.serviceWorker.getRegistration().catch(()=>null);
    const sub=reg?await reg.pushManager.getSubscription():null;
    if(sub){
      try{await jget('/push/subscribe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({subscription:sub.toJSON()})})}catch(_){}
      if(card)card.classList.add('hide');if(bar)bar.classList.add('hide');return;
    }
    if(card){card.classList.remove('hide');const btn=$('#pushbtn');if(btn){btn.textContent=Notification.permission==='granted'?'Turn on notifications':'Enable';btn.disabled=false}}
  }catch(_){}
}
// the pay gate (managed instances): show the subscribe screen until the space is subscribed.
function showGate(bill){
  $('#gatewho').textContent=me;
  $('#gateprice').textContent='$'+((bill.price_cents||800)/100).toFixed(0).replace(/\\.0$/,'')+' / month';
  $('#signin').classList.add('hide');$('#lock').classList.add('hide');$('#app').classList.add('hide');
  $('#gate').classList.remove('hide');
}
$('#subbtn')&&($('#subbtn').onclick=async()=>{
  const m=$('#gatemsg');
  $('#subbtn').disabled=true;m.textContent='Opening secure checkout…';
  try{const r=await jget('/billing/subscribe',{method:'POST',headers:{'Content-Type':'application/json'}});
    if(r.url)location.href=r.url;else{m.innerHTML='<b style="color:#e7857a">No checkout URL returned.</b>';$('#subbtn').disabled=false}
  }catch(e){m.innerHTML='<b style="color:#e7857a">'+(e.message||'failed')+'</b>';$('#subbtn').disabled=false}
});
// ── subscription footer: shows renewal/cancel state and the one-tap cancel (and resume). Only on a
// managed (billed) instance; self-host has nothing to manage so the footer stays hidden. ──
function fmtDate(ts){try{return ts?new Date(ts*1000).toLocaleDateString(undefined,{year:'numeric',month:'short',day:'numeric'}):null}catch{return null}}
function renderBilling(bill){
  __bill=bill;const foot=$('#subfoot');if(!foot)return;
  if(!bill||!bill.enabled){foot.classList.add('hide');return}
  foot.classList.remove('hide');
  const line=$('#subline'),cancel=$('#cancelsub'),resume=$('#resumesub'),end=fmtDate(bill.current_period_end);
  const price='$'+(((bill.price_cents||800)/100).toFixed(0).replace(/\\.0$/,''));
  $('#cancelconfirm').classList.add('hide'); // always reset the confirm step on any re-render
  if(bill.cancel_at_period_end){
    line.innerHTML='Your subscription ends'+(end?' on <b>'+end+'</b>':'')+'. You keep full access until then.';
    cancel.style.display='none';resume.style.display='';
  }else{
    line.textContent='Fort Card · '+price+'/mo'+(end?' · renews '+end:'')+' · cancel anytime';
    cancel.style.display='';resume.style.display='none';
  }
}
// Tap "Cancel" → only OPENS the confirm step (nothing is cancelled yet). An accidental bump lands here,
// where "Keep" is the prominent button; cancelling needs a second deliberate tap on "Yes, cancel".
$('#cancelsub')&&($('#cancelsub').onclick=()=>{
  const end=fmtDate(__bill&&__bill.current_period_end);
  $('#cancelconfirmmsg').innerHTML='Cancel Fort Card?'+(end?' You keep full access until <b>'+end+'</b>, then it lapses.':' You keep access until your period ends.')+' You can resume any time before then.';
  $('#cancelsub').style.display='none';$('#cancelconfirm').classList.remove('hide');
});
$('#cancelkeep')&&($('#cancelkeep').onclick=()=>{ $('#cancelconfirm').classList.add('hide');$('#cancelsub').style.display=''; }); // backed out — no change
$('#canceldo')&&($('#canceldo').onclick=async()=>{
  $('#canceldo').disabled=true;
  try{const r=await jget('/billing/cancel',{method:'POST',headers:{'Content-Type':'application/json'}});renderBilling({...__bill,...r});toast('Cancellation scheduled — active until '+(fmtDate(r.current_period_end)||'period end'))}
  catch(e){toast(e.message||'cancel failed')}finally{$('#canceldo').disabled=false}
});
$('#resumesub')&&($('#resumesub').onclick=async()=>{
  $('#resumesub').disabled=true;
  try{const r=await jget('/billing/resume',{method:'POST',headers:{'Content-Type':'application/json'}});renderBilling({...__bill,...r});toast('Subscription resumed ✓')}
  catch(e){toast(e.message||'resume failed')}finally{$('#resumesub').disabled=false}
});
$('#enroll').onclick=enroll;
$('#unlock').onclick=unlock;
$('#pushbtn').onclick=enablePush;
$('#installbtn').onclick=async()=>{if(!deferredPrompt)return;deferredPrompt.prompt();await deferredPrompt.userChoice;deferredPrompt=null;$('#installbar').classList.add('hide')};
$('#notifbtn').onclick=()=>enablePush().then(()=>$('#notifbar').classList.add('hide'));
$('#store').onclick=()=>{if(!$('#s_name').value||!$('#s_val').value){toast('Name and value required');return}act(async()=>{await storeKey($('#s_name').value,$('#s_val').value);$('#s_name').value='';$('#s_val').value=''},'Key stored ✓')};

// ── Data & privacy (GDPR / CCPA): export your data, or erase everything on demand. Both require a
// FRESH passkey step-up (one-shot token), on top of the two-step "are you sure" confirm for erase. ──
const lockaware=(m)=>{if((m||'').indexOf('lock')>=0&&hasPk){toast('Locked — tap to unlock');showLock(me);return true}return false};
$('#exportdata')&&($('#exportdata').onclick=async()=>{
  try{const tok=await stepUp('data.export');
    const d=await jget('/export',{headers:{'X-Fort-Action':tok}});const blob=new Blob([JSON.stringify(d,null,2)],{type:'application/json'});
    const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='fort-card-export-'+(d.generated_at||'').slice(0,10)+'.json';document.body.append(a);a.click();a.remove();URL.revokeObjectURL(a.href);toast('Downloaded ✓')}
  catch(e){const m=e.message||'';if(!lockaware(m))toast(m||'export failed')}});
$('#erasedata')&&($('#erasedata').onclick=()=>{$('#eraseconfirm').classList.remove('hide')});
$('#erasekeep')&&($('#erasekeep').onclick=()=>{$('#eraseconfirm').classList.add('hide')});
$('#erasedo')&&($('#erasedo').onclick=async()=>{$('#erasedo').disabled=true;
  try{const tok=await stepUp('data.erase');
    await jget('/erase',{method:'POST',headers:{'Content-Type':'application/json','X-Fort-Action':tok},body:JSON.stringify({confirm:'DELETE'})});
    toast('Everything deleted.');setTimeout(()=>location.reload(),1200)}
  catch(e){const m=e.message||'';$('#erasedo').disabled=false;if(!lockaware(m))toast(m||'erase failed')}});

// ── views: home / vault / log (single page, no reload) ──
function showView(v){['home','vault','log','data'].forEach(n=>{const el=$('#view-'+n);if(el)el.classList.toggle('hide',n!==v)});if(v!=='home')scrollTo(0,0)}
$('#tile-vault')&&($('#tile-vault').onclick=()=>{showView('vault');refreshLastmile()});
$('#tile-log')&&($('#tile-log').onclick=()=>{showView('log');loadEvents()});
$('#tile-data')&&($('#tile-data').onclick=()=>{showView('data');$('#eraseconfirm').classList.add('hide')});
$('#lmconnectbtn')&&($('#lmconnectbtn').onclick=()=>{const u=$('#lm_url').value.trim();if(!u){toast('Paste your lockbox URL');return}act(async()=>{await jget('/lastmile/connect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:u})});$('#lm_url').value='';await refreshLastmile()},'Lockbox connected ✓')});
// Claim-code onboarding: mint a one-time code, show it + the control-plane URL to paste on Cloudflare's deploy screen.
$('#lmsetupbtn')&&($('#lmsetupbtn').onclick=()=>{act(async()=>{const r=await jget('/lastmile/claim-code',{method:'POST'});const c=$('#lmclaimcode');if(c)c.textContent=r.code;const cp=$('#lmclaimcp');if(cp)cp.textContent=r.control_plane_url;$('#lmclaim').classList.remove('hide')},'Setup code ready — deploy your lockbox')});
// Approve a lockbox that phoned home — the passkey tap is the real gate. Promotes pending → connected.
$('#lmapprovebtn')&&($('#lmapprovebtn').onclick=()=>act(async()=>{await passkeyAssert();await jget('/lastmile/pending/approve',{method:'POST'});await refreshLastmile()},'Lockbox connected ✓'));
$('#lmrejectbtn')&&($('#lmrejectbtn').onclick=()=>act(async()=>{await jget('/lastmile/pending/reject',{method:'POST'});await refreshLastmile()},'Pending lockbox rejected'));
// Connect Cloudflare (one-tap): top-level navigation to the OAuth start (carries the session cookie).
$('#lmcfbtn')&&($('#lmcfbtn').onclick=()=>{location.href='/cloudflare/connect'});
// Returning from the Cloudflare round-trip: surface the outcome and refresh, then clean the URL.
(function(){const p=new URLSearchParams(location.search).get('cloudflare');if(!p)return;
  if(p==='connected')toast('Cloudflare lockbox connected ✓');
  else toast('Cloudflare connect failed: '+(new URLSearchParams(location.search).get('reason')||'try again'));
  history.replaceState({},'','/app');showView('vault');refreshLastmile()})();
document.querySelectorAll('[data-back]').forEach(b=>b.onclick=()=>showView('home'));

// ── the log: a human-readable type plus the detail the ledger already records ──
const EVNAMES={'card.request':'Card requested','card.approve':'Card approved','card.unfreeze':'Card unfrozen','card.freeze':'Card frozen','card.revoke':'Card revoked','card.issue':'Card issued','card.charge':'Charge','card.decline':'Declined','card.wake':'Agent woken','card.wake_skip':'Wake skipped','secret.store':'Key stored','vault.rotate':'Key rolled over'};
function evName(t){return EVNAMES[t]||String(t||'').replace(/[._]/g,' ').replace(/^./,c=>c.toUpperCase())}
function evDetail(e){const d=[];if(e.name)d.push(e.name);if(e.host)d.push(e.host);if(e.status!=null)d.push('→ '+e.status);if(e.allowed_hosts&&e.allowed_hosts.length)d.push(e.allowed_hosts.join(', '));if(e.limit!=null)d.push('cap '+e.limit);if(e.repo)d.push(e.repo);if(e.reason)d.push(e.reason);if(e.id)d.push(e.id);return d.join(' · ')}
function evTime(ts){return String(ts||'').replace('T',' ').slice(0,16)}
async function loadEvents(){try{const ev=(await jget('/events?limit=10')).events||[];$('#events').innerHTML=ev.length?ev.map(e=>'<div class="ev"><div class="row"><span class="evtype">'+evName(e.type)+'</span><span class="muted">'+evTime(e.ts)+'</span></div>'+(evDetail(e)?'<div class="muted evd">'+evDetail(e)+'</div>':'')+'</div>').join(''):'<div class="muted">No activity yet.</div>'}catch(e){$('#events').innerHTML='<div class="muted">'+e.message+'</div>'}}

(async()=>{
  let w;try{w=await jget('/whoami')}catch{$('#signin').classList.remove('hide');return regSW()}
  me=(w.login?w.login+' · ':'')+w.space;$('#who').textContent=me;
  // The door: on a managed (billed) instance the space must be subscribed before any wallet use.
  // Self-host returns enabled:false → subscribed:true, so this is a no-op there.
  let bill={enabled:false,subscribed:true};try{bill=await jget('/billing/status')}catch{}
  const qp=new URLSearchParams(location.search);
  if(qp.get('billing')==='success'&&qp.get('session_id')){
    try{const c=await jget('/billing/confirm',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_id:qp.get('session_id')})});
      if(c.subscribed){bill.subscribed=true;toast('Subscribed ✓')}else toast(c.reason||'Payment not confirmed')}catch(e){toast(e.message||'confirm failed')}
    history.replaceState({},'',location.pathname);
  }else if(qp.get('billing')==='cancel'){toast('Checkout canceled');history.replaceState({},'',location.pathname)}
  if(bill.enabled&&!bill.subscribed){showGate(bill);return regSW()}
  renderBilling(bill); // managed + subscribed: show the manage/cancel footer at the bottom of the wallet
  // GitHub is the floor. If this device has a passkey, a tap opens the wallet (every time).
  // If it doesn't (new/replacement device), GitHub alone gets you in to enable one — no lockout.
  let has=false;try{has=((await jget('/passkey/list')).passkeys||[]).length>0}catch{}
  hasPk=has;
  if(has)showLock(w.login||w.space);else showApp();
  regSW();
})();
</script></body></html>`;
