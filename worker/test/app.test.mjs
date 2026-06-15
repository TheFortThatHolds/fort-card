// Wallet PWA: the page renders, the routes resolve, and the inline browser JS parses. Run: node test/app.test.mjs
import { handleApp } from "../src/app.js";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✓ " + m)) : (fail++, console.error("  ✗ " + m)));

const html = await handleApp({}, null, null, "/app").text();
ok(html.includes('id="app"') && html.includes('id="signin"'), "renders the app + sign-in shells");
ok(html.includes("/passkey/assert/begin") && html.includes("X-Fort-Action"), "wires the passkey step-up + action header");
ok(html.includes("/login") && html.includes("/whoami"), "wires the OAuth login + whoami");

// the inline browser script must be syntactically valid (parse, don't execute)
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
let parsed = true;
try { new Function(script); } catch (e) { parsed = false; console.error("    " + e.message); }
ok(parsed, "inline browser JS parses");

ok(!!handleApp({}, null, null, "/app/manifest.webmanifest"), "serves the manifest");
ok(!!handleApp({}, null, null, "/app/sw.js"), "serves the service worker");
ok(handleApp({}, null, null, "/cards") === null, "passes non-app routes through");

// CORE_ORIGIN widens frame-ancestors so Fort Core can embed it as the plugin
const framed = handleApp({ CORE_ORIGIN: "https://fort.example" }, null, null, "/app");
ok((framed.headers.get("Content-Security-Policy") || "").includes("https://fort.example"), "CORE_ORIGIN allows the Core to frame the plugin");

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
