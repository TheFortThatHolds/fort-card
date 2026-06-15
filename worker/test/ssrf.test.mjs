// SSRF guard on the control-plane /use. Run: node test/ssrf.test.mjs
import { ssrfBlocked } from "../src/worker.js";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✓ " + m)) : (fail++, console.error("  ✗ " + m)));

for (const h of [
  "localhost", "foo.localhost", "printer.local", "svc.internal",
  "127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1", "172.31.255.255",
  "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1",
]) ok(ssrfBlocked(h) === true, `blocks ${h}`);

for (const h of [
  "api.openai.com", "api.cloudflare.com", "example.com", "8.8.8.8",
  "172.15.0.1", "172.32.0.1", "11.0.0.1", "192.167.0.1",
]) ok(ssrfBlocked(h) === false, `allows ${h}`);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
