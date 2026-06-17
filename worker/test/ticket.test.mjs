// Seal ticket: mint→verify roundtrips, and a tampered / expired / wrong-key ticket is rejected.
// This is the capability that lets the browser seal at the tenant's last-mile without the control
// plane ever seeing the plaintext. Run: node test/ticket.test.mjs
import { mintSealTicket, verifySealTicket } from "../src/ticket.js";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✓ " + m)) : (fail++, console.error("  ✗ " + m)));

(async () => {
  const KEY = "relay-key-abc";

  const t = await mintSealTicket(KEY);
  ok(await verifySealTicket(KEY, t), "a fresh ticket verifies under its relay key");

  ok(!(await verifySealTicket("other-key", t)), "a different relay key rejects it");

  const tampered = t.slice(0, -2) + (t.endsWith("a") ? "bb" : "aa");
  ok(!(await verifySealTicket(KEY, tampered)), "a tampered signature is rejected");

  ok(!(await verifySealTicket(KEY, "garbage")), "a malformed ticket is rejected");
  ok(!(await verifySealTicket(KEY, "")), "an empty ticket is rejected");

  // expiry: mint with a 1s TTL and verify as if 5s have passed
  const shortlived = await mintSealTicket(KEY, 1);
  ok(!(await verifySealTicket(KEY, shortlived, Date.now() + 5000)), "an expired ticket is rejected");
  ok(await verifySealTicket(KEY, shortlived, Date.now()), "...but is valid right now");

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
