// GitHub App JWT: mints a valid RS256 JWT from both PKCS#1 and PKCS#8 PEM keys. Run: node test/github-app.test.mjs
import nodeCrypto from "node:crypto";
import { mintAppJwt, appConfigured } from "../src/github-app.js";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✓ " + m)) : (fail++, console.error("  ✗ " + m)));

const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const pkcs1 = privateKey.export({ type: "pkcs1", format: "pem" }); // GitHub's format ("RSA PRIVATE KEY")
const pkcs8 = privateKey.export({ type: "pkcs8", format: "pem" }); // already-PKCS#8 ("PRIVATE KEY")
const pubPem = publicKey.export({ type: "spki", format: "pem" });

function verify(jwt) {
  const [h, p, s] = jwt.split(".");
  const data = h + "." + p;
  const sig = Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  const valid = nodeCrypto.verify("RSA-SHA256", Buffer.from(data), publicKey, sig);
  const payload = JSON.parse(Buffer.from(p.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString());
  return { valid, payload };
}

ok(appConfigured({ GH_APP_ID: "1", GH_APP_PRIVATE_KEY: pkcs1 }) === true, "appConfigured true when id + key set");
ok(appConfigured({}) === false, "appConfigured false when unset");

for (const [label, key] of [["PKCS#1 (GitHub format)", pkcs1], ["PKCS#8", pkcs8]]) {
  const jwt = await mintAppJwt({ GH_APP_ID: "4056461", GH_APP_PRIVATE_KEY: key });
  const { valid, payload } = verify(jwt);
  ok(valid, `${label}: signature verifies against the public key`);
  ok(payload.iss === "4056461", `${label}: iss is the app id`);
  ok(payload.exp > payload.iat && payload.exp - payload.iat <= 600, `${label}: short-lived (<=10m)`);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
