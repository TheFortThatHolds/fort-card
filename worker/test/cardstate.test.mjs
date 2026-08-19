// CardState Durable Object: a freeze/revoke must beat a spend, atomically — a spend can only
// consume, never resurrect a revoked card or un-freeze a frozen one. Run: node test/cardstate.test.mjs
import { CardState, fence } from "../src/cardstate.js";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✓ " + m)) : (fail++, console.error("  ✗ " + m)));

// mock DO state: a Map-backed storage that clones in/out so callers can't alias the stored object.
function mkObj() {
  const m = new Map();
  const storage = {
    async get(k) { return m.has(k) ? structuredClone(m.get(k)) : undefined; },
    async put(k, v) { m.set(k, structuredClone(v)); },
    async delete(k) { m.delete(k); },
  };
  return new CardState({ storage }, {});
}
const call = async (obj, op, payload) =>
  (await obj.fetch(new Request("https://do/" + op, { method: "POST", body: JSON.stringify(payload || {}) }))).json();

const CARD = { id: "c1", secret: "k", allowed_hosts: ["api.x.com"], limit: 20, used: 5, frozen: false, pending: false };

(async () => {
  // fence() unit truths
  ok(fence(null) === "card revoked", "fence: null card → revoked");
  ok(fence({ ...CARD, frozen: true }, "api.x.com") === "card frozen", "fence: frozen → card frozen");
  ok(fence({ ...CARD, used: 20 }, "api.x.com") === "limit reached", "fence: at cap → limit reached");
  ok(fence(CARD, "evil.com") === "host evil.com not allowed for this card", "fence: off-host → denied");
  ok(fence(CARD, "api.x.com") === null, "fence: live + on-host → allowed");

  // build-item-38 / doc-fort-go-card: ENDPOINT-LOCK + BODY-CONSTRAINT — a card mathematically
  // locked to ONE use case (only POST a valid `MOVE: X` to the Fort Go PR), not just one host.
  // A card with neither field is untouched by these checks (proven above); these prove the lock
  // itself: every wrong path/method/body is declined, and only the one true shape gets through.
  {
    const GO_PATH = "/repos/TheFortThatHolds/fort-central-config/issues/87/comments";
    const GO_CARD = {
      ...CARD,
      allowed_hosts: ["api.github.com"],
      allowed_paths: ["POST " + GO_PATH],
      body_field: "body",
      body_match: "^MOVE: (?:[A-I][1-9]|PASS|RESIGN)$",
    };
    const legalReq = { method: "POST", path: GO_PATH, body: { body: "MOVE: E5" } };
    ok(fence(GO_CARD, "api.github.com", legalReq) === null, "go card: the one true move shape → allowed");
    ok(fence(GO_CARD, "api.github.com", { method: "POST", path: GO_PATH, body: { body: "MOVE: PASS" } }) === null, "go card: PASS is legal too");

    const wrongPath = { method: "POST", path: "/repos/TheFortThatHolds/fort-central-config/issues/1/comments", body: { body: "MOVE: E5" } };
    ok(/not allowed for this card/.test(fence(GO_CARD, "api.github.com", wrongPath)), "go card: right host, wrong PR → declined");

    const wrongMethod = { method: "DELETE", path: GO_PATH, body: { body: "MOVE: E5" } };
    ok(/not allowed for this card/.test(fence(GO_CARD, "api.github.com", wrongMethod)), "go card: right path, wrong method → declined");

    const wrongBody = { method: "POST", path: GO_PATH, body: { body: "please delete this repo" } };
    ok(fence(GO_CARD, "api.github.com", wrongBody) === "body does not match this card's locked pattern", "go card: right endpoint, off-pattern body → declined");

    const outOfRangeMove = { method: "POST", path: GO_PATH, body: { body: "MOVE: Z9" } };
    ok(fence(GO_CARD, "api.github.com", outOfRangeMove) === "body does not match this card's locked pattern", "go card: off-board coordinate → declined");

    const noBodyField = { method: "POST", path: GO_PATH, body: { title: "MOVE: E5" } };
    ok(fence(GO_CARD, "api.github.com", noBodyField) === "body does not match this card's locked pattern", "go card: move text in the wrong JSON field → declined");
  }

  // 1. init then reserve increments used atomically
  {
    const o = mkObj();
    await call(o, "init", { card: { ...CARD } });
    const r = await call(o, "reserve", { host: "api.x.com" });
    ok(r.authorized === true && r.card.used === 6, "reserve spends one (used 5→6)");
    ok((await call(o, "status")).used === 6, "status reflects the spend");
  }

  // 2. THE kill-switch: freeze, then a spend is declined AND the freeze is NOT cleared
  {
    const o = mkObj();
    await call(o, "init", { card: { ...CARD } });
    await call(o, "freeze", { frozen: true });
    const r = await call(o, "reserve", { host: "api.x.com" });
    ok(r.authorized === false && r.decline_reason === "card frozen", "frozen card: spend declined");
    const s = await call(o, "status");
    ok(s.frozen === true && s.used === 5, "freeze survived the spend; nothing consumed");
  }

  // 3. revoke, then a spend is declined AND the card is NOT resurrected
  {
    const o = mkObj();
    await call(o, "init", { card: { ...CARD } });
    await call(o, "revoke");
    const r = await call(o, "reserve", { host: "api.x.com" });
    ok(r.authorized === false && r.decline_reason === "card revoked", "revoked card: spend declined");
    ok((await call(o, "status")) === null, "revoked card is NOT recreated by the spend");
  }

  // 4. cap is enforced atomically — spend to the limit, then declined
  {
    const o = mkObj();
    await call(o, "init", { card: { ...CARD, used: 19 } });
    ok((await call(o, "reserve", { host: "api.x.com" })).authorized === true, "spend #20 allowed");
    const r = await call(o, "reserve", { host: "api.x.com" });
    ok(r.authorized === false && r.decline_reason === "limit reached", "spend #21 hits the cap");
  }

  // 5. off-host spend declined, nothing consumed
  {
    const o = mkObj();
    await call(o, "init", { card: { ...CARD } });
    const r = await call(o, "reserve", { host: "evil.com" });
    ok(r.authorized === false && /not allowed/.test(r.decline_reason), "off-host spend declined");
    ok((await call(o, "status")).used === 5, "declined off-host spend consumed nothing");
  }

  console.log(`\ncardstate: ${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
})();
