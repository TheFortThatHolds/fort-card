// readUpstreamBody (build-item-52): .text() silently corrupts a non-UTF8 upstream response
// (audio/mpeg, image/*, etc.) before the caller ever sees it -- invalid byte sequences get
// replaced with U+FFFD, unrecoverably. This proves json/text responses still decode exactly as
// before, and anything else round-trips byte-for-byte through base64 instead of being mangled.
// Run: node test/binary-charge.test.mjs
import { readUpstreamBody } from "../src/worker.js";

let pass = 0, fail = 0;
const ok = (c, m) => (c ? (pass++, console.log("  ✓ " + m)) : (fail++, console.error("  ✗ " + m)));

function fakeResp(contentType, bodyBytesOrText) {
  const isText = typeof bodyBytesOrText === "string";
  return {
    headers: { get: (h) => (h.toLowerCase() === "content-type" ? contentType : null) },
    async text() { return isText ? bodyBytesOrText : new TextDecoder().decode(bodyBytesOrText); },
    async arrayBuffer() {
      const bytes = isText ? new TextEncoder().encode(bodyBytesOrText) : bodyBytesOrText;
      return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    },
  };
}

(async () => {
  // 1. application/json still parses to a real object, exactly as before this change.
  {
    const r = await readUpstreamBody(fakeResp("application/json; charset=utf-8", '{"ok":true,"n":5}'));
    ok(typeof r === "object" && r.ok === true && r.n === 5, "json content-type parses to an object");
  }

  // 2. malformed JSON with a json content-type falls back to the raw text (unchanged behavior).
  {
    const r = await readUpstreamBody(fakeResp("application/json", "not actually json"));
    ok(r === "not actually json", "malformed json falls back to raw text");
  }

  // 3. text/plain stays as plain text.
  {
    const r = await readUpstreamBody(fakeResp("text/plain", "hello world"));
    ok(r === "hello world", "text/plain stays a plain string");
  }

  // 4. no content-type at all defaults to text (matches the old unconditional-text behavior).
  {
    const r = await readUpstreamBody(fakeResp("", "legacy behavior"));
    ok(r === "legacy behavior", "missing content-type defaults to text");
  }

  // 5. THE ACTUAL BUG: a binary response (ElevenLabs-shaped audio/mpeg) round-trips byte-for-byte
  // via base64 instead of being corrupted by .text()'s UTF-8 decoding.
  {
    // bytes deliberately include values that are NOT valid standalone UTF-8 (0xFF, 0x80) --
    // the exact class of byte that .text() would replace with U+FFFD and never recover.
    const original = new Uint8Array([0x49, 0x44, 0x33, 0xff, 0x80, 0x00, 0x7f, 0xfe, 0x01, 0x02, 0x03]);
    const r = await readUpstreamBody(fakeResp("audio/mpeg", original));
    ok(r && r._binary === true, "binary response is flagged _binary");
    ok(r && r.content_type === "audio/mpeg", "binary response keeps its real content-type");
    const decoded = r ? Uint8Array.from(atob(r.base64), (c) => c.charCodeAt(0)) : null;
    ok(decoded && decoded.length === original.length && decoded.every((b, i) => b === original[i]),
      "binary bytes survive round-trip byte-for-byte through base64");
  }

  // 6. image/* (the OpenAI-cover-style case) is treated the same as audio -- binary-safe, not
  // just an ElevenLabs special case.
  {
    const original = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0xff, 0xd8, 0xff]); // PNG-ish magic + junk
    const r = await readUpstreamBody(fakeResp("image/png", original));
    const decoded = r ? Uint8Array.from(atob(r.base64), (c) => c.charCodeAt(0)) : null;
    ok(r && r._binary === true && decoded && decoded.length === original.length,
      "image/png also treated as binary, round-trips intact");
  }

  console.log(`\nbinary-charge: ${pass} passed, ${fail} failed`);
  if (fail) process.exit(1);
})();
