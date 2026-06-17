// fort-card-site — the public landing page for the Fort Card, served on its own subdomain.
// Routes:  /              -> the landing page (LinkedIn-pointable)
//          /card-demo.mjs -> the runnable demo file (so visitors can curl + run it)
// The demo source is embedded base64 (no escaping headaches) and decoded on the way out.

const DEMO_B64 = "IyEvdXNyL2Jpbi9lbnYgbm9kZQovLyBGb3J0IENhcmQg4oCUIGEgMi1taW51dGUgZGVtbyBvZiAiaXNzdWUgY3JlZGVudGlhbHMgbGlrZSBDUkVESVQgQ0FSRFMsIG5vdCBrZXlzLiIKLy8KLy8gVGhlIGlkZWE6IGEgcm9ib3QvYWdlbnQgc2hvdWxkIE5FVkVSIGhvbGQgeW91ciByZWFsIEFQSSBrZXkuIEl0IGhvbGRzIGEgQ0FSRCDigJQgYSB1c2VsZXNzCi8vIHBvaW50ZXIgdGhhdCdzIGxvY2tlZCB0byBPTkUgd2Vic2l0ZSwgY2FwcGVkIHRvIE4gdXNlcywgYW5kIGZyZWV6YWJsZSB3aXRoIG9uZSB0YXAuIFRoZQovLyBWQVVMVCBob2xkcyB0aGUgcmVhbCBrZXkgYW5kIG1ha2VzIHRoZSBjYWxsIG9uIHRoZSBjYXJkJ3MgYmVoYWxmLCByZXR1cm5pbmcgb25seSB0aGUKLy8gcmVzdWx0LiBTdGVhbCB0aGUgY2FyZCDihpIgeW91IGdldCBub3RoaW5nLiBTdGVhbCB0aGUga2V5IOKGkiB5b3UncmUgd2lwZWQgb3V0LiBXZSB1c2UgY2FyZHMuCi8vCi8vIFJ1bnMgb24gcGxhaW4gTm9kZSAxOCsgKG5vIGluc3RhbGwsIG5vIENsb3VkZmxhcmUgYWNjb3VudCkuIEJyaW5nIHlvdXIgb3duIEFQSSB0b2tlbi4KLy8KLy8gICBub2RlIGNhcmQtZGVtby5tanMgPEFQSV9UT0tFTj4gW0FMTE9XRURfSE9TVF0gW1RFU1RfVVJMXSBbSEVBREVSX1NDSEVNRV0KLy8KLy8gRGVmYXVsdCBleGFtcGxlIHVzZXMgYSBHaXRIdWIgdG9rZW46Ci8vICAgbm9kZSBjYXJkLWRlbW8ubWpzIGdocF95b3VydG9rZW4gYXBpLmdpdGh1Yi5jb20gaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS91c2VyIHRva2VuCi8vICAgKGNsYXNzaWMgR2l0SHViIFBBVHMgdXNlIHRoZSAidG9rZW4iIHNjaGVtZTsgbW9zdCBvdGhlciBBUElzIHVzZSAiQmVhcmVyIikKCmltcG9ydCB7IHdlYmNyeXB0byBhcyBjcnlwdG8gfSBmcm9tICJub2RlOmNyeXB0byI7CgovLyDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIAgVEhFIFZBVUxUIChob2xkcyByZWFsIGtleXMsIGVuY3J5cHRlZCkg4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSACi8vIFRoZSByZWFsIGtleSBnb2VzIGluIGhlcmUgYW5kIG5ldmVyIGNvbWVzIGJhY2sgb3V0LiBPbmx5IHRoZSB2YXVsdCBjYW4gcmVhZCBpdC4KY29uc3QgTUFTVEVSID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5nZW5lcmF0ZUtleSh7IG5hbWU6ICJBRVMtR0NNIiwgbGVuZ3RoOiAyNTYgfSwgdHJ1ZSwgWyJlbmNyeXB0IiwgImRlY3J5cHQiXSk7CmNvbnN0IFZBVUxUID0gbmV3IE1hcCgpOwphc3luYyBmdW5jdGlvbiBzdG9yZVNlY3JldChuYW1lLCB2YWx1ZSkgewogIGNvbnN0IGl2ID0gY3J5cHRvLmdldFJhbmRvbVZhbHVlcyhuZXcgVWludDhBcnJheSgxMikpOwogIGNvbnN0IGN0ID0gYXdhaXQgY3J5cHRvLnN1YnRsZS5lbmNyeXB0KHsgbmFtZTogIkFFUy1HQ00iLCBpdiB9LCBNQVNURVIsIG5ldyBUZXh0RW5jb2RlcigpLmVuY29kZSh2YWx1ZSkpOwogIFZBVUxULnNldChuYW1lLCB7IGl2LCBjdCB9KTsKfQphc3luYyBmdW5jdGlvbiByZWFkU2VjcmV0SW50ZXJuYWwobmFtZSkgewogIC8vIElOVEVSTkFMIHRvIHRoZSB2YXVsdCDigJQgbmV2ZXIgcmV0dXJuZWQgdG8gYSBjYWxsZXIsIG5ldmVyIGxvZ2dlZC4KICBjb25zdCBzID0gVkFVTFQuZ2V0KG5hbWUpOwogIGlmICghcykgdGhyb3cgbmV3IEVycm9yKCJubyBzdWNoIHNlY3JldCIpOwogIHJldHVybiBuZXcgVGV4dERlY29kZXIoKS5kZWNvZGUoYXdhaXQgY3J5cHRvLnN1YnRsZS5kZWNyeXB0KHsgbmFtZTogIkFFUy1HQ00iLCBpdjogcy5pdiB9LCBNQVNURVIsIHMuY3QpKTsKfQoKLy8g4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSAIFRIRSBDQVJEUyAocG9pbnRlcnMgYXQgc2VjcmV0cywgd2l0aCBsaW1pdHMpIOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgOKUgApjb25zdCBDQVJEUyA9IG5ldyBNYXAoKTsKZnVuY3Rpb24gaXNzdWVDYXJkKHsgbmFtZSwgc2VjcmV0LCBhbGxvd2VkSG9zdHMsIGxpbWl0LCBoZWFkZXJTY2hlbWUgPSAiQmVhcmVyIiB9KSB7CiAgY29uc3QgaWQgPSAiY2FyZF8iICsgY3J5cHRvLnJhbmRvbVVVSUQoKS5zbGljZSgwLCA4KTsKICBDQVJEUy5zZXQoaWQsIHsgaWQsIG5hbWUsIHNlY3JldCwgYWxsb3dlZEhvc3RzLCBsaW1pdCwgdXNlZDogMCwgZnJvemVuOiBmYWxzZSwgaGVhZGVyU2NoZW1lIH0pOwogIHJldHVybiBpZDsKfQpmdW5jdGlvbiBmcmVlemVDYXJkKGlkLCBmcm96ZW4gPSB0cnVlKSB7IENBUkRTLmdldChpZCkuZnJvemVuID0gZnJvemVuOyB9CgovLyDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIAgVEhFIEFVVEhPUklaQVRJT04gKElTTy04NTgzIGluIHNwaXJpdCkg4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSACi8vIFByZXNlbnQgYSBjYXJkICsgYSByZXF1ZXN0LiBDaGVjayB0aGUgcnVsZXMuIElmIE9LLCB0aGUgVkFVTFQgaW5qZWN0cyB0aGUgcmVhbCBrZXkgYW5kCi8vIG1ha2VzIHRoZSBjYWxsIOKAlCBhbmQgcmV0dXJucyBPTkxZIHRoZSByZXNwb25zZS4gVGhlIGNhbGxlciBuZXZlciBzZWVzIHRoZSBrZXkuCmFzeW5jIGZ1bmN0aW9uIHVzZUNhcmQoaWQsIHJlcXVlc3QpIHsKICBjb25zdCBjID0gQ0FSRFMuZ2V0KGlkKTsKICBpZiAoIWMpIHJldHVybiB7IGF1dGhvcml6ZWQ6IGZhbHNlLCBkZWNsaW5lOiAibm8gc3VjaCBjYXJkIiB9OwogIGlmIChjLmZyb3plbikgcmV0dXJuIHsgYXV0aG9yaXplZDogZmFsc2UsIGRlY2xpbmU6ICJjYXJkIGZyb3plbiIgfTsKICBpZiAoYy5saW1pdCAhPSBudWxsICYmIGMudXNlZCA+PSBjLmxpbWl0KSByZXR1cm4geyBhdXRob3JpemVkOiBmYWxzZSwgZGVjbGluZTogImxpbWl0IHJlYWNoZWQiIH07CiAgbGV0IGhvc3Q7CiAgdHJ5IHsgaG9zdCA9IG5ldyBVUkwocmVxdWVzdC51cmwpLmhvc3Q7IH0gY2F0Y2ggeyByZXR1cm4geyBhdXRob3JpemVkOiBmYWxzZSwgZGVjbGluZTogImJhZCB1cmwiIH07IH0KICBpZiAoIWMuYWxsb3dlZEhvc3RzLmluY2x1ZGVzKGhvc3QpKSByZXR1cm4geyBhdXRob3JpemVkOiBmYWxzZSwgZGVjbGluZTogYGhvc3QgJHtob3N0fSBub3QgYWxsb3dlZCBmb3IgdGhpcyBjYXJkYCB9OwoKICBjb25zdCBrZXkgPSBhd2FpdCByZWFkU2VjcmV0SW50ZXJuYWwoYy5zZWNyZXQpOyAvLyB0aGUgb25seSBwbGFjZSB0aGUga2V5IGJlY29tZXMgcmVhbAogIGNvbnN0IHJlc3AgPSBhd2FpdCBmZXRjaChyZXF1ZXN0LnVybCwgewogICAgbWV0aG9kOiByZXF1ZXN0Lm1ldGhvZCB8fCAiR0VUIiwKICAgIGhlYWRlcnM6IHsgQXV0aG9yaXphdGlvbjogYCR7Yy5oZWFkZXJTY2hlbWV9ICR7a2V5fWAsICJVc2VyLUFnZW50IjogImZvcnQtY2FyZC1kZW1vIiwgLi4uKHJlcXVlc3QuaGVhZGVycyB8fCB7fSkgfSwKICB9KTsKICBjb25zdCB0ZXh0ID0gYXdhaXQgcmVzcC50ZXh0KCk7CiAgbGV0IGJvZHk7IHRyeSB7IGJvZHkgPSBKU09OLnBhcnNlKHRleHQpOyB9IGNhdGNoIHsgYm9keSA9IHRleHQ7IH0KICBjLnVzZWQrKzsKICByZXR1cm4geyBhdXRob3JpemVkOiB0cnVlLCBzdGF0dXM6IHJlc3Auc3RhdHVzLCBib2R5LCBjYXJkOiB7IGlkLCB1c2VkOiBjLnVzZWQsIHJlbWFpbmluZzogYy5saW1pdCAhPSBudWxsID8gYy5saW1pdCAtIGMudXNlZCA6IG51bGwgfSB9Owp9CgovLyDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIDilIAgVEhFIERFTU8g4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSA4pSACmNvbnN0IFssICwgVE9LRU4sIEFMTE9XRURfSE9TVCA9ICJhcGkuZ2l0aHViLmNvbSIsIFRFU1RfVVJMID0gImh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vdXNlciIsIFNDSEVNRSA9ICJCZWFyZXIiXSA9IHByb2Nlc3MuYXJndjsKaWYgKCFUT0tFTikgewogIGNvbnNvbGUuZXJyb3IoCiAgICAiVXNhZ2U6IG5vZGUgY2FyZC1kZW1vLm1qcyA8QVBJX1RPS0VOPiBbQUxMT1dFRF9IT1NUXSBbVEVTVF9VUkxdIFtIRUFERVJfU0NIRU1FXVxuIiArCiAgICAgICJHaXRIdWIgZXhhbXBsZTogbm9kZSBjYXJkLWRlbW8ubWpzIGdocF94eHggYXBpLmdpdGh1Yi5jb20gaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS91c2VyIHRva2VuIiwKICApOwogIHByb2Nlc3MuZXhpdCgxKTsKfQpjb25zdCBwID0gKHMpID0+IGNvbnNvbGUubG9nKHMpOwoKcCgiXG7wn5SQIDEuIExvY2sgdGhlIHJlYWwga2V5IGluIHRoZSB2YXVsdCAoZW5jcnlwdGVkKS4gTm90aGluZyBvdXRzaWRlIHRoZSB2YXVsdCBldmVyIHNlZXMgaXQgYWdhaW4uIik7CmF3YWl0IHN0b3JlU2VjcmV0KCJteS1rZXkiLCBUT0tFTik7CgpwKGDwn5KzIDIuIElzc3VlIGEgQ0FSRCDigJQgbG9ja2VkIHRvICR7QUxMT1dFRF9IT1NUfSwgbWF4IDMgdXNlcywgZnJlZXphYmxlLiBUSElTIGlzIGFsbCB0aGUgcm9ib3QgZ2V0czpgKTsKY29uc3QgY2FyZCA9IGlzc3VlQ2FyZCh7IG5hbWU6ICJkZW1vIGNhcmQiLCBzZWNyZXQ6ICJteS1rZXkiLCBhbGxvd2VkSG9zdHM6IFtBTExPV0VEX0hPU1RdLCBsaW1pdDogMywgaGVhZGVyU2NoZW1lOiBTQ0hFTUUgfSk7CnAoYCAgICAgICR7Y2FyZH0gICDihpAgaGFuZCB0aGlzIHRvIHRoZSBhZ2VudCwgbmV2ZXIgdGhlIGtleWApOwoKcCgiXG7wn6SWIDMuIFRoZSBhZ2VudCAoaG9sZGluZyBPTkxZIHRoZSBjYXJkIGlkKSBtYWtlcyBhIHJlYWwgYXV0aGVudGljYXRlZCBjYWxsOiIpOwpjb25zdCByMSA9IGF3YWl0IHVzZUNhcmQoY2FyZCwgeyB1cmw6IFRFU1RfVVJMIH0pOwpwKGAgICAgICDihpIgYXV0aG9yaXplZDoke3IxLmF1dGhvcml6ZWR9ICBzdGF0dXM6JHtyMS5zdGF0dXN9ICAke0pTT04uc3RyaW5naWZ5KHIxLmNhcmQpfWApOwpwKGAgICAgICByZWFsIHJlc3BvbnNlICh0cmltbWVkKTogJHtKU09OLnN0cmluZ2lmeShyMS5ib2R5KS5zbGljZSgwLCAyMDApfWApOwoKcCgiXG7wn5qrIDQuIFRoZSBhZ2VudCB0cmllcyB0byBzZW5kIHlvdXIga2V5IHNvbWV3aGVyZSBFTFNFICh0aGVmdCAvIGV4ZmlsIGF0dGVtcHQpOiIpOwpwKGAgICAgICDihpIgJHtKU09OLnN0cmluZ2lmeShhd2FpdCB1c2VDYXJkKGNhcmQsIHsgdXJsOiAiaHR0cHM6Ly9ldmlsLmV4YW1wbGUuY29tL3N0ZWFsIiB9KSl9YCk7CgpwKCJcbvCfp4ogNS4gWW91IEZSRUVaRSB0aGUgY2FyZDsgdGhlIGFnZW50IHRyaWVzIGFnYWluOiIpOwpmcmVlemVDYXJkKGNhcmQsIHRydWUpOwpwKGAgICAgICDihpIgJHtKU09OLnN0cmluZ2lmeShhd2FpdCB1c2VDYXJkKGNhcmQsIHsgdXJsOiBURVNUX1VSTCB9KSl9YCk7CgpwKCJcbuKchSBUaGUgYWdlbnQgbWFkZSBhIHJlYWwgY2FsbCBhbmQgTkVWRVIgc2F3IHRoZSBrZXkuIFRoZWZ0IGFuZCB0aGUgZnJvemVuIGNhcmQgd2VyZSBib3RoIGRlY2xpbmVkLiIpOwpwKCIgICBUaGF0J3MgYSBjcmVkaXQgY2FyZCwgbm90IGEga2V5LiBUaGUgd2hvbGUgcG9pbnQgaW4gb25lIHNjcmVlbi5cbiIpOwo=";

const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Fort Card — issue credentials like credit cards, not keys</title>
<meta name="description" content="Stop handing robots your API keys. Give them a card: locked to one site, capped, logged, freezable — useless the moment it leaks. A 2-minute runnable demo from The Fort That Holds.">
<meta name="theme-color" content="#14110e">
<meta property="og:type" content="website">
<meta property="og:title" content="Stop handing robots your keys. Issue cards.">
<meta property="og:description" content="A credential locked to one site, capped, logged, and freezable — useless the moment it leaks. Banks solved this 70 years ago; we taught it to API keys. Runnable in 2 minutes.">
<meta property="og:url" content="https://card.thefortthatholds.com">
<meta name="twitter:card" content="summary_large_image">
<style>
  :root{color-scheme:dark}
  *{box-sizing:border-box;margin:0;padding:0}
  body{font:16px/1.6 -apple-system,system-ui,Segoe UI,Roboto,sans-serif;background:#14110e;color:#efe7da;
    -webkit-font-smoothing:antialiased}
  .wrap{max-width:820px;margin:0 auto;padding:0 20px}
  a{color:#d9943f}
  .kicker{color:#9a8f7d;font-size:13px;letter-spacing:.18em;text-transform:uppercase}
  header{padding:72px 0 28px}
  h1{font-size:clamp(32px,6vw,52px);line-height:1.08;margin:14px 0 16px;letter-spacing:-.02em}
  h1 .c{color:#d9943f}
  .lede{font-size:clamp(17px,2.4vw,21px);color:#cdc2af;max-width:620px}
  .btns{margin-top:28px;display:flex;gap:12px;flex-wrap:wrap}
  .btn{display:inline-block;padding:13px 20px;border-radius:11px;font-weight:600;text-decoration:none;cursor:pointer;border:1px solid #3a342b}
  .btn.p{background:#b87333;color:#14110e;border-color:#b87333}
  .btn.g{background:transparent;color:#e8dcc8}
  section{padding:34px 0;border-top:1px solid #221d17}
  h2{font-size:13px;letter-spacing:.12em;text-transform:uppercase;color:#b8ad99;margin-bottom:18px}
  .vs{display:grid;grid-template-columns:1fr 1fr;gap:14px}
  @media(max-width:620px){.vs{grid-template-columns:1fr}}
  .card{background:#1a1610;border:1px solid #2c2620;border-radius:14px;padding:18px}
  .card h3{font-size:18px;margin-bottom:6px}
  .card.key{border-color:#5a2d2d}
  .card.key h3{color:#e07a5f}
  .card.cc{border-color:#3a4a2c}
  .card.cc h3{color:#9ccc6a}
  .card ul{list-style:none;margin-top:8px}
  .card li{padding:3px 0;color:#cdc2af;font-size:15px}
  .term{background:#0f0d0a;border:1px solid #2c2620;border-radius:14px;padding:18px;font:14px/1.7 ui-monospace,SFMono-Regular,Menlo,monospace;min-height:248px;white-space:pre-wrap;overflow:hidden}
  .term .ln{opacity:0;transform:translateY(4px);transition:all .25s}
  .term .ln.on{opacity:1;transform:none}
  .ok{color:#9ccc6a}.no{color:#e07a5f}.dim{color:#857b6b}.cy{color:#62b6c7}.cu{color:#d9943f}
  .steps{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
  @media(max-width:620px){.steps{grid-template-columns:1fr}}
  .step .n{color:#d9943f;font-weight:700;font-size:13px}
  .step p{color:#cdc2af;font-size:15px;margin-top:4px}
  pre.code{background:#0f0d0a;border:1px solid #2c2620;border-radius:12px;padding:16px;overflow-x:auto;font:13.5px/1.6 ui-monospace,monospace;color:#e8dcc8}
  .copy{margin-top:10px;font-size:13px;background:transparent;border:1px solid #3a342b;color:#b8ad99;border-radius:9px;padding:8px 12px;cursor:pointer}
  .note{color:#857b6b;font-size:14px;margin-top:10px}
  footer{padding:40px 0 64px;color:#857b6b;font-size:14px;border-top:1px solid #221d17;margin-top:10px}
  .big{font-size:clamp(20px,3vw,26px);color:#e8dcc8;line-height:1.35}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="kicker">The Fort That Holds</div>
    <h1>Stop handing robots <span class="c">your keys.</span><br>Give them a <span class="c">card.</span></h1>
    <p class="lede">An API key is your bank card <em>with the PIN written on it</em> — whoever holds it can do anything, forever. A Fort Card is locked to one site, capped, logged, and freezable. Useless the moment it leaks.</p>
    <div class="btns">
      <a class="btn p" onclick="runDemo()">▶ Watch the 20-second demo</a>
      <a class="btn g" href="#run">Run it yourself</a>
      <a class="btn g" href="https://github.com/TheFortThatHolds/fort-card" target="_blank" rel="noopener">★ Open source — fork it</a>
    </div>
  </header>

  <section>
    <h2>Key vs. Card</h2>
    <div class="vs">
      <div class="card key">
        <h3>🔑 A key</h3>
        <ul>
          <li>Possession = total power</li>
          <li>Works everywhere, forever</li>
          <li>No limit, no log, no undo</li>
          <li>Leaks once → game over</li>
        </ul>
      </div>
      <div class="card cc">
        <h3>💳 A card</h3>
        <ul>
          <li>Locked to one site (merchant-lock)</li>
          <li>Capped to N uses</li>
          <li>Every charge logged</li>
          <li>Freeze it with one tap</li>
          <li>Leaks → you shrug</li>
        </ul>
      </div>
    </div>
  </section>

  <section>
    <h2>See it (simulated)</h2>
    <div id="term" class="term"><span class="dim">click “Watch the demo” above ↑</span></div>
  </section>

  <section>
    <h2>How it works</h2>
    <div class="steps">
      <div class="step"><div class="n">01</div><p>The real key goes in a <b>vault</b> — encrypted, never handed back out.</p></div>
      <div class="step"><div class="n">02</div><p>The agent gets a <b>card</b>, not the key: locked to one host, capped, freezable.</p></div>
      <div class="step"><div class="n">03</div><p>It taps the card; the <b>vault</b> makes the call and returns only the answer. The agent never sees the key.</p></div>
    </div>
  </section>

  <section id="run">
    <h2>Run the real thing — 2 minutes, your own token</h2>
    <p class="lede" style="font-size:17px;margin-bottom:14px">No account, no install beyond Node. It hits a real API with your token, succeeds, then blocks a theft attempt and a frozen card — and never prints your key.</p>
    <pre class="code" id="cmd">curl -O https://card.thefortthatholds.com/card-demo.mjs
node card-demo.mjs YOUR_TOKEN api.github.com https://api.github.com/user token</pre>
    <button class="copy" onclick="copyCmd(this)">Copy</button>
    <p class="note">Swap in any bearer-token API. The token stays in the process and is never logged. <a href="/card-demo.mjs">View the demo source →</a></p>
  </section>

  <section>
    <p class="big">Banks solved “let someone spend on your behalf without handing over the vault” <b>70 years ago.</b> We just taught it to API keys — and made it speak the language AI agents already use.</p>
  </section>

  <footer>
    Open source (MIT) · <a href="https://github.com/TheFortThatHolds/fort-card" target="_blank" rel="noopener">github.com/TheFortThatHolds/fort-card</a> — read the vault, run your own.<br>
    A sovereign, MCP-native credential wallet — your keys, your infra, your rules.<br>
    <a href="https://thefortthatholds.com/legal.html">Terms, Privacy &amp; Eligibility</a> · available in the United States only.<br>
    © The Fort That Holds · issue cards, don’t hand out keys.
  </footer>
</div>

<script>
  var STEPS = [
    {t:'$ vault.store("cf-key")', c:''},
    {t:'  🔒 locked in the vault, encrypted — never returned', c:'dim'},
    {t:'', c:''},
    {t:'$ issue_card  →  card_9f2a', c:'cu'},
    {t:'  merchant-lock: api.cloudflare.com  ·  limit: 5  ·  freezable', c:'dim'},
    {t:'  (this is all the agent gets — never the key)', c:'dim'},
    {t:'', c:''},
    {t:'$ agent.use(card_9f2a)  →  api.cloudflare.com', c:'cy'},
    {t:'  ✓ 200 OK  ·  real response returned  ·  used 1/5', c:'ok'},
    {t:'  the agent never saw the key', c:'dim'},
    {t:'', c:''},
    {t:'$ agent.use(card_9f2a)  →  evil.example.com   (theft attempt)', c:'cy'},
    {t:'  ✗ DECLINED — host not allowed for this card', c:'no'},
    {t:'', c:''},
    {t:'$ freeze(card_9f2a)   then  agent.use(card_9f2a)', c:'cy'},
    {t:'  ✗ DECLINED — card frozen', c:'no'},
    {t:'', c:''},
    {t:'✅ real call made. key never exposed. theft + freeze bounced.', c:'ok'}
  ];
  function runDemo(){
    var term = document.getElementById('term');
    term.innerHTML = '';
    STEPS.forEach(function(s, i){
      var el = document.createElement('div');
      el.className = 'ln' + (s.c ? ' ' + s.c : '');
      el.textContent = s.t || ' ';
      term.appendChild(el);
      setTimeout(function(){ el.classList.add('on'); }, 230 * i);
    });
    term.scrollIntoView({behavior:'smooth', block:'center'});
  }
  function copyCmd(btn){
    navigator.clipboard.writeText(document.getElementById('cmd').textContent).then(function(){
      btn.textContent = 'Copied ✓';
    });
  }
</script>
</body>
</html>`;

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/card-demo.mjs") {
      // decode the embedded demo source to raw BYTES (not a re-encoded string) so its
      // UTF-8 (em-dashes, emoji) survives intact.
      const bytes = Uint8Array.from(atob(DEMO_B64), (ch) => ch.charCodeAt(0));
      return new Response(bytes, {
        headers: { "Content-Type": "text/javascript; charset=utf-8", "Cache-Control": "public, max-age=300" },
      });
    }
    if (url.pathname === "/" || url.pathname === "") {
      return new Response(PAGE, {
        headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "public, max-age=300" },
      });
    }
    return new Response("Not found", { status: 404 });
  },
};
