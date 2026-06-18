// Fort Card — transactional email via Resend. OPTIONAL and off by default, exactly like billing:
// set the Worker secret RESEND_KEY (and the var WELCOME_FROM, e.g. "Fort Card <hello@yourdomain>")
// to turn emails on. Unset = silently skipped, so self-host and un-configured instances never try to
// send. The key is a Worker secret — never in the repo, never in a tenant vault, never agent-reachable
// (same posture as STRIPE_KEY).
//
//   secret RESEND_KEY     your Resend API key (email ON iff set)
//   var    WELCOME_FROM   From header — a verified Resend sender, e.g. "Fort Card <hello@yourdomain.com>"

const ESC = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const fmtDate = (ts) => { try { return ts ? new Date(ts * 1000).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" }) : null; } catch { return null; } };

export function emailConfigured(env) { return !!env.RESEND_KEY; }
// kept for back-compat with the welcome-only call site
export function welcomeConfigured(env) { return !!env.RESEND_KEY; }

// One shared sender. Best-effort: returns {sent:false,reason} instead of throwing, so a Resend hiccup
// never breaks a billing flow. Wraps the whole thing in a branded shell.
async function send(env, { to, subject, heading, bodyHtml, bodyText }) {
  if (!env.RESEND_KEY) return { sent: false, reason: "email off (no RESEND_KEY)" };
  if (!to) return { sent: false, reason: "no recipient email" };
  const from = env.WELCOME_FROM || "Fort Card <onboarding@resend.dev>";
  const html = `<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:520px;margin:0 auto;color:#2c251c;line-height:1.55">
  <h1 style="font-size:22px;margin:0 0 12px">${heading}</h1>
  ${bodyHtml}
  <p style="color:#9a8f7d;font-size:12px;margin:28px 0 0">Fort Card · The Fort That Holds</p>
</div>`;
  const text = bodyText + "\n\nFort Card · The Fort That Holds";
  try {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: "Bearer " + env.RESEND_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({ from, to, subject, html, text }),
    });
    if (r.status >= 400) { const b = await r.text().catch(() => ""); return { sent: false, reason: "resend " + r.status + ": " + b.slice(0, 200) }; }
    const b = await r.json().catch(() => ({}));
    return { sent: true, id: b.id || null };
  } catch (e) {
    return { sent: false, reason: (e && e.message) || "send failed" };
  }
}

const btn = (href, label) => `<p style="margin:0 0 18px"><a href="${ESC(href)}" style="display:inline-block;background:#d9943f;color:#1d1812;text-decoration:none;font-weight:600;padding:12px 20px;border-radius:10px">${label}</a></p>`;

// Welcome + thank-you on a new subscription. The one-tap cancel path (the wallet /app) is in the very
// first email, so the cancellation route is never hidden.
export function sendWelcomeEmail(env, { to, space, origin }) {
  const manage = origin + "/app";
  return send(env, {
    to,
    subject: "Welcome to Fort Card — your wallet is live",
    heading: `Welcome to Fort <span style="color:#d9943f">Card</span> 🏰`,
    bodyHtml:
      `<p style="margin:0 0 14px">Thank you for your order. Your sealed credential wallet is live — store your keys, issue capped cards, and approve every agent request right from your phone. Your agents spend your keys without ever seeing them.</p>` +
      btn(manage, "Open your wallet") +
      `<p style="color:#6b6155;font-size:14px;margin:0 0 4px">Need to step away? You can <a href="${ESC(manage)}" style="color:#b87333">cancel anytime</a> — one tap at the bottom of your wallet. You keep full access through the period you've already paid for, then it simply lapses. No phone calls, no maze, no dark patterns.</p>`,
    bodyText:
      "Thank you for your order — your wallet is live: " + manage +
      "\n\nYour agents spend your keys without ever seeing them. Store keys, issue capped cards, approve every request from your phone." +
      "\n\nCancel anytime: one tap at the bottom of your wallet (" + manage + "). You keep full access through the period you've paid for, then it lapses. No phone calls, no maze.",
  });
}

// Cancellation confirmation. States plainly that it's scheduled, the exact date access ends, and that
// they keep everything until then — plus a one-tap Resume link in case it was a mistake.
export function sendCancelEmail(env, { to, space, origin, current_period_end }) {
  const manage = origin + "/app";
  const end = fmtDate(current_period_end);
  return send(env, {
    to,
    subject: "Your Fort Card subscription is set to cancel",
    heading: `Cancellation confirmed`,
    bodyHtml:
      `<p style="margin:0 0 14px">Your Fort Card subscription is scheduled to end${end ? ` on <b>${ESC(end)}</b>` : ""}. You keep full access until then — nothing changes until the period you've already paid for runs out. We won't charge you again.</p>` +
      `<p style="margin:0 0 14px">Changed your mind? You can turn renewal back on any time before then — no new charge, nothing lost.</p>` +
      btn(manage, "Resume subscription") +
      `<p style="color:#6b6155;font-size:14px;margin:0 0 4px">Thank you for having trusted Fort Card with your keys.</p>`,
    bodyText:
      "Your Fort Card subscription is scheduled to end" + (end ? " on " + end : "") + "." +
      "\n\nYou keep full access until then — nothing changes until the period you've already paid for runs out, and we won't charge you again." +
      "\n\nChanged your mind? Resume any time before then (no new charge): " + manage +
      "\n\nThank you for having trusted Fort Card with your keys.",
  });
}

// Resume confirmation — the mirror of the cancel email.
export function sendResumeEmail(env, { to, space, origin, current_period_end }) {
  const manage = origin + "/app";
  const renews = fmtDate(current_period_end);
  return send(env, {
    to,
    subject: "Your Fort Card subscription is active again",
    heading: `You're all set — subscription resumed`,
    bodyHtml:
      `<p style="margin:0 0 14px">Welcome back. Your Fort Card subscription will keep renewing as normal${renews ? ` — next renewal <b>${ESC(renews)}</b>` : ""}. Nothing was interrupted.</p>` +
      btn(manage, "Open your wallet"),
    bodyText:
      "Welcome back. Your Fort Card subscription will keep renewing as normal" + (renews ? " — next renewal " + renews : "") + ". Nothing was interrupted." +
      "\n\nOpen your wallet: " + manage,
  });
}

// A quieter secondary button — used for the download/delete paths so they never out-shout the
// "re-up / keep my data" action.
const btn2 = (href, label, danger) =>
  `<p style="margin:0 0 12px"><a href="${ESC(href)}" style="display:inline-block;background:transparent;color:${danger ? "#a23b2d" : "#6b6155"};text-decoration:none;font-weight:600;padding:10px 18px;border:1px solid ${danger ? "#d8b4ad" : "#d8cfc0"};border-radius:10px">${label}</a></p>`;

// Subscription LAPSED — locked out, but the data survives a grace window. The email carries all three
// doors: re-up, download your data, or delete it now. The download/delete links are SIGNED and work
// without logging in (the customer is locked out — the token is the auth). States the exact deletion
// date. `purge_at` is epoch ms (the grace deadline).
export function sendLapseEmail(env, { to, space, origin, downloadUrl, deleteUrl, purge_at }) {
  const manage = origin + "/app";
  const end = fmtDate(purge_at ? Math.floor(purge_at / 1000) : null);
  return send(env, {
    to,
    subject: "Your Fort Card is locked — data kept until " + (end || "your grace period ends"),
    heading: `Your Fort Card is locked`,
    bodyHtml:
      `<p style="margin:0 0 14px">Your subscription didn't renew, so your wallet is locked and your cards have stopped working. <b>Your data is safe</b> — we keep everything${end ? ` until <b>${ESC(end)}</b>` : " for 30 days"}, then it's permanently deleted.</p>` +
      `<p style="margin:0 0 14px">Pick up exactly where you left off:</p>` +
      btn(manage, "Re-up & unlock my wallet") +
      `<p style="margin:0 0 8px;color:#6b6155;font-size:14px">Or, while you decide:</p>` +
      btn2(downloadUrl, "Download my data") +
      btn2(deleteUrl, "Delete my data now", true) +
      `<p style="color:#6b6155;font-size:13px;margin:14px 0 0">Secret values are never included in the download — the wallet can't read them. Deleting is permanent and can't be undone.</p>`,
    bodyText:
      "Your Fort Card subscription didn't renew, so your wallet is locked. Your data is safe" + (end ? " until " + end : " for 30 days") + ", then it's permanently deleted." +
      "\n\nRe-up & unlock: " + manage +
      "\nDownload my data: " + downloadUrl +
      "\nDelete my data now: " + deleteUrl +
      "\n\nSecret values are never included in the download. Deleting is permanent.",
  });
}

// 7-day warning before the grace window closes and the data is permanently deleted. Same three doors.
export function sendPurgeReminderEmail(env, { to, space, origin, downloadUrl, deleteUrl, purge_at }) {
  const manage = origin + "/app";
  const end = fmtDate(purge_at ? Math.floor(purge_at / 1000) : null);
  return send(env, {
    to,
    subject: "Last chance — your Fort Card data is deleted " + (end || "soon"),
    heading: `Your data is deleted ${end ? "on " + end : "soon"}`,
    bodyHtml:
      `<p style="margin:0 0 14px">Heads up: your Fort Card has been locked for a while, and on <b>${ESC(end || "your grace deadline")}</b> everything in your wallet is <b>permanently deleted</b> — secrets, cards, and your statement.</p>` +
      `<p style="margin:0 0 14px">If you want it back, re-up before then and nothing is lost:</p>` +
      btn(manage, "Re-up & keep everything") +
      `<p style="margin:0 0 8px;color:#6b6155;font-size:14px">Otherwise:</p>` +
      btn2(downloadUrl, "Download my data") +
      btn2(deleteUrl, "Delete my data now", true),
    bodyText:
      "Your Fort Card data is permanently deleted on " + (end || "your grace deadline") + " — secrets, cards, statement." +
      "\n\nRe-up & keep everything: " + manage +
      "\nDownload my data: " + downloadUrl +
      "\nDelete my data now: " + deleteUrl,
  });
}
