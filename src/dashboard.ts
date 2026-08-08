// Copyright (c) 2026 PaySafe, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * PaySafe usage dashboard — a single self-contained HTML page served at
 * GET /dashboard. Security posture:
 *  - Zero external resources (no CDN scripts/fonts/images): a strict CSP with
 *    default-src 'none' can be applied, so even a stored-XSS foothold has
 *    nowhere to exfiltrate to.
 *  - The API key is entered by the user, held only in the page's memory (and
 *    optionally sessionStorage, which dies with the tab), sent solely as the
 *    X-API-Key header to GET /v1/usage. It is NEVER placed in the URL, so it
 *    can't leak via history, referrer headers, or server logs.
 *  - Read-only: the page calls one GET endpoint and renders counts. It cannot
 *    move funds, change plans, or mutate anything.
 */
export function dashboardHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PaySafe — Usage Dashboard</title>
<style>
  :root { color-scheme: dark; --bg:#0b0e14; --card:#141a24; --line:#232c3b; --fg:#e6edf3; --muted:#8b98a9; --accent:#4c8dff; --allow:#3fb950; --flag:#d29922; --block:#f85149; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
  .wrap { max-width:720px; margin:0 auto; padding:32px 20px 64px; }
  h1 { font-size:22px; margin:0 0 4px; }
  .sub { color:var(--muted); margin:0 0 24px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:20px; margin-bottom:16px; }
  label { display:block; color:var(--muted); font-size:13px; margin-bottom:6px; }
  input[type=password] { width:100%; padding:11px 12px; border-radius:8px; border:1px solid var(--line); background:#0d1017; color:var(--fg); font:inherit; }
  .row { display:flex; gap:10px; align-items:flex-end; }
  button { padding:11px 18px; border-radius:8px; border:0; background:var(--accent); color:#fff; font:inherit; font-weight:600; cursor:pointer; }
  button:disabled { opacity:.5; cursor:default; }
  .remember { display:flex; align-items:center; gap:7px; color:var(--muted); font-size:13px; margin-top:12px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; }
  .stat { background:#0d1017; border:1px solid var(--line); border-radius:10px; padding:14px; }
  .stat .n { font-size:26px; font-weight:700; }
  .stat .l { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
  .bar { display:flex; height:10px; border-radius:6px; overflow:hidden; background:#0d1017; margin:10px 0 14px; }
  .bar > span { display:block; }
  .legend { display:flex; gap:16px; flex-wrap:wrap; color:var(--muted); font-size:13px; }
  .dot { display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:6px; vertical-align:middle; }
  .muted { color:var(--muted); }
  .err { color:var(--block); font-size:14px; margin-top:10px; min-height:18px; }
  .hidden { display:none; }
  h2 { font-size:14px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); margin:0 0 12px; }
  code { background:#0d1017; padding:1px 5px; border-radius:4px; font-size:13px; }
  a { color:var(--accent); }
</style>
</head>
<body>
<div class="wrap">
  <h1>PaySafe Usage</h1>
  <p class="sub">Your scan activity, free-tier quota, and plan status. Read-only — your key stays in this browser.</p>

  <div class="card">
    <label for="key">API key (from <code>POST /v1/keys</code>)</label>
    <div class="row">
      <input id="key" type="password" placeholder="psk_..." autocomplete="off" spellcheck="false">
      <button id="go">View</button>
    </div>
    <label class="remember"><input id="remember" type="checkbox"> Remember for this browser tab only</label>
    <div id="err" class="err"></div>
  </div>

  <div id="out" class="hidden">
    <div class="card">
      <h2>Free tier</h2>
      <div class="grid">
        <div class="stat"><div class="n" id="fRemaining">–</div><div class="l">Free calls left</div></div>
        <div class="stat"><div class="n" id="fUsed">–</div><div class="l">Free calls used</div></div>
        <div class="stat"><div class="n" id="planName">–</div><div class="l">Plan</div></div>
      </div>
      <p class="muted" id="planExpiry" style="margin:12px 0 0"></p>
    </div>

    <div class="card">
      <h2>Scans</h2>
      <div class="grid">
        <div class="stat"><div class="n" id="sTotal">–</div><div class="l">Total scans</div></div>
        <div class="stat"><div class="n" id="sAllow" style="color:var(--allow)">–</div><div class="l">Allowed</div></div>
        <div class="stat"><div class="n" id="sFlag" style="color:var(--flag)">–</div><div class="l">Flagged</div></div>
        <div class="stat"><div class="n" id="sBlock" style="color:var(--block)">–</div><div class="l">Blocked</div></div>
      </div>
      <div class="bar" id="bar"></div>
      <div class="legend">
        <span><span class="dot" style="background:var(--allow)"></span>allow</span>
        <span><span class="dot" style="background:var(--flag)"></span>flag</span>
        <span><span class="dot" style="background:var(--block)"></span>block</span>
      </div>
    </div>

    <div class="card hidden" id="apCard">
      <h2>Human approvals — your decision telemetry</h2>
      <div class="grid">
        <div class="stat"><div class="n" id="apRequested">–</div><div class="l">Requested</div></div>
        <div class="stat"><div class="n" id="apApproved" style="color:var(--allow)">–</div><div class="l">Approved</div></div>
        <div class="stat"><div class="n" id="apDenied" style="color:var(--block)">–</div><div class="l">Denied</div></div>
        <div class="stat"><div class="n" id="apExpired" style="color:var(--flag)">–</div><div class="l">Expired undecided</div></div>
      </div>
      <p class="muted" id="apLatency" style="margin:12px 0 0"></p>
      <p class="muted" id="apOutcomes" style="margin:6px 0 0"></p>
      <p class="muted" style="margin:12px 0 0">Visible only to this key — never shared, never fed into a verdict. A shrinking recent median with a near-100% approval rate is the signature of drift toward rubber-stamping, especially next to not-delivered outcomes on approved payments.</p>
    </div>

    <div class="card">
      <h2>Account</h2>
      <p class="muted" id="acct"></p>
    </div>
  </div>

  <p class="sub" style="margin-top:24px">No key yet? <code>curl -X POST https://paysafe-agent.com/v1/keys</code> — first 100 scans free.</p>
</div>

<script>
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var keyInput = $("key"), go = $("go"), err = $("err"), out = $("out"), remember = $("remember");

  // Restore a key remembered for this tab (sessionStorage clears on tab close).
  try {
    var saved = sessionStorage.getItem("paysafe_key");
    if (saved) { keyInput.value = saved; remember.checked = true; load(); }
  } catch (e) {}

  function text(id, v) { $(id).textContent = v; }

  function load() {
    var key = keyInput.value.trim();
    err.textContent = "";
    if (!key) { err.textContent = "Enter your API key."; return; }
    go.disabled = true; go.textContent = "…";
    fetch("/v1/usage", { headers: { "X-API-Key": key } })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (res) {
        go.disabled = false; go.textContent = "View";
        if (!res.ok) { out.classList.add("hidden"); err.textContent = (res.j && res.j.error) || "Request failed."; return; }
        try {
          if (remember.checked) sessionStorage.setItem("paysafe_key", key);
          else sessionStorage.removeItem("paysafe_key");
        } catch (e) {}
        render(res.j);
      })
      .catch(function () { go.disabled = false; go.textContent = "View"; err.textContent = "Network error."; });
  }

  function render(d) {
    var ft = d.free_tier || {}, sc = d.scans || {}, pl = d.plan || {}, ac = d.account || {};
    text("fRemaining", ft.remaining != null ? ft.remaining : "–");
    text("fUsed", ft.used != null ? ft.used : "–");
    text("planName", pl.name || "–");
    text("planExpiry", pl.expires_at ? ("Renews/expires " + new Date(pl.expires_at).toLocaleDateString() + " · " + (pl.price_per_scan || "") + "/scan") : ("Per-scan price " + (pl.price_per_scan || "")));
    text("sTotal", sc.total || 0);
    text("sAllow", sc.allow || 0);
    text("sFlag", sc.flag || 0);
    text("sBlock", sc.block || 0);

    var total = sc.total || 0, bar = $("bar");
    while (bar.firstChild) bar.removeChild(bar.firstChild);
    if (total > 0) {
      [["allow", "--allow"], ["flag", "--flag"], ["block", "--block"]].forEach(function (p) {
        var seg = document.createElement("span");
        seg.style.width = ((sc[p[0]] || 0) / total * 100) + "%";
        seg.style.background = "var(" + p[1] + ")";
        bar.appendChild(seg);
      });
    } else {
      var empty = document.createElement("span");
      empty.style.width = "100%"; empty.style.background = "#232c3b";
      bar.appendChild(empty);
    }

    var ap = d.approvals || {};
    var apCard = $("apCard");
    if (ap.configured || ap.requested > 0) {
      text("apRequested", ap.requested || 0);
      text("apApproved", ap.approved || 0);
      text("apDenied", ap.denied || 0);
      text("apExpired", ap.expired || 0);
      var lat = ap.decision_latency_ms;
      var fmtMs = function (ms) { return ms >= 60000 ? Math.round(ms / 60000) + "m" : ms >= 1000 ? Math.round(ms / 1000) + "s" : ms + "ms"; };
      var latLine = lat ? ("Decision latency: median " + fmtMs(lat.median) + " · p90 " + fmtMs(lat.p90) + " over " + lat.count + " decision(s)") : "No decisions recorded yet.";
      if (ap.recent && ap.baseline) {
        latLine += " — recent " + ap.recent.count + ": median " + fmtMs(ap.recent.median_latency_ms) + " at " + Math.round(ap.recent.approval_rate * 100) + "% approved; earlier " + ap.baseline.count + ": median " + fmtMs(ap.baseline.median_latency_ms) + " at " + Math.round(ap.baseline.approval_rate * 100) + "% approved";
      }
      text("apLatency", latLine);
      var oc = ap.approved_outcomes || {};
      text("apOutcomes", "Approved payments then reported: " + (oc.delivered || 0) + " delivered · " + (oc.not_delivered || 0) + " not delivered · " + (oc.partial || 0) + " partial · " + (oc.wrong_content || 0) + " wrong content · " + (oc.unreported || 0) + " unreported");
      apCard.classList.remove("hidden");
    } else {
      apCard.classList.add("hidden");
    }

    var created = ac.created_at ? new Date(ac.created_at).toLocaleDateString() : "—";
    var last = ac.last_used_at ? new Date(ac.last_used_at).toLocaleString() : "never";
    text("acct", "Agent: " + (ac.agent_id || "—") + "  ·  Key created " + created + "  ·  Last scan " + last);
    out.classList.remove("hidden");
  }

  go.addEventListener("click", load);
  keyInput.addEventListener("keydown", function (e) { if (e.key === "Enter") load(); });
})();
</script>
</body>
</html>`;
}
