// Copyright (c) 2026 PaySafe, LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
/**
 * PaySafe OWNER dashboard — served at GET /admin. Same interface and security
 * posture as the user dashboard (src/dashboard.ts):
 *  - Zero external resources; strict CSP (default-src 'none') applies.
 *  - The admin key is entered by the owner, held in page memory (optionally
 *    sessionStorage), sent only as the X-API-Key header. Never in the URL.
 *  - Read-only: GET /v1/admin/stats (aggregates) and GET /v1/audit/verify
 *    (chain integrity — already a public endpoint). Nothing can be mutated.
 * Access: only the key whose SHA-256 matches ADMIN_KEY_SHA256 gets data;
 * everyone else sees the same empty form as /dashboard does.
 */
export function adminDashboardHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PaySafe — Owner Dashboard</title>
<style>
  :root { color-scheme: dark; --bg:#0b0e14; --card:#141a24; --line:#232c3b; --fg:#e6edf3; --muted:#8b98a9; --accent:#4c8dff; --allow:#3fb950; --flag:#d29922; --block:#f85149; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
  .wrap { max-width:840px; margin:0 auto; padding:32px 20px 64px; }
  h1 { font-size:22px; margin:0 0 4px; }
  .sub { color:var(--muted); margin:0 0 24px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:20px; margin-bottom:16px; }
  label { display:block; color:var(--muted); font-size:13px; margin-bottom:6px; }
  input[type=password] { width:100%; padding:11px 12px; border-radius:8px; border:1px solid var(--line); background:#0d1017; color:var(--fg); font:inherit; }
  .row { display:flex; gap:10px; align-items:flex-end; }
  button { padding:11px 18px; border-radius:8px; border:0; background:var(--accent); color:#fff; font:inherit; font-weight:600; cursor:pointer; }
  button:disabled { opacity:.5; cursor:default; }
  button.ghost { background:#0d1017; border:1px solid var(--line); color:var(--fg); font-weight:500; }
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
  code { background:#0d1017; padding:1px 5px; border-radius:4px; font-size:13px; word-break:break-all; }
  .chart { display:flex; align-items:flex-end; gap:2px; height:96px; margin:6px 0 4px; }
  .chart > div { flex:1; background:#22314a; border-radius:2px 2px 0 0; min-height:2px; position:relative; }
  .chart > div > i { display:block; position:absolute; bottom:0; left:0; right:0; background:var(--block); border-radius:0 0 0 0; }
  .axis { display:flex; justify-content:space-between; color:var(--muted); font-size:12px; }
  table { width:100%; border-collapse:collapse; font-size:14px; }
  td { padding:6px 0; border-top:1px solid var(--line); }
  td:last-child { text-align:right; color:var(--muted); }
  .ok { color:var(--allow); } .bad { color:var(--block); }
</style>
</head>
<body>
<div class="wrap">
  <h1>PaySafe Owner Dashboard</h1>
  <p class="sub">All-time scan activity across every key, sourced from the tamper-evident audit log. Read-only.</p>

  <div class="card">
    <label for="key">Owner API key</label>
    <div class="row">
      <input id="key" type="password" placeholder="psk_..." autocomplete="off" spellcheck="false">
      <button id="go">View</button>
    </div>
    <label class="remember"><input id="remember" type="checkbox"> Remember for this browser tab only</label>
    <div id="err" class="err"></div>
  </div>

  <div id="out" class="hidden">
    <div class="card">
      <h2>All-time scans (audit log)</h2>
      <div class="grid">
        <div class="stat"><div class="n" id="aTotal">–</div><div class="l">Total scans</div></div>
        <div class="stat"><div class="n" id="aAllow" style="color:var(--allow)">–</div><div class="l">Allowed</div></div>
        <div class="stat"><div class="n" id="aFlag" style="color:var(--flag)">–</div><div class="l">Flagged</div></div>
        <div class="stat"><div class="n" id="aBlock" style="color:var(--block)">–</div><div class="l">Blocked</div></div>
      </div>
      <div class="bar" id="bar"></div>
      <div class="legend">
        <span><span class="dot" style="background:var(--allow)"></span>allow</span>
        <span><span class="dot" style="background:var(--flag)"></span>flag</span>
        <span><span class="dot" style="background:var(--block)"></span>block</span>
      </div>
      <p class="muted" id="aMeta" style="margin:12px 0 0"></p>
    </div>

    <div class="card">
      <h2>Last 30 days</h2>
      <div class="chart" id="chart"></div>
      <div class="axis"><span id="axFrom"></span><span>scans/day (red = blocked)</span><span id="axTo"></span></div>
    </div>

    <div class="card">
      <h2>Top fired checks</h2>
      <table id="checks"><tbody></tbody></table>
      <p class="muted hidden" id="noChecks" style="margin:0">No checks have fired yet.</p>
    </div>

    <div class="card">
      <h2>Accounts &amp; registry</h2>
      <div class="grid">
        <div class="stat"><div class="n" id="kTotal">–</div><div class="l">API keys</div></div>
        <div class="stat"><div class="n" id="kActive">–</div><div class="l">Active (7d)</div></div>
        <div class="stat"><div class="n" id="kPlan">–</div><div class="l">On paid plans</div></div>
        <div class="stat"><div class="n" id="rReports">–</div><div class="l">Reputation reports</div></div>
        <div class="stat"><div class="n" id="rPins">–</div><div class="l">Merchant pins</div></div>
        <div class="stat"><div class="n" id="rBad">–</div><div class="l">Badlist entries</div></div>
      </div>
    </div>

    <div class="card">
      <h2>Audit chain integrity</h2>
      <p class="muted" style="margin:0 0 10px">Head: <code id="head">–</code></p>
      <div class="row" style="align-items:center">
        <button id="verify" class="ghost">Verify full chain</button>
        <span id="vres" class="muted"></span>
      </div>
    </div>
  </div>
</div>

<script>
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var keyInput = $("key"), go = $("go"), err = $("err"), out = $("out"), remember = $("remember");

  try {
    var saved = sessionStorage.getItem("paysafe_admin_key");
    if (saved) { keyInput.value = saved; remember.checked = true; load(); }
  } catch (e) {}

  function text(id, v) { $(id).textContent = v; }

  function load() {
    var key = keyInput.value.trim();
    err.textContent = "";
    if (!key) { err.textContent = "Enter the owner API key."; return; }
    go.disabled = true; go.textContent = "…";
    fetch("/v1/admin/stats", { headers: { "X-API-Key": key } })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (res) {
        go.disabled = false; go.textContent = "View";
        if (!res.ok) { out.classList.add("hidden"); err.textContent = (res.j && res.j.error) || "Request failed."; return; }
        try {
          if (remember.checked) sessionStorage.setItem("paysafe_admin_key", key);
          else sessionStorage.removeItem("paysafe_admin_key");
        } catch (e) {}
        render(res.j);
      })
      .catch(function () { go.disabled = false; go.textContent = "View"; err.textContent = "Network error."; });
  }

  function render(d) {
    var a = d.audit, ac = d.accounts || {}, rg = d.registry || {};

    if (a) {
      var v = a.by_verdict || {};
      text("aTotal", a.count || 0);
      text("aAllow", v.allow || 0);
      text("aFlag", v.flag || 0);
      text("aBlock", v.block || 0);
      var meta = "Since " + (a.first_ts ? new Date(a.first_ts).toLocaleDateString() : "—")
        + "  ·  last scan " + (a.last_ts ? new Date(a.last_ts).toLocaleString() : "—")
        + "  ·  " + (a.distinct_agents || 0) + " distinct agents"
        + "  ·  $" + (a.total_scanned_usd || 0) + " total value scanned";
      text("aMeta", meta);

      var total = a.count || 0, bar = $("bar");
      while (bar.firstChild) bar.removeChild(bar.firstChild);
      if (total > 0) {
        [["allow", "--allow"], ["flag", "--flag"], ["block", "--block"]].forEach(function (p) {
          var seg = document.createElement("span");
          seg.style.width = ((v[p[0]] || 0) / total * 100) + "%";
          seg.style.background = "var(" + p[1] + ")";
          bar.appendChild(seg);
        });
      } else {
        var e0 = document.createElement("span");
        e0.style.width = "100%"; e0.style.background = "#232c3b";
        bar.appendChild(e0);
      }

      var chart = $("chart"), daily = a.daily || [];
      while (chart.firstChild) chart.removeChild(chart.firstChild);
      var max = 1;
      daily.forEach(function (day) { if (day.total > max) max = day.total; });
      daily.forEach(function (day) {
        var col = document.createElement("div");
        col.style.height = Math.max(2, day.total / max * 96) + "px";
        col.title = day.date + ": " + day.total + " scans, " + day.block + " blocked";
        if (day.total > 0 && day.block > 0) {
          var blk = document.createElement("i");
          blk.style.height = (day.block / day.total * 100) + "%";
          col.appendChild(blk);
        }
        chart.appendChild(col);
      });
      if (daily.length) { text("axFrom", daily[0].date); text("axTo", daily[daily.length - 1].date); }

      var tb = $("checks").tBodies[0];
      while (tb.firstChild) tb.removeChild(tb.firstChild);
      var checks = a.top_checks || [];
      $("noChecks").classList.toggle("hidden", checks.length > 0);
      checks.forEach(function (c) {
        var tr = document.createElement("tr"), td1 = document.createElement("td"), td2 = document.createElement("td");
        td1.textContent = c.id; td2.textContent = c.count;
        tr.appendChild(td1); tr.appendChild(td2); tb.appendChild(tr);
      });

      text("head", "seq " + ((a.head && a.head.seq) || 0) + " · " + (((a.head && a.head.hash) || "").slice(0, 16)) + "…");
    } else {
      text("aMeta", "Audit log is disabled (AUDIT_LOG=off) — all-time stats unavailable; only per-key counters below.");
    }

    text("kTotal", ac.total_keys != null ? ac.total_keys : "–");
    text("kActive", ac.active_7d != null ? ac.active_7d : "–");
    text("kPlan", ac.with_plan != null ? ac.with_plan : "–");
    text("rReports", rg.reports != null ? rg.reports : "–");
    text("rPins", rg.pins != null ? rg.pins : "–");
    text("rBad", rg.badlist != null ? rg.badlist : "–");
    out.classList.remove("hidden");
  }

  $("verify").addEventListener("click", function () {
    var vres = $("vres");
    vres.className = "muted"; vres.textContent = "verifying…";
    fetch("/v1/audit/verify")
      .then(function (r) { return r.json(); })
      .then(function (j) {
        if (j.ok) { vres.className = "ok"; vres.textContent = "✓ chain intact (" + j.count + " records)"; }
        else { vres.className = "bad"; vres.textContent = "✗ BROKEN at seq " + j.brokenAt + ": " + (j.reason || ""); }
      })
      .catch(function () { vres.className = "bad"; vres.textContent = "verify request failed"; });
  });

  go.addEventListener("click", load);
  keyInput.addEventListener("keydown", function (e) { if (e.key === "Enter") load(); });
})();
</script>
</body>
</html>`;
}
