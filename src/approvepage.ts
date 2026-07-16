/**
 * PaySafe approval page — the human side of step-up approvals, served at
 * GET /approve. The webhook's decide link lands here with `#id=..&token=..`
 * in the URL FRAGMENT (fragments never reach any server, so the one-time
 * decide token stays out of every request log).
 *
 * Security posture (same as the dashboards):
 *  - Zero external resources; strict CSP (default-src 'none') applies.
 *  - All rendering via textContent — payment facts are attacker-influenced
 *    strings and must never touch an HTML sink.
 *  - The FULL pay_to address is displayed prominently (address-poisoning
 *    lesson: truncated displays are how lookalike addresses win).
 *  - The token is read from location.hash, held in memory, and sent only in
 *    POST bodies to same-origin /v1/approvals/inspect and /decide.
 */
export function approvePageHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PaySafe — Payment Approval</title>
<style>
  :root { color-scheme: dark; --bg:#0b0e14; --card:#141a24; --line:#232c3b; --fg:#e6edf3; --muted:#8b98a9; --accent:#4c8dff; --allow:#3fb950; --flag:#d29922; --block:#f85149; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
  .wrap { max-width:640px; margin:0 auto; padding:32px 20px 64px; }
  h1 { font-size:22px; margin:0 0 4px; }
  .sub { color:var(--muted); margin:0 0 24px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:20px; margin-bottom:16px; }
  h2 { font-size:13px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); margin:0 0 10px; }
  .payto { font:600 16px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace; word-break:break-all; background:#0d1017; border:1px solid var(--flag); border-radius:8px; padding:12px; }
  .kv { display:grid; grid-template-columns:130px 1fr; gap:6px 12px; font-size:14px; }
  .kv .k { color:var(--muted); }
  .kv .v { word-break:break-all; }
  .warn { color:var(--flag); font-size:13px; margin-top:10px; }
  .row { display:flex; gap:12px; margin-top:18px; }
  button { flex:1; padding:13px 18px; border-radius:8px; border:0; font:inherit; font-weight:700; cursor:pointer; }
  button:disabled { opacity:.5; cursor:default; }
  #approve { background:var(--allow); color:#04160a; }
  #deny { background:var(--block); color:#fff; }
  .status { font-size:15px; margin-top:14px; min-height:20px; }
  .muted { color:var(--muted); }
  .err { color:var(--block); }
  .ok { color:var(--allow); }
  .hidden { display:none; }
  code { background:#0d1017; padding:1px 5px; border-radius:4px; font-size:13px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>Payment approval</h1>
  <p class="sub">PaySafe flagged this payment and paused it for your decision.</p>

  <div id="loading" class="card muted">Loading approval…</div>
  <div id="fail" class="card err hidden"></div>

  <div id="main" class="hidden">
    <div class="card">
      <h2>Pay to — verify the FULL address</h2>
      <div id="payTo" class="payto"></div>
      <p class="warn">Check it character by character. Lookalike addresses that match only the first and last characters (address poisoning) are a real attack.</p>
    </div>

    <div class="card">
      <h2>Payment facts</h2>
      <div class="kv">
        <div class="k">Amount</div><div class="v" id="amount"></div>
        <div class="k">Network</div><div class="v" id="network"></div>
        <div class="k">Asset</div><div class="v" id="asset"></div>
        <div class="k">Resource</div><div class="v" id="resource"></div>
        <div class="k">Description</div><div class="v" id="description"></div>
        <div class="k">Agent</div><div class="v" id="agent"></div>
        <div class="k">Checks fired</div><div class="v" id="fired"></div>
        <div class="k">Risk score</div><div class="v" id="risk"></div>
        <div class="k">Expires</div><div class="v" id="expires"></div>
      </div>
      <div class="row">
        <button id="approve">Approve payment</button>
        <button id="deny">Deny</button>
      </div>
      <div id="status" class="status"></div>
      <p class="muted" style="font-size:13px;margin:14px 0 0">Approving mints a signed override verdict valid for a few minutes, bound to exactly this payment. Denying records the refusal. Decisions are final.</p>
    </div>
  </div>
</div>
<script>
(function () {
  "use strict";
  var params = new URLSearchParams(location.hash.replace(/^#/, ""));
  var id = params.get("id") || "";
  var token = params.get("token") || "";
  var $ = function (i) { return document.getElementById(i); };

  function fail(msg) {
    $("loading").classList.add("hidden");
    $("main").classList.add("hidden");
    var f = $("fail");
    f.textContent = msg;
    f.classList.remove("hidden");
  }

  if (!id || !token) {
    fail("Missing approval reference. Open this page from the link in your PaySafe notification.");
    return;
  }

  function post(path, body) {
    return fetch(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }).then(function (r) { return r.json().then(function (j) { return { status: r.status, body: j }; }); });
  }

  function render(facts) {
    $("payTo").textContent = facts.payment.pay_to || "(missing)";
    $("amount").textContent = facts.payment.amount_usd !== undefined && facts.payment.amount_usd !== null
      ? "$" + facts.payment.amount_usd : (facts.payment.amount || "–") + " (atomic units)";
    $("network").textContent = facts.payment.network || "–";
    $("asset").textContent = facts.payment.asset || "–";
    $("resource").textContent = facts.payment.resource_url || "–";
    $("description").textContent = facts.payment.description || "–";
    $("agent").textContent = facts.payment.agent_id || "–";
    $("fired").textContent = (facts.payment.fired || []).join(", ") || "–";
    $("risk").textContent = String(facts.payment.risk_score);
    $("expires").textContent = facts.expires_at || "–";
    $("loading").classList.add("hidden");
    $("main").classList.remove("hidden");
    if (facts.status !== "pending") {
      done(facts.status === "approved" ? "Already approved." : facts.status === "denied" ? "Already denied." : "This approval has expired.", facts.status === "approved");
    }
  }

  function done(msg, ok) {
    $("approve").disabled = true;
    $("deny").disabled = true;
    var s = $("status");
    s.textContent = msg;
    s.className = "status " + (ok ? "ok" : "err");
  }

  function decide(decision) {
    $("approve").disabled = true;
    $("deny").disabled = true;
    $("status").textContent = "Submitting…";
    $("status").className = "status muted";
    post("/v1/approvals/decide", { approval_id: id, token: token, decision: decision }).then(function (r) {
      if (r.status === 200 && r.body.status === "approved") done("Approved. The agent receives a signed override verdict on its next poll.", true);
      else if (r.status === 200 && r.body.status === "denied") done("Denied. The agent will see the refusal.", false);
      else done(r.body && r.body.error ? r.body.error : "Decision failed.", false);
    }).catch(function () { done("Network error — decision not recorded.", false); });
  }

  $("approve").addEventListener("click", function () { decide("approve"); });
  $("deny").addEventListener("click", function () { decide("deny"); });

  post("/v1/approvals/inspect", { approval_id: id, token: token }).then(function (r) {
    if (r.status !== 200) { fail(r.body && r.body.error ? r.body.error : "Approval not found."); return; }
    render(r.body);
  }).catch(function () { fail("Could not load the approval — network error."); });
})();
</script>
</body>
</html>`;
}
