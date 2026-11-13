# =====================================================================
#  ParentGuard - 手机网页控制台
#  仅监听 127.0.0.1，由 SYSTEM 计划任务运行；外部访问走 Cloudflare 命名隧道
# =====================================================================
param(
    [string]$Root
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'GuardCore.ps1')
if ($Root) { Initialize-GuardPaths -Root $Root }

$cfg = Update-GuardConfigDefaults
if (-not $cfg) { exit }
if (-not [bool]$cfg.remoteEnabled) { exit }

$port = Get-GuardRemotePort
$token = [string]$cfg.remoteToken
if ([string]::IsNullOrWhiteSpace($token)) { exit }

function Write-PanelLog {
    param([string]$Message)
    Write-Log ('[面板] ' + $Message)
}

$html = @'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="家长防护">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="theme-color" content="#0b0d12">
<title>家长防护 · 手机控制台</title>
<style>
:root{--bg:#0b0d12;--panel:#151922;--panel2:#1c2230;--text:#eef1f6;--muted:#8d97ab;--line:#2a3142;--brand:#6c7cff;--green:#34d399;--amber:#fbbf24;--red:#f87171;--radius:16px}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0;padding:0;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC","Segoe UI",sans-serif}
body{min-height:100vh;padding:calc(env(safe-area-inset-top) + 18px) 16px calc(env(safe-area-inset-bottom) + 28px)}
h1{font-size:26px;line-height:1.2;margin:4px 0 2px;letter-spacing:-.02em}
h2{font-size:15px;margin:0;font-weight:600}
.hidden{display:none!important}
.eyebrow{color:var(--muted);font-size:12px;letter-spacing:.14em;text-transform:uppercase}
.host{color:var(--muted);font-size:12px;margin-top:6px}
.hero{display:flex;align-items:center;gap:14px;background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:18px;margin-top:18px}
.dot{width:12px;height:12px;border-radius:50%;background:var(--muted);flex:0 0 auto;box-shadow:0 0 0 6px rgba(141,151,171,.12)}
.dot.locked{background:var(--green);box-shadow:0 0 0 6px rgba(52,211,153,.14)}
.dot.unlocked{background:var(--amber);box-shadow:0 0 0 6px rgba(251,191,36,.14)}
.dot.bad{background:var(--red);box-shadow:0 0 0 6px rgba(248,113,113,.14)}
.state{font-size:19px;font-weight:600}
.sub{color:var(--muted);font-size:12px;margin-top:3px}
.warn{background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.4);color:#ffd7d7;border-radius:12px;padding:12px 14px;font-size:13px;line-height:1.5;margin-top:12px}
.metrics{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px}
.metric{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:13px 14px}
.metric .label{color:var(--muted);font-size:12px}
.metric .value{font-size:20px;font-weight:600;margin-top:5px;font-variant-numeric:tabular-nums}
.metric .value.small{font-size:14px;line-height:1.4}
.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:16px;margin-top:12px}
.card-head{display:flex;align-items:center;justify-content:space-between;gap:10px}
.section-label{color:var(--muted);font-size:12px;margin:18px 2px 0}
.actions{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:10px}
button{font:inherit;color:var(--text);background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:13px 12px;cursor:pointer;transition:transform .08s ease,opacity .15s ease}
button:active{transform:scale(.97);opacity:.85}
button.primary{background:var(--brand);border-color:var(--brand);color:#fff;font-weight:600}
button.wide{grid-column:1/-1}
button.danger{color:#ffd7d7;border-color:rgba(248,113,113,.45)}
button.ghost{background:transparent;padding:7px 11px;border-radius:9px;font-size:13px;color:var(--muted)}
.request{border-top:1px solid var(--line);padding:13px 0}
.request:first-child{border-top:none;padding-top:2px}
.request .top{display:flex;justify-content:space-between;gap:10px;align-items:baseline}
.request .target{font-weight:600;font-size:15px}
.request .kindtag{display:inline-block;font-size:11px;font-weight:600;color:var(--muted);border:1px solid var(--line);border-radius:6px;padding:1px 7px;margin-right:7px;vertical-align:2px}
.request .time{color:var(--muted);font-size:12px}
.request .reason{color:var(--muted);font-size:13px;line-height:1.5;margin-top:5px;white-space:pre-wrap;word-break:break-word}
.request .ops{display:flex;gap:8px;margin-top:10px}
.request .ops button{flex:1;padding:10px}
.empty{color:var(--muted);font-size:13px;padding:8px 0}
details{margin-top:12px;background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:14px 16px}
summary{cursor:pointer;font-weight:600;font-size:14px}
pre{white-space:pre-wrap;word-break:break-word;color:var(--muted);font-size:12px;line-height:1.5;margin:12px 0 0;max-height:260px;overflow:auto}
.footer{color:var(--muted);font-size:12px;line-height:1.6;margin:20px 4px 0}
.login{max-width:460px;margin:12vh auto 0;background:var(--panel);border:1px solid var(--line);border-radius:20px;padding:24px}
.login p{color:var(--muted);font-size:13px;line-height:1.6}
input{width:100%;box-sizing:border-box;background:var(--panel2);border:1px solid var(--line);border-radius:11px;color:var(--text);font:inherit;font-size:15px;padding:13px;margin-top:12px;outline:none}
input:focus{border-color:var(--brand)}
.toast{position:fixed;left:50%;bottom:calc(env(safe-area-inset-bottom) + 22px);transform:translate(-50%,16px);background:#232a3a;border:1px solid var(--line);color:var(--text);padding:11px 16px;border-radius:999px;font-size:13px;opacity:0;pointer-events:none;transition:.2s ease;max-width:86vw;text-align:center}
.toast.show{opacity:1;transform:translate(-50%,0)}
.toast.error{border-color:rgba(248,113,113,.5);color:#ffd7d7}
.usage-devices{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
.dev-chip{font-size:13px;padding:7px 12px;border-radius:999px;border:1px solid var(--line);background:var(--panel2);color:var(--muted)}
.dev-chip.active{border-color:var(--brand);color:var(--text);background:rgba(108,124,255,.14)}
.fleet-list{margin-top:10px}
.fleet-row{display:flex;align-items:center;gap:9px;border-top:1px dashed rgba(141,151,171,.18);padding:9px 0}
.fleet-row:first-child{border-top:none;padding-top:2px}
.fleet-dot{width:8px;height:8px;border-radius:50%;background:var(--muted);flex:0 0 auto}
.fleet-dot.on{background:var(--green);box-shadow:0 0 0 4px rgba(52,211,153,.14)}
.fleet-mid{flex:1;min-width:0}
.fleet-name{font-size:14px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fleet-sub{color:var(--muted);font-size:11.5px;margin-top:2px}
.fleet-hint{color:var(--muted);font-size:12px;line-height:1.6;margin-top:8px}
.join-box{margin-top:10px;background:rgba(108,124,255,.12);border:1px solid var(--brand);border-radius:11px;padding:11px 13px;font-size:12.5px;line-height:1.6}
.join-code{font-size:20px;font-weight:700;letter-spacing:.12em;font-variant-numeric:tabular-nums;margin-top:5px}
.usage-days{display:flex;gap:8px;margin-top:10px}
.day-btn{flex:1;padding:8px;font-size:13px;color:var(--muted)}
.day-btn.active{color:var(--text);border-color:var(--brand);background:rgba(108,124,255,.14)}
.usage-item{border-top:1px solid var(--line);padding:11px 0}
.usage-item:first-child{border-top:none;padding-top:2px}
.usage-item .top{display:flex;justify-content:space-between;gap:10px;align-items:baseline}
.usage-item .pname{font-weight:600;font-size:14px}
.usage-item .pexe{color:var(--muted);font-size:11px;margin-left:6px}
.usage-item .ptotal{font-variant-numeric:tabular-nums;font-size:13px;color:var(--brand);font-weight:600;white-space:nowrap}
.usage-bar{height:5px;background:var(--panel2);border-radius:3px;margin-top:7px;overflow:hidden}
.usage-bar i{display:block;height:100%;background:var(--brand);border-radius:3px}
.usage-item .sessions{color:var(--muted);font-size:12px;margin-top:7px;line-height:1.7;font-variant-numeric:tabular-nums}
.live{color:var(--green);font-weight:600}
.site-btn{margin-top:7px;background:transparent;border:1px dashed var(--line);color:var(--muted);font-size:12px;padding:5px 10px;border-radius:8px}
.site-btn.open{color:var(--text);border-style:solid;border-color:var(--brand)}
.site-panel{border-left:2px solid var(--line);margin:9px 0 2px 2px;padding:2px 0 2px 10px}
.site-row{display:flex;justify-content:space-between;gap:8px;align-items:baseline;font-size:13px;padding:7px 0;border-top:1px dashed rgba(141,151,171,.18)}
.site-row:first-child{border-top:none;padding-top:0}
.site-name{font-weight:600;word-break:break-all}
.site-cat{font-size:11px;color:var(--muted);border:1px solid var(--line);border-radius:5px;padding:1px 5px;margin-left:6px;white-space:nowrap}
.site-dur{color:var(--brand);font-variant-numeric:tabular-nums;white-space:nowrap;font-weight:600}
.site-times{color:var(--muted);font-size:11px;margin-top:3px;line-height:1.6;font-variant-numeric:tabular-nums}
.report-sum{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
.report-sum .rb{background:var(--panel2);border:1px solid var(--line);border-radius:11px;padding:10px 11px;flex:1;min-width:80px}
.report-sum .rb .k{color:var(--muted);font-size:11px}
.report-sum .rb .v{font-size:16px;font-weight:600;margin-top:4px;font-variant-numeric:tabular-nums}
.report-block{margin-top:16px}
.report-block h3{font-size:12px;font-weight:600;margin:0 0 8px;color:var(--muted);letter-spacing:.04em}
.rank-row{display:flex;align-items:center;gap:8px;font-size:12.5px;margin-top:8px}
.rank-row .rn{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rank-row .rb2{flex:0 0 32%;height:6px;background:var(--panel2);border-radius:3px;overflow:hidden}
.rank-row .rb2 i{display:block;height:100%;background:var(--brand)}
.rank-row .rv{flex:0 0 64px;text-align:right;color:var(--brand);font-variant-numeric:tabular-nums}
.cat-row{display:flex;align-items:center;gap:9px;font-size:12px;margin-top:7px}
.cat-row .cn{width:42px;flex:0 0 auto}
.cat-row .cb{flex:1;height:6px;background:var(--panel2);border-radius:3px;overflow:hidden}
.cat-row .cb i{display:block;height:100%;background:var(--brand);border-radius:3px}
.cat-row .cv{width:92px;flex:0 0 auto;text-align:right;color:var(--muted);font-variant-numeric:tabular-nums}
.hour-wrap{display:flex;align-items:flex-end;gap:2px;height:60px;margin-top:6px}
.hour-bar{flex:1;background:var(--panel2);border-radius:2px;min-height:2px}
.hour-bar i{display:block;background:linear-gradient(180deg,var(--brand),rgba(108,124,255,.35));border-radius:2px;height:100%}
.hour-labels{display:flex;justify-content:space-between;color:var(--muted);font-size:10px;margin-top:4px}
.trend-wrap{display:flex;align-items:flex-end;gap:6px;height:64px;margin-top:6px}
.trend-bar{flex:1;background:var(--panel2);border-radius:4px;min-height:2px}
.trend-bar i{display:block;height:100%;background:rgba(108,124,255,.5);border-radius:4px}
.trend-bar.today i{background:var(--brand)}
.trend-labels{display:flex;gap:6px;margin-top:4px}
.trend-labels span{flex:1;text-align:center;color:var(--muted);font-size:10px}
.alert-line{font-size:12.5px;line-height:1.6;padding:8px 10px;border-radius:9px;margin-top:7px;border:1px solid var(--line);background:var(--panel2)}
.alert-line.warn{border-color:rgba(251,191,36,.45);color:#ffe6a8;background:rgba(251,191,36,.08)}
.alert-line.good{border-color:rgba(52,211,153,.4);color:#c7f5e4;background:rgba(52,211,153,.08)}
.alert-line.info{color:var(--muted)}
</style>
</head>
<body>

<div id="login" class="login hidden">
  <div class="eyebrow">ParentGuard</div>
  <h1>连接家长防护</h1>
  <p>输入电脑控制台里显示的访问令牌。令牌只保存在这台手机的浏览器中。</p>
  <input id="tokenInput" type="password" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="粘贴访问令牌">
  <button class="primary wide" id="loginBtn" style="margin-top:12px">保存并进入</button>
  <div class="footer">通过 Cloudflare 加密隧道访问本页面；访问令牌仅保存在这台手机的浏览器中。</div>
</div>

<div id="app" class="hidden">
  <div class="eyebrow">ParentGuard</div>
  <h1>远程控制台</h1>
  <div class="host" id="hostText">正在连接…</div>

  <div class="hero">
    <div class="dot" id="stateDot"></div>
    <div>
      <div class="state" id="stateText">读取中…</div>
      <div class="sub" id="stateSub">请稍候</div>
    </div>
  </div>

  <div class="warn hidden" id="warnBox"></div>

  <div class="metrics">
    <div class="metric"><div class="label">剩余放行</div><div class="value" id="metricRemaining">--</div></div>
    <div class="metric"><div class="label">待审批申请</div><div class="value" id="metricPending">--</div></div>
    <div class="metric"><div class="label">守护心跳</div><div class="value small" id="metricHeartbeat">--</div></div>
    <div class="metric"><div class="label">策略完整性</div><div class="value small" id="metricApplied">--</div></div>
  </div>

  <div class="section-label">临时放行（到期自动恢复）</div>
  <div class="actions">
    <button data-minutes="15">放行 15 分钟</button>
    <button data-minutes="30">放行 30 分钟</button>
    <button data-minutes="60">放行 60 分钟</button>
    <button data-minutes="120">放行 120 分钟</button>
    <button class="danger wide" id="lockBtn">立即恢复全部限制</button>
  </div>

  <div class="card">
    <div class="card-head">
      <h2>孩子的使用申请</h2>
      <button class="ghost" id="refreshBtn">刷新</button>
    </div>
    <div id="requestList" style="margin-top:8px"></div>
  </div>

  <div class="card">
    <div class="card-head">
      <h2>设备与程序用量</h2>
      <div style="display:flex;gap:8px">
        <button class="ghost" id="joinCodeBtn">生成配对码</button>
        <button class="ghost" id="usageRefreshBtn">刷新</button>
      </div>
    </div>
    <div class="usage-devices" id="usageDevices"></div>
    <div class="fleet-list" id="fleetList"></div>
    <div id="fleetJoin"></div>
    <div class="usage-days">
      <button class="day-btn active" data-day="0">今天</button>
      <button class="day-btn" data-day="1">昨天</button>
      <button class="day-btn" data-day="2">前天</button>
    </div>
    <div id="usageList" style="margin-top:8px"></div>
  </div>

  <div class="card">
    <div class="card-head">
      <h2>网站使用分析</h2>
      <button class="ghost" id="reportRefreshBtn">刷新</button>
    </div>
    <div class="usage-days report-tabs">
      <button class="day-btn active" data-range="day">按天</button>
      <button class="day-btn" data-range="week">按周</button>
    </div>
    <div class="sub" id="reportHint">按天统计所选日期；按周统计截至该日期的最近 7 天</div>
    <div class="report-sum" id="reportSummary"></div>
    <div id="reportBody"></div>
  </div>

  <details>
    <summary>最近日志</summary>
    <pre id="logText">点开可加载最近 40 行。</pre>
  </details>

  <div class="footer">
    孩子必须使用标准用户（非管理员）账号，防卸载才会生效。<br>
    本页面经 Cloudflare 命名隧道加密访问，连续输错令牌会自动锁定。
  </div>
</div>

<div id="toast" class="toast"></div>

<script>
(function () {
  var token = localStorage.getItem("pg_token") || "";
  var login = document.getElementById("login");
  var app = document.getElementById("app");
  var toastEl = document.getElementById("toast");
  var toastTimer = null;
  var refreshTimer = null;
  var usageDevice = "__all__";
  var lastRequests = [];
  var usageDay = 0;
  var siteReportRange = "day";
  var sitePanels = {};

  function deviceParam() {
    return usageDevice === "__all__" ? "" : usageDevice;
  }

  function toast(message, isError) {
    toastEl.textContent = message;
    toastEl.className = "toast show" + (isError ? " error" : "");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { toastEl.className = "toast"; }, 2600);
  }

  function showLogin() {
    app.classList.add("hidden");
    login.classList.remove("hidden");
    document.getElementById("tokenInput").focus();
  }

  function showApp() {
    login.classList.add("hidden");
    app.classList.remove("hidden");
  }

  function saveToken(value) {
    token = (value || "").trim();
    if (!token) { toast("请输入访问令牌", true); return; }
    localStorage.setItem("pg_token", token);
    showApp();
    load();
  }

  function clearToken() {
    token = "";
    localStorage.removeItem("pg_token");
    showLogin();
  }

  function api(path, options) {
    options = options || {};
    var headers = { "X-PG-Token": token };
    if (options.body) { headers["Content-Type"] = "application/json"; }
    return fetch(path, {
      method: options.method || "GET",
      headers: headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
      cache: "no-store"
    }).then(function (res) {
      if (res.status === 401) {
        clearToken();
        throw new Error("访问令牌无效，请重新输入");
      }
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (!res.ok) { throw new Error(data.error || ("请求失败 " + res.status)); }
        return data;
      });
    });
  }

  function normalizeArray(value) {
    if (!value) { return []; }
    return Array.isArray(value) ? value : [value];
  }

  function renderStatus(s) {
    var dot = document.getElementById("stateDot");
    var text = document.getElementById("stateText");
    var sub = document.getElementById("stateSub");
    var state = s.state || "unknown";
    dot.className = "dot";
    if (state === "locked") {
      dot.classList.add("locked");
      text.textContent = "防护已锁定";
      sub.textContent = "微信 / QQ 与娱乐网站当前禁止使用";
    } else if (state === "unlocked") {
      dot.classList.add("unlocked");
      text.textContent = "临时放行中";
      sub.textContent = "到期后由守护任务自动恢复限制";
    } else {
      dot.classList.add("bad");
      text.textContent = state === "notinstalled" ? "未安装" : "状态未知";
      sub.textContent = "请在电脑上打开家长防护控制台";
    }

    document.getElementById("hostText").textContent =
      (s.host ? s.host : "电脑") + (s.serverTime ? " · " + s.serverTime : "");

    document.getElementById("metricRemaining").textContent =
      (state === "unlocked") ? ((s.remainingMinutes || 0) + " 分钟") : "0 分钟";
    document.getElementById("metricPending").textContent = String(s.pendingRequests || 0);

    var hb = document.getElementById("metricHeartbeat");
    if (s.watchdogOnline) {
      hb.textContent = "在线";
      hb.style.color = "var(--green)";
    } else {
      hb.textContent = "离线";
      hb.style.color = "var(--red)";
    }

    var applied = document.getElementById("metricApplied");
    if (s.applied) {
      applied.textContent = "正常";
      applied.style.color = "var(--green)";
    } else {
      applied.textContent = "异常";
      applied.style.color = "var(--red)";
    }

    var warn = document.getElementById("warnBox");
    var messages = [];
    if (s.weakPassword) {
      messages.push("仍在使用安装临时密码 123456。请在电脑控制台立即修改，否则孩子可能猜中密码。");
    }
    if (!s.watchdogOnline) {
      messages.push("超过 3 分钟没有收到守护心跳，防护任务可能已停止或被删除。");
    }
    if (!s.applied) {
      messages.push("hosts 或浏览器策略未完全生效，请在电脑控制台执行「检查状态」。");
    }
    if (messages.length) {
      warn.textContent = messages.join("  ");
      warn.classList.remove("hidden");
    } else {
      warn.classList.add("hidden");
    }
  }

  function renderRequests(items) {
    var list = document.getElementById("requestList");
    list.textContent = "";
    lastRequests = normalizeArray(items);
    var visible = lastRequests.filter(function (item) {
      return usageDevice === "__all__" || !item.device || item.device === usageDevice;
    });
    if (!visible.length) {
      var empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = "暂无待处理申请";
      list.appendChild(empty);
      return;
    }
    visible.forEach(function (item) {
      var row = document.createElement("div");
      row.className = "request";

      var top = document.createElement("div");
      top.className = "top";
      var target = document.createElement("div");
      target.className = "target";
      var tag = document.createElement("span");
      tag.className = "kindtag";
      tag.textContent = item.kind === "app" ? "应用" : (item.kind === "website" ? "网站" : "申请");
      target.appendChild(tag);
      target.appendChild(document.createTextNode(item.target || "未命名"));
      var time = document.createElement("div");
      time.className = "time";
      time.textContent = (item.time || "") + " · " + (item.minutes || 0) + " 分钟";
      top.appendChild(target);
      top.appendChild(time);
      row.appendChild(top);

      if (item.device) {
        var devLine = document.createElement("div");
        devLine.className = "time";
        devLine.textContent = "来自 " + item.device;
        row.appendChild(devLine);
      }

      if (item.reason) {
        var reason = document.createElement("div");
        reason.className = "reason";
        reason.textContent = item.reason;
        row.appendChild(reason);
      }

      if (item.status === "queued") {
        var queued = document.createElement("div");
        queued.className = "reason";
        queued.textContent = "已下发决定，等待设备上线后自动生效";
        row.appendChild(queued);
        list.appendChild(row);
        return;
      }

      var ops = document.createElement("div");
      ops.className = "ops";
      var approve = document.createElement("button");
      approve.className = "primary";
      approve.textContent = "批准";
      approve.addEventListener("click", function () {
        act("/api/requests/approve", { id: item.id }, "已批准，临时放行 " + (item.minutes || 0) + " 分钟");
      });
      var deny = document.createElement("button");
      deny.textContent = "拒绝";
      deny.addEventListener("click", function () {
        act("/api/requests/deny", { id: item.id }, "已拒绝该申请");
      });
      ops.appendChild(approve);
      ops.appendChild(deny);
      row.appendChild(ops);
      list.appendChild(row);
    });
  }

  function fmtDur(sec) {
    sec = Math.max(0, Math.round(sec));
    var h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60);
    if (h > 0) return h + " 小时 " + m + " 分";
    if (m > 0) return m + " 分钟";
    return sec + " 秒";
  }

  function renderDevices(items) {
    var box = document.getElementById("usageDevices");
    box.textContent = "";
    items = normalizeArray(items);
    if (!items.length) {
      box.innerHTML = '<div class="empty">暂无设备数据，守护任务运行后自动出现</div>';
      return;
    }
    if (items.length === 1) {
      usageDevice = items[0].name;
    } else {
      var allBtn = document.createElement("button");
      allBtn.className = "dev-chip" + (usageDevice === "__all__" ? " active" : "");
      allBtn.textContent = "全部设备";
      allBtn.addEventListener("click", function () {
        usageDevice = "__all__";
        renderRequests(lastRequests);
        loadUsage();
      });
      box.appendChild(allBtn);
      if (usageDevice !== "__all__" && !items.some(function (d) { return d.name === usageDevice; })) {
        usageDevice = "__all__";
      }
    }
    items.forEach(function (d) {
      var chip = document.createElement("button");
      chip.className = "dev-chip" + (d.name === usageDevice ? " active" : "");
      chip.textContent = d.name;
      chip.title = "最近活跃：" + (d.lastActive || "未知") +
        (d.fleet ? (d.online ? " · 在线" : " · 离线") : "");
      chip.addEventListener("click", function () {
        usageDevice = d.name;
        renderRequests(lastRequests);
        loadUsage();
      });
      box.appendChild(chip);
    });
  }

  function renderFleet(items) {
    var box = document.getElementById("fleetList");
    box.textContent = "";
    items = normalizeArray(items).filter(function (d) { return d.status !== "removed"; });
    if (!items.length) {
      var hint = document.createElement("div");
      hint.className = "fleet-hint";
      hint.textContent = "还没有其他设备加入：点右上角「生成配对码」，在子机上填写主机地址与该配对码即可。";
      box.appendChild(hint);
      return;
    }
    items.forEach(function (d) {
      var row = document.createElement("div");
      row.className = "fleet-row";
      var dot = document.createElement("span");
      dot.className = "fleet-dot" + (d.online ? " on" : "");
      var mid = document.createElement("div");
      mid.className = "fleet-mid";
      var nm = document.createElement("div");
      nm.className = "fleet-name";
      nm.textContent = d.name;
      var sub = document.createElement("div");
      sub.className = "fleet-sub";
      sub.textContent = (d.online ? "在线" : "离线") + " · 最后上报 " + (d.lastSeen || "从未");
      mid.appendChild(nm);
      mid.appendChild(sub);
      var remove = document.createElement("button");
      remove.className = "ghost";
      remove.textContent = "移除";
      remove.addEventListener("click", function () {
        if (!confirm("移除设备「" + d.name + "」？移除后需要重新配对才能上报。")) { return; }
        act("/api/fleet/devices/remove", { id: d.id }, "已移除该设备");
      });
      row.appendChild(dot);
      row.appendChild(mid);
      row.appendChild(remove);
      box.appendChild(row);
    });
  }

  function loadFleet() {
    if (!token) { return Promise.resolve(); }
    return api("/api/fleet/devices").then(function (d) {
      renderFleet(d.items);
    }).catch(function () { });
  }

  function renderUsage(data) {
    var list = document.getElementById("usageList");
    list.textContent = "";
    sitePanels = {};
    var items = normalizeArray(data.items);
    if (!items.length) {
      var empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = "该设备当天暂无程序使用记录";
      list.appendChild(empty);
      return;
    }
    var max = items[0].totalSeconds || 1;
    items.forEach(function (p) {
      var row = document.createElement("div");
      row.className = "usage-item";

      var top = document.createElement("div");
      top.className = "top";
      var left = document.createElement("div");
      var nm = document.createElement("span");
      nm.className = "pname";
      nm.textContent = p.name || p.exe;
      left.appendChild(nm);
      var ex = document.createElement("span");
      ex.className = "pexe";
      ex.textContent = p.exe;
      left.appendChild(ex);
      var total = document.createElement("div");
      total.className = "ptotal";
      total.textContent = fmtDur(p.totalSeconds);
      top.appendChild(left);
      top.appendChild(total);
      row.appendChild(top);

      var bar = document.createElement("div");
      bar.className = "usage-bar";
      var fill = document.createElement("i");
      fill.style.width = Math.max(2, Math.round(100 * p.totalSeconds / max)) + "%";
      bar.appendChild(fill);
      row.appendChild(bar);

      var sessions = document.createElement("div");
      sessions.className = "sessions";
      normalizeArray(p.sessions).forEach(function (s, i) {
        if (i > 0) sessions.appendChild(document.createTextNode("　"));
        var span = document.createElement("span");
        span.textContent = s.start + " – " + s.end;
        if (s.end === "进行中") {
          var live = document.createElement("span");
          live.className = "live";
          live.textContent = " 进行中";
          span.appendChild(live);
        }
        sessions.appendChild(span);
      });
      row.appendChild(sessions);

      // 浏览器可展开查看各网站分别用了多久、几点到几点
      if (/^(msedge|chrome)\.exe$/i.test(p.exe || "")) {
        var sbtn = document.createElement("button");
        sbtn.className = "site-btn";
        sbtn.textContent = "查看网站明细";
        sbtn.addEventListener("click", function () { toggleSiteDetail(p.exe, row, sbtn); });
        row.appendChild(sbtn);
      }

      list.appendChild(row);
    });
  }

  function ymdFor(offsetDays) {
    var d = new Date(Date.now() - offsetDays * 86400000);
    return "" + d.getFullYear() +
      ("0" + (d.getMonth() + 1)).slice(-2) +
      ("0" + d.getDate()).slice(-2);
  }

  function toggleSiteDetail(exe, row, btn) {
    if (sitePanels[exe]) {
      row.removeChild(sitePanels[exe]);
      delete sitePanels[exe];
      btn.textContent = "查看网站明细";
      btn.classList.remove("open");
      return;
    }
    api("/api/sites?device=" + encodeURIComponent(deviceParam()) +
        "&date=" + ymdFor(usageDay) + "&exe=" + encodeURIComponent(exe))
      .then(function (d) {
        var panel = document.createElement("div");
        panel.className = "site-panel";
        var items = normalizeArray(d.items);
        var unattr = normalizeArray(d.unattributed);
        if (!items.length && !unattr.length) {
          var em = document.createElement("div");
          em.className = "empty";
          em.textContent = "暂无网站记录（正常浏览页面后再查看）";
          panel.appendChild(em);
        }
        items.forEach(function (s) {
          var r = document.createElement("div");
          r.className = "site-row";
          var l = document.createElement("div");
          var n = document.createElement("span");
          n.className = "site-name";
          n.textContent = (s.name || s.host || "") + (s.blocked ? "（已拦截）" : "");
          l.appendChild(n);
          if (s.category) {
            var c = document.createElement("span");
            c.className = "site-cat";
            c.textContent = s.category;
            l.appendChild(c);
          }
          var times = document.createElement("div");
          times.className = "site-times";
          var parts = [];
          normalizeArray(s.sessions).forEach(function (x) { parts.push(x.start + " – " + x.end); });
          times.textContent = parts.join("　") + (s.basis ? "　依据：" + s.basis : "");
          l.appendChild(times);
          var dur = document.createElement("div");
          dur.className = "site-dur";
          dur.textContent = fmtDur(s.totalSeconds);
          r.appendChild(l);
          r.appendChild(dur);
          panel.appendChild(r);
        });
        if (unattr.length) {
          var uh = document.createElement("div");
          uh.className = "site-times";
          uh.textContent = "未归因时间（单独说明，不计入上面的站点）：";
          panel.appendChild(uh);
          unattr.forEach(function (u) {
            var r2 = document.createElement("div");
            r2.className = "site-row";
            var l2 = document.createElement("div");
            var n2 = document.createElement("span");
            n2.className = "site-name";
            n2.textContent = (u.reason || "未取到可归因的页面信息") + (u.basis ? "（依据：" + u.basis + "）" : "");
            l2.appendChild(n2);
            var t2 = document.createElement("div");
            t2.className = "site-times";
            var p2 = [];
            normalizeArray(u.sessions).forEach(function (x) { p2.push(x.start + " – " + x.end); });
            t2.textContent = p2.join("　");
            l2.appendChild(t2);
            var d2 = document.createElement("div");
            d2.className = "site-dur";
            d2.textContent = fmtDur(u.totalSeconds);
            r2.appendChild(l2);
            r2.appendChild(d2);
            panel.appendChild(r2);
          });
        }
        row.appendChild(panel);
        sitePanels[exe] = panel;
        btn.textContent = "收起网站明细";
        btn.classList.add("open");
      })
      .catch(function (err) { toast(err.message || "网站明细加载失败", true); });
  }

  function loadUsage() {
    if (!token) { return Promise.resolve(); }
    return api("/api/devices").then(function (d) {
      renderDevices(d.items);
      var date = new Date(Date.now() - usageDay * 86400000);
      var ymd = "" + date.getFullYear() +
        ("0" + (date.getMonth() + 1)).slice(-2) +
        ("0" + date.getDate()).slice(-2);
      return api("/api/usage?device=" + encodeURIComponent(deviceParam()) + "&date=" + ymd);
    }).then(function (u) {
      renderUsage(u);
      var btns = document.querySelectorAll("[data-day]");
      for (var i = 0; i < btns.length; i++) {
        if (Number(btns[i].getAttribute("data-day")) === usageDay) { btns[i].classList.add("active"); }
        else { btns[i].classList.remove("active"); }
      }
      return loadSiteReport();
    }).catch(function () { });
  }

  function loadSiteReport() {
    if (!token) { return Promise.resolve(); }
    return api("/api/site-report?device=" + encodeURIComponent(deviceParam()) +
        "&date=" + ymdFor(usageDay) + "&range=" + siteReportRange)
      .then(function (d) { renderSiteReport(d); })
      .catch(function () { });
  }

  function renderSiteReport(d) {
    var sum = document.getElementById("reportSummary");
    sum.textContent = "";
    function metric(k, v) {
      var b = document.createElement("div");
      b.className = "rb";
      var kk = document.createElement("div");
      kk.className = "k";
      kk.textContent = k;
      var vv = document.createElement("div");
      vv.className = "v";
      vv.textContent = v;
      b.appendChild(kk);
      b.appendChild(vv);
      sum.appendChild(b);
    }
    var total = d.totalSeconds || 0;
    var unattributed = d.unattributedSecs || 0;
    var attributed = (typeof d.attributedSecs === "number") ? d.attributedSecs : Math.max(0, total - unattributed);
    var rate = total > 0 ? Math.round(100 * attributed / total) : 0;
    metric("浏览器总时长", fmtDur(total));
    if (d.range === "week") { metric("日均", fmtDur(d.avgPerDay || 0)); }
    metric("归因站点数", String(normalizeArray(d.sites).length));
    metric("已归因占比", rate + "%");

    var body = document.getElementById("reportBody");
    body.textContent = "";

    function addBlock(title) {
      var b = document.createElement("div");
      b.className = "report-block";
      var h = document.createElement("h3");
      h.textContent = title;
      b.appendChild(h);
      body.appendChild(b);
      return b;
    }

    // 1) 站点时长排名
    var sites = normalizeArray(d.sites).slice(0, 8);
    if (sites.length) {
      var bSites = addBlock("站点时长排名");
      var maxSite = sites[0].totalSeconds || 1;
      sites.forEach(function (s) {
        var row = document.createElement("div");
        row.className = "rank-row";
        var n = document.createElement("div");
        n.className = "rn";
        n.textContent = (s.name || s.host || "") + (s.blocked ? "（已拦截）" : "") + " · " + (s.category || "其他");
        var bar = document.createElement("div");
        bar.className = "rb2";
        var fill = document.createElement("i");
        fill.style.width = Math.max(2, Math.round(100 * s.totalSeconds / maxSite)) + "%";
        bar.appendChild(fill);
        var v = document.createElement("div");
        v.className = "rv";
        v.textContent = (s.percent || 0) + "%";
        row.appendChild(n);
        row.appendChild(bar);
        row.appendChild(v);
        bSites.appendChild(row);
        var tm = document.createElement("div");
        tm.className = "site-times";
        var parts = [];
        normalizeArray(s.sessions).forEach(function (x) { parts.push(x.start + " – " + x.end); });
        tm.textContent = fmtDur(s.totalSeconds) + "　" + parts.slice(0, 3).join("　") +
          (parts.length > 3 ? "　…" : "") + (s.basis ? "　依据：" + s.basis : "");
        bSites.appendChild(tm);
      });
    }

    // 2) 未归因时间：单独说明，不混进站点列表
    var unattr = normalizeArray(d.unattributed);
    if (unattr.length) {
      var bUn = addBlock("未归因时间（单独说明，未计入上面的排名与类别）");
      var head = document.createElement("div");
      head.className = "site-times";
      head.textContent = "合计 " + fmtDur(unattributed) + "，按原因列出：";
      bUn.appendChild(head);
      unattr.forEach(function (u) {
        var row = document.createElement("div");
        row.className = "rank-row";
        var n = document.createElement("div");
        n.className = "rn";
        n.textContent = (u.reason || "未取到可归因的页面信息") +
          (u.basis ? "（依据：" + u.basis + "）" : "");
        var v = document.createElement("div");
        v.className = "rv";
        v.textContent = fmtDur(u.totalSeconds) + " · " + (u.percent || 0) + "%";
        row.appendChild(n);
        row.appendChild(v);
        bUn.appendChild(row);
      });
    }

    // 3) 类别归集
    var cats = normalizeArray(d.categories);
    if (cats.length) {
      var bCats = addBlock("类别归集");
      cats.forEach(function (c) {
        var row = document.createElement("div");
        row.className = "cat-row";
        var n = document.createElement("div");
        n.className = "cn";
        n.textContent = c.name;
        var bar = document.createElement("div");
        bar.className = "cb";
        var fill = document.createElement("i");
        fill.style.width = Math.max(2, c.percent || 0) + "%";
        bar.appendChild(fill);
        var v = document.createElement("div");
        v.className = "cv";
        v.textContent = fmtDur(c.seconds) + " · " + (c.percent || 0) + "%";
        row.appendChild(n);
        row.appendChild(bar);
        row.appendChild(v);
        bCats.appendChild(row);
      });
    }

    // 3) 时段分布
    var hourly = normalizeArray(d.hourly);
    if (hourly.length === 24) {
      var bHour = addBlock(d.range === "week" ? "时段分布（近 7 天累计）" : "时段分布");
      var wrap = document.createElement("div");
      wrap.className = "hour-wrap";
      var maxHour = 1;
      hourly.forEach(function (v) { if (v > maxHour) { maxHour = v; } });
      hourly.forEach(function (v, i) {
        var bar = document.createElement("div");
        bar.className = "hour-bar";
        bar.title = i + ":00 " + fmtDur(v);
        var fill = document.createElement("i");
        fill.style.height = Math.max(2, Math.round(100 * v / maxHour)) + "%";
        bar.appendChild(fill);
        wrap.appendChild(bar);
      });
      bHour.appendChild(wrap);
      var labels = document.createElement("div");
      labels.className = "hour-labels";
      ["0", "6", "12", "18", "23"].forEach(function (t) {
        var sp = document.createElement("span");
        sp.textContent = t + ":00";
        labels.appendChild(sp);
      });
      bHour.appendChild(labels);
    }

    // 4) 趋势
    var trend = normalizeArray(d.trend);
    if (trend.length) {
      var bTrend = addBlock("最近 7 天趋势");
      var twrap = document.createElement("div");
      twrap.className = "trend-wrap";
      var maxTrend = 1;
      trend.forEach(function (t) { if (t.seconds > maxTrend) { maxTrend = t.seconds; } });
      var todayYmd = ymdFor(0);
      trend.forEach(function (t) {
        var bar = document.createElement("div");
        bar.className = "trend-bar" + (t.date === todayYmd ? " today" : "");
        bar.title = (t.label || t.date) + " " + fmtDur(t.seconds) + (t.topHost ? "（最多：" + t.topHost + "）" : "");
        var fill = document.createElement("i");
        fill.style.height = Math.max(2, Math.round(100 * t.seconds / maxTrend)) + "%";
        bar.appendChild(fill);
        twrap.appendChild(bar);
      });
      bTrend.appendChild(twrap);
      var tlabels = document.createElement("div");
      tlabels.className = "trend-labels";
      trend.forEach(function (t) {
        var sp = document.createElement("span");
        sp.textContent = t.label || t.date;
        tlabels.appendChild(sp);
      });
      bTrend.appendChild(tlabels);
    }

    // 5) 关注提示
    var alerts = normalizeArray(d.alerts);
    var bAlerts = addBlock("关注提示");
    if (!alerts.length) {
      var ok = document.createElement("div");
      ok.className = "alert-line info";
      ok.textContent = "暂无需要特别关注的站点。";
      bAlerts.appendChild(ok);
    }
    alerts.forEach(function (a) {
      var line = document.createElement("div");
      line.className = "alert-line " + (a.level || "info");
      line.textContent = a.text || "";
      bAlerts.appendChild(line);
    });

    if (!sites.length && !cats.length) {
      var empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = "该区间暂无网站使用记录；浏览器正常浏览后会自动累积。";
      body.appendChild(empty);
    }
  }

  function load() {
    if (!token) { return Promise.resolve(); }
    return Promise.all([
      api("/api/status"),
      api("/api/requests"),
      loadFleet()
    ]).then(function (results) {
      renderStatus(results[0].status || results[0]);
      renderRequests(results[1].items);
      loadUsage();
    }).catch(function (err) {
      toast(err.message || "连接失败", true);
    });
  }

  function act(path, body, okText) {
    return api(path, { method: "POST", body: body }).then(function () {
      toast(okText || "操作成功");
      return load();
    }).catch(function (err) {
      toast(err.message || "操作失败", true);
    });
  }

  document.querySelectorAll("[data-minutes]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var minutes = Number(btn.getAttribute("data-minutes"));
      act("/api/unlock", { minutes: minutes }, "已放行 " + minutes + " 分钟");
    });
  });

  document.getElementById("lockBtn").addEventListener("click", function () {
    if (!confirm("确定立即恢复全部限制？")) { return; }
    act("/api/lock", {}, "已恢复全部限制");
  });

  document.getElementById("refreshBtn").addEventListener("click", function () {
    toast("正在刷新…");
    load();
  });

  document.getElementById("usageRefreshBtn").addEventListener("click", function () {
    toast("正在刷新…");
    loadFleet();
    loadUsage();
  });

  document.getElementById("joinCodeBtn").addEventListener("click", function () {
    api("/api/fleet/join-code", { method: "POST", body: {} }).then(function (d) {
      var box = document.getElementById("fleetJoin");
      box.textContent = "";
      var wrap = document.createElement("div");
      wrap.className = "join-box";
      var t = document.createElement("div");
      t.textContent = "在子机填写主机地址与下方配对码（30 分钟内有效，仅显示这一次）：";
      var code = document.createElement("div");
      code.className = "join-code";
      code.textContent = d.code || "";
      var exp = document.createElement("div");
      exp.className = "fleet-sub";
      exp.textContent = "到期时间：" + (d.expiresAt || "");
      wrap.appendChild(t);
      wrap.appendChild(code);
      wrap.appendChild(exp);
      box.appendChild(wrap);
    }).catch(function (err) {
      toast(err.message || "生成配对码失败", true);
    });
  });

  var dayBtns = document.querySelectorAll("[data-day]");
  for (var di = 0; di < dayBtns.length; di++) {
    (function (b) {
      b.addEventListener("click", function () {
        usageDay = Number(b.getAttribute("data-day"));
        loadUsage();
      });
    })(dayBtns[di]);
  }

  document.getElementById("reportRefreshBtn").addEventListener("click", function () {
    toast("正在刷新…");
    loadSiteReport();
  });

  var rangeBtns = document.querySelectorAll("[data-range]");
  for (var ri = 0; ri < rangeBtns.length; ri++) {
    (function (b) {
      b.addEventListener("click", function () {
        siteReportRange = b.getAttribute("data-range");
        for (var j = 0; j < rangeBtns.length; j++) {
          if (rangeBtns[j] === b) { rangeBtns[j].classList.add("active"); }
          else { rangeBtns[j].classList.remove("active"); }
        }
        document.getElementById("reportHint").textContent =
          siteReportRange === "week" ? "统计截至所选日期的最近 7 天" : "统计所选日期当天";
        loadSiteReport();
      });
    })(rangeBtns[ri]);
  }

  document.querySelector("details").addEventListener("toggle", function (event) {
    if (!event.target.open) { return; }
    api("/api/log?lines=40").then(function (data) {
      document.getElementById("logText").textContent = normalizeArray(data.lines).join("\n") || "暂无日志";
    }).catch(function (err) {
      toast(err.message || "日志读取失败", true);
    });
  });

  document.getElementById("loginBtn").addEventListener("click", function () {
    saveToken(document.getElementById("tokenInput").value);
  });

  document.getElementById("tokenInput").addEventListener("keydown", function (event) {
    if (event.key === "Enter") { saveToken(event.target.value); }
  });

  var hashMatch = location.hash.match(/[#&](?:t|token)=([^&]+)/);
  if (hashMatch) {
    token = decodeURIComponent(hashMatch[1]);
    localStorage.setItem("pg_token", token);
    try { history.replaceState(null, "", location.pathname); } catch (e) { }
  }

  if (token) {
    showApp();
    load();
  } else {
    showLogin();
  }

  refreshTimer = setInterval(load, 30000);
  window.addEventListener("beforeunload", function () { clearInterval(refreshTimer); });
})();
</script>
</body>
</html>
'@

function Send-SecurityHeaders {
    param($Context)
    try {
        $headers = $Context.Response.Headers
        $headers['Cache-Control'] = 'no-store'
        $headers['X-Content-Type-Options'] = 'nosniff'
        $headers['Referrer-Policy'] = 'no-referrer'
        $headers['X-Frame-Options'] = 'DENY'
        $headers['Content-Security-Policy'] = "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'self'"
    } catch { }
}

function Send-Bytes {
    param(
        $Context,
        [int]$StatusCode,
        [byte[]]$Bytes,
        [string]$ContentType
    )
    $response = $Context.Response
    $response.StatusCode = $StatusCode
    $response.ContentType = $ContentType

    # 经跨洋隧道时大响应易丢包中断，对支持 gzip 的客户端一律压缩后再发
    $outBytes = $Bytes
    try {
        $acceptEnc = [string]$Context.Request.Headers['Accept-Encoding']
        if ($Bytes.Length -gt 1024 -and $acceptEnc -match 'gzip') {
            Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
            $ms = New-Object System.IO.MemoryStream
            $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
            $gz.Write($Bytes, 0, $Bytes.Length)
            $gz.Close()
            $outBytes = $ms.ToArray()
            $ms.Dispose()
            $response.Headers['Content-Encoding'] = 'gzip'
        }
    } catch { }

    $response.ContentLength64 = $outBytes.Length
    Send-SecurityHeaders $Context
    if ($outBytes.Length -gt 0) {
        $response.OutputStream.Write($outBytes, 0, $outBytes.Length)
    }
    $response.OutputStream.Close()
    $response.Close()
}

function Send-Json {
    param($Context, [int]$StatusCode, $Object)
    $json = $Object | ConvertTo-Json -Depth 8 -Compress
    if ([string]::IsNullOrWhiteSpace($json)) { $json = '{}' }
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    Send-Bytes -Context $Context -StatusCode $StatusCode -Bytes $bytes `
        -ContentType 'application/json; charset=utf-8'
}

function Send-Html {
    param($Context)
    $bytes = [Text.Encoding]::UTF8.GetBytes($html)
    Send-Bytes -Context $Context -StatusCode 200 -Bytes $bytes `
        -ContentType 'text/html; charset=utf-8'
}

function Read-JsonBody {
    param($Context, [int]$MaxBytes = 4096)
    $reader = New-Object System.IO.StreamReader($Context.Request.InputStream, [Text.Encoding]::UTF8)
    $raw = $reader.ReadToEnd()
    $reader.Dispose()
    if ($raw.Length -gt $MaxBytes) { throw '请求内容过大' }
    if ([string]::IsNullOrWhiteSpace($raw)) { return [pscustomobject]@{} }
    return ($raw | ConvertFrom-Json)
}

function Get-AuthToken {
    param($Context)
    $value = $Context.Request.Headers['X-PG-Token']
    if ($value) { return [string]$value }
    return ''
}

# ---- 公网暴露防护：令牌防爆破锁定 ----
# 面板经 Cloudflare Tunnel 暴露到公网后，任何人都能访问登录页。
# 连续输错令牌 5 次锁定该 IP 10 分钟，并推送 Bark 告警。
$script:authFailures = @{}

function Get-ClientIp {
    param($Request)
    # Cloudflare Tunnel 回源时真实访客 IP 在 CF-Connecting-IP 头里
    $cf = $Request.Headers['CF-Connecting-IP']
    if ($cf) { return ([string]$cf).Trim() }
    try { return $Request.RemoteEndPoint.Address.ToString() } catch { return 'unknown' }
}

function Test-AuthLockedOut {
    param([string]$Ip)
    $entry = $script:authFailures[$Ip]
    if (-not $entry) { return $false }
    if ($entry.lockedUntil -and (Get-Date) -lt $entry.lockedUntil) { return $true }
    return $false
}

function Register-AuthFailure {
    param([string]$Ip)
    $now = Get-Date
    $entry = $script:authFailures[$Ip]
    if (-not $entry -or ($now - $entry.windowStart).TotalMinutes -gt 10) {
        $entry = @{ count = 0; windowStart = $now; lockedUntil = $null }
    }
    $entry.count++
    if ($entry.count -ge 5) {
        $entry.lockedUntil = $now.AddMinutes(10)
        $entry.count = 0
        $entry.windowStart = $now
        Write-PanelLog ('IP ' + $Ip + ' 连续输错令牌，锁定 10 分钟')
        Send-BarkAlertOnce -Key 'auth-lockout' -Title '家长防护：控制台登录爆破' `
            -Body ('IP ' + $Ip + ' 连续输错令牌，已锁定 10 分钟。') `
            -CooldownMinutes 30 | Out-Null
    }
    $script:authFailures[$Ip] = $entry
    $staleKeys = @($script:authFailures.Keys | Where-Object {
        ($now - $script:authFailures[$_].windowStart).TotalHours -gt 1 })
    foreach ($k in $staleKeys) { $script:authFailures.Remove($k) }
}

function Get-RequestById {
    param([string]$Id)
    if ([string]::IsNullOrWhiteSpace($Id)) { return $null }
    if ($Id -notmatch '^req_[A-Za-z0-9_.-]+\.json$') { return $null }
    $path = Join-Path $script:RequestsDir $Id
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try {
        $obj = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8) | ConvertFrom-Json
        $obj | Add-Member -NotePropertyName 'File' -NotePropertyValue $path -Force
        return $obj
    } catch {
        return $null
    }
}

# ---- 多设备上报通道：设备令牌防爆破（与面板令牌锁定表分开，互不影响） ----
$script:fleetAuthFailures = @{}

function Test-FleetLockedOut {
    param([string]$Ip)
    $entry = $script:fleetAuthFailures[$Ip]
    if (-not $entry) { return $false }
    if ($entry.lockedUntil -and (Get-Date) -lt $entry.lockedUntil) { return $true }
    return $false
}

function Register-FleetAuthFailure {
    param([string]$Ip)
    $now = Get-Date
    $entry = $script:fleetAuthFailures[$Ip]
    if (-not $entry -or ($now - $entry.windowStart).TotalMinutes -gt 10) {
        $entry = @{ count = 0; windowStart = $now; lockedUntil = $null }
    }
    $entry.count++
    if ($entry.count -ge 8) {
        $entry.lockedUntil = $now.AddMinutes(10)
        $entry.count = 0
        $entry.windowStart = $now
        Write-PanelLog ('IP ' + $Ip + ' 多设备上报鉴权连续失败，锁定 10 分钟')
    }
    $script:fleetAuthFailures[$Ip] = $entry
    if ($script:fleetAuthFailures.Count -gt 200) {
        foreach ($k in @($script:fleetAuthFailures.Keys | Where-Object {
                    ($now - $script:fleetAuthFailures[$_].windowStart).TotalHours -gt 1 })) {
            $script:fleetAuthFailures.Remove($k)
        }
    }
}

function Invoke-FleetApi {
    param($Context, [string]$Path, [string]$Method)
    $request = $Context.Request
    $ip = Get-ClientIp $request
    if (Test-FleetLockedOut $ip) {
        Send-Json $Context 429 ([ordered]@{ ok = $false; error = '失败次数过多，请稍后再试' })
        return
    }
    if ($Method -ne 'POST') {
        Send-Json $Context 405 ([ordered]@{ ok = $false; error = '请使用 POST' })
        return
    }

    if ($Path -eq '/api/fleet/register') {
        $body = $null
        try { $body = Read-JsonBody $Context -MaxBytes 32768 } catch { $body = $null }
        if (-not $body) {
            Send-Json $Context 400 ([ordered]@{ ok = $false; error = '请求格式错误' })
            return
        }
        try {
            $result = Register-GuardFleetDevice -JoinCode ([string]$body.joinCode) `
                -DeviceId ([string]$body.deviceId) -Name ([string]$body.name) -Version ([int]$body.version)
            Write-GuardAudit 'fleet-register' ('device=' + [string]$body.deviceId) $true
            Send-Json $Context 200 ([ordered]@{
                ok       = $true
                token    = [string]$result.token
                deviceId = [string]$result.deviceId
                name     = [string]$result.name
            })
        } catch {
            Register-FleetAuthFailure $ip
            Write-GuardAudit 'fleet-register' ('ip=' + $ip) $false
            Send-Json $Context 403 ([ordered]@{ ok = $false; error = '配对码无效或已过期' })
        }
        return
    }

    # /api/fleet/report
    $deviceId = [string]$request.Headers['X-PG-Device']
    $deviceToken = [string]$request.Headers['X-PG-Device-Token']
    $device = Test-GuardFleetDeviceToken -DeviceId $deviceId -Token $deviceToken
    if (-not $device) {
        Register-FleetAuthFailure $ip
        Write-GuardAudit 'fleet-report' ('ip=' + $ip) $false
        Send-Json $Context 401 ([ordered]@{ ok = $false; error = '设备令牌无效' })
        return
    }
    $body = $null
    try { $body = Read-JsonBody $Context -MaxBytes 1048576 } catch { $body = $null }
    if (-not $body) {
        Send-Json $Context 400 ([ordered]@{ ok = $false; error = '请求格式错误' })
        return
    }
    $version = 0
    try { $version = [int]$body.device.version } catch { $version = 0 }
    Update-GuardFleetDeviceSeen -DeviceId $deviceId -Version $version
    $accepted = Add-GuardFleetSegments -DeviceId $deviceId -DeviceName ([string]$device.name) `
        -Usage $body.usage -Web $body.web
    Sync-GuardFleetRequests -DeviceId $deviceId -DeviceName ([string]$device.name) -Requests $body.requests
    Confirm-GuardFleetCommands -DeviceId $deviceId -AckIds $body.ack

    # 返回游标：子机本地最大结束时刻（无新数据时原样返回）
    $cursor = [string]$body.cursor
    foreach ($rec in @($body.usage) + @($body.web)) {
        if (-not $rec) { continue }
        $e = [string]$rec.e
        if ((Test-GuardFleetTimestamp $e) -and (-not $cursor -or [string]::CompareOrdinal($e, $cursor) -gt 0)) {
            $cursor = $e
        }
    }
    $commands = @(Get-GuardFleetCommands -DeviceId $deviceId)
    Send-Json $Context 200 ([ordered]@{
        ok         = $true
        serverTime = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        cursor     = $cursor
        accepted   = $accepted
        commands   = @($commands)
    })
}

$listener = New-Object System.Net.HttpListener
$listenUrls = @("http://127.0.0.1:$port/")
# 除回环外再监听本机局域网 IPv4：公网入口依赖 Cloudflare 隧道，而 Cloudflare 分配的边缘
# 地址在部分运营商链路上会被阻断或中途重置，手机端表现为 "load failed"。
# 局域网入口不经过 Cloudflare，手机连在同一个 Wi-Fi 时可作为备用访问路径；
# 端口由防火墙规则限定在本网段，未向公网放通。
foreach ($lip in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
        Select-Object -ExpandProperty IPAddress)) {
    $listenUrls += "http://${lip}:$port/"
}
try {
    foreach ($u in $listenUrls) { try { $listener.Prefixes.Add($u) } catch { } }
    $listener.Start()
} catch {
    # 局域网前缀注册失败（例如 DHCP 换了地址、URL 保留项没跟上）时回退为仅回环，
    # 保证面板本身不会因为附加入口而不可用。
    Write-PanelLog ('局域网入口注册失败，回退为仅回环：' + $_.Exception.Message)
    try { $listener.Close() } catch { }
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://127.0.0.1:$port/")
    try { $listener.Start() } catch {
        Write-PanelLog ('启动失败：' + $_.Exception.Message)
        try { $listener.Close() } catch { }
        exit
    }
    $listenUrls = @("http://127.0.0.1:$port/")
}

$startedAt = Get-Date
Write-PanelLog ('已启动 ' + ($listenUrls -join ' , '))

try {
    while ($true) {
        $context = $null
        try {
            $context = $listener.GetContext()
            $request = $context.Request
            $path = [string]$request.Url.AbsolutePath
            $method = [string]$request.HttpMethod

            if ($path -eq '/' -or $path -eq '/index.html') {
                Send-Html $context
                continue
            }
            if ($path -eq '/favicon.ico') {
                Send-Bytes -Context $context -StatusCode 204 `
                    -Bytes ([byte[]]@()) -ContentType 'image/x-icon'
                continue
            }
            if ($path -eq '/api/ping') {
                Send-Json $context 200 ([ordered]@{
                    ok = $true
                    time = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                    host = $env:COMPUTERNAME
                })
                continue
            }
            if (-not $path.StartsWith('/api/')) {
                Send-Json $context 404 ([ordered]@{ ok = $false; error = 'not found' })
                continue
            }

            # 多设备上报通道使用每设备令牌，走独立鉴权，不复用面板令牌
            if ($path -eq '/api/fleet/register' -or $path -eq '/api/fleet/report') {
                Invoke-FleetApi -Context $context -Path $path -Method $method
                continue
            }

            $clientIp = Get-ClientIp $request
            if (Test-AuthLockedOut $clientIp) {
                Write-GuardAudit 'auth' ('ip=' + $clientIp + ';locked') $false
                Send-Json $context 429 ([ordered]@{ ok = $false; error = '失败次数过多，已锁定 10 分钟' })
                continue
            }
            if (-not (Test-GuardToken -Token (Get-AuthToken $context))) {
                Write-GuardAudit 'auth' ('ip=' + $clientIp) $false
                Register-AuthFailure $clientIp
                Send-Json $context 401 ([ordered]@{ ok = $false; error = '访问令牌无效' })
                continue
            }

            switch ($path) {
                '/api/status' {
                    $snapshot = Get-GuardStatusSnapshot
                    $snapshot['serverTime'] = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
                    $snapshot['panelUptimeSeconds'] = [int]((Get-Date) - $startedAt).TotalSeconds
                    # 待审批 = 本机申请 + 其他设备待审申请
                    try {
                        $snapshot['pendingRequests'] = [int]$snapshot['pendingRequests'] +
                            @(Get-GuardFleetRequests -PendingOnly).Count
                    } catch { }
                    $age = Get-GuardHeartbeatAgeSeconds
                    if ($null -ne $age -and $age -gt 180) {
                        Send-BarkAlertOnce -Key 'watchdog-stale' `
                            -Title '家长防护：守护任务失联' `
                            -Body ('超过 {0} 秒没有收到守护心跳，请检查电脑。' -f $age) `
                            -CooldownMinutes 30 | Out-Null
                    }
                    Send-Json $context 200 ([ordered]@{ ok = $true; status = $snapshot })
                    break
                }
                '/api/requests' {
                    $items = @()
                    $localName = Get-GuardDeviceName
                    foreach ($requestItem in @(Get-GuardRequests)) {
                        $items += [ordered]@{
                            id     = [IO.Path]::GetFileName([string]$requestItem.File)
                            device = $localName
                            time   = [string]$requestItem.time
                            kind   = [string]$requestItem.kind
                            target = [string]$requestItem.target
                            minutes = [int]$requestItem.minutes
                            reason = [string]$requestItem.reason
                            status = 'pending'
                        }
                    }
                    foreach ($fleetItem in @(Get-GuardFleetRequests)) {
                        $items += $fleetItem
                    }
                    Send-Json $context 200 ([ordered]@{ ok = $true; items = @($items) })
                    break
                }
                '/api/log' {
                    $lineCount = 40
                    $query = [string]$request.Url.Query
                    if ($query -match '[?&]lines=([0-9]+)') {
                        $lineCount = [int]$Matches[1]
                    }
                    $lineCount = [int][math]::Min([math]::Max($lineCount, 5), 200)
                    $lines = @()
                    if (Test-Path -LiteralPath $script:LogPath) {
                        $allLines = @([IO.File]::ReadAllLines($script:LogPath, [Text.Encoding]::UTF8))
                        if ($allLines.Count -gt 0) {
                            $startIndex = [int][math]::Max(0, $allLines.Count - $lineCount)
                            $lines = @($allLines[$startIndex..($allLines.Count - 1)])
                        }
                    }
                    Send-Json $context 200 ([ordered]@{ ok = $true; lines = @($lines) })
                    break
                }
                '/api/unlock' {
                    if ($method -ne 'POST') {
                        Send-Json $context 405 ([ordered]@{ ok = $false; error = '请使用 POST' })
                        break
                    }
                    $body = Read-JsonBody $context
                    $minutes = 0
                    try { $minutes = [int]$body.minutes } catch { $minutes = 0 }
                    if ($minutes -lt 1 -or $minutes -gt 240) {
                        Send-Json $context 400 ([ordered]@{ ok = $false; error = '放行时长必须在 1-240 分钟' })
                        break
                    }
                    Set-UnlockMinutes -Minutes $minutes
                    Write-GuardAudit 'unlock' ('minutes=' + $minutes) $true
                    Send-Json $context 200 ([ordered]@{
                        ok = $true
                        message = ('已临时放行 {0} 分钟' -f $minutes)
                        status = (Get-GuardStatusSnapshot)
                    })
                    break
                }
                '/api/lock' {
                    if ($method -ne 'POST') {
                        Send-Json $context 405 ([ordered]@{ ok = $false; error = '请使用 POST' })
                        break
                    }
                    Invoke-Lock
                    Write-GuardAudit 'lock' '' $true
                    Send-Json $context 200 ([ordered]@{
                        ok = $true
                        message = '已恢复全部限制'
                        status = (Get-GuardStatusSnapshot)
                    })
                    break
                }
                '/api/requests/approve' {
                    if ($method -ne 'POST') {
                        Send-Json $context 405 ([ordered]@{ ok = $false; error = '请使用 POST' })
                        break
                    }
                    $body = Read-JsonBody $context
                    $requestId = [string]$body.id
                    # 其他设备的申请：写入指令队列，等该设备下次上报时执行
                    if ($requestId -match '^fleet\|([a-f0-9]{16,40})\|(req_[A-Za-z0-9_.-]+\.json)$') {
                        $fleetDeviceId = $Matches[1]
                        $fleetFile = $Matches[2]
                        $fleetReq = Get-GuardFleetRequestById -DeviceId $fleetDeviceId -FileName $fleetFile
                        if (-not $fleetReq) {
                            Send-Json $context 404 ([ordered]@{ ok = $false; error = '申请不存在或已处理' })
                            break
                        }
                        if ([string]$fleetReq.status -eq 'queued') {
                            Send-Json $context 409 ([ordered]@{ ok = $false; error = '该申请已下发，等待设备上线' })
                            break
                        }
                        $minutes = [int]$fleetReq.minutes
                        if ($minutes -lt 1 -or $minutes -gt 240) { $minutes = 30 }
                        Invoke-GuardFleetEnqueueCommand -DeviceId $fleetDeviceId -RequestFile $fleetFile `
                            -Action 'approve' -Minutes $minutes | Out-Null
                        Write-GuardAudit 'approve' ('device=' + $fleetDeviceId + ';minutes=' + $minutes) $true
                        Send-Json $context 200 ([ordered]@{
                            ok      = $true
                            message = ('已下发批准指令（放行 {0} 分钟），设备上线后自动生效' -f $minutes)
                        })
                        break
                    }
                    $item = Get-RequestById -Id $requestId
                    if (-not $item) {
                        Send-Json $context 404 ([ordered]@{ ok = $false; error = '申请不存在或已处理' })
                        break
                    }
                    $minutes = [int]$item.minutes
                    if ($minutes -lt 1 -or $minutes -gt 240) { $minutes = 30 }
                    Set-UnlockMinutes -Minutes $minutes
                    Remove-GuardRequest -Path $item.File
                    Write-GuardAudit 'approve' ('id=' + [string]$body.id + ';minutes=' + $minutes) $true
                    Send-Json $context 200 ([ordered]@{
                        ok = $true
                        message = ('已批准，临时放行 {0} 分钟' -f $minutes)
                        status = (Get-GuardStatusSnapshot)
                    })
                    break
                }
                '/api/requests/deny' {
                    if ($method -ne 'POST') {
                        Send-Json $context 405 ([ordered]@{ ok = $false; error = '请使用 POST' })
                        break
                    }
                    $body = Read-JsonBody $context
                    $requestId = [string]$body.id
                    if ($requestId -match '^fleet\|([a-f0-9]{16,40})\|(req_[A-Za-z0-9_.-]+\.json)$') {
                        $fleetDeviceId = $Matches[1]
                        $fleetFile = $Matches[2]
                        $fleetReq = Get-GuardFleetRequestById -DeviceId $fleetDeviceId -FileName $fleetFile
                        if (-not $fleetReq) {
                            Send-Json $context 404 ([ordered]@{ ok = $false; error = '申请不存在或已处理' })
                            break
                        }
                        if ([string]$fleetReq.status -eq 'queued') {
                            Send-Json $context 409 ([ordered]@{ ok = $false; error = '该申请已下发，等待设备上线' })
                            break
                        }
                        Invoke-GuardFleetEnqueueCommand -DeviceId $fleetDeviceId -RequestFile $fleetFile `
                            -Action 'deny' -Minutes 0 | Out-Null
                        Write-GuardAudit 'deny' ('device=' + $fleetDeviceId) $true
                        Send-Json $context 200 ([ordered]@{ ok = $true; message = '已下发拒绝指令，设备上线后自动生效' })
                        break
                    }
                    $item = Get-RequestById -Id $requestId
                    if (-not $item) {
                        Send-Json $context 404 ([ordered]@{ ok = $false; error = '申请不存在或已处理' })
                        break
                    }
                    Remove-GuardRequest -Path $item.File
                    Write-GuardAudit 'deny' ('id=' + [string]$body.id) $true
                    Send-Json $context 200 ([ordered]@{ ok = $true; message = '已拒绝该申请' })
                    break
                }
                '/api/devices' {
                    Send-Json $context 200 ([ordered]@{ ok = $true; items = @(Get-GuardDeviceList) })
                    break
                }
                '/api/fleet/join-code' {
                    if ($method -ne 'POST') {
                        Send-Json $context 405 ([ordered]@{ ok = $false; error = '请使用 POST' })
                        break
                    }
                    $result = New-GuardFleetJoinCode
                    Write-PanelLog '已生成一次性设备配对码'
                    Send-Json $context 200 ([ordered]@{
                        ok        = $true
                        code      = [string]$result.code
                        expiresAt = [string]$result.expiresAt
                        message   = '配对码仅显示这一次，30 分钟内有效'
                    })
                    break
                }
                '/api/fleet/devices' {
                    Send-Json $context 200 ([ordered]@{ ok = $true; items = @(Get-GuardFleetDeviceList) })
                    break
                }
                '/api/fleet/devices/remove' {
                    if ($method -ne 'POST') {
                        Send-Json $context 405 ([ordered]@{ ok = $false; error = '请使用 POST' })
                        break
                    }
                    $body = Read-JsonBody $context
                    $removed = $false
                    try { $removed = Remove-GuardFleetDevice -DeviceId ([string]$body.id) } catch { $removed = $false }
                    if (-not $removed) {
                        Send-Json $context 404 ([ordered]@{ ok = $false; error = '设备不存在' })
                        break
                    }
                    Write-GuardAudit 'fleet-remove' ('device=' + [string]$body.id) $true
                    Send-Json $context 200 ([ordered]@{ ok = $true; message = '已移除设备，需重新配对才能上报' })
                    break
                }
                '/api/usage' {
                    $query = [string]$request.Url.Query
                    $dev = ''
                    $date = ''
                    if ($query -match '[?&]device=([^&]*)') { $dev = [Uri]::UnescapeDataString($Matches[1]) }
                    if ($query -match '[?&]date=(\d{8})') { $date = $Matches[1] }
                    $report = Get-GuardUsageReport -Device $dev -Date $date
                    $report['ok'] = $true
                    Send-Json $context 200 $report
                    break
                }
                '/api/sites' {
                    $query = [string]$request.Url.Query
                    $dev = ''
                    $date = ''
                    $exe = ''
                    if ($query -match '[?&]device=([^&]*)') { $dev = [Uri]::UnescapeDataString($Matches[1]) }
                    if ($query -match '[?&]date=(\d{8})') { $date = $Matches[1] }
                    if ($query -match '[?&]exe=([^&]*)') { $exe = [Uri]::UnescapeDataString($Matches[1]) }
                    $detail = Get-GuardSiteDetail -Device $dev -Date $date -Exe $exe
                    $detail['ok'] = $true
                    Send-Json $context 200 $detail
                    break
                }
                '/api/site-report' {
                    $query = [string]$request.Url.Query
                    $dev = ''
                    $date = ''
                    $range = 'day'
                    if ($query -match '[?&]device=([^&]*)') { $dev = [Uri]::UnescapeDataString($Matches[1]) }
                    if ($query -match '[?&]date=(\d{8})') { $date = $Matches[1] }
                    if ($query -match '[?&]range=([a-zA-Z]*)') { $range = $Matches[1] }
                    if ($range -ne 'week') { $range = 'day' }
                    $rep = Get-GuardSiteReport -Device $dev -Date $date -Range $range
                    $rep['ok'] = $true
                    Send-Json $context 200 $rep
                    break
                }
                default {
                    Send-Json $context 404 ([ordered]@{ ok = $false; error = '接口不存在' })
                    break
                }
            }
        } catch {
            Write-PanelLog ('请求异常：' + $_.Exception.Message)
            try {
                if ($context -and $context.Response) {
                    Send-Json $context 500 ([ordered]@{ ok = $false; error = '服务器内部错误' })
                }
            } catch { }
        } finally {
            try { if ($context) { $context.Response.Close() } } catch { }
        }
    }
} finally {
    try { $listener.Stop() } catch { }
    try { $listener.Close() } catch { }
    Write-PanelLog '已停止'
}
