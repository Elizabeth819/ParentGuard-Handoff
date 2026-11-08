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
    items = normalizeArray(items);
    if (!items.length) {
      var empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = "暂无待处理申请";
      list.appendChild(empty);
      return;
    }
    items.forEach(function (item) {
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

      if (item.reason) {
        var reason = document.createElement("div");
        reason.className = "reason";
        reason.textContent = item.reason;
        row.appendChild(reason);
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

  function load() {
    if (!token) { return Promise.resolve(); }
    return Promise.all([
      api("/api/status"),
      api("/api/requests")
    ]).then(function (results) {
      renderStatus(results[0].status || results[0]);
      renderRequests(results[1].items);
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
    param($Context)
    $reader = New-Object System.IO.StreamReader($Context.Request.InputStream, [Text.Encoding]::UTF8)
    $raw = $reader.ReadToEnd()
    $reader.Dispose()
    if ($raw.Length -gt 4096) { throw '请求内容过大' }
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

$listener = New-Object System.Net.HttpListener
try {
    $listener.Prefixes.Add("http://127.0.0.1:$port/")
    $listener.Start()
} catch {
    Write-PanelLog ('启动失败：' + $_.Exception.Message)
    try { $listener.Close() } catch { }
    exit
}

$startedAt = Get-Date
Write-PanelLog ('已启动 http://127.0.0.1:' + $port)

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
                    foreach ($requestItem in @(Get-GuardRequests)) {
                        $items += [ordered]@{
                            id = [IO.Path]::GetFileName([string]$requestItem.File)
                            time = [string]$requestItem.time
                            kind = [string]$requestItem.kind
                            target = [string]$requestItem.target
                            minutes = [int]$requestItem.minutes
                            reason = [string]$requestItem.reason
                        }
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
                    $item = Get-RequestById -Id ([string]$body.id)
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
                    $item = Get-RequestById -Id ([string]$body.id)
                    if (-not $item) {
                        Send-Json $context 404 ([ordered]@{ ok = $false; error = '申请不存在或已处理' })
                        break
                    }
                    Remove-GuardRequest -Path $item.File
                    Write-GuardAudit 'deny' ('id=' + [string]$body.id) $true
                    Send-Json $context 200 ([ordered]@{ ok = $true; message = '已拒绝该申请' })
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
