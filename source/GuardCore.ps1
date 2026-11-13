# =====================================================================
#  ParentGuard - 策略引擎
#  适用：Windows 10 / 11 + Windows PowerShell 5.1
#  说明：本文件只负责“拦截/放行”的底层实现，可被控制台与守护任务共用。
# =====================================================================

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

$script:GuardRoot   = Join-Path $env:ProgramData 'ParentGuard'
$script:HostsPath   = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$script:BeginMarker = '# BEGIN ParentGuard (managed)'
$script:EndMarker   = '# END ParentGuard'

$script:ChromiumPolicyRoots = @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Edge',
    'HKLM:\SOFTWARE\Policies\Google\Chrome',
    'HKLM:\SOFTWARE\Policies\Chromium',
    'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave',
    'HKLM:\SOFTWARE\Policies\Vivaldi'
)

function Initialize-GuardPaths {
    param([string]$Root)
    if ($Root) { $script:GuardRoot = $Root }
    $script:ConfigPath  = Join-Path $script:GuardRoot 'config.json'
    $script:StatePath   = Join-Path $script:GuardRoot 'state.txt'
    $script:LogPath     = Join-Path $script:GuardRoot 'logs\guard.log'
    $script:RequestsDir = Join-Path $script:GuardRoot 'requests'
    $script:UsageDir    = Join-Path $script:GuardRoot 'usage'
    $script:UsageInboxDir = Join-Path $script:UsageDir 'inbox'
    $script:BackupDir   = Join-Path $script:GuardRoot 'backup'
    $script:StubScript  = Join-Path $script:GuardRoot 'Show-Blocked.ps1'
    $script:PanelScript = Join-Path $script:GuardRoot 'RemotePanel.ps1'
    $script:HealthScript = Join-Path $script:GuardRoot 'health.ps1'
    $script:HeartbeatPath = Join-Path $script:GuardRoot 'heartbeat.json'
    $script:AlertStatePath = Join-Path $script:GuardRoot 'alert-state.json'
    $script:AuditLogPath = Join-Path $script:GuardRoot 'logs\remote-audit.log'
    $script:TunnelScript = Join-Path $script:GuardRoot 'cloudflared-panel.ps1'
    $script:TunnelExe    = Join-Path $script:GuardRoot 'cloudflared.exe'
    $script:TunnelUrlPath = Join-Path $script:GuardRoot 'tunnel-url.txt'
    # IFEO Debugger 命令行（路径均无空格，无需内嵌引号，避免 reg.exe 转义问题）
    $script:StubPath    = '{0} -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File {1}' -f `
        (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'), $script:StubScript
}

Initialize-GuardPaths

function Set-GuardAcls {
    # 配置目录只允许 SYSTEM / 管理员访问；普通用户仅能“穿过”目录并运行拦截提示程序
    & icacls.exe $script:GuardRoot /inheritance:r /grant:r `
        '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(X)' 2>&1 | Out-Null

    # 申请目录允许普通用户创建申请文件（只能新建，不能读改配置或已有申请）
    & icacls.exe $script:RequestsDir /inheritance:r /grant:r `
        '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(RX,WD,AD)' 2>&1 | Out-Null

    # 孩子只需要能运行“申请窗口”。其余脚本（GuardCore 内含完整拦截名单）
    # 一律撤销普通用户的读取权限，防止孩子翻脚本得到全部被拦截网站。
    foreach ($name in @('ParentGuard.ps1', 'GuardCore.ps1', 'RemotePanel.ps1', 'watchdog.ps1', 'health.ps1')) {
        $path = Join-Path $script:GuardRoot $name
        if (Test-Path -LiteralPath $path) {
            & icacls.exe $path /remove:g '*S-1-5-32-545' 2>&1 | Out-Null
        }
    }
    $stub = Join-Path $script:GuardRoot 'Show-Blocked.ps1'
    if (Test-Path -LiteralPath $stub) {
        & icacls.exe $stub /grant:r '*S-1-5-32-545:RX' 2>&1 | Out-Null
    }
}

# ---------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Log {
    param([string]$Message)
    try {
        $logDir = Split-Path -Parent $script:LogPath
        if (-not (Test-Path -LiteralPath $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
        Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8
    } catch { }
}

function Get-UptimeMs {
    if (-not ('ParentGuard.Native' -as [type])) {
        Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
namespace ParentGuard {
    public static class Native {
        [DllImport("kernel32.dll")]
        public static extern ulong GetTickCount64();
    }
}
'@
    }
    return [ParentGuard.Native]::GetTickCount64()
}

function Get-FixedTimeHashEqual {
    param([string]$A, [string]$B)
    if ($null -eq $A -or $null -eq $B) { return $false }
    $ba = [Text.Encoding]::UTF8.GetBytes($A)
    $bb = [Text.Encoding]::UTF8.GetBytes($B)
    if ($ba.Length -ne $bb.Length) { return $false }
    $diff = 0
    for ($i = 0; $i -lt $ba.Length; $i++) {
        $diff = $diff -bor ($ba[$i] -bxor $bb[$i])
    }
    return ($diff -eq 0)
}

# ---------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------

function Get-DefaultDomainBlockList {
    return @(
        # 社交 / 即时通讯
        'qq.com', 'wechat.com', 'weixin.com',
        'weibo.com', 'weibo.cn',
        'douyin.com', 'iesdouyin.com', 'tiktok.com',
        'kuaishou.com', 'gifshow.com', 'kwai.com',
        'xiaohongshu.com', 'xhslink.com',
        'bilibili.com', 'b23.tv', 'bilivideo.com',
        'douban.com', 'tieba.baidu.com', 'zhihu.com',
        'twitter.com', 'x.com', 'facebook.com', 'fb.com', 'instagram.com', 'threads.net',
        'snapchat.com', 'reddit.com', 'discord.com', 'telegram.org', 't.me',
        'whatsapp.com', 'line.me', 'pinterest.com', 'tumblr.com', 'linkedin.com',
        '9gag.com', 'imgur.com',
        # 视频 / 直播
        'youtube.com', 'youtu.be', 'netflix.com', 'twitch.tv',
        'youku.com', 'iqiyi.com', 'mgtv.com', 'tudou.com', 'tv.sohu.com',
        'huya.com', 'douyu.com', 'ixigua.com', 'haokan.baidu.com',
        'vimeo.com', 'disneyplus.com', 'hulu.com',
        # 游戏
        '4399.com', '7k7k.com', '17173.com', '9game.cn',
        'steamcommunity.com', 'store.steampowered.com', 'epicgames.com',
        # 购物
        'taobao.com', 'tmall.com', 'jd.com', 'pinduoduo.com', 'yangkeduo.com',
        '1688.com', 'aliexpress.com', 'temu.com', 'shein.com'
    )
}

function Get-DefaultConfig {
    return [pscustomobject]@{
        version             = 2
        installedAt         = (Get-Date).ToString('o')
        deviceName          = ''
        passwordSalt        = ''
        passwordHash        = ''
        passwordIterations  = 20000
        locked              = $true
        unlockUntilUptimeMs = $null
        mode                = 'blocklist'      # blocklist = 按名单拦截；strict = 浏览器只允许白名单
        blockBrowsers       = $true
        blockApps           = $true
        blockHosts          = $true
        disableDoH          = $true
        blockIncognito      = $true
        appBlockList        = @(
            'WeChat.exe', 'Weixin.exe', 'WeChatApp.exe', 'WeChatAppEx.exe',
            'QQ.exe', 'QQScLauncher.exe', 'Tim.exe'
        )
        domainBlockList     = @(Get-DefaultDomainBlockList)
        domainAllowList     = @(
            # 腾讯文档 / 腾讯会议（网课、作业常用）
            'docs.qq.com', 'meeting.qq.com',
            # 词典与翻译
            'youdao.com', 'fanyi.youdao.com', 'iciba.com', 'fanyi.baidu.com',
            # 百科与文库（注意：不整域放行 baidu.com，避免贴吧漏网）
            'baike.baidu.com', 'wenku.baidu.com', 'wikipedia.org', 'zh.wikipedia.org',
            # 搜索（必应，查资料）
            'bing.com', 'cn.bing.com',
            # 网盘（取学习资料）
            'pan.baidu.com',
            # 网课与公开课
            'icourse163.org', 'open.163.com', 'xuetangx.com', 'classin.com',
            'zoom.us', 'dingtalk.com'
        )
        # 手机远程控制
        remoteEnabled       = $true
        remotePort          = 8787
        remoteToken         = ''
        barkKey             = ''
    }
}

function Get-GuardConfig {
    if (-not (Test-Path -LiteralPath $script:ConfigPath)) { return $null }
    $raw = [IO.File]::ReadAllText($script:ConfigPath, [Text.Encoding]::UTF8)
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    return ($raw | ConvertFrom-Json)
}

function Save-GuardConfig {
    param($Config)
    $json = $Config | ConvertTo-Json -Depth 10
    $tmp = $script:ConfigPath + '.tmp'
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($tmp, $json, $utf8)
    Move-Item -LiteralPath $tmp -Destination $script:ConfigPath -Force
}

function Set-GuardPassword {
    param([string]$Password)
    if ([string]::IsNullOrWhiteSpace($Password)) { throw '密码不能为空' }
    $salt = [byte[]]::new(32)
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
    $iterations = 20000
    $cfg = Get-GuardConfig
    if (-not $cfg) { throw '配置不存在，无法设置密码' }
    $cfg.passwordSalt = [Convert]::ToBase64String($salt)
    $cfg.passwordIterations = $iterations
    $cfg.passwordHash = Get-Pbkdf2Hash -Password $Password -Salt $salt -Iterations $iterations
    Save-GuardConfig $cfg
}

function Get-Pbkdf2Hash {
    param([string]$Password, [byte[]]$Salt, [int]$Iterations)
    try {
        $kdf = [Security.Cryptography.Rfc2898DeriveBytes]::new(
            $Password, $Salt, $Iterations, [Security.Cryptography.HashAlgorithmName]::SHA256)
    } catch {
        $kdf = [Security.Cryptography.Rfc2898DeriveBytes]::new($Password, $Salt, $Iterations)
    }
    return [Convert]::ToBase64String($kdf.GetBytes(32))
}

function Test-GuardPassword {
    param([string]$Password)
    $cfg = Get-GuardConfig
    if (-not $cfg -or -not $cfg.passwordHash) { return $false }
    try {
        $salt = [Convert]::FromBase64String([string]$cfg.passwordSalt)
        $iterations = [int]$cfg.passwordIterations
        $computed = Get-Pbkdf2Hash -Password $Password -Salt $salt -Iterations $iterations
        return (Get-FixedTimeHashEqual -A $computed -B ([string]$cfg.passwordHash))
    } catch {
        return $false
    }
}

# ---------------------------------------------------------------------
# 手机远程控制：令牌 / 端口 / 心跳 / 推送
# ---------------------------------------------------------------------

function New-GuardRemoteToken {
    $bytes = [byte[]]::new(24)
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return (-join ($bytes | ForEach-Object { $_.ToString('x2') }))
}

function Test-GuardToken {
    param([string]$Token)
    $cfg = Get-GuardConfig
    if (-not $cfg) { return $false }
    $expected = [string]$cfg.remoteToken
    if ([string]::IsNullOrEmpty($expected) -or [string]::IsNullOrEmpty($Token)) { return $false }
    $a = [Text.Encoding]::UTF8.GetBytes($Token)
    $b = [Text.Encoding]::UTF8.GetBytes($expected)
    if ($a.Length -ne $b.Length) { return $false }
    $diff = 0
    for ($i = 0; $i -lt $a.Length; $i++) {
        $diff = $diff -bor ($a[$i] -bxor $b[$i])
    }
    return ($diff -eq 0)
}

function Get-GuardRemotePort {
    $cfg = Get-GuardConfig
    $port = 8787
    if ($cfg -and $cfg.remotePort) {
        try { $port = [int]$cfg.remotePort } catch { $port = 8787 }
    }
    if ($port -lt 1024 -or $port -gt 65535) { $port = 8787 }
    return $port
}

function Get-GuardRemainingMinutes {
    param($Config)
    if (-not $Config) { $Config = Get-GuardConfig }
    if (-not $Config) { return 0 }
    if ((Get-EffectiveState -Config $Config) -ne 'unlocked') { return 0 }
    try {
        return [int][math]::Max(0, [math]::Ceiling(
            (([double]$Config.unlockUntilUptimeMs - [double](Get-UptimeMs)) / 60000)))
    } catch {
        return 0
    }
}

function Update-GuardConfigDefaults {
    param($Config)
    if (-not $Config) { $Config = Get-GuardConfig }
    if (-not $Config) { return $null }
    $defaults = Get-DefaultConfig
    foreach ($name in @('remoteEnabled', 'remotePort', 'remoteToken', 'barkKey', 'deviceName')) {
        if (-not $Config.PSObject.Properties[$name]) {
            $Config | Add-Member -NotePropertyName $name -NotePropertyValue $defaults.$name -Force
        }
    }
    if ([string]::IsNullOrWhiteSpace([string]$Config.remoteToken)) {
        $Config.remoteToken = New-GuardRemoteToken
    }
    if ([string]::IsNullOrWhiteSpace([string]$Config.deviceName)) {
        $Config.deviceName = $env:COMPUTERNAME
    }
    if ([int]$Config.version -lt 2) { $Config.version = 2 }
    return $Config
}

function Test-GuardPortOpen {
    param([int]$Port)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne(1200)) { return $false }
        $client.EndConnect($iar)
        return $true
    } catch {
        return $false
    } finally {
        try { $client.Close() } catch { }
    }
}

function Get-GuardHeartbeat {
    if (-not (Test-Path -LiteralPath $script:HeartbeatPath)) { return $null }
    try {
        $raw = [IO.File]::ReadAllText($script:HeartbeatPath, [Text.Encoding]::UTF8)
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        return ($raw | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function Start-GuardPanelProcess {
    param([int]$Port = 0)
    if ($Port -le 0) { $Port = Get-GuardRemotePort }
    if (Test-GuardPortOpen -Port $Port) { return $true }
    if (-not (Test-Path -LiteralPath $script:PanelScript)) { return $false }
    $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    try {
        Start-Process -FilePath $psExe `
            -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' +
                $script:PanelScript + '"') `
            -WindowStyle Hidden | Out-Null
        Start-Sleep -Milliseconds 900
        return (Test-GuardPortOpen -Port $Port)
    } catch {
        Write-Log ('启动手机控制台失败：' + $_.Exception.Message)
        return $false
    }
}

function Test-GuardTunnelRunning {
    try {
        return $null -ne (Get-Process -Name 'cloudflared' -ErrorAction SilentlyContinue)
    } catch {
        return $false
    }
}

function Get-GuardTunnelUrl {
    if (-not (Test-Path -LiteralPath $script:TunnelUrlPath)) { return '' }
    try {
        $line = ([IO.File]::ReadAllLines($script:TunnelUrlPath, [Text.Encoding]::UTF8) |
            Where-Object { $_ -match '^https://[A-Za-z0-9.-]+' } | Select-Object -First 1)
        if ($line) { return ([string]$line).Trim() }
    } catch { }
    return ''
}

function Start-GuardTunnelProcess {
    # 返回隧道公网 URL；未配置 cloudflared.exe 时返回空字符串
    if (Test-GuardTunnelRunning) { return (Get-GuardTunnelUrl) }
    if (-not (Test-Path -LiteralPath $script:TunnelExe)) { return '' }
    if (-not (Test-Path -LiteralPath $script:TunnelScript)) { return '' }
    $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    try {
        Start-Process -FilePath $psExe `
            -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' +
                $script:TunnelScript + '"') `
            -WindowStyle Hidden | Out-Null
        for ($i = 0; $i -lt 20; $i++) {
            Start-Sleep -Seconds 1
            $url = Get-GuardTunnelUrl
            if ($url) { return $url }
            if (-not (Test-GuardTunnelRunning)) { break }
        }
    } catch {
        Write-Log ('启动公网隧道失败：' + $_.Exception.Message)
    }
    return (Get-GuardTunnelUrl)
}

function Save-GuardHeartbeat {
    param($Data)
    try {
        $json = $Data | ConvertTo-Json -Depth 6
        $tmp = $script:HeartbeatPath + '.tmp'
        [IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $tmp -Destination $script:HeartbeatPath -Force
        return $true
    } catch {
        return $false
    }
}

function Get-GuardHeartbeatAgeSeconds {
    $hb = Get-GuardHeartbeat
    if (-not $hb -or -not $hb.time) { return $null }
    try {
        return [int]((Get-Date) - [datetime]::Parse([string]$hb.time)).TotalSeconds
    } catch {
        return $null
    }
}

function Send-BarkAlert {
    param([string]$Title, [string]$Body, [string]$Level = 'active')
    $cfg = Get-GuardConfig
    if (-not $cfg -or [string]::IsNullOrWhiteSpace([string]$cfg.barkKey)) { return $false }
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $key = ([string]$cfg.barkKey).Trim()
        $url = 'https://api.day.app/{0}/{1}/{2}?group=ParentGuard&level={3}' -f `
            $key, [Uri]::EscapeDataString($Title), [Uri]::EscapeDataString($Body), $Level
        Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 10 -ErrorAction Stop | Out-Null
        return $true
    } catch {
        Write-Log ('Bark 推送失败：' + $_.Exception.Message)
        return $false
    }
}

function Send-BarkAlertOnce {
    param(
        [string]$Key,
        [string]$Title,
        [string]$Body,
        [int]$CooldownMinutes = 15
    )
    $state = @{}
    if (Test-Path -LiteralPath $script:AlertStatePath) {
        try {
            $obj = [IO.File]::ReadAllText($script:AlertStatePath, [Text.Encoding]::UTF8) | ConvertFrom-Json
            foreach ($p in $obj.PSObject.Properties) { $state[$p.Name] = [string]$p.Value }
        } catch { }
    }
    $last = $state[$Key]
    if ($last) {
        try {
            if (((Get-Date) - [datetime]::Parse($last)).TotalMinutes -lt $CooldownMinutes) { return $false }
        } catch { }
    }
    if (-not (Send-BarkAlert -Title $Title -Body $Body)) { return $false }
    $state[$Key] = (Get-Date).ToString('o')
    try {
        $tmp = $script:AlertStatePath + '.tmp'
        [IO.File]::WriteAllText($tmp, ([pscustomobject]$state | ConvertTo-Json -Depth 4),
            (New-Object System.Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $tmp -Destination $script:AlertStatePath -Force
    } catch { }
    return $true
}

function Write-GuardAudit {
    param([string]$Action, [string]$Detail = '', [bool]$Success = $true)
    try {
        $dir = Split-Path -Parent $script:AuditLogPath
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        $obj = [ordered]@{
            time    = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            action  = $Action
            detail  = $Detail
            success = $Success
        }
        Add-Content -LiteralPath $script:AuditLogPath -Value ($obj | ConvertTo-Json -Compress) -Encoding UTF8
    } catch { }
}

function Get-GuardAdminAccounts {
    try {
        $group = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
        return @(Get-LocalGroupMember -Group $group.Name -ErrorAction Stop |
            ForEach-Object { [string]$_.Name })
    } catch {
        return @()
    }
}

function Get-GuardStatusSnapshot {
    $cfg = Get-GuardConfig
    if (-not $cfg) {
        return [ordered]@{
            installed = $false
            state = 'notinstalled'
            remainingMinutes = 0
            pendingRequests = 0
            applied = $false
            watchdogOnline = $false
            heartbeatAgeSeconds = $null
            weakPassword = $false
            adminAccounts = @()
            host = $env:COMPUTERNAME
        }
    }
    $state = Get-EffectiveState -Config $cfg
    $remaining = Get-GuardRemainingMinutes -Config $cfg
    $hb = Get-GuardHeartbeat
    $hbAge = Get-GuardHeartbeatAgeSeconds
    $requests = @(Get-GuardRequests)
    return [ordered]@{
        installed = $true
        state = $state
        remainingMinutes = $remaining
        pendingRequests = $requests.Count
        applied = [bool](Test-GuardApplied -Config $cfg -SkipApps)
        watchdogOnline = ($null -ne $hbAge -and $hbAge -lt 180)
        lastHeartbeat = $(if ($hb -and $hb.time) { [string]$hb.time } else { '' })
        heartbeatAgeSeconds = $hbAge
        weakPassword = (Test-GuardPassword -Password '123456')
        adminAccounts = @(Get-GuardAdminAccounts)
        host = $env:COMPUTERNAME
        tunnelOnline = (Test-GuardTunnelRunning)
        tunnelUrl = (Get-GuardTunnelUrl)
    }
}


# ---------------------------------------------------------------------
# 状态（使用开机后的运行时长，避免修改系统时间绕过临时授权）
# ---------------------------------------------------------------------

function Get-EffectiveState {
    param($Config)
    if ($null -eq $Config) { return 'notinstalled' }
    if ([bool]$Config.locked) { return 'locked' }
    if ($null -eq $Config.unlockUntilUptimeMs) { return 'locked' }
    $now = [double](Get-UptimeMs)
    $until = [double]$Config.unlockUntilUptimeMs
    if ($now -lt $until) { return 'unlocked' }
    return 'locked'
}

function Get-GuardStateMarker {
    if (-not (Test-Path -LiteralPath $script:StatePath)) { return '' }
    return ([IO.File]::ReadAllText($script:StatePath, [Text.Encoding]::UTF8)).Trim()
}

function Set-GuardStateMarker {
    param([string]$State)
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($script:StatePath, $State, $utf8)
}

function Set-UnlockMinutes {
    param([int]$Minutes)
    if ($Minutes -lt 1) { $Minutes = 1 }
    $cfg = Get-GuardConfig
    if (-not $cfg) { throw '未安装' }
    $cfg.locked = $false
    $cfg.unlockUntilUptimeMs = [double](Get-UptimeMs) + ([double]$Minutes * 60000)
    Save-GuardConfig $cfg
    Invoke-ApplyGuard -State 'unlocked' -Config $cfg
    Write-Log ('临时放行 {0} 分钟' -f $Minutes)
}

function Invoke-Lock {
    $cfg = Get-GuardConfig
    if (-not $cfg) { throw '未安装' }
    $cfg.locked = $true
    $cfg.unlockUntilUptimeMs = $null
    Save-GuardConfig $cfg
    Invoke-ApplyGuard -State 'locked' -Config $cfg
    Write-Log '立即恢复限制'
}

# ---------------------------------------------------------------------
# 名单处理
# ---------------------------------------------------------------------

function Get-NormalizedDomains {
    param($List)
    $out = @()
    foreach ($item in @($List)) {
        $s = ([string]$item).Trim().ToLowerInvariant()
        if (-not $s) { continue }
        $s = $s -replace '^[a-z]+://', ''
        $s = $s -replace '/.*$', ''
        $s = $s -replace '^\*\.', ''
        $s = $s -replace ':.*$', ''
        if ($s) { $out += $s }
    }
    return @($out | Select-Object -Unique)
}

function Get-NormalizedApps {
    param($List)
    $out = @()
    foreach ($item in @($List)) {
        $s = ([string]$item).Trim()
        if (-not $s) { continue }
        if ($s -notmatch '(?i)\.exe$') { $s = $s + '.exe' }
        $out += $s
    }
    return @($out | Select-Object -Unique)
}

# ---------------------------------------------------------------------
# 浏览器管理策略（Edge / Chrome / Chromium 系）
# ---------------------------------------------------------------------

function Set-RegistryListPolicy {
    param([string]$Path, [string[]]$Values)
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
    New-Item -Path $Path -Force | Out-Null
    $index = 1
    foreach ($value in @($Values)) {
        if ([string]::IsNullOrWhiteSpace($value)) { continue }
        New-ItemProperty -Path $Path -Name ([string]$index) -Value ([string]$value) `
            -PropertyType String -Force | Out-Null
        $index++
    }
}

function Set-BrowserPolicy {
    param(
        [string[]]$Domains,
        [string[]]$Allow,
        [string]$Mode,
        [bool]$Enabled,
        [bool]$DisableDoH,
        [bool]$BlockIncognito,
        [switch]$DryRun
    )

    $domains = @(Get-NormalizedDomains $Domains)
    $allow = @(Get-NormalizedDomains $Allow)

    foreach ($root in $script:ChromiumPolicyRoots) {
        $blockPath = Join-Path $root 'URLBlocklist'
        $allowPath = Join-Path $root 'URLAllowlist'

        if ($Enabled) {
            $blockValues = @()
            if ($Mode -eq 'strict') {
                $blockValues += '*'
                # 严格模式下保留本机地址，避免影响本地应用
                $allow = @($allow + @('localhost', '127.0.0.1') | Select-Object -Unique)
            } else {
                $blockValues = $domains
            }

            if ($DryRun) {
                Write-Host ('[DryRun] 浏览器策略 {0}：模式={1}，拦截 {2} 条，例外 {3} 条' -f $root, $Mode, $blockValues.Count, $allow.Count)
                continue
            }

            New-Item -Path $root -Force | Out-Null
            Set-RegistryListPolicy -Path $blockPath -Values $blockValues
            if ($allow.Count -gt 0) {
                Set-RegistryListPolicy -Path $allowPath -Values $allow
            } else {
                if (Test-Path -LiteralPath $allowPath) { Remove-Item -LiteralPath $allowPath -Recurse -Force }
            }

            if ($DisableDoH) {
                New-ItemProperty -Path $root -Name 'DnsOverHttpsMode' -Value 'off' `
                    -PropertyType String -Force | Out-Null
            }

            if ($BlockIncognito) {
                if ($root -like '*Microsoft\Edge*') {
                    New-ItemProperty -Path $root -Name 'InPrivateModeAvailability' -Value 1 `
                        -PropertyType DWord -Force | Out-Null
                } else {
                    New-ItemProperty -Path $root -Name 'IncognitoModeAvailability' -Value 1 `
                        -PropertyType DWord -Force | Out-Null
                }
            }
        } else {
            if ($DryRun) {
                Write-Host ('[DryRun] 浏览器策略 {0}：移除拦截' -f $root)
                continue
            }
            if (Test-Path -LiteralPath $blockPath) { Remove-Item -LiteralPath $blockPath -Recurse -Force }
            if (Test-Path -LiteralPath $allowPath) { Remove-Item -LiteralPath $allowPath -Recurse -Force }
            Remove-ItemProperty -Path $root -Name 'DnsOverHttpsMode' -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $root -Name 'InPrivateModeAvailability' -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $root -Name 'IncognitoModeAvailability' -ErrorAction SilentlyContinue
        }
    }
}

# ---------------------------------------------------------------------
# 程序拦截（Image File Execution Options）
# ---------------------------------------------------------------------

function Set-AppBlock {
    param(
        [string[]]$Names,
        [bool]$Enabled,
        [switch]$DryRun
    )

    $ifeoRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    )
    $apps = @(Get-NormalizedApps $Names)

    $regExe = Join-Path $env:SystemRoot 'System32\reg.exe'

    foreach ($root in $ifeoRoots) {
        foreach ($app in $apps) {
            $keyPs = Join-Path $root $app
            # reg.exe 需要 HKLM\SOFTWARE\... 无冒号格式
            $keyReg = $keyPs -replace '^HKLM:', 'HKLM' -replace '^HKCU:', 'HKCU' -replace '^HKCR:', 'HKCR' -replace '^HKU:', 'HKU' -replace '^HKCC:', 'HKCC'
            if ($Enabled) {
                if ($DryRun) {
                    Write-Host ('[DryRun] IFEO {0} -> {1}' -f $keyPs, $script:StubPath)
                    continue
                }
                if (-not (Test-Path -LiteralPath $script:StubScript)) {
                    Write-Warning ('拦截提示脚本不存在，跳过 IFEO：' + $script:StubScript)
                    continue
                }
                # 先确保键存在（用 PowerShell）
                try {
                    if (-not (Test-Path -LiteralPath $keyPs)) {
                        New-Item -Path $keyPs -Force -ErrorAction Stop | Out-Null
                    }
                } catch { }
                # 用 reg.exe 写入值
                & $regExe add $keyReg /v Debugger /t REG_SZ /d $script:StubPath /f 2>&1 | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    try {
                        New-ItemProperty -Path $keyPs -Name 'Debugger' -Value $script:StubPath `
                            -PropertyType String -Force -ErrorAction Stop | Out-Null
                    } catch {
                        Write-Warning ('IFEO 写入失败（安全软件可能拦截）：' + $keyPs)
                    }
                }
            } else {
                if ($DryRun) {
                    Write-Host ('[DryRun] IFEO 取消拦截 {0}' -f $keyPs)
                    continue
                }
                & $regExe delete $keyReg /v Debugger /f 2>&1 | Out-Null
            }
        }
    }
}

# ---------------------------------------------------------------------
# hosts 兜底拦截（覆盖所有浏览器，含不支持策略的第三方浏览器）
# ---------------------------------------------------------------------

function Set-HostsBlock {
    param(
        [string[]]$Domains,
        [bool]$Enabled,
        [switch]$DryRun
    )

    $domains = @(Get-NormalizedDomains $Domains)

    if ($DryRun) {
        Write-Host ('[DryRun] hosts 文件 {0}：{1}' -f ($(if ($Enabled) { '写入' } else { '移除' })), $script:HostsPath)
        return
    }

    $lines = @()
    if (Test-Path -LiteralPath $script:HostsPath) {
        $lines = [IO.File]::ReadAllLines($script:HostsPath, [Text.Encoding]::Default)
    }

    $kept = New-Object System.Collections.Generic.List[string]
    $inside = $false
    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ($trimmed -eq $script:BeginMarker) { $inside = $true; continue }
        if ($trimmed -eq $script:EndMarker) { $inside = $false; continue }
        if (-not $inside) { $kept.Add($line) }
    }

    if ($Enabled) {
        $entries = New-Object System.Collections.Generic.List[string]
        foreach ($domain in $domains) {
            $entries.Add($domain)
            $entries.Add('www.' + $domain)
            $entries.Add('m.' + $domain)
        }
        # 网页微信 / 网页 QQ 常用子域（仅在对应主域被拦截时追加）
        if ($domains -contains 'qq.com') {
            foreach ($hostName in @('wx.qq.com', 'wx2.qq.com', 'wx8.qq.com', 'web.qq.com',
                    'web2.qq.com', 'im.qq.com', 'w.qq.com', 'qzone.qq.com', 'weixin.qq.com')) {
                $entries.Add($hostName)
            }
        }
        if ($domains -contains 'wechat.com') {
            foreach ($hostName in @('web.wechat.com', 'web1.wechat.com', 'wx.wechat.com')) {
                $entries.Add($hostName)
            }
        }

        $kept.Add('')
        $kept.Add($script:BeginMarker)
        foreach ($hostName in @($entries | Select-Object -Unique)) {
            $kept.Add('0.0.0.0 ' + $hostName)
        }
        $kept.Add($script:EndMarker)
    }

    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $content = ($kept -join "`r`n") + "`r`n"
    [IO.File]::WriteAllText($script:HostsPath, $content, $utf8)

    try { & ipconfig.exe /flushdns | Out-Null } catch { }
}

# ---------------------------------------------------------------------
# Firefox 策略（policies.json）
# ---------------------------------------------------------------------

function Get-FirefoxPolicyPaths {
    $dirs = New-Object System.Collections.Generic.List[string]
    if ($env:ProgramFiles) {
        $dirs.Add((Join-Path $env:ProgramFiles 'Mozilla Firefox'))
    }
    $programFilesX86 = ${env:ProgramFiles(x86)}
    if ($programFilesX86) {
        $dirs.Add((Join-Path $programFilesX86 'Mozilla Firefox'))
    }
    $result = @()
    foreach ($dir in $dirs) {
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        $result += (Join-Path $dir 'distribution\policies.json')
    }
    return @($result | Select-Object -Unique)
}

function New-FirefoxPolicyJson {
    param(
        [string[]]$Domains,
        [string[]]$Allow,
        [string]$Mode,
        [bool]$DisableDoH,
        [bool]$BlockIncognito
    )

    $domains = @(Get-NormalizedDomains $Domains)
    $allow = @(Get-NormalizedDomains $Allow)

    $block = New-Object System.Collections.Generic.List[string]
    if ($Mode -eq 'strict') {
        $block.Add('*://*/*')
        $allow = @($allow + @('localhost', '127.0.0.1') | Select-Object -Unique)
    } else {
        foreach ($domain in $domains) {
            $block.Add('*://' + $domain + '/*')
            $block.Add('*://*.' + $domain + '/*')
        }
    }

    $exceptions = New-Object System.Collections.Generic.List[string]
    foreach ($domain in $allow) {
        $exceptions.Add('*://' + $domain + '/*')
        $exceptions.Add('*://*.' + $domain + '/*')
    }

    $websiteFilter = [pscustomobject]@{
        Block      = @($block.ToArray())
        Exceptions = @($exceptions.ToArray())
    }
    $policies = [pscustomobject]@{
        WebsiteFilter = $websiteFilter
    }
    if ($DisableDoH) {
        $policies | Add-Member -NotePropertyName 'DNSOverHTTPS' `
            -NotePropertyValue ([pscustomobject]@{ Enabled = $false })
    }
    if ($BlockIncognito) {
        $policies | Add-Member -NotePropertyName 'DisablePrivateBrowsing' -NotePropertyValue $true
    }

    $root = [pscustomobject]@{ policies = $policies }
    return ($root | ConvertTo-Json -Depth 8)
}

function Backup-FirefoxPolicy {
    param([switch]$DryRun)
    $index = 0
    foreach ($policyPath in @(Get-FirefoxPolicyPaths)) {
        $index++
        $marker = Join-Path $script:BackupDir ('firefox_{0}.existed' -f $index)
        if (Test-Path -LiteralPath $marker) { continue }
        if ($DryRun) {
            Write-Host ('[DryRun] 备份 Firefox 策略：{0}' -f $policyPath)
            continue
        }
        if (-not (Test-Path -LiteralPath $script:BackupDir)) {
            New-Item -ItemType Directory -Path $script:BackupDir -Force | Out-Null
        }
        if (Test-Path -LiteralPath $policyPath) {
            Copy-Item -LiteralPath $policyPath -Destination (Join-Path $script:BackupDir ('firefox_{0}.policies.json' -f $index)) -Force
            Set-Content -LiteralPath $marker -Value '1' -Encoding ASCII
        } else {
            Set-Content -LiteralPath $marker -Value '0' -Encoding ASCII
        }
    }
}

function Set-FirefoxPolicy {
    param(
        [string[]]$Domains,
        [string[]]$Allow,
        [string]$Mode,
        [bool]$Enabled,
        [bool]$DisableDoH,
        [bool]$BlockIncognito,
        [switch]$DryRun
    )

    $paths = @(Get-FirefoxPolicyPaths)
    if ($paths.Count -eq 0) {
        if ($DryRun) { Write-Host '[DryRun] 未检测到 Firefox，跳过' }
        return
    }

    if ($Enabled) {
        Backup-FirefoxPolicy -DryRun:$DryRun
        $json = New-FirefoxPolicyJson -Domains $Domains -Allow $Allow -Mode $Mode `
            -DisableDoH $DisableDoH -BlockIncognito $BlockIncognito
    }

    $index = 0
    foreach ($policyPath in $paths) {
        $index++
        $marker = Join-Path $script:BackupDir ('firefox_{0}.existed' -f $index)
        $distDir = Split-Path -Parent $policyPath

        if ($Enabled) {
            if ($DryRun) {
                Write-Host ('[DryRun] 写入 Firefox 策略：{0}' -f $policyPath)
                continue
            }
            if (-not (Test-Path -LiteralPath $distDir)) {
                New-Item -ItemType Directory -Path $distDir -Force | Out-Null
            }
            $utf8 = New-Object System.Text.UTF8Encoding($false)
            [IO.File]::WriteAllText($policyPath, $json, $utf8)
        } else {
            if ($DryRun) {
                Write-Host ('[DryRun] 恢复 Firefox 策略：{0}' -f $policyPath)
                continue
            }
            if (-not (Test-Path -LiteralPath $marker)) { continue }
            $existed = (Get-Content -LiteralPath $marker -Raw).Trim()
            if ($existed -eq '1') {
                $backup = Join-Path $script:BackupDir ('firefox_{0}.policies.json' -f $index)
                if (Test-Path -LiteralPath $backup) {
                    Copy-Item -LiteralPath $backup -Destination $policyPath -Force
                }
            } else {
                if (Test-Path -LiteralPath $policyPath) {
                    Remove-Item -LiteralPath $policyPath -Force
                }
            }
        }
    }
}

# ---------------------------------------------------------------------
# 统一应用
# ---------------------------------------------------------------------

function Invoke-ApplyGuard {
    param(
        [ValidateSet('locked', 'unlocked')][string]$State,
        $Config,
        [switch]$DryRun
    )

    if (-not $Config) { $Config = Get-GuardConfig }
    if (-not $Config) { throw '未安装' }

    $enabled = ($State -eq 'locked')
    $domains = @(Get-NormalizedDomains $Config.domainBlockList)
    $allow = @(Get-NormalizedDomains $Config.domainAllowList)

    if ($Config.blockApps) {
        try {
            Set-AppBlock -Names @(Get-NormalizedApps $Config.appBlockList) -Enabled $enabled -DryRun:$DryRun
        } catch { Write-Warning ('程序拦截策略部分失败：' + $_.Exception.Message) }
    }
    if ($Config.blockBrowsers) {
        try {
            Set-BrowserPolicy -Domains $domains -Allow $allow -Mode ([string]$Config.mode) `
                -Enabled $enabled -DisableDoH ([bool]$Config.disableDoH) `
                -BlockIncognito ([bool]$Config.blockIncognito) -DryRun:$DryRun
        } catch { Write-Warning ('浏览器注册表策略失败：' + $_.Exception.Message) }
        try {
            Set-FirefoxPolicy -Domains $domains -Allow $allow -Mode ([string]$Config.mode) `
                -Enabled $enabled -DisableDoH ([bool]$Config.disableDoH) `
                -BlockIncognito ([bool]$Config.blockIncognito) -DryRun:$DryRun
        } catch { Write-Warning ('Firefox 策略失败：' + $_.Exception.Message) }
    }
    if ($Config.blockHosts) {
        try {
            Set-HostsBlock -Domains $domains -Enabled $enabled -DryRun:$DryRun
        } catch { Write-Warning ('hosts 文件修改失败：' + $_.Exception.Message) }
    }

    if (-not $DryRun) {
        Set-GuardStateMarker -State $State
        Write-Log ('已应用策略：{0}（模式={1}，网站 {2} 条，程序 {3} 条）' -f `
            $State, $Config.mode, $domains.Count, @(Get-NormalizedApps $Config.appBlockList).Count)
    }
}

function Test-GuardApplied {
    param($Config, [switch]$SkipApps)
    if (-not $Config) { return $false }

    if ($Config.blockBrowsers) {
        $edgeBlock = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLBlocklist'
        $chromeBlock = 'HKLM:\SOFTWARE\Policies\Google\Chrome\URLBlocklist'
        if (-not (Test-Path -LiteralPath $edgeBlock) -and -not (Test-Path -LiteralPath $chromeBlock)) {
            return $false
        }
    }
    if ($Config.blockHosts) {
        if (-not (Test-Path -LiteralPath $script:HostsPath)) { return $false }
        $hosts = [IO.File]::ReadAllText($script:HostsPath)
        if ($hosts.IndexOf($script:BeginMarker, [StringComparison]::OrdinalIgnoreCase) -lt 0) { return $false }
    }
    if ($Config.blockApps -and -not $SkipApps) {
        $apps = @(Get-NormalizedApps $Config.appBlockList)
        if ($apps.Count -gt 0) {
            $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\' + $apps[0]
            if (-not (Test-Path -LiteralPath $key)) { return $false }
            $value = (Get-ItemProperty -Path $key -Name 'Debugger' -ErrorAction SilentlyContinue).Debugger
            if ($value -ne $script:StubPath) { return $false }
        }
    }
    return $true
}

function Invoke-VerifyAndHeal {
    param($Config, [switch]$DryRun)
    if (-not $Config) { return $false }
    $state = Get-EffectiveState $Config
    if ($state -eq 'locked' -and -not (Test-GuardApplied -Config $Config)) {
        Invoke-ApplyGuard -State 'locked' -Config $Config -DryRun:$DryRun
        return $true
    }
    return $false
}

# ---------------------------------------------------------------------
# 申请记录
# ---------------------------------------------------------------------

function Get-GuardRequests {
    if (-not (Test-Path -LiteralPath $script:RequestsDir)) { return @() }
    $items = @()
    foreach ($file in @(Get-ChildItem -LiteralPath $script:RequestsDir -Filter 'req_*.json' -File -ErrorAction SilentlyContinue)) {
        try {
            $raw = [IO.File]::ReadAllText($file.FullName, [Text.Encoding]::UTF8)
            $request = $raw | ConvertFrom-Json
            $request | Add-Member -NotePropertyName 'File' -NotePropertyValue $file.FullName -Force
            $items += $request
        } catch { }
    }
    return @($items | Sort-Object -Property time)
}

function Remove-GuardRequest {
    param([string]$Path)
    if ($Path -and (Test-Path -LiteralPath $Path)) {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------
# 程序用量统计（守护任务每分钟采样一次，只统计带窗口的程序）
# ---------------------------------------------------------------------

function Get-GuardDeviceName {
    $cfg = Get-GuardConfig
    if ($cfg -and -not [string]::IsNullOrWhiteSpace([string]$cfg.deviceName)) {
        return [string]$cfg.deviceName
    }
    return $env:COMPUTERNAME
}

function Get-GuardUsageOpenPath {
    return (Join-Path $script:UsageDir 'open.json')
}

# 上一次真正观测到的时刻（采样空档检测用）：空档里的时间不算给任何程序/站点
function Get-GuardLastObsPath {
    return (Join-Path $script:UsageDir 'lastobs.json')
}

function Read-GuardLastObs {
    $path = Get-GuardLastObsPath
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try {
        $obj = ([IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)) | ConvertFrom-Json
        return [datetime]::ParseExact([string]$obj.ts, 'yyyy-MM-dd HH:mm:ss', $null)
    } catch { return $null }
}

function Save-GuardLastObs {
    param([datetime]$Ts)
    try {
        $path = Get-GuardLastObsPath
        if (-not (Test-Path -LiteralPath $script:UsageDir)) {
            New-Item -ItemType Directory -Path $script:UsageDir -Force | Out-Null
        }
        $json = ('{"ts":"' + $Ts.ToString('yyyy-MM-dd HH:mm:ss') + '"}')
        [IO.File]::WriteAllText($path, $json, (New-Object Text.UTF8Encoding($false)))
    } catch { }
}

function Read-GuardUsageOpen {
    $path = Get-GuardUsageOpenPath
    if (-not (Test-Path -LiteralPath $path)) { return @{} }
    try {
        $raw = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)
        if ([string]::IsNullOrWhiteSpace($raw)) { return @{} }
        $obj = $raw | ConvertFrom-Json
        $table = @{}
        foreach ($p in $obj.PSObject.Properties) {
            $table[$p.Name] = @{
                name  = [string]$p.Value.name
                start = [string]$p.Value.start
            }
        }
        return $table
    } catch {
        return @{}
    }
}

function Save-GuardUsageOpen {
    param([hashtable]$Open)
    $path = Get-GuardUsageOpenPath
    if ($Open.Count -eq 0) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
        return
    }
    if (-not (Test-Path -LiteralPath $script:UsageDir)) {
        New-Item -ItemType Directory -Path $script:UsageDir -Force | Out-Null
    }
    $json = $Open | ConvertTo-Json -Depth 4 -Compress
    [IO.File]::WriteAllText($path, $json, (New-Object Text.UTF8Encoding($false)))
}

function Write-GuardUsageSegment {
    param(
        [string]$Exe,
        [string]$Name,
        [datetime]$Start,
        [datetime]$End
    )
    # 用截断而不是四舍五入：落盘的 e 也是截断到秒的，保证 sec 与 (e - s) 完全一致
    $seconds = [int](($End - $Start).TotalSeconds)
    if ($seconds -lt 30) { return }   # 少于 30 秒的偶发窗口不记录
    if (-not (Test-Path -LiteralPath $script:UsageDir)) {
        New-Item -ItemType Directory -Path $script:UsageDir -Force | Out-Null
    }
    $file = Join-Path $script:UsageDir ('usage_' + $Start.ToString('yyyyMMdd') + '.jsonl')
    $record = [ordered]@{
        d    = (Get-GuardDeviceName)
        exe  = $Exe
        name = $Name
        s    = $Start.ToString('yyyy-MM-dd HH:mm:ss')
        e    = $End.ToString('yyyy-MM-dd HH:mm:ss')
        sec  = $seconds
    }
    $line = ($record | ConvertTo-Json -Compress)
    [IO.File]::AppendAllText($file, $line + "`r`n", (New-Object Text.UTF8Encoding($false)))
}

function Update-GuardUsage {
    $now = Get-Date
    # SYSTEM 会话看不到用户窗口，真实的"正在使用"列表由用户会话里的 UsageMeter 采集后写入 inbox，
    # 这里（SYSTEM 端）只消费 inbox 里 2 分钟内的新鲜快照
    $running = @{}
    $sites = @{}
    $obs = $null

    # 采集任务与守护任务几乎同秒触发，直接读会拿到"上一分钟"的快照（开/闭段整体晚 1-2 分钟）。
    # 这里最多等 9 秒，等用户会话把本分钟的快照写出来；快照长时间不新鲜则不再等待。
    for ($i = 0; $i -lt 3; $i++) {
        $newest = Get-ChildItem -LiteralPath $script:UsageInboxDir -Filter 'sess_*.json' -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($newest -and ((Get-Date) - $newest.LastWriteTime).TotalSeconds -lt 45) { break }
        Start-Sleep -Seconds 3
    }
    $now = Get-Date

    try {
        Set-GuardUsageInboxAcl
        $cutoff = $now.AddMinutes(-2)
        foreach ($f in @(Get-ChildItem -LiteralPath $script:UsageInboxDir -Filter 'sess_*.json' -File -ErrorAction SilentlyContinue)) {
            if ($f.LastWriteTime -lt $cutoff) {
                Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue
                continue
            }
            try {
                $snap = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
                # 记录快照自身的采样时刻：段边界用它比用守护进程启动时刻更贴近真实观测时刻
                if ($snap.ts) {
                    try {
                        $ts = [datetime]::ParseExact([string]$snap.ts, 'yyyy-MM-dd HH:mm:ss', $null)
                        if (-not $obs -or $ts -gt $obs) { $obs = $ts }
                    } catch { }
                }
                foreach ($prop in $snap.procs.PSObject.Properties) {
                    if (-not $running.ContainsKey($prop.Name)) { $running[$prop.Name] = [string]$prop.Value }
                }
                if ($snap.sites) {
                    foreach ($prop in $snap.sites.PSObject.Properties) {
                        if (-not $sites.ContainsKey($prop.Name)) {
                            $sites[$prop.Name] = @{
                                host  = [string]$prop.Value.host
                                basis = [string]$prop.Value.basis
                                note  = [string]$prop.Value.note
                                title = [string]$prop.Value.title
                            }
                        }
                    }
                }
            } catch { }
        }
    } catch { }

    $open = Read-GuardUsageOpen
    $changed = $false
    # 边界时刻：优先用快照采样时刻（快照过期太久时退回当前时刻）
    $boundary = $now
    if ($obs -and ($now - $obs).TotalSeconds -lt 150) { $boundary = $obs }

    # 采样空档（休眠/关机/任务未运行）：空档里没有任何观测，不能把这段时间算给程序或站点。
    # 超过 150 秒没有观测就把开着的段收口在上次观测时刻，再从 boundary 重新开段。
    $gap = $false
    $lastObs = Read-GuardLastObs
    if ($lastObs -and ($boundary - $lastObs).TotalSeconds -gt 150) { $gap = $true }
    $closeAt = $boundary
    if ($gap) { $closeAt = $lastObs }

    if ($gap) {
        foreach ($exe in @($open.Keys)) {
            $entry = $open[$exe]
            $startTime = $null
            try { $startTime = [datetime]::ParseExact([string]$entry.start, 'yyyy-MM-dd HH:mm:ss', $null) } catch { $startTime = $null }
            if ($startTime) {
                try { Write-GuardUsageSegment -Exe $exe -Name ([string]$entry.name) -Start $startTime -End $closeAt } catch { }
            }
        }
        $open = @{}
        $changed = $true
    }

    # 新出现的程序：开启一段
    foreach ($exe in $running.Keys) {
        if (-not $open.ContainsKey($exe)) {
            $open[$exe] = @{ name = $running[$exe]; start = $boundary.ToString('yyyy-MM-dd HH:mm:ss') }
            $changed = $true
        }
    }

    # 已关闭的程序：结束该段并落盘
    foreach ($exe in @($open.Keys)) {
        if (-not $running.ContainsKey($exe)) {
            $entry = $open[$exe]
            $startTime = $null
            try {
                $startTime = [datetime]::ParseExact([string]$entry.start, 'yyyy-MM-dd HH:mm:ss', $null)
            } catch { $startTime = $null }
            if ($startTime) {
                try {
                    Write-GuardUsageSegment -Exe $exe -Name ([string]$entry.name) -Start $startTime -End $closeAt
                } catch { }
            }
            $open.Remove($exe)
            $changed = $true
        }
    }

    if ($changed) { Save-GuardUsageOpen -Open $open }

    # 浏览器站点维度：同一份快照里按"浏览器 + 当前站点"开段/闭段
    try { Update-GuardWebUsage -Running $running -Sites $sites -Now $boundary -CloseAt $closeAt -Reset:$gap } catch { }

    # 只有拿到新鲜快照时才推进"上次观测时刻"，避免把停机时间当成已观测
    if ($obs) { Save-GuardLastObs -Ts $boundary }

    # 每小时整点附近清理一次历史文件
    if ($now.Minute -eq 0) { Remove-GuardOldUsage -KeepDays 30 }
}

# 确保 usage\inbox 目录存在且 ACL 正确：任何登录用户可写入自己的快照文件，
# 但只有创建者能改/删自己的文件（CREATOR OWNER），SYSTEM 始终完全控制
function Set-GuardUsageInboxAcl {
    if (Test-Path -LiteralPath $script:UsageInboxDir) {
        if ($script:UsageInboxAclDone) { return }
    } else {
        New-Item -ItemType Directory -Path $script:UsageInboxDir -Force | Out-Null
    }
    try {
        & icacls.exe $script:UsageInboxDir /inheritance:d 2>$null | Out-Null
        & icacls.exe $script:UsageInboxDir /grant 'Users:(WD,AD)' 2>$null | Out-Null
        & icacls.exe $script:UsageInboxDir /grant 'CREATOR OWNER:(OI)(CI)(IO)(F)' 2>$null | Out-Null
        & icacls.exe $script:UsageInboxDir /grant 'SYSTEM:(OI)(CI)(F)' 2>$null | Out-Null
        & icacls.exe $script:UsageInboxDir /grant 'Administrators:(OI)(CI)(F)' 2>$null | Out-Null
        # 采集脚本本身需要对普通用户可读（Limited 令牌下任务才能加载它）
        $meterScript = Join-Path $script:GuardRoot 'UsageMeter.ps1'
        if (Test-Path -LiteralPath $meterScript) {
            & icacls.exe $meterScript /grant 'Users:(R)' 2>$null | Out-Null
        }
        $script:UsageInboxAclDone = $true
    } catch { }
}

function Remove-GuardOldUsage {
    param([int]$KeepDays = 30)
    if (-not (Test-Path -LiteralPath $script:UsageDir)) { return }
    $limit = (Get-Date).AddDays(-1 * $KeepDays)
    foreach ($pattern in @('usage_*.jsonl', 'web_*.jsonl')) {
        foreach ($file in @(Get-ChildItem -LiteralPath $script:UsageDir -Filter $pattern -File -ErrorAction SilentlyContinue)) {
            if ($file.LastWriteTime -lt $limit) {
                Remove-Item -LiteralPath $file.FullName -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Get-GuardUsageDevices {
    $devices = @{}
    if (Test-Path -LiteralPath $script:UsageDir) {
        foreach ($pattern in @('usage_*.jsonl', 'web_*.jsonl')) {
            foreach ($file in @(Get-ChildItem -LiteralPath $script:UsageDir -Filter $pattern -File -ErrorAction SilentlyContinue)) {
                foreach ($line in @([IO.File]::ReadAllLines($file.FullName, [Text.Encoding]::UTF8))) {
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }
                    try {
                        $rec = $line | ConvertFrom-Json
                        $dev = [string]$rec.d
                        if ([string]::IsNullOrWhiteSpace($dev)) { $dev = $env:COMPUTERNAME }
                        $last = [string]$rec.e
                        if (-not $devices.ContainsKey($dev) -or $devices[$dev] -lt $last) {
                            $devices[$dev] = $last
                        }
                    } catch { }
                }
            }
        }
    }
    $open = Read-GuardUsageOpen
    if ($open.Count -gt 0) {
        $dev = Get-GuardDeviceName
        $nowText = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        if (-not $devices.ContainsKey($dev) -or $devices[$dev] -lt $nowText) {
            $devices[$dev] = $nowText
        }
    }
    $list = @()
    foreach ($name in @($devices.Keys | Sort-Object)) {
        $list += [ordered]@{
            name       = $name
            lastActive = $devices[$name]
            current    = ($name -eq (Get-GuardDeviceName))
        }
    }
    return @($list)
}

function Get-GuardUsageReport {
    param(
        [string]$Device,
        [string]$Date   # yyyyMMdd，默认今天
    )
    if ([string]::IsNullOrWhiteSpace($Date) -or $Date -notmatch '^\d{8}$') {
        $Date = (Get-Date).ToString('yyyyMMdd')
    }
    $dayStart = [datetime]::ParseExact($Date, 'yyyyMMdd', $null)
    $now = Get-Date
    $dayEnd = $dayStart.AddDays(1)
    if ($dayEnd -gt $now) { $dayEnd = $now }

    $segments = @()
    # 读前一天与当天文件：前一天开启、跨午夜结束的会话也计入当天
    foreach ($d in @($dayStart.AddDays(-1), $dayStart)) {
        $file = Join-Path $script:UsageDir ('usage_' + $d.ToString('yyyyMMdd') + '.jsonl')
        if (-not (Test-Path -LiteralPath $file)) { continue }
        foreach ($line in @([IO.File]::ReadAllLines($file, [Text.Encoding]::UTF8))) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try { $segments += ($line | ConvertFrom-Json) } catch { }
        }
    }
    # 正在进行的会话（结束时间按当前时刻显示）
    $open = Read-GuardUsageOpen
    foreach ($exe in $open.Keys) {
        $entry = $open[$exe]
        $segments += [pscustomobject]@{
            d    = (Get-GuardDeviceName)
            exe  = $exe
            name = [string]$entry.name
            s    = [string]$entry.start
            e    = $now.ToString('yyyy-MM-dd HH:mm:ss')
            live = $true
        }
    }

    $programs = @{}
    foreach ($rec in $segments) {
        if (-not [string]::IsNullOrWhiteSpace($Device) -and [string]$rec.d -ne $Device) { continue }
        $s = $null; $e = $null
        try { $s = [datetime]::ParseExact([string]$rec.s, 'yyyy-MM-dd HH:mm:ss', $null) } catch { }
        try { $e = [datetime]::ParseExact([string]$rec.e, 'yyyy-MM-dd HH:mm:ss', $null) } catch { }
        if (-not $s -or -not $e) { continue }
        # 只保留与当天有交集的段，并把起止时间裁剪到当天范围内
        if ($e -le $dayStart -or $s -ge $dayEnd) { continue }
        if ($s -lt $dayStart) { $s = $dayStart }
        if ($e -gt $dayEnd) { $e = $dayEnd }
        $secs = [int][math]::Max(0, ($e - $s).TotalSeconds)
        if ($secs -lt 1) { continue }
        $exe = [string]$rec.exe
        if (-not $programs.ContainsKey($exe)) {
            $programs[$exe] = @{
                name = [string]$rec.name
                exe = $exe
                totalSeconds = 0
                sessions = @()
            }
        }
        $programs[$exe].totalSeconds += $secs
        $programs[$exe].sessions += [ordered]@{
            start   = $s.ToString('HH:mm')
            end     = $(if ($rec.live) { '进行中' } else { $e.ToString('HH:mm') })
            seconds = $secs
        }
    }

    $items = @()
    foreach ($exe in $programs.Keys) {
        $p = $programs[$exe]
        $items += [ordered]@{
            exe          = $p.exe
            name         = $p.name
            totalSeconds = $p.totalSeconds
            sessions     = @($p.sessions)
        }
    }
    return [ordered]@{
        date   = $Date
        device = $Device
        items  = @($items | Sort-Object -Property totalSeconds -Descending)
    }
}

# ---------------------------------------------------------------------
# 网站用量统计（浏览器当前站点由用户会话侧判定，SYSTEM 侧聚合落盘）
# ---------------------------------------------------------------------

function Format-GuardDuration {
    param([int]$Seconds)
    if ($Seconds -lt 60) { return ('{0} 秒' -f $Seconds) }
    $m = [int][math]::Floor($Seconds / 60)
    $h = [int][math]::Floor($m / 60)
    if ($h -gt 0) { return ('{0} 小时 {1} 分' -f $h, ($m % 60)) }
    return ('{0} 分钟' -f $m)
}

function Get-GuardWebOpenPath {
    return (Join-Path $script:UsageDir 'openweb.json')
}

function Read-GuardWebOpen {
    $path = Get-GuardWebOpenPath
    if (-not (Test-Path -LiteralPath $path)) { return @{} }
    try {
        $raw = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)
        if ([string]::IsNullOrWhiteSpace($raw)) { return @{} }
        $obj = $raw | ConvertFrom-Json
        $table = @{}
        foreach ($p in $obj.PSObject.Properties) {
            $table[$p.Name] = @{
                exe   = [string]$p.Value.exe
                host  = [string]$p.Value.host
                basis = [string]$p.Value.basis
                note  = [string]$p.Value.note
                start = [string]$p.Value.start
            }
        }
        return $table
    } catch {
        return @{}
    }
}

function Save-GuardWebOpen {
    param([hashtable]$Open)
    $path = Get-GuardWebOpenPath
    if ($Open.Count -eq 0) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
        return
    }
    if (-not (Test-Path -LiteralPath $script:UsageDir)) {
        New-Item -ItemType Directory -Path $script:UsageDir -Force | Out-Null
    }
    $json = $Open | ConvertTo-Json -Depth 4 -Compress
    [IO.File]::WriteAllText($path, $json, (New-Object Text.UTF8Encoding($false)))
}

function Write-GuardWebSegment {
    param(
        [string]$Exe,
        [string]$HostName,
        [datetime]$Start,
        [datetime]$End,
        [string]$Basis = '',
        [string]$Note = '',
        [bool]$Blocked = $false
    )
    # 同程序段：截断取整，保证 sec == e - s
    $seconds = [int](($End - $Start).TotalSeconds)
    if ($seconds -lt 30) { return }
    if (-not (Test-Path -LiteralPath $script:UsageDir)) {
        New-Item -ItemType Directory -Path $script:UsageDir -Force | Out-Null
    }
    $file = Join-Path $script:UsageDir ('web_' + $Start.ToString('yyyyMMdd') + '.jsonl')
    $record = [ordered]@{
        d    = (Get-GuardDeviceName)
        exe  = $Exe
        host = $HostName
        s    = $Start.ToString('yyyy-MM-dd HH:mm:ss')
        e    = $End.ToString('yyyy-MM-dd HH:mm:ss')
        sec  = $seconds
    }
    # 归因依据随段落落盘：面板据此展示"这一段时间是怎么判出来的"
    if (-not [string]::IsNullOrWhiteSpace($Basis)) { $record['basis'] = $Basis }
    if (-not [string]::IsNullOrWhiteSpace($Note)) { $record['note'] = $Note }
    if ($Blocked) { $record['blocked'] = $true }
    $line = ($record | ConvertTo-Json -Compress)
    [IO.File]::AppendAllText($file, $line + "`r`n", (New-Object Text.UTF8Encoding($false)))
}

# 站点域名是否命中拦截名单（与策略引擎一致：白名单优先）。只用来给段落加"（已拦截）"标记，
# 不改变用量本身；拦截名单只在 SYSTEM 侧读取，避免普通用户从快照里反推出完整拦截名单。
function Test-GuardDomainBlocked {
    param([string]$HostName)
    $h = ([string]$HostName).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($h)) { return $false }
    if (-not $script:GuardBlockDomains) {
        $block = @{}
        $allow = @{}
        try {
            $cfg = Get-GuardConfig
            foreach ($d in @($cfg.domainBlockList)) { $block[([string]$d).ToLowerInvariant().TrimStart('.')] = $true }
            foreach ($d in @($cfg.domainAllowList)) { $allow[([string]$d).ToLowerInvariant().TrimStart('.')] = $true }
        } catch { }
        $script:GuardBlockDomains = @{ block = $block; allow = $allow }
    }
    foreach ($d in @($script:GuardBlockDomains.allow.Keys)) {
        if ($h -eq $d -or $h.EndsWith('.' + $d)) { return $false }
    }
    foreach ($d in @($script:GuardBlockDomains.block.Keys)) {
        if ($h -eq $d -or $h.EndsWith('.' + $d)) { return $true }
    }
    return $false
}

# 浏览器可见时，按"浏览器 + 当前站点"开段/闭段。
# host 为空表示"没有站点"，但仍然带 basis/note 说明真实状态（新标签页/错误页/无证据），
# 报告里这类时间单独列出，不再用"未知"兜底。
function Update-GuardWebUsage {
    param(
        [hashtable]$Running,
        [hashtable]$Sites,
        [datetime]$Now,
        [datetime]$CloseAt = $Now,
        [switch]$Reset
    )
    $webOpen = Read-GuardWebOpen
    $changed = $false

    # 休眠/停机导致的采样空档：先把所有开着的段收口在最后一次观测时刻，
    # 空档期间没有观测，不能算到任何站点头上
    if ($Reset) {
        foreach ($key in @($webOpen.Keys)) {
            $entry = $webOpen[$key]
            $startTime = $null
            try { $startTime = [datetime]::ParseExact([string]$entry.start, 'yyyy-MM-dd HH:mm:ss', $null) } catch { }
            if ($startTime) {
                try {
                    Write-GuardWebSegment -Exe ([string]$entry.exe) -HostName ([string]$entry.host) -Start $startTime -End $CloseAt `
                        -Basis ([string]$entry.basis) -Note ([string]$entry.note) -Blocked (Test-GuardDomainBlocked ([string]$entry.host))
                } catch { }
            }
        }
        $webOpen = @{}
        $changed = $true
    }

    $targets = @{}
    foreach ($exe in $Running.Keys) {
        if ($exe -notmatch '^(msedge|chrome)\.exe$') { continue }
        $hostName = ''
        $basis = ''
        $note = ''
        if ($Sites.ContainsKey($exe)) {
            $hostName = [string]$Sites[$exe].host
            $basis = [string]$Sites[$exe].basis
            $note = [string]$Sites[$exe].note
        }
        if ([string]::IsNullOrWhiteSpace($hostName) -and [string]::IsNullOrWhiteSpace($basis)) {
            $basis = '无页面证据'
            $note = '浏览器窗口存在，但当前页面没有留下可归因的记录'
        }
        $key = $exe + '|' + $hostName
        $targets[$key] = @{ exe = $exe; host = $hostName; basis = $basis; note = $note }
    }

    foreach ($key in @($webOpen.Keys)) {
        $entry = $webOpen[$key]
        $isTarget = $targets.ContainsKey($key)
        $basisChanged = $false
        if ($isTarget -and [string]::IsNullOrWhiteSpace($targets[$key].host)) {
            # 空 host 段：依据变了（例如 新标签页 → 错误页）就收口重开，保证依据跟着时段走
            if ([string]$entry.basis -ne [string]$targets[$key].basis) { $basisChanged = $true }
        }
        if (-not $isTarget -or $basisChanged) {
            $startTime = $null
            try { $startTime = [datetime]::ParseExact([string]$entry.start, 'yyyy-MM-dd HH:mm:ss', $null) } catch { }
            if ($startTime) {
                try {
                    Write-GuardWebSegment -Exe ([string]$entry.exe) -HostName ([string]$entry.host) -Start $startTime -End $CloseAt `
                        -Basis ([string]$entry.basis) -Note ([string]$entry.note) -Blocked (Test-GuardDomainBlocked ([string]$entry.host))
                } catch { }
            }
            if ($basisChanged) {
                $webOpen[$key] = @{
                    exe   = $entry.exe
                    host  = ''
                    basis = $targets[$key].basis
                    note  = $targets[$key].note
                    start = $Now.ToString('yyyy-MM-dd HH:mm:ss')
                }
            } else {
                $webOpen.Remove($key)
            }
            $changed = $true
        }
    }
    foreach ($key in $targets.Keys) {
        if (-not $webOpen.ContainsKey($key)) {
            $webOpen[$key] = @{
                exe   = $targets[$key].exe
                host  = $targets[$key].host
                basis = $targets[$key].basis
                note  = $targets[$key].note
                start = $Now.ToString('yyyy-MM-dd HH:mm:ss')
            }
            $changed = $true
        }
    }
    if ($changed) { Save-GuardWebOpen -Open $webOpen }
}

# ---------------------------------------------------------------------
# 站点分类（用于分析报告；只做域名后缀匹配，匹配不到归入"其他"）
# ---------------------------------------------------------------------
function Get-GuardSiteCategoryMap {
    if ($script:SiteCategoryMap) { return $script:SiteCategoryMap }
    $map = @(
        @{ cat = '视频'; domains = @('bilibili.com', 'douyin.com', 'tiktok.com', 'iqiyi.com', 'youku.com', 'v.qq.com', 'mgtv.com', 'youtube.com', 'netflix.com', 'ixigua.com', 'huya.com', 'douyu.com', 'twitch.tv', 'haokan.baidu.com') },
        @{ cat = '游戏'; domains = @('steampowered.com', 'steamcommunity.com', 'epicgames.com', '4399.com', '7k7k.com', '17173.com', 'game.qq.com', 'lol.qq.com', 'minecraft.net', 'roblox.com', 'blizzard.com', 'ea.com', 'taptap.com') },
        @{ cat = '学习'; domains = @('github.com', 'gitlab.com', 'gitee.com', 'csdn.net', 'cnblogs.com', 'juejin.cn', 'leetcode.cn', 'leetcode.com', 'coursera.org', 'edx.org', 'khanacademy.org', 'wikipedia.org', 'baike.baidu.com', 'runoob.com', 'w3school.com.cn', 'icourse163.org', 'xueersi.com', 'zuoyebang.com', 'yuanfudao.com', 'mooc.org') },
        @{ cat = '社交'; domains = @('weibo.com', 'zhihu.com', 'douban.com', 'tieba.baidu.com', 'qq.com', 'weixin.qq.com', 'facebook.com', 'twitter.com', 'x.com', 'instagram.com', 'reddit.com', 'discord.com', 'telegram.org', 'linkedin.com') },
        @{ cat = '购物'; domains = @('taobao.com', 'tmall.com', 'jd.com', 'pinduoduo.com', 'yangkeduo.com', 'amazon.com', 'aliexpress.com', 'suning.com', 'vip.com') },
        @{ cat = '新闻'; domains = @('news.qq.com', 'sina.com.cn', 'weibo.com', 'sohu.com', '163.com', 'thepaper.cn', 'ifeng.com', 'cctv.com', 'people.com.cn') },
        @{ cat = '工具'; domains = @('baidu.com', 'bing.com', 'google.com', 'sogou.com', 'so.com', 'office.com', 'microsoft.com', 'apple.com', 'aliyun.com', 'notion.so', 'translate.google.com', 'docs.qq.com', 'docs.google.com', 'wps.cn') }
    )
    # 展开成"域名 -> 类别"，按域名长度倒序，保证子域优先于父域
    $flat = @{}
    foreach ($item in $map) {
        foreach ($d in $item.domains) { $flat[$d] = $item.cat }
    }
    $script:SiteCategoryMap = $flat
    return $flat
}

function Get-GuardSiteCategory {
    param([string]$HostName)
    $h = ([string]$HostName).ToLowerInvariant()
    # 没有站点就不是类别：返回空串，由报告单独列为"未归因"，不再出现"未知"类别
    if ([string]::IsNullOrWhiteSpace($h)) { return '' }
    $flat = Get-GuardSiteCategoryMap
    $best = ''
    $bestCat = ''
    foreach ($domain in @($flat.Keys)) {
        if ($h -eq $domain -or $h.EndsWith('.' + $domain)) {
            if ($domain.Length -gt $best.Length) {
                $best = $domain
                $bestCat = [string]$flat[$domain]
            }
        }
    }
    if ($bestCat) { return $bestCat }
    return '其他'
}

function Get-GuardWebSegments {
    param(
        [string]$Device,
        [datetime]$Start,
        [datetime]$End
    )
    $segments = @()
    $from = $Start.Date.AddDays(-1)
    $to = $End.Date
    for ($d = $from; $d -le $to; $d = $d.AddDays(1)) {
        $file = Join-Path $script:UsageDir ('web_' + $d.ToString('yyyyMMdd') + '.jsonl')
        if (-not (Test-Path -LiteralPath $file)) { continue }
        foreach ($line in @([IO.File]::ReadAllLines($file, [Text.Encoding]::UTF8))) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try { $segments += ($line | ConvertFrom-Json) } catch { }
        }
    }
    # 正在进行的站点会话
    $webOpen = Read-GuardWebOpen
    $now = Get-Date
    foreach ($entry in $webOpen.Values) {
        $segments += [pscustomobject]@{
            d       = (Get-GuardDeviceName)
            exe     = [string]$entry.exe
            host    = [string]$entry.host
            s       = [string]$entry.start
            e       = $now.ToString('yyyy-MM-dd HH:mm:ss')
            basis   = [string]$entry.basis
            note    = [string]$entry.note
            blocked = (Test-GuardDomainBlocked ([string]$entry.host))
            live    = $true
        }
    }

    $result = @()
    foreach ($rec in $segments) {
        if (-not [string]::IsNullOrWhiteSpace($Device) -and [string]$rec.d -ne $Device) { continue }
        $s = $null; $e = $null
        try { $s = [datetime]::ParseExact([string]$rec.s, 'yyyy-MM-dd HH:mm:ss', $null) } catch { }
        try { $e = [datetime]::ParseExact([string]$rec.e, 'yyyy-MM-dd HH:mm:ss', $null) } catch { }
        if (-not $s -or -not $e) { continue }
        if ($e -le $Start -or $s -ge $End) { continue }
        if ($s -lt $Start) { $s = $Start }
        if ($e -gt $End) { $e = $End }
        $secs = [int][math]::Max(0, ($e - $s).TotalSeconds)
        if ($secs -lt 1) { continue }
        $hostName = [string]$rec.host
        $basis = ''
        $note = ''
        $blocked = $false
        if ($rec.PSObject.Properties['basis']) { $basis = [string]$rec.basis }
        if ($rec.PSObject.Properties['note']) { $note = [string]$rec.note }
        if ($rec.PSObject.Properties['blocked']) { $blocked = [bool]$rec.blocked }
        # 旧数据没有依据字段：有域名就按历史记录归属，空域名单独说明
        if ([string]::IsNullOrWhiteSpace($basis)) {
            $basis = $(if ($hostName) { '历史标题匹配' } else { '无页面证据' })
        }
        if ([string]::IsNullOrWhiteSpace($note)) {
            $note = $(if ($hostName) { '' } else { '旧记录：当时未取到可归因的页面信息' })
        }
        if (-not $blocked -and $hostName) { $blocked = (Test-GuardDomainBlocked $hostName) }
        $result += [pscustomobject]@{
            exe     = [string]$rec.exe
            host    = $hostName
            s       = $s
            e       = $e
            sec     = $secs
            basis   = $basis
            note    = $note
            blocked = $blocked
            live    = [bool]$rec.live
        }
    }
    return @($result)
}

# 单个浏览器当天的站点明细（供程序用量列表展开）。
# 有站点的时间进 items；没有站点的时间单独放 unattributed，并带上真实原因。
function Get-GuardSiteDetail {
    param(
        [string]$Device,
        [string]$Date,
        [string]$Exe
    )
    if ([string]::IsNullOrWhiteSpace($Date) -or $Date -notmatch '^\d{8}$') {
        $Date = (Get-Date).ToString('yyyyMMdd')
    }
    $dayStart = [datetime]::ParseExact($Date, 'yyyyMMdd', $null)
    $dayEnd = $dayStart.AddDays(1)
    $now = Get-Date
    if ($dayEnd -gt $now) { $dayEnd = $now }

    $segments = Get-GuardWebSegments -Device $Device -Start $dayStart -End $dayEnd
    $exeFilter = ([string]$Exe).ToLowerInvariant()
    $sites = @{}
    $unattr = @{}
    foreach ($rec in $segments) {
        if ($exeFilter -and $rec.exe.ToLowerInvariant() -ne $exeFilter) { continue }
        $session = [ordered]@{
            start   = $rec.s.ToString('HH:mm')
            end     = $(if ($rec.live) { '进行中' } else { $rec.e.ToString('HH:mm') })
            seconds = $rec.sec
        }
        if ([string]::IsNullOrWhiteSpace($rec.host)) {
            $reason = $(if ($rec.note) { [string]$rec.note } else { '未取到可归因的页面信息' })
            $uk = [string]$rec.basis + '|' + $reason
            if (-not $unattr.ContainsKey($uk)) {
                $unattr[$uk] = [ordered]@{
                    basis        = [string]$rec.basis
                    reason       = $reason
                    totalSeconds = 0
                    sessions     = @()
                }
            }
            $unattr[$uk].totalSeconds += $rec.sec
            if ($unattr[$uk].sessions.Count -lt 12) { $unattr[$uk].sessions += $session }
            continue
        }
        $key = $rec.host
        if (-not $sites.ContainsKey($key)) {
            $sites[$key] = [ordered]@{
                host         = $key
                name         = $key
                category     = (Get-GuardSiteCategory $key)
                basis        = [string]$rec.basis
                blocked      = [bool]$rec.blocked
                totalSeconds = 0
                sessions     = @()
            }
        }
        if ([string]::IsNullOrWhiteSpace([string]$sites[$key].basis) -and $rec.basis) { $sites[$key].basis = [string]$rec.basis }
        if ($rec.blocked) { $sites[$key].blocked = $true }
        $sites[$key].totalSeconds += $rec.sec
        if ($sites[$key].sessions.Count -lt 12) { $sites[$key].sessions += $session }
    }

    $items = @()
    foreach ($k in $sites.Keys) { $items += $sites[$k] }
    $items = @($items | Sort-Object -Property { $_.totalSeconds } -Descending)
    $unattrItems = @()
    foreach ($k in $unattr.Keys) { $unattrItems += $unattr[$k] }
    $unattrItems = @($unattrItems | Sort-Object -Property { $_.totalSeconds } -Descending)
    $total = 0
    foreach ($i in $items) { $total += $i.totalSeconds }
    $unattrTotal = 0
    foreach ($i in $unattrItems) { $unattrTotal += $i.totalSeconds }
    $total += $unattrTotal

    return [ordered]@{
        date             = $Date
        device           = $Device
        exe              = $Exe
        totalSeconds     = $total
        unattributedSecs = $unattrTotal
        items            = @($items)
        unattributed     = @($unattrItems)
    }
}

# 网站使用分析报告（按天 / 按周），供手机面板复用。
# 口径：totalSeconds = 浏览器可见的总时长；sites = 有具体站点的时间；unattributed = 没有站点的时间及原因。
# 类别归集和站点排名都不包含 unattributed，避免把"没有站点"混进站点列表。
function Get-GuardSiteReport {
    param(
        [string]$Device,
        [string]$Date,
        [string]$Range = 'day'
    )
    if ([string]::IsNullOrWhiteSpace($Date) -or $Date -notmatch '^\d{8}$') {
        $Date = (Get-Date).ToString('yyyyMMdd')
    }
    $dayStart = [datetime]::ParseExact($Date, 'yyyyMMdd', $null)
    $now = Get-Date
    $dayEnd = $dayStart.AddDays(1)
    if ($dayEnd -gt $now) { $dayEnd = $now }

    $isWeek = ([string]$Range).ToLowerInvariant() -eq 'week'
    $start = $(if ($isWeek) { $dayStart.AddDays(-6) } else { $dayStart })
    $trendStart = $dayStart.AddDays(-6)

    # 一次取够 7 天数据，同时用于区间统计和趋势
    $segments = Get-GuardWebSegments -Device $Device -Start $trendStart -End $dayEnd

    $sites = @{}
    $hourly = New-Object 'int[]' 24
    $total = 0
    $unattr = @{}
    $categorySeconds = @{}

    foreach ($rec in $segments) {
        # 区间内（按天 = 当天；按周 = 最近 7 天）统计，跨午夜的段裁剪到区间边界
        if ($rec.e -le $start -or $rec.s -ge $dayEnd) { continue }
        $rs = $rec.s; $re = $rec.e
        if ($rs -lt $start) { $rs = $start }
        if ($re -gt $dayEnd) { $re = $dayEnd }
        $secs = [int][math]::Max(0, ($re - $rs).TotalSeconds)
        if ($secs -lt 1) { continue }
        $total += $secs
        if ($isWeek) {
            $sStart = $rs.ToString('MM-dd HH:mm')
            $sEnd = $(if ($rec.live) { '进行中' } else { $re.ToString('HH:mm') })
        } else {
            $sStart = $rs.ToString('HH:mm')
            $sEnd = $(if ($rec.live) { '进行中' } else { $re.ToString('HH:mm') })
        }
        if ([string]::IsNullOrWhiteSpace($rec.host)) {
            # 没有具体站点：按"依据 + 原因"分桶单独说明，不进站点排名/类别
            $reason = $(if ($rec.note) { [string]$rec.note } else { '未取到可归因的页面信息' })
            $uk = [string]$rec.basis + '|' + $reason
            if (-not $unattr.ContainsKey($uk)) {
                $unattr[$uk] = [ordered]@{
                    basis        = [string]$rec.basis
                    reason       = $reason
                    totalSeconds = 0
                    sessions     = @()
                }
            }
            $unattr[$uk].totalSeconds += $secs
            if ($unattr[$uk].sessions.Count -lt 12) {
                $unattr[$uk].sessions += [ordered]@{ start = $sStart; end = $sEnd; seconds = $secs }
            }
        } else {
            $key = $rec.host
            if (-not $sites.ContainsKey($key)) {
                $sites[$key] = [ordered]@{
                    host         = $key
                    name         = $key
                    category     = (Get-GuardSiteCategory $key)
                    basis        = [string]$rec.basis
                    blocked      = [bool]$rec.blocked
                    totalSeconds = 0
                    sessions     = @()
                }
            }
            if ([string]::IsNullOrWhiteSpace([string]$sites[$key].basis) -and $rec.basis) { $sites[$key].basis = [string]$rec.basis }
            if ($rec.blocked) { $sites[$key].blocked = $true }
            $sites[$key].totalSeconds += $secs
            if ($sites[$key].sessions.Count -lt 12) {
                $sites[$key].sessions += [ordered]@{ start = $sStart; end = $sEnd; seconds = $secs }
            }
            $cat = [string]$sites[$key].category
            if (-not $categorySeconds.ContainsKey($cat)) { $categorySeconds[$cat] = 0 }
            $categorySeconds[$cat] += $secs
        }

        # 时段分布：把每段按小时边界切开累计
        $cursor = $rs
        while ($cursor -lt $re) {
            $hourIndex = [int]$cursor.Hour
            $nextHour = $cursor.Date.AddHours($cursor.Hour + 1)
            $sliceEnd = $(if ($nextHour -lt $re) { $nextHour } else { $re })
            $hourly[$hourIndex] += [int][math]::Max(0, ($sliceEnd - $cursor).TotalSeconds)
            $cursor = $sliceEnd
        }
    }

    # 站点排名（不含没有站点的时间）
    $items = @()
    foreach ($k in $sites.Keys) { $items += $sites[$k] }
    $items = @($items | Sort-Object -Property { $_.totalSeconds } -Descending)
    $attributed = 0
    foreach ($i in $items) { $attributed += $i.totalSeconds }

    # 未归因时间：单独列出原因，不混进站点列表
    $unattrItems = @()
    $unattrTotal = 0
    foreach ($k in $unattr.Keys) {
        $unattrItems += $unattr[$k]
        $unattrTotal += [int]$unattr[$k].totalSeconds
    }
    $unattrItems = @($unattrItems | Sort-Object -Property { $_.totalSeconds } -Descending)

    # 占比用"最大余数法"分配：站点 + 未归因合计严格 100%，不出现 101%
    $denom = [math]::Max($total, 1)
    $raw = @()
    foreach ($i in $items) { $raw += (100.0 * $i.totalSeconds / $denom) }
    foreach ($u in $unattrItems) { $raw += (100.0 * $u.totalSeconds / $denom) }
    $floors = @(); $fracs = @(); $sumFloor = 0
    foreach ($v in $raw) {
        $f = [math]::Floor($v)
        $floors += [int]$f
        $fracs += ($v - $f)
        $sumFloor += [int]$f
    }
    $bump = @{}
    if ($raw.Count -gt 0) {
        $need = [int](100 - $sumFloor)
        if ($need -gt 0) {
            $order = @(0..($raw.Count - 1) | Sort-Object -Property { -1 * $fracs[$_] } | Select-Object -First $need)
            foreach ($ix in $order) { $bump[[int]$ix] = $true }
        }
    }
    $idx = 0
    foreach ($i in $items) {
        $i['percent'] = $floors[$idx] + $(if ($bump.ContainsKey($idx)) { 1 } else { 0 })
        $idx++
    }
    $attributedPct = 0
    foreach ($i in $items) { $attributedPct += [int]$i['percent'] }
    foreach ($u in $unattrItems) {
        $u['percent'] = $floors[$idx] + $(if ($bump.ContainsKey($idx)) { 1 } else { 0 })
        $idx++
    }

    # 类别归集：类别只覆盖有站点的部分，占比按"站点占比总量"分配到 100%（不含未归因）
    $categories = @()
    foreach ($cat in @($categorySeconds.Keys)) {
        $categories += [ordered]@{
            name    = $cat
            seconds = [int]$categorySeconds[$cat]
            percent = 0
        }
    }
    $categories = @($categories | Sort-Object -Property { $_.seconds } -Descending)
    if ($attributedPct -gt 0 -and $categories.Count -gt 0) {
        $craw = @()
        foreach ($c in $categories) { $craw += (1.0 * $attributedPct * $c.seconds / [math]::Max($attributed, 1)) }
        $cfloors = @(); $cfrac = @(); $csum = 0
        foreach ($v in $craw) {
            $f = [math]::Floor($v)
            $cfloors += [int]$f
            $cfrac += ($v - $f)
            $csum += [int]$f
        }
        $cb = @{}
        $needc = [int]($attributedPct - $csum)
        if ($needc -gt 0) {
            $co = @(0..($craw.Count - 1) | Sort-Object -Property { -1 * $cfrac[$_] } | Select-Object -First $needc)
            foreach ($ix in $co) { $cb[[int]$ix] = $true }
        }
        for ($ci = 0; $ci -lt $categories.Count; $ci++) {
            $categories[$ci]['percent'] = $cfloors[$ci] + $(if ($cb.ContainsKey($ci)) { 1 } else { 0 })
        }
    }

    # 趋势：最近 7 天每天的浏览器总时长
    $trend = @()
    for ($i = 6; $i -ge 0; $i--) {
        $dStart = $dayStart.AddDays(-1 * $i)
        $dEnd = $dStart.AddDays(1)
        if ($dEnd -gt $now) { $dEnd = $now }
        $secs = 0
        $bestHost = ''
        $bestSecs = 0
        $perHost = @{}
        foreach ($rec in $segments) {
            if ($rec.e -le $dStart -or $rec.s -ge $dEnd) { continue }
            $s = $rec.s; $e = $rec.e
            if ($s -lt $dStart) { $s = $dStart }
            if ($e -gt $dEnd) { $e = $dEnd }
            $slice = [int][math]::Max(0, ($e - $s).TotalSeconds)
            if ($slice -lt 1) { continue }
            $secs += $slice
            $h = [string]$rec.host
            if ([string]::IsNullOrWhiteSpace($h)) { continue }
            if (-not $perHost.ContainsKey($h)) { $perHost[$h] = 0 }
            $perHost[$h] += $slice
        }
        foreach ($h in $perHost.Keys) {
            if ($perHost[$h] -gt $bestSecs) { $bestSecs = $perHost[$h]; $bestHost = $h }
        }
        $trend += [ordered]@{
            date    = $dStart.ToString('yyyyMMdd')
            label   = $dStart.ToString('MM-dd')
            seconds = $secs
            topHost = $(if ($bestHost) { $bestHost } else { '' })
        }
    }

    # 关注提示
    $alerts = @()
    $dayFactor = $(if ($isWeek) { 7 } else { 1 })
    $avgTotal = [int]($total / $dayFactor)
    if ($total -lt 300) {
        $alerts += [ordered]@{ level = 'info'; text = '浏览器使用很少，暂无足够数据做分析。' }
    } else {
        if ($unattrTotal -gt 0 -and ($unattrTotal / [math]::Max($total, 1)) -ge 0.4) {
            $reasonText = (@($unattrItems | Select-Object -First 2 | ForEach-Object { $_.reason }) -join '；')
            $alerts += [ordered]@{ level = 'warn'; text = ('有 {0} 的浏览器时间没有具体站点（{1}），已在下方单独列出，未计入站点排名。' -f (Format-GuardDuration $unattrTotal), $reasonText) }
        }
        if ($items.Count -gt 0 -and $items[0].totalSeconds -ge (2 * 3600) * $dayFactor) {
            $topName = [string]$items[0].name
            if ($items[0].blocked) { $topName += '（已拦截）' }
            $alerts += [ordered]@{ level = 'warn'; text = ('停留在 {0} 的时间较长（{1}），建议关注使用内容。' -f $topName, (Format-GuardDuration $items[0].totalSeconds)) }
        }
        $night = 0
        for ($h = 0; $h -lt 24; $h++) {
            if ($h -ge 22 -or $h -lt 6) { $night += $hourly[$h] }
        }
        if ($night -ge (30 * 60) * $dayFactor) {
            $alerts += [ordered]@{ level = 'warn'; text = ('夜间（22:00-06:00）浏览器使用 {0}，建议约定作息。' -f (Format-GuardDuration $night)) }
        }
        $play = 0
        foreach ($c in $categories) {
            if ($c.name -eq '视频' -or $c.name -eq '游戏') { $play += $c.seconds }
        }
        if ($play -gt 0 -and ($play / [math]::Max($total, 1)) -ge 0.6 -and $total -ge (45 * 60) * $dayFactor) {
            $alerts += [ordered]@{ level = 'warn'; text = ('视频/游戏类占比 {0}%，娱乐时间偏多。' -f [int][math]::Round(100 * $play / $total)) }
        }
        foreach ($c in $categories) {
            if ($c.name -eq '学习' -and $c.percent -ge 50) {
                $alerts += [ordered]@{ level = 'good'; text = ('学习类站点占 {0}%，使用结构良好。' -f $c.percent) }
                break
            }
        }
        if (-not $isWeek) {
            $prevDays = @($trend | Where-Object { $_.date -ne $dayStart.ToString('yyyyMMdd') })
            $prevAvg = 0
            if ($prevDays.Count -gt 0) {
                $sum = 0
                foreach ($t in $prevDays) { $sum += $t.seconds }
                $prevAvg = [int]($sum / $prevDays.Count)
            }
            if ($prevAvg -ge (10 * 60) -and $total -ge (30 * 60) -and $total -gt (1.5 * $prevAvg)) {
                $alerts += [ordered]@{ level = 'info'; text = ('比前几日平均（{0}）明显增加。' -f (Format-GuardDuration $prevAvg)) }
            }
        }
    }

    return [ordered]@{
        date             = $Date
        range            = $(if ($isWeek) { 'week' } else { 'day' })
        start            = $start.ToString('yyyy-MM-dd')
        end              = $dayEnd.ToString('yyyy-MM-dd HH:mm')
        totalSeconds     = $total
        avgPerDay        = $avgTotal
        siteCount        = $items.Count
        attributedSecs   = $attributed
        unattributedSecs = $unattrTotal
        sites            = @($items)
        unattributed     = @($unattrItems)
        categories       = @($categories)
        hourly           = @($hourly)
        trend            = @($trend)
        alerts           = @($alerts)
    }
}

# ---------------------------------------------------------------------
# 自检（-DryRun 只打印，不修改系统）
# ---------------------------------------------------------------------

function Assert-SelfTest {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw ('自检失败：' + $Message) }
    Write-Host ('[OK] ' + $Message)
}

function Invoke-SelfTest {
    param([switch]$DryRun)

    $tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('ParentGuardTest_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    try {
        Initialize-GuardPaths -Root $tempRoot
        New-Item -ItemType Directory -Path $script:RequestsDir -Force | Out-Null

        $cfg = Get-DefaultConfig
        Save-GuardConfig $cfg
        Assert-SelfTest (Test-Path -LiteralPath $script:ConfigPath) '配置文件已生成'

        $loaded = Get-GuardConfig
        Assert-SelfTest (@($loaded.domainBlockList).Count -gt 30) '网站拦截名单包含默认条目'
        Assert-SelfTest (@($loaded.domainAllowList).Count -ge 15) '网站白名单包含默认条目'
        Assert-SelfTest (@($loaded.appBlockList).Count -ge 7) '程序拦截名单包含默认条目'

        Set-GuardPassword -Password 'Test#12345'
        Assert-SelfTest (Test-GuardPassword -Password 'Test#12345') '正确密码校验通过'
        Assert-SelfTest (-not (Test-GuardPassword -Password 'wrong')) '错误密码被拒绝'

        $loaded = Get-GuardConfig
        $loaded.locked = $false
        $loaded.unlockUntilUptimeMs = [double](Get-UptimeMs) + 60000
        Save-GuardConfig $loaded
        Assert-SelfTest ((Get-EffectiveState -Config (Get-GuardConfig)) -eq 'unlocked') '临时放行状态生效'

        $loaded = Get-GuardConfig
        $loaded.unlockUntilUptimeMs = 1
        Save-GuardConfig $loaded
        Assert-SelfTest ((Get-EffectiveState -Config (Get-GuardConfig)) -eq 'locked') '放行到期自动回到锁定'

        $domains = @(Get-NormalizedDomains @('https://WWW.QQ.COM/abc', '  ', 'x.com', '*.weibo.com'))
        Assert-SelfTest ($domains.Count -eq 3) '域名规范化数量正确'
        Assert-SelfTest ($domains -contains 'www.qq.com') '域名规范化结果正确'

        $apps = @(Get-NormalizedApps @('WeChat', 'qq.exe'))
        Assert-SelfTest ($apps -contains 'WeChat.exe') '程序名自动补全 .exe'

        $samplePath = Join-Path $script:RequestsDir 'req_00000000_test.json'
        $sampleJson = '{"time":"2026-11-07 10:00:00","target":"微信","exe":"","minutes":30,"reason":"上课要用"}'
        [IO.File]::WriteAllText($samplePath, $sampleJson, (New-Object Text.UTF8Encoding($false)))
        $requests = @(Get-GuardRequests)
        Assert-SelfTest ($requests.Count -eq 1) '申请记录读取成功'
        Assert-SelfTest ([int]$requests[0].minutes -eq 30) '申请记录时长解析正确'
        Assert-SelfTest ($requests[0].File -eq $samplePath) '申请记录包含文件路径'

        $json = New-FirefoxPolicyJson -Domains @('qq.com') -Allow @('docs.qq.com') -Mode 'blocklist' `
            -DisableDoH $true -BlockIncognito $true
        $parsed = $json | ConvertFrom-Json
        Assert-SelfTest (@($parsed.policies.WebsiteFilter.Block).Count -eq 2) 'Firefox 策略包含拦截项'
        Assert-SelfTest ([bool]$parsed.policies.DNSOverHTTPS.Enabled -eq $false) 'Firefox 关闭 DoH'

        Invoke-ApplyGuard -State 'locked' -Config (Get-GuardConfig) -DryRun | Out-Null
        Invoke-ApplyGuard -State 'unlocked' -Config (Get-GuardConfig) -DryRun | Out-Null

        Assert-SelfTest ($script:StubPath -match 'Show-Blocked\.ps1') 'IFEO 拦截命令行指向提示脚本'

        Write-Host ''
        Write-Host '自检通过。'
    } finally {
        try { Initialize-GuardPaths } catch { }
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
