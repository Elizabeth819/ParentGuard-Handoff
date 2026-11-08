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
    foreach ($name in @('remoteEnabled', 'remotePort', 'remoteToken', 'barkKey')) {
        if (-not $Config.PSObject.Properties[$name]) {
            $Config | Add-Member -NotePropertyName $name -NotePropertyValue $defaults.$name -Force
        }
    }
    if ([string]::IsNullOrWhiteSpace([string]$Config.remoteToken)) {
        $Config.remoteToken = New-GuardRemoteToken
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
