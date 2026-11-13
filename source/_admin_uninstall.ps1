# =====================================================================
#  ParentGuard - 一键卸载（还原全部系统改动）
#  需管理员权限运行
# =====================================================================
$ErrorActionPreference = 'Continue'

# 禁用控制台"快速编辑模式"：防止鼠标误点窗口导致卸载被冻结
try {
    Add-Type -Name Win32Console -Namespace ParentGuard -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern System.IntPtr GetStdHandle(int nStdHandle);
[DllImport("kernel32.dll")] public static extern bool GetConsoleMode(System.IntPtr h, out uint mode);
[DllImport("kernel32.dll")] public static extern bool SetConsoleMode(System.IntPtr h, uint mode);
'@ -ErrorAction Stop
    $hIn = [ParentGuard.Win32Console]::GetStdHandle(-10)
    $cm = 0
    [void][ParentGuard.Win32Console]::GetConsoleMode($hIn, [ref]$cm)
    [void][ParentGuard.Win32Console]::SetConsoleMode($hIn, ($cm -band (-bnot 0x0040)))
} catch { }

$log = 'C:\Users\Public\pg_uninstall_log.txt'
'' | Out-File -FilePath $log -Encoding UTF8

function Write-Step($msg) {
    $line = '[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $msg
    $line | Out-File -FilePath $log -Append -Encoding UTF8
    Write-Host $line
}

# 管理员检查
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) {
    Write-Host '[FAIL] 需要管理员权限，请右键 cmd 选择"以管理员身份运行"' -ForegroundColor Red
    exit 1
}

Set-Location (Split-Path -Parent $MyInvocation.MyCommand.Path)

Write-Step '加载 GuardCore...'
. (Join-Path $PSScriptRoot 'GuardCore.ps1')
Initialize-GuardPaths

# 1. 删除计划任务
Write-Step '删除计划任务...'
& schtasks.exe /Delete /TN 'ParentGuard-Watchdog' /F 2>&1 | Out-Null
& schtasks.exe /Delete /TN 'ParentGuard-Boot' /F 2>&1 | Out-Null
& schtasks.exe /End /TN 'ParentGuard-Panel' 2>&1 | Out-Null
& schtasks.exe /Delete /TN 'ParentGuard-Panel' /F 2>&1 | Out-Null
& schtasks.exe /Delete /TN 'ParentGuard-Health' /F 2>&1 | Out-Null
& schtasks.exe /End /TN 'ParentGuard-UsageMeter' 2>&1 | Out-Null
& schtasks.exe /Delete /TN 'ParentGuard-UsageMeter' /F 2>&1 | Out-Null
& schtasks.exe /End /TN 'ParentGuard-Tunnel' 2>&1 | Out-Null
& schtasks.exe /Delete /TN 'ParentGuard-Tunnel' /F 2>&1 | Out-Null
Get-Process -Name 'cloudflared' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
# 注销 Cloudflare 命名隧道与 DNS（凭证/证书随安装目录删除；云端残留一并清理）
try {
    $cfExe = Join-Path $script:GuardRoot 'cloudflared.exe'
    $cfCert = Join-Path $script:GuardRoot 'cloudflared\cert.pem'
    if ((Test-Path -LiteralPath $cfExe) -and (Test-Path -LiteralPath $cfCert)) {
        & $cfExe tunnel cleanup parentguard --config (Join-Path $script:GuardRoot 'cloudflared\config.yml') 2>&1 | Out-Null
        & $cfExe tunnel delete parentguard --origincert $cfCert 2>&1 | Out-Null
        Write-Step '  云端隧道已注销'
    }
} catch { Write-Step ('  [warn] 云端隧道注销失败（可稍后在 Cloudflare 后台手动删除）: ' + $_.Exception.Message) }
$port = Get-GuardRemotePort
try {
    Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction Stop |
        ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
} catch { }
& netsh.exe http delete urlacl url=http://127.0.0.1:$port/ 2>&1 | Out-Null
Write-Step '  已删除'

# 2. 移除 IFEO 程序拦截
Write-Step '移除程序拦截（IFEO）...'
try {
    $cfg = Get-GuardConfig
    $apps = if ($cfg) { @(Get-NormalizedApps $cfg.appBlockList) } else {
        @('WeChat.exe','Weixin.exe','WeChatApp.exe','WeChatAppEx.exe','QQ.exe','QQScLauncher.exe','Tim.exe')
    }
    Set-AppBlock -Names $apps -Enabled $false
    Write-Step '  已移除'
} catch { Write-Step ('  [warn] ' + $_.Exception.Message) }

# 3. 恢复浏览器策略（Edge/Chrome/Chromium/Brave/Vivaldi）
Write-Step '恢复浏览器注册表策略...'
try {
    Set-BrowserPolicy -Domains @() -Allow @() -Mode 'blocklist' -Enabled $false `
        -DisableDoH $true -BlockIncognito $true
    Write-Step '  已恢复'
} catch { Write-Step ('  [warn] ' + $_.Exception.Message) }

# 4. 恢复 Firefox 策略
Write-Step '恢复 Firefox 策略...'
try {
    Set-FirefoxPolicy -Domains @() -Allow @() -Mode 'blocklist' -Enabled $false `
        -DisableDoH $true -BlockIncognito $true
    Write-Step '  已恢复'
} catch { Write-Step ('  [warn] ' + $_.Exception.Message) }

# 5. 还原 hosts 文件
Write-Step '还原 hosts 文件...'
try {
    Set-HostsBlock -Domains @() -Enabled $false
    & ipconfig.exe /flushdns 2>&1 | Out-Null
    Write-Step '  已还原并刷新 DNS 缓存'
} catch { Write-Step ('  [warn] ' + $_.Exception.Message) }

# 6. 删除桌面快捷方式
Write-Step '删除桌面快捷方式...'
$desk = [Environment]::GetFolderPath('CommonDesktopDirectory')
foreach ($n in @('家长防护控制台.lnk', '请求使用权限.lnk')) {
    $p = Join-Path $desk $n
    if (Test-Path -LiteralPath $p) {
        Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
        Write-Step "  已删除 $n"
    }
}

# 7. 延迟删除安装目录（等本脚本退出后执行）
Write-Step '删除安装目录（3 秒后）...'
$cmd = 'ping -n 4 127.0.0.1 >nul & rmdir /s /q "' + $script:GuardRoot + '"'
Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\cmd.exe') `
    -ArgumentList ('/c ' + $cmd) -WindowStyle Hidden
Write-Step ('  已安排删除 ' + $script:GuardRoot)

Write-Host ''
Write-Step '===== 卸载完成，系统已全部还原 ====='
