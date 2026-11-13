# =====================================================================
#  ParentGuard - 管理员安装（无 GUI）
#  用法: 右键“以管理员身份运行 PowerShell”，执行本脚本
#        powershell -NoProfile -ExecutionPolicy Bypass -File _admin_install.ps1 [-VerifyOnly]
# =====================================================================
param([switch]$VerifyOnly)

$ErrorActionPreference = 'Continue'

# 禁用控制台"快速编辑模式"：防止鼠标误点窗口导致安装被冻结
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

$log = 'C:\Users\Public\pg_install_log.txt'
'开始安装' | Out-File -FilePath $log -Encoding UTF8 -Append

function Write-Step($msg) {
    $line = '[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $msg
    $line | Out-File -FilePath $log -Append -Encoding UTF8
    Write-Host $line
}

# 切换目录并加载核心
Set-Location (Split-Path -Parent $MyInvocation.MyCommand.Path)
Write-Step '加载 GuardCore...'
. (Join-Path $PSScriptRoot 'GuardCore.ps1')
Initialize-GuardPaths

# 仅检查环境，不做任何改动
if ($VerifyOnly) {
    $ok = $true
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Host ("管理员权限: {0}" -f $isAdmin); if (-not $isAdmin) { $ok = $false }
    foreach ($n in @('ParentGuard.ps1','GuardCore.ps1','UsageMeter.ps1','RemotePanel.ps1','watchdog.ps1','health.ps1','Show-Blocked.ps1','Join-Fleet.ps1','RunHidden.vbs')) {
        $exists = Test-Path (Join-Path $PSScriptRoot $n)
        Write-Host ("文件 {0}: {1}" -f $n, $exists); if (-not $exists) { $ok = $false }
    }
    try { $port = Get-GuardRemotePort } catch { $port = 8787 }
    $busy = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    Write-Host ("端口 {0}: {1}" -f $port, $(if ($busy) { '被占用' } else { '空闲' }))
    foreach ($b in @("$env:LOCALAPPDATA\Microsoft\Edge\User Data", "$env:LOCALAPPDATA\Google\Chrome\User Data")) {
        Write-Host ("浏览器配置 {0}: {1}" -f $b, (Test-Path $b))
    }
    Write-Host ('目标安装目录: ' + $script:GuardRoot)
    Write-Host $(if ($ok) { 'VERIFY_OK' } else { 'VERIFY_FAILED' })
    exit $(if ($ok) { 0 } else { 1 })
}

# 准备目录
foreach ($dir in @($script:GuardRoot, $script:RequestsDir, $script:LogDir, $script:BackupDir)) {
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}
Write-Step '目录已准备'

# 复制文件
$srcDir = $PSScriptRoot
foreach ($name in @('ParentGuard.ps1', 'GuardCore.ps1', 'UsageMeter.ps1', 'watchdog.ps1', 'Show-Blocked.ps1', 'RemotePanel.ps1', 'health.ps1', 'Join-Fleet.ps1', 'RunHidden.vbs', 'cloudflared-panel.ps1', 'cloudflared.exe')) {
    $s = Join-Path $srcDir $name
    $d = Join-Path $script:GuardRoot $name
    if (Test-Path -LiteralPath $s) {
        Copy-Item -LiteralPath $s -Destination $d -Force
    }
}
# 清理旧版独立 EXE（已废弃，避免杀毒软件误报）
foreach ($old in @('BlockedApp.exe', 'BlockedApp.cs')) {
    $oldPath = Join-Path $script:GuardRoot $old
    if (Test-Path -LiteralPath $oldPath) {
        Remove-Item -LiteralPath $oldPath -Force -ErrorAction SilentlyContinue
    }
}
# 命名隧道用到的 cloudflared：同时放到安装根目录（GuardCore 按根目录查找）
$binSrc = Join-Path $srcDir 'bin\cloudflared.exe'
if (Test-Path -LiteralPath $binSrc) {
    Copy-Item -LiteralPath $binSrc -Destination (Join-Path $script:GuardRoot 'cloudflared.exe') -Force
    $binDstDir = Join-Path $script:GuardRoot 'bin'
    if (-not (Test-Path -LiteralPath $binDstDir)) {
        New-Item -ItemType Directory -Path $binDstDir -Force | Out-Null
    }
    Copy-Item -LiteralPath $binSrc -Destination (Join-Path $binDstDir 'cloudflared.exe') -Force
}
Write-Step '文件已复制'

# 初始化配置
$cfg = Get-GuardConfig
if (-not $cfg) {
    Save-GuardConfig (Get-DefaultConfig)
    Write-Step '默认配置已初始化'
} else {
    # 升级：合并新增的默认学习白名单条目（保留用户已有设置）
    $defaults = Get-DefaultConfig
    $merged = @(@($cfg.domainAllowList) + @($defaults.domainAllowList) |
        ForEach-Object { ([string]$_).Trim().ToLower() } |
        Where-Object { $_ } | Select-Object -Unique)
    if ($merged.Count -ne @($cfg.domainAllowList).Count) {
        $cfg.domainAllowList = $merged
        Save-GuardConfig $cfg
        Write-Step ('已合并新学习白名单（现 ' + $merged.Count + ' 条）')
    }
}
# 升级旧配置：补全手机远程控制字段并生成访问令牌
$cfg = Update-GuardConfigDefaults -Config (Get-GuardConfig)
Save-GuardConfig $cfg
Write-Step '手机远程配置已就绪'

# 仅当尚未设置密码时才设临时密码（避免重跑安装覆盖您已修改的密码）
if (-not (Get-GuardConfig).passwordHash) {
    Write-Step '设置临时密码 123456...'
    Set-GuardPassword -Password '123456'
} else {
    Write-Step '已存在密码，保持不变'
}

# ACL：孩子只保留“申请窗口”的读取/执行权；核心脚本含完整拦截名单，必须收回
Write-Step '设置 ACL...'
& icacls.exe $script:GuardRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(X)' 2>&1 | Out-Null
& icacls.exe $script:RequestsDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(RX,WD,AD)' 2>&1 | Out-Null
foreach ($name in @('ParentGuard.ps1', 'GuardCore.ps1', 'RemotePanel.ps1', 'watchdog.ps1', 'health.ps1', 'cloudflared-panel.ps1', 'cloudflared.exe')) {
    $p = Join-Path $script:GuardRoot $name
    if (Test-Path -LiteralPath $p) {
        & icacls.exe $p /remove:g '*S-1-5-32-545' 2>&1 | Out-Null
    }
}
$stubPath = Join-Path $script:GuardRoot 'Show-Blocked.ps1'
if (Test-Path -LiteralPath $stubPath) {
    & icacls.exe $stubPath /grant:r '*S-1-5-32-545:RX' 2>&1 | Out-Null
}
# 无窗口启动器由交互用户会话里的计划任务调用，必须让普通用户可读可执行
$launcherPath = Join-Path $script:GuardRoot 'RunHidden.vbs'
if (Test-Path -LiteralPath $launcherPath) {
    & icacls.exe $launcherPath /grant:r '*S-1-5-32-545:RX' 2>&1 | Out-Null
}
Write-Step 'ACL 已设置'

# Firefox 备份
Backup-FirefoxPolicy

# 计划任务
Write-Step '创建计划任务...'
$psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$watchdog = Join-Path $script:GuardRoot 'watchdog.ps1'
$taskCmd = '{0} -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File {1}' -f $psExe, $watchdog

& schtasks.exe /Create /TN 'ParentGuard-Watchdog' /TR $taskCmd /SC MINUTE /MO 1 /RU SYSTEM /RL HIGHEST /F 2>&1 | Out-Null
Write-Step '  Watchdog 任务创建完成'

& schtasks.exe /Create /TN 'ParentGuard-Boot' /TR $taskCmd /SC ONSTART /DELAY 0000:10 /RU SYSTEM /RL HIGHEST /F 2>&1 | Out-Null
Write-Step '  Boot 任务创建完成'

$panel = Join-Path $script:GuardRoot 'RemotePanel.ps1'
if (Test-Path -LiteralPath $panel) {
    $panelCmd = '{0} -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File {1}' -f $psExe, $panel
    & schtasks.exe /Create /TN 'ParentGuard-Panel' /TR $panelCmd /SC ONSTART /DELAY 0000:05 /RU SYSTEM /RL HIGHEST /F 2>&1 | Out-Null
    & schtasks.exe /Run /TN 'ParentGuard-Panel' 2>&1 | Out-Null
    $port = Get-GuardRemotePort
    & netsh.exe http add urlacl url=http://127.0.0.1:$port/ user='NT AUTHORITY\SYSTEM' 2>&1 | Out-Null
    Write-Step '  Panel 任务创建完成'
}

$health = Join-Path $script:GuardRoot 'health.ps1'
if (Test-Path -LiteralPath $health) {
    $healthCmd = '{0} -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File {1}' -f $psExe, $health
    & schtasks.exe /Create /TN 'ParentGuard-Health' /TR $healthCmd /SC MINUTE /MO 5 /RU SYSTEM /RL HIGHEST /F 2>&1 | Out-Null
    Write-Step '  Health 任务创建完成'
}

# 程序/网站用量采集：必须在交互用户会话中运行（SYSTEM 看不到用户窗口）。
# 用 wscript.exe（GUI 子系统）作为启动器，控制台窗口从创建起即隐藏，不会闪烁。
$meter = Join-Path $script:GuardRoot 'UsageMeter.ps1'
if (Test-Path -LiteralPath $meter) {
    try {
        $launcher = Join-Path $script:GuardRoot 'RunHidden.vbs'
        & icacls.exe $launcher /grant:r '*S-1-5-32-545:RX' 2>&1 | Out-Null
        $meterAction = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\wscript.exe') `
            -Argument ('//B //Nologo "{0}" "{1}" "{2}"' -f $launcher, $psExe, $meter)
        $meterTrigTime = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1).AddSeconds(30) `
            -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 3650)
        $meterTrigLogon = New-ScheduledTaskTrigger -AtLogOn
        $meterPrincipal = New-ScheduledTaskPrincipal -GroupId 'S-1-5-4' -RunLevel Highest
        $meterSettings = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit (New-TimeSpan -Minutes 1) `
            -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName 'ParentGuard-UsageMeter' -Action $meterAction `
            -Trigger @($meterTrigTime, $meterTrigLogon) -Principal $meterPrincipal `
            -Settings $meterSettings -Description 'ParentGuard per-user usage collector' -Force | Out-Null
        Write-Step '  UsageMeter 任务创建完成'
    } catch { Write-Step ('  [警告] 创建用量采集任务失败：' + $_.Exception.Message) }
}

# Cloudflare 命名隧道任务（未授权时守护脚本自动等待配置，授权后立即上线）
$tunnelScript = Join-Path $script:GuardRoot 'cloudflared-panel.ps1'
if ((Test-Path -LiteralPath $tunnelScript) -and (Test-Path -LiteralPath $script:TunnelExe)) {
    $tunnelCmd = '{0} -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File {1}' -f $psExe, $tunnelScript
    & schtasks.exe /Create /TN 'ParentGuard-Tunnel' /TR $tunnelCmd /SC ONSTART /DELAY 0000:15 /RU SYSTEM /RL HIGHEST /F 2>&1 | Out-Null
    & schtasks.exe /Run /TN 'ParentGuard-Tunnel' 2>&1 | Out-Null
    Write-Step '  Tunnel 任务创建完成（未授权前待机等待）'
}

# 笔记本默认“仅在交流电下运行”会让守护/面板在电池供电时停摆：
# 实测本机因该默认值在拔掉电源后面板与看门狗全部停止，4 天无人恢复。
foreach ($tn in @('ParentGuard-Watchdog','ParentGuard-Boot','ParentGuard-Panel','ParentGuard-Health','ParentGuard-UsageMeter')) {
    try {
        $task = Get-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue
        if ($task) {
            $ts = $task.Settings
            $ts.DisallowStartIfOnBatteries = $false
            $ts.StopIfGoingOnBatteries = $false
            Set-ScheduledTask -TaskName $tn -Settings $ts | Out-Null
        }
    } catch { }
}
Write-Step '计划任务电池策略已放宽'

if (Test-Path -LiteralPath $panel) {
    if (Start-GuardPanelProcess) {
        Write-Step '  手机控制台已运行'
    } else {
        Write-Step '  注意：手机控制台未能启动，稍后会由守护任务重试'
    }
}

# 应用策略
Write-Step '应用防护策略...'
$cfg = Get-GuardConfig
$cfg.locked = $true
$cfg.unlockUntilUptimeMs = $null
Save-GuardConfig $cfg
Invoke-ApplyGuard -State 'locked' -Config $cfg
Write-Step '策略已应用'

# 桌面快捷方式：孩子可见的公共桌面只放“申请入口”；家长入口放进受保护安装目录
Write-Step '创建快捷方式...'
$publicDesktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
$shell = New-Object -ComObject WScript.Shell

# 移除旧版本留在孩子桌面的家长控制台快捷方式
$legacyPanelLnk = Join-Path $publicDesktop '家长防护控制台.lnk'
if (Test-Path -LiteralPath $legacyPanelLnk) {
    Remove-Item -LiteralPath $legacyPanelLnk -Force -ErrorAction SilentlyContinue
    Write-Step '  已移除旧的公共桌面家长控制台快捷方式'
}

if (Test-Path -LiteralPath $script:StubScript) {
    $reqLnk = Join-Path $publicDesktop '请求使用权限.lnk'
    $reqShortcut = $shell.CreateShortcut($reqLnk)
    $reqShortcut.TargetPath = $psExe
    $reqShortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$($script:StubScript)`" -Request"
    $reqShortcut.WorkingDirectory = $script:GuardRoot
    $reqShortcut.IconLocation = "$env:SystemRoot\System32\imageres.dll,49"
    $reqShortcut.Save()
    Write-Step '  请求使用权限.lnk（孩子桌面）'
}

# 家长入口：安装目录内（普通用户无权列出该目录），不放到桌面
$parentLnk = Join-Path $script:GuardRoot '家长控制台.lnk'
$parentShortcut = $shell.CreateShortcut($parentLnk)
$parentShortcut.TargetPath = $psExe
$panelScript = Join-Path $script:GuardRoot 'ParentGuard.ps1'
$parentShortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$panelScript`" -Panel"
$parentShortcut.WorkingDirectory = $script:GuardRoot
$parentShortcut.IconLocation = "$env:SystemRoot\System32\imageres.dll,48"
$parentShortcut.Save()
Write-Step '  家长控制台.lnk（仅安装目录内）'

Write-Step ''
Write-Step '===== 安装完成 ====='
Write-Step '临时密码: 123456（首次打开家长控制台请立即修改）'
Write-Host ''
Write-Host '安装完成！'
Write-Host ('孩子桌面入口：请求使用权限；家长入口：' + (Join-Path $script:GuardRoot '家长控制台.lnk'))
Write-Host '审批 / 拒绝申请请使用手机远程控制台。'
Write-Host '日志: C:\Users\Public\pg_install_log.txt'
