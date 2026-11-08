# ParentGuard 进程哨兵（SYSTEM 常驻）
# 职责：监听进程创建事件，被锁定名单中的程序一启动立即终止（IFEO 之外的实时主防线）
# 由 ParentGuard-Sentinel 计划任务（ONSTART, SYSTEM）启动；watchdog 每分钟兜底拉起
# 适用：Windows PowerShell 5.1

$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'GuardCore.ps1')

# 单实例保护（服务宿主与守护链可能重复拉起）
$pgMutex = New-Object Threading.Mutex($false, 'Global\ParentGuardSentinel')
if (-not $pgMutex.WaitOne(0)) { return }

$sentinelLog = Join-Path $script:GuardRoot 'logs\sentinel.log'

function Write-SLog {
    param([string]$Message)
    try {
        $dir = Split-Path -Parent $sentinelLog
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -LiteralPath $sentinelLog -Value ('{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message) -Encoding UTF8
    } catch { }
}

$script:cfgCache   = $null
$script:stateCache = 'locked'
$script:blocks     = New-Object System.Collections.Generic.HashSet[string]
$script:lastCache  = [DateTime]::MinValue

function Update-Cache {
    try {
        $script:cfgCache = Get-GuardConfig
        $script:stateCache = Get-EffectiveState -Config $script:cfgCache
        $set = New-Object System.Collections.Generic.HashSet[string]
        foreach ($n in (Get-NormalizedApps $script:cfgCache.appBlockList)) {
            [void]$set.Add([string]$n.ToLowerInvariant())
        }
        # 测试覆盖文件：每行一个进程名（部署验证用，正常情况下不存在）
        $testFile = Join-Path $script:GuardRoot 'sentinel-test.txt'
        if (Test-Path -LiteralPath $testFile) {
            foreach ($line in [IO.File]::ReadAllLines($testFile)) {
                $t = ([string]$line).Trim().ToLowerInvariant()
                if ($t) {
                    if (-not $t.EndsWith('.exe')) { $t += '.exe' }
                    [void]$set.Add($t)
                }
            }
        }
        $script:blocks = $set
        $script:lastCache = Get-Date
    } catch {
        Write-SLog ('刷新配置失败：' + $_.Exception.Message)
    }
}

function Stop-BlockedProcess {
    param([int]$ProcessId, [string]$ProcessName)
    $via = ''
    try {
        Stop-Process -Id $ProcessId -Force -ErrorAction Stop
        $via = 'Stop-Process'
    } catch {
        & taskkill.exe /F /T /PID $ProcessId 2>&1 | Out-Null
        $via = 'taskkill'
    }
    Write-SLog ('已终止被禁止程序：{0} (PID={1}, {2})' -f $ProcessName, $ProcessId, $via)
}

function Invoke-Sweep {
    if ($script:stateCache -ne 'locked') { return }
    if ($script:blocks.Count -eq 0) { return }
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        try {
            $n = ($p.Name + '.exe').ToLowerInvariant()
            if ($script:blocks.Contains($n)) {
                Stop-BlockedProcess -ProcessId $p.Id -ProcessName ($p.Name + '.exe')
            }
        } catch { }
    }
}

Update-Cache
Write-SLog ('哨兵已启动：状态={0}，拦截程序数={1}' -f $script:stateCache, $script:blocks.Count)

$wql = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
$watcher = New-Object System.Management.ManagementEventWatcher($wql)
$watcher.Options.Timeout = [TimeSpan]::FromSeconds(5)
$watcher.Start()

try {
    while ($true) {
        try {
            $event = $watcher.WaitForNextEvent()
            # 配置缓存超过 5 秒则刷新（手机批准/禁止后 5 秒内生效）
            if (((Get-Date) - $script:lastCache).TotalSeconds -gt 5) { Update-Cache }
            if ($script:stateCache -eq 'locked' -and $script:blocks.Count -gt 0) {
                $ti = $event.TargetInstance
                $name = [string]$ti.Name
                if ($name -and $script:blocks.Contains($name.ToLowerInvariant())) {
                    Stop-BlockedProcess -ProcessId ([int]$ti.ProcessId) -ProcessName $name
                }
            }
        } catch [System.Management.ManagementException] {
            # WaitForNextEvent 5 秒超时：正常现象，借此周期刷新配置并兜底扫描
            Update-Cache
            Invoke-Sweep
        } catch {
            Write-SLog ('事件循环异常：' + $_.Exception.Message)
            Start-Sleep -Seconds 2
            try { Update-Cache } catch { }
        }
    }
} finally {
    try { $watcher.Stop() } catch { }
    Write-SLog '哨兵已退出'
}
