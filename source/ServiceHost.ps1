# =====================================================================
#  ParentGuard ServiceHost —— 由 Windows 服务 PgGuardSvc（SYSTEM）承载
#  职责：常驻守护 哨兵 / Ops通道 / 手机面板 三个进程，死了 5 秒内重启；
#        每 60 秒以一次性子进程方式跑 watchdog.ps1（策略自愈 + 心跳）
#  说明：宿主本身不向 SCM 报告状态，SCM 会记录一次 1053 超时但不杀进程，
#        开机时仍会照常拉起（实测可靠的轻量服务承载方式）
# =====================================================================
$ErrorActionPreference = 'Continue'
$root = Join-Path $env:ProgramData 'ParentGuard'
$psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$svcLog = Join-Path $root 'logs\service.log'

# 单实例
$hostMutex = New-Object Threading.Mutex($false, 'Global\PgServiceHost')
if (-not $hostMutex.WaitOne(0)) { return }

foreach ($d in @((Join-Path $root 'logs'))) {
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}
function Write-SvcLog([string]$m) {
    try { Add-Content -LiteralPath $svcLog -Value ('{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m) -Encoding UTF8 } catch { }
}

function Test-PanelPort([int]$Port = 8787) {
    try {
        $c = New-Object Net.Sockets.TcpClient
        $iar = $c.BeginConnect('127.0.0.1', $Port, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne(700, $false)
        if ($ok) { $c.EndConnect($iar); $c.Close(); return $true }
        $c.Close(); return $false
    } catch { return $false }
}

function Start-PgChild {
    param([string]$Script, [string]$Tag)
    try {
        $p = Start-Process -FilePath $psExe `
            -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File',$Script) `
            -WindowStyle Hidden -PassThru
        Write-SvcLog ("启动 {0} PID={1}" -f $Tag, $p.Id)
        return $p
    } catch {
        Write-SvcLog ("启动 {0} 失败：{1}" -f $Tag, $_.Exception.Message)
        return $null
    }
}

Write-SvcLog 'ServiceHost 已启动（SYSTEM）'
$sentinel = $null; $ops = $null
$lastWatchdog = [DateTime]::MinValue

while ($true) {
    try {
        # --- 哨兵 ---
        if ($null -eq $sentinel -or $sentinel.HasExited) {
            $sentinel = Start-PgChild (Join-Path $root 'GuardSentinel.ps1') 'sentinel'
        }
        # --- Ops 通道 ---
        if ($null -eq $ops -or $ops.HasExited) {
            $ops = Start-PgChild (Join-Path $root 'OpsRunner.ps1') 'opsrunner'
        }
        # --- 面板（先测端口，避免重复启动）---
        if (-not (Test-PanelPort 8787)) {
            $panel = Start-PgChild (Join-Path $root 'RemotePanel.ps1') 'panel'
            Start-Sleep -Seconds 2
        }
        # --- 每分钟一次 watchdog（策略自愈/心跳/到期处理）---
        if (((Get-Date) - $lastWatchdog).TotalSeconds -ge 60) {
            Start-Process -FilePath $psExe `
                -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File',(Join-Path $root 'watchdog.ps1')) `
                -WindowStyle Hidden | Out-Null
            $lastWatchdog = Get-Date
        }
    } catch {
        Write-SvcLog ('宿主循环异常：' + $_.Exception.Message)
    }
    Start-Sleep -Seconds 5
}
