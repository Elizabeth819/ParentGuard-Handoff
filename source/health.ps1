# =====================================================================
#  ParentGuard - 独立健康检查（每 5 分钟由 SYSTEM 任务运行）
#  用于发现守护任务停止、手机控制台进程消失，并发送 Bark 告警
# =====================================================================
param(
    [string]$Root
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'GuardCore.ps1')
if ($Root) { Initialize-GuardPaths -Root $Root }

try {
    $cfg = Get-GuardConfig
    if (-not $cfg) {
        Write-Log '[健康检查] 配置不存在，可能已被卸载或删除'
        exit
    }

    $cfg = Update-GuardConfigDefaults -Config $cfg
    Save-GuardConfig $cfg | Out-Null

    $age = Get-GuardHeartbeatAgeSeconds
    if ($null -eq $age) {
        Send-BarkAlertOnce -Key 'watchdog-missing' `
            -Title '家长防护：守护任务没有心跳' `
            -Body '没有找到心跳文件，守护任务可能从未启动或被删除。' `
            -CooldownMinutes 30 | Out-Null
    } elseif ($age -gt 180) {
        Send-BarkAlertOnce -Key 'watchdog-stale' `
            -Title '家长防护：守护任务失联' `
            -Body ('已经 {0} 分钟没有收到守护心跳，请检查电脑。' -f [int]($age / 60)) `
            -CooldownMinutes 30 | Out-Null
    }

    if ([bool]$cfg.remoteEnabled) {
        $port = Get-GuardRemotePort
        if (-not (Test-GuardPortOpen -Port $port)) {
            $ok = Start-GuardPanelProcess -Port $port
            if ($ok) {
                Send-BarkAlertOnce -Key 'panel-restarted' `
                    -Title '家长防护：手机控制台已重启' `
                    -Body ('手机控制台原先没有运行，已自动重启（端口 {0}）。' -f $port) `
                    -CooldownMinutes 15 | Out-Null
            } else {
                Send-BarkAlertOnce -Key 'panel-start-failed' `
                    -Title '家长防护：手机控制台启动失败' `
                    -Body ('尝试启动手机控制台失败，端口 {0}。请检查 RemotePanel.ps1。' -f $port) `
                    -CooldownMinutes 30 | Out-Null
            }
        }

        # 公网隧道互检：已安装 cloudflared 但进程消失时自动拉起
        if ((Test-Path -LiteralPath $script:TunnelExe) -and -not (Test-GuardTunnelRunning)) {
            $url = Start-GuardTunnelProcess
            if ($url) {
                Send-BarkAlertOnce -Key 'tunnel-restarted' `
                    -Title '家长防护：公网隧道已重连' `
                    -Body ('新的公网地址：' + $url) -CooldownMinutes 60 | Out-Null
            } else {
                Send-BarkAlertOnce -Key 'tunnel-start-failed' `
                    -Title '家长防护：公网隧道重连失败' `
                    -Body 'cloudflared 未能启动或未获取到地址，请检查电脑网络。' -CooldownMinutes 60 | Out-Null
            }
        }
    }
} catch {
    try { Write-Log ('[健康检查] 异常：' + $_.Exception.Message) } catch { }
}
