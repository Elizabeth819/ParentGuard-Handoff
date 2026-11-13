# ParentGuard 守护任务（由 SYSTEM 计划任务每分钟运行）
# 职责：检查授权是否到期；发现策略被改动时自动恢复；写心跳；发告警；拉起面板与进程哨兵。

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'GuardCore.ps1')

$heartbeat = $null
try {
    $cfg = Get-GuardConfig
    if (-not $cfg) { return }

    $tokenBefore = [string]$cfg.remoteToken
    $propCountBefore = @($cfg.PSObject.Properties).Count
    $cfg = Update-GuardConfigDefaults -Config $cfg
    if (@($cfg.PSObject.Properties).Count -ne $propCountBefore -or
        [string]$cfg.remoteToken -ne $tokenBefore) {
        Save-GuardConfig $cfg | Out-Null
    }

    $previous = Get-GuardHeartbeat
    $pendingBefore = 0
    if ($previous -and $previous.pendingRequests) {
        try { $pendingBefore = [int]$previous.pendingRequests } catch { $pendingBefore = 0 }
    }
    $requests = @(Get-GuardRequests)
    $pendingAfter = $requests.Count

    $state = Get-EffectiveState -Config $cfg

    # 授权到期：写回锁定状态
    if ($state -eq 'locked' -and -not [bool]$cfg.locked) {
        $cfg.locked = $true
        $cfg.unlockUntilUptimeMs = $null
        Save-GuardConfig $cfg
        $state = 'locked'
        Write-Log '临时放行已到期，自动恢复限制'
        Send-BarkAlertOnce -Key 'unlock-expired' `
            -Title '家长防护：临时放行已到期' `
            -Body '已自动恢复全部限制。' `
            -CooldownMinutes 5 | Out-Null
    }

    $marker = Get-GuardStateMarker
    if ($state -ne $marker) {
        Invoke-ApplyGuard -State $state -Config $cfg
    } elseif ($state -eq 'locked') {
        $healed = Invoke-VerifyAndHeal -Config $cfg
        if ($healed) {
            Write-Log '自检发现限制被改动，已自动恢复'
        }
    }

    $applied = $true
    if ($state -eq 'locked') {
        $applied = [bool](Test-GuardApplied -Config $cfg -SkipApps)
        if (-not $applied) {
            Send-BarkAlertOnce -Key 'policy-not-applied' `
                -Title '家长防护：策略未完全生效' `
                -Body 'hosts 或浏览器策略没有生效，请及时检查。' `
                -CooldownMinutes 30 | Out-Null
        }
    }

    # 孩子提交了新的使用申请
    if ($pendingAfter -gt $pendingBefore) {
        $latest = $requests | Sort-Object -Property time -Descending | Select-Object -First 1
        $targetName = if ($latest -and $latest.target) { [string]$latest.target } else { '未命名' }
        $minutes = if ($latest -and $latest.minutes) { [int]$latest.minutes } else { 0 }
        Send-BarkAlertOnce -Key 'new-request' `
            -Title '家长防护：孩子提交了使用申请' `
            -Body ('申请使用「{0}」{1} 分钟。打开手机控制台可以批准或拒绝。' -f $targetName, $minutes) `
            -CooldownMinutes 1 | Out-Null
    }

    # 程序用量采样（每分钟一次，记录带窗口程序的起止时间）
    try {
        Update-GuardUsage
    } catch {
        Write-Log ('用量采样异常：' + $_.Exception.Message)
    }

    # 手机控制台进程是否在运行
    $listening = $false
    if ([bool]$cfg.remoteEnabled) {
        $port = Get-GuardRemotePort
        $listening = Test-GuardPortOpen -Port $port
        if (-not $listening) {
            $listening = Start-GuardPanelProcess -Port $port
            if ($listening) {
                Write-Log '手机控制台未运行，已自动重启'
                Send-BarkAlertOnce -Key 'panel-restarted' `
                    -Title '家长防护：手机控制台已重启' `
                    -Body ('检测到手机控制台没有运行，已自动重启（端口 {0}）。' -f $port) `
                    -CooldownMinutes 15 | Out-Null
            } else {
                Send-BarkAlertOnce -Key 'panel-start-failed' `
                    -Title '家长防护：手机控制台启动失败' `
                    -Body ('尝试启动手机控制台失败，端口 {0}。' -f $port) `
                    -CooldownMinutes 30 | Out-Null
            }
        }
    }

    # 进程哨兵是否在运行（实时终止被禁止程序）
    $sentinelUp = $false
    if ([bool]$cfg.blockApps) {
        try {
            $sentinelProc = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
                Where-Object { $_.CommandLine -like '*GuardSentinel.ps1*' } | Select-Object -First 1
            $sentinelUp = [bool]$sentinelProc
            if (-not $sentinelUp) {
                $sentinelScript = Join-Path $script:GuardRoot 'GuardSentinel.ps1'
                if (Test-Path -LiteralPath $sentinelScript) {
                    $psExeS = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
                    Start-Process -FilePath $psExeS `
                        -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $sentinelScript + '"') `
                        -WindowStyle Hidden | Out-Null
                    Start-Sleep -Seconds 2
                    $sentinelProc = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
                        Where-Object { $_.CommandLine -like '*GuardSentinel.ps1*' } | Select-Object -First 1
                    $sentinelUp = [bool]$sentinelProc
                    if ($sentinelUp) { Write-Log '进程哨兵未运行，已自动拉起' }
                }
            }
        } catch {
            Write-Log ('进程哨兵守护检查异常：' + $_.Exception.Message)
        }
    }

    $heartbeat = [ordered]@{
        time = (Get-Date -Format 'o')
        state = $state
        remainingMinutes = (Get-GuardRemainingMinutes -Config $cfg)
        pendingRequests = $pendingAfter
        applied = $applied
        panelListening = $listening
        sentinelRunning = $sentinelUp
        host = $env:COMPUTERNAME
        version = [int]$cfg.version
    }
} catch {
    Write-Log ('守护任务异常：' + $_.Exception.Message)
    $heartbeat = [ordered]@{
        time = (Get-Date -Format 'o')
        state = 'error'
        remainingMinutes = 0
        pendingRequests = 0
        applied = $false
        panelListening = $false
        sentinelRunning = $false
        host = $env:COMPUTERNAME
        error = $_.Exception.Message
    }
} finally {
    if ($heartbeat) { Save-GuardHeartbeat -Data $heartbeat | Out-Null }
}
