# ParentGuard OpsRunner —— SYSTEM 常驻运维通道（由一次性 UAC 授权安装）
# 监视 wm 用户私有命令目录，发现 job_*.ps1 即以 SYSTEM 执行，结果写回 results
# 单实例（Global Mutex）；ONSTART 任务拉起，每 2 分钟的 Keep 任务兜底重启
$ErrorActionPreference = 'Continue'

$opsDir = '$env:LOCALAPPDATA\ParentGuardOps'
$cmdsDir   = Join-Path $opsDir 'cmds'
$resultDir = Join-Path $opsDir 'results'
$opsLog    = 'C:\ProgramData\ParentGuard\logs\ops.log'

foreach ($d in @($opsDir, $cmdsDir, $resultDir, (Split-Path -Parent $opsLog))) {
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}
function Write-OpsLog([string]$m) {
    try { Add-Content -LiteralPath $opsLog -Value ('{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m) -Encoding UTF8 } catch { }
}

$mutex = New-Object Threading.Mutex($false, 'Global\ParentGuardOpsRunner')
if (-not $mutex.WaitOne(0)) { Write-OpsLog '已有实例运行，本实例退出'; return }
Write-OpsLog 'OpsRunner 已启动（SYSTEM）'

function Invoke-OneJob([string]$job) {
    $name = [IO.Path]::GetFileNameWithoutExtension($job)
    $result = Join-Path $resultDir ($name + '.result.txt')
    $tmp = Join-Path ($job + '.running')
    try { Rename-Item -LiteralPath $job -NewName ([IO.Path]::GetFileName($tmp)) -ErrorAction Stop }
    catch { return }  # 被别的实例抢走或已处理
    $start = Get-Date
    try {
        $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $tmp 2>&1
        $code = $LASTEXITCODE
        $body = @(
            ('START=' + $start.ToString('o')),
            ('END='   + (Get-Date -Format 'o')),
            ('EXIT='  + $code),
            '----OUTPUT----',
            ($output | Out-String)
        ) -join "`r`n"
    } catch {
        $body = "JOB ERROR`r`n" + $_.Exception.Message
    }
    [IO.File]::WriteAllText($result, $body, (New-Object Text.UTF8Encoding($false)))
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    Write-OpsLog ('已执行作业：' + $name)
}

# 文件监视 + 定时轮询双保险
$fsw = New-Object IO.FileSystemWatcher $cmdsDir, 'job_*.ps1' -Property @{
    IncludeSubdirectories = $false
    NotifyFilter = [IO.NotifyFilters]::FileName -bor [IO.NotifyFilters]::LastWrite
    EnableRaisingEvents = $true
}
$action = {
    Get-ChildItem -LiteralPath $Event.MessageData.Cmds -Filter 'job_*.ps1' -File -ErrorAction SilentlyContinue |
        ForEach-Object { & $Event.MessageData.Invoke $_.FullName }
}
$state = [pscustomobject]@{ Cmds = $cmdsDir; Invoke = ${function:Invoke-OneJob} }
Register-ObjectEvent -InputObject $fsw -EventName Created -SourceIdentifier 'PGOpsCreate' -Action $action -MessageData $state | Out-Null
Register-ObjectEvent -InputObject $fsw -EventName Renamed -SourceIdentifier 'PGOpsRename' -Action $action -MessageData $state | Out-Null

while ($true) {
    try {
        Get-ChildItem -LiteralPath $cmdsDir -Filter 'job_*.ps1' -File -ErrorAction SilentlyContinue |
            ForEach-Object { Invoke-OneJob $_.FullName }
    } catch {
        Write-OpsLog ('轮询异常：' + $_.Exception.Message)
    }
    Start-Sleep -Seconds 3
}

