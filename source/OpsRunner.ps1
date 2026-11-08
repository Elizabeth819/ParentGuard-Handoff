# ParentGuard OpsRunner ?? SYSTEM ??????????? UAC ?????
# ?? wm ??????????? job_*.ps1 ?? SYSTEM ??????? results
# ????Global Mutex??ONSTART ?????? 2 ??? Keep ??????
$ErrorActionPreference = 'Continue'

$opsDir = 'C:\Users\user\AppData\Local\ParentGuardOps'
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
if (-not $mutex.WaitOne(0)) { Write-OpsLog '????????????'; return }
Write-OpsLog 'OpsRunner ????SYSTEM?'

function Invoke-OneJob([string]$job) {
    $name = [IO.Path]::GetFileNameWithoutExtension($job)
    $result = Join-Path $resultDir ($name + '.result.txt')
    $tmp = Join-Path ($job + '.running')
    try { Rename-Item -LiteralPath $job -NewName ([IO.Path]::GetFileName($tmp)) -ErrorAction Stop }
    catch { return }  # ???????????
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
    Write-OpsLog ('??????' + $name)
}

# ???? + ???????
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
        Write-OpsLog ('?????' + $_.Exception.Message)
    }
    Start-Sleep -Seconds 3
}
