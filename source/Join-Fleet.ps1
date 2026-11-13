#  ParentGuard - 子机加入主机设备清单
#  用法（管理员 PowerShell）：
#     .\Join-Fleet.ps1 -HostUrl http://主机地址:8787
#  配对码不写命令行时会被提示输入，避免留在命令历史里。
# =====================================================================
param(
    [Parameter(Mandatory = $true)]
    [string]$HostUrl,
    [string]$Code
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host '请以管理员身份运行（右键 PowerShell → 以管理员身份运行）。' -ForegroundColor Red
    exit 1
}

$root = Join-Path $env:ProgramData 'ParentGuard'
if (-not (Test-Path -LiteralPath (Join-Path $root 'GuardCore.ps1'))) {
    Write-Host '未找到 ParentGuard 安装目录，请先运行安装脚本。' -ForegroundColor Red
    exit 1
}
. (Join-Path $root 'GuardCore.ps1')
Initialize-GuardPaths -Root $root

$url = ([string]$HostUrl).Trim().TrimEnd('/')
if ($url -notmatch '^https?://[^\s]+$') {
    Write-Host '主机地址格式不正确，需要以 http:// 或 https:// 开头，例如 http://<主机地址>:8787' -ForegroundColor Red
    exit 1
}

if ([string]::IsNullOrWhiteSpace($Code)) {
    $secure = Read-Host '请输入主机上显示的配对码' -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $Code = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}
if ([string]::IsNullOrWhiteSpace($Code)) {
    Write-Host '配对码不能为空。' -ForegroundColor Red
    exit 1
}

$cfg = Get-GuardConfig
if (-not $cfg) {
    Write-Host '配置文件不存在，请先完成安装。' -ForegroundColor Red
    exit 1
}
$cfg = Update-GuardConfigDefaults -Config $cfg
if (-not [string]::IsNullOrWhiteSpace([string]$cfg.fleetDeviceToken)) {
    Write-Host '本机已经加入过主机；如需重新配对，请先在主机面板移除本设备。' -ForegroundColor Yellow
}
$cfg.fleetHost = $url
$cfg.fleetJoinCode = $Code
$cfg.fleetStatus = 'joining'
Save-GuardConfig $cfg

Write-Host '正在加入主机设备清单…'
Invoke-GuardFleetSync

$cfg = Get-GuardConfig
if ([string]$cfg.fleetStatus -eq 'joined' -and -not [string]::IsNullOrWhiteSpace([string]$cfg.fleetDeviceToken)) {
    Write-Host ('已加入，主机上的设备名：' + [string]$cfg.fleetMemberName) -ForegroundColor Green
    Write-Host '之后守护任务每分钟自动上报；在主机面板即可查看本机数据并完成审批。'
} else {
    Write-Host '加入未完成：请检查主机地址、配对码是否过期以及网络连通性。' -ForegroundColor Yellow
    Write-Host '详细原因见 C:\ProgramData\ParentGuard\logs\guard.log'
    exit 2
}
