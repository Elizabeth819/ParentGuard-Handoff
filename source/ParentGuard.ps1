# =====================================================================
#  ParentGuard - 家长防护控制台（安装 / 授权 / 卸载）
#  运行：Windows PowerShell 5.1，管理员权限
# =====================================================================

param(
    [switch]$Install,
    [switch]$Panel,
    [switch]$Uninstall,
    [switch]$Verify,
    [switch]$SelfTest,
    [switch]$DryRun,
    [string]$Root
)

$ErrorActionPreference = 'Stop'
$script:EntryScript = $PSCommandPath
$script:StatusLabel = $null
$script:PendingLabel = $null
$script:NewPasswordResult = $null

. (Join-Path $PSScriptRoot 'GuardCore.ps1')
if ($Root) { Initialize-GuardPaths -Root $Root }

if ($SelfTest) {
    Invoke-SelfTest -DryRun:$DryRun
    return
}

$wantUi = $Install -or $Panel -or $Uninstall -or ($PSBoundParameters.Count -eq 0)

# ---- 非管理员时自动请求 UAC 提权（这一步就是向家长要权限） ----
if ($wantUi -and -not (Test-Admin)) {
    $flags = @()
    if ($Uninstall) { $flags += '-Uninstall' }
    elseif ($Install) { $flags += '-Install' }
    else { $flags += '-Panel' }
    $argLine = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" {1}' -f `
        $script:EntryScript, ($flags -join ' ')
    Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') `
        -Verb RunAs -ArgumentList $argLine
    return
}

if ($wantUi) {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [Windows.Forms.Application]::EnableVisualStyles()
}

# =====================================================================
# 安装 / 卸载
# =====================================================================

function Install-Guard {
    param([string]$Password)

    if (-not (Test-Admin)) { throw '安装需要管理员权限' }

    foreach ($dir in @($script:GuardRoot, $script:RequestsDir, (Split-Path -Parent $script:LogPath), $script:BackupDir)) {
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }

    $files = @('ParentGuard.ps1', 'GuardCore.ps1', 'watchdog.ps1', 'Show-Blocked.ps1', 'RemotePanel.ps1', 'health.ps1', 'RunHidden.vbs')
    foreach ($name in $files) {
        $source = Join-Path $PSScriptRoot $name
        $dest = Join-Path $script:GuardRoot $name
        if (-not (Test-Path -LiteralPath $source)) { continue }
        if ([IO.Path]::GetFullPath($source) -eq [IO.Path]::GetFullPath($dest)) { continue }
        Copy-Item -LiteralPath $source -Destination $dest -Force
    }

    # 清理旧版独立 EXE（已废弃，避免杀毒软件误报）
    foreach ($old in @('BlockedApp.exe', 'BlockedApp.cs')) {
        $oldPath = Join-Path $script:GuardRoot $old
        if (Test-Path -LiteralPath $oldPath) {
            Remove-Item -LiteralPath $oldPath -Force -ErrorAction SilentlyContinue
        }
    }

    $cfg = Get-GuardConfig
    if (-not $cfg) {
        Save-GuardConfig (Get-DefaultConfig)
        $cfg = Get-GuardConfig
    } else {
        # 升级：合并新增的默认学习白名单条目（保留用户已有设置）
        $defaults = Get-DefaultConfig
        $merged = @(@($cfg.domainAllowList) + @($defaults.domainAllowList) |
            ForEach-Object { ([string]$_).Trim().ToLower() } |
            Where-Object { $_ } | Select-Object -Unique)
        if ($merged.Count -ne @($cfg.domainAllowList).Count) {
            $cfg.domainAllowList = $merged
            Save-GuardConfig $cfg
        }
    }
    # 升级旧配置：补全手机远程控制字段并生成访问令牌
    $cfg = Update-GuardConfigDefaults -Config $cfg
    Save-GuardConfig $cfg
    if ($Password -and -not $cfg.passwordHash) {
        Set-GuardPassword -Password $Password
    }
    if (-not (Get-GuardConfig).passwordHash) {
        throw '未设置家长防护密码'
    }

    Set-GuardAcls
    Backup-FirefoxPolicy
    Install-GuardTasks
    if (-not (Start-GuardPanelProcess)) {
        Write-Log '手机控制台未能立即启动，守护任务会在一分钟内重试'
    }

    $cfg = Get-GuardConfig
    $cfg.locked = $true
    $cfg.unlockUntilUptimeMs = $null
    Save-GuardConfig $cfg
    Invoke-ApplyGuard -State 'locked' -Config $cfg

    Install-GuardShortcuts
    Write-Log '安装/更新完成'
}

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
    # 无窗口启动器由交互用户会话里的计划任务调用，必须让普通用户可读可执行
    $launcher = Join-Path $script:GuardRoot 'RunHidden.vbs'
    if (Test-Path -LiteralPath $launcher) {
        & icacls.exe $launcher /grant:r '*S-1-5-32-545:RX' 2>&1 | Out-Null
    }
}

function Install-GuardTasks {
    $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $watchdog = Join-Path $script:GuardRoot 'watchdog.ps1'
    $panel = Join-Path $script:GuardRoot 'RemotePanel.ps1'
    $health = Join-Path $script:GuardRoot 'health.ps1'
    # 两个路径都不含空格，无需内嵌引号，避免 schtasks 参数转义问题
    $taskCmd = '{0} -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File {1}' -f $psExe, $watchdog

    & schtasks.exe /Create /TN 'ParentGuard-Watchdog' /TR $taskCmd /SC MINUTE /MO 1 `
        /RU SYSTEM /RL HIGHEST /F 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw '创建每分钟守护任务失败' }

    & schtasks.exe /Create /TN 'ParentGuard-Boot' /TR $taskCmd /SC ONSTART /DELAY 0000:10 `
        /RU SYSTEM /RL HIGHEST /F 2>&1 | Out-Null

    if (Test-Path -LiteralPath $panel) {
        $panelCmd = '{0} -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File {1}' -f $psExe, $panel
        & schtasks.exe /Create /TN 'ParentGuard-Panel' /TR $panelCmd /SC ONSTART /DELAY 0000:05 `
            /RU SYSTEM /RL HIGHEST /F 2>&1 | Out-Null
        & schtasks.exe /Run /TN 'ParentGuard-Panel' 2>&1 | Out-Null

        $port = Get-GuardRemotePort
        & netsh.exe http add urlacl url=http://127.0.0.1:$port/ user='NT AUTHORITY\SYSTEM' 2>&1 | Out-Null
    }

    if (Test-Path -LiteralPath $health) {
        $healthCmd = '{0} -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File {1}' -f $psExe, $health
        & schtasks.exe /Create /TN 'ParentGuard-Health' /TR $healthCmd /SC MINUTE /MO 5 `
            /RU SYSTEM /RL HIGHEST /F 2>&1 | Out-Null
    }

    # 程序用量采集：在交互用户会话中每分钟运行（SYSTEM 看不到用户窗口，必须用户身份）
    $meter = Join-Path $script:GuardRoot 'UsageMeter.ps1'
    if (Test-Path -LiteralPath $meter) {
        try {
            # 用 wscript.exe（GUI 子系统）做启动器：它自身不创建控制台，再用 SW_HIDE(0)
            # 拉起 powershell，控制台窗口从创建起就是隐藏的，不会闪烁。
            # 直接让任务执行 powershell.exe 时，-WindowStyle Hidden 是在控制台创建之后
            # 才生效，实测每分钟都会闪一下蓝色控制台窗口。
            $launcher = Join-Path $script:GuardRoot 'RunHidden.vbs'
            if (-not (Test-Path -LiteralPath $launcher)) {
                Set-Content -LiteralPath $launcher -Encoding ASCII -Value @(
                    "' ParentGuard hidden launcher (GUI subsystem: creates no console itself).",
                    'Option Explicit',
                    'Dim exe, script, extra, i, cmd',
                    'If WScript.Arguments.Count < 2 Then WScript.Quit 2',
                    'exe = WScript.Arguments(0)',
                    'script = WScript.Arguments(1)',
                    'extra = ""',
                    'For i = 2 To WScript.Arguments.Count - 1',
                    '    extra = extra & " " & WScript.Arguments(i)',
                    'Next',
                    'cmd = """" & exe & """ -NoProfile -ExecutionPolicy Bypass -File """ & script & """" & extra',
                    'CreateObject("WScript.Shell").Run cmd, 0, False'
                )
            }
            & icacls.exe $launcher /grant:r '*S-1-5-32-545:RX' 2>&1 | Out-Null
            $meterAction = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\wscript.exe') `
                -Argument ('//B //Nologo "{0}" "{1}" "{2}"' -f $launcher, $psExe, $meter)
            # 与 Watchdog（每分钟整点）错开 30 秒触发：否则两个任务同一秒启动，
            # 守护进程读到的是上一分钟的旧快照，导致开/闭段整体晚 1-2 分钟
            $meterTrigTime = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1).AddSeconds(30) `
                -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 3650)
            $meterTrigLogon = New-ScheduledTaskTrigger -AtLogOn
            # 实测 Limited 会导致任务无法写 ProgramData（0xC0000...），必须 Highest
            $meterPrincipal = New-ScheduledTaskPrincipal -GroupId 'S-1-5-4' -RunLevel Highest
            $meterSettings = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit (New-TimeSpan -Minutes 1) `
                -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
            Register-ScheduledTask -TaskName 'ParentGuard-UsageMeter' -Action $meterAction `
                -Trigger @($meterTrigTime, $meterTrigLogon) -Principal $meterPrincipal `
                -Settings $meterSettings -Description 'ParentGuard per-user usage collector' -Force | Out-Null
        } catch { Write-Host ("  [警告] 创建用量采集任务失败：" + $_.Exception.Message) -ForegroundColor Yellow }
    }
}

function Install-GuardShortcuts {
    $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $panelArgs = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Panel' -f `
        (Join-Path $script:GuardRoot 'ParentGuard.ps1')
    $publicDesktop = [Environment]::GetFolderPath('CommonDesktopDirectory')

    # 公共桌面是孩子能看到的地方：只保留“申请入口”，并移除旧版家长控制台快捷方式
    if ($publicDesktop) {
        $legacyConsole = Join-Path $publicDesktop '家长防护控制台.lnk'
        if (Test-Path -LiteralPath $legacyConsole) {
            Remove-Item -LiteralPath $legacyConsole -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $script:StubScript) {
            $reqArgs = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Request' -f `
                $script:StubScript
            New-GuardShortcut -Path (Join-Path $publicDesktop '请求使用权限.lnk') `
                -Target $psExe -Arguments $reqArgs -Description '向家长申请临时使用（孩子用）'
        }
    }

    # 家长入口放在受 ACL 保护的安装目录内：普通用户无权列出该目录，桌面不显示
    New-GuardShortcut -Path (Join-Path $script:GuardRoot '家长控制台.lnk') `
        -Target $psExe -Arguments $panelArgs -Description 'ParentGuard 家长控制台（需要密码）'
}

function New-GuardShortcut {
    param(
        [string]$Path,
        [string]$Target,
        [string]$Arguments,
        [string]$Description
    )
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($Path)
    $shortcut.TargetPath = $Target
    $shortcut.Arguments = $Arguments
    $shortcut.Description = $Description
    $shortcut.WorkingDirectory = $script:GuardRoot
    $shortcut.IconLocation = "$env:SystemRoot\System32\imageres.dll,48"
    $shortcut.Save()
}

function Remove-GuardShortcuts {
    $publicDesktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
    if (-not $publicDesktop) { return }
    foreach ($name in @('家长防护控制台.lnk', '请求使用权限.lnk')) {
        $path = Join-Path $publicDesktop $name
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }
}

function Uninstall-Guard {
    $cfg = Get-GuardConfig
    $apps = @()
    if ($cfg) { $apps = @(Get-NormalizedApps $cfg.appBlockList) }

    & schtasks.exe /Delete /TN 'ParentGuard-Watchdog' /F 2>&1 | Out-Null
    & schtasks.exe /Delete /TN 'ParentGuard-Boot' /F 2>&1 | Out-Null
    & schtasks.exe /End /TN 'ParentGuard-Panel' 2>&1 | Out-Null
    & schtasks.exe /Delete /TN 'ParentGuard-Panel' /F 2>&1 | Out-Null
    & schtasks.exe /Delete /TN 'ParentGuard-Health' /F 2>&1 | Out-Null
    & schtasks.exe /Delete /TN 'ParentGuard-UsageMeter' /F 2>&1 | Out-Null

    $port = Get-GuardRemotePort
    try {
        Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction Stop |
            ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
    } catch { }
    & netsh.exe http delete urlacl url=http://127.0.0.1:$port/ 2>&1 | Out-Null

    Set-FirefoxPolicy -Domains @() -Allow @() -Mode 'blocklist' -Enabled $false `
        -DisableDoH $true -BlockIncognito $true
    Set-AppBlock -Names $apps -Enabled $false
    Set-BrowserPolicy -Domains @() -Allow @() -Mode 'blocklist' -Enabled $false `
        -DisableDoH $true -BlockIncognito $true
    Set-HostsBlock -Domains @() -Enabled $false

    Remove-GuardShortcuts
    Write-Log '已卸载并恢复系统设置'

    # 延迟删除自身目录（脚本/PowerShell 进程退出后再删）
    $cmd = 'ping -n 4 127.0.0.1 >nul & rmdir /s /q "' + $script:GuardRoot + '"'
    Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\cmd.exe') `
        -ArgumentList ('/c ' + $cmd) -WindowStyle Hidden
}

# =====================================================================
# 界面通用
# =====================================================================

function Get-UiFont {
    try { return New-Object System.Drawing.Font('Microsoft YaHei UI', 9) }
    catch { return New-Object System.Drawing.Font('Segoe UI', 9) }
}

function Read-PasswordDialog {
    param(
        [string]$Title = '家长验证',
        [string]$Prompt = '请输入家长防护密码：'
    )

    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title
    $form.ClientSize = New-Object System.Drawing.Size(380, 160)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true
    $form.Font = Get-UiFont

    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Prompt
    $label.SetBounds(20, 20, 340, 24)

    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.SetBounds(20, 50, 340, 26)
    $textBox.UseSystemPasswordChar = $true

    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = '确定'
    $ok.SetBounds(200, 100, 75, 30)
    $ok.DialogResult = [Windows.Forms.DialogResult]::OK

    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = '取消'
    $cancel.SetBounds(285, 100, 75, 30)
    $cancel.DialogResult = [Windows.Forms.DialogResult]::Cancel

    $form.Controls.AddRange(@($label, $textBox, $ok, $cancel))
    $form.AcceptButton = $ok
    $form.CancelButton = $cancel
    $form.Add_Shown({ $textBox.Focus() })

    if ($form.ShowDialog() -eq [Windows.Forms.DialogResult]::OK) {
        return $textBox.Text
    }
    return $null
}

function Read-NewPasswordDialog {
    param(
        [string]$Title = '设置家长防护密码',
        [string]$Prompt = '设置密码（至少 6 位，用于放行与卸载）：'
    )

    $script:NewPasswordResult = $null
    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title
    $form.ClientSize = New-Object System.Drawing.Size(420, 220)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true
    $form.Font = Get-UiFont

    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Prompt
    $label.SetBounds(20, 18, 380, 22)

    $textBox1 = New-Object System.Windows.Forms.TextBox
    $textBox1.SetBounds(20, 45, 380, 26)
    $textBox1.UseSystemPasswordChar = $true

    $label2 = New-Object System.Windows.Forms.Label
    $label2.Text = '再输入一次确认：'
    $label2.SetBounds(20, 82, 380, 22)

    $textBox2 = New-Object System.Windows.Forms.TextBox
    $textBox2.SetBounds(20, 108, 380, 26)
    $textBox2.UseSystemPasswordChar = $true

    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = '确定'
    $ok.SetBounds(235, 165, 75, 30)

    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = '取消'
    $cancel.SetBounds(325, 165, 75, 30)
    $cancel.DialogResult = [Windows.Forms.DialogResult]::Cancel

    $ok.Add_Click({
        if ([string]::IsNullOrWhiteSpace($textBox1.Text)) {
            [Windows.Forms.MessageBox]::Show('密码不能为空。') | Out-Null
            return
        }
        if ($textBox1.Text.Length -lt 6) {
            [Windows.Forms.MessageBox]::Show('密码至少 6 位。') | Out-Null
            return
        }
        if ($textBox1.Text -ne $textBox2.Text) {
            [Windows.Forms.MessageBox]::Show('两次输入的密码不一致。') | Out-Null
            return
        }
        $script:NewPasswordResult = $textBox1.Text
        $form.DialogResult = [Windows.Forms.DialogResult]::OK
    })

    $form.Controls.AddRange(@($label, $textBox1, $label2, $textBox2, $ok, $cancel))
    $form.AcceptButton = $ok
    $form.CancelButton = $cancel
    $form.Add_Shown({ $textBox1.Focus() })

    if ($form.ShowDialog() -eq [Windows.Forms.DialogResult]::OK) {
        return $script:NewPasswordResult
    }
    return $null
}

# =====================================================================
# 主控制台
# =====================================================================

function Start-GuardUi {
    $installed = Test-Path -LiteralPath $script:ConfigPath

    if (-not $installed) {
        $password = Read-NewPasswordDialog
        if ($null -eq $password) { return }
        try {
            Install-Guard -Password $password
            [Windows.Forms.MessageBox]::Show(
                "安装完成。`r`n`r`n孩子侧（公共桌面只有这一个入口）：`r`n• 请求使用权限 —— 孩子在里面写明要放行的网站或应用并提交申请`r`n`r`n家长侧：`r`n• 批准 / 拒绝申请统一在手机控制台完成，电脑端不再提供审批按钮`r`n• 电脑端家长入口：$($script:GuardRoot)\家长控制台.lnk（需密码，目录默认隐藏）`r`n• 拦截名单默认只显示数量，需再次验证家长密码才能查看修改`r`n`r`n浏览器策略建议重启浏览器后生效。",
                'ParentGuard',
                [Windows.Forms.MessageBoxButtons]::OK,
                [Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        } catch {
            [Windows.Forms.MessageBox]::Show(('安装失败：' + $_.Exception.Message), 'ParentGuard', 'OK', 'Error') | Out-Null
            return
        }
    } elseif ($Install) {
        try {
            Install-Guard -Password ''
            [Windows.Forms.MessageBox]::Show('已更新策略文件并重新锁定。', 'ParentGuard') | Out-Null
        } catch {
            [Windows.Forms.MessageBox]::Show(('更新失败：' + $_.Exception.Message), 'ParentGuard', 'OK', 'Error') | Out-Null
        }
    }

    Show-GuardPanel
}

function Show-GuardPanel {
    $password = Read-PasswordDialog
    if ($null -eq $password) { return }
    if (-not (Test-GuardPassword -Password $password)) {
        [Windows.Forms.MessageBox]::Show('密码错误，已拒绝访问。', '家长防护', 'OK', 'Error') | Out-Null
        return
    }

    $font = Get-UiFont
    $form = New-Object System.Windows.Forms.Form
    $form.Text = '家长防护控制台（家长端）'
    $form.ClientSize = New-Object System.Drawing.Size(660, 392)
    $form.StartPosition = 'CenterScreen'
    $form.Font = $font
    $form.MaximizeBox = $false
    $form.FormBorderStyle = 'FixedSingle'

    $status = New-Object System.Windows.Forms.Label
    $status.SetBounds(20, 16, 620, 28)
    $status.Font = New-Object System.Drawing.Font('Microsoft YaHei UI', 10, [System.Drawing.FontStyle]::Bold)
    $script:StatusLabel = $status

    $unlockGroup = New-Object System.Windows.Forms.GroupBox
    $unlockGroup.Text = '临时授权（到期自动恢复限制）'
    $unlockGroup.SetBounds(20, 52, 620, 78)

    $unlockButtons = @()
    foreach ($minutes in @(15, 30, 60, 120)) {
        $button = New-UnlockButton -Minutes $minutes -X (20 + ($unlockButtons.Count * 145))
        $unlockGroup.Controls.Add($button)
        $unlockButtons += $button
    }

    $lockButton = New-Object System.Windows.Forms.Button
    $lockButton.Text = '立即恢复限制'
    $lockButton.SetBounds(20, 145, 150, 32)
    $lockButton.Add_Click({
        try {
            Invoke-Lock
            Update-PanelStatus
            [Windows.Forms.MessageBox]::Show('已立即恢复全部限制。') | Out-Null
        } catch {
            [Windows.Forms.MessageBox]::Show(('操作失败：' + $_.Exception.Message)) | Out-Null
        }
    })

    # 申请审批只在家长手机端完成；电脑端只显示数量提示，不提供任何审批动作
    $pendingBox = New-Object System.Windows.Forms.Label
    $pendingBox.SetBounds(20, 190, 620, 46)
    $pendingBox.Font = $font
    $script:PendingLabel = $pendingBox

    $listsButton = New-Object System.Windows.Forms.Button
    $listsButton.Text = '拦截名单设置'
    $listsButton.SetBounds(20, 248, 130, 32)
    $listsButton.Add_Click({ Show-BlocklistEditor })

    $passwordButton = New-Object System.Windows.Forms.Button
    $passwordButton.Text = '修改密码'
    $passwordButton.SetBounds(160, 248, 100, 32)
    $passwordButton.Add_Click({
        $newPassword = Read-NewPasswordDialog -Title '修改家长防护密码' -Prompt '设置新的密码（至少 6 位）：'
        if ($null -eq $newPassword) { return }
        try {
            Set-GuardPassword -Password $newPassword
            [Windows.Forms.MessageBox]::Show('密码已修改。') | Out-Null
        } catch {
            [Windows.Forms.MessageBox]::Show(('修改失败：' + $_.Exception.Message)) | Out-Null
        }
    })

    $helpButton = New-Object System.Windows.Forms.Button
    $helpButton.Text = '使用说明'
    $helpButton.SetBounds(270, 248, 100, 32)
    $helpButton.Add_Click({ Show-GuardHelpDialog })

    $verifyButton = New-Object System.Windows.Forms.Button
    $verifyButton.Text = '检查状态'
    $verifyButton.SetBounds(380, 248, 100, 32)
    $verifyButton.Add_Click({
        $text = Get-PanelStatusText
        $port = Get-GuardRemotePort
        $panelText = if (Test-GuardPortOpen -Port $port) { '运行中' } else { '未运行' }
        $age = Get-GuardHeartbeatAgeSeconds
        $hbText = if ($null -eq $age) { '无心跳' } elseif ($age -lt 180) { '在线' } else { ('已 {0} 分钟无心跳' -f [int]($age / 60)) }
        $extra = "`r`n`r`n手机控制台：{0}（端口 {1}）`r`n守护心跳：{2}" -f $panelText, $port, $hbText
        if (Test-GuardPassword -Password '123456') {
            $extra += "`r`n`r`n警告：仍在使用安装临时密码 123456，请立即修改。"
        }
        if (-not (Test-GuardApplied -Config (Get-GuardConfig))) {
            $extra += "`r`n`r`n注意：检测到部分限制尚未生效，可能需要在管理员权限下重新应用，请打开「拦截名单设置」验证密码后保存一次。"
        }
        [Windows.Forms.MessageBox]::Show(($text + $extra), '状态检查') | Out-Null
    })

    $uninstallButton = New-Object System.Windows.Forms.Button
    $uninstallButton.Text = '卸载'
    $uninstallButton.SetBounds(490, 248, 75, 32)
    $uninstallButton.Add_Click({
        $confirmPassword = Read-PasswordDialog -Title '确认卸载' -Prompt '请再次输入密码以卸载：'
        if ($null -eq $confirmPassword) { return }
        if (-not (Test-GuardPassword -Password $confirmPassword)) {
            [Windows.Forms.MessageBox]::Show('密码错误，已取消卸载。') | Out-Null
            return
        }
        $answer = [Windows.Forms.MessageBox]::Show(
            '确定要卸载并恢复微信/QQ 与网站访问吗？', '确认卸载',
            [Windows.Forms.MessageBoxButtons]::YesNo,
            [Windows.Forms.MessageBoxIcon]::Warning)
        if ($answer -ne [Windows.Forms.DialogResult]::Yes) { return }
        try {
            Uninstall-Guard
            $form.Close()
            [Windows.Forms.MessageBox]::Show('已卸载，系统限制已恢复。') | Out-Null
        } catch {
            [Windows.Forms.MessageBox]::Show(('卸载失败：' + $_.Exception.Message), '错误', 'OK', 'Error') | Out-Null
        }
    })

    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Text = '关闭'
    $closeButton.SetBounds(575, 248, 65, 32)
    $closeButton.Add_Click({ $form.Close() })

    $remoteButton = New-Object System.Windows.Forms.Button
    $remoteButton.Text = '手机远程控制（家长端）'
    $remoteButton.SetBounds(20, 292, 180, 32)
    $remoteButton.Add_Click({ Show-RemoteDialog })

    $footer = New-Object System.Windows.Forms.Label
    $footer.Text = "孩子的申请只能在手机控制台批准 / 拒绝；本电脑不提供审批入口，也不直接展示拦截名单。`r`n建议为孩子使用独立的标准用户账户；本入口位于受保护目录，请勿复制到孩子桌面。"
    $footer.SetBounds(20, 334, 620, 40)
    $footer.ForeColor = [System.Drawing.Color]::DimGray

    $form.Controls.AddRange(@(
        $status, $unlockGroup, $lockButton, $pendingBox,
        $listsButton, $passwordButton, $helpButton, $verifyButton, $uninstallButton, $closeButton,
        $remoteButton, $footer
    ))

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 1000
    $timer.Add_Tick({ Update-PanelStatus; Update-PanelPendingInfo })
    $form.Add_Shown({
        Update-PanelStatus
        Update-PanelPendingInfo
        $timer.Start()
    })
    $form.Add_FormClosed({ $timer.Stop() })

    [Windows.Forms.Application]::Run($form)
    $script:StatusLabel = $null
    $script:PendingLabel = $null
}

function Show-RemoteDialog {
    $cfg = Get-GuardConfig
    if (-not $cfg) {
        [Windows.Forms.MessageBox]::Show('还没有安装配置，请先安装。') | Out-Null
        return
    }
    $tokenBefore = [string]$cfg.remoteToken
    $cfg = Update-GuardConfigDefaults -Config $cfg
    if ([string]$cfg.remoteToken -ne $tokenBefore) {
        Save-GuardConfig $cfg
    }
    $port = Get-GuardRemotePort
    $font = Get-UiFont

    $form = New-Object System.Windows.Forms.Form
    $form.Text = '手机远程控制'
    $form.ClientSize = New-Object System.Drawing.Size(600, 560)
    $form.StartPosition = 'CenterScreen'
    $form.Font = $font
    $form.MaximizeBox = $false
    $form.FormBorderStyle = 'FixedSingle'

    $urlLabel = New-Object System.Windows.Forms.Label
    $urlLabel.Text = '电脑本机地址（只监听本机）'
    $urlLabel.SetBounds(20, 20, 560, 20)

    $urlBox = New-Object System.Windows.Forms.TextBox
    $urlBox.Text = ('http://127.0.0.1:{0}/' -f $port)
    $urlBox.SetBounds(20, 44, 430, 26)
    $urlBox.ReadOnly = $true
    $urlBox.Font = $font

    $copyUrlButton = New-Object System.Windows.Forms.Button
    $copyUrlButton.Text = '复制地址'
    $copyUrlButton.SetBounds(460, 44, 120, 26)
    $copyUrlButton.Add_Click({
        try {
            [Windows.Forms.Clipboard]::SetText($urlBox.Text)
            [Windows.Forms.MessageBox]::Show('本机地址已复制。') | Out-Null
        } catch {
            [Windows.Forms.MessageBox]::Show('复制失败，请手动选择文本。') | Out-Null
        }
    })

    $tokenLabel = New-Object System.Windows.Forms.Label
    $tokenLabel.Text = '访问令牌（手机首次打开时输入）'
    $tokenLabel.SetBounds(20, 84, 560, 20)

    $tokenBox = New-Object System.Windows.Forms.TextBox
    $tokenBox.Text = [string]$cfg.remoteToken
    $tokenBox.SetBounds(20, 108, 430, 26)
    $tokenBox.ReadOnly = $true
    $tokenBox.Font = $font

    $copyTokenButton = New-Object System.Windows.Forms.Button
    $copyTokenButton.Text = '复制令牌'
    $copyTokenButton.SetBounds(460, 108, 120, 26)
    $copyTokenButton.Add_Click({
        try {
            [Windows.Forms.Clipboard]::SetText($tokenBox.Text)
            [Windows.Forms.MessageBox]::Show('访问令牌已复制。') | Out-Null
        } catch {
            [Windows.Forms.MessageBox]::Show('复制失败，请手动选择文本。') | Out-Null
        }
    })

    $newTokenButton = New-Object System.Windows.Forms.Button
    $newTokenButton.Text = '生成新令牌'
    $newTokenButton.SetBounds(20, 142, 150, 28)
    $newTokenButton.Add_Click({
        $answer = [Windows.Forms.MessageBox]::Show(
            '生成新令牌后，旧令牌立即失效，手机需要重新输入。继续吗？', '确认',
            [Windows.Forms.MessageBoxButtons]::YesNo,
            [Windows.Forms.MessageBoxIcon]::Question)
        if ($answer -ne [Windows.Forms.DialogResult]::Yes) { return }
        $current = Get-GuardConfig
        $current = Update-GuardConfigDefaults -Config $current
        $current.remoteToken = New-GuardRemoteToken
        Save-GuardConfig $current
        $tokenBox.Text = [string]$current.remoteToken
        [Windows.Forms.MessageBox]::Show('新令牌已生成，旧令牌立即失效。') | Out-Null
    })

    $panelStatus = New-Object System.Windows.Forms.Label
    $panelStatus.SetBounds(190, 146, 390, 22)

    $barkLabel = New-Object System.Windows.Forms.Label
    $barkLabel.Text = 'Bark 推送 Key（iPhone 装 Bark App 后获取）'
    $barkLabel.SetBounds(20, 184, 560, 20)

    $barkBox = New-Object System.Windows.Forms.TextBox
    $barkBox.Text = [string]$cfg.barkKey
    $barkBox.SetBounds(20, 208, 430, 26)
    $barkBox.Font = $font

    $saveBarkButton = New-Object System.Windows.Forms.Button
    $saveBarkButton.Text = '保存 Key'
    $saveBarkButton.SetBounds(460, 208, 120, 26)
    $saveBarkButton.Add_Click({
        $current = Get-GuardConfig
        $current = Update-GuardConfigDefaults -Config $current
        $current.barkKey = $barkBox.Text.Trim()
        Save-GuardConfig $current
        [Windows.Forms.MessageBox]::Show('Bark Key 已保存。') | Out-Null
    })

    $testBarkButton = New-Object System.Windows.Forms.Button
    $testBarkButton.Text = '发送测试推送'
    $testBarkButton.SetBounds(20, 242, 150, 28)
    $testBarkButton.Add_Click({
        $current = Get-GuardConfig
        if (-not $current -or [string]::IsNullOrWhiteSpace([string]$current.barkKey)) {
            [Windows.Forms.MessageBox]::Show('请先填写并保存 Bark Key。') | Out-Null
            return
        }
        if (Send-BarkAlert -Title '家长防护测试' -Body '如果你收到这条消息，说明 Bark 推送已配置成功。') {
            [Windows.Forms.MessageBox]::Show('测试推送已发送，请查看 iPhone。') | Out-Null
        } else {
            [Windows.Forms.MessageBox]::Show('发送失败，请检查 Bark Key 和网络。') | Out-Null
        }
    })

    $tunnelUrlNow = Get-GuardTunnelUrl
    if ([string]::IsNullOrWhiteSpace($tunnelUrlNow)) { $tunnelUrlNow = '（尚未配置，电脑管理员运行 _tunnel_setup.ps1 授权后显示）' }
    $helpText = (@'
1. iPhone 用 Safari 打开下面这个固定地址，粘贴上面的访问令牌。
   {1}
2. 分享菜单选择「添加到主屏幕」，以后像 App 一样打开。
3. 地址由 Cloudflare 命名隧道加密，开机自动上线，保持不变。
4. iPhone 安装 Bark，把设备 Key 填到上面并保存，可收申请与告警。
5. 孩子必须使用标准用户账号，防卸载才会生效。
6. 连续 5 次输错令牌会被自动锁定 10 分钟；令牌泄露请立即换新。
'@) -f $port, $tunnelUrlNow

    $helpLabel = New-Object System.Windows.Forms.Label
    $helpLabel.Text = $helpText
    $helpLabel.SetBounds(20, 286, 560, 195)
    $helpLabel.ForeColor = [System.Drawing.Color]::DimGray

    $updateRemoteState = {
        if (Test-GuardPortOpen -Port $port) {
            $panelStatus.Text = '手机控制台：运行中'
            $panelStatus.ForeColor = [System.Drawing.Color]::ForestGreen
        } else {
            $panelStatus.Text = '手机控制台：未运行'
            $panelStatus.ForeColor = [System.Drawing.Color]::Firebrick
        }
        try {
            $tUrl = Get-GuardTunnelUrl
            if ($tUrl -and (Test-GuardTunnelRunning)) {
                $panelStatus.Text += '；公网隧道已连接'
            } elseif ($tUrl) {
                $panelStatus.Text += '；公网隧道未连接'
                $panelStatus.ForeColor = [System.Drawing.Color]::Firebrick
            }
        } catch { }
    }
    & $updateRemoteState

    $startPanelButton = New-Object System.Windows.Forms.Button
    $startPanelButton.Text = '启动 / 重启控制台'
    $startPanelButton.SetBounds(20, 500, 170, 30)
    $startPanelButton.Add_Click({
        $ok = Start-GuardPanelProcess -Port $port
        & $updateRemoteState
        if ($ok) {
            [Windows.Forms.MessageBox]::Show('手机控制台已启动。') | Out-Null
        } else {
            [Windows.Forms.MessageBox]::Show('启动失败，请检查 RemotePanel.ps1 是否存在。') | Out-Null
        }
    })

    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Text = '关闭'
    $closeButton.SetBounds(450, 500, 130, 30)
    $closeButton.Add_Click({ $form.Close() })

    $form.Controls.AddRange(@(
        $urlLabel, $urlBox, $copyUrlButton,
        $tokenLabel, $tokenBox, $copyTokenButton, $newTokenButton, $panelStatus,
        $barkLabel, $barkBox, $saveBarkButton, $testBarkButton,
        $helpLabel, $startPanelButton, $closeButton
    ))

    $form.Add_Shown({ & $updateRemoteState })
    $form.ShowDialog() | Out-Null
}

function New-UnlockButton {
    param([int]$Minutes, [int]$X)
    $button = New-Object System.Windows.Forms.Button
    $button.Text = ('放行 {0} 分钟' -f $Minutes)
    $button.SetBounds($X, 28, 135, 32)
    # GetNewClosure 让每个按钮绑定各自的小时数，避免循环变量共享
    $button.Add_Click({ Set-UnlockFromPanel -Minutes $Minutes }.GetNewClosure())
    return $button
}

function Set-UnlockFromPanel {
    param([int]$Minutes)
    try {
        Set-UnlockMinutes -Minutes $Minutes
        Update-PanelStatus
        [Windows.Forms.MessageBox]::Show(('已临时放行 {0} 分钟，到期自动恢复限制。' -f $Minutes)) | Out-Null
    } catch {
        [Windows.Forms.MessageBox]::Show(('操作失败：' + $_.Exception.Message)) | Out-Null
    }
}

function Get-PanelStatusText {
    $cfg = Get-GuardConfig
    if (-not $cfg) { return '未安装' }
    $state = Get-EffectiveState -Config $cfg
    if ($state -eq 'unlocked') {
        $remainingMs = [double]$cfg.unlockUntilUptimeMs - [double](Get-UptimeMs)
        $minutes = [int][math]::Max(0, [math]::Ceiling($remainingMs / 60000))
        return ('已临时放行：剩余约 {0} 分钟，到期自动恢复限制' -f $minutes)
    }
    $modeText = '标准模式（按名单拦截）'
    if ($cfg.mode -eq 'strict') { $modeText = '严格模式（浏览器只允许白名单）' }
    return ('已锁定：微信/QQ 与娱乐网站禁止使用 | ' + $modeText)
}

function Update-PanelStatus {
    if ($script:StatusLabel -and -not $script:StatusLabel.IsDisposed) {
        $script:StatusLabel.Text = Get-PanelStatusText
    }
}

function Update-PanelPendingInfo {
    if (-not $script:PendingLabel -or $script:PendingLabel.IsDisposed) { return }
    $count = @(Get-GuardRequests).Count
    if ($count -gt 0) {
        $script:PendingLabel.Text = ('孩子的使用申请：{0} 条待处理 —— 请在手机控制台批准或拒绝（本电脑端不提供审批）。' -f $count)
        $script:PendingLabel.ForeColor = [System.Drawing.Color]::FromArgb(160, 100, 20)
    } else {
        $script:PendingLabel.Text = '孩子的使用申请：暂无待处理申请。审批统一在手机控制台完成。'
        $script:PendingLabel.ForeColor = [System.Drawing.Color]::DimGray
    }
}

# =====================================================================
# 名单设置
# =====================================================================

function Show-BlocklistEditor {
    $cfg = Get-GuardConfig
    if (-not $cfg) { return }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = '拦截名单设置'
    $form.ClientSize = New-Object System.Drawing.Size(720, 620)
    $form.StartPosition = 'CenterScreen'
    $form.Font = Get-UiFont
    $form.MaximizeBox = $false
    $form.FormBorderStyle = 'FixedSingle'

    # ---------- 默认视图：只显示数量，不显示任何具体网站 / 程序名 ----------
    $modeText = if ($cfg.mode -eq 'strict') { '严格模式（浏览器只允许白名单网站）' } else { '标准模式（按名单拦截）' }
    $coverText = @"
为避免孩子看到完整拦截名单、照着名单逐个去试，这里默认不显示具体内容。

当前防护：$modeText
　禁止访问的网站：$(@($cfg.domainBlockList).Count) 个
　允许访问的网站：$(@($cfg.domainAllowList).Count) 个
　禁止运行的程序：$(@($cfg.appBlockList).Count) 个

确需查看或修改名单时，请验证家长密码。不要在孩子在场时显示名单。
"@

    $coverLabel = New-Object System.Windows.Forms.Label
    $coverLabel.SetBounds(20, 20, 680, 300)
    $coverLabel.Text = $coverText

    $revealButton = New-Object System.Windows.Forms.Button
    $revealButton.Text = '我是家长，验证密码后显示名单'
    $revealButton.SetBounds(20, 330, 260, 36)

    $closeCoverButton = New-Object System.Windows.Forms.Button
    $closeCoverButton.Text = '关闭'
    $closeCoverButton.SetBounds(595, 560, 105, 32)
    $closeCoverButton.Add_Click({ $form.Close() })

    # ---------- 编辑控件：初始隐藏且不装载数据，验证通过后才填充 ----------
    $modeLabel = New-Object System.Windows.Forms.Label
    $modeLabel.Text = '浏览器模式：'
    $modeLabel.SetBounds(20, 15, 100, 22)

    $standardRadio = New-Object System.Windows.Forms.RadioButton
    $standardRadio.Text = '标准模式：只拦截下面名单中的网站'
    $standardRadio.SetBounds(20, 38, 320, 24)

    $strictRadio = New-Object System.Windows.Forms.RadioButton
    $strictRadio.Text = '严格模式：浏览器只能访问白名单网站'
    $strictRadio.SetBounds(350, 38, 350, 24)

    $domainLabel = New-Object System.Windows.Forms.Label
    $domainLabel.Text = '禁止访问的网站域名（每行一个，自动覆盖子域名）：'
    $domainLabel.SetBounds(20, 72, 660, 22)

    $domainBox = New-Object System.Windows.Forms.TextBox
    $domainBox.SetBounds(20, 94, 680, 150)
    $domainBox.Multiline = $true
    $domainBox.ScrollBars = 'Vertical'

    $allowLabel = New-Object System.Windows.Forms.Label
    $allowLabel.Text = '允许访问的网站（例外 / 严格模式白名单，每行一个）：'
    $allowLabel.SetBounds(20, 254, 660, 22)

    $allowBox = New-Object System.Windows.Forms.TextBox
    $allowBox.SetBounds(20, 276, 680, 100)
    $allowBox.Multiline = $true
    $allowBox.ScrollBars = 'Vertical'

    $appLabel = New-Object System.Windows.Forms.Label
    $appLabel.Text = '禁止运行的程序（每行一个，可省略 .exe）：'
    $appLabel.SetBounds(20, 386, 660, 22)

    $appBox = New-Object System.Windows.Forms.TextBox
    $appBox.SetBounds(20, 408, 680, 100)
    $appBox.Multiline = $true
    $appBox.ScrollBars = 'Vertical'

    $hint = New-Object System.Windows.Forms.Label
    $hint.Text = '保存后立即生效；已打开的浏览器需要重启或重新打开页面。'
    $hint.ForeColor = [System.Drawing.Color]::DimGray
    $hint.SetBounds(20, 520, 680, 22)

    $saveButton = New-Object System.Windows.Forms.Button
    $saveButton.Text = '保存并生效'
    $saveButton.SetBounds(480, 560, 105, 32)
    $saveButton.Add_Click({
        try {
            $new = Get-GuardConfig
            $new.domainBlockList = @($domainBox.Lines | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            $new.domainAllowList = @($allowBox.Lines | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            $new.appBlockList = @($appBox.Lines | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            if ($strictRadio.Checked) { $new.mode = 'strict' } else { $new.mode = 'blocklist' }

            if ($new.mode -eq 'strict' -and @($new.domainAllowList).Count -eq 0) {
                $answer = [Windows.Forms.MessageBox]::Show(
                    '严格模式白名单为空，浏览器将无法访问任何网站（本机地址除外）。确定继续吗？',
                    '严格模式确认', 'YesNo', 'Warning')
                if ($answer -ne [Windows.Forms.DialogResult]::Yes) { return }
            }

            Save-GuardConfig $new
            if ((Get-EffectiveState -Config $new) -eq 'locked') {
                Invoke-ApplyGuard -State 'locked' -Config $new
            }
            Update-PanelStatus
            [Windows.Forms.MessageBox]::Show('名单已保存并生效。') | Out-Null
            $form.Close()
        } catch {
            [Windows.Forms.MessageBox]::Show(('保存失败：' + $_.Exception.Message), '错误', 'OK', 'Error') | Out-Null
        }
    })

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = '取消'
    $cancelButton.SetBounds(595, 560, 105, 32)
    $cancelButton.Add_Click({ $form.Close() })

    $editorControls = @(
        $modeLabel, $standardRadio, $strictRadio,
        $domainLabel, $domainBox, $allowLabel, $allowBox,
        $appLabel, $appBox, $hint, $saveButton, $cancelButton
    )
    foreach ($c in $editorControls) { $c.Visible = $false }

    $revealButton.Add_Click({
        $pwd = Read-PasswordDialog -Title '家长验证' -Prompt '查看或修改拦截名单需要再次输入家长密码：'
        if ($null -eq $pwd) { return }
        if (-not (Test-GuardPassword -Password $pwd)) {
            [Windows.Forms.MessageBox]::Show('密码错误，不能显示名单。', '家长防护', 'OK', 'Error') | Out-Null
            return
        }
        # 验证通过后才把名单内容装入控件
        if ($cfg.mode -eq 'strict') { $strictRadio.Checked = $true } else { $standardRadio.Checked = $true }
        $domainBox.Text = (@($cfg.domainBlockList) -join "`r`n")
        $allowBox.Text = (@($cfg.domainAllowList) -join "`r`n")
        $appBox.Text = (@($cfg.appBlockList) -join "`r`n")
        foreach ($c in $editorControls) { $c.Visible = $true }
        $coverLabel.Visible = $false
        $revealButton.Visible = $false
        $closeCoverButton.Visible = $false
    })

    $form.Controls.AddRange(@($coverLabel, $revealButton, $closeCoverButton) + $editorControls)

    $form.ShowDialog() | Out-Null
}

# =====================================================================
# 说明 / 卸载流程 / 状态检查
# =====================================================================

function Show-GuardHelpDialog {
    $text = @"
ParentGuard 家长防护 - 使用说明

孩子侧（电脑）：
1. 桌面只有「请求使用权限」一个入口；微信/QQ 等被拦截时也会自动弹出申请窗口。
2. 孩子在窗口里选择“网站”或“应用”，填写要放行的具体网站或应用名称、
   使用时长和用途后提交，窗口里看不到拦截名单，也没有任何家长操作。
3. 申请提交后等待家长在手机上批准；批准后按申请时长临时放行，到期自动恢复。

家长侧（手机）：
   - 批准 / 拒绝申请、临时放行、立即恢复限制全部在手机控制台完成。
   - 打开本控制台，点击「手机远程控制（家长端）」复制访问令牌、查看固定公网地址。
   - iPhone Safari 打开该固定地址（Cloudflare 命名隧道，开机自动上线），输入令牌，再「添加到主屏幕」。
   - iPhone 安装 Bark，把设备 Key 填进「手机远程控制」，可接收申请、离线、策略被改等告警。
   - 手机控制台只监听 127.0.0.1，由加密隧道回源，不要在路由器上映射面板端口。

家长侧（电脑，本窗口）：
   - 仅用于修改密码、维护名单、检查状态与卸载；不能直接批准孩子的申请。
   - 「拦截名单设置」默认只显示数量，需再次验证家长密码才会显示具体名单。
   - 本入口位于受保护目录（$($script:GuardRoot)\家长控制台.lnk），
     不出现在孩子的桌面。

防护方式：
   - 注册表管理策略：Edge / Chrome / Chromium 系浏览器的网站拦截、关闭 DoH、禁用无痕模式
   - 程序执行劫持（IFEO）：微信 / QQ / TIM 双击即被拦截
   - hosts 兜底：覆盖其他浏览器
   - Firefox policies.json（若安装了 Firefox）
   - SYSTEM 计划任务每分钟自检，被改动会自动恢复

重要提示：
   本软件依赖本机管理员权限。如果孩子知道管理员密码、或能在 UAC 弹窗中直接点「是」，
   任何本机限制都可能被绕过。建议为孩子使用独立的标准用户账户，家长账户单独设密码。
"@
    [Windows.Forms.MessageBox]::Show($text, '使用说明') | Out-Null
}

function Invoke-UninstallFlow {
    if (-not (Test-Path -LiteralPath $script:ConfigPath)) {
        [Windows.Forms.MessageBox]::Show('ParentGuard 尚未安装。', '提示') | Out-Null
        return
    }
    $password = Read-PasswordDialog -Title '卸载 ParentGuard' -Prompt '请输入家长防护密码以卸载：'
    if ($null -eq $password) { return }
    if (-not (Test-GuardPassword -Password $password)) {
        [Windows.Forms.MessageBox]::Show('密码错误，无法卸载。', '错误', 'OK', 'Error') | Out-Null
        return
    }
    $answer = [Windows.Forms.MessageBox]::Show(
        '确定要卸载并恢复微信/QQ 与网站访问吗？', '确认卸载',
        [Windows.Forms.MessageBoxButtons]::YesNo,
        [Windows.Forms.MessageBoxIcon]::Warning)
    if ($answer -ne [Windows.Forms.DialogResult]::Yes) { return }

    try {
        Uninstall-Guard
        [Windows.Forms.MessageBox]::Show('已卸载，系统限制已恢复。', 'ParentGuard') | Out-Null
    } catch {
        [Windows.Forms.MessageBox]::Show(('卸载失败：' + $_.Exception.Message), '错误', 'OK', 'Error') | Out-Null
    }
}

function Show-GuardVerification {
    $cfg = Get-GuardConfig
    if (-not $cfg) {
        Write-Host 'ParentGuard 未安装。' -ForegroundColor Yellow
        return
    }
    $state = Get-EffectiveState -Config $cfg
    $remaining = '—'
    if ($state -eq 'unlocked') {
        $remaining = '{0} 分钟' -f [int][math]::Max(0, [math]::Ceiling((([double]$cfg.unlockUntilUptimeMs - [double](Get-UptimeMs)) / 60000)))
    }

    Write-Host ''
    Write-Host '===== ParentGuard 状态检查 =====' -ForegroundColor Cyan
    Write-Host ('安装目录      : ' + $script:GuardRoot)
    Write-Host ('当前状态      : ' + $state + '  (剩余 ' + $remaining + ')')
    Write-Host ('浏览器模式    : ' + $cfg.mode)
    Write-Host ('网站拦截数量  : ' + @($cfg.domainBlockList).Count)
    Write-Host ('网站白名单    : ' + @($cfg.domainAllowList).Count)
    Write-Host ('程序拦截数量  : ' + @($cfg.appBlockList).Count)
    Write-Host ('Edge 策略     : ' + (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLBlocklist'))
    Write-Host ('Chrome 策略   : ' + (Test-Path 'HKLM:\SOFTWARE\Policies\Google\Chrome\URLBlocklist'))
    Write-Host ('hosts 标记    : ' + ((Test-Path -LiteralPath $script:HostsPath) -and ([IO.File]::ReadAllText($script:HostsPath).Contains($script:BeginMarker))))
    Write-Host ('程序劫持      : ' + (Test-Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\WeChat.exe')))
    Write-Host ('策略完整性    : ' + (Test-GuardApplied -Config $cfg))
    $taskWatch = & schtasks.exe /Query /TN 'ParentGuard-Watchdog' 2>&1
    Write-Host ('守护任务      : ' + ($LASTEXITCODE -eq 0))
    $taskMeter = & schtasks.exe /Query /TN 'ParentGuard-UsageMeter' 2>&1
    Write-Host ('用量采集任务  : ' + ($LASTEXITCODE -eq 0))
    Write-Host ('拦截提示脚本  : ' + (Test-Path -LiteralPath $script:StubScript))
    Write-Host ('待处理申请    : ' + @(Get-GuardRequests).Count)
    Write-Host ''
}

function Show-Help {
    Write-Host @"
ParentGuard - 家长防护（Windows）

用法：
  ParentGuard.ps1                 打开家长防护控制台（自动请求管理员权限，首次运行即安装）
  ParentGuard.ps1 -Install        安装 / 更新策略文件
  ParentGuard.ps1 -Uninstall      卸载并恢复系统
  ParentGuard.ps1 -Verify         查看当前状态（需管理员）
  ParentGuard.ps1 -SelfTest -DryRun   只读自检（不改动系统）

也可以直接双击 Run-ParentGuard.cmd 启动控制台。
"@
}

# =====================================================================
# 入口分发（必须放在所有函数定义之后）
# =====================================================================

if ($Verify) {
    if (-not (Test-Admin)) {
        Write-Host '请先以管理员身份运行本脚本后再执行 -Verify。' -ForegroundColor Yellow
        return
    }
    Show-GuardVerification
    return
}

if ($Uninstall) {
    Invoke-UninstallFlow
    return
}

if (-not $wantUi) {
    Show-Help
    return
}

Start-GuardUi
