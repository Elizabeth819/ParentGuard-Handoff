# =====================================================================
#  ParentGuard - 孩子端：被拦截提示 / 使用申请窗口
#  - 作为 IFEO Debugger 被拉起时：$RestArgs[0] 是被拦截程序路径
#  - 以 -Request 启动时（桌面快捷方式）：直接打开申请窗口
#  说明：本窗口只能“提交申请”，不含任何家长操作，也不展示拦截名单。
#        批准 / 拒绝由家长在手机控制台完成。
# =====================================================================
param(
    [switch]$Request,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RestArgs
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()

$requestsDir = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ParentGuard\requests'
$requestMode = $Request.IsPresent
$exePath = if ($requestMode) { '' } elseif ($RestArgs.Count -gt 0) { $RestArgs[0] } else { '' }

function Get-FriendlyName([string]$path) {
    if (-not $path) { return '' }
    $file = [IO.Path]::GetFileName($path).ToLowerInvariant()
    switch ($file) {
        'wechat.exe'      { return '微信' }
        'weixin.exe'      { return '微信' }
        'wechatapp.exe'   { return '微信' }
        'wechatappex.exe' { return '微信' }
        'qq.exe'          { return 'QQ' }
        'qqsclauncher.exe'{ return 'QQ' }
        'tim.exe'         { return 'TIM' }
        default           { return [IO.Path]::GetFileNameWithoutExtension($file) }
    }
}

$appPreset = Get-FriendlyName $exePath

# ---------- 配色 ----------
$clrBg      = [Drawing.Color]::FromArgb(238, 240, 245)
$clrCard    = [Drawing.Color]::White
$clrText    = [Drawing.Color]::FromArgb(17, 24, 39)
$clrSub     = [Drawing.Color]::FromArgb(107, 114, 128)
$clrAccent  = [Drawing.Color]::FromArgb(99, 102, 241)    # 靛蓝
$clrAccent2 = [Drawing.Color]::FromArgb(59, 130, 246)    # 亮蓝
$clrAccentD = [Drawing.Color]::FromArgb(79, 70, 229)
$clrBorder  = [Drawing.Color]::FromArgb(209, 213, 219)

$fontBase  = New-Object Drawing.Font('Microsoft YaHei UI', 9.5)
$fontTitle = New-Object Drawing.Font('Microsoft YaHei UI', 15, [Drawing.FontStyle]::Bold)
$fontSub   = New-Object Drawing.Font('Microsoft YaHei UI', 9)
$fontLabel = New-Object Drawing.Font('Microsoft YaHei UI', 9.5, [Drawing.FontStyle]::Bold)
$fontBtn   = New-Object Drawing.Font('Microsoft YaHei UI', 10.5, [Drawing.FontStyle]::Bold)

# ---------- 圆角路径工具 ----------
function New-RoundedPath([Drawing.Rectangle]$rect, [int]$radius) {
    $path = New-Object Drawing.Drawing2D.GraphicsPath
    $d = $radius * 2
    $path.AddArc($rect.X, $rect.Y, $d, $d, 180, 90)
    $path.AddArc($rect.Right - $d, $rect.Y, $d, $d, 270, 90)
    $path.AddArc($rect.Right - $d, $rect.Bottom - $d, $d, $d, 0, 90)
    $path.AddArc($rect.X, $rect.Bottom - $d, $d, $d, 90, 90)
    $path.CloseFigure()
    return $path
}

# ---------- 绘制现代盾牌图标 ----------
function New-ShieldIcon([int]$size) {
    $bmp = New-Object Drawing.Bitmap($size, $size)
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [Drawing.Drawing2D.SmoothingMode]::AntiAlias

    # 渐变圆角方形底
    $rect = New-Object Drawing.Rectangle(0, 0, ($size - 1), ($size - 1))
    $path = New-RoundedPath $rect ([int]($size * 0.28))
    $grad = New-Object Drawing.Drawing2D.LinearGradientBrush(
        $rect, $clrAccent, $clrAccent2,
        [Drawing.Drawing2D.LinearGradientMode]::ForwardDiagonal)
    $g.FillPath($grad, $path)

    # 白色盾牌（与设计稿 A 一致的平滑盾形）
    $u = $size / 48.0
    $shield = New-Object Drawing.Drawing2D.GraphicsPath
    # 顶部：M24,11 → 贝塞尔到右上肩 33,14.2
    $shield.AddBezier(24*$u, 11*$u, 26.4*$u, 12.8*$u, 29.4*$u, 14*$u, 33*$u, 14.2*$u)
    # 右边直下
    $shield.AddLine(33*$u, 14.2*$u, 33*$u, 24*$u)
    # 右侧弧线到底尖 24,36.8
    $shield.AddBezier(33*$u, 24*$u, 33*$u, 30.2*$u, 29*$u, 34.4*$u, 24*$u, 36.8*$u)
    # 左侧弧线回 15,24
    $shield.AddBezier(24*$u, 36.8*$u, 19*$u, 34.4*$u, 15*$u, 30.2*$u, 15*$u, 24*$u)
    # 左边直上回肩
    $shield.AddLine(15*$u, 24*$u, 15*$u, 14.2*$u)
    # 顶部贝塞尔回到起点
    $shield.AddBezier(15*$u, 14.2*$u, 18.6*$u, 14*$u, 21.6*$u, 12.8*$u, 24*$u, 11*$u)
    $shield.CloseFigure()
    $g.FillPath([Drawing.Brushes]::White, $shield)

    # 盾内对勾（用底色）
    $pen = New-Object Drawing.Pen($clrAccent, [single](2.6 * $u))
    $pen.StartCap = [Drawing.Drawing2D.LineCap]::Round
    $pen.EndCap = [Drawing.Drawing2D.LineCap]::Round
    $pen.LineJoin = [Drawing.Drawing2D.LineJoin]::Round
    $g.DrawLine($pen, [single](20*$u), [single](23.5*$u), [single](23*$u), [single](26.5*$u))
    $g.DrawLine($pen, [single](23*$u), [single](26.5*$u), [single](28.5*$u), [single](20.5*$u))

    $pen.Dispose(); $shield.Dispose(); $grad.Dispose(); $path.Dispose(); $g.Dispose()
    return $bmp
}

# ---------- 主窗口（无边框圆角）----------
$form = New-Object Windows.Forms.Form
$form.FormBorderStyle = 'None'
$form.ClientSize = New-Object Drawing.Size(520, 620)
$form.StartPosition = 'CenterScreen'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.ShowIcon = $false
$form.ShowInTaskbar = $true
$form.TopMost = $true
$form.Font = $fontBase
$form.BackColor = $clrBg

# 圆角窗口
$form.Add_Load({
    $p = New-RoundedPath (New-Object Drawing.Rectangle(0, 0, $form.Width, $form.Height)) 18
    $form.Region = New-Object Drawing.Region($p)
    $p.Dispose()
})

# 无边框拖动
$script:dragging = $false
$script:dragStart = [Drawing.Point]::Empty
function Start-Drag($sender, $e) {
    if ($e.Button -eq 'Left') {
        $script:dragging = $true
        $script:dragStart = $e.Location
    }
}
function Do-Drag($sender, $e) {
    if ($script:dragging) {
        $pt = $form.PointToScreen($e.Location)
        $form.Location = New-Object Drawing.Point(($pt.X - $script:dragStart.X), ($pt.Y - $script:dragStart.Y))
    }
}
function Stop-Drag { $script:dragging = $false }

# ---------- 白色卡片 ----------
$card = New-Object Windows.Forms.Panel
$card.SetBounds(24, 24, 472, 572)
$card.BackColor = $clrCard
$card.Add_MouseDown({ Start-Drag $args[0] $args[1] })
$card.Add_MouseMove({ Do-Drag $args[0] $args[1] })
$card.Add_MouseUp({ Stop-Drag })

# ---------- 关闭按钮（✕）----------
$closeX = New-Object Windows.Forms.Label
$closeX.SetBounds(428, 12, 32, 32)
$closeX.Text = [char]0x2715
$closeX.Font = New-Object Drawing.Font('Microsoft YaHei UI', 11)
$closeX.ForeColor = $clrSub
$closeX.TextAlign = 'MiddleCenter'
$closeX.Cursor = [Windows.Forms.Cursors]::Hand
$closeX.Add_Click({ $form.Close() })
$closeX.Add_MouseEnter({ $closeX.ForeColor = $clrText })
$closeX.Add_MouseLeave({ $closeX.ForeColor = $clrSub })

# ---------- 图标 + 标题 ----------
$iconBox = New-Object Windows.Forms.PictureBox
$iconBox.SetBounds(24, 28, 52, 52)
$iconBox.Image = New-ShieldIcon 52
$iconBox.SizeMode = 'Normal'
$iconBox.BackColor = [Drawing.Color]::Transparent

$title = New-Object Windows.Forms.Label
$title.SetBounds(90, 32, 340, 32)
$title.Font = $fontTitle
$title.ForeColor = $clrText
$title.Text = if ($requestMode) { '申请临时使用权限' } else { '程序已被家长拦截' }

$subtitle = New-Object Windows.Forms.Label
$subtitle.SetBounds(90, 66, 358, 20)
$subtitle.Font = $fontSub
$subtitle.ForeColor = $clrSub
$subtitle.Text = if ($requestMode) {
    '写清楚要用什么、做什么，提交后由家长在手机上批准。'
} else {
    $name = if ($appPreset) { "「$appPreset」" } else { '该程序' }
    "$name 已被禁止使用，可向家长提交申请。"
}

# ---------- 分隔线 ----------
$divider = New-Object Windows.Forms.Panel
$divider.SetBounds(24, 100, 424, 1)
$divider.BackColor = [Drawing.Color]::FromArgb(229, 231, 235)

# ---------- 申请类型 ----------
$kindLabel = New-Object Windows.Forms.Label
$kindLabel.Text = '申请类型'
$kindLabel.Font = $fontLabel
$kindLabel.ForeColor = $clrText
$kindLabel.SetBounds(24, 118, 200, 22)

$websiteRadio = New-Object Windows.Forms.RadioButton
$websiteRadio.Text = '网站'
$websiteRadio.SetBounds(24, 144, 90, 24)
$websiteRadio.ForeColor = $clrText

$appRadio = New-Object Windows.Forms.RadioButton
$appRadio.Text = '应用（程序）'
$appRadio.SetBounds(124, 144, 140, 24)
$appRadio.ForeColor = $clrText

if ($requestMode) { $websiteRadio.Checked = $true } else { $appRadio.Checked = $true }

# ---------- 申请对象 ----------
$targetLabel = New-Object Windows.Forms.Label
$targetLabel.Text = '申请放行的网站或应用（必填）'
$targetLabel.Font = $fontLabel
$targetLabel.ForeColor = $clrText
$targetLabel.SetBounds(24, 186, 420, 22)

$targetBox = New-Object Windows.Forms.TextBox
$targetBox.SetBounds(24, 212, 424, 28)
$targetBox.MaxLength = 120
$targetBox.BorderStyle = 'FixedSingle'
if (-not $requestMode -and $appPreset) { $targetBox.Text = $appPreset }

$targetHint = New-Object Windows.Forms.Label
$targetHint.SetBounds(24, 244, 424, 20)
$targetHint.Font = $fontSub
$targetHint.ForeColor = $clrSub

function Set-KindHint {
    if ($websiteRadio.Checked) {
        $targetHint.Text = '填写网址或网站名称，例如：www.baicizhan.com（百词斩）'
    } else {
        $targetHint.Text = '填写应用名称，例如：腾讯会议、网易有道词典'
    }
}
Set-KindHint
$websiteRadio.Add_Click({ Set-KindHint })
$appRadio.Add_Click({ Set-KindHint })

# ---------- 申请时长 ----------
$minutesLabel = New-Object Windows.Forms.Label
$minutesLabel.Text = '申请时长'
$minutesLabel.Font = $fontLabel
$minutesLabel.ForeColor = $clrText
$minutesLabel.SetBounds(24, 276, 200, 22)

$minutesBox = New-Object Windows.Forms.ComboBox
$minutesBox.SetBounds(24, 302, 160, 28)
$minutesBox.DropDownStyle = 'DropDownList'
$minutesBox.FlatStyle = 'Flat'
[void]$minutesBox.Items.AddRange([object[]]@('5 分钟', '15 分钟', '30 分钟', '60 分钟', '120 分钟'))
$minutesBox.SelectedIndex = 1

# ---------- 用途说明 ----------
$reasonLabel = New-Object Windows.Forms.Label
$reasonLabel.Text = '用途说明（必填）'
$reasonLabel.Font = $fontLabel
$reasonLabel.ForeColor = $clrText
$reasonLabel.SetBounds(24, 344, 420, 22)

$reasonBox = New-Object Windows.Forms.TextBox
$reasonBox.SetBounds(24, 370, 424, 76)
$reasonBox.Multiline = $true
$reasonBox.ScrollBars = 'Vertical'
$reasonBox.MaxLength = 200
$reasonBox.BorderStyle = 'FixedSingle'

$reasonHint = New-Object Windows.Forms.Label
$reasonHint.Text = '例如：上英语网课需要使用 / 老师布置的在线作业 / 查百科资料'
$reasonHint.Font = $fontSub
$reasonHint.ForeColor = $clrSub
$reasonHint.SetBounds(24, 450, 424, 20)

# ---------- 圆角按钮 ----------
$submit = New-Object Windows.Forms.Button
$submit.Text = '提交申请'
$submit.SetBounds(224, 490, 140, 44)
$submit.FlatStyle = 'Flat'
$submit.BackColor = $clrAccent
$submit.ForeColor = [Drawing.Color]::White
$submit.Font = $fontBtn
$submit.FlatAppearance.BorderSize = 0
$submit.FlatAppearance.MouseOverBackColor = $clrAccentD
$submit.Cursor = [Windows.Forms.Cursors]::Hand
$submit.Add_Resize({
    $rp = New-RoundedPath (New-Object Drawing.Rectangle(0, 0, $submit.Width, $submit.Height)) 10
    $submit.Region = New-Object Drawing.Region($rp)
    $rp.Dispose()
})

$close = New-Object Windows.Forms.Button
$close.Text = '关闭'
$close.SetBounds(378, 490, 70, 44)
$close.FlatStyle = 'Flat'
$close.BackColor = $clrCard
$close.ForeColor = $clrSub
$close.FlatAppearance.BorderColor = $clrBorder
$close.DialogResult = [Windows.Forms.DialogResult]::Cancel
$close.Cursor = [Windows.Forms.Cursors]::Hand

$submit.Add_Click({
    $kind = if ($websiteRadio.Checked) { 'website' } else { 'app' }
    $targetText = $targetBox.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($targetText)) {
        $msg = if ($websiteRadio.Checked) {
            "请填写要申请放行的网站地址或名称。`r`n例如：www.baicizhan.com"
        } else {
            "请填写要申请放行的应用名称。`r`n例如：腾讯会议"
        }
        [Windows.Forms.MessageBox]::Show($msg, 'ParentGuard', 'OK', 'Warning') | Out-Null
        $targetBox.Focus()
        return
    }
    if ($targetText -match '[\r\n\t]') {
        [Windows.Forms.MessageBox]::Show('网站或应用名称中不能包含换行等特殊字符。', 'ParentGuard', 'OK', 'Warning') | Out-Null
        $targetBox.Focus()
        return
    }
    if ([string]::IsNullOrWhiteSpace($reasonBox.Text)) {
        [Windows.Forms.MessageBox]::Show(
            '请填写用途说明，家长需要根据用途判断是否批准。',
            'ParentGuard', 'OK', 'Warning') | Out-Null
        $reasonBox.Focus()
        return
    }
    $minutes = @(5, 15, 30, 60, 120)[$minutesBox.SelectedIndex]
    try {
        if (-not (Test-Path -LiteralPath $requestsDir)) {
            New-Item -ItemType Directory -Path $requestsDir -Force | Out-Null
        }
        $name = 'req_' + (Get-Date -Format 'yyyyMMdd_HHmmss_fff') + '_' + ([Guid]::NewGuid().ToString('N').Substring(0, 8)) + '.json'
        $obj = [ordered]@{
            time    = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            kind    = $kind
            target  = $targetText
            exe     = if ($kind -eq 'app') { $exePath } else { '' }
            minutes = $minutes
            reason  = $reasonBox.Text.Trim()
        }
        $json = ($obj | ConvertTo-Json -Compress:$false)
        [IO.File]::WriteAllText((Join-Path $requestsDir $name), $json, (New-Object Text.UTF8Encoding($false)))
        [Windows.Forms.MessageBox]::Show(
            "申请已提交。`r`n请等待家长在手机控制台批准；批准后会按申请时长临时放行，到期自动恢复限制。",
            'ParentGuard', 'OK', 'Information') | Out-Null
        $form.Close()
    } catch {
        [Windows.Forms.MessageBox]::Show(
            "申请提交失败：$($_.Exception.Message)`r`n请直接告诉家长。",
            'ParentGuard', 'OK', 'Warning') | Out-Null
    }
})

$card.Controls.AddRange(@(
    $closeX, $iconBox, $title, $subtitle, $divider,
    $kindLabel, $websiteRadio, $appRadio,
    $targetLabel, $targetBox, $targetHint,
    $minutesLabel, $minutesBox,
    $reasonLabel, $reasonBox, $reasonHint,
    $submit, $close
))
$form.Controls.Add($card)
$form.AcceptButton = $submit
$form.CancelButton = $close
$form.Add_Shown({ if ($targetBox.CanFocus) { $targetBox.Focus() } })
[void]$form.ShowDialog()
