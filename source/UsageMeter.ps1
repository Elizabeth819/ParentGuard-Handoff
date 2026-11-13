# ParentGuard 用量采集器（完全自包含，不依赖 GuardCore.ps1）
# 由计划任务 ParentGuard-UsageMeter 在交互用户会话内每分钟运行一次：
#   1) 采集拥有可见窗口的程序 -> procs
#   2) 对 Edge / Chrome 读取浏览器历史库，判定当前所在站点 -> sites
# 结果写入 usage\inbox\sess_<sid>.json，由 SYSTEM 端的看门狗聚合落盘。
$ErrorActionPreference = 'SilentlyContinue'

$inboxDir = 'C:\ProgramData\ParentGuard\usage\inbox'
$exclude = @(
    'explorer.exe', 'textinputhost.exe', 'shellexperiencehost.exe', 'shellhost.exe',
    'searchhost.exe', 'searchui.exe', 'startmenuexperiencehost.exe', 'applicationframehost.exe',
    'lockapp.exe', 'widgets.exe', 'widgetservice.exe', 'systemsettings.exe', 'ctfmon.exe',
    'onedrive.exe', 'onedrivesetup.exe', 'cloudflared.exe', 'msmpeng.exe', 'securityhealthservice.exe',
    'securityhealthsystray.exe', 'runtimebroker.exe', 'dllhost.exe', 'backgroundtaskhost.exe',
    'sihost.exe', 'svchost.exe', 'dwm.exe', 'conhost.exe', 'openconsole.exe', 'powershell.exe', 'pwsh.exe',
    'searchapp.exe', 'sogousmartassistant.exe', 'sogoucloud.exe', 'sgtool.exe', 'smartscreen.exe'
)

# ------------------------------------------------------------------
# SQLite 读取器：用 Windows 自带的 winsqlite3.dll，无需安装任何依赖
# ------------------------------------------------------------------
$sqliteReady = $false
try {
    Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public class PGSqliteHist {
    const int SQLITE_OK = 0;
    const int SQLITE_ROW = 100;

    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_open_v2(string filename, out IntPtr db, int flags, IntPtr zVfs);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_close(IntPtr db);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_prepare_v2(IntPtr db, string sql, int nByte, out IntPtr stmt, IntPtr tail);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_step(IntPtr stmt);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr sqlite3_column_text(IntPtr stmt, int col);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_column_bytes(IntPtr stmt, int col);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern long sqlite3_column_int64(IntPtr stmt, int col);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_finalize(IntPtr stmt);

    // 返回 "url\t标题\tChrome时间戳" 字符串数组，按访问时间倒序
    public static string[] RecentUrls(string path, long minChromeTime, int limit) {
        IntPtr db = IntPtr.Zero;
        if (sqlite3_open_v2(path, out db, 1, IntPtr.Zero) != SQLITE_OK) { return new string[0]; }
        try {
            string sql = "SELECT url, title, last_visit_time FROM urls WHERE last_visit_time > " + minChromeTime + " ORDER BY last_visit_time DESC LIMIT " + limit;
            IntPtr stmt;
            if (sqlite3_prepare_v2(db, sql, -1, out stmt, IntPtr.Zero) != SQLITE_OK) { return new string[0]; }
            var list = new List<string>();
            try {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    list.Add(ColText(stmt, 0) + "\t" + ColText(stmt, 1) + "\t" + sqlite3_column_int64(stmt, 2).ToString());
                }
            } finally { sqlite3_finalize(stmt); }
            return list.ToArray();
        } finally { sqlite3_close(db); }
    }

    private static string ColText(IntPtr stmt, int col) {
        IntPtr p = sqlite3_column_text(stmt, col);
        int n = sqlite3_column_bytes(stmt, col);
        if (p == IntPtr.Zero || n <= 0) { return ""; }
        byte[] buf = new byte[n];
        Marshal.Copy(p, buf, 0, n);
        return Encoding.UTF8.GetString(buf);
    }
}
'@ -Language CSharp -ErrorAction Stop
    $sqliteReady = $true
} catch { }

$browserBases = @{
    'msedge.exe' = (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data')
    'chrome.exe' = (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data')
}
$epoch1601 = (Get-Date -Year 1601 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0).Ticks

# 站点归因证据链（可靠性从高到低；basis/note 会随快照落盘，供面板说明每一段的来源）：
#   ① 历史库标题精确/包含匹配 —— 同一时间窗口浏览过的页面标题与窗口标题一致，最可靠
#   ② 窗口标题本身就是域名/网址 —— 页面自己声明的站点（被拦截页、错误页常见这种标题）
#   ③ 历史库最近一次访问（仅限 5 分钟内）—— 标题对不上但刚访问过
#   ④ 浏览器会话/标签页文件里最近一次导航的域名 —— 历史库没有记录时用（被拦截的访问不写历史）
#   ⑤ 无站点页面（新标签页/空白页）—— 用确定性说明，不再记成"未知"
#   ⑥ 其它 —— 浏览器窗口存在但页面没留下可归因记录，同样给确定性说明
# 注：命中拦截名单的域名由 SYSTEM 端标注"（已拦截）"；普通用户会话读不到拦截名单，这里只给域名。
function New-SiteEvidence {
    param([string]$HostName, [string]$Basis, [string]$Note)
    return [ordered]@{ host = $HostName; basis = $Basis; note = $Note }
}

# 窗口标题本身是域名/网址时，直接取站点（"www.bilibili.com"、"http://bilibili.com/" 都算）
function Convert-TitleToHost {
    param([string]$Title)
    $t = ([string]$Title).Trim() -replace '^https?://', ''
    if (-not $t) { return '' }
    if ($t -notmatch '^([a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?))+)(?::\d+)?(?:[/?# ]|$)') { return '' }
    $h = $Matches[1].ToLowerInvariant() -replace '^www\.', ''
    $labels = $h -split '\.'
    $last = $labels[$labels.Count - 1]
    if ($last -notmatch '^[a-z]{2,6}$') { return '' }
    if (@('html', 'htm', 'php', 'asp', 'js', 'css', 'txt', 'jpg', 'png', 'gif', 'pdf', 'exe') -contains $last) { return '' }
    if ($h -eq 'localhost' -or $h -match '^\d+\.\d+\.\d+\.\d+$') { return '' }
    return $h
}

# ④ 浏览器会话/标签页文件里最近一次导航的域名（被拦截的访问不会进历史库，但会留在会话文件里）
function Get-SessionTabHost {
    param([string]$Exe)
    $base = $browserBases[$Exe]
    if ([string]::IsNullOrWhiteSpace($base) -or -not (Test-Path -LiteralPath $base)) { return '' }
    $files = @()
    foreach ($d in @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue)) {
        $sd = Join-Path $d.FullName 'Sessions'
        if (-not (Test-Path -LiteralPath $sd)) { continue }
        $files += @(Get-ChildItem -LiteralPath $sd -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^(Session|Tabs)_' -and $_.LastWriteTime -gt (Get-Date).AddMinutes(-30) })
    }
    $files = @($files | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 3)
    foreach ($f in $files) {
        try {
            $txt = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($f.FullName))
            # 会话里的标题是按字符拆开存的（UTF-16），先去掉 NUL 再匹配
            $flat = ($txt -replace "`0", '')
            $hits = [regex]::Matches($flat, 'https?://[!-~]{4,}')
            # 只认"标题就是域名"的导航：这是页面没加载成功（被拦截/错误页）的特征。
            # 成功打开的页面标题是正常文字，不会以域名开头，从而避免把后台标签页错记成当前站点。
            for ($i = $hits.Count - 1; $i -ge 0; $i--) {
                $h = ''
                try { $h = ([Uri]$hits[$i].Value).Host.ToLowerInvariant() } catch { continue }
                if (-not $h -or $h -notmatch '\.') { continue }
                if ($h -eq 'localhost' -or $h -match '^\d+\.\d+\.\d+\.\d+$') { continue }
                $tailStart = $hits[$i].Index + $hits[$i].Length
                $tailLen = [Math]::Min(160, $flat.Length - $tailStart)
                if ($tailLen -le 0) { continue }
                $clean = ($flat.Substring($tailStart, $tailLen) -replace '[^a-z0-9.]', '').ToLowerInvariant()
                if ($clean.StartsWith($h)) {
                    return ($h -replace '^www\.', '')
                }
            }
        } catch { }
    }
    return ''
}

function Get-BrowserHost {
    param(
        [string]$Exe,
        [string]$WindowTitle
    )
    $base = $browserBases[$Exe]
    $candidates = @()

    if ($sqliteReady -and -not [string]::IsNullOrWhiteSpace($base) -and (Test-Path -LiteralPath $base)) {
        $profiles = @()
        foreach ($d in @(Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue)) {
            $hist = Join-Path $d.FullName 'History'
            if (Test-Path -LiteralPath $hist) {
                $profiles += [pscustomobject]@{ Path = $hist; Stamp = (Get-Item -LiteralPath $hist).LastWriteTime }
            }
        }
        # 只扫描最近改动过的配置目录，避免无谓拷贝
        $profiles = @($profiles | Sort-Object -Property Stamp -Descending | Select-Object -First 4)

        $nowUtc = [datetime]::UtcNow
        $minChromeTime = [long](($nowUtc.AddHours(-12).Ticks - $epoch1601) / 10)
        foreach ($prof in $profiles) {
            if ($prof.Stamp -lt (Get-Date).AddHours(-12)) { continue }
            $tmpDir = Join-Path $env:TEMP ('PGHist_' + [guid]::NewGuid().ToString('N'))
            $tmp = Join-Path $tmpDir 'History'
            try {
                New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
                # 浏览器运行时库被锁定，但可以用共享读方式拷贝快照再读
                $src = [IO.File]::Open($prof.Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
                try {
                    $dst = [IO.File]::Create($tmp)
                    try { $src.CopyTo($dst) } finally { $dst.Close() }
                } finally { $src.Close() }
                # WAL / SHM 一起拷贝，保证最近访问记录可见
                foreach ($sfx in @('-wal', '-shm')) {
                    $p = $prof.Path + $sfx
                    if (Test-Path -LiteralPath $p) {
                        try {
                            $s2 = [IO.File]::Open($p, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
                            try {
                                $d2 = [IO.File]::Create($tmp + $sfx)
                                try { $s2.CopyTo($d2) } finally { $d2.Close() }
                            } finally { $s2.Close() }
                        } catch { }
                    }
                }
                foreach ($row in @([PGSqliteHist]::RecentUrls($tmp, $minChromeTime, 25))) {
                    $parts = $row -split "`t", 3
                    if ($parts.Count -lt 3) { continue }
                    $ts = 0L
                    try { $ts = [long]$parts[2] } catch { continue }
                    $visit = (New-Object datetime ($epoch1601 + $ts * 10)).ToLocalTime()
                    $candidates += [pscustomobject]@{
                        Url   = [string]$parts[0]
                        Title = ([string]$parts[1]).Trim()
                        Visit = $visit
                    }
                }
            } catch { } finally {
                Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # 窗口标题形如 "GitHub 和另外 2 个页面 - 个人 - Microsoft Edge"，
    # 依次剥掉"多标签后缀"和"浏览器/配置目录后缀"，留下当前标签页标题
    $cleanTitle = [string]$WindowTitle
    $cleanTitle = $cleanTitle -replace '\s*(?:和另外|and)\s*\d+\s*(?:个)?\s*(?:页面|标签页|more\s+pages?).*$', ''
    $cleanTitle = $cleanTitle -replace '\s*[-–—]\s*[^-–—]+\s*[-–—]\s*(?:Microsoft\s*Edge|Google\s*Chrome|Mozilla\s*Firefox).*$', ''
    $cleanTitle = $cleanTitle -replace '\s*[-–—]\s*(?:Microsoft\s*Edge|Google\s*Chrome|Mozilla\s*Firefox).*$', ''
    $cleanTitle = $cleanTitle.Trim()

    # ⑤ 新标签页/空白页：本来就没有站点，给确定性说明
    if ($cleanTitle -match '^(新标签页|新建标签页|New Tab|新分页|about:blank|空白页|Microsoft\s*Edge)$') {
        return (New-SiteEvidence '' '无站点页面' '浏览器停留在新标签页/空白页，未打开具体站点')
    }

    # ① 历史库标题匹配
    $pick = $null
    if ($cleanTitle.Length -ge 2) {
        foreach ($c in ($candidates | Sort-Object -Property Visit -Descending)) {
            if ($c.Title.Length -lt 2) { continue }
            if ($c.Title -eq $cleanTitle) { $pick = $c; break }
            if ($c.Title.Length -ge 5 -and $cleanTitle -like ('*' + $c.Title + '*')) { $pick = $c; break }
            if ($cleanTitle.Length -ge 5 -and $c.Title -like ('*' + $cleanTitle + '*')) { $pick = $c; break }
        }
    }
    $fromHistory = $false
    if (-not $pick) {
        # ② 标题本身就是域名/网址：页面自己声明的站点。必须排在"最近访问"之前，
        # 否则从 A 站跳到被拦截的 B 站时会被错记到 A 站上。
        $titleHost = Convert-TitleToHost $cleanTitle
        if ($titleHost) {
            return (New-SiteEvidence $titleHost '标题域名' ('窗口标题即访问域名：' + $cleanTitle))
        }
        # ③ 标题匹配失败时，只在"刚访问过"的情况下沿用最近一次访问（5 分钟）
        $recent = $candidates | Sort-Object -Property Visit -Descending | Select-Object -First 1
        if ($recent -and ((Get-Date) - $recent.Visit).TotalMinutes -le 5) { $pick = $recent; $fromHistory = $true }
    }

    if ($pick) {
        $hostName = ''
        try {
            $u = [Uri]$pick.Url
            if ($u.Scheme -eq 'http' -or $u.Scheme -eq 'https') {
                $hostName = $u.Host.ToLowerInvariant() -replace '^www\.', ''
            }
        } catch { }
        if ($hostName -and $hostName -match '\.') {
            $basis = $(if ($fromHistory) { '历史最近访问' } else { '历史标题匹配' })
            return (New-SiteEvidence $hostName $basis ('历史记录：' + $pick.Title))
        }
    }

    # ④ 会话/标签页文件里最近一次导航
    $sessionHost = Get-SessionTabHost -Exe $Exe
    if ($sessionHost) {
        return (New-SiteEvidence $sessionHost '会话标签页' '按浏览器会话文件里最近一次导航归属（该页面可能未写入浏览历史）')
    }

    # ⑥ 错误页/其余情况：给确定性说明，不再出现"未知"
    if ($cleanTitle -match '^(无法访问此网站|找不到服务器|网页无法打开|连接已重置|已阻止加载|此网站已被阻止|This site can|This page isn)') {
        return (New-SiteEvidence '' '错误页' '浏览器显示错误页，且历史/会话里都没有可对应到具体域名的记录')
    }
    return (New-SiteEvidence '' '无页面证据' '浏览器窗口存在，但当前页面没有留下可归因的记录')
}

# ------------------------------------------------------------------
# 1) 可见窗口程序
# ------------------------------------------------------------------
$procs = @{}
$titles = @{}
foreach ($p in @(Get-Process | Where-Object { $_.MainWindowHandle -ne 0 })) {
    $exe = ''
    try { if ($p.Path) { $exe = [IO.Path]::GetFileName($p.Path) } } catch { }
    if ([string]::IsNullOrWhiteSpace($exe)) { $exe = $p.ProcessName + '.exe' }
    $exe = $exe.ToLowerInvariant()
    if ($exclude -contains $exe) { continue }
    if ($procs.ContainsKey($exe)) { continue }
    $friendly = ''
    try { $friendly = [string]$p.MainModule.FileVersionInfo.FileDescription } catch { }
    if ([string]::IsNullOrWhiteSpace($friendly)) { $friendly = $p.ProcessName }
    $procs[$exe] = $friendly
    $titles[$exe] = [string]$p.MainWindowTitle
}

# ------------------------------------------------------------------
# 2) 浏览器当前站点
# ------------------------------------------------------------------
$sites = [ordered]@{}
foreach ($exe in @('msedge.exe', 'chrome.exe')) {
    if (-not $procs.ContainsKey($exe)) { continue }
    $site = Get-BrowserHost -Exe $exe -WindowTitle $titles[$exe]
    if ($site) { $sites[$exe] = $site }
}

$sid = 0
try { $sid = (Get-Process -Id $PID).SessionId } catch { }
$snap = [ordered]@{
    ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    sid = $sid
    procs = $procs
    sites = $sites
}

try {
    if (-not (Test-Path -LiteralPath $inboxDir)) { New-Item -ItemType Directory -Path $inboxDir -Force | Out-Null }
    $final = Join-Path $inboxDir ('sess_' + $sid + '.json')
    $tmpFile = $final + '.tmp'
    ($snap | ConvertTo-Json -Compress -Depth 5) | Out-File -LiteralPath $tmpFile -Encoding utf8 -Force
    Move-Item -LiteralPath $tmpFile -Destination $final -Force
} catch { }
