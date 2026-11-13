# ParentGuard（Windows 家长防护 + 用量管理）

开源的家庭电脑使用管理工具：程序/网站使用统计、黑名单拦截、限时放行、手机网页家长面板。
面向 Windows 10/11，全部为 PowerShell 脚本，无云端依赖；数据默认只保存在本机，启用多设备汇总时只上报到你自己的主机。

> **默认口令是 `123456`，安装后第一次登录必须立即修改。**

## 适用范围与免责

- 仅用于监护人对家庭自有设备做使用管理，请在设备使用者知情的前提下使用。
- 不做隐蔽监控、不上传数据：记录保存在本机 `C:\ProgramData\ParentGuard`。
- 不提供绕过系统安全机制的能力；卸载需要管理员权限。
- 作者不对使用本软件造成的任何损失负责；在受管设备上安装前请确认符合当地法律法规。

## 两步安装

1. 下载 Release 中的 `ParentGuard-Package.zip` 并解压。
2. 管理员 PowerShell 执行 `source\_admin_install.ps1`（可先加 `-VerifyOnly` 自检）。

## 卸载

管理员 PowerShell 执行 `source\_admin_uninstall.ps1`。

---

# 便携安装包说明

把整套家长防护 + 用量采集 + 手机面板装到另一台 Windows 电脑。
本包与当前生产机同源（2026-11-13 导出），已包含无窗口采集启动器。

## 目录

```
ParentGuard-Package\
├─ README.md                 本说明
├─ config.example.json       配置样例（安装时自动生成正式配置，不含密码）
└─ source\
   ├─ _admin_install.ps1     安装入口（需管理员）
   ├─ _admin_uninstall.ps1   卸载入口（需管理员）
   ├─ ParentGuard.ps1        家长控制台 / 策略
   ├─ GuardCore.ps1          核心：配置、拦截、用量落盘
   ├─ UsageMeter.ps1         每分钟采集窗口与站点
   ├─ RemotePanel.ps1        手机网页面板
   ├─ watchdog.ps1           每分钟守护
   ├─ health.ps1             每 5 分钟自检
   ├─ Show-Blocked.ps1       孩子端“申请使用”窗口
   ├─ Join-Fleet.ps1         子机加入主机设备清单（多设备汇总）
   ├─ RunHidden.vbs          无窗口启动器（避免蓝窗闪烁）
   ├─ GuardSentinel.ps1 / ServiceHost.ps1 / OpsRunner.ps1   辅助
   └─ bin\cloudflared.exe    Cloudflare 隧道客户端（可选）
```

## 场景 A：只查看、不安装（在那台电脑上打开面板）

面板装在**被管控的那台电脑**上；"只查看"指的是用另一台设备（手机/电脑）去访问它。

| 情形 | 地址 | 前提 |
|---|---|---|
| 同一台电脑 | `http://127.0.0.1:8787/` | 面板任务已运行 |
| 同一局域网 | `http://<那台电脑的局域网IP>:8787/` | 面板监听局域网地址；防火墙放行 8787 |
| 公网 | `https://<隧道域名>/` | 该机器已配置 Cloudflare 隧道，或使用快速隧道地址 |

访问令牌：
- 在**被管控电脑**上打开「家长控制台」（安装目录内 `家长控制台.lnk`），手机访问页会显示令牌；
- 或由管理员查看 `C:\ProgramData\ParentGuard\config.json` 的 `remoteToken`。
- 令牌只保存在访问设备的浏览器里，连续输错会锁定。

## 场景 B：完整安装（管控 + 采集）

### 前置
- Windows 10/11，管理员账户
- PowerShell 5.1
- 目标机没有装过 ParentGuard（装过则本脚本按"升级"处理，会保留配置与密码）
- 8787 端口未被占用

### 步骤
1. 把整个 `ParentGuard-Package` 目录复制到目标机，例如 `C:\Temp\ParentGuard-Package`
2. 开始菜单搜索 PowerShell → 右键**以管理员身份运行**
3. 先自检（不改任何东西）：
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Temp\ParentGuard-Package\source\_admin_install.ps1" -VerifyOnly
```
看到 `VERIFY_OK` 再继续。

4. 正式安装：
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Temp\ParentGuard-Package\source\_admin_install.ps1"
```
安装做了什么：
- 复制脚本到 `C:\ProgramData\ParentGuard`
- 生成配置、设置初始密码 `123456`、生成面板访问令牌
- 收紧目录 ACL（普通用户不能读拦截名单）
- 注册计划任务：`ParentGuard-Watchdog`（每分钟）、`ParentGuard-Boot`、`ParentGuard-Panel`、`ParentGuard-Health`（每 5 分钟）、`ParentGuard-UsageMeter`（每分钟、交互用户、无窗口）
- 应用拦截策略、创建桌面入口

### 安装后验证
```powershell
# 1) 任务都在运行
Get-ScheduledTask -TaskName 'ParentGuard-*' | Select-Object TaskName,State

# 2) 面板本机可开
curl.exe -s -o NUL -w "%{http_code} %{size_download}" http://127.0.0.1:8787/

# 3) 采集有快照（约 1-2 分钟后出现）
Get-ChildItem C:\ProgramData\ParentGuard\usage\inbox\*.json | Select-Object Name,Length,LastWriteTime

# 4) 采集在增长（第二次执行数字应变大或文件更新时间变化）
Get-ChildItem C:\ProgramData\ParentGuard\usage\*.jsonl | Select-Object Name,Length,LastWriteTime
```
面板里「设备」一栏出现新设备名，说明该机数据已被面板识别。

### 首次登录后必须做
- 打开家长控制台，把密码从 `123456` 改掉
- 需要手机公网访问时，再配置隧道（本包已带 `cloudflared.exe`，但隧道授权需单独完成）

## 多设备汇总（可选）

任一装了本软件的 Windows 设备，只要填主机地址 + 一次性配对码，就会把自己的程序/网站用量、
在线状态和待审批申请汇总到主机面板；在一个面板里看全部设备、在一个地方完成审批。

不填 `fleetHost`（默认）就是单机模式，行为与旧版完全一致。

### 主机（要汇总到的那台电脑）
1. 打开主机面板，在「设备与程序用量」卡片点**生成配对码**，得到 8 位配对码。
   配对码 30 分钟内有效、只能用一次，页面只显示这一次。

### 子机（要加入的那台电脑）
2. 管理员 PowerShell 执行（配对码按提示输入，不写进命令历史）：
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\ParentGuard\Join-Fleet.ps1" -HostUrl http://<主机地址>:8787
```
   也可以直接编辑 `C:\ProgramData\ParentGuard\config.json`，填入 `fleetHost` 与 `fleetJoinCode`，
   下一分钟由守护任务自动完成加入（加入后配对码会自动清空，设备令牌保存到本机配置）。
3. 主机面板出现该设备后：
   - **全部设备 / 单台设备**切换后，程序用量、网站分析、申请列表都按所选范围显示；
   - 批准/拒绝会下发到申请所属设备执行，离线时排队，设备上线后自动生效并回执。

### 行为与安全说明
- 数据只从子机发到**你自己的主机**，不经过任何第三方服务；主机地址可填局域网地址或自己的隧道地址。
- 配对码与设备令牌在主机侧只保存哈希；凭据不写日志、不在面板回显（注册响应只回一次给该设备）。
- 面板原有的访问令牌、失败锁定机制不变；多设备上报通道有独立的失败锁定。
- 子机断网或主机关机：本地照常记录，恢复后自动补报；重复上报按记录指纹去重，不会重复计时。
- 审批指令保存在主机队列里直到子机确认执行，断电/断网都不会丢。
- 历史与保留策略不变：用量保留 30 天；主机移除设备后该设备立即停止上报，需重新配对。
- 传输走 HTTP（局域网）或你自己的 HTTPS 隧道；公网加入建议使用隧道地址。

## 站点采集注意事项

- 数据源：Edge / Chrome 的 `History` 数据库（`%LOCALAPPDATA%\Microsoft\Edge\User Data`、
  `%LOCALAPPDATA%\Google\Chrome\User Data`），以及窗口标题、被拦截记录、会话标签页。
- 采集任务必须跑在**实际使用浏览器的那个登录用户**会话里（安装脚本已按交互用户注册）；
  SYSTEM 身份看不到用户窗口。
- 只采当前登录用户：一台机器有多个 Windows 账户时，每个账户各自需要登录后才会产生该账户的数据。
- 浏览器正在运行时数据库被锁定，采集端用复制副本的方式读取，不会影响正常使用。
- 浏览器从未使用过 / 停留在新标签页 / 无历史记录时，会记为"无页面证据"并单独说明，
  不会笼统写成"未知"。
- 如果目标机没有安装 Edge/Chrome，站点采集为空，程序用量仍正常。

## 卸载

管理员 PowerShell：
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Temp\ParentGuard-Package\source\_admin_uninstall.ps1"
```
会删除计划任务、解除策略、移除安装目录（可选择保留 usage 数据，脚本会提示）。

## 常见问题

| 现象 | 处理 |
|---|---|
| 安装报"创建任务失败" | 确认是管理员窗口；`schtasks /query` 看是否被组策略限制 |
| 拔掉电源后面板/采集全停 | 计划任务默认只在交流电下运行。安装脚本已改为电池下也运行；旧机器可手动改任务"条件"里的电源选项 |
| 面板打不开 | `Get-NetTCPConnection -LocalPort 8787` 看是否监听；`logs\guard.log` 看前缀冲突 |
| inbox 一直没有 json | 确认已登录交互用户且 `ParentGuard-UsageMeter` 状态为 Ready/Running |
| 装了但没拦截 | 安装末尾会应用策略；重启一次或运行 `ParentGuard.ps1 -Apply` |
| 想换端口 | 安装前改 `config.example.json` 的 `remotePort`，或装完改 `config.json` 后重启 Panel 任务 |
