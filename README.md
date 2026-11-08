# ParentGuard 交接包（Windows → iPad / macOS 复刻）

> 本包用途：把一台 Windows 上已上线的家长防护系统，完整交接给另一台 MacBook 上的 AI，由它在新平台复刻。  
> 包内 `source/` 是真实生产源码（已剔除令牌、密码哈希、Bark Key、隧道信息等机密）；`config.example.json` 是脱敏配置样例。

---

## 一、系统三句话

1. 它是一套 Windows 家长防护系统：以「锁定 / 临时放行」为核心状态，用浏览器注册表策略、hosts 文件和 IFEO 程序劫持三重手段，拦截 69 个娱乐网站与微信、QQ、TIM 等程序，并用 SYSTEM 计划任务每分钟自检、自愈、写心跳、拉起面板与进程哨兵，做到开机自启、改了会被恢复、卸载需要家长密码。
2. 家长可以通过本地密码控制台，或手机网页端（Cloudflare 隧道 + 访问令牌）查看运行状态、一键临时放行 15–120 分钟、立即恢复限制；孩子被拦时会看到定制提示框，填写要用的网站/应用、时长和理由提交申请，家长在手机上批准或拒绝，到期自动恢复，关键事件通过 Bark 推送并写入审计日志。
3. 所有规则对所有使用者统一生效，默认「先禁止、再按需限时放行」，密码用 PBKDF2-SHA256 存储，公网入口连续输错 5 次即锁定 IP 10 分钟并告警，全程不依赖内核驱动。

---

## 二、行为契约（复刻时必须逐条对齐）

| ID | 行为 | Windows 实现（见 `source/`） | iPad / macOS 等价实现 | 验收标准 |
|---|---|---|---|---|
| P01 | 锁定/放行状态机 | `GuardCore.ps1` `Get-EffectiveState` | Swift 状态机 + 单调时钟（`ProcessInfo.systemUptime` / 后端时间） | 修改系统时间不能延长放行 |
| P02 | 限时放行 1–240 分钟，UI 预设 5/15/30/60/120 | `Set-UnlockMinutes`、`ParentGuard.ps1` 面板按钮 | `ManagedSettings` 解除 shield + `DeviceActivity` 定时重新 shield | 到期自动恢复，App 不在前台也生效 |
| P03 | 立即恢复限制 | `Invoke-Lock` | 立即重新施加 shield | 操作后 ≤5 秒生效 |
| P04 | 网站拦截 + 白名单 + 严格模式 + 禁 DoH/无痕 | `Set-BrowserPolicy`（Edge/Chrome 注册表 `URLBlocklist`/`URLAllowlist`） | `ManagedSettings.webContentFilter`（auto/allowlist/blocklist）或 MDM Web 过滤；DNS 方案作兜底 | 白名单可访问，其余被拦；App 内置浏览器同样生效 |
| P05 | 应用拦截 + 定制提示 + 申请入口 | IFEO `Debugger` 指向 `Show-Blocked.ps1` | `ManagedSettings.shield` + `ShieldConfiguration` 自定义盾牌页，带「申请使用」按钮 | 点开被拦 App 显示中文盾牌，可提交申请 |
| P06 | 进程哨兵实时终止被拦程序 | `GuardSentinel.ps1` 轮询并杀进程 | iOS 无等价能力（系统不允许）；iPad 由 Shield 阻止启动即可。macOS 需 EndpointSecurity 权限，属降级项 | 明确记录「不可复刻」，不得伪造 |
| P07 | 孩子提交申请（类型/目标/时长/理由） | `Show-Blocked.ps1` 写 `requests/req_*.json` | App Group 本地队列 + 后端 API；离线可提交，联网后送达 | 离线提交不丢失；字段完整 |
| P08 | 远程审批 / 拒绝 | `RemotePanel.ps1` 的 `/api/requests/approve` 与 `/api/requests/deny` | 后端（Cloudflare Worker 或 VPS）+ APNs；iPad 不能自己监听公网端口 | 批准后 ≤10 秒生效；拒绝留审计 |
| P09 | 家长手机面板（状态/申请/日志/放行/锁定） | `RemotePanel.ps1` PWA，`X-PG-Token` 鉴权，gzip，安全响应头 | 优先复用现有 Web 面板 + 后端；或原生 SwiftUI 家长 App | 可「添加到主屏幕」；无令牌不可读 |
| P10 | 事件推送 | `Send-BarkAlert*`（Bark） | 继续用 Bark，或 APNs；至少覆盖：新申请、放行到期、守护失联、策略未生效 | 4 类事件均能收到 |
| P11 | 自愈 / 心跳 / 开机自启 | 4 个 SYSTEM 计划任务：Boot、Watchdog（每分钟）、Panel、Health；`heartbeat.json` | iPad 无法常驻后台：用 `BGTaskScheduler` + `DeviceActivityMonitor` + 服务端心跳与告警；macOS 用 launchd | 被终止后 ≤3 分钟恢复（iPad 上为「服务端告警 + 下次打开即恢复」） |
| P12 | 防卸载 / 防篡改 | 家长密码 + 目录 ACL + SYSTEM 任务 + 无密码不可卸载 | 必须依赖 MDM 监督设备，或 Screen Time 密码；未监督设备只能做到「App 内自保护」 | 未监督设备必须在 UI 明示「不保证防删除」 |
| P13 | 审计日志 | `logs/guard.log`、`logs/remote-audit.log` | 后端审计表 + 本地统一日志；记录谁、何时、对什么、放行多久、结果 | 放行/锁定/审批/改名单全可追溯 |
| P14 | 安装 / 卸载 / 备份恢复 | `_admin_install.ps1`、`_admin_uninstall.ps1`、`backup/` | 安装引导 + 一键解除并恢复原设置；保留配置导出 | 卸载后不残留拦截 |
| P15 | 弱口令检测 + 防爆破 | PBKDF2-SHA256 2 万次；连续 5 次错误锁 IP 10 分钟 | 同策略：PBKDF2/Argon2 + 设备/IP 限流 + 告警 | 5 次错误后锁定；默认口令触发警告 |

### 状态与数据模型

`config.json`（见 `config.example.json`）：

- `locked`：总开关，`true` 表示限制生效。
- `unlockUntilUptimeMs`：放行截止点，以**开机后毫秒数**计（防改系统时间）；`null` 表示无放行。
- `mode`：`blocklist`（默认）或 `strict`（`*` 全拦 + 白名单）。
- `blockBrowsers` / `blockApps` / `blockHosts`：三类手段的开关。
- `disableDoH` / `blockIncognito`：禁 DNS-over-HTTPS、禁无痕。
- `appBlockList`：进程名列表（Windows）；iPad 端改为 Screen Time 的 `ApplicationToken` / 分类 token，**不能按名字运行时枚举**，必须由家长在 `FamilyActivityPicker` 中勾选。
- `domainBlockList` / `domainAllowList`：域名黑白名单，白名单优先级更高。
- `remoteEnabled` / `remotePort` / `remoteToken` / `barkKey`：远程面板与推送。

申请文件：`requests/req_YYYYMMDD_HHmmss_fff_<guid8>.json`

```json
{
  "time": "2026-11-08 20:30:00",
  "kind": "website",
  "target": "www.baicizhan.com",
  "exe": "",
  "minutes": 15,
  "reason": "英语网课需要查词"
}
```

### 远程面板 API（必须保持一致，便于手机端与后端复用）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/` | 单页 PWA（登录 + 状态 + 申请 + 日志） |
| GET | `/api/ping` | 免鉴权存活探测 |
| GET | `/api/status` | 状态快照：`installed/state/remainingMinutes/pendingRequests/applied/watchdogOnline/heartbeatAgeSeconds/weakPassword/adminAccounts/host/tunnelOnline` |
| GET | `/api/requests` | 待审批列表：`id/time/kind/target/minutes/reason` |
| GET | `/api/log?lines=N` | 最近日志，N 限制 5–200 |
| POST | `/api/unlock` | `{minutes}`，1–240 |
| POST | `/api/lock` | 立即恢复 |
| POST | `/api/requests/approve` | `{id}`，按申请时长放行 |
| POST | `/api/requests/deny` | `{id}`，删除申请 |

鉴权：请求头 `X-PG-Token`；公网回源取 `CF-Connecting-IP` 作为限流键；错误 5 次锁 10 分钟。

---

## 三、iPad 版的硬约束（必须先让 AI 明确，不能照搬）

iPadOS 沙盒不允许第三方 App 结束别的 App、改系统 hosts、写注册表。**「Windows 原样搬过去」不成立**，只有三条可行路线：

- **路线 A（推荐，功能最接近）Screen Time 家长控制 App**
  - 技术栈：SwiftUI + `FamilyControls` + `DeviceActivity` + `ManagedSettings` + 自定义 `ShieldConfiguration` + 后端 + APNs。
  - 需要 Apple Developer Program，并向 Apple 申请 `com.apple.developer.family-controls` 能力（需审核，个人账号也可申请但通过率有限）。
  - 孩子使用**儿童 Apple ID**并加入「家人共享」；家长在自己的设备上完成授权。
  - 能实现：应用/分类/网站 Shield、定时、放行、自定义拦截页、申请按钮、使用报告。
  - 不能实现：静默杀进程、防卸载（除非 MDM）、后台常驻守护。
- **路线 B（最接近「卸不掉、改不掉」）MDM 监督**
  - 用 Apple Configurator（Mac）或 Apple School/Business Manager 监督 iPad，再接入 Jamf / Intune 等 MDM。
  - 能实现：应用白名单、禁止安装/删除 App、强制 Web 内容过滤、强制 DNS/Always-On VPN、配置描述文件不可移除。
  - 自研 App 只做「申请 + 审批 + 报告」前端，拦截交给系统策略。
- **路线 C（最快落地，仅网站层）DNS / Web 过滤**
  - NextDNS、AdGuard DNS 等加密 DNS 描述文件 + Screen Time 内置限制。
  - 只能拦网站，拦不了 App 内自有内容；监督设备上描述文件才不可移除。

MacBook 的角色：作为开发机与家长控制台（macOS SwiftUI 菜单栏 App 或直接复用 Web 面板）。**不要承诺在 macOS 上复刻进程拦截**：需要 EndpointSecurity 授权，苹果审核严格，属可选增强。

---

## 四、给 Mac 上 AI 的实施顺序

1. **先读包，不写码**：输出「P01–P15 对齐表 + 平台不可实现项 + 需要用户拍板的 3 个问题（路线 A/B/C、是否有 Apple 开发者账号与 Family Controls 权限、孩子 iPad 是否可监督）」。
2. **P0 骨架**：数据模型、状态机、审计、配置导入（直接吃 `config.example.json`）。
3. **P1 本地限制**：Shield + 白名单/黑名单 + 限时放行 + 到期恢复；先用 `FamilyActivityPicker` 完成应用选择。
4. **P2 申请闭环**：自定义盾牌页 → 本地队列 → 后端 → 家长审批 → 下发放行。
5. **P3 家长端**：复用现有 Web 面板与 API 契约；补 APNs/Bark 推送。
6. **P4 加固**：令牌鉴权、限流、审计、卸载/恢复、弱口令告警；按路线 B 补 MDM 约束。
7. **P5 验收**：逐条跑下方测试矩阵，输出「已实现/降级/不可实现」报告。

### 验收测试矩阵（iPad 端）

| 编号 | 步骤 | 期望 |
|---|---|---|
| T01 | 锁定状态下点开被拦 App | 出现中文盾牌页，含「申请使用」 |
| T02 | 提交申请（15 分钟 + 理由） | 家长端出现待审批，含理由与目标 |
| T03 | 家长批准 | ≤10 秒解除限制，倒计时正确 |
| T04 | 等待放行到期 | 自动恢复拦截，无需打开 App |
| T05 | 放行期间改系统时间 +2 小时 | 剩余时间不增加 |
| T06 | 家长点「立即恢复」 | ≤5 秒重新拦截 |
| T07 | 访问白名单站点 / 非白名单站点 | 前者放行，后者拦截 |
| T08 | 用 Safari 与 App 内置浏览器分别访问 | 两者都被拦 |
| T09 | 断网提交申请 | 本地保存，恢复网络后自动送达 |
| T10 | 连续 5 次错误令牌 | 第 6 次被锁定 10 分钟并告警 |
| T11 | 删除/重装 App（未监督设备） | 明确提示防护会失效（或按路线 B 被系统阻止） |
| T12 | 杀掉 App 后重开 | 状态与剩余时间一致，限制仍生效 |
| T13 | 审计日志 | 放行/锁定/审批/改名单均有记录 |
| T14 | 卸载流程 | 需家长验证，卸载后系统恢复原状 |

---

## 五、安全与交接注意

- 生产配置里的 `remoteToken` 是明文、`barkKey` 是推送密钥，**均已从本包剔除**；上线前重新生成，不要沿用旧值。
- 密码只存 PBKDF2-SHA256（20000 次迭代 + 随机盐），不存明文；迁移时保留盐与迭代次数即可校验旧密码。
- 公网入口必须有令牌 + 限流 + 审计；不要把面板直接暴露在公网端口。
- 包内源码仅用于行为对照与逻辑复用，Windows 专有部分（注册表、hosts、IFEO、计划任务、WinForms）不能直接在 iPad 上编译。

## 六、包内清单

```
ParentGuard-Handoff/
├─ README.md                 ← 本文件（规格 + 验收）
├─ PROMPT.md                 ← 直接粘贴给 Mac 上 AI 的主提示词
├─ config.example.json       ← 脱敏配置样例
└─ source/
   ├─ GuardCore.ps1          ← 策略引擎/状态机/密码/心跳/审计
   ├─ ParentGuard.ps1        ← 本地家长控制台（WinForms）
   ├─ RemotePanel.ps1        ← 手机网页面板 + API + 防爆破
   ├─ Show-Blocked.ps1       ← 拦截提示 + 申请表单
   ├─ GuardSentinel.ps1      ← 进程哨兵
   ├─ watchdog.ps1           ← 每分钟自愈/心跳/拉起
   ├─ health.ps1             ← 健康检查
   ├─ ServiceHost.ps1        ← 面板守护宿主
   ├─ OpsRunner.ps1          ← 运维任务执行器
   ├─ _admin_install.ps1     ← 安装（任务/ACL/快捷方式）
   └─ _admin_uninstall.ps1   ← 卸载恢复
```
