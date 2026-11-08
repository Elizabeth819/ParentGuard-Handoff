# 主提示词（整段复制给 MacBook 上的 AI）

```text
你是一名资深 Apple 平台工程师。请在这个工作区里，把一套已在 Windows 上跑通的家长防护系统，复刻成 iPad 版本（家长端可运行在 MacBook / iPhone）。工作区里已经有交接包，先完整阅读再动手。

【必读文件】
1. README.md —— 三句话系统描述、P01–P15 行为契约、iPad 平台硬约束、验收矩阵。
2. config.example.json —— 配置数据模型（已脱敏，令牌为空）。
3. source/*.ps1 —— 真实生产源码，仅作为行为与算法参考；Windows 专有机制不能照搬。

【第一步：只分析，不写代码】
输出三份东西：
A. P01–P15 对齐表：每条给「iPad 实现方式 / 是否完全可复刻 / 降级说明 / 验收方法」。
B. 平台不可实现清单：明确列出 iOS 沙盒做不到的事（结束其他 App 进程、改 hosts、注册表、后台常驻、无 MDM 时防卸载），不允许用伪造能力糊弄。
C. 需要我拍板的问题，最多 5 个，必须包含：
   - 选路线 A（Screen Time / FamilyControls + DeviceActivity + ManagedSettings）、路线 B（MDM 监督设备）、还是路线 C（DNS/Web 过滤兜底）？可组合。
   - 我是否有 Apple Developer Program 账号，是否已拿到 com.apple.developer.family-controls 权限？
   - 目标 iPad 是否为可监督设备（Apple Configurator / ABM + MDM）？孩子是否使用儿童 Apple ID 并加入家人共享？
   - 家长端形态：复用现有 Web 面板，还是做原生 SwiftUI App？
   - 是否保留 Bark 推送，还是改用 APNs？

【第二步：先写计划】
等我回答后，给出文件级实施计划（目录结构、模块、后端接口、推送、权限申请清单、需要我手动完成的一次性步骤，例如 Xcode 签名、Apple 后台申请、设备监督）。计划需覆盖：
- 状态机与单调时钟（防改时间）；
- Shield 拦截 + 白名单/黑名单 + 严格模式；
- 限时放行（5/15/30/60/120 分钟与 1–240 分钟接口）与到期自动恢复；
- 自定义 ShieldConfiguration 中文拦截页 + 「申请使用」；
- 申请数据模型（time/kind/target/minutes/reason）与离线队列；
- 家长审批 API（/api/status、/api/requests、/api/log、/api/unlock、/api/lock、/api/requests/approve、/api/requests/deny，X-PG-Token 鉴权）；
- 令牌防爆破（5 次错误锁 10 分钟）、审计日志、弱口令告警；
- 卸载/解除流程与配置导出；
- 本地化中文 UI。

【第三步：分阶段实现并自证】
按 P0 骨架 → P1 本地限制 → P2 申请闭环 → P3 家长端 → P4 加固 → P5 验收 的顺序实现。每个阶段结束：
- 跑可自动化的单元测试/构建；
- 对无法自动验证的项，给出可照着点的真机测试步骤；
- 更新 README 的「实现状态」表，标注 已实现 / 降级 / 不可实现及原因。

【硬性约束】
- 不要声称拿到未获批的 Apple 权限；缺权限时给出可编译运行的降级路径（例如先用 MDM/DNS 路线验证闭环）。
- 不要把密钥、令牌、密码哈希写入仓库；配置读取本地 Keychain 或环境变量。
- 不复刻 Windows 的注册表/hosts/IFEO/计划任务写法；只复刻行为契约。
- 所有面向孩子的文案用中文，语气平和；家长端操作必须二次确认。
- 代码改动要小步可验证，不要一次性生成整套工程后无法编译。

【完成标准】
1. 能编译并在真机/模拟器跑通路线 A（或我选的路线）；
2. P01–P15 每一项有明确状态与证据（测试截图、日志或测试用例）；
3. T01–T14 验收矩阵有执行结果；
4. 输出一份「与 Windows 版的差异说明」，列出降级项和替代方案；
5. 交给我一份「一次性人工步骤清单」（开发者账号、entitlement 申请、设备监督、推送证书等）。

现在请先执行【第一步】，不要写代码。
```

## 配套操作（在 Mac 上）

1. 把整个 `ParentGuard-Handoff` 文件夹拷到 MacBook。
2. 用 Trae / Cursor / Claude Code 打开该文件夹作为工作区。
3. 新建对话，粘贴上面整段提示词。
4. 回答它提出的 5 个问题（尤其是路线与 entitlement）。
5. 计划确认后再让它进入实现；每阶段用 README 的 T01–T14 验收。
