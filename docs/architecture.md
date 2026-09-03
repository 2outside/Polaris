# Polaris 当前架构与责任边界

本文描述当前代码的实际组成，不是理想化蓝图。判断架构是否闭环时，必须同时核对生产调用路径、
跨进程契约、运行态事务和可重现的验收证据。单有类型、函数或 UI 入口不等于功能已经接线。

## 系统分层

```text
React 页面 / 对话框 / 托盘浮层
        │  Zustand 暂存态与展示投影
        ▼
ui/src/ipc + contracts + domain
        │  稳定 command/event/error-code 契约
        ▼
Tauri command adapter
        │  参数校验、权限边界、事件转发
        ▼
AppRuntime / ProxyRuntime 编排层
        │  generation、事务、取消、超时、运行核快照
        ▼
domain crates / 三平台 helper / sing-box sidecar
```

| 层 | 责任 | 不应承担的事 |
|---|---|---|
| `ui/src/components` | 交互与可见状态 | 配置生成、路由真值、后端错误文本解析 |
| `ui/src/store` | 磁盘快照、暂存意图、运行快照的前端投影 | 跨窗口的权威运行态 |
| `ui/src/domain` | 纯展示派生与稳定码映射 | OS 调用或网络 side effect |
| `src-tauri/src/commands` | IPC adapter；校验后委托 owner | 重复实现 runtime/domain 逻辑 |
| `src-tauri/src/runtime` | 跨 crate 编排、长期任务、运行核事务 | 协议字段的第二份真值 |
| `crates/config-engine` | `UserConfig` 转 sing-box 配置的唯一生成器 | UI 状态 |
| `crates/system-integration` | 系统代理、DNS、路由和网卡的平台语义 | App 生命周期决策 |
| `crates/helper*` | 最小特权协议与三平台 daemon | 不受限的任意命令执行 |
| `crates/core-supervisor` | 进程、世代、就绪与崩溃恢复原语 | UI 提示策略 |

## 配置事务

Polaris 存在三个不可混同的真值：

1. **staged**：用户尚未保存的编辑意图，只在 renderer 内存中。
2. **committed**：已原子写入磁盘的 `UserConfig`，是下次起核的输入。
3. **running snapshot**：当前 sing-box 真正吃到的配置与节点集。

```text
编辑 ──► staged ──保存──► committed ──应用/重启──► running snapshot
                    │                         │
                    └─重置可撤销              └─待应用差集可见
```

删除节点、订阅刷新淘汰节点和资源删除都不能在编辑瞬间破坏运行核。只有应用事务才提交不可逆的运行态
变化。selector 热切只适用于新旧运行配置都存在且不需重建 outbound 的情形；其余变化走受控重启。

## 代理运行时

`ProxyRuntime` 保留为跨领域事务 façade。它负责起停、换核、受控重启、配置世代、真实
selector 切换事务和运行快照提交。以下独立 owner 已从根文件中分离：

- `runtime/proxy/system_takeover.rs`：系统代理接管、恢复快照、marker 和残留检测。
- `runtime/proxy/dns_race.rs`：仅节点拨号 DNS race sidecar、DoH 上游与 watchdog；普通 DNS 规则不经该 sidecar。
- `runtime/proxy/selector_reconcile.rs`：latest-wins 意图、单飞 reconcile、脏位与退避唤醒。
- `runtime/proxy/network_settle.rs`：起核、TUN flush 与恢复探测之间的 RAII 计数门。
- `runtime/route_binding.rs`：按真正承流 endpoint/detour 根规划绑定网卡，不遍历并阻断空闲节点。

DNS sidecar 锁序固定为 `sidecar → state`，世代判断与复合提交在同一临界区内。selector 不拥有
`switch_serial`；它只生成意图，真实 config CAS、gRPC I/O、lifecycle 复核和运行快照提交仍在 façade
的一条事务内。

## DNS 与网卡路由

DNS 服务器、DNS 服务器组、DNS 规则和默认解析行为是一等配置，不是流量路由规则的附属字段。
普通查询交给 sing-box 原生 DNS 规则与服务器组；当前自定义 sidecar 只承担尚无原生等价接线的节点
域名拨号竞速。

网卡决策顺序为：节点显式绑定 → 订阅策略 → 全局默认 → TUN 会话期特殊逐目的路由 → 内核自动探测。
TUN 起核前会同时读取节点目的出口与默认出口：两者相同就不写 `bind_interface`，由 sing-box 原生
`auto_detect_interface` 跟随 Wi-Fi/有线默认路由；只有两者不同时才生成会话级绑定。显式绑定失效时
fail-closed，不静默换网卡；陈旧会话推断不写回用户配置，可在本轮安全降级到内核自动探测。
System Proxy/Manual 在无显式绑定时不下发全局 `auto_detect_interface`，由 OS 每次按目标地址选路。

网络 watcher 只消费外部网络事实：Windows 原生回调按本次 TUN 的接口索引过滤 Polaris 自己批量安装/
删除的路由，Linux 按固定 TUN 接口 token 过滤，避免“自身路由变化 → 重启 → 再次安装路由”的反馈环。
普通默认出口变化由 sing-box 原生监控关闭旧连接、让新连接跟随新接口，不重启进程；特殊逐目的路由、
未解析候选或显式接口恢复才进入 Polaris 的去抖受控重启。

## 长期任务与有界状态

- Taildrop：最多 4 个并发任务、每任务 128 个文件、32 份任务快照；任务有 ID、取消信号和代次事件，窗口
  重开从 runtime 快照恢复，不把对话框存活期当成任务存活期。
- 订阅/资源/内核调度器：单飞、挂起补更、退避和锁毒恢复；重复 `start` 幂等。
- 解锁检测、节点测速和去抖重启：新一轮会取消旧一轮，不只用令牌忽略旧结果而任由旧任务继续占用资源。
- stats：按 topic 订阅和窗口可见性逐级启停 worker；已结束连接、聚合榜和 relay 通道均有容量上限。

## 特权与错误边界

特权 helper 只接受协议中白名单命令。token 由 OS CSPRNG 生成；含密文件以 0600/平台 ACL 创建。
Linux 特权日志通过已打开的父目录 fd 与 `O_NOFOLLOW` 创建；macOS 从 `/` 逐级 `openat(O_NOFOLLOW)`，
Windows 逐级持有 no-reparse/no-share-delete handle。current 与 `.1` 在起核前同时预开，运行期只在已持有
对象间 copy/truncate；安全打开失败会关闭日志能力并继续排空 pipe，不能退回按路径写。Windows 命名管道
安全描述符创建失败时 fail-closed。

helper v1 的安全承诺明确以“同一登录账户可信”为边界：token 与 `conf_dir` 都属于该账户，该账户能写配置
及其资源引用；路径白名单只约束 helper 自己的 cfg/log 操作数，不沙箱 root/SYSTEM child 对配置内容的消费。
若未来需要抵抗已经取得同账户执行权的恶意进程，必须验证签名 app identity，并由 helper 生成/封存完整
config/resource closure；`canonicalize` 或只暂存主 JSON 都不能建立这条新边界。

跨 IPC 的 `message`/`detail` 是可脱敏日志诊断，不是 UI 文案。用户可见错误只按稳定码映射到 locale；
未知/缺码使用通用本地化失败句或无 reason 终态，不显示路径、PID、命令、OS 原文或内核 stderr。

WebView 生产 CSP 的脚本源仅为 `self`，不允许 inline script 或 `unsafe-eval`；Tauri IPC 与本地图标 scheme
单独列入 connect/img 白名单。原生 host 注入与页面脚本执行是两条边界，不能用放宽页面 CSP 解决原生菜单、
托盘或窗口健康检查。

## 大文件判定准则

文件长度是复审信号，不是拆分目标。只有同时满足以下条件才继续拆：

1. 存在独立状态、资源或不变式的真实 owner；
2. 边界不切断一个事务、锁序或 generation guard；
3. 拆分后不需要反向暴露大量内部状态或制造循环依赖；
4. 行为门能证明等价，而不是只有源码字符门。

`main.rs`、`commands/{misc,rules,updater}.rs`、`NodesScreen` 与 `ProxyRuntime` 中的上述 owner 已按此准则拆分。
`ProxyRuntime` 根文件仍然较长，但剩余主体是真实跨域事务和大量就地并发变异测试；为压缩 LOC 强拆会改变
`switch_serial`、start commit/stop reset 或 helper/marker 等待边界，不属于本轮的安全重构。

设置更新页同样按 owner 拆分：`SettingsUpdate` 只编排卡片与共享设置，`use-app-update` / `AppUpdateCard`
拥有应用更新状态机和呈现，`use-core-update` / `CoreUpdateCard` 拥有内核更新状态机和呈现。下载进度订阅、
安装期包快照和回滚确认仍由各自 hook 持有，不把异步事务重新散回页面组件。
App 更新通道的前端归一化位于 `domain/app-update-channel`，宿主侧候选策略位于
`commands/updater/app_update_policy`；两者只解释持久配置，下载、校验和安装仍由既有 App 更新 owner 单点完成。

`settings-dns-logic.ts` 只持有 DNS spec 解析、IP/端口校验、race 池额度与稳定 ID 对账、FakeIP 风险判定和
默认值归一化；它不依赖 React、IPC、store 或配置写入。`SettingsDns` 保留草稿、effect、i18n 预设、确认弹窗
和一次性 `update` 事务，纯逻辑与页面副作用没有第二份实现。

## 命名与兼容边界

仓库内部路径按模块职责统一：React 业务模块（包括组件族）使用 `PascalCase.tsx`，普通 TypeScript 模块、
hook 与目录使用 `kebab-case`，Rust 文件与内部函数使用 `snake_case`；`main.tsx` 与 `index.tsx` 仅作为工具链
入口和目录聚合入口保留生态固定名。组件测试跟随 `ComponentName[.behavior].test.tsx`，跨模块行为测试使用
`kebab-case.test.ts`。TypeScript 函数与方法使用 `camelCase`、React 组件和类型使用 `PascalCase`、常量使用
`UPPER_SNAKE_CASE`；Rust 的对应命名由编译器 lint 与严格 Clippy 门共同守卫。

大小写与路径一致性由 TypeScript 的 `forceConsistentCasingInFileNames`、`file-naming.test.ts` 和三平台构建共同
守卫；该契约也拒绝新增带下划线的内部 TypeScript 命名函数。命名治理不覆盖外部契约：Tauri command、
事件名、serde/JSON 配置键、helper wire command、C ABI、
BCP-47 locale、NSIS/Tauri 固定资源名均保持其协议或工具规定的拼写；此类名称只能通过兼容迁移单独变更。

## 验证分层

- 纯逻辑与契约：单元测试、golden config、Rust/TypeScript 字段对账、IPC 定义/注册/调用三方对账。
- 目标平台：三平台 `fmt + clippy + build + test` 与打包契约。
- 真实 OS side effect：System/TUN/Manual、helper、DNS/路由、强杀恢复、安装升级卸载和网卡路由切换只能由
  对应平台同一候选 SHA 的真机门证明。

默认 ignored 不是免测：不改宿主网络的项目应改为自动化；需要真实内核、接口或网络的项目必须显式提供
前置条件并实际执行；会改写系统代理、DNS、路由或特权 helper 的项目保留 live gate，并记录基线、回滚和
实际执行证据。
