mod reconcile_tests;

/// 订阅预检的**生产组合面门**（§K7.1 血证：mock 绿 ≠ 生产路径跑通）。
///
/// 这里驱动的是**生产唯一路径** [`preview_core`]，注入的 `client` 是**真** [`HttpRuntime`]
/// （真 reqwest），不是 mock HttpClient。三扇门：
/// 1. 真 client 注入 → command 核心真调 fetch → 真 socket 收字节 → 真解析出节点数（正门）；
/// 2. **变异**：把真 client 换成「连不上服务器」的 client（去掉 resolve 钉定）→ 门必须转红；
/// 3. SSRF guard 真的在生产路径上跑（用公网 IP 的 mock lookup 放行，用内网 IP 的 mock lookup 拒绝）。
mod production_gate;

/// C14 · 订阅经代理策略求值（真值表 + 配置键提取）。
///
/// 变异验证：打断 `Some("proxy") => true` / `Some("direct") => false` / follow 的 per-sub 读取任一，
/// 对应断言即转红——证明全局三态策略确实作用于「是否经代理」决策（此前后端零消费）。
mod proxy_policy_tests;

mod ua_tests;

/// 编排层（tauri command / 拉取编排）**接线**变异锁 —— 与「方法体单测」分工不同。
///
/// 本仓未引 `tauri::test`，命令壳带 `State<AppRuntime>` 无法在单测里直调；而本轮 review 明确点出
/// 「测方法体 ≠ 测接线」：净零序短路、UA 三级链、`failed_providers` 传递三处的**纯函数**全都有单测，
/// 但把编排层那一行改回旧行为（恒 save / 只读 per-sub / 丢名单）时，那些单测**一条都不会红**。
///
/// 故这里按本仓既有的源码扫描门（同 `runtime/rule_resource_scheduler.rs` 的
/// `scheduler_actually_wires_the_catalog_refresh_leg`）钉住调用点本身。它薄，但它抓的正是
/// 「纯函数还在、调用点没了」这一类假绿。
mod wiring_gate;

mod create_operation_tests;
/// 订阅更新进度帧的**纯逻辑**门（`EVENT_SUBSCRIPTION_UPDATE_PROGRESS` 的载荷形状）。
///
/// 放在 `mod wiring_gate` **之后**是刻意的：`production_src()` 截断到 `mod wiring_gate {` 为止，
/// 本模块里的 `"phase"` / `"failed"` 等字面量因此不在扫描面内，不会把上面那些源码门喂成假绿。
mod progress_tests;
