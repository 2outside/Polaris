/// P0-1 **无载荷守卫**：`event:configChanged` 是纯信号 —— 发射点不带配置内容，四个消费方一个都不读。
///
/// # 为什么只能是结构守卫
///
/// 发射点要 `AppHandle`（本仓未引 `tauri::test`），四个消费方里三个在渲染端 —— 没有任何一条行为
/// 断言能同时站在两侧。而这条不变式破掉时的症状是**纯性能回退**：`cfg` 在 emit 之后仍被使用
/// （logLevel / uiTheme / move 进 `switch_mode_with`）⇒ 载荷里写 `cfg` 只能借用 ⇒ `json!` 展开成
/// `to_value(&cfg)`，在既有 clone 之外再深拷一整棵配置树，外加整份 JSON 序列化、按 webview 拼注入
/// 脚本、`NSString` 构造各一份。行为面**完全看不出来**，只能锁结构。
///
/// # 射程为什么是五个点（发射点 + 四个消费方），缺一不可
///
/// 少了发射点 = 载荷可以悄悄加回来；少了任一消费方 = 有人开始读 `{}` 里不存在的字段，拿到
/// `undefined` 后走出一条静默错路。`newValue` 恰恰是「看着能用、其实不能用」的那类字段：它经
/// `strip_privacy_secrets` 脱敏、也没走 `config_get` 那侧的 bypassLANList 补齐（见 `use-config.ts`）。
mod config_changed_payload_tests;

mod privacy_tests;

// ── 后端权威字段闭环（用户报「托盘最近节点只剩 1 条」的回归门）────────────────────
//
// 全部经**生产路径** `config_save_core` 驱动（而非测试自己调 `enforce_backend_authoritative_fields`
// 再 `save_full`）—— 后者会让「删掉生产代码里的 enforce 调用后测试照样绿」成为可能 = 假绿，
// 同 `config_save_core` 文档里记的那条纪律。
mod backend_authoritative_tests;

// ── 真实 ConfigStore 驱动的隐私密码闭环（HIGH 安全回归）──────────────────────────
//
// 核心不变式：hash 存进 `privacyPasswordHash` → 经 store 的 sanitize/migrate/validate/save + 重 load
// 后**存活**（migrate 只清 legacy 明文 `privacyPassword`，不碰 hash 键）。若回归到把 hash 存进
// `privacyPassword`，reload 后 hash 被 migrate 抹空 → has=false + 任意密码免验通过，下列测试转红。
mod privacy_store_tests;

// ── A7（R21）换出口 → 解锁缓存失效：谓词 + 决策核心 + 老/新提取链变异门 ─────────────────
mod unlock_invalidate_tests;

// ── 启动期配置维护（clashApiSecret 回填 / F29 无损迁移 / tmp 清扫）变异门 ─────────────
mod startup_maintenance_tests;

// ── LOW-1 回归门：全局订阅 UA 变更必须作废条件 GET 验证器 ────────────────────────────
//
// 全部经**生产路径**驱动（`config_save_core` / `set_value_with_ua_invalidation`），而非测试自己调
// `invalidate_validators_on_global_ua_change` 再 `save_full` —— 后者会让「删掉生产代码里的那行调用
// 测试照样绿」成为可能 = 假绿，同 `config_save_core` 文档里记的那条纪律。
//
// 判据本体的射程/归一语义由 `commands/subscription::ua_tests` 的纯函数用例覆盖；这里只锁
// **两条 config 写腿有没有真接上**。
mod subscription_ua_invalidation_tests;

// ── P5：乐观并发 + 内容版本（spec §2.5 Q8-b / §3.7 / R6）────────────────────────────
mod optimistic_concurrency_tests;

mod config_patch_tests;
