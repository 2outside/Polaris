use crate::test_support::module_files;

/// **R7**：`proxy` 子模块不得回头 `use super::<私有项>` 把 façade 变成公共工具箱——正确方向是
/// 被调用的域把项升到 `pub(super)`，调用方走 `crate::runtime::proxy::<域>::<项>`
/// （即 `use super::<域>::<项>;`，多段路径，天然放行；本门只抓**单段**叶子导入）。
///
/// 白名单是 façade **定义**的公共契约面：`ProxyRuntime` / `ProxyStatus` / `StartError` / `code`
/// / `ProxyErrorEmitter` 不动（§C 例外①②），`PendingChangesSummary` / `ProxyLifecycleEvent`
/// 搬出后由 façade `pub use` 再导出（§A.3）。除这 7 个之外的任何 `use super::{叶子项};`
/// 都意味着有一个私有工具函数被回头掏走。
///
/// 判据只看 `module_files("runtime/proxy")`（排除 `tests/`，见 `module_files_in` 文档）里
/// **除 façade 根文件外**的每个文件；把每条 `use super::…` **拼到分号为止**（rustfmt 会把长导入
/// 折成多行，逐行解析时整条导入会静默隐形 —— 那是「门在但没牙」，不是取舍），再逐项判定：
/// - `use super::*;` 全量 glob → **判红**：取材面里只有生产文件（`tests/` 已被 `module_files`
///   排除），生产文件把 façade 整个 glob 进来等于绕开本门的逐项白名单；
/// - `use super::<mod>::<item>;` 多段路径（穿过一个子模块）→ 放行（§B.1 #4 的正确方向）；
/// - `use super::{a, b};` / `use super::a;` 单段叶子列表 → 逐项核对白名单，越界即 panic
///   点名文件 + 行号 + 符号。
#[test]
fn proxy_submodules_only_reach_back_for_whitelisted_facade_items() {
    const WHITELIST: &[&str] = &[
        "ProxyRuntime",
        "ProxyStatus",
        "StartError",
        "code",
        "ProxyErrorEmitter",
        "PendingChangesSummary",
        "ProxyLifecycleEvent",
        // **永久面项**（非过渡）：`TUN_ADDRESS_UNAVAILABLE_MSG` 是 §C 例外① 钉死在 façade 的五条
        // `*_MSG` 兜底文案之一（与 `pub mod code` 同锚，四条跨语言门以它们为判据），永不外移；
        // 其消费者 `core_log::settle_start_failure` 只能回掏。删除条件同 `TUN_ROUTE_NOT_CAPTURED_MSG`。
        "TUN_ADDRESS_UNAVAILABLE_MSG",
        // **永久面项**（非过渡，B9 引入）：同上三条 `*_MSG`（§C 例外①），消费者是随 B9 进
        // `startup.rs` 的 `run_helper_gate` / `start_inner` 的 TUN 前置门。
        "HELPER_NOT_INSTALLED_MSG",
        "HELPER_GATE_ABORTED_MSG",
        "TUN_ADAPTER_MISSING_MSG",
        // **永久面项**（非过渡，B9 引入）：`PROBE_POOL_SIZE` 按 §A.3 的 `336-343` 行与
        // `CoreBuildEnv` / `SpeedProbeTargets` 同属 façade 的 speedtest 契约面（`runtime::speedtest`
        // 经 `crate::runtime::proxy::` 取用），不随 `startup` 外移；其起核侧消费者
        // `start_inner` 的探测池端口分配只能回掏。删除条件：§A.3 该行被推翻之日。
        "PROBE_POOL_SIZE",
        // **永久面项**（非过渡）：`TUN_ROUTE_NOT_CAPTURED_MSG` 是 §C 例外① 钉死在 façade 的五条
        // `*_MSG` 兜底文案之一（与 `pub mod code` 同锚，四条跨语言门以它们为判据），永不外移；
        // 其唯一消费者 `route_replan::verify_tun_route_captured` 只能回掏。故本项没有删除条件 ——
        // 只有当 §C 例外① 被推翻（`*_MSG` 允许随域外移）时才随之下线。
        "TUN_ROUTE_NOT_CAPTURED_MSG",
        // 过渡项（B7 引入，2026-08-31 复核仍成立）：`UnlockInvalidationProbe` 是 `#[cfg(test)]`
        // 的类型别名，按 §A.3 的「`2128-2208` 注入桩」行归 `unlock_refresh.rs`——该域文件已建，
        // 但别名**至今仍定义在 façade**（`proxy.rs`，`RecordingErrorEmitter` 句柄同型注释旁）；
        // 其**唯一**消费者 `TestPutSink` 在 `hot_switch.rs`。多段路径今天走不通（目标域里没有
        // 这个名字），搬生产代码又不归本门管，故本项暂留。删除条件：别名定义搬进
        // `unlock_refresh.rs` 之日，hot_switch 改
        // `use super::unlock_refresh::UnlockInvalidationProbe;`（多段路径，天然放行）。
        "UnlockInvalidationProbe",
    ];

    for (file, content) in module_files("runtime/proxy") {
        // façade 根文件本身在 §A.5 判定表里是「定义 + 再导出」的一方，不受本门约束。
        if file == "proxy.rs" {
            continue;
        }
        // 先剥行注释再取材：判据看的是**代码**，注释里出现的 `use super::…` 不是导入。
        let lines: Vec<String> = content
            .lines()
            .map(|l| l.split("//").next().unwrap_or("").trim_end().to_owned())
            .collect();
        let mut cursor = 0usize;
        while cursor < lines.len() {
            let idx = cursor;
            let trimmed = lines[cursor].trim_start();
            cursor += 1;
            let Some(first) = trimmed.strip_prefix("use super::") else {
                continue;
            };
            // 跨行拼接：`use super::{` + 若干行 + `};` 是 rustfmt 对长导入的既定折行形态，
            // 逐行解析会整条跳过。拼到分号为止，再按单行形态解析（fail-closed：拼不到分号即红）。
            let mut stmt = first.to_owned();
            while !stmt.contains(';') {
                assert!(
                    cursor < lines.len(),
                    "{file}:{}：`use super::…` 直到文件尾都没有分号 —— 取材面已经不是 Rust 源码",
                    idx + 1
                );
                stmt.push_str(lines[cursor].trim());
                cursor += 1;
            }
            let rest = stmt.as_str();
            assert!(
                !rest.starts_with('*'),
                "{file}:{}：`use super::*;` 把 façade 整个 glob 进生产文件 —— 逐项白名单就此失效。\
                 正确做法同下：把需要的项升到目标域的 `pub(super)`，调用方走多段路径。",
                idx + 1
            );
            let items_part = rest
                .split_once(';')
                .expect("上面的循环已保证含分号")
                .0
                .trim();
            let leafs = if let Some(inner) = items_part
                .strip_prefix('{')
                .and_then(|s| s.strip_suffix('}'))
            {
                inner
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
            } else {
                vec![items_part]
            };
            for leaf in leafs {
                // `super::<mod>::<item>` —— 穿过一个子模块拿项，是 §B.1 #4 的正确方向，放行。
                if leaf.contains("::") {
                    continue;
                }
                // `as` 重命名只看被导入的原名。
                let symbol = leaf.split_whitespace().next().unwrap_or(leaf);
                assert!(
                    WHITELIST.contains(&symbol),
                    "{file}:{}：`use super::{{{symbol}}}` 越过白名单 {WHITELIST:?}——\
                     `{symbol}` 是某个域的私有工具项，正确做法是把它升到目标域的 `pub(super)`，\
                     调用方改走 `crate::runtime::proxy::<域>::{symbol}`，不是回头掏 façade。",
                    idx + 1
                );
            }
        }
    }
}
