//! 运行期绑定计划的**数据模型**。
//!
//! 只有模型和它的纯操作在这里；真正去问操作系统的规划器（tokio 并发探测 + 平台 helper 调用）
//! 留在 `src-tauri` 的 `runtime::route_binding`。

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeBindingPlan {
    /// 物理拨号根 server id → 系统路由选出的接口名。
    pub bindings: BTreeMap<String, String>,
    /// 节点目的与默认出口一致、可直接交给 sing-box `auto_detect_interface` 的根。
    ///
    /// 这类根不能再写 `bind_interface`：写入后会关闭 sing-box 的原生默认接口监控，使普通的
    /// Wi-Fi ↔ 有线切换退化为整核重启。只有逐目的路由与默认出口确实不同的根才进入 `bindings`。
    pub native_roots: BTreeSet<String>,
    /// 本次起核前纳入逐目的规划的 hot-switch automatic roots。查询失败的根仍保留在册；只有运行期
    /// 新增、未进入当前 selector 的根才会落在集合外并要求整核重启。
    pub covered_roots: BTreeSet<String>,
    /// 已解析出的物理拨号目标 IP。运行期路由 watcher 用它把“任意路由表噪音”收窄为“确实覆盖
    /// 当前特殊/未解析根的前缀变化”。
    pub probe_ips: BTreeMap<String, IpAddr>,
    /// 本次规划**没能得出可用绑定决策**的根：server id → 重新规划时该根的路由探测目标
    /// （DNS 名、字面量地址，或接口消失前已解析出的 IP）。
    ///
    /// 取代此前的 `unresolved_count`。计数只回答「有几个我不知道」，而下游要判定的是「这条路由
    /// 前缀跟不知道的那些根有没有关系」、以及将来「对它们重新发起解析」——两件事都需要身份。
    /// 用 `candidate - bindings - native` 反推出的数字，是同一份已经丢掉的信息的第二个症状。
    ///
    /// 三类根都在册：DNS/探针 IP 解析失败、路由查询无结果、以及整轮预算超时被 abort 的根。
    pub unresolved_roots: BTreeMap<String, String>,
    pub candidate_count: usize,
}

impl RuntimeBindingPlan {
    /// 在最终写盘/spawn 前剔除已经不可用的推断绑定。
    ///
    /// 推断绑定是一次会话的性能/正确性增强，不是用户显式策略：接口在规划后消失或 down 时，继续把
    /// 陈旧名字写进 `bind_interface` 会令该节点确定性拨号失败；剔除后由 TUN 的全局
    /// `auto_detect_interface` 接管。显式绑定不进入本 plan，仍由运行时 fail-closed 校验。
    pub fn retain_available(&mut self, interfaces: &BTreeMap<String, bool>) -> usize {
        let before = self.bindings.len();
        let dropped: Vec<String> = self
            .bindings
            .iter()
            .filter(|(_, interface)| interfaces.get(*interface).copied() != Some(true))
            .map(|(server_id, _)| server_id.clone())
            .collect();
        self.bindings
            .retain(|_, interface| interfaces.get(interface).copied() == Some(true));
        // 被剔除的根当场失去决策 → 进未决集合，且带上它已解析出的 IP 作为重新规划的目标。
        // **不裁 `unresolved_roots`**：它记的是「没有可用决策的根是谁」，不含任何接口名，没有会
        // 随接口消失而失效的内容；按接口可用性去裁它只会把保守面悄悄缩小，正是本批要治的方向。
        for server_id in dropped {
            let target = self
                .probe_ips
                .get(&server_id)
                .map_or_else(String::new, ToString::to_string);
            self.unresolved_roots.insert(server_id, target);
        }
        before.saturating_sub(self.bindings.len())
    }
}

#[cfg(test)]
mod tests;
