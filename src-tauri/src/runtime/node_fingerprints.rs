//! **两条节点指纹判据的单点定义 + 它们之间的包含关系**。
//!
//! # 这里有两个判据，因为这是两个问题
//!
//! | 判据 | 问的是什么 | 公式 | 消费者 |
//! |---|---|---|---|
//! | [`modified_fingerprint`](crate::runtime::node_fingerprints::modified_fingerprint) | **运行核里跑的，还是不是用户当前配置？** | **全维** = `config_generation_norm` 的逐节点投影 | `pending_changes().modified` → pending-bar 「待生效」 |
//! | [`dirty_fingerprint`](crate::runtime::node_fingerprints::dirty_fingerprint) | **池里那个出口，还能不能代表这个节点？** | **5 维** `protocol\|address\|port\|cred\|network` | `partition_dirty` → 测速波前预筛 |
//!
//! 二者**同基准**（起核那一刻的 `SwitchSnapshot`，与 `startup_snapshot` 同刻同源）、**不同投影**。
//! 这不是「两套判据漂移」，是两个问题本来就该有不同的答案：
//!
//! - 只改了 `name` 的节点：生成产物变了（sing-box 的 outbound tag 会变）⇒ 核里跑的确实不是当前配置
//!   ⇒ **该进 `modified`**；但连接参数一个字没变，池里那个出口**完全能代表它**，测出来的延迟是准的
//!   ⇒ **不该判 dirty**。把它判 dirty 拒测，是白白不测一个本可测的节点（误报）。
//! - 改了 `port` 的节点：两条都成立 ⇒ 两个集合都进。
//!
//! # 包含关系：`dirty ⊆ modified`（本模块的核心不变式）
//!
//! **凡被测速判 dirty 的节点，必然在 pending 的 `modified` 集里。** 这是用户实报症状
//! ——「测速说『已编辑未生效，去应用』，而 pending-bar 上根本没有那个节点」——
//! 在**结构上**不可能再发生的保证：被指引去点的那个东西，一定在条上。
//!
//! 为什么成立（逐字段核过，非假设）：5 维读的是 `protocol` / `address` / `port` / `network`
//! 与 `cred`（= `uuid` → `password` → `shadowsocksSettings.password` → `username` →
//! `sshSettings.password` → `wireguardSettings.peerPublicKey` 的首个非空值）。全维投影 =
//! `ServerConfig` 整份序列化**仅剔** `updatedAt` / `createdAt` / `providerName` —— 这 3 个键
//! 与上述任何一个 5 维输入都不重合，且那些字段全部无 `#[serde(skip)]`
//! （`crates/config-engine/src/user_config/server_config.rs` 逐字段核过）。
//! ⇒ 全维投影**逐字保留**了 5 维的全部输入 ⇒ 全维相等 ⇒ 5 维的每个输入都相等 ⇒ 5 维相等。
//! 取逆否即 `5 维不等 ⇒ 全维不等`，也就是 `dirty ⊆ modified`。
//!
//! 反向**不**成立且**刻意不成立**：改 `name` / `tls` / `ws-path` 只进 `modified` 不进 `dirty`，
//! 正是上面那条「不误报、不白白拒测」。由 `tests::containment_holds_across_field_kinds` 实跑钉死。
//!
//! # 单一可替换点
//!
//! 两条判据各只有一个函数体。要换某一条的公式，改对应函数的那一行即可，两个消费面自动跟随 ——
//! 不存在「快照侧改了、当前侧忘了改」的半改状态（那正是收口前的活 bug，见 [`dirty_fingerprint`](crate::runtime::node_fingerprints::dirty_fingerprint) 文档）。

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use polaris_config_engine::user_config::server_config::ServerConfig;
use serde_json::Value;

/// **`pending_changes().modified` 的判据**（单一可替换点）：**全维**逐节点投影。
///
/// = `polaris_config_engine::builder::orchestration::server_fingerprint`，也**正是**
/// `config_generation_norm` 里 `servers` 那一段的元素构造式（`orchestration.rs` 的「servers 投影」腿
/// 逐节点调的就是它）⇒ 「全维逐节点投影」与「重启判据看得见的粒度」逐字节同源，不是近似。
///
/// 语义：任何影响生成产物的差异都算 —— 因为 `modified` 回答的是「核里跑的还是不是用户当前配置」。
#[must_use]
pub fn modified_fingerprint(s: &ServerConfig) -> String {
    polaris_config_engine::builder::orchestration::server_fingerprint(s)
}

/// **测速 `partition_dirty` 的判据**（单一可替换点）：**5 维** `protocol|address|port|cred|network`。
///
/// 与 `commands/speedtest.rs` 里 `current_server_fingerprints` 用的是**同一个函数**
/// （`polaris_net_stack::subscription::server_fingerprint`）—— 这条「同一个函数」是硬要求：
///
/// > 收口前，`partition_dirty` 的「旧」侧取 `SwitchSnapshot::fingerprints`（由 config-engine 的
/// > **全维** `server_fingerprint` 算出，形如 `{"address":"1.2.3.4","id":"a",...}`），而「新」侧
/// > 是 net-stack 的**5 维**串（形如 `vless|1.2.3.4|443|u-1|tcp`）。两种串**永不相等**
/// > ⇒ 凡在起核快照里的节点一律被判 dirty ⇒ **整个测速波前每次都被免测**。
/// > `speedtest.rs` 自己那句注释预言过这个失败模式（「各算各的公式必然漂移，表现是『永远 dirty』
/// > 或『永远不 dirty』，两种都静默」），但没有任何测试跨两个 crate 比对，于是一直没自曝。
///
/// 语义：连接参数是否变了 —— 因为 dirty 回答的是「池里那个出口还能不能代表这个节点」。
/// 改 `name` 不动它，是**对的**：出口没变，测出来的延迟仍然准。
#[must_use]
pub fn dirty_fingerprint(s: &ServerConfig) -> String {
    polaris_net_stack::subscription::server_fingerprint(s)
}

/// 逐节点 `modified` 判据指纹表（typed 入口，起核快照侧用）。键 = 节点 id。
#[must_use]
pub fn modified_table(servers: &[ServerConfig]) -> BTreeMap<String, String> {
    servers
        .iter()
        .map(|s| (s.id.clone(), modified_fingerprint(s)))
        .collect()
}

/// 逐节点 dirty 判据指纹表（typed 入口，起核快照侧用）。键 = 节点 id。
#[must_use]
pub fn dirty_table(servers: &[ServerConfig]) -> BTreeMap<String, String> {
    servers
        .iter()
        .map(|s| (s.id.clone(), dirty_fingerprint(s)))
        .collect()
}

/// 逐节点 `modified` 判据指纹表（JSON 入口，「当前配置」侧用）。
///
/// 解析不出 [`ServerConfig`] 的条目（配置损坏 / 未来字段）→ **直接跳过**：没有指纹 ⇒ 不判 modified，
/// 保守方向正确（少显示不虚报），绝不因为解析失败就把一个正常节点报成「待生效」。
/// 与 `commands/speedtest::current_server_fingerprints` 的同名容错腿同型。
#[must_use]
pub fn modified_table_json(config: &Value) -> BTreeMap<String, String> {
    config
        .get("servers")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|s| {
                    let id = s.get("id").and_then(Value::as_str)?;
                    let parsed: ServerConfig = serde_json::from_value(s.clone()).ok()?;
                    Some((id.to_string(), modified_fingerprint(&parsed)))
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
