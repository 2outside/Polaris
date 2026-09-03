//! TUN 网络栈解析（上游 `shared/tun-stack.ts` 1:1 移植）。
//!
//! resolveTunStack：用户选择（含 auto）→ 下发给核的具体栈（恒 system|gvisor|mixed）。
//! Polaris 始终显式 pin，绝不吃 sing-box build-tag 默认（会漂）。

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// TUN 栈选项（含 auto 默认档，仅存储/UI 层）。上游 `TunStack`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunStack {
    #[default]
    Auto,
    System,
    Gvisor,
    Mixed,
}

/// 下发给核的具体栈（永不含 auto）。上游 `ConcreteTunStack`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConcreteTunStack {
    System,
    Gvisor,
    Mixed,
}

impl ConcreteTunStack {
    pub fn as_str(self) -> &'static str {
        match self {
            ConcreteTunStack::System => "system",
            ConcreteTunStack::Gvisor => "gvisor",
            ConcreteTunStack::Mixed => "mixed",
        }
    }
}

/// 平台默认栈映射：mac·win→gvisor / linux→system / 未知→system。
///
/// # 为什么 Windows 从 system 改到 gvisor（2026-08-05，实测驱动）
///
/// 上游原值是 system，那是**没有测量数据的沿袭**。vault `design/networking/` 下的 win-tun MTU
/// 基准记录 §0.6 在同机同节点下把栈 × MTU 交叉测了一遍：
///
/// | 组合 | TCP 吞吐 |
/// |---|---|
/// | system / 65535 | **11 Mbps**（链路层塌陷，CPU 几乎没在干活） |
/// | mixed / 65535 | 11 Mbps（mixed 的 TCP 那半就是 system） |
/// | gvisor / 65535 | **919 Mbps** ≈ 无 TUN userspace 天花板（990）的 93% |
///
/// 且 gvisor 单栈 MTU 扫描 1350→65535 单调上升（465 → 916）。**Windows 上 gvisor 不是「更慢的
/// 用户态栈」，它是唯一能吃下大 MTU 的栈** —— 而大 MTU 正是 wintun 逐包 ring（无批量、无 GSO）
/// 下的主要收益来源。
///
/// Linux 保持 system：§0.65 / §0.655 两轮实测**栈之间无可测差异**（system/4064=475 vs
/// gvisor/4064=467 vs mixed/4064=467），没有换默认的依据；而 system 是内核栈、开销更低。
/// 「无差异」不等于「等价」——那两轮都在 ≤~490 Mbps 处撞到别的瓶颈，此处只是**没有理由改**。
pub fn platform_default_stack(platform: &str) -> ConcreteTunStack {
    match platform {
        "darwin" | "win32" => ConcreteTunStack::Gvisor,
        "linux" => ConcreteTunStack::System,
        _ => ConcreteTunStack::System,
    }
}

/// 未显式设置 MTU 时的默认值，按**最终栈 × 平台**取。
///
/// # 判据来源（全部实测，非推理）
///
/// 见 vault `design/networking/` 下的 win-tun MTU 基准记录：
///
/// - **gvisor + Windows → 65535**：§0.6 实测 919 Mbps，是全矩阵最高格；gvisor 下 MTU 越大越快，
///   65535 就是 sing-box 桌面上游默认值本身。
/// - **gvisor + macOS/Linux → 9000**：这两个平台的吞吐实验**都没跑出区分力**（Linux 撞 1GbE 线速、
///   macOS 撞 Wi-Fi 噪声与 CPU 争抢），故**不照搬 Windows 的 65535** —— 没有数据支持的极端值不该
///   当默认。9000 是 sing-box 自己的 Android 默认，也是 jumbo frame 的常规上限，是这条区间里
///   证据最强的一档（Linux §0.655 实测 4064/9000/65535 三档并列 443–491，即 ≥4064 后再抬无收益）。
/// - **system / mixed（三平台）→ 4064**：Apple Network Extension 的上限（超过则上游注释称性能显著
///   下降），也是 Karing 全平台默认。**下界由一条正确性事实钉死**：`system` 栈 + MTU 1350 会丢
///   1400B 的 UDP 数据报（Windows / Linux / macOS **三平台各自复现 0/5**，而同 MTU 下 gvisor 均通过
///   —— gvisor 的 UDP 路径处理 IP 分片、system 的不处理）。**上界**由 §0.5/§0.6 钉死：system/mixed
///   在 65535 下塌到 11 Mbps。4064 同时避开两头。
///
/// 三条都不是「上游默认」的照抄：上游 65535 与其默认栈（带 gvisor 的 mixed）是一套，单取一半就是
/// 两头都不在设计点上 —— 上游 此前取 system 却沿用 1350，正是那个形态。
pub fn default_mtu_for(stack: ConcreteTunStack, platform: &str) -> u32 {
    match stack {
        ConcreteTunStack::Gvisor if platform == "win32" => 65535,
        ConcreteTunStack::Gvisor => 9000,
        ConcreteTunStack::System | ConcreteTunStack::Mixed => 4064,
    }
}

/// 解析用户 TUN stack → 具体栈。上游 `resolveTunStack`。
/// auto/缺省 → 平台默认；显式 system/gvisor/mixed → 原样（全平台 honor，零强制回退）。
pub fn resolve_tun_stack(user_stack: Option<TunStack>, platform: &str) -> ConcreteTunStack {
    match user_stack {
        None | Some(TunStack::Auto) => platform_default_stack(platform),
        Some(TunStack::System) => ConcreteTunStack::System,
        Some(TunStack::Gvisor) => ConcreteTunStack::Gvisor,
        Some(TunStack::Mixed) => ConcreteTunStack::Mixed,
    }
}

#[cfg(test)]
mod tests;
