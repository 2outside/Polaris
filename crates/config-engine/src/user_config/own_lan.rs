//! 本机接口 CIDR 枚举的**纯逻辑部分**（netmask→prefix / 格式化 / dedupe / 滤回环）。
//!
//! 上游 `getOwnLanCidrs`（`singbox-inbounds-builder.ts:57-69`）的确定性子集：源在 Node 侧靠
//! `os.networkInterfaces()` 的 `.cidr`（已是 `192.168.10.5/24` 形态）直接取，故 TS 侧无 netmask→prefix
//! 转换。Rust 侧 runtime 用 `getifaddrs` 拿到的是 **addr + netmask 分离**，故把「netmask 位数 → prefix、
//! 组 CIDR 串（含主机位）、去重、滤回环」这段无 I/O 逻辑抽到本模块做**确定性单测**（真实接口枚举是
//! 只读系统调用、非破坏性，但结果随宿主网络变化不可对拍，故枚举 I/O 留 runtime、判定逻辑留纯函数）。
//!
//! **刻意保留主机位**（与 `os.networkInterfaces().cidr` 同）：`192.168.10.5/24` 而非掩到 `192.168.10.0/24`
//! ——下游 overlap 判定（`cidr::parse_ipv4_cidr`）会自行掩到网络地址，此处保留主机位与 Polaris 逐字节一致。

#![forbid(unsafe_code)]

use crate::user_config::collections::dedupe;

/// IPv4 netmask（u32，大端主机序）→ 前缀长度。
///
/// 要求掩码为**连续高位 1**（合法子网掩码）；非连续（如 `255.0.255.0`）→ `None`（best-effort 丢弃，
/// 与 上游「取不到就跳过、宁漏排不误破」同侧）。`0` → 0，`0xFFFFFFFF` → 32。
#[must_use]
pub fn prefix_from_netmask_v4(mask: u32) -> Option<u8> {
    let prefix = mask.leading_ones();
    // 连续性校验：前 `prefix` 位全 1、其余全 0 才是合法掩码。
    let expected = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (mask == expected).then_some(prefix as u8)
}

/// IPv6 netmask（u128）→ 前缀长度。同 v4 的连续性校验。
#[must_use]
pub fn prefix_from_netmask_v6(mask: u128) -> Option<u8> {
    let prefix = mask.leading_ones();
    let expected = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (mask == expected).then_some(prefix as u8)
}

/// 组一条 own-lan CIDR（`addr/prefix`，**含主机位**）。回环接口 / 空地址 / `prefix == 0` → `None`。
///
/// = 上游 `getOwnLanCidrs` 的 `if (!a.internal && a.cidr) out.push(a.cidr)`：`is_loopback`（内部/回环）
/// 剔除对齐 `!a.internal`，`addr` 空剔除对齐 `a.cidr` 真值判定。
///
/// **为什么 `prefix == 0` 要拒**：`/0` 不是「本机 LAN 段」，是默认路由。适配器在隧道 / 未配置完成态会给出
/// `prefix = 0`（Windows `OnLinkPrefixLength = 0`；unix 腿 netmask `0.0.0.0` 经
/// [`prefix_from_netmask_v4`] 换算也是 0）。而 own-lan 的消费面是
/// `builder::tun_route_exclude::compute_win_bypass_exclude` 的 **carve guard** —— `/0` 与**一切** mesh 段
/// 相交，会让全部 mesh 段进 `mesh_skipped_own_lan`、一条都不 carve ⇒ bypassLAN 下组网段整体绕 TUN
/// 静默失效（无报错、无日志差异，只是不通）。
///
/// 策略放在这里而不是 [`prefix_from_netmask_v4`]/[`prefix_from_netmask_v6`]：那两个是纯 netmask→prefix
/// **换算**，`0.0.0.0 → 0` 是正确换算，不该在换算处做取舍。本函数是 unix 腿与 windows 腿的**共用汇流点**，
/// 一处拒绝两条腿都挡住。
#[must_use]
pub fn own_lan_cidr(addr: &str, prefix: u8, is_loopback: bool) -> Option<String> {
    if is_loopback || addr.is_empty() || prefix == 0 {
        return None;
    }
    Some(format!("{addr}/{prefix}"))
}

/// 去重保序（= 上游 `dedupe(out)`）。
#[must_use]
pub fn dedupe_own_lan(cidrs: Vec<String>) -> Vec<String> {
    dedupe(cidrs)
}

#[cfg(test)]
mod tests;
