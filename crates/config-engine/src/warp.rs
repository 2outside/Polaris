//! Cloudflare WARP 节点身份判定（`ui/src/domain/warp.ts` 的 Rust 对应物）。
//!
//! # 为什么这个谓词必须在 Rust 侧有一份
//!
//! 渲染端 `isWarpServer` 原本被标注为「Rust 侧无对应物，漂移后果止于 UI」——**那个前提在
//! `meshUsesSystemInterface` 上不成立**。config-engine 是 `system:true` 的**唯一发射方**，
//! 而落盘的 `servers[]` 有三条**不经渲染端**的入口（导入配置 / 手改 config.json /
//! 从 上游 迁移的配置）。于是：磁盘上一个 `protocol:"wireguard" + reverseMesh:true` 的
//! WARP 节点 ⇒ Rust `mesh_uses_system_interface` 返 true ⇒ endpoint 带 `system:true` ⇒
//! 与主 TUN 抢内核 utun ⇒ `post-start endpoint/wireguard[...]: Connect: resource busy`
//! **FATAL，整个内核起不来**（真机实证记于 `ui/src/domain/warp.ts` 的 `isWarpServer` 文档）。
//! 前端那道否决（`ui/src/domain/endpoint-routes.ts` 的 `meshUsesSystemInterface`）挡不住这三条腿。
//!
//! # 判据与前端逐字同源
//!
//! 三个字段、同样的短路顺序：`protocol == wireguard` → `wireguardSettings.warpDevice` 存在 →
//! `address` 含 [`WARP_ENDPOINT_DOMAIN`]。**兜底那条不可省**：老 WARP 节点（含从 上游 迁来的）
//! 没有 `warpDevice` 自删凭据标记，只认标记会漏判 —— 而漏判的后果正是上面那条 FATAL。
//!
//! 两侧不漂移由 `ui/src/contracts/warp-veto-parity.test.ts` 这道跨语言门守（读两边源码对字段集
//! 与常量字面量，并断言两侧的否决接线仍在）。
//!
//! # 常量归属
//!
//! [`WARP_ENDPOINT_DOMAIN`] 的 Rust 唯一定义在本模块，`polaris-mesh` 从这里再导出
//! （`polaris-mesh` 依赖 `polaris-config-engine`，反向会成环）。[`WARP_MTU`] 同样归生成配置的
//! config-engine 所有，注册服务不再把默认值塞进草稿。**别在 mesh 侧重新写一份字面量**。

#![forbid(unsafe_code)]

use crate::user_config::server_config::{Protocol, ServerConfig};

/// WARP 端点域名锚点：注册响应给出的 endpoint 均属此域（engage / 162.159.x 走 `*.cloudflareclient.com`）。
/// 前端同名常量在 `ui/src/domain/warp.ts`。
pub const WARP_ENDPOINT_DOMAIN: &str = "cloudflareclient.com";

/// WARP 接口的缺省 MTU。显式配置仍优先；普通 WireGuard 使用 sing-box 的 1408 缺省值。
pub const WARP_MTU: u32 = 1280;

/// 判定 WireGuard 节点是否为 Cloudflare WARP。前端 `isWarpServer`（`ui/src/domain/warp.ts`）的逐字对应物。
///
/// **鲁棒**：新节点带自删凭据 `warpDevice`，但旧 / 导入 / 从 上游 迁移的 WARP 节点无此标记
/// → 必须同时按端点域名兜底。
pub fn is_warp_server(server: &ServerConfig) -> bool {
    if server.protocol != Protocol::Wireguard {
        return false;
    }
    if server
        .wireguard_settings
        .as_ref()
        .is_some_and(|w| w.warp_device.is_some())
    {
        return true;
    }
    server.address.to_lowercase().contains(WARP_ENDPOINT_DOMAIN)
}

#[cfg(test)]
mod tests;
