//! 平台网络事件的解析与归一（macOS/Linux `route -n monitor` 文本、Linux `ip monitor` label、
//! Windows IP Helper row → `RoutePrefix` / `NetworkChangeImpact`），以及运行期绑定计划的数据模型。
//!
//! 从 `src-tauri/src/runtime/` 下沉（E2②）。两条动机：
//!
//! 1. `src-tauri` 因 objc2 / tauri 的 C 依赖**永远**进不了
//!    `cargo check --target x86_64-apple-darwin`（objc2-exception-helper 的 build script 要 Apple clang）。
//!    这部分是纯 Rust 文本解析，下沉后就落进跨目标检查的射程。
//! 2. 跨 crate 的 `pub` 项不触发 `dead_code` ⇒ 删掉一批只为压 warning 的
//!    `#[cfg(any(target_os = "macos", target_os = "linux", test))]`。那些 cfg 描述的不是平台语义，
//!    是「Windows 构建里没人调用它」这个编译期事实 —— 判据与它要表达的东西对不上。
//!
//! # 边界
//!
//! 只装**数据模型与纯解析**。真正去问操作系统的那些（`plan_runtime_bindings` 的 tokio 并发探测、
//! `query_route_interface` 的 wintun / `ip route` 调用）留在 `src-tauri`，它们吃 tokio 与平台 helper。
#![forbid(unsafe_code)]

pub mod binding_plan;
pub mod network_change;
pub mod route_prefix;

pub use binding_plan::RuntimeBindingPlan;
pub use network_change::{
    debounced_network_change, monitor_line_impact, route_replan_needed, MacRouteMonitorParser,
    NetworkChangeImpact, NetworkMonitorUpdate,
};
pub use route_prefix::RoutePrefix;
