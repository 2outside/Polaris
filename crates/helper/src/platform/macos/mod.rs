//! macOS 特权 helper（§D.1 day-1 Rust，移植自 上游 `helper/helper.go`）。
//!
//! ## 职责（system-design §D.3 mac 行）
//!
//! root LaunchDaemon（plist + `launchctl bootstrap`）+ 0666 unix socket + **token 行协议**
//! （token 即全部边界，`helper.go:87-90` 威胁模型）+ `route -ifscope` 白名单接口面 + DNS flush
//! （dscacheutil+killall）+ install-core（mac 专属内核持久化）+ BTM 三级探测（13/14/15 分叉）。
//!
//! ## 共用层（不在本模块 —— 见 crate 顶层）
//!
//! - token 行鉴权：[`crate::token`]（与 win 逐字同 → 单一真值。原 `helper-mac/src/token.rs` 是
//!   thin re-export 壳，单 crate 后转发无意义，已删；调用点直接用 [`crate::token::check_token`]）。
//! - install-core 核心：[`crate::core_install`]（与 linux 逐字同）。本模块只留 [`install_core::to_response`]
//!   （wire 适配）+ handler 里的 xattr/codesign hook（真 mac 差异）。
//! - 行协议读写：[`crate::line_io`]（与 linux 共用；win 是裸 HANDLE 整帧读，真差异）。
//!
//! ## 本模块布局（真 mac 差异）
//!
//! 纯逻辑（跨平台可测，无 mac syscall）：
//! - [`whitelist`]：cfg 路径 + iface 白名单。
//! - [`exec`]：[`exec::CommandRunner`] trait + 生产 [`exec::SystemRunner`]（带超时）。
//! - [`route`]：route-add/del/default-restore argv 构造。
//! - [`flush_dns`]：DNS 刷新两步逻辑。
//! - [`install_core`]：公共核心的 mac wire 适配。
//! - [`freeport`]：端口 LISTEN 持有者定位（mac 机制：`lsof` + `ps` + kill 子进程 —— 真差异）。
//! - [`btm`]：BTM 三级探测评估（13/14/15）。
//! - [`proc_start`]：进程启动时间格式化 + 存活分类（sysctl 部分见下方 mac-gated）。
//! - [`handler`]：[`handler::dispatch`] 协议分派（核心）。
//! - [`server`]：[`server::decode_request`] 帧解码 + [`server::process_connection`] 连接处理。
//!
//! mac-gated（`#[cfg(target_os = "macos")]`，非 mac 编译跳过 —— `nix` 依赖只在此层出现）：
//! - [`proc_start`] 的 sysctl/kill(0) 真调用。
//! - [`launchd`]：plist 生成（跨平台）+ install/uninstall（mac syscall）。
//! - [`server`] 的 unix socket serve。
//!
//! ## 移植纪律
//!
//! 1. **Go 源仅 oracle**：逐行对照 `helper/helper.go` + `proc_starttime_darwin.go`，Rust 重写。
//! 2. **复用 helper-proto**：[`Request`](polaris_helper_proto::Request)/[`Response`](polaris_helper_proto::Response)/
//!    [`codec`](polaris_helper_proto::codec) 全 import。
//! 3. **`deny(unsafe_code)`**（C6-0 前曾是 `forbid`，已降为 `deny` 与 win 一致）：纯逻辑 + nix safe wrapper
//!    的 syscall（如 [`daemon`] 收割器的 `SigSet::wait`）零 unsafe；C6-1 的 `sysctl` procStartTime 需 FFI 时，
//!    在 [`proc_start`] 用模块级 `#![allow(unsafe_code)]` + `// SAFETY:`（`deny` 可覆盖，`forbid` 不能 —— 见 crate 文档）。
//! 4. **不触碰宿主**：系统操作 trait 抽象（[`exec::CommandRunner`]/[`handler::MacServices`]），测试 mock。
//!
//! 地雷（B3 真机复验）：BTM 三级探测（13/14/15 分叉）、默认路由 EEXIST 兜底、kinfo_proc 布局偏移。

#![deny(unsafe_code)]

pub mod btm;
pub mod daemon;
pub mod exec;
pub mod flush_dns;
pub mod freeport;
pub mod handler;
pub mod install_core;
pub mod proc_start;
pub mod route;
pub mod server;
pub mod whitelist;

// launchd 模块：plist 生成跨平台（供测试），install/uninstall mac-gated。
// 整个模块的 mac syscall 部分（install_launchdaemon/uninstall_launchdaemon）已内部 cfg gate，
// 但 plist 生成函数跨平台 —— 故模块本身不整体 gate。
pub mod launchd;

// 便利重导出：让 `platform::macos::MacConfig` 等无需钻模块路径。
pub use handler::{dispatch, MacConfig, MacServices};
pub use server::{decode_request, process_connection, ConnOutcome};

// daemon 入口（binary main 经 cfg 调）：serve 入口即 [`daemon::daemon_main`]（内部调 server::serve）。
pub use daemon::daemon_main;

/// macOS helper protoVersion（三平台统一演进，见 `polaris_helper_proto` crate 文档；不移植上游
/// mac=9 的历史谱系）。
pub const PROTO_VERSION: u32 = polaris_helper_proto::proto_version::CURRENT;

#[cfg(test)]
mod tests;
