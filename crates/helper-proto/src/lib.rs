//! polaris-helper-proto — core ↔ helper 共享协议 crate（§D.1 day-1 Rust 收益：消灭跨语言 wire drift）。
//!
//! Polaris 今天 core(TS)↔helper(Go) 的 line-based 文本协议在两侧手工同步（`singbox-api-client.ts:303-306`
//! 甚至用 proto 内容 hash 防上游漂移）。全 Rust 后 core 与 helper 引用本 crate，协议演进编译期强一致。
//!
//! ## 协议形态（Polaris Go 源作移植 oracle，逐序列对照）
//!
//! Polaris helper 用 **line-based 文本协议**（非 protobuf/gRPC）：每行以 `\n` 结尾，Go 源用
//! `bufio.Reader.ReadString('\n')` 读、`fmt.Fprintln(conn, ...)` 写。本 crate 把这套 wire 协议固化为
//! 类型化的 Rust 类型 —— 选 serde 而非 prost/tonic 的理由：
//! 1. **逐字移植 Polaris wire 形态**：Go 源没有 .proto 文件、没有 gRPC，只有 `fmt.Fprintf(conn, "OK ...\n")`。
//!    prost/tonic 会引入一套全新 wire 格式，与已部署 helper（迁移期共存）断协议。
//! 2. **wire drift 收益不依赖 prost**：类型化枚举 + 编译期单一定义点已经消灭 drift（core/helper 引用同一
//!    `Request::Stop` 而非各自手写字符串）。
//! 3. **最小依赖 + 审计友好**：line-based 协议仅靠 std 即可编解码，符合 Polaris helper「仅依赖标准库便于审计」
//!    的设计纪律（`helper.go:18`）。serde 用于把 [`Request`]/[`Response`] 暴露给 core 侧的 IPC 层
//!    （Tauri command 经 serde_json 序列化到 renderer），与 wire 形态解耦。
//!
//! ## protoVersion 三平台统一演进（不移植 上游的三谱系）
//!
//! 上游的 9/5/1 是**三套独立 Go module 各自演进出的历史谱系**（mac 从 v1 加到 v9、win 加到 v5、
//! linux 停在 v1），版本号唯一的作用是让新 client 认出「机器上装着的是哪一代旧 helper」。
//! Polaris 是全新产品 + 全新 Rust helper：**世上不存在旧版 Polaris helper**，没有任何一代需要被认出，
//! 抄那三个数字只会把别人的演进史当成自己的约束。故三平台始终共用同一个
//! [`proto_version::CURRENT`]。
//!
//! 平台差异不再靠版本号表达，而是由 [`Platform`] 承载（mac/win 有 token 行、linux 走 SO_PEERCRED；
//! 命令集差异由 [`command`] 常量 + 各平台 handler 的 `case` 覆盖面表达）——本 crate 是三平台**共用**
//! 的单一 crate，编译期就保证 core 与 helper 引用同一份定义，版本号本就无需分叉。
//!
//! Linux resolved 接管在正式发布前作为 v1 的向后兼容命令扩展加入；旧开发版 helper 收到未知命令时，
//! app 会明确提示升级并把 DNS 接管标为降级，绝不静默假成功。能力判断依赖实际命令结果，不滥用版本号。
//!
//! ## 模块布局
//!
//! - [`proto_version`] / [`Platform`]：协议版本 + 平台标识（B0 建立的骨架，本批保持向后兼容）。
//! - [`command`]：wire 命令名常量（逐字对照 Go `case` 分支）。
//! - [`error`]：错误码 [`ErrorCode`] + [`Error`]（对照 Go 所有 `ERR <code>` 调用点）。
//! - [`response`]：成功响应 [`Response`] / [`ResponseKind`]（对照 Go 所有 `OK ...` 调用点）。
//! - [`request`]：请求 [`Request`] + 参数类型（对照 Go 各 `case` 的 readLine 序列）。
//! - [`codec`]：帧编解码 + 安全白名单（移植自 Go 的 ifaceAllowed/cfgAllowed/ParseCIDR 校验）。

#![forbid(unsafe_code)]

pub mod codec;
pub mod command;
pub mod error;
pub mod request;
pub mod response;

// 顶层便利重导出：让 `polaris_helper_proto::Request` 等无需钻模块路径（core/helper 两侧主用类型）。
pub use error::{Error, ErrorCode};
pub use request::{
    parse_stop_pid, stop_pid_matches, InstallCoreParams, LinuxDnsSetParams, LinuxStartParams,
    Request, RouteParams, StartParams,
};
pub use response::{
    FlushDns, FreePort, LinuxDns, Pong, Response, ResponseKind, Start, StartTiming, Status, Stop,
};

/// Linux resolved 接管跨 crate 契约。
///
/// 接口名同时被 config-engine 写进 sing-box TUN 配置、app 发给 helper、helper 做 root 白名单校验；
/// DNS IP 同时被系统接管与 route `hijack-dns` 消费。放在 helper-proto 是为了让三方编译期共用，避免
/// 任何一侧改名后静默把系统 DNS 指向不存在的接口或真实公共 DNS。
pub mod linux_dns {
    /// Polaris 在 Linux 上创建的固定 TUN 接口名（Linux IFNAMSIZ=16，含结尾 NUL，故最多 15 字节）。
    pub const TUN_INTERFACE_NAME: &str = "polaris-tun0";
    /// systemd-resolved 被指向的受控 DNS 哨兵；其 UDP/TCP 53 会被 TUN 的 `hijack-dns` 捕获。
    pub const CONTROLLED_DNS_IP: &str = "8.8.8.8";
    /// route-only 根域：让 resolved 把所有普通 DNS 查询交给 Polaris TUN 链路。
    pub const ROUTE_ALL_DOMAIN: &str = "~.";

    /// root helper 的最窄白名单判据：只允许操作 Polaris 自己的 TUN 与固定受控哨兵。
    #[must_use]
    pub fn takeover_request_allowed(interface_name: &str, server_ip: &str) -> bool {
        interface_name == TUN_INTERFACE_NAME && server_ip == CONTROLLED_DNS_IP
    }
}

/// 协议版本（**三平台统一**，单一常量）。
pub mod proto_version {
    /// 当前 wire 协议版本，mac/win/linux 共用。
    ///
    /// 唯一定义点：helper 侧的 `ping`/`version` 响应与 client 侧的握手期望都读它 → 结构上不可能分叉。
    /// Linux resolved 命令在首次正式发布前加入，仍属于 v1；只有已发布 wire 出现不兼容变化时才递增。
    pub const CURRENT: u32 = 1;
}

/// 当前安装包内 app/helper 的共同构建身份。
///
/// 发布流水线把同一份 `github.sha` 通过 `POLARIS_BUILD_ID` 注入 helper 与 app 的所有 Cargo
/// 编译步骤；两侧都链接本 crate，因而不会再各自维护版本字符串。开发/源码包未注入时退回 workspace
/// package version，保证本地分别编译 app/helper 仍能互认。
pub mod build_identity {
    /// wire token 的最大长度。Git SHA-1 为 40 字节；留出算法升级和带前缀身份的余量。
    pub const MAX_BYTES: usize = 96;

    const CONFIGURED: &str = match option_env!("POLARIS_BUILD_ID") {
        Some(value) => value,
        None => env!("CARGO_PKG_VERSION"),
    };

    /// 当前构建身份；若构建环境误注入了会破坏行协议的值，安全退回 package version。
    #[must_use]
    pub fn current() -> &'static str {
        if is_wire_safe(CONFIGURED) {
            CONFIGURED
        } else {
            env!("CARGO_PKG_VERSION")
        }
    }

    /// 构建身份必须是单个、可审计的 ASCII token，不能注入空白或换行。
    #[must_use]
    pub fn is_wire_safe(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= MAX_BYTES
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
    }
}

/// 平台标识（helper 协议谱系选择，运行期由编译 target 决定）。
///
/// 单一真值：全 workspace 仅此处定义，其余 crate（system-integration / mesh / config-engine）
/// 一律 `use polaris_helper_proto::Platform`。变体名对齐 helper 协议三谱系（mac/win/linux），
/// 三处历史重定义的别名（Macos/Windows/Darwin/Win32）已统一。
///
/// [`Platform`] 决定帧结构差异（mac/win 有 token 行，linux 经 SO_PEERCRED 无 token 行）——
/// 见 [`codec::encode_frame`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// macOS：root LaunchDaemon + 0666 unix socket + token 行协议。
    Mac,
    /// Windows：SCM 服务 + 命名管道（SDDL）+ token 行协议。
    Win,
    /// Linux：root systemd + 0666 unix socket + SO_PEERCRED（无 token 行）。
    Linux,
    /// 未知平台兜底（freebsd/openbsd/…）。无对应 helper 实现，按 Linux 语义保守处理
    /// （无 token 行、走 Unix 路径），避免对未鉴权对端误发 token 行。
    Other,
}

impl Platform {
    /// 当前平台是否在 wire 头部带 token 行（mac/win = true，linux/other = false）。
    ///
    /// 移植自：linux `helper-linux/main.go` 经 SO_PEERCRED 取对端 uid，`handle()` 首个 `readLine` 读的是
    /// command 而非 token（对照 mac `helper.go:403-404` 的 token+command 两行）。
    ///
    /// [`Platform::Other`] 视同 Linux（无 token 行）：未知平台无对应 helper 实现，保守按 SO_PEERCRED
    /// 类语义处理，避免对未鉴权对端误发 token 行。
    #[must_use]
    pub const fn has_token_line(self) -> bool {
        matches!(self, Self::Mac | Self::Win)
    }

    /// 编译目标平台（下沉自 system-integration/dns_flush.rs 三分 cfg!）。运行期决定本机谱系。
    ///
    /// 未知 target（非 mac/win/linux）→ [`Platform::Other`]。
    #[must_use]
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::Mac
        } else if cfg!(target_os = "windows") {
            Self::Win
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else {
            Self::Other
        }
    }

    /// 平台字符串解析（下沉自 mesh/exit_route.rs，对齐 上游 `process.platform` 口径）。
    ///
    /// 非 std `FromStr`：未知串不报错，返 [`Platform::Other`]。兼容 "darwin"/"macos" 与
    /// "win32"/"windows" 两套写法（各历史调用点传参不一，合并后仍受支持）。
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "darwin" | "macos" => Self::Mac,
            "win32" | "windows" => Self::Win,
            "linux" => Self::Linux,
            _ => Self::Other,
        }
    }
}

#[cfg(test)]
mod tests;
