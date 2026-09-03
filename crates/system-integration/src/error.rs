//! 系统接管层错误类型。
//!
//! Polaris 侧系统代理 / DNS 操作以「best-effort + 日志降级」为主（失败兜底回滚、不阻断 TUN 启动），
//! 仅在少数结构性不可降级场景抛错（代理设置失败、不可逆接管等）。本 Error 用于这些显式信号；
//! 一般 marker IO 仍为 best-effort，唯独 macOS 逐服务原生接管要求完整恢复快照先持久化，失败即在
//! 零系统修改状态终止。

#![forbid(unsafe_code)]

use thiserror::Error;

/// Windows 原生系统代理 writer 错误。
///
/// Win32 失败保留数值 code，上层重试分类不得再依赖本地化文案。`Other` 只承载没有
/// Win32 code 的本地校验/运行时错误。
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WindowsProxyWriterError {
    #[error("Windows proxy writer {operation} failed (win32={code}): {message}")]
    Win32 {
        operation: String,
        code: u32,
        message: String,
    },
    #[error("Windows proxy writer error: {0}")]
    Other(String),
}

impl WindowsProxyWriterError {
    pub const ACCESS_DENIED_CODE: u32 = 5;

    #[must_use]
    pub fn win32(operation: impl Into<String>, code: u32, message: impl Into<String>) -> Self {
        Self::Win32 {
            operation: operation.into(),
            code,
            message: message.into(),
        }
    }

    #[must_use]
    pub fn other(message: impl Into<String>) -> Self {
        Self::Other(message.into())
    }

    #[must_use]
    pub fn is_access_denied(&self) -> bool {
        matches!(
            self,
            Self::Win32 {
                code: Self::ACCESS_DENIED_CODE,
                ..
            }
        )
    }
}

/// 系统接管错误。
#[derive(Debug, Clone, Error)]
pub enum SystemIntegrationError {
    /// 系统代理设置/清除失败（对应 Polaris enableProxy/disableProxy 的 throw 分支）。
    #[error("system proxy error: {0}")]
    Proxy(String),

    /// Windows 原生 writer 错误；保留 Win32 code 供重试策略做结构化分类。
    #[error(transparent)]
    WindowsProxyWriter(#[from] WindowsProxyWriterError),

    /// 系统 DNS 接管失败（非 best-effort 降级路径，仅显式调用方预期）。
    #[error("system dns error: {0}")]
    Dns(String),

    /// 路由出口探测失败（`route -n get` / `ip route get` / `Find-NetRoute` 命令失败或输出无法解析）。
    #[error("system route error: {0}")]
    Route(String),

    /// 不支持的平台。
    #[error("unsupported platform: {0}")]
    UnsupportedPlatform(String),
}

impl SystemIntegrationError {
    /// 构造代理错误。
    pub fn proxy(msg: impl Into<String>) -> Self {
        Self::Proxy(msg.into())
    }

    /// 构造 DNS 错误。
    pub fn dns(msg: impl Into<String>) -> Self {
        Self::Dns(msg.into())
    }

    /// 构造路由错误。
    pub fn route(msg: impl Into<String>) -> Self {
        Self::Route(msg.into())
    }
}
