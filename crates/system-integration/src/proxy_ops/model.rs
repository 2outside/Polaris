//! `proxy_ops` 共享数据模型：请求/结果类型 + 平台写入抽象 trait。

pub use crate::error::WindowsProxyWriterError;
use crate::proxy::{SystemProxyStatus, WindowsProxyRegistrySnapshot};

/// 代理设置请求。上游 `enableProxy(address, httpPort, socksPort, bypassList?)`。
#[derive(Debug, Clone)]
pub struct ProxyEnableRequest {
    pub address: String,
    pub http_port: u16,
    pub socks_port: u16,
    pub bypass_list: Vec<String>,
}

/// Windows 原生注册表写入所需的完整值集。格式仍由 system-integration 单点生成，平台 FFI 只负责落盘。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsProxyRegistryValues {
    pub proxy_server: String,
    pub proxy_enable: u32,
    pub proxy_override: String,
}

/// Windows 系统代理注册表窄写入口。生产由 App crate 的 `windows-sys` FFI 实现；测试默认继续走
/// `reg.exe` runner，因此跨平台 argv 门与回退路径都保留。
pub trait WindowsProxyRegistryWriter: Send + Sync {
    /// 精确读取 Polaris 会触碰的三值；生产实现必须区分 absent/empty/value 与 DWORD 原值。
    fn capture(&self) -> Result<WindowsProxyRegistrySnapshot, WindowsProxyWriterError> {
        Err(WindowsProxyWriterError::other(
            "Windows proxy writer does not support exact capture",
        ))
    }

    fn write(&self, values: &WindowsProxyRegistryValues) -> Result<(), WindowsProxyWriterError>;

    /// 精确恢复三值。默认拒绝，避免旧 writer 把 absent/empty 折成有损写入。
    fn restore(
        &self,
        _snapshot: &WindowsProxyRegistrySnapshot,
    ) -> Result<(), WindowsProxyWriterError> {
        Err(WindowsProxyWriterError::other(
            "Windows proxy writer does not support exact restore",
        ))
    }

    /// 通知 Windows 系统代理消费方重新读取 Internet Settings。默认 no-op 让跨平台 mock 与旧库调用方
    /// 保持纯内存；Windows 生产 writer 必须覆盖。
    fn notify_settings_changed(&self) -> Result<(), WindowsProxyWriterError> {
        Ok(())
    }
}

/// macOS 原生代理写事务的外部执行面。App 实现把不透明 payload 发给已安装的 root helper；
/// system-integration 保留状态机、完整快照和 payload 生成的唯一真值。
pub trait MacProxyTransactionWriter: Send + Sync {
    /// 只做本地安装态探测，不连接 helper、更不触发安装/提权。
    ///
    /// System 模式必须把「没有 helper」当成正常部署形态：capability probe 不可用时由
    /// controller 选择 legacy `networksetup`，避免每次接管、恢复和清理都先制造一次必败 IPC。
    /// exact 路径被选中后不得再回落。测试/外部 writer 默认可用，生产 helper 覆盖此方法。
    fn available(&self) -> bool {
        true
    }

    /// compare command capability probe。生产实现必须在任何系统写入前完成；旧 helper 返回 unknown
    /// 时是 `Ok(false)`，连接建立后的 timeout/IO/空响应则是结果不明错误，调用方不得再走 CLI 写腿。
    fn compare_capable(&self) -> Result<bool, MacProxyWriterError> {
        Ok(true)
    }

    fn execute(&self, payload_hex: &str) -> Result<(), MacProxyWriterError>;
}

/// helper 写入失败分类。只有 [`Unavailable`](Self::Unavailable) 保证“事务尚未开始”，因而
/// legacy 路径允许安全回落既有 networksetup；exact 路径已做出选择，仍必须 fail closed。
/// 超时/空响应等结果不明归 [`Failed`](Self::Failed)，始终禁止二次写入。
#[derive(Debug, Clone, thiserror::Error)]
pub enum MacProxyWriterError {
    #[error("macOS 系统代理 helper 不可用：{0}")]
    Unavailable(String),
    #[error("macOS 系统代理 helper 事务失败：{0}")]
    Failed(String),
}

impl ProxyEnableRequest {
    pub fn our_host_port(&self) -> String {
        format!("{}:{}", self.address, self.http_port)
    }
}

/// 活态系统代理判定结果。
///
/// **判据不是「系统代理是否开着」，而是「它是否仍指向本进程的 mixed 入站」** —— 指向别的代理
/// 同样意味着我们的流量没走本地核（用户读到的「已连接」与真相相反）。见 [`points_to_mixed_inbound`]。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemProxyLiveStatus {
    /// 读到的 OS 代理设置原样（诊断/展示用；判定一律看 `points_to_us`）。
    pub status: SystemProxyStatus,
    /// **本结构的核心**：当前 OS 代理是否仍指向 `expected`。
    pub points_to_us: bool,
    /// 比对基准 `address:mixed_port`（如 `127.0.0.1:7890`）。
    pub expected: String,
}

/// 「当前 OS 代理是否仍指向本进程 mixed 入站」的**唯一**判据（纯函数）。
///
/// 三条缺一不可：
/// 1. `enabled` —— 关着的代理不导流（Windows 注册表在 `ProxyEnable=0` 时仍留 `ProxyServer` 值，
///    只看串会误判）。
/// 2. **至少一条协议腿等于 `address:mixed_port`** —— 端口必须逐字比对。只比 host 会把
///    `127.0.0.1:9999`（用户改了端口 / 另一个本地代理软件）判成「仍指向我们」，那是本函数
///    存在意义的反面（变异锁：`live_status_rejects_port_mismatch` 专锁这条）。
/// 3. **不得有任何一条腿指向别处** —— 我们 enable 时把 http/https(/socks) 全部指向同一个 mixed
///    端口；若某条腿被改成别的代理，该协议的流量就绕开了本地核 = 部分明文/第三方转发，
///    对「已连接」这个断言而言同样是假的。未设（`None`）的腿不算指向别处（Windows 从不设 socks=）。
pub fn points_to_mixed_inbound(status: &SystemProxyStatus, address: &str, mixed_port: u16) -> bool {
    if !status.enabled {
        return false;
    }
    let ours = format!("{address}:{mixed_port}");
    let mut matched = false;
    for leg in [&status.http_proxy, &status.https_proxy, &status.socks_proxy] {
        match leg {
            Some(p) if *p == ours => matched = true,
            // 指向别的代理 / 别的端口 → 该协议的流量不经我们，整体判未生效。
            Some(_) => return false,
            None => {}
        }
    }
    matched
}
