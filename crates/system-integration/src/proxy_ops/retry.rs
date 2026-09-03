//! 系统代理 enable 的重试原语（1:1 移植上游 `retry.ts`），DNS 侧 `dns_ops` 亦复用本模块的
//! `RetryConfig` / `retry_op` / `is_permission_denied`。

use crate::error::SystemIntegrationError;
use std::time::Duration;

// ── 重试原语（1:1 移植 上游 `src/main/utils/retry.ts` + 三平台 enableProxy retry 块）──
//
// FX-proxy-ops-retry（审查表 row69）：上游三平台 `enableProxy` 都用 `retry(...)` 包裹「设代理命令序列」，
// 单条命令瞬时抖动（Win reg/netsh 占用、mac networksetup 竞态、gsettings 瞬时失败）不误判失败回滚。
// 此前 Polaris `set_proxy` 是无重试单次 `run_all` → 一次抖动即失败回滚。以下按上游**逐字**迁移退避 /
// 重试上限 / shouldRetry 谓词（三平台参数各异，勿合并成单一配置）。

/// 单次 enable 的重试配置。对齐上游 `RetryOptions`（省略 `onRetry` 日志钩子——纯观察、无行为影响，
/// 且本 crate 此层无 logger seam）。三平台参数不同：见 [`WIN_ENABLE_RETRY`] / [`MAC_ENABLE_RETRY`] /
/// [`LINUX_ENABLE_RETRY`]。
///
/// `pub(crate)`（含字段）：DNS 侧 `dns_ops::SystemDnsController::set_dns` 复用本原语与类型
/// （上游 `SystemDnsManager.setDns` 同样用 `retry()` 包裹 apply 循环，见该 mod 内 `DNS_SET_RETRY`）。
pub(crate) struct RetryConfig {
    /// 最大重试次数（**不含**首次尝试）。总执行 = `max_retries + 1`
    /// （逐字对齐上游 `for (attempt=0; attempt<=maxRetries; attempt++)`，`retry.ts:58`）。
    pub(crate) max_retries: u32,
    /// 基础退避延迟（上游三平台均 `delay: 500`）。
    pub(crate) delay: Duration,
    /// 指数退避（上游 `exponentialBackoff` 缺省 **true**，三处均未显式关闭）：第 n 次重试前 `sleep(delay * 2^n)`
    /// → 500ms、1000ms……（**非**固定 500ms；`retry.ts:50,72`）。
    pub(crate) exponential_backoff: bool,
    /// 可重试谓词：`false` = 立即放弃（权限拒绝 / 命令未找到 / 非瞬时错误）。对齐上游 `shouldRetry`。
    pub(crate) should_retry: fn(&SystemIntegrationError) -> bool,
}

/// Windows `enableProxy` retry 块（上游 `SystemProxyManager.ts:252-265`）：`maxRetries:2, delay:500`
/// （指数退避缺省 true → 退避 500/1000ms），`shouldRetry`= 权限拒绝 / 命令未找到 → 不重试，其余瞬时 → 重试。
pub(super) const WIN_ENABLE_RETRY: RetryConfig = RetryConfig {
    max_retries: 2,
    delay: Duration::from_millis(500),
    exponential_backoff: true,
    should_retry: win_enable_should_retry,
};

/// macOS `enableProxy` retry 块（上游 `SystemProxyManager.ts:518-531`）：`maxRetries:2, delay:500`
/// （指数退避缺省 true → 退避 500/1000ms），`shouldRetry`= 权限 / 未授权 → 不重试。
pub(super) const MAC_ENABLE_RETRY: RetryConfig = RetryConfig {
    max_retries: 2,
    delay: Duration::from_millis(500),
    exponential_backoff: true,
    should_retry: mac_enable_should_retry,
};

/// Linux `enableProxy` retry 块（上游 `SystemProxyManager.ts:764`）：`{ maxRetries: 1, delay: 500 }`
/// —— **未传 `shouldRetry` → 用上游 `defaultShouldRetry`**（仅瞬时网络类错误重试）。指数退避缺省 true。
pub(super) const LINUX_ENABLE_RETRY: RetryConfig = RetryConfig {
    max_retries: 1,
    delay: Duration::from_millis(500),
    exponential_backoff: true,
    should_retry: default_should_retry,
};

/// 通用重试（1:1 移植上游 `retry()`，`retry.ts:43-89`）。循环语义逐字对齐 `for (attempt=0; attempt<=maxRetries; attempt++)`：
/// 失败后 `attempt >= max_retries` → 放弃并返回**最后一次**错误；`!should_retry` → 立即放弃；否则
/// `sleep(退避)` 后重试。`sleep` 注入便于测试（生产 [`std::thread::sleep`]，测试传 no-op / 记录器，
/// 杜绝真睡 —— 对齐 crate 既有「可注入执行缝」风格）。
///
/// `pub(crate)`：`dns_ops::SystemDnsController::set_dns` 复用（DNS apply 循环重试，见该处调用点）。
pub(crate) fn retry_op<T>(
    cfg: &RetryConfig,
    mut op: impl FnMut() -> Result<T, SystemIntegrationError>,
    mut sleep: impl FnMut(Duration),
) -> Result<T, SystemIntegrationError> {
    let mut attempt: u32 = 0;
    loop {
        match op() {
            Ok(v) => return Ok(v),
            Err(e) => {
                // 已到上限（首次 + max_retries 次重试全败）→ 抛最后一次错误。
                if attempt >= cfg.max_retries {
                    return Err(e);
                }
                // 不可重试（权限/命令未找到/非瞬时）→ 立即放弃，不浪费退避。
                if !(cfg.should_retry)(&e) {
                    return Err(e);
                }
                let backoff = if cfg.exponential_backoff {
                    cfg.delay * 2u32.pow(attempt)
                } else {
                    cfg.delay
                };
                sleep(backoff);
                attempt += 1;
            }
        }
    }
}

/// 错误消息（小写）—— shouldRetry 谓词按上游对 `error.message.toLowerCase()` 的子串判定。
/// `Display` 形如 `system proxy error: <msg>`，前缀不含任何目标子串，判定不受污染。
fn err_message_lower(e: &SystemIntegrationError) -> String {
    e.to_string().to_lowercase()
}

/// 上游 `defaultShouldRetry`（`retry.ts:20-41`）：仅瞬时网络类错误重试。上游另判结构化
/// `error.code`（'ENOENT'/9009 等）；Rust 侧无结构化 code，执行缝把原因归入消息串 → 统一按消息子串判。
pub(super) fn default_should_retry(e: &SystemIntegrationError) -> bool {
    const TEMPORARY_ERRORS: [&str; 9] = [
        "timeout",
        "timed out",
        "econnrefused",
        "econnreset",
        "etimedout",
        "enetunreach",
        "ehostunreach",
        "enotfound",
        "temporary failure",
    ];
    let msg = err_message_lower(e);
    TEMPORARY_ERRORS.iter().any(|p| msg.contains(p))
}

/// Windows enable 的 `shouldRetry`（上游 `SystemProxyManager.ts:255-264`）：权限拒绝 / 命令未找到 →
/// 不重试（重试无意义，直给对症诊断），其余瞬时错误 → 重试。
pub(super) fn win_enable_should_retry(e: &SystemIntegrationError) -> bool {
    if matches!(
        e,
        SystemIntegrationError::WindowsProxyWriter(error) if error.is_access_denied()
    ) {
        return false;
    }
    let msg = err_message_lower(e);
    // reg.exe 回退没有结构化 code；英文 Windows 实际文案同时存在
    // "Access denied" 与 "Access is denied" 形态，两者都应立即放弃。
    if msg.contains("access denied")
        || msg.contains("access is denied")
        || is_permission_denied(&msg)
    {
        return false;
    }
    if is_command_not_found(&msg) {
        return false;
    }
    true
}

/// 「权限被拒」消息判据（**唯一词表**，mac enable / DNS set 共用）。
///
/// # 为什么词表必须比上游宽
///
/// 上游只判 `permission` / `not authorized` 两词，那是 Electron 侧 `execFileAsync` 抛出的 Node 错误
/// 文案；Rust 侧的执行缝（[`crate::exec::StdCommandRunner`]）把**子进程 stderr 原文**归入消息串 ——
/// 而 macOS `networksetup` 权限失败的常见原文是 **`requires admin privileges`** 形态，
/// 一个目标词都不含。漏判的代价不是「少一条日志」：`should_retry` 会把它当瞬时抖动，
/// **多跑 2 次必败重试 + 1.5s 指数退避**，而 DNS 那条重试是**持 `dns_controller` 锁**跑的
/// （见 `dns_ops::DNS_SET_RETRY`）—— 一次必败的权限错误会把锁多占 1.5 秒。
///
/// 词表按「消息里出现即可判定权限」筛，宁窄勿宽：多判一个词只会让某个**真瞬时**错误少重试 2 次
/// （代价有限、可观测）；少判一个词则是上面那条静默的锁占用。
///
/// TODO(真机采集)：macOS 各版本 `networksetup` / `scutil` 的权限失败原文尚未在真机逐条采样，
/// 本表是「已知形态 + EPERM/root 通用形态」的保守并集。真机采到新文案时补进本表（**只加不改**：
/// 现有词各自对应一种已知形态，删词等于把那种形态放回误重试路径）。
// Re-exported through `proxy_ops` solely for the `dns_ops.rs` intra-doc link.
pub(crate) const PERMISSION_DENIED_NEEDLES: [&str; 7] = [
    "permission",               // "permission denied"（EACCES 通用文案 + 上游原判据）
    "not authorized",           // 上游原判据（Electron 侧文案）
    "not permitted",            // EPERM: "Operation not permitted"
    "requires admin",           // "requires admin privileges" / "requires administrator privileges"
    "administrator privileges", // 同上的另一种措辞（不含 "requires" 前缀时）
    "must be root",             // "You must be root to ..."
    "as root",                  // "You must be running as root to ..." / "run as root"
];

/// 消息（**已 lowercase**）是否命中 [`PERMISSION_DENIED_NEEDLES`]。
pub(crate) fn is_permission_denied(msg_lower: &str) -> bool {
    PERMISSION_DENIED_NEEDLES
        .iter()
        .any(|p| msg_lower.contains(p))
}

/// macOS enable 的 `shouldRetry`（上游 `SystemProxyManager.ts:521-526`）：权限 / 未授权 → 不重试。
/// 判据词表见 [`PERMISSION_DENIED_NEEDLES`]（与 DNS set 共用，两处口径不可分叉）。
pub(super) fn mac_enable_should_retry(e: &SystemIntegrationError) -> bool {
    !is_permission_denied(&err_message_lower(e))
}

/// 命令未找到判定（移植上游 `win-system32.ts:isCommandNotFoundError` 的消息子串）。上游还判
/// `code==='ENOENT'||9009`；Polaris 侧 reg/netsh 已绝对路径化，缺失表现为 spawn 失败，经
/// [`crate::exec::StdCommandRunner`] 归一为「`<program> 启动失败: …`」→ 补该本地标记作 Rust 侧 ENOENT 等价。
fn is_command_not_found(msg_lower: &str) -> bool {
    const NEEDLES: [&str; 6] = [
        "不是内部或外部命令",   // cmd zh-CN: 'X' 不是内部或外部命令
        "is not recognized",    // cmd en: 'X' is not recognized
        "command not found",    // POSIX shell
        "系统找不到指定的路径", // cmd zh-CN: 绝对路径不存在
        "cannot find the path", // cmd en
        "启动失败",             // Rust spawn ENOENT（StdCommandRunner 措辞）
    ];
    NEEDLES.iter().any(|n| msg_lower.contains(n))
}
