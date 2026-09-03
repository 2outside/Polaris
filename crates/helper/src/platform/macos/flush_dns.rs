//! 系统 DNS 缓存刷新（移植自 上游 `helper/helper.go:492-506`，proto v9）。
//!
//! ## Go 源根因（`helper.go:492-497`）
//!
//! root 刷系统 DNS 缓存：`dscacheutil -flushcache` 清 Directory Services 缓存 + `killall -HUP mDNSResponder`
//! 清 unicast resolver 缓存。**用户级 dscacheutil 无权 HUP mDNSResponder**（清不到后者），故需 root helper。
//!
//! 核 start/stop 后由 app 侧 best-effort 调用：清掉「系统解析器受控/还原」边界另一侧的陈旧记录
//! （如 TUN+FakeIP 会话缓存的假 IP 骑跨到直连态）。
//!
//! ## 错误降级矩阵（逐字对照 Go `helper.go:498-506`）
//!
//! | dscacheutil | killall HUP | 响应 | 理由 |
//! |-------------|-------------|------|------|
//! | 失败 | — | `ERR dscacheutil <err> <out>` | app 降级用户级 dscacheutil 有意义 |
//! | 成功 | 成功 | `OK flushed` | 两层全清 |
//! | 成功 | 失败 | `OK flushed-partial killall-hup <err> <out>` | app 不降级——用户级同样无权 HUP，重复无益 |
//!
//! ## 命令路径（`helper.go:498,502`）
//!
//! - dscacheutil: `/usr/bin/dscacheutil -flushcache`
//! - killall: `/usr/bin/killall -HUP mDNSResponder`

use crate::platform::macos::exec::{CommandRunner, RunError, EXEC_TIMEOUT};
use polaris_helper_proto::response::{FlushDns, ResponseKind};
use polaris_helper_proto::Response;

/// dscacheutil 程序路径（`helper.go:498`：`/usr/bin/dscacheutil`）。
pub const DSCACHEUTIL_BIN: &str = "/usr/bin/dscacheutil";
/// killall 程序路径（`helper.go:502`：`/usr/bin/killall`）。
pub const KILLALL_BIN: &str = "/usr/bin/killall";

/// flush-dns 命令参数（`/usr/bin/dscacheutil -flushcache`）。
pub const DSCACHEUTIL_ARGS: &[&str] = &["-flushcache"];
/// flush-dns 的 killall 参数（`/usr/bin/killall -HUP mDNSResponder`）。
pub const KILLALL_HUP_ARGS: &[&str] = &["-HUP", "mDNSResponder"];

/// flush-dns 响应结果（携带诊断信息，便于 handler 构造 wire 响应）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlushResult {
    /// 两层全清成功 → `OK flushed`。
    Flushed,
    /// dscacheutil 成功但 HUP mDNSResponder 失败 → `OK flushed-partial killall-hup <err> <out>`。
    Partial { tail: String },
    /// dscacheutil 失败 → `ERR dscacheutil <err> <out>`。
    DscacheutilFailed { detail: String },
}

/// 执行 flush-dns 两步（移植自 `helper.go:498-506`）。
///
/// 严格对照 Go 的顺序与错误分派：
/// 1. 先 dscacheutil（combined 捕获 stderr 作诊断）。失败 → [`FlushResult::DscacheutilFailed`]。
/// 2. 再 killall -HUP mDNSResponder。失败 → [`FlushResult::Partial`]（tail 含 `killall-hup <err> <out>`）。
/// 3. 两步都成功 → [`FlushResult::Flushed`]。
pub fn flush_dns(runner: &dyn CommandRunner) -> FlushResult {
    // helper.go:498-501: dscacheutil 失败 → ERR dscacheutil <err> <out>
    if let Err(e) = runner.combined(EXEC_TIMEOUT, DSCACHEUTIL_BIN, DSCACHEUTIL_ARGS) {
        return FlushResult::DscacheutilFailed {
            detail: format!("dscacheutil {e}"),
        };
    }
    // helper.go:502-505: HUP 失败 → OK flushed-partial killall-hup <err> <out>
    if let Err(e) = runner.combined(EXEC_TIMEOUT, KILLALL_BIN, KILLALL_HUP_ARGS) {
        return FlushResult::Partial {
            tail: format_partial_tail(&e),
        };
    }
    // helper.go:506: 两层全清 → OK flushed
    FlushResult::Flushed
}

/// 把 killall 的 RunError 格式化为 `killall-hup <err> <out>` 形态（`helper.go:503`）。
///
/// 对照 Go：`fmt.Fprintf(conn, "OK flushed-partial killall-hup %v %s\n", err, strings.TrimSpace(string(out)))`。
/// 即 `killall-hup ` + 错误描述 + 空格 + trimmed 输出。
fn format_partial_tail(e: &RunError) -> String {
    match e {
        RunError::NonZero { code, output } => {
            // Go err 是 *exec.ExitError（"exit status 1"），out 是 CombinedOutput 的合并字节
            let err_str = format!("exit status {code}");
            let out_str = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            if out_str.is_empty() {
                format!("killall-hup {err_str}")
            } else {
                format!("killall-hup {err_str} {out_str}")
            }
        }
        RunError::Timeout => "killall-hup timeout".to_owned(),
        RunError::Spawn(msg) => format!("killall-hup spawn failed: {msg}"),
    }
}

/// 把 [`FlushResult`] 转换为 wire [`Response`]（便于 handler 直接发送）。
impl From<FlushResult> for Response {
    fn from(r: FlushResult) -> Self {
        match r {
            FlushResult::Flushed => Response::Ok(ResponseKind::FlushDns(FlushDns::Flushed)),
            FlushResult::Partial { tail } => {
                Response::Ok(ResponseKind::FlushDns(FlushDns::FlushedPartial { tail }))
            }
            FlushResult::DscacheutilFailed { detail } => {
                Response::Err(polaris_helper_proto::Error::with_detail(
                    polaris_helper_proto::ErrorCode::Dscacheutil,
                    detail,
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests;
