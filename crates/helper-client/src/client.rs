//! [`HelperClient`] —— 主进程侧 helper socket 客户端。
//!
//! ## 职责（移植自 上游 `HelperManager.ts:433-457` 的 `sendCommand`）
//!
//! 连接 helper socket/pipe → 发 [`Request`]（复用 `helper-proto::codec::encode` 编帧）→ 读单行
//! [`Response`]（复用 `helper-proto::Response::parse` 解码）→ 关连接。每次请求一连接（Polaris 即此模型：
//! `net.connect` → `sock.end(frame)` → 读 `data`+`end` → 销毁，无长连接）。
//!
//! ## 连接抽象
//!
//! 生产侧 socket/pipe 与测试 mock 经 [`ConnectionStream`] trait 解耦。
//! [`HelperClient`] 持有一个 [`Connector`]（连接工厂）：每次 [`HelperClient::send`] 调
//! [`Connector::connect`] 建新连接。生产注入 `UnixConnector`/pipe connector，测试注入返回
//! `MockStream`（测试替身）的闭包。
//!
//! ## token 行鉴权
//!
//! mac/win 带 token 行（[`Platform::has_token_line`]），linux 无（SO_PEERCRED）。token 由调用方提供
//! （从 [`token::read_token`](crate::token::read_token) 读到的 app 侧 token 文件）。
//!
//! ## 重连 / 超时
//!
//! - **超时**：单请求超时由调用方传入（默认 [`DEFAULT_REQUEST_TIMEOUT_MS`]，install-core 用 [`INSTALL_CORE_TIMEOUT_MS`](crate::transport::INSTALL_CORE_TIMEOUT_MS)）。
//!   超时返回 [`ClientError::Timeout`]（对齐 上游 `helper socket 超时`，HelperManager.ts:441）。
//! - **重连**：[`HelperClient::send_with_retry`] 在连接失败 / 超时时按策略重试（默认 0 次 —— Polaris sendCommand
//!   不重试，调用方决定。重试用于「刚 install 完等 daemon 起来」场景，对齐 Polaris install 后轮询就绪
//!   `HelperManager.ts:519-522`）。
//!
//! ## 移植纪律
//!
//! 1. 复用 `helper-proto::codec::encode` + `Response::parse`，不重写帧。
//! 2. socket/pipe 经 trait 抽象，测试 mock（不碰宿主）。
//! 3. `forbid(unsafe_code)`。

#[cfg(test)]
use crate::transport::INSTALL_CORE_TIMEOUT_MS;
use crate::transport::{ConnectionStream, DEFAULT_REQUEST_TIMEOUT_MS};
use polaris_helper_proto::codec;
use polaris_helper_proto::{Platform, Request, Response};
#[cfg(test)]
use std::io;
use std::time::{Duration, Instant};

/// helper 连接工厂 trait —— 每次调用返回一个新的已连接 [`ConnectionStream`]。
///
/// 抽象 `net.connect(SOCKET_PATH)`（上游 `HelperManager.ts:435`）。生产实现打开 Unix socket / 命名管道；
/// 测试实现返回 `MockStream`（测试替身）。
pub trait Connector: Send {
    /// 建立一条新连接。失败返回 [`ClientError`]（连接拒绝 = helper 未装/未跑，对齐 上游 `sock.on('error')`）。
    fn connect(&self) -> Result<Box<dyn ConnectionStream>, ClientError>;
}

/// helper 客户端错误（对齐 Polaris 的 reject 路径：超时 / 连接错误 / IO 错误 / 协议错误）。
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// 连接 helper 失败（socket/pipe 不存在 = helper 未安装或未运行）。
    #[error("连接 helper 失败: {0}")]
    Connect(String),
    /// 读响应超时（对齐 上游 `helper socket 超时`，HelperManager.ts:441）。
    #[error("helper socket 超时")]
    Timeout,
    /// IO 错误（读写失败、对端关闭等）。
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
    /// 空响应（连接建立但未读到数据，对齐 上游 `helper 无响应`）。
    #[error("helper 无响应")]
    EmptyResponse,
}

/// helper 客户端 —— 发送 [`Request`] 并接收 [`Response`]。
///
/// 持有 [`Connector`]（连接工厂）+ 平台标识 + token。
///
/// # 用法
///
/// ```no_run
/// # #[cfg(unix)]
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use polaris_helper_client::{HelperClient, UnixConnector};
/// use polaris_helper_proto::{Platform, Request};
///
/// let connector = UnixConnector::new("/run/polaris/helper.sock");
/// let client = HelperClient::new(Box::new(connector), Platform::Linux, "");
/// let response = client.send(&Request::Ping)?;
/// # let _ = response;
/// # Ok(())
/// # }
/// # #[cfg(not(unix))]
/// # fn main() {}
/// ```
pub struct HelperClient {
    connector: Box<dyn Connector>,
    platform: Platform,
    token: String,
}

impl HelperClient {
    /// 构造客户端。`connector` 负责建连接，`token` 用于 mac/win 鉴权行（linux 忽略）。
    pub fn new(
        connector: Box<dyn Connector>,
        platform: Platform,
        token: impl Into<String>,
    ) -> Self {
        Self {
            connector,
            platform,
            token: token.into(),
        }
    }

    /// 发送一个请求，默认超时 [`DEFAULT_REQUEST_TIMEOUT_MS`]（ping/status 等短命令）。
    ///
    /// 一次连接一次请求（对齐 Polaris sendCommand 模型）。
    pub fn send(&self, req: &Request) -> Result<Response, ClientError> {
        self.send_with_timeout(req, Duration::from_millis(DEFAULT_REQUEST_TIMEOUT_MS))
    }

    /// 发送一个请求，自定义超时。
    ///
    /// install-core 用 [`INSTALL_CORE_TIMEOUT_MS`](crate::transport::INSTALL_CORE_TIMEOUT_MS)（sha256 + 大文件复制耗时长，HelperManager.ts:421）。
    pub fn send_with_timeout(
        &self,
        req: &Request,
        timeout: Duration,
    ) -> Result<Response, ClientError> {
        let deadline = Instant::now() + timeout;
        // 1. 建连接
        let mut conn = self.connector.connect().map_err(|e| {
            log::warn!("helper 连接失败: {e}");
            e
        })?;
        // 2. 编帧（复用 helper-proto codec）
        let frame = codec::encode(self.platform, &self.token, req);
        // 3. 写帧 + shutdown（对齐 Polaris sock.end(frame)，HelperManager.ts:438）
        conn.write_all(&frame).map_err(ClientError::Io)?;
        conn.shutdown().map_err(ClientError::Io)?;
        // 4. 读单行响应（行协议：响应一行 \n 结尾）
        let line = read_response_line(&mut *conn, deadline)?;
        // 5. 解析响应（复用 helper-proto Response::parse）
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Err(ClientError::EmptyResponse);
        }
        Ok(Response::parse(trimmed))
    }

    /// 带重试的发送：连接失败 / 超时时按 `retry_delay` 间隔重试 `max_retries` 次。
    ///
    /// 用于「install 后等 daemon 起来」场景（上游 `HelperManager.ts:519-522` 轮询就绪）：
    /// daemon 注册到 launchd/systemd/SCM 后绑定 socket 需要时间，首次 ping 可能 ECONNREFUSED。
    pub fn send_with_retry(
        &self,
        req: &Request,
        timeout: Duration,
        max_retries: u32,
        retry_delay: Duration,
    ) -> Result<Response, ClientError> {
        let mut last_err = None;
        for attempt in 0..=max_retries {
            if attempt > 0 {
                std::thread::sleep(retry_delay);
            }
            match self.send_with_timeout(req, timeout) {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    log::debug!("helper 请求第 {attempt} 次失败: {e}");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or(ClientError::EmptyResponse))
    }

    /// 更新 token（install/uninstall 后 app 侧 token 文件变化时）。
    pub fn set_token(&mut self, token: impl Into<String>) {
        self.token = token.into();
    }

    /// 当前 token。
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// 当前平台。
    #[must_use]
    pub const fn platform(&self) -> Platform {
        self.platform
    }
}

/// 读完整一行响应（到 `\n` 或 EOF），受 deadline 超时约束。
///
/// 行协议：helper 回单行 `\n` 结尾（`fmt.Fprintln(conn, ...)`）。读到 `\n` 即完整响应。
///
/// **deadline 必须下发到流**：连接器建连时给流设的是自己的默认读超时（`transport::READ_TIMEOUT` = 5s，
/// 对齐 Go `SetReadDeadline`），它与调用方的单请求预算无关。不下发的话，30s 的 install-core /
/// 45s 的 linux-resolved 会在 5s 被判失败而 helper 仍把动作做完（app 报失败、系统状态已改）。
/// 故每轮读前把**剩余预算**经 [`ConnectionStream::set_read_timeout`] 下发；预算耗尽 ⇒
/// [`ClientError::Timeout`]（而非把 `TimedOut` 当普通 IO 错误上抛，见 `send_with_timeout` 文档承诺）。
fn read_response_line(
    conn: &mut dyn ConnectionStream,
    deadline: Instant,
) -> Result<String, ClientError> {
    let mut buf = Vec::new();
    loop {
        // 超时检查 + 把剩余预算下发给流（生产腿据此设 SO_RCVTIMEO / 轮询 deadline）。
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(ClientError::Timeout);
        };
        if remaining.is_zero() {
            return Err(ClientError::Timeout);
        }
        conn.set_read_timeout(remaining).map_err(ClientError::Io)?;
        let mut byte_buf = Vec::new();
        match conn.read_until_timeout(&mut byte_buf) {
            Ok(0) => {
                // EOF —— helper 关闭连接，返回当前已读内容（可能为空）
                break;
            }
            Ok(n) => {
                buf.extend_from_slice(&byte_buf[..n]);
                // 检查是否读到行尾
                if buf.last() == Some(&b'\n') {
                    break;
                }
            }
            // 流侧报超时（Unix 归一后的 TimedOut / 原始 WouldBlock）= 本次请求预算用尽。
            Err(e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                return Err(ClientError::Timeout);
            }
            Err(e) => return Err(ClientError::Io(e)),
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests;
