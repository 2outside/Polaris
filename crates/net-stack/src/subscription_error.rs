//! 订阅错误分类（审计 §C4）。移植 上游 `shared/subscription-preview.ts` 的
//! `classifySubscriptionError` + `SUBSCRIPTION_ERROR_I18N_KEY`。
//!
//! **为什么在 Rust 侧**：上游的分类跑在 main（Node）——catch 后把错误摊平成信号再判。Polaris 的
//! main = Rust，故分类归此层；渲染侧只消费 `errorKind` + i18n key 取文案（`sub.preview.*` 十类
//! title/detail 已在 `ui/src/i18n/locales/*.json` 齐备）。TS 侧同名函数因此是**主进程逻辑的残留**
//! （零调用方），已随本批删除，避免双真值漂移。
//!
//! **分层**：本模块只做「信号 → 分类」的纯映射。拉取层（[`crate::subscription`]）对自己主动
//! 抛出的错误（scheme/ssrf/toolarge/http）**在源头直接定 kind**，不回头 re-parse 自己的字符串
//! （上游 用 `/HTTP Error: (\d+)/` 正则从自己抛的文案里反提 status —— 文案一改就静默失配）。
//! 本模块的文案关键字分支服务于**不透明信号**：注入的 HttpClient 冒泡上来的网络错误（io 错误串）。

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// 订阅错误分类。与 TS `SubscriptionErrorKind` 联合类型逐项对齐（serde 字面量 = TS 字面量）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubscriptionErrorKind {
    /// 域名解析失败。
    Dns,
    /// 连接/读取超时。
    Timeout,
    /// 连接被拒绝（端口不可达）。
    Refused,
    /// 服务器返回 4xx/5xx。
    Http,
    /// 命中 SSRF guard（内网/本机地址），含重定向超限。
    Ssrf,
    /// 非 http(s) 协议。
    Scheme,
    /// 响应体积超上限。
    TooLarge,
    /// 拉到内容但非有效订阅格式。
    Parse,
    /// 独立解析执行器当前无法接收任务。
    #[serde(rename = "parse_busy")]
    ParseBusy,
    /// 订阅解析触发显式资源上限。
    #[serde(rename = "parse_limit")]
    ParseLimit,
    /// 拉取到的正文不是有效 UTF-8。
    #[serde(rename = "invalid_encoding")]
    InvalidEncoding,
    /// 整个订阅操作耗尽总时限（区别于网络 I/O 超时）。
    #[serde(rename = "operation_timeout")]
    OperationTimeout,
    /// 解析成功但 0 节点。
    Empty,
    /// 未归类。
    Unknown,
}

/// [`classify_subscription_error`] 的输入：调用方把错误的可判定信号摊平传入。
/// 对齐 TS `SubscriptionErrorSignal`。
#[derive(Debug, Clone, Default)]
pub struct SubscriptionErrorSignal {
    /// 错误文案（拉取/解析层抛出的 message）。
    pub message: Option<String>,
    /// 平台网络错误码（如 `ECONNREFUSED`）。运行时 HttpClient 实现侧由
    /// `std::io::ErrorKind` / 平台 errno 映射填入；无则 None。
    pub code: Option<String>,
    /// HTTP 状态码（非 2xx 时由调用方显式传入，**优先级最高**）。
    pub http_status: Option<u16>,
}

/// 分类结果。`http_status` 仅 [`SubscriptionErrorKind::Http`] 时有值（供 i18n `{{status}}` 插值）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscriptionErrorClass {
    pub kind: SubscriptionErrorKind,
    pub http_status: Option<u16>,
}

/// 子串命中任一（大小写由调用方先归一）。
///
/// 用 `contains` 而非 `regex`：TS 侧这些 pattern 全是纯字面量交替（无字符类/量词/锚点），
/// regex 引擎在此零收益（简约阶梯：原生 > 依赖）。
fn any_of(hay: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| hay.contains(n))
}

/// 错误信号 → 分类。**判定顺序即优先级**（1:1 移植 TS `classifySubscriptionError`）：
///
/// 1. `http_status >= 400` → [`SubscriptionErrorKind::Http`]（确定性最强，显式传入）；
/// 2. **本项目主动抛出的确定性文案**（体积/协议/空/SSRF）—— 先于网络码，因为这些文案由我们自己
///    产出、形态稳定；
/// 3. 平台网络错误码（`ENOTFOUND` / `ETIMEDOUT` / `ECONNREFUSED` …）；
/// 4. 文案关键字兜底（错误码常被实现侧藏进 message）；
/// 5. 解析类文案 → [`SubscriptionErrorKind::Parse`]。
///
/// 未覆盖形态 → [`SubscriptionErrorKind::Unknown`]（UI 给通用文案 + 原始 message 供上报），**不误判**。
pub fn classify_subscription_error(sig: &SubscriptionErrorSignal) -> SubscriptionErrorClass {
    // 1) HTTP 状态显式传入。
    if let Some(status) = sig.http_status {
        if status >= 400 {
            return SubscriptionErrorClass {
                kind: SubscriptionErrorKind::Http,
                http_status: Some(status),
            };
        }
    }

    let code = sig.code.as_deref().unwrap_or("").to_ascii_uppercase();
    let msg = sig.message.as_deref().unwrap_or("");
    // 仅 ASCII 小写：中文不受影响，与 TS `toLowerCase()` 在本用例等价。
    let m = msg.to_lowercase();

    let cls = |kind| SubscriptionErrorClass {
        kind,
        http_status: None,
    };

    // 2) 本项目确定性文案（体积 / 协议 / 空集 / SSRF）。
    //
    // **有意分歧（上游 bug）**：TS 侧只认 `体积超过上限`，但 content-length 预检抛的是
    // `订阅响应体积 {n} 字节超过上限 {max}，已拒绝` —— 中间插了字节数，**子串不连续**，
    // 上游 自己的分类器认不出自己抛的文案 → 落 unknown（UI 显示「无法验证订阅」而非「订阅过大」）。
    // 此处补 `字节超过上限` 覆盖该形态。
    // 刻意**不**收敛成 `超过上限`：那会把 `重定向次数超过上限` 抢在 ssrf 分支前误判成 toolarge。
    if any_of(
        msg,
        &["体积超过上限", "字节超过上限", "too large", "导入内容过大"],
    ) {
        return cls(SubscriptionErrorKind::TooLarge);
    }
    if any_of(msg, &["协议不支持", "仅允许 http"]) {
        return cls(SubscriptionErrorKind::Scheme);
    }
    if any_of(msg, &["0 个可用节点", "得到 0 个", "为空"]) {
        return cls(SubscriptionErrorKind::Empty);
    }
    if any_of(
        &m,
        &[
            "内网",
            "本机",
            "私有地址",
            "ssrf",
            "loopback",
            "private",
            "重定向次数超过",
        ],
    ) {
        return cls(SubscriptionErrorKind::Ssrf);
    }

    // 3) 平台网络错误码。
    match code.as_str() {
        "ENOTFOUND" | "EAI_AGAIN" => return cls(SubscriptionErrorKind::Dns),
        "ETIMEDOUT" | "UND_ERR_CONNECT_TIMEOUT" | "ABORT_ERR" => {
            return cls(SubscriptionErrorKind::Timeout)
        }
        "ECONNREFUSED" | "ECONNRESET" | "EHOSTUNREACH" | "ENETUNREACH" => {
            return cls(SubscriptionErrorKind::Refused)
        }
        _ => {}
    }

    // 4) 文案关键字兜底。
    if any_of(&m, &["err_name_not_resolved", "getaddrinfo", "dns"]) {
        return cls(SubscriptionErrorKind::Dns);
    }
    if any_of(
        &m,
        &[
            "err_timed_out",
            "timeout",
            "timed out",
            "aborted",
            "the operation was aborted",
        ],
    ) {
        return cls(SubscriptionErrorKind::Timeout);
    }
    if any_of(
        &m,
        &[
            "err_connection_refused",
            "connection refused",
            "econnrefused",
        ],
    ) {
        return cls(SubscriptionErrorKind::Refused);
    }
    if any_of(
        &m,
        &[
            "err_connection_reset",
            "err_connection_closed",
            "err_address_unreachable",
            "unreachable",
        ],
    ) {
        return cls(SubscriptionErrorKind::Refused);
    }

    // 5) 解析类文案。
    if any_of(
        &m,
        &[
            "解析失败",
            "无法识别",
            "结构异常",
            "格式错误",
            "不是有效",
            "parse",
            "yaml",
            "json",
        ],
    ) || any_of(msg, &["解析", "识别", "格式"])
    {
        return cls(SubscriptionErrorKind::Parse);
    }

    cls(SubscriptionErrorKind::Unknown)
}

/// errorKind → i18n key 对（渲染侧 `t()` 取展示文案）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscriptionErrorI18nKey {
    pub title: &'static str,
    pub detail: &'static str,
}

/// 分类 → i18n key。1:1 对齐 TS `SUBSCRIPTION_ERROR_I18N_KEY`（渲染侧同名常量保留，供 UI 直接取）。
///
/// 每个 kind 都有独立的 `sub.preview.*` title/detail；
/// `httpDetail` 带 `{{status}}` 插值 → 取 [`SubscriptionErrorClass::http_status`]。
pub fn subscription_error_i18n_key(kind: SubscriptionErrorKind) -> SubscriptionErrorI18nKey {
    use SubscriptionErrorKind as K;
    let (title, detail) = match kind {
        K::Dns => ("sub.preview.dnsTitle", "sub.preview.dnsDetail"),
        K::Timeout => ("sub.preview.timeoutTitle", "sub.preview.timeoutDetail"),
        K::Refused => ("sub.preview.refusedTitle", "sub.preview.refusedDetail"),
        K::Http => ("sub.preview.httpTitle", "sub.preview.httpDetail"),
        K::Ssrf => ("sub.preview.ssrfTitle", "sub.preview.ssrfDetail"),
        K::Scheme => ("sub.preview.schemeTitle", "sub.preview.schemeDetail"),
        K::TooLarge => ("sub.preview.toolargeTitle", "sub.preview.toolargeDetail"),
        K::Parse => ("sub.preview.parseTitle", "sub.preview.parseDetail"),
        K::ParseBusy => ("sub.preview.parseBusyTitle", "sub.preview.parseBusyDetail"),
        K::ParseLimit => (
            "sub.preview.parseLimitTitle",
            "sub.preview.parseLimitDetail",
        ),
        K::InvalidEncoding => (
            "sub.preview.invalidEncodingTitle",
            "sub.preview.invalidEncodingDetail",
        ),
        K::OperationTimeout => (
            "sub.preview.operationTimeoutTitle",
            "sub.preview.operationTimeoutDetail",
        ),
        K::Empty => ("sub.preview.emptyTitle", "sub.preview.emptyDetail"),
        K::Unknown => ("sub.preview.unknownTitle", "sub.preview.unknownDetail"),
    };
    SubscriptionErrorI18nKey { title, detail }
}

#[cfg(test)]
mod tests;
