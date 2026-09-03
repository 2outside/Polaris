//! 诊断报告 Markdown 构建 —— 纯字符串拼装，零 IO、零脱敏（输入必须**已脱敏**）。
//!
//! Polaris 锚点：`shared/diagnostic-redact.ts` 的 `buildDiagnosticReport`（:388-560）。
//!
//! 设计取舍（沿用 Polaris）：**单 Markdown 文件（非 zip）** —— 一个文件更易上传、人可读、零新依赖。
//!
//! # 分工
//!
//! 本模块**只拼装**。脱敏在 [`crate::redact`]，IO / 取数在 `src-tauri` 的 command 层。
//! 「构建器不做脱敏」是刻意的：脱敏若散在拼装各处，漏一处就是红线破口；收口到 [`crate::redact`]
//! 才谈得上「单一真值」。
//!
//! # 与 上游 报告的段落差异（Tauri ≠ Electron）
//!
//! 上游的「进程内存 / 渲染进程堆分层 / 内存时间线 / 渲染进程内存看护」四段（issue #242）建立在
//! Electron 专有 API 上（`app.getAppMetrics()` / `webFrame` / `executeJavaScript` 取 V8 堆）。
//! Tauri 架构里**没有对应物**（webview 是系统 WebView2/WKWebView，无 V8 堆内省、无 Electron 进程树），
//! 照搬只会得到一段恒为 "unavailable" 的死段 → **本移植不含这四段**。缺口性质属「Electron 专有能力，
//! Tauri 无等价物」，非「漏移植」。
//!
//! 保留并接线的是 [`DiagnosticCounters`] 两轴（慢起 vs 核崩），它与运行时无关。

#![forbid(unsafe_code)]

use serde_json::Value;

use crate::diagnostic::DiagnosticCounters;
use crate::redact::{redact_identifiers, NodeIdentifier};

/// 环境快照段。
#[derive(Debug, Clone, Default)]
pub struct AppSection {
    /// Polaris 版本。
    pub polaris_version: String,
    /// sing-box 内核版本。
    pub core_version: String,
    /// 系统串（如 `linux x86_64 6.8.0`）。
    pub os: String,
}

/// 运行态段。可选字段 = 取不到就不渲染该行（best-effort，绝不因取数失败阻断导出）。
#[derive(Debug, Clone, Default)]
pub struct RuntimeSection {
    pub proxy_mode: String,
    pub proxy_mode_type: String,
    pub proxy_running: bool,
    /// 经提权 helper 启动。
    pub started_via_helper: Option<bool>,
    pub helper_status: Option<String>,
    /// 实际生效的系统代理（脱敏无关，IP:port）。
    pub system_proxy: Option<String>,
    /// 生效系统解析器。
    pub effective_dns: Option<String>,
    /// #57 节点域名解析档位。
    pub node_domain_resolver: Option<String>,
    pub log_level: String,
    // 曾有一行 `capture_active`（旧 `diagnosticCapture` 采集态）。该机制已整体删除 —— 核日志经
    // `SubscribeLog` 全级别送达、级别筛在客户端，不再需要「临时把核提级到 debug」这套会话。
    // 报告里那一行随之撤掉：留着它只会恒为 false，成为一条永远不变的噪音。
    /// 两轴计数（慢起 / 核崩）。见 [`DiagnosticCounters`]。
    pub counters: DiagnosticCounters,
}

/// 诊断报告输入（全部**已脱敏 / 已 tail**；构建器只拼装，不做任何 IO 或脱敏）。
#[derive(Debug, Clone, Default)]
pub struct DiagnosticReportInput {
    /// ISO 8601 生成时刻。
    pub generated_at: String,
    pub app: AppSection,
    pub runtime: RuntimeSection,
    /// **已过 `redact_deep`** 的 UserConfig。
    pub redacted_user_config: Value,
    /// **已过 `redact_deep`** 的生成 sing-box 配置。
    pub redacted_singbox_config: Value,
    pub app_log_tail: String,
    pub singbox_log_tail: String,
    /// 节点标识符 → 占位符：构建末尾在全报告统一替换，打码节点身份，保留形态与跨段相关性。
    pub node_identifiers: Vec<NodeIdentifier>,
    /// 当前级别不含连接明细（>info）且日志疑似有连接/DNS 错误 → 提示把日志级别切到 DEBUG 复现。
    /// （文案由调用方给；本 crate 只负责把它渲染进报告。）
    pub hint: Option<String>,
}

/// 动态围栏（CommonMark）：扫描 body 内最长连续反引号串，用 `max(3, n+1)` 个反引号作围栏。
///
/// **防内容提前闭合代码块**：日志 / 节点名 / 订阅名都是**机场可控**的外部输入，含 ``` 会截断代码块、
/// 把后续报告内容甩到围栏外（结构破坏 = 阅读者可能看不到关键段，也给注入留面）。
fn fence(lang: &str, body: &str) -> String {
    let safe = if body.is_empty() { "(空)" } else { body };
    let mut max_run = 0usize;
    let mut cur = 0usize;
    for ch in safe.chars() {
        if ch == '`' {
            cur += 1;
            if cur > max_run {
                max_run = cur;
            }
        } else {
            cur = 0;
        }
    }
    let ticks = "`".repeat(std::cmp::max(3, max_run + 1));
    format!("{ticks}{lang}\n{safe}\n{ticks}")
}

/// 构建诊断报告 Markdown（纯字符串拼装，可单测）。上游 `buildDiagnosticReport`。
#[must_use]
pub fn build_diagnostic_report(input: &DiagnosticReportInput) -> String {
    let app = &input.app;
    let rt = &input.runtime;
    let mut lines: Vec<String> = vec![
        "# Polaris 诊断报告".into(),
        String::new(),
        "> 本报告用于排障，可附到 GitHub issue。**密钥与节点身份已脱敏**（uuid/密码/私钥/订阅 token 已打码；\
节点域名/IP/SNI/节点名已替换为 `<domain-N>`/`<ip-N>`/`<node-N>` 占位符）。\
日志明细可能仍含访问过的**其它**域名/IP——介意可自行删减后再上传。"
            .into(),
        String::new(),
    ];
    if let Some(hint) = &input.hint {
        lines.push(format!("> 提示：{hint}"));
        lines.push(String::new());
    }

    lines.push("## 环境".into());
    lines.push(String::new());
    lines.push(format!("- 生成时间：{}", input.generated_at));
    lines.push(format!("- Polaris 版本：{}", app.polaris_version));
    lines.push(format!("- 内核版本：{}", app.core_version));
    lines.push(format!("- 系统：{}", app.os));
    lines.push(String::new());

    lines.push("## 运行态".into());
    lines.push(String::new());
    lines.push(format!(
        "- 代理模式：{} / {}",
        rt.proxy_mode, rt.proxy_mode_type
    ));
    lines.push(format!("- 代理运行中：{}", zh_bool(rt.proxy_running)));
    if let Some(v) = rt.started_via_helper {
        lines.push(format!("- 经提权 helper 启动：{}", zh_bool(v)));
    }
    if let Some(v) = &rt.helper_status {
        lines.push(format!("- Helper 状态：{v}"));
    }
    if let Some(v) = &rt.system_proxy {
        lines.push(format!("- 系统代理实际值：{v}"));
    }
    if let Some(v) = &rt.effective_dns {
        lines.push(format!("- 生效系统 DNS：{v}"));
    }
    if let Some(v) = &rt.node_domain_resolver {
        lines.push(format!("- 节点域名解析档位：{v}"));
    }
    lines.push(format!("- 日志级别：{}", rt.log_level));
    // 两轴分开呈现（维度7 #11）：「争用下起得慢但已自愈」≠「核崩溃自动重启」，混为一谈会误报核崩。
    if rt.counters.last_start_ready_retries > 0 {
        lines.push(format!(
            "- 最近一次起核经 {} 次就绪重试才成功（起核慢，多因 Windows 重启争用下 wintun 适配器未及时释放；非核崩溃）",
            rt.counters.last_start_ready_retries
        ));
    }
    if rt.counters.restart_count > 0 {
        lines.push(format!(
            "- 核崩溃自动重启：{} 次（冷却窗口内）",
            rt.counters.restart_count
        ));
    }
    lines.push(String::new());

    lines.push("## 生成的 sing-box 配置（脱敏）".into());
    lines.push(String::new());
    lines.push(fence("json", &pretty(&input.redacted_singbox_config)));
    lines.push(String::new());

    lines.push("## 用户配置（脱敏）".into());
    lines.push(String::new());
    lines.push(fence("json", &pretty(&input.redacted_user_config)));
    lines.push(String::new());

    lines.push("## app.log（近期）".into());
    lines.push(String::new());
    lines.push(fence("text", &input.app_log_tail));
    lines.push(String::new());

    lines.push("## singbox.log（近期）".into());
    lines.push(String::new());
    lines.push(fence("text", &input.singbox_log_tail));
    lines.push(String::new());

    // 末尾在全报告（配置块 + 日志 + 运行态）统一打码节点标识符，跨段占位一致便于关联诊断。
    redact_identifiers(&lines.join("\n"), &input.node_identifiers)
}

/// 诊断报告的**原始**输入（配置**未脱敏**，由 [`assemble_diagnostic_report`] 内部统一脱敏）。
///
/// # 为什么要有这一层（§K7.1 的教训）
///
/// [`DiagnosticReportInput`] 要求调用方**先脱敏再传**——那是个火药桶：`redact_deep` 有门、
/// `build_diagnostic_report` 有门，但**两者的组合（也就是唯一的生产路径）无门**。调用方忘了脱敏、
/// 或漏传 `extra_secret_keys`（custom 协议密钥必需），两扇门都照样全绿，而报告已经在泄漏。
///
/// 本结构收口这条组合面：**喂进来的是原始 config，脱敏由内部做，调用方没有「忘记」的机会**。
/// 命令层只负责 IO（读日志 / 取版本号），拿不到绕过脱敏的入口。
#[derive(Debug, Clone, Default)]
pub struct DiagnosticReportSource {
    pub generated_at: String,
    pub app: AppSection,
    pub runtime: RuntimeSection,
    /// **原始** UserConfig（未脱敏）。
    pub user_config: Value,
    /// **原始**生成 sing-box 配置（未脱敏）。取不到时传 `Value::Null` 或错误说明对象。
    pub singbox_config: Value,
    /// #57 resolve-ahead 预解析出的节点 IP（不在 `config.servers` 里，需一并按节点身份打码）。
    pub extra_addresses: Vec<String>,
    pub app_log_tail: String,
    pub singbox_log_tail: String,
    pub hint: Option<String>,
}

/// 从**原始**输入一步产出脱敏后的诊断报告 Markdown。**生产路径唯一入口。**
///
/// 内部依次：汇总 custom `secretKeys` → 脱敏 UserConfig + 生成配置（同一个 `redact_deep`，单一真值）
/// → 收集节点标识符 → 拼装 → 末尾全报告统一打码节点身份。
#[must_use]
pub fn assemble_diagnostic_report(src: &DiagnosticReportSource) -> String {
    // custom 协议的自定义密钥键：必须从 UserConfig 汇总后同时喂给两份配置的脱敏——
    // 生成配置里 customSettings 包装已被剥离，就地读不到 secretKeys（见 redact::collect_custom_secret_keys）。
    let extra = crate::redact::collect_custom_secret_keys(&src.user_config);
    let input = DiagnosticReportInput {
        generated_at: src.generated_at.clone(),
        app: src.app.clone(),
        runtime: src.runtime.clone(),
        redacted_user_config: crate::redact::redact_deep(&src.user_config, &extra),
        redacted_singbox_config: crate::redact::redact_deep(&src.singbox_config, &extra),
        app_log_tail: src.app_log_tail.clone(),
        singbox_log_tail: src.singbox_log_tail.clone(),
        node_identifiers: crate::redact::collect_node_identifiers(
            &src.user_config,
            &src.extra_addresses,
        ),
        hint: src.hint.clone(),
    };
    build_diagnostic_report(&input)
}

fn zh_bool(v: bool) -> &'static str {
    if v {
        "是"
    } else {
        "否"
    }
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|e| format!("(序列化失败: {e})"))
}

#[cfg(test)]
mod tests;
