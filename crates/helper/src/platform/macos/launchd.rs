//! launchd plist **纯渲染**（移植自 上游 `helper/main.go` 的 plist 结构）。
//!
//! ## 职责（C6-4 收敛后：纯渲染，不含编排）
//!
//! 生成 macOS root LaunchDaemon 的 plist 字符串（`Label` / `ProgramArguments` / `RunAtLoad` / `KeepAlive`），
//! 外加 plist 路径、launchctl `bootstrap`/`bootout` 参数构造。**不含**「写 plist 文件 + 跑 launchctl」的系统
//! 编排 —— 那属安装流程，是单一编排真值源 `HelperManager`（`polaris-helper-client` crate）的职责（C6-4 双
//! install SoT 收敛：install/uninstall 的 launchctl bootstrap 侧移入 HelperManager 的 root 安装脚本，见 design
//! `polaris-c6-helper-migration-plan.md` §3.3）。
//!
//! 安装走 osascript 一次授权（`do shell script ... with administrator privileges`），之后 launchd 常驻、
//! socket 命令免再次授权（Go `helper.go:2` 注释）。
//!
//! ## 移植纪律
//!
//! 全模块**纯字符串构造**（跨平台可测，零系统副作用、零 `CommandRunner` 依赖）。

use std::path::PathBuf;

/// LaunchDaemon 默认安装目录（`/Library/LaunchDaemons`）。
pub const LAUNCHDAEMONS_DIR: &str = "/Library/LaunchDaemons";

/// launchctl 程序路径。
pub const LAUNCHCTL_BIN: &str = "/bin/launchctl";

/// LaunchDaemon 的 label（Reverse-DNS 风格，Polaris 用 `com.polaris.helper`，Polaris 沿用兼容）。
pub const DEFAULT_LABEL: &str = "com.polaris.helper";

/// plist 配置（生成 LaunchDaemon plist 所需的全部字段）。
#[derive(Debug, Clone)]
pub struct PlistConfig {
    /// Label（CFBundleIdentifier 风格）。
    pub label: String,
    /// helper 二进制路径（ProgramArguments[0]）。
    pub program: String,
    /// 传给 helper 的参数（`--singbox` / `--confdir` / `--support` / `--coredir`）。
    pub args: Vec<String>,
    /// 是否 RunAtLoad（true = 开机自启）。
    pub run_at_load: bool,
    /// 是否 KeepAlive（true = 崩溃自动重启，对齐 launchd 守护进程语义）。
    pub keep_alive: bool,
}

impl PlistConfig {
    /// 构造默认 Polaris helper plist 配置。
    #[must_use]
    pub fn new(label: &str, program: &str, args: Vec<String>) -> Self {
        Self {
            label: label.to_owned(),
            program: program.to_owned(),
            args,
            run_at_load: true,
            keep_alive: true,
        }
    }
}

/// 生成 LaunchDaemon plist XML（纯字符串构造，跨平台可测）。
///
/// 对照 Polaris 部署的 plist 结构（osascript 安装期生成）。字段：
/// - `Label`：launchd 标识
/// - `ProgramArguments`：argv 数组
/// - `RunAtLoad`：开机自启
/// - `KeepAlive`：崩溃重启
///
/// 注：Polaris Go 源 `helper/main.go` 的 plist 由 app 侧 osascript 脚本生成（不在 Go helper 本体），
/// 此处把生成逻辑固化到 Rust 侧（day-1 收益：消灭「plist 模板在 TS/Go 两侧手同步」的 drift）。
#[must_use]
pub fn render_plist(cfg: &PlistConfig) -> String {
    let mut args_xml = String::new();
    args_xml.push_str("    <key>ProgramArguments</key>\n    <array>\n");
    // ProgramArguments[0] 是 program 路径
    args_xml.push_str(&format!(
        "      <string>{}</string>\n",
        escape_xml(&cfg.program)
    ));
    for arg in &cfg.args {
        args_xml.push_str(&format!("      <string>{}</string>\n", escape_xml(arg)));
    }
    args_xml.push_str("    </array>\n");

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
    <key>Label</key>\n    <string>{label}</string>\n\
{args_xml}\
    <key>RunAtLoad</key>\n    <{run_at_load}/>\n\
    <key>KeepAlive</key>\n    <{keep_alive}/>\n\
</dict>\n\
</plist>\n",
        label = escape_xml(&cfg.label),
        args_xml = args_xml,
        run_at_load = if cfg.run_at_load { "true" } else { "false" },
        keep_alive = if cfg.keep_alive { "true" } else { "false" },
    )
}

/// plist 文件路径（`/Library/LaunchDaemons/<label>.plist`）。
#[must_use]
pub fn plist_path(label: &str) -> PathBuf {
    // ⚠️ **整串拼接而不是 `from(dir).join(leaf)`**：这条路径要交给 macOS 的 launchctl，
    // 分隔符必须恒为 `/`；而 `join` 用**宿主平台**的分隔符 —— 本模块无 cfg 门控、三平台都编译，
    // 在 Windows 上会产出 `/Library/LaunchDaemons\<label>.plist`。生产只在 mac 跑，不是线上缺陷，
    // 但它让 Windows CI 腿的测试恒红（见 `bootstrap_args_format` 的注释）。
    PathBuf::from(format!("{LAUNCHDAEMONS_DIR}/{label}.plist"))
}

/// XML 字符转义（防 label/路径里的 `<`/`&` 破坏 plist）。
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// launchctl bootstrap 参数（macOS 13+ 用 `bootstrap`，替换老 `load`）。
#[must_use]
pub fn bootstrap_args(label: &str) -> Vec<String> {
    let path = plist_path(label);
    vec![
        "bootstrap".to_owned(),
        "system/".to_owned() + label,
        path.to_string_lossy().into_owned(),
    ]
}

/// launchctl bootout 参数（卸载，macOS 13+ 替换老 `unload`）。
#[must_use]
pub fn bootout_args(label: &str) -> Vec<String> {
    vec!["bootout".to_owned(), "system/".to_owned() + label]
}

// 注：install/uninstall 的「写 plist + launchctl bootstrap/bootout」系统编排已移入单一编排真值源
// HelperManager（C6-4 双 install SoT 收敛）—— 本模块只保留纯渲染（render_plist / plist_path /
// bootstrap_args / bootout_args），零系统副作用。

#[cfg(test)]
mod tests;
