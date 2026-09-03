//! 路径 / 接口白名单（移植自 上游 `helper/helper.go:245-272`）。
//!
//! ## 职责
//!
//! 1. **`cfg_allowed`**：start 的 cfg 路径必须落在 `--confdir` 白名单目录内（防越权指定任意路径作
//!    root 配置，`helper.go:245-252`）。清洗后前缀匹配。
//! 2. **iface 白名单**：route-add/del 的接口名仅允许 Polaris 自家接口（复用 proto crate 的
//!    [`is_mac_iface_allowed`](polaris_helper_proto::codec::is_mac_iface_allowed)，逐字移植
//!    `helper.go:255-272`）。
//!
//! ## 移植纪律
//!
//! Go 用 `filepath.Clean` + `filepath.Join` + `strings.HasPrefix` 做路径前缀匹配。Rust 等价用
//! `std::path::Path::components` 收集规范化段（`.` 折叠、`..` 不展开但清洗后仍可比对）。
//! 关键：Go 的 `filepath.Clean("/a/b/../c")` → `/a/c`，Rust `Path::components()` 会保留 `..`，
//! 故这里手动实现等价 Clean（NormalizeComponents）—— 见 [`normalize_path`]。

use std::path::{Path, PathBuf};

/// 判断 cfg 路径是否在 conf_dir 白名单内（移植自 `helper.go:245-252` 的 `cfgAllowed`）。
///
/// 对照 Go：
/// ```text
/// func cfgAllowed(cfg string) bool {
///     if confDir == "" { return true }
///     clean := filepath.Clean(cfg)
///     base := filepath.Clean(confDir) + string(os.PathSeparator)
///     return strings.HasPrefix(clean, base)
/// }
/// ```
///
/// conf_dir 为空 → 一律拒绝。它是 root helper 的文件系统权限边界，若把缺失
/// `--confdir` 解释成「无白名单」，持 token 的普通用户便能让 root 核读任意路径、写任意日志。
/// 否则 cfg 与 conf_dir 各自 Clean 后，cfg 须以 `<conf_dir>/` 为前缀（含分隔符防 `/foo` 误匹配 `/foobar`）。
#[must_use]
pub fn cfg_allowed(cfg: &str, conf_dir: &str) -> bool {
    if conf_dir.is_empty() {
        return false;
    }
    let clean_cfg = normalize_path(cfg);
    let clean_base = normalize_path(conf_dir);
    // Go: base = Clean(confDir) + PathSeparator；cfg 须 HasPrefix base。
    // 即 cfg == base 或 cfg 以 "base/" 开头。cfg == base 本身（无文件名）也应算越权（cfg 是文件不是目录），
    // 但 Go 的 HasPrefix 在 cfg==base 时也返回 true —— 严格对照 Go 行为，此处同样放行。
    if clean_cfg == clean_base {
        return true;
    }
    // Go: base = Clean(confDir) + PathSeparator；cfg 须 HasPrefix base。
    // 构造 "base/" 字符串做前缀比对（防 /foo 误匹配 /foobar）。
    let base_with_sep = format!("{}{}", clean_base.display(), std::path::MAIN_SEPARATOR);
    clean_cfg.starts_with(base_with_sep)
}

/// 判断接口名是否在 macOS 白名单内（委托 proto crate，逐字移植 `helper.go:255-272`）。
///
/// 仅允许 `polaris-ts` / `polaris-wg` / `utunN`（N 为 1-3 位数字）。详见
/// [`polaris_helper_proto::codec::is_mac_iface_allowed`]。
#[must_use]
pub fn iface_allowed(s: &str) -> bool {
    polaris_helper_proto::codec::is_mac_iface_allowed(s)
}

/// 路径规范化（移植自 Go `filepath.Clean`）。
///
/// Go `filepath.Clean` 语义：折叠 `.`、解析 `..`（向上消解前一段，根的 `..` 仍是根）、合并连续分隔符、
/// 去尾随分隔符（根 `/` 除外）。返回的字符串是规范形式，前缀比对可靠。
///
/// 用 `Vec<Component>` 栈式消解 `..`：遇 `CurDir`/`RootDir`/分隔符折叠跳过，遇 `..` 弹栈（栈空且绝对路径则
/// 保留在根，等价 Go `/..` → `/`）。
fn normalize_path(p: &str) -> PathBuf {
    let path = Path::new(p);
    let mut stack: Vec<std::path::Component<'_>> = Vec::new();
    for comp in path.components() {
        match comp {
            std::path::Component::CurDir => { /* 折叠 `.` */ }
            std::path::Component::ParentDir => {
                // Go filepath.Clean 语义：
                // - 栈顶是 Normal 段 → 弹栈消解（a/../b → a/b）
                // - 栈顶是 RootDir 或栈空 → Go 的 Clean 丢弃此 ..（`/..` → `/`，根的 .. 仍是根）
                // - 栈顶是已存在的 .. → Go Clean 会保留连续 ..（`../..` → `../..`）
                match stack.last() {
                    Some(std::path::Component::Normal(_)) => {
                        stack.pop();
                    }
                    Some(std::path::Component::RootDir) | None => {
                        // 根下的 .. 丢弃（Go: `/..` → `/`；相对路径栈空的 .. 也丢弃是 Go 的行为差异，
                        // 但本协议 cfg/confdir 都是绝对路径，根下丢弃对齐 Go）
                    }
                    _ => stack.push(comp),
                }
            }
            other => stack.push(other),
        }
    }
    let mut out = PathBuf::new();
    for comp in &stack {
        out.push(comp);
    }
    // Go Clean 对空输入返回 "."；Rust 空 PathBuf → "" ，对齐：返回 "."
    if out.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        out
    }
}

#[cfg(test)]
mod tests;
