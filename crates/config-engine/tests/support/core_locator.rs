//! 随包 `sing-box` 定位的单一事实源。
//!
//! 这些集成测试在不同平台各自执行；macOS 不能按「哪个文件先存在」选核，
//! 因为打包目录同时带 arm64/x64 两份二进制。package 优先传入打包目标，不能只看 runner 架构。

use std::path::{Path, PathBuf};
use std::process::Command;

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("CARGO_MANIFEST_DIR 应形如 <repo>/crates/config-engine")
        .to_path_buf()
}

/// 打包工作流传入的目标标签优先；本地/非 package 调用才按宿主推断。
pub fn kernel_gate_target() -> String {
    if let Ok(target) = std::env::var("POLARIS_KERNEL_GATE_TARGET") {
        assert!(
            matches!(target.as_str(), "linux" | "windows" | "macos-arm64" | "macos-x64"),
            "POLARIS_KERNEL_GATE_TARGET 必须是 linux/windows/macos-arm64/macos-x64，收到 {target:?}"
        );
        return target;
    }
    if cfg!(target_os = "windows") {
        "windows".to_owned()
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        "macos-arm64".to_owned()
    } else if cfg!(target_os = "macos") {
        "macos-x64".to_owned()
    } else {
        "linux".to_owned()
    }
}

/// 打包目标 → 唯一允许执行/读取的随包核相对路径。
///
/// 返回 slice 是为调用端保留「候选」的统一接口；每个目标只有一个元素，绝不允许跨架构回退。
pub fn bundled_core_candidates_for(target: &str) -> &'static [&'static str] {
    match target {
        "windows" => &["resources/win/sing-box.exe"],
        "macos-arm64" => &["resources/mac-arm64/sing-box"],
        "macos-x64" => &["resources/mac-x64/sing-box"],
        "linux" => &["resources/linux/sing-box"],
        _ => panic!("未知随包核目标：{target}"),
    }
}

/// 当前打包目标对应的随包核；缺失时不尝试另一架构。
pub fn bundled_core() -> Option<PathBuf> {
    bundled_core_candidates_for(&kernel_gate_target())
        .iter()
        .map(|path| repo_root().join(path))
        .find(|path| path.is_file())
}

/// macOS x64 package job 实际在 arm64 runner 上，只有它需要 Rosetta。
pub fn target_needs_rosetta(target: &str) -> bool {
    match target {
        "linux" | "windows" | "macos-arm64" => false,
        "macos-x64" => true,
        _ => panic!("未知随包核目标：{target}"),
    }
}

/// 为显式目标核构造命令。macOS x64 交叉构建 job 运行在 arm64 runner，必须经 Rosetta。
pub fn command_for_core_target(target: &str, core: &Path) -> Command {
    if target_needs_rosetta(target) {
        let mut command = Command::new("/usr/bin/arch");
        command.arg("-x86_64").arg(core);
        command
    } else {
        Command::new(core)
    }
}

/// 为当前 package/local 目标核构造命令。
#[allow(dead_code)] // core_dep_fingerprint 单独编译此模块，只读二进制而不执行它。
pub fn command_for_core(core: &Path) -> Command {
    command_for_core_target(&kernel_gate_target(), core)
}

/// 缺核时的统一处置：硬化门红，开发机明确跳过。
pub fn core_or_skip(what: &str) -> Option<PathBuf> {
    if let Some(core) = bundled_core() {
        return Some(core);
    }
    let required = std::env::var("POLARIS_REQUIRE_KERNEL_GATE").is_ok_and(|value| value == "1");
    assert!(
        !required,
        "POLARIS_REQUIRE_KERNEL_GATE=1 但盘上没有当前目标对应的随包核 —— \\
         打包腿的 `node scripts/fetch-core.mjs` 是不是失败了？（{what} 未执行）"
    );
    eprintln!(
        "⚠ 跳过 {what}：盘上没有当前目标对应的随包核（`.gitignore` 的 /resources/*）。\\
         跑 `node scripts/fetch-core.mjs` 后本门自动生效；打包腿带 POLARIS_REQUIRE_KERNEL_GATE=1 强制生效。"
    );
    None
}
