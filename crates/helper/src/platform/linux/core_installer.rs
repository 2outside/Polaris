//! install-core —— linux 薄壳：公共核心下沉 [`crate::core_install`]，本文件
//! 只留 linux 平台 hook（保守 lib*.so 清理）。
//!
//! ## 公共核心（已下沉）
//!
//! sha256 校验 / 枚举源目录 / 逐文件原子安装 一律走 [`crate::core_install`]，
//! 结果类型直接用公共 [`InstallResult`]。mac/linux 两份原本逐字同，合并后单一真值。
//!
//! 原先此处另有个 `InstallOutcome` 影子枚举：与 [`InstallResult`] **10 个 variant 逐一同构**
//!（唯一差异是拼写 `CoredirUnset` vs `CoreDirUnset`，纯历史命名不一致，wire 输出本就相同），
//! 外加 `to_common`/`from_common` 双向映射把公共枚举翻来覆去搬一遍。影子枚举 + 双射已删（G3.4）：
//! `install_core` 直接返回 `InstallResult`，各步的 `Err(e) => return e` 一步到位。
//!
//! ## linux 专属（本 crate 保留）
//!
//! - **保守 prune**：linux 仅清 `sing-box` / `lib*` 前缀残留（防误删同目录 helper 二进制），
//!   不用公共通用版 `prune_extra_files`（那个会删 keep_names 外的所有文件）。此安全语义为
//!   linux 专属，保留本 crate。
//!
//! ## 安全模型（对照 Go 源注释 :9-18）
//!
//! - 核二进制在 root-owned 受管目录（coreDir），普通用户改不动 → 杜绝「借 helper 给任意自有二进制赋 CAP_NET_ADMIN」。
//! - start 只跑锁定的 `coreDir/sing-box`，绝不跑客户端指定的任意路径（见 handler.rs 的 start 路径锁）。
//! - install-core 校验 `sha256(srcDir/sing-box) == wantHash` 后，逐文件 `.new + rename` 原子就位（防 TOCTOU）。
//! - 只写 coreDir、不接受任意路径；清陈旧残留仅删核配套（sing-box / lib*.so*），不碰 helper 自身二进制。

use std::fs;
use std::path::Path;

// 公共核心走同 crate 的共用层（合并前是 `pub use polaris_helper_common::core_install::{...}` 的
// 转发块 —— 单 crate 后转发已无意义，降为普通 `use`，不再对外重复导出一份公共符号）。
use crate::core_install::{
    atomic_install_files, list_src_files, verify_singbox_hash, InstallResult, SINGBOX_BIN_NAME,
};
use polaris_helper_proto::codec::is_valid_sha256_hex;

/// 执行 install-core（移植自 Go `installCore`，:183-244）。
///
/// 参数：
/// - `core_dir`：锁定的 root-owned 受管核目录（None = 未配置 → `ERR coredir-unset`）。
/// - `src_dir`：app 下载+预检的临时核源目录。
/// - `want_hash`：期望的 sing-box sha256（hex，64 字符）。
///
/// 文件操作：建 coreDir → 读 srcDir/sing-box 校验 sha256 → 逐文件 `.new + rename` 原子就位 →
/// 清陈旧残留（linux 保守策略：仅 sing-box / lib* 前缀）。公共核心步骤走 helper-common，
/// 本函数只加参数适配 + linux 专属保守 prune。
pub fn install_core(core_dir: Option<&Path>, src_dir: &str, want_hash: &str) -> InstallResult {
    // :184-185: coreDir 未配置。
    let Some(core_dir) = core_dir else {
        return InstallResult::CoreDirUnset;
    };
    // :187-188: bad-args —— srcDir 空 或 wantHash 非 64 hex 字符。
    if src_dir.is_empty() || !is_valid_sha256_hex(want_hash) {
        return InstallResult::BadArgs;
    }
    let src = Path::new(src_dir);

    // 公共核心：校验 sing-box 哈希（:190-196）。各 Err 已是 InstallResult，原样返回。
    let sb_data = match verify_singbox_hash(src, want_hash) {
        Ok(d) => d,
        Err(e) => return e,
    };

    // 公共核心：枚举源目录（:198-200）。
    let names = match list_src_files(src) {
        Ok(n) => n,
        Err(e) => return e,
    };

    // 公共核心：逐文件 .new + rename 原子就位（:202-228，含 MkdirAll coreDir）。
    if let Err(e) = atomic_install_files(src, core_dir, &names, &sb_data) {
        return e;
    }

    // :230-242: linux 专属保守 prune —— 仅清 sing-box / lib* 前缀残留（防误删同目录 helper 二进制）。
    // 不走公共通用 prune_extra_files（那个会删 keep_names 外的全部文件，对 linux 太宽）。
    prune_lib_and_singbox(core_dir, &names);

    InstallResult::Installed
}

/// 清 coreDir 里非本次 srcDir 的旧核配套残留（rollback 后陈旧 lib*.so 等）—— linux 保守策略。
///
/// 仅删 `sing-box` 或 `lib*` 前缀（Go: `n == "sing-box" || strings.HasPrefix(n, "lib")`）；
/// 保留本次 src_names 命中的；跳过子目录与 .new 临时件。best-effort，单项失败跳过。
fn prune_lib_and_singbox(core_dir: &Path, src_names: &[String]) {
    let Ok(old) = fs::read_dir(core_dir) else {
        return;
    };
    for ent_res in old {
        let Ok(ent) = ent_res else { continue };
        let Ok(ft) = ent.file_type() else { continue };
        if ft.is_dir() {
            continue;
        }
        let n = ent.file_name().to_string_lossy().into_owned();
        // 保留本次安装的 + .new 临时件（上方刚 rename 完，理论上无 .new 残留）。
        if src_names.iter().any(|s| s == &n) || n.ends_with(".new") {
            continue;
        }
        // 仅清核配套：sing-box 或 lib* 前缀（Go: n == "sing-box" || strings.HasPrefix(n, "lib")）。
        if n == SINGBOX_BIN_NAME || n.starts_with("lib") {
            let _ = fs::remove_file(core_dir.join(&n));
        }
    }
}

#[cfg(test)]
mod tests;
