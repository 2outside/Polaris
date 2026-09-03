//! 换核落位编排：备份 → 原子替换 → chmod/重签 → 回滚（移植 上游 `CoreUpdateService` 的落位段）。
//!
//! # 边界（本模块**不做**什么）
//!
//! - **不停/起核**：`LifecycleGate` + `ProxyRuntime` 的停起协同归 command 层（`commands/updater.rs`）。
//!   本模块只做「文件层的换与还原」，故可在本机零起核完整单测。
//! - **不发 HTTP**：字节由调用方给（在线更新经 `CoreDownloader`，手动换核经本地文件）。
//!
//! # 提权：不需要
//!
//! 落位目标是 `<config_dir>/core_update/`（用户可写），三平台统一 ⇒ **换核/回滚/reset 全程零提权**。
//! helper 的受保护核目录（`crates/helper/src/core_install.rs`）是可选 hardening，不是本路径的前置。
//!
//! # 归档解压：用 OS 自带 `tar`，不引新 Rust 依赖
//!
//! sing-box 的官方 release 资产是 `.tar.gz`（Linux/macOS）/ `.zip`（Windows），不是裸二进制。
//! 解压不引 `tar`/`zip`/`flate2` crate —— **bsdtar 三平台自带**（Windows 10 1803+ 的 `tar.exe` 即 bsdtar，
//! 能解 zip），与 `scripts/fetch-core.mjs` 构建期的做法同源（简约阶梯：原生 > 新依赖）。
//! 命令选择是纯函数 [`archive_extract_command`]，产物定位是纯函数 [`pick_core_from_dir`]，
//! 二者均有单测；真正的 `tar` 调用是薄执行腿。

use std::path::{Path, PathBuf};

use polaris_updater::traits::StdFs;
use polaris_updater::verify::atomic_replace;

use crate::runtime::core_paths::{
    backup_path_for, core_update_dir_in, make_executable, post_install_macos,
    writable_core_path_in, write_seed_marker, CoreSeedMarker,
};

/// 换核来源（写进播种簿记的 `source` 字段 + 日志）。
///
/// ⚠️ **[`Manual`](SwapSource::Manual) 参与决策**：`core_paths::decide_reseed` 据它豁免
/// 「用户手动上传替换的核」，使其不被随包基线覆盖（判据见那里的函数文档）。其余取值仅供诊断。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapSource {
    /// 在线内核更新。
    Update,
    /// 用户手动上传替换。**reseed 豁免来源**。
    Manual,
    /// 恢复出厂（随包核）。
    ResetFactory,
    /// 回滚到备份。
    Rollback,
}

impl SwapSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Update => "update",
            // 取读侧常量而非再写一份字面量：两处各写会「改一处漏一处」，且症状静默
            // （豁免恒不命中 ⇒ 手动核照旧被覆盖，两侧单测都还绿）。
            Self::Manual => crate::runtime::core_paths::SOURCE_MANUAL,
            Self::ResetFactory => "reset-factory",
            Self::Rollback => "rollback",
        }
    }
}

/// 一次换核的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapResult {
    /// 现役核路径。
    pub core_path: PathBuf,
    /// 是否留下了可回滚的备份。
    pub backed_up: bool,
}

// ── 归档解压（纯决策 + 薄执行腿）────────────────────────────────────────────

/// 由归档文件名决定解压命令（**纯函数**）。
///
/// 三平台统一走 `tar -xf`：bsdtar 同时认 `.tar.gz` 与 `.zip`，故无需按平台分支两套命令。
///
/// # Errors
///
/// 无法识别的归档后缀（**不猜**：猜错就是把随便一个文件当核落位）。
pub fn archive_extract_command(archive_name: &str) -> Result<(&'static str, Vec<String>), String> {
    let lower = archive_name.to_ascii_lowercase();
    if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") || lower.ends_with(".zip") {
        Ok(("tar", vec!["-xf".into()]))
    } else {
        Err(format!(
            "无法识别的内核归档形态: {archive_name}（仅支持 .tar.gz / .tgz / .zip）"
        ))
    }
}

/// 归档是否**不需要**解压（资产本身就是裸二进制；手动换核路径常见）。
#[must_use]
pub fn is_raw_binary_asset(name: &str) -> bool {
    archive_extract_command(name).is_err()
}

/// 在解压产物里定位核二进制（**纯函数**：吃相对路径清单，不碰 FS）。
///
/// sing-box 官方归档的布局是 `sing-box-<ver>-<os>-<arch>/sing-box`（带一层顶层目录），
/// 但镜像/自建包可能是平铺的 —— 两种都认，**最多下探一层**（再深就不是官方结构，宁可报错也不乱捡）。
#[must_use]
pub fn pick_core_from_listing(entries: &[PathBuf], core_filename: &str) -> Option<PathBuf> {
    // 平铺优先（更明确）。
    if let Some(p) = entries
        .iter()
        .find(|p| p.components().count() == 1 && p.file_name().is_some_and(|n| n == core_filename))
    {
        return Some(p.clone());
    }
    entries
        .iter()
        .find(|p| p.components().count() == 2 && p.file_name().is_some_and(|n| n == core_filename))
        .cloned()
}

/// 在已解压目录里定位核（**薄 FS 腿**：读目录 → 交给 [`pick_core_from_listing`] 决策）。
///
/// # Errors
///
/// 读目录失败 / 产物里没有核（官方资产结构变化）。
pub fn pick_core_from_dir(root: &Path, core_filename: &str) -> Result<PathBuf, String> {
    let mut rel: Vec<PathBuf> = Vec::new();
    let top =
        std::fs::read_dir(root).map_err(|e| format!("读解压目录失败 {}: {e}", root.display()))?;
    for ent in top.flatten() {
        let name = PathBuf::from(ent.file_name());
        if ent.path().is_file() {
            rel.push(name.clone());
        } else if ent.path().is_dir() {
            if let Ok(inner) = std::fs::read_dir(ent.path()) {
                for e2 in inner.flatten() {
                    if e2.path().is_file() {
                        rel.push(name.join(e2.file_name()));
                    }
                }
            }
        }
    }
    pick_core_from_listing(&rel, core_filename)
        .map(|p| root.join(p))
        .ok_or_else(|| format!("解压产物未找到 {core_filename}（官方资产结构可能已变化）"))
}

/// 解压归档到目录（**执行腿**：调 OS 自带 `tar`）。
///
/// # Errors
///
/// 归档形态不认识 / `tar` 不可用 / 解压非零退出。
pub fn extract_archive(archive: &Path, dest_dir: &Path) -> Result<(), String> {
    let name = archive
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (program, args) = archive_extract_command(&name)?;
    std::fs::create_dir_all(dest_dir)
        .map_err(|e| format!("建解压目录失败 {}: {e}", dest_dir.display()))?;
    let out = crate::runtime::win_console::no_console_window(
        std::process::Command::new(program)
            .args(&args)
            .arg(archive)
            .arg("-C")
            .arg(dest_dir),
    )
    .output()
    .map_err(|e| format!("调用 {program} 解压失败: {e}（系统缺 tar？）"))?;
    if !out.status.success() {
        return Err(format!(
            "解压 {name} 失败（{}）：{}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

// ── 换核 / 回滚 / 重置 ───────────────────────────────────────────────────────

/// 落位后**簿记回写值**（纯函数）：`None` = 无需回写，沿用 [`install_core_bytes`] 已写的。
///
/// - `declared`：调用方声明的版本行（release tag / 上传文件名 token / staged 记录 / 随包基线）。
/// - `probed`：落位**之后**对盘上那个二进制实跑 `sing-box version` 读回的**原始首行**
///   （必须来自 `UpdaterRuntime::read_core_version_line` —— 探测失败返空串那一个；
///   **绝不可**用 `read_core_version`，它探测失败会回落随包基线，把「读不到」伪装成「就是基线」）。
///
/// 规则：`declared` 非空 ⇒ `None`（调用方已有准确值，不覆盖 —— 手动上传核的文件名 token 即此类）；
/// `declared` 空 ⇒ 用 `probed`；两者都空 ⇒ `None`（**诚实保留 unknown，不编造**）。
///
/// # 为什么必须有这一步：空簿记 = 该核被静默永久钉住
///
/// 簿记 `version_line` 为空 ⇒ [`classify_core_build`](polaris_updater::core_build::classify_core_build)
/// 判 `Unknown` ⇒ `decide_core_override` 对 unknown 恒 `reseed:false` ⇒
/// [`decide_reseed`](crate::runtime::core_paths::decide_reseed) 恒 `Keep`。而
/// [`resolve_core_binary`](crate::runtime::proxy::resolve_core_binary) 第 2 级优先可写核 ⇒
/// **之后把 `bundledCoreVersion` 提到多高都不会再播种，而盘面与 UI 都看不出来。**
///
/// 而「声明值为空」不是边角情况，是**两条主路径的常态**：
///  - `core_update_run`：前端恒传 `downloadUrl`（`SettingsUpdate.tsx` → `api-client.ts`），
///    后端那一支 `latest` 恒为空串 ⇒ 凡从设置页点过「更新内核」的机器都中；
///  - `core_rollback`：调用点直接传字面 `""`。
///
/// 版本的**唯一可靠真值是盘上那个二进制自己**，故这里以实读为准。刻意**不**走「让前端把
/// `coreLatest.version` 透传下来」：那是在契约上再加一个可漏传的参数，而正确答案就在盘上。
#[must_use]
pub fn marker_rewrite_line<'a>(declared: &str, probed: &'a str) -> Option<&'a str> {
    if !declared.trim().is_empty() {
        return None;
    }
    let p = probed.trim();
    if p.is_empty() {
        return None;
    }
    Some(p)
}

/// [`marker_rewrite_line`] 的**薄执行腿**：需要回写就回写，返回是否真写了。
///
/// 拆成独立函数（而非在 Tauri 命令里内联）有两个实打实的理由：`SwapSource::as_str` 得以保持私有；
/// 且「回写」这条路径能被 tempdir 单测**按生产代码本身**驱动，而不是在测试里手抄一份。
///
/// # Errors
///
/// 写簿记失败（磁盘满 / 权限）。调用方**不该**据此中止换核 —— 核已落位且已验证起得来，
/// 此刻中止只会丢掉一次成功的换核；但必须如实告警（簿记仍空 ⇒ 该核不被后续基线重播种）。
pub fn rewrite_marker_from_probe(
    base: &Path,
    declared: &str,
    probed: &str,
    source: SwapSource,
) -> Result<bool, String> {
    let Some(line) = marker_rewrite_line(declared, probed) else {
        return Ok(false);
    };
    write_seed_marker(
        base,
        &CoreSeedMarker {
            version_line: line.to_string(),
            source: source.as_str().to_string(),
        },
    )?;
    log::info!("换核簿记已按盘上实读补齐：{line}");
    Ok(true)
}

/// 把 `bytes` 落位为现役核（备份 → 原子替换 → chmod → macOS 后处理 → 更新播种簿记）。
///
/// 语义严格对齐 上游 `CoreUpdateService.installCoreFromDir` + `backupCurrentCore`：
///  - `skip_backup=true`（reset-factory 专用）：**不备份**（现役核是用户要丢弃的，出厂核已知稳定），
///    并顺手 [`prune_backup`] 清残留 `.bak`（= 上游 `:1475-1484`）。
///  - 否则：现役核先复制成 `<core>.bak`（回滚源），再原子替换。
///
/// `version_line` 是新核的原始版本行（用于播种簿记 → 决定后续 app 升级是否重播种）；
/// 不知道时传空串，**但调用方随后必须按 [`marker_rewrite_line`] 用盘上实读补齐** ——
/// 空簿记会让这个核被永久钉住（成因见该函数文档），那不是失败安全，是静默失效。
///
/// # Errors
///
/// 建目录 / 备份 / 原子替换 / chmod / 写簿记 失败。
pub fn install_core_bytes(
    base: &Path,
    os: &str,
    bytes: &[u8],
    version_line: &str,
    source: SwapSource,
    skip_backup: bool,
) -> Result<SwapResult, String> {
    let dest = writable_core_path_in(base, os);
    let dir = core_update_dir_in(base);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("建可写核目录失败 {}: {e}", dir.display()))?;

    let backup = backup_path_for(&dest);
    let mut backed_up = false;
    if skip_backup {
        // reset-factory：不备份 + 清残留（否则会留下指向「用户已放弃的核」的陈旧回滚项）。
        prune_backup(base, os);
    } else if dest.is_file() {
        std::fs::copy(&dest, &backup).map_err(|e| {
            format!(
                "备份现役核失败 {} → {}: {e}",
                dest.display(),
                backup.display()
            )
        })?;
        backed_up = true;
    }

    // tmp → rename（同目录 rename 原子；杜绝「写到一半」的半截核）。
    atomic_replace(&StdFs, &dest, bytes)
        .map_err(|e| format!("原子替换内核失败 {}: {e}", dest.display()))?;
    make_executable(&dest)?;
    post_install_macos(&dest);

    write_seed_marker(
        base,
        &CoreSeedMarker {
            version_line: version_line.to_string(),
            source: source.as_str().to_string(),
        },
    )?;
    log::info!(
        "内核已换（{}）：{}（备份={backed_up}）",
        source.as_str(),
        dest.display()
    );
    Ok(SwapResult {
        core_path: dest,
        backed_up,
    })
}

/// 是否存在可回滚的备份（**纯 FS 查询**）。
#[must_use]
pub fn has_backup(base: &Path, os: &str) -> bool {
    backup_path_for(&writable_core_path_in(base, os)).is_file()
}

/// 回滚到备份核：`<core>.bak` → `<core>`（**备份消费后即删**，= 上游 `rollbackCore`）。
///
/// 回滚后**不再留备份**：旧核已成为现役核，把它同时留在 `.bak` 只会让 UI 显示一个「回滚到自己」
/// 的假选项（上游 同语义）。
///
/// # Errors
///
/// 无备份 / 读备份失败 / 原子替换失败。
pub fn rollback_core(base: &Path, os: &str, version_line: &str) -> Result<SwapResult, String> {
    let dest = writable_core_path_in(base, os);
    let backup = backup_path_for(&dest);
    if !backup.is_file() {
        return Err("无可回滚的内核备份".to_string());
    }
    let bytes = std::fs::read(&backup)
        .map_err(|e| format!("读取内核备份失败 {}: {e}", backup.display()))?;
    atomic_replace(&StdFs, &dest, &bytes)
        .map_err(|e| format!("回滚原子替换失败 {}: {e}", dest.display()))?;
    make_executable(&dest)?;
    post_install_macos(&dest);
    let _ = std::fs::remove_file(&backup);
    write_seed_marker(
        base,
        &CoreSeedMarker {
            version_line: version_line.to_string(),
            source: SwapSource::Rollback.as_str().to_string(),
        },
    )?;
    Ok(SwapResult {
        core_path: dest,
        backed_up: false,
    })
}

/// 清备份残留（reset-factory 末尾调用；= 上游 `pruneBackup`）。失败无害（best-effort）。
pub fn prune_backup(base: &Path, os: &str) {
    let backup = backup_path_for(&writable_core_path_in(base, os));
    if backup.exists() {
        let _ = std::fs::remove_file(&backup);
    }
}

#[cfg(test)]
mod tests;
