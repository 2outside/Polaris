//! 文件系统抽象 + 原子写逻辑。
//!
//! Polaris 锚点：`main/services/ConfigManager.ts#saveConfig`（writeFileAtomic tmp→rename）
//! + `utils/atomic-write.ts` + `sweepStaleTmpFiles`。
//!
//! 纯逻辑纪律：FS 操作收口到 [`ConfigFs`] trait，运行时层注入实现、测试注入 mock。
//! [`atomic_write_plan`] 仅做「路径编排 + tmp 名生成」纯逻辑，实际读写经 trait 委派。

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

/// 文件系统抽象（运行时层注入 std::fs 实现，测试注入 mock）。
///
/// 对齐 Polaris ConfigManager 使用的 fs/promises 子集：read / write / rename / mkdir /
/// copy / access(存在性) / remove。所有方法返回 Result，错误由调用方决定是否吞掉
/// （迁移/落盘失败 best-effort，绝不清空用户配置）。
pub trait ConfigFs {
    /// 读取文件内容（utf-8）。文件不存在 → Err(StoreError::Io)。
    fn read_to_string(&self, path: &Path) -> Result<String, crate::StoreError>;

    /// 写入文件（覆盖）。需保证 mode 0o600（运行时实现负责；含密 clashApiSecret）。
    fn write(&self, path: &Path, content: &str) -> Result<(), crate::StoreError>;

    /// rename（同分区原子；跨分区可能非原子，运行时实现保证同目录）。
    fn rename(&self, from: &Path, to: &Path) -> Result<(), crate::StoreError>;

    /// 递归创建目录（已存在不报错）。
    fn create_dir_all(&self, path: &Path) -> Result<(), crate::StoreError>;

    /// 复制文件（用于损坏备份 / 迁移前备份）。
    fn copy(&self, from: &Path, to: &Path) -> Result<(), crate::StoreError>;

    /// 文件是否存在。
    fn exists(&self, path: &Path) -> bool;

    /// 删除文件（不存在视为成功，best-effort）。
    fn remove(&self, path: &Path) -> Result<(), crate::StoreError>;

    /// 列出目录下的直接子项文件名（basename，不含路径）。目录不存在/无权限 → Err。
    /// 供损坏备份清理（`prune_corrupt_backups`）枚举 `config.corrupt-*.json`。
    fn list_dir(&self, dir: &Path) -> Result<Vec<String>, crate::StoreError>;
}

/// 基于 `std::fs` 的 [`ConfigFs`] 具体实现（运行时层直接可用）。
///
/// 写入采用 0o600 权限（含密 clashApiSecret；Unix 下 open(2) 即生效，无 0644 携密窗口）。
/// Windows 下 set_permissions 为 no-op（chmod 双保险仅 Unix）。
#[derive(Debug, Default, Clone, Copy)]
pub struct StdFs;

impl StdFs {
    /// 以 0o600 权限写入文件（Unix）；Windows 忽略权限（chmod 无效）。
    fn write_secure(path: &Path, content: &str) -> Result<(), crate::StoreError> {
        use std::io::Write;
        // open(2) 即以 0o600 创建（Unix），防 0644 携密窗口。
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(path)
            .map_err(|e| crate::StoreError::Io(e.to_string()))?;
        f.write_all(content.as_bytes())
            .map_err(|e| crate::StoreError::Io(e.to_string()))?;
        Ok(())
    }
}

impl ConfigFs for StdFs {
    fn read_to_string(&self, path: &Path) -> Result<String, crate::StoreError> {
        std::fs::read_to_string(path).map_err(|e| crate::StoreError::Io(e.to_string()))
    }

    fn write(&self, path: &Path, content: &str) -> Result<(), crate::StoreError> {
        Self::write_secure(path, content)
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<(), crate::StoreError> {
        std::fs::rename(from, to).map_err(|e| crate::StoreError::Io(e.to_string()))
    }

    fn create_dir_all(&self, path: &Path) -> Result<(), crate::StoreError> {
        std::fs::create_dir_all(path).map_err(|e| crate::StoreError::Io(e.to_string()))
    }

    fn copy(&self, from: &Path, to: &Path) -> Result<(), crate::StoreError> {
        std::fs::copy(from, to)
            .map(|_| ())
            .map_err(|e| crate::StoreError::Io(e.to_string()))
    }

    fn exists(&self, path: &Path) -> bool {
        std::fs::exists(path).unwrap_or(false)
    }

    fn remove(&self, path: &Path) -> Result<(), crate::StoreError> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(crate::StoreError::Io(e.to_string())),
        }
    }

    fn list_dir(&self, dir: &Path) -> Result<Vec<String>, crate::StoreError> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).map_err(|e| crate::StoreError::Io(e.to_string()))? {
            let entry = entry.map_err(|e| crate::StoreError::Io(e.to_string()))?;
            if let Some(name) = entry.file_name().to_str() {
                out.push(name.to_string());
            }
        }
        Ok(out)
    }
}

/// 生成唯一 tmp 文件路径（`<base>.<12hex>.tmp`）。
///
/// Polaris 锚点：`saveConfig` 的 `makeTmpSuffix: () => randomBytes(6).toString('hex')`
/// + `sweepStaleTmpFiles` 正则 `^<base>\.[0-9a-f]{12}\.tmp$`。
///
/// `suffix_hex` 由调用方提供（12 位小写 hex），便于纯逻辑测试（无 RNG 依赖）。
/// 生产侧注入随机 12hex，测试注入固定值。
pub fn tmp_path(base: &Path, suffix_hex: &str) -> PathBuf {
    // 与 Polaris 一致：12 位 hex 后缀（randomBytes(6) → 12 hex chars）。
    debug_assert!(
        suffix_hex.len() == 12 && suffix_hex.bytes().all(|b| b.is_ascii_hexdigit()),
        "tmp suffix must be 12 lowercase hex chars"
    );
    let file_name = base.file_name().map_or_else(
        || format!(".{suffix_hex}.tmp"),
        |n| format!("{}.{suffix_hex}.tmp", n.to_string_lossy()),
    );
    let mut p = base.to_path_buf();
    p.set_file_name(file_name);
    p
}

/// 生成随机 12 位小写 hex tmp 后缀 —— [`tmp_path`] 文档里那句「**生产侧注入随机 12hex**」的兑现。
///
/// Polaris 锚点：`makeTmpSuffix: () => randomBytes(6).toString('hex')`（6 字节 = 12 hex）。
///
/// # 为什么它必须存在（这行代码的由来）
///
/// 在此之前**生产侧从来没有注入过随机值**：`runtime/config.rs:74/95` 传的是字面量 `"polaris"`。
/// 后果两个构型都坏，且坏法不同：
/// - **debug**：[`tmp_path`] 的 `debug_assert!` 触发 → **首启即崩**（config.json 不存在 →
///   `was_missing` → 存默认 → 撞断言）。
/// - **release**：断言被编掉 → tmp 名恒为 `config.json.polaris.tmp` → **永不匹配
///   [`is_stale_tmp`] 的 `[0-9a-f]{12}` 锚点** → 孤儿 tmp 永不被清扫；且并发保存全撞同一路径，
///   「唯一 tmp 名」的原子写设计被彻底架空。
///
/// # 实现：stdlib only（本 workspace 无 `rand`/`getrandom`，且最小依赖面是有意设计）
///
/// `RandomState::new()` 的 key 由 **OS 随机源**每进程 seed 一次，且每次 `new()` 递增 →
/// 同进程内连续调用天然不同（这点关键：退化成「同进程恒定」等于没修）。再混入 `SystemTime`
/// 纳秒做二重保险。取低 48 bit → `{:012x}` 恰好 12 位小写 hex（48 bit = 12 nibble，含前导零）。
///
/// 唯一性够用即可：这是 tmp 文件名去撞，不是密码学场景（真撞了也只是 rename 覆盖同一份内容）。
///
/// 注入式设计**刻意保留**：[`tmp_path`] / [`atomic_write_plan`] / [`crate::ConfigStore::save`]
/// 仍收 `suffix_hex` 参数，测试注入固定值（纯逻辑可测）；只有生产调用点调本函数。
pub fn random_tmp_suffix() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut h = RandomState::new().build_hasher();
    h.write_u128(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    // 低 48 bit → 恰好 12 nibble，`{:012x}` 补前导零 ⇒ len 恒 12、恒小写 hex。
    format!("{:012x}", h.finish() & 0xffff_ffff_ffff)
}

/// 清扫孤儿 tmp 文件的正则锚点（`<base>.<12hex>.tmp`）。
///
/// Polaris 锚点：`sweepStaleTmpFiles` 的正则 `^${base}\.[0-9a-f]{12}\.tmp$`。
/// 仅匹配同目录、同 basename + 12hex + .tmp 的文件；mtime>60s 守卫避免误删并发 saveConfig 在途 tmp。
/// 此处提供纯谓词 `is_stale_tmp` 供运行时层 list_dir 后筛选；mdate 判断由调用方做。
pub fn is_stale_tmp(base_name: &str, candidate: &str) -> bool {
    // ^<escaped-base>\.[0-9a-f]{12}\.tmp$
    if candidate.len() != base_name.len() + 1 + 12 + 4 {
        return false;
    }
    let suffix = ".tmp";
    let Some(rest) = candidate.strip_suffix(suffix) else {
        return false;
    };
    // rest = base_name + '.' + 12hex
    let Some(hex_part) = rest.strip_prefix(base_name) else {
        return false;
    };
    let Some(hex) = hex_part.strip_prefix('.') else {
        return false;
    };
    hex.len() == 12 && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

/// 孤儿 tmp 的 mtime 守卫下限（秒）。上游 `sweepStaleTmpFiles`：`now - mtimeMs > 60_000`。
///
/// 仅删「过老」的孤儿 tmp（进程写完 tmp 但 rename 前被硬杀/断电留下的），避免误删并发 saveConfig 在途 tmp。
pub const STALE_TMP_MIN_AGE_SECS: u64 = 60;

/// 孤儿 tmp 清扫决策（纯逻辑，运行时层供文件名 + mtime 龄期）：名匹配 [`is_stale_tmp`] **且**
/// 龄期 > [`STALE_TMP_MIN_AGE_SECS`] 才删。抽成纯函数便于变异验证（翻比较号/换阈值即转红），
/// FS 遍历/unlink 由运行时层驱动（`commands/config.rs#sweep_stale_tmp_files`）。
#[must_use]
pub fn should_sweep_stale_tmp(base_name: &str, candidate: &str, age_secs: u64) -> bool {
    is_stale_tmp(base_name, candidate) && age_secs > STALE_TMP_MIN_AGE_SECS
}

/// 原子写逻辑编排：tmp 路径 + 写 tmp + rename 替换。
///
/// Polaris 锚点：`writeFileAtomic`（mode 0o600 在 open(2) 即生效 + 非 Win chmod 双保险；
/// 后缀 `<rand6hex>.tmp` 匹配 sweepStaleTmpFiles 清扫正则）。
///
/// 防崩溃/进程被杀写到一半截断 config.json → loadConfig 校验失败回落默认配置并覆盖落盘 → 整份配置丢失
/// （节点/订阅/规则全丢）。tmp→rename 保证：要么完整新内容、要么完整旧内容，绝不半截。
///
/// `suffix_hex`：12 位随机 hex（调用方提供，便于测试）。生产侧应注入 CSPRNG 输出。
/// 纯逻辑：本函数不触碰 FS，仅返回编排好的步骤；由调用方驱动 trait 执行。
pub fn atomic_write_plan(base: &Path, suffix_hex: &str, content: &str) -> AtomicWritePlan {
    AtomicWritePlan {
        tmp_path: tmp_path(base, suffix_hex),
        final_path: base.to_path_buf(),
        content: content.to_string(),
    }
}

/// 原子写步骤编排结果（纯数据）。由 [`ConfigStore`](crate::store::ConfigStore) 实现驱动 trait 执行。
#[derive(Debug, Clone)]
pub struct AtomicWritePlan {
    /// 临时文件路径（写入目标）。
    pub tmp_path: PathBuf,
    /// 最终路径（rename 目标）。
    pub final_path: PathBuf,
    /// 写入内容。
    pub content: String,
}

impl AtomicWritePlan {
    /// 在给定 FS 上执行：mkdir(parent) → write(tmp) → rename(tmp, final)。
    /// 失败时尽力清理 tmp（best-effort，不掩盖原错误）。
    pub fn execute<F: ConfigFs + ?Sized>(&self, fs: &F) -> Result<(), crate::StoreError> {
        if let Some(parent) = self.final_path.parent() {
            fs.create_dir_all(parent)?;
        }
        let res = fs.write(&self.tmp_path, &self.content).and_then(|()| {
            fs.rename(&self.tmp_path, &self.final_path)?;
            Ok(())
        });
        if res.is_err() {
            // 清理半写 tmp（best-effort；忽略清理自身错误，不掩盖 write/rename 原错误）。
            let _ = fs.remove(&self.tmp_path);
        }
        res
    }
}

#[cfg(test)]
mod tests;
