//! SHA256 校验纯逻辑 + tmp→rename 原子替换编排。
//!
//! 移植自：
//!   - `shared/file-hash.ts:sha256File`（createHash('sha256') 整文件哈希）。
//!   - `CoreUpdateService.installCoreFromDir:453-479`（非 Windows staged-rename 落位编排）：
//!     先把全部文件复制到同目录临时名（`.polaris-new-*`，见 `tmp_name`），全部成功后逐个原子 rename 就位；
//!     复制阶段任一失败 → 删临时文件、抛错，现役核心目录完全未动（杜绝「新核心 + 旧/坏 libcronet」半替换混搭）。
//!
//! 设计：校验与 rename 编排都是纯函数（校验吃 `&[u8]` + 期望 hash；编排吃 [`UpdateFs`] trait
//! 注入），可单测。真实 sha256 算法由 `sha2` crate 提供（与 helper-linux/helper-mac 同口径）。

use std::path::Path;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::traits::UpdateFs;

// 去重：复用 polaris-helper-proto 的 is_valid_sha256_hex（旧 verify.rs 本地副本已删）。
// `pub use` 使 `crate::verify::is_valid_sha256_hex`（manifest.rs 调用路径）+ 本模块内调用都解析到 helper-proto 版。
pub use polaris_helper_proto::codec::is_valid_sha256_hex;

/// SHA256 校验错误。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    /// 期望的 hash 不是合法的 64 字符 hex（移植自 `helper.go:137` 的 `len(wantHash) != 64` 校验）。
    #[error("invalid expected hash: not 64-char hex (got {0} chars)")]
    InvalidExpectedHash(usize),
    /// 字节流/文件的实际 hash 与期望不符（移植自 `helper.go:146` 的 hash-mismatch）。
    #[error("hash mismatch: expected {expected}, actual {actual}")]
    HashMismatch { expected: String, actual: String },
}

/// 计算字节的 SHA256 hex（小写，移植自 `file-hash.ts:sha256File` 的 `.digest('hex')`）。
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// 计算字节的 SHA256 hex（小写，别名——与 helper-linux `sha256_hex` 同名同形，便于跨 crate 对照）。
#[must_use]
pub fn sha256_hex_lower(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

// `is_valid_sha256_hex`（校验 64 字符合法 hex）由本模块顶部的 `pub use` 从
// `polaris_helper_proto::codec` re-export，故 `crate::verify::is_valid_sha256_hex`（manifest.rs 的调用路径）继续可用。
// 用 `//` 而非 `///`：doc 注释必须挂在 item 上，此处后面并无 item（原为悬空 doc → clippy `empty_line_after_doc_comments`）。

/// 比对**已经算好**的实际摘要与期望摘要 —— 全 crate 摘要判定的**单点**。
///
/// # 为什么必须是单点（这不是洁癖）
///
/// 判定本身只有两行，但它有**两个变体**（[`VerifyError::InvalidExpectedHash`] =
/// 发布方把摘要写坏了 / [`VerifyError::HashMismatch`] = 包与摘要对不上），而两者的**处置相反**：
/// 前者重下一万次也不会好，后者才值得让用户重试。手搓一份
/// `!is_valid_sha256_hex(..) || !eq_ignore_ascii_case(..)` 就把这条分野压成了一个 bool ——
/// 调用方只能报一句「可能被截断或篡改」，把发布方的失误显示成投毒警告（生产的
/// `update_download` 腿此前正是这个形态）。
///
/// [`verify_bytes`] 与 [`Sha256Stream::verify`] 都委托本函数：三处各写一份必然在
/// 「大小写敏不敏感」「先验格式还是先比对」上分叉，而分叉只在真机大包上暴露。
///
/// # Errors
///
/// - [`VerifyError::InvalidExpectedHash`]：`expected_hex` 非 64 字符 hex。
/// - [`VerifyError::HashMismatch`]：实际 hash 与期望不符（大小写不敏感比对）。
pub fn verify_hex_digest(actual_hex: &str, expected_hex: &str) -> Result<(), VerifyError> {
    if !is_valid_sha256_hex(expected_hex) {
        return Err(VerifyError::InvalidExpectedHash(expected_hex.len()));
    }
    if actual_hex.eq_ignore_ascii_case(expected_hex) {
        Ok(())
    } else {
        Err(VerifyError::HashMismatch {
            expected: expected_hex.to_string(),
            actual: actual_hex.to_string(),
        })
    }
}

/// 校验字节流的 SHA256 是否等于期望（大小写不敏感，对齐 Polaris Go `strings.EqualFold`）。
///
/// 移植自 `CoreUpdateService.installCoreFromDir` 经 helper install-core 路径的 sha256 校验
/// （`helper-linux/core_installer.rs:99` 同款 `eq_ignore_ascii_case`）。
///
/// 判定委托 [`verify_hex_digest`]（单点），本函数只负责「把字节算成 hex」。
///
/// # Errors
///
/// - [`VerifyError::InvalidExpectedHash`]：`expected_hex` 非 64 字符 hex。
/// - [`VerifyError::HashMismatch`]：实际 hash 与期望不符。
pub fn verify_bytes(bytes: &[u8], expected_hex: &str) -> Result<(), VerifyError> {
    // 先验格式再算摘要：期望值本身非法时不白算一遍几十 MiB 的 sha256
    // （= 委托单点之前的行为，逐字保留）。
    verify_hex(expected_hex)?;
    verify_hex_digest(&sha256_hex(bytes), expected_hex)
}

/// **增量** SHA-256：边收边算，不要求把整个负载留在内存里。
///
/// # 为什么与 [`verify_bytes`] 并存而不是取代它
///
/// [`verify_bytes`] 吃 `&[u8]` —— 它的调用方（staged 换核周期）本来就持着整包字节（解归档要用），
/// 换成流式只会平白多一次拷贝。真正需要流式的是 **App 安装包腿**：几十 MiB 到上百 MiB 的包
/// 「整包入内存再校验落盘」把内存峰值与包体积绑死。故此处新增累加式能力，
/// **既有函数签名一个不动**。
///
/// 语义与 [`verify_bytes`] 逐字一致：[`Self::verify`] 同样先验期望 hex 的格式
/// （[`VerifyError::InvalidExpectedHash`]）、再做大小写不敏感比对
/// （[`VerifyError::HashMismatch`]）—— 两条腿判出来的结论必须是同一个，
/// 否则「内存校验过、流式校验不过」这类分叉没人能解释。
#[derive(Debug, Clone, Default)]
pub struct Sha256Stream {
    hasher: Sha256,
    len: u64,
}

impl Sha256Stream {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 喂一段字节（可调任意多次；分片方式不影响最终摘要）。
    pub fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
        self.len += bytes.len() as u64;
    }

    /// 已喂入的累计字节数。
    ///
    /// **生产消费点**：流式下载腿拿它与网络侧独立维护的 `received` 互校
    /// （`runtime/http.rs` 的 `HashingSink::finish` → `download_to_sink_with_progress`）。
    /// 两个计数分别由「网络收了多少」与「sink 真吃下多少」维护，对不上就说明
    /// 中间有一段字节没进 hasher —— 那会让摘要算在一份与盘上不同的内容上。
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// 是否一个字节都没喂过。
    ///
    /// 无生产调用点（如实登记）：clippy 的 `len_without_is_empty` 要求与 [`Self::len`] 配对，
    /// 单测也用它断言「空输入」。**不删**是因为删了 `len` 就得一并抑制那条 lint。
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// 结束累加，返回小写 hex 摘要（与 [`sha256_hex`] 同口径）。
    #[must_use]
    pub fn finish(self) -> String {
        hex::encode(self.hasher.finalize())
    }

    /// 结束累加并与期望摘要比对（大小写不敏感）。
    ///
    /// 判定委托 [`verify_hex_digest`]（与 [`verify_bytes`] 同一个单点）——「内存校验过、
    /// 流式校验不过」这类分叉没人能解释，故两条腿不许各留一份比较逻辑。
    ///
    /// # Errors
    ///
    /// - [`VerifyError::InvalidExpectedHash`]：`expected_hex` 非 64 字符 hex。
    /// - [`VerifyError::HashMismatch`]：实际 hash 与期望不符。
    pub fn verify(self, expected_hex: &str) -> Result<(), VerifyError> {
        verify_hex_digest(&self.finish(), expected_hex)
    }
}

/// 流式计算一个 reader 的 SHA-256 hex（**不把内容整块读进内存**）。
///
/// 用于「文件已在盘、只想知道它的摘要」的场景（如复用判定）：`std::fs::read` + [`sha256_hex`]
/// 会为一次判定把整包搬进内存，而判定本身只需要 64 字节的结论。
///
/// # Errors
///
/// 透传 reader 的 IO 错误。
pub fn sha256_reader_hex<R: std::io::Read>(mut reader: R) -> std::io::Result<String> {
    // 64 KiB：足够摊薄 syscall 开销，又不会在栈/堆上占显眼的一块。
    let mut buf = vec![0u8; 64 * 1024];
    let mut stream = Sha256Stream::new();
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return Ok(stream.finish()),
            Ok(n) => stream.update(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// 校验 hex（仅格式校验的别名，供 staged 周期在下载前先验 manifest 里的 hash 字段）。
///
/// # Errors
///
/// 仅 [`VerifyError::InvalidExpectedHash`]（不计算任何字节）。
pub fn verify_hex(expected_hex: &str) -> Result<(), VerifyError> {
    if is_valid_sha256_hex(expected_hex) {
        Ok(())
    } else {
        Err(VerifyError::InvalidExpectedHash(expected_hex.len()))
    }
}

/// 单文件原子替换编排：把 `bytes` 写到 `dest` 旁的**唯一**临时名（见 `tmp_name`），再原子 rename 到 `dest`。
///
/// 移植自 `CoreUpdateService.installCoreFromDir:459-469` 的单文件 staged-rename：
///   1. `tmp = tmp_name(dest)`（`{dest}.polaris-new-{pid}-{seq}`，**每次调用都不同**——固定名会让并发替换互相踩，见 `tmp_name`）
///   2. write(tmp, bytes) —— 失败抛出，dest 未动
///   3. rename(tmp → dest) —— 失败删 tmp 残件后抛出（对齐 上游 `if exists then unlink tmp`）
///
/// 同目录 rename 在 Unix/Win 均为原子 syscall（覆盖 dest），故 dest 要么是旧内容、要么是新内容，
/// 不会出现「写到一半」的半替换态。
///
/// # 已知限制：**rename 之前不 fsync**（如实登记，2026-08-17；本批刻意不做）
///
/// 上一段那句「不会出现写到一半的半替换态」**只对进程崩溃成立**。断电 / 内核崩溃是另一回事：
/// rename 只保证**目录项**的原子替换，不保证被替换的那个 inode 的**数据**已经离开 page cache
/// ⇒ 完全可能出现「dest 这个名字在、内容是零或半截」。本函数第 2 步与第 3 步之间没有任何 `sync`。
///
/// 同一条窗口在 App 更新包腿已经堵上了（`commands/updater::land_payload` 在
/// [`promote_staged`] 之前调 [`UpdateFs::sync_file`]）；本函数的两个调用点 ——
/// `runtime/core_swap.rs` 的换核落位与回滚落位 —— **未改**，故这条腿的窗口仍在。
///
/// 不在本批一起改的理由是后果弱一档、且改动落在另一条腿的射程里：
///  - **App 包腿**：坏 dest ⇒ `update_install` 直接拿去装一个坏包（用户侧不可逆）；
///  - **换核腿**：坏 dest ⇒ 下次起核失败，而换核**留有 `.bak`**（`core_swap` 的备份/回滚腿），
///    退化成「回滚一次」而不是「装坏东西」。
///
/// 真要补：在本函数第 2 步之后、第 3 步之前插一次 `fs.sync_file(&tmp)`，与 `land_payload` 同形。
/// 那是换核腿的**行为**改动（多一次 fsync = 多一次同步 IO，落在换核的关键路径上），
/// 应当与它自己的真机验证同批做，不该顺手夹带。目录级 fsync 同样未做，理由见
/// `land_payload` 头注（缺它只会丢文件，不会产生半截文件）。
///
/// # Errors
///
/// 透传 [`UpdateFs::write`] / [`UpdateFs::rename`] 的 IO 错误。rename 失败时尽力删 tmp 残件
/// （残件清理失败被吞，对齐 上游 `try { unlink } catch {}`）。
pub fn atomic_replace(fs: &dyn UpdateFs, dest: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let tmp = tmp_name(dest);
    // 1. 写临时文件。失败 → dest 未动；tmp 名带唯一后缀故不会被下次写入覆盖 ⇒ 必须主动删残件。
    if let Err(e) = fs.write(&tmp, bytes) {
        let _ = fs.remove_file(&tmp);
        return Err(e);
    }
    // 2. 原子 rename。失败 → 删 tmp 残件后抛出（防残件累积；清理失败无害）。
    if let Err(e) = fs.rename(&tmp, dest) {
        let _ = fs.remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// 把**已经在盘**的临时文件提升为 `dest`：只做一次同目录 rename，**绝不把内容读回内存**。
///
/// # 为什么不能用 [`atomic_replace`] 代替
///
/// [`atomic_replace`] 吃 `&[u8]`。对「刚流式写完一个几十 MiB 的临时文件」的调用方，
/// 它意味着**把整个文件读回内存再写一遍** —— 正好抵消掉流式下载省下的内存与一次全量写。
/// 故落位路径分成两个入口：字节还在内存里 → [`atomic_replace`]；字节已在盘 → 本函数。
///
/// `tmp` 必须由 [`tmp_name`] 生成（保证与 `dest` **同目录同卷** —— 跨卷 rename 不是原子操作，
/// 在 Windows 上还会直接失败）。
///
/// 失败语义与 [`atomic_replace`] 第 3 步一致：rename 失败即删 tmp 残件后抛出
/// （残件清理失败被吞）。dest 要么保持原样、要么是完整的新内容，**不存在半截态**。
///
/// # Errors
///
/// 透传 [`UpdateFs::rename`] 的 IO 错误。
pub fn promote_staged(fs: &dyn UpdateFs, tmp: &Path, dest: &Path) -> Result<(), std::io::Error> {
    if let Err(e) = fs.rename(tmp, dest) {
        let _ = fs.remove_file(tmp);
        return Err(e);
    }
    Ok(())
}

/// 多文件原子替换编排（移植自 `CoreUpdateService.installCoreFromDir:457-479` 的 staged-rename 循环）。
///
/// 语义（逐字对齐 Polaris）：
///   1. 先把 `entries`（文件名 → 字节）全部复制到 `dest_dir` 下的唯一临时名（`tmp_name`），
///      记录已复制的 staged rename 列表。
///   2. **复制阶段任一失败** → 删除所有已复制的临时文件、抛错，`dest_dir` 完全未动
///      （杜绝「新核心 + 旧/坏 libcronet」半替换混搭——原逐文件直接覆盖在中途失败时会留下此混搭，
///      而 restoreBackup 仅回滚主二进制救不回）。
///   3. 全部复制成功 → 逐个原子 rename 就位（同目录 rename 几乎不失败）。
///
/// 不变量：要么 `dest_dir` 下所有 `entries` 都换成新内容，要么一个都没换（无中间态）。
///
/// # Errors
///
/// - 复制阶段：透传 [`UpdateFs::write`] 错误（已复制的临时文件会先被清理）。
/// - rename 阶段：透传 [`UpdateFs::rename`] 错误（已 rename 的不回滚——同目录 rename 失败极罕见，
///   且 Polaris 原实现此处也不回滚已就位的，留待上层 restoreBackup 兜底）。
pub fn atomic_replace_multi(
    fs: &dyn UpdateFs,
    dest_dir: &Path,
    entries: &[(String, Vec<u8>)],
) -> Result<(), std::io::Error> {
    // 已复制到 tmp 的（tmp_path, dest_path）对：失败时用于清理。
    let mut staged: Vec<(std::path::PathBuf, std::path::PathBuf)> =
        Vec::with_capacity(entries.len());

    // 1. 全部先复制到临时名。
    for (name, bytes) in entries {
        let dest = fs.join(dest_dir, name);
        let tmp = tmp_name(&dest);
        if let Err(e) = fs.write(&tmp, bytes) {
            // 复制失败：清理已暂存的 tmp 残件，dest_dir 未动。
            for (t, _) in &staged {
                let _ = fs.remove_file(t);
            }
            return Err(e);
        }
        staged.push((tmp, dest));
    }

    // 2. 全部复制成功 → 逐个原子 rename 就位。
    //    rename 失败：Polaris 原实现此处不回滚已就位的（同目录 rename 几乎不失败），透传错误由上层 restoreBackup 兜底。
    for (tmp, dest) in &staged {
        if let Err(e) = fs.rename(tmp, dest) {
            // 清理尚未 rename 的 tmp 残件（已 rename 的不回滚）。
            let _ = fs.remove_file(tmp);
            return Err(e);
        }
    }
    Ok(())
}

/// 生成**每次调用都不同**的临时名：`{dest}.polaris-new-{pid}-{seq}`。
///
/// # 为什么不能沿用固定的 `.polaris-new`
///
/// 固定名让「同一个 `dest` 的两次并发原子替换」互相踩：A 的 `write` 还没写完，B 的 `write`
/// 以 truncate 打开**同一个** tmp 从头覆盖 → 随后任一方的 `rename` 都可能把一个长度不对的
/// 半截文件搬成 `dest`。而先返回的那一方已经报了「成功 + 已校验」——校验对象是内存里的字节，
/// **不是**落盘后的文件，故这种破损完全不会被现有校验拦住（安装时才炸）。
///
/// 并发不是异常路径：`autoDownloadUpdate` 开启时，启动腿在后台下载的同时弹 remind 窗邀请用户
/// 点「更新」，两条腿写的正是同一个 dest。加唯一后缀后，两条腿各写各的 tmp，`dest` 恒是
/// 某一方的**完整**内容。
///
/// 上游 原名是 `${dest}.polaris-new`（`CoreUpdateService.ts:462`）；此处刻意分叉并留档。
///
/// **已知代价（如实登记）**：进程在 write 与 rename 之间被硬杀会留下带唯一后缀的残件
/// （固定名那版会被下一次写入覆盖掉）。两条正常失败路径（write / rename 报错）都会主动删。
///
/// 残件的兜底回收**分腿不同，别把换核腿的兜底当成全仓的**（2026-08-16 订正：本段原写
/// 「换核的暂存目录每次 `stage` 都整目录重建，也会一并清掉」，那句话只对换核腿成立）：
///  - **换核腿**：暂存目录每次 `stage` 整目录重建 ⇒ 残件确实被一并清掉；
///  - **App 更新腿**：落在 `<cache>/updates/`，**没有任何整目录重建**。且它的主触发器不是硬崩 ——
///    `update_download` 是 async command，tmp 建立后唯一的 await 点是 `spawn_blocking(...).await`，
///    下载途中退出 App 会让 tauri runtime **drop 掉那个 future**，三处清理全被绕过，
///    而 blocking 线程仍可能把 tmp 写完。故该腿必须自带清扫
///    （`commands/updater.rs` 的 `sweep_orphan_downloads`），不能指望本段的「硬崩才残留」。
///
/// `pub`：流式下载腿要**先**拿到 tmp 路径（下载直接写它）、再交 [`promote_staged`] 提升，
/// 而不是像 [`atomic_replace`] 那样在函数内部一手包办。两条腿共用本函数是硬要求 ——
/// 各造一份 tmp 命名必然在「是否与 dest 同目录」上分叉，而那正是原子性的前提
/// （由 `tmp_name_is_unique_per_call` 的同目录断言锁死）。
#[must_use]
pub fn tmp_name(dest: &Path) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    /// 进程内单调序号：同一毫秒内的多次调用也不会撞名。
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut s = dest.as_os_str().to_os_string();
    s.push(format!(".polaris-new-{}-{seq}", std::process::id()));
    std::path::PathBuf::from(s)
}

#[cfg(test)]
mod tests;
