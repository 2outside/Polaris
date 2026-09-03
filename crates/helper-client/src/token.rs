//! Token 行鉴权（移植自 上游 `HelperManager.ts` 的 token 文件管理）。
//!
//! ## Polaris 设计
//!
//! macOS/Windows helper 用 **token 行** 作为 socket 鉴权边界（linux 经 SO_PEERCRED 无 token 行）。
//! app 侧持有一个 token 文件（`getUserDataPath()/helper-client.token`，0600），root 侧 helper 持同值的
//! `helper.token`（`HelperManager.ts:93,811`）。每次连接首行发 token，helper 比对（`helper.go:403-406`）。
//!
//! token 刻意独立成文件（非 config 字段）：渲染端 saveConfig 整体回写 config.json 时永远碰不到它，
//! 杜绝「装好后 token 被携旧快照的 saveConfig 清零 → 需修复」的竞态（`HelperManager.ts:91-93`）。
//!
//! ## 本模块职责
//!
//! 纯文件 IO + 字符串比对，无 socket 依赖：
//! - [`read_token`]：读 app 侧 token 文件（缺失/读失败返回空串，对齐 上游 `token()` 的 try/catch）。
//! - [`write_token`]：生成随机 token 并写文件（0600）。
//!
//! ## 移植纪律
//!
//! - `forbid(unsafe_code)`：随机数统一经 `getrandom` 调宿主 OS CSPRNG；熵源失败则拒绝生成 token。
//! - 不触碰宿主：所有路径由调用方传入，测试用 tempdir。
//! - token 格式：32 字符 hex（16 字节随机），对齐 上游 `randomBytes(16).toString('hex')`（`HelperManager.ts:479`）。

use std::fs;
use std::io;
use std::path::Path;

/// 生成的 token 字节长度（16 字节 → 32 hex 字符），对齐 上游 `randomBytes(16)`。
pub const TOKEN_BYTES: usize = 16;

/// 读 token 文件内容（trim 后）。缺失或读失败返回空串。
///
/// 移植自 `HelperManager.ts:97-103` 的 `token()`：
/// ```text
/// try { return fs.readFileSync(this.tokenFilePath(), 'utf8').trim(); }
/// catch { return ''; }
/// ```
pub fn read_token(path: &Path) -> String {
    match fs::read_to_string(path) {
        Ok(s) => s.trim().to_owned(),
        Err(_) => String::new(),
    }
}

/// 生成新 token（32 hex 字符）并写入指定路径（权限 0600）。
///
/// 移植自 `HelperManager.ts:479`：`token = randomBytes(16).toString('hex')` + `writeFileSync(path, token, {mode: 0o600})`。
///
/// 返回生成的 token（已写盘）。写失败返回 [`io::Error`]（调用方据此报错，对齐 Polaris 的 catch）。
///
/// **随机源**：`getrandom` 直接使用宿主 OS CSPRNG（Unix `getrandom`/`/dev/urandom`、Windows
/// `ProcessPrng`）。熵源失败直接返回错误；认证边界不允许退回时间戳、线程号等可预测材料。
pub fn write_token(path: &Path) -> io::Result<String> {
    let token = generate_token()?;
    write_token_content(path, &token)?;
    Ok(token)
}

/// 把已知 token 内容写入指定路径（0600）。
///
/// 供 install 流程复用（root 安装脚本写 `helper.token`，app 侧写同值到 client token 文件）。
pub fn write_token_content(path: &Path, token: &str) -> io::Result<()> {
    // 父目录确保存在（对齐 Polaris getUserDataPath 通常存在，但防御性 mkdir）
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_EXCL 不用 —— 重装时复用同 token，需覆盖（Polaris install 复用已有 token，HelperManager.ts:478）
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        // `mode` 只影响新建文件；重装复用的旧文件可能权限更宽。先在已打开句柄上强制收紧，
        // 失败则拒绝写入新 token，不能一边向上报错、一边留下内容已更新但仍可被旁人读取的文件。
        f.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
        f.set_len(0)?;
        use std::io::Write;
        f.write_all(token.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, token.as_bytes())?;
    }
    Ok(())
}

/// 删除 token 文件（卸载时清 app 侧 token）。
///
/// 移植自 `HelperManager.ts:567-571`：`fs.unlinkSync(this.tokenFilePath())`（不存在则忽略）。
pub fn remove_token(path: &Path) {
    let _ = fs::remove_file(path);
}

// ===== token 生成 =====

/// 生成 32 字符 hex token。
///
/// 对齐 上游 `randomBytes(16).toString('hex')`（`HelperManager.ts:479`）。
/// 用 OS CSPRNG；失败时拒绝生成弱 token。
fn generate_token() -> io::Result<String> {
    let mut bytes = [0u8; TOKEN_BYTES];
    getrandom::fill(&mut bytes)
        .map_err(|error| io::Error::other(format!("OS random source unavailable: {error}")))?;
    Ok(hex_encode(&bytes))
}

/// 16 进制编码（小写），无依赖。
///
/// # 为何不用 `hex::encode`（审计 G4.2 的取舍）
///
/// workspace 内 `hex` 0.4 确已在用（`helper-common/src/core_install.rs:97` 等 4 个 crate），
/// 换过去技术上可行。**仍保留手写**，理由是收益/成本不成比例：
///
/// - 收益仅 10 行。本函数是**全函数**（无错误分支、无解析、无边界情况），4 条单测已锁死
///   空/0x00/0xff/多字节，出错概率与维护负担均为零 —— 与 G4.1 情况相反：那里手写 IP 解析
///   有真 bug（前导零、双 `::`），stdlib 严格更优且 stdlib 不算依赖，故换；此处无 bug 可修。
/// - 成本是给**非特权侧**新增一条依赖边；但本 crate 已为安全 token 必须引入 `getrandom`，仍不应
///   再为纯编码加 `hex`。
///
/// 若将来本 crate 因别的理由已引入 `hex`，本函数应随之删除，改调 `hex::encode`。
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests;
