//! 隐私锁密码哈希（scrypt KDF）+ 独立文件存储（`privacy-lock.json`，0600）。
//!
//! Polaris/上游 锚点：`main/utils/privacy-lock.ts`。逐字移植 scrypt 交互档参数
//! （N=2^14 / r=8 / p=1 / keyLen=32，salt 16B CSPRNG，timingSafeEqual 常量时间比较），
//! 存独立 `privacy-lock.json`（永不进 config 对象 → 无需在 10+ 个 configChanged 广播点脱敏与 merge 保护）。
//!
//! 安全定位（沿用 上游 原文）：本特性是「前端威慑闸」加固，非 auth-grade——但密码绝不明文落盘、
//! 绝不下发渲染端。文件缺失/损坏 → `None`（fail-open = 未设密码，符合威慑闸语义，与 上游 `readPrivacyHash` 同口径）。
//!
//! # 为什么 scrypt 而非 salted SHA-256
//! Polaris 早期把 salted SHA-256（**快**哈希，GPU 每秒几十亿次）存进 config.json `privacyPasswordHash`。
//! 本模块升级为 scrypt（memory-hard **慢**哈希，单次 ~50-100ms，抬高离线暴力成本）+ 独立文件 0600。
//! 存量 SHA-256 用户的平滑迁移（解锁验过即升级、set 即改写）在 `commands/config.rs`；本模块只管
//! scrypt 纯逻辑 + 文件读写，不含存量迁移决策。
//!
//! # 纯逻辑纪律
//! 盐由**调用方** CSPRNG 生成（`commands/config.rs::gen_salt`，复用 ring）并传入——[`hash_password`]
//! 同 `plain`+`salt` → 同结果，故可单测；本 crate 不引 RNG 依赖。FS 经 [`ConfigFs`] trait（0600 由
//! [`crate::StdFs`] 的 open(2) 保证），测试注入 `crate::MockFs`。

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::fs::ConfigFs;
use crate::StoreError;

/// 独立哈希文件名（userData 下，与 config.json 同目录）。对齐 上游 `privacy-lock.json`。
pub const LOCK_FILE_NAME: &str = "privacy-lock.json";

/// 盐长度（16 字节）。对齐 上游 `randomBytes(16)`。
pub const SALT_LEN: usize = 16;

/// scrypt 参数（交互档，逐字对齐 上游 `PARAMS = { N: 16384, r: 8, p: 1, keyLen: 32 }`）。
///
/// 序列化键名与 上游 一致（`N` / `r` / `p` / `keyLen`），便于跨端一致核对。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScryptParams {
    /// CPU/内存 cost 参数 N（必为 2 的幂；scrypt::Params 取 log2(N)）。上游 = 16384 = 2^14。
    #[serde(rename = "N")]
    pub n: u32,
    /// 块大小参数 r。上游 = 8。
    pub r: u32,
    /// 并行度参数 p。上游 = 1。
    pub p: u32,
    /// 派生密钥长度（字节）。上游 = 32。
    #[serde(rename = "keyLen")]
    pub key_len: u32,
}

/// scrypt 交互档参数常量。**不得弱于此**——变异门 `params_match_oracle_上游` 逐字锁死（改弱即转红）。
pub const PARAMS: ScryptParams = ScryptParams {
    n: 16384,
    r: 8,
    p: 1,
    key_len: 32,
};

/// 隐私锁落盘结构（对齐 上游 `PrivacyPasswordHash`）。`salt`/`hash` 均为小写 hex。
///
/// `params` 随每条哈希一起落盘，[`verify`] 复算时按**存储值**取参（绝不用编译期常量覆盖），
/// 使将来调参的存量哈希仍可校验。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyPasswordHash {
    /// 算法标识，恒 `"scrypt"`（读取时校验，异类 → 视为损坏 → `None`）。
    pub algo: String,
    /// 盐（hex，16B）。
    pub salt: String,
    /// 派生密钥（hex，keyLen 字节）。
    pub hash: String,
    /// scrypt 参数。
    pub params: ScryptParams,
}

/// 隐私锁文件绝对路径（`<userData>/privacy-lock.json`）。
#[must_use]
pub fn lock_path(user_data_dir: &Path) -> PathBuf {
    user_data_dir.join(LOCK_FILE_NAME)
}

/// scrypt 派生（`plain` + `salt` + `params` → keyLen 字节派生密钥）。
///
/// 参数非法（N 非 2 的幂 / scrypt 约束不满足）或派生失败 → `Err`（[`verify`] 侧据此 fail-closed）。
fn derive(plain: &str, salt: &[u8], params: &ScryptParams) -> Result<Vec<u8>, StoreError> {
    // N 必为 2 的幂：scrypt::Params 取 log2(N)。存储值被篡改成非 2 的幂 → 明确报错（verify → false，fail-closed）。
    if !params.n.is_power_of_two() {
        return Err(StoreError::Io("scrypt N 非 2 的幂".into()));
    }
    let log_n = params.n.trailing_zeros() as u8;
    let key_len = params.key_len as usize;
    let sp = scrypt::Params::new(log_n, params.r, params.p)
        .map_err(|e| StoreError::Io(format!("scrypt 参数非法: {e}")))?;
    let mut out = vec![0u8; key_len];
    scrypt::scrypt(plain.as_bytes(), salt, &sp, &mut out)
        .map_err(|e| StoreError::Io(format!("scrypt 派生失败: {e}")))?;
    Ok(out)
}

/// 用给定盐算 scrypt 哈希（盐由调用方 CSPRNG 生成并保证每次 set 新生成、唯一）。
///
/// 纯函数（同 `plain`+`salt` → 同结果），便于单测。落盘结构**绝不含明文**。
///
/// # Errors
/// scrypt 派生失败（参数非法等，正常常量下不会发生）→ [`StoreError::Io`]。
pub fn hash_password(plain: &str, salt: &[u8]) -> Result<PrivacyPasswordHash, StoreError> {
    let dk = derive(plain, salt, &PARAMS)?;
    Ok(PrivacyPasswordHash {
        algo: "scrypt".to_string(),
        salt: hex_encode(salt),
        hash: hex_encode(&dk),
        params: PARAMS,
    })
}

/// 校验明文是否匹配存储哈希：按**存储的** salt+params 复算 + **常量时间**比较。
///
/// 结构 / 参数 / hex / 算法异常一律返回 `false`（fail-closed），绝不 panic。对齐 上游 `verifyPassword`。
#[must_use]
pub fn verify(plain: &str, stored: &PrivacyPasswordHash) -> bool {
    if stored.algo != "scrypt" {
        return false;
    }
    let (Some(salt), Some(expected)) = (hex_decode(&stored.salt), hex_decode(&stored.hash)) else {
        return false;
    };
    match derive(plain, &salt, &stored.params) {
        Ok(dk) => constant_time_eq(&dk, &expected),
        Err(_) => false,
    }
}

/// 读隐私锁文件 → 有效哈希 / `None`（缺失 / 坏 JSON / 结构非法 / algo 异类 → `None`，fail-open）。
pub fn read<F: ConfigFs + ?Sized>(fs: &F, path: &Path) -> Option<PrivacyPasswordHash> {
    let raw = fs.read_to_string(path).ok()?;
    let parsed: PrivacyPasswordHash = serde_json::from_str(&raw).ok()?;
    if parsed.algo == "scrypt" && !parsed.salt.is_empty() && !parsed.hash.is_empty() {
        Some(parsed)
    } else {
        None
    }
}

/// 是否已设隐私密码（隐私锁文件存在且结构有效）。
pub fn has<F: ConfigFs + ?Sized>(fs: &F, path: &Path) -> bool {
    read(fs, path).is_some()
}

/// 写隐私锁文件（0600 由 [`crate::StdFs`] 的 open(2) 保证；先建父目录）。**绝不写明文**。
///
/// # Errors
/// 序列化或 FS 写失败 → [`StoreError`]。
pub fn write<F: ConfigFs + ?Sized>(
    fs: &F,
    path: &Path,
    hash: &PrivacyPasswordHash,
) -> Result<(), StoreError> {
    if let Some(parent) = path.parent() {
        fs.create_dir_all(parent)?;
    }
    let content = serde_json::to_string(hash).map_err(StoreError::from_parse)?;
    fs.write(path, &content)
}

/// 删除隐私锁文件（清除密码；不存在视为成功，best-effort）。
///
/// # Errors
/// FS 删除失败（非「不存在」）→ [`StoreError::Io`]。
pub fn remove<F: ConfigFs + ?Sized>(fs: &F, path: &Path) -> Result<(), StoreError> {
    fs.remove(path)
}

/// 常量时间比较（等长逐字节 XOR 累加，无早退时序泄漏）。长度不等直接 `false`（hash 恒等长，不泄信息）。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 字节 → 小写 hex。
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    s
}

/// hex → 字节。非偶长度 / 非法字符 → `None`。
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests;
