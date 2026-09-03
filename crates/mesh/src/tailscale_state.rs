//! Tailscale state 目录工具（上游 `src/main/services/tailscale-state.ts` 1:1 移植）。
//!
//! `<userData>/tailscale/<serverId>` 的路径与存在性判定。交互登录（无 auth_key）产出的是该目录下的
//! 会话文件（跨重启免重认证）。1.14 起登录态判定全量迁移到管理 API STATUS 流，此模块仅余两用途：
//! 1) [`tailscale_state_dir`]：buildTailscaleEndpoint 的 state_directory + 删节点/登出时清理目录；
//! 2) [`state_exists`]：proxy-handlers 登录态秒显兜底 + startInternal reassert 登录期出口让位预置的
//!    「是否曾登录」判据（已不再用于登录成功判定，stateExists 误判是 #132 根因，已剥离轮询）。
//!
//! ## 纯逻辑边界
//! Polaris 用 node `fs.readdirSync` 直接读盘——本 crate 不触碰宿主 FS：路径计算纯函数，存在性判定经
//! [`TailscaleStateFs`] trait 注入（测试 mock；应用层用 std::fs）。

#![forbid(unsafe_code)]

use std::path::{Component, Path, PathBuf};

/// 不可信节点 id 不能作为路径片段使用。该错误只表达技术边界；面向用户的文案由应用层按错误码本地化。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidTailscaleStateId;

impl std::fmt::Display for InvalidTailscaleStateId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid Tailscale state id")
    }
}

impl std::error::Error for InvalidTailscaleStateId {}

/// Tailscale state 目录：`<userData>/tailscale/<serverId>`，跨重启免重认证、删节点时清理。
/// 上游 `tailscaleStateDir`。`user_data` 由调用方注入（应用层 = getUserDataPath）。
pub fn tailscale_state_dir(
    user_data: &Path,
    server_id: &str,
) -> Result<PathBuf, InvalidTailscaleStateId> {
    // `Path::components` 是宿主平台语义，额外拒绝两种分隔符与 `:`，使 Unix 上也能拦住从
    // Windows 导入的 drive/UNC 路径。长度上限同时避免不可信配置制造 ENAMETOOLONG。
    let is_portable_component = !server_id.is_empty()
        && server_id.len() <= 255
        && !server_id
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\' | ':'))
        && matches!(
            Path::new(server_id)
                .components()
                .collect::<Vec<_>>()
                .as_slice(),
            [Component::Normal(_)]
        );
    if !is_portable_component {
        return Err(InvalidTailscaleStateId);
    }
    Ok(user_data.join("tailscale").join(server_id))
}

/// Tailscale state FS 契约：列出目录条目（存在性/非空判定）。
/// Polaris 用 `fs.readdirSync(dir)`，目录缺失抛 ENOENT → catch 返 false。
/// 实现方负责真实 FS（应用层 std::fs）；测试 mock 注入。
pub trait TailscaleStateFs: Send + Sync {
    /// 列出 `dir` 的条目名；目录缺失/读失败返 None（失败安全，对齐 Polaris catch→false）。
    fn read_dir_names(&self, dir: &Path) -> Option<Vec<String>>;
}

/// state 目录存在且非空 → 已有持久登录会话。缺失/空/读失败 → false（失败安全）。
/// 上游 `tailscaleStateExists`。
pub fn state_exists(fs: &dyn TailscaleStateFs, user_data: &Path, server_id: &str) -> bool {
    let Ok(dir) = tailscale_state_dir(user_data, server_id) else {
        return false;
    };
    match fs.read_dir_names(&dir) {
        Some(names) => !names.is_empty(),
        None => false,
    }
}

#[cfg(test)]
mod tests;
