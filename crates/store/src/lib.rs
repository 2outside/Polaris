//! polaris-store — 配置持久化层纯逻辑核心。
//!
//! Polaris 锚点：`main/services/ConfigManager.ts`（loadConfig / saveConfig / sanitize / migrate /
//! validate / atomic-write 的纯逻辑核心，FS 操作经 [`fs::ConfigFs`] trait 抽象）。
//!
//! 职责：
//! - [`backup`]：选择性备份 / 恢复的类别模型（6 类分桶 + 整类替换 + 空跳过）+ 备份文件格式解析。
//! - [`sanitize`]：宽容反序列化（坏字段跳过不崩，维度7 #7 HIGH）+ 默认值填充。
//! - [`migrate`]：一次性迁移链（全量移植，幂等 + 绝不抛，维度7 #54）。
//! - [`validate`]：规则 / 节点 / 端口合法性校验 + 纯校验辅助函数（协议白名单、CIDR、规则类型）。
//! - [`fs`]：[`fs::ConfigFs`] trait + [`fs::atomic_write_plan`]（tmp→rename 原子写逻辑）。
//! - [`store`]：[`store::ConfigStore`] 编排 load / save / backup 的纯逻辑核心。
//!
//! 纯逻辑纪律：FS 收口到 trait，运行时层注入 std::fs 实现、测试注入 `MockFs`。
//! 不持有 currentConfig 缓存（运行时层包装维护，对齐 Polaris ConfigManager.currentConfig）。
//!
//! 见 ~/docs/polaris/design/polaris-system-design.md §B.2（crate 边界 + 职责 + Polaris 锚点）。
//! 行为不变式见 vault 的能力入口点清单（special-logic 分册）（维度7 淬炼 70 条）。

// `store::default_config()` 的 `json!` 字面量已接近默认 128 层展开上限（每个键约一层），
// 加一个键就会 `recursion limit reached`。抬到 256 是编译器给的处置，且只作用于宏展开深度，
// 不影响运行期。**别改成「把默认值拆成多个 json! 再 merge」**：那会让「默认配置长什么样」
// 从一处字面量散成几处拼装，是拿可读性换一个编译器参数。
#![recursion_limit = "256"]
#![forbid(unsafe_code)]

pub mod backup;
pub mod error;
pub mod fs;
pub mod migrate;
pub mod privacy_lock;
pub mod sanitize;
pub mod store;
pub mod validate;

pub use backup::{
    build_backup_info, count_category, detect_categories, merge_categories, parse_backup_content,
    pick_categories, sanitize_cross_platform_rules, BackupCategory, BackupInfo, MergeOutcome,
    ParsedBackup, BACKUP_CATEGORIES, BACKUP_FILE_VERSION,
};
pub use error::StoreError;
pub use fs::{atomic_write_plan, AtomicWritePlan, ConfigFs, StdFs};
pub use migrate::{migrate_all, MigrationDelta};
pub use privacy_lock::{PrivacyPasswordHash, ScryptParams};
pub use sanitize::sanitize_config;
pub use store::{
    corrupt_backup_stamp, default_config, finalize_config, prune_corrupt_backups, ConfigStore,
    LoadResult,
};
pub use validate::validate_config;

/// 字符串去重保序（保序 = 按首次出现顺序）。复用 config-engine collections::dedupe。
///
/// 供 sanitize / migrate 内 CIDR / bypassProcesses 去重。返回新 Vec。
pub fn dedupe_str(items: &[String]) -> Vec<String> {
    polaris_config_engine::user_config::collections::dedupe(items.iter().cloned())
}

#[cfg(test)]
pub use tests::test_support::{FsOp, MockFs};

#[cfg(test)]
mod tests;
