//! App 自更新候选通道的单点策略。
//!
//! 更新检查有设置页、常驻横幅、启动任务、托盘和 mini 弹窗复查等入口。它们只共享“是否纳入
//! GitHub prerelease”这一项策略；下载、校验和安装仍由 `app_update` 的既有状态机负责。

use serde_json::Value;

/// `config.appUpdateChannel == "prerelease"` 时纳入预发布，其余一律稳定通道。
///
/// 缺省与非法值都回落稳定版，保证存量用户不会在升级后被动进入测试通道。非法值通常已被
/// `polaris-store` 清理；这里仍失败安全，覆盖启动早期或手工修改配置的读取路径。
#[must_use]
pub(crate) fn app_update_channel_is_prerelease(config: &Value) -> bool {
    config.get("appUpdateChannel").and_then(Value::as_str) == Some("prerelease")
}

#[cfg(test)]
mod tests;
