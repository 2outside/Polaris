//! 更新类 command（上游 `update-handlers.ts` + `core-update-handlers.ts`）。
//!
//! # 实现状态（**逐个 command 如实标注，禁假成功**）
//!
//! | command | 状态 |
//! |---|---|
//! | `version_get_info` / `update_check` / `update_download` / `update_install` / `update_skip` / `update_open_releases` | ✅ 真实现 |
//! | `update_popup_*` | ✅ 真实现 |
//! | `core_update_check` / `core_update_run` / `core_get_version_info` / `core_rollback` / `core_replace_manual` / `core_reset_factory` / `core_update_apply_staged` / `core_update_get_auto_status` / `core_update_ack_version_change` | ✅ 真实现 |
//! | `app_uninstall_all` | ✅ 真实现（编排见 [`crate::runtime::uninstall`]；三平台可行性逐项如实标注） |
//!
//! # ⚠️ 为什么「未接线」返 `success:false` 而非 `{ok:false}`
//!
//! 本文件原先的 placeholder 返回 `ApiResponse::ok(json!({"ok": false}))` —— **信封是 `success:true`**。
//! 前端 `ipc-client.ts` 在 `success:true` 时**不 throw**、原样返回 `{ok:false}`，于是「功能根本没实现」
//! 在调用侧长得和「一次正常的业务性失败」一模一样（审计 §N4 点名的「能解析、不报 not found、
//! 但功能是空的 —— 比 not found 更隐蔽」）。
//!
//! 未接线者一律用 [`ApiResponse::err_with_code`](crate::response::ApiResponse::err_with_code)（`success:false` + 结构化 `code`）：前端 throw `IpcError`
//! 带 code，UI 能把「未接线」与「失败」分开呈现。**这是反伪造的底线：没实现就不能返成功信封。**
//!
//! # 📌 注释订正记录（2026-07-20，#13/#14 接线批）
//!
//! 本文件有**注释滞后于实现**的既往史（模块文档自陈「2026-07-16 旧注与 2026-07-18 早注均已过时」）。
//! 本批又订正了下面这批**与事实不符**的断言 —— 它们直接误导了后续判断，故逐条留档：
//!
//! | 旧注（**错的**） | 事实 |
//! |---|---|
//! | 「App 自更新的下载+安装/重启需 `tauri-updater`(签名 key) 未接入」 | **完全错误**。参考实现 上游 **从头到尾没用过任何 updater 框架、没有任何应用级签名密钥对**（`UpdateService.ts` 1212 行手写 fetch + 平台脚本）。Polaris 同理不引 `tauri-plugin-updater` ⇒ **不需要 minisign 密钥对**。该断言把「Tauri 官方 updater 插件的要求」错当成了「实现自更新的要求」 |
//! | 「内核更新的下载+落位需 helper 特权写受保护核目录」 | **错误**。换核落位于 `<config_dir>/core_update/`（用户可写），三平台统一 ⇒ **全程零提权**。helper 的受保护核目录是**可选 hardening**，且它本来就已完整实现 |
//! | 「本批不得触碰 `proxy.rs`：有并发 agent 在接热切换」 | 该并发批已结束。且路径逻辑已抽到 `runtime/core_paths.rs`，`proxy.rs` 只留三级优先级的一处插入 |
//! | 「备份仅由更新成功产生，而更新链路 HTTP 阻塞 → 本机永无备份可回滚」 | 更新链路已接线；备份由**任何**换核（在线/手动）产生，`hasBackup` 现读真实 `.bak` 状态 |
//! | 「`update_download` 需 HTTPS 下载 + 超时/OOM 闸/限流分类/镜像回退/idle 看门狗……该编排须只写一份」 | 那份编排**早就写好了**：[`CoreDownloader`](crate::runtime::http::CoreDownloader)（`runtime/http.rs`，含端到端单测）。stub 之所以是 stub，只因注入的是 `UnavailableDownloader` ——**接线缺口，不是实现缺口** |
//!
//! # 供应链：真伪与完整性靠什么
//!
//! | 层 | 手段 |
//! |---|---|
//! | 传输 | HTTPS（rustls）+ `safe_redirect_fetch` 逐跳 SSRF 闸 |
//! | 完整性 | Content-Length 比对（`CoreDownloader`）**＋ sha256 强校验**（GitHub release asset 的 `digest` 字段；**上游 没有这一层**，补上「镜像回退把信任面扩到 gh-proxy 运营方」的洞） |
//! | 真伪 | OS 层。**用户已拍板走 ad-hoc 签名**（不买 Developer ID / Authenticode）⇒ macOS 必须在安装脚本里清 quarantine，Windows 必须提前告知 SmartScreen 的点法。判定逻辑见 [`crate::runtime::update_install::install_advisory`] |
//!
//! **不需要任何应用级签名密钥对。**

mod app_update;
mod app_update_policy;
mod core_update;
mod shared;
#[path = "updater/uninstall.rs"]
mod uninstall_command;

pub use app_update::{
    update_check, update_download, update_install, update_open_releases, update_popup_action,
    update_popup_show, update_skip, version_get_info,
};
pub use core_update::{
    core_get_version_info, core_replace_manual, core_reset_factory, core_rollback,
    core_update_ack_version_change, core_update_apply_staged, core_update_check,
    core_update_get_auto_status, core_update_run,
};
pub use uninstall_command::app_uninstall_all;

// 仅供同 crate 的调度器/启动任务复用，避免复制可写路径、下载器或自动换核语义。
pub(crate) use app_update::{
    is_portable_layout, CODE_CHECK_TIMEOUT, CODE_CORE_DIR_UNAVAILABLE, CODE_FORK_BLOCKED,
    CODE_NO_BACKUP, CORE_CHECK_TOTAL_TIMEOUT_MS, GITHUB_FETCH_TIMEOUT_MS, MAX_GITHUB_JSON_BYTES,
};
pub(crate) use app_update_policy::app_update_channel_is_prerelease;
pub(crate) use core_update::{
    core_update_apply_staged_auto, extract_core_bytes, staged_core_sha_path,
};
#[cfg(test)]
use shared::github_status_error;
pub(crate) use shared::updater_downloader;
use shared::{core_base_dir, fetch_releases_json};

#[cfg(test)]
mod tests;
