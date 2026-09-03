//! 托盘浮层冷建状态机 + 保留态判定（纯状态机与纯判定，零 `AppHandle` 依赖，零 tauri 副作用）。
//! 从 `tray.rs` 整段搬出（Phase 4A 批 B6）。`window.rs`（批 B7）与 `commands.rs`（批 B8）跨域调用，
//! 故本模块的类型/方法均升 `pub(super)`（tray 子树内可见，见设计 SoT §B.2）。

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OverlayOpenAction {
    ShowNow,
    AwaitReady,
    QueueBuild { generation: u64 },
}

/// 托盘浮层的冷建状态机。所有字段都在同一把锁下迁移，避免「窗口已建」与「renderer 已就绪」分别用
/// 原子量表示时读到撕裂组合。`generation` 隔离被销毁旧 WebView 的迟到 ready 回执。
#[derive(Default)]
pub(super) struct OverlayLifecycle {
    pub(super) generation: u64,
    pub(super) build_queued: bool,
    pub(super) renderer_ready: bool,
    pub(super) show_requested: bool,
}

impl OverlayLifecycle {
    /// 后台预热一代 renderer，但不登记展示意图。ready 回执只把本代提交为可热开，绝不能自行 show。
    #[cfg(any(target_os = "macos", target_os = "windows", test))]
    pub(super) fn request_prewarm(&mut self, window_exists: bool) -> Option<u64> {
        if window_exists || self.build_queued {
            return None;
        }
        self.generation = self.generation.wrapping_add(1);
        self.build_queued = true;
        self.renderer_ready = false;
        self.show_requested = false;
        Some(self.generation)
    }

    pub(super) fn request_open(&mut self, window_exists: bool) -> OverlayOpenAction {
        self.show_requested = true;
        if window_exists && self.renderer_ready {
            OverlayOpenAction::ShowNow
        } else if window_exists || self.build_queued {
            OverlayOpenAction::AwaitReady
        } else {
            self.generation = self.generation.wrapping_add(1);
            self.build_queued = true;
            self.renderer_ready = false;
            OverlayOpenAction::QueueBuild {
                generation: self.generation,
            }
        }
    }

    pub(super) fn build_finished(&mut self, generation: u64, success: bool) {
        if self.generation != generation {
            return;
        }
        self.build_queued = false;
        if !success {
            self.show_requested = false;
        }
    }

    pub(super) fn mark_ready(&mut self, generation: u64) -> bool {
        if self.generation != generation {
            return false;
        }
        self.renderer_ready = true;
        self.show_requested
    }

    pub(super) fn should_show(&self, generation: u64) -> bool {
        self.generation == generation && self.renderer_ready && self.show_requested
    }

    pub(super) fn hide(&mut self) {
        self.show_requested = false;
    }

    pub(super) fn reset(&mut self) {
        // 让旧 renderer 的迟到 ready 回执失效；新冷建再递增一次不影响语义。
        self.generation = self.generation.wrapping_add(1);
        self.build_queued = false;
        self.renderer_ready = false;
        self.show_requested = false;
    }
}

#[derive(Clone, Copy)]
pub(super) struct OverlayOpenProbe {
    pub(super) started: Instant,
    pub(super) cold: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OverlayRetentionAction {
    None,
    CancelReclaim,
    ScheduleReclaim,
}

/// 配置切换时该怎样处理已存在的浮层计时器。
///
/// case 矩阵：
/// - 值没变：不动（否则任意配置保存都会把 120s 计时器无限续期）；
/// - 关→开：使已有回收任务失效；
/// - 开→关：若浮层已隐藏则立即重新挂 120s 回收，若仍可见则等本次 hide 再挂。
#[must_use]
pub(super) fn overlay_retention_action(
    previous: bool,
    next: bool,
    overlay_hidden: bool,
) -> OverlayRetentionAction {
    if previous == next {
        OverlayRetentionAction::None
    } else if next {
        OverlayRetentionAction::CancelReclaim
    } else if overlay_hidden {
        OverlayRetentionAction::ScheduleReclaim
    } else {
        OverlayRetentionAction::None
    }
}

/// 销毁任意最后一个 WebView 前的纯判据：只为末窗且托盘仍可作为唤出锚点时武装退出守卫。
#[must_use]
pub(super) fn should_arm_last_webview_exit_guard(
    webview_window_count: usize,
    tray_present: bool,
) -> bool {
    webview_window_count == 1 && tray_present
}

/// 只回滚本调用者在失败 destroy 前亲自武装的退出守卫。
///
/// 已经武装不等于归当前销毁腿所有：另一个仍在途的轻量转场可能持有它。因此成功或非 owner
/// 都不得清位，避免重新放开实际要拦截的 `ExitRequested`。
pub(super) fn rollback_owned_exit_guard(
    exit_guard: &AtomicBool,
    destroy_failed: bool,
    armed_by_this_caller: bool,
) {
    if destroy_failed && armed_by_this_caller {
        exit_guard.store(false, Ordering::SeqCst);
    }
}
