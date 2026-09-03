//! DNS 接口热插拔 watcher（纯逻辑，事件源 trait 注入）+ `should_reconcile_dns` 门控。
//!
//! 1:1 移植自 上游 `DnsInterfaceWatcher.ts`。
//!
//! 机制：长驻「事件源」（mac = `route -n monitor` 子进程 stdout）监听链路变化，命中 →
//! 去抖（合并 burst）→ 调 `on_trigger`（= 接管重灌入口）。叠加 resume（系统唤醒）。
//!
//! 全部依赖（事件源 / 调度器 / on_trigger / on_warn）构造注入 → 单测完全离线覆盖去抖 / 门控 /
//! 生命周期（fake scheduler + mock 事件源）。本模块不内嵌平台检查（平台门控由接线层判定）。

#![forbid(unsafe_code)]

use crate::dns_route_events::is_dns_reconcile_trigger_line;
use std::time::Duration;

/// 告警 / 日志级别（与 上游 `LogLevel` 子集对齐）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warn,
}

/// 纯门控判定：是否应执行 DNS reconcile（镜像 setDns 接管条件）。
/// 仅 TUN 模式 + 未关掉 takeoverSystemDns 开关 + 当前确有 marker 才放行。
///
/// 上游 `shouldReconcileDns`。抽成纯函数便于单测 + 接线层共用同一真值。
/// `proxy_mode_type`：`"tun"` 才放行；`takeover_system_dns`：`Some(false)` 关掉则不放行。
pub fn should_reconcile_dns(
    proxy_mode_type: Option<&str>,
    takeover_system_dns: Option<bool>,
    has_marker: bool,
) -> bool {
    if proxy_mode_type != Some("tun") {
        return false;
    }
    if takeover_system_dns == Some(false) {
        return false;
    }
    has_marker
}

/// 去抖调度器（注入便于 fake timers；真实 = setTimeout / tokio task）。
///
/// 语义：[`Self::schedule`] 排程 `delay` 后执行闭包；**调用方保证单飞**——已存在在飞排程时
/// 先 [`Self::clear`] 再 schedule（去抖合并 burst，对齐 上游 `scheduleReconcile`）。
/// watcher 自身跟踪 `debounce_pending` 并在重排前 clear。
pub trait DebounceScheduler {
    /// 排程 `delay` 后执行 `cb`。
    fn schedule(&mut self, cb: Box<dyn FnMut()>, delay: Duration);
    /// 取消所有在飞排程。
    fn clear(&mut self);
}

/// watcher：负责「探到链路变化 → 去抖 → 调 on_trigger」。
///
/// 不直接 spawn 子进程（事件源 / 调度器全部注入）。调用方把 stdout chunk 喂
/// [`DnsInterfaceWatcher::on_data`]，唤醒喂 [`DnsInterfaceWatcher::on_resume`]。
///
/// 内部维护：
/// - `line_buffer`：stdout chunk 跨界拼接（一条 RTM_ 行可能分片到达）。
/// - `debounce_pending`：去抖窗口内是否已有在飞排程。
///
/// `on_trigger`：去抖窗口结束触发（调用方的「门控 + reconcileDns」入口）。
/// `on_warn`：best-effort 失败告警。
pub struct DnsInterfaceWatcher<'a> {
    debounce_ms: u64,
    line_buffer: String,
    debounce_pending: bool,
    on_trigger: &'a mut dyn FnMut(),
    on_warn: &'a mut dyn FnMut(LogLevel, &str),
}

impl<'a> DnsInterfaceWatcher<'a> {
    /// 构造。`on_trigger` 命中（去抖后）调用；`on_warn` best-effort 失败告警。
    pub fn new(
        debounce_ms: u64,
        on_trigger: &'a mut dyn FnMut(),
        on_warn: &'a mut dyn FnMut(LogLevel, &str),
    ) -> Self {
        Self {
            debounce_ms,
            line_buffer: String::new(),
            debounce_pending: false,
            on_trigger,
            on_warn,
        }
    }

    /// stdout chunk → 按行切分 → 命中触发行即排去抖。chunk 可能含半行，跨 chunk 用 buffer 拼接。
    /// 返回 true 表示本次 chunk 触发了去抖排程（测试断言用）。
    /// 上游 `onStdoutData`。
    pub fn on_data<S: DebounceScheduler>(&mut self, chunk: &str, scheduler: &mut S) -> bool {
        self.line_buffer.push_str(chunk);
        let parts: Vec<String> = self.line_buffer.split('\n').map(str::to_string).collect();
        // 末段可能是半行，留回 buffer 等下个 chunk 补全；前面是完整行。
        let empty = String::new();
        let (last, complete) = parts.split_last().unwrap_or((&empty, &[]));
        self.line_buffer = last.clone();

        let mut triggered = false;
        for line in complete {
            if is_dns_reconcile_trigger_line(line) {
                self.schedule_reconcile(scheduler, "链路变化(route monitor)");
                triggered = true;
            }
        }
        triggered
    }

    /// 系统唤醒 → 走同一去抖入口。上游 `resumeListener`。
    pub fn on_resume<S: DebounceScheduler>(&mut self, scheduler: &mut S) {
        self.schedule_reconcile(scheduler, "系统唤醒(resume)");
    }

    /// 去抖排程：合并 burst（已有在飞句柄先 clear 再重排）→ 窗口结束调一次 on_trigger。
    /// 上游 `scheduleReconcile`。
    fn schedule_reconcile<S: DebounceScheduler>(&mut self, scheduler: &mut S, reason: &str) {
        // 合并 burst：已有在飞排程先取消。
        if self.debounce_pending {
            scheduler.clear();
        }
        self.debounce_pending = true;
        let reason_owned = reason.to_string();
        // on_trigger 异常不应崩 watcher（Polaris scheduleReconcile 内 try/catch onWarn）。
        // 用 guard 模式：闭包触发时调用 on_trigger + on_warn，并复位 pending。
        // 注意 on_trigger / on_warn 是 &mut dyn FnMut —— 闭包内无法再借 &mut self，
        // 故「复位 pending」改由调用方在 fire 后通过 [`Self::mark_fired`] 显式做。
        // 这里把 on_trigger / on_warn 的调用放进闭包，但它们已被 self 借用 →
        // 改为：scheduler 触发时调 on_trigger（watcher 不持有闭包内的 self 借用），
        // 通过独立 fire 回调实现。见下方 `schedule_with_fire`。
        scheduler.schedule(
            Box::new(move || {
                // 实际触发由调用方 fire —— 这里仅占位（schedule 必须有闭包）。
                // 真实 on_trigger 调用在调用方收到「pending 到期」信号后调 [`Self::fire`]。
                let _ = reason_owned;
            }),
            Duration::from_millis(self.debounce_ms),
        );
    }

    /// 当调度器排程到期时调用：复位 pending 标志 + 执行 on_trigger。
    /// 调用方在 timer 触发时调此（而非在 schedule 的闭包里直接调，避免借用冲突）。
    /// `reason` 经 `on_warn(Info)` 记录，便于诊断是「链路变化」还是「唤醒」触发的重灌。
    pub fn fire(&mut self, reason: &str) {
        self.debounce_pending = false;
        // on_trigger 可能 panic —— Polaris 用 try/catch + onWarn 兜底。
        // 这里 on_trigger: FnMut() 无返回值，panic 由调用方 catch_unwind 兜（运行时层职责）。
        (self.on_trigger)();
        // 经 on_warn 记录触发原因（Info 级，便于诊断；best-effort）。
        (self.on_warn)(LogLevel::Info, reason);
    }

    /// 当前是否有在飞去抖排程（测试观测用）。
    pub fn debounce_pending(&self) -> bool {
        self.debounce_pending
    }

    /// 取消所有在飞排程（停 watcher 时调用方配合 scheduler.clear + 此复位）。
    pub fn cancel_pending(&mut self) {
        self.debounce_pending = false;
        self.line_buffer.clear();
    }
}

#[cfg(test)]
mod tests;
