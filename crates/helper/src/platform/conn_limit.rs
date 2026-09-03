//! 连接并发闸（**mac / linux 两条 accept 腿共用**的纯逻辑，无 OS 调用）。
//!
//! ## 为什么要有这一层
//!
//! 两条 unix 腿的形态逐条同构：socket 0666（任何本地进程可连）+ **读 token / 取 SO_PEERCRED
//! 之前**就把连接交给独立执行体（mac 是 `thread::spawn`，linux 是 `spawn_blocking`）。于是
//! 「连上 → 滴喂 → 不发完整帧」的无 token 进程能按连接数线性吃掉 helper 的执行体与 fd：
//! 5s 读超时只限制单连接寿命，不限制连接数。先发作的不是 EMFILE，而是**阻塞池饥饿**
//! （linux 的 `spawn_blocking` 池被占满后合法请求排队等不到），随后 fd 攥满才是 EMFILE。
//!
//! 闸必须落在**起执行体之前**：执行体一旦起了就已经被对端按住 5s，事后限流没有意义。
//!
//! ## 为什么放在 `platform/`（不是某个平台子模块）
//!
//! 与 [`crate::platform::accept_retry`] 同一份理由：linux 模块在编 macOS 时不存在、macos 模块在编
//! linux 时不存在，两侧都够不着对方 ⇒ 共用点只能在这一层。本类型不碰 OS、不依赖任何平台原语
//! （只有 `AtomicUsize` + `Arc`），故两条腿的行为由同一份单测钉住。Windows 腿受
//! `PIPE_INSTANCES = 4` 天然限流，不消费本模块。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// 在途连接数上限。
///
/// 值 **可调，无契约源**：Go 源无上限，本条是新增护栏。取 32 —— 客户端是单个 app、一请求一连接，
/// 正常在途并发个位数；同位点的 Windows 腿受 `PIPE_INSTANCES = 4` 天然限流，32 已宽它一个量级，
/// 不会误伤正常流量。两条腿取同一个值：口径分叉等于给「哪条腿更容易被打穿」留出无人看管的差异。
pub const MAX_CONCURRENT_CONNECTIONS: usize = 32;

/// 连接并发闸：拿到许可才起执行体，许可随执行体结束归还。
#[derive(Debug)]
pub struct ConnLimiter {
    live: AtomicUsize,
    max: usize,
}

impl ConnLimiter {
    #[must_use]
    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            live: AtomicUsize::new(0),
            max,
        })
    }

    /// 取一个许可；已达上限返回 `None`。
    ///
    /// **快速失败**（不排队、不阻塞 accept 循环）：排队等于把耗尽从执行体搬到队列，攻击面不变；
    /// 而阻塞 accept 会让合法客户端也连不上。
    pub fn try_acquire(self: &Arc<Self>) -> Option<ConnPermit> {
        self.live
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.max).then_some(n + 1)
            })
            .ok()?;
        Some(ConnPermit(Arc::clone(self)))
    }

    /// 当前在途连接数（观测/单测用）。
    #[must_use]
    pub fn live(&self) -> usize {
        self.live.load(Ordering::Acquire)
    }
}

/// 在途连接许可：drop 即归还。
///
/// 必须是 RAII 而不是手工加减：连接执行体可能在处理的任意一步 panic 退出，手工归还会漏，
/// 漏几次就把闸门永久关死（比没有闸更糟）。
#[derive(Debug)]
pub struct ConnPermit(Arc<ConnLimiter>);

impl Drop for ConnPermit {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests;
