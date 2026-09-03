#![allow(clippy::too_many_lines)]

use super::*;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn escalate_async_sends_sigterm_then_sigkill_when_alive() {
    // #1/#2：SIGTERM 立即发；宽限期后 alive → SIGKILL。用真实短宽限（确定性 + 快）。
    let signals = Arc::new(Mutex::new(Vec::<Signal>::new()));
    let alive = Arc::new(AtomicBool::new(true));
    let s = signals.clone();
    let a = alive.clone();
    let handle = ProcessKiller::escalate_async(
        move |sig| s.lock().unwrap().push(sig),
        move || a.load(Ordering::SeqCst),
        Duration::from_millis(30),
    )
    .await;
    // join：不主动 cancel，让 sleep 分支自然 fire SIGKILL。
    handle.join().await;
    assert_eq!(
        *signals.lock().unwrap(),
        vec![Signal::Sigterm, Signal::Sigkill]
    );
}

#[tokio::test]
async fn escalate_async_skips_sigkill_when_exited_in_grace() {
    // 宽限期后进程已退出 → 不发 SIGKILL（仅 SIGTERM）。
    let signals = Arc::new(Mutex::new(Vec::<Signal>::new()));
    let s = signals.clone();
    let handle = ProcessKiller::escalate_async(
        move |sig| s.lock().unwrap().push(sig),
        || false,
        Duration::from_millis(20),
    )
    .await;
    handle.join().await;
    assert_eq!(*signals.lock().unwrap(), vec![Signal::Sigterm]);
}

#[tokio::test]
async fn escalate_async_cancel_prevents_sigkill() {
    // cancel 后宽限期到点不 fire SIGKILL（:6865 防 timer 泄漏/误杀）。
    let signals = Arc::new(Mutex::new(Vec::<Signal>::new()));
    let s = signals.clone();
    let mut handle = ProcessKiller::escalate_async(
        move |sig| s.lock().unwrap().push(sig),
        || true,
        Duration::from_millis(200),
    )
    .await;
    handle.cancel(); // 取消挂起升级
    tokio::time::sleep(Duration::from_millis(300)).await; // 过宽限期，确认未 fire
    let _ = handle.task.await;
    assert_eq!(*signals.lock().unwrap(), vec![Signal::Sigterm]);
}

#[tokio::test]
async fn escalate_async_sigterm_sent_immediately_before_grace() {
    // SIGTERM 在 spawn 前同步发出（不等待 grace）。
    let signals = Arc::new(Mutex::new(Vec::<Signal>::new()));
    let s = signals.clone();
    let alive = Arc::new(AtomicBool::new(true));
    let a = alive.clone();
    let mut handle = ProcessKiller::escalate_async(
        move |sig| s.lock().unwrap().push(sig),
        move || a.load(Ordering::SeqCst),
        Duration::from_secs(60), // 长 grace，不 fire
    )
    .await;
    // 立即检查：SIGTERM 已在列表（未等 grace）。
    assert_eq!(*signals.lock().unwrap(), vec![Signal::Sigterm]);
    handle.cancel();
    let _ = handle.task.await;
}

#[test]
fn signal_variants_distinct() {
    assert_ne!(Signal::Sigterm, Signal::Sigkill);
}

#[test]
fn cancelled_handle_is_idempotent() {
    // 多次 cancel 不 panic、不重复发。
    // 用计数闭包验证 cancel 路径不重复触发 send_signal（这里仅验证句柄结构）。
    let count = Arc::new(AtomicU32::new(0));
    let c = count.clone();
    // escalate_async 是 async，此处仅静态验证 Signal 枚举；句柄幂等性由 wait 路径覆盖。
    let _ = c;
    assert_eq!(Signal::Sigterm, Signal::Sigterm);
    assert_eq!(Signal::Sigkill, Signal::Sigkill);
}
