use super::*;

fn initial() -> MountGateState {
    MountGateState::default()
}

// ── 上屏时机（[`resolve_show_timing`]）────────────────────────────────────
//
// 变异对照（改坏哪一处 → 哪条转红）：
//   · 整个函数恒返回 `Now`（= 退回本次改动前「建窗即上屏」）→ `blank_window_is_never_shown_before_ready` 红
//   · `!gate_enabled` 写成 `gate_enabled`                    → `gate_disabled_must_never_hold_the_window` 红
//     （外加 `blank_window_is_never_shown_before_ready` 一并红）
//   · 去掉 `|| ready`                                        → `ready_window_shows_immediately` 红
//   · 去掉 `|| currently_visible`                            → `visible_window_is_never_pulled_back` 红

/// 本次要修的那条：门武装 + 当前文档没 mount 成功 + 窗还没上屏 → 必须扣住，等首帧可绘。
#[test]
fn blank_window_is_never_shown_before_ready() {
    assert_eq!(
        resolve_show_timing(true, false, false),
        ShowTiming::WhenReady
    );
}

/// 门没武装（dev 档默认关）⇒ `renderer:ready` 永远不会被投递到门里 ⇒ 扣窗 = 窗口永不出现。
/// 空窗只是难看，死界面是坏掉，故此处必须让路。
#[test]
fn gate_disabled_must_never_hold_the_window() {
    assert_eq!(resolve_show_timing(false, false, false), ShowTiming::Now);
}

/// 当前文档已 mount 成功 → 窗里本就有内容，没有可等的东西。托盘/dock 反复唤出走这条，必须零延迟。
#[test]
fn ready_window_shows_immediately() {
    assert_eq!(resolve_show_timing(true, true, false), ShowTiming::Now);
}

/// 窗口已在屏上 → 扣它只能先 hide，那是「窗突然消失又回来」的闪烁，比空窗更糟。已上屏只能往前走。
#[test]
fn visible_window_is_never_pulled_back() {
    assert_eq!(resolve_show_timing(true, false, true), ShowTiming::Now);
}

#[test]
fn show_probe_coalesces_repeated_requests_without_losing_cold_attribution() {
    let mut probe = MainWindowShowProbe::new(false);
    probe.register_request(true);
    probe.register_request(false);
    assert!(probe.cold, "任一次命中无主窗态，整轮都必须归为 cold");
    assert_eq!(probe.requests, 3, "加载期重复双击须保留在同一轮计数里");
}

#[test]
fn page_started_arms_the_gate() {
    let (s, a) = reduce_mount_gate(initial(), MountGateEvent::PageStarted);
    assert_eq!(a, MountGateAction::Arm);
    assert!(!s.ready);
}

#[test]
fn ready_clears_the_gate() {
    let (s, _) = reduce_mount_gate(initial(), MountGateEvent::PageStarted);
    let (s, a) = reduce_mount_gate(s, MountGateEvent::RendererReady);
    assert_eq!(a, MountGateAction::Clear);
    assert!(s.ready);
}

#[test]
fn timeout_without_ready_reloads_once_then_finalizes() {
    let (s, _) = reduce_mount_gate(initial(), MountGateEvent::PageStarted);
    let (s, a) = reduce_mount_gate(s, MountGateEvent::Timeout);
    assert_eq!(a, MountGateAction::Reload);
    assert!(s.reloaded && s.reloading);

    // reload 后的新文档：PageStarted → 重新武装
    let (s, a) = reduce_mount_gate(s, MountGateEvent::PageStarted);
    assert_eq!(a, MountGateAction::Arm);
    assert!(!s.reloading);

    // 二次超时 → 终局
    let (s, a) = reduce_mount_gate(s, MountGateEvent::Timeout);
    assert_eq!(a, MountGateAction::Fatal);
    assert!(s.finalized);
}

/// L1 不变式：reload 在途时到达的**陈旧 ready**（来自 pre-reload 旧文档）必须被丢弃。
/// 若被采信 → ready=true → 重载页再 C 类失败时 Timeout 走 `ready` 分支 no-op → 门失明、无终局兜底。
#[test]
fn stale_ready_during_reload_does_not_blind_the_gate() {
    let (s, _) = reduce_mount_gate(initial(), MountGateEvent::PageStarted);
    let (s, a) = reduce_mount_gate(s, MountGateEvent::Timeout);
    assert_eq!(a, MountGateAction::Reload);

    // 旧文档的在途 ready 到达 → 必须丢弃
    let (s, a) = reduce_mount_gate(s, MountGateEvent::RendererReady);
    assert_eq!(a, MountGateAction::None);
    assert!(!s.ready, "陈旧 ready 被采信 → 门失明");

    // 重载页 mount 又失败 → 必须能升级到终局
    let (s, _) = reduce_mount_gate(s, MountGateEvent::PageStarted);
    let (_, a) = reduce_mount_gate(s, MountGateEvent::Timeout);
    assert_eq!(a, MountGateAction::Fatal, "reload 后仍须能升级终局");
}

/// 新文档开始加载必须作废上一文档的 ready，否则重载页天然被判「已就绪」→ 门失明。
#[test]
fn page_started_resets_stale_ready_from_previous_document() {
    let (s, _) = reduce_mount_gate(initial(), MountGateEvent::PageStarted);
    let (s, _) = reduce_mount_gate(s, MountGateEvent::RendererReady);
    assert!(s.ready);
    let (s, a) = reduce_mount_gate(s, MountGateEvent::PageStarted);
    assert_eq!(a, MountGateAction::Arm);
    assert!(!s.ready, "新文档必须重新证明能 mount");
}

/// finalized 后，除 PageStarted 外一切事件 no-op（终局页已是末路，ready/timeout 不该再驱动任何动作）。
#[test]
fn finalized_gate_is_inert_except_new_page_load() {
    let s = MountGateState {
        finalized: true,
        ..initial()
    };
    for ev in [MountGateEvent::RendererReady, MountGateEvent::Timeout] {
        let (next, a) = reduce_mount_gate(s, ev);
        assert_eq!(a, MountGateAction::None);
        assert_eq!(next, s);
    }
}

/// **真机实测逼出的不变式**：B 类（load 失败）页面上 `__TAURI_INTERNALS__` 不存在 → 终局页按钮只能
/// 回退 `location.reload()`（发不出 fatal_retry）。那条路径必须仍能让门复活，否则恢复出来的页面再白屏
/// 就彻底无兜底 —— 逃生门不能依赖它要救的那套东西还活着。
#[test]
fn new_page_load_revives_finalized_gate_without_ipc() {
    let s = MountGateState {
        finalized: true,
        reloaded: true,
        ..initial()
    };
    // 用户在终局页点重载 → location.reload() → 新文档 PageStarted
    let (s, a) = reduce_mount_gate(s, MountGateEvent::PageStarted);
    assert_eq!(a, MountGateAction::Arm, "门必须复活并重新武装");
    assert!(!s.finalized);
    assert!(s.reloaded, "reloaded 须粘滞（防自动重载死循环）");
    // 恢复后的页面能 mount → 门满足
    let (s2, a) = reduce_mount_gate(s, MountGateEvent::RendererReady);
    assert_eq!(a, MountGateAction::Clear);
    assert!(s2.ready);
    // 若恢复后的页面又 C 类失败 → 因 reloaded 粘滞，直接进终局页（不再自动 reload）
    let (_, a) = reduce_mount_gate(s, MountGateEvent::Timeout);
    assert_eq!(
        a,
        MountGateAction::Fatal,
        "手动重载再失败应直落终局，不得再自动 reload"
    );
}

/// 防自动重载死循环：`reloaded` 必须跨 reload→PageStarted 粘滞，否则 timeout→Reload→navigate→
/// PageStarted 重置 reloaded→timeout→Reload… 无限循环烧 CPU。
#[test]
fn reloaded_is_sticky_across_navigation_no_infinite_auto_reload() {
    let (s, _) = reduce_mount_gate(initial(), MountGateEvent::PageStarted);
    let (s, a) = reduce_mount_gate(s, MountGateEvent::Timeout);
    assert_eq!(a, MountGateAction::Reload);
    // Reload 触发 navigate → 新文档 PageStarted
    let (s, _) = reduce_mount_gate(s, MountGateEvent::PageStarted);
    assert!(s.reloaded, "reloaded 不得被 PageStarted 重置");
    // 第二次 timeout 必须是 Fatal 而非又一次 Reload
    let (_, a) = reduce_mount_gate(s, MountGateEvent::Timeout);
    assert_eq!(
        a,
        MountGateAction::Fatal,
        "第二次超时必须终局，不得无限自动 reload"
    );
}

/// 不变式 6：`fatal_retry` 的 `reset()` 让门**全量**复位（含 reloaded）——用户显式「我要重来一遍」，
/// 故连自动 reload 的额度也一并归还，区别于上面「手动 location.reload()」的半复位。
#[test]
fn fatal_retry_reset_fully_revives_the_gate() {
    // reset() 等价把状态置回 default
    let s = MountGateState::default();
    let (s, a) = reduce_mount_gate(s, MountGateEvent::PageStarted);
    assert_eq!(a, MountGateAction::Arm);
    assert!(!s.reloaded, "reset 后自动 reload 额度须归还");
    let (_, a) = reduce_mount_gate(s, MountGateEvent::Timeout);
    assert_eq!(
        a,
        MountGateAction::Reload,
        "reset 后应重新享有一次自动 reload"
    );
}

#[test]
fn console_rate_limit_admits_up_to_max_then_drops() {
    let mut ts: Vec<u64> = Vec::new();
    for i in 0..10 {
        let (next, admit) = admit_console_message(&ts, 1_000 + i, 1_000, 10);
        ts = next;
        assert!(admit, "窗口内前 10 条应放行");
    }
    let (next, admit) = admit_console_message(&ts, 1_010, 1_000, 10);
    assert!(!admit, "超上限应丢弃");
    assert_eq!(next.len(), 10, "丢弃的条目不得占额度（否则风暴期无界增长）");
}

#[test]
fn console_rate_limit_prunes_outside_window() {
    let ts: Vec<u64> = (0..10).map(|i| 1_000 + i).collect();
    let (next, admit) = admit_console_message(&ts, 5_000, 1_000, 10);
    assert!(admit, "旧时刻出窗后应重新放行");
    assert_eq!(next, vec![5_000]);
}

#[test]
fn truncate_keeps_short_messages_and_marks_long_ones() {
    assert_eq!(truncate_console_message("abc", 10), "abc");
    assert_eq!(truncate_console_message("abcdef", 3), "abc…(+3 chars)");
}

/// 多字节字符必须按 char 边界切（按 byte 切会 panic —— 逃生门自己崩了就没救了）。
#[test]
fn truncate_is_utf8_safe() {
    let msg = "渲染进程错误：节点配置解析失败";
    let out = truncate_console_message(msg, 4);
    assert!(out.starts_with(
        "渲染进程错"[..]
            .chars()
            .take(4)
            .collect::<String>()
            .as_str()
    ));
    assert!(out.contains("chars)"));
}

#[test]
fn renderer_log_boundary_redacts_credentials_after_bounding_input() {
    let out = sanitize_renderer_log_message(
        "probe failed: password=secret https://user:pass@example.com/path?token=abc",
        4_096,
    );
    assert!(!out.contains("secret"));
    assert!(!out.contains("user:pass"));
    assert!(!out.contains("token=abc"));
    assert!(out.contains("example.com"), "应保留非敏感的目标主机供排障");
}

#[test]
fn renderer_log_boundary_redacts_secrets_crossing_truncation_point() {
    let url_secret = "CROSS_BOUNDARY_URL_SECRET";
    let url = format!(
        "{} https://user:{url_secret}@example.com/path",
        "x".repeat(79)
    );
    // 若先截断，这个位置会恰好保留密码、丢掉 `@host`，URL 规则无法识别 userinfo。
    let url_out =
        sanitize_renderer_log_message(&url, 80 + "https://user:".len() + url_secret.len());
    assert!(!url_out.contains(url_secret));
    assert!(!url_out.contains("user:"));
    assert!(url_out.contains("example.com"));

    let pem_secret = "CROSS_BOUNDARY_PEM_SECRET";
    let pem = format!(
        "{}\n-----BEGIN PRIVATE KEY-----\n{pem_secret}\n-----END PRIVATE KEY-----",
        "y".repeat(79)
    );
    // 同样把旧顺序的截点落在 PEM body 之后、END marker 之前。
    let pem_out = sanitize_renderer_log_message(
        &pem,
        80 + "-----BEGIN PRIVATE KEY-----\n".len() + pem_secret.len(),
    );
    assert!(!pem_out.contains(pem_secret));
    assert!(!pem_out.contains("BEGIN PRIVATE KEY"));
}

/// 终局页脚本必须是自洽的一段 JS：HTML 经 JSON 字面量嵌入，不得裸拼引号。
#[test]
fn fatal_page_script_embeds_html_as_js_literal() {
    let js = fatal_page_script(crate::i18n::Lang::EnUS);
    assert!(js.contains("polaris-fatal-reload"), "须含重载按钮 id");
    assert!(js.contains("__TAURI_INTERNALS__"), "按钮须能回主进程复位门");
    assert!(js.contains("fatal_retry"), "须调 fatal_retry 命令");
    assert!(js.contains("location.reload()"), "invoke 不可用须有回退");
    assert!(js.contains(r#"d.documentElement.lang="en-US""#));
    assert!(js.contains(r#"h.textContent="Interface failed to initialize""#));
    assert!(js.contains(r#"b.textContent="Reload""#));
    assert!(js.contains("p.textContent="), "正文须经 textContent 写入");
    // innerHTML 赋值必须是 JSON 字面量（带转义的双引号串），而非裸 HTML 拼接
    assert!(
        js.contains(r#"d.body.innerHTML="<div"#),
        "HTML 须以 JS 字符串字面量嵌入"
    );

    let rtl = fatal_page_script(crate::i18n::Lang::Fa);
    assert!(rtl.contains(r#"d.documentElement.lang="fa""#));
    assert!(rtl.contains(r#"d.documentElement.dir="rtl""#));
    assert!(rtl.contains("راه‌اندازی رابط کاربری انجام نشد"));
}
