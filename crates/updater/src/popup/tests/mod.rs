use super::*;
use std::cell::RefCell;

/// 记录型 transport：把推送过的状态与窗高留痕，供断言。
#[derive(Debug, Default)]
struct RecordingTransport {
    sent: RefCell<Vec<UpdatePopupState>>,
    heights: RefCell<Vec<u32>>,
    fail: bool,
}

impl RecordingTransport {
    fn failing() -> Self {
        Self {
            fail: true,
            ..Self::default()
        }
    }
}

impl PopupTransport for RecordingTransport {
    fn send_state(&self, state: &UpdatePopupState) -> Result<(), String> {
        if self.fail {
            return Err("mock: window destroyed".into());
        }
        self.sent.borrow_mut().push(state.clone());
        Ok(())
    }

    fn set_content_height(&self, height: u32) -> Result<(), String> {
        if self.fail {
            return Err("mock: window destroyed".into());
        }
        self.heights.borrow_mut().push(height);
        Ok(())
    }
}

// ── #300/#301 不变式 ──

#[test]
fn open_seeds_last_state_the_300_invariant() {
    // #300 的根因：新建窗口路径从不下发初始态 → lastPopupState 恒 null → 重放条件 false → 页面永空。
    // 本移植：open 是 bootstrap 的唯一产地，必然 seed。
    let mut s = PopupSession::new(RecordingTransport::default());
    assert!(!s.is_seeded(), "建窗前不应有状态");

    let boot = s.open(UpdatePopupState::remind("4.2.4", "v4.2.3"));

    assert!(s.is_seeded(), "#300 不变式：open 后 last_state 必须有料");
    assert_eq!(s.last_state().unwrap().phase, PopupPhase::Remind);
    // bootstrap 必须真的带上初始态（页面首帧的唯一来源）。
    assert!(boot
        .init_script
        .contains("__POLARIS_UPDATE_POPUP_INITIAL__"));
    assert!(boot.init_script.contains("\"phase\":\"remind\""));
    assert!(boot.init_script.contains("\"version\":\"4.2.4\""));
}

#[test]
fn open_bootstrap_carries_remind_geometry() {
    // remind 是 #300 唯一中招的入口态：窗高必须是 184，宽 380。
    let mut s = PopupSession::new(RecordingTransport::default());
    let boot = s.open(UpdatePopupState::remind("4.2.4", "v4.2.3"));
    assert_eq!(boot.width, POPUP_WIDTH);
    assert_eq!(boot.height, 184, "remind 态窗高（对齐 popupHeightFor）");
}

#[test]
fn replay_after_open_always_has_payload() {
    // did-finish-load 重放：#300 里这一步恒 false（lastPopupState null）。本移植恒有料。
    let mut s = PopupSession::new(RecordingTransport::default());
    s.open(UpdatePopupState::remind("4.2.4", "v4.2.3"));

    assert!(s.replay().unwrap(), "open 之后重放必须有料可放");
    let sent = s.transport().sent.borrow();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].phase, PopupPhase::Remind);
}

#[test]
fn replay_without_open_reports_empty_rather_than_lying() {
    // 哨兵：未 open 就重放 → false（本移植下不可达；若为 true 说明 last_state 被别处写脏）。
    let s: PopupSession<RecordingTransport> = PopupSession::new(RecordingTransport::default());
    assert!(!s.replay().unwrap());
    assert!(s.transport().sent.borrow().is_empty());
}

#[test]
fn send_state_writes_last_state_even_when_push_fails() {
    // 上游把 `lastPopupState = state` 放在 destroyed 检查之前（UpdateService.ts:637），
    // 正是为了「推送失败也不让重放失去依据」。此处钉住该时序。
    let mut s = PopupSession::new(RecordingTransport::failing());
    s.open(UpdatePopupState::remind("4.2.4", "v4.2.3"));

    let r = s.send_state(UpdatePopupState::progress(42, None, None));
    assert!(r.is_err(), "mock transport 应报失败");
    // 关键：推送失败，但 last_state 已推进到 progress。
    assert_eq!(s.last_state().unwrap().phase, PopupPhase::Progress);
    assert_eq!(s.last_state().unwrap().percentage, Some(42));
}

// ── 代次（🟡#4/F1）：进程级发号，跨会话不复用 ──

/// 🟡#4/F1：代次语义——`open` 从**进程级**计数领新号；`reuse` / `send_state`（同窗流转）不换号；
/// **跨会话**（旧会话被丢弃、新会话从 `new` 重开）必须领到更大的号。
///
/// 生存域是这条守卫的命门（复审 F1 的教训）：若代次是每会话对象自增，宿主「关旧窗 →
/// 3s 内开新窗」恰好撞回同一编号（1==1），陈旧定时器照样关掉新窗——判据在单会话内全绿、
/// 在标称主场景失效。故第 4 条（跨会话）是本测试的真牙。
///
/// **变异探针**：把 `open` 的领号改回 `self.generation += 1` ⇒ 第 4 条红；挪进 `reuse` ⇒
/// 第 3 条红；删掉 ⇒ 第 2 条红。
#[test]
fn generation_is_process_scoped_and_advances_only_on_new_windows() {
    let mut s = PopupSession::new(RecordingTransport::default());
    assert_eq!(s.generation(), 0, "未建窗的会话代次是 0（未领号）");
    s.open(UpdatePopupState::remind("v1.2.0", "v1.1.0"));
    let first = s.generation();
    assert!(first > 0, "建窗后必须已从进程计数领到号");
    s.reuse(UpdatePopupState::progress(30, None, None)).unwrap();
    s.send_state(UpdatePopupState::no_update(Some("v1.2.0".to_string())))
        .unwrap();
    assert_eq!(
        s.generation(),
        first,
        "同一扇窗的状态流转（reuse/send_state）不得换号 —— 换了会作废本窗的合法定时器"
    );
    // 跨会话（= 复审 F1 的主场景）：模拟宿主「关窗清槽（丢弃整个 session）→ 另一条腿
    // 新建弹窗（new 一个新 session 再 open）」。新窗必须领到**更大**的号——否则两扇窗
    // 同号，旧窗的定时器 fire 时对上号，把新窗关掉。
    drop(s);
    let mut s2 = PopupSession::new(RecordingTransport::default());
    assert_eq!(s2.generation(), 0, "新会话建窗前同样未领号");
    s2.open(UpdatePopupState::remind("v1.3.0", "v1.1.0"));
    assert!(
        s2.generation() > first,
        "跨会话必须领到更大的号（实得 {} ≤ 旧窗 {}）—— 每会话自增的代次会让\
             「关旧 3s 内开新」撞回同号，陈旧定时器关掉新窗（复审 F1）",
        s2.generation(),
        first
    );
}

// ── 邀请过的版本号：会话级事实，跨 phase 不蒸发 ──

/// 🟡 **不变量：一次弹窗会话邀请过的版本号，跨 phase 一直在。**
///
/// `progress` / `error` / `done` 三个构造点都不填 `version`。不继承的话，会话一离开 remind 就
/// 忘了自己邀请过谁，而 `Error` 态恰恰挂着**两个**需要它的动作（[`PopupAction::is_valid_for`]
/// 白名单里的 `Retry` 与 `ManualDownload`）：
///  - `Retry`：宿主拿它与复查回来的版本对账。恒 `None` ⇒ 恒判「变了」⇒ 退回 remind、一个字节
///    都不下，「重试」退化成「返回」。
///  - `ManualDownload`：拿它拼该版本的 release tag 页；`None` 回落泛列表页（#311 修的就是这个）。
///
/// **变异探针**：删掉 `send_state` 里那三行继承 ⇒ 本条转红（且 `error` 那格恰好复刻真实故障）。
#[test]
fn the_invited_version_survives_phase_changes() {
    let mut s = PopupSession::new(RecordingTransport::default());
    s.open(UpdatePopupState::remind_with_channel(
        "v1.2.0", "v1.1.0", true,
    ));

    for (step, state) in [
        ("progress", UpdatePopupState::progress(30, None, None)),
        (
            "error",
            UpdatePopupState::error(UpdateErrCode::DownloadFailed, "net down"),
        ),
        ("done", UpdatePopupState::done(None, "/tmp/polaris.dmg")),
        ("noupdate", UpdatePopupState::no_update(None)),
    ] {
        s.send_state(state).unwrap();
        assert_eq!(
            s.last_state().unwrap().version.as_deref(),
            Some("v1.2.0"),
            "{step} 态把邀请版本弄丢了 —— error 态丢它会让「重试」永不下载"
        );
        assert_eq!(
            s.last_state().unwrap().include_prerelease,
            Some(true),
            "{step} 态把邀请通道弄丢了 —— 复查会改用稳定版候选集"
        );
    }

    // 推给 renderer 的载荷也得带着它（宿主读的是 `popup_state()`，而它就是 last_state 的克隆；
    // 这里连推送侧一起钉，免得将来有人只改 last_state 不改推送）。
    let sent = s.transport().sent.borrow();
    assert!(
        sent.iter().all(|p| p.version.as_deref() == Some("v1.2.0")),
        "推送出去的状态里版本号丢了：{sent:?}"
    );
}

/// 🟡 **新邀请压过旧记忆：`remind` 恒显式带版本，不被继承值污染。**
///
/// 继承只在 `version.is_none()` 时发生。这条钉住「同一会话里换了个版本重新提醒」时不会举着
/// 上一轮的版本号 —— 本批 `update_popup_action` 的对账不一致分支正是这么用的。
#[test]
fn a_fresh_remind_overrides_the_inherited_version() {
    let mut s = PopupSession::new(RecordingTransport::default());
    s.open(UpdatePopupState::remind("v1.2.0", "v1.1.0"));
    s.send_state(UpdatePopupState::progress(10, None, None))
        .unwrap();
    s.send_state(UpdatePopupState::remind("v1.3.0", "v1.1.0"))
        .unwrap();
    assert_eq!(
        s.last_state().unwrap().version.as_deref(),
        Some("v1.3.0"),
        "新一轮 remind 必须覆盖继承来的旧版本号"
    );
}

// ── 状态流转 / 窗高 ──

#[test]
fn send_state_adjusts_height_only_on_phase_height_change() {
    let mut s = PopupSession::new(RecordingTransport::default());
    s.open(UpdatePopupState::remind("4.2.4", "v4.2.3")); // 184
    s.send_state(UpdatePopupState::progress(10, None, None))
        .unwrap(); // 116 → 改高
    s.send_state(UpdatePopupState::progress(20, None, None))
        .unwrap(); // 116 → 同高，不改
    s.send_state(UpdatePopupState::error(
        UpdateErrCode::DownloadFailed,
        "boom",
    ))
    .unwrap(); // 152 → 改高

    let heights = s.transport().heights.borrow();
    assert_eq!(
        *heights,
        vec![116, 152],
        "仅在窗高真变化时调用 setContentSize"
    );
}

#[test]
fn reuse_branch_sends_state_immediately() {
    // 复用分支（Polaris createUpdatePopup:542-545）：直接下发 + 早返回。
    let mut s = PopupSession::new(RecordingTransport::default());
    s.open(UpdatePopupState::remind("4.2.4", "v4.2.3"));
    s.transport().sent.borrow_mut().clear();

    s.reuse(UpdatePopupState::progress(5, None, None)).unwrap();
    let sent = s.transport().sent.borrow();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].phase, PopupPhase::Progress);
}

#[test]
fn reset_clears_state_on_close() {
    let mut s = PopupSession::new(RecordingTransport::default());
    s.open(UpdatePopupState::remind("4.2.4", "v4.2.3"));
    assert!(s.is_seeded());
    s.reset();
    assert!(!s.is_seeded());
}

// ── 布局 / 载荷 ──

#[test]
fn popup_heights_match_upstream_layout() {
    // 逐字对齐 update-popup-layout.ts:18-28。
    assert_eq!(popup_height_for(PopupPhase::Remind), 184);
    assert_eq!(popup_height_for(PopupPhase::Error), 152);
    assert_eq!(popup_height_for(PopupPhase::Progress), 116);
    assert_eq!(popup_height_for(PopupPhase::Done), 116);
    // 上游无此态（本移植新增），与 progress/done 同档，见 `popup_height_for` 文档。
    assert_eq!(popup_height_for(PopupPhase::NoUpdate), 116);
    assert_eq!(POPUP_WIDTH, 380);
    assert_eq!(DONE_AUTO_CLOSE_MS, 800);
    // 钉的是**关系**不是数值：3s 属判断值、可调；「不得短于 done 的确认动画」才是不变量
    // （沿用 800ms 等于让那句话一闪而过 = 说了等于没说）。经 `let` 读取是为了绕开
    // clippy::assertions_on_constants —— 它只认常量表达式，而这里要断言的正是两个常量的关系。
    let (settle_ms, read_ms) = (DONE_AUTO_CLOSE_MS, NO_UPDATE_AUTO_CLOSE_MS);
    assert!(
        read_ms > settle_ms,
        "「没有可下载的更新」是唯一要求用户读完一句话的终态，停留时间不得短于 done 的确认动画"
    );
}

#[test]
fn state_serializes_camel_case_lowercase_phase() {
    // 前端契约：phase 小写、字段 camelCase。
    let s = UpdatePopupState {
        phase: PopupPhase::Progress,
        percentage: Some(37),
        received_bytes: Some(19_240_000),
        total_bytes: Some(52_000_000),
        mirror: true,
        ..UpdatePopupState::default()
    };
    let j = serde_json::to_string(&s).unwrap();
    assert!(j.contains("\"phase\":\"progress\""), "phase 必须小写: {j}");
    assert!(j.contains("\"receivedBytes\":19240000"), "camelCase: {j}");
    assert!(j.contains("\"totalBytes\":52000000"), "camelCase: {j}");
    assert!(j.contains("\"mirror\":true"));
    // None 字段不出现（前端按可选处理）。
    assert!(!j.contains("errorCode"));
    assert!(!j.contains("filePath"));
    // 新增那一档的 phase 串（跨语言契约：TS 侧 `PopupPhase` 联合逐字用它）。
    assert!(
        serde_json::to_string(&UpdatePopupState::no_update(None))
            .unwrap()
            .contains("\"phase\":\"noupdate\""),
        "noupdate 的 phase 串变了 —— 渲染端会掉进「未知状态」兜底分支"
    );
}

/// 🟡 **分母未知时不许拿已收字节凑一个假分母。**
///
/// 清单 `fileSize` 缺失或为 0 时 `total_bytes` 必须是 `None`：渲染端据此只显示已收量。
/// 传 `Some(0)` 进来也当没有 —— 否则前端会算出 `x / 0.0 MB` 甚至除零。
///
/// **变异探针**：去掉 `total.filter(|n| *n > 0)` ⇒ 第二条转红。
#[test]
fn progress_bytes_are_carried_verbatim_and_a_zero_total_is_not_a_denominator() {
    let p = UpdatePopupState::progress(37, Some(19_240_000), Some(52_000_000));
    assert_eq!(p.received_bytes, Some(19_240_000), "已收字节须是回调原值");
    assert_eq!(p.total_bytes, Some(52_000_000));

    let zero = UpdatePopupState::progress(37, Some(19_240_000), Some(0));
    assert_eq!(
        zero.total_bytes, None,
        "`fileSize` 为 0 = 分母未知，不得当成真分母"
    );
    assert_eq!(zero.received_bytes, Some(19_240_000), "已收量仍是真的");

    let blind = UpdatePopupState::progress(0, None, None);
    assert_eq!((blind.received_bytes, blind.total_bytes), (None, None));
}

#[test]
fn progress_percentage_clamped() {
    assert_eq!(
        UpdatePopupState::progress(200, None, None).percentage,
        Some(100)
    );
}

#[test]
fn done_state_is_full_and_matches_layout() {
    // done 与 progress 同高（116），进度条留满值——否则最后一帧掉回 0。
    let d = UpdatePopupState::done(Some("v1.2.0".into()), "/tmp/updates/polaris.dmg");
    assert_eq!(d.phase, PopupPhase::Done);
    assert_eq!(d.percentage, Some(100));
    assert_eq!(d.height(), 116);
    // 「完成」必须说得出下的是哪一版、落在哪儿 —— 否则它与「什么都没下」长得一模一样。
    assert_eq!(d.version.as_deref(), Some("v1.2.0"));
    assert_eq!(d.file_path.as_deref(), Some("/tmp/updates/polaris.dmg"));
    // done 态用户无按钮可点，仅容 close 兜底（上游白名单）。
    assert!(PopupAction::Close.is_valid_for(PopupPhase::Done));
    assert!(!PopupAction::Cancel.is_valid_for(PopupPhase::Done));
}

/// 🟡 **「没有可下载的更新」是独立一档，且它与 `done` 在载荷上分得开。**
///
/// 分不开就等于没分：若本态也带 `file_path` / 满格 `percentage`，渲染端只要读错一个字段
/// 就又把它画成「下载完成」。这里钉住它**只**带主语。
///
/// **变异探针**：把 `no_update` 改成 `done(version, "")` ⇒ phase / file_path 两条转红。
#[test]
fn no_update_state_carries_only_its_subject() {
    let n = UpdatePopupState::no_update(Some("v1.2.0".into()));
    assert_eq!(n.phase, PopupPhase::NoUpdate);
    assert_eq!(n.version.as_deref(), Some("v1.2.0"), "得说得出是关于哪一版");
    assert_eq!(n.file_path, None, "一个字节都没下，不许带落位路径");
    assert_eq!(
        n.percentage, None,
        "不许带进度 —— 满格进度条正是那句谎话的形状"
    );
    assert_eq!(n.height(), 116);
    // 终态：只容 close 兜底（角标 × 与 Esc 都发它）。
    assert!(PopupAction::Close.is_valid_for(PopupPhase::NoUpdate));
    assert!(!PopupAction::Retry.is_valid_for(PopupPhase::NoUpdate));
    assert!(!PopupAction::Update.is_valid_for(PopupPhase::NoUpdate));
}

// ── 动作白名单 ──

#[test]
fn action_whitelist_per_phase_matches_upstream() {
    use PopupAction::{Cancel, Close, ManualDownload, Retry, Skip, Update, ViewLog};
    // remind：update / later / skip / viewLog
    assert!(Update.is_valid_for(PopupPhase::Remind));
    assert!(Skip.is_valid_for(PopupPhase::Remind));
    assert!(ViewLog.is_valid_for(PopupPhase::Remind));
    assert!(!Retry.is_valid_for(PopupPhase::Remind));
    // progress：仅 cancel
    assert!(Cancel.is_valid_for(PopupPhase::Progress));
    assert!(!Update.is_valid_for(PopupPhase::Progress));
    // error：retry / manualDownload / close
    assert!(Retry.is_valid_for(PopupPhase::Error));
    assert!(ManualDownload.is_valid_for(PopupPhase::Error));
    assert!(Close.is_valid_for(PopupPhase::Error));
    assert!(!Cancel.is_valid_for(PopupPhase::Error));
}

#[test]
fn view_log_is_non_resolving() {
    // Polaris UpdateService.ts:683-686：viewLog 开页面但不 resolve，弹窗停在 remind。
    assert!(PopupAction::ViewLog.is_non_resolving());
    assert!(!PopupAction::Update.is_non_resolving());
    assert!(!PopupAction::Skip.is_non_resolving());
}

#[test]
fn action_serde_camel_case() {
    assert_eq!(
        serde_json::to_string(&PopupAction::ManualDownload).unwrap(),
        "\"manualDownload\""
    );
    assert_eq!(
        serde_json::from_str::<PopupAction>("\"viewLog\"").unwrap(),
        PopupAction::ViewLog
    );
}

// ── 载荷的两道结构门：字段有没有人写 / 每一档带没带它那屏要的事实 ──────────────

/// 本文件自身的源码（源码级判据的取材源；同 `crates/unlock-transport` 的自扫先例）。
fn src() -> String {
    polaris_source_probe::crate_source!("popup.rs")
}

/// 取 `impl UpdatePopupState {` 块的源码切片，并剥掉整行注释。
///
/// **必须封顶到该 impl 自己的列 0 右花括号**：切到 EOF 会把 `#[cfg(test)]` 模块一起吃进来，
/// 而测试里到处都是 `field: value` 的构造字面量 —— 判据会被自己的样本喂饱，「字段没人写」
/// 永远查不出来（本仓登记在案的「邻居喂饱判据」形态）。
///
/// 剥整行注释同理：本 impl 的文档注释里逐字写着 `version: None`、`bytes_text: Option<String>`
/// 这类字样，不剥就等于让注释替生产代码作证（同 `commands::guard_scan::strip_line_comments`
/// 的理由）。
fn state_impl_block() -> String {
    let src = src();
    const ANCHOR: &str = "impl UpdatePopupState {";
    let at = src
        .find(ANCHOR)
        .expect("锚点消失：`impl UpdatePopupState` 被改形，本门已失去判据");
    let rest = &src[at..];
    let end = rest
        .find("\n}\n")
        .expect("找不到 `impl UpdatePopupState` 的列 0 右花括号");
    rest[..end]
        .lines()
        .map(|l| {
            if l.trim_start().starts_with("//") {
                ""
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// 取 `impl UpdatePopupState` 里**全部 `Self { … }` 结构体字面量的体**（按花括号配对切）。
///
/// # 为什么取材面必须是字面量体，而不是整个 impl 块
///
/// 「字段有没有被写」这句话的意图面很窄：**某个字段名出现在一个结构体字面量的字段位上**。
/// 前一版把取材面放到整个 impl 块 + 行首 `<ident>:` 的形状上，宽了一级 —— 而宽出来的那一格
/// 恰好装得下**函数签名的形参声明**：`done` 只要多一个参数，rustfmt 就会把签名折成
///
/// ```text
///     pub fn done(
///         version: Option<String>,
///         file_path: impl Into<String>,   // ← 行首裸标识符 + 冒号，与字段写点同形
///     ) -> Self {
/// ```
///
/// 于是删掉 `file_path: Some(..)` 这个真写点之后本门照样绿（复审实测 M4b）。那正是本门存在的
/// 意义所在的反面：**新加的字段没有专属断言，全靠本门兜底**，兜漏了就是 `bytes_text` 躺一个
/// 移植周期的形态原样复发。
///
/// 按 `# 为什么取材面必须是字面量体` 收窄之后，形参列表、`let` 绑定、`match` 臂一律不在
/// 取材面内 —— 收到形状上，而不是再加一个串去堵 `_file_path:`。
///
/// # ⚠️ `Self {` 的第一击可能不是字面量，是函数签名（confirm 轮 🔴#1 实证）
///
/// `impl` 块里的构造函数签名长 `pub fn done(…) -> Self {`——`find("Self {")` **先命中它**，
/// 花括号配对切出来的是**整个函数体**，取材面悄悄宽回上一节刚否掉的那个形态：
/// `:902` 附近「形参不在取材面内」的旧登记与「没有跨行实参可混淆、认简写安全」的前提
/// 全部失效，且为消那个（本就不存在的）误红面放开的简写形态成了净回退。
/// 处置：命中 `Self {` 时若其前文本 `trim_end()` 以 `->` 结尾 ⇒ 是签名，跳过继续找下一个。
/// 收据（复审实跑）：删掉 `done` 的真写点 `file_path: Some(..)`、体内留一行折行实参 ⇒
/// 旧判据绿 / 本判据红；加零写点新字段后旁系结构体字面量在函数体内 ⇒ 旧判据全绿
/// （死字段静默过门）/ 本判据红（函数体不再入取材面）。
fn self_literal_bodies() -> Vec<String> {
    let block = state_impl_block();
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = block[from..].find("Self {") {
        let at = from + rel;
        // 函数签名的返回类型（`-> Self {`）不是字面量：跳过这一击，从它的下一个字符继续找。
        // 判据咬 `->` 的裸形状而不解析语法——本 impl 内 `->` 只出现在签名位，够窄且响亮
        // （写歪了会在下方的 `>= 4` 自检上炸，不会静默收窄）。
        if block[..at].trim_end().ends_with("->") {
            from = at + "Self {".len();
            continue;
        }
        let open = at + "Self {".len();
        let mut depth = 1usize;
        let mut end = open;
        for (i, c) in block[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + i;
                        break;
                    }
                }
                _ => {}
            }
        }
        assert!(depth == 0, "`Self {{` 的花括号没配上对 —— 取材器判据已过期");
        out.push(block[open..end].to_string());
        from = end;
    }
    assert!(
        out.len() >= 4,
        "只切到 {} 个 `Self {{ … }}` 字面量 —— 构造函数写法变了（或签名跳过判据失效），判据面塌了",
        out.len()
    );
    out
}

/// 🟡 **载荷里声明的每个字段都必须有生产写点，否则它只是个骗前端的坑。**
///
/// 这是本批第二条缺陷的判据面。`bytes_text` 在本结构里躺了整整一个移植周期：有字段、有
/// serde 单测、渲染端有读点（`state.bytesText ?? \`${pct}%\``），**唯独没有任何一处生产代码
/// 写过它** ⇒ 用户永远只看得见百分比。这种「声明了但永远是 `None`」的字段在两侧都长得跟
/// 「后端这一帧没给」一模一样，`cargo build` 与 `tsc` 都不会说话。
///
/// 判据面是**结构体自己的字段表**（不是点名清单）：加字段就自动进判据面，加完不写它必红。
/// 写点认定 = 该字段名出现在 `impl UpdatePopupState` 内某个 **`Self { … }` 字面量体**的字段位上
/// （取材器见 [`self_literal_bodies`]；那是全仓唯一的构造入口，下方反向断言钉住这个前提）。
///
/// **变异探针**：把 `progress` 里的 `received_bytes: received` 删掉 ⇒ 转红并点名
/// `received_bytes`；把 `mirror` 从待修表里去掉 ⇒ 转红（登记表只降不升，两个方向都说话）。
#[test]
fn every_declared_field_has_a_production_write_point() {
    /// 今天确实没有生产写点的字段。**逐条待修，不是豁免。**
    ///
    /// 修好（补上写点）之后本表必须一起改小 —— 下面是双向相等断言，只降不升都会说话。
    const KNOWN_INERT: [(&str, &str); 1] = [(
        "mirror",
        "待修：App 更新下载腿不回报本次走的是源站还是 gh 镜像 —— `runtime/http.rs` 的镜像回退\
             没有把结论带回调用方，故 `emit_progress` 手上根本没有这个事实。要补的是下载腿的回报\
             路径（同 W5 给进度帧补 `received` / `filePath` 的做法），不是本结构。",
    )];

    let src = src();
    let struct_at = src
        .find("pub struct UpdatePopupState {")
        .expect("锚点消失：结构体被改名，本门已失去判据");
    let rest = &src[struct_at..];
    let struct_body = &rest[..rest.find("\n}\n").expect("找不到结构体的列 0 右花括号")];
    // `pub <ident>: <ty>,` 才算字段 —— 必须要求有冒号，否则结构体自己的头一行
    // （`pub struct UpdatePopupState {`）会被当成一个名叫 `struct UpdatePopupState {` 的字段，
    // 而它永远不会有写点 ⇒ 判据面里凭空多一个恒不满足项。
    let fields: Vec<&str> = struct_body
        .lines()
        .filter_map(|l| l.trim().strip_prefix("pub "))
        .filter_map(|l| l.split_once(':').map(|(name, _)| name))
        .filter(|n| !n.is_empty() && n.chars().all(|c| c.is_alphanumeric() || c == '_'))
        .collect();
    assert!(
        fields.len() >= 8,
        "只解析到 {} 个字段 —— 结构体写法变了，判据面塌了",
        fields.len()
    );

    // 写点 = **`Self { … }` 字面量体内**的字段位（`field: expr,` 或简写 `field,`）。
    //
    // 取材面就是那几个字面量体（见 [`self_literal_bodies`]），不是整个 impl 块 —— 后者宽出来
    // 的那一格装得下**函数签名的形参声明**：`done` 多一个参数、rustfmt 一折行，
    // `    file_path: impl Into<String>,` 就与字段写点同形，删掉真写点本门照样绿（复审实测
    // M4b）。收到字面量体之后，形参列表 / `let` 绑定 / `match` 臂一律不在取材面内。
    //
    // ⚠️ **上一版这句话曾经是假的**（confirm 轮 🔴#1）：`find("Self {")` 先命中函数签名的
    // `-> Self {`，配对切出来的是**整个函数体**，上面那段「不在取材面内」从未成立过——
    // 取材器现在跳过 `->` 前缀的命中（见 [`self_literal_bodies`] 的 ⚠️ 段），本段才重新为真。
    // 谁再动取材器，先重跑该段的变异收据，别让登记再次跑赢事实。
    //
    // 字面量体内可以既认冒号形态又认简写形态（`Self { version, .. }`，`done` / `no_update`
    // 里就有）：字面量体内没有「跨行函数实参」可混淆，认简写消掉一个误红面
    // （——这个前提同样依赖上面的签名跳过；签名混进来时「认简写」曾被折行实参喂饱过）。
    //
    // 失效方向（**登记修正**：上一版写成「两个方向都是误红」，那是错的，漏了下面第 2 条）：
    //  1. 误红 —— 某字段的写点整个消失。安全方向，正是本门要的。
    //  2. **误绿** —— 生产代码不经 `Self { … }` 造状态（比如换成 `..existing` 更新式，或另写一个
    //     builder）。那时字段确实被写了，本门却看不见其形状；反过来若那种写法**取代**了字面量，
    //     本门会因取材为空而在 [`self_literal_bodies`] 的自检上先炸（`>= 4` 那条），不会静默。
    //     真正的哑格只剩「字面量与另一种写法并存、且某字段只在后者里被写」—— 今天不可达
    //     （全部构造都是 `Self { .. }`），谁要引入第二种构造形态，请连同本门一起改判据。
    let inert: Vec<&str> = {
        let bodies = self_literal_bodies();
        let written: std::collections::BTreeSet<&str> = bodies
            .iter()
            .flat_map(|b| b.lines())
            .filter_map(|l| {
                let t = l.trim();
                // `field: expr,` / `field,` 两种字段位形态；`..Self::default()` 之类不含冒号
                // 也不是裸标识符，天然落选。
                let name = t.split_once(':').map_or_else(
                    || t.strip_suffix(',').unwrap_or(""),
                    |(name, _)| name.trim_end(),
                );
                (!name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_'))
                    .then_some(name)
            })
            .collect();
        fields
            .iter()
            .copied()
            .filter(|f| !written.contains(f))
            .collect()
    };
    let known: Vec<&str> = KNOWN_INERT.iter().map(|(f, _)| *f).collect();
    assert_eq!(
        inert, known,
        "没有生产写点的字段与待修表不符 —— 见 KNOWN_INERT 头注。\
             多出来的那个字段今天是死的：前端读到的恒是「后端没给」"
    );
    for (field, why) in KNOWN_INERT {
        assert!(
            fields.contains(&field),
            "待修表里的 `{field}` 已不在结构体上 —— 表该跟着删"
        );
        assert!(
            why.starts_with("待修"),
            "{field} 不是豁免，理由须以「待修」起头"
        );
        assert!(why.len() > 40, "{field} 的理由太短");
    }

    // 反向对照：写点认定之所以只扫 impl 块，前提是**本文件的生产代码不拿结构体字面量绕过
    // 构造函数**。该前提一旦破了（`UpdatePopupState { .. }` 直接写在别处），那些写点就在
    // impl 块之外，本门的射程立刻短于它声称的范围，而且是静默的。
    //
    // 判据：本文件生产段里 `UpdatePopupState {` 的出现处，除了「结构体声明」与「impl 头」
    // 这两个**声明形态**，一处都不许有。
    //
    // 射程（如实登记）：只扫本文件。别的 crate（如 `src-tauri`）拿字面量造这个类型，本门看
    // 不见 —— 那一侧由 `commands/updater.rs` 的调用点门与跨语言载荷门覆盖。
    let prod = &src[..src.find("\n#[cfg(test)]\n").unwrap_or(src.len())];
    let literal_sites: Vec<usize> = prod
        .match_indices("UpdatePopupState {")
        .filter(|(i, _)| {
            let before = prod[..*i].trim_end();
            !before.ends_with("struct") && !before.ends_with("impl")
        })
        .map(|(i, _)| prod[..i].lines().count() + 1)
        .collect();
    assert!(
        literal_sites.is_empty(),
        "生产代码在第 {literal_sites:?} 行拿结构体字面量造了状态 —— 绕过构造函数，\
             本门就扫不到那些写点了（也绕过了 `done` 必填落位路径这道类型闸）"
    );
}

/// 🟡 **每一档载荷都得带它那一屏依赖的随行事实，且不得夹带别档的。**
///
/// 本批第一、三条缺陷的判据面。`done` 此前零参、不带任何事实，于是：
///  - 它说不出「下了哪一版、落在哪儿」；
///  - 「什么都没下」能借用同一个构造函数收场，弹窗照样画「下载完成」+ 满格进度条。
///
/// 判据是**逐档的键集**：必带的一个不许少、登记之外的一个不许夹带。档数由
/// [`PopupPhase::ALL`] 给，而 `ALL` 自己由 `state.rs` 的门与枚举对账 ⇒ 加一档而不给它样本，
/// 这里必红。`required` / `optional` 都写成穷尽 `match` ⇒ 加一档不表态就编译不过。
///
/// # 为什么必须分「必带 / 可缺」两档
///
/// 上一版只有一张 `required` 表，靠**手写夹具**自证 —— 而那张表的 `Progress` 一行声明
/// `receivedBytes`/`totalBytes` 必带，样本恰好是 `progress(37, Some, Some)`。**生产里有反例**：
/// 用户点「更新」后复查前那一发是 `progress(0, None, None)`（`commands/updater.rs` 的
/// `Update | Retry` 臂），序列化后根本没有这两个键。即「档数覆盖」是判据定的，而「逐档带哪些
/// 键」那一半是夹具定的 —— 本仓刚在别处栽过同一形态。
///
/// 现在样本表按**档 × 生产可达形态**展开（`Progress` 两个：知道字节数的、不知道的），
/// 判据是 `required ⊆ keys ⊆ required ∪ optional`。哪个字段进 `optional` 必须有生产理由，
/// 不是「反正它可能没有」。
///
/// **变异探针**：`done` 里删掉 `file_path: Some(...)` ⇒ done 那格转红；`no_update` 里补一个
/// `percentage: Some(100)` ⇒ noupdate 那格报「夹带」；把 `receivedBytes` 从 `optional` 挪进
/// `required` ⇒ 复查前那一发的样本转红（证明这张表现在真按生产形态判，不是按夹具）。
#[test]
fn every_phase_carries_the_facts_its_screen_depends_on() {
    /// 该档序列化后**必须**出现的键。穷尽 match ⇒ 新增一档即编译错误。
    fn required(phase: PopupPhase) -> &'static [&'static str] {
        match phase {
            PopupPhase::Remind => &["phase", "version", "currentVersion"],
            // 字节数**不在**必带里：复查前那一发（`progress(0, None, None)`）此刻确实什么都
            // 不知道。百分比与版本号则每一发都有。
            PopupPhase::Progress => &["phase", "percentage", "version"],
            // 落位路径必带 —— 没有它，本档与「什么都没下」在屏幕上长得一模一样。
            PopupPhase::Done => &["phase", "version", "percentage", "filePath"],
            PopupPhase::NoUpdate => &["phase", "version"],
            PopupPhase::Error => &["phase", "version", "errorCode", "errorDetail"],
        }
    }

    /// 该档**允许出现但可缺**的键（逐条要有生产理由）。必带之外的一律算夹带。
    fn optional(phase: PopupPhase) -> &'static [&'static str] {
        match phase {
            // 分母未知时 `total_bytes` 被 `progress()` 滤成 `None`；两者同缺于复查前那一发。
            PopupPhase::Progress => &["receivedBytes", "totalBytes"],
            PopupPhase::Remind | PopupPhase::Done | PopupPhase::NoUpdate | PopupPhase::Error => &[],
        }
    }

    // 样本一律经会话下发：`version` 的会话级继承是生产路径的一部分（`error` / `done` 的版本号
    // 就是这么来的），拿裸构造体断言等于测了一条用户走不到的路。
    let mut s = PopupSession::new(RecordingTransport::default());
    s.open(UpdatePopupState::remind("v1.2.0", "v1.1.0"));
    // 每一档**全部生产可达的构造形态**（不是每档一个夹具）。`Progress` 两发对应
    // `commands/updater.rs` 的两个调用点：复查前的 `progress(0, None, None)` 与下载回调那一发。
    let samples = |phase: PopupPhase| -> Vec<UpdatePopupState> {
        match phase {
            PopupPhase::Remind => vec![UpdatePopupState::remind("v1.2.0", "v1.1.0")],
            PopupPhase::Progress => vec![
                UpdatePopupState::progress(0, None, None),
                UpdatePopupState::progress(37, Some(19_240_000), Some(52_000_000)),
            ],
            PopupPhase::Done => vec![UpdatePopupState::done(
                Some("v1.2.0".into()),
                "/tmp/updates/polaris.dmg",
            )],
            PopupPhase::NoUpdate => vec![UpdatePopupState::no_update(None)],
            PopupPhase::Error => vec![UpdatePopupState::error(
                UpdateErrCode::DownloadFailed,
                "net down",
            )],
        }
    };

    for phase in PopupPhase::ALL {
        for sample in samples(phase) {
            s.send_state(sample).expect("mock transport 不会失败");
            let state = s.last_state().expect("刚推过");
            assert_eq!(state.phase, phase, "样本表里 {phase} 那一格造错了档");
            let json = serde_json::to_value(state).expect("载荷必须可序列化");
            let obj = json.as_object().expect("载荷必须是 JSON 对象");
            for key in required(phase) {
                assert!(
                    obj.contains_key(*key),
                    "{phase} 档缺随行事实 `{key}` —— 那一屏只剩一个状态字"
                );
            }
            let extra: Vec<&String> = obj
                .keys()
                .filter(|k| {
                    !required(phase).contains(&k.as_str()) && !optional(phase).contains(&k.as_str())
                })
                .collect();
            assert!(extra.is_empty(), "{phase} 档夹带了未登记的键: {extra:?}");
        }
    }

    // `optional` 不许当豁免用：登记为可缺的键，必须真有**至少一个**生产形态带着它 ——
    // 否则那一格与「这个字段根本没人写」不可分辨（`bytes_text` 正是那个形态）。
    for phase in PopupPhase::ALL {
        for key in optional(phase) {
            let seen = samples(phase).into_iter().any(|st| {
                serde_json::to_value(&st)
                    .expect("载荷必须可序列化")
                    .get(key)
                    .is_some()
            });
            assert!(
                seen,
                "{phase} 档把 `{key}` 登记成「可缺」，却没有任何一个生产形态带着它 —— \
                     那不是可选字段，那是死字段"
            );
        }
    }

    // 逐值对账（上面只管「在不在」）：两个终态的事实必须指向**这一次**下载。
    let done = samples(PopupPhase::Done).remove(0);
    assert_eq!(done.file_path.as_deref(), Some("/tmp/updates/polaris.dmg"));
    assert_eq!(done.version.as_deref(), Some("v1.2.0"));
    // `no_update` 自己不带版本号，靠会话继承拿到弹窗邀请的那一版 —— 它是「关于哪一版没得下」
    // 这句话的主语，丢了就只剩一句无主语的状态字。
    s.send_state(UpdatePopupState::no_update(None)).unwrap();
    assert_eq!(
        s.last_state().unwrap().version.as_deref(),
        Some("v1.2.0"),
        "noupdate 档把主语弄丢了"
    );
}
