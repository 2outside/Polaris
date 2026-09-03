use super::*;

#[test]
fn default_is_idle() {
    assert_eq!(UpdateState::default(), UpdateState::Idle);
}

#[test]
fn happy_path_full_cycle() {
    // Idle → Checking → Ready → Verifying → Installing → Idle
    let s = UpdateState::Idle;
    let s = s.start_check().unwrap();
    assert_eq!(s, UpdateState::Checking);
    let s = s.found().unwrap();
    assert_eq!(s, UpdateState::Ready);
    let s = s.start_verify().unwrap();
    assert_eq!(s, UpdateState::Verifying);
    let s = s.start_install().unwrap();
    assert_eq!(s, UpdateState::Installing);
    let s = s.installed().unwrap();
    assert_eq!(s, UpdateState::Idle);
}

#[test]
fn not_found_returns_idle() {
    let s = UpdateState::Idle
        .start_check()
        .unwrap()
        .not_found()
        .unwrap();
    assert_eq!(s, UpdateState::Idle);
}

#[test]
fn error_can_retry() {
    let s = UpdateState::Idle.start_check().unwrap().with_error();
    assert_eq!(s, UpdateState::Error);
    let s = s.retry().unwrap();
    assert_eq!(s, UpdateState::Checking);
}

#[test]
fn any_state_can_reset() {
    for s in [
        UpdateState::Idle,
        UpdateState::Checking,
        UpdateState::Ready,
        UpdateState::Verifying,
        UpdateState::Installing,
        UpdateState::Error,
    ] {
        assert_eq!(s.reset(), UpdateState::Idle, "reset from {s:?}");
    }
}

#[test]
fn any_state_can_error() {
    for s in [
        UpdateState::Idle,
        UpdateState::Checking,
        UpdateState::Ready,
        UpdateState::Verifying,
        UpdateState::Installing,
    ] {
        assert_eq!(s.with_error(), UpdateState::Error, "error from {s:?}");
    }
}

#[test]
fn invalid_transitions_rejected() {
    // Idle 不能直接 found（须先 start_check）。
    assert_eq!(
        UpdateState::Idle.found(),
        Err(UpdateStateError {
            from: UpdateState::Idle,
            to: UpdateState::Ready,
        })
    );
    // Ready 不能再 start_check（活跃态防重入）。
    assert_eq!(
        UpdateState::Ready.start_check(),
        Err(UpdateStateError {
            from: UpdateState::Ready,
            to: UpdateState::Checking,
        })
    );
    // Checking 不能直接 start_install（须先 found → start_verify）。
    assert_eq!(
        UpdateState::Checking.start_install(),
        Err(UpdateStateError {
            from: UpdateState::Checking,
            to: UpdateState::Installing,
        })
    );
    // Verifying 不能直接 installed（须先 start_install）。
    assert_eq!(
        UpdateState::Verifying.installed(),
        Err(UpdateStateError {
            from: UpdateState::Verifying,
            to: UpdateState::Idle,
        })
    );
    // 非 Error 态不能 retry。
    assert_eq!(
        UpdateState::Idle.retry(),
        Err(UpdateStateError {
            from: UpdateState::Idle,
            to: UpdateState::Checking,
        })
    );
}

#[test]
fn is_active_and_terminal() {
    assert!(!UpdateState::Idle.is_active());
    assert!(UpdateState::Checking.is_active());
    assert!(UpdateState::Ready.is_active());
    assert!(UpdateState::Verifying.is_active());
    assert!(UpdateState::Installing.is_active());
    assert!(!UpdateState::Error.is_active());

    assert!(UpdateState::Ready.is_terminal());
    assert!(UpdateState::Error.is_terminal());
    assert!(!UpdateState::Idle.is_terminal());
    assert!(!UpdateState::Checking.is_terminal());
}

#[test]
fn popup_phase_mapping() {
    // 移植自 Polaris popup phase 选择：done 态对应 Ready，error 对应 Error，其余 progress。
    assert_eq!(UpdateState::Idle.popup_phase(), PopupPhase::Progress);
    assert_eq!(UpdateState::Checking.popup_phase(), PopupPhase::Progress);
    assert_eq!(UpdateState::Ready.popup_phase(), PopupPhase::Done);
    assert_eq!(UpdateState::Verifying.popup_phase(), PopupPhase::Progress);
    assert_eq!(UpdateState::Installing.popup_phase(), PopupPhase::Progress);
    assert_eq!(UpdateState::Error.popup_phase(), PopupPhase::Error);
}

#[test]
fn display_strings() {
    assert_eq!(UpdateState::Idle.to_string(), "idle");
    assert_eq!(UpdateState::Checking.to_string(), "checking");
    assert_eq!(UpdateState::Ready.to_string(), "ready");
    assert_eq!(UpdateState::Verifying.to_string(), "verifying");
    assert_eq!(UpdateState::Installing.to_string(), "installing");
    assert_eq!(UpdateState::Error.to_string(), "error");
    assert_eq!(PopupPhase::Remind.to_string(), "remind");
    assert_eq!(PopupPhase::Progress.to_string(), "progress");
    assert_eq!(PopupPhase::Done.to_string(), "done");
    assert_eq!(PopupPhase::NoUpdate.to_string(), "noupdate");
    assert_eq!(PopupPhase::Error.to_string(), "error");
}

/// 🟡 **[`PopupPhase::ALL`] 必须逐个覆盖真实变体表。**
///
/// `ALL` 是所有遍历型判据（弹窗载荷的随行事实门、镜像闸门、跨语言 phase 对拍）的取材源。
/// 它一旦落后于枚举，那些门就**静默少跑一格** —— 新加的那一档没有任何断言碰过，而全部转绿。
/// 故此处不比对手抄的清单，而是拿 `Display` 那个**编译器强制穷尽**的 match 当变体数的真值源。
///
/// # 判据是「`Self::<Ident> =>` 这样的匹配臂」，不是「出现过 `Self::`」
///
/// 裸数 `Self::` 会漂：同一个 impl 块里任何别的写法（`matches!(self, Self::Done)`、
/// `Self::from_str`、辅助分支）都会把计数顶高，而顶高之后本门要么误红、要么在 `ALL` 恰好也
/// 多一项时**假绿**。故只认「`Self::` + 标识符 + 可选空白 + `=>`」这一形状。
///
/// 剩下的射程边界（如实登记，逐条都不是静默的）：
///  1. **or-pattern 臂**（`Self::A | Self::B => …`）：只有末项后面跟着 `=>` ⇒ 计数**偏低**
///     ⇒ 与 `ALL` 不等 ⇒ 转红。方向安全（宁可误红，不放过没被遍历到的变体）。
///  2. **同 impl 块里出现第二个 `match self`**：计数偏高 ⇒ 同样转红。今天该块只有 `fmt` 一个
///     方法，不可达。
///  3. **`_ => …` 通配臂**：计数停在通配那一刻，且 match 不再被编译器强制穷尽 ⇒ 新变体既不
///     编译红、也不被本门抓到 —— **这一条是真的哑**。今天无通配臂；谁要加，请连同本门一起
///     重新设计判据（通配臂本身就是「新变体不必表态」的宣言）。
///
/// **变异探针**：从 `ALL` 里删掉任意一项 ⇒ 数量不等，转红；把两项写成同一个变体 ⇒ 去重后数量
/// 不等，转红；给枚举加一档而不加进 `ALL` ⇒ 转红；在本 impl 块里加一行
/// `let _ = Self::Done;` ⇒ 裸数版本会转红，本版本纹丝不动。
#[test]
fn all_lists_every_popup_phase_exactly_once() {
    let src = polaris_source_probe::crate_source!("state.rs");
    const ANCHOR: &str = "impl fmt::Display for PopupPhase {";
    let at = src
        .find(ANCHOR)
        .expect("锚点消失：`Display for PopupPhase` 被改形，本门已失去变体数的真值源");
    let rest = &src[at..];
    let body = &rest[..rest.find("\n}\n").expect("找不到该 impl 块的列 0 右花括号")];
    // 「`Self::` + 标识符 + 可选空白 + `=>`」= 一条匹配臂。本 crate 无 regex 依赖，手写扫描。
    let variants = body
        .match_indices("Self::")
        .filter(|(i, m)| {
            let tail = &body[i + m.len()..];
            let ident_len = tail
                .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                .unwrap_or(tail.len());
            ident_len > 0 && tail[ident_len..].trim_start().starts_with("=>")
        })
        .count();
    assert!(
        variants >= 4,
        "`Display` 的 match 一条臂都没解析到（实得 {variants}）—— 取材器塌了"
    );
    assert_eq!(
        PopupPhase::ALL.len(),
        variants,
        "`PopupPhase::ALL` 有 {} 项，而枚举有 {variants} 个变体 —— 所有遍历型门都会漏掉那一格",
        PopupPhase::ALL.len()
    );
    let distinct: std::collections::BTreeSet<String> =
        PopupPhase::ALL.iter().map(ToString::to_string).collect();
    assert_eq!(
        distinct.len(),
        PopupPhase::ALL.len(),
        "`PopupPhase::ALL` 里有重复项 —— 数量对得上，却有一格从没被遍历到"
    );
}
