use super::*;

#[test]
fn explicit_false_disables() {
    let raw = r#"{"hardwareAcceleration":false}"#;
    assert!(should_disable_hardware_acceleration(Some(raw)));
}

#[test]
fn explicit_true_keeps_default_on() {
    let raw = r#"{"hardwareAcceleration":true}"#;
    assert!(!should_disable_hardware_acceleration(Some(raw)));
}

/// 正向语义核心：字段缺失 = 默认开 = 不禁。存量配置（升级前落盘的）必须逐字节行为不变。
#[test]
fn missing_field_keeps_default_on() {
    let raw = r#"{"language":"zh-CN"}"#;
    assert!(!should_disable_hardware_acceleration(Some(raw)));
}

/// 容错第一：绝不因脏值误禁用户的硬件加速（"false"/0/null 都不是 JSON false）。
#[test]
fn dirty_values_never_disable() {
    for raw in [
        r#"{"hardwareAcceleration":"false"}"#,
        r#"{"hardwareAcceleration":0}"#,
        r#"{"hardwareAcceleration":null}"#,
        r#"{"hardwareAcceleration":[]}"#,
        r#"{"hardwareAcceleration":{}}"#,
    ] {
        assert!(
            !should_disable_hardware_acceleration(Some(raw)),
            "脏值 {raw} 不得触发禁用"
        );
    }
}

/// 容错第一：文件缺失 / 空 / 损坏 / 顶层非对象 → 一律不禁，且绝不 panic。
#[test]
fn broken_config_never_disables_and_never_panics() {
    for raw in [
        None,
        Some(""),
        Some("   "),
        Some("{"),
        Some("not json at all"),
        Some("[1,2,3]"),
        Some("null"),
        Some(r#"{"hardwareAcceleration":fals"#),
    ] {
        assert!(!should_disable_hardware_acceleration(raw));
    }
}

/// 单向依赖：`windowEffects` 现已有行为消费（门控 vibrancy/Mica），但它**不得反向**影响
/// hardwareAcceleration 的 GPU 环境变量判定 —— 关特效不该连带禁掉硬件加速。
#[test]
fn window_effects_field_does_not_affect_hardware_acceleration() {
    let raw = r#"{"hardwareAcceleration":true,"windowEffects":false}"#;
    assert!(!should_disable_hardware_acceleration(Some(raw)));
    let raw = r#"{"hardwareAcceleration":false,"windowEffects":true}"#;
    assert!(should_disable_hardware_acceleration(Some(raw)));
}

/// 直接开关：`windowEffects === false` → 不上特效。
#[test]
fn window_effects_explicit_false_skips_effects() {
    assert!(!should_apply_window_effects(Some(
        r#"{"windowEffects":false}"#
    )));
}

/// 正向语义：显式 true / 字段缺失 → 上特效（存量配置逐字节不变）。
#[test]
fn window_effects_true_or_missing_applies_effects() {
    assert!(should_apply_window_effects(Some(
        r#"{"windowEffects":true}"#
    )));
    assert!(should_apply_window_effects(Some(r#"{"language":"zh-CN"}"#)));
}

/// 第二个否决位：逃生门开着（hardwareAcceleration=false）→ 即便 windowEffects 为 true / 缺失也不上特效
/// （vibrancy/Mica 本身就是合成层负载，正是用户要躲的白屏向量）。
#[test]
fn hardware_acceleration_off_also_skips_effects() {
    assert!(!should_apply_window_effects(Some(
        r#"{"hardwareAcceleration":false,"windowEffects":true}"#
    )));
    assert!(!should_apply_window_effects(Some(
        r#"{"hardwareAcceleration":false}"#
    )));
}

/// 真值表全枚举：两个否决位的 4 种组合，仅「两个都不是 false」才上特效。
/// 覆盖所有逃逸路径 —— 把实现改成任一单字段判定、或把 && 换成 ||，都会有格子翻红。
#[test]
fn window_effects_truth_table() {
    for (hw, we, expect) in [
        (true, true, true),
        (true, false, false),
        (false, true, false),
        (false, false, false),
    ] {
        let raw = format!(r#"{{"hardwareAcceleration":{hw},"windowEffects":{we}}}"#);
        assert_eq!(
            should_apply_window_effects(Some(&raw)),
            expect,
            "hardwareAcceleration={hw} windowEffects={we} 应 apply_effects={expect}"
        );
    }
}

/// 容错第一：配置缺失 / 空 / 损坏 / 顶层非对象 → 回落默认开 = 上特效，且绝不 panic。
/// （逃生门自己崩了就没救了；脏值绝不误关用户的窗口特效。）
#[test]
fn broken_config_keeps_effects_on_and_never_panics() {
    for raw in [
        None,
        Some(""),
        Some("   "),
        Some("{"),
        Some("not json at all"),
        Some("[1,2,3]"),
        Some("null"),
        Some(r#"{"windowEffects":"false"}"#),
        Some(r#"{"windowEffects":0}"#),
        Some(r#"{"windowEffects":null}"#),
    ] {
        assert!(should_apply_window_effects(raw), "{raw:?} 不得关掉窗口特效");
    }
}

#[test]
fn read_config_raw_missing_file_is_none() {
    let dir = std::env::temp_dir().join("polaris-graphics-compat-absent");
    assert!(read_config_raw(&dir).is_none());
}
