use super::*;

#[test]
fn every_supported_language_maps_to_a_macos_code() {
    for (key, code) in APPLE_LANGUAGES {
        assert_eq!(
            apple_language_for(key),
            Some(*code),
            "{key} 的映射查不回来 —— 表里有重复键或查找逻辑坏了"
        );
    }
}

/// 存量 `fa-IR` 必须与前端 `migrateLanguageCode` 同口径迁移到 `fa`。
/// 不迁移的症状：波斯语老用户的原生对话框恒回落系统语言，而应用内一切正常 —— 查不出来。
#[test]
fn legacy_fa_ir_migrates_to_fa() {
    assert_eq!(apple_language_for("fa-IR"), Some("fa"));
}

/// `auto` 与任何不认识的码都必须落到 `None`（= 删键 = 跟随系统），
/// **不得**回落成某个具体语言 —— 那会让「跟随系统」永久失效。
#[test]
fn auto_and_unknown_choices_fall_back_to_system() {
    for choice in ["auto", "", "system", "de-DE", "zh", "ZH-CN"] {
        assert_eq!(
            apple_language_for(choice),
            None,
            "{choice} 不该映射出具体语言"
        );
    }
}

/// 从原始 JSON 文本取值的正常腿。
#[test]
fn reads_language_out_of_raw_config() {
    assert_eq!(
        apple_language_from_raw(Some(r#"{"language":"ru","uiTheme":"dark"}"#)),
        Some("ru")
    );
    assert_eq!(
        apple_language_from_raw(Some(r#"{"language":" zh-TW "}"#)),
        Some("zh-Hant"),
        "两侧空白应被 trim（sanitize 侧同样 trim，两边口径要一致）"
    );
}

/// 容错腿：这一堆输入里任何一个 panic 都会让 App 起不来（调用点在 `main()` 第一屏）。
#[test]
fn malformed_config_never_panics_and_falls_back_to_system() {
    for raw in [
        None,
        Some(""),
        Some("   "),
        Some("{"),
        Some("[]"),
        Some("null"),
        Some(r#"{"language":null}"#),
        Some(r#"{"language":42}"#),
        Some(r#"{"language":["ru"]}"#),
        Some(r#"{"uiTheme":"dark"}"#),
        Some(r#"{"language":"auto"}"#),
    ] {
        assert_eq!(
            apple_language_from_raw(raw),
            None,
            "脏输入 {raw:?} 应回落跟随系统"
        );
    }
}

/// 路径拼装：入参是 **`$HOME`**（不是 app support 目录），`Library/Application Support`
/// 由本函数补，叶名取自 `uninstall::CONFIG_DIR_LEAF`，identifier 来自 tauri.conf.json。
///
/// 拼错的形态是**恒读空 → 恒跟随系统 → 与本改动落地前完全一样**，没有任何报错，
/// 所以这条断言必须写死整条绝对路径而不是只查末几段（本测试第一版就把 app support 目录
/// 当 `$HOME` 喂进来，拼出了 `.../Application Support/Library/Application Support/...`，
/// 只查叶名的话这条就绿了）。
#[test]
fn user_config_path_is_home_then_app_support_then_identifier_then_polaris_leaf() {
    let p = user_config_path(Path::new("/Users/x"), "com.polaris.app");
    assert_eq!(
        p,
        Path::new("/Users/x/Library/Application Support/com.polaris.app/polaris/config.json")
    );
}
