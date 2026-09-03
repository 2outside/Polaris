use super::*;

fn argv(rest: &[&str]) -> Vec<String> {
    // 首元素恒是程序名（std::env::args 的 argv[0]），判定须跳过它——测试连同 argv[0] 一起喂。
    std::iter::once("polaris")
        .chain(rest.iter().copied())
        .map(String::from)
        .collect()
}

#[cfg(not(target_os = "macos"))]
#[test]
fn maximize_observation_only_commits_real_transitions() {
    let state = AtomicBool::new(false);
    assert!(!commit_maximized_observation(&state, false));
    assert!(commit_maximized_observation(&state, true));
    assert!(!commit_maximized_observation(&state, true));
    assert!(commit_maximized_observation(&state, false));
}

#[test]
fn version_and_help_win_over_everything() {
    // CLI 查询优先级最高：即便无显示 / 带 --hidden 也先返 Version/Help（三平台通用）。
    assert_eq!(
        resolve_startup(&argv(&["--version", "--hidden"]), false),
        StartupAction::Version
    );
    assert_eq!(
        resolve_startup(&argv(&["-V"]), true),
        StartupAction::Version
    );
    assert_eq!(
        resolve_startup(&argv(&["--help"]), false),
        StartupAction::Help
    );
    assert_eq!(resolve_startup(&argv(&["-h"]), true), StartupAction::Help);
}

#[test]
fn version_precedes_help_when_both_present() {
    // -V 在 -h 之前判定（上游 同序）。
    assert_eq!(
        resolve_startup(&argv(&["-h", "-V"]), true),
        StartupAction::Version
    );
}

#[test]
fn headless_exit_only_when_no_display_and_no_cli_query() {
    // 无显示 + 非 CLI 查询 → HeadlessExit（规避无 GUI 崩溃）。
    assert_eq!(
        resolve_startup(&argv(&[]), false),
        StartupAction::HeadlessExit
    );
    // 有显示 → 正常起 GUI，不 headless。
    assert_eq!(
        resolve_startup(&argv(&[]), true),
        StartupAction::Run { hidden: false }
    );
}

#[test]
fn hidden_flag_only_affects_run_variant() {
    assert_eq!(
        resolve_startup(&argv(&["--hidden"]), true),
        StartupAction::Run { hidden: true }
    );
    // --hidden 但无显示 → 仍 headless 早退（headless 先于 hidden）。
    assert_eq!(
        resolve_startup(&argv(&["--hidden"]), false),
        StartupAction::HeadlessExit
    );
    // 无 --hidden → hidden:false。
    assert_eq!(
        resolve_startup(&argv(&["--autostart"]), true),
        StartupAction::Run { hidden: false }
    );
}

#[test]
fn silent_start_parsed_from_raw_config() {
    assert!(config_silent_start(Some(r#"{"silentStart":true}"#)));
    assert!(!config_silent_start(Some(r#"{"silentStart":false}"#)));
    // 缺字段 / 非 bool / 坏 JSON / None → 默认 false（显示）。
    assert!(!config_silent_start(Some(r#"{"autoStart":true}"#)));
    assert!(!config_silent_start(Some(r#"{"silentStart":"yes"}"#)));
    assert!(!config_silent_start(Some("not json")));
    assert!(!config_silent_start(None));
}

#[test]
fn remember_window_size_defaults_to_true() {
    // 正向语义 + 缺省 true（对齐 UI `config.rememberWindowSize !== false`）。
    assert!(config_remember_window_size(Some(
        r#"{"rememberWindowSize":true}"#
    )));
    assert!(!config_remember_window_size(Some(
        r#"{"rememberWindowSize":false}"#
    )));
    // 缺字段 / 非 bool / 坏 JSON / None → true（开）。
    assert!(config_remember_window_size(Some(r#"{"silentStart":true}"#)));
    assert!(config_remember_window_size(Some(
        r#"{"rememberWindowSize":"yes"}"#
    )));
    assert!(config_remember_window_size(Some("not json")));
    assert!(config_remember_window_size(None));
}

#[test]
fn close_action_allows_close_while_quitting() {
    // 显式退出进行中 → 恒放行，托盘 / minimizeToTray 组合一概不影响（否则退不掉）。
    for tray in [true, false] {
        for m2t in [true, false] {
            assert_eq!(
                resolve_close_action(true, tray, m2t),
                CloseAction::AllowClose,
                "quitting=true, tray={tray}, minimizeToTray={m2t}"
            );
        }
    }
}

#[test]
fn close_action_enters_lightweight_only_when_wanted_and_tray_present() {
    // 用户选「收进托盘」+ 托盘在 → 唯一销毁 renderer、保核驻托盘的组合。
    assert_eq!(
        resolve_close_action(false, true, true),
        CloseAction::EnterLightweight
    );
    // 想收纳但托盘缺失 → 销毁即僵尸，改真退出。
    assert_eq!(
        resolve_close_action(false, false, true),
        CloseAction::QuitApp
    );
}

#[test]
fn close_action_quits_when_user_chose_exit_app() {
    // 用户选「退出应用」→ 托盘在不在都退（#10 之前这里恒 hide，开关是死装饰）。
    assert_eq!(
        resolve_close_action(false, true, false),
        CloseAction::QuitApp
    );
    assert_eq!(
        resolve_close_action(false, false, false),
        CloseAction::QuitApp
    );
}

#[test]
fn cli_help_text_lists_hidden_flag() {
    let text = cli_help_text();
    assert!(text.contains("--hidden"));
    assert!(text.contains("--version"));
    assert!(text.starts_with("Polaris "));
}
