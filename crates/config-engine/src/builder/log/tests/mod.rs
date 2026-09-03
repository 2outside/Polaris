use super::*;

fn deps(privacy: bool, platform: Platform, path: Option<&str>) -> LogBuildDeps<'_> {
    LogBuildDeps {
        privacy_mode: privacy,
        platform,
        log_file_path: path,
    }
}

#[test]
fn system_proxy_no_output() {
    let input = LogConfigInput {
        proxy_mode_type: ProxyModeType::SystemProxy,
        ..Default::default()
    };
    let cfg = build_log_config(&input, &deps(false, Platform::Linux, Some("/tmp/sb.log")));
    assert_eq!(cfg.level, "info");
    assert!(cfg.timestamp);
    assert!(cfg.disabled.is_none());
    assert!(cfg.output.is_none(), "systemProxy 不写文件");
}

#[test]
fn tun_linux_writes_output() {
    let input = LogConfigInput {
        proxy_mode_type: ProxyModeType::Tun,
        ..Default::default()
    };
    let cfg = build_log_config(
        &input,
        &deps(false, Platform::Linux, Some("/fake/singbox.log")),
    );
    assert_eq!(cfg.output.as_deref(), Some("/fake/singbox.log"));
}

#[test]
fn tun_mac_writes_output() {
    let input = LogConfigInput {
        proxy_mode_type: ProxyModeType::Tun,
        ..Default::default()
    };
    let cfg = build_log_config(&input, &deps(false, Platform::Mac, Some("/fake/sb.log")));
    assert_eq!(cfg.output.as_deref(), Some("/fake/sb.log"));
}

#[test]
fn privacy_raises_level() {
    let input = LogConfigInput {
        log_level: LogLevel::Debug,
        proxy_mode_type: ProxyModeType::SystemProxy,
        ..Default::default()
    };
    let cfg = build_log_config(&input, &deps(true, Platform::Linux, None));
    assert_eq!(cfg.level, "warn", "隐私模式 debug → warn");
}

#[test]
fn disable_log_file_short_circuits() {
    let input = LogConfigInput {
        disable_log_file: true,
        proxy_mode_type: ProxyModeType::Tun,
        ..Default::default()
    };
    let cfg = build_log_config(&input, &deps(false, Platform::Linux, Some("/fake/sb.log")));
    assert_eq!(cfg.disabled, Some(true));
    assert!(cfg.output.is_none(), "disabled 时不写 output");
}

#[test]
fn manual_mode_no_output() {
    let input = LogConfigInput {
        proxy_mode_type: ProxyModeType::Manual,
        ..Default::default()
    };
    let cfg = build_log_config(&input, &deps(false, Platform::Linux, Some("/fake/sb.log")));
    assert!(cfg.output.is_none(), "manual 模式 stdout 直喂不写文件");
}
