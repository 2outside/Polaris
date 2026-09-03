use super::LogLevel;

#[test]
fn effective_privacy_raises_below_warn() {
    assert_eq!(LogLevel::Debug.effective(true), LogLevel::Warn);
    assert_eq!(LogLevel::Info.effective(true), LogLevel::Warn);
}

#[test]
fn effective_privacy_keeps_warn_and_above() {
    assert_eq!(LogLevel::Warn.effective(true), LogLevel::Warn);
    assert_eq!(LogLevel::Error.effective(true), LogLevel::Error);
    assert_eq!(LogLevel::Fatal.effective(true), LogLevel::Fatal);
}

#[test]
fn effective_no_privacy_passthrough() {
    for lvl in [
        LogLevel::Debug,
        LogLevel::Info,
        LogLevel::Warn,
        LogLevel::Error,
        LogLevel::Fatal,
    ] {
        assert_eq!(lvl.effective(false), lvl);
    }
}
