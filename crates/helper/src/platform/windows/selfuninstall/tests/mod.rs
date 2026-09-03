#![allow(clippy::too_many_lines)]

use super::*;

// 逐条移植 Go selfuninstall_test.go（同款断言）—— 这是 cmd 引号 HIGH bug 的回归护栏。

#[test]
fn cmd_line_uses_real_quotes_around_rmdir_path() {
    // 必须用**真双引号**包裹 rmdir 路径（非 \" 转义）：cmd 不识别 \" 反转义，转义版会令 rmdir 收到
    // 非法路径 \C:\…\ → 目录删不掉（selfuninstall.go:10-18 的 HIGH bug）。
    let cl = self_uninstall_cmd_line("PolarisHelper", r"C:\ProgramData\Polaris");
    assert!(
        cl.contains(r#"rmdir /s /q "C:\ProgramData\Polaris""#),
        "rmdir 路径未用真双引号包裹: {cl:?}"
    );
    assert!(
        !cl.contains(r#"\""#),
        "命令行含 \\\" 转义引号（cmd 不反转义→路径非法）: {cl:?}"
    );
}

#[test]
fn cmd_line_wrapped_in_cmd_c_quotes() {
    // 整行经 cmd /c 包裹（首尾真引号）：cmd strip 首尾各一引号后内层真引号原样存活。
    let cl = self_uninstall_cmd_line("PolarisHelper", r"C:\ProgramData\Polaris");
    assert!(
        cl.starts_with(r#"cmd /c ""#) && cl.ends_with('"'),
        r#"未用 cmd /c "…" 包裹: {cl:?}"#
    );
}

#[test]
fn cmd_line_step_order_is_stop_delete_rmdir() {
    // 停服务在删服务前、删服务在 rmdir 前（sc delete 要服务先停；rmdir 要 exe 先随 helper 退出解锁）。
    let cl = self_uninstall_cmd_line("PolarisHelper", r"C:\ProgramData\Polaris");
    let i_stop = cl.find("sc stop PolarisHelper");
    let i_del = cl.find("sc delete PolarisHelper");
    let i_rmdir = cl.find("rmdir");
    assert!(
        i_stop.is_some()
            && i_del.is_some()
            && i_rmdir.is_some()
            && i_stop < i_del
            && i_del < i_rmdir,
        "命令顺序应为 stop→delete→rmdir: stop={i_stop:?} del={i_del:?} rmdir={i_rmdir:?} ({cl:?})"
    );
}

#[test]
fn cmd_line_has_two_rmdir_and_ping_delay() {
    // rmdir 出现两次（解锁竞态兜底）；删目录前有 ping 延迟（等 exe 解锁，DETACHED 下不能用 timeout）。
    let cl = self_uninstall_cmd_line("PolarisHelper", r"C:\ProgramData\Polaris");
    assert_eq!(
        cl.matches("rmdir /s /q").count(),
        2,
        "rmdir 应出现两次（兜底）: {cl:?}"
    );
    assert!(cl.contains("ping 127.0.0.1"), "缺 ping 延迟: {cl:?}");
}

#[test]
fn cmd_line_handles_spaced_path() {
    // 服务名/路径含空格时仍正确包裹（虽默认无空格，验证不退化）。
    let cl = self_uninstall_cmd_line("PolarisHelper", r"C:\Program Data\Polaris");
    assert!(
        cl.contains(r#"rmdir /s /q "C:\Program Data\Polaris""#),
        "含空格路径未用真双引号包裹: {cl:?}"
    );
    assert!(!cl.contains(r#"\""#), "含空格路径出现转义引号: {cl:?}");
}

#[test]
fn cmd_line_unsafe_path_uses_placeholder() {
    // 恶意 support_dir（含 cmd 元字符）走安全占位，关闭 SYSTEM 注入窗口。
    let cl = self_uninstall_cmd_line("PolarisHelper", r"C:\evil & calc.exe");
    // 原恶意片段不得出现在最终命令行（防 & 触发 cmd 注入即提权）。
    assert!(
        !cl.contains("evil & calc"),
        "恶意 support_dir 未被占位替换，注入面仍开: {cl:?}"
    );
    assert!(
        cl.contains("safe-placeholder-nonexistent"),
        "恶意路径应改用安全占位: {cl:?}"
    );
}

#[test]
fn is_safe_support_dir_boundary_cases() {
    // Go selfuninstall_test.go TestIsSafeSupportDir 的全部用例。
    let cases: &[(&str, bool)] = &[
        (r"C:\ProgramData\Polaris", true),
        (r"C:\Program Data\Polaris", true), // 空格允许
        ("", false),
        (r"C:\evil & calc", false), // &
        (r#"C:\x"y"#, false),       // 引号
        (r"C:\a|b", false),         // 管道
        (r"D:/path", true),         // 正斜杠允许
        (r"C:\应用\Polaris", true), // 中文 Unicode 允许
    ];
    for &(input, want) in cases {
        assert_eq!(
            is_safe_support_dir(input),
            want,
            "is_safe_support_dir({input:?}) mismatch"
        );
    }
}

#[test]
fn is_safe_support_dir_rejects_all_cmd_metacharacters() {
    // 兜底测全部 cmd 元字符（Go 源用白名单，本测补强黑名单视角）。
    for &bad in &["%", "^", "<", ">", "(", ")", ";", "=", "\t"] {
        assert!(
            !is_safe_support_dir(&format!("C:\\x{bad}y")),
            "应拒绝 cmd 元字符 {bad:?}"
        );
    }
}

#[test]
fn cmd_line_default_args_match_production_constants() {
    // 锁住：用 crate 常量（SERVICE_NAME / DEFAULT_SUPPORT_DIR）拼出的命令行 = 生产路径。
    let cl = self_uninstall_cmd_line(
        crate::platform::windows::SERVICE_NAME,
        crate::platform::windows::DEFAULT_SUPPORT_DIR,
    );
    assert!(cl.contains("sc stop PolarisHelper"));
    assert!(cl.contains("sc delete PolarisHelper"));
    assert!(cl.contains(r#"rmdir /s /q "C:\ProgramData\Polaris""#));
}
