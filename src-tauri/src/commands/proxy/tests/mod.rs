mod probe_tests;

/// [`parse_probe_diagnostic`] 结构化提取门。样本来源标注在每条测试里：**真机**＝真跑随包
/// `resources/linux/sing-box`（`version` 自报 `1.14.0-beta.7`）对构造出的坏 config 执行
/// `check -c` 拿到的原始 stderr（未做任何清理，含真实 ANSI 色码），**构造**＝Windows 场景本机无法
/// 跑 `.exe`，按已用 Linux 等价场景（含冒号目录名）验证过的分隔符规律手工拼的字符串。
mod probe_diagnostic_tests;

/// [`run_probe_check`](super::run_probe_check) 的真子进程接线门：探针只在 unix 有
/// （理由见 [`crate::test_support::write_sleeping_probe`]）。
#[cfg(unix)]
mod probe_check_process;

mod system_proxy_live_tests;

mod start_payload_guard;

mod system_proxy_live_guard;
