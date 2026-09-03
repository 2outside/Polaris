use super::*;
use std::path::PathBuf;

fn ours() -> PathBuf {
    PathBuf::from("/opt/polaris/resources/linux/sing-box")
}

fn cmd(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_string()).collect()
}

#[test]
fn our_core_matches_binary_path_plus_run() {
    let c = cmd(&[
        "/opt/polaris/resources/linux/sing-box",
        "run",
        "-c",
        "/home/u/.config/polaris/singbox-runtime.json",
    ]);
    assert!(is_our_core(&c, &ours()));
}

#[test]
fn foreign_singbox_at_different_path_is_not_ours() {
    // **变异门 / 核心安全点**：用户系统装的 sing-box（不同路径）绝不能被判为「本 app 起的」。
    let sys = cmd(&[
        "/usr/bin/sing-box",
        "run",
        "-c",
        "/etc/sing-box/config.json",
    ]);
    assert!(
        !is_our_core(&sys, &ours()),
        "系统 sing-box 路径不同，绝不能误判为本 app 的核"
    );
}

#[test]
fn binary_path_without_run_is_not_a_core() {
    // `less <path>` / `tar <path>` 只是打开了核文件 → 不含 run token → 不杀（上游 P2-2）。
    let opener = cmd(&["less", "/opt/polaris/resources/linux/sing-box"]);
    assert!(!is_our_core(&opener, &ours()));
}

#[test]
fn run_without_our_binary_is_not_a_core() {
    // 任意 `xxx run` 不含本 app 二进制路径 → 不杀。
    let other = cmd(&["/usr/bin/docker", "run", "hello-world"]);
    assert!(!is_our_core(&other, &ours()));
}

#[test]
fn stale_pids_selects_only_our_cores_excluding_managed() {
    let candidates = vec![
        CoreProcess {
            pid: 100,
            cmdline: cmd(&["/opt/polaris/resources/linux/sing-box", "run", "-c", "a"]),
            ..Default::default()
        },
        // 系统 sing-box（不同路径）→ 必须存活。
        CoreProcess {
            pid: 200,
            cmdline: cmd(&["/usr/bin/sing-box", "run", "-c", "b"]),
            ..Default::default()
        },
        // 无关进程。
        CoreProcess {
            pid: 300,
            cmdline: cmd(&["/bin/sleep", "30"]),
            ..Default::default()
        },
        // 本 app 的核，但正是当前受管 pid → 排除，不自杀。
        CoreProcess {
            pid: 424242,
            cmdline: cmd(&["/opt/polaris/resources/linux/sing-box", "run", "-c", "c"]),
            ..Default::default()
        },
    ];
    let victims = stale_pids(&candidates, &ours(), &[424242]);
    assert_eq!(
        victims,
        vec![100],
        "只清本 app 起的孤儿（100），排除系统 sing-box（200）/ 无关进程（300）/ 当前受管（424242）"
    );
}

#[test]
fn empty_candidates_yields_no_victims() {
    assert!(stale_pids(&[], &ours(), &[]).is_empty());
}

// ─── macOS `ps` 腿（真机卡死链的扫描侧）────────────────────────────────────────────

/// 真机现场那条命令行（路径含空格，逐字取自 5.238 的 `pgrep` 输出）。
fn mac_core() -> PathBuf {
    PathBuf::from("/Library/Application Support/Polaris/core/sing-box")
}
const MAC_PS_LINE: &str = "  6439 /Library/Application Support/Polaris/core/sing-box run -c /Users/sway/Library/Application Support/com.polaris.app/polaris/singbox-runtime.json";

/// **本次真机卡死的扫描侧根因门**：ps 行必须被解析出 pid，且含空格的核路径必须仍能匹配。
/// 打断（把 `raw` 改成按空白切分后走 argv 全等比对）→ 路径被劈成 `/Library/Application`
/// 与 `Support/...` 两段 → 匹配失败 → 本测转红。
#[test]
fn mac_ps_line_with_spaces_in_path_is_recognized_as_our_core() {
    let procs = parse_ps_output(MAC_PS_LINE);
    assert_eq!(procs.len(), 1, "单行 ps 输出必须解析出一个候选");
    assert_eq!(procs[0].pid, 6439, "pid 必须从行首取出");
    assert!(
        is_our_core_raw(&procs[0].raw, &mac_core()),
        "含空格的 macOS 核路径必须仍被判为本 app 的核——切分即失配，孤儿就永远扫不出来"
    );
    assert_eq!(
        stale_pids(&procs, &mac_core(), &[]),
        vec![6439],
        "该孤儿必须进清理名单"
    );
}

/// 安全契约在 raw 腿上同样成立：外部 sing-box / 只是打开核文件的进程绝不被选中。
#[test]
fn raw_leg_keeps_the_same_safety_contract() {
    // 系统装的 sing-box：路径不同 → 不杀。
    assert!(!is_our_core_raw(
        "/usr/local/bin/sing-box run -c /etc/sing-box/config.json",
        &mac_core()
    ));
    // `less <path>`：含路径但不含 `<path> run` → 不杀（上游 P2-2 教训）。
    assert!(!is_our_core_raw(
        "less /Library/Application Support/Polaris/core/sing-box",
        &mac_core()
    ));
    // 空 raw（Linux 侧的候选）绝不因「空串被任意串包含」而误命中。
    assert!(!is_our_core_raw("", &mac_core()));
}

/// ps 输出的噪声行（表头残留 / 无命令行 / pid 非数字）不得产出候选，也不得 panic。
#[test]
fn ps_parser_skips_malformed_lines() {
    let out = "  PID ARGS\n\n  123\nnotapid /Library/Application Support/Polaris/core/sing-box run\n  456 /bin/sleep 30\n";
    let procs = parse_ps_output(out);
    // 只有 "456 /bin/sleep 30" 与 "PID ARGS"（PID 非数字→跳过）中的后者被拒；
    // "  123" 无命令行余部 → 跳过；"notapid ..." pid 不可解析 → 跳过。
    assert_eq!(procs.len(), 1);
    assert_eq!(procs[0].pid, 456);
    // 且它不是我们的核 → 不进名单。
    assert!(stale_pids(&procs, &mac_core(), &[]).is_empty());
}

/// 当前受管 pid 在 raw 腿上同样必须被排除（否则启动期清扫会杀掉自己刚起的核）。
#[test]
fn raw_leg_excludes_currently_managed_pid() {
    let procs = parse_ps_output(MAC_PS_LINE);
    assert!(
        stale_pids(&procs, &mac_core(), &[6439]).is_empty(),
        "受管 pid 必须被排除，raw 腿不得绕过 exclude"
    );
}
