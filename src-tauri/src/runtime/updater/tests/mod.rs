use super::*;
use crate::test_support::TestDir;

fn rt(dir: &Path) -> UpdaterRuntime {
    UpdaterRuntime::new(dir.to_path_buf())
}

#[test]
fn bundled_core_version_parses_from_embedded_manifest() {
    // 编译期嵌入的 core-manifest.json 必须解析出非空基线 —— 它是 C6 全部决策的锚。
    // 若清单改名/改结构，这条即刻转红（而非在运行期静默按空基线跑）。
    let v = bundled_core_version();
    assert!(!v.is_empty(), "bundledCoreVersion 不得为空");
    assert!(
        v.starts_with(|c: char| c.is_ascii_digit()),
        "基线应是版本号，实得: {v}"
    );
}

#[test]
fn state_file_roundtrip_is_atomic_and_survives_reload() {
    let tmp = TestDir::new("polaris-updater-runtime-test-");
    let r = rt(tmp.path());
    assert!(r.state().skipped_version.is_none());

    r.mutate_state(|s| s.skipped_version = Some("4.2.5".into()))
        .unwrap();
    assert_eq!(r.state().skipped_version.as_deref(), Some("4.2.5"));

    // 新实例重读磁盘 → 状态持久化生效。
    let r2 = rt(tmp.path());
    assert_eq!(r2.state().skipped_version.as_deref(), Some("4.2.5"));
    // 无 .tmp 残件。
    assert!(!tmp.path().join("update-state.json.tmp").exists());
}

#[test]
fn corrupt_state_file_degrades_to_empty_not_panic() {
    let tmp = TestDir::new("polaris-updater-runtime-test-");
    std::fs::write(tmp.path().join("update-state.json"), b"{not json").unwrap();
    // 损坏文件不得 panic（更新域瘫掉 ≠ App 起不来）。
    let r = rt(tmp.path());
    assert!(r.state().skipped_version.is_none());
    // 仍可正常写回（覆盖损坏文件）。
    r.mutate_state(|s| s.skipped_version = Some("1.0.0".into()))
        .unwrap();
    assert_eq!(
        rt(tmp.path()).state().skipped_version.as_deref(),
        Some("1.0.0")
    );
}

#[test]
fn pending_change_notice_show_then_ack_clears_once() {
    // 「弹一次非每启」：写入 → 读到 → ack 清除 → 再读为空。
    let tmp = TestDir::new("polaris-updater-runtime-test-");
    let r = rt(tmp.path());
    r.mutate_state(|s| {
        s.pending_change_notice = Some(PendingChangeNotice {
            previous_version: "1.13.13".into(),
            current_version: "1.14.0".into(),
        });
    })
    .unwrap();
    assert!(r.state().pending_change_notice.is_some());

    r.mutate_state(|s| s.pending_change_notice = None).unwrap();
    assert!(r.state().pending_change_notice.is_none());
    // 重启后仍为空（不复活 → 不会每次启动重弹）。
    assert!(rt(tmp.path()).state().pending_change_notice.is_none());
}

#[test]
fn core_version_readers_are_asymmetric_the_150_f1_trap() {
    // **本仓最要紧的一条不变式**（Polaris issue #150 review F1）：
    //   read_core_version_line 探测失败 → ""（诚实失败）
    //   read_core_version      探测失败 → 回落随包基线（会伪装成「活核=基线」）
    // 二者若同语义，reseed 校验就会把「重读失败」当成「换核成功」→ 带旧核硬跑退回死循环。
    let tmp = TestDir::new("polaris-updater-runtime-test-");
    let r = rt(tmp.path());
    // 未注入核路径 = 探测必失败（本机不 spawn 真核，符合「真实安装核不在本机跑」纪律）。
    assert!(r.core_binary_path().is_none());

    assert_eq!(
        r.read_core_version_line(),
        "",
        "失败置空的读法必须返回空串——它是 classify_reseed_result 的唯一合法入参来源"
    );
    assert_eq!(
        r.read_core_version(),
        r.bundled_core_version(),
        "回落基线的读法必须回落基线（刻意保留的上游陷阱语义）"
    );
    // 两者**必须不同**——这正是不对称本身。
    assert_ne!(
        r.read_core_version_line(),
        r.read_core_version(),
        "双读法失败语义一旦对称，#150 F1 的防线即失效"
    );
}

#[test]
fn core_build_kind_unknown_when_probe_fails() {
    // 探测失败 → 版本行空 → classify_core_build 视为 unknown（**不硬判 fork**、更不判 official）。
    let tmp = TestDir::new("polaris-updater-runtime-test-");
    let r = rt(tmp.path());
    assert_eq!(r.core_build_kind(), CoreBuildKind::Unknown);
}

#[test]
fn decide_core_override_never_reseeds_when_probe_fails() {
    // 失败安全：探测不到活核 → unknown → 绝不 reseed（不覆盖用户的核）。
    let tmp = TestDir::new("polaris-updater-runtime-test-");
    let r = rt(tmp.path());
    let d = r.decide_core_override_for("1.13.13");
    assert!(!d.reseed, "unknown 构建绝不 reseed");
    assert!(d.warn, "旧于基线的 unknown 核应 warn");
}
