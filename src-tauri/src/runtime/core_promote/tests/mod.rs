use super::*;
use crate::test_support::{module_code, TestDir};

// ── promote_names（allowlist）──

#[test]
fn promote_names_keeps_core_and_cronet_only() {
    let entries: Vec<String> = [
        "sing-box",
        "sing-box.bak",
        ".core-seed.json",
        "libcronet.so",
        "libcronet.dylib",
        "junk.tmp",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    let got = promote_names(&entries, "sing-box");
    assert_eq!(
        got,
        vec![
            "libcronet.dylib".to_owned(),
            "libcronet.so".to_owned(),
            "sing-box".to_owned()
        ]
    );
}

/// 🟡 **门：备份与簿记绝不能进受保护目录**。
///
/// 这不是洁癖：`install-core` 会把 src_dir 的每个文件都搬进 root 目录，`sing-box.bak` 与核同尺寸
/// （实测 80MB），簿记则毫无意义。
///
/// **变异探针**：把 [`promote_names`] 的 `filter` 改成恒 `true`（或删掉 `.bak` 之外的条件），本门转红。
#[test]
fn promote_names_excludes_backup_and_marker() {
    let entries: Vec<String> = ["sing-box", "sing-box.bak", ".core-seed.json"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let got = promote_names(&entries, "sing-box");
    assert!(
        !got.iter().any(|n| n.ends_with(".bak")),
        "备份文件绝不能进受保护核目录，实得 {got:?}"
    );
    assert!(
        !got.iter().any(|n| n.starts_with(".core-seed")),
        "播种簿记绝不能进受保护核目录，实得 {got:?}"
    );
}

#[test]
fn promote_names_windows_filename() {
    let entries: Vec<String> = ["sing-box.exe", "sing-box"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    assert_eq!(
        promote_names(&entries, "sing-box.exe"),
        vec!["sing-box.exe".to_owned()]
    );
}

// ── decide_promote ──

#[test]
fn decide_promote_skips_when_hash_equal() {
    let h = "a".repeat(64);
    assert_eq!(
        decide_promote(&h, Some(&h.to_uppercase()), true),
        PromoteDecision::UpToDate,
        "hex 比对须大小写不敏感（对齐 helper 侧 EqualFold）"
    );
}

#[test]
fn decide_promote_when_dest_absent_or_differs() {
    let h = "a".repeat(64);
    assert_eq!(decide_promote(&h, None, true), PromoteDecision::Promote);
    assert_eq!(
        decide_promote(&h, Some(&"b".repeat(64)), true),
        PromoteDecision::Promote
    );
}

#[test]
fn decide_promote_when_core_matches_but_sidecar_does_not() {
    let h = "a".repeat(64);
    assert_eq!(
        decide_promote(&h, Some(&h), false),
        PromoteDecision::Promote,
        "Linux 旧安装的同版核心缺 libcronet.so 时必须重推 payload"
    );
}

/// 空源 hash 绝不能判「已最新」（否则读不出源就静默跳过提升 = 又一条静默失效路径）。
#[test]
fn decide_promote_empty_src_hash_never_up_to_date() {
    assert_eq!(decide_promote("", Some(""), true), PromoteDecision::Promote);
}

#[test]
fn sidecar_payload_match_requires_the_same_names_and_bytes() {
    let src = TestDir::new("polaris-core-promote-test-");
    let dest = TestDir::new("polaris-core-promote-test-");
    assert!(
        sidecar_payload_matches(src.path(), dest.path()),
        "macOS 两边均无动态库是合法稳态"
    );

    std::fs::write(src.path().join("libcronet.so"), b"CRONET-A").unwrap();
    assert!(
        !sidecar_payload_matches(src.path(), dest.path()),
        "源有而受保护目录缺失必须判漂移"
    );

    std::fs::write(dest.path().join("libcronet.so"), b"CRONET-A").unwrap();
    assert!(sidecar_payload_matches(src.path(), dest.path()));

    std::fs::write(dest.path().join("libcronet.so"), b"CRONET-B").unwrap();
    assert!(
        !sidecar_payload_matches(src.path(), dest.path()),
        "同名不同 ABI/内容必须判漂移"
    );

    std::fs::write(dest.path().join("libcronet.so"), b"CRONET-A").unwrap();
    std::fs::write(dest.path().join("libcronet.legacy"), b"STALE").unwrap();
    assert!(
        !sidecar_payload_matches(src.path(), dest.path()),
        "受保护目录多出旧 sidecar 也要经 helper prune"
    );
}

#[test]
fn payload_stamp_is_stable_until_core_or_sidecar_identity_changes() {
    let payload = TestDir::new("polaris-core-promote-test-");
    std::fs::write(payload.path().join("sing-box"), b"CORE").unwrap();
    let first = payload_stamp(payload.path(), "sing-box").unwrap();
    assert_eq!(payload_stamp(payload.path(), "sing-box").unwrap(), first);

    std::fs::write(payload.path().join("libcronet.so"), b"CRONET").unwrap();
    assert_ne!(payload_stamp(payload.path(), "sing-box").unwrap(), first);
}

#[test]
fn payload_stamp_requires_the_core_file() {
    let payload = TestDir::new("polaris-core-promote-test-");
    std::fs::write(payload.path().join("libcronet.so"), b"CRONET").unwrap();
    assert!(payload_stamp(payload.path(), "sing-box").is_err());
}

#[test]
fn windows_has_no_protected_core() {
    assert!(!platform_has_protected_core(Platform::Win));
    assert!(platform_has_protected_core(Platform::Mac));
    assert!(platform_has_protected_core(Platform::Linux));
}

// ── attest_core_binary ──

fn p(s: &str) -> PathBuf {
    PathBuf::from(s)
}

#[test]
fn attest_same_path_passes_without_versions() {
    let a = p("/x/sing-box");
    // 版本双空也判通过：同一个文件，版本无需再问。
    assert_eq!(
        attest_core_binary(&a, Some(&a), "", ""),
        CoreBinaryAttestation::SamePath
    );
}

#[test]
fn attest_same_version_across_paths_passes() {
    let got = attest_core_binary(
        &p("/u/core_update/sing-box"),
        Some(&p("/Library/Application Support/Polaris/core/sing-box")),
        "sing-box version 1.14.0-beta.3",
        "sing-box version 1.14.0-beta.3",
    );
    assert!(!got.is_alarm());
    assert!(matches!(got, CoreBinaryAttestation::SameVersion { .. }));
}

/// 🔴 **门：p101 实测现场必须被判为告警**。
///
/// 现场（2026-07-29~31，SSH 别名 p101）：app 解析 `core_update/sing-box`（1.14.0-beta.3），
/// helper 实跑 `/Library/Application Support/Polaris/core/sing-box`（1.14.0-alpha.45）。
/// 缺陷期间零告警，用户看到的是「已连接 + 已升级」。
///
/// **变异探针**：把 [`attest_core_binary`] 里 `rv == ev` 的分支改成恒返回 `SameVersion`
/// （即"路径不同一律放行"），或把 [`CoreBinaryAttestation::is_alarm`] 的 `VersionMismatch`
/// 去掉 → 本门转红。
#[test]
fn attest_p101_ground_truth_is_alarm() {
    let got = attest_core_binary(
        &p("/Users/sway/Library/Application Support/com.polaris.app/polaris/core_update/sing-box"),
        Some(&p("/Library/Application Support/Polaris/core/sing-box")),
        "sing-box version 1.14.0-beta.3",
        "sing-box version 1.14.0-alpha.45",
    );
    assert!(
        got.is_alarm(),
        "实跑 alpha.45 而期望 beta.3 必须告警，实得 {got:?}"
    );
    assert!(matches!(got, CoreBinaryAttestation::VersionMismatch { .. }));
    let msg = got.user_message();
    assert!(msg.contains("1.14.0-alpha.45") && msg.contains("1.14.0-beta.3"));
}

/// 路径不同 + 读不出版本 → 告警（不得当作通过）。
///
/// **变异探针**：把 `VersionUnreadable` 从 [`CoreBinaryAttestation::is_alarm`] 里去掉 → 转红。
#[test]
fn attest_unreadable_version_is_alarm_not_pass() {
    for (rv, ev) in [("", "1.0.0"), ("1.0.0", ""), ("", "")] {
        let got = attest_core_binary(&p("/a/sing-box"), Some(&p("/b/sing-box")), ev, rv);
        assert!(
            got.is_alarm(),
            "读不出版本不得判通过（rv={rv:?} ev={ev:?}），实得 {got:?}"
        );
    }
}

/// 观测不到实跑 exe → 既不报通过也不报错。
#[test]
fn attest_unobservable_is_neither_pass_nor_alarm() {
    let got = attest_core_binary(&p("/a/sing-box"), None, "1.0.0", "1.0.0");
    assert_eq!(got, CoreBinaryAttestation::Unobservable);
    assert!(!got.is_alarm());
    assert!(
        !got.user_message().contains("通过"),
        "「没观测到」绝不能写成「通过」，实得 {}",
        got.user_message()
    );
}

// ── 暂存腿（真 FS，tempdir，无网络无提权）──

#[test]
fn stage_promote_dir_links_only_allowlisted_files() {
    let src = TestDir::new("polaris-core-promote-test-");
    let staged = TestDir::new("polaris-core-promote-test-");
    std::fs::write(src.path().join("sing-box"), b"CORE").unwrap();
    std::fs::write(src.path().join("sing-box.bak"), b"OLDCORE").unwrap();
    std::fs::write(src.path().join(".core-seed.json"), b"{}").unwrap();
    std::fs::write(src.path().join("libcronet.so"), b"CRONET").unwrap();

    let names = promote_names(&list_file_names(src.path()), "sing-box");
    let dest = staged.path().join(CORE_PROMOTE_DIR_NAME);
    stage_promote_dir(src.path(), &dest, &names).unwrap();

    let mut got = list_file_names(&dest);
    got.sort();
    assert_eq!(got, vec!["libcronet.so".to_owned(), "sing-box".to_owned()]);
    assert_eq!(std::fs::read(dest.join("sing-box")).unwrap(), b"CORE");
}

/// 暂存目录**先清后建**：上一轮残留不得混入下一次提升。
///
/// **变异探针**：删掉 [`stage_promote_dir`] 里的 `remove_dir_all` → 本门转红。
#[test]
fn stage_promote_dir_wipes_stale_residue() {
    let src = TestDir::new("polaris-core-promote-test-");
    let staged = TestDir::new("polaris-core-promote-test-");
    std::fs::write(src.path().join("sing-box"), b"NEW").unwrap();
    let dest = staged.path().join(CORE_PROMOTE_DIR_NAME);
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::write(dest.join("libcronet.so"), b"STALE").unwrap();

    let names = promote_names(&list_file_names(src.path()), "sing-box");
    stage_promote_dir(src.path(), &dest, &names).unwrap();
    assert_eq!(
        list_file_names(&dest),
        vec!["sing-box".to_owned()],
        "上一轮的 libcronet.so 必须被清掉，否则会被 install-core 搬进 root 目录"
    );
}

#[test]
fn sha256_file_matches_known_vector() {
    let d = TestDir::new("polaris-core-promote-test-");
    let f = d.path().join("x");
    std::fs::write(&f, b"").unwrap();
    assert_eq!(
        sha256_file(&f).unwrap(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert!(sha256_file(&d.path().join("nope")).is_err());
}

// ── 调用点守卫（源码扫描）──────────────────────────────────────────────
//
// 上面那组纯函数门只证明「判据本身对」。**判据对而没人调用 = 缺陷原样存活**，
// 而这恰恰就是本缺陷的形态：helper 侧 `install-core` 早已完整落地并配着单测全绿，
// 唯独 app 侧从头到尾没有一处调用它，于是换核一年也不生效。故必须把「腿还在不在、
// 顺序对不对」单独钉死。
//
// 取材 `proxy.rs` 源码而非在 proxy.rs 里加测试：本轮改动要与另两个并行改 proxy.rs 的
// 分支合并，测试收在本文件可把冲突面压到最小。

/// 取 `proxy.rs` 里某方法的**自身**函数体（按花括号配对精确截断，不会漏到同 impl 的下一个方法）。
fn proxy_method(sig: &str) -> String {
    let src = module_code("runtime/proxy");
    crate::runtime::core_update_scheduler::method_scan::method_body(&src, sig)
}

/// 🔴 **门：经 helper 起核前必须先对账受保护核，且必须在 IPC 之前。**
///
/// 顺序是硬要求：`install-core` 换的是 helper 下次 exec 的那个文件的内容，推晚一步
/// （比如放到 `start_core` 之后）就要等**再下一次**起核才生效——用户点一次连接看不到变化，
/// 与今天的症状肉眼无法区分。
///
/// **变异探针**：删掉 `reconcile_protected_core(` 那一行 / 把它挪到 `start_core(` 之后 → 转红。
#[test]
fn helper_start_leg_reconciles_protected_core_before_ipc() {
    let body = proxy_method("    pub(super) async fn spawn_core_via_helper(");
    let reconcile_at = body.find("reconcile_protected_core(").expect(
        "经 helper 起核前的受保护核对账被删了 —— helper 会继续 exec 它锁定路径上的旧核，\
             换核对 TUN 提权路径永久不生效（p101 实测：实跑 alpha.45 而期望 beta.3，持续一天多）",
    );
    let start_at = body.find("start_core(").expect("锚点消失：守卫已失去判据");
    assert!(
        reconcile_at < start_at,
        "对账必须在起核 IPC **之前** —— 放在之后，新核要等下一次起核才生效"
    );
}

/// 🔴 **门：`start_core` 不得再被传入核路径。**
///
/// mac/win 的 `start` 协议没有核路径字段，helper 恒跑自己锁定的那个；早先调用方传了
/// `&binary` 而 mac 分支**整个丢掉**，制造出「我请求了 A」的假象，正是本缺陷长期无人察觉的原因。
///
/// **变异探针**：把 `start_core(&binary, &config_path, ...)` 改回去 → 转红。
#[test]
fn helper_start_never_passes_a_binary_path() {
    let body = proxy_method("    pub(super) async fn spawn_core_via_helper(");
    assert!(
        body.contains("start_core(&config_path,"),
        "start_core 的首参必须是 config —— 传核路径会让调用方误以为 helper 跑的是它指定的核"
    );
    assert!(
        !body.contains("start_core(&binary"),
        "又把核路径传给 start_core 了：mac 分支会静默丢弃它，缺陷原样复现"
    );
}

/// 🔴 **门：核就绪后必须调度实跑二进制自证，且在拿到 pid 之后。**
///
/// 没有这一条，「helper 跑的不是我们要的核」就再次退回**零信号**状态——正是本次缺陷
/// 一天多无人发现的根本原因（UI 一路显示已连接 + 已升级）。
///
/// 自证是非致命诊断，允许后台执行以免两次 `version` spawn 阻塞 ready 主链；这里只锁死调度入口
/// 不能消失。后台结果另有“同世代 + 同 PID + 仍运行”提交门，防旧任务污染新会话。
///
/// **变异探针**：删掉 `spawn_running_core_binary_attestation(` 调用 → 转红。
#[test]
fn start_leg_attests_running_core_binary_after_ready() {
    let body = proxy_method("    pub(super) async fn start_inner(");
    let attest_at = body.find("spawn_running_core_binary_attestation(").expect(
        "起核后的实跑二进制自证被删了 —— 换核没生效将再次完全静默（UI 照旧显示已连接/已升级）",
    );
    let ready_at = body
        .find("CoreReadyOutcome::Ready")
        .expect("锚点消失：守卫已失去判据");
    assert!(
        ready_at < attest_at,
        "自证必须在就绪门之后 —— 核还没起来时没有 pid 可观测"
    );
}

/// 🔴 **门：自证必须走 `set_nonfatal_error`（落状态 + 广播事件），不得退化成只打日志。**
///
/// 「只 log::error」正是本仓 A1 腿踩过的坑：用户看到的是绿灯，日志在他看不见的地方喊。
///
/// **变异探针**：把 `set_nonfatal_error` 换成 `log::error!` → 转红。
#[test]
fn core_binary_attestation_surfaces_via_nonfatal_error_channel() {
    let body = proxy_method("    async fn attest_running_core_binary(");
    assert!(
        body.contains("set_nonfatal_error(") && body.contains("code::CORE_BINARY_MISMATCH"),
        "自证告警必须经 set_nonfatal_error + CORE_BINARY_MISMATCH 落状态并广播，\
             只打日志等于用户看不到"
    );
    assert!(
        body.contains("is_alarm()"),
        "告警判定必须走 CoreBinaryAttestation::is_alarm（单一真值），别在此处另写一套分支"
    );
}

#[test]
fn protected_core_path_is_platform_named() {
    assert_eq!(
        protected_core_path_in(Path::new("/c"), "windows"),
        p("/c/sing-box.exe")
    );
    assert_eq!(
        protected_core_path_in(Path::new("/c"), "macos"),
        p("/c/sing-box")
    );
}
