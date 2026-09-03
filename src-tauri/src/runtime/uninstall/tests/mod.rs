use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

// ── 临时副本工具（**破坏性测试只碰这里造出来的副本，绝不碰真实安装**）────────────

/// 独占临时目录；`Drop` 里清理（与本仓 `commands/updater::scratch` 同款，无 tempfile dev-dep）。
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
impl Scratch {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "polaris-uninstall-test-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Self(d)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

/// 造一份**同构的**用户配置目录副本：`<scratch>/polaris/{config.json,core_update/sing-box,rules/}`。
fn fake_config_dir(root: &Path) -> PathBuf {
    let dir = root.join(CONFIG_DIR_LEAF);
    std::fs::create_dir_all(dir.join("core_update")).unwrap();
    std::fs::create_dir_all(dir.join("rules")).unwrap();
    std::fs::write(dir.join("config.json"), b"{}").unwrap();
    std::fs::write(dir.join("core_update").join("sing-box"), b"fake").unwrap();
    dir
}

/// 造一份同构的 macOS `.app` 包副本：`<scratch>/Polaris.app/Contents/MacOS/polaris`。
#[cfg(not(windows))]
fn fake_app_bundle(root: &Path) -> (PathBuf, PathBuf) {
    let bundle = root.join("Polaris.app");
    let macos = bundle.join("Contents").join("MacOS");
    std::fs::create_dir_all(&macos).unwrap();
    let exe = macos.join("polaris");
    std::fs::write(&exe, b"fake").unwrap();
    (bundle, exe)
}

// ── 可注入替身 ──────────────────────────────────────────────────────────

/// 记录调用序 + 可指定每条腿结果的 [`UninstallOps`] 替身。
struct RecordingOps {
    calls: Mutex<Vec<UninstallStep>>,
    autostart: StepOutcome,
    helper: StepOutcome,
    config: StepOutcome,
    cache: StepOutcome,
    prefs: StepOutcome,
    app: StepOutcome,
}
impl RecordingOps {
    fn all_ok() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            autostart: StepOutcome::done("autostart"),
            helper: StepOutcome::done("helper"),
            config: StepOutcome::done("config"),
            cache: StepOutcome::done("cache"),
            prefs: StepOutcome::done("prefs"),
            app: StepOutcome::done("app"),
        }
    }
    fn calls(&self) -> Vec<UninstallStep> {
        self.calls.lock().unwrap().clone()
    }
}
impl UninstallOps for RecordingOps {
    fn disable_autostart(&self) -> StepOutcome {
        self.calls.lock().unwrap().push(UninstallStep::Autostart);
        self.autostart.clone()
    }
    fn remove_cache_dir(&self) -> StepOutcome {
        self.calls.lock().unwrap().push(UninstallStep::CacheDir);
        self.cache.clone()
    }
    fn uninstall_helper(&self) -> StepOutcome {
        self.calls.lock().unwrap().push(UninstallStep::Helper);
        self.helper.clone()
    }
    fn remove_user_config(&self) -> StepOutcome {
        self.calls.lock().unwrap().push(UninstallStep::UserConfig);
        self.config.clone()
    }
    fn remove_preferences(&self) -> StepOutcome {
        self.calls.lock().unwrap().push(UninstallStep::Preferences);
        self.prefs.clone()
    }
    fn remove_app(&self) -> StepOutcome {
        self.calls.lock().unwrap().push(UninstallStep::AppBundle);
        self.app.clone()
    }
}

/// [`HelperUninstallOps`] 替身：不起 daemon、不弹提权框。
struct FakeHelper {
    supported: bool,
    installed: bool,
    result: Result<(), String>,
    calls: AtomicUsize,
}
impl FakeHelper {
    fn ready() -> Self {
        Self {
            supported: true,
            installed: true,
            result: Ok(()),
            calls: AtomicUsize::new(0),
        }
    }
}
impl HelperUninstallOps for FakeHelper {
    fn supported(&self) -> bool {
        self.supported
    }
    fn installed(&self) -> bool {
        self.installed
    }
    fn uninstall(&self) -> Result<(), String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.result.clone()
    }
    fn protected_core_dir(&self) -> String {
        "/fake/protected/core".to_owned()
    }
}

/// [`AutostartOps`] 替身：不碰真实登录项（那是 launchd/注册表/.desktop，单测绝不该动）。
struct FakeAutostart {
    enabled: bool,
    result: Result<(), String>,
    calls: AtomicUsize,
}
impl FakeAutostart {
    fn off() -> Self {
        Self {
            enabled: false,
            result: Ok(()),
            calls: AtomicUsize::new(0),
        }
    }
    fn on() -> Self {
        Self {
            enabled: true,
            ..Self::off()
        }
    }
}
impl AutostartOps for FakeAutostart {
    fn is_enabled(&self) -> bool {
        self.enabled
    }
    fn disable(&self) -> Result<(), String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.result.clone()
    }
}

fn outcome_of(r: &UninstallReport, step: UninstallStep) -> &StepOutcome {
    &r.steps.iter().find(|s| s.step == step).unwrap().outcome
}

// ── 编排：顺序 ──────────────────────────────────────────────────────────

/// 🟡 **变异锁：删除腿的因果序不可变动。**
///
/// 顺序错了不是「风格问题」：把 `UserConfig` 排到 `Helper` 前面，helper 的提权脚本就没地方落、
/// app 侧 token 也没得读 ⇒ helper 永远卸不掉（见模块文档的表）。
///
/// **变异探针**：把 [`UninstallStep::DELETE_ORDER`] 里任意两项对调 ⇒ 本条转红。
#[test]
fn delete_legs_run_in_causal_order() {
    let ops = RecordingOps::all_ok();
    let report = run_uninstall(&ops, StepOutcome::done("stopped"));
    assert_eq!(
            ops.calls(),
            vec![
                UninstallStep::Autostart,
                UninstallStep::Helper,
                UninstallStep::UserConfig,
                UninstallStep::CacheDir,
                UninstallStep::Preferences,
                UninstallStep::AppBundle
            ],
            "先注销登录项（最便宜可逆）→ 卸 helper（它要用配置目录）→ 删配置 → 清更新缓存 \
             → 清应用偏好域（本进程还在跑，越晚清回写窗口越小）→ 最后删应用本体（它是当前进程的载体）"
        );
    assert_eq!(report.verdict, UninstallVerdict::Complete);
    assert_eq!(report.steps.len(), 7, "七个步骤必须逐项出现在报告里");
}

/// 报告里第一条恒为停核腿（它是前置条件，排在所有删除之前）。
#[test]
fn report_leads_with_the_stop_core_leg() {
    let ops = RecordingOps::all_ok();
    let report = run_uninstall(&ops, StepOutcome::skipped("no core"));
    assert_eq!(report.steps[0].step, UninstallStep::StopCore);
}

// ── 编排：失败传播（红线「上一步失败不得继续删下一项」）──────────────────

/// 🟡 **变异锁：停核失败 ⇒ 一项都不许删。**
///
/// **变异探针**：把 `run_uninstall` 里 `stop_core.is_failure().then_some(...)` 换成 `None`
/// ⇒ 三条删除腿都会被调用 ⇒ 本条转红。
#[test]
fn stop_core_failure_blocks_every_delete() {
    let ops = RecordingOps::all_ok();
    let report = run_uninstall(&ops, StepOutcome::failed("core still alive"));
    assert!(
        ops.calls().is_empty(),
        "停核失败后一个删除动作都不许发生 —— 否则终局是 root 孤儿核 + 应用被删 = 断网且无处补救"
    );
    for step in UninstallStep::DELETE_ORDER {
        assert!(
            matches!(outcome_of(&report, step), StepOutcome::NotAttempted { .. }),
            "{step:?} 必须如实记为「未执行」，而不是悄悄消失"
        );
    }
    assert_eq!(report.verdict, UninstallVerdict::Failed);
}

/// 🟡 **变异锁：卸 helper 失败 ⇒ 不许继续删配置与应用本体。**
///
/// **变异探针**：把 `if outcome.is_failure() { halted = Some(step); }` 删掉 ⇒ 本条转红。
#[test]
fn helper_failure_blocks_the_remaining_deletes() {
    let mut ops = RecordingOps::all_ok();
    ops.helper = StepOutcome::failed("用户取消了管理员授权");
    let report = run_uninstall(&ops, StepOutcome::done("stopped"));
    assert_eq!(
        ops.calls(),
        vec![UninstallStep::Autostart, UninstallStep::Helper],
        "helper 失败后不得再删配置（配置里的 token 一没，helper 就永远卸不掉了）"
    );
    let cfg = outcome_of(&report, UninstallStep::UserConfig);
    match cfg {
        StepOutcome::NotAttempted { detail } => {
            assert!(
                detail.contains("卸载提权助手"),
                "必须点名是谁把它拦下的：{detail}"
            );
        }
        other => panic!("配置腿应为 NotAttempted，实得 {other:?}"),
    }
    assert_eq!(report.verdict, UninstallVerdict::Failed);
}

/// 删配置失败 ⇒ 应用本体不许删（否则残留配置再没有任何 UI 能清）。
#[test]
fn config_failure_blocks_app_removal() {
    let mut ops = RecordingOps::all_ok();
    ops.config = StepOutcome::failed("permission denied");
    let report = run_uninstall(&ops, StepOutcome::done("stopped"));
    assert_eq!(
        ops.calls(),
        vec![
            UninstallStep::Autostart,
            UninstallStep::Helper,
            UninstallStep::UserConfig
        ]
    );
    assert!(matches!(
        outcome_of(&report, UninstallStep::AppBundle),
        StepOutcome::NotAttempted { .. }
    ));
}

// ── 编排：整体判定（红线「删了一半绝不能报成功」）────────────────────────

/// 🟡 **变异锁：删了一半绝不能判成功。**
///
/// **变异探针**：把 [`verdict_of`] 里 `Failed | NotAttempted` 那条早退删掉 ⇒ 本条转红。
#[test]
fn partial_deletion_is_never_complete() {
    let mut ops = RecordingOps::all_ok();
    ops.config = StepOutcome::failed("boom");
    let report = run_uninstall(&ops, StepOutcome::done("stopped"));
    assert_ne!(
        report.verdict,
        UninstallVerdict::Complete,
        "helper 已删、配置没删掉 —— 这是部分成功，判成 Complete 就是假成功"
    );
    assert_eq!(report.verdict, UninstallVerdict::Failed);
}

/// 🟡 **变异锁：有 `Unsupported` 就不是 Complete（Windows 便携版的常态）。**
///
/// **变异探针**：把 `verdict_of` 里 `Unsupported` 那条早退删掉 ⇒ 本条转红。
#[test]
fn unsupported_step_downgrades_to_incomplete() {
    let mut ops = RecordingOps::all_ok();
    ops.app = StepOutcome::unsupported("Windows 便携版无 uninstaller");
    let report = run_uninstall(&ops, StepOutcome::done("stopped"));
    assert_eq!(
        report.verdict,
        UninstallVerdict::Incomplete,
        "应用本体还在原地 ⇒ 不是「完全卸载」，必须让用户知道还剩什么要手动做"
    );
}

/// `Skipped` **不**降级：helper 本就没装，是一次干净的完全卸载。
///
/// **变异探针**：把 `verdict_of` 的 `Unsupported` 判据放宽到也包含 `Skipped` ⇒ 本条转红。
#[test]
fn skipped_step_still_counts_as_complete() {
    let mut ops = RecordingOps::all_ok();
    ops.helper = StepOutcome::skipped("未安装");
    let report = run_uninstall(&ops, StepOutcome::skipped("代理没跑"));
    assert_eq!(report.verdict, UninstallVerdict::Complete);
}

/// 删过配置或应用本体 ⇒ 必须提示退出；一步都没删成 ⇒ 不提示。
#[test]
fn requires_exit_tracks_real_deletions() {
    let ops = RecordingOps::all_ok();
    assert!(run_uninstall(&ops, StepOutcome::done("s")).requires_exit);

    let ops = RecordingOps::all_ok();
    assert!(
        !run_uninstall(&ops, StepOutcome::failed("s")).requires_exit,
        "一项都没删就不该催用户退出"
    );

    let mut ops = RecordingOps::all_ok();
    ops.config = StepOutcome::skipped("不存在");
    ops.app = StepOutcome::unsupported("做不到");
    assert!(!run_uninstall(&ops, StepOutcome::done("s")).requires_exit);
}

// ── 停核腿真值表 ────────────────────────────────────────────────────────

/// 🟡 **变异锁：停核三态各自映射到不同结果。**
///
/// **变异探针**：把 `stop_core_outcome` 的 `Some(e)` 腿改成 `StepOutcome::done(..)`
/// （即恢复 helper 单卸载那条「停不掉也继续」的语义）⇒ 本条转红，且
/// [`stop_core_failure_blocks_every_delete`] 一并转红。
#[test]
fn stop_core_outcome_truth_table() {
    assert!(matches!(
        stop_core_outcome(UninstallPreflight::ProceedDirectly, None),
        StepOutcome::Skipped { .. }
    ));
    assert!(
        matches!(
            stop_core_outcome(UninstallPreflight::ProceedDirectly, Some("ignored")),
            StepOutcome::Skipped { .. }
        ),
        "没发起过停核 ⇒ 不该因为一个陈旧的错误串就报失败"
    );
    assert!(matches!(
        stop_core_outcome(UninstallPreflight::StopCoreFirst, None),
        StepOutcome::Done { .. }
    ));
    let failed = stop_core_outcome(UninstallPreflight::StopCoreFirst, Some("EPERM"));
    assert!(failed.is_failure(), "完全卸载里停不掉核必须是硬失败");
    match failed {
        StepOutcome::Failed { detail } => assert!(detail.contains("EPERM"), "原因必须原样带出"),
        other => panic!("实得 {other:?}"),
    }
}

// ── 应用本体：三平台可行性 ──────────────────────────────────────────────

/// 🟡 **变异锁：三平台各自的可行/不可行判定。**
///
/// 这组是本任务里**唯一**能覆盖 mac/win 腿的手段（开发机是 Linux，真机又不许跑卸载）。
/// **变异探针**：把 macOS 腿的 `mac_app_bundle_from_exe` 换成恒 `None` ⇒ 第 1 条转红；
/// 把 Windows 腿的 `exists(&uninstaller)` 换成恒 true ⇒ 第 5 条转红；
/// 把 Linux 的 `/usr` 判据删掉 ⇒ 第 4 条转红。
#[test]
fn plan_app_removal_covers_all_three_platforms() {
    let never = |_: &Path| false;
    let always = |_: &Path| true;

    // 1. macOS 正常安装 → 删 .app 包。
    assert_eq!(
        plan_app_removal(
            "macos",
            Path::new("/Applications/Polaris.app/Contents/MacOS/polaris"),
            None,
            &never
        ),
        AppRemoval::RemoveDir(PathBuf::from("/Applications/Polaris.app"))
    );
    // 2. macOS 开发构建（不在 .app 内）→ 不猜路径。
    assert!(matches!(
        plan_app_removal(
            "macos",
            Path::new("/home/dev/target/debug/polaris"),
            None,
            &never
        ),
        AppRemoval::Unsupported(_)
    ));
    // 3. Linux AppImage → 删那个文件。
    assert_eq!(
        plan_app_removal(
            "linux",
            Path::new("/tmp/.mount_abc/AppRun"),
            Some(Path::new("/home/u/Apps/Polaris-0.1.0.AppImage")),
            &never
        ),
        AppRemoval::RemoveFile(PathBuf::from("/home/u/Apps/Polaris-0.1.0.AppImage"))
    );
    // 4. Linux 包管理器安装 → **故意不碰**。
    match plan_app_removal("linux", Path::new("/usr/bin/polaris"), None, &never) {
        AppRemoval::Unsupported(why) => {
            assert!(why.contains("包管理器"), "必须说清为什么不删：{why}");
        }
        other => panic!("绕过 dpkg/rpm 删文件会留下坏态，必须 Unsupported，实得 {other:?}"),
    }
    // 5. Windows 有 NSIS uninstaller → 拉起它（进程删不掉自己的 .exe）。
    //
    // ⚠️ 字面量用**正斜杠**：`Path` 的分隔符是**宿主**的，在 Linux 上跑测时 `C:\a\b` 会被当成
    // 单个文件名、`parent()` 返空 —— 那样测到的是 Linux 的解析规则，不是本函数的判定。
    // 正斜杠在 Windows 上同样合法，两边都能正确切出 parent，故它才是这条断言的正确取材。
    // （同一个坑 `InstallPaths::win()` 已踩过并成文：`PathBuf::join` 用宿主分隔符。）
    assert_eq!(
        plan_app_removal(
            "windows",
            Path::new("C:/Program Files/Polaris/polaris.exe"),
            None,
            &always
        ),
        AppRemoval::LaunchUninstaller(Path::new("C:/Program Files/Polaris").join("uninstall.exe"))
    );
    // 6. Windows 便携版（无 uninstaller）→ 如实说做不到 + 给手动路径。
    match plan_app_removal(
        "windows",
        Path::new("D:/portable/polaris.exe"),
        None,
        &never,
    ) {
        AppRemoval::Unsupported(why) => assert!(why.contains("手动删除"), "{why}"),
        other => panic!("实得 {other:?}"),
    }
    // 7. 未知平台。
    assert!(matches!(
        plan_app_removal("freebsd", Path::new("/usr/local/bin/polaris"), None, &never),
        AppRemoval::Unsupported(_)
    ));
}

/// Windows 腿**不真起进程**也能断言：`spawn` 注入 + 措辞必须是「已启动」而非「已删除」。
#[test]
fn windows_leg_reports_launch_not_deletion() {
    let seen = Mutex::new(Vec::<PathBuf>::new());
    let spawn = |p: &Path| {
        seen.lock().unwrap().push(p.to_path_buf());
        Ok(())
    };
    let out = execute_app_removal(
        AppRemoval::LaunchUninstaller(PathBuf::from(r"C:\Program Files\Polaris\uninstall.exe")),
        &spawn,
    );
    assert_eq!(seen.lock().unwrap().len(), 1, "必须真去拉 uninstaller");
    match out {
        StepOutcome::Done { detail } => {
            assert!(detail.contains("已启动"), "{detail}");
            assert!(
                detail.contains("不代表已删除"),
                "拉起 uninstaller ≠ 应用本体已删 —— 措辞不能骗人：{detail}"
            );
        }
        other => panic!("实得 {other:?}"),
    }
    // 拉不起来必须是失败，不能静默当成功。
    let fail = execute_app_removal(
        AppRemoval::LaunchUninstaller(PathBuf::from(r"C:\x\uninstall.exe")),
        &|_| Err("ACCESS_DENIED".to_owned()),
    );
    assert!(fail.is_failure());
}

// ── 路径判定：白名单（破坏性腿只碰临时副本）────────────────────────────

#[test]
fn reject_relative_path() {
    assert_eq!(
        validate_config_dir(Path::new("polaris")),
        Err(PathReject::NotAbsolute)
    );
}

#[test]
fn reject_leaf_mismatch() {
    let s = Scratch::new("leaf");
    let other = s.path().join("not-polaris");
    std::fs::create_dir_all(&other).unwrap();
    assert_eq!(validate_config_dir(&other), Err(PathReject::LeafMismatch));
    assert!(other.exists(), "被拒的路径必须原封不动");
}

#[test]
fn reject_too_shallow() {
    // `/polaris`：叶名对得上，但没有具名父目录 ⇒ 必须拒。
    let shallow = if cfg!(windows) {
        PathBuf::from(r"C:\polaris")
    } else {
        PathBuf::from("/polaris")
    };
    assert_eq!(validate_config_dir(&shallow), Err(PathReject::TooShallow));
}

#[test]
fn reject_missing() {
    let s = Scratch::new("missing");
    assert_eq!(
        validate_config_dir(&s.path().join(CONFIG_DIR_LEAF)),
        Err(PathReject::Missing)
    );
}

/// 🟡 **变异锁：软链必须被拒（跟随删除会删到链外的任意位置）。**
///
/// **变异探针**：把 `validate_removable` 的 `symlink_metadata` 换成 `metadata` ⇒ 本条转红。
#[cfg(unix)]
#[test]
fn reject_symlinked_dir() {
    let s = Scratch::new("symlink");
    let real = s.path().join("real-target");
    std::fs::create_dir_all(&real).unwrap();
    std::fs::write(real.join("precious.txt"), b"must survive").unwrap();
    let link = s.path().join(CONFIG_DIR_LEAF);
    std::os::unix::fs::symlink(&real, &link).unwrap();

    assert_eq!(validate_config_dir(&link), Err(PathReject::Symlink));
    assert!(real.join("precious.txt").exists(), "链外内容必须毫发无伤");
}

#[test]
fn reject_file_where_dir_expected() {
    let s = Scratch::new("kind");
    let f = s.path().join(CONFIG_DIR_LEAF);
    std::fs::write(&f, b"not a dir").unwrap();
    assert_eq!(validate_config_dir(&f), Err(PathReject::KindMismatch));
}

#[test]
fn accept_a_well_formed_config_dir() {
    let s = Scratch::new("accept");
    let dir = fake_config_dir(s.path());
    assert_eq!(validate_config_dir(&dir), Ok(()));
}

// ── 薄壳：对着**临时副本**真删一次 ──────────────────────────────────────

/// 配置腿在副本上跑通：目录连同可写内核一起消失，报告点名删了哪儿。
#[test]
fn config_leg_deletes_the_copy_and_reports_the_path() {
    let s = Scratch::new("cfgdel");
    let dir = fake_config_dir(s.path());
    let helper = FakeHelper::ready();
    let ops = SystemUninstallOps {
        helper: &helper,
        autostart: &FakeAutostart::off(),
        os: "linux",
        config_dir: dir.clone(),
        cache_updates_dir: None,
        bundle_identifier: "com.polaris.app".to_owned(),
        exe: None,
        appimage: None,
    };
    match ops.remove_user_config() {
        StepOutcome::Done { detail } => {
            assert!(detail.contains(&dir.display().to_string()), "{detail}");
        }
        other => panic!("实得 {other:?}"),
    }
    assert!(!dir.exists(), "副本应已删除");
}

/// 配置目录不存在 ⇒ `Skipped`，**不是** `Failed`（一次幂等的重试不该报错）。
#[test]
fn config_leg_skips_when_absent() {
    let s = Scratch::new("cfgabsent");
    let helper = FakeHelper::ready();
    let ops = SystemUninstallOps {
        helper: &helper,
        autostart: &FakeAutostart::off(),
        os: "linux",
        config_dir: s.path().join(CONFIG_DIR_LEAF),
        cache_updates_dir: None,
        bundle_identifier: "com.polaris.app".to_owned(),
        exe: None,
        appimage: None,
    };
    assert!(matches!(
        ops.remove_user_config(),
        StepOutcome::Skipped { .. }
    ));
}

/// 🟡 **变异锁：白名单不匹配 ⇒ 拒删且目录必须还在。**
///
/// **变异探针**：把 `remove_user_config` 里的 `validate_config_dir` 调用删掉（直接 `remove_dir_all`）
/// ⇒ 本条转红（目录会被真删）。
#[test]
fn config_leg_refuses_a_path_outside_the_whitelist() {
    let s = Scratch::new("cfgguard");
    let rogue = s.path().join("Documents");
    std::fs::create_dir_all(&rogue).unwrap();
    std::fs::write(rogue.join("thesis.txt"), b"10 years of work").unwrap();
    let helper = FakeHelper::ready();
    let ops = SystemUninstallOps {
        helper: &helper,
        autostart: &FakeAutostart::off(),
        os: "linux",
        config_dir: rogue.clone(),
        cache_updates_dir: None,
        bundle_identifier: "com.polaris.app".to_owned(),
        exe: None,
        appimage: None,
    };
    assert!(ops.remove_user_config().is_failure());
    assert!(
        rogue.join("thesis.txt").exists(),
        "白名单外的路径一个字节都不许动"
    );
}

/// macOS 腿在**副本 .app 包**上跑通（本机是 Linux，但这条腿只用到 `.app` 的路径形态与 FS 语义）。
///
/// # 为什么排除 Windows（2026-08-05，Windows CI 腿首次跑通后实测）
///
/// 判定入口 `update_install::mac_app_bundle_from_exe` 是**按 `/` 硬匹配** `".app/Contents/MacOS/"`
/// 的字符串查找。那在它的实际作用域内正确 —— 它只被 `plan_app_removal` 的 `"macos"` 分支调用，
/// 而 macOS 的路径分隔符恒为 `/`。**不是生产缺陷，Windows 上永远走不到这条腿。**
///
/// 但本用例用 `Path::join` 造副本路径，在 Windows 上产出 `\` 分隔符（`…\Polaris.app\Contents\
/// MacOS\polaris`）⇒ 查找落空 ⇒ 判 `Unsupported`。即「借 FS 语义」这个前提在 Windows 上不成立：
/// 那里的路径语义与 macOS 不同，借不成。
///
/// 用 `not(windows)` 而非 `target_os = "macos"`：Linux 才是它当前的主要运行环境（`/` 分隔符
/// 使前提成立），门控成 macOS-only 等于把这条覆盖整个丢掉。
#[cfg(not(windows))]
#[test]
fn mac_leg_deletes_a_copied_app_bundle() {
    let s = Scratch::new("appdel");
    let (bundle, exe) = fake_app_bundle(s.path());
    let helper = FakeHelper::ready();
    let ops = SystemUninstallOps {
        helper: &helper,
        autostart: &FakeAutostart::off(),
        os: "macos",
        config_dir: s.path().join(CONFIG_DIR_LEAF),
        cache_updates_dir: None,
        bundle_identifier: "com.polaris.app".to_owned(),
        exe: Some(exe),
        appimage: None,
    };
    match ops.remove_app() {
        StepOutcome::Done { detail } => assert!(detail.contains("Polaris.app"), "{detail}"),
        other => panic!("实得 {other:?}"),
    }
    assert!(!bundle.exists(), "副本 .app 应已删除");
}

/// Linux AppImage 腿在副本文件上跑通；叶名不像 AppImage 的一律拒。
#[test]
fn appimage_leg_deletes_a_copied_file_but_guards_the_leaf() {
    let s = Scratch::new("appimg");
    let img = s.path().join("Polaris-0.1.0.AppImage");
    std::fs::write(&img, b"fake").unwrap();
    assert!(matches!(
        execute_app_removal(AppRemoval::RemoveFile(img.clone()), &|_| Ok(())),
        StepOutcome::Done { .. }
    ));
    assert!(!img.exists());

    let decoy = s.path().join("important.tar.gz");
    std::fs::write(&decoy, b"payload").unwrap();
    assert!(execute_app_removal(AppRemoval::RemoveFile(decoy.clone()), &|_| Ok(())).is_failure());
    assert!(decoy.exists(), "非 AppImage 叶名一个字节都不许动");
}

// ── 薄壳：helper 腿的三态 ───────────────────────────────────────────────

#[test]
fn helper_leg_three_states() {
    let s = Scratch::new("helperleg");
    let mk = |h: &FakeHelper| -> StepOutcome {
        SystemUninstallOps {
            helper: h,
            autostart: &FakeAutostart::off(),
            os: "linux",
            config_dir: s.path().join(CONFIG_DIR_LEAF),
            cache_updates_dir: None,
            bundle_identifier: "com.polaris.app".to_owned(),
            exe: None,
            appimage: None,
        }
        .uninstall_helper()
    };

    // 未安装 → 跳过，且**不该白弹一次提权框**。
    let not_installed = FakeHelper {
        installed: false,
        ..FakeHelper::ready()
    };
    assert!(matches!(mk(&not_installed), StepOutcome::Skipped { .. }));
    assert_eq!(
        not_installed.calls.load(Ordering::SeqCst),
        0,
        "没装还去调 uninstall = 平白弹一次要密码的框"
    );

    // 平台不支持 → 如实标 Unsupported。
    let unsupported = FakeHelper {
        supported: false,
        ..FakeHelper::ready()
    };
    assert!(matches!(mk(&unsupported), StepOutcome::Unsupported { .. }));

    // 用户取消提权 → 失败，原因原样带出。
    let cancelled = FakeHelper {
        result: Err("已取消管理员授权".to_owned()),
        ..FakeHelper::ready()
    };
    match mk(&cancelled) {
        StepOutcome::Failed { detail } => assert!(detail.contains("已取消管理员授权")),
        other => panic!("实得 {other:?}"),
    }

    // 成功 → 报告必须点名受保护目录（用户得知道到底删了哪儿）。
    let ok = FakeHelper::ready();
    match mk(&ok) {
        StepOutcome::Done { detail } => {
            assert!(detail.contains("/fake/protected/core"), "{detail}");
        }
        other => panic!("实得 {other:?}"),
    }
}

// ── 开机自启腿（OS 登录项在配置目录之外，漏掉就是「卸载不干净」的最痛一项）──────

/// 🟡 **变异锁：登录项三态 + 摘不掉必须硬失败。**
///
/// 这条腿删的东西**不在配置目录里**（macOS LaunchAgent plist / Windows 注册表 Run 键 /
/// Linux `~/.config/autostart/*.desktop`），删配置目录顺手带不走它。留着的后果是永久性的：
/// 应用都没了，系统每次登录还去拉那个不存在的可执行文件。
///
/// **变异探针**：把 `disable_autostart` 的 `Err` 腿改成 `StepOutcome::skipped(..)`
/// ⇒ 第 3 段转红；把 `is_enabled()` 判定删掉（无条件 disable）⇒ 第 1 段的调用次数断言转红。
#[test]
fn autostart_leg_three_states() {
    let s = Scratch::new("autostart");
    let helper = FakeHelper::ready();
    let mk = |a: &FakeAutostart| -> StepOutcome {
        SystemUninstallOps {
            helper: &helper,
            autostart: a,
            os: "linux",
            config_dir: s.path().join(CONFIG_DIR_LEAF),
            cache_updates_dir: None,
            bundle_identifier: "com.polaris.app".to_owned(),
            exe: None,
            appimage: None,
        }
        .disable_autostart()
    };

    // 1. 本就没开 → 跳过，且**不去动登录项**（没开还去 disable 是无谓的系统写操作）。
    let off = FakeAutostart::off();
    assert!(matches!(mk(&off), StepOutcome::Skipped { .. }));
    assert_eq!(off.calls.load(Ordering::SeqCst), 0);

    // 2. 开着 → 注销成功。
    let on = FakeAutostart::on();
    assert!(matches!(mk(&on), StepOutcome::Done { .. }));
    assert_eq!(on.calls.load(Ordering::SeqCst), 1);

    // 3. 摘不掉 → **硬失败**（fail-fast 会据此拦下后面所有删除）。
    let stuck = FakeAutostart {
        result: Err("registry access denied".to_owned()),
        ..FakeAutostart::on()
    };
    let out = mk(&stuck);
    assert!(
        out.is_failure(),
        "登录项摘不掉却继续删，等于给用户留一个永久报错的登录项"
    );
    match out {
        StepOutcome::Failed { detail } => assert!(detail.contains("registry access denied")),
        other => panic!("实得 {other:?}"),
    }
}

/// 🟡 **变异锁：登录项摘不掉 ⇒ helper / 配置 / 应用本体一项都不许删。**
///
/// **变异探针**：把 `DELETE_ORDER` 里的 `Autostart` 挪到末尾 ⇒ 本条转红（前面几项已被删）。
#[test]
fn autostart_failure_blocks_everything_after_it() {
    let mut ops = RecordingOps::all_ok();
    ops.autostart = StepOutcome::failed("摘不掉");
    let report = run_uninstall(&ops, StepOutcome::done("stopped"));
    assert_eq!(
        ops.calls(),
        vec![UninstallStep::Autostart],
        "登录项这一步失败后，一个删除动作都不该发生（此时代价还是零）"
    );
    for step in [
        UninstallStep::Helper,
        UninstallStep::UserConfig,
        UninstallStep::CacheDir,
        UninstallStep::AppBundle,
    ] {
        assert!(matches!(
            outcome_of(&report, step),
            StepOutcome::NotAttempted { .. }
        ));
    }
}

// ── 更新包缓存腿（`app_cache_dir()/updates`，同样在配置目录之外）────────────

/// 缓存腿在**副本**上跑通；叶名不是 `updates` 的一律拒（白名单同款）。
///
/// **变异探针**：把 `remove_cache_dir` 里的 `validate_cache_updates_dir` 去掉 ⇒ 第 2 段转红。
#[test]
fn cache_leg_deletes_the_copy_and_guards_the_leaf() {
    let s = Scratch::new("cache");
    let helper = FakeHelper::ready();
    let autostart = FakeAutostart::off();
    let mk = |dir: Option<PathBuf>| -> StepOutcome {
        SystemUninstallOps {
            helper: &helper,
            autostart: &autostart,
            os: "linux",
            config_dir: s.path().join(CONFIG_DIR_LEAF),
            cache_updates_dir: dir,
            bundle_identifier: "com.polaris.app".to_owned(),
            exe: None,
            appimage: None,
        }
        .remove_cache_dir()
    };

    // 1. 正常：副本被删。
    let updates = s.path().join(CACHE_UPDATES_LEAF);
    std::fs::create_dir_all(&updates).unwrap();
    std::fs::write(updates.join("Polaris-0.1.1.AppImage"), b"installer").unwrap();
    assert!(matches!(
        mk(Some(updates.clone())),
        StepOutcome::Done { .. }
    ));
    assert!(!updates.exists());

    // 2. 叶名不在白名单 → 拒删且目录必须还在。
    let rogue = s.path().join("Downloads");
    std::fs::create_dir_all(&rogue).unwrap();
    std::fs::write(rogue.join("keep.bin"), b"x").unwrap();
    assert!(mk(Some(rogue.clone())).is_failure());
    assert!(rogue.join("keep.bin").exists(), "白名单外一个字节都不许动");

    // 3. 不存在 / 解析不到 → Skipped（幂等重试不该报错）。
    assert!(matches!(mk(Some(updates)), StepOutcome::Skipped { .. }));
    assert!(matches!(mk(None), StepOutcome::Skipped { .. }));
}

// ── Preferences 域腿（macOS `~/Library/Preferences/<id>.plist`，同样在配置目录之外）────
//
// 真清除只在 macOS 上发生且**不可测**（本机是 Linux；真跑一次会清掉真实用户的偏好域）。
// 故这一族测的是：清单里有没有它、序在哪、域名判定挡不挡得住误清、路径拼得对不对。

/// 🟡 **变异锁：Preferences 域必须在删除清单里，且排在应用本体之前。**
///
/// 漏掉它 = 卸载完 `~/Library/Preferences/com.polaris.app.plist` 还躺着一条
/// 「这台机器的 Polaris 被设成过俄语」的记录，重装后以一个用户没设过的语言启动。
/// 排到 `AppBundle` 之后 = 那一步之后已经没有代码可执行（mac 上 `.app` 已被删）。
///
/// **变异探针**：把 `Preferences` 从 [`UninstallStep::DELETE_ORDER`] 里删掉 ⇒ 本条转红；
/// 与它对调 `AppBundle` ⇒ 第 2 段转红。
#[test]
fn preferences_leg_is_in_the_delete_list_before_the_app_bundle() {
    let order = UninstallStep::DELETE_ORDER;
    let at = order.iter().position(|s| *s == UninstallStep::Preferences);
    let app = order.iter().position(|s| *s == UninstallStep::AppBundle);
    assert!(
        at.is_some(),
        "Preferences 域不在删除清单里 —— 卸载会留下 ~/Library/Preferences/<id>.plist"
    );
    assert!(at < app, "必须早于删应用本体：那一步之后没有代码可执行了");

    // 编排层真的会调它（只在常量里写一笔而 `dispatch` 漏了 ⇒ 永远不执行）。
    let ops = RecordingOps::all_ok();
    let _ = run_uninstall(&ops, StepOutcome::done("stopped"));
    assert!(
        ops.calls().contains(&UninstallStep::Preferences),
        "DELETE_ORDER 里有、dispatch 里没有 = 一条永不执行的清单项"
    );
}

/// 清偏好域失败 ⇒ 应用本体不许删（fail-fast 对新腿同样成立）。
#[test]
fn preferences_failure_blocks_app_removal() {
    let mut ops = RecordingOps::all_ok();
    ops.prefs = StepOutcome::failed("拒绝清除");
    let report = run_uninstall(&ops, StepOutcome::done("stopped"));
    assert!(!ops.calls().contains(&UninstallStep::AppBundle));
    assert!(matches!(
        outcome_of(&report, UninstallStep::AppBundle),
        StepOutcome::NotAttempted { .. }
    ));
}

/// 🟡 **变异锁：域名白名单挡得住「清掉用户全系统偏好」。**
///
/// `removePersistentDomainForName:` 收到 `NSGlobalDomain` 会抹掉
/// `~/Library/Preferences/.GlobalPreferences.plist` —— 用户的系统语言/区域/键盘设置，
/// 与 Polaris 毫无关系。这是本判定存在的首要理由。
///
/// **变异探针**：删掉 [`validate_pref_domain`] 里的 `GLOBAL_PREF_DOMAINS` 判据 ⇒ 本条转红。
#[test]
fn reject_global_pref_domains() {
    for d in [
        "NSGlobalDomain",
        "nsglobaldomain",
        ".GlobalPreferences",
        "kCFPreferencesAnyApplication",
    ] {
        assert_eq!(
            validate_pref_domain(d),
            Err(PrefDomainReject::Global),
            "{d} 必须被拒 —— 清它等于抹掉用户全系统的偏好"
        );
    }
}

/// 空 / 非反向 DNS 形态一律拒（identifier 已经不是本应用那一个了）。
///
/// **变异探针**：删掉 `contains('.')` 判据 ⇒ `"polaris"` 那条转红。
#[test]
fn reject_malformed_pref_domain() {
    assert_eq!(validate_pref_domain(""), Err(PrefDomainReject::Empty));
    assert_eq!(validate_pref_domain("   "), Err(PrefDomainReject::Empty));
    for d in [
        "polaris",                      // 裸名：不是本应用的域
        ".hidden",                      // 点开头：`.GlobalPreferences` 那一族的形状
        "/Users/x/Library/Preferences", // 拿到的是路径不是域名
        "com.polaris.app/../other",     // 路径穿越
        "com.polaris app",              // 含空白
    ] {
        assert_eq!(
            validate_pref_domain(d),
            Err(PrefDomainReject::Malformed),
            "{d} 必须被拒"
        );
    }
    assert_eq!(validate_pref_domain("com.polaris.app"), Ok(()));
    assert_eq!(
        validate_pref_domain(" com.polaris.app "),
        Ok(()),
        "两侧空白应被 trim"
    );
}

/// 非 macOS 上这一步是 `Skipped` 而**不是** `Unsupported` ——
/// 后者会让 Linux/Windows 上每一次干净卸载都被判成 `Incomplete`。
///
/// **变异探针**：把非 macOS 那支的 `skipped` 改成 `unsupported` ⇒ 本条在 Linux/Windows 上转红。
#[cfg(not(target_os = "macos"))]
#[test]
fn preferences_leg_is_skipped_not_unsupported_off_macos() {
    let s = Scratch::new("prefs");
    let helper = FakeHelper::ready();
    let autostart = FakeAutostart::off();
    let ops = SystemUninstallOps {
        helper: &helper,
        autostart: &autostart,
        os: "linux",
        config_dir: s.path().join(CONFIG_DIR_LEAF),
        cache_updates_dir: None,
        bundle_identifier: "com.polaris.app".to_owned(),
        exe: None,
        appimage: None,
    };
    assert!(matches!(
        ops.remove_preferences(),
        StepOutcome::Skipped { .. }
    ));

    // 域名坏掉时**照样**是硬失败（这条判定不分平台）。
    let bad = SystemUninstallOps {
        bundle_identifier: "NSGlobalDomain".to_owned(),
        ..ops
    };
    assert!(bad.remove_preferences().is_failure());
}

/// plist 路径拼装：`$HOME/Library/Preferences/<identifier>.plist`。
///
/// 只进报告文案，但拼错的形态是「报告里指了个不存在的文件」，用户照着去看会以为没清干净。
/// 与 `app_language::user_config_path` 那条同款：写死整条绝对路径，不只查叶名。
#[test]
fn preferences_plist_path_is_home_then_library_preferences_then_identifier() {
    assert_eq!(
        preferences_plist_path(Path::new("/Users/x"), "com.polaris.app"),
        Path::new("/Users/x/Library/Preferences/com.polaris.app.plist"),
    );
}

// ── 前端契约面 ──────────────────────────────────────────────────────────

/// 报告的序列化形是前端逐项渲染的契约：字段名/步骤名/结果 kind 一变前端就哑了。
#[test]
fn report_serializes_the_frontend_contract() {
    let mut ops = RecordingOps::all_ok();
    ops.app = StepOutcome::unsupported("便携版");
    let report = run_uninstall(&ops, StepOutcome::done("stopped"));
    let v = serde_json::to_value(&report).unwrap();

    assert_eq!(v["verdict"], "incomplete");
    assert_eq!(v["requiresExit"], true);
    let steps = v["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 7);
    assert_eq!(steps[0]["step"], "stopCore");
    assert_eq!(steps[1]["step"], "autostart");
    assert_eq!(steps[2]["step"], "helper");
    assert_eq!(steps[3]["step"], "userConfig");
    assert_eq!(steps[4]["step"], "cacheDir");
    assert_eq!(steps[5]["step"], "preferences");
    assert_eq!(steps[6]["step"], "appBundle");
    assert_eq!(steps[6]["outcome"]["kind"], "unsupported");
    assert_eq!(steps[6]["outcome"]["detail"], "便携版");
}
