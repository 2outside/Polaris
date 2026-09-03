use super::*;

use crate::test_support::TestDir;

fn tmpdir() -> TestDir {
    TestDir::new("polaris-core-paths-test-")
}

// ── 路径解析纯函数 ──

#[test]
fn core_filename_is_platform_specific() {
    assert_eq!(core_filename_for("windows"), "sing-box.exe");
    assert_eq!(core_filename_for("linux"), "sing-box");
    assert_eq!(core_filename_for("macos"), "sing-box");
    // 未知 OS 回落 Unix 名（不 panic、不返空）。
    assert_eq!(core_filename_for("freebsd"), "sing-box");
}

#[test]
fn core_sidecar_filename_matches_packaged_cronet() {
    assert_eq!(core_sidecar_filename_for("windows"), Some("libcronet.dll"));
    assert_eq!(core_sidecar_filename_for("linux"), Some("libcronet.so"));
    assert_eq!(core_sidecar_filename_for("macos"), None);
    assert_eq!(core_sidecar_filename_for("freebsd"), None);
}

#[test]
fn writable_core_path_layout_is_stable() {
    let base = Path::new("/tmp/polaris-base");
    assert_eq!(
        writable_core_path_in(base, "linux"),
        Path::new("/tmp/polaris-base/core_update/sing-box")
    );
    assert_eq!(
        writable_core_path_in(base, "windows"),
        Path::new("/tmp/polaris-base/core_update/sing-box.exe")
    );
    assert_eq!(
        staged_dir_in(base),
        Path::new("/tmp/polaris-base/core-staged")
    );
    assert_eq!(
        seed_marker_path_in(base),
        Path::new("/tmp/polaris-base/core_update/.core-seed.json")
    );
}

#[test]
fn backup_path_appends_suffix_never_replaces_extension() {
    // 变异防线：若改用 `Path::with_extension("bak")`，Windows 的 sing-box.exe 会得到
    // sing-box.bak —— 与 Unix 侧撞名，跨平台语义漂移。
    assert_eq!(
        backup_path_for(Path::new("/a/core_update/sing-box")),
        Path::new("/a/core_update/sing-box.bak")
    );
    assert_eq!(
        backup_path_for(Path::new("/a/core_update/sing-box.exe")),
        Path::new("/a/core_update/sing-box.exe.bak")
    );
}

#[test]
fn accessors_return_none_when_base_dir_not_injected() {
    // 未注入基目录时全部访问器返 None → resolve_core_binary 回落随包种子（行为与接线前一致）。
    // 注：OnceLock 是进程级；本测试只在 base_dir 未被其它测试注入时有效地断言 None，
    // 故只断言「访问器与 base_dir() 同生共死」这一不变式，不硬断言 None。
    assert_eq!(base_dir().is_none(), writable_core_path().is_none());
    assert_eq!(base_dir().is_none(), core_backup_path().is_none());
    assert_eq!(base_dir().is_none(), staged_dir().is_none());
}

// ── reseed 决策真值表 + 逃逸用例（门有没有牙）──

fn marker(line: &str) -> CoreSeedMarker {
    CoreSeedMarker {
        version_line: line.to_string(),
        source: "test".into(),
    }
}

#[test]
fn reseed_seeds_when_writable_core_missing() {
    assert_eq!(decide_reseed(false, None, "1.13.0"), ReseedAction::Seed);
    // 有簿记但核不在（用户删了）→ 仍须播种。
    assert_eq!(
        decide_reseed(false, Some(&marker("sing-box version 1.13.0")), "1.13.0"),
        ReseedAction::Seed
    );
}

#[test]
fn reseed_keeps_user_placed_core_without_marker() {
    // **逃逸用例**：有核 + 无簿记 = 用户自放。若这里判 Reseed 就会静默吃掉用户的核。
    assert_eq!(decide_reseed(true, None, "9.9.9"), ReseedAction::Keep);
}

#[test]
fn reseed_overwrites_only_older_official_core() {
    // 官方 + 旧 → 重播种（app 升级带来更新的随包核）。
    assert_eq!(
        decide_reseed(true, Some(&marker("sing-box version 1.12.0")), "1.13.0"),
        ReseedAction::Reseed
    );
    // 官方 + 同版 → 保持（不做无谓写盘）。
    assert_eq!(
        decide_reseed(true, Some(&marker("sing-box version 1.13.0")), "1.13.0"),
        ReseedAction::Keep
    );
    // **逃逸用例**：官方 + 更新 → 必须 Keep。判 Reseed 就是把用户已在线更新的核降级回随包版本。
    assert_eq!(
        decide_reseed(true, Some(&marker("sing-box version 1.14.0")), "1.13.0"),
        ReseedAction::Keep
    );
}

/// **随包基线跨 prerelease 标识符升级（alpha→beta）必须重播种** —— 端到端串起
/// 「[`CoreSeedMarker::bundled`] 写的簿记 → [`classify_core_build`] 判官方 →
/// `compare_semver` 判更旧 → [`ReseedAction::Reseed`]」这条链。
///
/// 为什么非要一条：`bundled()` 写进簿记的是**裸版本 token**（不带 `sing-box version ` 前缀），
/// 而 `alpha.45`/`beta.3` 的数字段是**降序**（45 → 3）。任一环退化（簿记前缀口径变了 /
/// prerelease 比较被简化成只比数字段）都会得出「随包核更旧 ⇒ Keep」——症状正是
/// 「装了新包，运行的还是 `core_update/` 里那个旧核」，而这在盘面上完全无声。
///
/// 变异锁：`crates/updater` 的 `cmp_pre` 改成只比末段数字 → 本用例转红；
/// `bundled()` 改成写 `format!("sing-box version {v}")` 之外的脏串 → `classify_core_build`
/// 落 Unknown → Keep → 转红。
#[test]
fn reseed_fires_on_bundled_alpha_to_beta_upgrade() {
    assert_eq!(
        decide_reseed(
            true,
            Some(&CoreSeedMarker::bundled("1.14.0-alpha.45")),
            "1.14.0-beta.3"
        ),
        ReseedAction::Reseed
    );
    // 反向（随包核回退到 alpha）→ 绝不降级用户已在跑的 beta。
    assert_eq!(
        decide_reseed(
            true,
            Some(&CoreSeedMarker::bundled("1.14.0-beta.3")),
            "1.14.0-alpha.45"
        ),
        ReseedAction::Keep
    );
}

/// **手动上传的核显式豁免 reseed** —— 与「它是什么版本」无关。
///
/// 三行覆盖豁免前会被覆盖的全部形态：官方旧核（文件名解析得出版本的那条老路，**旧行为会
/// 被吃掉**）、官方新核、版本读不出（空簿记）。豁免只看 `source`，故三者一律 Keep。
///
/// 变异锁：删掉 `decide_reseed` 里的 `if m.is_manual()` 早返回 → 第 1 行转红
/// （`1.12.0` official 旧于 `1.13.0` ⇒ 落回 Reseed = 用户手放的核被随包基线吃掉）。
#[test]
fn reseed_exempts_manually_uploaded_core_regardless_of_version() {
    let manual = |line: &str| CoreSeedMarker {
        version_line: line.to_string(),
        source: SOURCE_MANUAL.to_string(),
    };
    // ① 官方 + 旧于随包 —— 这一行就是裁定要修的形态。
    assert_eq!(
        decide_reseed(true, Some(&manual("sing-box version 1.12.0")), "1.13.0"),
        ReseedAction::Keep,
        "手动上传的核绝不能因为「官方且旧」就被随包基线覆盖"
    );
    // ② 官方 + 更新（本来也 Keep，但要确认豁免没把语义弄反）。
    assert_eq!(
        decide_reseed(true, Some(&manual("sing-box version 1.14.0")), "1.13.0"),
        ReseedAction::Keep
    );
    // ③ 版本读不出（簿记 version_line 空）——豁免不依赖能否解析版本。
    assert_eq!(
        decide_reseed(true, Some(&manual("")), "1.13.0"),
        ReseedAction::Keep
    );
    // 大小写/空白不敏感：簿记是 JSON，手改过的文件不该让豁免静默失效。
    assert_eq!(
        decide_reseed(
            true,
            Some(&CoreSeedMarker {
                version_line: "sing-box version 1.12.0".into(),
                source: "  Manual ".into(),
            }),
            "1.13.0"
        ),
        ReseedAction::Keep
    );
}

/// 🔴 **豁免的正向对照：非 manual 的官方旧核必须仍被 reseed。**
///
/// 没有这一条，上面那道门可以被「把整条 reseed 关掉」骗过去（`decide_reseed` 无条件返
/// `Keep` 时它照样绿）—— 而那等于随包核升级对所有人失效，正是本轮一直在修的病。
///
/// 变异锁：把 `is_manual()` 写成恒 `true` / 让 `decide_reseed` 无条件返 `Keep` → 本条转红。
#[test]
fn reseed_still_fires_for_non_manual_sources() {
    for source in ["bundled", "update", "rollback", "reset-factory", ""] {
        assert_eq!(
            decide_reseed(
                true,
                Some(&CoreSeedMarker {
                    version_line: "sing-box version 1.12.0".into(),
                    source: source.to_string(),
                }),
                "1.13.0"
            ),
            ReseedAction::Reseed,
            "source={source:?} 的官方旧核仍必须被随包基线重播种（否则升级对所有人失效）"
        );
    }
}

#[test]
fn reseed_never_overwrites_fork_or_unknown_builds() {
    // **逃逸用例（最要紧）**：fork 核即便版本号旧于随包，也绝不能被覆盖 ——
    // 用户装 fork 是明确选择（reF1nd/nekolsd 之类带特性分支）。
    assert_eq!(
        decide_reseed(
            true,
            Some(&marker("sing-box version 1.11.0-reF1nd")),
            "1.13.0"
        ),
        ReseedAction::Keep
    );
    // unknown（go install / 源码自建 / 探测失败）同样不覆盖。
    assert_eq!(
        decide_reseed(true, Some(&marker("")), "1.13.0"),
        ReseedAction::Keep
    );
    assert_eq!(
        decide_reseed(true, Some(&marker("sing-box version unknown")), "1.13.0"),
        ReseedAction::Keep
    );
}

// ── reseed 执行（tempdir 驱动；不碰真 bundle、不起核）──

#[test]
fn ensure_writable_core_seeds_then_is_idempotent() {
    let tmp = tmpdir();
    let base = tmp.path();
    // 假随包核（**不用真 bundle**）。
    let bundled = base.join("bundled-sing-box");
    std::fs::write(&bundled, b"BUNDLED-1.13.0").unwrap();

    let dest = ensure_writable_core_at(base, "linux", &bundled, "1.13.0").unwrap();
    assert_eq!(dest, writable_core_path_in(base, "linux"));
    assert_eq!(std::fs::read(&dest).unwrap(), b"BUNDLED-1.13.0");
    assert_eq!(
        read_seed_marker(base).unwrap().version_line,
        "1.13.0",
        "播种后必须写簿记，否则下次启动会判「用户自放」永不重播种"
    );
    // 无 .polaris-seed 残件。
    assert!(!dest.with_extension("polaris-seed").exists());

    // 幂等：同版本再跑不覆盖（把内容改掉验证「确实没重写」）。
    std::fs::write(&dest, b"USER-EDITED").unwrap();
    ensure_writable_core_at(base, "linux", &bundled, "1.13.0").unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"USER-EDITED");
}

#[test]
fn ensure_writable_core_seeds_and_repairs_windows_cronet_sidecar() {
    let tmp = tmpdir();
    let base = tmp.path();
    let bundled_dir = base.join("resources-win");
    std::fs::create_dir_all(&bundled_dir).unwrap();
    let bundled = bundled_dir.join("sing-box.exe");
    std::fs::write(&bundled, b"BUNDLED").unwrap();
    std::fs::write(bundled_dir.join("libcronet.dll"), b"CRONET").unwrap();

    let dest = ensure_writable_core_at(base, "windows", &bundled, "1.13.0").unwrap();
    let sidecar = core_sidecar_path_for(&dest, "windows").unwrap();
    assert_eq!(std::fs::read(&sidecar).unwrap(), b"CRONET");

    // 模拟从旧版 Polaris 升级：核心与 bundled 簿记都在，但 sidecar 从未被播种。
    std::fs::remove_file(&sidecar).unwrap();
    ensure_writable_core_at(base, "windows", &bundled, "1.13.0").unwrap();
    assert_eq!(
        std::fs::read(&sidecar).unwrap(),
        b"CRONET",
        "同版 bundled 核必须自愈缺失的 libcronet.dll"
    );
}

#[test]
fn ensure_writable_core_reseeds_cronet_with_core_upgrade() {
    let tmp = tmpdir();
    let base = tmp.path();
    let bundled_dir = base.join("resources-linux");
    std::fs::create_dir_all(&bundled_dir).unwrap();
    let bundled = bundled_dir.join("sing-box");
    std::fs::write(&bundled, b"CORE-OLD").unwrap();
    std::fs::write(bundled_dir.join("libcronet.so"), b"CRONET-OLD").unwrap();
    let dest = ensure_writable_core_at(base, "linux", &bundled, "1.12.0").unwrap();

    std::fs::write(&bundled, b"CORE-NEW").unwrap();
    std::fs::write(bundled_dir.join("libcronet.so"), b"CRONET-NEW").unwrap();
    ensure_writable_core_at(base, "linux", &bundled, "1.13.0").unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"CORE-NEW");
    assert_eq!(
        std::fs::read(core_sidecar_path_for(&dest, "linux").unwrap()).unwrap(),
        b"CRONET-NEW"
    );
}

#[test]
fn ensure_writable_core_never_injects_bundled_sidecar_into_manual_core() {
    let tmp = tmpdir();
    let base = tmp.path();
    let bundled_dir = base.join("resources-win");
    std::fs::create_dir_all(&bundled_dir).unwrap();
    let bundled = bundled_dir.join("sing-box.exe");
    std::fs::write(&bundled, b"BUNDLED").unwrap();
    std::fs::write(bundled_dir.join("libcronet.dll"), b"BUNDLED-CRONET").unwrap();

    let dest = writable_core_path_in(base, "windows");
    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
    std::fs::write(&dest, b"MANUAL").unwrap();
    write_seed_marker(
        base,
        &CoreSeedMarker {
            version_line: "sing-box version 1.12.0".into(),
            source: SOURCE_MANUAL.into(),
        },
    )
    .unwrap();

    ensure_writable_core_at(base, "windows", &bundled, "1.13.0").unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"MANUAL");
    assert!(
        !core_sidecar_path_for(&dest, "windows").unwrap().exists(),
        "手动核的 cronet ABI 未知，禁止注入随包 DLL"
    );
}

#[test]
fn ensure_writable_core_reseeds_on_app_upgrade() {
    let tmp = tmpdir();
    let base = tmp.path();
    let bundled = base.join("bundled-sing-box");
    std::fs::write(&bundled, b"OLD").unwrap();
    ensure_writable_core_at(base, "linux", &bundled, "1.12.0").unwrap();

    // 模拟 app 升级：随包核变新。
    std::fs::write(&bundled, b"NEW").unwrap();
    let dest = ensure_writable_core_at(base, "linux", &bundled, "1.13.0").unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"NEW");
    assert_eq!(read_seed_marker(base).unwrap().version_line, "1.13.0");
}

#[test]
fn ensure_writable_core_keeps_fork_core_across_app_upgrade() {
    // 端到端逃逸用例：用户换成 fork → app 升级 → fork 必须原样保留。
    let tmp = tmpdir();
    let base = tmp.path();
    let bundled = base.join("bundled-sing-box");
    std::fs::write(&bundled, b"OFFICIAL").unwrap();
    ensure_writable_core_at(base, "linux", &bundled, "1.12.0").unwrap();

    let dest = writable_core_path_in(base, "linux");
    std::fs::write(&dest, b"FORK-BINARY").unwrap();
    write_seed_marker(
        base,
        &CoreSeedMarker {
            version_line: "sing-box version 1.11.0-reF1nd".into(),
            source: "manual".into(),
        },
    )
    .unwrap();

    ensure_writable_core_at(base, "linux", &bundled, "1.13.0").unwrap();
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        b"FORK-BINARY",
        "app 升级绝不能吃掉用户手动换上的 fork 核"
    );
}

#[test]
fn seed_marker_roundtrip_and_corruption_degrades_to_none() {
    let tmp = tmpdir();
    let base = tmp.path();
    assert!(read_seed_marker(base).is_none());
    write_seed_marker(base, &CoreSeedMarker::bundled("1.13.0")).unwrap();
    assert_eq!(read_seed_marker(base).unwrap().version_line, "1.13.0");
    // 损坏 → None（→ decide_reseed 判 Keep，失败安全，不覆盖用户核）。
    std::fs::write(seed_marker_path_in(base), b"{not json").unwrap();
    assert!(read_seed_marker(base).is_none());
    // 无 .tmp 残件。
    assert!(!seed_marker_path_in(base)
        .with_extension("json.tmp")
        .exists());
}

#[test]
fn ensure_writable_core_fails_loudly_when_bundled_missing() {
    // 失败不 fatal 但必须**如实报错**（调用方据此回落随包种子起核，绝不假成功）。
    let tmp = tmpdir();
    let base = tmp.path();
    let missing = base.join("nope");
    let e = ensure_writable_core_at(base, "linux", &missing, "1.13.0").unwrap_err();
    assert!(e.contains("复制随包核失败"), "实得: {e}");
    assert!(!writable_core_path_in(base, "linux").exists());
}

#[cfg(unix)]
#[test]
fn seeded_core_is_executable() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tmpdir();
    let base = tmp.path();
    let bundled = base.join("bundled-sing-box");
    std::fs::write(&bundled, b"X").unwrap();
    // 源文件刻意无执行位 —— 落位必须自己补，否则换核后起核 EACCES。
    std::fs::set_permissions(&bundled, std::fs::Permissions::from_mode(0o644)).unwrap();
    let dest = ensure_writable_core_at(base, "linux", &bundled, "1.13.0").unwrap();
    let mode = std::fs::metadata(&dest).unwrap().permissions().mode();
    assert_eq!(
        mode & 0o111,
        0o111,
        "落位后的核必须三位可执行，实得 {mode:o}"
    );
}
