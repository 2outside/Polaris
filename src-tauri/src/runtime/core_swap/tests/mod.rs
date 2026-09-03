use super::*;
use crate::runtime::core_paths::read_seed_marker;

use crate::test_support::TestDir;

fn tmpdir() -> TestDir {
    TestDir::new("polaris-core-swap-test-")
}

// ── 簿记回写（空簿记 = 该核被静默永久钉住）──

/// [`marker_rewrite_line`] 真值表。**第一条就是缺陷本体**：声明值为空时必须用盘上实读。
///
/// 变异锁：
///  - 删掉「declared 空 ⇒ 用 probed」那条腿（直接返 `None`）→ 第 1、4 条红；
///  - 改成「无条件用 probed」→ 第 2 条红（会盖掉手动上传核的文件名 token）；
///  - 去掉 `probed` 的空判 → 第 3 条红（把空串写进簿记 = 缺陷原样复现）。
#[test]
fn marker_rewrite_line_fills_only_when_declared_is_blank() {
    // ① 缺陷本体：`core_update_run`（前端传 downloadUrl ⇒ latest 空）/ `core_rollback`（传 ""）。
    assert_eq!(
        marker_rewrite_line("", "sing-box version 1.14.0-beta.3"),
        Some("sing-box version 1.14.0-beta.3")
    );
    // ② 调用方已给准确值 ⇒ 不覆盖（手动上传核的文件名 token、staged 记录、随包基线）。
    assert_eq!(
        marker_rewrite_line("1.14.0-beta.3", "sing-box version 1.14.0-beta.3"),
        None
    );
    // ③ 两者都空 ⇒ 诚实保留 unknown，**绝不编造**。
    assert_eq!(marker_rewrite_line("", ""), None);
    // ④ 纯空白等同于空（两侧都 trim）。
    assert_eq!(
        marker_rewrite_line("   ", "  sing-box version 1.14.0-beta.3  "),
        Some("sing-box version 1.14.0-beta.3")
    );
}

/// 端到端：模拟 UI 换核路径（声明值为空）落位后回写簿记，**后续随包升级必须能重播种**。
///
/// 这条锁的是缺陷本体而不是它的后果：先断言「不回写 ⇒ 簿记为空 ⇒ decide_reseed 判 Keep」
/// 确实成立（否则这道门在测一个不存在的问题），再断言回写后变成 Reseed。
#[test]
fn empty_declared_marker_pins_core_forever_until_rewritten() {
    use crate::runtime::core_paths::{decide_reseed, ReseedAction};

    let tmp = tmpdir();
    let base = tmp.path();
    // 模拟 `core_update_run` 的 UI 路径：version_line = ""（前端传了 downloadUrl）。
    install_core_bytes(base, "linux", b"NEWCORE", "", SwapSource::Update, false).unwrap();
    let m = read_seed_marker(base).expect("落位必须写簿记");
    assert!(
        m.version_line.is_empty(),
        "前置断言：声明值为空时 install_core_bytes 写的就是空簿记（这是缺陷的入口）"
    );
    // 缺陷本体：空簿记 ⇒ 判 unknown ⇒ 无论随包核多新都 Keep ⇒ 该核被永久钉住。
    assert_eq!(
        decide_reseed(true, Some(&m), "9.9.9"),
        ReseedAction::Keep,
        "前置断言：空簿记确实会让任意新随包核都不播种"
    );

    // 修复动作：驱动**生产代码本身**（= `swap_core_with_restart` 验证闩之后那一句）。
    assert!(
        rewrite_marker_from_probe(
            base,
            &m.version_line,
            "sing-box version 1.14.0-beta.3",
            SwapSource::Update,
        )
        .unwrap(),
        "声明值为空 + 实读有值 ⇒ 必须真回写"
    );

    let m2 = read_seed_marker(base).unwrap();
    assert!(!m2.version_line.is_empty(), "回写后簿记不得再为空");
    assert_eq!(
        decide_reseed(true, Some(&m2), "1.14.1"),
        ReseedAction::Reseed,
        "回写后，更新的随包基线必须能重播种（否则升级对这台机器仍然无效）"
    );
    // 反向：随包基线更旧时仍不得降级用户在跑的核。
    assert_eq!(
        decide_reseed(true, Some(&m2), "1.14.0-alpha.45"),
        ReseedAction::Keep
    );
}

/// 🔴 **跨写读边界的端到端豁免用例**：`SwapSource::Manual` 落位 → 读回簿记 → `decide_reseed`
/// 判 `Keep`；`SwapSource::Update` 同条件必须判 `Reseed`。
///
/// **为什么非要端到端而不是只测 `decide_reseed`**：豁免的判据是一个**字符串**，写侧在
/// `SwapSource::as_str`、读侧在 `core_paths::decide_reseed`。两侧各写一份字面量时，
/// 写 `"Manual"` 而读比 `"manual"` ⇒ 豁免恒不命中 ⇒ 手动核照旧被覆盖，而**两侧的单侧单测
/// 都还是绿的**。这条用例是唯一能抓住那种漂移的门（`SOURCE_MANUAL` 常量是第二道）。
///
/// 变异锁：把 `as_str` 的 Manual 臂改回独立字面量 `"Manual"`（或任何拼写差异）→ 第 1 段红；
/// 把 `is_manual()` 放宽成恒 true → 第 2 段（Update 正向对照）红。
#[test]
fn manual_source_survives_write_read_roundtrip_and_exempts_reseed() {
    use crate::runtime::core_paths::{decide_reseed, ReseedAction, SOURCE_MANUAL};

    // ① 手动上传：走真 `install_core_bytes`，版本行取「官方且旧于随包」——豁免前必被覆盖。
    let tmp = tmpdir();
    let base = tmp.path();
    install_core_bytes(
        base,
        "linux",
        b"USER-UPLOADED",
        "sing-box version 1.12.0",
        SwapSource::Manual,
        false,
    )
    .unwrap();
    let m = read_seed_marker(base).expect("落位必须写簿记");
    assert_eq!(
        m.source, SOURCE_MANUAL,
        "写侧 source 必须逐字等于读侧判据常量，否则豁免恒不命中（且两侧单测都绿）"
    );
    assert!(m.is_manual());
    assert_eq!(
        decide_reseed(true, Some(&m), "1.13.0"),
        ReseedAction::Keep,
        "手动上传的核必须被豁免，绝不能被随包基线覆盖"
    );
    // 簿记仍**如实**记着版本（豁免不靠「把版本抹掉」换来）。
    assert_eq!(m.version_line, "sing-box version 1.12.0");

    // ② 正向对照：同样的版本行、只把来源换成 Update ⇒ 必须 Reseed。
    //    没有这一段，上面那条可以被「decide_reseed 无条件 Keep」骗过去。
    let tmp2 = tmpdir();
    let base2 = tmp2.path();
    install_core_bytes(
        base2,
        "linux",
        b"APP-UPDATED",
        "sing-box version 1.12.0",
        SwapSource::Update,
        false,
    )
    .unwrap();
    let m2 = read_seed_marker(base2).unwrap();
    assert!(!m2.is_manual());
    assert_eq!(
        decide_reseed(true, Some(&m2), "1.13.0"),
        ReseedAction::Reseed,
        "非手动来源的官方旧核仍须被重播种，否则随包核升级对所有人失效"
    );
}

// ── 归档决策 ──

#[test]
fn archive_extract_command_recognizes_official_shapes_only() {
    for n in [
        "sing-box-1.13.0-linux-amd64.tar.gz",
        "sing-box-1.13.0-windows-amd64.zip",
        "x.TGZ",
    ] {
        assert!(archive_extract_command(n).is_ok(), "{n} 应可解压");
    }
    // **逃逸用例**：认不出的后缀必须报错。若这里放行，会把任意文件当归档喂给 tar，
    // 解压失败后的空目录再走 pick → 报「产物未找到」，成因被掩盖两层。
    for n in ["sing-box", "sing-box.exe", "x.7z", "x.tar.xz"] {
        assert!(archive_extract_command(n).is_err(), "{n} 不应被当作归档");
    }
    assert!(is_raw_binary_asset("sing-box"));
    assert!(!is_raw_binary_asset("sing-box-1.0-linux-amd64.tar.gz"));
}

#[test]
fn pick_core_from_listing_handles_both_layouts_and_refuses_deep_nesting() {
    // 官方布局：一层顶层目录。
    let entries = vec![
        PathBuf::from("sing-box-1.13.0-linux-amd64/LICENSE"),
        PathBuf::from("sing-box-1.13.0-linux-amd64/sing-box"),
    ];
    assert_eq!(
        pick_core_from_listing(&entries, "sing-box"),
        Some(PathBuf::from("sing-box-1.13.0-linux-amd64/sing-box"))
    );
    // 平铺布局。
    let flat = vec![PathBuf::from("sing-box"), PathBuf::from("LICENSE")];
    assert_eq!(
        pick_core_from_listing(&flat, "sing-box"),
        Some(PathBuf::from("sing-box"))
    );
    // 平铺优先于嵌套（更明确）。
    let both = vec![PathBuf::from("a/sing-box"), PathBuf::from("sing-box")];
    assert_eq!(
        pick_core_from_listing(&both, "sing-box"),
        Some(PathBuf::from("sing-box"))
    );
    // **逃逸用例**：埋太深 → 不捡（非官方结构，宁可报错也不乱落位一个不明二进制）。
    let deep = vec![PathBuf::from("a/b/c/sing-box")];
    assert_eq!(pick_core_from_listing(&deep, "sing-box"), None);
    // 文件名不符 → 不捡。
    let wrong = vec![PathBuf::from("dir/sing-box-cli")];
    assert_eq!(pick_core_from_listing(&wrong, "sing-box"), None);
    // Windows 名分开判定（拿 Unix 名去 Windows 归档里找必须落空）。
    let win = vec![PathBuf::from("d/sing-box.exe")];
    assert_eq!(pick_core_from_listing(&win, "sing-box"), None);
    assert_eq!(
        pick_core_from_listing(&win, "sing-box.exe"),
        Some(PathBuf::from("d/sing-box.exe"))
    );
}

#[test]
fn pick_core_from_dir_walks_at_most_one_level() {
    let tmp = tmpdir();
    let root = tmp.path();
    let sub = root.join("sing-box-1.13.0-linux-amd64");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(sub.join("sing-box"), b"CORE").unwrap();
    std::fs::write(sub.join("LICENSE"), b"L").unwrap();
    assert_eq!(
        pick_core_from_dir(root, "sing-box").unwrap(),
        sub.join("sing-box")
    );
    // 空目录 → 如实报错（不返回一个瞎猜的路径）。
    let empty = tmpdir();
    assert!(pick_core_from_dir(empty.path(), "sing-box").is_err());
}

// ── 换核 / 备份 / 回滚 ──

#[test]
fn install_backs_up_current_core_then_rollback_restores_it() {
    let tmp = tmpdir();
    let base = tmp.path();
    let dest = writable_core_path_in(base, "linux");

    // v1 落位（首次：无现役核 → 无备份）。
    let r = install_core_bytes(base, "linux", b"V1", "1.12.0", SwapSource::Manual, false).unwrap();
    assert!(!r.backed_up, "首次落位无现役核可备份");
    assert!(!has_backup(base, "linux"));

    // v2 落位 → 备份 v1。
    let r = install_core_bytes(base, "linux", b"V2", "1.13.0", SwapSource::Update, false).unwrap();
    assert!(r.backed_up);
    assert_eq!(std::fs::read(&dest).unwrap(), b"V2");
    assert!(has_backup(base, "linux"));
    assert_eq!(read_seed_marker(base).unwrap().version_line, "1.13.0");

    // 回滚 → 恢复 v1，且备份被消费掉（不留「回滚到自己」的假选项）。
    let r = rollback_core(base, "linux", "1.12.0").unwrap();
    assert!(!r.backed_up);
    assert_eq!(std::fs::read(&dest).unwrap(), b"V1");
    assert!(!has_backup(base, "linux"), "回滚后备份必须消费掉");
    assert_eq!(read_seed_marker(base).unwrap().version_line, "1.12.0");
}

#[test]
fn rollback_without_backup_fails_honestly() {
    let tmp = tmpdir();
    let e = rollback_core(tmp.path(), "linux", "1.0.0").unwrap_err();
    assert!(e.contains("无可回滚"), "实得: {e}");
}

#[test]
fn reset_factory_skips_backup_and_prunes_stale_one() {
    // **逃逸用例**：reset-factory 若照常备份，用户「重置到出厂」后 UI 会出现一个「回滚到刚被
    // 主动丢弃的那个核」的选项 —— 语义倒错。skip_backup 必须同时**清掉旧备份**。
    let tmp = tmpdir();
    let base = tmp.path();
    install_core_bytes(base, "linux", b"V1", "1.12.0", SwapSource::Manual, false).unwrap();
    install_core_bytes(base, "linux", b"V2", "1.13.0", SwapSource::Update, false).unwrap();
    assert!(has_backup(base, "linux"));

    let r = install_core_bytes(
        base,
        "linux",
        b"FACTORY",
        "1.13.0",
        SwapSource::ResetFactory,
        true,
    )
    .unwrap();
    assert!(!r.backed_up);
    assert!(!has_backup(base, "linux"), "reset-factory 必须清掉残留备份");
    assert_eq!(
        std::fs::read(writable_core_path_in(base, "linux")).unwrap(),
        b"FACTORY"
    );
}

#[test]
fn atomic_replace_leaves_no_temp_residue() {
    let tmp = tmpdir();
    let base = tmp.path();
    install_core_bytes(base, "linux", b"V1", "1.0.0", SwapSource::Manual, false).unwrap();
    let dir = core_update_dir_in(base);
    let names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        !names
            .iter()
            .any(|n| n.contains("polaris-new") || n.ends_with(".tmp")),
        "换核后不得留临时残件，实得: {names:?}"
    );
}

#[test]
fn unknown_build_marker_after_manual_swap_protects_user_core() {
    // 手动换核时探测不到版本 → 簿记记空串 → classify 为 unknown → 后续 app 升级永不覆盖。
    let tmp = tmpdir();
    let base = tmp.path();
    install_core_bytes(base, "linux", b"MYSTERY", "", SwapSource::Manual, false).unwrap();
    let m = read_seed_marker(base).unwrap();
    assert_eq!(m.version_line, "");
    assert_eq!(
        crate::runtime::core_paths::decide_reseed(true, Some(&m), "9.9.9"),
        crate::runtime::core_paths::ReseedAction::Keep,
        "版本未知的用户核绝不能被随包核覆盖"
    );
}

#[cfg(unix)]
#[test]
fn swapped_core_is_executable() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tmpdir();
    let base = tmp.path();
    install_core_bytes(base, "linux", b"V1", "1.0.0", SwapSource::Update, false).unwrap();
    let mode = std::fs::metadata(writable_core_path_in(base, "linux"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o111, 0o111, "换核后必须可执行，实得 {mode:o}");
}
