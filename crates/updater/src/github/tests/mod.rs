use super::*;

fn asset(name: &str, size: u64) -> GithubAsset {
    GithubAsset {
        name: name.to_string(),
        browser_download_url: format!("https://github.com/o/r/releases/download/x/{name}"),
        size,
        digest: None,
    }
}

#[test]
fn parse_asset_digest_accepts_only_wellformed_sha256() {
    let hex = "a".repeat(64);
    assert_eq!(
        parse_asset_digest(&format!("sha256:{hex}")),
        Some(hex.clone())
    );
    // 大写规范化为小写（便于簿记比对；verify_bytes 本身大小写不敏感）。
    assert_eq!(
        parse_asset_digest(&format!("sha256:{}", "AB".repeat(32))),
        Some("ab".repeat(32))
    );
    // **逃逸用例**：长度不对 / 非 hex / 换算法 / 无前缀 / 空 → 一律 None。
    // 若被当成 sha256 传给 verify_bytes，会把「拿不到可用摘要」伪装成「校验失败」。
    assert_eq!(parse_asset_digest("sha256:abcd"), None);
    assert_eq!(
        parse_asset_digest(&format!("sha256:{}", "z".repeat(64))),
        None
    );
    assert_eq!(parse_asset_digest(&format!("blake3:{hex}")), None);
    assert_eq!(parse_asset_digest(&hex), None);
    assert_eq!(parse_asset_digest(""), None);
}

#[test]
fn check_app_update_threads_digest_into_sha256_but_tolerates_absence() {
    let hex = "b".repeat(64);
    let json = format!(
        r#"[{{"tag_name":"v2.0.0","published_at":"2024-05-01T00:00:00Z","assets":[
                {{"name":"polaris_2.0.0_amd64.deb","browser_download_url":"https://x/d","size":9,
                  "digest":"sha256:{hex}"}}]}}]"#
    );
    let r = check_app_update(
        &json,
        "1.0.0",
        false,
        None,
        AssetPlatform::Linux,
        AssetArch::X64,
        false,
    )
    .unwrap();
    let AppUpdateCheck::Available(info) = r else {
        panic!("应有更新");
    };
    assert_eq!(info.sha256.as_deref(), Some(hex.as_str()));

    // 旧 release 无 digest → sha256=None，但**仍然报有更新**（缺摘要不阻断更新）。
    let json = r#"[{"tag_name":"v2.0.0","published_at":"2024-05-01T00:00:00Z","assets":[
            {"name":"polaris_2.0.0_amd64.deb","browser_download_url":"https://x/d","size":9}]}]"#;
    let r = check_app_update(
        json,
        "1.0.0",
        false,
        None,
        AssetPlatform::Linux,
        AssetArch::X64,
        false,
    )
    .unwrap();
    let AppUpdateCheck::Available(info) = r else {
        panic!("缺 digest 不得让更新消失");
    };
    assert_eq!(info.sha256, None);
}

#[test]
fn asset_digest_is_optional_and_parses_when_present() {
    // 旧 release 无 digest 字段 → 必须解析成功（缺摘要不是错误，回落 Content-Length 校验）。
    let no_digest = r#"[{"tag_name":"v2.0.0","published_at":"2024-05-01T00:00:00Z",
            "assets":[{"name":"polaris_2.0.0_amd64.deb","browser_download_url":"https://x/d","size":1}]}]"#;
    let rs: Vec<GithubRelease> = serde_json::from_str(no_digest).unwrap();
    assert_eq!(rs[0].assets[0].digest, None);

    let with_digest = r#"[{"tag_name":"v2.0.0","published_at":"2024-05-01T00:00:00Z",
            "assets":[{"name":"a.deb","browser_download_url":"https://x/d","size":1,
            "digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}]}]"#;
    let rs: Vec<GithubRelease> = serde_json::from_str(with_digest).unwrap();
    assert!(rs[0].assets[0]
        .digest
        .as_deref()
        .unwrap()
        .starts_with("sha256:"));
}

// ── 更新源常量 / URL ──────────────────────────────────────────────────────

#[test]
fn source_repo_constants_are_the_polaris_and_sagernet_repos() {
    // 更新源仓库是全链路的锚：改错 = 检查更新指向错误的 repo（拉不到或拉到别人的 release）。
    assert_eq!(APP_UPDATE_REPO, ("2outside", "Polaris"));
    assert_eq!(CORE_UPDATE_REPO, ("SagerNet", "sing-box"));
    assert_eq!(
        github_releases_api_url("2outside", "Polaris"),
        "https://api.github.com/repos/2outside/Polaris/releases"
    );
    // 便携资产前缀是三处（package.yml 产出 / 本模块选包 / verify-packaging.mjs 断言）
    // 共用的命名契约，改它必须三处同改，故在此钉死字面值。
    assert_eq!(PORTABLE_ZIP_PREFIX, "polaris-portable-");
}

#[test]
fn platform_and_arch_mapping_from_std_env_consts() {
    assert_eq!(
        AssetPlatform::from_os("windows"),
        Some(AssetPlatform::Windows)
    );
    assert_eq!(AssetPlatform::from_os("macos"), Some(AssetPlatform::Macos));
    assert_eq!(AssetPlatform::from_os("linux"), Some(AssetPlatform::Linux));
    assert_eq!(AssetPlatform::from_os("freebsd"), None);
    assert_eq!(AssetArch::from_arch("x86_64"), AssetArch::X64);
    assert_eq!(AssetArch::from_arch("aarch64"), AssetArch::Arm64);
    assert_eq!(AssetArch::from_arch("riscv64"), AssetArch::Other);
}

// ── App 安装包资产选择真值表（findSuitableUpdateAsset）────────────────────

/// 一个 release 的**真实资产集**（6 个，= README「各恰好一个」那张表 + `package.yml` 的实际产物名）。
///
/// 🔴 用真产物名，不用理想化名字：本函数此前的 Windows 测试用的是
/// `Polaris-0.2.0-win-x64-portable.exe` —— 一个**打包链从未产出过**的名字（便携产物是 zip）。
/// 测试在虚构输入上绿，真资产集下 loose 形态却恒命中 NSIS setup，缺陷因此活过了「全绿」。
fn release_assets() -> Vec<GithubAsset> {
    vec![
        asset("Polaris_0.2.0_x64-win-setup.exe", 100),
        asset("polaris-portable-v0.2.0.zip", 90),
        asset("Polaris_0.2.0_aarch64-mac-arm64.dmg", 110),
        asset("Polaris_0.2.0_x64-mac-x64.dmg", 111),
        asset("polaris_0.2.0_amd64.deb", 80),
        asset("Polaris_0.2.0_amd64.AppImage", 81),
    ]
}

/// 🔴 回归门（2026-07-22 修 #72 形态错配本体）：便携形态必须拿到**便携产物**。
///
/// 变异探针（每条覆盖一条独立逃逸路径，单条不足）：
///  - loose 分支改回共用 `.exe && contains("win")` 候选集 ⇒ ①③ 转红；
///  - loose 分支尾部补任何一级 `.or_else(...)` 回落到 `.exe` ⇒ ② 转红；
///  - 两个分支对调 ⇒ ①④ 转红；
///  - 前缀判据写成大小写不敏感 / `contains(".zip")` 而非 `ends_with` ⇒ ⑤⑥ 转红。
#[test]
fn update_asset_windows_loose_picks_portable_zip_never_an_installer() {
    let assets = release_assets();

    // ① 便携形态：拿到 zip，**不是** setup。
    let loose = find_suitable_update_asset(&assets, AssetPlatform::Windows, AssetArch::X64, true)
        .expect("便携形态必须能选到 polaris-portable-*.zip");
    assert_eq!(
        loose.name, "polaris-portable-v0.2.0.zip",
        "便携用户拿到安装器 = #72 形态错配本体（装出与便携副本并存的第二份程序）"
    );

    // ② 便携产物缺失（portable 那步挂了）：**必须 None**，绝不回落任一 `.exe`。
    //    宁可不更新，也不发错形态包 —— 与 macOS「不发错架构包」同一条纪律。
    let no_zip: Vec<GithubAsset> = release_assets()
        .into_iter()
        .filter(|a| !a.name.ends_with(".zip"))
        .collect();
    assert!(
        find_suitable_update_asset(&no_zip, AssetPlatform::Windows, AssetArch::X64, true).is_none(),
        "便携形态选不到 zip 时必须返回 None，不得回落 NSIS setup"
    );

    // ③ 安装形态：仍然是 downloadBootstrapper 安装器，**不是** zip（命名契约一字未动）。
    let installed =
        find_suitable_update_asset(&assets, AssetPlatform::Windows, AssetArch::X64, false)
            .expect("安装形态必须能选到 bootstrapper");
    assert_eq!(installed.name, "Polaris_0.2.0_x64-win-setup.exe");

    // ④ 安装形态下便携 zip 存在也绝不被选中（两条规则不相交）。
    assert!(!installed.name.ends_with(".zip"));

    // ⑤ 前缀大小写敏感：非 `package.yml` 那个字面名的 zip 不得被当成便携产物。
    let wrong_case = vec![asset("Polaris-Portable-v0.2.0.zip", 90)];
    assert!(
        find_suitable_update_asset(&wrong_case, AssetPlatform::Windows, AssetArch::X64, true)
            .is_none(),
        "判据须与 package.yml 的字面产物名同口径（大小写敏感）"
    );

    // ⑥ `--clobber` 失效产生的 `.zip.1` 重复资产不得被选中（判据是 `ends_with`，不是 `contains`）。
    let clobber_dupe = vec![asset("polaris-portable-v0.2.0.zip.1", 90)];
    assert!(
        find_suitable_update_asset(&clobber_dupe, AssetPlatform::Windows, AssetArch::X64, true)
            .is_none(),
        "`.zip.1` 不是可用产物，不得被便携规则命中"
    );
}

#[test]
fn update_asset_windows_none_when_no_win_exe() {
    let assets = vec![
        asset("Polaris-0.2.0.dmg", 100),
        asset("Polaris-0.2.0.AppImage", 100),
    ];
    assert!(
        find_suitable_update_asset(&assets, AssetPlatform::Windows, AssetArch::X64, false)
            .is_none()
    );
    // 便携形态同样无适配（没有 zip）。
    assert!(
        find_suitable_update_asset(&assets, AssetPlatform::Windows, AssetArch::X64, true).is_none()
    );
}

/// 非 Windows 平台的选包**不受本次改动影响**：同一份真实资产集下 mac 双架构各自命中、
/// Linux 双形态各自命中。（防「顺手把 zip 规则套到别的平台」这类逃逸。）
#[test]
fn update_asset_other_platforms_unaffected_by_windows_portable_rule() {
    let assets = release_assets();
    let arm =
        find_suitable_update_asset(&assets, AssetPlatform::Macos, AssetArch::Arm64, true).unwrap();
    assert_eq!(arm.name, "Polaris_0.2.0_aarch64-mac-arm64.dmg");
    let x64 =
        find_suitable_update_asset(&assets, AssetPlatform::Macos, AssetArch::X64, false).unwrap();
    assert_eq!(x64.name, "Polaris_0.2.0_x64-mac-x64.dmg");
    let loose_linux =
        find_suitable_update_asset(&assets, AssetPlatform::Linux, AssetArch::X64, true).unwrap();
    assert_eq!(loose_linux.name, "Polaris_0.2.0_amd64.AppImage");
    let inst_linux =
        find_suitable_update_asset(&assets, AssetPlatform::Linux, AssetArch::X64, false).unwrap();
    assert_eq!(inst_linux.name, "polaris_0.2.0_amd64.deb");
}

/// 正常路径：双 dmg 齐全时两个架构各自命中，互不交叉。
///
/// 名字用 CI 真实产出（`package.yml` 的 `Tag macOS dmg with arch` 步：Tauri 默认名
/// `Polaris_<ver>_<triple-arch>.dmg` 追加 `-<mac_arch_tag>`），避免测试用理想化名字
/// 通过、真产物名不通过。注意 arm64 那份名里含 `aarch64`、x64 那份含 `x64`。
#[test]
fn update_asset_macos_picks_own_arch_dmg_when_both_present() {
    let assets = vec![
        asset("Polaris_0.2.0_aarch64-mac-arm64.dmg", 100),
        asset("Polaris_0.2.0_x64-mac-x64.dmg", 100),
    ];
    let arm =
        find_suitable_update_asset(&assets, AssetPlatform::Macos, AssetArch::Arm64, false).unwrap();
    assert_eq!(arm.name, "Polaris_0.2.0_aarch64-mac-arm64.dmg");
    let x64 =
        find_suitable_update_asset(&assets, AssetPlatform::Macos, AssetArch::X64, false).unwrap();
    assert_eq!(x64.name, "Polaris_0.2.0_x64-mac-x64.dmg");
    // 形态（loose_form）不参与 macOS 选包：两个形态选到同一份。
    assert_eq!(
        find_suitable_update_asset(&assets, AssetPlatform::Macos, AssetArch::Arm64, true)
            .unwrap()
            .name,
        arm.name
    );
}

/// 🔴 回归门（2026-07-21 用户裁定「宁可不更新，也不发错架构包」）：
/// release 里某个架构的 dmg 缺失（该 mac job 挂掉）时，**必须返回 None**，
/// 不得回落到另一架构那份 —— 否则 x64 用户会静默拿到 arm64 包。
///
/// 这两条是把 `.or_else(|| assets.iter().find(|a| a.name.ends_with(".dmg")))`
/// 加回去就会转红的变异探针（两个方向各一条，单向探针会漏掉对称的另一半）。
#[test]
fn update_asset_macos_returns_none_rather_than_cross_arch_dmg() {
    // 只剩 arm64 → x64 请求返回 None（不得拿到 arm64 包）。
    let only_arm = vec![asset("Polaris_0.2.0_aarch64-mac-arm64.dmg", 100)];
    assert!(
        find_suitable_update_asset(&only_arm, AssetPlatform::Macos, AssetArch::X64, false)
            .is_none(),
        "x64 请求在只有 arm64 dmg 时必须返回 None，不得回落跨架构包"
    );
    // 只剩 x64 → arm64 请求返回 None（对称方向）。
    let only_x64 = vec![asset("Polaris_0.2.0_x64-mac-x64.dmg", 100)];
    assert!(
        find_suitable_update_asset(&only_x64, AssetPlatform::Macos, AssetArch::Arm64, false)
            .is_none(),
        "arm64 请求在只有 x64 dmg 时必须返回 None，不得回落跨架构包"
    );
    // 无架构标记的裸 dmg（改名步失效的产物）同样不得被任一架构选中。
    let untagged = vec![asset("Polaris_0.2.0_aarch64.dmg", 100)];
    assert!(
        find_suitable_update_asset(&untagged, AssetPlatform::Macos, AssetArch::Arm64, false)
            .is_none()
    );
    assert!(
        find_suitable_update_asset(&untagged, AssetPlatform::Macos, AssetArch::X64, false)
            .is_none()
    );
}

#[test]
fn update_asset_linux_loose_picks_appimage_installed_picks_deb() {
    let assets = vec![
        asset("polaris_0.2.0_amd64.deb", 100),
        asset("Polaris-0.2.0.AppImage", 90),
    ];
    assert!(
        find_suitable_update_asset(&assets, AssetPlatform::Linux, AssetArch::X64, true)
            .unwrap()
            .name
            .ends_with(".AppImage")
    );
    assert!(
        find_suitable_update_asset(&assets, AssetPlatform::Linux, AssetArch::X64, false)
            .unwrap()
            .name
            .ends_with(".deb")
    );
    // installed 但只有 AppImage → 回落 AppImage。
    let only_img = vec![asset("Polaris-0.2.0.AppImage", 90)];
    assert!(
        find_suitable_update_asset(&only_img, AssetPlatform::Linux, AssetArch::X64, false)
            .unwrap()
            .name
            .ends_with(".AppImage")
    );
}

// ── 内核资产选择真值表（findSuitableSingboxAsset）─────────────────────────

#[test]
fn singbox_asset_matches_platform_arch_and_prefers_naive() {
    let assets = vec![
        asset("sing-box-1.14.0-linux-amd64.tar.gz", 10),
        asset("sing-box-1.14.0-linux-amd64-with-naive.tar.gz", 12),
        asset("sing-box-1.14.0-linux-amd64-legacy.tar.gz", 9),
        asset("sing-box-1.14.0-darwin-arm64.tar.gz", 10),
    ];
    // linux/amd64 + with-naive 优先。
    let picked =
        find_suitable_singbox_asset(&assets, AssetPlatform::Linux, AssetArch::X64).unwrap();
    assert!(picked.name.contains("with-naive"));
}

#[test]
fn singbox_asset_non_legacy_then_first_when_no_naive() {
    let assets = vec![
        asset("sing-box-1.14.0-windows-amd64-legacy.zip", 9),
        asset("sing-box-1.14.0-windows-amd64.zip", 10),
    ];
    // 无 naive → 非 legacy 优先。
    let picked =
        find_suitable_singbox_asset(&assets, AssetPlatform::Windows, AssetArch::X64).unwrap();
    assert!(!picked.name.contains("legacy"));
}

#[test]
fn singbox_asset_none_when_no_platform_match() {
    let assets = vec![asset("sing-box-1.14.0-darwin-arm64.tar.gz", 10)];
    // 找 windows/amd64 → 无命中。
    assert!(find_suitable_singbox_asset(&assets, AssetPlatform::Windows, AssetArch::X64).is_none());
}

// ── App 检查全链路（check_app_update）─────────────────────────────────────

/// 两个 release 的样本 JSON（GitHub 原始形状）：0.1.0（旧）+ 0.2.0（新，含多平台资产）。
fn sample_releases_json() -> String {
    r#"[
          {
            "tag_name": "v0.2.0",
            "name": "Polaris 0.2.0",
            "body": "新版说明",
            "prerelease": false,
            "published_at": "2024-05-01T12:00:00Z",
            "assets": [
              {"name": "Polaris-0.2.0-mac-arm64.dmg", "browser_download_url": "https://x/mac", "size": 12345},
              {"name": "Polaris-Setup-0.2.0-win-x64.exe", "browser_download_url": "https://x/win", "size": 999},
              {"name": "polaris_0.2.0_amd64.deb", "browser_download_url": "https://x/deb", "size": 555}
            ]
          },
          {
            "tag_name": "v0.1.0",
            "name": "Polaris 0.1.0",
            "prerelease": false,
            "published_at": "2024-01-01T00:00:00Z",
            "assets": []
          }
        ]"#
        .to_string()
}

#[test]
fn check_app_update_returns_available_with_faithful_fields() {
    let json = sample_releases_json();
    let r = check_app_update(
        &json,
        "0.1.0",
        false,
        None,
        AssetPlatform::Macos,
        AssetArch::Arm64,
        false,
    )
    .unwrap();
    match r {
        AppUpdateCheck::Available(info) => {
            assert_eq!(
                info.version, "v0.2.0",
                "version 保留原始 tag（含 v，对齐 上游）"
            );
            assert_eq!(info.title, "Polaris 0.2.0");
            assert_eq!(info.release_notes, "新版说明");
            assert_eq!(info.download_url, "https://x/mac");
            assert_eq!(info.file_size, 12345);
            assert_eq!(info.published_at, "2024-05-01T12:00:00Z");
            assert!(!info.is_prerelease);
            assert_eq!(info.file_name, "Polaris-0.2.0-mac-arm64.dmg");
        }
        AppUpdateCheck::NoUpdate => panic!("应发现 0.2.0 更新"),
    }
}

#[test]
fn check_app_update_no_update_when_current_is_latest() {
    let json = sample_releases_json();
    // 当前已是 0.2.0 → 无更新。
    let r = check_app_update(
        &json,
        "0.2.0",
        false,
        None,
        AssetPlatform::Macos,
        AssetArch::Arm64,
        false,
    )
    .unwrap();
    assert_eq!(r, AppUpdateCheck::NoUpdate);
}

#[test]
fn resolve_current_app_release_returns_only_the_same_channel_latest() {
    let json = sample_releases_json();
    let current = resolve_current_app_release(
        &json,
        "0.2.0",
        false,
        AssetPlatform::Macos,
        AssetArch::Arm64,
        false,
    )
    .unwrap();
    assert!(matches!(current, AppUpdateCheck::Available(ref i) if i.version == "v0.2.0"));

    let older = resolve_current_app_release(
        &json,
        "0.3.0",
        false,
        AssetPlatform::Macos,
        AssetArch::Arm64,
        false,
    )
    .unwrap();
    assert_eq!(older, AppUpdateCheck::NoUpdate, "不得借重装入口降级");

    let newer = resolve_current_app_release(
        &json,
        "0.1.0",
        false,
        AssetPlatform::Macos,
        AssetArch::Arm64,
        false,
    )
    .unwrap();
    assert_eq!(
        newer,
        AppUpdateCheck::NoUpdate,
        "真正的新版本应走普通更新入口"
    );
}

#[test]
fn check_app_update_skipped_version_is_no_update() {
    let json = sample_releases_json();
    // 跳过 0.2.0（存的是去 v 的版本）→ 无更新。
    let r = check_app_update(
        &json,
        "0.1.0",
        false,
        Some("0.2.0"),
        AssetPlatform::Macos,
        AssetArch::Arm64,
        false,
    )
    .unwrap();
    assert_eq!(r, AppUpdateCheck::NoUpdate);

    // W8 反例（同口径门的另一半）：存**原始 tag**（`v0.2.0`，修复前两个写点的实存形态）
    // ⇒ 与比较侧 strip_v 后的值永不相等 ⇒ 照常报 Available。若有人把比较侧改回原始 tag
    // 来「修」跳过，这半句转红——口径必须由写侧归一化（stored_skip_version），
    // 不是把比侧改脏。
    let raw = check_app_update(
        &json,
        "0.1.0",
        false,
        Some("v0.2.0"),
        AssetPlatform::Macos,
        AssetArch::Arm64,
        false,
    )
    .unwrap();
    assert!(
        matches!(raw, AppUpdateCheck::Available(_)),
        "原始 tag 不该命中跳过——命中了说明比较侧被改回原始 tag 口径"
    );
}

#[test]
fn check_app_update_prerelease_filtered_unless_included() {
    let json = r#"[
          {"tag_name":"v0.3.0-beta.1","prerelease":true,"published_at":"2024-06-01T00:00:00Z",
           "assets":[{"name":"Polaris-0.3.0-mac-arm64.dmg","browser_download_url":"https://x/beta","size":1}]},
          {"tag_name":"v0.2.0","prerelease":false,"published_at":"2024-05-01T00:00:00Z",
           "assets":[{"name":"Polaris-0.2.0-mac-arm64.dmg","browser_download_url":"https://x/stable","size":1}]}
        ]"#;
    // include_prerelease=false → beta 被过滤，最新正式 = 0.2.0。
    let stable = check_app_update(
        json,
        "0.1.0",
        false,
        None,
        AssetPlatform::Macos,
        AssetArch::Arm64,
        false,
    )
    .unwrap();
    assert!(matches!(stable, AppUpdateCheck::Available(ref i) if i.version == "v0.2.0"));
    // include_prerelease=true → 取最新发布 = beta。
    let beta = check_app_update(
        json,
        "0.1.0",
        true,
        None,
        AssetPlatform::Macos,
        AssetArch::Arm64,
        false,
    )
    .unwrap();
    assert!(matches!(beta, AppUpdateCheck::Available(ref i) if i.version == "v0.3.0-beta.1"));
}

#[test]
fn check_app_update_no_suitable_asset_is_no_update() {
    // 有更新但当前平台无适配资产（release 只有 mac dmg，平台是 windows）→ 无更新（非报错）。
    let json = sample_releases_json();
    let r = check_app_update(
        &json,
        "0.1.0",
        false,
        None,
        AssetPlatform::Windows,
        AssetArch::X64,
        false,
    )
    .unwrap();
    // 注：sample 里有 win-x64.exe → windows 应能匹配到 setup 包，故这里改用只有 dmg 的 release 断言无资产。
    // （sample 覆盖三平台，windows 有 setup → 会命中。故此断言其实是 Available；用独立样本测无资产。）
    assert!(matches!(r, AppUpdateCheck::Available(_)));

    let mac_only = r#"[{"tag_name":"v0.2.0","prerelease":false,"published_at":"2024-05-01T00:00:00Z",
          "assets":[{"name":"Polaris-0.2.0-mac-arm64.dmg","browser_download_url":"https://x/mac","size":1}]}]"#;
    let none = check_app_update(
        mac_only,
        "0.1.0",
        false,
        None,
        AssetPlatform::Windows,
        AssetArch::X64,
        false,
    )
    .unwrap();
    assert_eq!(none, AppUpdateCheck::NoUpdate);
}

/// 全链路：Windows 便携形态请求 → `updateInfo` 指向便携 zip（下载 URL / 文件名都是它）。
///
/// 只测 `find_suitable_update_asset` 不够：`check_app_update` 是宿主真正调的入口，
/// 形态参数得**一路传到底**才有意义（少传一层 = 选包器修好了、用户仍拿安装器）。
#[test]
fn check_app_update_windows_loose_form_yields_portable_zip() {
    let json = r#"[{"tag_name":"v0.2.0","prerelease":false,"published_at":"2024-05-01T00:00:00Z",
          "assets":[
            {"name":"Polaris_0.2.0_x64-win-setup.exe","browser_download_url":"https://x/win","size":1},
            {"name":"polaris-portable-v0.2.0.zip","browser_download_url":"https://x/zip","size":3}]}]"#;

    let loose = check_app_update(
        json,
        "0.1.0",
        false,
        None,
        AssetPlatform::Windows,
        AssetArch::X64,
        true,
    )
    .unwrap();
    let AppUpdateCheck::Available(info) = loose else {
        panic!("便携形态应发现更新（便携 zip 在 release 里）");
    };
    assert_eq!(info.file_name, "polaris-portable-v0.2.0.zip");
    assert_eq!(info.download_url, "https://x/zip");

    // 安装形态在同一份 release 上仍拿 bootstrapper。
    let installed = check_app_update(
        json,
        "0.1.0",
        false,
        None,
        AssetPlatform::Windows,
        AssetArch::X64,
        false,
    )
    .unwrap();
    let AppUpdateCheck::Available(info) = installed else {
        panic!("安装形态应发现更新");
    };
    assert_eq!(info.file_name, "Polaris_0.2.0_x64-win-setup.exe");

    // 便携产物缺失 ⇒ 便携用户如实「无更新」，**不是**被发安装器。
    let no_zip = r#"[{"tag_name":"v0.2.0","prerelease":false,"published_at":"2024-05-01T00:00:00Z",
          "assets":[{"name":"Polaris_0.2.0_x64-win-setup.exe","browser_download_url":"https://x/win","size":1}]}]"#;
    let r = check_app_update(
        no_zip,
        "0.1.0",
        false,
        None,
        AssetPlatform::Windows,
        AssetArch::X64,
        true,
    )
    .unwrap();
    assert_eq!(r, AppUpdateCheck::NoUpdate);
}

#[test]
fn check_app_update_malformed_json_errors() {
    let err = check_app_update(
        "{not json",
        "0.1.0",
        false,
        None,
        AssetPlatform::Linux,
        AssetArch::X64,
        false,
    )
    .unwrap_err();
    assert!(matches!(err, ManifestError::ParseJson(_)));
}

#[test]
fn check_app_update_empty_releases_is_no_update() {
    let r = check_app_update(
        "[]",
        "0.1.0",
        false,
        None,
        AssetPlatform::Linux,
        AssetArch::X64,
        false,
    )
    .unwrap();
    assert_eq!(r, AppUpdateCheck::NoUpdate);
}
