use super::*;

fn p(s: &str) -> PathBuf {
    PathBuf::from(s)
}

// ── 资产形态分类 ──

#[test]
fn classify_installer_covers_all_four_shapes_case_insensitively() {
    assert_eq!(
        classify_installer("Polaris-Setup-1.0.exe"),
        Some(InstallerKind::WinExe)
    );
    assert_eq!(
        classify_installer("Polaris-1.0.dmg"),
        Some(InstallerKind::Dmg)
    );
    assert_eq!(
        classify_installer("Polaris-1.0.AppImage"),
        Some(InstallerKind::AppImage)
    );
    assert_eq!(
        classify_installer("polaris-1.0.appimage"),
        Some(InstallerKind::AppImage)
    );
    assert_eq!(
        classify_installer("polaris_1.0_amd64.deb"),
        Some(InstallerKind::Deb)
    );
    // 认不出的一律 None（**不猜**：猜错就是拿错脚本去改宿主应用本体）。
    assert_eq!(classify_installer("polaris-1.0.tar.gz"), None);
    assert_eq!(classify_installer("README"), None);
}

// ── 运行形态判定 ──

#[test]
fn detect_run_form_truth_table() {
    assert_eq!(
        detect_run_form("linux", Some(Path::new("/a.AppImage")), None),
        RunForm::Loose
    );
    assert_eq!(detect_run_form("linux", None, None), RunForm::Installed);
    assert_eq!(
        detect_run_form("windows", None, Some(Path::new("C:\\p.exe"))),
        RunForm::Loose
    );
    // 无便携标记（`portable.marker` 不在 exe 同级，或被用户删了）→ Installed（保守：推安装器）。
    assert_eq!(detect_run_form("windows", None, None), RunForm::Installed);
    assert_eq!(detect_run_form("macos", None, None), RunForm::Loose);
}

// ── .app 包路径推导 ──

#[test]
fn mac_app_bundle_from_exe_matches_only_real_bundle_layout() {
    assert_eq!(
        mac_app_bundle_from_exe(Path::new(
            "/Applications/Polaris.app/Contents/MacOS/polaris"
        )),
        Some(p("/Applications/Polaris.app"))
    );
    // 非 bundle 布局 → None（**不瞎猜**，回退 open DMG 手动拖拽）。
    assert_eq!(
        mac_app_bundle_from_exe(Path::new("/usr/local/bin/polaris")),
        None
    );
    assert_eq!(
        mac_app_bundle_from_exe(Path::new("/A/Polaris.app/Contents/MacOS/")),
        None
    );
    // 尾段含 `/`（多层）→ 不匹配。
    assert_eq!(
        mac_app_bundle_from_exe(Path::new("/A/Polaris.app/Contents/MacOS/sub/polaris")),
        None
    );
}

// ── 安装计划真值表（含跨形态错配逃逸用例）──

#[test]
fn plan_windows_portable_vs_setup() {
    // ⚠️ 本测试跑在 Linux gate 上，而 `Path::parent` 的分隔符语义是**编译目标平台**的
    // （Linux 上 `C:\App\x.exe` 是单个组件，parent 为空）。故这里用 `/` 分隔——Windows API
    // 同样接受正斜杠，且这样断言的是「新包落在原 exe 同目录」这条真正的业务规则，
    // 而不是宿主平台的分隔符解析。反斜杠路径的真实拆分属真机门（§8.3）。
    let plan = decide_install_plan(
        "windows",
        RunForm::Loose,
        Path::new("C:/Temp/Polaris-1.2-win-portable.exe"),
        Path::new("C:/App/Polaris-1.1-win-portable.exe"),
        None,
        Some(Path::new("C:/App/Polaris-1.1-win-portable.exe")),
    )
    .unwrap();
    assert_eq!(plan.platform, InstallPlatform::WindowsPortable);
    assert_eq!(
        plan.portable_target,
        Some(p("C:/App/Polaris-1.1-win-portable.exe"))
    );
    // 新版本名文件落在**原目录**，保留 release 的带版本号命名。
    assert_eq!(
        plan.portable_new_path,
        Some(p("C:/App/Polaris-1.2-win-portable.exe"))
    );

    let plan = decide_install_plan(
        "windows",
        RunForm::Installed,
        Path::new("C:/Temp/Polaris-1.2-win-setup.exe"),
        Path::new("C:/Program Files/Polaris/polaris.exe"),
        None,
        None,
    )
    .unwrap();
    assert_eq!(plan.platform, InstallPlatform::WindowsSetup);
    assert!(plan.portable_target.is_none());
}

#[test]
fn plan_macos_carries_bundle_or_falls_back() {
    let plan = decide_install_plan(
        "macos",
        RunForm::Loose,
        Path::new("/tmp/Polaris-1.2-mac-arm64.dmg"),
        Path::new("/Applications/Polaris.app/Contents/MacOS/polaris"),
        None,
        None,
    )
    .unwrap();
    assert_eq!(plan.platform, InstallPlatform::Macos);
    assert_eq!(plan.app_bundle_path, Some(p("/Applications/Polaris.app")));

    // 定位不到 bundle → 计划仍成立，但 app_bundle_path=None（脚本走 open DMG 手动拖拽）。
    let plan = decide_install_plan(
        "macos",
        RunForm::Loose,
        Path::new("/tmp/x.dmg"),
        Path::new("/usr/local/bin/polaris"),
        None,
        None,
    )
    .unwrap();
    assert!(plan.app_bundle_path.is_none());
}

#[test]
fn plan_linux_appimage_requires_appimage_env() {
    let plan = decide_install_plan(
        "linux",
        RunForm::Loose,
        Path::new("/tmp/Polaris-1.2.AppImage"),
        Path::new("/tmp/.mount_x/polaris"),
        Some(Path::new("/home/u/Apps/Polaris.AppImage")),
        None,
    )
    .unwrap();
    assert_eq!(plan.platform, InstallPlatform::LinuxAppImage);
    assert_eq!(
        plan.appimage_target,
        Some(p("/home/u/Apps/Polaris.AppImage"))
    );

    // **逃逸用例**：loose 形态但 $APPIMAGE 缺失 → 无覆盖目标，必须拒绝（否则会覆盖到 exe_path，
    // 而 AppImage 运行时的 exe_path 在 /tmp/.mount_* 只读挂载里 —— 覆盖它毫无意义且必失败）。
    let r = decide_install_plan(
        "linux",
        RunForm::Loose,
        Path::new("/tmp/Polaris-1.2.AppImage"),
        Path::new("/tmp/.mount_x/polaris"),
        None,
        None,
    );
    assert!(matches!(r, Err(InstallReject::FormMismatch { .. })));
}

#[test]
fn plan_rejects_cross_form_mismatch_and_never_escalates_to_root() {
    // **最要紧的逃逸用例**（§8.1 点名）：AppImage 运行形态 + .deb 资产。
    // 若这里放行，就会在 AppImage 用户机器上 `pkexec apt-get install` —— 提权装出第二份。
    let r = decide_install_plan(
        "linux",
        RunForm::Loose,
        Path::new("/tmp/polaris_1.2_amd64.deb"),
        Path::new("/tmp/.mount_x/polaris"),
        Some(Path::new("/home/u/Polaris.AppImage")),
        None,
    );
    match r {
        Err(InstallReject::FormMismatch {
            ref installer,
            ref form,
            ..
        }) => {
            assert_eq!(installer, "polaris_1.2_amd64.deb");
            assert_eq!(*form, RunForm::Loose);
        }
        other => panic!("AppImage 形态拿到 .deb 必须拒绝，实得: {other:?}"),
    }

    // 反向：deb 安装态 + AppImage 资产 → 同样拒绝。
    assert!(matches!(
        decide_install_plan(
            "linux",
            RunForm::Installed,
            Path::new("/tmp/Polaris.AppImage"),
            Path::new("/usr/bin/polaris"),
            None,
            None,
        ),
        Err(InstallReject::FormMismatch { .. })
    ));

    // 跨 OS 错配：Linux 上拿到 .dmg / .exe → 拒绝。
    for name in ["/tmp/x.dmg", "/tmp/x.exe"] {
        assert!(
            matches!(
                decide_install_plan(
                    "linux",
                    RunForm::Installed,
                    Path::new(name),
                    Path::new("/usr/bin/polaris"),
                    None,
                    None
                ),
                Err(InstallReject::FormMismatch { .. })
            ),
            "{name} 在 Linux 上必须被拒"
        );
    }
    // macOS 上拿到 .deb → 拒绝。
    assert!(matches!(
        decide_install_plan(
            "macos",
            RunForm::Loose,
            Path::new("/tmp/x.deb"),
            Path::new("/A/P.app/Contents/MacOS/p"),
            None,
            None
        ),
        Err(InstallReject::FormMismatch { .. })
    ));
}

#[test]
fn plan_rejects_unknown_asset() {
    assert!(matches!(
        decide_install_plan(
            "linux",
            RunForm::Installed,
            Path::new("/tmp/x.tar.gz"),
            Path::new("/usr/bin/p"),
            None,
            None
        ),
        Err(InstallReject::UnknownAsset { .. })
    ));
}

// ── 安装前告知（ad-hoc 签名 / 提权）──

fn plan_of(platform: InstallPlatform) -> InstallPlan {
    InstallPlan {
        platform,
        installer_path: p("/tmp/x"),
        exe_path: p("/usr/bin/polaris"),
        portable_target: None,
        portable_new_path: None,
        app_bundle_path: Some(p("/Applications/Polaris.app")),
        appimage_target: Some(p("/home/u/P.AppImage")),
    }
}

#[test]
fn advisory_is_required_wherever_os_will_block_or_prompt() {
    // 用户拍板走 ad-hoc 签名 ⇒ mac/win 都会被 OS 拦一道，**必须**提前告知可执行的下一步。
    assert_eq!(
        install_advisory(&plan_of(InstallPlatform::Macos)),
        Some(InstallAdvisory::MacosGatekeeper)
    );
    assert_eq!(
        install_advisory(&plan_of(InstallPlatform::WindowsSetup)),
        Some(InstallAdvisory::WindowsSmartScreen)
    );
    assert_eq!(
        install_advisory(&plan_of(InstallPlatform::WindowsPortable)),
        Some(InstallAdvisory::WindowsSmartScreen)
    );
    // deb：polkit 提权框（= 上游 confirmDebElevation），必须在停代理**之前**确认。
    assert_eq!(
        install_advisory(&plan_of(InstallPlatform::LinuxDeb)),
        Some(InstallAdvisory::DebElevation)
    );
    // AppImage：无签名校验、无提权 → 唯一无需告知的路径。
    assert_eq!(
        install_advisory(&plan_of(InstallPlatform::LinuxAppImage)),
        None
    );
}

#[test]
fn advisory_keys_are_distinct_and_stable() {
    // key 是前端 i18n 的契约面；三者必须互不相同（撞 key = 弹错说明）。
    let keys = [
        InstallAdvisory::DebElevation.key(),
        InstallAdvisory::WindowsSmartScreen.key(),
        InstallAdvisory::MacosGatekeeper.key(),
    ];
    let mut sorted = keys.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 3, "advisory key 必须互不相同");
}

// ── 脚本生成 ──

#[test]
fn windows_vbs_is_utf16le_with_bom() {
    // **变异防线**：若 utf16le_with_bom 退化成 `s.into_bytes()`（UTF-8），中文用户名路径会被
    // wscript 按系统代码页解释 → 找不到文件 → 更新静默失败。
    let plan = InstallPlan {
        portable_target: Some(p("C:\\用户\\Polaris.exe")),
        portable_new_path: Some(p("C:\\用户\\Polaris-1.2.exe")),
        ..plan_of(InstallPlatform::WindowsPortable)
    };
    let spec = build_install_script(&plan, &InstallTexts::default());
    assert_eq!(
        &spec.bytes[..2],
        &[0xFF, 0xFE],
        "VBS 必须以 UTF-16LE BOM 开头"
    );
    assert_eq!(
        spec.program, "wscript.exe",
        "必须用 wscript（无窗口），非 cscript"
    );
    // UTF-16LE：ASCII 字符后必跟 0x00。
    assert_eq!(spec.bytes[2], b'W');
    assert_eq!(spec.bytes[3], 0x00);
    // 解回文本验证内容。
    let units: Vec<u16> = spec.bytes[2..]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    let text = String::from_utf16(&units).unwrap();
    assert!(
        text.contains("C:\\\\用户\\\\Polaris.exe"),
        "路径反斜杠须双写"
    );
    assert!(text.contains("\r\n"), "VBS 行分隔符须是 CRLF");
    assert!(
        text.contains("MsgBox"),
        "覆盖失败必须提示用户手动替换，不得静默"
    );
}

#[test]
fn windows_setup_script_passes_update_flag() {
    let spec = build_install_script(
        &plan_of(InstallPlatform::WindowsSetup),
        &InstallTexts::default(),
    );
    let units: Vec<u16> = spec.bytes[2..]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    let text = String::from_utf16(&units).unwrap();
    // `/UPDATE` 不可省：Tauri NSIS 模板的 `$UpdateMode` 靠它，缺了会让应用内更新静默降级成
    // 全新安装模式（弹卸载/重装选择页 + 重跑 WebView2 安装 + 卸载器侧清理闸失效）。
    assert!(text.contains("/UPDATE"), "NSIS setup 必须带 /UPDATE");
    // 同时钉死**不得**再出现 electron-builder 的 `--updated`：这条门此前锁的正是那个错 flag，
    // 于是「传了个 Tauri 根本不认的参数」看起来像验过了。反向断言让退回旧写法直接转红。
    assert!(
        !text.contains("--updated"),
        "`--updated` 是 electron-builder 的约定，Tauri 不认（会静默降级成全新安装）"
    );
}

#[test]
fn mac_script_must_clear_quarantine_and_resign_adhoc() {
    // **变异验证（用户点名）**：删掉 quarantine 清除步骤 → 本测试必须转红。
    // ad-hoc 签名下不清 quarantine = 用户点了更新、装完打不开（最差体验）。
    let spec = build_install_script(&plan_of(InstallPlatform::Macos), &InstallTexts::default());
    let s = String::from_utf8(spec.bytes).unwrap();
    assert!(
        s.contains("xattr -dr com.apple.quarantine \"$DEST\""),
        "ad-hoc 签名下必须清 quarantine，否则 Gatekeeper 拦「身份不明的开发者」"
    );
    assert!(
        s.contains("codesign --force --deep --sign - \"$DEST\""),
        "签名校验不过时必须 ad-hoc 重签（`-s -` 无需任何证书）"
    );
    // 清 quarantine 必须在 `open` **之前**（顺序颠倒 = 先被拦一次）。
    let q = s.find("xattr -dr com.apple.quarantine").unwrap();
    let o = s.find("open \"$DEST\"").unwrap();
    assert!(q < o, "清 quarantine 必须早于启动新版");
    // 兜底指引：若仍起不来，把 .app 亮给用户（可右键→打开放行）。
    assert!(
        s.contains("open -R \"$DEST\""),
        "启动失败须给出用户可执行的下一步"
    );
    // 原子性：mv-swap，绝不先 rm 目标。
    assert!(
        !s.contains("rm -rf \"$DEST\""),
        "绝不先毁目标再建（brick 风险）"
    );
    assert!(s.contains("hdiutil attach"), "须挂载 DMG");
    assert!(s.contains("hdiutil detach"), "须卸载 DMG（否则残留挂载点）");
}

/// 成功判据必须落在 `$STAGE`（被移走 = 真替换过），不得落在 `$BAK` 不在场上。
///
/// `[ ! -d "$BAK" ]` 是**三种状态共有**的：真成功、第二步 mv 失败后已回滚、第一步 mv 就失败
/// （含提权密码框被取消，$BAK 从未产生）。后两种落进成功分支 = 删掉新版与 DMG、把旧版拉起来，
/// 而调用方已经向前端回了 success。
#[test]
fn mac_script_success_branch_keys_on_stage_not_bak() {
    let spec = build_install_script(&plan_of(InstallPlatform::Macos), &InstallTexts::default());
    let s = String::from_utf8(spec.bytes).unwrap();

    assert!(
        s.contains(r#"if [ -d "$DEST" ] && [ ! -d "$STAGE" ]; then"#),
        "成功判据没落在 $STAGE 上：\n{s}"
    );
    assert!(
        !s.contains(r#"[ ! -d "$BAK" ]"#),
        "还在用 $BAK 不在场当成功判据 —— 失败已回滚与提权被取消都满足它"
    );

    // 破坏性收尾必须落在**成功分支体内**。
    // 不做全局位置比较：脚本更早还有一条合法的早退腿（找不到 `.app` 时 `rm -f "$DMG"; exit 0`），
    // 全局 `find` 会撞上它 —— 实测本门第一版就是这么误红的。
    let cond = s.find(r#"[ ! -d "$STAGE" ]"#).expect("上一条已断言存在");
    let branch_end = s[cond..].find("\nelse\n").map_or(s.len(), |i| cond + i);
    let branch = &s[cond..branch_end];
    for destructive in [r#"rm -f "$DMG""#, r#"open "$DEST""#, r#"rm -rf "$STAGE""#] {
        assert!(
            branch.contains(destructive),
            "`{destructive}` 不在成功分支体内（跑到判据之外 = 失败时也会执行）：\n{branch}"
        );
    }

    // 失败侧的退路必须还在：重新打开 DMG 让用户手动拖拽。
    // **判据必须落在 else 分支体内**：脚本更早还有两处 `open "$DMG"`（挂载失败早退、
    // 定位不到 bundle 的回退），裸 `contains` 会被它们喂饱 —— 实测本门第一版就是这样，
    // 把 else 里那行删掉照样绿。
    let else_at = s[cond..]
        .find("\nelse\n")
        .map(|i| cond + i)
        .expect("成功分支没有 else —— 失败时无退路");
    let else_end = s[else_at..].find("\nfi").map_or(s.len(), |i| else_at + i);
    let else_body = &s[else_at..else_end];
    assert!(
        else_body.contains(r#"open "$DMG""#),
        "else 分支的手动拖拽退路没了 —— 失败时用户无路可走：\n{else_body}"
    );

    // 自检：$STAGE 确实是被 mv 走的那个（否则上面的判据在语义上不成立）。
    assert!(
        s.contains(r#"mv "$STAGE" "$DEST""#),
        "$STAGE 不再是被移走的对象，本门的整个前提失效"
    );
}

#[test]
fn mac_script_falls_back_to_open_dmg_without_bundle() {
    let plan = InstallPlan {
        app_bundle_path: None,
        ..plan_of(InstallPlatform::Macos)
    };
    let s = String::from_utf8(build_install_script(&plan, &InstallTexts::default()).bytes).unwrap();
    assert!(s.contains("open '/tmp/x'"));
    // 定位不到 bundle 时**绝不**瞎猜路径去 mv。
    assert!(!s.contains("mv "), "定位不到 .app 时不得做任何替换");
}

#[test]
fn linux_scripts_match_form() {
    let s = String::from_utf8(
        build_install_script(
            &plan_of(InstallPlatform::LinuxAppImage),
            &InstallTexts::default(),
        )
        .bytes,
    )
    .unwrap();
    assert!(s.contains("chmod +x \"$DEST\""), "覆盖后必须补执行位");
    assert!(!s.contains("pkexec"), "AppImage 路径绝不提权");

    let s = String::from_utf8(
        build_install_script(
            &plan_of(InstallPlatform::LinuxDeb),
            &InstallTexts::default(),
        )
        .bytes,
    )
    .unwrap();
    assert!(
        s.contains("pkexec apt-get install"),
        "deb 须走 apt 原位升级"
    );
    assert!(
        s.contains("xdg-open"),
        "提权被取消须回退到打开下载目录，不静默"
    );
}

#[test]
fn sh_quote_neutralizes_injection() {
    // 路径里的单引号是命令注入面（脚本以 root 跑 deb 分支）。
    assert_eq!(sh_quote("/tmp/a b"), "'/tmp/a b'");
    assert_eq!(
        sh_quote("/tmp/x';rm -rf /;'"),
        r"'/tmp/x'\'';rm -rf /;'\'''"
    );
    let plan = InstallPlan {
        installer_path: p("/tmp/x';touch /tmp/pwned;'"),
        ..plan_of(InstallPlatform::LinuxDeb)
    };
    let s = String::from_utf8(build_install_script(&plan, &InstallTexts::default()).bytes).unwrap();
    assert!(
        !s.contains("DEB='/tmp/x';touch"),
        "单引号必须被转义，不得逃出字面量"
    );
}

#[test]
fn utf16le_with_bom_roundtrips_non_ascii() {
    let bytes = utf16le_with_bom("中文A");
    assert_eq!(&bytes[..2], &[0xFF, 0xFE]);
    let units: Vec<u16> = bytes[2..]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    assert_eq!(String::from_utf16(&units).unwrap(), "中文A");
}

#[test]
fn script_generation_is_deterministic() {
    // 快照断言的前提：同一 plan 恒得同一字节（脚本里不得掺时间戳/随机数；$$ 是 shell 运行期取的）。
    let plan = plan_of(InstallPlatform::Macos);
    let a = build_install_script(&plan, &InstallTexts::default());
    let b = build_install_script(&plan, &InstallTexts::default());
    assert_eq!(a, b);
}
