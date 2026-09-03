//! App 自更新的**安装计划决策 + 平台脚本生成**（移植 上游 `update-install-script.ts`）。
//!
//! # 结构纪律：决策与执行切开
//!
//! 本模块 99% 是**纯函数**（形态判定 / 计划决策 / 脚本文本生成），可在本机零副作用单测；
//! 真正的执行腿只有一个 [`spawn_detached_script`]（写脚本 + `spawn(detached)`），且**本机绝不跑**
//! （改写宿主应用本体 + 需提权，属真机门）。
//!
//! # 为什么是「自写脚本」而不是 updater 框架
//!
//! 上游 全程**不用任何 updater 框架、不用任何应用级签名密钥对**（`UpdateService.ts` 1212 行手写）。
//! Polaris 同理：不引 `tauri-plugin-updater`，因而**不需要 minisign 密钥对**。真伪由 OS 层负责
//! （见下方「代码签名：ad-hoc 的后果」）。
//!
//! # 代码签名：ad-hoc 的后果（**用户已拍板走 ad-hoc，不买证书**）
//!
//! 没有 Developer ID / Authenticode ⇒ OS 层的「真伪」校验会拦下来。两平台表现与对策：
//!
//! | 平台 | 症状 | 应用内能否消除 | 本模块的处置 |
//! |---|---|---|---|
//! | macOS | 下载件带 `com.apple.quarantine` → Gatekeeper「来自身份不明的开发者」，**装完打不开** | ✅ **能** | 安装脚本在替换成功后**必跑** `xattr -dr com.apple.quarantine`（对齐 上游 `update-install-script.ts:259`）+ ad-hoc 重签兜底；失败分支给出「右键→打开」指引 |
//! | Windows | SmartScreen「未知发布者」 | ❌ **不能**（唯一解是买证书 / 攒信誉） | 安装**前**经 [`install_advisory`] 返 [`InstallAdvisory::WindowsSmartScreen`]，UI 弹说明框告知「更多信息 → 仍要运行」的具体点法 |
//!
//! **诚实原则**：无法在应用内消除拦截的平台，**必须**在安装前把用户可执行的下一步说清楚
//! （不是装完了事）。该判定是纯函数 [`install_advisory`]，有单测 + 变异用例钉死。
//!
//! # 移植对照
//!
//! | 平台 | 上游 | 本模块 |
//! |---|---|---|
//! | Windows 便携/NSIS | `buildWindowsUpdateVbs`（UTF-16LE+BOM 的 `.vbs`，`wscript` 无窗口跑） | [`build_install_script`] → [`ScriptSpec`] |
//! | macOS | `buildMacUpdateScript`（`hdiutil attach` → `ditto` 暂存 → mv-swap 原子替换 → `xattr -dr`） | 同上 |
//! | Linux AppImage | `buildLinuxAppImageScript`（覆盖 `$APPIMAGE` + chmod +x） | 同上 |
//! | Linux deb | `buildLinuxDebScript`（`pkexec apt-get install`） | 同上 |
//! | 形态错配 | 不强制 root，回退 `shell.openPath` 交系统（`UpdateService.ts:427-436`） | [`InstallReject::FormMismatch`]，command 层回退 `shell.open` |

use std::path::{Path, PathBuf};

// ── 运行形态 / 资产形态（纯判定）────────────────────────────────────────────

/// 应用运行形态（= 上游的 loose vs installed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunForm {
    /// 便携/免安装（Windows portable、Linux AppImage、macOS `.app`）。
    Loose,
    /// 安装态（Windows NSIS、Linux deb）。
    Installed,
}

/// 下载件的资产形态（由文件名后缀判定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallerKind {
    /// Windows 可执行安装器 / 便携包。
    WinExe,
    /// macOS 磁盘镜像。
    Dmg,
    /// Linux AppImage。
    AppImage,
    /// Linux Debian 包。
    Deb,
}

/// 由资产文件名判定形态（**纯函数**）。无法识别 → `None`。
///
/// 大小写：`.AppImage` 是官方命名（驼峰），但用户重命名/镜像改名很常见 → 一律按小写比较。
#[must_use]
pub fn classify_installer(file_name: &str) -> Option<InstallerKind> {
    let lower = file_name.to_ascii_lowercase();
    if lower.ends_with(".exe") {
        Some(InstallerKind::WinExe)
    } else if lower.ends_with(".dmg") {
        Some(InstallerKind::Dmg)
    } else if lower.ends_with(".appimage") {
        Some(InstallerKind::AppImage)
    } else if lower.ends_with(".deb") {
        Some(InstallerKind::Deb)
    } else {
        None
    }
}

/// 运行形态判定（**纯函数**：形态证据由调用方注入，本函数不读环境、不碰文件系统）。
///
/// - Linux：`APPIMAGE` 由 AppImage 运行时注入（真值，Electron/Tauri 通用）→ Loose；否则 deb 安装态。
/// - Windows：便携判据 = **exe 同级的 `portable.marker` 标记文件** —— 打包侧
///   `.github/workflows/package.yml` 的 `Build Windows portable zip` 步写进 zip 根，运行侧
///   `commands/updater::is_portable_layout` 探测。**判定只在那一处实现**，本函数只消费其结果：
///   `Some(便携 exe 路径)` → Loose；`None` → Installed（选 NSIS setup，保守且不会误覆盖）。
///   判据**不是** electron-builder 的 `PORTABLE_EXECUTABLE_FILE`（那是它自解压 stub 注入的，
///   Polaris 的便携版是纯 zip、无 stub ⇒ 该 env 恒不存在，成因详见 `is_portable_layout` 文档）。
/// - macOS：`.app` 恒 Loose（不分形态）。
///
/// ⚠️ **已知边界（未解决，如实登记）**：用户手动删掉 `portable.marker` 后判定退回 Installed，
/// 该用户会重新被推 NSIS 安装器。方向是失败安全的那一侧（安装器能装、不会砸掉便携副本），
/// 但**没有任何自动手段能守住它** —— 兜底只有标记文件内写明的「勿删」。
#[must_use]
pub fn detect_run_form(
    os: &str,
    appimage_env: Option<&Path>,
    portable_exe: Option<&Path>,
) -> RunForm {
    match os {
        "linux" => {
            if appimage_env.is_some() {
                RunForm::Loose
            } else {
                RunForm::Installed
            }
        }
        "windows" => {
            if portable_exe.is_some() {
                RunForm::Loose
            } else {
                RunForm::Installed
            }
        }
        "macos" => RunForm::Loose,
        _ => RunForm::Installed,
    }
}

// ── 安装计划 ────────────────────────────────────────────────────────────────

/// 安装路径（平台 × 形态的笛卡儿积收敛后的五种真实执行路径）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallPlatform {
    /// Windows 便携：把新版本名文件移入原目录 + 删旧版本名。
    WindowsPortable,
    /// Windows 安装态：跑 NSIS setup 原位升级。
    WindowsSetup,
    /// macOS：挂 DMG → 暂存 → mv-swap 原子替换 `.app` → 清 quarantine。
    Macos,
    /// Linux AppImage：覆盖 `$APPIMAGE` 原位。
    LinuxAppImage,
    /// Linux deb：`pkexec apt-get install` 原位升级。
    LinuxDeb,
}

/// 安装计划（[`build_install_script`] 的唯一输入）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallPlan {
    pub platform: InstallPlatform,
    /// 已下载的安装件路径。
    pub installer_path: PathBuf,
    /// 当前应用可执行文件路径（重启用）。
    pub exe_path: PathBuf,
    /// Windows 便携：原便携 exe 路径（被覆盖的目标）。
    pub portable_target: Option<PathBuf>,
    /// Windows 便携：新版本名文件在原目录的落点（保留 release 的带版本号命名）。
    pub portable_new_path: Option<PathBuf>,
    /// macOS：`.app` 包路径；`None` = 定位不到 → 回退 `open` DMG 手动拖拽。
    pub app_bundle_path: Option<PathBuf>,
    /// Linux AppImage：`$APPIMAGE` 原位路径。
    pub appimage_target: Option<PathBuf>,
}

/// 安装计划被拒的原因（**不是错误，是安全兜底**：拒绝即回退交系统处理）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallReject {
    /// 资产形态与当前运行形态不匹配（如 AppImage 运行 + `.deb` 资产）。
    ///
    /// **绝不强制 root 安装**（= 上游 `UpdateService.ts:427-436`）：错配下自动提权装 deb
    /// 会在 AppImage 用户机器上装出第二份、且要 root，是最坏结果。回退 `shell.open` 交系统。
    FormMismatch {
        installer: String,
        os: String,
        form: RunForm,
    },
    /// 文件名无法识别为任何已知安装件形态。
    UnknownAsset { file_name: String },
}

/// 从可执行路径推导 `.app` 包路径（**纯函数**，= 上游 `macAppBundleFromExe`）。
///
/// `/Applications/Polaris.app/Contents/MacOS/polaris` → `/Applications/Polaris.app`；不匹配返 `None`。
#[must_use]
pub fn mac_app_bundle_from_exe(exe_path: &Path) -> Option<PathBuf> {
    let s = exe_path.to_str()?;
    let idx = s.find(".app/Contents/MacOS/")?;
    let bundle = &s[..idx + 4];
    // 尾段必须是单层文件名（`/Contents/MacOS/<name>`，name 内无 `/`）。
    let tail = &s[idx + ".app/Contents/MacOS/".len()..];
    if tail.is_empty() || tail.contains('/') {
        return None;
    }
    Some(PathBuf::from(bundle))
}

/// 安装计划决策（**纯函数**：全部环境真值由参数注入 → 三平台真值表可在 Linux 上单测）。
///
/// # Errors
///
/// - [`InstallReject::UnknownAsset`]：文件名后缀不认识。
/// - [`InstallReject::FormMismatch`]：资产形态与 OS/运行形态错配。
pub fn decide_install_plan(
    os: &str,
    run_form: RunForm,
    installer_path: &Path,
    exe_path: &Path,
    appimage_env: Option<&Path>,
    portable_exe: Option<&Path>,
) -> Result<InstallPlan, InstallReject> {
    let file_name = installer_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let Some(kind) = classify_installer(&file_name) else {
        return Err(InstallReject::UnknownAsset { file_name });
    };
    let mismatch = || InstallReject::FormMismatch {
        installer: file_name.clone(),
        os: os.to_string(),
        form: run_form,
    };

    let base = |platform: InstallPlatform| InstallPlan {
        platform,
        installer_path: installer_path.to_path_buf(),
        exe_path: exe_path.to_path_buf(),
        portable_target: None,
        portable_new_path: None,
        app_bundle_path: None,
        appimage_target: None,
    };

    match (os, kind) {
        ("windows", InstallerKind::WinExe) => {
            if run_form == RunForm::Loose {
                // 便携：新版本名文件落在**原 exe 所在目录**（保留 release 的带版本号命名）。
                let target = portable_exe
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| exe_path.to_path_buf());
                let new_path = target
                    .parent()
                    .map(|d| d.join(&file_name))
                    .unwrap_or_else(|| target.clone());
                Ok(InstallPlan {
                    portable_target: Some(target),
                    portable_new_path: Some(new_path),
                    ..base(InstallPlatform::WindowsPortable)
                })
            } else {
                Ok(base(InstallPlatform::WindowsSetup))
            }
        }
        ("macos", InstallerKind::Dmg) => Ok(InstallPlan {
            app_bundle_path: mac_app_bundle_from_exe(exe_path),
            ..base(InstallPlatform::Macos)
        }),
        ("linux", InstallerKind::AppImage) => {
            // AppImage 资产只在 AppImage 运行形态下原位覆盖；deb 安装态拿到 AppImage 属错配。
            if run_form != RunForm::Loose {
                return Err(mismatch());
            }
            let Some(target) = appimage_env else {
                return Err(mismatch());
            };
            Ok(InstallPlan {
                appimage_target: Some(target.to_path_buf()),
                ..base(InstallPlatform::LinuxAppImage)
            })
        }
        ("linux", InstallerKind::Deb) => {
            // **关键安全闸**：AppImage 运行形态拿到 .deb → 拒绝（绝不 pkexec 装 deb）。
            if run_form != RunForm::Installed {
                return Err(mismatch());
            }
            Ok(base(InstallPlatform::LinuxDeb))
        }
        _ => Err(mismatch()),
    }
}

// ── 安装前告知（ad-hoc 签名 / 提权的用户可执行下一步）───────────────────────

/// 安装前必须告知用户的事项（**纯函数判定**，见模块文档「代码签名：ad-hoc 的后果」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallAdvisory {
    /// Linux deb：即将弹 polkit 提权框（= 上游 `confirmDebElevation`）。
    ///
    /// **必须在停代理之前弹**：用户取消即真 no-op，不留「代理被停但没更新」坏态
    /// （上游 `UpdateService.ts:306-315` 明确注释）。
    DebElevation,
    /// Windows：无 Authenticode 证书 → SmartScreen「未知发布者」。
    ///
    /// **应用内无法消除**（唯一解是买证书或攒 reputation）⇒ 只能提前把「更多信息 → 仍要运行」讲清楚。
    WindowsSmartScreen,
    /// macOS：ad-hoc 签名 → 下载件带 quarantine。
    ///
    /// 脚本会自动 `xattr -dr com.apple.quarantine` 清除；**万一失败**要告诉用户「右键 → 打开」。
    MacosGatekeeper,
}

/// 该计划是否需要安装前告知用户（**纯函数**）。
///
/// 返回 `Some` 时 command 层必须先把说明交给 UI 确认，**确认后**才停代理 + 起脚本。
#[must_use]
pub fn install_advisory(plan: &InstallPlan) -> Option<InstallAdvisory> {
    match plan.platform {
        InstallPlatform::LinuxDeb => Some(InstallAdvisory::DebElevation),
        InstallPlatform::WindowsPortable | InstallPlatform::WindowsSetup => {
            Some(InstallAdvisory::WindowsSmartScreen)
        }
        InstallPlatform::Macos => Some(InstallAdvisory::MacosGatekeeper),
        // AppImage 原位覆盖：无签名校验、无提权，装完直接跑 → 无需额外告知。
        InstallPlatform::LinuxAppImage => None,
    }
}

impl InstallAdvisory {
    /// 前端 i18n key 后缀（UI 据此取 `settings.update.advisory.<key>` 文案）。
    ///
    /// **Rust 侧不建 i18n 框架**（YAGNI）：这里只出 key，文案全在 `ui/src/i18n/locales/*.json`。
    #[must_use]
    pub fn key(self) -> &'static str {
        match self {
            Self::DebElevation => "debElevation",
            Self::WindowsSmartScreen => "windowsSmartScreen",
            Self::MacosGatekeeper => "macosGatekeeper",
        }
    }
}

// ── 脚本生成（纯字符串）──────────────────────────────────────────────────────

/// 生成的安装脚本规格。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptSpec {
    /// 脚本文件名（落到临时目录）。
    pub file_name: String,
    /// 脚本字节（**Windows 是 UTF-16LE + BOM**，故是字节而非 String）。
    pub bytes: Vec<u8>,
    /// 解释器程序。
    pub program: String,
    /// 解释器参数（脚本路径由 command 层追加到末尾）。
    pub leading_args: Vec<String>,
}

/// POSIX shell 单引号转义（= 上游 `shq`）。
#[must_use]
pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// VBS 字符串字面量：反斜杠双写（Windows 容忍双反斜杠路径，= 上游 `vbsPath`）。
#[must_use]
pub fn vbs_path(s: &str) -> String {
    s.replace('\\', r"\\")
}

/// VBS 字符串字面量：双引号双写（= 上游 `vbsStr`）。
#[must_use]
pub fn vbs_str(s: &str) -> String {
    s.replace('"', "\"\"")
}

/// UTF-16LE + BOM 编码（**Windows `.vbs` 必须**）。
///
/// # 为什么非它不可（上游的血泪注释，`UpdateService.ts:354-356`）
///
/// `wscript.exe` 按**系统代码页**解释无 BOM 的脚本。中文用户名路径
/// （`C:\Users\张三\AppData\Local\Temp\...`）在 UTF-8 字节被按 GBK 解释时会乱码 →
/// `fso.CopyFile` 找不到文件 → 更新静默失败。带 BOM 的 UTF-16LE 让 wscript 走 Unicode 路径。
#[must_use]
pub fn utf16le_with_bom(s: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE]; // BOM
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// 脚本里的用户可见文案（**由 command 层按 locale 注入**；Rust 侧不建 i18n 框架）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallTexts {
    /// Windows 便携覆盖失败时的 MsgBox 提示。
    pub portable_manual_replace: String,
    /// 产品名（MsgBox 标题）。
    pub product: String,
}

impl Default for InstallTexts {
    fn default() -> Self {
        Self {
            portable_manual_replace:
                "Polaris could not replace the portable executable. The new version was downloaded to the path below — please replace it manually:"
                    .to_string(),
            product: "Polaris".to_string(),
        }
    }
}

/// 按计划生成安装脚本（**纯函数**：同一 plan 恒得同一字节序列，可快照断言）。
#[must_use]
pub fn build_install_script(plan: &InstallPlan, texts: &InstallTexts) -> ScriptSpec {
    match plan.platform {
        InstallPlatform::WindowsPortable | InstallPlatform::WindowsSetup => {
            let text = build_windows_vbs(plan, texts);
            ScriptSpec {
                file_name: "polaris-update.vbs".to_string(),
                bytes: utf16le_with_bom(&text),
                program: "wscript.exe".to_string(),
                leading_args: vec![],
            }
        }
        InstallPlatform::Macos => ScriptSpec {
            file_name: "polaris-update.sh".to_string(),
            bytes: build_mac_script(plan).into_bytes(),
            program: "/bin/bash".to_string(),
            leading_args: vec![],
        },
        InstallPlatform::LinuxAppImage => ScriptSpec {
            file_name: "polaris-update.sh".to_string(),
            bytes: build_linux_appimage_script(plan).into_bytes(),
            program: "/bin/bash".to_string(),
            leading_args: vec![],
        },
        InstallPlatform::LinuxDeb => ScriptSpec {
            file_name: "polaris-update.sh".to_string(),
            bytes: build_linux_deb_script(plan).into_bytes(),
            program: "/bin/bash".to_string(),
            leading_args: vec![],
        },
    }
}

/// Windows 更新 VBS（移植 `buildWindowsUpdateVbs`）。行分隔符是 `\r\n`（wscript 要求）。
fn build_windows_vbs(plan: &InstallPlan, texts: &InstallTexts) -> String {
    let src_raw = plan.installer_path.to_string_lossy().into_owned();
    let src = vbs_path(&src_raw);

    let Some(old_exe_p) = plan.portable_target.as_ref() else {
        // NSIS 安装态：跑 setup 原位升级 + 删自身。
        return [
            "WScript.Sleep 2000".to_string(),
            "Set WshShell = CreateObject(\"WScript.Shell\")".to_string(),
            // 🔴 `/UPDATE`，**不是 上游的 `--updated`**（2026-08-05 修）：`--updated` 是
            // **electron-builder** 的约定（它的模板里由 `${isUpdated}` 消费），换到 Tauri 后不成立。
            // Tauri 的 NSIS 模板解析的是 `/UPDATE`（tauri-cli 2.11.4 内嵌模板逐字：
            // `${GetOptions} $CMDLINE "/UPDATE" $UpdateMode`，安装器与卸载器双侧各一处），
            // 且 `$UpdateMode` 有真实语义：
            //   · `${If} $UpdateMode = 1 → Goto reinst_done` —— 跳过「卸载旧版 / 重装」选择页
            //   · `${If} $UpdateMode <> 1` 才装 WebView2 —— 升级时不重跑 WebView2 安装
            //   · 卸载器侧三处 `${If} $UpdateMode <> 1` 清理闸 —— 升级时不做整卸清理
            // `${GetOptions}` 匹配不到只置 error flag、`$UpdateMode` 停在 0 ⇒ 传错 flag 不会报错，
            // 而是**静默降级成全新安装模式**。
            format!("WshShell.Run \"\"\"{src}\"\" /UPDATE\", 1, False"),
            "Set fso = CreateObject(\"Scripting.FileSystemObject\")".to_string(),
            "fso.DeleteFile WScript.ScriptFullName, True".to_string(),
        ]
        .join("\r\n");
    };

    let old_exe = vbs_path(&old_exe_p.to_string_lossy());
    let new_exe = vbs_path(
        &plan
            .portable_new_path
            .as_ref()
            .unwrap_or(old_exe_p)
            .to_string_lossy(),
    );
    let msg = vbs_str(&texts.portable_manual_replace);
    let product = vbs_str(&texts.product);
    // MsgBox 展示用**单**反斜杠原路径（双写路径给文件操作「容忍」用，直接展示/粘贴资源管理器不友好）。
    let src_display = vbs_str(&src_raw);

    [
        "WScript.Sleep 2000".to_string(),
        "Set WshShell = CreateObject(\"WScript.Shell\")".to_string(),
        "Set fso = CreateObject(\"Scripting.FileSystemObject\")".to_string(),
        format!("src = \"{src}\""),
        format!("oldExe = \"{old_exe}\""),
        format!("newExe = \"{new_exe}\""),
        "On Error Resume Next".to_string(),
        // 清上次残留 .old（新旧两路径都清）。
        "If fso.FileExists(newExe & \".old\") Then fso.DeleteFile newExe & \".old\", True"
            .to_string(),
        "If fso.FileExists(oldExe & \".old\") Then fso.DeleteFile oldExe & \".old\", True"
            .to_string(),
        "Err.Clear".to_string(),
        // 新版本名文件若已存在（重装同版本/残留被锁）→ rename 挪开腾出原名。
        "If fso.FileExists(newExe) Then fso.MoveFile newExe, newExe & \".old\"".to_string(),
        "Err.Clear".to_string(),
        "fso.CopyFile src, newExe, True".to_string(),
        "If Err.Number = 0 Then".to_string(),
        "  Err.Clear".to_string(),
        // 删旧版本名文件：被 stub 锁 → DeleteFile 失败则 rename 到 .old，下次启动清。
        "  If LCase(oldExe) <> LCase(newExe) Then".to_string(),
        "    fso.DeleteFile oldExe, True".to_string(),
        "    If Err.Number <> 0 Then".to_string(),
        "      Err.Clear".to_string(),
        "      fso.MoveFile oldExe, oldExe & \".old\"".to_string(),
        "    End If".to_string(),
        "  End If".to_string(),
        "  Err.Clear".to_string(),
        "  WshShell.Run \"\"\"\" & newExe & \"\"\"\", 1, False".to_string(),
        "  fso.DeleteFile src, True".to_string(),
        "Else".to_string(),
        // 写新名失败（原目录只读）→ **不静默**：跑临时新版 + 明确提示手动替换。
        "  Err.Clear".to_string(),
        "  WshShell.Run \"\"\"\" & src & \"\"\"\", 1, False".to_string(),
        format!("  MsgBox \"{msg}\" & vbCrLf & \"{src_display}\", 48, \"{product}\""),
        "End If".to_string(),
        "On Error Goto 0".to_string(),
        "fso.DeleteFile WScript.ScriptFullName, True".to_string(),
    ]
    .join("\r\n")
}

/// macOS 更新脚本（移植 `buildMacUpdateScript`）。
///
/// # ad-hoc 签名的关键一步
///
/// 替换成功后**必跑** `xattr -dr com.apple.quarantine "$DEST"`：ad-hoc 签名的 `.app` 一旦带
/// quarantine 属性，Gatekeeper 直接拒绝启动（「来自身份不明的开发者」）——**用户点了更新、装完打不开**，
/// 比不做更新还糟。再加一道 `codesign` 校验 + ad-hoc 重签兜底；两步都失败才落到「右键→打开」指引。
fn build_mac_script(plan: &InstallPlan) -> String {
    let dmg = sh_quote(&plan.installer_path.to_string_lossy());
    let Some(bundle) = plan.app_bundle_path.as_ref() else {
        // 定位不到 `.app` → 回退手动拖拽（**不猜路径**）。
        return format!("#!/bin/bash\nsleep 2\nopen {dmg}\n");
    };
    let dest = sh_quote(&bundle.to_string_lossy());
    [
        "#!/bin/bash",
        "sleep 2",
        &format!("DMG={dmg}"),
        &format!("DEST={dest}"),
        "BAK=\"$DEST.bak-$$\"",
        "STAGE=\"$(dirname \"$DEST\")/.polaris-update-$$.app\"",
        // 清历史中断遗留的暂存（防 /Applications 下垃圾堆积）。
        "rm -rf \"$(dirname \"$DEST\")\"/.polaris-update-*.app 2>/dev/null",
        "MNT=$(hdiutil attach \"$DMG\" -nobrowse -noautoopen -mountrandom /tmp 2>/dev/null | grep -o \"/tmp/[^[:space:]]*\" | tail -1)",
        "[ -z \"$MNT\" ] && { open \"$DMG\"; exit 0; }",
        "SRC=$(/usr/bin/find \"$MNT\" -maxdepth 1 -name \"*.app\" | head -1)",
        "[ -z \"$SRC\" ] && { hdiutil detach \"$MNT\" >/dev/null 2>&1; rm -f \"$DMG\"; exit 0; }",
        "rm -rf \"$STAGE\"",
        "if ! ditto \"$SRC\" \"$STAGE\"; then hdiutil detach \"$MNT\" >/dev/null 2>&1; rm -rf \"$STAGE\"; rm -f \"$DMG\"; exit 0; fi",
        "hdiutil detach \"$MNT\" >/dev/null 2>&1",
        // mv-swap 原子替换（**绝不先毁后建**）；失败回滚旧版并保留 $BAK 可人工恢复。
        "replace() {",
        "  mv \"$DEST\" \"$BAK\" 2>/dev/null || return 1",
        "  if mv \"$STAGE\" \"$DEST\" 2>/dev/null; then rm -rf \"$BAK\"; return 0; fi",
        "  mv \"$BAK\" \"$DEST\" 2>/dev/null; return 1",
        "}",
        "if ! replace; then",
        // 无提权失败 → 同一 mv-swap 落盘成脚本，osascript 一次性 root 跑（系统原生密码框，不依赖常驻 helper）。
        "  ELEV=\"$(dirname \"$DEST\")/.polaris-elev-$$.sh\"",
        "  cat > \"$ELEV\" <<EOF",
        "#!/bin/bash",
        "mv $(printf %q \"$DEST\") $(printf %q \"$BAK\") || exit 1",
        "mv $(printf %q \"$STAGE\") $(printf %q \"$DEST\") || { mv $(printf %q \"$BAK\") $(printf %q \"$DEST\"); exit 1; }",
        "rm -rf $(printf %q \"$BAK\")",
        "EOF",
        "  osascript -e \"do shell script \\\"/bin/bash '$ELEV'\\\" with administrator privileges\" 2>/dev/null",
        "  rm -f \"$ELEV\"",
        "fi",
        // 成功判据取 **$STAGE 是否已被移走**，不取 `[ ! -d "$BAK" ]`。
        //
        // `$BAK` 不在场是**三种状态共有**的，其中两种是失败：
        //   ① 真成功（`mv "$STAGE" "$DEST"` 后 `rm -rf "$BAK"`）
        //   ② 第二步 mv 失败 → 脚本自己回滚（`mv "$BAK" "$DEST"`）⇒ $BAK 也不在，而 $DEST 是**旧版**
        //   ③ 第一步 mv 就失败（非管理员账户 / .app 在只读位置）或提权密码框被取消 ⇒ $BAK 从未产生
        // ②③ 落进成功分支的后果是：删掉已解压好的新版与刚下载的 DMG、把**旧版**重新拉起来，
        // 而调用方在 spawn 后立即 `app.exit(0)` 并向前端回 success ⇒ 用户看到「更新完成、应用重启」，
        // 版本号却没变，且手动拖拽的退路（else 分支的 `open "$DMG"`）被绕过、安装包已被删。
        //
        // `$STAGE` 没有这个歧义：成功时它被 `mv` 移走，**任何**失败腿上它都还在
        //（第一步失败没动过它；第二步失败后回滚也没动过它；提权腿的 mv 失败同理）。
        "if [ -d \"$DEST\" ] && [ ! -d \"$STAGE\" ]; then",
        // ── ad-hoc 签名必需的两步（顺序不可换）──
        // ① 清 quarantine：不清则 Gatekeeper 拦「身份不明的开发者」→ 装完打不开。
        "  xattr -dr com.apple.quarantine \"$DEST\" 2>/dev/null",
        // ② 校验签名；ad-hoc 签名在替换过程中可能被破坏 → 就地重签（`-s -` = ad-hoc，无需任何证书）。
        "  if ! codesign --verify --deep --strict \"$DEST\" >/dev/null 2>&1; then",
        "    codesign --force --deep --sign - \"$DEST\" >/dev/null 2>&1",
        "  fi",
        "  rm -rf \"$STAGE\" 2>/dev/null",
        "  rm -f \"$DMG\"",
        "  open \"$DEST\"",
        // ③ 兜底：`open` 若仍被 Gatekeeper 拦，把 .app 所在目录亮出来，用户可「右键 → 打开」放行。
        "  sleep 3",
        "  pgrep -f \"$DEST\" >/dev/null 2>&1 || open -R \"$DEST\"",
        "else",
        "  open \"$DMG\"",
        "fi",
        "",
    ]
    .join("\n")
}

/// Linux AppImage 原位覆盖脚本（移植 `buildLinuxAppImageScript`）。
fn build_linux_appimage_script(plan: &InstallPlan) -> String {
    let src = sh_quote(&plan.installer_path.to_string_lossy());
    let dst = sh_quote(
        &plan
            .appimage_target
            .as_ref()
            .unwrap_or(&plan.exe_path)
            .to_string_lossy(),
    );
    [
        "#!/bin/bash",
        "sleep 2",
        &format!("NEW={src}"),
        &format!("DEST={dst}"),
        // 只覆盖 AppImage 这一个文件；`~/.config/polaris` 不动 → 配置 + 已更新内核零丢失。
        "if cp -f \"$NEW\" \"$DEST\" 2>/dev/null; then",
        "  chmod +x \"$DEST\" 2>/dev/null",
        "  rm -f \"$NEW\" 2>/dev/null",
        "  nohup \"$DEST\" >/dev/null 2>&1 &",
        "else",
        // 覆盖失败（原 AppImage 只读/无权限）→ 跑临时新版，至少本次拿到新版（不删临时件）。
        "  chmod +x \"$NEW\" 2>/dev/null",
        "  nohup \"$NEW\" >/dev/null 2>&1 &",
        "fi",
        "",
    ]
    .join("\n")
}

/// Linux deb 原位升级脚本（移植 `buildLinuxDebScript`）。
fn build_linux_deb_script(plan: &InstallPlan) -> String {
    let deb = sh_quote(&plan.installer_path.to_string_lossy());
    let exe = sh_quote(&plan.exe_path.to_string_lossy());
    [
        "#!/bin/bash",
        "sleep 2",
        &format!("DEB={deb}"),
        &format!("EXE={exe}"),
        // apt-get install 本地 deb（apt 1.1+ 支持绝对路径）：解依赖 + 同包名版本升级。
        // Ubuntu 24.04+ 默认 .deb 处理器是 App Center，对本地 deb 只按包名判「已安装」、不比较版本
        // → `xdg-open` 是死路，故必须走 apt。
        "if pkexec apt-get install -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \"$DEB\"; then",
        "  rm -f \"$DEB\" 2>/dev/null",
        "  nohup \"$EXE\" >/dev/null 2>&1 &",
        "else",
        // 用户取消授权 / apt 失败 → 打开下载目录让用户手动（**不**回退到 App Center 死路）。
        "  xdg-open \"$(dirname \"$DEB\")\" >/dev/null 2>&1 &",
        "fi",
        "",
    ]
    .join("\n")
}

// ── 唯一的执行腿（**真机门**：本机绝不调用）────────────────────────────────

/// 写脚本到临时目录并 `spawn(detached)`（**执行腿**）。
///
/// 调用方必须**先**停代理（Windows 文件占用会让替换失败），**后**退出应用。
///
/// # Errors
///
/// 写脚本 / spawn 失败。
pub fn spawn_detached_script(dir: &Path, spec: &ScriptSpec) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("建脚本目录失败 {}: {e}", dir.display()))?;
    let path = dir.join(&spec.file_name);
    std::fs::write(&path, &spec.bytes)
        .map_err(|e| format!("写安装脚本失败 {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755));
    }
    let mut cmd = std::process::Command::new(&spec.program);
    cmd.args(&spec.leading_args).arg(&path);
    // detached：父进程随即 exit(0)，脚本必须活下去。
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // setsid：脱离本进程会话，父退出不带走脚本。
        // SAFETY: pre_exec 闭包不捕获借用、不分配也不持 Rust 锁；`setsid` 是单次 libc syscall，满足
        // fork 后到 exec 前只能做 async-signal-safe 操作的约束。失败按既有 best-effort 语义继续 exec。
        unsafe {
            cmd.pre_exec(|| {
                let _ = nix::unistd::setsid();
                Ok(())
            });
        }
    }
    cmd.spawn()
        .map_err(|e| format!("启动安装脚本失败 {}: {e}", spec.program))?;
    Ok(path)
}

#[cfg(test)]
mod tests;
