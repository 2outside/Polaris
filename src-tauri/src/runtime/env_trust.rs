//! 路径型环境逃生门的**信任级**判定单点。
//!
//! # 根因（为什么需要这一层）
//!
//! `POLARIS_SINGBOX_PATH` / `POLARIS_HELPER_PATH` 这类「用环境变量指一个可执行文件」的逃生门，
//! 问题不在「有一个环境变量」，而在：**同一段路径解析逻辑同时服务两种信任级**——
//! 开发机上它回答「我这次想跑哪个核」，用户机上它回答「这台机器上唯一可信的那个核在哪」。
//! 前者必须让人插队，后者必须谁都不能插队。两者共用一条判据、且环境变量还排在优先级链首时，
//! **开发便利就以「发行包里的第一优先级」的形态出厂**：任何能给本进程设环境变量的上下文
//! （被劫持的启动器 / `.desktop` 文件 / 登录脚本 / 父进程）都能改写 app 的代码执行链，
//! 而 app 全程认为一切正常。
//!
//! 清单与守门在 `src-tauri/tests/release_escape_hatches.rs`（本模块是那张清单里 `VALIDATED`
//! 一类的实现腿）。
//!
//! # 判据（唯一一条：canonical containment）
//!
//! release 构型下，逃生门给出的路径 canonicalize 之后必须落在**可信来源根**之内
//! （见 [`TrustScope`](crate::runtime::env_trust::TrustScope)）。
//!
//! **刻意没有第二条判据**：仓内不存在「随包二进制的运行期指纹」可供比对 ——
//! `core-manifest.json` 的 `coreArchiveSha256` 是**下载压缩包本体**的摘要（`scripts/fetch-core.mjs`
//! 只在拉取期消费它），不是解压后二进制的摘要；`staged_core_sha_path` 只覆盖更新流程 staged
//! 下来的核，覆盖不到随包核。所以「校验二进制哈希」这条判据按字面**不可实现**，别再往这里加，
//! 也别用别的东西冒充它。
//!
//! # 构型分流
//!
//! | 构型 | 行为 |
//! |---|---|
//! | debug / test | 逃生门**原样**是第一优先级：命中即用；指向不存在的文件即 `Err`（不静默回落）。与引入信任级之前逐字一致 |
//! | release | 仍读，但路径必须过 containment；不过 ⇒ 拒绝 + 结构化日志 + 稳定错误码 [`CODE_ENV_PATH_UNTRUSTED`](crate::runtime::env_trust::CODE_ENV_PATH_UNTRUSTED) + 回落调用方的既有优先级 |
//!
//! 分流谓词是 `cfg!(any(debug_assertions, test))`（见 `dev_build`）。两个原子缺一不可：
//! `cargo test --release` 关掉 `debug_assertions` 但被测 crate 的 `test` 仍为真，`cargo run`
//! （dev profile）反过来 —— 少任何一个都会让一整类开发 / 真机验收路径掉进 release 分支。
//!
//! # 这条判据到底买到了什么（安全论证）
//!
//! containment 通过之后，逃生门能指向的位置只剩「app 自有数据目录」与「随包资源目录」，
//! 而能往这两处写文件的人本来就能直接替换 `core_update/sing-box` 或包内资源。也就是说：
//! **环境变量不再是一条独立的能力**，它降级成「在已经有写权限的地方再指一次路」。
//! 这才是本模块的收益，不是「让路径看起来更规范」。

use std::path::{Path, PathBuf};

/// **稳定错误码**：release 构型下逃生门给出的路径不在可信来源内，已被拒绝并回落。
///
/// 形态对齐仓内既有码（`commands/speedtest.rs` 的 `CODE_*`、`commands/taildrop.rs` 的 `ERR_*`）：
/// SCREAMING_SNAKE 常量 + 定值串。它进**日志**而不进 IPC 信封 —— 逃生门被拒不是一次用户动作
/// 的失败（app 照常起核、照常装 helper），而是一条**取证线索**：真机验收时「为什么没用我指的
/// 核」必须能从日志一眼判定，否则这个安全修复就变成一次难查的行为改变。
pub(crate) const CODE_ENV_PATH_UNTRUSTED: &str = "ENV_PATH_UNTRUSTED";

/// 可信来源面。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TrustScope {
    /// **L1（喂代码执行链）**：app 自有数据目录 ∪ 随包资源目录。
    AppDataOrBundle,
    /// **L2（喂提权安装链）**：只认 app 自有数据目录。
    ///
    /// 比 L1 严一档，因为后果不同：L1 拿到的是 app 权限，L2 拿到的是一个开机自启的 root 级
    /// 常驻进程。随包资源目录在 L2 这里也没有存在价值 —— 随包 helper 本就由
    /// `resolve_helper_binary` 的兜底腿解析得到，逃生门再指一次只是多一个入口。
    AppDataOnly,
}

/// 一次逃生门判定的结果。
///
/// 它存在的理由是**可测性**：`cargo test` 下 `cfg!(test)` 恒真，release 分支永远走不到；
/// 若把构型判定焊死在读取函数里，那条腿就成了「没有任何测试能覆盖」的代码 —— 而它恰恰是本
/// 模块唯一带安全语义的一条。[`classify`] 把「构型」与「可信根」都收成入参，release 语义于是
/// 能在测试构型下被逐条钉住。
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EnvPathVerdict {
    /// 环境变量未设 → 调用方按既有优先级继续。
    Unset,
    /// 采纳。dev 原样返回；release 返回 **canonical** 路径 —— 被验证的是 canonical 那一个，
    /// 返回原始串等于「验了 A、用了 B」。
    Accepted(PathBuf),
    /// release 侧判据不通过 → 拒绝并回落。`code` 是稳定错误码，`detail` 进日志。
    Rejected { code: &'static str, detail: String },
}

/// 「开发 / 测试构型」判据（见模块文档「构型分流」）。
const fn dev_build() -> bool {
    cfg!(any(debug_assertions, test))
}

/// 读取并按信任级采纳一个「路径型」环境逃生门。
///
/// - `Ok(None)` = 未设，或 release 侧被拒（**已记日志**）→ 调用方回落既有优先级；
/// - `Ok(Some(p))` = 采纳；
/// - `Err(msg)` = **开发态**逃生门指向不存在的文件（既有语义：不静默回落）。
///
/// # `var` 与 `raw` 为什么分开传
///
/// `raw` 必须由调用方以 `std::env::var("字面量").ok()` 取。`release_escape_hatches` 门的探测器①
/// 靠「`env::var(` + **字面量**实参」这个形态清点发行包里的逃生门；把名字提成常量或只在本函数
/// 里读，会让那个探测器读不出名字（只剩探测器②的名字面兜底）—— 那是在给自己的门拆牙。
/// 于是名字在调用点出现两次：一次给探测器，一次给日志。
pub(crate) fn adopt_trusted_env_path(
    var: &str,
    raw: Option<String>,
    scope: TrustScope,
) -> Result<Option<PathBuf>, String> {
    let roots = trusted_roots(scope);
    match classify(var, raw.as_deref(), dev_build(), &roots)? {
        EnvPathVerdict::Unset => Ok(None),
        EnvPathVerdict::Accepted(path) => Ok(Some(path)),
        EnvPathVerdict::Rejected { code, detail } => {
            // 结构化日志：`[标签] 码 详情`（标签形态对齐 `runtime/mesh.rs` 的 `[WarpService]` 等）。
            // **绝不静默回落** —— 静默回落会把一个安全修复变成一次无从排查的行为改变。
            log::warn!("[逃生门信任级] {code} {detail}");
            Ok(None)
        }
    }
}

/// [`adopt_trusted_env_path`] 的**纯**判定：不读环境、不写日志、不碰全局态。
pub(crate) fn classify(
    var: &str,
    raw: Option<&str>,
    dev_build: bool,
    roots: &[PathBuf],
) -> Result<EnvPathVerdict, String> {
    let Some(raw) = raw else {
        return Ok(EnvPathVerdict::Unset);
    };
    let path = PathBuf::from(raw);

    if dev_build {
        // 开发 / 测试构型：与引入信任级之前逐字一致（原样第一优先级；指向不存在即硬失败）。
        return if path.is_file() {
            Ok(EnvPathVerdict::Accepted(path))
        } else {
            Err(format!("{var} 指向的文件不存在：{}", path.display()))
        };
    }

    match contained_in_trusted_roots(&path, roots) {
        Some(canonical) => Ok(EnvPathVerdict::Accepted(canonical)),
        None => Ok(EnvPathVerdict::Rejected {
            code: CODE_ENV_PATH_UNTRUSTED,
            detail: format!(
                "{var} 指向的路径不在可信来源内，已拒绝并回落既有优先级：path={} roots=[{}]",
                path.display(),
                roots
                    .iter()
                    .map(|root| root.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" | ")
            ),
        }),
    }
}

/// **containment 判据本体**：`path` canonicalize 后必须落在某个 canonical 根之内。
///
/// 通过时返回 **canonical 路径**。
///
/// 三条性质，删掉任一条都会放行一整类逃逸：
///
/// 1. **两侧都 `canonicalize`**。目标侧消解 `..` 与 symlink / junction / reparse point；
///    根侧同样消解 —— 根自己被换成 symlink 时，只 canonicalize 目标会把「根外」判成「根内」。
///    canonicalize 失败（路径不存在 / 断链 symlink / 无权限）⇒ **判据不成立 ⇒ 拒绝**：
///    先验检查失败时宁可什么都不做，与 `runtime/mesh.rs::tailscale_logout` 同一失败方向。
/// 2. **按路径组件比，不是字面串前缀**（`Path::starts_with`）。字面前缀会把
///    `/opt/polaris-evil/sing-box` 判成落在 `/opt/polaris` 之内。
/// 3. 目标必须是**文件**：目录 / 设备节点不是内核或 helper 二进制，且旧腿的 `is_file()` 语义
///    要保住 —— 否则「逃生门指向一个目录」会从 `Err` 悄悄变成 `Ok`。
fn contained_in_trusted_roots(path: &Path, roots: &[PathBuf]) -> Option<PathBuf> {
    let target = path.canonicalize().ok()?;
    if !target.is_file() {
        return None;
    }
    roots
        .iter()
        .filter_map(|root| root.canonicalize().ok())
        .any(|root| target.starts_with(root))
        .then_some(target)
}

/// 本进程的可信来源根（顺序无关，判据是「落在其中任一个之内」）。
fn trusted_roots(scope: TrustScope) -> Vec<PathBuf> {
    // app 自有数据目录 = `core_paths` 的基目录（`main.rs` 启动期注入的 `<app_config_dir>/polaris`，
    // 注入点排在 `AppRuntime::new` 之前）。未注入（单测 / 子进程 / 异常启动路径）⇒ 这一根缺席，
    // containment 只会更严、不会更松。
    let mut roots: Vec<PathBuf> = crate::runtime::core_paths::base_dir()
        .map(Path::to_path_buf)
        .into_iter()
        .collect();
    if scope == TrustScope::AppDataOrBundle {
        // 随包资源根与候选文件表**共用同一份布局真值**（`bundle_resource_candidates` 也走它），
        // 免得一边认 `_up_/resources`、另一边漏掉它之后两处慢慢漂开。
        let exe = std::env::current_exe().ok();
        roots.extend(crate::runtime::proxy::bundle_resource_roots(
            exe.as_deref().and_then(Path::parent),
            crate::runtime::proxy::dev_manifest_dir(),
        ));
    }
    roots
}

#[cfg(test)]
mod tests;
