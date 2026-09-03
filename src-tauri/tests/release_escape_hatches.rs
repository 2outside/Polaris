//! 门 3：release 逃生门清单 —— 发行包里读得到的 `POLARIS_*` 环境变量必须逐条登记。
//!
//! # 守的是什么（根因）
//!
//! 根因不是「有一个环境变量」。根因是：**同一段路径解析逻辑同时服务「开发者」与「发行包」
//! 两种信任级，却只有一套判据**。
//!
//! `resolve_core_binary` 要回答的问题，在开发机上是「我这次想跑哪个核」，在用户机上是
//! 「这台机器上唯一可信的那个核在哪」。两个问题的正确答案不同 —— 前者必须让人插队，后者
//! 必须谁都不能插队。但今天它们共用一个函数、一条优先级链，而链首就是环境变量。于是
//! **开发便利以「发行包里的第一优先级」的形态出厂**：随包核、签名、更新流程全部排在它后面。
//!
//! `resolve_helper_source` 是同一形状的第二例，且喂的东西更硬 —— 特权 helper 的**安装源**，
//! 安装链随后以管理员 / root 权限把那个文件装成系统服务。
//!
//! 两处都不是「配置被改」，是**代码执行链被改**：一个只要能给本进程设环境变量的上下文
//! （被劫持的启动器 / 桌面 `.desktop` 文件 / 登录脚本 / 父进程），就能把内核二进制或提权
//! 安装源换成任意可执行文件，而 app 自己全程认为一切正常。
//!
//! # 失效形态（为什么必须是源码级门，且必须是**清单**门）
//!
//! 「这个环境变量在发行包里读得到」**没有任何运行期表征**：不设它时行为完全正常，单测全绿、
//! clippy 全绿、打包全绿。它只在被设的那一刻改变行为，而那一刻不在 CI 里。
//!
//! 更关键的是：这类逃生门是**一条一条长出来的**。每一条单独看都有正当理由（「调试要用」
//! 「真机验证要用」），没有清单时没有任何一刻会有人把它们摆在一起看，于是「发行包里一共有
//! 几个能改代码执行链的入口」这个问题**永远没有答案**。本门的产物就是那个答案，且它由代码
//! 持有而不是由文档持有 —— 文档里的清单在下一次重构时不会自己变红。
//!
//! # 判据
//!
//! 取材面里每一处 `POLARIS_*` 环境变量读取（`env::var` / `env::var_os`，三种写法全覆盖），
//! 必须落进下面四类之一，否则红：
//!
//! 1. **只在测试构型下编译** —— 文件位于 `tests/` 目录下，或读取点处在一个「在**任何** release
//!    构型下都为假」的 `#[cfg(..)]` 罩住的块内（判据见 [`release_reachability`]）；
//! 2. **[`ALLOWED`] 永久白名单** —— release 里读它是设计意图，取到的值**按原样**被采纳；
//!    每条写清它喂给谁、最坏能做什么；
//! 3. **[`VALIDATED`] 校验后采纳** —— release 里读得到，但取到的**路径必须先过可信来源判据**
//!    才被采纳，不过则拒绝 + 记稳定错误码 + 回落既有优先级。每条写清**由哪个函数校验**、
//!    **不通过时怎么办**；
//! 4. **[`PENDING_TRUST_GATE`] 临时清单** —— 已知违规、正在下一批修，每条写清为什么还在这儿、
//!    修完之后要做什么。
//!
//! 四张清单（含 [`TEXT_ONLY`]）都要求**每条恰好命中一次**。命中 0 次说明它守的东西已经没了，
//! 条目本身成了将来某个真违规的免死金牌；命中多次说明一条豁免覆盖了它没打算覆盖的地方。
//! [`PENDING_TRUST_GATE`] 的条目在下一批修完后会因「命中 0 次」自动转红 —— **这是刻意设计**，
//! 它把清理逼出来，而不是让临时清单静静地烂在那里变成永久豁免。
//!
//! # [`VALIDATED`] 为什么必须自带一条源码级断言
//!
//! 「校验后采纳」如果只是一张登记表，那它登记的是一句**承诺**，而承诺不是门：把校验调用从
//! 读取点删掉，表还在、四条清单断言全绿、编译器也不会说话 —— 本仓已经为「门在但没牙」付过账。
//! 因此 [`validated_read_sites_must_call_their_validator`] 断言的是**代码形态**：每个
//! [`VALIDATED`] 条目的读取点**所在函数体内**必须出现它登记的那个校验函数调用。
//! 取材面是本门已有的定位面（[`polaris_source_probe::mask_comments_and_strings`] 剥过注释与
//! 字面量），所以注释里写一句 `adopt_trusted_env_path(...)` 不算数。
//!
//! # 两套取材面（本仓踩过的坑）
//!
//! 本门自己的说明里写满了 `POLARIS_SINGBOX_PATH` 这类串，不剥注释与字面量就全是假阳性；
//! 可**要找的变量名本身就是字符串字面量**，剥了就什么都读不出来。所以取材面是两套，
//! 靠 [`polaris_source_probe::mask_comments_and_strings`] **保留字节偏移**这一性质对齐：
//!
//! - **定位面（masked）**：注释与字面量全剥。用来找 `env::var(` 这个调用形态、匹配 `#[cfg(..)]`
//!   的方括号、算花括号深度。判据必须落在可执行形态上 —— 注释里的 `env::var("POLARIS_X")`
//!   不是一次读取。
//! - **读取面（raw）**：原文。在定位面上拿到偏移后，回原文同一偏移读出实参字面量与 cfg
//!   表达式。`#[cfg(any(test, feature = "test-utils"))]` 里那个 `"test-utils"` 是**字面量**，
//!   在定位面上已被抹成空格 —— 拿定位面去求值会把这个门读成「不带门」而静默放行。
//!   `src-tauri/tests/test_only_symbols_gated.rs` 的首版正是这个 bug。
//!
//! # 两个探测器（间接读取不能靠调用形态抓）
//!
//! `env::var(` 只抓得到实参是**字面量**的直接读取。`const H: &str = "POLARIS_X"; env::var(H)`
//! 会整个逃出去。所以还有第二个、与调用形态无关的探测器：
//! [`polaris_names_in`] 扫**整份生产文本**（代码 + 注释 + 字面量）里的 `POLARIS_*` 名字，
//! 要求每个名字都被三张清单之一认领（[`production_polaris_names_are_all_accounted_for`]）。
//! 于是间接读取仍然红 —— 那个字面量总得存在于某处。
//!
//! 副作用是：**生产注释里提到某个 `POLARIS_*` 名字也要登记**。这是特性不是噪声 ——
//! 讲逃生门的注释与逃生门清单从此不会各说各话。
//!
//! # 不在射程内（显式声明，不是遗漏）
//!
//! - **`build.rs` / `env!` / `option_env!`**：编译期读取，值在**构建**那一刻烘进二进制，
//!   发行包的运行环境改不了它。`option_env!("POLARIS_BUILD_ID")` 与
//!   `env!("POLARIS_PRODUCT_NAME")`（由 `src-tauri/build.rs` 的 `cargo:rustc-env` 注入）属此类，
//!   登记在 [`TEXT_ONLY`]。任何一条哪天被改写成 `std::env::var(..)`，本门立刻转红 ——
//!   编译期与运行期读同一个名字，是两件性质完全不同的事。
//!   `build.rs` 本身不在取材面（它不在任何成员的 `src/` 或 `tests/` 下，且它跑在构建机上，
//!   不进发行包）。
//! - **实参非字面量的 `env::var*`**（如 `graphics_compat.rs` 的 `set_env_if_absent(key)`）：
//!   名字在调用点看不见，第一个探测器读不出来；由第二个探测器兜住（名字的字面量必然在某处）。
//! - **文件形态的 `tests.rs`**（旧写法，仓内尚存 `crates/net-stack/src/share_link/tests.rs`）：
//!   归属不可判，本门一律按 release 侧处理 —— 宁可多红。要消除请迁成 `<dir>/tests/mod.rs`。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

// ============================================================================
// 三张清单
// ============================================================================

/// 一条按**变量名**登记的条目。
///
/// 按名字聚合、不按行号：行号会随重构漂，清单钉行号等于给每次重构埋一颗雷。
struct Entry {
    /// 变量名全称（`POLARIS_` 开头）。
    name: &'static str,
    /// 为什么它可以是今天这个状态。写清楚是为了让下一个人**判断得了它还该不该在**。
    reason: &'static str,
}

/// [`VALIDATED`] 的条目：比 [`Entry`] 多一个**可执行**的字段。
///
/// `validator` 单独成一个字段而不是写进 `reason` 里，是因为它要被
/// [`validated_read_sites_must_call_their_validator`] 当搜索串用 —— 写在散文里的函数名对门
/// 没有任何强制力，判据必须由代码持有。
struct Validated {
    /// 变量名全称（`POLARIS_` 开头）。
    name: &'static str,
    /// 校验函数的**调用形态**（带左括号，避免撞上同名的 `use` 或文档链接）。
    /// 读取点所在的函数体里必须出现它。
    validator: &'static str,
    /// 喂给谁 / 由哪个函数校验 / 不通过时怎么办。
    reason: &'static str,
}

/// 永久白名单：在 release 里读它是设计意图。
///
/// 每条必须回答两个问题：**它喂给谁**、**最坏能做什么**。回答不了的不许进这张表 ——
/// 「看起来无害」不是论证。
const ALLOWED: &[Entry] = &[
    Entry {
        name: "POLARIS_LOG",
        reason: "喂给谁：`logging.rs` 的 `startup_level` → `resolve_startup_level` → `parse_level`，\
                 终点是一个 `log::LevelFilter`。取值域是**闭集**（trace/debug/info/warn/error/fatal/off），\
                 无法识别的值返回 `None` 并回落到 config/Info —— 它没有任何一条路径能变成路径串、\
                 命令行参数或进程名。最坏能做什么：把日志级别拉到 trace（磁盘写入变多、日志里出现\
                 更详细的运行信息），或设成 `off` 把日志关掉（事后取证少一份材料）。不改任何\
                 二进制选择、不起进程、不参与权限决策。release 里保留它是设计意图：用户报障时\
                 无需换装 debug 构型即可抓全量日志，这正是「排障者的临时超驰」。",
    },
    Entry {
        name: "POLARIS_MOUNT_GATE",
        reason: "喂给谁：`window_health.rs` 的 `WindowHealth::new`，终点是一个 `bool gate_enabled`，\
                 唯一消费者是 `resolve_show_timing`（主窗是否等 `renderer:ready` 再上屏）。\
                 release 构型下语义是「默认开，`=0` 可关」。最坏能做什么：设 `=0` 关掉挂载门 ⇒\
                 主窗不等渲染就绪就显示，白屏/未上色的一帧可能被用户看到。不喂路径、不起进程、\
                 不碰权限。release 里可读是设计意图：这是唯一能在**用户机的发行包**上原地复现\
                 「窗口卡在挂载门」的开关，否则该类问题只能靠重装 debug 构型复现。",
    },
];

/// 「校验后采纳」清单：release 里读得到，但取到的**路径必须先过可信来源判据**才被采纳。
///
/// 每条必须回答三个问题：**它喂给谁**、**由哪个函数校验**、**判据不通过时怎么办**。
/// 回答不了的不许进这张表 —— 「加了个检查」不是论证。
///
/// `validator` 不是文档而是**判据**：[`validated_read_sites_must_call_their_validator`] 会去
/// 读取点所在的函数体里找这个串，找不到当场红。这一条是本类别与「一句承诺」的全部差别。
const VALIDATED: &[Validated] = &[
    Validated {
        name: "POLARIS_SINGBOX_PATH",
        validator: "adopt_trusted_env_path(",
        reason: "【L1 喂代码执行链】喂给谁：`runtime/proxy/core_binary.rs::core_binary_env_override` —— 它是\
                 `resolve_core_binary`（内核二进制解析链第 1 级）与 `UpdaterRuntime::new`\
                 （版本双读法的探测目标）的**唯一**共用实现；解析出来的路径会被 spawn 成活核，\
                 并经 `HelperRuntime::install_params` 作为 `bundled_core` / `--singbox` 播进\
                 root 受管核目录。最坏能做什么（若无判据）：把 app 拉起的 sing-box 换成任意可\
                 执行文件，以 app 身份 + 代理配置运行。\
                 由哪个函数校验：`runtime/env_trust::adopt_trusted_env_path`，\
                 `TrustScope::AppDataOrBundle`（canonicalize 后须落在 app 自有数据目录或随包\
                 资源目录之内；目录穿越 / symlink / junction 逃逸、路径不存在、canonicalize\
                 失败一律不过）。\
                 不通过时怎么办：**不采纳**，记 `ENV_PATH_UNTRUSTED`（`log::warn`，带 path 与\
                 roots）并回落既有优先级（可写现役核 → 随包种子）—— 绝不静默，也绝不因为逃生门\
                 越界就让 app 起不来。\
                 debug / test 构型不受本判据影响（`cfg!(any(debug_assertions, test))`）：逃生门\
                 仍是原样的第一优先级，本地开发与全部 `#[ignore]` 真机验证逐字不变。",
    },
    Validated {
        name: "POLARIS_HELPER_PATH",
        validator: "adopt_trusted_env_path(",
        reason: "【L2 喂提权安装链】喂给谁：`runtime/helper.rs::resolve_helper_binary` → \
                 `install_params.src_binary` → 提权安装链，该文件随后被以管理员 / root 权限装成\
                 系统服务（systemd unit / launchd plist / Windows 服务）。最坏能做什么（若无\
                 判据）：把任意二进制喂进提权安装链，得到一个开机自启的 root 级常驻进程 —— \
                 比 L1 更硬（L1 拿 app 权限，L2 拿系统权限）。\
                 由哪个函数校验：同一个 `adopt_trusted_env_path`，但 scope 是\
                 `TrustScope::AppDataOnly` —— 比 L1 严一档，**随包资源目录也不接受**。\
                 随包 helper 本就由兜底腿解析得到，逃生门再指一次只多一个入口、不多一分能力。\
                 不通过时怎么办：不采纳，记 `ENV_PATH_UNTRUSTED` 并回落随包 helper 兜底腿；\
                 兜底腿也找不到就是既有的「二进制缺失」早返（**不触发提权**）。\
                 debug / test 构型同样不受影响：helper 的本地迭代仍靠它装自编产物。",
    },
];

/// 临时清单：**已知违规**，下一批修。
///
/// 每条必须写清「为什么现在还在这儿」与「修完之后要做什么」。
///
/// **本表的条目在被修完后会因「命中 0 次」自动转红**（见
/// [`registry_entries_must_all_match_exactly_once`]）——这是刻意设计：临时清单必须有一个
/// 自己会响的闹钟，否则它和永久白名单没有区别，三个月后没人记得它当初是临时的。
///
/// # 当前为空 —— 以及上一版本条目里那句**错的**「修完就删掉」
///
/// L1 `POLARIS_SINGBOX_PATH` 与 L2 `POLARIS_HELPER_PATH` 曾登记在这里，条目末尾写着
/// 「修完之后 release 侧不再读它 ⇒ 命中 0 次 ⇒ 删掉本条」。**那个前提是错的**：信任级修复
/// 并没有让 release 侧停止读这两个变量，只是给读到的路径加了一道可信来源判据。它们因此
/// 移进了 [`VALIDATED`]（release 可读 + 必须过校验），而不是消失。
///
/// 这条经验值得留在这里：给一个逃生门「修复」不等于「删除」。判断一条 PENDING 该往哪去，
/// 要看修完之后 **release 侧还读不读它**，而不是看有没有人动过那段代码。
const PENDING_TRUST_GATE: &[Entry] = &[];

/// 只以**文本**形态出现在生产代码里的 `POLARIS_*` 名字：它们不是运行期读取点。
///
/// 存在的理由：第二个探测器（[`polaris_names_in`]）故意扫整份生产文本，好把
/// 「常量间接读取」这条路堵死；代价是它也会扫到 shell heredoc 定界符、编译期常量名这类
/// **同形但非读取**的串。每条同样要求恰好命中一次 —— 那个串一旦消失，条目必须跟着走。
const TEXT_ONLY: &[Entry] = &[
    Entry {
        name: "POLARIS_BUILD_ID",
        reason: "`crates/helper-proto/src/lib.rs` 的 `option_env!(\"POLARIS_BUILD_ID\")` —— \
                 **编译期**读取：发布流水线把同一份 `github.sha` 注入 helper 与 app 的构建环境，\
                 值在构建那一刻烘成常量。发行包的运行环境改不了它，故不是逃生门。\
                 若它被改写成 `std::env::var(\"POLARIS_BUILD_ID\")`，第一个探测器会立刻把它\
                 认成 release 侧读取点并转红。",
    },
    Entry {
        name: "POLARIS_PRODUCT_NAME",
        reason: "`src-tauri/src/runtime/proxy.rs` 的 \
                 `const LINUX_BUNDLE_PRODUCT_DIR: &str = env!(\"POLARIS_PRODUCT_NAME\")` —— \
                 **编译期**读取：值由 `src-tauri/build.rs` 从 `tauri.conf.json` 的 `productName` \
                 经 `cargo:rustc-env` 注入，`env!` 在编译期展开成一个 `&'static str`。\
                 发行包的运行环境改不了它，故不是逃生门。\
                 注意 `env!` 与 `std::env::var` 只差一个宏叹号却是两种信任级：前者的值由构建机\
                 决定，后者的值由用户机的进程环境决定。改成后者即转红。",
    },
    Entry {
        name: "POLARIS_UNIT_EOF",
        reason: "`crates/helper-client/src/manager.rs` 里 systemd unit 安装脚本的 shell heredoc \
                 定界符（`cat > … <<'POLARIS_UNIT_EOF'`）。是被生成的 shell 脚本的语法成分，\
                 与进程环境无关。",
    },
    Entry {
        name: "POLARIS_PLIST_EOF",
        reason: "同上，launchd plist 安装脚本的 heredoc 定界符。",
    },
];

// ============================================================================
// 取材面
// ============================================================================

/// 一份被扫描的源文件。
struct SourceFile {
    /// 仓库相对路径（`/` 分隔）。失败信息全靠它定位。
    rel: String,
    path: PathBuf,
    /// 路径里含 `tests/` 目录段 ⇒ 整份文件是测试面（本仓约定：`<dir>/tests/` 恒为测试）。
    in_tests_dir: bool,
    /// **整份文件在 release 构型下都不编译**：
    ///
    /// - 它属于一个 dev-only crate（每一处反向依赖都写在 `[dev-dependencies]` 下），或
    /// - 承载它的那条 `mod <名>;` 声明带了一个 release 侧恒假的 `#[cfg(..)]`
    ///   （如 `main.rs` 的 `#[cfg(test)] mod test_support;`）。
    ///
    /// 判据必须是**跨文件**的：文件自身可能一个 `#[cfg]` 都没有，门却在它的父模块里。
    /// 只看文件内属性会把整类 dev-only 文件误判成「会出厂」—— 方向是 fail-closed（多红），
    /// 但对「开发树锚点」这类判据就变成一片假红。
    release_off_file: bool,
}

fn workspace_root() -> PathBuf {
    polaris_source_probe::workspace_root_from(env!("CARGO_MANIFEST_DIR"))
}

/// 从 workspace 根 `Cargo.toml` 的 `members` 推导成员目录（含 `crates/*` 通配展开）。
///
/// 不手写 crate 清单：新加一个 crate 就该自动进取材面，否则「新 crate 里的新逃生门」
/// 是本门的**永久盲区** —— 而逃生门恰恰最容易长在新代码里。
fn workspace_members(root: &Path) -> Vec<PathBuf> {
    let manifest =
        std::fs::read_to_string(root.join("Cargo.toml")).expect("读不到 workspace 根 Cargo.toml");
    let masked = mask_toml_comments(&manifest);
    let start = masked
        .find("members")
        .expect("workspace 根 Cargo.toml 没有 members");
    let open = masked[start..].find('[').expect("members 后面没有 `[`") + start;
    let close = masked[open..].find(']').expect("members 列表没有闭合 `]`") + open;

    let mut members = Vec::new();
    for raw in manifest[open + 1..close].split(',') {
        let entry = raw.trim().trim_matches('"').trim();
        if entry.is_empty() {
            continue;
        }
        if let Some(prefix) = entry.strip_suffix("/*") {
            let dir = root.join(prefix);
            let entries = std::fs::read_dir(&dir).unwrap_or_else(|err| {
                panic!("读不到 members 通配目录 `{}`（{err}）", dir.display())
            });
            for child in entries.flatten() {
                let path = child.path();
                if path.join("Cargo.toml").is_file() {
                    members.push(path);
                }
            }
        } else {
            members.push(root.join(entry));
        }
    }
    members.sort();
    assert!(
        !members.is_empty(),
        "members 解析出来是空的 —— 取材面为空，本门的否定型断言会恒真"
    );
    members
}

/// TOML 行注释抹成空格（保留长度与换行），避免注释里的 `members` 把定位带偏。
fn mask_toml_comments(source: &str) -> String {
    source
        .lines()
        .map(|line| match line.find('#') {
            Some(at) => format!("{}{}", &line[..at], " ".repeat(line.len() - at)),
            None => line.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn collect_rs(root: &Path, dir: &Path, out: &mut Vec<SourceFile>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs(root, &path, out);
            continue;
        }
        if !path.extension().is_some_and(|ext| ext == "rs") {
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .expect("文件不在仓库根内")
            .to_string_lossy()
            .replace('\\', "/");
        let in_tests_dir = rel.contains("/tests/");
        out.push(SourceFile {
            rel,
            path,
            in_tests_dir,
            release_off_file: false,
        });
    }
}

/// 取材面：全部 workspace 成员的 `src/` 与 `tests/` 下的 `.rs`。
///
/// `tests/` 必须进面 —— 它是「类别 1（只在测试构型下编译）」的一半判据来源；只扫 `src/` 的话
/// 那一支永远拿不到样本，[`scan_surface_self_check`] 里的分流活性对照就成了空话。
fn scan_surface() -> Vec<SourceFile> {
    let root = workspace_root();
    let mut files = Vec::new();
    for member in workspace_members(&root) {
        for sub in ["src", "tests"] {
            let dir = member.join(sub);
            if dir.is_dir() {
                collect_rs(&root, &dir, &mut files);
            }
        }
    }
    files.sort_by(|a, b| a.rel.cmp(&b.rel));
    assert!(!files.is_empty(), "取材面是空的 —— 本门会恒真");
    mark_release_off_files(&root, &mut files);
    files
}

/// 标记 [`SourceFile::release_off_file`]：dev-only crate 的全部文件 + 被 release 侧恒假的
/// `mod <名>;` 声明承载的文件（含向下传播）。
fn mark_release_off_files(root: &Path, files: &mut [SourceFile]) {
    let dev_only = dev_only_crate_dirs(root);
    let known: BTreeSet<String> = files.iter().map(|f| f.rel.clone()).collect();

    // `mod <名>;` 声明 → 它承载的两种文件路径。
    let mut off: BTreeSet<String> = BTreeSet::new();
    let mut edges: Vec<(String, String, bool)> = Vec::new(); // (子, 父, 该声明是否 release 侧恒假)
    for file in files.iter() {
        let Ok(raw) = std::fs::read_to_string(&file.path) else {
            continue;
        };
        let masked = polaris_source_probe::mask_comments_and_strings(&raw);
        let off_regions = release_off_regions(&masked, &raw);
        for (at, name) in mod_declarations(&masked) {
            // 声明形态没有块体 ⇒ [`release_off_regions`]（按 `{}` 取区间）对它恒空。
            // 门挂在**紧邻的属性**上，必须直接读属性，不能指望区间。
            let gated = preceding_cfg_is_release_off(&masked, &raw, at)
                || off_regions.iter().any(|(a, b)| *a <= at && at <= *b);
            for child in child_module_paths(&file.rel, &name) {
                if known.contains(&child) {
                    edges.push((child, file.rel.clone(), gated));
                }
            }
        }
    }
    // 传播：父不出厂 ⇒ 子也不出厂。深度以模块层数为界，16 轮足够且不会打转。
    for _ in 0..16 {
        let before = off.len();
        for (child, parent, gated) in &edges {
            if *gated || off.contains(parent) {
                off.insert(child.clone());
            }
        }
        if off.len() == before {
            break;
        }
    }
    for file in files.iter_mut() {
        file.release_off_file =
            off.contains(&file.rel) || dev_only.iter().any(|d| file.rel.starts_with(d));
    }
}

/// `at` 处的 item 是否被一个 **release 侧恒假**的紧邻 `#[cfg(..)]` 属性罩住。
///
/// 从 `at` 往回跳过空白与 doc 注释（净化面里注释已是空白），逐个吃掉紧邻的 `#[..]` 属性块；
/// 任一属性是 `cfg` 且 [`release_reachability`] 判 [`Tri::False`] 即返回 true。
/// 属性内层文本取**原文**：`feature = "test-utils"` 的判据在字符串字面量里，取净化面会读成空。
fn preceding_cfg_is_release_off(masked: &str, raw: &str, at: usize) -> bool {
    let bytes = masked.as_bytes();
    let mut i = at;
    loop {
        while i > 0 && bytes[i - 1].is_ascii_whitespace() {
            i -= 1;
        }
        if i == 0 || bytes[i - 1] != b']' {
            return false;
        }
        // 从 `]` 往回配对到对应的 `[`
        let mut depth = 0i32;
        let mut j = i - 1;
        loop {
            match bytes[j] {
                b']' => depth += 1,
                b'[' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            if j == 0 {
                return false;
            }
            j -= 1;
        }
        // `#` 必须紧贴 `[`
        if j == 0 || bytes[j - 1] != b'#' {
            return false;
        }
        let inner = &masked[j + 1..i - 1];
        let trimmed = inner.trim_start();
        if let Some(rest) = trimmed.strip_prefix("cfg") {
            let rest = rest.trim_start();
            if rest.starts_with('(') && rest.ends_with(')') {
                // 原文求值（字符串字面量是判据本身）。偏移一致，直接切原文同一区间。
                let start = j + 1 + (inner.len() - trimmed.len()) + 3;
                let expr_open = masked[start..i - 1].find('(').map(|o| start + o);
                if let Some(open) = expr_open {
                    let expr = &raw[open + 1..i - 2];
                    if release_reachability(expr) == Tri::False {
                        return true;
                    }
                }
            }
        }
        i = j - 1;
    }
}

/// 净化面里全部 `mod <名>;`（声明形态，不含 `mod <名> {`）：`(字节偏移, 模块名)`。
fn mod_declarations(masked: &str) -> Vec<(usize, String)> {
    let bytes = masked.as_bytes();
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(off) = masked[from..].find("mod ") {
        let at = from + off;
        from = at + 4;
        // 必须是词首（`mod` 前一个字节不是标识符字符），排除 `submod ` 之类。
        if at > 0 && (bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_') {
            continue;
        }
        let rest = &masked[at + 4..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        let after = rest[name.len()..].trim_start();
        if after.starts_with(';') {
            out.push((at, name));
        }
    }
    out
}

/// `mod <名>;` 在 `parent`（仓库相对路径）里承载的两种文件路径。
///
/// `lib.rs` / `main.rs` / `mod.rs` 代表**它所在的目录**，子模块是同级兄弟；其余 `foo.rs`
/// 的子模块在 `foo/` 下。写错这一条会让整棵子树的门丢掉。
fn child_module_paths(parent: &str, name: &str) -> Vec<String> {
    let (dir, stem) = match parent.rsplit_once('/') {
        Some((d, f)) => (d.to_string(), f.trim_end_matches(".rs").to_string()),
        None => (String::new(), parent.trim_end_matches(".rs").to_string()),
    };
    let base = if matches!(stem.as_str(), "lib" | "main" | "mod") {
        dir
    } else if dir.is_empty() {
        stem
    } else {
        format!("{dir}/{stem}")
    };
    vec![format!("{base}/{name}.rs"), format!("{base}/{name}/mod.rs")]
}

/// **dev-only crate** 的目录前缀（仓库相对，带尾斜杠）：本仓每一处引用它的地方都写在
/// `[dev-dependencies]` 下 ⇒ 它整份不进任何 lib/bin 依赖图，也就不可能进发行产物。
///
/// 这不是白名单，是**从清单推导的事实**：哪天有人把它加进某个 crate 的 `[dependencies]`，
/// 它当场不再是 dev-only，本函数返回值随之变化，依赖它的判据自动收紧。
fn dev_only_crate_dirs(root: &Path) -> Vec<String> {
    let members = workspace_members(root);
    let mut out = Vec::new();
    for member in &members {
        let Some(dir_name) = member.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Ok(manifest) = std::fs::read_to_string(member.join("Cargo.toml")) else {
            continue;
        };
        let Some(pkg) = toml_package_name(&manifest) else {
            continue;
        };
        let mut referenced = false;
        let mut only_dev = true;
        for other in &members {
            // 跳过自己：`[package] name = "…"` 里当然出现自己的名字，算进来会让每个 crate 都
            // 被判成「有一处非 dev 引用」，本函数直接恒返回空表（第一版正是这么错的）。
            if other == member {
                continue;
            }
            let Ok(raw) = std::fs::read_to_string(other.join("Cargo.toml")) else {
                continue;
            };
            for (section, body) in toml_sections(&raw) {
                if !body.contains(&pkg) {
                    continue;
                }
                referenced = true;
                if !section.contains("dev-dependencies") {
                    only_dev = false;
                }
            }
        }
        if referenced && only_dev {
            let rel = member
                .strip_prefix(root)
                .unwrap_or(member)
                .to_string_lossy()
                .replace('\\', "/");
            out.push(format!("{rel}/"));
            let _ = dir_name;
        }
    }
    out
}

fn toml_package_name(manifest: &str) -> Option<String> {
    for (section, body) in toml_sections(manifest) {
        if section != "package" {
            continue;
        }
        for line in body.lines() {
            if let Some(rest) = line.trim().strip_prefix("name") {
                let rest = rest.trim_start().strip_prefix('=')?.trim();
                return Some(rest.trim_matches('"').to_string());
            }
        }
    }
    None
}

/// TOML 顶层分段：`(段名, 段体)`。注释已剥（复用本门的 [`mask_toml_comments`]）。
fn toml_sections(raw: &str) -> Vec<(String, String)> {
    let masked = mask_toml_comments(raw);
    let mut out: Vec<(String, String)> = Vec::new();
    let mut current: Option<(String, String)> = None;
    for line in masked.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if let Some(done) = current.take() {
                out.push(done);
            }
            current = Some((trimmed.trim_matches(['[', ']']).to_string(), String::new()));
            continue;
        }
        if let Some((_, body)) = current.as_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    if let Some(done) = current.take() {
        out.push(done);
    }
    out
}

// ============================================================================
// cfg 求值：三值逻辑
// ============================================================================

/// 一个 cfg 表达式在 **release 构型集合**上的可满足性。
///
/// 为什么是三值而不是二值：本门要判定的是「这段代码**会不会**进发行包」，而 release
/// 不是单一构型 —— 它是一族（linux / macos / windows / 各 target_os / 各 feature 组合）。
/// `#[cfg(not(any(windows, test)))]` 在 Windows 上为假、在 Linux 上为真：二值求值器把
/// `windows` 当成恒真会算出「整体为假」，于是这段代码被判成「不进发行包」而**静默放行** ——
/// 那正是本门最危险的失效方向。
///
/// 三值下：只有 [`Tri::False`]（在**任何** release 构型下都为假）才算「被门罩住」，
/// [`Tri::Unknown`] 一律按「可能出厂」处理。宁可多红。
///
/// > 与 `test_only_symbols_gated.rs` 的二值 `eval_cfg` 差异是**有意的**：那道门问的是
/// > 「这个符号有没有被任何 cfg 挡过一次」（宽一点只是多罩住几个测试替身），本门问的是
/// > 「这段代码会不会出厂」（宽一点就是漏掉一个逃生门）。同一形状的问题，安全方向相反。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tri {
    True,
    False,
    Unknown,
}

/// 求 `expr` 在 release 构型集合上的可满足性。
///
/// 三个原子在 release 下**恒假**：
///
/// - `test`；
/// - `feature = "test-utils"`（按 `test_only_symbols_gated.rs` 的对账，只从 dev-dependencies 开启）；
/// - `debug_assertions` —— **这条是有前提的**，前提由
///   [`release_profiles_must_not_enable_debug_assertions`] 亲自守着：任何 release 形态的
///   `[profile.*]` 段、以及 `.cargo/config.toml` / CI workflow 里的 `RUSTFLAGS`，都不许把它打开。
///   那条门红了，本函数这一格就不再成立 —— 两者必须一起读。
///
/// 其余原子（`unix` / `windows` / `target_os = ".."` / 其它 feature）一律 [`Tri::Unknown`]
/// —— 它们在某个 release 构型下可能为真。
fn release_reachability(expr: &str) -> Tri {
    let e = expr.trim();
    for kw in ["all", "any", "not"] {
        if let Some(rest) = e.strip_prefix(kw) {
            let rest = rest.trim_start();
            if rest.starts_with('(') && rest.ends_with(')') {
                let inner = &rest[1..rest.len() - 1];
                let parts: Vec<Tri> = split_top_level(inner)
                    .iter()
                    .map(|p| release_reachability(p))
                    .collect();
                return match kw {
                    "all" => {
                        if parts.contains(&Tri::False) {
                            Tri::False
                        } else if parts.iter().all(|v| *v == Tri::True) {
                            Tri::True
                        } else {
                            Tri::Unknown
                        }
                    }
                    "any" => {
                        if parts.contains(&Tri::True) {
                            Tri::True
                        } else if parts.iter().all(|v| *v == Tri::False) {
                            Tri::False
                        } else {
                            Tri::Unknown
                        }
                    }
                    _ => match parts.first().copied().unwrap_or(Tri::Unknown) {
                        Tri::True => Tri::False,
                        Tri::False => Tri::True,
                        Tri::Unknown => Tri::Unknown,
                    },
                };
            }
        }
    }
    let flat: String = e.chars().filter(|ch| !ch.is_whitespace()).collect();
    if flat == "test" || flat == "feature=\"test-utils\"" || flat == "debug_assertions" {
        Tri::False
    } else {
        Tri::Unknown
    }
}

/// 按顶层逗号切分 cfg 参数列表。
fn split_top_level(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for ch in s.chars() {
        match ch {
            '(' => {
                depth += 1;
                cur.push(ch);
            }
            ')' => {
                depth -= 1;
                cur.push(ch);
            }
            ',' if depth == 0 => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// `masked` / `raw` 里全部「在任何 release 构型下都不会编译」的花括号块的字节区间。
///
/// 定位（找 `#[cfg(`、匹配 `]`、匹配 `{}`）走 **masked**：注释里被注释掉的 `#[cfg(test)]`
/// 不是门，字符串里的 `]` 也不该干扰括号匹配。求值走 **raw** 的同一段偏移：cfg 谓词里的
/// `"test-utils"` 是字面量，在 masked 上已被抹空。
fn release_off_regions(masked: &str, raw: &str) -> Vec<(usize, usize)> {
    let mb = masked.as_bytes();
    let mut regions = Vec::new();
    let mut from = 0usize;
    while let Some(offset) = masked[from..].find("#[cfg(") {
        let start = from + offset;
        from = start + "#[cfg(".len();

        // 属性的方括号闭合位置（在 masked 上匹配）。
        let Some(i) = match_delim(mb, start + 1, b'[', b']') else {
            break;
        };

        // 从 raw 的同一段偏移取谓词原文（含字面量）。
        let Some(attr_raw) = raw.get(start..=i) else {
            continue;
        };
        let Some(paren) = attr_raw.find('(') else {
            continue;
        };
        let Some(close) = attr_raw.rfind(')') else {
            continue;
        };
        if close <= paren {
            continue;
        }
        if release_reachability(&attr_raw[paren + 1..close]) != Tri::False {
            continue;
        }

        // 属性罩住的块：跳过夹在中间的其它属性，取第一个 `{`；若 `;` 先到则是声明形态
        // （`#[cfg(test)] mod tests;`），它指向的文件由路径规则覆盖，这里没有块可罩。
        let brace = masked[i..].find('{').map(|off| i + off);
        let semi = masked[i..].find(';').map(|off| i + off);
        let Some(open) = brace else { continue };
        if semi.is_some_and(|s| s < open) {
            continue;
        }
        // 不闭合（文件被截断 / 定位面被破坏）⇒ 罩到文件末尾：宁可多罩几行也不放行一段
        // 判不出归属的代码 —— 本门的安全方向是「宁可多红」。
        regions.push((start, match_delim(mb, open, b'{', b'}').unwrap_or(mb.len())));
    }
    regions
}

/// `bytes[from]` 处的开定界符所匹配的闭定界符下标（含嵌套计数）；不闭合或起点不是开定界符
/// 时返回 `None`。
///
/// **只此一份**：`#[cfg(..)]` 的方括号匹配、cfg 罩住的块的花括号匹配、[`enclosing_fn_body`]
/// 的函数体匹配是同一件事，各写一份就是给三处各自漂移的机会。
///
/// 调用方必须传**定位面**（注释与字面量已剥）——字符串里的 `}` 会把深度算歪。
fn match_delim(bytes: &[u8], from: usize, open: u8, close: u8) -> Option<usize> {
    if bytes.get(from) != Some(&open) {
        return None;
    }
    let mut depth = 0usize;
    for (offset, byte) in bytes.iter().enumerate().skip(from) {
        if *byte == open {
            depth += 1;
        } else if *byte == close {
            depth -= 1;
            if depth == 0 {
                return Some(offset);
            }
        }
    }
    None
}

/// `masked` 里包含字节 `at` 的**最内层**函数体（含首尾花括号）；不在任何函数体内 → `None`。
///
/// 这是 [`validated_read_sites_must_call_their_validator`] 的取材面。三条性质各自堵一类失效：
///
/// - **走定位面**：注释里的 `fn foo() {` 不是一个函数，字符串里的 `}` 不闭合任何块；
/// - **最内层**：嵌套函数 / `impl` 方法里的读取点只看自己那一层。取外层会把「校验调用在不在
///   同一个函数里」稀释成「在不在同一个文件里」—— 那样断言就没牙了（正向对照见
///   [`enclosing_fn_body_is_scoped_to_the_innermost_function`]）；
/// - **取不到就是 `None`**：调用方据此判**红**（读取点连所在函数都定位不了，谈不上「已校验」）。
///   失败方向朝红，不朝绿。
fn enclosing_fn_body(masked: &str, at: usize) -> Option<&str> {
    let bytes = masked.as_bytes();
    let mut best: Option<(usize, usize)> = None;
    let mut from = 0usize;
    while let Some(offset) = masked[from..].find("fn ") {
        let kw = from + offset;
        from = kw + "fn ".len();
        // `fn` 必须是独立标识符：`my_fn (` / `asfn ` 不是函数定义。
        if kw > 0 && is_ident_byte(bytes[kw - 1]) {
            continue;
        }
        let Some(open_paren) = masked[kw..].find('(').map(|o| kw + o) else {
            break;
        };
        let Some(close_paren) = match_delim(bytes, open_paren, b'(', b')') else {
            continue;
        };
        // 参数表之后第一个 `{` 是函数体；`;` 先到 = 无体声明（trait 方法签名 / `fn` 指针类型）。
        let Some(open) = masked[close_paren..].find('{').map(|o| close_paren + o) else {
            continue;
        };
        if masked[close_paren..]
            .find(';')
            .is_some_and(|o| close_paren + o < open)
        {
            continue;
        }
        let Some(close) = match_delim(bytes, open, b'{', b'}') else {
            continue;
        };
        if open <= at && at <= close && best.is_none_or(|(a, b)| close - open < b - a) {
            best = Some((open, close));
        }
    }
    best.and_then(|(a, b)| masked.get(a..=b))
}

/// 把 `regions` 覆盖的字节抹成空格，换行原样保留（行号是失败信息的全部价值）。
fn blank_regions(raw: &str, regions: &[(usize, usize)]) -> String {
    let total = raw.len();
    let mut bytes = raw.as_bytes().to_vec();
    for &(from, to) in regions {
        for byte in bytes[from.min(total)..to.min(total)].iter_mut() {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    }
    String::from_utf8(bytes).expect("整段区间被换成 ASCII 空格，不会破坏 UTF-8")
}

// ============================================================================
// 探测器
// ============================================================================

/// 变量名前缀。
const PREFIX: &str = "POLARIS_";

/// 被识别为「运行期读环境变量」的调用形态。
///
/// 只写后缀，于是 `std::env::var(` / `env::var(`（`use std::env;`）/ `::std::env::var(`
/// 三种写法一次覆盖。`set_var` / `remove_var` 不含 `env::var(` 子串，天然不误命中。
const READ_CALLS: &[&str] = &["env::var(", "env::var_os("];

/// 一处 `POLARIS_*` 读取点。
struct Hit {
    file: String,
    line: usize,
    name: String,
    /// 判定依据（进失败信息）。
    why: &'static str,
    /// 是否在 release 构型下可达。
    release: bool,
    /// 读取点所在函数体的**定位面**文本（只对 release 侧读取点取；`None` = 定位不到所在函数）。
    /// [`validated_read_sites_must_call_their_validator`] 的判据面就是它。
    body: Option<String>,
}

/// 从 `raw[at..]` 读出紧跟其后的字符串字面量内容（跳过空白）。
///
/// 只认普通字面量 `"…"`。读不出来（实参是常量 / 表达式 / 原始字符串）时返回 `None` ——
/// 那条路由第二个探测器 [`polaris_names_in`] 兜住，不在这里猜。
fn literal_arg(raw: &str, at: usize) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut i = at;
    while i < bytes.len() && (bytes[i] as char).is_whitespace() {
        i += 1;
    }
    if bytes.get(i) != Some(&b'"') {
        return None;
    }
    i += 1;
    let start = i;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return raw.get(start..i).map(str::to_owned),
            _ => i += 1,
        }
    }
    None
}

/// `text` 里全部 `POLARIS_*` 名字及其字节偏移。
///
/// 要求 `POLARIS_` 前一个字节**不是**标识符字符：这样 `window.__POLARIS_TRAY_EDGE__` 这类
/// 注入渲染端的 JS 全局名不会被当成环境变量名（它们与进程环境无关，且有十来个）。
fn polaris_names_in(text: &str) -> Vec<(usize, String)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(offset) = text[from..].find(PREFIX) {
        let at = from + offset;
        from = at + PREFIX.len();
        if at > 0 && is_ident_byte(bytes[at - 1]) {
            continue;
        }
        let mut end = at + PREFIX.len();
        while end < bytes.len() && is_ident_byte(bytes[end]) {
            end += 1;
        }
        out.push((at, text[at..end].to_owned()));
    }
    out
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn line_of(text: &str, at: usize) -> usize {
    text[..at].matches('\n').count() + 1
}

/// 一次全仓扫描的结果。
struct Scan {
    /// 全部 `POLARIS_*` 读取点（含测试侧）。
    hits: Vec<Hit>,
    /// **生产文本**（release 构型下会编译进去的那部分，代码 + 注释 + 字面量）里出现过的
    /// `POLARIS_*` 名字 → `文件:行号` 列表。
    names: BTreeMap<String, Vec<String>>,
    /// 生产文件（非 `tests/` 目录）里 [`release_off_regions`] 实际算出的区间数。
    ///
    /// 探测器 ② 的 `blank_regions` 与探测器 ①「被 cfg 罩住」的分流都以它为输入：它恒为 0
    /// 时两处都退化成「整份文件都是生产」，是本门唯一的静默失效入口，故计数留档供自检断言。
    off_regions: usize,
}

fn scan() -> Scan {
    let mut hits = Vec::new();
    let mut names: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut off_regions = 0usize;

    for file in scan_surface() {
        let raw = std::fs::read_to_string(&file.path)
            .unwrap_or_else(|err| panic!("读不到 `{}`（{err}）", file.path.display()));
        let masked = polaris_source_probe::mask_comments_and_strings(&raw);
        let regions = release_off_regions(&masked, &raw);

        // ── 探测器 ①：`env::var*(` 调用形态 + 字面量实参 ──
        for call in READ_CALLS {
            let mut from = 0usize;
            while let Some(offset) = masked[from..].find(call) {
                let at = from + offset;
                from = at + call.len();
                let Some(name) = literal_arg(&raw, at + call.len()) else {
                    continue;
                };
                if !name.starts_with(PREFIX) {
                    continue;
                }
                let (why, release) = if file.in_tests_dir {
                    (
                        "文件在 `tests/` 目录下（本仓约定：`<dir>/tests/` 恒为测试）",
                        false,
                    )
                } else if regions.iter().any(|(a, b)| *a <= at && at <= *b) {
                    (
                        "位于「任何 release 构型下都不编译」的 `#[cfg(..)]` 块内",
                        false,
                    )
                } else {
                    ("在 release 构型下可读", true)
                };
                hits.push(Hit {
                    file: file.rel.clone(),
                    line: line_of(&masked, at),
                    name,
                    why,
                    release,
                    // 只对 release 侧取：测试侧读取点不受信任级判据约束，存它只是白占内存。
                    body: release.then(|| {
                        enclosing_fn_body(&masked, at)
                            .unwrap_or_default()
                            .to_owned()
                    }),
                });
            }
        }

        // ── 探测器 ②：生产文本里的 `POLARIS_*` 名字（与调用形态无关）──
        if !file.in_tests_dir {
            off_regions += regions.len();
            let production = blank_regions(&raw, &regions);
            for (at, name) in polaris_names_in(&production) {
                names.entry(name).or_default().push(format!(
                    "{}:{}",
                    file.rel,
                    line_of(&production, at)
                ));
            }
        }
    }

    Scan {
        hits,
        names,
        off_regions,
    }
}

impl Scan {
    /// release 侧读取点，按变量名聚合（清单登记的单位就是名字，不是行号）。
    fn release_reads(&self) -> BTreeMap<&str, Vec<&Hit>> {
        let mut out: BTreeMap<&str, Vec<&Hit>> = BTreeMap::new();
        for hit in self.hits.iter().filter(|h| h.release) {
            out.entry(hit.name.as_str()).or_default().push(hit);
        }
        out
    }
}

/// 三张「运行期读取点」清单铺平成 `(清单名, 变量名, 理由)`。
///
/// 铺平而不是返回 `&Entry`，是因为 [`VALIDATED`] 用的是另一个结构体（多一个 `validator`
/// 字段）；让四条断言各自去 match 两种类型，等于把「清单是几张」这件事复制到每条断言里。
fn registry() -> Vec<(&'static str, &'static str, &'static str)> {
    ALLOWED
        .iter()
        .map(|e| ("ALLOWED", e.name, e.reason))
        .chain(VALIDATED.iter().map(|e| ("VALIDATED", e.name, e.reason)))
        .chain(
            PENDING_TRUST_GATE
                .iter()
                .map(|e| ("PENDING_TRUST_GATE", e.name, e.reason)),
        )
        .collect()
}

fn describe(hits: &[&Hit]) -> String {
    hits.iter()
        .map(|h| format!("    {}:{} · {} · {}", h.file, h.line, h.name, h.why))
        .collect::<Vec<_>>()
        .join("\n")
}

// ============================================================================
// 门
// ============================================================================

/// 🔴 release 侧读得到的每一个 `POLARIS_*` 都必须在 [`ALLOWED`] 或 [`PENDING_TRUST_GATE`] 里。
///
/// **变异探针**：在任意生产函数里加一行 `let _ = std::env::var("POLARIS_MUTATION_PROBE");`
/// ⇒ 本条转红并点名 `文件:行号 · 变量名 · 判定依据`；把同一行挪进 `#[cfg(test)] mod` 内
/// ⇒ 恢复绿。
#[test]
fn release_reachable_env_reads_are_all_registered() {
    let scan = scan();
    let known: BTreeSet<&str> = registry().iter().map(|(_, name, _)| *name).collect();
    let reads = scan.release_reads();
    let unknown: Vec<(&&str, &Vec<&Hit>)> = reads
        .iter()
        .filter(|(name, _)| !known.contains(**name))
        .collect();

    assert!(
        unknown.is_empty(),
        "发行包里有 {} 个未登记的 `POLARIS_*` 环境逃生门：\n{}\n\n\
         这不是「多了个环境变量」：release 构型下读环境变量，等于让**任何能给本进程设环境的\
         上下文**参与一次本该由发行包自己决定的判断。先回答两个问题，再选一张清单：\n\
           · 它喂给谁？终点是日志级别 / 布尔开关，还是路径、进程、权限？\n\
           · 最坏能做什么？（能换掉被执行的二进制 ⇒ 它是代码执行链的入口，不是配置项）\n\
         然后四选一：\n\
           ① 它只服务测试 ⇒ 挪进 `#[cfg(test)]` 块或 `tests/` 目录；\n\
           ② release 里读它、且取到的值**按原样**采纳也无妨 ⇒ 进 `ALLOWED`，\
              写清「喂给谁 / 最坏能做什么」；\n\
           ③ release 里读它，但取到的值必须先过校验才敢用（路径 / 命令 / 提权来源）⇒ \
              进 `VALIDATED`，写清「由哪个函数校验 / 不通过时怎么办」，\
              并让读取点所在函数真的调那个校验函数（有源码级断言盯着）；\n\
           ④ 是违规、下一批修 ⇒ 进 `PENDING_TRUST_GATE`，写清「为什么还在 / 修完做什么」。\n\
         本门在 `src-tauri/tests/release_escape_hatches.rs`。",
        unknown.len(),
        unknown
            .iter()
            .map(|(name, hits)| format!("  {name}\n{}", describe(hits)))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// 🔴 [`ALLOWED`] / [`PENDING_TRUST_GATE`] 每条恰好命中一次，且两表不重不漏。
///
/// 命中 0 次 = 它守的东西已经没了，条目成了将来某个真违规的免死金牌 ——
/// [`PENDING_TRUST_GATE`] 的条目在下一批修完后正是靠这一条自动转红，把清理逼出来。
/// 命中多次 = 一条豁免覆盖了它没打算覆盖的地方（今天只会由「两表登记了同一个名字」造成）。
///
/// **变异探针**：删掉 `PENDING_TRUST_GATE` 里 `POLARIS_SINGBOX_PATH` 那条
/// ⇒ [`release_reachable_env_reads_are_all_registered`] 转红点名它的全部 release 侧读取点；
/// 把 `POLARIS_SINGBOX_PATH` 同时写进 `ALLOWED` ⇒ 本条以「命中 2 次」转红。
#[test]
fn registry_entries_must_all_match_exactly_once() {
    let scan = scan();
    let reads = scan.release_reads();

    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for (list, name, reason) in registry() {
        *seen.entry(name).or_default() += 1;
        let count = usize::from(reads.contains_key(name));
        assert_eq!(
            count, 1,
            "{list} 的 `{name}` 命中 {count} 次（应为 1）。\n\
             命中 0 次 = 它守的东西已经没了：release 侧再没有读这个变量的地方。\
             **删掉这条**，不要留着 —— 留着等于给将来某个同名的真违规发免死金牌。\n\
             （若这是 `PENDING_TRUST_GATE` 的条目转红，先判一件事：修完之后 release 侧**还读不读**\
             它？还读 ⇒ 它该进 `VALIDATED` 而不是被删掉。）\n\
             条目理由：{reason}"
        );
    }
    let dup: Vec<&&str> = seen
        .iter()
        .filter(|(_, n)| **n > 1)
        .map(|(k, _)| k)
        .collect();
    assert!(
        dup.is_empty(),
        "同一个变量名被登记了不止一次：{dup:?}。一个变量只能有一个状态 —— \
         要么是设计意图（ALLOWED），要么是待修（PENDING_TRUST_GATE）。"
    );
}

/// 🔴 [`VALIDATED`] 的每个读取点，其**所在函数体内**必须出现该条目登记的校验调用。
///
/// # 为什么这一条不可省（本类别与「一句承诺」的全部差别）
///
/// [`VALIDATED`] 说的是「release 里读得到，但取到的路径必须先过校验」。这句话如果只写在
/// 清单的 `reason` 里，那么把校验调用从读取点删掉之后：清单还在、上面三条断言全绿、
/// 编译器不会说话、`cargo test` 不会说话 —— 逃生门当场退回「第一优先级的任意路径」，而门
/// 依旧是绿的。本仓已经为「门在但没牙」付过账，所以这一类别必须自带一条**源码级**断言。
///
/// # 判据面
///
/// 取材面是本门已有的定位面（[`polaris_source_probe::mask_comments_and_strings`] 剥过注释与
/// 字面量），切片由 [`enclosing_fn_body`] 取**最内层**函数体。于是：
/// 注释里写一句 `adopt_trusted_env_path(...)` 不算数（被剥掉了）；
/// 隔壁函数里调了也不算数（不在同一层函数体内）。
///
/// **变异探针**：把 `runtime/proxy/core_binary.rs::core_binary_env_override` 里的
/// `adopt_trusted_env_path(..)` 换回裸的 `std::env::var("POLARIS_SINGBOX_PATH")` 解析
/// ⇒ 本条转红并点名 `src-tauri/src/runtime/proxy/core_binary.rs:<行号> · POLARIS_SINGBOX_PATH`；
/// 对 `runtime/helper.rs::resolve_helper_binary` 做同样的事 ⇒ 点名 L2 那条腿。
#[test]
fn validated_read_sites_must_call_their_validator() {
    let scan = scan();
    let reads = scan.release_reads();

    // 取材面自检：本类别为空、或某条一个读取点都没有时，下面的否定型断言会恒真。
    assert!(
        !VALIDATED.is_empty(),
        "VALIDATED 是空的 —— 本条断言从此恒真。要么真的没有这一类了（那就连同这条断言一起删），\
         要么是条目被误删。"
    );

    let mut missing: Vec<String> = Vec::new();
    for entry in VALIDATED {
        let hits = reads.get(entry.name).map(Vec::as_slice).unwrap_or_default();
        assert!(
            !hits.is_empty(),
            "VALIDATED 的 `{}` 在 release 侧一个读取点都没有 —— 它已经不是「校验后采纳」了。\
             若 release 侧确实不再读它，删掉本条；若它换了读取形态（实参不再是字面量），\
             把字面量还回 `env::var(` 调用处，否则探测器①从此看不见它。\n\
             条目理由：{}",
            entry.name,
            entry.reason
        );
        for hit in hits {
            let calls = hit
                .body
                .as_deref()
                .is_some_and(|body| body.contains(entry.validator));
            if !calls {
                missing.push(format!(
                    "    {}:{} · {} · 所在函数体内没有 `{}`{}",
                    hit.file,
                    hit.line,
                    hit.name,
                    entry.validator,
                    if hit.body.is_none() {
                        "（而且连所在函数都定位不到）"
                    } else {
                        ""
                    }
                ));
            }
        }
    }

    assert!(
        missing.is_empty(),
        "有 {} 处 `VALIDATED` 读取点没有调用它登记的校验函数：\n{}\n\n\
         `VALIDATED` 的含义是「release 里读得到，但取到的路径必须先过可信来源判据才被采纳」。\
         读取点所在函数里没有那个调用，就说明这句话在这条腿上**不成立** —— 它退回成了\
         「发行包里的第一优先级 + 任意路径」，而清单还在替它作保。\n\
         三选一：把校验调用加回去；或者这条腿本就不该读这个变量（删掉读取点）；\
         或者它确实不需要校验（那它属于 `ALLOWED`，去那张表里写清「喂给谁 / 最坏能做什么」）。\n\
         本门在 `src-tauri/tests/release_escape_hatches.rs`。",
        missing.len(),
        missing.join("\n")
    );
}

/// 🔴 生产文本里出现的每个 `POLARIS_*` 名字都必须被四张清单之一认领。
///
/// 这是与调用形态无关的第二个探测器：`const H: &str = "POLARIS_X"; env::var(H)` 逃得过
/// `env::var(` 的形态匹配，但逃不过「那个字面量总得存在于生产代码里」。
///
/// **变异探针**：在任意生产文件里加一行注释 `// POLARIS_MUTATION_PROBE`
/// ⇒ 本条转红点名 `文件:行号`（哪怕根本没有 `env::var`）。
#[test]
fn production_polaris_names_are_all_accounted_for() {
    let scan = scan();
    let claimed: BTreeSet<&str> = registry()
        .iter()
        .map(|(_, name, _)| *name)
        .chain(TEXT_ONLY.iter().map(|e| e.name))
        .collect();
    let orphan: Vec<(&String, &Vec<String>)> = scan
        .names
        .iter()
        .filter(|(name, _)| !claimed.contains(name.as_str()))
        .collect();

    assert!(
        orphan.is_empty(),
        "生产代码里出现了 {} 个没有归属的 `POLARIS_*` 名字：\n{}\n\n\
         每个名字必须落一张清单：`ALLOWED` / `VALIDATED` / `PENDING_TRUST_GATE`（运行期读取点），\
         或 `TEXT_ONLY`（不是运行期读取 —— 编译期 `option_env!`、shell heredoc 定界符之类，\
         登记时写清它**为什么不是**读取点）。\n\
         若它确实是通过常量间接读的环境变量，那它就是一个逃生门，按逃生门登记。",
        orphan.len(),
        orphan
            .iter()
            .map(|(name, sites)| format!("  {name}\n    {}", sites.join("\n    ")))
            .collect::<Vec<_>>()
            .join("\n")
    );

    for entry in TEXT_ONLY {
        let count = usize::from(scan.names.contains_key(entry.name));
        assert_eq!(
            count, 1,
            "TEXT_ONLY 的 `{}` 命中 {count} 次（应为 1）—— 那个串已经不在生产代码里了，删掉本条。\n\
             条目理由：{}",
            entry.name, entry.reason
        );
        assert!(
            !scan.release_reads().contains_key(entry.name),
            "`{}` 登记在 TEXT_ONLY（「不是运行期读取点」），但现在它**是**一个 release 侧 \
             `env::var*` 读取点。把它移进 ALLOWED 或 PENDING_TRUST_GATE。",
            entry.name
        );
    }
}

/// 🔴 开发树锚点（`env!("CARGO_MANIFEST_DIR")`）不得进发行产物。
///
/// # 守的是什么
///
/// `env!("CARGO_MANIFEST_DIR")` 把**构建机上的绝对路径**变成一个 `&'static str` 编进 `.rodata`。
/// 两层后果：
///
/// 1. **信息泄露**：发行二进制里明晃晃写着开发者的目录结构。2026-08-30 对 `strip = "symbols"`
///    之后的产物实测：仍有 143 处 `/home/sway/Code/polaris` 字样。
/// 2. **语义错误**：这些调用点把它当成「随包资源根的开发态候选」喂给
///    `bundle_resource_candidates`。在用户机上那条路径不存在，只是白扫一遍；但在**打包机**上
///    它真实存在 —— `geo_seed` 的头注已经记下过这个坑：源码仓候选会让「随包 `.srs` 一个都没有」
///    的包在打包机上验证成功，而终端用户拿到零 `.srs`。
///
/// # 判据
///
/// `<crate>/src/**` 里每一处 `env!("CARGO_MANIFEST_DIR")` 都必须落在
/// [`release_off_regions`] 算出的「任何 release 构型下都不编译」区间内
/// （`#[cfg(test)]` / `#[cfg(debug_assertions)]` / …）。`tests/` 目录整份免检。
///
/// **必须是 `#[cfg]` 不是 `cfg!()`**：后者两条腿都编译，字面量照样进 `.rodata` —— 那正是
/// 这批修复前的形态。本门只认属性，看不见 `cfg!()`，所以它抓的就是「字面量在不在产物里」。
///
/// **变异探针**：把 `runtime/proxy.rs` 的 `dev_manifest_dir()` 上那对 `#[cfg(debug_assertions)]`
/// / `#[cfg(not(debug_assertions))]` 去掉、合成一个无 cfg 的函数 ⇒ 本条转红并点名它。
#[test]
fn dev_tree_anchor_is_debug_only() {
    const ANCHOR: &str = "env!(\"CARGO_MANIFEST_DIR\")";

    let mut seen = 0usize;
    let mut total = 0usize;
    let mut off_files = 0usize;
    let mut on_files = 0usize;
    let mut bad: Vec<String> = Vec::new();
    for file in scan_surface() {
        if !file.rel.contains("/src/") {
            continue;
        }
        if file.in_tests_dir || file.release_off_file {
            off_files += 1;
        } else {
            on_files += 1;
        }
        {
            // 全量计数（含被排除的文件）：定位器活性由它证明，而不是由「恰好还剩一处合法锚点」证明。
            let raw = std::fs::read_to_string(&file.path).unwrap_or_default();
            let masked = polaris_source_probe::mask_comments_and_strings(&raw);
            let mut f = 0usize;
            while let Some(o) = masked[f..].find("env!(") {
                let a = f + o;
                f = a + 5;
                if raw[a..].starts_with(ANCHOR) {
                    total += 1;
                }
            }
        }
        if file.in_tests_dir || file.release_off_file {
            continue;
        }
        let raw = std::fs::read_to_string(&file.path)
            .unwrap_or_else(|err| panic!("读不到 `{}`（{err}）", file.path.display()));
        // 定位面剥注释与字符串：文档里写 `env!("CARGO_MANIFEST_DIR")` 的地方遍布（本门自己就写了）。
        let masked = polaris_source_probe::mask_comments_and_strings(&raw);
        let regions = release_off_regions(&masked, &raw);
        // `ANCHOR` 自带字符串字面量，净化面里那段被抹空 ⇒ 只能按 `env!(` 定位，再回原文核实。
        let mut from = 0usize;
        while let Some(off) = masked[from..].find("env!(") {
            let at = from + off;
            from = at + "env!(".len();
            if !raw[at..].starts_with(ANCHOR) {
                continue;
            }
            seen += 1;
            if !regions.iter().any(|(a, b)| *a <= at && at <= *b) {
                bad.push(format!("  {}:{}", file.rel, line_of(&masked, at)));
            }
        }
    }

    // 阳性对照三条，缺一条本门就可能是「绿但没执行」：
    // ① 定位器还认得这个锚点（全量计数，不受排除逻辑影响）；
    // ② 排除逻辑没把**所有**文件都排掉（那样 `bad` 恒空）；
    // ③ 也没有一个都排不掉（那样 dev-only / 声明式门整条失效，本门会一片假红）。
    assert!(
        total > 10,
        "全仓只扫到 {total} 处 `{ANCHOR}` —— 锚点写法变了或取材面塌了，本门在裸奔"
    );
    assert!(
        on_files > 0,
        "`src/**` 里一个 release 侧会编译的文件都没有 —— 排除逻辑把取材面整个吃掉了，`bad` 恒空"
    );
    assert!(
        off_files > 0,
        "一个 release 侧不编译的文件都没识别出来 —— dev-only crate 与声明式 `#[cfg] mod x;` \
         两条判据双双失效（`polaris-source-probe` 与 `main.rs` 的 `#[cfg(test)] mod test_support;` \
         是它们各自的活样本）"
    );
    let _ = seen;
    assert!(
        bad.is_empty(),
        "\n{} 处 `{ANCHOR}` 不在「release 侧不编译」的 `#[cfg(..)]` 之下 —— \
         构建机绝对路径会编进发行产物：\n{}\n\
         修法：走 `runtime::proxy::dev_manifest_dir()`（`#[cfg]` 分叉，release 腿里没有这个 `env!`）。\n",
        bad.len(),
        bad.join("\n")
    );
    eprintln!(
        "[门 3] 开发树锚点：全仓 {total} 处；release 侧会编译的文件 {on_files} 个（其中锚点 {seen} 处，\
         全部在不编译的腿下）、不编译的文件 {off_files} 个"
    );
}

/// 🔴 取材面自检 + 分流活性。
///
/// 否定型断言在空取材面上恒真，这是本门最危险的失效方向：上面三条门在「一个文件都没扫到」
/// 或「三条分流只有一条活着」时会**全部变绿**且毫无信息量。
///
/// **变异探针**：把 [`workspace_members`] 改成只取第一个 member（`members.truncate(1)`）
/// ⇒ 本条转红（`crates/` 覆盖数与 `src-tauri/` 两项同时失守）。
#[test]
fn scan_surface_self_check() {
    let files = scan_surface();
    assert!(
        files.iter().any(|f| f.rel.starts_with("src-tauri/src/")),
        "取材面里没有 `src-tauri/src/`"
    );
    assert!(
        files.iter().any(|f| f.rel.starts_with("src-tauri/tests/")),
        "取材面里没有 `src-tauri/tests/` —— 只扫 `src/` 时「类别 1」的 tests 目录支拿不到样本"
    );
    let crates: BTreeSet<&str> = files
        .iter()
        .filter_map(|f| f.rel.strip_prefix("crates/"))
        .filter_map(|rest| rest.split('/').next())
        .collect();
    assert!(
        crates.len() > 5,
        "只扫到 {} 个 crate，members 解析多半只取到了第一条。实际：{crates:?}",
        crates.len()
    );

    // 两条**语料**分流必须都活着：任何一条恒空，对应的判据就从此没被执行过。
    //
    // 第三条形态（「被 `#[cfg(..)]` 罩住的读取点」）此处**不**要求语料里有样本。它此前的
    // 样本全部来自生产文件里内联的 `#[cfg(test)] mod tests { … env::var("POLARIS_…") }`；
    // 测试实体外移到 `<dir>/tests/` 之后，这些读取点整体落进了下面那条 `tests/` 分流，
    // 语料侧归零是**代码变干净**的结果，不是判据失守。继续断言「语料里必须有」＝ 让本门在
    // 仓库更规范时转红，判据方向就反了。
    //
    // 该形态的分流覆盖因此由合成夹具持有，正反两向都钉死，见
    // [`extraction_and_classification_self_check`]：`POLARIS_FIXTURE_CFG_TEST` /
    // `POLARIS_FIXTURE_FEATURE_GATED` 必须判成非 release，`POLARIS_FIXTURE_NOT_WINDOWS`
    // 必须判成 release。语料侧改钉下面的 `off_regions`。
    let scan = scan();
    let this_gate = "src-tauri/tests/release_escape_hatches.rs";
    for (what, alive) in [
        ("release 侧读取点", scan.hits.iter().any(|h| h.release)),
        (
            "`tests/` 目录下的读取点（本门自己的夹具不算）",
            scan.hits
                .iter()
                .any(|h| !h.release && h.file.contains("/tests/") && h.file != this_gate),
        ),
    ] {
        assert!(
            alive,
            "分流「{what}」今天一个样本都没有 —— 该支判据从未被执行，它是绿的但没有信息量。"
        );
    }

    // `release_off_regions` 必须在**真实语料**上算出非空区间：生产文件里仍有大量
    // `#[cfg(test)] fn` / `#[cfg(test)] mod …;` / `#[cfg(feature = "test-utils")]` 条目。
    // 它恒为 0 时探测器 ② 的 `blank_regions` 退化成恒等函数，`#[cfg(test)]` 里提到的
    // `POLARIS_*` 名字会被当成生产文本，而分流也再不会走「被罩住」那一支 —— 两处同时失效
    // 且都不报错。夹具只能证明区间算法本身对，证明不了它在真语料上被喂到了。
    //
    // **变异探针**：把 [`release_off_regions`] 的返回改成 `Vec::new()` ⇒ 本条转红。
    assert!(
        scan.off_regions > 0,
        "真实语料里一个「release 侧不编译」的 `#[cfg(..)]` 区间都没算出来 —— \
         区间计算在真语料上是死的，探测器 ② 的 `blank_regions` 已退化成恒等函数"
    );

    // 生产名字面同样不能是空的（探测器 ② 的恒真方向）。
    assert!(
        !scan.names.is_empty(),
        "生产文本里一个 `POLARIS_*` 名字都没扫到 —— 探测器 ② 的取材面是空的"
    );
}

// ============================================================================
// 判据自检（合成夹具：不依赖真实语料，证明分流真的在分流）
// ============================================================================

/// 🔴 cfg 三值求值对差表。
///
/// 只有「在**任何** release 构型下都为假」才算被罩住。表里 `not(any(windows, test))` 那一行
/// 是本门与二值求值器的分水岭：二值把 `windows` 当恒真 ⇒ 整体假 ⇒ 该块被判成不出厂 ⇒
/// 里面的逃生门静默放行。
///
/// **变异探针**：把 [`release_reachability`] 里 `Tri::Unknown` 的兜底改成 `Tri::True`
/// ⇒ `not(unix)` / `not(any(windows, test))` 两行转红。
#[test]
fn cfg_predicate_truth_table() {
    for (expr, want) in [
        ("test", Tri::False),
        // `debug_assertions` 恒假的前提由 `release_profiles_must_not_enable_debug_assertions` 守。
        ("debug_assertions", Tri::False),
        ("not(debug_assertions)", Tri::True),
        ("any(debug_assertions, test)", Tri::False),
        ("all(test, unix)", Tri::False),
        ("feature = \"test-utils\"", Tri::False),
        ("any(test, feature = \"test-utils\")", Tri::False),
        ("not(test)", Tri::True),
        ("any(test, target_os = \"macos\")", Tri::Unknown),
        ("any(test, unix)", Tri::Unknown),
        ("unix", Tri::Unknown),
        ("not(unix)", Tri::Unknown),
        ("target_os = \"macos\"", Tri::Unknown),
        ("not(any(windows, test))", Tri::Unknown),
        ("all(unix, not(test))", Tri::Unknown),
        ("any(all(test, unix), feature = \"test-utils\")", Tri::False),
    ] {
        assert_eq!(
            release_reachability(expr),
            want,
            "cfg `{expr}` 的 release 可达性判错"
        );
    }
}

/// 合成夹具：覆盖两套取材面与三条分流的全部形态。
///
/// 本文件在 `src-tauri/tests/` 下 ⇒ 整份属测试面，夹具里的 `POLARIS_FIXTURE_*` 不会污染
/// 真实扫描（探测器 ② 只看 `src/`，探测器 ① 会把它们判成 `tests/` 侧）。
const FIXTURE: &str = r####"
fn production() {
    let _ = std::env::var("POLARIS_FIXTURE_PROD");
    // std::env::var("POLARIS_FIXTURE_COMMENTED") —— 注释里的读取不是读取
    let _msg = "POLARIS_FIXTURE_IN_STRING 只是错误消息里的文本";
    let _ = std::env::var_os("POLARIS_FIXTURE_VAR_OS");
}

#[cfg(test)]
mod tests {
    fn inside() {
        let _ = env::var("POLARIS_FIXTURE_CFG_TEST");
    }
}

#[cfg(any(test, feature = "test-utils"))]
fn helper() {
    let _ = std::env::var("POLARIS_FIXTURE_FEATURE_GATED");
}

#[cfg(not(any(windows, test)))]
fn ships_on_linux() {
    let _ = std::env::var("POLARIS_FIXTURE_NOT_WINDOWS");
}

#[cfg(test)]
mod decl_form;
"####;

/// 🔴 取材与分流的切片自检（合成夹具 + 正反对照）。
///
/// 三件事必须同时成立，缺一条本门就有一整类静默失效：
/// ① 注释与字面量里的「读取」不算读取（定位面剥干净了）；
/// ② 变量名读得出来（读取面没被剥）；
/// ③ cfg 归属真的在分流 —— 特别是 `#[cfg(any(test, feature = "test-utils"))]`：
///    它的 `"test-utils"` 是字面量，若拿定位面求值会被读成「无门」而放行。
#[test]
fn extraction_and_classification_self_check() {
    let masked = polaris_source_probe::mask_comments_and_strings(FIXTURE);
    assert_eq!(
        FIXTURE.split('\n').count(),
        masked.split('\n').count(),
        "定位面行数漂移 —— 失败信息里的行号会全错"
    );

    let regions = release_off_regions(&masked, FIXTURE);
    let mut found: BTreeMap<String, bool> = BTreeMap::new();
    for call in READ_CALLS {
        let mut from = 0usize;
        while let Some(offset) = masked[from..].find(call) {
            let at = from + offset;
            from = at + call.len();
            let Some(name) = literal_arg(FIXTURE, at + call.len()) else {
                continue;
            };
            let release = !regions.iter().any(|(a, b)| *a <= at && at <= *b);
            found.insert(name, release);
        }
    }

    // ① 定位面：注释与字面量里的同形串不是读取点。
    assert!(
        !found.contains_key("POLARIS_FIXTURE_COMMENTED"),
        "注释里的 `env::var` 被当成了读取点 —— 定位面没剥注释，本门会假红一片"
    );
    assert!(
        !found.contains_key("POLARIS_FIXTURE_IN_STRING"),
        "字符串里的名字被当成了读取点"
    );

    // ② 读取面：变量名必须读得出来（剥了字面量就恒空 ⇒ 门恒绿）。
    assert_eq!(
        found.get("POLARIS_FIXTURE_PROD"),
        Some(&true),
        "生产读取点没被识别成 release 侧 —— 读取面被剥掉了，或分流判错"
    );
    assert_eq!(
        found.get("POLARIS_FIXTURE_VAR_OS"),
        Some(&true),
        "`env::var_os` 形态漏检"
    );

    // ③ cfg 归属：三种形态各一，证明分流不是恒红也不是恒绿。
    assert_eq!(
        found.get("POLARIS_FIXTURE_CFG_TEST"),
        Some(&false),
        "`#[cfg(test)] mod` 内的读取被判成了 release 侧（恒红方向）"
    );
    assert_feature_gate_read_off(&found);
    assert_eq!(
        found.get("POLARIS_FIXTURE_NOT_WINDOWS"),
        Some(&true),
        "`#[cfg(not(any(windows, test)))]` 的块在 Linux release 里**会**出厂，\
         判成「被罩住」就是静默放行 —— 这正是二值求值器的失效点"
    );
}

/// [`extraction_and_classification_self_check`] 的第 ③ 条里最关键的一格，单独拎出来命名：
/// `#[cfg(any(test, feature = "test-utils"))]` 的谓词求值必须走**原文**。
///
/// **变异探针**：把 [`release_off_regions`] 里的 `raw.get(start..=i)` 换成 `masked.get(..)`
/// ⇒ 本条转红（`"test-utils"` 被抹空后整个 `any(..)` 读成 `Tri::Unknown` ⇒ 判成会出厂）。
fn assert_feature_gate_read_off(found: &BTreeMap<String, bool>) {
    assert_eq!(
        found.get("POLARIS_FIXTURE_FEATURE_GATED"),
        Some(&false),
        "`#[cfg(any(test, feature = \"test-utils\"))]` 被读成了「无门」—— \
         cfg 谓词求值跑在了剥掉字面量的定位面上"
    );
}

/// [`enclosing_fn_body`] 的切片自检夹具：三个读取点，只有第一个所在的函数真调了校验函数。
///
/// 第三个（`inner`）是关键格：它嵌在一个**自己调了**校验函数的方法里 —— 取外层就会把它误判成
/// 「已校验」，而那正是 [`validated_read_sites_must_call_their_validator`] 最危险的失效方向
/// （断言还在，但它检查的是「同一个文件里有没有」而不是「同一个函数里有没有」）。
const FN_SCOPE_FIXTURE: &str = r####"
fn guarded() {
    let _ = std::env::var("POLARIS_FIXTURE_GUARDED");
    let _ = adopt_trusted_env_path("POLARIS_FIXTURE_GUARDED", None, TrustScope::AppDataOnly);
}

fn bare() {
    let _ = std::env::var("POLARIS_FIXTURE_BARE");
    // 只在注释里写 adopt_trusted_env_path( 不算调用
}

impl Thing {
    fn outer_calls_it(&self) -> Result<(), String> {
        fn inner() {
            let _ = std::env::var("POLARIS_FIXTURE_INNER");
        }
        inner();
        let _ = adopt_trusted_env_path("POLARIS_FIXTURE_OUTER", None, TrustScope::AppDataOnly);
        Ok(())
    }
}
"####;

/// 🔴 [`enclosing_fn_body`] 的切片自检（合成夹具 + 三向对照）。
///
/// 三格缺一不可：**正向**（真调了 ⇒ 看得见）证明断言不是恒红；**反向**（隔壁函数调了 ⇒ 看不见）
/// 与**嵌套**（外层调了、内层没调 ⇒ 内层看不见）证明它不是恒绿。
///
/// **变异探针**：把 [`enclosing_fn_body`] 里的「最内层」判据（`close - open < b - a`）改成
/// 「取第一个命中」⇒ 嵌套那格转红；把取材面从定位面换成原文 ⇒ `bare` 那格转红（注释里的调用
/// 被当成了调用）。
#[test]
fn enclosing_fn_body_is_scoped_to_the_innermost_function() {
    let masked = polaris_source_probe::mask_comments_and_strings(FN_SCOPE_FIXTURE);
    assert_eq!(
        FN_SCOPE_FIXTURE.split('\n').count(),
        masked.split('\n').count(),
        "定位面行数漂移"
    );

    const CALL: &str = "env::var(";
    const VALIDATOR: &str = "adopt_trusted_env_path(";
    let mut bodies: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut from = 0usize;
    while let Some(offset) = masked[from..].find(CALL) {
        let at = from + offset;
        from = at + CALL.len();
        let Some(name) = literal_arg(FN_SCOPE_FIXTURE, at + CALL.len()) else {
            continue;
        };
        bodies.insert(name, enclosing_fn_body(&masked, at).map(str::to_owned));
    }

    let sees = |name: &str| -> bool {
        bodies
            .get(name)
            .unwrap_or_else(|| panic!("夹具里的 `{name}` 读取点没被识别 —— 切片自检本身失灵了"))
            .as_deref()
            .is_some_and(|body| body.contains(VALIDATOR))
    };

    assert!(
        sees("POLARIS_FIXTURE_GUARDED"),
        "同一函数体内的校验调用必须看得见（恒红方向）"
    );
    assert!(
        !sees("POLARIS_FIXTURE_BARE"),
        "隔壁函数的校验调用被算进来了 —— 切片取大了，断言退化成「同一个文件里有没有」"
    );
    assert!(
        !sees("POLARIS_FIXTURE_INNER"),
        "嵌套函数取到了外层的函数体 —— 「最内层」判据失效，外层的校验调用会替内层的读取点作保"
    );
}

/// 清单打印（非门，`#[ignore]`）：把「发行包里一共有几个逃生门」这个问题的答案打出来。
///
/// `cargo test -p polaris --test release_escape_hatches -- --ignored --nocapture inventory`
///
/// 模块文档说本门的产物就是那份清单 —— 那就得有一条命令能把它拿出来，否则「清单」只存在于
/// 断言失败的那一刻，平时谁也看不见。
#[test]
#[ignore = "清单打印，非门"]
fn inventory() {
    let scan = scan();
    let known: BTreeMap<&str, &str> = registry()
        .iter()
        .map(|(list, name, _)| (*name, *list))
        .chain(TEXT_ONLY.iter().map(|e| (e.name, "TEXT_ONLY")))
        .collect();
    println!("\n{:<44} 变量名 · 归属 · 判定依据", "文件:行号");
    println!("{}", "-".repeat(112));
    let mut hits: Vec<&Hit> = scan.hits.iter().collect();
    hits.sort_by(|a, b| (&a.name, &a.file, a.line).cmp(&(&b.name, &b.file, b.line)));
    for hit in hits {
        let verdict = if hit.release {
            known.get(hit.name.as_str()).copied().unwrap_or("未登记")
        } else {
            "类别①(测试构型)"
        };
        println!(
            "{:<44} {} · {} · {}",
            format!("{}:{}", hit.file, hit.line),
            hit.name,
            verdict,
            hit.why
        );
    }
    println!("\n== release 侧读取点按变量名聚合 ==");
    for (name, sites) in scan.release_reads() {
        println!(
            "  {name}  [{}]  {}",
            known.get(name).copied().unwrap_or("未登记"),
            sites
                .iter()
                .map(|h| format!("{}:{}", h.file, h.line))
                .collect::<Vec<_>>()
                .join("  ")
        );
    }
    println!("\n== 生产文本里出现过的 POLARIS_* 名字（探测器 ②）==");
    for (name, sites) in &scan.names {
        println!(
            "  {name}  [{}]  {} 处：{}",
            known.get(name.as_str()).copied().unwrap_or("未登记"),
            sites.len(),
            sites.join("  ")
        );
    }
}

// ============================================================================
// 分流谓词的前提：release 构型下 `debug_assertions` 必须是关的
// ============================================================================

/// 信任级分流靠 `cfg!(any(debug_assertions, test))`（见 `runtime/env_trust.rs::dev_build`）。
/// 这条谓词成立的前提是**发行构型下 `debug_assertions` 为假**——今天成立，因为全仓一个
/// `[profile.*]` 段都没有，`cargo build --release` 取默认值 `false`。
///
/// 但这个前提**没有任何东西在守**，而它正要被动到：打包治理的 L12 会加
/// `[profile.release] strip = "symbols"`。在那个新段里顺手写一句
/// `debug-assertions = true`（「release 也保留断言」是个很自然的决定）会让
/// **L1/L2 的信任级校验整条失效** —— 不报错、不转红、不改任何测试计数，
/// 逃生门悄悄退回裸信任。
///
/// 这是「新路径绕开旧闸门」的标准形状：闸门本身没坏，是它依赖的那个前提被从别处改掉了。
/// 故把前提本身钉成断言，而不是指望改 profile 的人记得这条依赖。
///
/// 覆盖两类入口，缺一条都是「新路径绕开旧闸门」：
///
/// 1. **清单**：`[profile.release]`、`[profile.release.*]`（如 `.package.foo`），以及任何
///    `inherits = "release"` 的自定义 profile；
/// 2. **rustflags**：`.cargo/config.toml`（`[build]` / `[target.*]` 的 `rustflags`）与
///    `.github/workflows/*.yml` 里的 `RUSTFLAGS` / `CARGO_BUILD_RUSTFLAGS` /
///    `CARGO_ENCODED_RUSTFLAGS`。`-C debug-assertions=on` 与在 profile 里写 `= true` 等效，
///    而本仓的 `.cargo/config.toml` 已经在用 rustflags（`+crt-static`）、CI 也在 step 级设
///    `RUSTFLAGS` —— 这条路是活的，不是假想。
///
/// [`release_reachability`] 把 `debug_assertions` 判成 [`Tri::False`] 的**唯一依据**就是本门。
///
/// **变异探针**：① 在根 `Cargo.toml` 加 `[profile.release]\ndebug-assertions = true`；
/// ② 在 `.cargo/config.toml` 的 rustflags 里加 `"-C", "debug-assertions=on"` —— 各让本条转红。
#[test]
fn release_profiles_must_not_enable_debug_assertions() {
    let root = workspace_root();
    let mut manifests = vec![root.join("Cargo.toml")];
    manifests.extend(
        workspace_members(&root)
            .into_iter()
            .map(|m| m.join("Cargo.toml")),
    );

    let mut offenders = Vec::new();
    for manifest in &manifests {
        let Ok(raw) = std::fs::read_to_string(manifest) else {
            continue;
        };
        let masked = mask_toml_comments(&raw);
        // 逐段切：`[profile.x]` 到下一个顶层 `[` 之间。
        let mut sections: Vec<(String, String)> = Vec::new();
        let mut current: Option<(String, String)> = None;
        for line in masked.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                if let Some(done) = current.take() {
                    sections.push(done);
                }
                current = Some((trimmed.trim_matches(['[', ']']).to_string(), String::new()));
                continue;
            }
            if let Some((_, body)) = current.as_mut() {
                body.push_str(line);
                body.push('\n');
            }
        }
        if let Some(done) = current.take() {
            sections.push(done);
        }

        for (name, body) in &sections {
            let Some(rest) = name.strip_prefix("profile.") else {
                continue;
            };
            // release 本体 / 它的子表 / 显式 inherits 过来的自定义 profile
            let is_release_shaped = rest == "release"
                || rest.starts_with("release.")
                || body.replace(' ', "").contains("inherits=\"release\"");
            if !is_release_shaped {
                continue;
            }
            let flat = body.replace(' ', "");
            if flat.contains("debug-assertions=true") || flat.contains("debug_assertions=true") {
                offenders.push(format!(
                    "  {} 的 [{name}]",
                    manifest
                        .strip_prefix(&root)
                        .unwrap_or(manifest)
                        .to_string_lossy()
                ));
            }
        }
    }

    // ── ② rustflags 入口 ──
    let mut flag_files: Vec<PathBuf> = vec![root.join(".cargo").join("config.toml")];
    if let Ok(entries) = std::fs::read_dir(root.join(".github").join("workflows")) {
        let mut ws: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "yml" || x == "yaml"))
            .collect();
        ws.sort();
        flag_files.extend(ws);
    }
    let mut flag_surface_seen = 0usize;
    for file in &flag_files {
        let Ok(raw) = std::fs::read_to_string(file) else {
            continue;
        };
        flag_surface_seen += 1;
        // 只看**代码面**：两种文件的注释都以 `#` 起头，而本门自己的说明就写着这个字样。
        let code: String = raw
            .lines()
            .map(|l| {
                if l.trim_start().starts_with('#') {
                    ""
                } else {
                    l
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let flat: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        let flat = flat.replace(['"', '\'', ','], "");
        for bad in [
            "debug-assertions=on",
            "debug-assertions=yes",
            "debug-assertions=true",
            "-Cdebug-assertions",
        ] {
            if flat.contains(bad) && !flat.contains("debug-assertions=off") {
                offenders.push(format!(
                    "  {} 的 rustflags 含 `{bad}`",
                    file.strip_prefix(&root).unwrap_or(file).to_string_lossy()
                ));
            }
        }
    }
    // 阳性对照：rustflags 那半边一个文件都没读到 ⇒ 它是绿的但没执行过。
    assert!(
        flag_surface_seen >= 2,
        "rustflags 取材面只读到 {flag_surface_seen} 个文件（期望 `.cargo/config.toml` + \
         `.github/workflows/*.yml`）—— 该半边判据没在跑"
    );

    assert!(
        offenders.is_empty(),
        "以下 release 构型打开了 `debug-assertions`：\n{}\n\
         这会让 `runtime/env_trust.rs::dev_build()` 的 `cfg!(any(debug_assertions, test))` \
         在**发行包里恒真** ⇒ POLARIS_SINGBOX_PATH / POLARIS_HELPER_PATH 的信任级校验整条失效，\
         逃生门退回裸信任。要在 release 保留断言，先把 `dev_build()` 的判据换成不依赖它的东西\
         （例如构建期注入的显式标记），再改 profile。",
        offenders.join("\n")
    );
}
