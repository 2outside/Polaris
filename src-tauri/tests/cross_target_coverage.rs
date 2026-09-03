//! CI 交叉检查（Linux 腿验 `cfg(windows)` / `cfg(macos)` 分支）的接线门。
//!
//! # 守的是什么
//!
//! Linux CI 腿编译 `polaris` 时，`#[cfg(windows)]` / `#[cfg(target_os = "macos")]` 的分支
//! 根本不参与编译 —— 本地 `cargo build/clippy/test` 对它们的检出力恒为 0。
//! 唯一的检出通道是 `.github/workflows/ci.yml` 里 `Cross-check platform targets` 那一步：
//! 装上 `x86_64-pc-windows-msvc` / `x86_64-apple-darwin` 交叉 target，对派生出的包清单跑
//! `cargo clippy --target <t> -- -D warnings`。本门不重跑那一步，只守「那一步还在、
//! 还是派生形态、豁免表没坏」——那一步本身消失或退化，Windows/macOS 专属代码就重新回到
//! 零检出，而这件事在 Linux 上没有任何运行期表征（同型论证见 `windows_console_suppression.rs`
//! 头部）。
//!
//! # 实测正向对照（抄自旧门，结论依旧成立）
//!
//! 往 `cfg(target_os = "windows")` 分支塞一个类型错误，Linux 上 `cargo build` 照样绿，
//! 交叉 target 上的检查会红 —— 这正是「交叉检查步骤本身没被删/没被削弱」值得单独立门的理由。
//!
//! # 为什么判据是 clippy 不是 check
//!
//! 实测（2026-08-30）：同一份带 `field_reassign_with_default` 的 `cfg(windows)` 代码，
//! `cargo check --target x86_64-pc-windows-gnu` rc=0（绿），`cargo clippy` 同 target rc=101。
//! `cargo check` 对整类 clippy lint 的检出力为零，只抓「编不过」；那批缺陷是「编得过但
//! clippy 拒收」，会一路滑到 windows-2022 腿的 clippy 步才炸。判据字面量必须是
//! `cargo clippy --target`，不能是 `cargo check --target`。
//!
//! # 派生 vs 硬编码
//!
//! CI 步骤已从「硬编码 4 个 `-p` 包名 + `cargo check`」重写为「`cargo metadata` 派生全部
//! workspace 包 + 豁免表排除 + `cargo clippy -D warnings`」：新增 crate 默认被覆盖，不需要
//! 有人记得手动加一行 `-p`。本门断言：派生锚点还在、硬编码清单没有复辟、豁免表本身结构
//! 没烂、豁免面没有无声扩大。

use std::collections::BTreeSet;

use serde_json::Value;

/// 仓库根（`src-tauri/` 的上一级，即 workspace 根）。
fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("src-tauri 必有上级目录")
        .to_path_buf()
}

fn read(rel: &str) -> String {
    let p = repo_root().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("读不到 {}: {e}", p.display()))
}

/// 剥掉整行注释（`#` 开头的行）—— 判据必须落在 `run:` 的可执行内容上，
/// 不能被解释性注释里出现的同名词（比如注释里提一嘴 `cargo check`）污染。
fn ci_yml_stripped() -> String {
    let raw = read(".github/workflows/ci.yml");
    let yml: String = raw
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !yml.is_empty(),
        "ci.yml 剥注释后是空的 —— 取材面坏了，下面所有断言都会恒真"
    );
    yml
}

/// 🔴 交叉步骤还在，且判据口径是 clippy（不是 check）。
///
/// `cargo check` 对 clippy lint 的检出力为零（见文件头实测），口径本身就是本门要守的事。
///
/// 判据必须是**主步那一整行**，不能拆成 `contains("cargo clippy --target")` +
/// `contains("-- -D warnings")` 两条泛锚 —— 反腐烂步（`Cross-target exemptions must
/// still be necessary`）里同样含 `cargo clippy --target` 与 `-- -D warnings` 字面量
/// （只是命令形态是 `-p "$e"`，不是 `"${TARGETS[@]}"`），两条泛锚会被它单独喂饱。
/// 实测（2026-08-30 变异）：只把主步这行回退成 `cargo check --target "$t" --all-targets
/// "${TARGETS[@]}"`、反腐烂步不动，两条泛锚照样绿 —— 判据必须钉死主步的完整命令行。
#[test]
fn cross_step_uses_clippy_not_check() {
    let yml = ci_yml_stripped();
    assert!(
        yml.contains("rustup target add x86_64-pc-windows-msvc x86_64-apple-darwin"),
        "ci.yml 不再安装交叉 target —— 平台特定代码在 Linux 腿上重新变成零检出"
    );
    assert!(
        yml.contains(r#"cargo clippy --target "$t" --all-targets "${TARGETS[@]}" -- -D warnings"#),
        "ci.yml 主步不再是完整的 `cargo clippy --target \"$t\" --all-targets \"${{TARGETS[@]}}\" \
         -- -D warnings` —— 交叉检查步骤被删了，或者退回了检出力为零的 `cargo check`\
         （见文件头实测：check 抓不到 clippy 才拒收的缺陷）。\
         注意判据是全行锚，不是拆成 `cargo clippy --target` / `-- -D warnings` 两条泛锚：\
         反腐烂步里也有这两个字面量，泛锚会被它喂饱，只回退主步时门会假绿（2026-08-30 变异实测）"
    );
}

/// 🔴 覆盖面派生锚点还在：包清单来自 `cargo metadata`，豁免来自 exempt.json，
/// 不是谁手写的静态列表。
#[test]
fn coverage_is_derived_not_hand_maintained() {
    let yml = ci_yml_stripped();
    assert!(
        yml.contains("cargo metadata --no-deps"),
        "ci.yml 不再用 `cargo metadata --no-deps` 派生包清单 —— 新建 crate 可能不会自动被交叉检查覆盖"
    );
    assert!(
        yml.contains("scripts/cross-target-exempt.json"),
        "ci.yml 不再读 scripts/cross-target-exempt.json —— 豁免表失去接线，\
         要么全部包被漏检、要么该豁免的包也被拉去交叉检查而必炸"
    );
}

/// 🔴 不许硬编码回归：旧口径的 `-p polaris-xxx` 字面量不能在 ci.yml 里复活。
///
/// 派生清单存在的意义就是不需要有人手写/维护 `-p` 列表；一旦有人「顺手加回」一份硬编码，
/// 覆盖面就会静默退回旧问题（新建 crate 默认不被覆盖，且没有东西会告诉你）。
#[test]
fn hardcoded_package_list_does_not_come_back() {
    let yml = ci_yml_stripped();
    assert!(
        !yml.contains("-p polaris-"),
        "ci.yml 里出现了 `-p polaris-` 字面量 —— 交叉检查的覆盖面正在从「派生」退回「手写清单」，\
         新建 crate 会重新默认不被覆盖，且没有任何东西会提醒你"
    );
}

/// 跑一次 `cargo metadata --no-deps`，返回 workspace 全部包名。
///
/// 与 CI 步骤同一派生口径：手写/解析 Cargo.toml 会在覆盖面上与 CI 漂移，且代码量大数倍；
/// `cargo metadata` 打错包名会直接红，口径永远和 CI 对齐。
fn workspace_package_names() -> BTreeSet<String> {
    let out = std::process::Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(repo_root())
        .output()
        .unwrap_or_else(|e| panic!("`cargo metadata` 起不来: {e}"));
    assert!(
        out.status.success(),
        "`cargo metadata --no-deps` 退出非 0：{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("`cargo metadata` 输出不是合法 JSON: {e}"));
    meta["packages"]
        .as_array()
        .expect("`cargo metadata` 输出里没有 `packages` 数组 —— 输出形状变了，取材面坏了")
        .iter()
        .map(|p| {
            p["name"]
                .as_str()
                .expect("某个 package 条目没有 `name` 字段")
                .to_string()
        })
        .collect()
}

/// CI 主步实际遍历（且已 `rustup target add` 安装）的交叉 triple 集。
///
/// 从 ci.yml 的 `rustup target add …` 行派生，而不是在本文件再写死一份：
/// 那一行已被 [`cross_step_uses_clippy_not_check`] 钉住，是「哪些 triple 真的会被检查」
/// 的单一真相源 —— CI 增删 triple 时本判据自动跟随，不会漂成第二份清单。
fn ci_cross_targets() -> BTreeSet<String> {
    let yml = ci_yml_stripped();
    let targets: BTreeSet<String> = yml
        .lines()
        .filter_map(|l| l.trim().strip_prefix("rustup target add "))
        .flat_map(str::split_whitespace)
        .map(str::to_string)
        .collect();
    assert!(
        !targets.is_empty(),
        "ci.yml 里解析不出任何 `rustup target add` 的 triple —— 取材面坏了，         豁免 targets 的成员校验会恒真"
    );
    targets
}

/// 解析豁免表为 JSON 对象（key = 包名）。
fn exempt_table() -> serde_json::Map<String, Value> {
    let raw = read("scripts/cross-target-exempt.json");
    let v: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("scripts/cross-target-exempt.json 不是合法 JSON: {e}"));
    v.as_object()
        .unwrap_or_else(|| panic!("scripts/cross-target-exempt.json 顶层不是一个 JSON 对象"))
        .clone()
}

/// 🔴 豁免表结构没烂：每条 key 是真包名，`targets` 非空**且每个值都是 CI 主步真正遍历的
/// triple**，`why` 是一段站得住的中文说明。
///
/// 没有这一条，豁免表就只是一份没人守的自由文本：拼错包名会静默豁免不到任何东西，
/// 空 `targets` 等于白豁免，敷衍的 `why` 让读者判断不了这条豁免还该不该在；而 `targets`
/// 若填了 CI 不遍历的 triple，反腐烂步会对它 clippy 必败并误判「豁免仍必要」——
/// 豁免的过期闹钟被永久关掉。
#[test]
fn exemption_entries_are_well_formed() {
    let table = exempt_table();
    let packages = workspace_package_names();
    let ci = ci_cross_targets();
    let mut bad = Vec::new();
    for (name, entry) in &table {
        if !packages.contains(name) {
            bad.push(format!(
                "  {name}：不是 workspace 包名 —— 拼错了，或者包被重命名/删除了，这条豁免豁免不到任何东西"
            ));
            continue;
        }
        let targets = entry
            .get("targets")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if targets.is_empty() {
            bad.push(format!(
                "  {name}：`targets` 缺失或为空 —— 这条豁免实际上不豁免任何 target"
            ));
        }
        // `targets` 的每个值必须落在 CI 主步真正遍历的 triple 集内（复审 2026-08-31
        // tests12域-判据）。输入对差：旧判据只查非空 —— 把 targets 改成一个未安装的
        // triple（如 `aarch64-unknown-linux-musl`）旧绿新红；这种改法会让反腐烂步的
        // `cargo clippy --target <未安装>` 恒败，而它把「clippy 失败」判成「豁免仍必要」
        // ⇒ 豁免的过期闹钟被永久关掉，且没有任何门转红。现有两条豁免（msvc/darwin 双
        // triple）旧新同判。
        for t in &targets {
            let Some(t) = t.as_str() else {
                bad.push(format!("  {name}：`targets` 里有非字符串成员 {t}"));
                continue;
            };
            if !ci.contains(t) {
                bad.push(format!(
                    "  {name}：target `{t}` 不在 CI 主步遍历的 triple 集 {ci:?} 内 ——                      反腐烂步对它的 clippy 必败并被误读成「豁免仍必要」，过期闹钟从此永久哑火"
                ));
            }
        }
        let why_len = entry
            .get("why")
            .and_then(Value::as_str)
            .map(|s| s.chars().count())
            .unwrap_or(0);
        if why_len <= 40 {
            bad.push(format!(
                "  {name}：`why` 只有 {why_len} 个字符 —— 豁免必须写清楚具体卡在哪一步、\
                 为什么本机和 CI 都过不了，不能敷衍"
            ));
        }
    }
    assert!(bad.is_empty(), "\n豁免表结构有问题：\n{}\n", bad.join("\n"));
}

/// 🔴 豁免面反哨兵：条目数必须落在 `[1, 3]`。
///
/// 0 条 = 有人清空了豁免表却没有在本机说明原因 —— CI 上一批依赖 host 没有的 C 工具链的包
/// 会同时炸；超过 3 条 = 豁免面在扩大，交叉检查实际覆盖的东西越来越少，必须先说清为什么
/// 又多豁免了一个包，而不是让门自己适应放行。
#[test]
fn exemption_surface_is_bounded() {
    let table = exempt_table();
    let n = table.len();
    assert!(
        n >= 1,
        "豁免表是空的 —— 清空豁免表须先在本机说明原因，否则 CI 上一堆包会同时炸"
    );
    assert!(
        n <= 3,
        "豁免表有 {n} 条 —— 豁免面在扩大，先说清为什么，而不是顺手再加一条"
    );
}
