//! 次级窗口的 Tauri plugin capability 契约：从真实入口求本地 import 闭包，
//! 再把实际 plugin invoke 与生成的 ACL manifest、逐窗 capability 精确对拍。

use super::*;

/// 次级窗入口的**本地静态 import 闭包**。
///
/// capability 是按 window 生效的，但插件调用常在 `ui/src/lib/` 共享模块里（tray 的
/// `notifyDesktop` 就是实例）；只扫 `ui/src/<label>/` 会漏掉这类实际可达的调用。这里刻意只
/// 认识静态 ES import / re-export 与**字面量** dynamic import 的模块说明符：相对路径与 `@/`
/// 均递归展开；动态目标不可判、不完整的 import 语句、或解析不到的本地路径一律失败关闭。它不是
/// TS parser：需要超出这套可审计边界的加载方式时，应先把 capability 边界改成静态可判的入口。
fn secondary_window_source_closure(
    label: &str,
) -> Result<Vec<(std::path::PathBuf, String)>, String> {
    let root = std::fs::canonicalize(ui_src())
        .map_err(|error| format!("ui/src 路径规范化失败：{error}"))?;
    let entry = [
        root.join(label).join("main.ts"),
        root.join(label).join("main.tsx"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .and_then(|path| std::fs::canonicalize(path).ok())
    .ok_or_else(|| format!("window {label:?} 没有 main.ts(x) 入口"))?;
    let mut pending = vec![entry];
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    while let Some(path) = pending.pop() {
        if !seen.insert(path.clone()) {
            continue;
        }
        let raw = std::fs::read_to_string(&path)
            .map_err(|error| format!("读 window {label:?} 的 {} 失败：{error}", path.display()))?;
        let source = strip_ts_comments(&raw);
        for specifier in static_module_specifiers(&source)? {
            if let Some(next) = resolve_local_ui_module(&root, &path, &specifier)? {
                pending.push(next);
            }
        }
        out.push((path, source));
    }
    if out.is_empty() {
        return Err(format!("window {label:?} 的本地静态 import 闭包为空"));
    }
    Ok(out)
}

/// 找出源码中位于代码态（含模板 `${…}` 表达式、排除字符串 / 模板文本 / 正则）的关键字位置。
/// `strip_ts_comments` 已先剥注释；这里继续做字面量词法分层，既不让文案误报，也不让
/// `await import()` / `return import()` / 模板表达式里的 import 逃出依赖闭包。
fn code_keyword_positions(src: &str, keyword: &str) -> Vec<usize> {
    fn scan(
        src: &str,
        keyword: &[u8],
        mut i: usize,
        mut template_expression_depth: usize,
        out: &mut Vec<usize>,
    ) -> usize {
        let bytes = src.as_bytes();
        while i < bytes.len() {
            match bytes[i] {
                b'\'' | b'"' => {
                    let quote = bytes[i];
                    i += 1;
                    let mut escaped = false;
                    while i < bytes.len() {
                        let current = bytes[i];
                        i += 1;
                        if escaped {
                            escaped = false;
                        } else if current == b'\\' {
                            escaped = true;
                        } else if current == quote || current == b'\n' {
                            break;
                        }
                    }
                }
                b'`' => {
                    i += 1;
                    let mut escaped = false;
                    while i < bytes.len() {
                        let current = bytes[i];
                        if escaped {
                            escaped = false;
                            i += 1;
                        } else if current == b'\\' {
                            escaped = true;
                            i += 1;
                        } else if current == b'`' {
                            i += 1;
                            break;
                        } else if current == b'$' && bytes.get(i + 1) == Some(&b'{') {
                            i = scan(src, keyword, i + 2, 1, out);
                        } else {
                            i += 1;
                        }
                    }
                }
                b'{' if template_expression_depth > 0 => {
                    template_expression_depth += 1;
                    i += 1;
                }
                b'}' if template_expression_depth > 0 => {
                    template_expression_depth -= 1;
                    i += 1;
                    if template_expression_depth == 0 {
                        return i;
                    }
                }
                b'/' if regex_can_start(&src[..i]) => {
                    i += 1;
                    let mut escaped = false;
                    let mut in_class = false;
                    while i < bytes.len() {
                        let current = bytes[i];
                        i += 1;
                        if escaped {
                            escaped = false;
                        } else {
                            match current {
                                b'\\' => escaped = true,
                                b'[' => in_class = true,
                                b']' => in_class = false,
                                b'/' if !in_class => break,
                                b'\n' => break,
                                _ => {}
                            }
                        }
                    }
                }
                _ if bytes[i..].starts_with(keyword) => {
                    let ident =
                        |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$');
                    let before_ok = i == 0 || !ident(bytes[i - 1]);
                    let after = i + keyword.len();
                    let after_ok = after == bytes.len() || !ident(bytes[after]);
                    if before_ok && after_ok {
                        out.push(i);
                        i = after;
                    } else {
                        i += 1;
                    }
                }
                _ => i += 1,
            }
        }
        i
    }

    let mut out = Vec::new();
    scan(src, keyword.as_bytes(), 0, 0, &mut out);
    out
}

/// 从已剥注释的源码中取静态 import / re-export 的模块说明符。
///
/// 本仓 formatter 使 import/export 语句以行首关键字开始、以分号结束；若未来写法突破这个小
/// 静态子集，宁可测试转红，也不把「没扫到」伪装成「没有插件调用」。字面量 dynamic import
/// 与静态 import 同样进入闭包（JSON/CSS 等静态资产仍由 resolver 排除）；无法判定的动态目标失败关闭。
fn static_module_specifiers(src: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut statements: Vec<(usize, &str)> = ["import", "export"]
        .iter()
        .flat_map(|keyword| {
            code_keyword_positions(src, keyword)
                .into_iter()
                .map(move |position| (position, *keyword))
        })
        .collect();
    statements.sort_unstable();
    for (position, keyword) in statements {
        let rest = &src[position + keyword.len()..];
        let trimmed = rest.trim_start();
        if keyword == "import" && trimmed.starts_with('.') {
            continue; // `import.meta` 不是加载边。
        }
        if keyword == "import" && trimmed.starts_with('(') {
            let body = trimmed[1..].trim_start();
            let Some((specifier, _)) = quoted_literal(body) else {
                return Err("动态 import 的目标不可静态判定，拒绝扫描面静默漏项".into());
            };
            if is_local_ui_specifier(specifier) {
                out.push(specifier.to_owned());
            }
            continue;
        }
        let statement = trimmed
            .split_once(';')
            .map(|(statement, _)| statement)
            .ok_or_else(|| format!("{keyword} 语句没有分号，无法静态解析模块说明符"))?;
        // `export function` / `export const` 是本模块自己的导出，不带依赖边；只有 re-export
        // (`export { x } from '…'`) 才进入 closure。不能把函数体里的字符串误当模块说明符。
        if keyword == "export" && !statement.contains(" from ") {
            continue;
        }
        let Some((_, specifier)) = module_specifier(statement) else {
            return Err(format!("{keyword} 语句没有可解析的模块说明符：{statement}"));
        };
        out.push(specifier.to_owned());
    }
    Ok(out)
}

fn quoted_literal(src: &str) -> Option<(&str, &str)> {
    let quote = src.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let body = &src[quote.len_utf8()..];
    let end = body.find(quote)?;
    Some((&body[..end], &body[end + quote.len_utf8()..]))
}

fn is_local_ui_specifier(specifier: &str) -> bool {
    specifier.starts_with("./") || specifier.starts_with("../") || specifier.starts_with("@/")
}

fn resolve_local_ui_module(
    root: &std::path::Path,
    from: &std::path::Path,
    specifier: &str,
) -> Result<Option<std::path::PathBuf>, String> {
    if !is_local_ui_specifier(specifier) {
        return Ok(None); // npm / Tauri plugin 等外部模块不在本仓源码闭包内。
    }
    let base = if let Some(rest) = specifier.strip_prefix("@/") {
        root.join(rest)
    } else {
        from.parent()
            .expect("source file 必有父目录")
            .join(specifier)
    };
    // CSS / JSON 等静态资产不是 TS 调用面；显式 TS/TSX 必须精确存在。其它点号可能只是模块
    // basename（如 `flag-assets.generated` → `.generated.ts`），仍走 extensionless 候选，不能误判。
    // `Path::extension()` 会把 `./types/foo` 里的 leading dot 误当扩展分隔符；这里按说明符
    // 的最后路径段判断显式扩展名，未显式扩展的一律走 TS/TSX/index 候选。
    let explicit_ext = specifier
        .rsplit('/')
        .next()
        .and_then(|name| name.rsplit_once('.').map(|(_, ext)| ext));
    if let Some(ext) = explicit_ext {
        if matches!(ext, "css" | "json" | "svg" | "png" | "webp" | "ico") {
            return Ok(None);
        }
        if matches!(ext, "ts" | "tsx") {
            return base
                .is_file()
                .then(|| std::fs::canonicalize(&base))
                .transpose()
                .map_err(|error| format!("本地 import {specifier:?} 路径规范化失败：{error}"))?
                .ok_or_else(|| {
                    format!(
                        "本地 import {specifier:?} 解析到不存在文件 {}",
                        base.display()
                    )
                })
                .map(Some);
        }
    }
    let candidates = [
        base.with_extension("ts"),
        base.with_extension("tsx"),
        base.join("index.ts"),
        base.join("index.tsx"),
    ];
    for candidate in &candidates {
        if candidate.is_file() {
            return std::fs::canonicalize(candidate)
                .map(Some)
                .map_err(|error| format!("本地 import {specifier:?} 路径规范化失败：{error}"));
        }
    }
    Err(format!(
        "本地 import {specifier:?} 找不到 .ts/.tsx/index 模块（from={}；candidates={:?}）",
        from.display(),
        candidates
    ))
}

/// `invoke<T>('plugin:name|command', …)` 的真实 plugin 命令面。
///
/// 只认调用的**首参**，不把普通字符串、文档或测试文本当调用点；源码已在入口处剥注释且测试文件
/// 不进入 closure。命中 plugin 前缀但不能拆成 `plugin:<name>|<command>` 是配置边界不明，直接失败。
fn plugin_invokes(src: &str) -> Result<std::collections::BTreeSet<String>, String> {
    let mut out = std::collections::BTreeSet::new();
    for at in code_keyword_positions(src, "invoke") {
        let before_args = &src[at + "invoke".len()..];
        let Some(open) = before_args.find('(') else {
            continue;
        };
        let between = before_args[..open].trim();
        if !between.is_empty() && !(between.starts_with('<') && between.ends_with('>')) {
            continue;
        }
        let args = before_args[open + 1..].trim_start();
        let Some((literal, _)) = quoted_literal(args) else {
            continue;
        };
        if !literal.starts_with("plugin:") {
            continue;
        }
        let Some((plugin, command)) = literal
            .strip_prefix("plugin:")
            .and_then(|rest| rest.split_once('|'))
        else {
            return Err(format!(
                "plugin invoke {literal:?} 不是 plugin:<name>|<command> 形态"
            ));
        };
        if plugin.is_empty() || command.is_empty() {
            return Err(format!("plugin invoke {literal:?} 含空 plugin 或 command"));
        }
        out.insert(literal.to_owned());
    }
    Ok(out)
}

/// 生成的 Tauri ACL manifest 是插件 command → permission 的唯一机器真值；不要在测试里再抄一张
/// plugin→permission 表。`plugin:default` / 自定义 permission set 均在这里递归展开。
#[derive(Default)]
struct PluginAclManifest {
    command_permissions: std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
    permission_sets: std::collections::BTreeMap<String, Vec<String>>,
}

fn plugin_acl_manifest() -> PluginAclManifest {
    let value: serde_json::Value =
        serde_json::from_str(&crate_file("gen/schemas/acl-manifests.json"))
            .expect("生成的 ACL manifest 必须是合法 JSON");
    let plugins = value
        .as_object()
        .expect("ACL manifest 顶层必须是 plugin object");
    let mut out = PluginAclManifest::default();
    for (plugin, manifest) in plugins {
        let prefix = format!("{plugin}:");
        let permissions = manifest["permissions"]
            .as_object()
            .unwrap_or_else(|| panic!("ACL manifest {plugin} 缺 permissions object"));
        for (permission, detail) in permissions {
            let full = format!("{prefix}{permission}");
            let commands = detail["commands"]["allow"]
                .as_array()
                .unwrap_or_else(|| panic!("ACL manifest {full} 缺 commands.allow"));
            for command in commands {
                let command = command
                    .as_str()
                    .unwrap_or_else(|| panic!("ACL manifest {full} 的 command 非字符串"));
                out.command_permissions
                    .entry(format!("plugin:{plugin}|{command}"))
                    .or_default()
                    .insert(full.clone());
            }
        }
        let mut sets = manifest["permission_sets"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        if let Some(default) = manifest.get("default_permission") {
            sets.insert("default".to_owned(), default.clone());
        }
        for (name, set) in sets {
            let members = set["permissions"]
                .as_array()
                .unwrap_or_else(|| {
                    panic!("ACL manifest permission set {plugin}:{name} 缺 permissions")
                })
                .iter()
                .map(|member| {
                    let member = member.as_str().unwrap_or_else(|| {
                        panic!("ACL manifest permission set {plugin}:{name} 成员非字符串")
                    });
                    format!("{prefix}{member}")
                })
                .collect();
            out.permission_sets
                .insert(format!("{plugin}:{name}"), members);
        }
    }
    assert!(
        !out.command_permissions.is_empty() && !out.permission_sets.is_empty(),
        "ACL manifest 解析为空，plugin capability 门会恒绿"
    );
    out
}

fn expanded_plugin_permissions(
    granted: &[String],
    manifest: &PluginAclManifest,
) -> std::collections::BTreeSet<String> {
    fn expand(
        permission: &str,
        manifest: &PluginAclManifest,
        visiting: &mut std::collections::BTreeSet<String>,
        out: &mut std::collections::BTreeSet<String>,
    ) {
        if !visiting.insert(permission.to_owned()) {
            panic!("ACL permission set 出现循环：{permission}");
        }
        if let Some(members) = manifest.permission_sets.get(permission) {
            for member in members {
                expand(member, manifest, visiting, out);
            }
        } else if permission.contains(':') {
            out.insert(permission.to_owned());
        }
        visiting.remove(permission);
    }
    let mut out = std::collections::BTreeSet::new();
    for permission in granted {
        expand(
            permission,
            manifest,
            &mut std::collections::BTreeSet::new(),
            &mut out,
        );
    }
    out
}

#[test]
fn import_closure_lexes_dynamic_imports_in_every_code_position() {
    let source = strip_ts_comments(
        r#"
import { a } from './a';
const first = await import('@/b');
function load() { return import('./c'); }
const nested = `${condition ? import('./d') : 'import(\"./text\")'}`;
const prose = "return import('./not-code')";
const pattern = /import\(['\"]\.\/not-code/;
// return import('./comment');
void import('external-package');
void import.meta.url;
"#,
    );
    assert_eq!(
        static_module_specifiers(&source).expect("字面量 dynamic import 应可判"),
        ["./a", "@/b", "./c", "./d"]
    );
    assert!(static_module_specifiers("const x = import(target);")
        .expect_err("非字面量 dynamic import 必须失败关闭")
        .contains("不可静态判定"));
}

#[test]
fn plugin_invoke_inventory_ignores_literals_but_sees_member_calls() {
    let source = r#"
const prose = "invoke('plugin:fake|text')";
const pattern = /invoke\('plugin:fake\|regex/;
void invoke('plugin:notification|notify');
void window.__TAURI_INTERNALS__.invoke('plugin:os|platform');
"#;
    assert_eq!(
        plugin_invokes(source).expect("plugin invoke 面应可判"),
        [
            "plugin:notification|notify".to_owned(),
            "plugin:os|platform".to_owned(),
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn secondary_windows_plugin_calls_are_capability_covered() {
    // 能力集按 window label 生效（default.json 只覆盖 "main"）。次级窗是**独立 window**；它的
    // 本地 import 闭包里任一真实 plugin invoke 都必须被本窗 capability 覆盖。dialog 的 import /
    // global 覆写形态继续走既有精确检测面，不能因泛化而降级。
    //
    // 窗口清单**不再手写**：原来写死 `[("tray", …)]`，于是 `update-popup` 整个窗漏在射程外 ——
    // 它有前端入口目录、有 Rust 建窗路径（`runtime::update_popup::POPUP_LABEL`），却一份
    // capability 都没有 ⇒ 零权限，`listen()` 真机被 ACL 拒，而调用点是 `.catch(() => {})`
    // ⇒ 静默失效，连报错都看不到。改为「前端入口目录 × capabilities/*.json」双向驱动。
    let by_window = capabilities_by_window();
    let dirs = secondary_window_dirs();
    // 清单本身要**钉死**：只断言「清单里的窗都被覆盖」是杀不掉「有人把清单写回硬编码」的 ——
    // 原缺陷正是这个形态（写死 [("tray", …)] ⇒ update-popup 整个窗不在射程内，永远绿）。
    // 新增次级窗时本条先红，逼人当场确认 capability 与扫描面都跟上了。
    assert_eq!(
            dirs,
            ["tray", "update-popup"],
            "次级窗前端入口目录清单变了（ui/src/<label>/main.ts(x)）—— 新窗必须同时有 capability 覆盖；\
             若这里为空说明扫描面塌了，本测将退化成恒绿"
        );

    let acl = plugin_acl_manifest();
    for label in &dirs {
        let perms = by_window.get(label).unwrap_or_else(|| {
            panic!(
                "window \"{label}\" 有前端入口目录 ui/src/{label}/ 却没有任何 capability 覆盖它 \
                     ⇒ 该窗零权限：listen / 插件命令真机一律被 ACL 拒（前端常写 .catch(() => {{}}) \
                     ⇒ 静默失效）。请在 capabilities/ 下补一份 windows 含 \"{label}\" 的能力集"
            )
        });
        let files = secondary_window_source_closure(label)
            .unwrap_or_else(|why| panic!("window {label:?} 的本地 import 闭包不可判：{why}"));
        assert!(
            !files.is_empty(),
            "window \"{label}\" 一份前端源码都没扫到 —— 空扫描面 = 恒绿，本条形同虚设"
        );
        let expanded = expanded_plugin_permissions(perms, &acl);
        let mut required_notification_permissions = std::collections::BTreeSet::new();
        for (path, src) in &files {
            // 与主窗同一条 dialog 检测面（invoke 裸串 ∪ 全局覆写 ∪ 具名 import）。
            let need = required_dialog_perms(src)
                .unwrap_or_else(|why| panic!("{}：{why}", path.display()));
            for perm in need {
                assert!(
                        perms.iter().any(|p| p == perm),
                        "{} 属 window \"{label}\"，用了 dialog 命令但该 window 的 capability 未授 {perm}",
                        path.display()
                    );
            }
            for command in plugin_invokes(src)
                .unwrap_or_else(|why| panic!("{}：plugin invoke 形态不可判：{why}", path.display()))
            {
                let accepted = acl.command_permissions.get(&command).unwrap_or_else(|| {
                    panic!(
                        "{} 调用了 {command}，但生成 ACL manifest 找不到该 plugin command 的 permission",
                        path.display()
                    )
                });
                assert!(
                    accepted.iter().any(|permission| expanded.contains(permission)),
                    "{} 属 window \"{label}\"，调用 {command} 需要 {:?} 之一，但 capability 未授（直接或经 permission set 展开）",
                    path.display(), accepted
                );
                let notification: std::collections::BTreeSet<String> = accepted
                    .iter()
                    .filter(|permission| permission.starts_with("notification:"))
                    .cloned()
                    .collect();
                if !notification.is_empty() {
                    assert_eq!(
                        notification.len(),
                        1,
                        "{command} 在 ACL manifest 里有多个 notification permission，最小授权判据不再明确"
                    );
                    required_notification_permissions.extend(notification);
                }
            }
        }
        // tray 的通知只来自 closure 内的实际三条 plugin command。禁止用 notification:default 以一把
        // 伞掩住多余能力；新增真实通知命令时，这里会先红，逼人把最小权限同调用面一起更新。
        if label == "tray" {
            let direct_notification: std::collections::BTreeSet<String> = perms
                .iter()
                .filter(|permission| permission.starts_with("notification:"))
                .cloned()
                .collect();
            assert!(
                !direct_notification.contains("notification:default"),
                "tray 不得授 notification:default；只授 import 闭包中实际调用的 notification command"
            );
            assert_eq!(
                direct_notification, required_notification_permissions,
                "tray 的 notification 授权必须与本地 import 闭包里真实 plugin command 一一相等"
            );
        }
    }
}
