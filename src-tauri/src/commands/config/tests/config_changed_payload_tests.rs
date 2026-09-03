use crate::commands::guard_scan::{strip_block_comments, strip_line_comments, top_level_fn_body};
use crate::test_support::{crate_code, repo_file};

/// 三个渲染端消费点（仓内相对路径 → 源码）。
///
/// 用 `include_str!` 而不是运行期读盘：文件被挪走 = **编译失败**，而不是守卫静默扫了个空串
/// 然后断言恒真。仓内已有同款先例（本文件的 `config-version.fixture.json`）。
///
/// # 跨语言耦合是刻意的
///
/// 这三份前端源码被直接嵌进 Rust 测试判据：`App.tsx` / `TrayMenu.tsx` / `use-config.ts` 任一个
/// 多挂或删掉一个 `.onChanged(` 都会让 `cargo test -p polaris` 转红（见下面
/// `every_consumer_discards_the_payload` 的数量断言）。只改前端的人未必会想到去跑 Rust 测试——
/// 灯下记账：
///
/// CI 覆盖面（`.github/workflows/ci.yml` 实测）：`pull_request` 触发**无路径过滤**，纯改这三个
/// 文件的 PR 仍会跑 `cargo test --workspace`，本测试正常拦截。只有**绕过 PR 直接 push 到
/// main**、且改动只命中 `on.push.paths-ignore` 里的 `ui/**`/`**.md`/`docs/**` 时，整条 Rust 链
/// （含本测试）才会被跳过——那是 push 主干的调试期额度优化，不针对本测试。结论：这道门在
/// 「PR 流程」下始终执行；只在「绕过 PR 的直接 push」这一条路径上失效。
fn ts_consumers() -> Vec<(&'static str, String)> {
    vec![
        ("ui/src/App.tsx", repo_file("ui/src/App.tsx")),
        (
            "ui/src/tray/TrayMenu.tsx",
            repo_file("ui/src/tray/TrayMenu.tsx"),
        ),
        (
            "ui/src/components/screens/settings/use-config.ts",
            repo_file("ui/src/components/screens/settings/use-config.ts"),
        ),
    ]
}

/// 发射点：`app.emit(EVENT_CONFIG_CHANGED, …)` 的实参必须是空对象字面量 `json!({})`。
///
/// 判据是**对实参的正向等值断言**，不是负向枚举——旧版判据是「实参里不出现 `cfg`/`newValue`
/// 这两个今天恰好在用的标识符」，换个变量名（`broadcast_config_changed_with` 的形参本身就叫
/// `new_value`）或直接把载荷内容写成字面量，两条禁词一条都不命中，守卫全绿而配置树已在路上。
/// 判据按配对括号取实参，不要求 emit 与其实参写在同一行（rustfmt 拆行不影响本判据）。
///
/// 扫**全部** `app.emit(` 调用点，只对事件名匹配 `EVENT_CONFIG_CHANGED` 的逐一断言载荷、且
/// 数量必须恰为 1——而不是只看函数体里第一个 `app.emit(`：只看第一个会两头出错：本函数如果
/// 先发别的事件（如隐私模式跃迁）再发 configChanged，事件名断言会误红；反过来，如果
/// configChanged 之后又插入第二个带载荷的 `app.emit(EVENT_CONFIG_CHANGED, …)`，第一个合规、
/// 第二个违规，只看第一个会让第二个静默漏检。数量断言与消费方那侧（`sites == 1`）同规：多插
/// 一个**合规**的重复 emit 同样要停下来裁定——重复广播 = 三个前端消费方各多跑一次全量
/// `config_get`，正是本批要防的白付出。
///
/// 事件名不匹配时不再直接跳过不留痕迹：扫到的全部事件名收进 `seen_events`，0 命中时打进失败
/// 消息——有人把 `EVENT_CONFIG_CHANGED` 改写成全路径或换了个本地别名，emit 明明还在原地，
/// 消息也不会说成「发射点没了」这种指错方向的话。
///
/// 牙：把载荷改回 `json!({ "config": new_value })`（或任何非空内容，哪怕换个变量名）→ 转红；
/// 在合规 emit 之后再插一个**同样合规**的 `app.emit(EVENT_CONFIG_CHANGED, json!({}))` → 数量
/// 断言转红；把 `EVENT_CONFIG_CHANGED` 换成一个不存在的名字 → 转红且消息里能看到扫到的事件名
/// 不含它。
#[test]
fn emit_site_carries_no_config_content() {
    let broadcast_body = top_level_fn_body(
        &crate_code("commands/config.rs"),
        "pub(crate) fn broadcast_config_changed_with(",
    );
    // 切点自检①：扫到的确实是那个生产函数体。
    assert!(
        broadcast_body.contains("strip_privacy_secrets(&mut cfg)"),
        "扫到的不是 broadcast_config_changed_with 的函数体 —— 守卫已失去判据"
    );
    assert!(
        broadcast_body.contains("emit_config_changed_signal(app)"),
        "普通配置汇流点必须复用 signal-only 发射函数，禁止另立第二个 configChanged emit"
    );
    // 切点自检②：判据词在本文件的测试代码里也各有一份，切片若漏封顶就会被自己喂饱 ——
    // 那正是「源码级判据被自己污染」的形态。
    assert!(
        !broadcast_body.contains("config_changed_payload_tests"),
        "切片切进了本测试模块，判据会被自己写的字面量喂饱"
    );
    let body = top_level_fn_body(
        &crate_code("commands/config.rs"),
        "pub(crate) fn emit_config_changed_signal(",
    );
    assert!(
        !body.contains("config_changed_payload_tests"),
        "signal-only 发射函数切片切进了测试模块"
    );

    let mut config_changed_emits = 0usize;
    // 扫到的每个 emit 的事件名，仅用于失败诊断——事件名对不上时把它打进消息，不能只说
    // 「发射点没了」（那会把排查方向指反：emit 明明在原地，只是名字变了）。
    let mut seen_events: Vec<&str> = Vec::new();
    for (call_at, _) in body.match_indices("app.emit(") {
        let args_at = call_at + "app.emit(".len();
        // 按配对括号取到本次调用的实参列表（而非要求「事件名 + 逗号」紧跟在 `app.emit(`
        // 后面同一行）。
        let mut depth = 1i32;
        let mut close = None;
        for (k, ch) in body[args_at..].char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(k);
                        break;
                    }
                }
                _ => {}
            }
        }
        let close = close.expect("app.emit(...) 括号未配对 —— 发射调用格式已变，需要更新守卫");
        let args = body[args_at..args_at + close].trim();
        let event = args.split_once(',').map_or(args, |(event, _)| event.trim());
        seen_events.push(event);
        if event != "EVENT_CONFIG_CHANGED" {
            continue; // 别的事件，不归本守卫管。
        }
        config_changed_emits += 1;
        if let Some((_, payload)) = args.split_once(',') {
            let payload = payload.trim().trim_end_matches(',').trim();
            assert_eq!(
                payload, "json!({})",
                "configChanged 的发射载荷不是空对象字面量（实参：`{payload}`）——\
                     要发载荷必须用剥过隐私的那一份（`strip_privacy_secrets` 之后），且必须\
                     同步改本断言"
            );
        } // 单参数 emit（无逗号）：天然无载荷可言，直接过。
    }
    // 与消费方那侧（`sites == 1`）同规：增减都要停下来人工裁定，不止拦删除。多插一个**合规**
    // 的 `app.emit(EVENT_CONFIG_CHANGED, json!({}))` 一样是重复广播——三个前端消费方各多跑一次
    // 全量 `config_get`、托盘多一次 reconcile，正是本批要防的那类白付出。
    assert_eq!(
        config_changed_emits, 1,
        "configChanged 的发射点数不是 1（实为 {config_changed_emits}）。本函数体内扫到的全部 \
             emit 事件名：{seen_events:?}"
    );
}

/// 四个消费方（三个渲染端 + Rust 侧托盘汇流）必须全部丢弃 payload。
///
/// 判据是「形参表为空」，不是字面 `() =>` 前缀匹配。TS 可赋值性规则是「source **必需**形参数
/// ≤ target 形参数」，rest 形参在这条规则下视作「零个必需形参」——`(...a: unknown[]) => void`、
/// `async (...a: unknown[]) => void`，以及先具名再传入的
/// `const h = (...a: unknown[]) => {…}; onChanged(h)`，**全部**能合法赋给
/// `onChanged(listener: () => void)`（签名见 `ui/src/ipc/api-client.ts`）——类型层完全挡不住
/// rest 参数，这正是本结构守卫存在的理由；「非箭头字面量就退回类型层」这个论证只在「箭头函数
/// 只有裸 `(...) =>` 一种写法」时成立，`async` 前缀与具名传参都会绕开它。
///
/// 故判定前先剥可选的 `async ` 前缀，落到真正的形参括号上再比较是否为 `()`；剥完仍不是 `(`
/// 开头（裸标识符、`function` 表达式、或其它未识别形态，如无括号的单参箭头 `x => …`）
/// **不静默放过**——源码扫描判不出那类实参的形参表，直接 panic 要求人工裁定。
///
/// `function` 表达式**故意**没有像 `async` 那样被剥前缀特殊处理，即便它形参表可以是空
/// `()`——因为 `function () { … }` 会绑定 `arguments`，`arguments[0]` 照样能读到完整 payload；
/// 箭头函数不绑定 `arguments`，才是「形参表空 ⇒ 读不到 payload」这条判据成立的前提。把
/// `function` 也纳入「形参表为空即放行」会在这条新腿上开一个箭头函数没有的洞，故与裸标识符
/// 归同一类：源码扫描判不全，一律 panic 要求人工裁定，不假定它已被类型层挡住。
///
/// 牙：`onChanged(() => …)` 改成 `onChanged((...args: unknown[]) => …)`（或加 `async`）→
/// 转红；改成 `onChanged(onCfg)`（具名回调）或 `onChanged(function () { … })` → panic 要求
/// 人工裁定。
#[test]
fn every_consumer_discards_the_payload() {
    const CALL: &str = ".onChanged(";
    for (path, src) in ts_consumers() {
        // 先剥块注释（含 JSDoc）再剥整行注释：注释里出现调用形态（如 `use-config.ts` 头部 JSDoc
        // 提到的 `` `configApi.onChanged` ``）会喂饱/顶红判据（与 Rust 侧剥行注释同一理由）。
        let src = strip_line_comments(&strip_block_comments(&src));
        // **自曝**：`strip_block_comments` 找不到闭合就不清空、原样保留——那份「不作为」必须
        // 自己被看见，不能只在剩余文本恰好含 `.onChanged(` 时才被数量断言间接带出来（那是零
        // 信号的巧合绿）。扫一遍剥完的文本，任何一行 trim 后仍以 `/*`/`{/*` 开头，说明这正是
        // 一次未闭合起笔被原样吐了回来。
        for (n, line) in src.lines().enumerate() {
            let t = line.trim_start();
            assert!(
                !t.starts_with("/*") && !t.starts_with("{/*"),
                "{path}:{} 有一个块注释起笔从未找到闭合 `*/`，strip_block_comments 按 doc 原样\
                     保留了它——这段残留文本没有被清空扫描过，可能藏着一次伪造/丢失的 `.onChanged(` \
                     订阅，需要人工核实",
                n + 1
            );
        }
        let mut sites = 0usize;
        for (i, _) in src.match_indices(CALL) {
            sites += 1;
            let rest = &src[i + CALL.len()..];
            let rest = rest.trim_start();
            // 剥 `async `：`async (...) => …` 与 `(...) => …` 的形参表位置相同。`function`
            // 前缀不剥——理由见上面 doc 的 `arguments` 那段。
            let param_scan_at = rest.strip_prefix("async").map_or(rest, str::trim_start);
            match param_scan_at.strip_prefix('(') {
                Some(after_open) => {
                    // 形参表 = 首个 `(` 到与之配对的 `)`（含首尾括号）。
                    let mut depth = 1i32;
                    let mut close = None;
                    for (k, ch) in after_open.char_indices() {
                        match ch {
                            '(' => depth += 1,
                            ')' => {
                                depth -= 1;
                                if depth == 0 {
                                    close = Some(k);
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    let close = close.unwrap_or_else(|| {
                        panic!(
                            "{path} 的 `.onChanged(` 实参括号未配对（实处：`{}`）",
                            rest.chars().take(60).collect::<String>()
                        )
                    });
                    let params = &param_scan_at[..close + 2];
                    assert_eq!(
                        params, "()",
                        "{path} 的 configChanged 订阅读了 payload —— 事件已是无载荷信号，读到的\
                             只会是 `{{}}`。形参表：`{params}`"
                    );
                }
                None => panic!(
                    "{path} 的 `.onChanged(` 实参不是箭头函数字面量（实处：`{}`）——具名回调 / \
                         `function` 表达式源码扫描判不出（`function` 还会绑定 `arguments`，形参表\
                         为空也可能读到 payload），需要人工核实该回调是否读了 payload，再决定是否\
                         扩展本判据",
                    rest.chars().take(60).collect::<String>()
                ),
            }
        }
        // 数量断言：订阅点增减必须停下来显式裁定，不许守卫自适应放行（多了 = 新消费方没过判据；
        // 少了 = 这一腿已删，判据表该同步改）。射程记账：本判据只抗块注释伪造（见
        // `strip_block_comments`），不抗**行尾**注释（`foo(); // 见 api.onChanged(cb)` 照数）、
        // 也不抗字符串/模板字面量/JSX 文本里出现 `.onChanged(` 这串字面量——这两类都不做词法
        // 分析，真被这么写就会被静默算作一次「订阅还在」。
        assert_eq!(sites, 1, "{path} 的 configChanged 订阅点数变了");
    }

    // Rust 侧第四腿：`TRAY_SYNC_EVENTS` 含 `EVENT_CONFIG_CHANGED`（订阅面由 `main.rs` 自己的
    // `tray_icon_events_are_the_proxy_lifecycle_channels` 钉住），本条只钉**回调丢弃 payload**。
    let main_body = top_level_fn_body(&crate_code("main.rs"), "fn main() {");
    assert!(
        main_body.contains("wire_tray_icon_sync("),
        "扫到的不是 main() 的函数体 —— 守卫已失去判据"
    );
    // 回调现有两项工作（同步 warm 偏好 + reconcile tray），不能再把整条闭包钉成单表达式；
    // 真正的契约只有形参必须是 `_`，这样闭包体结构扩展也不会误红，同时 payload 仍结构性不可读。
    assert!(
        main_body.contains("handle.listen_any(ev, move |_| {"),
        "托盘汇流的事件回调不再以 `_` 丢弃 payload —— configChanged 已无载荷，读它只会拿到空对象"
    );
}

/// **预防性自检**：块注释（含 JSDoc）里若提到调用形态 `.onChanged(cb)` 不得被计入。
///
/// 今天的收益是 0：`use-config.ts` 头部 JSDoc 提到的是 `` `configApi.onChanged` ``（**没有**左
/// 括号），不含判据串 `.onChanged(`，就算没有 `strip_block_comments` 也数不进来——本用例钉的是
/// 「JSDoc 一旦被后人改写成带括号的调用形态」这类将来态，不是复现今天已经存在的漏洞。少了这条
/// 剥离、且真出现这种改写时：注释能伪造一次订阅、真订阅被删也仍全绿（`sites == 1` 是三腿
/// 「订阅还在」唯一的钉子）。
///
/// 变异锁：把 `strip_block_comments(src)` 换成裸 `src` → 本用例转红（`sites` 变 2）。
#[test]
fn block_comment_mentioning_on_changed_is_not_counted() {
    let src = "/**\n * see `configApi.onChanged(cb)` for details\n */\n\
                   const off = api.onChanged(() => void load());\n";
    let src = strip_line_comments(&strip_block_comments(src));
    let sites = src.match_indices(".onChanged(").count();
    assert_eq!(
        sites, 1,
        "块注释里的 `.onChanged(` 被计入了 —— TS 取材器漏剥块注释，注释能伪造一次订阅"
    );
}
