use super::*;
use crate::test_support::{crate_bytes, crate_code};

fn wired_sources() -> (Vec<&'static str>, Vec<std::time::Duration>) {
    let mut events = Vec::new();
    let mut polls = Vec::new();
    wire_tray_icon_sync(|ev| events.push(ev), |d| polls.push(d));
    (events, polls)
}

fn vis(state: crate::tray::TrayState, dark_bg: bool, lang: crate::i18n::Lang) -> TrayVisual {
    TrayVisual {
        state,
        dark_bg,
        lang,
    }
}

fn run(cache: &mut Option<TrayVisual>, next: TrayVisual, applied_ok: bool) -> bool {
    let mut called = false;
    reconcile_tray_visual(cache, next, |v| {
        assert_eq!(v, next, "apply 必须拿到本次要落的态，不是别的");
        called = true;
        applied_ok
    });
    called
}

#[test]
fn tray_icon_subscribes_every_terminal_event() {
    let (events, _) = wired_sources();
    // ERROR 是本 bug 的原形：`set_error()` 把 running=false 落盘却只发它，图标此前收不到。
    for want in [
        crate::events::channel::EVENT_PROXY_STARTED,
        crate::events::channel::EVENT_PROXY_STOPPED,
        crate::events::channel::EVENT_PROXY_ERROR,
    ] {
        assert!(
            events.contains(&want),
            "终态事件 {want} 未接入托盘图标汇流点 → 该腿触发时图标会卡住"
        );
    }
    // 无重复订阅（同一事件订两次 = 每次终态刷两遍图标）。
    let mut uniq = events.clone();
    uniq.sort_unstable();
    uniq.dedup();
    assert_eq!(uniq.len(), events.len(), "存在重复订阅：{events:?}");
}

#[test]
fn tray_icon_has_polling_self_heal_net() {
    let (_, polls) = wired_sources();
    assert_eq!(
        polls.len(),
        1,
        "自愈轮询网必须且只须挂一条；缺它则 restart 失败 / updater 停核 / 休眠唤醒这些\
             **零 emit** 的腿无人兜，图标照样卡死（只补 ERROR 监听是半修）"
    );
    let every = polls[0];
    assert!(!every.is_zero(), "周期 0 = 忙循环，不是自愈网");
    assert!(
        every <= std::time::Duration::from_secs(30),
        "自愈周期不得慢于主窗 App.tsx:210-213 的 30s 网（{every:?}），否则托盘比主窗还晚回正"
    );
}

#[test]
fn tray_reconcile_reads_config_by_projection_not_full_clone() {
    use crate::commands::guard_scan::top_level_fn_body;
    for (src, head, who) in [
        (
            crate_code("app_tray.rs"),
            "pub(crate) fn reconcile_tray_menu(app: &tauri::AppHandle) {",
            "菜单汇流点",
        ),
        (
            crate_code("i18n.rs"),
            "pub fn app_lang(app: &AppHandle) -> Lang {",
            "原生文案语言",
        ),
    ] {
        let body = top_level_fn_body(&src, head);
        assert!(
            !body.contains(".current()"),
            "{who}（`{head}`）出现了 `config.current()` —— 它挂在 30s 自愈轮询上，\
                 每次叫醒都会整份深拷贝配置。改用 `with_current(|c| …)` 只投影要用的字段。"
        );
        assert!(
            body.contains(".with_current("),
            "{who} 里连 `with_current` 都没有了 —— 负面断言会因此恒真（门被抽空）"
        );
    }

    // 嵌套禁忌：`app_lang(app)` 必须在 `with_current` 闭包**之后**（平铺），不得被包进闭包里。
    let menu = top_level_fn_body(
        &crate_code("app_tray.rs"),
        "pub(crate) fn reconcile_tray_menu(app: &tauri::AppHandle) {",
    );
    let close = menu
        .find(".with_current(tray_menu_config_projection)")
        .expect("锚点消失：菜单专用 `with_current` 投影，守卫已失去判据");
    let lang = menu
        .find("app_lang(app)")
        .expect("锚点消失：菜单语言读取，守卫已失去判据");
    assert!(
        lang > close,
        "`app_lang(app)` 落进了 `with_current` 闭包内 —— 闭包里持着 ConfigManager 的读锁，\
             而 app_lang 自己还要再读一次配置：递归读在有写者排队时永久阻塞。两次读必须平铺。"
    );
}

#[test]
fn tray_state_icons_are_all_distinct() {
    // 取材锚在 crate 根（`src-tauri/`），不随本测试文件的深度变。
    // `include_bytes!` 与 `include_str!` 的锚点语义相同，失效方式也相同：那串 `..` 的个数
    // 就是锚点，测试一搬家整体平移，撞上另一个真实文件则编译通过、断言跑在别的字节上。
    let icons: [(&str, Vec<u8>); 4] = [
        ("on", crate_bytes("icons/tray-on-black.png")),
        ("connecting", crate_bytes("icons/tray-connecting-black.png")),
        ("off", crate_bytes("icons/tray-off-black.png")),
        ("error", crate_bytes("icons/tray-error-black.png")),
    ];
    for i in 0..icons.len() {
        for j in (i + 1)..icons.len() {
            assert_ne!(
                icons[i].1, icons[j].1,
                "托盘 `{}` 与 `{}` 用的是同一张图 —— 这两个态在菜单栏里无法区分",
                icons[i].0, icons[j].0
            );
        }
        // 白变体只换 RGB、不动 alpha ⇒ 与黑变体等大、必然不同字节。缺一半会让 Win/Linux 某个明暗下无图。
        let white: Vec<u8> = match icons[i].0 {
            "on" => crate_bytes("icons/tray-on-white.png"),
            "connecting" => crate_bytes("icons/tray-connecting-white.png"),
            "off" => crate_bytes("icons/tray-off-white.png"),
            _ => crate_bytes("icons/tray-error-white.png"),
        };
        assert_ne!(
            white, icons[i].1,
            "托盘 `{}` 的黑白变体是同一张图",
            icons[i].0
        );
    }
}

#[test]
fn tray_icon_reconcile_stays_io_free() {
    let src = crate_code("app_tray.rs");
    let body =
        crate::commands::guard_scan::top_level_fn_body(&src, "pub(crate) fn reconcile_tray_icon(");
    for forbidden in [
        "system_proxy",
        "spawn_blocking",
        "Command::new",
        "block_on",
        ".await",
    ] {
        assert!(
            !body.contains(forbidden),
            "图标汇流点里出现了 `{forbidden}` —— 它被 4 个事件源 + 30s 轮询叫醒，\
                 无 IO 是它能被这样叫醒的前提（补 degraded 态的正确前置是后端先有低成本活态，\
                 见 tray/model.rs 里 `TrayState` 下方的 degraded 决策登记）"
        );
    }
}

#[test]
fn tray_visual_first_paint_always_applies() {
    use crate::i18n::Lang;
    use crate::tray::TrayState;
    // 缓存空（进程刚起）→ 必须画一次，否则托盘停在 conf 里的静态初值。
    let mut cache = None;
    assert!(run(
        &mut cache,
        vis(TrayState::Idle, true, Lang::ZhCN),
        true
    ));
    assert_eq!(
        cache,
        Some(vis(TrayState::Idle, true, Lang::ZhCN)),
        "画完要记下来"
    );
}

#[test]
fn tray_visual_unchanged_state_is_short_circuited() {
    use crate::i18n::Lang;
    use crate::tray::TrayState;
    // 本条就是 B1 的正题：代理长期未运行时，30s 轮询每一轮拿到的都是同一个态。
    let mut cache = None;
    let same = vis(TrayState::Idle, true, Lang::ZhCN);
    assert!(run(&mut cache, same, true), "第一次要画");
    for round in 0..3 {
        assert!(
            !run(&mut cache, same, true),
            "第 {round} 轮轮询：视觉态未变仍重设 = 每 30s 一次 PNG 落盘 + indicator 重载（图标闪）"
        );
    }
}

#[test]
fn tray_visual_every_field_change_repaints() {
    use crate::i18n::Lang;
    use crate::tray::TrayState;
    let base = vis(TrayState::Idle, true, Lang::ZhCN);
    // 逐字段单独翻转：任何一个字段被漏出比较键，对应这条就会因为「该画却短路了」而红。
    for (label, changed) in [
        (
            "state（四态 → 四种图标形态 + tooltip 文案）",
            vis(TrayState::Connected, true, Lang::ZhCN),
        ),
        (
            "dark_bg（任务栏明暗 → 黑/白变体）",
            vis(TrayState::Idle, false, Lang::ZhCN),
        ),
        (
            "lang（tooltip 文案语言）",
            vis(TrayState::Idle, true, Lang::EnUS),
        ),
    ] {
        let mut cache = Some(base);
        assert!(
            run(&mut cache, changed, true),
            "{label} 变了却没重画 —— 短路过度，图标/tooltip 停在旧态"
        );
    }
}

#[test]
fn tray_visual_cache_tracks_latest_applied_state() {
    use crate::i18n::Lang;
    use crate::tray::TrayState;
    // 缓存只在首次写入、之后不更新（一种典型写错法）→ 第三步会误判「变了」而重画，本条转红。
    let mut cache = None;
    let a = vis(TrayState::Idle, true, Lang::ZhCN);
    let b = vis(TrayState::Connected, true, Lang::ZhCN);
    assert!(run(&mut cache, a, true));
    assert!(run(&mut cache, b, true), "a → b 该画");
    assert!(
        !run(&mut cache, b, true),
        "b → b 该短路（缓存必须跟到最新态）"
    );
}

#[test]
fn tray_visual_failed_apply_is_retried_next_round() {
    use crate::i18n::Lang;
    use crate::tray::TrayState;
    // 落盘失败还照存缓存 → 之后每轮自愈都短路，托盘永久停在旧图：自愈网被自己的缓存关掉。
    let mut cache = None;
    let want = vis(TrayState::Connected, false, Lang::EnUS);
    assert!(run(&mut cache, want, false), "第一次尝试");
    assert_eq!(cache, None, "落盘失败不得记成「已落」");
    assert!(
        run(&mut cache, want, true),
        "上次落盘失败 → 下一轮自愈必须重试，而不是被缓存短路掉"
    );
    assert!(!run(&mut cache, want, true), "重试成功后才轮到短路");
}

#[test]
fn tray_icon_events_are_the_proxy_lifecycle_channels() {
    use crate::events::channel as ch;
    // 订的必须是既有通道常量本身（防有人把常量改成拼错的字面量：listen_any 对不存在的
    // 事件名不会报错，只会**静默永不触发**——与本 bug 同型的静默失败）。
    // 逐条列举而非只查前缀：CONFIG_CHANGED 不带 `event:proxy` 前缀，旧的前缀断言会把它误判成非法，
    // 而「只查前缀」本身也放得过 `event:proxyFoo` 这种拼错的近似名。
    assert_eq!(
            TRAY_SYNC_EVENTS,
            [
                ch::EVENT_PROXY_STARTED,
                ch::EVENT_PROXY_STOPPED,
                ch::EVENT_PROXY_ERROR,
                ch::EVENT_CONFIG_CHANGED,
            ],
            "三条代理终态 + 一条配置变更（后者喂原生菜单的勾选/语言，少了它 Linux 上要等 30s 轮询才回正）"
        );
}

#[test]
fn tray_state_error_is_distinguishable_from_idle() {
    use crate::tray::{resolve_tray_state, TrayState};
    // 这条正是 A2 要修的缺口：`set_error()` 写 running=false + error_code，只发 ERROR 事件。
    // 修之前托盘回读到的就是 running=false ⇒ 与用户主动断开**完全同形**。
    assert_eq!(
        resolve_tray_state(false, false, true),
        TrayState::Error,
        "核崩溃/起核失败必须与主动断开可辨"
    );
    assert_eq!(resolve_tray_state(false, false, false), TrayState::Idle);
}

#[test]
fn tray_state_running_wins_over_stale_error() {
    use crate::tray::{resolve_tray_state, TrayState};
    // `set_nonfatal_error`（如 A1 的 SYSTEM_PROXY_FAILED）在**活核**上留 error_code。
    // 那不是「没连上」，托盘不该翻红叉。
    assert_eq!(resolve_tray_state(true, false, true), TrayState::Connected);
    assert_eq!(resolve_tray_state(true, true, true), TrayState::Connected);
}

#[test]
fn tray_state_starting_wins_over_stale_error() {
    use crate::tray::{resolve_tray_state, TrayState};
    // 新一轮起核已在飞 ⇒ 上一轮的失败不该盖住「正在重试」这个更新的事实。
    assert_eq!(resolve_tray_state(false, true, true), TrayState::Connecting);
    assert_eq!(
        resolve_tray_state(false, true, false),
        TrayState::Connecting
    );
}

#[test]
fn tray_state_four_states_map_to_four_distinct_visuals() {
    use crate::i18n::Lang;
    use crate::tray::TrayState;
    // 变异锁：把某两个态映射到同一张图/同一句 tooltip（例如「connecting 先复用 idle 图标」这种
    // 常见的偷懒实现）必须转红 —— 否则 A2 的「起核中有反馈、错误态可辨」就成了空话。
    let states = [
        TrayState::Idle,
        TrayState::Connecting,
        TrayState::Connected,
        TrayState::Error,
    ];
    let mut tips: Vec<String> = states
        .iter()
        .map(|s| crate::tray::tooltip_text(Lang::ZhCN, *s))
        .collect();
    tips.sort_unstable();
    let n = tips.len();
    tips.dedup();
    assert_eq!(tips.len(), n, "四态 tooltip 必须两两不同");
    // 视觉键同理：TrayVisual 以 state 为键 ⇒ 四态必须产出四个互不相等的键（否则幂等闸门会把
    // 「态变了」误判成「没变」而不重画）。
    let mut keys: Vec<TrayVisual> = states.iter().map(|s| vis(*s, true, Lang::ZhCN)).collect();
    keys.dedup();
    assert_eq!(keys.len(), 4, "四态必须产出四个不同的视觉键");
}

#[test]
fn tray_interaction_mode_is_direct_only_on_mac_and_windows() {
    assert_eq!(
        tray_interaction_mode(Platform::Mac),
        TrayInteractionMode::DirectClicks
    );
    assert_eq!(
        tray_interaction_mode(Platform::Win),
        TrayInteractionMode::DirectClicks
    );
    assert_eq!(
        tray_interaction_mode(Platform::Linux),
        TrayInteractionMode::NativeMenu
    );
    assert_eq!(
        tray_interaction_mode(Platform::Other),
        TrayInteractionMode::NativeMenu
    );
}

#[test]
fn direct_tray_clicks_toggle_overlay_for_left_and_right() {
    use tauri::tray::{MouseButton, MouseButtonState};

    for platform in [Platform::Mac, Platform::Win] {
        assert!(
            tray_click_toggles_overlay(platform, MouseButton::Left, MouseButtonState::Up),
            "{platform:?} 左键抬起必须切换自绘浮层"
        );
        assert!(
            tray_click_toggles_overlay(platform, MouseButton::Right, MouseButtonState::Up),
            "{platform:?} 右键抬起必须切换自绘浮层"
        );
        assert!(
            !tray_click_toggles_overlay(platform, MouseButton::Middle, MouseButtonState::Up),
            "中键没有产品动作，不得猜测"
        );
        for button in [MouseButton::Left, MouseButton::Right, MouseButton::Middle] {
            assert!(
                !tray_click_toggles_overlay(platform, button, MouseButtonState::Down),
                "按下帧不得执行，避免 down/up 重复触发"
            );
        }
    }
}

#[test]
fn native_menu_platforms_ignore_all_tray_click_events() {
    use tauri::tray::{MouseButton, MouseButtonState};

    for platform in [Platform::Linux, Platform::Other] {
        for button in [MouseButton::Left, MouseButton::Right, MouseButton::Middle] {
            for state in [MouseButtonState::Down, MouseButtonState::Up] {
                assert!(
                    !tray_click_toggles_overlay(platform, button, state),
                    "{platform:?} 点击归原生菜单所有，不得叠开自绘浮层"
                );
            }
        }
    }
}

#[test]
fn menu_ids_parse_to_actions() {
    assert_eq!(parse_menu_action("tray_show"), Some(MenuAction::Show));
    assert_eq!(parse_menu_action("tray_quit"), Some(MenuAction::Quit));
    assert_eq!(
        parse_menu_action("tray_toggle"),
        Some(MenuAction::ToggleProxy)
    );
    assert_eq!(parse_menu_action("tray_open_nodes"), None);
    assert_eq!(
        parse_menu_action("tray_settings"),
        Some(MenuAction::OpenSettings)
    );
    assert_eq!(
        parse_menu_action("tray_check_update"),
        Some(MenuAction::CheckUpdate)
    );
    assert_eq!(
        parse_menu_action("tray_speed_test"),
        Some(MenuAction::SpeedTest)
    );
    assert_eq!(parse_menu_action("tray_lock"), Some(MenuAction::Lock));
    assert_eq!(
        parse_menu_action("tray_lightweight"),
        Some(MenuAction::EnterLightweight)
    );
    assert_eq!(
        parse_menu_action("tray_select:node:with:colon"),
        Some(MenuAction::SelectExit("node:with:colon".into())),
        "节点 id 载荷必须完整往返，不能按冒号二次切割"
    );
}

#[test]
fn submenu_ids_roundtrip_for_every_declared_value() {
    // **每一个**声明出来的档都必须能解析回去：菜单是按 TAKEOVER_KINDS/ROUTING_MODES 生成 id 的，
    // 少了任何一档的解析 = 那一项点了没反应（且没有任何报错，纯静默）。
    for k in crate::tray::TAKEOVER_KINDS {
        assert_eq!(
            parse_menu_action(&format!("{MENU_ID_TAKEOVER}{k}")),
            Some(MenuAction::Takeover(k)),
            "接管方式 {k} 的菜单项点了会没反应"
        );
    }
    for m in crate::tray::ROUTING_MODES {
        assert_eq!(
            parse_menu_action(&format!("{MENU_ID_ROUTING}{m}")),
            Some(MenuAction::Routing(m)),
            "分流策略 {m} 的菜单项点了会没反应"
        );
    }
}

#[test]
fn unknown_menu_ids_are_rejected_not_guessed() {
    // 载荷必须回查白名单，不能把 id 尾巴透传去写配置（写进 config.proxyMode 的值域由本文件钉死）。
    assert_eq!(parse_menu_action("tray_routing:evil"), None);
    assert_eq!(parse_menu_action("tray_takeover:"), None);
    assert_eq!(parse_menu_action("tray_takeover:TUN"), None, "大小写不放行");
    assert_eq!(parse_menu_action("tray_select:"), None);
    assert_eq!(parse_menu_action("tray_select:   "), None);
    assert_eq!(
        parse_menu_action("app_quit"),
        None,
        "应用菜单的 id 不该被托盘 handler 认领"
    );
    assert_eq!(parse_menu_action(""), None);
}

#[test]
fn native_proxy_toggle_cancels_startup_instead_of_starting_again() {
    assert_eq!(tray_proxy_action(false, false), TrayProxyAction::Start);
    assert_eq!(tray_proxy_action(true, false), TrayProxyAction::Stop);
    assert_eq!(
        tray_proxy_action(false, true),
        TrayProxyAction::Cancel,
        "起核期 running=false 也必须走 stop 取消，不能叠第二次 start"
    );
    assert_eq!(
        tray_proxy_action(true, true),
        TrayProxyAction::Cancel,
        "starting 与 running 同时为真时，仍与自绘按钮一致由 starting 优先"
    );
}

#[test]
fn native_menu_escapes_user_ampersands() {
    assert_eq!(native_menu_user_text("A&B && C"), "A&&B &&&& C");
    assert_eq!(native_menu_user_text("普通节点"), "普通节点");
}

#[test]
fn linux_node_menu_is_a_native_cascade_without_an_overlay_escape_hatch() {
    let body = crate::commands::guard_scan::top_level_fn_body(
        &crate_code("app_tray.rs"),
        "pub(crate) fn build_tray_menu(",
    );
    assert!(body.contains("for group in &m.node_groups"));
    assert!(body.contains("let group_menu = Submenu::new("));
    assert!(body.contains("nodes.append(&group_menu)"));
    assert!(
        !body.contains("tray_open_nodes") && !body.contains("show_node_picker"),
        "Linux 原生菜单不得再跳进无法取得托盘锚点的自绘窗口"
    );
}

#[test]
fn native_node_projection_builds_cascading_groups_without_losing_nodes() {
    let projection = tray_menu_config_projection(&serde_json::json!({
        "proxyMode": "global",
        "proxyModeType": "tun",
        "selectedServerId": "sub-node",
        "recentServerIds": ["missing", "mesh", "manual", "manual", "orphan"],
        "subscriptions": [
            { "id": "sub-a", "name": "订阅 A&B" },
            { "id": "sub-empty", "name": "空订阅" }
        ],
        "servers": [
            { "id": "manual", "name": "自建", "protocol": "vless" },
            { "id": "mesh", "name": "企业 VPN", "protocol": "openconnect" },
            { "id": "orphan", "name": "孤儿", "protocol": "trojan", "subscriptionId": "gone" },
            { "id": "sub-node", "name": "订阅节点", "protocol": "shadowsocks", "subscriptionId": "sub-a" }
        ]
    }));

    assert_eq!(projection.mode.as_deref(), Some("global"));
    assert_eq!(projection.mode_type.as_deref(), Some("tun"));
    assert_eq!(projection.selected_server_id.as_deref(), Some("sub-node"));
    assert!(projection.has_real_nodes);
    assert_eq!(
        projection.node_groups,
        vec![
            TrayMenuGroup {
                label: TrayMenuGroupLabel::Manual,
                nodes: vec![
                    TrayMenuNode {
                        id: "manual".into(),
                        name: "自建".into()
                    },
                    TrayMenuNode {
                        id: "orphan".into(),
                        name: "孤儿".into()
                    },
                ],
            },
            TrayMenuGroup {
                label: TrayMenuGroupLabel::Mesh,
                nodes: vec![TrayMenuNode {
                    id: "mesh".into(),
                    name: "企业 VPN".into()
                }],
            },
            TrayMenuGroup {
                label: TrayMenuGroupLabel::Subscription("订阅 A&B".into()),
                nodes: vec![TrayMenuNode {
                    id: "sub-node".into(),
                    name: "订阅节点".into()
                }],
            },
        ],
        "原生菜单须按自建、组网、订阅顺序级联，并保留孤儿节点；空订阅不显示"
    );
}

#[test]
fn sentinel_selection_keeps_cascading_node_groups_available() {
    use polaris_config_engine::user_config::dns_constants::DIRECT_SERVER_ID;
    let projection = tray_menu_config_projection(&serde_json::json!({
        "selectedServerId": DIRECT_SERVER_ID,
        "recentServerIds": ["node-a"],
        "servers": [{ "id": "node-a", "name": "节点 A" }]
    }));
    assert!(
        projection.has_real_nodes,
        "测速/启动可用性仍须知道真实节点存在"
    );
    assert_eq!(projection.node_groups.len(), 1);
    assert_eq!(projection.node_groups[0].nodes[0].id, "node-a");
}

#[test]
fn menu_model_gate_repaints_on_every_field_and_only_then() {
    use crate::i18n::Lang;
    let base = TrayMenuModel {
        running: false,
        starting: false,
        mode: "smart".into(),
        mode_type: "systemProxy".into(),
        selected_server_id: Some("manual".into()),
        has_real_nodes: true,
        node_groups: vec![TrayMenuGroup {
            label: TrayMenuGroupLabel::Manual,
            nodes: vec![TrayMenuNode {
                id: "manual".into(),
                name: "节点".into(),
            }],
        }],
        lang: Lang::ZhCN,
    };
    // 未变 → 不重建（GTK 每次 set_menu 重建整棵 widget 树；菜单开着时重建会闪/收起）。
    let mut cache = Some(base.clone());
    let mut called = false;
    reconcile_tray_menu_model(&mut cache, base.clone(), |_| {
        called = true;
        true
    });
    assert!(!called, "模型未变不得重建菜单");

    // 每个字段逐个变 → 每一个都必须触发重建（漏比某字段 = 菜单显示陈旧且无人发现）。
    for (why, next) in [
        (
            "running（连接项文案）",
            TrayMenuModel {
                running: true,
                ..base.clone()
            },
        ),
        (
            "starting（连接项取消文案）",
            TrayMenuModel {
                starting: true,
                ..base.clone()
            },
        ),
        (
            "mode（分流勾选）",
            TrayMenuModel {
                mode: "global".into(),
                ..base.clone()
            },
        ),
        (
            "selected_server_id（出口勾选）",
            TrayMenuModel {
                selected_server_id: Some("other".into()),
                ..base.clone()
            },
        ),
        (
            "has_real_nodes（启动与测速可用性）",
            TrayMenuModel {
                has_real_nodes: false,
                ..base.clone()
            },
        ),
        (
            "node_groups（级联出口菜单内容）",
            TrayMenuModel {
                node_groups: vec![TrayMenuGroup {
                    label: TrayMenuGroupLabel::Mesh,
                    nodes: vec![TrayMenuNode {
                        id: "mesh".into(),
                        name: "组网节点".into(),
                    }],
                }],
                ..base.clone()
            },
        ),
        (
            "mode_type（接管勾选）",
            TrayMenuModel {
                mode_type: "tun".into(),
                ..base.clone()
            },
        ),
        (
            "lang（全部项文案）",
            TrayMenuModel {
                lang: Lang::EnUS,
                ..base.clone()
            },
        ),
    ] {
        let mut cache = Some(base.clone());
        let mut called = false;
        reconcile_tray_menu_model(&mut cache, next, |_| {
            called = true;
            true
        });
        assert!(called, "{why} 变了必须重建菜单");
    }
}

#[test]
fn menu_model_gate_invalidates_cache_when_apply_fails() {
    use crate::i18n::Lang;
    // 失败照存 = 之后每一轮都短路、再也不重试 —— 自愈网被自己的缓存关掉（同 reconcile_tray_visual）。
    let mut cache = None;
    let next = TrayMenuModel {
        running: true,
        starting: false,
        mode: "smart".into(),
        mode_type: "tun".into(),
        selected_server_id: None,
        has_real_nodes: false,
        node_groups: Vec::new(),
        lang: Lang::EnUS,
    };
    reconcile_tray_menu_model(&mut cache, next.clone(), |_| false);
    assert_eq!(cache, None, "装载失败必须作废缓存，下一轮无条件重建");
    reconcile_tray_menu_model(&mut cache, next.clone(), |_| true);
    assert_eq!(cache, Some(next), "成功才记账");
}
