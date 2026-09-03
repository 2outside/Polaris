use super::*;

/// 🔴 **连接流的 demand = 四个需求的并集**（aggregate / topology / detail / closed 任一有需求即保持）。
///
/// **变异探针**：`should_stream_connections` 改成只看 `Topic::Connections` ⇒ 「只开着首页、排名页
/// 没订阅」时流不开，首页拓扑永远冻结 ⇒ 转红；改成 `&&` ⇒ 全订上才开流 ⇒ 转红。
#[test]
fn 连接流demand是四个需求的并集() {
    let mut r = SubscriptionRegistry::new();
    assert!(!r.should_stream_connections(), "都没订阅 → 不开流");

    let t_agg = r.subscribe(Topic::Connections, "main");
    assert!(r.should_stream_connections(), "只订排名聚合 → 也得开流");
    r.unsubscribe(Topic::Connections, t_agg);

    let t_topo = r.subscribe(Topic::Topology, "main");
    assert!(
        r.should_stream_connections(),
        "只订首页流向信号 → 也得开流（漏算它 = 只开首页时整条流被误停，拓扑冻结）"
    );
    r.unsubscribe(Topic::Topology, t_topo);

    let t_detail = r.subscribe(Topic::Detail, "main");
    assert!(r.should_stream_connections(), "只订明细 → 也得开流");
    r.unsubscribe(Topic::Detail, t_detail);

    let t_closed = r.subscribe(Topic::Closed, "main");
    assert!(r.should_stream_connections(), "只订已结束历史 → 也得开流");
    r.unsubscribe(Topic::Closed, t_closed);

    // Stats 是另一条腿（走 Status/轮询），不该把连接流拉起来
    r.subscribe(Topic::Stats, "main");
    assert!(
        !r.should_stream_connections(),
        "stats 订阅不得拉起连接流 —— 它不消费连接表"
    );
}

/// 🔴 **流的需求 ≠ 载荷的需求**：只订 [`Topic::Topology`] 时连接流必须开着，但排名聚合那条
/// emit 门必须仍是关的（否则本次拆分白做 —— 首页在场就等于排名载荷永远在算）。
///
/// **变异探针**：把 `Topology` 并进 `should_stream(Topic::Connections)` 的判据（或让 `parse_topic`
/// 把 `"topology"` 映回 `Topic::Connections`）⇒ 第二段转红。
#[test]
fn 首页流向令牌开流但不开排名聚合门() {
    let mut r = SubscriptionRegistry::new();
    r.subscribe(Topic::Topology, "main");
    assert!(r.should_stream_connections(), "首页在场 → 连接流必须开着");
    assert!(
        !r.should_stream(Topic::Connections),
        "首页不消费 Top-N 聚合载荷 → 那条 emit 门必须仍关着"
    );
    r.subscribe(Topic::Connections, "main");
    assert!(
        r.should_stream(Topic::Connections),
        "排名页进场 → 聚合门才开"
    );
}

/// 🔴 **窗口不可见 → 连接流必须 drop**（长驻流下降流的实质：断流，不是 park 一拍）。
///
/// **变异探针**：`should_stream_connections` 绕过 `should_stream` 直接看 `subscriber_count`
/// （即「不可见时不 drop 流」）⇒ 转红。
#[test]
fn 窗口不可见时连接流必须drop() {
    let mut r = SubscriptionRegistry::new();
    r.subscribe(Topic::Connections, "main");
    r.subscribe(Topic::Detail, "main");
    assert!(r.should_stream_connections());

    r.set_window_visible(false);
    assert!(
        !r.should_stream_connections(),
        "窗口隐藏 = 无 UI 消费者 → 长驻流必须断掉，而不是留着白收事件"
    );

    r.set_window_visible(true);
    assert!(r.should_stream_connections(), "窗口回来 → 必须重订阅");
}

#[test]
fn subscribe_returns_unique_tokens() {
    let mut r = SubscriptionRegistry::new();
    let t1 = r.subscribe(Topic::Stats, "win1");
    let t2 = r.subscribe(Topic::Stats, "win2");
    assert_ne!(t1, t2);
    assert_eq!(r.subscriber_count(Topic::Stats), 2);
}

#[test]
fn unsubscribe_by_token_removes_one() {
    let mut r = SubscriptionRegistry::new();
    let t1 = r.subscribe(Topic::Connections, "win1");
    let _t2 = r.subscribe(Topic::Connections, "win2");
    assert!(r.unsubscribe(Topic::Connections, t1));
    assert_eq!(r.subscriber_count(Topic::Connections), 1);
    // 再次注销同一 token → false
    assert!(!r.unsubscribe(Topic::Connections, t1));
}

#[test]
fn unsubscribe_wrong_topic_returns_false() {
    let mut r = SubscriptionRegistry::new();
    let t = r.subscribe(Topic::Stats, "win1");
    assert!(!r.unsubscribe(Topic::Connections, t));
}

/// Stats 也受可见性门控（原 `should_stream_stats_only_needs_subscribers` 的新语义）。
///
/// 旧断言是「窗口隐藏也保持流」，其前提是 上游 那条「status 流是 worker demand 握手的载体」
/// ——Polaris 没有 worker、没有该握手，见 [`Topic::gated_by_visibility`]。隐藏后继续流 =
/// 每秒一次无人消费的 IPC + 重渲染。
#[test]
fn should_stream_stats_needs_subscribers_and_visibility() {
    let mut r = SubscriptionRegistry::new();
    assert!(!r.should_stream(Topic::Stats)); // 无订阅者
    let _t = r.subscribe(Topic::Stats, "win1");
    assert!(r.should_stream(Topic::Stats)); // 有订阅者 + 可见
    r.set_window_visible(false);
    assert!(
        !r.should_stream(Topic::Stats),
        "窗口隐藏 → Stats 也降流（无 UI 消费者，不做无人消费的 IPC）"
    );
    r.set_window_visible(true);
    assert!(r.should_stream(Topic::Stats), "窗口回来 → 恢复");
}

#[test]
fn should_stream_connections_gated_by_visibility() {
    let mut r = SubscriptionRegistry::new();
    let _t = r.subscribe(Topic::Connections, "win1");
    assert!(r.should_stream(Topic::Connections)); // 可见 + 有订阅者
    r.set_window_visible(false);
    // 无可见窗口 → 降流（省核 CPU），即使有订阅者
    assert!(!r.should_stream(Topic::Connections));
}

#[test]
fn should_stream_detail_gated_by_visibility() {
    let mut r = SubscriptionRegistry::new();
    let _t = r.subscribe(Topic::Detail, "conn-page");
    assert!(r.should_stream(Topic::Detail));
    r.set_window_visible(false);
    assert!(!r.should_stream(Topic::Detail));
}

#[test]
fn 降流_注册后注销至无订阅者应停止流() {
    // 维度7 降流测试：注册 → 注销 → should_stream 翻 false
    let mut r = SubscriptionRegistry::new();
    let t = r.subscribe(Topic::Connections, "win1");
    assert!(r.should_stream(Topic::Connections));
    r.unsubscribe(Topic::Connections, t);
    assert!(!r.should_stream(Topic::Connections), "注销后无订阅者应降流");
}

#[test]
fn 降流_多订阅者最后一个注销才降流() {
    let mut r = SubscriptionRegistry::new();
    let t1 = r.subscribe(Topic::Connections, "win1");
    let t2 = r.subscribe(Topic::Connections, "win2");
    assert!(r.should_stream(Topic::Connections));
    r.unsubscribe(Topic::Connections, t1);
    assert!(
        r.should_stream(Topic::Connections),
        "仍有一个订阅者，保持流"
    );
    r.unsubscribe(Topic::Connections, t2);
    assert!(!r.should_stream(Topic::Connections), "全部注销才降流");
}

#[test]
fn 降流_窗口隐藏时全部topic门控口径一致() {
    // ★ 契约测试（口径一致）：本条是 `Topic::gated_by_visibility` 恒 true 的锁。
    //
    // 前身是 `降流_窗口隐藏取消connections保持stats`，断言「隐藏时 connections 降流但 stats 不降」的
    // **差异化**门控。该差异随其前提作废（见 `Topic::gated_by_visibility` 的「为什么与 上游 表面形态
    // 不同」：上游的 status 不门控是 worker demand 握手载体 + 廉价 server-push 帧，两条前提 Polaris
    // 都没有；而 上游 广播侧 `StatsService.ts:312` / `StatsWorkerHost.ts:217` 本来就按可见性门控 stats）。
    //
    // 任何一条 topic 再被单独开成「隐藏也流」→ 本测转红。
    let mut r = SubscriptionRegistry::new();
    for t in [
        Topic::Stats,
        Topic::Connections,
        Topic::Topology,
        Topic::Detail,
        Topic::Closed,
    ] {
        r.subscribe(t, "win1");
        assert!(r.should_stream(t), "{t:?}：可见 + 有订阅 → 应保持流");
        assert!(
            t.gated_by_visibility(),
            "{t:?}：必须受可见性门控（口径一致）"
        );
    }
    r.set_window_visible(false);
    for t in [
        Topic::Stats,
        Topic::Connections,
        Topic::Topology,
        Topic::Detail,
        Topic::Closed,
    ] {
        assert!(
            !r.should_stream(t),
            "{t:?}：窗口隐藏 → 必须降流（无可见窗口 = 无 UI 消费者，全部 topic 同一口径）"
        );
    }
    r.set_window_visible(true);
    for t in [
        Topic::Stats,
        Topic::Connections,
        Topic::Topology,
        Topic::Detail,
        Topic::Closed,
    ] {
        assert!(r.should_stream(t), "{t:?}：窗口回来 → 全部一起恢复");
    }
}

#[test]
fn window_visible_defaults_true() {
    let r = SubscriptionRegistry::new();
    // fail-open 缺省：真值由调用方首拍按窗口实况回写，缺省只保证「不确定」时不先饿死 UI。
    assert!(r.window_visible());
}

#[test]
fn clear_topic_empties_only_that_topic() {
    let mut r = SubscriptionRegistry::new();
    r.subscribe(Topic::Stats, "w1");
    r.subscribe(Topic::Connections, "w1");
    r.clear_topic(Topic::Connections);
    assert_eq!(r.subscriber_count(Topic::Connections), 0);
    assert_eq!(r.subscriber_count(Topic::Stats), 1);
}

#[test]
fn clear_all_empties_everything() {
    let mut r = SubscriptionRegistry::new();
    r.subscribe(Topic::Stats, "w1");
    r.subscribe(Topic::Connections, "w1");
    r.subscribe(Topic::Detail, "w1");
    r.clear_all();
    assert!(!r.has_any_subscriber());
}

#[test]
fn has_any_subscriber_tracks_across_topics() {
    let mut r = SubscriptionRegistry::new();
    assert!(!r.has_any_subscriber());
    r.subscribe(Topic::Detail, "w1");
    assert!(r.has_any_subscriber());
}

#[test]
fn same_subscriber_id_can_subscribe_multiple_times() {
    let mut r = SubscriptionRegistry::new();
    let _t1 = r.subscribe(Topic::Stats, "win1");
    let _t2 = r.subscribe(Topic::Stats, "win1"); // 同 id 再订一次
    assert_eq!(r.subscriber_count(Topic::Stats), 2);
}
