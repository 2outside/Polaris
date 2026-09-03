use super::super::*;
use polaris_config_engine::user_config::server_config::{Protocol, ServerConfig};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn id_gen() -> impl FnMut() -> String {
    let mut n = 0;
    move || {
        n += 1;
        format!("pid-{n}")
    }
}

/// 造一个 Clash 订阅正文（ss 节点，name 列表）。
fn clash_body(nodes: &[(&str, &str)]) -> String {
    let proxies = nodes
            .iter()
            .map(|(name, host)| {
                format!(
                    "  - {{name: {name}, type: ss, server: {host}, port: 8388, cipher: aes-256-gcm, password: pw}}"
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
    format!("proxies:\n{proxies}")
}

/// mock fetch_text：url → `Ok(body)` / `Err(ProviderFetchError)`。
/// 未登记的 URL 一律 **transient**（= 「没桩」不该被当成「远端确认没了」）。
fn mock_fetch(
    map: HashMap<String, Result<String, ProviderFetchError>>,
) -> impl Fn(&str) -> Pin<Box<dyn Future<Output = Result<String, ProviderFetchError>> + Send>>
       + Send
       + Sync {
    let responses = Arc::new(map);
    move |url: &str| {
        let r = responses
            .get(url)
            .cloned()
            .unwrap_or_else(|| Err(ProviderFetchError::transient("no mock for url")));
        Box::pin(async move { r })
            as Pin<Box<dyn Future<Output = Result<String, ProviderFetchError>> + Send>>
    }
}

fn providers_yaml(yaml: &str) -> serde_yaml::Value {
    serde_yaml::from_str(yaml).expect("providers yaml")
}

#[tokio::test]
async fn two_http_providers_merge_and_tag_provider_name() {
    let fetch = mock_fetch(HashMap::from([
        (
            "https://p1.com/sub".to_string(),
            Ok(clash_body(&[("A", "a.com")])),
        ),
        (
            "https://p2.com/sub".to_string(),
            Ok(clash_body(&[("B", "b.com")])),
        ),
    ]));
    let providers = providers_yaml(
            "p1:\n  type: http\n  url: https://p1.com/sub\np2:\n  type: http\n  url: https://p2.com/sub\n",
        );
    let mut g = id_gen();
    let r = resolve_proxy_providers(&providers, "sub1", "now", 8, &fetch, &mut g).await;
    assert_eq!(r.servers.len(), 2, "两 provider 各 1 节点");
    assert!(!r.any_failed);
    // 打断 provider_name 标记 → 此断言转红。
    let names: Vec<&str> = r
        .servers
        .iter()
        .filter_map(|s| s.provider_name.as_deref())
        .collect();
    assert!(
        names.contains(&"p1") && names.contains(&"p2"),
        "节点须标 provider_name: {names:?}"
    );
}

#[tokio::test]
async fn provider_bodies_fetch_concurrently_but_parse_in_declaration_order() {
    // 两条拉取都必须到达 barrier 才能继续：若实现退回串行，第一条会一直等第二条，timeout 硬红。
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let fetch = {
        let barrier = Arc::clone(&barrier);
        move |url: &str| {
            let barrier = Arc::clone(&barrier);
            let body = if url.contains("p1") {
                clash_body(&[("A", "a.com")])
            } else {
                clash_body(&[("B", "b.com")])
            };
            Box::pin(async move {
                barrier.wait().await;
                Ok(body)
            })
                as Pin<Box<dyn Future<Output = Result<String, ProviderFetchError>> + Send>>
        }
    };
    let providers = providers_yaml(
            "p1:\n  type: http\n  url: https://p1.com/sub\np2:\n  type: http\n  url: https://p2.com/sub\n",
        );
    let mut g = id_gen();
    let r = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        resolve_proxy_providers(&providers, "sub1", "now", 8, &fetch, &mut g),
    )
    .await
    .expect("两个 provider 应并发越过 barrier，不能串行等待");

    assert_eq!(r.servers.len(), 2);
    assert_eq!(r.servers[0].name, "A", "完成顺序不得改变声明顺序");
    assert_eq!(r.servers[1].name, "B");
    assert_eq!(r.servers[0].id, "pid-1", "ID 仍按声明序分配");
    assert_eq!(r.servers[1].id, "pid-2");
}

#[tokio::test]
async fn transient_fetch_failure_sets_any_failed_and_names() {
    let fetch = mock_fetch(HashMap::from([
        (
            "https://ok.com/sub".to_string(),
            Ok(clash_body(&[("A", "a.com")])),
        ),
        (
            "https://bad.com/sub".to_string(),
            Err(ProviderFetchError::transient("timeout")),
        ),
    ]));
    let providers = providers_yaml(
            "ok:\n  type: http\n  url: https://ok.com/sub\nbad:\n  type: http\n  url: https://bad.com/sub\n",
        );
    let mut g = id_gen();
    let r = resolve_proxy_providers(&providers, "sub1", "now", 8, &fetch, &mut g).await;
    assert!(
        r.any_failed,
        "拉取失败 → any_failed（触发 merge-only 防穿仓）"
    );
    assert_eq!(r.failed_providers, vec!["bad".to_string()]);
    assert_eq!(r.servers.len(), 1, "成功 provider 节点保留");
}

/// **permanent 拉取失败**（4xx / SSRF 拒绝）→ 仅 warn，**不**保护存量。
///
/// 变异锁：把 `resolve_proxy_providers` 的 `Err(e) if e.permanent` 臂删掉（退回「一律 transient」）
/// → 本用例转红。守的是「provider URL 永久坏掉 → 整条订阅永久 partial」这一终态：
/// `failed_providers` 非空会让**无 `providerName`** 的主正文内联节点也一律保留（命令层
/// `leftover_survives_partial` 规则 2）→ 内联真下架节点永不删除，且每轮 partial 都 save+broadcast。
#[tokio::test]
async fn permanent_fetch_failure_does_not_protect_leftovers() {
    let fetch = mock_fetch(HashMap::from([
        (
            "https://ok.com/sub".to_string(),
            Ok(clash_body(&[("A", "a.com")])),
        ),
        (
            "https://gone.com/sub".to_string(),
            Err(ProviderFetchError::permanent("HTTP 404")),
        ),
    ]));
    let providers = providers_yaml(
            "ok:\n  type: http\n  url: https://ok.com/sub\ngone:\n  type: http\n  url: https://gone.com/sub\n",
        );
    let mut g = id_gen();
    let r = resolve_proxy_providers(&providers, "sub1", "now", 8, &fetch, &mut g).await;
    assert!(
        !r.any_failed,
        "永久失败不得触发 merge-only（否则订阅永久钉在 partial）"
    );
    assert!(r.failed_providers.is_empty());
    assert_eq!(r.servers.len(), 1, "成功 provider 节点仍保留");
    assert!(
        r.warnings.iter().any(|w| w.contains("永久失败")),
        "永久失败须在 warning 里可见: {:?}",
        r.warnings
    );
}

#[tokio::test]
async fn permanent_config_issue_warns_but_not_any_failed() {
    // type:file（安全面拒）+ 不支持 type + 缺 url —— 配置面非法 = permanent（不置 any_failed）。
    let providers = providers_yaml(
            "f:\n  type: file\n  path: /x\nq:\n  type: quic\n  url: https://q.com\nnourl:\n  type: http\n",
        );
    let mut g = id_gen();
    let fetch = mock_fetch(HashMap::new());
    let r = resolve_proxy_providers(&providers, "sub1", "now", 8, &fetch, &mut g).await;
    assert!(
        !r.any_failed,
        "配置面问题是 permanent，不置 any_failed（否则永久 merge-only）"
    );
    assert!(r.failed_providers.is_empty());
    assert!(r.servers.is_empty());
    // 汇总 warning 存在。
    assert!(
        r.warnings.iter().any(|w| w.contains("成功")),
        "应有汇总 warning: {:?}",
        r.warnings
    );
}

/// **0 节点 → 保护存量**（与主正文「0 节点 → merge-only」同口径）。
///
/// 变异锁：把 0 节点分支改回「仅 warn、不进 `failed_providers`」→ 本用例转红。
/// 触发形态：机场 200 + 空正文，或 `filter` 因上游改名临时滤尽 —— 判 permanent 会把该 provider
/// 名下**全部存量节点当场删光**，而同一现象在主正文那边是不删的。
#[tokio::test]
async fn zero_node_provider_is_protected_like_the_main_body() {
    let fetch = mock_fetch(HashMap::from([
        (
            "https://ok.com/sub".to_string(),
            Ok(clash_body(&[("A", "a.com")])),
        ),
        (
            "https://empty.com/sub".to_string(),
            Ok("proxies: []".to_string()),
        ),
    ]));
    let providers = providers_yaml(
            "ok:\n  type: http\n  url: https://ok.com/sub\nempty:\n  type: http\n  url: https://empty.com/sub\n",
        );
    let mut g = id_gen();
    let r = resolve_proxy_providers(&providers, "sub1", "now", 8, &fetch, &mut g).await;
    assert!(r.any_failed, "0 节点须触发 merge-only 保护");
    assert_eq!(
        r.failed_providers,
        vec!["empty".to_string()],
        "只保护 0 节点那一个 provider，成功 provider 的真下架照常删"
    );
    assert_eq!(r.servers.len(), 1);

    // filter 滤尽（上游把节点名前缀改了）→ 同样保护。
    let fetch = mock_fetch(HashMap::from([(
        "https://f.com/sub".to_string(),
        Ok(clash_body(&[("A", "a.com")])),
    )]));
    let providers = providers_yaml(
        "flt:\n  type: http\n  url: https://f.com/sub\n  filter: \"NOTHING-MATCHES\"\n",
    );
    let mut g = id_gen();
    let r = resolve_proxy_providers(&providers, "sub1", "now", 8, &fetch, &mut g).await;
    assert!(r.any_failed, "filter 滤尽 → 保护存量（不当真下架）");
    assert_eq!(r.failed_providers, vec!["flt".to_string()]);
}

/// **被 `max_providers` 截断的 provider 必须进 `failed_providers`。**
///
/// 变异锁：删掉截断分支里的 `out.any_failed = true` / `failed_providers.extend(truncated)`
/// → 本用例转红。守的是最恶性的一条：第 9+ 个 provider **压根没被拉取**，此前既不进名单也不置
/// `any_failed` → 它名下的存量节点在全量 reconcile 里被当成「远端已下架」**每轮真删**
/// （而下一轮它仍被截断，于是删了也拿不回来）。
#[tokio::test]
async fn truncates_at_max_providers_and_protects_the_untried_ones() {
    let fetch = mock_fetch(HashMap::from([
        (
            "https://p1.com/sub".to_string(),
            Ok(clash_body(&[("A", "a.com")])),
        ),
        (
            "https://p2.com/sub".to_string(),
            Ok(clash_body(&[("B", "b.com")])),
        ),
    ]));
    let providers = providers_yaml(
            "p1:\n  type: http\n  url: https://p1.com/sub\np2:\n  type: http\n  url: https://p2.com/sub\n",
        );
    let mut g = id_gen();
    let r = resolve_proxy_providers(&providers, "sub1", "now", 1, &fetch, &mut g).await;
    assert_eq!(r.servers.len(), 1, "max=1 只拉第一个");
    assert!(
        r.warnings.iter().any(|w| w.contains("超上限")),
        "应有截断 warning"
    );
    assert!(
        r.any_failed,
        "有 provider 没被拉过 → 必须触发 merge-only 保护"
    );
    assert_eq!(
        r.failed_providers,
        vec!["p2".to_string()],
        "被截断的 provider 名必须进保护名单（拿不到 ≠ 下架）"
    );
    assert!(
        r.warnings.iter().any(|w| w.contains("p2")),
        "截断 warning 须点名是谁没拉: {:?}",
        r.warnings
    );
}

#[tokio::test]
async fn controlled_provider_resolve_cancels_in_flight_and_discards_results() {
    let providers = providers_yaml("p1:\n  type: http\n  url: https://p1.com/sub\n");
    let fetch = |_url: &str| {
        Box::pin(async {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            Ok(clash_body(&[("late", "late.example")]))
        }) as Pin<Box<dyn Future<Output = Result<String, ProviderFetchError>> + Send>>
    };
    let control = ProviderResolveControl::default();
    let cancel = control.clone();
    let mut g = id_gen();
    let (result, ()) = tokio::join!(
        resolve_proxy_providers_controlled(
            &providers,
            "sub1",
            "now",
            ProviderResolveLimits::default(),
            &control,
            &fetch,
            &mut g,
        ),
        async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            cancel.cancel();
        }
    );
    assert!(result.cancelled);
    assert!(result.servers.is_empty(), "取消后的正文不得进入解析结果");
}

#[tokio::test]
async fn controlled_provider_resolve_cancels_while_parser_future_is_in_flight() {
    let providers = providers_yaml("p1:\n  type: http\n  url: https://p1.com/sub\n");
    let fetch = mock_fetch(HashMap::from([(
        "https://p1.com/sub".to_string(),
        Ok(clash_body(&[("queued", "queued.example")])),
    )]));
    let control = ProviderResolveControl::default();
    let cancel = control.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let cancel_task = tokio::spawn(async move {
        started_rx
            .await
            .expect("parser callback must start before cancellation");
        cancel.cancel();
    });
    let mut started_tx = Some(started_tx);
    let mut parse = move |_request: ProviderParseRequest| {
        let started = started_tx
            .take()
            .expect("one provider invokes one parser callback");
        async move {
            let _ = started.send(());
            std::future::pending::<Result<ProviderParsedOutput, ProviderFetchError>>().await
        }
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        resolve_proxy_providers_controlled_with_parser(
            &providers,
            "sub1",
            "now",
            ProviderResolveLimits::default(),
            &control,
            &fetch,
            &mut parse,
        ),
    )
    .await
    .expect("cancellation must win while parser receiver is pending");
    cancel_task.await.unwrap();
    assert!(result.cancelled);
    assert!(
        result.servers.is_empty(),
        "cancelled parser output must be discarded"
    );
}

#[tokio::test]
async fn controlled_provider_resolve_rejects_body_over_memory_limit() {
    let providers = providers_yaml("p1:\n  type: http\n  url: https://p1.com/sub\n");
    let fetch = |_url: &str| {
        Box::pin(async { Ok("x".repeat(128)) })
            as Pin<Box<dyn Future<Output = Result<String, ProviderFetchError>> + Send>>
    };
    let mut g = id_gen();
    let result = resolve_proxy_providers_controlled(
        &providers,
        "sub1",
        "now",
        ProviderResolveLimits {
            max_provider_body_bytes: 64,
            max_buffered_body_bytes: 64,
            ..Default::default()
        },
        &ProviderResolveControl::default(),
        &fetch,
        &mut g,
    )
    .await;
    assert!(result.any_failed);
    assert_eq!(result.failed_providers, vec!["p1"]);
    assert!(result.warnings.iter().any(|w| w.contains("内存上限")));
}

#[tokio::test]
async fn controlled_provider_resolve_rejects_total_body_before_next_parse() {
    let providers = providers_yaml(
        "p1:\n  type: http\n  url: https://p1/sub\np2:\n  type: http\n  url: https://p2/sub\n",
    );
    let body = clash_body(&[("A", "a.example")]);
    let body_len = body.len();
    let fetch = move |_url: &str| {
        let body = body.clone();
        Box::pin(async move { Ok(body) })
            as Pin<Box<dyn Future<Output = Result<String, ProviderFetchError>> + Send>>
    };
    let mut gen = id_gen();
    let result = resolve_proxy_providers_controlled(
        &providers,
        "sub",
        "now",
        ProviderResolveLimits {
            max_total_provider_body_bytes: body_len + 1,
            ..Default::default()
        },
        &ProviderResolveControl::default(),
        &fetch,
        &mut gen,
    )
    .await;
    assert!(result
        .fatal_error
        .as_ref()
        .is_some_and(|error| error.message.contains("正文累计超过上限")));
}

#[tokio::test]
async fn controlled_provider_resolve_rejects_nodes_before_accumulation() {
    let providers = providers_yaml(
        "p1:\n  type: http\n  url: https://p1/sub\np2:\n  type: http\n  url: https://p2/sub\n",
    );
    let fetch = mock_fetch(HashMap::from([
        (
            "https://p1/sub".to_string(),
            Ok(clash_body(&[("A", "a.example")])),
        ),
        (
            "https://p2/sub".to_string(),
            Ok(clash_body(&[("B", "b.example")])),
        ),
    ]));
    let mut gen = id_gen();
    let result = resolve_proxy_providers_controlled(
        &providers,
        "sub",
        "now",
        ProviderResolveLimits {
            max_nodes_per_provider: 1,
            max_total_nodes: 1,
            ..Default::default()
        },
        &ProviderResolveControl::default(),
        &fetch,
        &mut gen,
    )
    .await;
    assert_eq!(
        result.servers.len(),
        1,
        "second provider must not be appended"
    );
    assert!(result
        .fatal_error
        .as_ref()
        .is_some_and(|error| error.message.contains("节点累计超过上限")));
}

#[tokio::test]
async fn provider_parser_resource_limit_is_fatal_not_partial() {
    let providers = providers_yaml("p1:\n  type: http\n  url: https://p1/sub\n");
    let fetch = mock_fetch(HashMap::from([(
        "https://p1/sub".to_string(),
        Ok(clash_body(&[("A", "a.example")])),
    )]));
    let mut ids = id_gen();
    let result = resolve_proxy_providers_controlled(
        &providers,
        "sub",
        "now",
        ProviderResolveLimits {
            max_nodes_per_provider: 0,
            ..Default::default()
        },
        &ProviderResolveControl::default(),
        &fetch,
        &mut ids,
    )
    .await;
    assert!(
        result.fatal_error.is_some(),
        "provider parser limits must discard the whole operation rather than become partial"
    );
    assert!(!result.any_failed);
    assert!(result.servers.is_empty());
}

#[tokio::test]
async fn provider_output_budget_accepts_exact_small_merged_array() {
    let providers = providers_yaml(
        "p1:\n  type: http\n  url: https://p1/sub\np2:\n  type: http\n  url: https://p2/sub\n",
    );
    let responses = HashMap::from([
        (
            "https://p1/sub".to_string(),
            Ok(clash_body(&[("A", "a.example")])),
        ),
        (
            "https://p2/sub".to_string(),
            Ok(clash_body(&[("B", "b.example")])),
        ),
    ]);
    let mut baseline_ids = id_gen();
    let baseline = resolve_proxy_providers_controlled(
        &providers,
        "sub",
        "now",
        ProviderResolveLimits::default(),
        &ProviderResolveControl::default(),
        &mock_fetch(responses.clone()),
        &mut baseline_ids,
    )
    .await;
    let exact_bytes = baseline.output_metrics.output_bytes().unwrap();
    assert_eq!(baseline.servers.len(), 2);

    // Two one-item JSON arrays become one two-item array: this is one byte smaller than naively
    // summing them. An exact boundary must remain legal, otherwise ordinary small provider
    // subscriptions are spuriously rejected.
    let mut ids = id_gen();
    let result = resolve_proxy_providers_controlled(
        &providers,
        "sub",
        "now",
        ProviderResolveLimits {
            max_output_bytes: exact_bytes,
            ..Default::default()
        },
        &ProviderResolveControl::default(),
        &mock_fetch(responses),
        &mut ids,
    )
    .await;
    assert!(result.fatal_error.is_none(), "{result:?}");
    assert_eq!(result.servers.len(), 2);
    assert_eq!(result.output_metrics.output_bytes().unwrap(), exact_bytes);
}

#[tokio::test]
async fn provider_output_budget_fails_closed_before_second_provider_append() {
    let providers = providers_yaml(
        "p1:\n  type: http\n  url: https://p1/sub\np2:\n  type: http\n  url: https://p2/sub\n",
    );
    let responses = HashMap::from([
        (
            "https://p1/sub".to_string(),
            Ok(clash_body(&[("A", "a.example")])),
        ),
        (
            "https://p2/sub".to_string(),
            Ok(clash_body(&[("B", "b.example")])),
        ),
    ]);
    let mut baseline_ids = id_gen();
    let baseline = resolve_proxy_providers_controlled(
        &providers,
        "sub",
        "now",
        ProviderResolveLimits::default(),
        &ProviderResolveControl::default(),
        &mock_fetch(responses.clone()),
        &mut baseline_ids,
    )
    .await;
    let exact_bytes = baseline.output_metrics.output_bytes().unwrap();

    let mut ids = id_gen();
    let result = resolve_proxy_providers_controlled(
        &providers,
        "sub",
        "now",
        ProviderResolveLimits {
            max_output_bytes: exact_bytes - 1,
            ..Default::default()
        },
        &ProviderResolveControl::default(),
        &mock_fetch(responses),
        &mut ids,
    )
    .await;
    assert!(
        !result.any_failed,
        "limit is not a partial provider failure"
    );
    assert!(
        result
            .fatal_error
            .as_ref()
            .is_some_and(|error| error.message.contains("输出超过上限")),
        "provider aggregate must fail closed at the output boundary: {result:?}"
    );
    assert!(
        result.servers.len() <= 1,
        "the over-budget provider must never be appended"
    );
}

#[tokio::test]
async fn controlled_provider_resolve_keeps_network_concurrent_but_bounded() {
    let providers = providers_yaml(
        "p1:\n  type: http\n  url: https://p1/sub\np2:\n  type: http\n  url: https://p2/sub\np3:\n  type: http\n  url: https://p3/sub\np4:\n  type: http\n  url: https://p4/sub\n",
    );
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let fetch = {
        let active = Arc::clone(&active);
        let peak = Arc::clone(&peak);
        move |url: &str| {
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            let name = url
                .trim_start_matches("https://")
                .trim_end_matches("/sub")
                .to_string();
            Box::pin(async move {
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(clash_body(&[(name.as_str(), "node.example")]))
            })
                as Pin<Box<dyn Future<Output = Result<String, ProviderFetchError>> + Send>>
        }
    };
    let mut g = id_gen();
    let result = resolve_proxy_providers_controlled(
        &providers,
        "sub1",
        "now",
        ProviderResolveLimits {
            max_concurrent_fetches: 2,
            max_provider_body_bytes: 1024,
            max_buffered_body_bytes: 2048,
            ..Default::default()
        },
        &ProviderResolveControl::default(),
        &fetch,
        &mut g,
    )
    .await;
    assert_eq!(result.servers.len(), 4);
    assert_eq!(peak.load(Ordering::SeqCst), 2, "必须并发但不得越过上限");
}

fn ss(name: &str, host: &str, port: u16, pw: &str) -> ServerConfig {
    ServerConfig {
        id: format!("id-{name}"),
        name: name.to_string(),
        protocol: Protocol::Shadowsocks,
        address: host.to_string(),
        port,
        password: Some(pw.to_string()),
        ..Default::default()
    }
}

#[test]
fn fingerprint_excludes_name_includes_cred_and_network() {
    // 同 host:port:cred，仅 name 不同 → 同指纹（改名不误判增删）。
    let a = ss("HK-1", "cdn.com", 443, "pw");
    let b = ss("HK-2", "cdn.com", 443, "pw");
    assert_eq!(
        server_fingerprint(&a),
        server_fingerprint(&b),
        "改名不改指纹"
    );
    // 不同 cred → 不同指纹。
    let c = ss("HK-1", "cdn.com", 443, "other");
    assert_ne!(
        server_fingerprint(&a),
        server_fingerprint(&c),
        "cred 变 → 指纹变"
    );
    // 不同 network → 不同指纹。
    let mut d = ss("HK-1", "cdn.com", 443, "pw");
    d.network = Some("ws".to_string());
    assert_ne!(
        server_fingerprint(&a),
        server_fingerprint(&d),
        "network 变 → 指纹变"
    );
    // 指纹形态：protocol|address|port|cred|network（无 name）。
    assert_eq!(server_fingerprint(&a), "shadowsocks|cdn.com|443|pw|tcp");
}

#[test]
fn dedupe_keeps_first_of_same_fingerprint() {
    let inline = ss("inline", "x.com", 443, "pw");
    let provider = ss("provider-dup", "x.com", 443, "pw"); // 同指纹（仅 name 异）
    let other = ss("other", "y.com", 443, "pw");
    let out = dedupe_by_fingerprint(vec![inline, provider, other]);
    assert_eq!(out.len(), 2, "同指纹去重");
    assert_eq!(out[0].name, "inline", "首见（内联）保留");
}

#[test]
fn extract_proxy_providers_detects_and_ignores() {
    let with = "proxy-providers:\n  p1:\n    type: http\n    url: https://x.com\n";
    assert!(extract_proxy_providers(with).is_some());
    // 纯 inline clash（无 providers）→ None。
    assert!(extract_proxy_providers("proxies:\n  - {name: a, type: ss, server: a.com, port: 1, cipher: aes-256-gcm, password: p}").is_none());
    // 非 clash → None。
    assert!(extract_proxy_providers("vless://u@h:443#n").is_none());
}
