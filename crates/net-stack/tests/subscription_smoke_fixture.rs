use polaris_config_engine::user_config::server_config::Protocol;
use polaris_net_stack::singbox_import::ImportOrigin;
use polaris_net_stack::subscription::parse_subscription_bundle;

#[test]
fn public_clash_http_smoke_fixture_parses_through_the_subscription_bundle() {
    let clash_http_smoke =
        polaris_source_probe::crate_file!("tests/fixtures/assets/clash-http-smoke.yaml");
    let mut next_id = 0u8;
    let mut id_gen = || {
        next_id += 1;
        format!("fixture-node-{next_id}")
    };

    let bundle = parse_subscription_bundle(
        &clash_http_smoke,
        "fixture-subscription",
        "2026-09-02T00:00:00Z",
        &mut id_gen,
        ImportOrigin::RemoteSubscription,
    );

    assert!(
        bundle.proxy_providers.is_none(),
        "smoke fixture must stay a single inline Clash subscription"
    );
    assert_eq!(
        bundle.parsed.servers.len(),
        1,
        "smoke fixture must parse to exactly one node"
    );

    let server = &bundle.parsed.servers[0];
    assert_eq!(server.protocol, Protocol::Http);
    assert_eq!(server.name, "Polaris Smoke HTTP");
    assert_eq!(server.address, "example.com");
    assert_eq!(server.port, 8080);
    assert_eq!(
        server.subscription_id.as_deref(),
        Some("fixture-subscription")
    );
}
