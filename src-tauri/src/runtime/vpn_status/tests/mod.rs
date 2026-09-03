use super::*;

#[test]
fn decoders_filter_unknown_tags_and_keep_native_challenge_shape() {
    let tags = BTreeMap::from([("oc-tag".to_string(), "oc-id".to_string())]);
    let update = daemon::OpenConnectStatusUpdate {
        endpoints: vec![
            daemon::OpenConnectEndpointStatus {
                endpoint_tag: "oc-tag".into(),
                state: "auth-pending".into(),
                auth_challenge: Some(daemon::OpenConnectAuthChallenge {
                    id: "challenge-1".into(),
                    challenge: Some(daemon::open_connect_auth_challenge::Challenge::Browser(
                        daemon::OpenConnectBrowserRequest {
                            url: "https://vpn.example/login?token=secret".into(),
                            cookie_names: vec!["webvpn".into()],
                            ..Default::default()
                        },
                    )),
                    ..Default::default()
                }),
                ..Default::default()
            },
            daemon::OpenConnectEndpointStatus {
                endpoint_tag: "ghost".into(),
                ..Default::default()
            },
        ],
    };
    let decoded = decode_openconnect_status(&update, &tags);
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].server_id, "oc-id");
    let challenge = decoded[0].auth_challenge.as_ref().unwrap();
    assert_eq!(challenge.kind, "browser");
    assert_eq!(challenge.browser.as_ref().unwrap().cookie_names, ["webvpn"]);
}
