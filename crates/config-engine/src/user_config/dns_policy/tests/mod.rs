use super::*;

#[test]
fn outbound_is_a_strict_tagged_union() {
    let node: DnsServerOutbound = serde_json::from_str(r#"{"type":"node","nodeId":"n1"}"#).unwrap();
    assert_eq!(
        node,
        DnsServerOutbound::Node {
            node_id: "n1".into()
        }
    );
    assert!(serde_json::from_str::<DnsServerOutbound>(r#"{"type":"unknown"}"#).is_err());
}

#[test]
fn hosts_first_roundtrips_without_losing_fallback() {
    let action = DnsPolicyAction::HostsFirst {
        hosts_server_id: "hosts".into(),
        fallback: Box::new(DnsPolicyAction::Server {
            server_id: "real".into(),
        }),
    };
    let json = serde_json::to_value(&action).unwrap();
    assert_eq!(
        serde_json::from_value::<DnsPolicyAction>(json).unwrap(),
        action
    );
}
