//! Subscription-only SOCKS inbound routing guard.
//!
//! The three rules are intentionally adjacent and ordered: resolve through the
//! selected remote DNS transport, reject any resolved local target, then pin
//! the already-reviewed IP to the selected update outbound.

#![forbid(unsafe_code)]

use crate::singbox::{OneOrMany, RouteRule};

pub const SUBSCRIPTION_UPDATE_INBOUND_TAG: &str = "subscription-update-in";

/// Local and non-public ranges that subscription traffic must never reach.
///
/// `198.18.0.0/15` is deliberately absent: sing-box FakeIP uses that range and
/// the resolved address must remain usable by an external TUN mapping.
pub const SUBSCRIPTION_BLOCKED_CIDRS: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::/128",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "::ffff:0:0/104",
    "::ffff:a00:0/104",
    "::ffff:6440:0/106",
    "::ffff:7f00:0/104",
    "::ffff:a9fe:0/112",
    "::ffff:ac10:0/108",
    "::ffff:c0a8:0/112",
];

pub fn subscription_update_route_rules(outbound: &str) -> Vec<RouteRule> {
    let inbound = || {
        Some(OneOrMany::Many(vec![
            SUBSCRIPTION_UPDATE_INBOUND_TAG.to_string()
        ]))
    };
    vec![
        RouteRule {
            inbound: inbound(),
            action: Some("resolve".to_string()),
            server: Some("dns-remote".to_string()),
            ..Default::default()
        },
        RouteRule {
            inbound: inbound(),
            ip_cidr: Some(
                SUBSCRIPTION_BLOCKED_CIDRS
                    .iter()
                    .map(|cidr| (*cidr).to_string())
                    .collect(),
            ),
            action: Some("reject".to_string()),
            no_drop: Some(true),
            ..Default::default()
        },
        RouteRule {
            inbound: inbound(),
            action: Some("route".to_string()),
            outbound: Some(outbound.to_string()),
            ..Default::default()
        },
    ]
}
