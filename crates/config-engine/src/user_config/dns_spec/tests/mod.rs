use super::*;

#[test]
fn doh_domain() {
    let r = parse_dns_server_spec(Some("https://doh.pub/dns-query")).unwrap();
    assert_eq!(r.server_type, DnsServerType::Https);
    assert_eq!(r.server, "doh.pub");
    assert_eq!(r.port, 443);
    assert_eq!(r.path.as_deref(), Some("/dns-query"));
    assert!(r.is_domain);
}

#[test]
fn doh_ip_with_port() {
    let r = parse_dns_server_spec(Some("https://223.5.5.5:443/dns-query")).unwrap();
    assert_eq!(r.server, "223.5.5.5");
    assert_eq!(r.port, 443);
    assert!(!r.is_domain);
}

#[test]
fn doh_v6() {
    let r = parse_dns_server_spec(Some("https://[2606:4700:4700::1111]/dns-query")).unwrap();
    assert_eq!(r.server, "2606:4700:4700::1111");
    assert_eq!(r.port, 443);
    assert!(!r.is_domain);
}

#[test]
fn dot() {
    let r = parse_dns_server_spec(Some("tls://dns.google")).unwrap();
    assert_eq!(r.server_type, DnsServerType::Tls);
    assert_eq!(r.server, "dns.google");
    assert_eq!(r.port, 853);
}

#[test]
fn bare_ip_udp() {
    let r = parse_dns_server_spec(Some("8.8.8.8")).unwrap();
    assert_eq!(r.server_type, DnsServerType::Udp);
    assert_eq!(r.port, 53);
    assert!(!r.is_domain);
}

#[test]
fn bare_v6() {
    let r = parse_dns_server_spec(Some("::1")).unwrap();
    assert_eq!(r.server_type, DnsServerType::Udp);
    assert_eq!(r.server, "::1");
}

#[test]
fn empty_invalid() {
    assert!(parse_dns_server_spec(None).is_none());
    assert!(parse_dns_server_spec(Some("")).is_none());
    assert!(parse_dns_server_spec(Some("  ")).is_none());
    assert!(parse_dns_server_spec(Some("random text")).is_none());
}

#[test]
fn doh_default_path_when_missing() {
    let r = parse_dns_server_spec(Some("https://doh.pub")).unwrap();
    assert_eq!(r.path.as_deref(), Some("/dns-query"));
}
