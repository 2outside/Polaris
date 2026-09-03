use super::*;

#[test]
fn parse_typical_china_ipip() {
    // location 含一个空段（区县缺）：country 拼接跳过空段，countryCode 仍据 loc[0]/loc[1] 得 cn。
    let body =
        r#"{"ret":"ok","data":{"ip":"1.2.3.4","location":["中国","北京","北京","","电信"]}}"#;
    let info = parse_ipip(body).unwrap();
    assert_eq!(info.ip, "1.2.3.4");
    assert_eq!(info.country.as_deref(), Some("中国 北京 北京 电信"));
    assert_eq!(info.country_code.as_deref(), Some("cn"));
}

#[test]
fn parse_hongkong_maps_hk() {
    let body = r#"{"ret":"ok","data":{"ip":"1.2.3.4","location":["中国","香港","","",""]}}"#;
    assert_eq!(
        parse_ipip(body).unwrap().country_code.as_deref(),
        Some("hk")
    );
}

#[test]
fn parse_foreign_no_country_code() {
    // 境外直连出口：ipip 库无 ISO 码 → countryCode None，但 country 展示串仍在（渲染端 Globe 兜底）。
    let body = r#"{"ret":"ok","data":{"ip":"8.8.8.8","location":["美国","加利福尼亚","","",""]}}"#;
    let info = parse_ipip(body).unwrap();
    assert_eq!(info.country_code, None);
    assert_eq!(info.country.as_deref(), Some("美国 加利福尼亚"));
}

#[test]
fn parse_no_location_country_none() {
    // data.ip 有、location 缺 → ip 保留，country/countryCode 均 None（对齐 上游 parts.length? : undefined）。
    let body = r#"{"ret":"ok","data":{"ip":"1.2.3.4"}}"#;
    let info = parse_ipip(body).unwrap();
    assert_eq!(info.ip, "1.2.3.4");
    assert_eq!(info.country, None);
    assert_eq!(info.country_code, None);
}

#[test]
fn parse_missing_ip_returns_none() {
    // data 无 ip（缺字段）→ None（对齐 上游：d.ip 非 string 即弃）。
    let body = r#"{"ret":"ok","data":{"location":["中国"]}}"#;
    assert!(parse_ipip(body).is_none());
}

#[test]
fn parse_missing_data_returns_none() {
    let body = r#"{"ret":"ok"}"#;
    assert!(parse_ipip(body).is_none());
}

#[test]
fn parse_ret_not_ok_returns_none() {
    let body = r#"{"ret":"err","data":{"ip":"1.2.3.4"}}"#;
    assert!(parse_ipip(body).is_none());
}

#[test]
fn parse_invalid_or_empty_body_returns_none() {
    // 劫持页/portal HTML / 截断响应 → 非法 JSON → None（direct 出口不被假数据污染）。
    assert!(parse_ipip("<html>portal</html>").is_none());
    assert!(parse_ipip("").is_none());
}

#[test]
fn cc_from_location_macau_and_taiwan() {
    assert_eq!(
        cc_from_ipip_location(&["中国".to_string(), "澳门".to_string()]).as_deref(),
        Some("mo")
    );
    assert_eq!(
        cc_from_ipip_location(&["中国".to_string(), "台湾".to_string()]).as_deref(),
        Some("tw")
    );
}

#[test]
fn cc_from_location_empty_or_foreign_is_none() {
    assert_eq!(cc_from_ipip_location(&[]), None);
    assert_eq!(cc_from_ipip_location(&["美国".to_string()]), None);
}
