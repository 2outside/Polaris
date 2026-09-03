use super::*;

#[test]
fn netflix_region_re_extracts_id() {
    let body = r#"{"id":"HK","foo":"bar","countryName":"Hong Kong"}"#;
    let m = NetflixEndpoints::region_re().captures(body);
    assert_eq!(m.and_then(|c| c.get(1)).map(|m| m.as_str()), Some("HK"));
}

#[test]
fn gemini_region_re_extracts_three_letter() {
    let body = "blah,2,1,200,\"USA\",more";
    let m = GeminiEndpoints::region_re().captures(body);
    assert_eq!(m.and_then(|c| c.get(1)).map(|m| m.as_str()), Some("USA"));
}

#[test]
fn disney_assertion_re_extracts_token() {
    let body = r#"{"assertion":"abc123"}"#;
    let m = DisneyEndpoints::assertion_re().captures(body);
    assert_eq!(m.and_then(|c| c.get(1)).map(|m| m.as_str()), Some("abc123"));
}

#[test]
fn disney_country_code_uppercased_match() {
    let body = r#"{"countryCode":"jp"}"#;
    let m = DisneyEndpoints::country_code_re().captures(body);
    assert_eq!(m.and_then(|c| c.get(1)).map(|m| m.as_str()), Some("jp"));
}

#[test]
fn tiktok_store_region_re_extracts_from_nested_json() {
    // 真实形态：{"data":{"store_region":"us"},"message":"success"}
    let body = r#"{"data":{"store_region":"us"},"message":"success"}"#;
    let m = TiktokEndpoints::store_region_re().captures(body);
    assert_eq!(m.and_then(|c| c.get(1)).map(|m| m.as_str()), Some("us"));
}

#[test]
fn tiktok_store_region_re_none_when_absent() {
    let body = r#"{"message":"error","data":{}}"#;
    assert!(TiktokEndpoints::store_region_re().captures(body).is_none());
}

#[test]
fn spotify_status_re_extracts_number() {
    let body = r#"{"status":1,"country":"US"}"#;
    let m = SpotifyEndpoints::status_re().captures(body);
    assert_eq!(m.and_then(|c| c.get(1)).map(|m| m.as_str()), Some("1"));
}

#[test]
fn token_body_template_contains_placeholder() {
    assert!(DisneyEndpoints::TOKEN_BODY_TEMPLATE.contains(DisneyEndpoints::ASSERTION_PLACEHOLDER));
}

#[test]
fn graphql_body_template_contains_placeholder() {
    assert!(
        DisneyEndpoints::GRAPHQL_BODY_TEMPLATE.contains(DisneyEndpoints::REFRESH_TOKEN_PLACEHOLDER)
    );
}

#[test]
fn devices_body_is_valid_json() {
    // 不变量：DEVICES_BODY 必须是合法 JSON（Polaris 经 JSON.stringify 产出）
    let _: serde_json::Value =
        serde_json::from_str(DisneyEndpoints::DEVICES_BODY).expect("DEVICES_BODY must be JSON");
}
