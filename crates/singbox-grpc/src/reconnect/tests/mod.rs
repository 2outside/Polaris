use super::*;

#[test]
fn auth_request_rejects_invalid_metadata_without_panicking() {
    let secret = Some("line-one\nline-two".to_string());
    assert!(auth_request(&secret, ()).is_err());
}

#[test]
fn auth_request_sets_bearer_value_for_valid_secret() {
    let secret = Some("abc-123".to_string());
    let request = auth_request(&secret, ()).unwrap();
    assert_eq!(
        request
            .metadata()
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        "Bearer abc-123"
    );
}
