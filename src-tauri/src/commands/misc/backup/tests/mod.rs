use super::*;

#[test]
fn backup_failure_exposes_only_the_stable_error_code() {
    let payload = backup_failure("writeFailed");
    assert_eq!(payload["success"], false);
    assert_eq!(payload["errorCode"], "writeFailed");
    assert!(payload.get("error").is_none());
    assert!(payload.get("diagnostic").is_none());
}
