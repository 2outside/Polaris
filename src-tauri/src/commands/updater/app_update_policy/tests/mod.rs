use serde_json::json;

use super::app_update_channel_is_prerelease;

#[test]
fn app_channel_defaults_and_invalid_values_to_stable() {
    assert!(!app_update_channel_is_prerelease(&json!({})));
    assert!(!app_update_channel_is_prerelease(
        &json!({ "appUpdateChannel": "stable" })
    ));
    assert!(!app_update_channel_is_prerelease(
        &json!({ "appUpdateChannel": "nightly" })
    ));
    assert!(!app_update_channel_is_prerelease(
        &json!({ "appUpdateChannel": true })
    ));
    assert!(app_update_channel_is_prerelease(
        &json!({ "appUpdateChannel": "prerelease" })
    ));
}
