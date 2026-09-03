use super::*;
use std::sync::{Arc, Mutex};

/// 记录型 keypair mock：返回固定 (priv, pub)。
struct FixedKeypair;
impl WarpKeypair for FixedKeypair {
    fn generate_keypair(&self) -> (String, String) {
        ("PRIVB64".to_string(), "PUBB64".to_string())
    }
}

#[derive(Clone, Default)]
struct CaptureLog(Arc<Mutex<Vec<String>>>);

impl WarpLog for CaptureLog {
    fn log(&self, level: &str, message: &str) {
        self.0.lock().unwrap().push(format!("{level}:{message}"));
    }
}

impl CaptureLog {
    fn joined(&self) -> String {
        self.0.lock().unwrap().join("\n")
    }
}

/// HTTP mock：按 method+url 片段匹配，返回预设结果。
#[derive(Default, Clone)]
struct MockHttp {
    responses: Arc<Mutex<Vec<MockResp>>>,
}

struct MockResp {
    match_url_contains: String,
    match_method: WarpHttpMethod,
    outcome: MockOutcome,
}

enum MockOutcome {
    JsonOk(String),
    JsonErr(String),
    Status(WarpHttpResponse),
    NetErr(String),
}

impl MockHttp {
    fn push_json_ok(&self, match_url_contains: &str, method: WarpHttpMethod, body: &str) {
        self.responses.lock().unwrap().push(MockResp {
            match_url_contains: match_url_contains.to_string(),
            match_method: method,
            outcome: MockOutcome::JsonOk(body.to_string()),
        });
    }
    fn push_status(
        &self,
        match_url_contains: &str,
        method: WarpHttpMethod,
        resp: WarpHttpResponse,
    ) {
        self.responses.lock().unwrap().push(MockResp {
            match_url_contains: match_url_contains.to_string(),
            match_method: method,
            outcome: MockOutcome::Status(resp),
        });
    }
}

#[async_trait]
impl WarpHttp for MockHttp {
    async fn json_request(&self, req: &WarpHttpRequest) -> Result<String, String> {
        let mut guard = self.responses.lock().unwrap();
        for (i, r) in guard.iter().enumerate() {
            if r.match_method == req.method && req.url.contains(&r.match_url_contains) {
                let outcome = std::mem::replace(
                    &mut guard[i].outcome,
                    MockOutcome::JsonErr("consumed".into()),
                );
                return match outcome {
                    MockOutcome::JsonOk(body) => Ok(body),
                    MockOutcome::JsonErr(e) => Err(e),
                    _ => Err("json_request matched a status outcome".to_string()),
                };
            }
        }
        Err(format!("no mock for {} {}", req.method.as_str(), req.url))
    }

    async fn status_request(&self, req: &WarpHttpRequest) -> Result<WarpHttpResponse, String> {
        let mut guard = self.responses.lock().unwrap();
        for (i, r) in guard.iter().enumerate() {
            if r.match_method == req.method && req.url.contains(&r.match_url_contains) {
                let outcome = std::mem::replace(
                    &mut guard[i].outcome,
                    MockOutcome::JsonErr("consumed".into()),
                );
                return match outcome {
                    MockOutcome::Status(resp) => Ok(resp),
                    MockOutcome::NetErr(e) => Err(e),
                    _ => Err("status_request matched a json outcome".to_string()),
                };
            }
        }
        Err(format!("no mock for {} {}", req.method.as_str(), req.url))
    }
}

fn ok_register_body() -> String {
    serde_json::json!({
        "id": "devid",
        "token": "secret-token",
        "account": { "id": "acctid", "license": "lic", "warp_plus": false },
        "config": {
            "interface": { "addresses": { "v4": "172.16.0.2" } },
            "peers": [{ "public_key": "PEERPUB", "endpoint": { "host": "engage.cloudflareclient.com:2408" } }],
        }
    })
    .to_string()
}

#[tokio::test]
async fn register_no_license_produces_draft() {
    let http = MockHttp::default();
    http.push_json_ok("/reg", WarpHttpMethod::Post, &ok_register_body());
    let svc = WarpService::new(http, FixedKeypair, NoopWarpLog);
    let draft = svc.register(RegisterOptions::default()).await.unwrap();
    assert_eq!(draft.address, "engage.cloudflareclient.com");
    assert_eq!(draft.port, 2408);
    assert_eq!(draft.private_key, "PRIVB64");
    assert_eq!(draft.peer_public_key, "PEERPUB");
    assert_eq!(draft.local_address, vec!["172.16.0.2/32"]);
    assert_eq!(draft.warp_device.device_id, "devid");
    assert_eq!(draft.warp_device.token, "secret-token");
    assert!(!draft.meta.warp_plus);
}

#[tokio::test]
async fn register_with_license_applies_then_updates_warpplus() {
    let http = MockHttp::default();
    http.push_json_ok("/reg", WarpHttpMethod::Post, &ok_register_body());
    http.push_json_ok(
        "/account",
        WarpHttpMethod::Put,
        serde_json::json!({ "warp_plus": true, "license": "newlic" })
            .to_string()
            .as_str(),
    );
    let svc = WarpService::new(http, FixedKeypair, NoopWarpLog);
    let draft = svc
        .register(RegisterOptions {
            license_key: Some("mykey".to_string()),
        })
        .await
        .unwrap();
    assert!(draft.meta.warp_plus);
    assert_eq!(draft.meta.license, "newlic");
}

#[tokio::test]
async fn register_license_failure_degrades_to_free() {
    let http = MockHttp::default();
    http.push_json_ok("/reg", WarpHttpMethod::Post, &ok_register_body());
    // applyLicense 失败：json_request 返 Err。
    http.responses.lock().unwrap().push(MockResp {
        match_url_contains: "/account".to_string(),
        match_method: WarpHttpMethod::Put,
        outcome: MockOutcome::JsonErr("WARP API 403: error 1020".to_string()),
    });
    let svc = WarpService::new(http, FixedKeypair, NoopWarpLog);
    // register 不应因 license 失败而失败（降级免费）。
    let draft = svc
        .register(RegisterOptions {
            license_key: Some("mykey".to_string()),
        })
        .await
        .unwrap();
    assert!(!draft.meta.warp_plus);
}

#[tokio::test]
async fn register_non2xx_errors() {
    let http = MockHttp::default();
    http.responses.lock().unwrap().push(MockResp {
        match_url_contains: "/reg".to_string(),
        match_method: WarpHttpMethod::Post,
        outcome: MockOutcome::JsonErr("WARP API 403: error 1020".to_string()),
    });
    let svc = WarpService::new(http, FixedKeypair, NoopWarpLog);
    let err = svc.register(RegisterOptions::default()).await.unwrap_err();
    assert!(err.contains("403"));
}

#[tokio::test]
async fn lifecycle_logs_keep_stage_but_never_copy_http_credentials_or_body() {
    let http = MockHttp::default();
    http.responses.lock().unwrap().push(MockResp {
        match_url_contains: "/reg".to_string(),
        match_method: WarpHttpMethod::Post,
        outcome: MockOutcome::JsonErr(
            "WARP API 403 Authorization: Bearer SUPER_TOKEN body={license:SUPER_LICENSE}"
                .to_string(),
        ),
    });
    let captured = CaptureLog::default();
    let svc = WarpService::new(http, FixedKeypair, captured.clone());

    let err = svc.register(RegisterOptions::default()).await.unwrap_err();
    assert!(err.contains("SUPER_TOKEN"), "调用方仍应拿到原始业务错误");
    let logs = captured.joined();
    assert!(logs.contains("WARP 注册中"));
    assert!(logs.contains("WARP 注册请求失败"));
    assert!(!logs.contains("SUPER_TOKEN"));
    assert!(!logs.contains("SUPER_LICENSE"));
}

#[tokio::test]
async fn apply_license_requires_credentials() {
    let http = MockHttp::default();
    let svc = WarpService::new(http, FixedKeypair, NoopWarpLog);
    assert!(svc.apply_license("", "tok", "lic").await.is_err());
    assert!(svc.apply_license("dev", "", "lic").await.is_err());
    assert!(svc.apply_license("dev", "tok", "  ").await.is_err());
}

#[tokio::test]
async fn unregister_204_is_done() {
    let http = MockHttp::default();
    http.push_status(
        "/reg/dev-123",
        WarpHttpMethod::Delete,
        WarpHttpResponse {
            status: 204,
            body: String::new(),
        },
    );
    let svc = WarpService::new(http, FixedKeypair, NoopWarpLog);
    assert_eq!(
        svc.unregister("dev-123", "tok").await,
        DeregisterResult::Done
    );
}

#[tokio::test]
async fn unregister_404_is_done() {
    let http = MockHttp::default();
    http.push_status(
        "/reg/dev-123",
        WarpHttpMethod::Delete,
        WarpHttpResponse {
            status: 404,
            body: String::new(),
        },
    );
    let svc = WarpService::new(http, FixedKeypair, NoopWarpLog);
    assert_eq!(
        svc.unregister("dev-123", "tok").await,
        DeregisterResult::Done
    );
}

#[tokio::test]
async fn unregister_403_with_1020_is_retry() {
    let http = MockHttp::default();
    http.push_status(
        "/reg/dev-123",
        WarpHttpMethod::Delete,
        WarpHttpResponse {
            status: 403,
            body: "error 1020".to_string(),
        },
    );
    let svc = WarpService::new(http, FixedKeypair, NoopWarpLog);
    assert_eq!(
        svc.unregister("dev-123", "tok").await,
        DeregisterResult::Retry
    );
}

#[tokio::test]
async fn unregister_401_is_drop() {
    let http = MockHttp::default();
    http.push_status(
        "/reg/dev-123",
        WarpHttpMethod::Delete,
        WarpHttpResponse {
            status: 401,
            body: String::new(),
        },
    );
    let svc = WarpService::new(http, FixedKeypair, NoopWarpLog);
    assert_eq!(
        svc.unregister("dev-123", "tok").await,
        DeregisterResult::Drop
    );
}

#[tokio::test]
async fn unregister_network_error_is_retry() {
    let http = MockHttp::default();
    http.responses.lock().unwrap().push(MockResp {
        match_url_contains: "/reg/dev-123".to_string(),
        match_method: WarpHttpMethod::Delete,
        outcome: MockOutcome::NetErr("ETIMEDOUT".to_string()),
    });
    let svc = WarpService::new(http, FixedKeypair, NoopWarpLog);
    assert_eq!(
        svc.unregister("dev-123", "tok").await,
        DeregisterResult::Retry
    );
}

#[tokio::test]
async fn unregister_no_credentials_is_drop() {
    let http = MockHttp::default();
    let svc = WarpService::new(http, FixedKeypair, NoopWarpLog);
    assert_eq!(svc.unregister("", "tok").await, DeregisterResult::Drop);
    assert_eq!(svc.unregister("dev", "").await, DeregisterResult::Drop);
}
