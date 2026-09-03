use super::super::*;
use std::sync::Mutex;

use polaris_mesh::warp_http::RegisterOptions;

// ── 组合面门（§K7.1）：mock WarpHttp 注入 + 真 keypair + 真 WarpService → 真解析 WG 草稿 ──────
//
// 只 mock 网络；keypair（ring 种子 + X25519）、register body 构造、响应解析、草稿装配全走真实路径。
// 单测 crate 内部函数不够（那只覆盖 mesh crate）；此处覆盖「命令用的确切装配」。

/// mock：register 返预设 JSON（并把 register body 捕获到共享 handle）；applyLicense（/account）返预设或 Err。
/// 捕获用 `Arc<Mutex<..>>`（clone 一份 handle 留在测试里，mock 本体 move 进 WarpService 后仍可读）。
struct MockWarpHttp {
    register_body: String,
    account_body: Option<String>,
    captured_register_body: Arc<Mutex<Option<String>>>,
}

#[async_trait]
impl WarpHttp for MockWarpHttp {
    async fn json_request(&self, req: &WarpHttpRequest) -> Result<String, String> {
        if req.url.contains("/account") {
            self.account_body
                .clone()
                .ok_or_else(|| "WARP API 403: error 1020".to_string())
        } else {
            *self.captured_register_body.lock().unwrap() = req.body.clone();
            Ok(self.register_body.clone())
        }
    }
    async fn status_request(&self, _req: &WarpHttpRequest) -> Result<WarpHttpResponse, String> {
        Err("status_request 不应在 register/applyLicense 路径被调".to_string())
    }
}

fn canned_register(warp_plus: bool) -> String {
    serde_json::json!({
        "id": "devid-123",
        "token": "secret-token",
        "account": { "id": "acctid", "license": "lic", "warp_plus": warp_plus },
        "config": {
            "client_id": "AAEC",
            "interface": { "addresses": { "v4": "172.16.0.2", "v6": "2606:4700:110::1" } },
            "peers": [{ "public_key": "PEERPUBKEY", "endpoint": { "host": "engage.cloudflareclient.com:2408" } }],
        }
    })
    .to_string()
}

/// base64 字符数 → 解码字节数（仅测试断言长度用）。
fn b64_len(s: &str) -> usize {
    s.bytes().filter(|c| *c != b'=').count() * 6 / 8
}

#[tokio::test]
async fn warp_register_end_to_end_real_keypair_mock_http() {
    // 真种子 → 真 X25519 公钥 → 真 register body → mock CF 响应 → 真解析草稿。
    let seed = generate_warp_seed().expect("CSPRNG 应可用");
    let capture = Arc::new(Mutex::new(None));
    let mock = MockWarpHttp {
        register_body: canned_register(false),
        account_body: None,
        captured_register_body: capture.clone(),
    };
    let svc = WarpService::new(mock, SeededWarpKeypair { seed }, LogWarpLog);
    let draft = svc
        .register(RegisterOptions::default())
        .await
        .expect("mock 注册应产出草稿");

    // 私钥 = 裸种子的 base64（keypair 真喂进去了）。
    assert_eq!(draft.private_key, base64_encode(&seed));
    assert_eq!(b64_len(&draft.private_key), 32, "私钥应为 32 字节");
    // 公钥解析自 mock CF 响应（真解析）。
    assert_eq!(draft.peer_public_key, "PEERPUBKEY");
    assert_eq!(draft.address, "engage.cloudflareclient.com");
    assert_eq!(draft.port, 2408);
    assert_eq!(
        draft.local_address,
        vec!["172.16.0.2/32", "2606:4700:110::1/128"]
    );
    assert_eq!(draft.warp_device.device_id, "devid-123");
    assert_eq!(draft.warp_device.token, "secret-token");
    assert!(!draft.meta.warp_plus);

    // 组合面门加强（keypair 生成门）：register body 里的 "key" == 由种子算出的真 X25519 公钥。
    // 打断 x25519_base → 此断言转红。
    let sent = capture
        .lock()
        .unwrap()
        .clone()
        .expect("register body 应被捕获");
    let parsed: serde_json::Value = serde_json::from_str(&sent).unwrap();
    assert_eq!(
        parsed["key"].as_str().unwrap(),
        base64_encode(&x25519::x25519_base(&seed)),
        "register 请求携带的公钥必须由种子经 X25519 导出"
    );
}

#[tokio::test]
async fn warp_apply_license_upgrades_warp_plus_end_to_end() {
    // license 应用门：register 带 licenseKey → applyLicense（mock /account 返 warp_plus:true）→ 草稿 warpPlus=true。
    let seed = generate_warp_seed().expect("CSPRNG 应可用");
    let mock = MockWarpHttp {
        register_body: canned_register(false),
        account_body: Some(
            serde_json::json!({ "warp_plus": true, "license": "newlic" }).to_string(),
        ),
        captured_register_body: Arc::new(Mutex::new(None)),
    };
    let svc = WarpService::new(mock, SeededWarpKeypair { seed }, LogWarpLog);
    let draft = svc
        .register(RegisterOptions {
            license_key: Some("mykey".to_string()),
        })
        .await
        .expect("注册+许可应成功");
    assert!(
        draft.meta.warp_plus,
        "warp_plus 应经 applyLicense 升为 true"
    );
    assert_eq!(draft.meta.license, "newlic");
}

#[test]
fn base64_encode_matches_known_vectors() {
    assert_eq!(base64_encode(b""), "");
    assert_eq!(base64_encode(b"f"), "Zg==");
    assert_eq!(base64_encode(b"fo"), "Zm8=");
    assert_eq!(base64_encode(b"foo"), "Zm9v");
    assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    // 32 字节 → 44 字符（含 padding）。
    assert_eq!(base64_encode(&[0u8; 32]).len(), 44);
}

#[test]
fn generate_warp_seed_yields_32_bytes_and_varies() {
    let a = generate_warp_seed().expect("CSPRNG 可用");
    let b = generate_warp_seed().expect("CSPRNG 可用");
    assert_eq!(a.len(), 32);
    assert_ne!(a, b, "两次种子应不同（CSPRNG）");
}
