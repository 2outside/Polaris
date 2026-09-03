use super::subscription_transport::{classify_transport_failure, sanitized_body_read_error};
use super::*;
use crate::test_support::TestDir;
use polaris_net_stack::safe_redirect::{
    safe_redirect_fetch, safe_redirect_fetch_until, FetchInit, GuardedTarget, HttpClient,
    SafeFetchRejectReason, SafeRedirectFetchOptions,
};
use polaris_net_stack::ssrf::DnsLookup;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::thread;

// ── 本地 HTTP server（stdlib，回环端口；不触碰宿主网络）──────────────────
//
// 与 net-stack `tests/fetch_pipeline.rs` 的 server 同形态但**刻意不共用**：那个在 net-stack 的
// tests/ 下（跨 crate 不可 import），且此处要的是「真 reqwest 打真 socket」。共用需提第三个
// dev-dep crate —— 二十行 stdlib 不值得（简约阶梯）。

fn spawn_server(responses: Vec<Vec<u8>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 回环端口");
    let addr = listener.local_addr().expect("取端口");
    thread::spawn(move || {
        for resp in responses {
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0u8; 8192];
            let _ = sock.read(&mut buf);
            let _ = sock.write_all(&resp);
            let _ = sock.flush();
        }
    });
    addr
}

fn http_response(status_line: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status_line}\r\n");
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    out.push_str("Connection: close\r\n\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn transport_failure_classifier_extracts_stable_categories_without_echoing_sources() {
    let cases = [
            (true, true, "contains secret.example", "request timeout"),
            (
                false,
                true,
                "failed to lookup address information for token.example",
                "dns resolution failed",
            ),
            (
                false,
                true,
                "No connection could be made because the target machine actively refused it. (os error 10061)",
                "connection refused or unreachable",
            ),
            (
                false,
                true,
                "certificate verify failed for secret.example",
                "tls handshake failed",
            ),
            (false, true, "opaque source", "connection failed"),
            (false, false, "opaque source", "request failed"),
        ];
    for (is_timeout, is_connect, source, expected) in cases {
        let actual = classify_transport_failure(is_timeout, is_connect, source);
        assert_eq!(actual, expected);
        assert!(
            !actual.contains("secret.example") && !actual.contains("token.example"),
            "稳定诊断不得回显 source chain 里的订阅域名"
        );
    }
}

#[test]
fn body_read_failures_map_to_existing_subscription_error_keywords() {
    assert!(sanitized_body_read_error(BodyReadError::Stalled).contains("timeout"));
    assert!(sanitized_body_read_error(BodyReadError::TooLarge(1024)).contains("too large"));
    assert_eq!(
        sanitized_body_read_error(BodyReadError::Io {
            received: 0,
            message: "connection reset by peer".to_string(),
        }),
        "connection refused or unreachable"
    );
}

// ── provider 陷阱的门（见模块文档）────────────────────────────────────────

#[tokio::test]
async fn http_runtime_builds_a_real_client_without_panicking() {
    // **这扇门守的是「编译过 ≠ 能跑」**：reqwest `rustls-no-provider` 下若没先装 ring provider，
    // `Client::builder().build()` 在 client.rs:2482 直接 panic!。
    // 删掉 HttpRuntime::new 里的 install_ring_provider() → 本测试 panic 转红。
    let rt = HttpRuntime::new().expect("建 client 不得失败");
    assert!(
        rustls::crypto::CryptoProvider::get_default().is_some(),
        "ring provider 必须已安装——否则 reqwest 建 client 时 panic"
    );
    // 真发一个请求以证明 client 可用（打回环，不碰宿主网络/公网）。
    let addr = spawn_server(vec![http_response("200 OK", &[], b"ok")]);
    let init = FetchInit {
        user_agent: app_user_agent(),
        ..Default::default()
    };
    let r = rt
        .fetch(&format!("http://{addr}/probe"), &init)
        .await
        .expect("回环请求应成功");
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"ok");
}

// ── HttpClient 契约门 ────────────────────────────────────────────────────

#[tokio::test]
async fn fetch_does_not_follow_redirects_and_returns_location() {
    // 契约硬要求：**不得自动跟随**（自动跟随 = SSRF 逐跳复检被绕过）。
    // 若 HttpRuntime::new 把 Policy::none() 改成默认（follow）→ 本测试转红。
    let addr = spawn_server(vec![http_response(
        "302 Found",
        &[("Location", "https://evil.internal/secret")],
        b"",
    )]);
    let rt = HttpRuntime::new().unwrap();
    let init = FetchInit::default();
    let r = rt.fetch(&format!("http://{addr}/r"), &init).await.unwrap();
    assert_eq!(r.status, 302, "30x 必须原样返回，不得跟随");
    assert_eq!(r.location.as_deref(), Some("https://evil.internal/secret"));
}

#[tokio::test]
async fn fetch_headers_are_case_insensitively_retrievable() {
    let addr = spawn_server(vec![http_response(
        "200 OK",
        &[("Content-Type", "text/yaml"), ("ETag", "\"abc\"")],
        b"proxies: []",
    )]);
    let rt = HttpRuntime::new().unwrap();
    let r = rt
        .fetch(&format!("http://{addr}/s"), &FetchInit::default())
        .await
        .unwrap();
    assert_eq!(r.header("content-type"), Some("text/yaml"));
    assert_eq!(r.header("etag"), Some("\"abc\""));
}

#[tokio::test]
async fn fetch_body_over_limit_errors_and_never_truncates() {
    // MinimalResponse doc 的硬契约：超限**中断并 Err**，不得截断后返回
    // （截断 = 把超大订阅变成「解析出半截节点」的坏数据，比明确失败更糟）。
    let body = vec![b'x'; 4096];
    let addr = spawn_server(vec![http_response("200 OK", &[], &body)]);
    let rt = HttpRuntime::new().unwrap();
    let init = FetchInit {
        max_body_bytes: Some(1024),
        ..Default::default()
    };
    let r = rt.fetch(&format!("http://{addr}/big"), &init).await;
    assert!(
        r.is_err(),
        "超限必须 Err，实得 Ok（= 截断后返回，契约违反）"
    );
}

#[tokio::test]
async fn fetch_network_error_surfaces_as_err_not_panic() {
    // 关键分层：连不上 → Err（reason=Network），由 safe_redirect_fetch 归类；不得 panic。
    let rt = HttpRuntime::new().unwrap();
    // 端口 1 上不会有 listener（无副作用、不触碰宿主网络配置）。
    let error = rt
        .fetch(
            "http://127.0.0.1:1/nope?token=must-not-leak",
            &FetchInit::default(),
        )
        .await
        .expect_err("连不上必须 Err");
    assert!(!error.contains("must-not-leak"), "错误不得回显订阅凭据");
    assert!(!error.contains("token="), "错误不得回显订阅 query");
}

// ── 经本机入站的两个构造器：scheme × 入站类型 配对门（「经代理更新订阅」断链的根因）────
//
// 此前订阅/图标两条链都用 `via_local_proxy`（`http://127.0.0.1:{port}`）打 `update-in`，而它是
// sing-box **`type:"socks"`** 入站（`config-engine/builder/inbounds.rs:86-105`）—— 明文 HTTP
// 打 socks 服务器首字节就对不上，整条「经代理更新订阅」恒失败。
//
// 该缺陷**靠「构建成功」根本发现不了**（建 client 本来就成功，失败在真握手），故这里起真回环
// 服务器实测协议：socks5 变体必须真说 socks5；http 变体必须**仍**说 HTTP（`probe-in-k` 是纯
// `http` 入站，被误改成 socks5 会让测速在真机上全线超时——正是本批刻意不把两者合并的原因）。

/// 极小 SOCKS5 服务器（RFC1928 no-auth + CONNECT），握手完成后**直接**在同一连接上
/// 回 `body`（客户端此时认为隧道已建立，会在其上发明文 HTTP，正好被我们当请求读掉）。
///
/// 仅支持一次连接、no-auth、CONNECT —— 够钉住「reqwest 到底说不说 socks5」这一件事。
///
/// 第二个返回值把观察到的 **CONNECT 目标**（`(ATYP, 地址串)`）回传给用例：`0x03` = 域名原样
/// 转交代理端解析（`socks5h`），`0x01` = 客户端已在本机解析成 IP（`socks5`）。这是
/// 「解析归属」唯一能被自动断言的地面证据 —— 见
/// [`HttpRuntime::via_local_socks_proxy`] 的「域名解析归属」小节。
fn spawn_socks5_server(
    body: &'static str,
) -> (SocketAddr, std::sync::mpsc::Receiver<(u8, String)>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 回环端口");
    let addr = listener.local_addr().expect("取端口");
    let (target_tx, target_rx) = std::sync::mpsc::channel::<(u8, String)>();
    thread::spawn(move || {
        let Ok((mut sock, _)) = listener.accept() else {
            return;
        };
        // 1) 问候：VER=5, NMETHODS=n, METHODS[n]。
        let mut head = [0u8; 2];
        if sock.read_exact(&mut head).is_err() || head[0] != 0x05 {
            return; // 首字节不是 0x05 ⇒ 客户端说的不是 socks5（正是回归形态）
        }
        let mut methods = vec![0u8; head[1] as usize];
        if sock.read_exact(&mut methods).is_err() {
            return;
        }
        // 2) 选 no-auth。
        if sock.write_all(&[0x05, 0x00]).is_err() {
            return;
        }
        // 3) 请求：VER=5, CMD=1(CONNECT), RSV=0, ATYP, ADDR, PORT。
        let mut req = [0u8; 4];
        if sock.read_exact(&mut req).is_err() || req[0] != 0x05 || req[1] != 0x01 {
            return;
        }
        let addr_len = match req[3] {
            0x01 => 4,
            0x04 => 16,
            0x03 => {
                let mut n = [0u8; 1];
                if sock.read_exact(&mut n).is_err() {
                    return;
                }
                n[0] as usize
            }
            _ => return,
        };
        let mut rest = vec![0u8; addr_len + 2]; // ADDR + PORT
        if sock.read_exact(&mut rest).is_err() {
            return;
        }
        // 回传 CONNECT 目标（域名 → 原样字符串；IPv4 → 点分十进制），供解析归属断言。
        let observed = match req[3] {
            0x03 => String::from_utf8_lossy(&rest[..addr_len]).into_owned(),
            0x01 => format!("{}.{}.{}.{}", rest[0], rest[1], rest[2], rest[3]),
            _ => String::new(),
        };
        let _ = target_tx.send((req[3], observed));
        // 4) 回成功（BND.ADDR=0.0.0.0:0，客户端不校验）。
        if sock
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .is_err()
        {
            return;
        }
        // 5) 隧道内的明文 HTTP 请求 → 直接回响应。
        let mut buf = [0u8; 8192];
        let _ = sock.read(&mut buf);
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = sock.write_all(resp.as_bytes());
        let _ = sock.flush();
    });
    (addr, target_rx)
}

#[tokio::test]
async fn via_local_socks_proxy_really_speaks_socks5_to_a_socks_inbound() {
    // 变异验证：把 `via_local_socks_proxy` 的 scheme 改回 `http://` → reqwest 发的首字节是
    // 'C'(CONNECT) 而非 0x05 → 上面的 server 直接 return → 请求失败 → 本测试转红。
    // 摘掉 Cargo.toml 的 reqwest `socks` feature → `Proxy::all` 直接 Err → 同样转红。
    let (addr, _targets) = spawn_socks5_server("OK-VIA-SOCKS");
    let rt = HttpRuntime::via_local_socks_proxy(addr.port())
        .expect("建经本机 socks 代理 client 不得失败（socks feature 未启用时会在此 Err）");
    // 目标用回环地址：本地解析无需真 DNS，且请求真正落到上面的 socks server 上。
    let r = rt
        .fetch("http://127.0.0.1:9/sub", &FetchInit::default())
        .await
        .expect("经 socks5 代理的请求应成功（http:// 代理打 socks 入站必失败）");
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"OK-VIA-SOCKS");
}

/// **变异锁（解析归属）**：把 `via_local_socks_proxy` 的 scheme 从 `socks5h://` 改回
/// `socks5://` → reqwest 走 `DnsResolve::Local`、先在本机把域名解析成 IP 再发 ATYP=0x01
/// → 本用例的 `atyp == 0x03` 断言当场转红（且 `sub.invalid` 本地解析必失败，请求直接 Err）。
///
/// 这条钉的是功能语义而非协议语义：用户开「经代理更新订阅」正是因为**本地**解析不可信
/// （被污染/被封锁/泄漏域名），域名必须原样交给 sing-box 由代理端解析。
#[tokio::test]
async fn via_local_socks_proxy_hands_the_hostname_to_the_proxy_not_the_local_resolver() {
    let (addr, targets) = spawn_socks5_server("OK-REMOTE-DNS");
    let rt = HttpRuntime::via_local_socks_proxy(addr.port()).expect("建经本机 socks 代理 client");
    // `.invalid` 是 RFC 2606 保留 TLD：本机**永远解析不出来**（不碰宿主 DNS、不出网）。
    // 本地解析变体会在这里直接失败；代理端解析变体则把域名原样发给上面的 mock server。
    let r = rt
        .fetch("http://sub.invalid/list", &FetchInit::default())
        .await
        .expect("socks5h 不做本地解析 → 请求应到达 mock socks server");
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"OK-REMOTE-DNS");

    let (atyp, target) = targets
        .recv_timeout(Duration::from_secs(5))
        .expect("mock socks server 应观测到 CONNECT 目标");
    assert_eq!(
        atyp, 0x03,
        "必须 ATYP=DOMAIN（域名交代理端解析）；实得 {atyp:#04x} 说明客户端在本机解析了"
    );
    assert_eq!(target, "sub.invalid", "域名须原样转交，不得被本机改写成 IP");
}

struct StaticLookup(Vec<String>);

impl DnsLookup for StaticLookup {
    fn lookup_all(&self, _host: &str) -> impl Future<Output = Result<Vec<String>, String>> + Send {
        let ips = self.0.clone();
        async move { Ok(ips) }
    }
}

#[tokio::test]
async fn direct_guarded_fetch_pins_socket_but_preserves_hostname_header() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 回环端口");
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let n = socket.read(&mut buf).unwrap_or(0);
        tx.send(String::from_utf8_lossy(&buf[..n]).into_owned())
            .unwrap();
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
    });

    let runtime = HttpRuntime::new().unwrap();
    let response = runtime
        .fetch_guarded(
            &format!("http://pin.invalid:{}/sub", addr.port()),
            &FetchInit::default(),
            &GuardedTarget {
                host: "pin.invalid".to_string(),
                addresses: vec![addr.ip()],
            },
        )
        .await
        .expect("真实 dial 应使用 guard 提供的地址");
    assert_eq!(response.body, b"ok");
    let request = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(
        request
            .lines()
            .any(|line| line.eq_ignore_ascii_case(&format!("host: pin.invalid:{}", addr.port()))),
        "DNS pin 不得把 HTTP Host 改写成 IP: {request:?}"
    );
}

#[tokio::test]
async fn proxied_hostname_fake_ip_still_uses_remote_domain_resolution() {
    let (addr, targets) = spawn_socks5_server("OK-FAKEIP-REMOTE");
    let runtime = HttpRuntime::via_local_socks_proxy(addr.port()).unwrap();
    let response = safe_redirect_fetch(SafeRedirectFetchOptions {
        fetch_impl: &runtime,
        url: "http://fake-sub.invalid/list",
        user_agent: "Polaris/test".to_string(),
        headers: None,
        exempt_fake_ip: true,
        max_redirects: None,
        timeout_ms: Some(1_000),
        max_body_bytes: Some(1024),
        lookup: &StaticLookup(vec!["198.18.9.9".to_string()]),
    })
    .await
    .expect("代理域名 FakeIP 应放行并由 SOCKS5h 恢复真实域名");
    assert_eq!(response.body, b"OK-FAKEIP-REMOTE");
    let (atyp, target) = targets.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(atyp, 0x03, "不得把本机 FakeIP pin 给 Polaris SOCKS");
    assert_eq!(target, "fake-sub.invalid");
}

#[tokio::test]
async fn absolute_deadline_covers_terminal_body_after_headers() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 回环端口");
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = socket.read(&mut buf);
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n")
            .unwrap();
        socket.flush().unwrap();
        thread::sleep(Duration::from_millis(200));
        let _ = socket.write_all(b"ok");
    });
    let runtime = HttpRuntime::with_resolve_overrides(&[("body-deadline.invalid", addr)]).unwrap();
    let result = safe_redirect_fetch_until(
        SafeRedirectFetchOptions {
            fetch_impl: &runtime,
            url: &format!("http://body-deadline.invalid:{}/sub", addr.port()),
            user_agent: "Polaris/test".to_string(),
            headers: None,
            exempt_fake_ip: false,
            max_redirects: None,
            timeout_ms: None,
            max_body_bytes: Some(1024),
            lookup: &StaticLookup(vec!["8.8.8.8".to_string()]),
        },
        std::time::Instant::now() + Duration::from_millis(30),
    )
    .await;
    assert_eq!(result.unwrap_err().reason, SafeFetchRejectReason::Timeout);
}

#[tokio::test]
async fn via_local_proxy_still_speaks_plain_http_to_an_http_inbound() {
    // 反向门：`probe-in-k` / `probe-*-in` 是 sing-box **纯 `http`** 入站（`inbounds.rs`
    // `http_loopback`），测速探测池全靠它。若有人图省事把 `via_local_proxy` 也改成 socks5
    // 「统一一下」，真机上测速会全线超时而单测毫无察觉 —— 本门就是拦这个。
    //
    // 断言方式：HTTP 代理的请求行是**绝对 URI**（`GET http://host/path HTTP/1.1`），
    // socks5 则是先发 0x05 二进制握手。直接看首字节/请求行即可区分。
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 回环端口");
    let addr = listener.local_addr().expect("取端口");
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let n = sock.read(&mut buf).unwrap_or(0);
            let _ = tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            let _ = sock.flush();
        }
    });

    let rt = HttpRuntime::via_local_proxy(addr.port()).expect("建经本机 http 代理 client");
    let r = rt
        .fetch("http://example.invalid/probe", &FetchInit::default())
        .await
        .expect("经 http 代理的请求应成功");
    assert_eq!(r.status, 200);

    let first_request = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("代理服务器应收到请求");
    assert!(
        first_request.starts_with("GET http://example.invalid/probe "),
        "http 入站要求绝对 URI 的明文 HTTP 请求行（socks5 会先发 0x05 二进制握手），实得: {:?}",
        first_request.lines().next()
    );
}

// ── 下载适配器：纯函数门 ─────────────────────────────────────────────────

#[test]
fn classify_403_ratelimit_is_distinguishable_from_403_forbidden() {
    // 二者表象同、处置相反（限流=等一会就好；无权限=永远不好）→ 消息必须能区分。
    let limited = classify_download_status(403, &[("x-ratelimit-remaining".into(), "0".into())])
        .expect("403 必须是错误");
    assert!(
        format!("{limited}").contains("限流"),
        "限流 403 的消息应点明限流，实得: {limited}"
    );

    let forbidden = classify_download_status(403, &[]).expect("403 必须是错误");
    assert!(matches!(forbidden, DownloadError::HttpStatus(403)));
}

#[test]
fn classify_2xx_is_not_an_error() {
    assert!(classify_download_status(200, &[]).is_none());
    assert!(classify_download_status(204, &[]).is_none());
    assert!(matches!(
        classify_download_status(500, &[]),
        Some(DownloadError::HttpStatus(500))
    ));
}

#[test]
fn gh_mirror_is_fallback_not_primary_and_only_for_github() {
    let http = Arc::new(HttpRuntime::new().unwrap());
    let handle = tokio::runtime::Runtime::new().unwrap().handle().clone();
    let dl = CoreDownloader::new(http, handle).with_gh_proxy("https://ghproxy.net/");

    let gh = dl.candidates("https://github.com/a/b/releases/download/v1/core.zip");
    assert_eq!(gh.len(), 2, "GitHub 资产应有原址 + 镜像两个候选");
    assert!(gh[0].starts_with("https://github.com/"), "原址必须**优先**");
    assert!(gh[1].starts_with("https://ghproxy.net/https://github.com/"));

    // 非 GitHub 地址不套镜像（gh 镜像只代理 GitHub）。
    let other = dl.candidates("https://example.com/core.zip");
    assert_eq!(other, vec!["https://example.com/core.zip".to_string()]);
}

#[test]
fn no_gh_proxy_configured_means_no_mirror_candidate() {
    let http = Arc::new(HttpRuntime::new().unwrap());
    let handle = tokio::runtime::Runtime::new().unwrap().handle().clone();
    let dl = CoreDownloader::new(http, handle);
    assert_eq!(
        dl.candidates("https://github.com/a/b/core.zip").len(),
        1,
        "未配前缀时不得凭空造镜像地址"
    );
}

// ── 下载适配器：真 socket 门 ─────────────────────────────────────────────

#[test]
fn download_follows_redirect_and_returns_bytes() {
    // 下载路径**必须**自己跟随 30x（GitHub 资产必然 302 到 objects.githubusercontent.com），
    // 因为 client 全局关了 redirect。若把 `open_download_response` 的 30x 分支删掉 → 本测试转红
    // （U1 把重定向跟随从 `download_once` 抽进了两条腿共用的 `open_download_response`，
    //  故锚点是后者 —— 与下方 `streaming_download_follows_redirects_and_hashes_while_writing`
    //  的措辞对齐）。
    let rt = tokio::runtime::Runtime::new().unwrap();
    let addr = spawn_server(vec![
        // 首跳 302 → 同 server 的 /asset
        b"HTTP/1.1 302 Found\r\nLocation: /asset\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_vec(),
        http_response("200 OK", &[], b"CORE-BYTES"),
    ]);
    let http = Arc::new(HttpRuntime::new().unwrap());
    let dl = CoreDownloader::new(http, rt.handle().clone());
    // 在 blocking 线程上调（契约：download 是同步桥）。
    let bytes = std::thread::spawn(move || dl.download(&format!("http://{addr}/start")))
        .join()
        .unwrap()
        .expect("下载应成功");
    assert_eq!(bytes, b"CORE-BYTES");
}

/// 🟡 **进度回调必须真被逐 chunk 调用，且带上 Content-Length 分母**。
///
/// 此前 `CoreDownloader::download` 只返 `Vec<u8>`，`update_download` 因此只能发
/// `downloading(0%)` / `downloaded(100%)` 两点，进度条整段 indeterminate。
///
/// **变异锁**：把 `read_body_capped_with_progress` 里的 `cb(...)` 删掉、或把 `expected`
/// 换成 `None` 传下去 ⇒ 本条转红。
#[test]
fn download_with_progress_reports_received_and_total() {
    use std::sync::Mutex as StdMutex;

    let rt = tokio::runtime::Runtime::new().unwrap();
    let body = vec![b'z'; 3000];
    let total = body.len() as u64;
    let addr = spawn_server(vec![http_response("200 OK", &[], &body)]);
    let http = Arc::new(HttpRuntime::new().unwrap());
    let dl = CoreDownloader::new(http, rt.handle().clone());

    /// 一次进度回调的观测记录：`(已收字节, Content-Length)`。
    type ProgressLog = Arc<StdMutex<Vec<(u64, Option<u64>)>>>;
    let seen: ProgressLog = Arc::new(StdMutex::new(Vec::new()));
    let sink = seen.clone();
    let cb: Arc<DownloadProgressFn> = Arc::new(move |received, expected| {
        sink.lock().unwrap().push((received, expected));
    });

    let bytes =
        std::thread::spawn(move || dl.download_with_progress(&format!("http://{addr}/asset"), cb))
            .join()
            .unwrap()
            .expect("下载应成功");
    assert_eq!(bytes.len(), body.len());

    let seen = seen.lock().unwrap();
    assert!(!seen.is_empty(), "进度回调一次都没触发 = 进度腿是死的");
    assert_eq!(
        seen.last().copied(),
        Some((total, Some(total))),
        "末次回调须是 (总字节, Content-Length)——分母缺失则百分比算不出来"
    );
    // 单调不减（received 是累计值，不是增量）。
    assert!(
        seen.windows(2).all(|w| w[0].0 <= w[1].0),
        "received 必须是累计值：{seen:?}"
    );
}

#[test]
fn download_without_progress_still_works_trait_path_unchanged() {
    // 门：加进度腿不得改变既有 trait 路径的行为（staged 周期走的就是它）。
    let rt = tokio::runtime::Runtime::new().unwrap();
    let addr = spawn_server(vec![http_response("200 OK", &[], b"PLAIN")]);
    let http = Arc::new(HttpRuntime::new().unwrap());
    let dl = CoreDownloader::new(http, rt.handle().clone());
    let bytes = std::thread::spawn(move || dl.download(&format!("http://{addr}/x")))
        .join()
        .unwrap()
        .expect("无进度回调路径应照常成功");
    assert_eq!(bytes, b"PLAIN");
}

#[test]
fn download_incomplete_body_is_reported_not_silently_accepted() {
    // Content-Length 撒谎（说 100，实给 5）→ 必须报 Incomplete，**不得**把半截字节当成功返回
    // （半截核二进制过了 SHA256 校验才被发现 = 白下一次；更糟的是若没校验就落位）。
    let rt = tokio::runtime::Runtime::new().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf);
            let _ = sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort",
            );
            let _ = sock.flush();
        }
    });
    let http = Arc::new(HttpRuntime::new().unwrap());
    let dl = CoreDownloader::new(http, rt.handle().clone());
    let err = std::thread::spawn(move || dl.download(&format!("http://{addr}/x")))
        .join()
        .unwrap()
        .expect_err("Content-Length 不符必须报错");
    assert!(
        matches!(
            err,
            DownloadError::Incomplete {
                received: 5,
                expected: 100
            }
        ),
        "应报 Incomplete{{received:5,expected:100}}，实得: {err:?}"
    );
}

// ── 流式落盘腿（U1）───────────────────────────────────────────────────────
//
// 全部走本文件既有的**回环** mock server（`spawn_server`，见其上方注释：stdlib TcpListener
// 绑 127.0.0.1，不触碰宿主网络），与内存腿的门同形态。

/// 收进内存的假 sink（测试用）：验「写进去的字节 == 服务端发的字节」。
#[derive(Clone, Default)]
struct MemSink(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for MemSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// 写到第 `fail_after` 字节就报错的 sink（测「写盘失败**不得**冒充下载不完整」）。
struct FailingSink {
    written: usize,
    fail_after: usize,
}

impl std::io::Write for FailingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.written + buf.len() > self.fail_after {
            return Err(std::io::Error::other("mock: disk full"));
        }
        self.written += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// 🟡 **流式腿必须与内存腿走同一条编排：重定向照跟、字节一个不少、摘要边写边算。**
///
/// **变异探针**：把 `download_once_to_sink` 里的 `open_download_response` 换成一份
/// 自己复制的请求逻辑（漏掉 30x 分支）⇒ 本条转红。
#[test]
fn streaming_download_follows_redirects_and_hashes_while_writing() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let payload = vec![b'q'; 5000];
    let addr = spawn_server(vec![
        b"HTTP/1.1 302 Found\r\nLocation: /asset\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_vec(),
        http_response("200 OK", &[], &payload),
    ]);
    let http = Arc::new(HttpRuntime::new().unwrap());
    let dl = CoreDownloader::new(http, rt.handle().clone());

    let sink = MemSink::default();
    let sink_for_factory = sink.clone();
    let factory: Arc<DownloadSinkFactory> =
        Arc::new(move || Ok(Box::new(sink_for_factory.clone())));
    let noop: Arc<DownloadProgressFn> = Arc::new(|_, _| {});

    let out = std::thread::spawn(move || {
        dl.download_to_sink_with_progress(&format!("http://{addr}/start"), factory, noop)
    })
    .join()
    .unwrap()
    .expect("流式下载应成功");

    assert_eq!(out.bytes, payload.len() as u64);
    assert_eq!(
        *sink.0.lock().unwrap(),
        payload,
        "写进 sink 的字节必须与服务端发的逐字相同"
    );
    assert_eq!(
        out.sha256_hex,
        polaris_updater::verify::sha256_hex(&payload),
        "边写边算的摘要必须等于整包摘要"
    );
}

/// 🟡 **进度回调在流式腿上必须与内存腿同时机同分母。**
///
/// 前端契约零改动的前提就是这条：回调仍在每个 chunk 到达时以 `(累计已收, Content-Length)` 触发。
///
/// **变异探针**：把 sink 版循环里的 `cb(...)` 删掉、或把 `expected` 换成 `None` ⇒ 转红。
#[test]
fn streaming_download_reports_progress_like_the_memory_leg() {
    use std::sync::Mutex as StdMutex;

    let rt = tokio::runtime::Runtime::new().unwrap();
    let payload = vec![b'w'; 4000];
    let total = payload.len() as u64;
    let addr = spawn_server(vec![http_response("200 OK", &[], &payload)]);
    let http = Arc::new(HttpRuntime::new().unwrap());
    let dl = CoreDownloader::new(http, rt.handle().clone());

    /// 一次进度回调的观测记录：`(已收字节, Content-Length)`（同内存腿那条门）。
    type ProgressLog = Arc<StdMutex<Vec<(u64, Option<u64>)>>>;
    let seen: ProgressLog = Arc::new(StdMutex::new(Vec::new()));
    let log = seen.clone();
    let cb: Arc<DownloadProgressFn> = Arc::new(move |received, expected| {
        log.lock().unwrap().push((received, expected));
    });
    let factory: Arc<DownloadSinkFactory> = Arc::new(|| Ok(Box::new(std::io::sink())));

    std::thread::spawn(move || {
        dl.download_to_sink_with_progress(&format!("http://{addr}/asset"), factory, cb)
    })
    .join()
    .unwrap()
    .expect("流式下载应成功");

    let seen = seen.lock().unwrap();
    assert!(!seen.is_empty(), "进度回调一次都没触发 = 进度腿是死的");
    assert_eq!(
        seen.last().copied(),
        Some((total, Some(total))),
        "末次回调须是 (总字节, Content-Length)——分母缺失则百分比算不出来"
    );
    assert!(
        seen.windows(2).all(|w| w[0].0 <= w[1].0),
        "received 必须是累计值：{seen:?}"
    );
}

/// 🟡 **Content-Length 撒谎在流式腿上照样报 Incomplete（不得因为字节已落盘就当成功）。**
#[test]
fn streaming_download_reports_incomplete_body_too() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf);
            let _ = sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort",
            );
            let _ = sock.flush();
        }
    });
    let http = Arc::new(HttpRuntime::new().unwrap());
    let dl = CoreDownloader::new(http, rt.handle().clone());
    let factory: Arc<DownloadSinkFactory> = Arc::new(|| Ok(Box::new(std::io::sink())));
    let noop: Arc<DownloadProgressFn> = Arc::new(|_, _| {});

    let err = std::thread::spawn(move || {
        dl.download_to_sink_with_progress(&format!("http://{addr}/x"), factory, noop)
    })
    .join()
    .unwrap()
    .expect_err("Content-Length 不符必须报错");
    assert!(
        matches!(
            err,
            DownloadError::Incomplete {
                received: 5,
                expected: 100
            }
        ),
        "应报 Incomplete{{received:5,expected:100}}，实得: {err:?}"
    );
}

/// 🟡 **写盘失败必须原样报 IO，绝不冒充「下载不完整」。**
///
/// 磁盘满被报成 Incomplete ⇒ 上层判「网络把包送少了」→ 引导用户一遍遍重下一个永远装不满的盘。
///
/// **变异探针**：把 [`BodyReadError::Sink`] 折叠进 [`BodyReadError::Io`] ⇒ 本条转红
/// （会变成 `Incomplete`，因为服务端给了 Content-Length）。
#[test]
fn sink_write_failure_is_reported_as_io_not_incomplete_download() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let payload = vec![b'p'; 8000];
    let addr = spawn_server(vec![http_response("200 OK", &[], &payload)]);
    let http = Arc::new(HttpRuntime::new().unwrap());
    let dl = CoreDownloader::new(http, rt.handle().clone());
    // 只允许写 10 字节 → 必然在中途失败（服务端要发 8000）。
    let factory: Arc<DownloadSinkFactory> = Arc::new(|| {
        Ok(Box::new(FailingSink {
            written: 0,
            fail_after: 10,
        }))
    });
    let noop: Arc<DownloadProgressFn> = Arc::new(|_, _| {});

    let err = std::thread::spawn(move || {
        dl.download_to_sink_with_progress(&format!("http://{addr}/asset"), factory, noop)
    })
    .join()
    .unwrap()
    .expect_err("写盘失败必须报错");
    assert!(
        matches!(err, DownloadError::Io(_)),
        "写盘失败必须报 Io（磁盘满不是「下载不完整」），实得: {err:?}"
    );
    assert!(format!("{err}").contains("disk full"), "实得: {err}");
    // `BodyReadError::Sink.received` 必须**真被消费**（此前它构造后即被 `..` 丢弃 = 死字段）：
    // 磁盘满的诊断价值一半在「写到第几字节才满」。
    assert!(
        format!("{err}").contains("已写出"),
        "写盘失败的消息须带上已写出的字节数，实得: {err}"
    );
}

fn scratch(tag: &str) -> TestDir {
    TestDir::new(&format!("polaris-http-test-{tag}-"))
}

/// 🟡 **镜像回退必须让下一个候选从「空文件」重写，绝不把字节接在上一次的残料后面。**
///
/// [`DownloadSinkFactory`] 传**工厂**而非句柄，唯一理由就是这条。而此前唯一验字节的用例
/// （`streaming_download_follows_redirects_and_hashes_while_writing`）用的是共享
/// `Arc<Mutex<Vec<u8>>>` 的 `MemSink`：工厂每次返回的「新句柄」共享同一个 buffer 且**不截断**，
/// 于是「换候选时句柄到底有没有被截断」在结构上根本检不出 —— 实现正确但零覆盖。
///
/// 本条用**真文件**（生产就是 `StdFs::open_write` → `File::create`）复现真实回退形态：
/// 首候选写出 5 字节后报 Incomplete，次候选返完整包。
///
/// **变异探针**：把 `StdFs::open_write` 的 `File::create` 换成
/// `OpenOptions::new().append(true).create(true)` ⇒ 盘上变成 `short` + payload，
/// 三条断言（字节数 / 逐字内容 / sha256）同时转红。
#[test]
fn mirror_fallback_rewrites_the_sink_from_scratch() {
    use polaris_updater::traits::UpdateFs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let rt = tokio::runtime::Runtime::new().unwrap();
    let payload = vec![b'm'; 3000];
    let addr = spawn_server(vec![
        // 首候选：声明 100 字节只发 5 → 写出 5 字节后判 Incomplete（镜像回退的真实触发形态）。
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort".to_vec(),
        // 次候选：完整包。
        http_response("200 OK", &[], &payload),
    ]);

    // 候选表要产出「原址 + 镜像」两条，故 host 必须是 GitHub 资产域名；用 resolve 覆盖把它们
    // 都钉到回环 mock server 上（**端口必须写在 URL 里** —— reqwest 的 resolve 覆盖只改 IP，
    // 端口取自 URL）。不出网。
    let http = Arc::new(
        HttpRuntime::with_resolve_overrides(&[("github.com", addr), ("ghmirror.invalid", addr)])
            .unwrap(),
    );
    let url = format!("http://github.com:{}/a/b/core.zip", addr.port());
    let dl = CoreDownloader::new(http, rt.handle().clone())
        .with_gh_proxy(format!("http://ghmirror.invalid:{}/", addr.port()));
    assert_eq!(dl.candidates(&url).len(), 2, "本用例的前提是真有两个候选");

    let dir = scratch("mirror-fallback");
    let tmp = dir.join("update.pkg.polaris-new");
    let created = Arc::new(AtomicUsize::new(0));
    let factory: Arc<DownloadSinkFactory> = {
        let (tmp, created) = (tmp.clone(), created.clone());
        Arc::new(move || {
            created.fetch_add(1, Ordering::SeqCst);
            polaris_updater::traits::StdFs.open_write(&tmp)
        })
    };
    let noop: Arc<DownloadProgressFn> = Arc::new(|_, _| {});

    let out = std::thread::spawn(move || dl.download_to_sink_with_progress(&url, factory, noop))
        .join()
        .unwrap()
        .expect("首候选失败后应由镜像候选把包下完");

    assert_eq!(
        created.load(Ordering::SeqCst),
        2,
        "换候选必须**重新**建句柄（传工厂的全部意义）"
    );
    assert_eq!(
        out.bytes,
        payload.len() as u64,
        "字节数带上了首候选的残料 = 句柄没被截断"
    );
    assert_eq!(
        std::fs::read(&tmp).unwrap(),
        payload,
        "盘上必须**只有**次候选的完整包，不得是 `short` + payload"
    );
    assert_eq!(
        out.sha256_hex,
        polaris_updater::verify::sha256_hex(&payload),
        "摘要必须算在干净的那一份上（否则落位校验会对着一份拼接内容成立）"
    );
}

/// 🟡 **流式腿的读侧超限：与内存腿同一条判定，且已写出的部分绝不算成功。**
///
/// 刻意**不给 Content-Length** ⇒ `open_download_response` 的预检不参与，只剩
/// [`read_body_to_sink_with_progress`] 的读侧闸 —— 那正是内存腿有门、流式腿此前没门的一格。
///
/// **变异探针**：删掉 sink 版循环里的 `if received + chunk.len() > limit` 判定 ⇒ 转红。
#[test]
fn streaming_leg_rejects_an_oversized_body_on_the_read_side_too() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let payload = vec![b'o'; 4096];
    // 无 Content-Length（靠 close 定界）⇒ 预检无从早拒。
    let mut raw = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
    raw.extend_from_slice(&payload);
    let addr = spawn_server(vec![raw]);

    let http = Arc::new(HttpRuntime::new().unwrap());
    let dl = CoreDownloader::new(http, rt.handle().clone()).with_max_bytes(1024);
    let sink = MemSink::default();
    let sink_for_factory = sink.clone();
    let factory: Arc<DownloadSinkFactory> =
        Arc::new(move || Ok(Box::new(sink_for_factory.clone())));
    let noop: Arc<DownloadProgressFn> = Arc::new(|_, _| {});

    let err = std::thread::spawn(move || {
        dl.download_to_sink_with_progress(&format!("http://{addr}/big"), factory, noop)
    })
    .join()
    .unwrap()
    .expect_err("超本腿闸值必须报错，不得把已落盘的部分当成功");
    assert!(format!("{err}").contains("超过上限 1024"), "实得: {err}");

    let written = sink.0.lock().unwrap().len();
    assert!(
        written <= 1024 && written < payload.len(),
        "超限那一 chunk 不得写出去（实得已写 {written} 字节）"
    );
}

/// 🟡 **流式腿的停滞看门狗：与内存腿同一条判定，且已写出的部分绝不算成功。**
///
/// 走**直调**而非端到端：`STALL_TIMEOUT` 是 30s 常量，端到端跑要等半分钟；
/// 而 [`read_body_to_sink_with_progress`] 的 `stall` 本就是形参，直调即可注入 150ms。
///
/// **变异探针**：把 sink 版循环里的 `tokio::time::timeout(stall, resp.chunk())` 换成裸
/// `resp.chunk().await` ⇒ 本条挂死（超时转红）；把 `Stalled` 折叠进 `Io` ⇒ 首条断言转红。
#[tokio::test]
async fn streaming_leg_reports_a_stall_without_accepting_the_partial_write() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hold = Arc::new(AtomicBool::new(true));
    let hold_srv = hold.clone();
    thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf);
            // 发头 + 一小段 body 后**不再发也不关连接** —— 关了就变成 Io/Incomplete，测不到 Stalled。
            let _ = sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\npart",
            );
            let _ = sock.flush();
            while hold_srv.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    });

    let rt = HttpRuntime::new().unwrap();
    let mut resp = rt
        .client()
        .get(format!("http://{addr}/slow"))
        .send()
        .await
        .expect("首字节应到达");
    let sink = MemSink::default();
    let mut sink_handle = sink.clone();
    let err = read_body_to_sink_with_progress(
        &mut resp,
        Some(1024),
        Duration::from_millis(150),
        Some(100),
        None,
        &mut sink_handle,
    )
    .await
    .expect_err("两个 chunk 之间超过看门狗间隔必须报停滞");

    assert!(
        matches!(err, BodyReadError::Stalled),
        "停滞必须报 Stalled（折叠进 Io 会被还原成「下载不完整」，引导用户白重下），实得: {err:?}"
    );
    assert_eq!(
        sink.0.lock().unwrap().len(),
        4,
        "停滞前已写出的字节留在 sink 里（清残件是调用方的责任），但结论必须是失败"
    );
    // 与内存腿共用同一条映射（`DownloadError::Stalled`，不是 Incomplete）。
    assert!(matches!(
        map_body_error(err, Some(100)),
        DownloadError::Stalled(_)
    ));
    hold.store(false, Ordering::Relaxed);
}

/// 🟡 **三处体积闸都是「严格大于才拒」——恰好等于上限的包必须放行。**
///
/// 三处判定（Content-Length 预检 / 内存腿读侧 / 流式腿读侧）今日全用 `>`，但**此前无任何测试
/// 钉住边界**：现有的门一律拿 `limit + 1` 去撞，把任一处改成 `>=` 全套仍绿。
///
/// 本条现在**是 App 腿的地基**（2026-08-17 订正：原写「App 腿的闸值是『声明值 + 裕度』」，
/// 那个裕度已删）。`commands/updater::app_update_size_limit` 现在让闸值**恰好等于**
/// 清单声明的 `fileSize`，删裕度不卡正常包的**全部理由**就是这三处的严格大于语义 ——
/// 任一处改成 `>=`，一个大小正好等于声明值的正常安装包就会被拒，且失败长得像
/// 「服务端给多了」。两边互引，口径必须一致。
///
/// **变异探针**：把三处任一的 `>` 改成 `>=` ⇒ 对应那一段转红。
#[test]
fn size_limit_boundary_admits_a_body_of_exactly_the_limit() {
    const LIMIT: usize = 2048;
    let rt = tokio::runtime::Runtime::new().unwrap();
    let payload = vec![b'e'; LIMIT];

    // ① Content-Length 预检：`n > max_bytes` —— CL 恰好等于闸值必须放行。
    let addr = spawn_server(vec![http_response("200 OK", &[], &payload)]);
    let http = Arc::new(HttpRuntime::new().unwrap());
    let dl = CoreDownloader::new(http, rt.handle().clone()).with_max_bytes(LIMIT);
    let bytes = std::thread::spawn(move || dl.download(&format!("http://{addr}/exact")))
        .join()
        .unwrap()
        .expect("Content-Length 恰好等于闸值不得被预检拒掉");
    assert_eq!(bytes.len(), LIMIT);

    // ② 内存腿读侧：`buf.len() + chunk.len() > limit`。无 Content-Length ⇒ 预检不参与。
    let mut raw = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
    raw.extend_from_slice(&payload);
    let addr2 = spawn_server(vec![raw.clone()]);
    let http2 = Arc::new(HttpRuntime::new().unwrap());
    let dl2 = CoreDownloader::new(http2, rt.handle().clone()).with_max_bytes(LIMIT);
    let bytes2 = std::thread::spawn(move || dl2.download(&format!("http://{addr2}/exact")))
        .join()
        .unwrap()
        .expect("读侧累计恰好等于闸值不得被拒（内存腿）");
    assert_eq!(bytes2.len(), LIMIT);

    // ③ 流式腿读侧：`received + chunk.len() > limit`，同上。
    let addr3 = spawn_server(vec![raw]);
    let http3 = Arc::new(HttpRuntime::new().unwrap());
    let dl3 = CoreDownloader::new(http3, rt.handle().clone()).with_max_bytes(LIMIT);
    let sink = MemSink::default();
    let sink_for_factory = sink.clone();
    let factory: Arc<DownloadSinkFactory> =
        Arc::new(move || Ok(Box::new(sink_for_factory.clone())));
    let noop: Arc<DownloadProgressFn> = Arc::new(|_, _| {});
    let out = std::thread::spawn(move || {
        dl3.download_to_sink_with_progress(&format!("http://{addr3}/exact"), factory, noop)
    })
    .join()
    .unwrap()
    .expect("读侧累计恰好等于闸值不得被拒（流式腿）");
    assert_eq!(out.bytes, LIMIT as u64);
    assert_eq!(sink.0.lock().unwrap().len(), LIMIT);
}

/// 🟡 **体积闸是**形参**：内核腿的 16MiB 与 App 腿的清单闸互不干扰。**
///
/// **变异探针**：把 `open_download_response` 里的 `self.max_bytes` 改回常量
/// `MAX_DOWNLOAD_BYTES` ⇒ 第一条断言转红（一个 1KiB 的闸拦不住 2KiB 的响应）。
#[test]
fn per_leg_size_limit_is_honoured_not_the_global_constant() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let payload = vec![b'x'; 2048];

    // ① 闸收紧到 1 KiB → Content-Length 预检就该早拒（远小于全局 16MiB 常量）。
    let addr = spawn_server(vec![http_response("200 OK", &[], &payload)]);
    let http = Arc::new(HttpRuntime::new().unwrap());
    let tight = CoreDownloader::new(http, rt.handle().clone()).with_max_bytes(1024);
    let err = std::thread::spawn(move || tight.download(&format!("http://{addr}/asset")))
        .join()
        .unwrap()
        .expect_err("超本腿闸值必须早拒");
    assert!(format!("{err}").contains("超过上限"), "实得: {err}");

    // ② 闸放宽到远超全局常量 → 同一份响应照常通过（证明常量已不再是硬编码的天花板）。
    let addr2 = spawn_server(vec![http_response("200 OK", &[], &payload)]);
    let http2 = Arc::new(HttpRuntime::new().unwrap());
    let loose =
        CoreDownloader::new(http2, rt.handle().clone()).with_max_bytes(MAX_DOWNLOAD_BYTES * 8);
    let bytes = std::thread::spawn(move || loose.download(&format!("http://{addr2}/asset")))
        .join()
        .unwrap()
        .expect("闸放宽后应成功");
    assert_eq!(bytes.len(), payload.len());
}

/// 失败分类映射是纯函数，两个消费端共用同一条 —— 逐条钉住。
#[test]
fn body_error_maps_to_the_same_download_error_for_both_legs() {
    assert!(matches!(
        map_body_error(BodyReadError::Stalled, Some(10)),
        DownloadError::Stalled(_)
    ));
    assert!(format!("{}", map_body_error(BodyReadError::TooLarge(99), None)).contains("超过上限"));
    // Io + 已知 Content-Length → Incomplete（结构化，不是泛化 Other）。
    assert!(matches!(
        map_body_error(
            BodyReadError::Io {
                received: 5,
                message: "boom".into()
            },
            Some(100)
        ),
        DownloadError::Incomplete {
            received: 5,
            expected: 100
        }
    ));
    // Io + 长度未知 → Other（算不出 Incomplete 就不许编一个）。
    assert!(matches!(
        map_body_error(
            BodyReadError::Io {
                received: 5,
                message: "boom".into()
            },
            None
        ),
        DownloadError::Other(_)
    ));
    // 写盘失败即便有 Content-Length 也**不得**变成 Incomplete。
    assert!(matches!(
        map_body_error(
            BodyReadError::Sink {
                received: 5,
                source: std::io::Error::other("disk full")
            },
            Some(100)
        ),
        DownloadError::Io(_)
    ));
}

#[test]
fn content_length_check_is_shared_by_both_legs() {
    assert!(check_content_length(100, Some(100)).is_ok());
    assert!(check_content_length(100, None).is_ok(), "长度未知即不判");
    assert!(matches!(
        check_content_length(5, Some(100)),
        Err(DownloadError::Incomplete {
            received: 5,
            expected: 100
        })
    ));
    assert!(
        check_content_length(101, Some(100)).is_err(),
        "多给也是不完整（服务端撒谎/被注入）"
    );
}

#[test]
fn download_rejects_oversized_content_length_before_reading_body() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let big = MAX_DOWNLOAD_BYTES + 1;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf);
            let _ = sock.write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Length: {big}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            );
            let _ = sock.flush();
        }
    });
    let http = Arc::new(HttpRuntime::new().unwrap());
    let dl = CoreDownloader::new(http, rt.handle().clone());
    let err = std::thread::spawn(move || dl.download(&format!("http://{addr}/big")))
        .join()
        .unwrap()
        .expect_err("超 16MiB 必须早拒");
    assert!(format!("{err}").contains("超过上限"), "实得: {err}");
}

// ── 换核链路：下载半程的生产组合面门 ─────────────────────────────────────
//
// §K7.1 纪律 + updater 批的等待项：真 CoreDownloader（真 reqwest）**真被注入**
// CoreStagedUpdater → 真下载 → 真 SHA256 校验 → 真落位。
// **未覆盖**（如实登记）：真机换核落位到受保护核目录需 helper 特权写 + ProxyRuntime 停起协同，
// 本机不验（破坏宿主）。本门只证「下载半程」在生产路径上真能跑通，不冒充全链闭环。

#[test]
fn core_swap_download_half_real_downloader_injected_into_staged_updater() {
    use polaris_updater::manifest::VersionManifestEntry;
    use polaris_updater::staged::{
        ApplyOutcome, CoreStagedUpdater, MemoryStateStore, StagedConfig,
    };
    use polaris_updater::traits::StdFs;
    use polaris_updater::verify::sha256_hex_lower;

    let rt = tokio::runtime::Runtime::new().unwrap();
    // 真核字节（内容任意，关键是 SHA256 真校验）。
    let core_bytes = b"POLARIS-FAKE-CORE-BINARY-BYTES".to_vec();
    let sha = sha256_hex_lower(&core_bytes);

    // 真回环 server 服核字节。
    let body = core_bytes.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf);
            let mut resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            resp.extend_from_slice(&body);
            let _ = sock.write_all(&resp);
            let _ = sock.flush();
        }
    });

    let dest = std::env::temp_dir().join(format!("polaris-coreswap-gate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dest);

    let entry = VersionManifestEntry {
        version: "9.9.9".into(), // 远新于 current → 过版本闸
        url: format!("http://{addr}/sing-box.zip"),
        sha256: Some(sha),
        prerelease: false,
        notes: String::new(),
    };

    // ── 真 CoreDownloader 注入 CoreStagedUpdater ──
    let http = Arc::new(HttpRuntime::new().unwrap());
    let downloader = CoreDownloader::new(http, rt.handle().clone());
    let fs = StdFs;
    let store = MemoryStateStore::default();
    let mut cfg = StagedConfig::new(&dest);
    cfg.restrict_band = false; // 手动路径允许跨带（本门测的是下载+校验+落位，非带闸）

    // apply 是同步（内部 download 会 spawn 到 rt.handle 并阻塞等）——须在 blocking 线程调，
    // 不能占用 rt 的 worker。
    let dest2 = dest.clone();
    let outcome = std::thread::spawn(move || {
        let updater = CoreStagedUpdater::new(&downloader, &fs, &store, cfg);
        updater.apply(&entry, "1.0.0", "sing-box")
    })
    .join()
    .unwrap()
    .expect("下载半程应成功（真 socket 收字节 + SHA256 校验过 + 落位）");

    assert_eq!(
        outcome,
        ApplyOutcome::Applied,
        "真下载器注入后，下载→校验→落位应 Applied"
    );
    // 真落位物：dest/sing-box 存在且字节 = 我们服的真核字节。
    let landed = std::fs::read(dest2.join("sing-box")).expect("落位的核应可读");
    assert_eq!(landed, core_bytes, "落位字节须与下载字节逐字节相同");
    let _ = std::fs::remove_dir_all(&dest2);
}

#[test]
fn core_swap_download_half_sha256_mismatch_is_rejected_not_landed() {
    // 变异/安全门：manifest 的 sha256 与真下载字节不符（中间人篡改形态）→ 必须拒绝落位。
    // 证明「下载成功」不等于「盲信落位」——SHA256 校验真的在生产下载路径后面把关。
    use polaris_updater::manifest::VersionManifestEntry;
    use polaris_updater::staged::{CoreStagedUpdater, MemoryStateStore, StagedConfig};
    use polaris_updater::traits::StdFs;

    let rt = tokio::runtime::Runtime::new().unwrap();
    let body = b"REAL-BYTES".to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf);
            let mut resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            resp.extend_from_slice(&body);
            let _ = sock.write_all(&resp);
            let _ = sock.flush();
        }
    });

    let dest =
        std::env::temp_dir().join(format!("polaris-coreswap-mismatch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dest);
    let entry = VersionManifestEntry {
        version: "9.9.9".into(),
        url: format!("http://{addr}/sing-box.zip"),
        // 故意给错 hash（64 个 a）。
        sha256: Some("a".repeat(64)),
        prerelease: false,
        notes: String::new(),
    };
    let http = Arc::new(HttpRuntime::new().unwrap());
    let downloader = CoreDownloader::new(http, rt.handle().clone());
    let fs = StdFs;
    let store = MemoryStateStore::default();
    let mut cfg = StagedConfig::new(&dest);
    cfg.restrict_band = false;

    let dest2 = dest.clone();
    let res = std::thread::spawn(move || {
        let updater = CoreStagedUpdater::new(&downloader, &fs, &store, cfg);
        updater.apply(&entry, "1.0.0", "sing-box")
    })
    .join()
    .unwrap();

    assert!(res.is_err(), "SHA256 不符必须报错，不得落位");
    assert!(
        !dest2.join("sing-box").exists(),
        "校验失败时核**不得**落到 dest（否则坏核入库）"
    );
    let _ = std::fs::remove_dir_all(&dest2);
}

// ── UnlockHttp 契约门（已迁出）───────────────────────────────────────────
//
// 原先这里有 4 扇门（never-err / redirect_chain / cf-mitigated 捕获 / body 截断）。
// `impl UnlockHttp for HttpRuntime` 迁到 `polaris-unlock-transport` 后，那些门**同步迁过去了**
// 并且更强 —— 它们现在打的是**真正的生产传输**（wreq + Chrome 指纹），而不是一个已经不再
// 服务解锁的 reqwest client。见 `crates/unlock-transport/src/lib.rs` 的 tests：
//   never_errs_on_network_failure_it_reports_status_zero
//   records_redirect_chain_without_following_automatically
//   captures_cf_mitigated_header_for_challenge_detection
//   truncates_body_rather_than_failing
//   declared_accept_encoding_is_decodable_end_to_end（新增：解压门）
//   browser_headers_reach_the_wire（新增：头集线级门）

// ── WarpHttp 契约门 ──────────────────────────────────────────────────────

#[tokio::test]
async fn warp_status_request_preserves_4xx_for_classification() {
    // 契约关键：unregister **不抛错**，保留 4xx 让 classify_deregister_result 分类
    // （403 + body code 1020 → Retry，而非 Drop）。若这里跟 json_request 一样把非 2xx 变 Err，
    // 分类器就永远收不到 status → 1020 被误判成 Drop → 设备泄漏在 CF 侧。
    let addr = spawn_server(vec![http_response("403 Forbidden", &[], b"error 1020")]);
    let rt = HttpRuntime::new().unwrap();
    let resp = rt
        .status_request(&WarpHttpRequest {
            method: WarpHttpMethod::Delete,
            url: format!("http://{addr}/reg/dev"),
            headers: Default::default(),
            body: None,
        })
        .await
        .expect("status_request 对 4xx 必须 Ok（保留状态），不得 Err");
    assert_eq!(resp.status, 403);
    assert_eq!(resp.body, "error 1020");
}

#[tokio::test]
async fn warp_json_request_maps_non_2xx_to_err_with_status_and_body() {
    let addr = spawn_server(vec![http_response("403 Forbidden", &[], b"error 1020")]);
    let rt = HttpRuntime::new().unwrap();
    let err = rt
        .json_request(&WarpHttpRequest {
            method: WarpHttpMethod::Post,
            url: format!("http://{addr}/reg"),
            headers: Default::default(),
            body: Some("{}".into()),
        })
        .await
        .expect_err("register 非 2xx 必须 Err");
    assert!(err.contains("403"), "错误须带 status，实得: {err}");
    assert!(
        err.contains("1020"),
        "错误须带 body（CF 的 1020 在里面），实得: {err}"
    );
}

/// 🔵 **`warp_client` 惰性**：建 `HttpRuntime` 不得顺带建 WARP client。
///
/// [`HttpRuntime::via_local_proxy`] 是**测速热路径**（每个被测节点一次），而 WARP client 与测速毫无
/// 关系：Linux 上每建一个就读一次系统信任库（reqwest 0.13.4 → `rustls_platform_verifier`
/// `others.rs:88-100`，十几到几十毫秒），Mac/Win 便宜但同样是白建。
///
/// **变异锁**：把三个构造器里的 `OnceLock::new()` 换回 `build_warp_client()?` → 第一条断言转红。
#[test]
fn warp_client_is_not_built_until_a_warp_request_needs_it() {
    let rt = HttpRuntime::via_local_proxy(1080).expect("建经代理 client 不得失败");
    assert!(
        rt.warp_client.get().is_none(),
        "测速热路径的构造器不得顺带建 WARP client"
    );
    // 首次取用才建，且此后复用同一个（惰性 ≠ 每次重建）。
    let first: *const reqwest::Client = rt.warp_client().expect("按需构造必须成功");
    assert!(rt.warp_client.get().is_some(), "取用后必须已缓存");
    let second: *const reqwest::Client = rt.warp_client().expect("第二次取用必须成功");
    assert!(std::ptr::eq(first, second), "惰性构造必须只建一次");
}

// ── WARP TLS 指纹隔离门（FX-warp-tls / 审查表 row32）───────────────────────
//
// warp_client 必须钉 TLS1.2 + HTTP/1.1（对齐 上游 node-`https` 规避 CF 1020），且**独立于**共享 client。
// 下列门在**线级**断言（真 reqwest 打真回环 socket、解析 ClientHello 字节）——reqwest 不暴露 client 的 TLS
// 配置（读不到），且唯有线级才防得住「配置设了但 reqwest 未真正下发 pin」这类组合面漏（§K7.1）。

/// 起一个回环 TCP listener，捕获客户端发来的**首个**请求字节（TLS ClientHello 或明文 HTTP），
/// 经 channel 回传后随即关连接（握手/请求随之快速失败——本门只看已捕获字节，不需完成握手）。
fn spawn_capture() -> (SocketAddr, std::sync::mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 回环端口");
    let addr = listener.local_addr().expect("取端口");
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            sock.set_read_timeout(Some(Duration::from_millis(500))).ok();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                match sock.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        // TLS 握手记录（byte0=0x16，[3..5]=record len）完整即停。
                        if buf.len() >= 5 && buf[0] == 0x16 {
                            let rec = 5 + u16::from_be_bytes([buf[3], buf[4]]) as usize;
                            if buf.len() >= rec {
                                break;
                            }
                        }
                        // 明文 HTTP：请求头结束（CRLFCRLF）即停。
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                        if buf.len() >= 16 * 1024 {
                            break;
                        }
                    }
                    Err(_) => break, // 读超时/连接错——回传已有字节。
                }
            }
            let _ = tx.send(buf);
        }
    });
    (addr, rx)
}

/// 解析 ClientHello 扩展表 → (是否宣告 TLS1.3, ALPN 协议名列表)。**只**解析定位 1020 判据的两项：
/// supported_versions(0x002b) 是否含 0x0304、ALPN(0x0010) 的协议名。字节级、无第三方 TLS 解析依赖。
fn parse_client_hello(buf: &[u8]) -> (bool, Vec<Vec<u8>>) {
    // record(5) + handshake 头(4 = type1 + len3) + client_version(2) + random(32)
    let mut p = 5 + 4 + 2 + 32;
    if p + 1 > buf.len() {
        return (false, Vec::new());
    }
    let sid = buf[p] as usize; // session_id
    p += 1 + sid;
    if p + 2 > buf.len() {
        return (false, Vec::new());
    }
    let cs = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize; // cipher_suites
    p += 2 + cs;
    if p + 1 > buf.len() {
        return (false, Vec::new());
    }
    let comp = buf[p] as usize; // compression_methods
    p += 1 + comp;
    if p + 2 > buf.len() {
        return (false, Vec::new());
    }
    let ext_total = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2;
    let end = (p + ext_total).min(buf.len());
    let mut offers_tls13 = false;
    let mut alpn: Vec<Vec<u8>> = Vec::new();
    while p + 4 <= end {
        let ty = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let ln = u16::from_be_bytes([buf[p + 2], buf[p + 3]]) as usize;
        p += 4;
        if p + ln > end {
            break;
        }
        let data = &buf[p..p + ln];
        if ty == 0x002b && !data.is_empty() {
            // supported_versions: list_len(1) 后接 u16 版本表；0x0304 = TLS1.3。
            let list_len = data[0] as usize;
            let list = &data[1..(1 + list_len).min(data.len())];
            if list.chunks(2).any(|c| c == [0x03, 0x04]) {
                offers_tls13 = true;
            }
        } else if ty == 0x0010 && data.len() >= 2 {
            // ALPN: list_len(2) 后接 [name_len(1) name..]。
            let mut q = 2;
            while q < data.len() {
                let nl = data[q] as usize;
                q += 1;
                if q + nl > data.len() {
                    break;
                }
                alpn.push(data[q..q + nl].to_vec());
                q += nl;
            }
        }
        p += ln;
    }
    (offers_tls13, alpn)
}

#[tokio::test]
async fn warp_client_pins_tls12_and_http1_on_the_wire() {
    // 线级门：warp_send（经 WarpHttp impl）打出的 ClientHello 必须【不宣告 TLS1.3】且【ALPN 只 http/1.1】。
    //   变异①（载荷）：删 build_warp_client 的 .tls_version_max(TLS_1_2) → 出现 0x0304 → offers_tls13 转真 → 红。
    //   变异②：删 .http1_only() → 本构建无 http2 feature，ALPN 仍只 http/1.1，本门**不转红**（如实标注：
    //           http1_only 是前瞻护栏，其牙在开启 http2 feature 后才咬——见对照门注释）。
    //   变异③（隔离）：warp_send 改回 &self.client → shared 宣告 TLS1.3 → offers_tls13 转真 → 红。
    let (addr, rx) = spawn_capture();
    let rt = HttpRuntime::new().unwrap();
    let _ = rt
        .json_request(&WarpHttpRequest {
            method: WarpHttpMethod::Post,
            url: format!("https://127.0.0.1:{}/reg", addr.port()),
            headers: Default::default(),
            body: Some("{}".into()),
        })
        .await; // 握手必失败（listener 读完即关）——只取已捕获的 ClientHello。
    let hello = rx
        .recv_timeout(Duration::from_secs(3))
        .expect("应捕获到 ClientHello");
    assert_eq!(hello.first(), Some(&0x16u8), "首字节应为 TLS 握手记录");
    let (offers_tls13, alpn) = parse_client_hello(&hello);
    assert!(
        !offers_tls13,
        "WARP client 不得宣告 TLS1.3（supported_versions 不得含 0x0304）"
    );
    assert!(
        !alpn.is_empty(),
        "应解析出 ALPN，实得空（解析失败或未发 ALPN）"
    );
    assert!(
        alpn.iter().all(|p| p != b"h2"),
        "WARP client ALPN 不得含 h2，实得 {alpn:?}"
    );
    assert!(
        alpn.iter().any(|p| p == b"http/1.1"),
        "WARP client ALPN 应含 http/1.1，实得 {alpn:?}"
    );
}

#[tokio::test]
async fn shared_client_offers_tls13_on_the_wire_unlike_warp() {
    // 对照门：共享 client **确实**宣告 TLS1.3 —— 这正是 warp_client 相对它收窄掉的**载荷维度**（TLS1.2 pin）。
    // 二义：(1) 证 warp 与 shared 是真差异、非两 client 恰好同形；(2) 证 parse_client_hello 非「恒返 false」的
    // 坏解析器（坏解析器会让 assert!(offers_tls13) 转红）。
    //
    // **h2 不作对照**：本仓 reqwest 关掉了 `http2` feature（`default-features=false`），故**两个** client 的
    // ALPN 都只报 http/1.1 —— h2 规避是**构建级**属性、非 warp 专属。warp_client 仍显式 `.http1_only()` 作
    // 前瞻护栏（若日后有人开 http2 feature，shared 会向 CF 类端点报 h2，而 warp 借此仍锁 http/1.1）。
    let (addr, rx) = spawn_capture();
    let rt = HttpRuntime::new().unwrap();
    let _ = rt
        .client()
        .get(format!("https://127.0.0.1:{}/", addr.port()))
        .send()
        .await;
    let hello = rx
        .recv_timeout(Duration::from_secs(3))
        .expect("应捕获到 ClientHello");
    let (offers_tls13, alpn) = parse_client_hello(&hello);
    assert!(
        offers_tls13,
        "共享 client 应宣告 TLS1.3（正是 warp_client 收窄掉的载荷维度）"
    );
    assert!(
        alpn.iter().any(|p| p == b"http/1.1"),
        "本构建（无 http2 feature）两 client ALPN 均应含 http/1.1，实得 {alpn:?}"
    );
}

#[tokio::test]
async fn warp_send_forwards_okhttp_headers_to_wire() {
    // 契约门：warp_send 逐条下发请求头（okhttp UA + CF-Client-Version 由 mesh 层给，见 warp_http.rs）。
    //   变异：warp_send 删 `for (k,v) in &req.headers` 循环 → UA 不达线 → 红。
    //   兼防「误给 warp_client 设默认 UA=Polaris/x 覆盖」的回归（本门断言线上是 okhttp 而非 Polaris）。
    let (addr, rx) = spawn_capture();
    let rt = HttpRuntime::new().unwrap();
    let mut headers = std::collections::BTreeMap::new();
    headers.insert("User-Agent".to_string(), "okhttp/3.12.1".to_string());
    headers.insert("CF-Client-Version".to_string(), "a-7.21-0721".to_string());
    let _ = rt
        .json_request(&WarpHttpRequest {
            method: WarpHttpMethod::Post,
            url: format!("http://127.0.0.1:{}/reg", addr.port()), // 明文：直接读 HTTP 请求头
            headers,
            body: Some("{}".into()),
        })
        .await;
    let req = rx
        .recv_timeout(Duration::from_secs(3))
        .expect("应捕获到 HTTP 请求");
    let text = String::from_utf8_lossy(&req);
    assert!(
        text.contains("okhttp/3.12.1"),
        "请求须带 okhttp UA，实得:\n{text}"
    );
    assert!(
        text.contains("a-7.21-0721"),
        "请求须带 CF-Client-Version，实得:\n{text}"
    );
    assert!(
        !text.contains("Polaris/"),
        "WARP 请求不得漏出应用默认 UA（Polaris/…）"
    );
}

// ── 真实 HTTPS 冒烟（默认 #[ignore]：依赖公网，不进默认 gate）─────────────
//
// 证「ring-backed rustls 握手对真实公网 HTTPS 端点真能打通」——这是「编译过 + 回环 HTTP 跑通」
// **之外**唯一能证 TLS 栈真可用的路径（回环用的是明文 HTTP，不碰 TLS 握手）。
// 纯出站 GET，不接管网络（brief 明确允许）。跑法：`cargo test -p polaris -- --ignored real_https`。
#[tokio::test]
#[ignore = "依赖公网 HTTPS 连通性；手动 --ignored 跑"]
async fn real_https_get_handshakes_and_returns_body() {
    let rt = HttpRuntime::new().expect("建 client");
    let init = FetchInit {
        user_agent: app_user_agent(),
        max_body_bytes: Some(64 * 1024),
        timeout_ms: Some(10_000),
        ..Default::default()
    };
    // 稳定的小 HTTPS 端点（返回请求者 IP 的纯文本；小、无重定向）。
    let r = rt
        .fetch("https://api.ipify.org/", &init)
        .await
        .expect("真实 HTTPS 握手 + 请求应成功（ring/rustls 打通）");
    assert_eq!(r.status, 200, "实得 status={}", r.status);
    assert!(!r.body.is_empty(), "应收到非空 body（TLS 握手 + 传输成功）");
}

// ── DnsLookup 生产实现门 ─────────────────────────────────────────────────

#[tokio::test]
async fn system_dns_resolves_localhost_to_loopback() {
    // 只解析 localhost（不出网、不碰宿主 DNS 配置）。证明 SSRF guard 终于有解析器可注入。
    let ips = SystemDnsLookup
        .lookup_all("localhost")
        .await
        .expect("解析 localhost");
    assert!(!ips.is_empty());
    assert!(
        ips.iter().any(|i| i == "127.0.0.1" || i == "::1"),
        "localhost 应解析到回环，实得: {ips:?}"
    );
}

// ── C19：更新链路经代理决策真值表 ────────────────────────────────────────

#[test]
fn resolve_main_session_via_proxy_truth_table() {
    // 核未运行 → 恒直连（自举友好），无视 msvp。
    assert!(!resolve_main_session_via_proxy(false, None));
    assert!(!resolve_main_session_via_proxy(false, Some(true)));
    assert!(!resolve_main_session_via_proxy(false, Some(false)));
    // 核运行中 → 默认经代理（缺省/开）；仅显式 false 才直连。
    assert!(resolve_main_session_via_proxy(true, None), "缺省=经代理");
    assert!(resolve_main_session_via_proxy(true, Some(true)));
    assert!(
        !resolve_main_session_via_proxy(true, Some(false)),
        "显式关闭=直连"
    );
}

#[test]
fn resolve_update_proxy_target_port_gate() {
    // 经代理但端口不可用（0）→ 强制直连（端口闸），且 port 透传。
    assert_eq!(resolve_update_proxy_target(true, None, 0), (false, 0));
    // 经代理 + 有效端口 → viaProxy=true，port>0（自洽）。
    assert_eq!(
        resolve_update_proxy_target(true, None, 45678),
        (true, 45678)
    );
    // 核未运行 → 直连，即便端口非 0（核未运行时 update-in 口本就不存在）。
    assert_eq!(
        resolve_update_proxy_target(false, None, 45678),
        (false, 45678)
    );
    // 显式关闭 msvp → 直连，即便端口有效。
    assert_eq!(
        resolve_update_proxy_target(true, Some(false), 45678),
        (false, 45678)
    );
    // 自洽不变式：via_proxy=true ⟹ port>0。
    for running in [true, false] {
        for msvp in [None, Some(true), Some(false)] {
            for port in [0u16, 1, 45678] {
                let (via, p) = resolve_update_proxy_target(running, msvp, port);
                if via {
                    assert!(p > 0, "via_proxy=true 时 port 必 >0（running={running} msvp={msvp:?} port={port}）");
                }
            }
        }
    }
}

/// # 为什么排除 Windows（2026-08-05，Windows CI 腿首次跑通后实测）
///
/// 空主机名在 unix 的 `getaddrinfo` 上本地即返 `EAI_NONAME`，而 **Windows 把它解析成本机地址**
/// ⇒ `lookup_all("")` 返回非空 `Ok` ⇒ 本断言在 Windows 上必红。
///
/// **这不是安全缺口**：被守的那条腿在实现里是
/// `if ips.is_empty() { return Err(...) }`（见 `SystemDnsLookup::lookup_all`）——
/// `Ok(vec![])` 根本构造不出来，「空循环放行」在实现层已被堵死。本用例守的是另一条腿
/// （`lookup_host(...).map_err(...)?` 的失败传播），那行代码**与平台无关**，
/// Linux/macOS 覆盖到它就等于覆盖了 Windows 上的同一行。
///
/// 没有换成「跨平台都注定失败」的输入，是因为找不到一个既满足这条又满足下面那三个约束
/// （不出网 / 不看解析器脸色 / 本地即失败）的输入 —— 猜一个再让 Windows 腿红一次，
/// 比诚实门控更糟。
#[cfg(not(windows))]
#[tokio::test]
async fn system_dns_failure_is_err_not_empty_ok() {
    // 关键失败安全：解析失败必须 Err。若返回 Ok(vec![])，guard 的「逐 IP 判定」会**空循环通过**
    // → 解析失败静默变成「SSRF 检查通过」。
    //
    // **失败输入必须在 resolver 之前就注定失败，不能靠上游 DNS 诚实回 NXDOMAIN**：原先用
    // `this-host-does-not-exist.invalid`，在会劫持/fake-ip 的解析器后面（家用路由跑
    // OpenClash 就是）会解析「成功」→ 本门转红（2026-07-28 在 5.238 实测）。空主机名让
    // `getaddrinfo` 本地即返 EAI_NONAME，不出网、不看解析器脸色，走的仍是同一条 `map_err` 腿。
    let r = SystemDnsLookup.lookup_all("").await;
    assert!(
        r.is_err(),
        "解析失败必须 Err（Ok(vec![]) 会让 guard 空循环放行）"
    );
}
