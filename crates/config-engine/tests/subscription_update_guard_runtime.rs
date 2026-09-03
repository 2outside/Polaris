//! subscription-update-in 的随包 sing-box 1.14 地面门。
//!
//! `check` 只能证明 JSON 可解码；本门还真起核心、真走 SOCKS inbound，并用受控 DNS 与上游
//! SOCKS 观察器证明 resolve → private reject → route 的运行顺序。危险地址若抵达上游观察器即失败。

#[path = "support/core_locator.rs"]
mod core_locator;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use core_locator::{command_for_core, core_or_skip};
use polaris_config_engine::builder::subscription_guard::{
    subscription_update_route_rules, SUBSCRIPTION_UPDATE_INBOUND_TAG,
};
use serde_json::{json, Value};
use tempfile::tempdir;

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn parse_dns_question(packet: &[u8]) -> Option<(String, u16, usize)> {
    if packet.len() < 17 {
        return None;
    }
    let mut cursor = 12;
    let mut labels = Vec::new();
    loop {
        let len = *packet.get(cursor)? as usize;
        cursor += 1;
        if len == 0 {
            break;
        }
        labels.push(std::str::from_utf8(packet.get(cursor..cursor + len)?).ok()?);
        cursor += len;
    }
    let qtype = u16::from_be_bytes([*packet.get(cursor)?, *packet.get(cursor + 1)?]);
    Some((labels.join("."), qtype, cursor + 4))
}

fn dns_answers(name: &str, qtype: u16, rebind_queries: &AtomicUsize) -> Vec<Vec<u8>> {
    match (name, qtype) {
        ("public.test", 1) => vec![Ipv4Addr::new(203, 0, 113, 10).octets().to_vec()],
        ("fakeip.test", 1) => vec![Ipv4Addr::new(198, 18, 1, 2).octets().to_vec()],
        ("loopback.test", 1) => vec![Ipv4Addr::LOCALHOST.octets().to_vec()],
        ("private.test", 1) => vec![Ipv4Addr::new(10, 1, 2, 3).octets().to_vec()],
        ("cgnat.test", 1) => vec![Ipv4Addr::new(100, 64, 1, 2).octets().to_vec()],
        ("linklocal.test", 1) => vec![Ipv4Addr::new(169, 254, 1, 2).octets().to_vec()],
        ("mixed.test", 1) => vec![
            Ipv4Addr::new(203, 0, 113, 20).octets().to_vec(),
            Ipv4Addr::LOCALHOST.octets().to_vec(),
        ],
        ("rebind.test", 1) => {
            if rebind_queries.fetch_add(1, Ordering::SeqCst) == 0 {
                vec![Ipv4Addr::new(203, 0, 113, 30).octets().to_vec()]
            } else {
                vec![Ipv4Addr::LOCALHOST.octets().to_vec()]
            }
        }
        ("ula.test", 28) => vec!["fd00::1".parse::<Ipv6Addr>().unwrap().octets().to_vec()],
        ("mapped.test", 28) => vec!["::ffff:127.0.0.1"
            .parse::<Ipv6Addr>()
            .unwrap()
            .octets()
            .to_vec()],
        _ => Vec::new(),
    }
}

fn spawn_dns() -> (SocketAddr, Arc<AtomicBool>, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let addr = socket.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let rebind_queries = Arc::new(AtomicUsize::new(0));
    let stop_thread = Arc::clone(&stop);
    let rebind_thread = Arc::clone(&rebind_queries);
    thread::spawn(move || {
        let mut packet = [0u8; 2048];
        while !stop_thread.load(Ordering::Acquire) {
            let Ok((len, peer)) = socket.recv_from(&mut packet) else {
                continue;
            };
            let Some((name, qtype, question_end)) = parse_dns_question(&packet[..len]) else {
                continue;
            };
            let answers = dns_answers(&name, qtype, &rebind_thread);
            let mut response = Vec::with_capacity(512);
            response.extend_from_slice(&packet[0..2]);
            response.extend_from_slice(&0x8180u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&(answers.len() as u16).to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&packet[12..question_end]);
            for answer in answers {
                response.extend_from_slice(&[0xc0, 0x0c]);
                response.extend_from_slice(&qtype.to_be_bytes());
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&0u32.to_be_bytes());
                response.extend_from_slice(&(answer.len() as u16).to_be_bytes());
                response.extend_from_slice(&answer);
            }
            let _ = socket.send_to(&response, peer);
        }
    });
    (addr, stop, rebind_queries)
}

fn read_socks_target(stream: &mut TcpStream) -> Option<String> {
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).ok()?;
    let mut methods = vec![0u8; greeting[1] as usize];
    stream.read_exact(&mut methods).ok()?;
    stream.write_all(&[5, 0]).ok()?;
    let mut request = [0u8; 4];
    stream.read_exact(&mut request).ok()?;
    let target = match request[3] {
        1 => {
            let mut raw = [0u8; 4];
            stream.read_exact(&mut raw).ok()?;
            Ipv4Addr::from(raw).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).ok()?;
            let mut raw = vec![0u8; len[0] as usize];
            stream.read_exact(&mut raw).ok()?;
            String::from_utf8(raw).ok()?
        }
        4 => {
            let mut raw = [0u8; 16];
            stream.read_exact(&mut raw).ok()?;
            Ipv6Addr::from(raw).to_string()
        }
        _ => return None,
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).ok()?;
    stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).ok()?;
    Some(target)
}

fn spawn_upstream_socks() -> (SocketAddr, mpsc::Receiver<String>, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    thread::spawn(move || {
        while !stop_thread.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                    if let Some(target) = read_socks_target(&mut stream) {
                        let _ = tx.send(target);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    (addr, rx, stop)
}

fn socks_connect(proxy: SocketAddr, host: &str) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&proxy, Duration::from_secs(2)) else {
        return false;
    };
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
    if stream.write_all(&[5, 1, 0]).is_err() {
        return false;
    }
    let mut method = [0u8; 2];
    if stream.read_exact(&mut method).is_err() || method != [5, 0] {
        return false;
    }
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&80u16.to_be_bytes());
    if stream.write_all(&request).is_err() {
        return false;
    }
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).is_ok() && reply[1] == 0
}

fn wait_listening(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("sing-box SOCKS inbound 未在时限内监听 {addr}");
}

fn config(inbound_port: u16, dns_addr: SocketAddr, upstream_addr: SocketAddr) -> Value {
    let guard_rules = subscription_update_route_rules("fixture-exit");
    json!({
        "log": {"level": "error"},
        "dns": {
            "servers": [{
                "type": "udp",
                "tag": "dns-remote",
                "server": dns_addr.ip().to_string(),
                "server_port": dns_addr.port()
            }],
            "final": "dns-remote",
            "strategy": "prefer_ipv4"
        },
        "inbounds": [{
            "type": "socks",
            "tag": SUBSCRIPTION_UPDATE_INBOUND_TAG,
            "listen": "127.0.0.1",
            "listen_port": inbound_port
        }],
        "outbounds": [{
            "type": "socks",
            "tag": "fixture-exit",
            "server": upstream_addr.ip().to_string(),
            "server_port": upstream_addr.port(),
            "version": "5"
        }],
        "route": {
            "rules": guard_rules,
            "final": "fixture-exit"
        }
    })
}

#[test]
fn bundled_core_enforces_subscription_update_guard_at_runtime() {
    let Some(core) = core_or_skip("subscription-update-in 真运行安全门") else {
        return;
    };
    let (dns_addr, dns_stop, rebind_queries) = spawn_dns();
    let (upstream_addr, observed, upstream_stop) = spawn_upstream_socks();
    let inbound_addr = SocketAddr::from(([127, 0, 0, 1], free_tcp_port()));
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("subscription-update-guard.json");
    std::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&config(inbound_addr.port(), dns_addr, upstream_addr)).unwrap(),
    )
    .unwrap();

    let check = command_for_core(&core)
        .arg("--disable-color")
        .arg("check")
        .arg("-c")
        .arg(&config_path)
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "sing-box check 失败: {}",
        String::from_utf8_lossy(&check.stderr)
    );
    let formatted = command_for_core(&core)
        .arg("format")
        .arg("-c")
        .arg(&config_path)
        .output()
        .unwrap();
    assert!(formatted.status.success());
    let formatted: Value = serde_json::from_slice(&formatted.stdout).unwrap();
    assert_eq!(formatted["route"]["rules"][0]["action"], "resolve");
    assert_eq!(formatted["route"]["rules"][0]["server"], "dns-remote");
    assert_eq!(formatted["route"]["rules"][1]["action"], "reject");
    assert_eq!(formatted["route"]["rules"][1]["no_drop"], true);
    assert_eq!(formatted["route"]["rules"][2]["outbound"], "fixture-exit");

    let mut child = command_for_core(&core)
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_listening(inbound_addr);

    for host in ["public.test", "fakeip.test"] {
        assert!(
            socks_connect(inbound_addr, host),
            "{host} 应允许抵达既有出口"
        );
        let target = observed
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_else(|_| panic!("{host} 未抵达上游 SOCKS"));
        assert!(
            target == "203.0.113.10" || target == "198.18.1.2",
            "resolve action 必须把域名钉成已审查 IP，实得 {target}"
        );
    }

    for host in [
        "loopback.test",
        "private.test",
        "cgnat.test",
        "linklocal.test",
        "ula.test",
        "mapped.test",
        "mixed.test",
    ] {
        assert!(!socks_connect(inbound_addr, host), "{host} 必须被 reject");
        assert!(
            observed.recv_timeout(Duration::from_millis(150)).is_err(),
            "{host} 的危险目标抵达了上游出口"
        );
    }

    assert!(socks_connect(inbound_addr, "rebind.test"));
    assert_eq!(
        observed.recv_timeout(Duration::from_secs(2)).unwrap(),
        "203.0.113.30",
        "首次受控解析的公网 IP 必须被 pin 给出口，不得转交域名后二次解析"
    );
    assert_eq!(
        rebind_queries.load(Ordering::SeqCst),
        1,
        "同一连接不得二次 DNS 查询落到 rebind 私网回答"
    );

    let _ = child.kill();
    let _ = child.wait();
    dns_stop.store(true, Ordering::Release);
    upstream_stop.store(true, Ordering::Release);
}
