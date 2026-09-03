use super::*;

#[test]
fn ping_version_status_no_args() {
    for r in [Request::Ping, Request::Version, Request::Status] {
        assert!(r.args_lines().is_empty(), "{r:?} 不应有参数行");
    }
}

// ===== stop 的受管 pid 身份（杀错进程的防线）=====

/// **变异门（判据本体）**：`stop_pid_matches` 必须只在「want 未声明」或「want == 手里那个」时放行。
///
/// 改成恒 `true`（= 去掉身份判据，退回「反正要停就杀当前的」）→ 第二条断言转红。
/// 改成 `want.is_some_and(|p| p == current)`（连 `None` 也拒）→ 第一条转红，那会让「起核 IPC
/// 在飞、pid 未回传」时的 racing stop 停不掉核 = 留 root 孤儿。
#[test]
fn stop_pid_matches_only_when_unspecified_or_equal() {
    assert!(
        stop_pid_matches(None, 4242),
        "未声明身份 = 旧语义「停当前受管核」：这是 pid 尚未回传时防孤儿所必需"
    );
    assert!(stop_pid_matches(Some(4242), 4242), "同一个 pid → 放行");
    assert!(
        !stop_pid_matches(Some(4242), 9001),
        "手里的核不是请求所指的那个 = 它属另一个会话 → 绝不动手"
    );
}

/// `parse_stop_pid`：空/非数字/0 一律 `None`（0 归 None 而非 Some(0)，否则身份恒不匹配 = 停不掉核）。
#[test]
fn parse_stop_pid_rejects_empty_zero_and_garbage() {
    assert_eq!(parse_stop_pid("4242"), Some(4242));
    assert_eq!(parse_stop_pid("  4242  "), Some(4242));
    assert_eq!(parse_stop_pid(""), None);
    assert_eq!(parse_stop_pid("0"), None);
    assert_eq!(parse_stop_pid("abc"), None);
    assert_eq!(parse_stop_pid("-1"), None);
}

/// **wire 兼容门（两向）**：`Stop { pid: None }` 的帧必须与旧客户端**逐字节一致**（不多发空行），
/// `Some` 才多一行 —— 这样旧 helper 收到新客户端的 stop 仍照旧停核，绝不会「永远停不掉核」。
///
/// 变异：把 `None` 写成 `out.push(String::new())`（发空行）→ 首条转红。旧 helper 的 stop 分支
/// 不读参数行，多出的空行虽被连接关闭丢弃，但会让 wire 形态与已部署实现失配（且 linux 侧
/// 新 helper 读到空行 = None，等价，但形态漂移无收益）。
#[test]
fn stop_omits_identity_line_when_unspecified() {
    assert!(
        Request::Stop { pid: None }.args_lines().is_empty(),
        "不声明身份 → 帧与旧客户端逐字节一致（旧 helper 照常停核）"
    );
    assert_eq!(Request::Stop { pid: Some(4242) }.args_lines(), vec!["4242"]);
}

/// 整帧形态（含平台差异）：stop 的身份行紧跟 command 行。
#[test]
fn stop_frame_shape_carries_identity_line() {
    use crate::{codec, Platform};
    let framed = String::from_utf8(codec::encode(
        Platform::Mac,
        "TOK",
        &Request::Stop { pid: Some(7) },
    ))
    .unwrap();
    assert_eq!(framed, "TOK\nstop\n7\n");
    let linux = String::from_utf8(codec::encode(
        Platform::Linux,
        "",
        &Request::Stop { pid: None },
    ))
    .unwrap();
    assert_eq!(linux, "stop\n", "旧语义帧不变");
}

#[test]
fn start_writes_cfg_log_fwd_ppid_lines() {
    // 对照 mac helper.go:508-513 的 readLine 顺序
    let r = Request::Start(StartParams {
        cfg: "/tmp/cfg.json".into(),
        log: "/tmp/log.txt".into(),
        fwd: true,
        parent_pid: Some(4242),
    });
    assert_eq!(
        r.args_lines(),
        vec!["/tmp/cfg.json", "/tmp/log.txt", "1", "4242"]
    );
}

#[test]
fn start_without_ppid_omits_line() {
    // 兼容旧客户端：ppid 缺失 = 不启父死看护（Go readLine EOF → "" → Atoi=0）
    let r = Request::Start(StartParams {
        cfg: "/tmp/c.json".into(),
        log: String::new(),
        fwd: false,
        parent_pid: None,
    });
    assert_eq!(r.args_lines(), vec!["/tmp/c.json", "", "0"]);
}

#[test]
fn linux_start_writes_singbox_first() {
    // 对照 linux helper-linux/helper.go:401-405（singbox 行在最前）
    let r = Request::LinuxStart(LinuxStartParams {
        singbox_path: "/usr/local/lib/polaris/core/sing-box".into(),
        common: StartParams {
            cfg: "/tmp/c.json".into(),
            log: String::new(),
            fwd: false,
            parent_pid: None,
        },
    });
    assert_eq!(
        r.args_lines(),
        vec![
            "/usr/local/lib/polaris/core/sing-box",
            "/tmp/c.json",
            "",
            "0",
        ]
    );
}

#[test]
fn route_add_writes_iface_then_cidrs_csv() {
    // 对照 helper.go:455-456
    let r = Request::RouteAdd(RouteParams {
        iface: "polaris-ts".into(),
        cidrs: vec!["10.0.0.0/8".into(), "172.16.0.0/12".into()],
    });
    assert_eq!(
        r.args_lines(),
        vec!["polaris-ts", "10.0.0.0/8,172.16.0.0/12"]
    );
}

#[test]
fn install_core_writes_src_then_hash() {
    // 对照 helper.go:583-584
    let r = Request::InstallCore(InstallCoreParams {
        src_dir: "/tmp/core-staging".into(),
        want_hash: "abc123def4567890abcdef1234567890abcdef1234567890abcdef1234567890".into(),
    });
    let args = r.args_lines();
    assert_eq!(args.len(), 2);
    assert_eq!(args[0], "/tmp/core-staging");
    assert_eq!(args[1].len(), 64, "want_hash 须 64 字符 hex");
}

#[test]
fn mac_proxy_transaction_is_one_opaque_payload_line() {
    let request = Request::MacProxyTransaction {
        payload_hex: "7b226f7065726174696f6e223a22636c656172227d".into(),
    };
    assert_eq!(
        request.command_name(),
        command::mac::SYSTEM_PROXY_TRANSACTION
    );
    assert_eq!(
        request.args_lines(),
        vec!["7b226f7065726174696f6e223a22636c656172227d"]
    );
    assert_eq!(
        String::from_utf8(crate::codec::encode(crate::Platform::Mac, "TOK", &request)).unwrap(),
        "TOK\nsystem-proxy-transaction\n7b226f7065726174696f6e223a22636c656172227d\n"
    );
}

#[test]
fn mac_proxy_compare_commands_lock_name_args_and_complete_frames() {
    let transaction = Request::MacProxyCompareTransaction {
        payload_hex: "7b7d".into(),
    };
    assert_eq!(
        transaction.command_name(),
        command::mac::SYSTEM_PROXY_COMPARE_TRANSACTION
    );
    assert_eq!(transaction.args_lines(), vec!["7b7d"]);
    assert_eq!(
        String::from_utf8(crate::codec::encode(
            crate::Platform::Mac,
            "TOK",
            &transaction,
        ))
        .unwrap(),
        "TOK\nsystem-proxy-compare-transaction\n7b7d\n"
    );

    let capability = Request::MacProxyCompareCapability;
    assert_eq!(
        capability.command_name(),
        command::mac::SYSTEM_PROXY_COMPARE_CAPABILITY
    );
    assert!(capability.args_lines().is_empty());
    assert_eq!(
        String::from_utf8(crate::codec::encode(
            crate::Platform::Mac,
            "TOK",
            &capability,
        ))
        .unwrap(),
        "TOK\nsystem-proxy-compare-capability\n"
    );
}

#[test]
fn command_name_mapping() {
    // 锁住 wire 命令名 ↔ Request 变体映射
    assert_eq!(Request::Ping.command_name(), "ping");
    assert_eq!(Request::Stop { pid: None }.command_name(), "stop");
    assert_eq!(Request::FreePort { port: 1 }.command_name(), "freeport");
    assert_eq!(
        Request::Start(StartParams {
            cfg: String::new(),
            log: String::new(),
            fwd: false,
            parent_pid: None,
        })
        .command_name(),
        "start"
    );
    assert_eq!(Request::FlushDns.command_name(), "flush-dns");
    assert_eq!(Request::Uninstall.command_name(), "uninstall");
    assert_eq!(
        Request::LinuxDnsSet(LinuxDnsSetParams {
            interface_name: crate::linux_dns::TUN_INTERFACE_NAME.into(),
            server_ip: crate::linux_dns::CONTROLLED_DNS_IP.into(),
        })
        .command_name(),
        "resolved-dns-set"
    );
    assert_eq!(
        Request::LinuxDnsRevert {
            interface_name: crate::linux_dns::TUN_INTERFACE_NAME.into(),
        }
        .args_lines(),
        vec![crate::linux_dns::TUN_INTERFACE_NAME]
    );
    assert_eq!(
        Request::DefaultRestore {
            gateway_ipv4: "1.2.3.4".into()
        }
        .command_name(),
        "default-restore"
    );
}
