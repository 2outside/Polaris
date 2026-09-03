use super::*;

#[cfg(target_os = "macos")]
struct HostMacProxyWriter {
    socket_path: String,
    token: String,
}

#[cfg(target_os = "macos")]
impl HostMacProxyWriter {
    fn send(
        &self,
        request: &polaris_helper_proto::Request,
    ) -> Result<polaris_helper_proto::Response, proxy_ops::MacProxyWriterError> {
        use std::io::{BufRead, Write};
        use std::net::Shutdown;
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|error| proxy_ops::MacProxyWriterError::Unavailable(error.to_string()))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| proxy_ops::MacProxyWriterError::Failed(error.to_string()))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| proxy_ops::MacProxyWriterError::Failed(error.to_string()))?;
        let frame = polaris_helper_proto::codec::encode(
            polaris_helper_proto::Platform::Mac,
            &self.token,
            request,
        );
        stream
            .write_all(&frame)
            .map_err(|error| proxy_ops::MacProxyWriterError::Failed(error.to_string()))?;
        stream
            .shutdown(Shutdown::Write)
            .map_err(|error| proxy_ops::MacProxyWriterError::Failed(error.to_string()))?;
        let mut response = String::new();
        std::io::BufReader::new(stream)
            .read_line(&mut response)
            .map_err(|error| proxy_ops::MacProxyWriterError::Failed(error.to_string()))?;
        Ok(polaris_helper_proto::Response::parse(response.trim()))
    }
}

#[cfg(target_os = "macos")]
impl proxy_ops::MacProxyTransactionWriter for HostMacProxyWriter {
    fn compare_capable(&self) -> Result<bool, proxy_ops::MacProxyWriterError> {
        match self.send(&polaris_helper_proto::Request::MacProxyCompareCapability)? {
            polaris_helper_proto::Response::Ok(
                polaris_helper_proto::ResponseKind::MacProxyTransaction,
            ) => Ok(true),
            polaris_helper_proto::Response::Err(error)
                if matches!(
                    error.code,
                    polaris_helper_proto::ErrorCode::Unknown
                        | polaris_helper_proto::ErrorCode::Auth
                ) =>
            {
                Ok(false)
            }
            other => Err(proxy_ops::MacProxyWriterError::Failed(format!(
                "host helper capability returned {other:?}"
            ))),
        }
    }

    fn execute(&self, payload_hex: &str) -> Result<(), proxy_ops::MacProxyWriterError> {
        match self.send(&polaris_helper_proto::Request::MacProxyCompareTransaction {
            payload_hex: payload_hex.to_owned(),
        })? {
            polaris_helper_proto::Response::Ok(
                polaris_helper_proto::ResponseKind::MacProxyTransaction,
            ) => Ok(()),
            other => Err(proxy_ops::MacProxyWriterError::Failed(format!(
                "host helper returned {other:?}"
            ))),
        }
    }
}

#[cfg(target_os = "macos")]
fn host_proxy_controller(marker_path: &str) -> ProdProxyController {
    let socket_path = std::env::var("POLARIS_MACOS_PROXY_HELPER_SOCKET")
        .expect("set POLARIS_MACOS_PROXY_HELPER_SOCKET for the attended host test");
    let token_path = std::env::var("POLARIS_MACOS_PROXY_HELPER_TOKEN_FILE")
        .expect("set POLARIS_MACOS_PROXY_HELPER_TOKEN_FILE for the attended host test");
    let token = std::fs::read_to_string(token_path)
        .expect("read attended host helper token")
        .trim()
        .to_owned();
    production_proxy_controller_with_macos_writer(
        marker_path,
        std::sync::Arc::new(HostMacProxyWriter { socket_path, token }),
    )
}

/// macOS 真机门：生产 SystemConfiguration 路径完成「完整快照落 marker →
/// 接管 → 活态读回 → 原样恢复」。默认 ignored + 环境变量双闸，避免普通 test
/// 触碰开发机系统代理。
#[cfg(target_os = "macos")]
#[test]
#[ignore = "modifies the host macOS system proxy; run only on an attended test machine"]
fn production_macos_native_proxy_transaction_restores_after_takeover() {
    assert_eq!(
        std::env::var("POLARIS_RUN_MACOS_PROXY_HOST_TEST").as_deref(),
        Ok("1"),
        "set POLARIS_RUN_MACOS_PROXY_HOST_TEST=1 after confirming an attended test machine"
    );

    struct RestoreGuard {
        controller: ProdProxyController,
        armed: bool,
    }
    impl Drop for RestoreGuard {
        fn drop(&mut self) {
            if self.armed {
                let _ = self.controller.disable();
            }
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let marker_path = dir.path().join(PROXY_MARKER_FILENAME);
    let mut controller = host_proxy_controller(marker_path.to_str().unwrap());
    let request = proxy_ops::ProxyEnableRequest {
        address: "127.0.0.1".into(),
        http_port: 48_987,
        socks_port: 48_987,
        bypass_list: vec!["localhost".into(), "127.0.0.1".into()],
    };
    controller.enable(&request).expect("native takeover");
    let mut guard = RestoreGuard {
        controller,
        armed: true,
    };

    let proxy::ProxyMarkerRead::CurrentValidated(marker) =
        proxy::ProxyMarker::new(StdMarkerFs, marker_path.to_str().unwrap()).read_checked()
    else {
        panic!("native takeover must persist a validated current marker");
    };
    assert!(
        marker.mac_service_settings.is_empty(),
        "current envelope must not expose a legacy full-plist mac snapshot"
    );
    for (name, snapshot) in [
        ("exact_original", marker.exact_original.as_ref()),
        ("exact_apply_base", marker.exact_apply_base.as_ref()),
        ("exact_applied", marker.exact_applied.as_ref()),
    ] {
        assert!(
            snapshot.is_some_and(|snapshot| !snapshot.mac_services.is_empty()),
            "native takeover must persist {name}.mac_services before mutation"
        );
    }
    assert!(
        production_system_proxy_live_status("127.0.0.1", 48_987)
            .expect("live readback after takeover")
            .points_to_us
    );

    let restored = guard.controller.disable();
    if restored.is_ok() {
        guard.armed = false;
    }
    restored.expect("native restore");
    assert!(
        !marker_path.exists(),
        "successful restore must clear marker"
    );
    assert!(
        !production_system_proxy_live_status("127.0.0.1", 48_987)
            .expect("live readback after restore")
            .points_to_us,
        "restored system proxy must not retain Polaris' dead test port"
    );
}

/// macOS 真机崩溃恢复门：第一控制器提交接管后直接丢弃（模拟进程被强杀，未走
/// disable），第二控制器只能依赖落盘 marker 恢复完整配置。
#[cfg(target_os = "macos")]
#[test]
#[ignore = "modifies the host macOS system proxy; run only on an attended test machine"]
fn production_macos_native_proxy_recovers_across_process_sessions() {
    assert_eq!(
        std::env::var("POLARIS_RUN_MACOS_PROXY_HOST_TEST").as_deref(),
        Ok("1"),
        "set POLARIS_RUN_MACOS_PROXY_HOST_TEST=1 after confirming an attended test machine"
    );

    struct RecoveryGuard {
        marker_path: String,
        armed: bool,
    }
    impl Drop for RecoveryGuard {
        fn drop(&mut self) {
            if self.armed {
                let mut controller = host_proxy_controller(&self.marker_path);
                let _ = controller.recover_from_marker();
            }
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let marker_path = dir.path().join(PROXY_MARKER_FILENAME);
    let marker_path = marker_path.to_str().unwrap().to_owned();
    let mut guard = RecoveryGuard {
        marker_path: marker_path.clone(),
        armed: false,
    };
    let mut first_session = host_proxy_controller(&marker_path);
    let request = proxy_ops::ProxyEnableRequest {
        address: "127.0.0.1".into(),
        http_port: 48_988,
        socks_port: 48_988,
        bypass_list: vec!["localhost".into(), "127.0.0.1".into()],
    };
    first_session.enable(&request).expect("native takeover");
    guard.armed = true;
    drop(first_session);

    assert!(
        std::path::Path::new(&marker_path).exists(),
        "simulated crash must leave the durable recovery marker"
    );
    let proxy::ProxyMarkerRead::CurrentValidated(marker) =
        proxy::ProxyMarker::new(StdMarkerFs, marker_path.clone()).read_checked()
    else {
        panic!("simulated crash must leave a validated current marker");
    };
    assert!(marker.mac_service_settings.is_empty());
    assert!(marker
        .exact_original
        .as_ref()
        .is_some_and(|snapshot| !snapshot.mac_services.is_empty()));
    assert!(
        production_system_proxy_live_status("127.0.0.1", 48_988)
            .expect("live readback after simulated crash")
            .points_to_us,
        "simulated crash must leave a state that the next process has to recover"
    );

    let mut second_session = host_proxy_controller(&marker_path);
    match second_session.recover_from_marker() {
        Ok(Some(_)) => guard.armed = false,
        Ok(None) => panic!("the second process must consume the first process marker"),
        Err(error) => panic!("native crash recovery: {error}"),
    }
    assert!(
        !std::path::Path::new(&marker_path).exists(),
        "successful crash recovery must clear marker"
    );
    assert!(
        !production_system_proxy_live_status("127.0.0.1", 48_988)
            .expect("live readback after crash recovery")
            .points_to_us,
        "crash recovery must not retain Polaris' dead test port"
    );
}

/// 生产装配冒烟：**真实**类型（StdCommandRunner + StdMarkerFs + 本机 Platform）在
/// **无 marker** 时必须完全惰性 —— 不读系统代理状态、不跑任何命令。
///
/// 这条测的是生产路径本身（非 mock），且**证明其在本机零副作用**：门控 1（无 marker）在
/// 任何 OS 调用之前就返回。fresh start 走的正是这条腿 —— 也正因如此，`ensure_cleared`
/// 可以被无脑挂在每个 start 失败腿上。
///
/// 安全性：marker 路径在 tempdir（无 marker）→ 恒走门控 1 早退 → **不触碰宿主系统代理**。
#[test]
fn production_proxy_controller_is_inert_without_marker() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(PROXY_MARKER_FILENAME);
    let mut c = production_proxy_controller(path.to_str().unwrap());

    assert!(!c.has_marker(), "tempdir 里无 marker");
    // 无 marker → false 且零系统调用（若门控 1 失效，这里会去读真实系统代理状态）。
    assert!(!c.ensure_cleared(), "fresh start 必须 no-op");
    // recover_from_marker 同样：无 marker → None，不动系统。
    assert!(c.recover_from_marker().unwrap().is_none());
    assert!(!path.exists(), "不得凭空造出 marker");
}

/// 生产 DNS 控制器在无 marker 时同样惰性（Linux 本机还额外被 takeover_supported=false 兜住）。
#[test]
fn production_dns_controller_is_inert_without_marker() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(DNS_MARKER_FILENAME);
    let mut c = production_dns_controller(path.to_str().unwrap());
    assert!(!c.has_marker());
    // 本机 Linux：takeover_supported=false → restore_dns 只清 marker，绝不写系统 DNS。
    c.restore_dns();
    assert!(!c.has_marker());
    assert!(!path.exists());
}
