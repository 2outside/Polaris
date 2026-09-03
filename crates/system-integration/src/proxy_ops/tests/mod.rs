use super::controller::points_to_us;
use super::linux::{
    encode_gvariant_string, linux_applied_snapshot, linux_exact_restore_commands,
    validate_linux_gsettings_snapshot, LINUX_GSETTINGS_KEYS,
};
use super::retry::{default_should_retry, mac_enable_should_retry, win_enable_should_retry};
use super::windows::{windows_registry_projection, WINDOWS_QUIC_CLEANUP_TIMEOUT};
use super::*;
use crate::error::SystemIntegrationError;
use crate::exec::{CommandOutput, CommandRunner};
use crate::proxy::{
    LinuxGSettingsSnapshot, MacProxyServiceSnapshot, MacProxyTouchedSnapshot, MarkerFs,
    ProxyMarker, ProxyMarkerBeginOutcome, ProxyMarkerData, ProxyMarkerPhase, ProxyMarkerRead,
    ProxyOriginalSettings, ProxyTransactionSnapshot, SystemProxyStatus,
    WindowsProxyRegistrySnapshot, WindowsRegistryDwordValue, WindowsRegistryStringValue,
};
use polaris_helper_proto::Platform;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

mod live_status_tests;
mod mac_leg_exclusivity_gate;
mod mac_service_enum_tests;

/// 记录所有调用的 mock ops（不触碰宿主网络）。
#[derive(Default)]
struct MockOps {
    calls: RefCell<Vec<&'static str>>,
    status: RefCell<SystemProxyStatus>,
    full_settings: Option<ProxyOriginalSettings>,
    exact_available: bool,
    transaction_status: RefCell<Option<ProxyTransactionSnapshot>>,
    status_fails: bool,
    capture_fails: bool,
    requires_snapshot: bool,
    set_fails: bool,
    clear_fails: bool,
    restore_fails: bool,
    forced_relation: Option<ProxySnapshotRelation>,
}
impl SystemProxyOps for MockOps {
    fn exact_transaction_available(&self) -> Result<bool, SystemIntegrationError> {
        Ok(self.exact_available)
    }
    fn get_proxy_status(&self) -> Result<SystemProxyStatus, SystemIntegrationError> {
        self.calls.borrow_mut().push("get_status");
        if self.status_fails {
            return Err(SystemIntegrationError::proxy("status query failed"));
        }
        Ok(self.status.borrow().clone())
    }
    /// 与 `get_proxy_status` 分开记账，便于断言 enable 走的是**捕获**口径而非残留检测口径。
    fn capture_original_status(&self) -> Result<SystemProxyStatus, SystemIntegrationError> {
        self.calls.borrow_mut().push("capture");
        Ok(self.status.borrow().clone())
    }
    fn capture_original_settings(&self) -> Result<ProxyOriginalSettings, SystemIntegrationError> {
        if self.capture_fails {
            return Err(SystemIntegrationError::proxy("capture failed"));
        }
        match self.full_settings.as_ref() {
            Some(settings) => {
                self.calls.borrow_mut().push("capture_full");
                Ok(settings.clone())
            }
            None => self
                .capture_original_status()
                .map(ProxyOriginalSettings::from_status),
        }
    }
    fn requires_original_snapshot(&self) -> bool {
        self.requires_snapshot
    }
    fn capture_transaction_snapshot(
        &self,
    ) -> Result<ProxyTransactionSnapshot, SystemIntegrationError> {
        self.calls.borrow_mut().push("capture_transaction");
        self.transaction_status
            .borrow()
            .clone()
            .ok_or_else(|| SystemIntegrationError::proxy("exact capture missing"))
    }
    fn build_applied_snapshot(
        &self,
        req: &ProxyEnableRequest,
        _apply_base: &ProxyTransactionSnapshot,
    ) -> Result<ProxyTransactionSnapshot, SystemIntegrationError> {
        self.calls.borrow_mut().push("build_applied");
        Ok(exact_linux_snapshot(&req.our_host_port()))
    }
    fn apply_transaction(
        &self,
        req: &ProxyEnableRequest,
        _apply_base: &ProxyTransactionSnapshot,
    ) -> Result<(), SystemIntegrationError> {
        self.calls.borrow_mut().push("apply_transaction");
        *self.transaction_status.borrow_mut() = Some(exact_linux_snapshot(&req.our_host_port()));
        if self.set_fails {
            return Err(SystemIntegrationError::proxy("apply transaction failed"));
        }
        Ok(())
    }
    fn restore_transaction(
        &self,
        original: &ProxyTransactionSnapshot,
        _current: &ProxyTransactionSnapshot,
    ) -> Result<(), SystemIntegrationError> {
        self.calls.borrow_mut().push("restore_transaction");
        if self.restore_fails {
            return Err(SystemIntegrationError::proxy("restore transaction failed"));
        }
        *self.transaction_status.borrow_mut() = Some(original.clone());
        Ok(())
    }
    fn snapshot_relation(
        &self,
        from: &ProxyTransactionSnapshot,
        to: &ProxyTransactionSnapshot,
        current: &ProxyTransactionSnapshot,
    ) -> ProxySnapshotRelation {
        self.calls.borrow_mut().push("snapshot_relation");
        if let Some(relation) = self.forced_relation {
            relation
        } else if !from.mac_services.is_empty()
            || !to.mac_services.is_empty()
            || !current.mac_services.is_empty()
        {
            super::ops::mac_snapshot_relation(
                &from.mac_services,
                &to.mac_services,
                &current.mac_services,
            )
        } else if current == to {
            ProxySnapshotRelation::Exact
        } else if current == from {
            ProxySnapshotRelation::Unchanged
        } else {
            ProxySnapshotRelation::Foreign
        }
    }
    fn list_network_services(&self) -> Result<Vec<String>, SystemIntegrationError> {
        Ok(vec!["Wi-Fi".into()])
    }
    fn set_proxy(&self, req: &ProxyEnableRequest) -> Result<(), SystemIntegrationError> {
        self.calls.borrow_mut().push("set");
        *self.status.borrow_mut() = SystemProxyStatus {
            enabled: true,
            http_proxy: Some(req.our_host_port()),
            https_proxy: Some(req.our_host_port()),
            socks_proxy: Some(format!("{}:{}", req.address, req.socks_port)),
            bypass_domains: Some(req.bypass_list.clone()),
        };
        if self.set_fails {
            return Err(SystemIntegrationError::proxy("set failed"));
        }
        Ok(())
    }
    fn clear_proxy(&self) -> Result<(), SystemIntegrationError> {
        self.calls.borrow_mut().push("clear");
        if self.clear_fails {
            return Err(SystemIntegrationError::proxy("clear failed"));
        }
        *self.status.borrow_mut() = SystemProxyStatus::default();
        Ok(())
    }
    fn restore_proxy(&self, original: &SystemProxyStatus) -> Result<(), SystemIntegrationError> {
        self.calls.borrow_mut().push("restore");
        if self.restore_fails {
            return Err(SystemIntegrationError::proxy("restore failed"));
        }
        *self.status.borrow_mut() = original.clone();
        Ok(())
    }
    fn restore_original_settings(
        &self,
        original: &ProxyOriginalSettings,
    ) -> Result<(), SystemIntegrationError> {
        if original.mac_services.is_empty() {
            return match original.fallback.as_ref() {
                Some(status) => self.restore_proxy(status),
                None => self.clear_proxy(),
            };
        }
        self.calls.borrow_mut().push("restore_full");
        if self.restore_fails {
            return Err(SystemIntegrationError::proxy("restore full failed"));
        }
        Ok(())
    }
}

fn mem_marker() -> ProxyMarker<crate::proxy::proxy_tests_helpers::MemFs> {
    ProxyMarker::new(
        crate::proxy::proxy_tests_helpers::MemFs::new(),
        "/marker.json",
    )
}

fn write_legacy_marker<Fs: MarkerFs>(
    marker: &ProxyMarker<Fs>,
    host: &str,
    original: Option<&SystemProxyStatus>,
) {
    let original = original.cloned().map(ProxyOriginalSettings::from_status);
    assert!(matches!(
        marker.begin_legacy_if_absent(host, original.as_ref()),
        crate::proxy::ProxyMarkerBeginOutcome::Begun(_)
    ));
}

fn req() -> ProxyEnableRequest {
    ProxyEnableRequest {
        address: "127.0.0.1".into(),
        http_port: 8080,
        socks_port: 1080,
        bypass_list: vec!["10.0.0.0/8".into(), "localhost".into()],
    }
}

fn exact_linux_snapshot(http_proxy: &str) -> ProxyTransactionSnapshot {
    ProxyTransactionSnapshot {
        projection: Some(SystemProxyStatus {
            enabled: true,
            http_proxy: Some(http_proxy.into()),
            ..Default::default()
        }),
        linux_gsettings: Some(LinuxGSettingsSnapshot {
            http_host: format!("'{http_proxy}'"),
            http_port: "7890".into(),
            http_enabled: "true".into(),
            https_host: "''".into(),
            https_port: "0".into(),
            socks_host: "''".into(),
            socks_port: "0".into(),
            ignore_hosts: "@as []".into(),
            mode: "'manual'".into(),
        }),
        ..Default::default()
    }
}

fn exact_linux_disabled_snapshot() -> ProxyTransactionSnapshot {
    ProxyTransactionSnapshot {
        projection: Some(SystemProxyStatus::default()),
        linux_gsettings: Some(LinuxGSettingsSnapshot {
            http_host: "''".into(),
            http_port: "0".into(),
            http_enabled: "false".into(),
            https_host: "''".into(),
            https_port: "0".into(),
            socks_host: "''".into(),
            socks_port: "0".into(),
            ignore_hosts: "@as []".into(),
            mode: "'none'".into(),
        }),
        ..Default::default()
    }
}

fn exact_mac_service(id: &str, protocol_present: bool) -> MacProxyServiceSnapshot {
    MacProxyServiceSnapshot {
        service_id: id.into(),
        service_name: format!("service-{id}"),
        service_enabled: true,
        had_proxy_protocol: protocol_present,
        protocol_enabled: protocol_present,
        configuration_plist: protocol_present
            .then(|| r#"<plist version="1.0"><dict/></plist>"#.into()),
        touched: Some(MacProxyTouchedSnapshot {
            protocol_present,
            protocol_enabled: protocol_present,
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn exact_mac_snapshot(services: Vec<MacProxyServiceSnapshot>) -> ProxyTransactionSnapshot {
    ProxyTransactionSnapshot {
        projection: Some(SystemProxyStatus::default()),
        mac_services: services,
        ..Default::default()
    }
}

fn seed_current_marker<Fs: MarkerFs>(
    marker: &ProxyMarker<Fs>,
    original: &ProxyTransactionSnapshot,
    apply_base: &ProxyTransactionSnapshot,
    applied: &ProxyTransactionSnapshot,
    phase: ProxyMarkerPhase,
) -> ProxyMarkerData {
    let crate::proxy::ProxyMarkerBeginOutcome::Begun(begun) =
        marker.begin_if_absent("127.0.0.1:8080", original, apply_base, applied)
    else {
        panic!("current marker seed must persist");
    };
    let txn_id = begun.txn_id.as_deref().unwrap();
    match phase {
        ProxyMarkerPhase::Applying => {}
        ProxyMarkerPhase::Owned => assert_eq!(
            marker.update_current_phase(
                txn_id,
                ProxyMarkerPhase::Applying,
                ProxyMarkerPhase::Owned,
            ),
            crate::proxy::ProxyMarkerMutationOutcome::Updated
        ),
        ProxyMarkerPhase::Restoring | ProxyMarkerPhase::RestoredPendingClear => {
            assert_eq!(
                marker.update_current_phase(
                    txn_id,
                    ProxyMarkerPhase::Applying,
                    ProxyMarkerPhase::Restoring,
                ),
                crate::proxy::ProxyMarkerMutationOutcome::Updated
            );
            if phase == ProxyMarkerPhase::RestoredPendingClear {
                assert_eq!(
                    marker.update_current_phase(
                        txn_id,
                        ProxyMarkerPhase::Restoring,
                        ProxyMarkerPhase::RestoredPendingClear,
                    ),
                    crate::proxy::ProxyMarkerMutationOutcome::Updated
                );
            }
        }
    }
    match marker.read_checked() {
        ProxyMarkerRead::CurrentValidated(marker) => marker,
        other => panic!("expected current marker, got {other:?}"),
    }
}

fn exact_ops(original: ProxyTransactionSnapshot) -> MockOps {
    MockOps {
        exact_available: true,
        transaction_status: RefCell::new(Some(original)),
        ..Default::default()
    }
}

#[derive(Clone)]
struct FailNthWriteFs {
    inner: Rc<FailNthWriteInner>,
}

struct FailNthWriteInner {
    file: RefCell<Option<String>>,
    writes: Cell<usize>,
    fail_on: usize,
}

impl FailNthWriteFs {
    fn new(fail_on: usize) -> Self {
        Self {
            inner: Rc::new(FailNthWriteInner {
                file: RefCell::new(None),
                writes: Cell::new(0),
                fail_on,
            }),
        }
    }
}

impl MarkerFs for FailNthWriteFs {
    fn write_marker(&self, _path: &str, data: &str) -> std::io::Result<()> {
        let write = self.inner.writes.get() + 1;
        self.inner.writes.set(write);
        if write == self.inner.fail_on {
            return Err(std::io::Error::other("injected marker write failure"));
        }
        *self.inner.file.borrow_mut() = Some(data.into());
        Ok(())
    }

    fn read_marker(&self, _path: &str) -> Option<String> {
        self.inner.file.borrow().clone()
    }

    fn remove_marker(&self, _path: &str) -> std::io::Result<()> {
        *self.inner.file.borrow_mut() = None;
        Ok(())
    }
}

#[derive(Clone, Default)]
struct StaleCasFs {
    file: Rc<RefCell<Option<String>>>,
    mutate_after_reads: Rc<Cell<Option<usize>>>,
}

impl StaleCasFs {
    fn arm_after_reads(&self, reads: usize) {
        self.mutate_after_reads.set(Some(reads));
    }
}

impl MarkerFs for StaleCasFs {
    fn write_marker(&self, _path: &str, data: &str) -> std::io::Result<()> {
        *self.file.borrow_mut() = Some(data.into());
        Ok(())
    }

    fn read_marker(&self, _path: &str) -> Option<String> {
        if let Some(remaining) = self.mutate_after_reads.get() {
            if remaining == 0 {
                let mut root: serde_json::Value = serde_json::from_str(
                    self.file
                        .borrow()
                        .as_deref()
                        .expect("stale CAS fixture marker"),
                )
                .expect("valid marker fixture");
                root["systemProxyTxnV2"]["txn_id"] =
                    serde_json::Value::String("concurrent-transaction".into());
                *self.file.borrow_mut() = Some(serde_json::to_string(&root).unwrap());
                self.mutate_after_reads.set(None);
            } else {
                self.mutate_after_reads.set(Some(remaining - 1));
            }
        }
        self.file.borrow().clone()
    }

    fn remove_marker(&self, _path: &str) -> std::io::Result<()> {
        *self.file.borrow_mut() = None;
        Ok(())
    }
}

// ── 接管/释放状态机 ──

#[test]
fn exact_missing_persists_complete_marker_then_applies_and_owns() {
    let original = exact_linux_snapshot("proxy.corp:3128");
    let ops = exact_ops(original.clone());
    let mut controller = SystemProxyController::new(ops, mem_marker());

    controller.enable(&req()).unwrap();

    let ProxyMarkerRead::CurrentValidated(marker) = controller.marker.read_checked() else {
        panic!("exact enable must leave a validated V2 marker");
    };
    assert_eq!(marker.phase, ProxyMarkerPhase::Owned);
    assert_eq!(marker.exact_original.as_ref(), Some(&original));
    assert_eq!(marker.exact_apply_base.as_ref(), Some(&original));
    assert_eq!(
        marker.exact_applied.as_ref(),
        Some(&exact_linux_snapshot("127.0.0.1:8080"))
    );
    assert!(controller.ops.calls.borrow().contains(&"apply_transaction"));
    assert!(!controller.ops.calls.borrow().contains(&"set"));
}

#[test]
fn exact_marker_write_failure_performs_zero_os_writes() {
    let fs = FailNthWriteFs::new(1);
    let ops = exact_ops(exact_linux_snapshot("proxy.corp:3128"));
    let mut controller = SystemProxyController::new(ops, ProxyMarker::new(fs, "/marker.json"));

    let error = controller.enable(&req()).unwrap_err();

    assert!(error.to_string().contains("持久化"));
    assert!(!controller.ops.calls.borrow().contains(&"apply_transaction"));
}

#[test]
fn exact_apply_failure_rolls_back_only_owned_prefix_and_keeps_marker() {
    let original = exact_linux_snapshot("proxy.corp:3128");
    let ops = MockOps {
        set_fails: true,
        ..exact_ops(original.clone())
    };
    let mut controller = SystemProxyController::new(ops, mem_marker());

    let error = controller.enable(&req()).unwrap_err();

    assert!(error.to_string().contains("apply transaction failed"));
    assert!(controller
        .ops
        .calls
        .borrow()
        .contains(&"restore_transaction"));
    assert_eq!(
        controller.ops.transaction_status.borrow().as_ref(),
        Some(&original)
    );
    let ProxyMarkerRead::CurrentValidated(marker) = controller.marker.read_checked() else {
        panic!("failed exact apply must retain recoverable marker");
    };
    assert_eq!(marker.phase, ProxyMarkerPhase::Applying);
    assert_eq!(marker.exact_original.as_ref(), Some(&original));
}

#[test]
fn exact_owned_phase_persist_failure_returns_error_and_keeps_applying_marker() {
    let fs = FailNthWriteFs::new(2);
    let inspector = fs.clone();
    let ops = exact_ops(exact_linux_snapshot("proxy.corp:3128"));
    let mut controller = SystemProxyController::new(ops, ProxyMarker::new(fs, "/marker.json"));

    let error = controller.enable(&req()).unwrap_err();

    assert!(error.to_string().contains("Owned"));
    assert!(controller.ops.calls.borrow().contains(&"apply_transaction"));
    let ProxyMarkerRead::CurrentValidated(marker) =
        ProxyMarker::new(inspector, "/marker.json").read_checked()
    else {
        panic!("failed phase persist must keep the previous marker");
    };
    assert_eq!(marker.phase, ProxyMarkerPhase::Applying);
    let writes = controller
        .ops
        .calls
        .borrow()
        .iter()
        .filter(|call| **call == "apply_transaction")
        .count();
    assert!(controller.enable(&req()).is_err());
    assert_eq!(
        controller
            .ops
            .calls
            .borrow()
            .iter()
            .filter(|call| **call == "apply_transaction")
            .count(),
        writes,
        "Current Applying marker must reject a new OS write"
    );
}

#[test]
fn exact_owned_phase_cas_mismatch_keeps_concurrent_marker() {
    let fs = StaleCasFs::default();
    fs.arm_after_reads(2);
    let ops = exact_ops(exact_linux_snapshot("proxy.corp:3128"));
    let mut controller = SystemProxyController::new(ops, ProxyMarker::new(fs, "/marker.json"));

    let error = controller.enable(&req()).unwrap_err();

    assert!(error.to_string().contains("CAS"));
    let ProxyMarkerRead::CurrentValidated(marker) = controller.marker.read_checked() else {
        panic!("concurrent marker must remain valid");
    };
    assert_eq!(marker.txn_id.as_deref(), Some("concurrent-transaction"));
    assert_eq!(marker.phase, ProxyMarkerPhase::Applying);
}

#[test]
fn exact_owned_replacement_preserves_earliest_original_and_uses_fresh_base() {
    let original = exact_linux_snapshot("proxy.corp:3128");
    let ops = exact_ops(original.clone());
    let mut controller = SystemProxyController::new(ops, mem_marker());
    controller.enable(&req()).unwrap();
    let first = match controller.marker.read_checked() {
        ProxyMarkerRead::CurrentValidated(marker) => marker,
        other => panic!("unexpected first marker: {other:?}"),
    };

    let mut replacement = req();
    replacement.http_port = 8081;
    controller.enable(&replacement).unwrap();

    let second = match controller.marker.read_checked() {
        ProxyMarkerRead::CurrentValidated(marker) => marker,
        other => panic!("unexpected replacement marker: {other:?}"),
    };
    assert_ne!(first.txn_id, second.txn_id);
    assert_eq!(second.phase, ProxyMarkerPhase::Owned);
    assert_eq!(second.exact_original.as_ref(), Some(&original));
    assert_eq!(second.exact_apply_base, first.exact_applied);
    assert_eq!(
        second.exact_applied.as_ref(),
        Some(&exact_linux_snapshot("127.0.0.1:8081"))
    );
}

#[test]
fn exact_owned_replacement_rejects_prefix_and_foreign_state_without_writing() {
    let original = exact_linux_snapshot("proxy.corp:3128");
    let ops = exact_ops(original.clone());
    let mut controller = SystemProxyController::new(ops, mem_marker());
    controller.enable(&req()).unwrap();
    let before = controller.marker.read_checked();
    let writes_before = controller
        .ops
        .calls
        .borrow()
        .iter()
        .filter(|call| **call == "apply_transaction")
        .count();
    let mut replacement = req();
    replacement.http_port = 8081;

    *controller.ops.transaction_status.borrow_mut() = Some(original);
    assert!(controller.enable(&replacement).is_err(), "Prefix must stop");
    assert_eq!(controller.marker.read_checked(), before);

    *controller.ops.transaction_status.borrow_mut() =
        Some(exact_linux_snapshot("foreign.proxy:9000"));
    assert!(
        controller.enable(&replacement).is_err(),
        "Foreign must stop"
    );
    assert_eq!(controller.marker.read_checked(), before);
    assert_eq!(
        controller
            .ops
            .calls
            .borrow()
            .iter()
            .filter(|call| **call == "apply_transaction")
            .count(),
        writes_before
    );
}

#[test]
fn exact_replacement_stale_cas_does_not_overwrite_concurrent_marker_or_apply() {
    let fs = StaleCasFs::default();
    let race = fs.clone();
    let ops = exact_ops(exact_linux_snapshot("proxy.corp:3128"));
    let mut controller = SystemProxyController::new(ops, ProxyMarker::new(fs, "/marker.json"));
    controller.enable(&req()).unwrap();
    let writes_before = controller
        .ops
        .calls
        .borrow()
        .iter()
        .filter(|call| **call == "apply_transaction")
        .count();
    race.arm_after_reads(1);
    let mut replacement = req();
    replacement.http_port = 8081;

    assert!(controller.enable(&replacement).is_err());

    let ProxyMarkerRead::CurrentValidated(marker) = controller.marker.read_checked() else {
        panic!("concurrent marker must remain valid");
    };
    assert_eq!(marker.txn_id.as_deref(), Some("concurrent-transaction"));
    assert_eq!(
        controller
            .ops
            .calls
            .borrow()
            .iter()
            .filter(|call| **call == "apply_transaction")
            .count(),
        writes_before
    );
}

#[test]
fn no_exact_capability_uses_legacy_path_and_never_overwrites_existing_marker() {
    let ops = MockOps::default();
    let mut controller = SystemProxyController::new(ops, mem_marker());
    controller.enable(&req()).unwrap();
    assert!(matches!(
        controller.marker.read_checked(),
        ProxyMarkerRead::Legacy(_)
    ));
    assert!(controller.ops.calls.borrow().contains(&"set"));
    assert!(!controller.ops.calls.borrow().contains(&"apply_transaction"));

    let before = controller.marker.read_checked();
    assert!(controller.enable(&req()).is_err());
    assert_eq!(controller.marker.read_checked(), before);
    assert_eq!(
        controller
            .ops
            .calls
            .borrow()
            .iter()
            .filter(|call| **call == "set")
            .count(),
        1
    );
}

#[test]
fn exact_capability_rejects_legacy_marker_without_capture_or_os_write() {
    let fs = crate::proxy::proxy_tests_helpers::MemFs::new();
    let fixture_writer = ProxyMarker::new(fs.clone(), "/marker.json");
    write_legacy_marker(&fixture_writer, "mutation-lock-existing:7000", None);
    let marker = ProxyMarker::new(fs, "/marker.json");
    let before = marker.read_checked();
    assert!(matches!(
        before,
        ProxyMarkerRead::Legacy(ref marker)
            if marker.our_host_port == "mutation-lock-existing:7000"
    ));
    let ops = exact_ops(exact_linux_snapshot("proxy.corp:3128"));
    let mut controller = SystemProxyController::new(ops, marker);

    assert!(controller.enable(&req()).is_err());

    assert_eq!(controller.marker.read_checked(), before);
    assert!(!controller
        .ops
        .calls
        .borrow()
        .contains(&"capture_transaction"));
    assert!(!controller.ops.calls.borrow().contains(&"apply_transaction"));
}

#[test]
fn exact_applying_reconcile_distinguishes_unchanged_prefix_and_foreign() {
    let original = exact_linux_snapshot("proxy.corp:3128");
    let apply_base = exact_linux_snapshot("127.0.0.1:7000");
    let applied = exact_linux_snapshot("127.0.0.1:8080");
    let cases = [
        ("exact", applied.clone(), None, true),
        ("unchanged replacement base", apply_base.clone(), None, true),
        (
            "nonzero prefix even with disabled projection",
            exact_linux_disabled_snapshot(),
            Some(ProxySnapshotRelation::Prefix),
            true,
        ),
        (
            "foreign",
            exact_linux_snapshot("foreign.proxy:9000"),
            None,
            false,
        ),
    ];

    for (name, current, forced_relation, should_restore) in cases {
        let marker = mem_marker();
        seed_current_marker(
            &marker,
            &original,
            &apply_base,
            &applied,
            ProxyMarkerPhase::Applying,
        );
        let mut controller = SystemProxyController::new(
            MockOps {
                forced_relation,
                ..exact_ops(current)
            },
            marker,
        );

        assert_eq!(controller.ensure_cleared(), should_restore, "{name}");
        assert_eq!(
            controller.marker.read_checked(),
            ProxyMarkerRead::Missing,
            "{name}"
        );
        let calls = controller.ops.calls.borrow();
        assert_eq!(
            &calls[..2],
            &["capture_transaction", "snapshot_relation"],
            "relation must precede enabled projection: {name}"
        );
        assert_eq!(
            calls.contains(&"restore_transaction"),
            should_restore,
            "{name}"
        );
    }
}

#[test]
fn exact_applying_fresh_unchanged_clears_without_os_write() {
    let original = exact_linux_snapshot("proxy.corp:3128");
    let applied = exact_linux_snapshot("127.0.0.1:8080");
    let marker = mem_marker();
    seed_current_marker(
        &marker,
        &original,
        &original,
        &applied,
        ProxyMarkerPhase::Applying,
    );
    let mut controller = SystemProxyController::new(exact_ops(original), marker);

    assert!(!controller.ensure_cleared());
    assert_eq!(controller.marker.read_checked(), ProxyMarkerRead::Missing);
    assert!(!controller
        .ops
        .calls
        .borrow()
        .contains(&"restore_transaction"));
}

#[test]
fn exact_owned_reconcile_matrix_only_restores_exact_applied() {
    let original = exact_linux_snapshot("proxy.corp:3128");
    let apply_base = exact_linux_snapshot("127.0.0.1:7000");
    let applied = exact_linux_snapshot("127.0.0.1:8080");
    let cases = [
        ("exact", applied.clone(), true),
        ("unchanged", apply_base.clone(), false),
        ("foreign", exact_linux_snapshot("foreign.proxy:9000"), false),
        ("disabled", exact_linux_disabled_snapshot(), false),
    ];

    for (name, current, should_restore) in cases {
        let marker = mem_marker();
        seed_current_marker(
            &marker,
            &original,
            &apply_base,
            &applied,
            ProxyMarkerPhase::Owned,
        );
        let mut controller = SystemProxyController::new(exact_ops(current), marker);

        controller.disable().unwrap();
        assert_eq!(controller.marker.read_checked(), ProxyMarkerRead::Missing);
        assert_eq!(
            controller
                .ops
                .calls
                .borrow()
                .contains(&"restore_transaction"),
            should_restore,
            "{name}"
        );
    }
}

#[test]
fn exact_owned_mac_reorder_restores_by_stable_service_id() {
    let original = exact_mac_snapshot(vec![
        exact_mac_service("a", false),
        exact_mac_service("b", false),
    ]);
    let applied = exact_mac_snapshot(vec![
        exact_mac_service("a", true),
        exact_mac_service("b", true),
    ]);
    let current_reordered = exact_mac_snapshot(vec![
        exact_mac_service("b", true),
        exact_mac_service("a", true),
    ]);
    let marker = mem_marker();
    seed_current_marker(
        &marker,
        &original,
        &original,
        &applied,
        ProxyMarkerPhase::Owned,
    );
    let mut controller = SystemProxyController::new(exact_ops(current_reordered), marker);

    controller.disable().unwrap();

    assert_eq!(controller.marker.read_checked(), ProxyMarkerRead::Missing);
    assert!(controller
        .ops
        .calls
        .borrow()
        .contains(&"restore_transaction"));
    assert_eq!(
        controller.ops.transaction_status.borrow().as_ref(),
        Some(&original)
    );
}

#[test]
fn production_mac_relation_drives_same_target_owned_restore_on_disable_and_recovery() {
    let original = exact_mac_snapshot(vec![
        exact_mac_service("a", false),
        exact_mac_service("b", false),
    ]);
    let applied = exact_mac_snapshot(vec![
        exact_mac_service("a", true),
        exact_mac_service("b", true),
    ]);
    let current_reordered = exact_mac_snapshot(vec![
        exact_mac_service("b", true),
        exact_mac_service("a", true),
    ]);
    let production = SystemProxyOpsImpl::with_platform(MockRunner::default(), Platform::Mac);
    assert_eq!(
        production.snapshot_relation(&applied, &applied, &current_reordered),
        ProxySnapshotRelation::Exact,
        "macOS from == to must prefer Exact even when service enumeration is reordered"
    );

    // The controller remains cross-platform and delegates the exact same pure production macOS
    // relation; native SystemConfiguration mutation is deliberately not claimed on this host.
    for recovery in [false, true] {
        let marker = mem_marker();
        seed_current_marker(
            &marker,
            &original,
            &applied,
            &applied,
            ProxyMarkerPhase::Owned,
        );
        let mut controller =
            SystemProxyController::new(exact_ops(current_reordered.clone()), marker);

        if recovery {
            assert!(controller.recover_from_marker().unwrap().is_some());
        } else {
            controller.disable().unwrap();
        }

        assert_eq!(
            controller.ops.transaction_status.borrow().as_ref(),
            Some(&original),
            "same-target Owned must restore earliest original"
        );
        assert_eq!(controller.marker.read_checked(), ProxyMarkerRead::Missing);
    }
}

#[test]
fn exact_restoring_matrix_resumes_unchanged_but_preserves_foreign_or_query_error() {
    let original = exact_linux_snapshot("proxy.corp:3128");
    let applied = exact_linux_snapshot("127.0.0.1:8080");

    let exact_marker = mem_marker();
    seed_current_marker(
        &exact_marker,
        &original,
        &original,
        &applied,
        ProxyMarkerPhase::Restoring,
    );
    let mut exact = SystemProxyController::new(exact_ops(original.clone()), exact_marker);
    assert!(
        !exact.ensure_cleared(),
        "already restored must not rewrite OS"
    );
    assert!(!exact.ops.calls.borrow().contains(&"restore_transaction"));
    assert_eq!(exact.marker.read_checked(), ProxyMarkerRead::Missing);

    let unchanged_marker = mem_marker();
    seed_current_marker(
        &unchanged_marker,
        &original,
        &original,
        &applied,
        ProxyMarkerPhase::Restoring,
    );
    let mut unchanged = SystemProxyController::new(exact_ops(applied.clone()), unchanged_marker);
    assert!(unchanged.ensure_cleared());
    assert!(unchanged
        .ops
        .calls
        .borrow()
        .contains(&"restore_transaction"));
    assert_eq!(unchanged.marker.read_checked(), ProxyMarkerRead::Missing);

    let foreign_marker = mem_marker();
    seed_current_marker(
        &foreign_marker,
        &original,
        &original,
        &applied,
        ProxyMarkerPhase::Restoring,
    );
    let mut foreign = SystemProxyController::new(
        exact_ops(exact_linux_snapshot("foreign.proxy:9000")),
        foreign_marker,
    );
    assert!(foreign.disable().is_err());
    assert!(matches!(
        foreign.marker.read_checked(),
        ProxyMarkerRead::CurrentValidated(ref marker)
            if marker.phase == ProxyMarkerPhase::Restoring
    ));
    assert!(!foreign.ops.calls.borrow().contains(&"restore_transaction"));

    let query_marker = mem_marker();
    seed_current_marker(
        &query_marker,
        &original,
        &original,
        &applied,
        ProxyMarkerPhase::Restoring,
    );
    let mut query = SystemProxyController::new(
        MockOps {
            exact_available: true,
            ..Default::default()
        },
        query_marker,
    );
    assert!(query.disable().is_err());
    assert!(matches!(
        query.marker.read_checked(),
        ProxyMarkerRead::CurrentValidated(ref marker)
            if marker.phase == ProxyMarkerPhase::Restoring
    ));
}

#[test]
fn exact_restored_pending_clear_never_reads_or_writes_os() {
    let original = exact_linux_snapshot("proxy.corp:3128");
    let applied = exact_linux_snapshot("127.0.0.1:8080");
    let marker = mem_marker();
    seed_current_marker(
        &marker,
        &original,
        &original,
        &applied,
        ProxyMarkerPhase::RestoredPendingClear,
    );
    let mut controller = SystemProxyController::new(
        MockOps {
            exact_available: true,
            ..Default::default()
        },
        marker,
    );

    assert!(!controller.ensure_cleared());
    assert_eq!(controller.marker.read_checked(), ProxyMarkerRead::Missing);
    assert!(controller.ops.calls.borrow().is_empty());
}

#[test]
fn exact_current_without_capability_preserves_marker_and_performs_zero_os_io() {
    let original = exact_linux_snapshot("proxy.corp:3128");
    let applied = exact_linux_snapshot("127.0.0.1:8080");
    let marker = mem_marker();
    let seeded = seed_current_marker(
        &marker,
        &original,
        &original,
        &applied,
        ProxyMarkerPhase::Owned,
    );
    let mut controller = SystemProxyController::new(MockOps::default(), marker);

    assert!(controller.disable().is_err());
    assert_eq!(
        controller.marker.read_checked(),
        ProxyMarkerRead::CurrentValidated(seeded)
    );
    assert!(controller.ops.calls.borrow().is_empty());
}

#[test]
fn exact_restore_failure_keeps_restoring_marker_as_recovery_anchor() {
    let original = exact_linux_snapshot("proxy.corp:3128");
    let applied = exact_linux_snapshot("127.0.0.1:8080");
    let marker = mem_marker();
    seed_current_marker(
        &marker,
        &original,
        &original,
        &applied,
        ProxyMarkerPhase::Owned,
    );
    let mut controller = SystemProxyController::new(
        MockOps {
            exact_available: true,
            transaction_status: RefCell::new(Some(applied)),
            restore_fails: true,
            ..Default::default()
        },
        marker,
    );

    assert!(controller.disable().is_err());
    assert!(controller
        .ops
        .calls
        .borrow()
        .contains(&"restore_transaction"));
    assert!(matches!(
        controller.marker.read_checked(),
        ProxyMarkerRead::CurrentValidated(ref marker)
            if marker.phase == ProxyMarkerPhase::Restoring
                && marker.exact_original.as_ref() == Some(&original)
    ));
}

#[test]
fn exact_reconcile_cas_mismatch_and_persist_failure_are_zero_os_write() {
    let original = exact_linux_snapshot("proxy.corp:3128");
    let applied = exact_linux_snapshot("127.0.0.1:8080");

    let stale_fs = StaleCasFs::default();
    let stale_marker = ProxyMarker::new(stale_fs.clone(), "/marker.json");
    seed_current_marker(
        &stale_marker,
        &original,
        &original,
        &applied,
        ProxyMarkerPhase::Applying,
    );
    stale_fs.arm_after_reads(1);
    let mut stale = SystemProxyController::new(exact_ops(applied.clone()), stale_marker);
    assert!(stale.disable().is_err());
    assert!(!stale.ops.calls.borrow().contains(&"restore_transaction"));
    assert!(matches!(
        stale.marker.read_checked(),
        ProxyMarkerRead::CurrentValidated(ref marker)
            if marker.txn_id.as_deref() == Some("concurrent-transaction")
                && marker.our_host_port == "127.0.0.1:8080"
    ));

    let fail_fs = FailNthWriteFs::new(2);
    let fail_marker = ProxyMarker::new(fail_fs, "/marker.json");
    seed_current_marker(
        &fail_marker,
        &original,
        &original,
        &applied,
        ProxyMarkerPhase::Applying,
    );
    let mut persist = SystemProxyController::new(exact_ops(applied), fail_marker);
    assert!(persist.disable().is_err());
    assert!(!persist.ops.calls.borrow().contains(&"restore_transaction"));
    assert!(matches!(
        persist.marker.read_checked(),
        ProxyMarkerRead::CurrentValidated(ref marker)
            if marker.phase == ProxyMarkerPhase::Applying
    ));
}

#[test]
fn exact_system_to_system_disable_restores_earliest_original() {
    let original = exact_linux_snapshot("proxy.corp:3128");
    let first_applied = exact_linux_snapshot("127.0.0.1:7000");
    let second_applied = exact_linux_snapshot("127.0.0.1:8080");
    let marker = mem_marker();
    let first = seed_current_marker(
        &marker,
        &original,
        &original,
        &first_applied,
        ProxyMarkerPhase::Owned,
    );
    let crate::proxy::ProxyMarkerReplaceOutcome::Replaced(second) = marker.replace_if_current(
        first.txn_id.as_deref().unwrap(),
        "127.0.0.1:8080",
        &first_applied,
        &second_applied,
    ) else {
        panic!("replacement marker must persist");
    };
    assert_eq!(
        marker.update_current_phase(
            second.txn_id.as_deref().unwrap(),
            ProxyMarkerPhase::Applying,
            ProxyMarkerPhase::Owned,
        ),
        crate::proxy::ProxyMarkerMutationOutcome::Updated
    );
    let mut controller = SystemProxyController::new(exact_ops(second_applied), marker);

    controller.disable().unwrap();
    assert_eq!(
        controller.ops.transaction_status.borrow().as_ref(),
        Some(&original),
        "System→System 必须越过 fresh apply_base 恢复最早 original"
    );
    assert_eq!(controller.marker.read_checked(), ProxyMarkerRead::Missing);
}

#[test]
fn legacy_shared_marker_query_failure_preserves_token_and_ensure_bool_tracks_os_restore() {
    let fs = crate::proxy::proxy_tests_helpers::MemFs::new();
    let writer = ProxyMarker::new(fs.clone(), "/marker.json");
    write_legacy_marker(&writer, "127.0.0.1:8080", None);
    let before = writer.read_checked();
    let mut query_failure = SystemProxyController::new(
        MockOps {
            status_fails: true,
            ..Default::default()
        },
        ProxyMarker::new(fs.clone(), "/marker.json"),
    );
    assert!(!query_failure.ensure_cleared());
    assert_eq!(query_failure.marker.read_checked(), before);
    assert!(!query_failure.ops.calls.borrow().contains(&"clear"));

    let mut recovery = SystemProxyController::new(
        MockOps {
            status: RefCell::new(SystemProxyStatus {
                enabled: true,
                http_proxy: Some("127.0.0.1:8080".into()),
                ..Default::default()
            }),
            ..Default::default()
        },
        ProxyMarker::new(fs, "/marker.json"),
    );
    assert!(recovery.ensure_cleared());
    assert!(recovery.ops.calls.borrow().contains(&"clear"));
    assert_eq!(recovery.marker.read_checked(), ProxyMarkerRead::Missing);
}

#[test]
fn strict_read_errors_block_all_reconcile_entrypoints_and_marker_absence_checks() {
    let invalid_fs = crate::proxy::proxy_tests_helpers::MemFs::new();
    invalid_fs
        .write_marker("/marker.json", "{not-json")
        .unwrap();
    let mut invalid = SystemProxyController::new(
        MockOps::default(),
        ProxyMarker::new(invalid_fs, "/marker.json"),
    );
    assert!(invalid.disable().is_err());
    assert!(!invalid.ensure_cleared());
    assert!(invalid.has_marker(), "Invalid is blocking, not Missing");
    assert_eq!(invalid.detect_foreign_proxy(), None);
    assert!(invalid.ops.calls.borrow().is_empty());

    let unsupported_fs = crate::proxy::proxy_tests_helpers::MemFs::new();
    unsupported_fs
        .write_marker(
            "/marker.json",
            r#"{"systemProxyTxnV2":{"our_host_port":"127.0.0.1:8080","txn_id":"future","plan_version":99,"phase":"applying","exact_original":{},"exact_apply_base":{},"exact_applied":{}}}"#,
        )
        .unwrap();
    let mut unsupported = SystemProxyController::new(
        MockOps::default(),
        ProxyMarker::new(unsupported_fs, "/marker.json"),
    );
    assert!(matches!(
        unsupported.marker.read_checked(),
        ProxyMarkerRead::UnsupportedVersion(99)
    ));
    assert!(unsupported.recover_from_marker().is_err());
    assert!(unsupported.has_marker());
    assert!(unsupported.ops.calls.borrow().is_empty());

    struct IoReadFs(Rc<Cell<usize>>);
    impl MarkerFs for IoReadFs {
        fn write_marker(&self, _path: &str, _data: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn read_marker(&self, _path: &str) -> Option<String> {
            None
        }
        fn read_marker_checked(&self, _path: &str) -> std::io::Result<Option<String>> {
            Err(std::io::Error::other("injected strict read failure"))
        }
        fn remove_marker(&self, _path: &str) -> std::io::Result<()> {
            self.0.set(self.0.get() + 1);
            Ok(())
        }
    }
    let removes = Rc::new(Cell::new(0));
    let mut io = SystemProxyController::new(
        MockOps::default(),
        ProxyMarker::new(IoReadFs(Rc::clone(&removes)), "/marker.json"),
    );
    assert!(!io.ensure_cleared());
    assert!(io.has_marker(), "IoError is blocking, not Missing");
    assert_eq!(io.detect_foreign_proxy(), None);
    assert_eq!(removes.get(), 0);
    assert!(io.ops.calls.borrow().is_empty());
}

#[test]
fn enable_writes_marker_then_set_clears_on_disable() {
    let ops = MockOps::default();
    let mut controller = SystemProxyController::new(ops, mem_marker());

    // enable：mock status 默认 enabled=false → stripSelf 返回 Some(disabled) 作为 original。
    controller.enable(&req()).unwrap();
    assert!(controller.has_marker());
    assert!(controller.ops.calls.borrow().contains(&"set"));

    // disable：original=Some(disabled) → restore 被调（恢复原始=禁用态）。
    controller.disable().unwrap();
    assert!(!controller.has_marker());
    assert!(controller.ops.calls.borrow().contains(&"restore"));
}

#[test]
fn enable_captures_original_via_capture_path_not_residue_scan() {
    // 命令回退接线断言：enable 的原始快照走 `capture_original_status`，**不**走
    // `get_proxy_status`（残留检测，扫全部服务）。macOS 生产构造另由完整快照覆盖。
    let ops = MockOps::default();
    let mut controller = SystemProxyController::new(ops, mem_marker());
    controller.enable(&req()).unwrap();

    let calls = controller.ops.calls.borrow().clone();
    assert!(calls.contains(&"capture"), "enable 必须走捕获口径");
    assert!(
        !calls.contains(&"get_status"),
        "enable 不得走残留检测口径（扫全部服务）"
    );
}

#[test]
fn enable_failure_rolls_back_via_disable() {
    let ops = MockOps {
        set_fails: true,
        ..Default::default()
    };
    let mut controller = SystemProxyController::new(ops, mem_marker());
    let err = controller.enable(&req()).unwrap_err();
    assert!(err.to_string().contains("set failed"));
    // 失败兜底：disable 被调用（original=Some(disabled) → restore）→ marker 清。
    assert!(controller.ops.calls.borrow().contains(&"restore"));
    assert!(!controller.has_marker());
}

#[test]
fn disable_keeps_marker_on_failure_for_retry() {
    // original 会是 Some(disabled)（mock status 默认 enabled=false）→ disable 走 restore；
    // 让 restore 失败以验证 marker 保留。
    let ops = MockOps {
        restore_fails: true,
        ..Default::default()
    };
    let mut controller = SystemProxyController::new(ops, mem_marker());
    controller.enable(&req()).unwrap();
    assert!(controller.has_marker());

    // disable 失败（restore_fails）→ marker 保留（供下次启动重试）。
    controller.disable().unwrap_err();
    assert!(controller.has_marker());
    assert!(
        controller.complete_original_snapshot().is_some(),
        "同一会话内也必须保留原值，允许调用方立即重试"
    );
}

#[test]
fn disable_reports_marker_removal_failure_and_keeps_in_memory_snapshot() {
    #[derive(Default)]
    struct RemoveFailFs {
        file: RefCell<Option<String>>,
    }
    impl MarkerFs for RemoveFailFs {
        fn write_marker(&self, _path: &str, data: &str) -> std::io::Result<()> {
            *self.file.borrow_mut() = Some(data.to_string());
            Ok(())
        }
        fn read_marker(&self, _path: &str) -> Option<String> {
            self.file.borrow().clone()
        }
        fn remove_marker(&self, _path: &str) -> std::io::Result<()> {
            Err(std::io::Error::other("read-only filesystem"))
        }
    }

    let ops = MockOps::default();
    let marker = ProxyMarker::new(RemoveFailFs::default(), "/marker.json");
    let mut controller = SystemProxyController::new(ops, marker);
    controller.enable(&req()).unwrap();

    let error = controller.disable().unwrap_err();
    assert!(error
        .to_string()
        .contains("删除 legacy 系统代理 marker 失败"));
    assert!(controller.has_marker());
    assert!(controller.complete_original_snapshot().is_some());
}

#[test]
fn complete_macos_snapshot_is_persisted_before_set_and_restored_by_id_path() {
    let original = ProxyOriginalSettings {
        fallback: None,
        mac_services: vec![crate::proxy::MacProxyServiceSnapshot {
            service_id: "stable-service-id".into(),
            service_name: "Wi-Fi".into(),
            service_enabled: true,
            had_proxy_protocol: true,
            protocol_enabled: true,
            configuration_plist: Some("<plist>opaque</plist>".into()),
            status: SystemProxyStatus {
                enabled: true,
                http_proxy: Some("proxy.corp:3128".into()),
                ..Default::default()
            },
            touched: None,
            clear_on_restore: false,
        }],
        linux_gsettings: None,
        windows_registry: None,
    };
    let ops = MockOps {
        full_settings: Some(original.clone()),
        status: RefCell::new(SystemProxyStatus {
            enabled: true,
            http_proxy: Some("127.0.0.1:8080".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut controller = SystemProxyController::new(ops, mem_marker());

    controller.enable(&req()).unwrap();
    let persisted = match controller.marker.read_checked() {
        ProxyMarkerRead::Legacy(data) => data.original_snapshot(),
        other => panic!("expected legacy marker, got {other:?}"),
    }
    .expect("set 前 marker 必须已有完整恢复锚点");
    assert_eq!(persisted, original);
    assert_eq!(
        controller.ops.calls.borrow().as_slice(),
        &["capture_full", "set"]
    );

    controller.disable().unwrap();
    assert!(controller.ops.calls.borrow().contains(&"restore_full"));
    assert!(!controller.has_marker());
}

#[test]
fn snapshot_required_path_aborts_before_set_when_capture_fails() {
    let ops = MockOps {
        capture_fails: true,
        requires_snapshot: true,
        ..Default::default()
    };
    let mut controller = SystemProxyController::new(ops, mem_marker());

    let error = controller.enable(&req()).unwrap_err();
    assert!(error.to_string().contains("capture failed"));
    assert!(!controller.ops.calls.borrow().contains(&"set"));
    assert!(!controller.has_marker(), "只读捕获失败时不应创建 marker");
    assert!(controller.complete_original_snapshot().is_none());
}

#[test]
fn snapshot_required_path_aborts_before_set_when_marker_write_fails() {
    struct WriteFailFs;
    impl MarkerFs for WriteFailFs {
        fn write_marker(&self, _path: &str, _data: &str) -> std::io::Result<()> {
            Err(std::io::Error::other("disk full"))
        }
        fn read_marker(&self, _path: &str) -> Option<String> {
            None
        }
        fn remove_marker(&self, _path: &str) -> std::io::Result<()> {
            Ok(())
        }
    }

    let ops = MockOps {
        requires_snapshot: true,
        ..Default::default()
    };
    let marker = ProxyMarker::new(WriteFailFs, "/marker.json");
    let mut controller = SystemProxyController::new(ops, marker);

    let error = controller.enable(&req()).unwrap_err();
    assert!(error.to_string().contains("持久化"));
    assert!(!controller.ops.calls.borrow().contains(&"set"));
    assert!(controller.complete_original_snapshot().is_none());
}

#[test]
fn legacy_marker_lock_failure_is_zero_os_write_even_without_required_snapshot() {
    #[derive(Clone, Default)]
    struct LockFailFs {
        writes: Rc<Cell<usize>>,
        removes: Rc<Cell<usize>>,
    }
    impl MarkerFs for LockFailFs {
        fn write_marker(&self, _path: &str, _data: &str) -> std::io::Result<()> {
            self.writes.set(self.writes.get() + 1);
            Ok(())
        }
        fn read_marker(&self, _path: &str) -> Option<String> {
            None
        }
        fn remove_marker(&self, _path: &str) -> std::io::Result<()> {
            self.removes.set(self.removes.get() + 1);
            Ok(())
        }
        fn acquire_marker_mutation_lock(
            &self,
            _path: &str,
        ) -> std::io::Result<crate::proxy::MarkerMutationLockGuard> {
            Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "injected sibling lock contention",
            ))
        }
    }

    let fs = LockFailFs::default();
    let mut controller = SystemProxyController::new(
        MockOps::default(),
        ProxyMarker::new(fs.clone(), "/marker.json"),
    );

    let error = controller.enable(&req()).unwrap_err();

    assert!(error.to_string().contains("持久化"));
    let calls = controller.ops.calls.borrow();
    for forbidden in ["set", "clear", "restore", "restore_full"] {
        assert!(
            !calls.contains(&forbidden),
            "unexpected OS write: {forbidden}"
        );
    }
    assert_eq!(fs.writes.get(), 0, "lock failure must precede marker write");
    assert_eq!(
        fs.removes.get(),
        0,
        "failure must not pretend to clear marker"
    );
    assert_eq!(controller.marker.read_checked(), ProxyMarkerRead::Missing);
    assert!(controller.complete_original_snapshot().is_none());
}

#[test]
fn enable_strips_self_referential_original() {
    // 当前代理已指向我们自己 → stripSelf → original=None（disable 不会恢复死端口）。
    let ops = MockOps {
        status: RefCell::new(SystemProxyStatus {
            enabled: true,
            http_proxy: Some("127.0.0.1:8080".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut controller = SystemProxyController::new(ops, mem_marker());
    controller.enable(&req()).unwrap();
    assert!(controller.original_snapshot().is_none());
}

#[test]
fn enable_preserves_real_external_original() {
    let external = SystemProxyStatus {
        enabled: true,
        http_proxy: Some("proxy.corp:3128".into()),
        ..Default::default()
    };
    let ops = MockOps {
        status: RefCell::new(external.clone()),
        ..Default::default()
    };
    let mut controller = SystemProxyController::new(ops, mem_marker());
    controller.enable(&req()).unwrap();
    // 真实第三方代理被保留为 original → disable 时会 restore。
    assert_eq!(controller.original_snapshot(), Some(&external));
}

// ── 维度7 #8：marker 崩溃恢复（核心验收）──

#[test]
fn recover_from_marker_clears_residual_proxy() {
    // 场景：上次会话 enable 写了 marker，进程崩溃（未 disable）→ marker 残留。
    // 重启新会话 → recover_from_marker 读到 → 清除残留代理 → 清 marker。
    let ops = MockOps {
        status: RefCell::new(SystemProxyStatus {
            enabled: true,
            http_proxy: Some("127.0.0.1:8080".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut controller = SystemProxyController::new(ops, mem_marker());

    // 模拟崩溃残留：直接写 marker（绕过 enable，仿佛上个进程写的）。
    write_legacy_marker(&controller.marker, "127.0.0.1:8080", None);
    assert!(controller.has_marker());

    // 重启后恢复。
    let recovered = controller.recover_from_marker().unwrap();
    assert!(recovered.is_some());
    assert_eq!(recovered.unwrap().our_host_port, "127.0.0.1:8080");
    // 无 original → clear_proxy 被调（清除指向死端口的残留代理）。
    assert!(controller.ops.calls.borrow().contains(&"clear"));
    // marker 已清（下次启动不再误恢复）。
    assert!(!controller.has_marker());
}

#[test]
fn recover_from_marker_restores_original_when_present() {
    // marker 携带 original（Linux 写入路径）→ 恢复原始代理而非简单关。
    let ops = MockOps {
        status: RefCell::new(SystemProxyStatus {
            enabled: true,
            http_proxy: Some("127.0.0.1:8080".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut controller = SystemProxyController::new(ops, mem_marker());

    let original = SystemProxyStatus {
        enabled: true,
        http_proxy: Some("proxy.lan:3128".into()),
        ..Default::default()
    };
    write_legacy_marker(&controller.marker, "127.0.0.1:8080", Some(&original));

    let recovered = controller
        .recover_from_marker()
        .unwrap()
        .expect("marker present");
    assert_eq!(
        recovered.original_settings.unwrap().http_proxy,
        Some("proxy.lan:3128".to_string())
    );
    // restore 被调（恢复用户原始代理）。
    assert!(controller.ops.calls.borrow().contains(&"restore"));
    assert!(!controller.has_marker());
}

#[test]
fn recover_from_marker_noop_when_no_marker() {
    let ops = MockOps::default();
    let mut controller = SystemProxyController::new(ops, mem_marker());
    // 无 marker → 不动作。
    assert!(controller.recover_from_marker().unwrap().is_none());
    assert!(controller.ops.calls.borrow().is_empty());
}

#[test]
fn failed_crash_recovery_keeps_marker_and_snapshot_for_retry() {
    let ops = MockOps {
        restore_fails: true,
        status: RefCell::new(SystemProxyStatus {
            enabled: true,
            http_proxy: Some("127.0.0.1:8080".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut controller = SystemProxyController::new(ops, mem_marker());
    let original = ProxyOriginalSettings {
        fallback: None,
        mac_services: vec![crate::proxy::MacProxyServiceSnapshot {
            service_id: "stable-service-id".into(),
            service_name: "Wi-Fi".into(),
            had_proxy_protocol: true,
            ..Default::default()
        }],
        linux_gsettings: None,
        windows_registry: None,
    };
    assert!(matches!(
        controller
            .marker
            .begin_legacy_if_absent("127.0.0.1:8080", Some(&original)),
        crate::proxy::ProxyMarkerBeginOutcome::Begun(_)
    ));

    assert!(controller.recover_from_marker().is_err());
    assert!(controller.has_marker(), "恢复失败不得销毁唯一恢复锚点");
    assert_eq!(controller.complete_original_snapshot(), Some(&original));
    assert!(controller.ops.calls.borrow().contains(&"restore_full"));
}

#[test]
fn crash_recovery_full_cycle_two_sessions() {
    // 端到端：会话1 enable → 崩溃 → 会话2 recover → 干净。
    // 用 Clone-共享 FS 模拟跨会话同一磁盘 marker 文件（MemFs 内部 Rc 共享状态）。
    use crate::proxy::proxy_tests_helpers::MemFs;
    let fs = MemFs::new();
    // 会话1：写 marker 后「崩溃」（未 disable）。
    let marker1 = ProxyMarker::new(fs.clone(), "/m");
    write_legacy_marker(&marker1, "127.0.0.1:8080", None);

    // 「重启」：新 ProxyMarker 读同一文件（FS 状态跨「进程」存活）。
    let marker2 = ProxyMarker::new(fs, "/m");
    let ProxyMarkerRead::Legacy(data) = marker2.read_checked() else {
        panic!("marker survived crash");
    };
    assert_eq!(
        marker2.clear_legacy_if_current(&data),
        crate::proxy::ProxyMarkerMutationOutcome::Updated
    );
    assert_eq!(marker2.read_checked(), ProxyMarkerRead::Missing);
}

// ── 三平台命令构造测试 ──

/// 从 reg add 命令里取 /d 后的值（形如 add REG_PATH /v K /t T /d `<VAL>` /f）。
fn reg_value(cmd: &Command) -> &String {
    // /d 的下一项即值。
    let idx = cmd.args.iter().position(|a| a == "/d").expect("/d present");
    cmd.args.get(idx + 1).expect("value after /d")
}

#[test]
fn windows_enable_commands_no_socks_in_proxyserver() {
    let cmds = windows_enable_commands("reg.exe", &req());
    let values = windows_enable_values(&req());
    assert_eq!(
        values.proxy_server,
        "http=127.0.0.1:8080;https=127.0.0.1:8080"
    );
    assert_eq!(values.proxy_enable, 1);
    assert!(!values.proxy_override.is_empty());
    // ProxyServer 行：只 http/https，无 socks（Chromium SOCKS5 DNS 污染防护）。
    let proxy_server = cmds
        .iter()
        .find(|c| c.args.get(3) == Some(&"ProxyServer".to_string()))
        .expect("ProxyServer cmd");
    let val = reg_value(proxy_server);
    assert!(val.contains("http=127.0.0.1:8080"));
    assert!(val.contains("https=127.0.0.1:8080"));
    assert!(
        !val.contains("socks="),
        "must not set socks= in ProxyServer"
    );
    // ProxyEnable=1
    let enable = cmds
        .iter()
        .find(|c| c.args.get(3) == Some(&"ProxyEnable".to_string()))
        .unwrap();
    assert_eq!(reg_value(enable), "1");
    assert_eq!(cmds.len(), 3, "代理事务只包含三条必要的注册表写");
    let write_order = cmds
        .iter()
        .map(|command| command.args[3].as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        write_order,
        ["ProxyServer", "ProxyOverride", "ProxyEnable"],
        "两个配置值必须先写，ProxyEnable 作为生效门最后写"
    );
    assert!(
        !cmds
            .iter()
            .any(|c| c.args.contains(&"name=Polaris_Block_QUIC".to_string())),
        "可选 QUIC 清理不得混进必要事务"
    );
}

#[test]
fn windows_disable_sets_proxyenable_zero() {
    let cmd = windows_disable_commands("reg.exe");
    assert_eq!(reg_value(&cmd), "0");
    assert_eq!(cmd.args.get(3), Some(&"ProxyEnable".to_string()));
}

#[test]
fn mac_enable_commands_per_service_all_protocols() {
    let cmds = mac_service_enable_commands("Wi-Fi", &req());
    // 三条 set 本身即启用对应协议，外加 bypass；不得退回每协议再 spawn 一条 state-on。
    assert_eq!(cmds.len(), 4);
    assert!(cmds
        .iter()
        .any(|c| c.args[0] == "-setwebproxy" && c.args[1] == "Wi-Fi"));
    assert!(cmds.iter().any(|c| c.args[0] == "-setsecurewebproxy"));
    assert!(cmds.iter().any(|c| c.args[0] == "-setsocksfirewallproxy"));
    assert!(!cmds
        .iter()
        .any(|c| c.args[0].ends_with("proxystate") && c.args.last() == Some(&"on".to_string())));
    assert!(cmds.iter().any(|c| c.args[0] == "-setproxybypassdomains"));
}

#[test]
fn mac_disable_commands_all_off() {
    let cmds = mac_service_disable_commands("Ethernet");
    assert_eq!(cmds.len(), 3);
    assert!(cmds
        .iter()
        .all(|c| c.args.last() == Some(&"off".to_string())));
}

#[test]
fn parse_mac_network_services_filters() {
    let stdout = "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Bluetooth PAN\nEthernet\n\nBluetooth PAN\n";
    let svcs = parse_mac_network_services(stdout);
    assert_eq!(svcs, vec!["Wi-Fi".to_string(), "Ethernet".to_string()]);
}

#[test]
fn linux_enable_commands_gnome_manual() {
    let cmds = linux_enable_commands(&req()).unwrap();
    assert_eq!(cmds.len(), LINUX_GSETTINGS_KEYS.len());
    for (command, key) in cmds.iter().zip(LINUX_GSETTINGS_KEYS) {
        assert_eq!(&command.args[1], key.schema);
        assert_eq!(&command.args[2], key.key);
    }
    assert_eq!(cmds.last().unwrap().args[2], "mode", "mode 必须最后写");
    // http host/port/enabled
    assert!(cmds.iter().any(|c| {
        c.args[1] == "org.gnome.system.proxy.http"
            && c.args[2] == "host"
            && c.args[3] == "'127.0.0.1'"
    }));
    assert!(cmds.iter().any(|c| {
        c.args[1] == "org.gnome.system.proxy.http" && c.args[2] == "enabled" && c.args[3] == "true"
    }));
    // socks
    assert!(cmds.iter().any(|c| {
        c.args[1] == "org.gnome.system.proxy.socks" && c.args[2] == "port" && c.args[3] == "1080"
    }));
    // ignore-hosts（GVariant 数组）
    let ignore = cmds.iter().find(|c| c.args[2] == "ignore-hosts").unwrap();
    let val = ignore.args.last().unwrap();
    assert!(val.starts_with("['") && val.ends_with("']"));
    assert!(val.contains("'10.0.0.0/8'"));
    assert!(val.contains("'localhost'"));
}

#[test]
fn linux_gvariant_encoder_escapes_bypass_without_changing_array_shape() {
    assert_eq!(
        encode_gvariant_string("slash\\quote'\n\r\t\u{0001}").unwrap(),
        "\"slash\\\\quote'\\n\\r\\t\\u0001\""
    );
    assert_eq!(
        encode_gvariant_string("double\"quote").unwrap(),
        "'double\"quote'"
    );
    assert_eq!(
        encode_gvariant_string("both'\"quotes").unwrap(),
        "\"both'\\\"quotes\""
    );
    assert!(encode_gvariant_string("not\0representable").is_err());
    let mut special = req();
    special.bypass_list = vec!["corp\\share".into(), "o'hare".into(), "line\nbreak".into()];
    let applied = linux_applied_snapshot(&special).unwrap();
    assert_eq!(
        applied.ignore_hosts,
        "['corp\\\\share', \"o'hare\", 'line\\nbreak']"
    );
    validate_linux_gsettings_snapshot(&applied).unwrap();

    special.bypass_list.clear();
    let empty = linux_applied_snapshot(&special).unwrap();
    assert_eq!(empty.ignore_hosts, "@as []");
    assert_eq!(empty.http_port, "8080", "port canonical raw 是裸十进制");
}

#[test]
fn linux_exact_restore_rejects_noncanonical_or_invalid_raw_before_writing() {
    for invalid_port in [
        "uint32 8080",
        "uint16 8080",
        "08080",
        "8080 ",
        "-1",
        "65536",
        "not-a-port",
    ] {
        let mut snapshot = linux_applied_snapshot(&req()).unwrap();
        snapshot.http_port = invalid_port.into();
        assert!(linux_exact_restore_commands(&snapshot).is_err());
    }

    for invalid_array in [
        "[]",
        " @as []",
        "@as [] ",
        "[ 'local']",
        "['local' ]",
        "['local','host']",
        "['o\\'hare']",
        "['unterminated]",
    ] {
        let mut snapshot = linux_applied_snapshot(&req()).unwrap();
        snapshot.ignore_hosts = invalid_array.into();
        assert!(linux_exact_restore_commands(&snapshot).is_err());
    }

    for invalid_host in [" 'proxy'", "'proxy' ", "\"proxy\"", "'o\\'hare'"] {
        let mut snapshot = linux_applied_snapshot(&req()).unwrap();
        snapshot.http_host = invalid_host.into();
        assert!(linux_exact_restore_commands(&snapshot).is_err());
    }

    for invalid_mode in ["\"manual\"", " 'manual'", "'manual' "] {
        let mut snapshot = linux_applied_snapshot(&req()).unwrap();
        snapshot.mode = invalid_mode.into();
        assert!(linux_exact_restore_commands(&snapshot).is_err());
    }

    let mut nul = linux_applied_snapshot(&req()).unwrap();
    nul.ignore_hosts = "['bad\\u0000']".into();
    assert!(linux_exact_restore_commands(&nul).is_err());
}

#[test]
fn linux_exact_restore_roundtrips_all_raw_values_in_fixed_order() {
    let snapshot = crate::proxy::LinuxGSettingsSnapshot {
        http_host: "'  dormant proxy  '".into(),
        http_port: "3128".into(),
        http_enabled: "false".into(),
        https_host: "'secure.example'".into(),
        https_port: "4443".into(),
        socks_host: "'socks.example'".into(),
        socks_port: "1080".into(),
        ignore_hosts: "[\"local'host\", 'corp\\\\share']".into(),
        mode: "'auto'".into(),
    };
    let commands = linux_exact_restore_commands(&snapshot).unwrap();
    let restored = commands
        .iter()
        .map(|command| command.args[3].as_str())
        .collect::<Vec<_>>();
    assert_eq!(restored, snapshot.raw_values());
}

#[test]
fn linux_disable_sets_mode_none() {
    let cmd = linux_disable_command();
    assert_eq!(cmd.args[3], "none");
}

// ── 三平台状态解析（纯函数，Linux 上跑测 win/mac 解析）──

#[test]
fn parse_win_proxy_enable_requires_exact_key_type_and_value() {
    assert!(parse_win_proxy_enable(
        "\r\nHKEY_CURRENT_USER\\...\\Internet Settings\r\n    ProxyEnable    REG_DWORD    0x1\r\n"
    ));
    assert!(parse_win_proxy_enable(
        "    ProxyEnable    REG_DWORD    1\r\n"
    ));
    assert!(parse_win_proxy_enable(
        "    proxyenable    REG_DWORD    0x1\r\n"
    ));
    assert!(!parse_win_proxy_enable(
        "    ProxyEnable    REG_DWORD    0x0\r\n"
    ));
    assert!(!parse_win_proxy_enable(
        "    ProxyEnable    REG_DWORD    0x10\r\n"
    ));
    assert!(!parse_win_proxy_enable(
        "    ProxyEnableBackup    REG_DWORD    0x1\r\n"
    ));
    assert!(!parse_win_proxy_enable(
        "    ProxyEnable    REG_SZ    0x1\r\n"
    ));
    assert!(!parse_win_proxy_enable(
        "    ProxyEnable    REG_DWORD    0x1    trailing\r\n"
    ));
    assert!(!parse_win_proxy_enable(""));
}

#[test]
fn parse_win_proxy_server_splits_protocols() {
    let stdout = "\r\nHKEY_CURRENT_USER\\Software\\...\\Internet Settings\r\n    ProxyServer    REG_SZ    http=127.0.0.1:8080;https=127.0.0.1:8080;socks=127.0.0.1:1080\r\n";
    let st = parse_win_proxy_server(stdout);
    assert!(st.enabled);
    assert_eq!(st.http_proxy, Some("127.0.0.1:8080".into()));
    assert_eq!(st.https_proxy, Some("127.0.0.1:8080".into()));
    assert_eq!(st.socks_proxy, Some("127.0.0.1:1080".into()));
}

#[test]
fn parse_win_proxy_server_missing_line_keeps_enabled_true() {
    // 上游：`if (!proxyServerMatch) return { enabled: true }` —— 有 ProxyEnable=1 但读不到明细。
    let st = parse_win_proxy_server("some unrelated output");
    assert!(st.enabled);
    assert!(!st.has_any_proxy());
}

#[test]
fn parse_win_proxy_server_ignores_similar_key_name() {
    // 防前缀误匹配（ProxyServerBackup 不是 ProxyServer）。
    let st = parse_win_proxy_server("    ProxyServerBackup    REG_SZ    http=evil:1\r\n");
    assert!(!st.has_any_proxy(), "不得匹配 ProxyServerBackup");
}

/// **裸 `host:port`（Windows 设置 UI 手填形态）必须被认成「全协议同值」。**
///
/// 变异锁：删掉 `parse_win_proxy_server` 里那段 `if !value.contains('=')` 早退 → 三腿全 `None`
/// → 下面的 `points_to_mixed_inbound` 断言当场转红（= 用户手填了我们的地址却被判「未生效」，
/// 稳定误亮降级黄灯）。
#[test]
fn parse_win_proxy_server_accepts_bare_hostport_as_all_protocols() {
    let st = parse_win_proxy_server("    ProxyServer    REG_SZ    127.0.0.1:7890\r\n");
    assert!(st.enabled);
    assert_eq!(st.http_proxy.as_deref(), Some("127.0.0.1:7890"));
    assert_eq!(st.https_proxy.as_deref(), Some("127.0.0.1:7890"));
    assert_eq!(
        st.socks_proxy, None,
        "裸形态不填 socks 腿：未设 ≠ 指向别处，多填会在用户另设 socks 时造假象"
    );
    // 真正要守的终态：手填我们的地址 → 活态判定必须说「生效」。
    assert!(
        points_to_mixed_inbound(&st, "127.0.0.1", 7890),
        "裸形态指向我们的 mixed 口 → 必须判生效"
    );
    // 反向不受影响：手填了别的代理仍判未生效。
    let other = parse_win_proxy_server("    ProxyServer    REG_SZ    proxy.corp:3128\r\n");
    assert!(!points_to_mixed_inbound(&other, "127.0.0.1", 7890));

    // 空值 / 纯空白仍按「读不到明细」处理（不造出一条 `Some("")` 的假腿）。
    let blank = parse_win_proxy_server("    ProxyServer    REG_SZ       \r\n");
    assert!(!blank.has_any_proxy());
}

#[test]
fn parse_mac_service_proxy_reads_server_port() {
    let stdout = "Enabled: Yes\nServer: 127.0.0.1\nPort: 8080\nAuthenticated Proxy Enabled: 0\n";
    assert_eq!(
        parse_mac_service_proxy(stdout),
        Some("127.0.0.1:8080".into())
    );
}

#[test]
fn parse_mac_service_proxy_none_when_disabled() {
    let stdout = "Enabled: No\nServer:\nPort: 0\n";
    assert_eq!(parse_mac_service_proxy(stdout), None);
}

#[test]
fn parse_gsettings_host_strips_quotes_and_empty() {
    assert_eq!(
        parse_gsettings_host("'127.0.0.1'\n"),
        Some("127.0.0.1".into())
    );
    // 用户清了 host → gsettings 返回 '' → None（不误报 enabled，否则 advisory 弹 ":port"）。
    assert_eq!(parse_gsettings_host("''\n"), None);
    assert_eq!(parse_gsettings_host("\n"), None);
}

/// 当前 GNOME port canonical raw 是裸 `i`；旧诊断/fixture 曾留下 `uint16`/`uint32` 前缀，
/// legacy projection parser 继续兼容。V2 exact validator 另行严格拒绝这些非 canonical raw。
#[test]
fn parse_gsettings_port_strips_gvariant_prefix() {
    assert_eq!(parse_gsettings_port("uint32 8080\n"), "8080");
    assert_eq!(parse_gsettings_port("uint16 3128\n"), "3128");
    assert_eq!(parse_gsettings_port("8080\n"), "8080");
    // 端口剥完须能被 split_host_port 吃下（组合面，防「两扇门之间的缝」）。
    let hp = crate::proxy::split_host_port(Some(&format!(
        "127.0.0.1:{}",
        parse_gsettings_port("uint32 8080\n")
    )));
    assert_eq!(hp.map(|h| h.port), Some(8080));
}

// ── 恢复命令构造 ──

#[test]
fn windows_restore_commands_rebuild_proxyserver_and_enable() {
    let original = SystemProxyStatus {
        enabled: true,
        http_proxy: Some("proxy.corp:3128".into()),
        socks_proxy: Some("socks.corp:1080".into()),
        ..Default::default()
    };
    let cmds = windows_restore_commands("reg.exe", &original);
    let server = cmds
        .iter()
        .find(|c| c.args.get(3) == Some(&"ProxyServer".to_string()))
        .expect("ProxyServer cmd");
    let val = reg_value(server);
    assert!(val.contains("http=proxy.corp:3128"));
    assert!(val.contains("socks=socks.corp:1080"));
    assert!(!val.contains("https="), "原始未设 https → 不得凭空造出");
    // ProxyEnable=1 且在 ProxyServer 之后（先值后开关）。
    let enable_idx = cmds
        .iter()
        .position(|c| c.args.get(3) == Some(&"ProxyEnable".to_string()))
        .unwrap();
    let server_idx = cmds
        .iter()
        .position(|c| c.args.get(3) == Some(&"ProxyServer".to_string()))
        .unwrap();
    assert!(server_idx < enable_idx);
    assert_eq!(reg_value(&cmds[enable_idx]), "1");
}

#[test]
fn mac_service_restore_commands_symmetric_undo() {
    let original = SystemProxyStatus {
        enabled: true,
        http_proxy: Some("proxy.corp:3128".into()),
        ..Default::default()
    };
    let cmds = mac_service_restore_commands("Wi-Fi", &original);
    // 设了的 → set + state on
    assert!(cmds
        .iter()
        .any(|c| c.args[0] == "-setwebproxy" && c.args[2] == "proxy.corp" && c.args[3] == "3128"));
    assert!(cmds
        .iter()
        .any(|c| c.args[0] == "-setwebproxystate" && c.args[2] == "on"));
    // 没设的 → state off（对称撤销，不把 http 扇出到 https/socks）
    assert!(cmds
        .iter()
        .any(|c| c.args[0] == "-setsecurewebproxystate" && c.args[2] == "off"));
    assert!(cmds
        .iter()
        .any(|c| c.args[0] == "-setsocksfirewallproxystate" && c.args[2] == "off"));
    assert!(!cmds.iter().any(|c| c.args[0] == "-setsecurewebproxy"));
}

#[test]
fn linux_restore_schema_set_and_clear() {
    // set：有 host:port
    let set_entry = crate::proxy::RestorePlanEntry {
        schema: "http",
        hp: Some(crate::proxy::HostPort {
            host: "proxy.lan".into(),
            port: 3128,
        }),
    };
    let set_cmds = linux_restore_schema_commands(&set_entry);
    assert!(set_cmds
        .iter()
        .any(|c| c.args[2] == "host" && c.args[3] == "proxy.lan"));
    assert!(set_cmds
        .iter()
        .any(|c| c.args[2] == "port" && c.args[3] == "3128"));
    assert!(set_cmds
        .iter()
        .any(|c| c.args[2] == "enabled" && c.args[3] == "true"));

    // clear：无 hp
    let clear_entry = crate::proxy::RestorePlanEntry {
        schema: "https",
        hp: None,
    };
    let clear_cmds = linux_restore_schema_commands(&clear_entry);
    assert!(clear_cmds
        .iter()
        .any(|c| c.args[2] == "host" && c.args[3].is_empty()));
    // 非 http schema 不写 enabled
    assert!(!clear_cmds.iter().any(|c| c.args[2] == "enabled"));
}

// ══════════ 生产实现接线（SystemProxyOpsImpl）══════════
//
// 全部在 Linux 上跑测三平台 —— 靠运行时 Platform 枚举 + MockRunner 注入，不碰宿主网络。
// 这正是审计 §M1 判「运行时枚举优于 cfg」的兑现处：若这些分派是 #[cfg]，以下测试在 Linux 上
// 一条都跑不到。

use crate::exec::exec_tests_helpers::MockRunner;

fn linux_transaction_snapshot(snapshot: LinuxGSettingsSnapshot) -> ProxyTransactionSnapshot {
    ProxyTransactionSnapshot {
        projection: Some(super::linux::linux_snapshot_projection(&snapshot)),
        linux_gsettings: Some(snapshot),
        ..Default::default()
    }
}

#[derive(Clone)]
struct StatefulLinuxRunner {
    current: Rc<RefCell<LinuxGSettingsSnapshot>>,
    set_calls: Rc<Cell<usize>>,
    get_calls: Rc<Cell<usize>>,
    fail_first_set_after_mutation: Rc<Cell<bool>>,
    panic_first_set_after_mutation: Rc<Cell<bool>>,
}

impl StatefulLinuxRunner {
    fn new(current: LinuxGSettingsSnapshot) -> Self {
        Self {
            current: Rc::new(RefCell::new(current)),
            set_calls: Rc::new(Cell::new(0)),
            get_calls: Rc::new(Cell::new(0)),
            fail_first_set_after_mutation: Rc::new(Cell::new(false)),
            panic_first_set_after_mutation: Rc::new(Cell::new(false)),
        }
    }

    fn with_partial_first_write(self) -> Self {
        self.fail_first_set_after_mutation.set(true);
        self
    }

    fn with_crash_after_first_write(self) -> Self {
        self.panic_first_set_after_mutation.set(true);
        self
    }
}

impl CommandRunner for StatefulLinuxRunner {
    fn run(
        &self,
        command: &Command,
        _timeout: std::time::Duration,
    ) -> Result<CommandOutput, String> {
        let operation = command.args.first().map(String::as_str);
        let schema = command.args.get(1).map(String::as_str);
        let key = command.args.get(2).map(String::as_str);
        let index = LINUX_GSETTINGS_KEYS
            .iter()
            .position(|entry| Some(entry.schema) == schema && Some(entry.key) == key)
            .ok_or_else(|| "unexpected Linux exact command".to_string())?;
        match operation {
            Some("get") => {
                self.get_calls.set(self.get_calls.get() + 1);
                Ok(CommandOutput {
                    stdout: self.current.borrow().raw_values()[index].to_owned(),
                    stderr: String::new(),
                })
            }
            Some("set") => {
                self.set_calls.set(self.set_calls.get() + 1);
                let value = command.args.get(3).cloned().unwrap_or_default();
                let mut current = self.current.borrow_mut();
                match index {
                    0 => current.http_host = value,
                    1 => current.http_port = value,
                    2 => current.http_enabled = value,
                    3 => current.https_host = value,
                    4 => current.https_port = value,
                    5 => current.socks_host = value,
                    6 => current.socks_port = value,
                    7 => current.ignore_hosts = value,
                    8 => current.mode = value,
                    _ => unreachable!(),
                }
                if self.panic_first_set_after_mutation.replace(false) {
                    drop(current);
                    panic!("simulated process crash after partial Linux exact write");
                }
                if self.fail_first_set_after_mutation.replace(false) {
                    return Err("timeout after partial Linux exact write".into());
                }
                Ok(CommandOutput::default())
            }
            _ => Err("unexpected Linux exact operation".into()),
        }
    }
}

fn windows_exact_snapshot(
    proxy_server: WindowsRegistryStringValue,
    proxy_override: WindowsRegistryStringValue,
    proxy_enable: WindowsRegistryDwordValue,
) -> ProxyTransactionSnapshot {
    let windows = WindowsProxyRegistrySnapshot {
        proxy_server,
        proxy_override,
        proxy_enable,
    };
    ProxyTransactionSnapshot {
        projection: Some(windows_registry_projection(&windows)),
        windows_registry: Some(windows),
        ..Default::default()
    }
}

#[cfg(target_os = "macos")]
fn mac_exact_snapshot() -> ProxyTransactionSnapshot {
    ProxyTransactionSnapshot {
        projection: Some(SystemProxyStatus::default()),
        mac_services: vec![crate::proxy::MacProxyServiceSnapshot {
            service_id: "service-id".into(),
            service_name: "Wi-Fi".into(),
            service_enabled: true,
            touched: Some(crate::proxy::MacProxyTouchedSnapshot::default()),
            ..Default::default()
        }],
        ..Default::default()
    }
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct ProbeThenUnavailableMacWriter {
    executes: std::sync::atomic::AtomicUsize,
}

#[cfg(target_os = "macos")]
struct CapabilityMacWriter {
    probe: Result<bool, MacProxyWriterError>,
    executes: std::sync::atomic::AtomicUsize,
}

#[cfg(target_os = "macos")]
impl MacProxyTransactionWriter for CapabilityMacWriter {
    fn compare_capable(&self) -> Result<bool, MacProxyWriterError> {
        self.probe.clone()
    }

    fn execute(&self, _payload_hex: &str) -> Result<(), MacProxyWriterError> {
        self.executes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl MacProxyTransactionWriter for ProbeThenUnavailableMacWriter {
    fn compare_capable(&self) -> Result<bool, MacProxyWriterError> {
        Ok(true)
    }

    fn execute(&self, _payload_hex: &str) -> Result<(), MacProxyWriterError> {
        self.executes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Err(MacProxyWriterError::Unavailable(
            "helper disappeared after capability probe".into(),
        ))
    }
}

#[cfg(target_os = "macos")]
#[test]
fn production_macos_old_helper_probe_selects_legacy_without_writes() {
    let writer = Arc::new(CapabilityMacWriter {
        probe: Ok(false),
        executes: std::sync::atomic::AtomicUsize::new(0),
    });
    let ops = SystemProxyOpsImpl::new(MockRunner::default()).with_macos_writer(writer.clone());

    assert!(!ops.exact_transaction_available().unwrap());
    assert_eq!(
        writer.executes.load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    assert!(ops.runner.snapshot().is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn production_macos_installed_helper_connect_unavailable_selects_legacy_without_writes() {
    let writer = Arc::new(CapabilityMacWriter {
        probe: Err(MacProxyWriterError::Unavailable(
            "installed helper socket refused connection".into(),
        )),
        executes: std::sync::atomic::AtomicUsize::new(0),
    });
    let ops = SystemProxyOpsImpl::new(MockRunner::default()).with_macos_writer(writer.clone());

    assert!(!ops.exact_transaction_available().unwrap());
    assert_eq!(
        writer.executes.load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    assert!(ops.runner.snapshot().is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn production_macos_existing_v2_connect_unavailable_preserves_marker_without_cli_write() {
    let writer = Arc::new(CapabilityMacWriter {
        probe: Err(MacProxyWriterError::Unavailable(
            "installed helper socket refused connection".into(),
        )),
        executes: std::sync::atomic::AtomicUsize::new(0),
    });
    let build_ops =
        SystemProxyOpsImpl::new(MockRunner::default()).with_macos_writer(writer.clone());
    let original = mac_exact_snapshot();
    let applied = build_ops.build_applied_snapshot(&req(), &original).unwrap();
    let marker = mem_marker();
    seed_current_marker(
        &marker,
        &original,
        &original,
        &applied,
        ProxyMarkerPhase::Owned,
    );
    let before = marker.read_checked();
    let mut controller = SystemProxyController::new(build_ops, marker);

    assert!(controller.disable().is_err());
    assert_eq!(controller.marker.read_checked(), before);
    assert_eq!(
        writer.executes.load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    assert!(controller.ops.runner.snapshot().is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn production_macos_uncertain_probe_error_runs_zero_cli_commands() {
    let writer = Arc::new(CapabilityMacWriter {
        probe: Err(MacProxyWriterError::Failed("probe timed out".into())),
        executes: std::sync::atomic::AtomicUsize::new(0),
    });
    let ops = SystemProxyOpsImpl::new(MockRunner::default()).with_macos_writer(writer.clone());

    assert!(ops.exact_transaction_available().is_err());
    assert_eq!(
        writer.executes.load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    assert!(ops.runner.snapshot().is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn production_macos_exact_apply_unavailable_after_probe_runs_zero_cli_commands() {
    let writer = Arc::new(ProbeThenUnavailableMacWriter::default());
    let ops = SystemProxyOpsImpl::new(MockRunner::default()).with_macos_writer(writer.clone());
    let apply_base = mac_exact_snapshot();

    assert!(ops.exact_transaction_available().unwrap());
    let error = ops.apply_transaction(&req(), &apply_base).unwrap_err();

    assert!(error.to_string().contains("helper"));
    assert_eq!(
        writer.executes.load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert!(ops.runner.snapshot().is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn production_macos_exact_restore_unavailable_after_probe_runs_zero_cli_commands() {
    let writer = Arc::new(ProbeThenUnavailableMacWriter::default());
    let ops = SystemProxyOpsImpl::new(MockRunner::default()).with_macos_writer(writer.clone());
    let original = mac_exact_snapshot();
    let expected_current = ops.build_applied_snapshot(&req(), &original).unwrap();

    assert!(ops.exact_transaction_available().unwrap());
    let error = ops
        .restore_transaction(&original, &expected_current)
        .unwrap_err();

    assert!(error.to_string().contains("helper"));
    assert_eq!(
        writer.executes.load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert!(ops.runner.snapshot().is_empty());
}

struct ExactWindowsWriter {
    current: std::sync::Mutex<WindowsProxyRegistrySnapshot>,
    writes: std::sync::atomic::AtomicUsize,
    restores: std::sync::atomic::AtomicUsize,
    notifications: std::sync::atomic::AtomicUsize,
    fail_first_write_after_mutation: std::sync::atomic::AtomicBool,
    panic_first_write_after_mutation: std::sync::atomic::AtomicBool,
}

impl ExactWindowsWriter {
    fn new(current: WindowsProxyRegistrySnapshot) -> Self {
        Self {
            current: std::sync::Mutex::new(current),
            writes: std::sync::atomic::AtomicUsize::new(0),
            restores: std::sync::atomic::AtomicUsize::new(0),
            notifications: std::sync::atomic::AtomicUsize::new(0),
            fail_first_write_after_mutation: std::sync::atomic::AtomicBool::new(false),
            panic_first_write_after_mutation: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn with_partial_first_write(self) -> Self {
        self.fail_first_write_after_mutation
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self
    }

    fn with_crash_after_first_write(self) -> Self {
        self.panic_first_write_after_mutation
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self
    }
}

impl WindowsProxyRegistryWriter for ExactWindowsWriter {
    fn capture(&self) -> Result<WindowsProxyRegistrySnapshot, WindowsProxyWriterError> {
        Ok(self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone())
    }

    fn write(&self, values: &WindowsProxyRegistryValues) -> Result<(), WindowsProxyWriterError> {
        self.writes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let desired = WindowsProxyRegistrySnapshot {
            proxy_server: if values.proxy_server.is_empty() {
                WindowsRegistryStringValue::PresentEmpty
            } else {
                WindowsRegistryStringValue::PresentValue(values.proxy_server.clone())
            },
            proxy_override: if values.proxy_override.is_empty() {
                WindowsRegistryStringValue::PresentEmpty
            } else {
                WindowsRegistryStringValue::PresentValue(values.proxy_override.clone())
            },
            proxy_enable: WindowsRegistryDwordValue::PresentValue(values.proxy_enable),
        };
        let mut current = self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self
            .panic_first_write_after_mutation
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            current.proxy_server = desired.proxy_server;
            drop(current);
            panic!("simulated process crash after partial Windows exact write");
        }
        if self
            .fail_first_write_after_mutation
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            current.proxy_server = desired.proxy_server;
            return Err(WindowsProxyWriterError::other(
                "timeout after partial Windows exact write",
            ));
        }
        *current = desired;
        Ok(())
    }

    fn restore(
        &self,
        snapshot: &WindowsProxyRegistrySnapshot,
    ) -> Result<(), WindowsProxyWriterError> {
        self.restores
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        *self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = snapshot.clone();
        Ok(())
    }

    fn notify_settings_changed(&self) -> Result<(), WindowsProxyWriterError> {
        self.notifications
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

fn ops_for(platform: Platform, runner: MockRunner) -> SystemProxyOpsImpl<MockRunner> {
    SystemProxyOpsImpl::with_platform(runner, platform)
}

#[test]
fn production_linux_exact_apply_preflight_rejects_stale_base_without_writing() {
    let expected = exact_linux_snapshot("proxy.corp:3128");
    let actual = exact_linux_snapshot("changed.externally:9000")
        .linux_gsettings
        .unwrap();
    let ops = SystemProxyOpsImpl::with_platform(StatefulLinuxRunner::new(actual), Platform::Linux)
        .with_noop_sleeper();

    let error = ops.apply_transaction(&req(), &expected).unwrap_err();

    assert!(error.to_string().contains("ownership lost"));
    assert_eq!(ops.runner.set_calls.get(), 0);
}

#[test]
fn production_linux_exact_apply_rechecks_after_partial_retry_and_stops() {
    let expected = exact_linux_snapshot("proxy.corp:3128");
    let actual = expected.linux_gsettings.clone().unwrap();
    let runner = StatefulLinuxRunner::new(actual).with_partial_first_write();
    let ops = SystemProxyOpsImpl::with_platform(runner, Platform::Linux).with_noop_sleeper();

    let error = ops.apply_transaction(&req(), &expected).unwrap_err();

    assert!(error.to_string().contains("ownership lost"));
    assert_eq!(ops.runner.set_calls.get(), 1, "Prefix 后不得盲重试写入");
    assert_eq!(
        ops.runner.get_calls.get(),
        LINUX_GSETTINGS_KEYS.len() * 2,
        "首次 attempt 与 retry 都必须重捕获"
    );
}

#[test]
fn production_linux_exact_apply_and_restore_write_only_on_exact_preflight() {
    let original = exact_linux_snapshot("proxy.corp:3128");
    let original_linux = original.linux_gsettings.clone().unwrap();
    let apply_ops = SystemProxyOpsImpl::with_platform(
        StatefulLinuxRunner::new(original_linux.clone()),
        Platform::Linux,
    )
    .with_noop_sleeper();
    apply_ops.apply_transaction(&req(), &original).unwrap();
    assert_eq!(apply_ops.runner.set_calls.get(), LINUX_GSETTINGS_KEYS.len());

    let expected_current = linux_transaction_snapshot(linux_applied_snapshot(&req()).unwrap());
    let foreign = exact_linux_snapshot("changed.externally:9000")
        .linux_gsettings
        .unwrap();
    let rejected_restore =
        SystemProxyOpsImpl::with_platform(StatefulLinuxRunner::new(foreign), Platform::Linux);
    let error = rejected_restore
        .restore_transaction(&original, &expected_current)
        .unwrap_err();
    assert!(error.to_string().contains("ownership lost"));
    assert_eq!(rejected_restore.runner.set_calls.get(), 0);

    let restore_ops = SystemProxyOpsImpl::with_platform(
        StatefulLinuxRunner::new(expected_current.linux_gsettings.clone().unwrap()),
        Platform::Linux,
    );
    restore_ops
        .restore_transaction(&original, &expected_current)
        .unwrap();
    assert_eq!(
        restore_ops.runner.set_calls.get(),
        LINUX_GSETTINGS_KEYS.len()
    );
}

#[test]
fn production_linux_same_target_owned_restores_earliest_original_on_disable_and_recovery() {
    let original = exact_linux_snapshot("proxy.corp:3128");
    let applied = exact_linux_snapshot("127.0.0.1:8080");
    let original_linux = original.linux_gsettings.clone().unwrap();
    let applied_linux = applied.linux_gsettings.clone().unwrap();

    for recovery in [false, true] {
        let fs = crate::proxy::proxy_tests_helpers::MemFs::new();
        let marker = ProxyMarker::new(fs.clone(), "/marker.json");
        seed_current_marker(
            &marker,
            &original,
            &applied,
            &applied,
            ProxyMarkerPhase::Owned,
        );
        let runner = StatefulLinuxRunner::new(applied_linux.clone());
        let ops =
            SystemProxyOpsImpl::with_platform(runner.clone(), Platform::Linux).with_noop_sleeper();
        assert_eq!(
            ops.snapshot_relation(&applied, &applied, &applied),
            ProxySnapshotRelation::Exact,
            "from == to must prefer Exact"
        );
        let mut controller = SystemProxyController::new(ops, marker);

        if recovery {
            assert!(controller.recover_from_marker().unwrap().is_some());
        } else {
            controller.disable().unwrap();
        }

        assert_eq!(*runner.current.borrow(), original_linux);
        assert_eq!(
            ProxyMarker::new(fs, "/marker.json").read_checked(),
            ProxyMarkerRead::Missing
        );
    }
}

#[test]
fn controller_recovers_production_linux_partial_write_after_process_crash() {
    let original = exact_linux_snapshot("proxy.corp:3128");
    let original_linux = original.linux_gsettings.clone().unwrap();
    let runner = StatefulLinuxRunner::new(original_linux.clone()).with_crash_after_first_write();
    let fs = crate::proxy::proxy_tests_helpers::MemFs::new();
    let mut crashed_controller = SystemProxyController::new(
        SystemProxyOpsImpl::with_platform(runner.clone(), Platform::Linux).with_noop_sleeper(),
        ProxyMarker::new(fs.clone(), "/marker.json"),
    );

    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = crashed_controller.enable(&req());
    }));
    assert!(crashed.is_err());
    assert!(matches!(
        ProxyMarker::new(fs.clone(), "/marker.json").read_checked(),
        ProxyMarkerRead::CurrentValidated(ref marker)
            if marker.phase == ProxyMarkerPhase::Applying
    ));
    assert_ne!(*runner.current.borrow(), original_linux);

    let mut recovery = SystemProxyController::new(
        SystemProxyOpsImpl::with_platform(runner.clone(), Platform::Linux).with_noop_sleeper(),
        ProxyMarker::new(fs.clone(), "/marker.json"),
    );
    assert!(recovery.ensure_cleared());
    assert_eq!(*runner.current.borrow(), original_linux);
    assert_eq!(
        ProxyMarker::new(fs, "/marker.json").read_checked(),
        ProxyMarkerRead::Missing
    );
}

fn windows_original_snapshot() -> ProxyTransactionSnapshot {
    windows_exact_snapshot(
        WindowsRegistryStringValue::PresentValue("proxy.corp:3128".into()),
        WindowsRegistryStringValue::PresentValue("<local>".into()),
        WindowsRegistryDwordValue::PresentValue(1),
    )
}

fn windows_foreign_snapshot() -> ProxyTransactionSnapshot {
    windows_exact_snapshot(
        WindowsRegistryStringValue::PresentValue("changed.externally:9000".into()),
        WindowsRegistryStringValue::PresentEmpty,
        WindowsRegistryDwordValue::PresentValue(1),
    )
}

#[test]
fn production_windows_exact_apply_preflight_rejects_stale_base_without_writing() {
    let expected = windows_original_snapshot();
    let writer = Arc::new(ExactWindowsWriter::new(
        windows_foreign_snapshot().windows_registry.unwrap(),
    ));
    let ops = ops_for(Platform::Win, MockRunner::default())
        .with_noop_sleeper()
        .with_windows_registry_writer(writer.clone(), true);

    let error = ops.apply_transaction(&req(), &expected).unwrap_err();

    assert!(error.to_string().contains("ownership lost"));
    assert_eq!(writer.writes.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(
        writer
            .notifications
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[test]
fn production_windows_exact_apply_rechecks_after_partial_retry_and_stops() {
    let expected = windows_original_snapshot();
    let writer = Arc::new(
        ExactWindowsWriter::new(expected.windows_registry.clone().unwrap())
            .with_partial_first_write(),
    );
    let ops = ops_for(Platform::Win, MockRunner::default())
        .with_noop_sleeper()
        .with_windows_registry_writer(writer.clone(), true);

    let error = ops.apply_transaction(&req(), &expected).unwrap_err();

    assert!(error.to_string().contains("ownership lost"));
    assert_eq!(
        writer.writes.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "partial 后的 retry 必须先重比并停止"
    );
}

#[test]
fn production_windows_exact_apply_and_restore_write_only_on_exact_preflight() {
    let original = windows_original_snapshot();
    let writer = Arc::new(ExactWindowsWriter::new(
        original.windows_registry.clone().unwrap(),
    ));
    let apply_ops = ops_for(Platform::Win, MockRunner::default())
        .with_windows_registry_writer(writer.clone(), true);
    apply_ops.apply_transaction(&req(), &original).unwrap();
    assert_eq!(writer.writes.load(std::sync::atomic::Ordering::Relaxed), 1);

    let expected_current = apply_ops.build_applied_snapshot(&req(), &original).unwrap();
    *writer
        .current
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        windows_foreign_snapshot().windows_registry.unwrap();
    let error = apply_ops
        .restore_transaction(&original, &expected_current)
        .unwrap_err();
    assert!(error.to_string().contains("ownership lost"));
    assert_eq!(
        writer.restores.load(std::sync::atomic::Ordering::Relaxed),
        0
    );

    *writer
        .current
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        expected_current.windows_registry.clone().unwrap();
    apply_ops
        .restore_transaction(&original, &expected_current)
        .unwrap();
    assert_eq!(
        writer.restores.load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[test]
fn production_windows_same_target_owned_restores_earliest_original_on_disable_and_recovery() {
    let original = windows_original_snapshot();
    let applied = windows_exact_snapshot(
        WindowsRegistryStringValue::PresentValue("http=127.0.0.1:8080;https=127.0.0.1:8080".into()),
        WindowsRegistryStringValue::PresentValue("<local>".into()),
        WindowsRegistryDwordValue::PresentValue(1),
    );
    let original_windows = original.windows_registry.clone().unwrap();
    let applied_windows = applied.windows_registry.clone().unwrap();

    for recovery in [false, true] {
        let fs = crate::proxy::proxy_tests_helpers::MemFs::new();
        let marker = ProxyMarker::new(fs.clone(), "/marker.json");
        seed_current_marker(
            &marker,
            &original,
            &applied,
            &applied,
            ProxyMarkerPhase::Owned,
        );
        let writer = Arc::new(ExactWindowsWriter::new(applied_windows.clone()));
        let ops = ops_for(Platform::Win, MockRunner::default())
            .with_noop_sleeper()
            .with_windows_registry_writer(writer.clone(), true);
        assert_eq!(
            ops.snapshot_relation(&applied, &applied, &applied),
            ProxySnapshotRelation::Exact,
            "from == to must prefer Exact"
        );
        let mut controller = SystemProxyController::new(ops, marker);

        if recovery {
            assert!(controller.recover_from_marker().unwrap().is_some());
        } else {
            controller.disable().unwrap();
        }

        assert_eq!(
            *writer
                .current
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            original_windows
        );
        assert_eq!(
            writer.restores.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            ProxyMarker::new(fs, "/marker.json").read_checked(),
            ProxyMarkerRead::Missing
        );
    }
}

#[test]
fn controller_recovers_production_windows_partial_write_after_process_crash() {
    let original = windows_original_snapshot();
    let original_windows = original.windows_registry.clone().unwrap();
    let writer =
        Arc::new(ExactWindowsWriter::new(original_windows.clone()).with_crash_after_first_write());
    let fs = crate::proxy::proxy_tests_helpers::MemFs::new();
    let mut crashed_controller = SystemProxyController::new(
        ops_for(Platform::Win, MockRunner::default())
            .with_noop_sleeper()
            .with_windows_registry_writer(writer.clone(), true),
        ProxyMarker::new(fs.clone(), "/marker.json"),
    );

    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = crashed_controller.enable(&req());
    }));
    assert!(crashed.is_err());
    assert!(matches!(
        ProxyMarker::new(fs.clone(), "/marker.json").read_checked(),
        ProxyMarkerRead::CurrentValidated(ref marker)
            if marker.phase == ProxyMarkerPhase::Applying
    ));
    assert_ne!(
        *writer
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        original_windows
    );

    let mut recovery = SystemProxyController::new(
        ops_for(Platform::Win, MockRunner::default())
            .with_noop_sleeper()
            .with_windows_registry_writer(writer.clone(), true),
        ProxyMarker::new(fs.clone(), "/marker.json"),
    );
    assert!(recovery.ensure_cleared());
    assert_eq!(
        *writer
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        original_windows
    );
    assert_eq!(
        ProxyMarker::new(fs, "/marker.json").read_checked(),
        ProxyMarkerRead::Missing
    );
}

// ── Windows 腿 ──

#[test]
fn windows_native_registry_access_gate_is_function_scoped_and_mutation_sensitive() {
    fn function_body<'a>(code: &'a str, signature: &str) -> Option<&'a str> {
        let mut matches = code.match_indices(signature);
        let (signature_start, _) = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        let search_start = signature_start + signature.len();
        let tail = &code[search_start..];
        let open_relative = tail.find('{')?;
        if tail[..open_relative].contains(';') {
            return None;
        }
        let open = search_start + open_relative;
        let mut depth = 0_usize;
        for (relative, byte) in code.as_bytes()[open..].iter().enumerate() {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return Some(&code[open + 1..open + relative]);
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn compact_expression(body: &str) -> String {
        body.chars().filter(|char| !char.is_whitespace()).collect()
    }

    fn access_gate(source: &str) -> bool {
        let code = crate::test_support::code_face(source);
        let Some(read_wrapper) = function_body(&code, "fn open_internet_settings_read()") else {
            return false;
        };
        let Some(write_wrapper) = function_body(&code, "fn open_internet_settings_write()") else {
            return false;
        };
        let Some(capture) = function_body(&code, "fn capture(&self)") else {
            return false;
        };
        let Some(write) = function_body(&code, "fn write(&self,") else {
            return false;
        };
        let Some(restore) = function_body(&code, "fn restore(") else {
            return false;
        };

        compact_expression(read_wrapper) == "open_internet_settings_with_access(KEY_QUERY_VALUE)"
            && compact_expression(write_wrapper)
                == "open_internet_settings_with_access(KEY_QUERY_VALUE|KEY_SET_VALUE)"
            && capture.matches("open_internet_settings_read()?").count() == 1
            && !capture.contains("open_internet_settings_write()?")
            && write.matches("open_internet_settings_write()?").count() == 1
            && !write.contains("open_internet_settings_read()?")
            && restore.matches("open_internet_settings_write()?").count() == 1
            && !restore.contains("open_internet_settings_read()?")
    }

    fn replace_occurrence(source: &str, from: &str, to: &str, occurrence: usize) -> String {
        let (index, _) = source
            .match_indices(from)
            .nth(occurrence)
            .expect("production source mutation anchor");
        format!(
            "{}{}{}",
            &source[..index],
            to,
            &source[index + from.len()..]
        )
    }

    let source =
        polaris_source_probe::repo_file!("src-tauri/src/runtime/windows_proxy_registry.rs");
    assert!(access_gate(&source));

    let read_escalated_with_dead_syntax = replace_occurrence(
        &source,
        "open_internet_settings_with_access(KEY_QUERY_VALUE)",
        r#"{
        let _dead_expected = "} open_internet_settings_with_access(KEY_QUERY_VALUE) {";
        // } open_internet_settings_with_access(KEY_QUERY_VALUE) {
        open_internet_settings_with_access(KEY_QUERY_VALUE | KEY_SET_VALUE)
    }"#,
        0,
    );
    let capture_wrong_with_dead_syntax = replace_occurrence(
        &source,
        "let key = open_internet_settings_read()?;",
        r#"let _dead_expected = "} open_internet_settings_read()? {";
        // } open_internet_settings_read()? {
        let key = open_internet_settings_write()?;"#,
        0,
    );
    let mutations = [
        read_escalated_with_dead_syntax,
        replace_occurrence(
            &source,
            "open_internet_settings_with_access(KEY_QUERY_VALUE | KEY_SET_VALUE)",
            "open_internet_settings_with_access(KEY_QUERY_VALUE)",
            0,
        ),
        replace_occurrence(
            &source,
            "open_internet_settings_read()?",
            "open_internet_settings_write()?",
            0,
        ),
        capture_wrong_with_dead_syntax,
        replace_occurrence(
            &source,
            "open_internet_settings_write()?",
            "open_internet_settings_read()?",
            0,
        ),
        replace_occurrence(
            &source,
            "open_internet_settings_write()?",
            "open_internet_settings_read()?",
            1,
        ),
    ];
    for mutation in mutations {
        assert!(
            !access_gate(&mutation),
            "function-scoped access gate accepted a permission/caller mutation"
        );
    }
}

#[test]
fn impl_win_get_status_disabled_short_circuits() {
    // ProxyEnable=0x0 → 早退，不再查 ProxyServer（上游 getProxyStatus 早退腿）。
    let ops = ops_for(
        Platform::Win,
        MockRunner::default().with_arg_stdout("ProxyEnable", "ProxyEnable REG_DWORD 0x0"),
    );
    let st = ops.get_proxy_status().unwrap();
    assert!(!st.enabled);
    assert!(
        !ops.runner.ran_arg("ProxyServer"),
        "disabled 时不该查 ProxyServer"
    );
}

#[test]
fn impl_win_get_status_parses_enabled_proxy() {
    let runner = MockRunner::default()
        .with_arg_stdout("ProxyEnable", "ProxyEnable REG_DWORD 0x1")
        .with_arg_stdout(
            "ProxyServer",
            "    ProxyServer    REG_SZ    http=127.0.0.1:8080;socks=127.0.0.1:1080",
        );
    let st = ops_for(Platform::Win, runner).get_proxy_status().unwrap();
    assert!(st.enabled);
    assert_eq!(st.http_proxy, Some("127.0.0.1:8080".into()));
    assert_eq!(st.socks_proxy, Some("127.0.0.1:1080".into()));
}

#[test]
fn impl_win_get_status_falls_back_to_disabled_on_command_failure() {
    // 上游 getProxyStatus 整体 try/catch → { enabled: false }。
    let runner = MockRunner {
        fail_args: vec!["ProxyEnable".into()],
        ..Default::default()
    };
    let st = ops_for(Platform::Win, runner).get_proxy_status().unwrap();
    assert!(!st.enabled);
}

#[test]
fn impl_win_set_proxy_runs_reg_add_sequence_via_runner() {
    let ops = ops_for(Platform::Win, MockRunner::default());
    ops.set_proxy(&req()).unwrap();
    // reg add ProxyServer / ProxyEnable / ProxyOverride + netsh QUIC 清理，全经 runner 下发。
    assert!(ops.runner.ran_arg("ProxyServer"));
    assert!(ops.runner.ran_arg("ProxyEnable"));
    assert!(ops.runner.ran_arg("ProxyOverride"));
    assert!(ops.runner.ran_arg("Polaris_Block_QUIC"));
    assert_eq!(
        ops.runner.timeout_for_arg("Polaris_Block_QUIC"),
        Some(WINDOWS_QUIC_CLEANUP_TIMEOUT),
        "可选 QUIC 清理必须使用独立短预算，不能再把启动主链钉住 10s"
    );
    assert_eq!(
        ops.runner.timeout_for_arg("ProxyServer"),
        Some(PROXY_EXEC_TIMEOUT),
        "必要注册表事务仍保留宽预算"
    );
    // 用 System32 绝对路径（PATH 缺 System32 的设备也能跑）。
    assert!(ops
        .runner
        .snapshot()
        .iter()
        .any(|c| c.program.ends_with("reg.exe")));
}

#[test]
fn impl_win_set_proxy_survives_quic_cleanup_failure() {
    // `netsh delete rule` 在规则本来就不存在时返回 exit=1；这已经是目标状态，不能让三条
    // 注册表写成功后的系统代理事务被反判失败。真实注册表写失败仍由 run_all/retry 返回 Err。
    let runner = MockRunner {
        fail_args: vec!["Polaris_Block_QUIC".into()],
        ..Default::default()
    };
    let ops = ops_for(Platform::Win, runner);
    ops.set_proxy(&req())
        .expect("可选 QUIC 清理失败不得阻断系统代理启用");
    assert!(ops.runner.ran_arg("Polaris_Block_QUIC"));
    assert!(ops.runner.ran_arg("ProxyServer"));
    assert!(ops.runner.ran_arg("ProxyEnable"));
    assert!(ops.runner.ran_arg("ProxyOverride"));
}

struct RecordingWindowsRegistryWriter {
    calls: std::sync::atomic::AtomicUsize,
    notifications: std::sync::atomic::AtomicUsize,
    fail: bool,
    notify_fail: bool,
}

impl WindowsProxyRegistryWriter for RecordingWindowsRegistryWriter {
    fn write(&self, values: &WindowsProxyRegistryValues) -> Result<(), WindowsProxyWriterError> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert!(values.proxy_server.contains("http=127.0.0.1:8080"));
        if self.fail {
            Err(WindowsProxyWriterError::other("native write failed"))
        } else {
            Ok(())
        }
    }

    fn notify_settings_changed(&self) -> Result<(), WindowsProxyWriterError> {
        self.notifications
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.notify_fail {
            Err(WindowsProxyWriterError::other("native notification failed"))
        } else {
            Ok(())
        }
    }
}

#[test]
fn impl_win_native_writer_and_quic_prewarm_remove_child_processes_from_enable() {
    let writer = Arc::new(RecordingWindowsRegistryWriter {
        calls: std::sync::atomic::AtomicUsize::new(0),
        notifications: std::sync::atomic::AtomicUsize::new(0),
        fail: false,
        notify_fail: false,
    });
    let ops = ops_for(Platform::Win, MockRunner::default())
        .with_windows_registry_writer(writer.clone(), true);
    ops.set_proxy(&req()).unwrap();
    assert_eq!(writer.calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(
        writer
            .notifications
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert!(!ops.runner.ran_arg("ProxyServer"));
    assert!(!ops.runner.ran_arg("Polaris_Block_QUIC"));
}

#[test]
fn impl_win_native_writer_failure_keeps_existing_retry_contract() {
    let writer = Arc::new(RecordingWindowsRegistryWriter {
        calls: std::sync::atomic::AtomicUsize::new(0),
        notifications: std::sync::atomic::AtomicUsize::new(0),
        fail: true,
        notify_fail: false,
    });
    let ops = ops_for(Platform::Win, MockRunner::default())
        .with_noop_sleeper()
        .with_windows_registry_writer(writer.clone(), true);
    assert!(ops.set_proxy(&req()).is_err());
    assert_eq!(
        writer.calls.load(std::sync::atomic::Ordering::Relaxed),
        3,
        "原生写失败仍是首次 + 两次 retry"
    );
    assert!(!ops.runner.ran_arg("Polaris_Block_QUIC"));
    assert_eq!(
        writer
            .notifications
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "注册表写失败不得发布虚假的设置变更通知"
    );
}

struct AccessDeniedWindowsRegistryWriter {
    calls: std::sync::atomic::AtomicUsize,
}

impl WindowsProxyRegistryWriter for AccessDeniedWindowsRegistryWriter {
    fn write(&self, _values: &WindowsProxyRegistryValues) -> Result<(), WindowsProxyWriterError> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Err(WindowsProxyWriterError::win32(
            "RegOpenKeyExW",
            WindowsProxyWriterError::ACCESS_DENIED_CODE,
            "message intentionally contains no permission words",
        ))
    }
}

#[test]
fn impl_win_native_access_denied_code_aborts_without_retry() {
    let writer = Arc::new(AccessDeniedWindowsRegistryWriter {
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let ops = ops_for(Platform::Win, MockRunner::default())
        .with_noop_sleeper()
        .with_windows_registry_writer(writer.clone(), true);
    let error = ops.set_proxy(&req()).unwrap_err();
    assert!(matches!(
        error,
        SystemIntegrationError::WindowsProxyWriter(ref writer_error)
            if writer_error.is_access_denied()
    ));
    assert_eq!(
        writer.calls.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "Win32 access-denied code 必须立即放弃，不依赖错误文案"
    );
}

#[test]
fn impl_win_native_writer_notifies_after_clear_and_restore() {
    let writer = Arc::new(RecordingWindowsRegistryWriter {
        calls: std::sync::atomic::AtomicUsize::new(0),
        notifications: std::sync::atomic::AtomicUsize::new(0),
        fail: false,
        notify_fail: false,
    });
    let ops = ops_for(Platform::Win, MockRunner::default())
        .with_windows_registry_writer(writer.clone(), true);
    ops.clear_proxy().unwrap();
    ops.restore_proxy(&SystemProxyStatus {
        enabled: true,
        http_proxy: Some("http://127.0.0.1:8080".into()),
        https_proxy: Some("http://127.0.0.1:8080".into()),
        socks_proxy: None,
        bypass_domains: None,
    })
    .unwrap();
    assert_eq!(writer.calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(
        writer
            .notifications
            .load(std::sync::atomic::Ordering::Relaxed),
        2,
        "禁用和原值恢复都必须通知 Windows 消费方刷新"
    );
}

#[test]
fn impl_win_notification_failure_retries_the_whole_enable_transaction() {
    let writer = Arc::new(RecordingWindowsRegistryWriter {
        calls: std::sync::atomic::AtomicUsize::new(0),
        notifications: std::sync::atomic::AtomicUsize::new(0),
        fail: false,
        notify_fail: true,
    });
    let ops = ops_for(Platform::Win, MockRunner::default())
        .with_noop_sleeper()
        .with_windows_registry_writer(writer.clone(), true);
    assert!(ops.set_proxy(&req()).is_err());
    assert_eq!(writer.calls.load(std::sync::atomic::Ordering::Relaxed), 3);
    assert_eq!(
        writer
            .notifications
            .load(std::sync::atomic::Ordering::Relaxed),
        3
    );
}

#[test]
fn impl_win_set_proxy_still_fails_on_required_registry_write_failure() {
    // best-effort 只放宽 QUIC 清理；任何必要注册表写失败仍须让整个 attempt 失败并走既有重试。
    let runner = MockRunner {
        fail_args: vec!["ProxyOverride".into()],
        ..Default::default()
    };
    let ops = ops_for(Platform::Win, runner).with_noop_sleeper();
    assert!(
        ops.set_proxy(&req()).is_err(),
        "必要注册表写失败必须继续向上报错"
    );
    assert_eq!(
        ops.runner.count_arg("ProxyOverride"),
        3,
        "首次 + 两次 retry 都应在必要写失败处中止"
    );
    assert!(
        !ops.runner.ran_arg("ProxyEnable"),
        "ProxyEnable 生效门在前置必要写失败后不得继续"
    );
    assert!(
        !ops.runner.ran_arg("Polaris_Block_QUIC"),
        "必要事务未完成时不得提前做可选清理"
    );
}

#[test]
fn impl_win_clear_proxy_survives_quic_cleanup_failure() {
    // QUIC 规则清理失败**不得**阻断禁用 —— 关代理是断网防线。
    let runner = MockRunner {
        fail_args: vec!["Polaris_Block_QUIC".into()],
        ..Default::default()
    };
    let ops = ops_for(Platform::Win, runner);
    ops.clear_proxy()
        .expect("QUIC 清理失败不该阻断 ProxyEnable=0");
    assert!(ops.runner.ran_arg("ProxyEnable"));
}

// ── macOS 腿 ──

const MAC_SERVICES: &str =
    "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\nEthernet\n";

/// 与 [`MAC_SERVICES`] 等价的 `-listnetworkserviceorder` 形态（两个服务各带 BSD 设备名）。
/// mac 枚举口径 2026-08-08 起以本命令为主、`-listallnetworkservices` 仅作回落，
/// 故这些测试要喂它才不会走进回落腿（走了就多一次 exec，掩盖「只读首个服务」这类计数断言）。
const MAC_SERVICE_ORDER: &str = "An asterisk (*) denotes that a network service is disabled.\n\
(1) Wi-Fi\n\
(Hardware Port: Wi-Fi, Device: en0)\n\
\n\
(2) Ethernet\n\
(Hardware Port: Ethernet, Device: en4)\n";

#[test]
fn impl_mac_get_status_scans_all_services_not_just_first() {
    // 代理设在**第二个**服务（Ethernet）上 —— 只看 services[0] 会漏检（上游修过的 macOS 误判）。
    let runner = MockRunner::default().with_arg_stdout("-listallnetworkservices", MAC_SERVICES);
    // Wi-Fi 三协议均返回空（Enabled: No）；Ethernet 的 -getwebproxy 返回启用。
    runner.by_arg.borrow_mut().insert(
        "Ethernet".to_string(),
        "Enabled: Yes\nServer: 10.0.0.1\nPort: 3128\n".to_string(),
    );
    let ops = ops_for(Platform::Mac, runner);
    let st = ops.get_proxy_status().unwrap();
    assert!(st.enabled, "非首服务上的代理必须被检出");
    assert_eq!(st.http_proxy, Some("10.0.0.1:3128".into()));
}

#[test]
fn impl_mac_capture_original_reads_only_first_service() {
    // R0.5：原始快照只读 services[0]（回写目标），不扫全部 —— 7 服务时省 18 次 networksetup exec。
    // 与上一个测试成对：`get_proxy_status` 仍扫全部（残留检测），两条口径互不塌陷。
    let runner = MockRunner::default()
        .with_arg_stdout("-listnetworkserviceorder", MAC_SERVICE_ORDER)
        .with_arg_stdout("-listallnetworkservices", MAC_SERVICES);
    let ops = ops_for(Platform::Mac, runner);
    ops.capture_original_status().unwrap();

    // 三协议 + bypass 各读一次，且**只**读首个服务。
    assert_eq!(ops.runner.count_arg_exact("-getwebproxy"), 1);
    assert_eq!(ops.runner.count_arg_exact("-getsecurewebproxy"), 1);
    assert_eq!(ops.runner.count_arg_exact("-getsocksfirewallproxy"), 1);
    // bypass 清单：enable 会整表覆盖它 ⇒ 不捕获就还不回去（2026-08-09 补）。
    assert_eq!(ops.runner.count_arg_exact("-getproxybypassdomains"), 1);
    assert!(ops.runner.ran_arg("Wi-Fi"));
    assert_eq!(
        ops.runner.count_arg("Ethernet"),
        0,
        "非首服务不得被读 —— 扫全部正是本条要砍掉的启动开销"
    );
    // 总 exec = 1 次服务枚举 + 3 次协议读 + 1 次 bypass 读（扫全部会是 1 + 8）。
    // 这个数是**成本棘轮**：每加一次读都要在这里显式认账，别让捕获阶段悄悄变胖
    // —— mac 起核耗时里 networksetup 串行调用本就是大头。
    assert_eq!(ops.runner.snapshot().len(), 5);
    // 顺带钉死：枚举走的是带设备名那条，没落进 `-listallnetworkservices` 回落腿
    // （落进去就是 5 次 exec，且会把无底层设备的虚拟服务一并纳入）。
    assert!(!ops.runner.ran_arg("-listallnetworkservices"));
}

/// **读失败必须落 `None`，不得折成空清单** —— 折成空 = restore 时写 `Empty` = 把用户清单清掉。
///
/// 这条是「两者必须可分辨」那句文档的**可执行版本**。第一版门只测了纯函数
/// `mac_service_restore_commands`，于是「把 `.ok()` 补个 `.or(Some(vec![]))`」这个变异逃逸了
/// —— 判据落在被调函数上、没落在捕获腿上。
#[test]
fn mac_bypass_read_failure_is_not_an_empty_list() {
    let runner = MockRunner {
        // 只让 bypass 那条读失败，三协议照常成功 —— 单独钉住这一格。
        fail_args: vec!["-getproxybypassdomains".into()],
        ..Default::default()
    }
    .with_arg_stdout("-listnetworkserviceorder", MAC_SERVICE_ORDER)
    .with_arg_stdout("-getwebproxy", "Enabled: Yes\nServer: h\nPort: 80\n");
    let ops = ops_for(Platform::Mac, runner);
    let st = ops.capture_original_status().unwrap();

    assert!(
        st.bypass_domains.is_none(),
        "bypass 读失败被折成了 {:?} —— restore 会据此写 Empty，把用户自定义的清单清掉",
        st.bypass_domains
    );
    // 自检：这次确实尝试读过（否则「是 None」只说明压根没读）。
    assert!(
        ops.runner.ran_arg("-getproxybypassdomains"),
        "根本没读 bypass —— 上一条断言恒真"
    );
    // 正向对照：同一次捕获里三协议是读成功的，证明失败注入只打中了 bypass 这一条。
    assert_eq!(st.http_proxy.as_deref(), Some("h:80"));
}

#[test]
fn impl_mac_restore_does_not_leak_proxy_onto_untouched_services() {
    // **核心缺陷断言**：original 是 services[0] 的快照，绝不能铺到本来没设代理的其余服务上。
    // 退回「逐服务全铺」→ Ethernet 会被写上 proxy.lan 并 state on（污染用户网络配置）→ 本测试转红。
    let runner = MockRunner::default().with_arg_stdout("-listallnetworkservices", MAC_SERVICES);
    let ops = ops_for(Platform::Mac, runner);
    let original = SystemProxyStatus {
        enabled: true,
        http_proxy: Some("proxy.lan:3128".into()),
        ..Default::default()
    };
    ops.restore_proxy(&original).unwrap();
    let cmds = ops.runner.snapshot();

    // 1) 回写只发生一次，且落在捕获源 Wi-Fi 上。
    assert_eq!(
        ops.runner.count_arg_exact("-setwebproxy"),
        1,
        "回写必须只落在捕获源（services[0]），不得逐服务全铺"
    );
    assert!(cmds
        .iter()
        .any(|c| c.args.iter().any(|a| a == "-setwebproxy")
            && c.args.iter().any(|a| a == "Wi-Fi")
            && c.args.iter().any(|a| a == "proxy.lan")));

    // 2) 任何提到非首服务的命令都不得携带原始代理的 host —— 这是「误铺」的直接指纹。
    assert!(
        !cmds.iter().any(|c| c.args.iter().any(|a| a == "Ethernet")
            && c.args.iter().any(|a| a.contains("proxy.lan"))),
        "本来没设代理的服务被写入了原始代理值 = 污染用户网络配置"
    );

    // 3) 但非首服务仍须被**关**掉（enable 在全部服务上留了痕，disable 必须全部撤干净）。
    assert!(cmds
        .iter()
        .any(|c| c.args.iter().any(|a| a == "-setwebproxystate")
            && c.args.iter().any(|a| a == "Ethernet")
            && c.args.iter().any(|a| a == "off")));
    assert!(cmds.iter().any(
        |c| c.args.iter().any(|a| a == "-setsocksfirewallproxystate")
            && c.args.iter().any(|a| a == "Ethernet")
            && c.args.iter().any(|a| a == "off")
    ));
}

/// helper 在捕获完整快照后消失时，回退恢复必须只向 `networksetup` 自己列出的服务写入，
/// 并按服务名恢复各自原值；SystemConfiguration 多出来的历史/本地化服务名不得进入 argv。
#[test]
fn impl_mac_full_snapshot_fallback_restores_only_manageable_services() {
    let runner =
        MockRunner::default().with_arg_stdout("-listnetworkserviceorder", MAC_SERVICE_ORDER);
    let ops = ops_for(Platform::Mac, runner);
    let original = ProxyOriginalSettings {
        fallback: None,
        mac_services: vec![
            crate::proxy::MacProxyServiceSnapshot {
                service_id: "native-history-id".into(),
                service_name: "以太网转换器(en6)".into(),
                service_enabled: true,
                had_proxy_protocol: true,
                protocol_enabled: true,
                configuration_plist: Some(r#"<plist version="1.0"><dict/></plist>"#.into()),
                status: SystemProxyStatus {
                    enabled: true,
                    http_proxy: Some("must-not-run.invalid:1".into()),
                    ..Default::default()
                },
                touched: Some(crate::proxy::MacProxyTouchedSnapshot {
                    protocol_present: true,
                    protocol_enabled: true,
                    ..Default::default()
                }),
                ..Default::default()
            },
            crate::proxy::MacProxyServiceSnapshot {
                service_id: "wifi-id".into(),
                service_name: "Wi-Fi".into(),
                service_enabled: true,
                had_proxy_protocol: true,
                protocol_enabled: true,
                configuration_plist: Some(r#"<plist version="1.0"><dict/></plist>"#.into()),
                status: SystemProxyStatus {
                    enabled: true,
                    http_proxy: Some("proxy.corp:3128".into()),
                    bypass_domains: Some(vec!["intranet.corp".into()]),
                    ..Default::default()
                },
                touched: Some(crate::proxy::MacProxyTouchedSnapshot {
                    protocol_present: true,
                    protocol_enabled: true,
                    ..Default::default()
                }),
                ..Default::default()
            },
        ],
        linux_gsettings: None,
        windows_registry: None,
    };

    ops.restore_original_settings(&original).unwrap();
    let commands = ops.runner.snapshot();
    assert!(ops.runner.ran_arg("-listnetworkserviceorder"));
    assert!(commands.iter().any(|command| {
        command.args.iter().any(|arg| arg == "Wi-Fi")
            && command.args.iter().any(|arg| arg == "proxy.corp")
    }));
    assert!(commands.iter().any(|command| {
        command.args.iter().any(|arg| arg == "Ethernet")
            && command.args.iter().any(|arg| arg == "-setwebproxystate")
            && command.args.last().is_some_and(|arg| arg == "off")
    }));
    assert!(
        !commands.iter().any(|command| command
            .args
            .iter()
            .any(|arg| arg == "以太网转换器(en6)" || arg == "must-not-run.invalid")),
        "原生枚举里的历史/本地化服务不得传给 networksetup"
    );
}

#[test]
fn impl_mac_capture_original_with_no_services_is_empty_snapshot() {
    // 无网络服务（无网卡）→ 无可捕获也无可回写 → 空快照（disable 退化为 clear，不 panic/不越界）。
    let runner = MockRunner::default()
        .with_arg_stdout("-listallnetworkservices", "An asterisk (*) denotes...\n");
    let ops = ops_for(Platform::Mac, runner);
    let st = ops.capture_original_status().unwrap();
    assert!(!st.enabled);
    assert!(!st.has_any_proxy());
}

#[test]
fn impl_mac_set_proxy_applies_to_every_service() {
    let runner = MockRunner::default().with_arg_stdout("-listallnetworkservices", MAC_SERVICES);
    let ops = ops_for(Platform::Mac, runner);
    ops.set_proxy(&req()).unwrap();
    // 两个服务各一套 set（Wi-Fi + Ethernet）。精确匹配 —— `-setwebproxystate` 含 `-setwebproxy`。
    assert_eq!(ops.runner.count_arg_exact("-setwebproxy"), 2);
    assert!(ops.runner.ran_arg("Wi-Fi"));
    assert!(ops.runner.ran_arg("Ethernet"));
    assert!(ops.runner.ran_arg("-setproxybypassdomains"));
}

#[test]
fn impl_mac_list_services_filters_disabled_and_bluetooth() {
    let runner = MockRunner::default().with_arg_stdout(
        "-listallnetworkservices",
        "An asterisk (*) denotes...\nWi-Fi\n*Thunderbolt Bridge\nBluetooth PAN\nEthernet\n",
    );
    let svcs = ops_for(Platform::Mac, runner)
        .list_network_services()
        .unwrap();
    assert_eq!(svcs, vec!["Wi-Fi".to_string(), "Ethernet".to_string()]);
}

// ── Linux 腿 ──

#[test]
fn impl_linux_get_status_reads_canonical_int_port() {
    // 读取序：mode → http host/port → https host（空）→ socks host（空）。
    let runner = MockRunner {
        stdouts: RefCell::new(vec![
            "'manual'\n".into(),
            "'127.0.0.1'\n".into(), // http host
            "8080\n".into(),        // http port（GNOME schema canonical `i`）
            "''\n".into(),          // https host（未设）
            "''\n".into(),          // socks host（未设）
        ]),
        ..Default::default()
    };
    let ops = ops_for(Platform::Linux, runner);
    let st = ops.get_proxy_status().unwrap();
    assert!(st.enabled);
    assert_eq!(st.http_proxy, Some("127.0.0.1:8080".into()));
    assert_eq!(st.https_proxy, None, "host 空 → 不得扇出 http 的值");
    assert_eq!(st.socks_proxy, None);
    assert!(
        !ops.runner
            .snapshot()
            .iter()
            .any(|command| command.args[2] == "enabled"),
        "GNOME 不消费 http.enabled；status 不得查询或闸门"
    );
}

#[test]
fn impl_linux_get_status_all_hosts_empty_is_disabled() {
    // 三 schema host 全空 = 用户清了 → 不误报 enabled（否则 advisory 弹 ":port"）。
    let runner = MockRunner {
        stdouts: RefCell::new(vec![
            "'manual'\n".into(),
            "''\n".into(),
            "''\n".into(),
            "''\n".into(),
        ]),
        ..Default::default()
    };
    let st = ops_for(Platform::Linux, runner).get_proxy_status().unwrap();
    assert!(!st.enabled);
    assert!(!st.has_any_proxy());
}

#[test]
fn impl_linux_status_filters_inactive_values_but_capture_preserves_dormant_projection() {
    for mode in ["none", "auto"] {
        let runner = MockRunner {
            stdouts: RefCell::new(vec![format!("'{mode}'\n")]),
            ..Default::default()
        };
        let ops = ops_for(Platform::Linux, runner);
        assert!(!ops.get_proxy_status().unwrap().enabled);
        assert_eq!(ops.runner.snapshot().len(), 1, "非 manual 必须早退");
    }

    let zero_port = MockRunner {
        stdouts: RefCell::new(vec![
            "'manual'\n".into(),
            "'dormant.example'\n".into(),
            "0\n".into(),
            "''\n".into(),
            "''\n".into(),
        ]),
        ..Default::default()
    };
    assert!(
        !ops_for(Platform::Linux, zero_port)
            .get_proxy_status()
            .unwrap()
            .enabled
    );

    let runner = MockRunner {
        stdouts: RefCell::new(vec![
            "''\n".into(),
            "'secure.dormant'\n".into(),
            "4443\n".into(),
            "'socks.dormant'\n".into(),
            "1080\n".into(),
        ]),
        ..Default::default()
    };
    let ops = ops_for(Platform::Linux, runner);
    let captured = ops.capture_original_status().unwrap();
    assert!(captured.enabled, "capture 必须保留 dormant 协议投影");
    assert_eq!(captured.https_proxy.as_deref(), Some("secure.dormant:4443"));
    assert_eq!(captured.socks_proxy.as_deref(), Some("socks.dormant:1080"));
    let calls = ops.runner.snapshot();
    assert!(!calls.iter().any(|command| command.args[2] == "mode"));
    assert!(!calls.iter().any(|command| command.args[2] == "enabled"));

    let failing = MockRunner {
        fail_args: vec!["host".into()],
        ..Default::default()
    };
    assert!(ops_for(Platform::Linux, failing)
        .capture_original_status()
        .is_err());
}

#[test]
fn impl_linux_get_status_propagates_query_failure() {
    for failure in ["mode", "host", "port"] {
        let runner = MockRunner {
            stdouts: RefCell::new(vec!["'manual'\n".into(), "'127.0.0.1'\n".into()]),
            fail_args: vec![failure.into()],
            ..Default::default()
        };
        assert!(ops_for(Platform::Linux, runner).get_proxy_status().is_err());
    }
}

#[test]
fn impl_linux_set_and_clear_via_gsettings() {
    let ops = ops_for(Platform::Linux, MockRunner::default());
    ops.set_proxy(&req()).unwrap();
    assert!(ops.runner.ran_arg("org.gnome.system.proxy.http"));
    assert!(ops.runner.ran_arg("ignore-hosts"));

    let ops2 = ops_for(Platform::Linux, MockRunner::default());
    ops2.clear_proxy().unwrap();
    assert!(ops2.runner.ran_arg("none"), "clear → mode none");
}

#[test]
fn impl_linux_restore_uses_capture_three_symmetric_undo() {
    let original = SystemProxyStatus {
        enabled: true,
        http_proxy: Some("proxy.lan:3128".into()),
        ..Default::default()
    };
    let ops = ops_for(Platform::Linux, MockRunner::default());
    ops.restore_proxy(&original).unwrap();
    // mode manual + http 回写 + https/socks 清空（对称撤销）。
    assert!(ops.runner.ran_arg("manual"));
    assert!(ops.runner.ran_arg("proxy.lan"));
    let cmds = ops.runner.snapshot();
    assert!(
        !cmds.iter().any(|command| command.args[2] == "ignore-hosts"),
        "legacy projection restore 不得伪装成九键 exact restore"
    );
    // https host 被置空串。
    assert!(cmds.iter().any(|c| c.args.len() >= 4
        && c.args[1] == "org.gnome.system.proxy.https"
        && c.args[2] == "host"
        && c.args[3].is_empty()));
}

// ── 跨平台：restore 无原始 → 退化为 clear ──

#[test]
fn impl_restore_with_empty_original_degrades_to_clear() {
    for platform in [Platform::Win, Platform::Mac, Platform::Linux] {
        let runner = MockRunner::default().with_arg_stdout("-listallnetworkservices", MAC_SERVICES);
        let ops = ops_for(platform, runner);
        // enabled=false 的原始 → 等价「关」，绝不回写空代理串。
        ops.restore_proxy(&SystemProxyStatus::default()).unwrap();
        let cmds = ops.runner.snapshot();
        assert!(!cmds.is_empty(), "{platform:?} 应执行清除动作");
        // 不得出现「回写原始」的痕迹（win: ProxyEnable=1 / linux: mode manual）。
        assert!(
            !ops.runner.ran_arg("manual"),
            "{platform:?}: 无原始不该置 manual"
        );
    }
}

#[test]
fn impl_other_platform_is_unsupported_not_silent_noop() {
    let ops = ops_for(Platform::Other, MockRunner::default());
    // 未知平台须显式报错，不得静默假装成功（否则 UI 显示「已接管」而系统毫无变化）。
    assert!(matches!(
        ops.get_proxy_status(),
        Err(SystemIntegrationError::UnsupportedPlatform(_))
    ));
    assert!(ops.set_proxy(&req()).is_err());
    assert!(ops.clear_proxy().is_err());
    assert!(ops.runner.snapshot().is_empty(), "不该跑任何命令");
}

// ══════════ FX-proxy-ops-retry（row69）：重试原语 + 三平台 enable 重试 ══════════

// ── retry_op 纯函数：次数 / 指数退避 / shouldRetry 短路 / 上限 ──

#[test]
fn retry_op_retries_until_success_and_backs_off_exponentially() {
    let attempts = Cell::new(0u32);
    let slept: RefCell<Vec<Duration>> = RefCell::new(vec![]);
    let cfg = RetryConfig {
        max_retries: 2,
        delay: Duration::from_millis(500),
        exponential_backoff: true,
        should_retry: |_| true,
    };
    let out: Result<u32, SystemIntegrationError> = retry_op(
        &cfg,
        || {
            let n = attempts.get() + 1;
            attempts.set(n);
            if n < 3 {
                Err(SystemIntegrationError::proxy("transient"))
            } else {
                Ok(n)
            }
        },
        |d| slept.borrow_mut().push(d),
    );
    assert_eq!(out.unwrap(), 3, "第 3 次尝试成功");
    assert_eq!(attempts.get(), 3, "首次 + 2 次重试 = 3 次执行");
    // 指数退避：500ms, 1000ms（第 0/1 次重试前）。锁死 exponential_backoff=true。
    assert_eq!(
        *slept.borrow(),
        vec![Duration::from_millis(500), Duration::from_millis(1000)]
    );
}

#[test]
fn retry_op_gives_up_after_max_retries_plus_one_attempts() {
    let attempts = Cell::new(0u32);
    let cfg = RetryConfig {
        max_retries: 2,
        delay: Duration::from_millis(1),
        exponential_backoff: false,
        should_retry: |_| true,
    };
    let out: Result<(), SystemIntegrationError> = retry_op(
        &cfg,
        || {
            attempts.set(attempts.get() + 1);
            Err(SystemIntegrationError::proxy("always fails"))
        },
        |_| {},
    );
    assert!(out.is_err());
    assert_eq!(attempts.get(), 3, "总尝试 = max_retries + 1");
}

#[test]
fn retry_op_aborts_immediately_when_should_retry_false() {
    let attempts = Cell::new(0u32);
    let cfg = RetryConfig {
        max_retries: 3,
        delay: Duration::from_millis(1),
        exponential_backoff: false,
        should_retry: |_| false,
    };
    let out: Result<(), SystemIntegrationError> = retry_op(
        &cfg,
        || {
            attempts.set(attempts.get() + 1);
            Err(SystemIntegrationError::proxy("not retryable"))
        },
        |_| panic!("shouldRetry=false 不该 sleep"),
    );
    assert!(out.is_err());
    assert_eq!(attempts.get(), 1, "shouldRetry=false → 只跑首次，不重试");
}

#[test]
fn retry_op_fixed_backoff_when_exponential_disabled() {
    let slept: RefCell<Vec<Duration>> = RefCell::new(vec![]);
    let cfg = RetryConfig {
        max_retries: 2,
        delay: Duration::from_millis(500),
        exponential_backoff: false,
        should_retry: |_| true,
    };
    let _: Result<(), SystemIntegrationError> = retry_op(
        &cfg,
        || Err(SystemIntegrationError::proxy("always")),
        |d| slept.borrow_mut().push(d),
    );
    // 固定退避：两次都 500ms（与指数分支区分）。
    assert_eq!(
        *slept.borrow(),
        vec![Duration::from_millis(500), Duration::from_millis(500)]
    );
}

// ── shouldRetry 谓词（逐字对齐三平台）──

#[test]
fn win_should_retry_aborts_on_permission_and_command_not_found() {
    let ret = |m: &str| win_enable_should_retry(&SystemIntegrationError::proxy(m));
    assert!(
        !ret("reg.exe 退出码 1: Access Denied"),
        "access denied → 不重试"
    );
    assert!(
        !ret("ERROR: Access is denied."),
        "reg.exe 英文 Access is denied → 不重试"
    );
    assert!(
        !win_enable_should_retry(&SystemIntegrationError::from(
            WindowsProxyWriterError::win32("RegOpenKeyExW", 5, "localized text irrelevant")
        )),
        "原生 writer 必须按 Win32 code=5 结构化放弃重试"
    );
    assert!(
        win_enable_should_retry(&SystemIntegrationError::from(
            WindowsProxyWriterError::win32("RegSetValueExW", 32, "sharing violation")
        )),
        "非权限 Win32 失败保持既有可重试契约"
    );
    assert!(
        !ret("ProxyServer requires permission"),
        "permission → 不重试"
    );
    assert!(
        !ret("reg.exe 启动失败: No such file"),
        "命令未找到 → 不重试"
    );
    assert!(
        ret("reg.exe 退出码 1: being used by another process"),
        "瞬时占用 → 重试"
    );
}

#[test]
fn mac_should_retry_aborts_on_permission_or_not_authorized() {
    let ret = |m: &str| mac_enable_should_retry(&SystemIntegrationError::proxy(m));
    assert!(
        !ret("networksetup: permission denied"),
        "permission → 不重试"
    );
    assert!(
        !ret("Error: not authorized to change"),
        "not authorized → 不重试"
    );
    assert!(ret("networksetup connection timed out"), "瞬时 → 重试");
}

/// **变异锁（权限词表）**：把 [`PERMISSION_DENIED_NEEDLES`] 缩回上游那两词
/// （`permission` / `not authorized`）→ 本用例的 `requires admin privileges` 等断言立刻转红。
///
/// 守的是「必败错误被当成瞬时抖动」这一形态：mac enable 会多跑 2 次必败重试 + 1.5s 退避，
/// DNS set 更贵 —— 那 1.5s 是**持 `dns_controller` 锁**空耗的。
#[test]
fn permission_needles_cover_macos_admin_privileges_wording() {
    // 真机 macOS `networksetup` 的常见权限失败原文（Rust 侧把子进程 stderr 原文归入消息串）。
    for msg in [
        "networksetup: requires admin privileges to change proxy settings",
        "** Error: requires administrator privileges.",
        "setting DNS: Operation not permitted",
        "You must be root to run this command",
        "You must be running as root to modify network configuration",
        "networksetup: permission denied",
        "Error: not authorized to change",
    ] {
        assert!(
            !mac_enable_should_retry(&SystemIntegrationError::proxy(msg)),
            "权限类错误必须立即放弃（重试 100 次也不会变好）: {msg}"
        );
    }
    // 真瞬时错误不得被误判成权限（词表宁窄勿宽的另一半）。
    for msg in [
        "networksetup connection timed out",
        "reg.exe 退出码 1: being used by another process",
        "resource temporarily unavailable",
    ] {
        assert!(
            mac_enable_should_retry(&SystemIntegrationError::proxy(msg)),
            "瞬时错误必须仍可重试: {msg}"
        );
    }
}

#[test]
fn linux_default_should_retry_only_on_temporary_patterns() {
    let ret = |m: &str| default_should_retry(&SystemIntegrationError::proxy(m));
    assert!(
        ret("gsettings 超时: connection timed out"),
        "timed out → 重试"
    );
    assert!(ret("ETIMEDOUT while setting"), "ETIMEDOUT → 重试");
    assert!(!ret("gsettings: No such schema"), "非瞬时错误 → 不重试");
}

// ── set_proxy 整体重试（经 FlakyRunner 注入「前 N 次失败、其后成功」，Linux 上跑测三平台）──

/// 前 N 次「首命令」失败、其后全部成功的瞬时抖动 mock。
///
/// `run_all` 遇首个失败即中止 → 每个失败 attempt 恰好消耗 1 次命令调用 → `remaining` 每 attempt 减 1，
/// 故 `remaining=k` 精确模拟「前 k 次 attempt 失败」。`fail_msg` 决定 shouldRetry 走「重试」还是「放弃」。
struct FlakyRunner {
    calls: RefCell<Vec<Command>>,
    remaining_failures: RefCell<u32>,
    fail_msg: String,
    /// 成功路径的 argv 子串 → stdout（如 mac `-listallnetworkservices`）。
    by_arg: HashMap<String, String>,
}

impl FlakyRunner {
    fn new(fail_first: u32, fail_msg: &str) -> Self {
        Self {
            calls: RefCell::new(vec![]),
            remaining_failures: RefCell::new(fail_first),
            fail_msg: fail_msg.to_string(),
            by_arg: HashMap::new(),
        }
    }
    fn with_arg_stdout(mut self, arg_substr: &str, stdout: &str) -> Self {
        self.by_arg
            .insert(arg_substr.to_string(), stdout.to_string());
        self
    }
    fn count_arg(&self, substr: &str) -> usize {
        self.calls
            .borrow()
            .iter()
            .filter(|c| c.args.iter().any(|a| a.contains(substr)))
            .count()
    }
    fn ran_arg(&self, substr: &str) -> bool {
        self.calls
            .borrow()
            .iter()
            .any(|c| c.args.iter().any(|a| a.contains(substr)))
    }
}

impl CommandRunner for FlakyRunner {
    fn run(&self, cmd: &Command, _timeout: Duration) -> Result<crate::exec::CommandOutput, String> {
        self.calls.borrow_mut().push(cmd.clone());
        {
            let mut rem = self.remaining_failures.borrow_mut();
            if *rem > 0 {
                *rem -= 1;
                return Err(self.fail_msg.clone());
            }
        }
        for (k, v) in &self.by_arg {
            if cmd.args.iter().any(|a| a.contains(k)) {
                return Ok(crate::exec::CommandOutput {
                    stdout: v.clone(),
                    stderr: String::new(),
                });
            }
        }
        Ok(crate::exec::CommandOutput::default())
    }
}

#[test]
fn set_proxy_win_retries_transient_then_succeeds() {
    // 前 2 次瞬时失败（占用类），第 3 次成功 —— maxRetries=2 恰够。
    let runner = FlakyRunner::new(2, "reg.exe 退出码 1: being used by another process");
    let ops = SystemProxyOpsImpl::with_platform(runner, Platform::Win).with_noop_sleeper();
    ops.set_proxy(&req()).expect("2 次瞬时失败后应重试成功");
    // 首命令 ProxyServer 被尝试 3 次（首次 + 2 重试）；成功 attempt 跑完整序列。
    assert_eq!(ops.runner.count_arg("ProxyServer"), 3);
    assert!(ops.runner.ran_arg("ProxyEnable"));
    assert!(ops.runner.ran_arg("ProxyOverride"));
}

#[test]
fn set_proxy_win_exhausts_after_max_retries_plus_one() {
    // 永远失败 → 总尝试 = maxRetries(2) + 1 = 3，锁死 Windows maxRetries=2。
    let runner = FlakyRunner::new(99, "reg.exe 退出码 1: being used by another process");
    let ops = SystemProxyOpsImpl::with_platform(runner, Platform::Win).with_noop_sleeper();
    assert!(ops.set_proxy(&req()).is_err(), "耗尽重试仍失败");
    assert_eq!(
        ops.runner.count_arg("ProxyServer"),
        3,
        "maxRetries=2 → 3 次尝试"
    );
}

#[test]
fn set_proxy_win_access_denied_aborts_without_retry() {
    // 权限拒绝 → shouldRetry=false → 仅 1 次尝试，绝不重试。
    let runner = FlakyRunner::new(99, "reg.exe 退出码 1: Access Denied");
    let ops = SystemProxyOpsImpl::with_platform(runner, Platform::Win).with_noop_sleeper();
    assert!(ops.set_proxy(&req()).is_err());
    assert_eq!(
        ops.runner.count_arg("ProxyServer"),
        1,
        "access denied → 立即放弃，仅 1 次"
    );
}

#[test]
fn set_proxy_mac_retries_transient_then_succeeds() {
    // mac：首命令是 -listnetworkserviceorder（2026-08-08 起的枚举口径；在 retry 闭包内重取）。
    // 前 2 次失败、第 3 次成功。
    let runner = FlakyRunner::new(2, "networksetup: temporarily unavailable")
        .with_arg_stdout("-listnetworkserviceorder", MAC_SERVICE_ORDER)
        .with_arg_stdout("-listallnetworkservices", MAC_SERVICES);
    let ops = SystemProxyOpsImpl::with_platform(runner, Platform::Mac).with_noop_sleeper();
    ops.set_proxy(&req()).expect("mac 瞬时失败后应重试成功");
    assert_eq!(
        ops.runner.count_arg("-listnetworkserviceorder"),
        3,
        "首命令被尝试 3 次（maxRetries=2）"
    );
    assert!(
        ops.runner.ran_arg("-setwebproxy"),
        "成功 attempt 跑完设代理序列"
    );
}

#[test]
fn set_proxy_linux_retries_temporary_but_not_generic() {
    // Linux 用 defaultShouldRetry：仅瞬时网络类错误重试。九键事务首命令 = http.host，mode 最后。
    // (a) "timed out" 属瞬时 → maxRetries=1 → 首次失败后第 2 次成功。
    let r1 = FlakyRunner::new(1, "gsettings 超时: connection timed out");
    let ops1 = SystemProxyOpsImpl::with_platform(r1, Platform::Linux).with_noop_sleeper();
    ops1.set_proxy(&req()).expect("timed out 属瞬时 → 重试成功");
    assert_eq!(ops1.runner.calls.borrow().len(), 1 + 9);
    assert_eq!(
        ops1.runner.count_arg("manual"),
        1,
        "仅成功 attempt 到达末尾 mode"
    );

    // (b) 非瞬时错误 → defaultShouldRetry=false → 不重试（即便 maxRetries=1），仅 1 次。
    let r2 = FlakyRunner::new(1, "gsettings: No such schema org.gnome.system.proxy");
    let ops2 = SystemProxyOpsImpl::with_platform(r2, Platform::Linux).with_noop_sleeper();
    assert!(ops2.set_proxy(&req()).is_err(), "非瞬时错误不重试 → 失败");
    assert_eq!(ops2.runner.calls.borrow().len(), 1);
    assert_eq!(
        ops2.runner.count_arg("manual"),
        0,
        "失败在首键，不得提前写 mode"
    );
}

// ══════════ 维度7 #8：ensure_cleared 终态收口 ══════════

#[test]
fn ensure_cleared_noop_without_marker() {
    // **fresh start 路径**：无 marker → 零副作用（故可在每个 start 失败腿无脑调）。
    let ops = MockOps::default();
    let mut c = SystemProxyController::new(ops, mem_marker());
    assert!(!c.ensure_cleared());
    assert!(c.ops.calls.borrow().is_empty(), "无 marker 不得读状态/动手");
}

#[test]
fn ensure_cleared_disables_when_still_pointing_at_our_dead_port() {
    // 核心不变式：旧会话系统代理仍指向现已死的端口 → 必须清，否则全网断。
    let ops = MockOps {
        status: RefCell::new(SystemProxyStatus {
            enabled: true,
            http_proxy: Some("127.0.0.1:8080".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut c = SystemProxyController::new(ops, mem_marker());
    write_legacy_marker(&c.marker, "127.0.0.1:8080", None);

    assert!(c.ensure_cleared(), "指向我们 → 应执行 disable");
    assert!(c.ops.calls.borrow().contains(&"clear"));
    assert!(!c.has_marker(), "清完须删 marker");
}

#[test]
fn ensure_cleared_restores_original_from_marker_across_sessions() {
    // 崩溃跨会话：marker 里带着 enable 前的用户原始代理 → 恢复它而非简单关。
    let ops = MockOps {
        status: RefCell::new(SystemProxyStatus {
            enabled: true,
            http_proxy: Some("127.0.0.1:8080".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut c = SystemProxyController::new(ops, mem_marker());
    let original = SystemProxyStatus {
        enabled: true,
        http_proxy: Some("proxy.corp:3128".into()),
        ..Default::default()
    };
    write_legacy_marker(&c.marker, "127.0.0.1:8080", Some(&original));

    assert!(c.ensure_cleared());
    assert!(
        c.ops.calls.borrow().contains(&"restore"),
        "marker 带原始 → 恢复用户代理，不是简单关"
    );
    assert!(!c.has_marker());
}

#[test]
fn ensure_cleared_never_touches_user_configured_proxy() {
    // 门控 1：无 marker = 代理不是我们设的 → 即便系统代理开着也绝不动。
    let ops = MockOps {
        status: RefCell::new(SystemProxyStatus {
            enabled: true,
            http_proxy: Some("proxy.corp:3128".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut c = SystemProxyController::new(ops, mem_marker());
    assert!(!c.ensure_cleared());
    assert!(
        !c.ops.calls.borrow().contains(&"clear"),
        "绝不误清用户自配代理"
    );
}

#[test]
fn ensure_cleared_only_drops_stale_marker_when_proxy_moved_elsewhere() {
    // 门控 2：marker 在但用户已手改代理指向别处 → 只清失真 marker，不 disable 用户的新代理。
    let ops = MockOps {
        status: RefCell::new(SystemProxyStatus {
            enabled: true,
            http_proxy: Some("proxy.corp:3128".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut c = SystemProxyController::new(ops, mem_marker());
    write_legacy_marker(&c.marker, "127.0.0.1:8080", None);

    assert!(!c.ensure_cleared(), "未指向我们 → 不 disable");
    assert!(
        !c.ops.calls.borrow().contains(&"clear"),
        "不得动用户改到别处的代理"
    );
    assert!(!c.has_marker(), "失真 marker 应被清");
}

#[test]
fn ensure_cleared_keeps_newer_marker_from_concurrent_enable() {
    // 门控 3（C1 竞态）：清失真 marker 前重读；若已被新一轮 enable 写了**新** marker → 保留，
    // 否则会删掉新会话的 marker 致其兜底全瞎。
    struct RewritingOps {
        marker_fs: crate::proxy::proxy_tests_helpers::MemFs,
    }
    impl SystemProxyOps for RewritingOps {
        fn get_proxy_status(&self) -> Result<SystemProxyStatus, SystemIntegrationError> {
            // 模拟：读状态期间，另一轮 enable 写了新 marker（新 host:port）。
            let marker = ProxyMarker::new(self.marker_fs.clone(), "/marker.json");
            let ProxyMarkerRead::Legacy(current) = marker.read_checked() else {
                panic!("legacy marker expected");
            };
            assert_eq!(
                marker.clear_legacy_if_current(&current),
                crate::proxy::ProxyMarkerMutationOutcome::Updated
            );
            assert!(matches!(
                marker.begin_legacy_if_absent("127.0.0.1:9999", None),
                ProxyMarkerBeginOutcome::Begun(_)
            ));
            // 返回「指向别处」的状态 → 走清失真 marker 腿。
            Ok(SystemProxyStatus {
                enabled: true,
                http_proxy: Some("proxy.corp:3128".into()),
                ..Default::default()
            })
        }
        fn list_network_services(&self) -> Result<Vec<String>, SystemIntegrationError> {
            Ok(vec![])
        }
        fn set_proxy(&self, _r: &ProxyEnableRequest) -> Result<(), SystemIntegrationError> {
            Ok(())
        }
        fn clear_proxy(&self) -> Result<(), SystemIntegrationError> {
            Ok(())
        }
        fn restore_proxy(&self, _o: &SystemProxyStatus) -> Result<(), SystemIntegrationError> {
            Ok(())
        }
    }
    let fs = crate::proxy::proxy_tests_helpers::MemFs::new();
    let mut c = SystemProxyController::new(
        RewritingOps {
            marker_fs: fs.clone(),
        },
        ProxyMarker::new(fs.clone(), "/marker.json"),
    );
    write_legacy_marker(&c.marker, "127.0.0.1:8080", None); // 旧 marker

    c.ensure_cleared();
    // 新 marker（9999）必须存活 —— 它属于新会话。
    let cur = ProxyMarker::new(fs, "/marker.json").read_checked();
    assert_eq!(
        match cur {
            ProxyMarkerRead::Legacy(marker) => Some(marker.our_host_port),
            _ => None,
        },
        Some("127.0.0.1:9999".to_owned()),
        "不得删掉并发 enable 写的新 marker"
    );
}

#[test]
fn ensure_cleared_is_idempotent() {
    // 幂等：多路终态并发/重复调用安全（第一次清了 marker → 后续门控 1 即返）。
    let ops = MockOps {
        status: RefCell::new(SystemProxyStatus {
            enabled: true,
            http_proxy: Some("127.0.0.1:8080".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut c = SystemProxyController::new(ops, mem_marker());
    write_legacy_marker(&c.marker, "127.0.0.1:8080", None);

    assert!(c.ensure_cleared());
    let calls_after_first = c.ops.calls.borrow().len();
    // 再调两次 → 不得再 disable。
    assert!(!c.ensure_cleared());
    assert!(!c.ensure_cleared());
    assert_eq!(
        c.ops.calls.borrow().len(),
        calls_after_first,
        "重复调用不得重复 disable"
    );
}

#[test]
fn ensure_cleared_matches_by_host_when_socks_port_differs() {
    // mac：socks 端口 ≠ http 端口，而 marker 只记 address:http_port。
    // 仅按 host:port 精确匹配会漏判 socks 腿的残留 → 必须也认 host 匹配。
    let ops = MockOps {
        status: RefCell::new(SystemProxyStatus {
            enabled: true,
            socks_proxy: Some("127.0.0.1:1080".into()), // 端口与 marker 的 8080 不同
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut c = SystemProxyController::new(ops, mem_marker());
    write_legacy_marker(&c.marker, "127.0.0.1:8080", None);

    assert!(
        c.ensure_cleared(),
        "socks 端口不同但 host 相同 → 仍是我们的残留，必须清"
    );
    assert!(!c.has_marker());
}

#[test]
fn ensure_cleared_ignores_disabled_status() {
    // 系统代理已关（enabled=false）→ 无需 disable，仅清失真 marker。
    let ops = MockOps::default(); // status 默认 enabled=false
    let mut c = SystemProxyController::new(ops, mem_marker());
    write_legacy_marker(&c.marker, "127.0.0.1:8080", None);
    assert!(!c.ensure_cleared());
    assert!(!c.has_marker());
}

// ── detect_foreign_proxy（EVENT_SYSTEM_PROXY_RESIDUAL 的真值源）─────────────────

#[test]
fn detect_foreign_proxy_reports_others_proxy_when_no_marker() {
    // 无 marker（不是我们设的）+ 系统里确有启用的代理 → 报出其 host:port。
    let ops = MockOps {
        status: RefCell::new(SystemProxyStatus {
            enabled: true,
            http_proxy: Some("192.168.1.2:7890".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let c = SystemProxyController::new(ops, mem_marker());
    assert_eq!(
        c.detect_foreign_proxy(),
        Some("192.168.1.2:7890".into()),
        "无 marker + 有代理 = 别人的残留，应报出"
    );
}

#[test]
fn detect_foreign_proxy_none_when_marker_present() {
    // 有 marker = 系统代理是我们设的 → 不是「别人的」，绝不误报（该场景归 ensure_cleared）。
    let ops = MockOps {
        status: RefCell::new(SystemProxyStatus {
            enabled: true,
            http_proxy: Some("127.0.0.1:8080".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let c = SystemProxyController::new(ops, mem_marker());
    write_legacy_marker(&c.marker, "127.0.0.1:8080", None);
    assert_eq!(
        c.detect_foreign_proxy(),
        None,
        "有 marker → 是我们设的，不算残留"
    );
    // 有 marker 时早退：连状态都不读（省一次 exec）。
    assert!(
        c.ops.calls.borrow().is_empty(),
        "有 marker 应门控 1 即返，不查状态"
    );
}

#[test]
fn detect_foreign_proxy_none_when_no_proxy_set() {
    // 无 marker 且系统无代理 → None（干净环境不打扰用户）。
    let ops = MockOps::default(); // status 默认 enabled=false / 全空
    let c = SystemProxyController::new(ops, mem_marker());
    assert_eq!(c.detect_foreign_proxy(), None);
}

#[test]
fn detect_foreign_proxy_none_when_server_present_but_disabled() {
    // 显式守卫：enabled=false 但 http_proxy 有值（Win 注册表 ProxyServer 在 ProxyEnable=0 时留值的形态）
    // → 不得误报。锁死 detect_foreign_proxy 里 `!status.enabled || ...` 的 enabled 判据。
    let ops = MockOps {
        status: RefCell::new(SystemProxyStatus {
            enabled: false,
            http_proxy: Some("10.0.0.9:1080".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let c = SystemProxyController::new(ops, mem_marker());
    assert_eq!(
        c.detect_foreign_proxy(),
        None,
        "enabled=false 的残留 server 值不算启用中的代理"
    );
}

#[test]
fn points_to_us_unit() {
    let st = SystemProxyStatus {
        enabled: true,
        http_proxy: Some("127.0.0.1:8080".into()),
        ..Default::default()
    };
    assert!(points_to_us(Some(&st), "127.0.0.1:8080"));
    assert!(points_to_us(Some(&st), "127.0.0.1:1080")); // host 匹配
    assert!(!points_to_us(Some(&st), "10.0.0.1:8080"));
    assert!(!points_to_us(None, "127.0.0.1:8080"));
    // 关着的代理不算指向我们。
    let off = SystemProxyStatus {
        enabled: false,
        http_proxy: Some("127.0.0.1:8080".into()),
        ..Default::default()
    };
    assert!(!points_to_us(Some(&off), "127.0.0.1:8080"));
}
