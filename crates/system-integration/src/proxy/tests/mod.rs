use super::*;
use crate::proxy::proxy_tests_helpers::MemFs;

fn write_legacy<Fs: MarkerFs>(
    marker: &ProxyMarker<Fs>,
    host: &str,
    original: Option<&SystemProxyStatus>,
) {
    let original = original.cloned().map(ProxyOriginalSettings::from_status);
    assert!(matches!(
        marker.begin_legacy_if_absent(host, original.as_ref()),
        ProxyMarkerBeginOutcome::Begun(_)
    ));
}

fn read_present<Fs: MarkerFs>(marker: &ProxyMarker<Fs>) -> ProxyMarkerData {
    match marker.read_checked() {
        ProxyMarkerRead::Legacy(data) | ProxyMarkerRead::CurrentValidated(data) => data,
        other => panic!("expected marker, got {other:?}"),
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

const EMPTY_DICT_PLIST: &str = concat!(
    r#"<?xml version="1.0" encoding="UTF-8"?>"#,
    r#"<plist version="1.0"><dict/></plist>"#,
);
const EMPTY_STRING_PLIST: &str = r#"<plist version="1.0"><string></string></plist>"#;
const INTEGER_PLIST: &str = r#"<plist version="1.0"><integer>1</integer></plist>"#;

fn mac_snapshot(id: &str, touched: MacProxyTouchedSnapshot) -> MacProxyServiceSnapshot {
    MacProxyServiceSnapshot {
        service_id: id.into(),
        service_name: format!("service-{id}"),
        service_enabled: true,
        had_proxy_protocol: touched.protocol_present,
        protocol_enabled: touched.protocol_enabled,
        configuration_plist: touched
            .protocol_present
            .then(|| EMPTY_DICT_PLIST.to_string()),
        touched: Some(touched),
        ..Default::default()
    }
}

fn present_touched(value: MacProxyPropertyValue) -> MacProxyTouchedSnapshot {
    MacProxyTouchedSnapshot {
        protocol_present: true,
        protocol_enabled: true,
        http_enabled: value.clone(),
        http_host: value.clone(),
        http_port: value.clone(),
        https_enabled: value.clone(),
        https_host: value.clone(),
        https_port: value.clone(),
        socks_enabled: value.clone(),
        socks_host: value.clone(),
        socks_port: value.clone(),
        exceptions: value,
    }
}

fn mac_transaction_snapshot(services: Vec<MacProxyServiceSnapshot>) -> ProxyTransactionSnapshot {
    ProxyTransactionSnapshot {
        projection: Some(SystemProxyStatus::default()),
        mac_services: services,
        ..Default::default()
    }
}

#[test]
fn mac_snapshot_validator_rejects_empty_duplicate_invalid_and_mismatched_scope() {
    assert!(validate_mac_proxy_snapshots(&[], None).is_err());
    let one = mac_snapshot("a", MacProxyTouchedSnapshot::default());
    assert!(validate_mac_proxy_snapshots(&[one.clone(), one.clone()], None).is_err());

    let mut invalid_id = one.clone();
    invalid_id.service_id = "bad\nid".into();
    assert!(validate_mac_proxy_snapshots(&[invalid_id], None).is_err());

    let two = mac_snapshot("b", MacProxyTouchedSnapshot::default());
    assert!(validate_mac_proxy_snapshots(
        std::slice::from_ref(&one),
        Some(std::slice::from_ref(&two)),
    )
    .is_err());
    assert!(validate_mac_proxy_snapshots(
        &[one.clone(), two.clone()],
        Some(std::slice::from_ref(&one)),
    )
    .is_err());
    assert!(validate_mac_proxy_snapshots(
        &[one, two.clone()],
        Some(&[two, mac_snapshot("a", MacProxyTouchedSnapshot::default(),)])
    )
    .is_ok());
}

#[test]
fn mac_snapshot_validator_enforces_protocol_null_and_touched_invariants() {
    let absent = mac_snapshot("absent", MacProxyTouchedSnapshot::default());
    assert!(validate_mac_proxy_snapshots(std::slice::from_ref(&absent), None).is_ok());

    let mut absent_with_member = absent;
    absent_with_member.touched.as_mut().unwrap().http_host =
        MacProxyPropertyValue::PropertyListXml(INTEGER_PLIST.into());
    assert!(validate_mac_proxy_snapshots(&[absent_with_member], None).is_err());

    let mut null_configuration =
        mac_snapshot("null", present_touched(MacProxyPropertyValue::Absent));
    null_configuration.configuration_plist = None;
    assert!(
        validate_mac_proxy_snapshots(std::slice::from_ref(&null_configuration), None,).is_err()
    );
    null_configuration.clear_on_restore = true;
    assert!(validate_mac_proxy_snapshots(&[null_configuration], None).is_ok());
}

#[test]
fn mac_snapshot_validator_parses_all_ten_absent_empty_and_value_members() {
    for (id, value) in [
        ("absent", MacProxyPropertyValue::Absent),
        (
            "empty",
            MacProxyPropertyValue::PropertyListXml(EMPTY_STRING_PLIST.into()),
        ),
        (
            "value",
            MacProxyPropertyValue::PropertyListXml(INTEGER_PLIST.into()),
        ),
    ] {
        assert!(
            validate_mac_proxy_snapshots(&[mac_snapshot(id, present_touched(value))], None).is_ok()
        );
    }

    let mut invalid_member = mac_snapshot(
        "invalid-member",
        present_touched(MacProxyPropertyValue::Absent),
    );
    invalid_member.touched.as_mut().unwrap().exceptions =
        MacProxyPropertyValue::PropertyListXml("<plist><string>".into());
    assert!(validate_mac_proxy_snapshots(&[invalid_member], None).is_err());

    let mut non_dictionary = mac_snapshot(
        "not-dictionary",
        present_touched(MacProxyPropertyValue::Absent),
    );
    non_dictionary.configuration_plist = Some(INTEGER_PLIST.into());
    assert!(validate_mac_proxy_snapshots(&[non_dictionary], None).is_err());
}

#[test]
fn mac_v2_marker_accepts_reordered_stable_service_id_set() {
    let a = mac_snapshot("a", MacProxyTouchedSnapshot::default());
    let b = mac_snapshot("b", MacProxyTouchedSnapshot::default());
    let original = mac_transaction_snapshot(vec![a.clone(), b.clone()]);
    let reordered = mac_transaction_snapshot(vec![b, a]);
    let marker = ProxyMarker::new(MemFs::new(), "/marker.json");

    assert!(matches!(
        marker.begin_if_absent("127.0.0.1:8080", &original, &original, &reordered),
        ProxyMarkerBeginOutcome::Begun(_)
    ));
    assert!(matches!(
        marker.read_checked(),
        ProxyMarkerRead::CurrentValidated(_)
    ));
}

#[test]
fn marker_write_read_roundtrip() {
    let fs = MemFs::new();
    let marker = ProxyMarker::new(fs, "/marker.json");
    assert_eq!(marker.read_checked(), ProxyMarkerRead::Missing);

    let original = SystemProxyStatus {
        enabled: true,
        http_proxy: Some("proxy.lan:3128".into()),
        ..Default::default()
    };
    write_legacy(&marker, "127.0.0.1:8080", Some(&original));
    assert!(matches!(marker.read_checked(), ProxyMarkerRead::Legacy(_)));

    let data = read_present(&marker);
    assert_eq!(data.our_host_port, "127.0.0.1:8080");
    let orig = data.original_settings.expect("original saved");
    assert_eq!(orig.http_proxy.as_deref(), Some("proxy.lan:3128"));
}

#[test]
fn marker_write_without_original() {
    let fs = MemFs::new();
    let marker = ProxyMarker::new(fs, "/m");
    write_legacy(&marker, "127.0.0.1:8080", None);
    let data = read_present(&marker);
    assert_eq!(data.our_host_port, "127.0.0.1:8080");
    assert!(data.original_settings.is_none());
    assert!(data.mac_service_settings.is_empty());
}

#[test]
fn marker_roundtrips_complete_macos_service_snapshot() {
    let fs = MemFs::new();
    let marker = ProxyMarker::new(fs, "/m");
    let snapshot = ProxyOriginalSettings {
        fallback: None,
        mac_services: vec![MacProxyServiceSnapshot {
            service_id: "stable-service-id".into(),
            service_name: "Wi-Fi".into(),
            service_enabled: true,
            had_proxy_protocol: true,
            protocol_enabled: true,
            configuration_plist: Some("<plist>opaque-complete-config</plist>".into()),
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

    assert!(matches!(
        marker.begin_legacy_if_absent("127.0.0.1:8080", Some(&snapshot)),
        ProxyMarkerBeginOutcome::Begun(_)
    ));
    let recovered = read_present(&marker)
        .original_snapshot()
        .expect("complete snapshot must survive marker roundtrip");
    assert_eq!(recovered, snapshot);
}

#[test]
fn old_marker_without_macos_services_remains_readable() {
    let data: ProxyMarkerData = serde_json::from_str(
        r#"{"our_host_port":"127.0.0.1:8080","at":1,"original_settings":{"enabled":false}}"#,
    )
    .unwrap();
    assert!(data.mac_service_settings.is_empty());
    assert_eq!(
        data.original_snapshot().unwrap().fallback,
        Some(SystemProxyStatus::default())
    );
}

#[test]
fn marker_clear_removes() {
    let fs = MemFs::new();
    let marker = ProxyMarker::new(fs, "/m");
    write_legacy(&marker, "127.0.0.1:8080", None);
    let ProxyMarkerRead::Legacy(data) = marker.read_checked() else {
        panic!("legacy marker expected");
    };
    assert_eq!(
        marker.clear_legacy_if_current(&data),
        ProxyMarkerMutationOutcome::Updated
    );
    assert_eq!(marker.read_checked(), ProxyMarkerRead::Missing);
}

#[test]
fn marker_read_returns_invalid_for_corrupt_json() {
    struct CorruptFs;
    impl MarkerFs for CorruptFs {
        fn write_marker(&self, _p: &str, _d: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn read_marker(&self, _p: &str) -> Option<String> {
            Some("{not json".into())
        }
        fn remove_marker(&self, _p: &str) -> std::io::Result<()> {
            Ok(())
        }
    }
    let marker = ProxyMarker::new(CorruptFs, "/m");
    assert!(matches!(marker.read_checked(), ProxyMarkerRead::Invalid(_)));
}

#[test]
fn marker_read_returns_invalid_for_empty_our_host_port() {
    struct EmptyFs;
    impl MarkerFs for EmptyFs {
        fn write_marker(&self, _p: &str, _d: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn read_marker(&self, _p: &str) -> Option<String> {
            Some(r#"{"our_host_port":"","at":0}"#.into())
        }
        fn remove_marker(&self, _p: &str) -> std::io::Result<()> {
            Ok(())
        }
    }
    let marker = ProxyMarker::new(EmptyFs, "/m");
    assert!(matches!(marker.read_checked(), ProxyMarkerRead::Invalid(_)));
}

#[test]
fn marker_v2_roundtrips_snapshots_and_phase() {
    let marker = ProxyMarker::new(MemFs::new(), "/marker.json");
    let linux = LinuxGSettingsSnapshot {
        http_host: "'proxy.corp'".into(),
        http_port: "3128".into(),
        http_enabled: "true".into(),
        https_host: "''".into(),
        https_port: "0".into(),
        socks_host: "''".into(),
        socks_port: "0".into(),
        ignore_hosts: "@as []".into(),
        mode: "'manual'".into(),
    };
    let original = ProxyTransactionSnapshot {
        projection: Some(SystemProxyStatus {
            enabled: true,
            http_proxy: Some("proxy.corp:3128".into()),
            ..Default::default()
        }),
        linux_gsettings: Some(linux.clone()),
        ..Default::default()
    };
    let applied = ProxyTransactionSnapshot {
        projection: Some(SystemProxyStatus {
            enabled: true,
            http_proxy: Some("127.0.0.1:7890".into()),
            ..Default::default()
        }),
        linux_gsettings: Some(linux),
        ..Default::default()
    };

    let ProxyMarkerBeginOutcome::Begun(begun) =
        marker.begin_if_absent("127.0.0.1:7890", &original, &original, &applied)
    else {
        panic!("V2 marker must persist");
    };
    assert!(begun.txn_id.as_deref().is_some_and(|id| !id.is_empty()));
    assert_eq!(begun.plan_version, PROXY_TRANSACTION_PLAN_VERSION);
    assert_eq!(begun.phase, ProxyMarkerPhase::Applying);
    assert_eq!(begun.exact_original.as_ref(), Some(&original));
    assert_eq!(begun.exact_apply_base.as_ref(), Some(&original));
    assert_eq!(begun.exact_applied.as_ref(), Some(&applied));
    assert_eq!(
        marker.read_checked(),
        ProxyMarkerRead::CurrentValidated(begun)
    );
}

#[test]
fn current_marker_envelope_fences_every_phase_from_frozen_head_reader() {
    #[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "camelCase")]
    enum FrozenHeadPhase {
        Applying,
        #[default]
        Owned,
        Restoring,
        RestoredPendingClear,
    }

    #[derive(Debug, Deserialize)]
    struct FrozenHeadMarker {
        our_host_port: String,
        #[serde(default)]
        at: u64,
        #[serde(default)]
        txn_id: Option<String>,
        #[serde(default)]
        plan_version: u32,
        #[serde(default)]
        phase: FrozenHeadPhase,
        #[serde(default)]
        original: Option<ProxyTransactionSnapshot>,
        #[serde(default)]
        apply_base: Option<ProxyTransactionSnapshot>,
        #[serde(default)]
        applied: Option<ProxyTransactionSnapshot>,
        #[serde(default)]
        original_settings: Option<SystemProxyStatus>,
        #[serde(default)]
        mac_service_settings: Vec<MacProxyServiceSnapshot>,
    }

    fn frozen_head_recovery_entry(raw: &str) -> Option<FrozenHeadMarker> {
        serde_json::from_str(raw).ok()
    }

    let original = exact_linux_snapshot("proxy.corp:3128");
    let applied = exact_linux_snapshot("127.0.0.1:7890");
    for phase in [
        ProxyMarkerPhase::Applying,
        ProxyMarkerPhase::Owned,
        ProxyMarkerPhase::Restoring,
        ProxyMarkerPhase::RestoredPendingClear,
    ] {
        let fs = MemFs::new();
        let marker = ProxyMarker::new(fs.clone(), "/marker.json");
        let ProxyMarkerBeginOutcome::Begun(begun) =
            marker.begin_if_absent("127.0.0.1:7890", &original, &original, &applied)
        else {
            panic!("current marker must persist");
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
                ProxyMarkerMutationOutcome::Updated
            ),
            ProxyMarkerPhase::Restoring => assert_eq!(
                marker.update_current_phase(
                    txn_id,
                    ProxyMarkerPhase::Applying,
                    ProxyMarkerPhase::Restoring,
                ),
                ProxyMarkerMutationOutcome::Updated
            ),
            ProxyMarkerPhase::RestoredPendingClear => {
                assert_eq!(
                    marker.update_current_phase(
                        txn_id,
                        ProxyMarkerPhase::Applying,
                        ProxyMarkerPhase::Restoring,
                    ),
                    ProxyMarkerMutationOutcome::Updated
                );
                assert_eq!(
                    marker.update_current_phase(
                        txn_id,
                        ProxyMarkerPhase::Restoring,
                        ProxyMarkerPhase::RestoredPendingClear,
                    ),
                    ProxyMarkerMutationOutcome::Updated
                );
            }
        }

        let raw = fs.read_marker("/marker.json").unwrap();
        let root: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            root.as_object().unwrap().keys().collect::<Vec<_>>(),
            vec![PROXY_TRANSACTION_ENVELOPE_KEY]
        );
        assert!(
            frozen_head_recovery_entry(&raw).is_none(),
            "frozen reader must not enter recovery for {phase:?}"
        );
        assert!(matches!(
            marker.read_checked(),
            ProxyMarkerRead::CurrentValidated(current) if current.phase == phase
        ));
    }

    let fs = MemFs::new();
    let marker = ProxyMarker::new(fs.clone(), "/legacy.json");
    write_legacy(&marker, "127.0.0.1:8080", None);
    let raw = fs.read_marker("/legacy.json").unwrap();
    let frozen = frozen_head_recovery_entry(&raw).expect("legacy remains visible to old reader");
    assert_eq!(frozen.our_host_port, "127.0.0.1:8080");
    assert!(frozen.at > 0);
    assert_eq!(frozen.txn_id, None);
    assert_eq!(frozen.plan_version, 0);
    assert_eq!(frozen.phase, FrozenHeadPhase::Owned);
    assert!(frozen.original.is_none());
    assert!(frozen.apply_base.is_none());
    assert!(frozen.applied.is_none());
    assert!(frozen.original_settings.is_none());
    assert!(frozen.mac_service_settings.is_empty());
    assert!(matches!(marker.read_checked(), ProxyMarkerRead::Legacy(_)));
}

#[test]
fn top_level_exact_fields_are_invalid_not_current_or_legacy() {
    let fs = MemFs::new();
    fs.write_marker(
        "/marker.json",
        r#"{"our_host_port":"127.0.0.1:7890","txn_id":"old-shape","plan_version":1,"phase":"applying","exact_original":null,"exact_apply_base":null,"exact_applied":null}"#,
    )
    .unwrap();
    let marker = ProxyMarker::new(fs, "/marker.json");
    assert!(matches!(marker.read_checked(), ProxyMarkerRead::Invalid(_)));
}

#[test]
fn linux_exact_snapshot_type_is_shared_by_runtime_and_persisted_carriers() {
    let linux = LinuxGSettingsSnapshot {
        mode: "'none'".into(),
        ignore_hosts: "@as []".into(),
        http_host: "''".into(),
        http_port: "0".into(),
        http_enabled: "false".into(),
        https_host: "''".into(),
        https_port: "0".into(),
        socks_host: "''".into(),
        socks_port: "0".into(),
    };
    let runtime = ProxyOriginalSettings {
        fallback: None,
        mac_services: Vec::new(),
        linux_gsettings: Some(linux.clone()),
        windows_registry: None,
    };
    let persisted = ProxyTransactionSnapshot::from_original(&runtime);
    assert_eq!(persisted.linux_gsettings.as_ref(), Some(&linux));
    assert_eq!(persisted.original_settings(), Some(runtime));
}

#[test]
fn windows_exact_snapshot_preserves_registry_presence_and_raw_dword() {
    let windows = WindowsProxyRegistrySnapshot {
        proxy_server: WindowsRegistryStringValue::Absent,
        proxy_override: WindowsRegistryStringValue::PresentEmpty,
        proxy_enable: WindowsRegistryDwordValue::PresentValue(7),
    };
    let runtime = ProxyOriginalSettings {
        windows_registry: Some(windows.clone()),
        ..Default::default()
    };
    assert!(!runtime.is_empty());

    let persisted = ProxyTransactionSnapshot::from_original(&runtime);
    assert_eq!(persisted.windows_registry.as_ref(), Some(&windows));
    let json = serde_json::to_string(&persisted).unwrap();
    assert_eq!(
        json,
        r#"{"windows_registry":{"proxy_server":{"state":"absent"},"proxy_override":{"state":"presentEmpty"},"proxy_enable":{"state":"presentValue","value":7}}}"#,
        "Windows exact marker JSON 是跨版本恢复协议，三态标签与 raw DWORD 不得漂移"
    );
    let decoded: ProxyTransactionSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, persisted);
    assert_eq!(decoded.original_settings(), Some(runtime));

    let non_empty = WindowsRegistryStringValue::PresentValue("proxy.corp:3128".into());
    assert_eq!(
        serde_json::to_string(&non_empty).unwrap(),
        r#"{"state":"presentValue","value":"proxy.corp:3128"}"#
    );
    assert_ne!(non_empty, WindowsRegistryStringValue::PresentEmpty);
    assert_ne!(WindowsRegistryDwordValue::Absent, windows.proxy_enable);
}

#[test]
fn old_v2_marker_without_windows_registry_remains_readable() {
    let marker: ProxyMarkerData = serde_json::from_str(
        r#"{"our_host_port":"127.0.0.1:7890","txn_id":"legacy-v2","plan_version":2,"phase":"owned","original":{"projection":{"enabled":false}}}"#,
    )
    .unwrap();
    let original = marker.original.as_ref().expect("V2 original snapshot");
    assert!(original.windows_registry.is_none());
    assert_eq!(
        marker.original_snapshot(),
        Some(ProxyOriginalSettings::from_status(
            SystemProxyStatus::default()
        ))
    );
}

#[test]
fn marker_v2_transaction_ids_distinguish_process_sequence_and_restart_entropy() {
    let first = format_proxy_txn_id(42, 7, 11);
    assert_ne!(first, format_proxy_txn_id(42, 8, 11));
    assert_ne!(first, format_proxy_txn_id(42, 7, 12));

    let ids = (0..1_024)
        .map(|_| new_proxy_txn_id())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(ids.len(), 1_024);
}

#[test]
fn marker_v2_phase_update_is_a_transaction_and_phase_cas() {
    let marker = ProxyMarker::new(MemFs::new(), "/marker.json");
    let original = exact_linux_snapshot("proxy.corp:3128");
    let applied = exact_linux_snapshot("127.0.0.1:7890");
    let ProxyMarkerBeginOutcome::Begun(begun) =
        marker.begin_if_absent("127.0.0.1:7890", &original, &original, &applied)
    else {
        panic!("begin must succeed");
    };
    let txn_id = begun.txn_id.as_deref().unwrap();

    assert_eq!(
        marker.update_current_phase(txn_id, ProxyMarkerPhase::Applying, ProxyMarkerPhase::Owned,),
        ProxyMarkerMutationOutcome::Updated
    );
    assert_eq!(
        marker.update_current_phase(
            txn_id,
            ProxyMarkerPhase::Applying,
            ProxyMarkerPhase::Restoring,
        ),
        ProxyMarkerMutationOutcome::Mismatch
    );
    assert_eq!(read_present(&marker).phase, ProxyMarkerPhase::Owned);
}

#[test]
fn marker_v2_same_port_new_transaction_rejects_stale_update_and_clear() {
    let marker = ProxyMarker::new(MemFs::new(), "/marker.json");
    let original = exact_linux_snapshot("proxy.corp:3128");
    let applied = exact_linux_snapshot("127.0.0.1:7890");
    let ProxyMarkerBeginOutcome::Begun(old) =
        marker.begin_if_absent("127.0.0.1:7890", &original, &original, &applied)
    else {
        panic!("begin must succeed");
    };
    let old_id = old.txn_id.as_deref().unwrap();
    assert_eq!(
        marker.update_current_phase(old_id, ProxyMarkerPhase::Applying, ProxyMarkerPhase::Owned,),
        ProxyMarkerMutationOutcome::Updated
    );
    let next_applied = exact_linux_snapshot("127.0.0.1:7891");
    let ProxyMarkerReplaceOutcome::Replaced(new) =
        marker.replace_if_current(old_id, "127.0.0.1:7890", &applied, &next_applied)
    else {
        panic!("replace must succeed");
    };
    let new_id = new.txn_id.as_deref().unwrap();
    assert_ne!(old_id, new_id);

    assert_eq!(
        marker.update_current_phase(old_id, ProxyMarkerPhase::Applying, ProxyMarkerPhase::Owned,),
        ProxyMarkerMutationOutcome::Mismatch
    );
    assert_eq!(
        marker.clear_current(old_id, ProxyMarkerPhase::Applying),
        ProxyMarkerMutationOutcome::Mismatch
    );
    assert_eq!(read_present(&marker).txn_id.as_deref(), Some(new_id));
    assert_eq!(
        marker.clear_current(new_id, ProxyMarkerPhase::Owned),
        ProxyMarkerMutationOutcome::Mismatch
    );
    assert_eq!(read_present(&marker).txn_id.as_deref(), Some(new_id));
    assert_eq!(
        marker.clear_current(new_id, ProxyMarkerPhase::Applying),
        ProxyMarkerMutationOutcome::Updated
    );
    assert_eq!(marker.read_checked(), ProxyMarkerRead::Missing);
}

#[test]
fn marker_v1_json_defaults_to_legacy_owned_semantics() {
    let fs = MemFs::new();
    fs.write_marker(
        "/marker.json",
        r#"{"our_host_port":"127.0.0.1:8080","at":5,"original_settings":{"enabled":false}}"#,
    )
    .unwrap();
    let marker = ProxyMarker::new(fs, "/marker.json");
    let ProxyMarkerRead::Legacy(legacy) = marker.read_checked() else {
        panic!("legacy marker expected");
    };
    assert_eq!(legacy.txn_id, None);
    assert_eq!(legacy.plan_version, 0);
    assert_eq!(legacy.phase, ProxyMarkerPhase::Owned);
    assert!(legacy.original.is_none());
    assert!(legacy.applied.is_none());
    assert!(legacy
        .original_snapshot()
        .unwrap()
        .linux_gsettings
        .is_none());
    assert_eq!(
        legacy.original_snapshot().unwrap().fallback,
        legacy.original_settings
    );
}

#[test]
fn std_marker_fs_atomically_replaces_and_leaves_no_temporary_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proxy-marker.json");
    let path_string = path.to_string_lossy().into_owned();
    let marker = ProxyMarker::new(StdMarkerFs, path_string);

    let original = exact_linux_snapshot("proxy.corp:3128");
    let applied = exact_linux_snapshot("127.0.0.1:7001");
    let ProxyMarkerBeginOutcome::Begun(begun) =
        marker.begin_if_absent("127.0.0.1:7001", &original, &original, &applied)
    else {
        panic!("begin must succeed");
    };
    assert_eq!(
        marker.update_current_phase(
            begun.txn_id.as_deref().unwrap(),
            ProxyMarkerPhase::Applying,
            ProxyMarkerPhase::Owned,
        ),
        ProxyMarkerMutationOutcome::Updated
    );
    assert_eq!(read_present(&marker).phase, ProxyMarkerPhase::Owned);

    let mut entries = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    entries.sort();
    assert_eq!(
        entries,
        vec![
            std::ffi::OsString::from("proxy-marker.json"),
            std::ffi::OsString::from("proxy-marker.json.lock"),
        ]
    );
}

#[test]
fn std_marker_fs_lock_contention_fails_all_mutations_closed() {
    let dir = tempfile::tempdir().unwrap();
    let empty_path = dir.path().join("empty-marker.json");
    let empty_path = empty_path.to_string_lossy().into_owned();
    let held = StdMarkerFs
        .acquire_marker_mutation_lock(&empty_path)
        .expect("first independent fd acquires lock");
    let original = exact_linux_snapshot("proxy.corp:3128");
    let applied = exact_linux_snapshot("127.0.0.1:7890");
    let blocked = ProxyMarker::new(StdMarkerFs, empty_path.clone());
    assert!(matches!(
        blocked.begin_if_absent("127.0.0.1:7890", &original, &original, &applied),
        ProxyMarkerBeginOutcome::PersistFailed
    ));
    assert_eq!(blocked.read_checked(), ProxyMarkerRead::Missing);
    drop(held);

    let ProxyMarkerBeginOutcome::Begun(begun) =
        blocked.begin_if_absent("127.0.0.1:7890", &original, &original, &applied)
    else {
        panic!("begin succeeds after OS releases first fd");
    };
    let before = blocked.read_checked();
    let held = StdMarkerFs
        .acquire_marker_mutation_lock(&empty_path)
        .expect("first independent fd reacquires lock");
    let txn_id = begun.txn_id.as_deref().unwrap();
    assert_eq!(
        blocked.replace_if_current(txn_id, "127.0.0.1:7891", &applied, &original),
        ProxyMarkerReplaceOutcome::PersistFailed
    );
    assert_eq!(
        blocked.update_current_phase(txn_id, ProxyMarkerPhase::Applying, ProxyMarkerPhase::Owned,),
        ProxyMarkerMutationOutcome::PersistFailed
    );
    assert_eq!(
        blocked.clear_current(txn_id, ProxyMarkerPhase::Applying),
        ProxyMarkerMutationOutcome::PersistFailed
    );
    assert_eq!(blocked.read_checked(), before);
    drop(held);
}

#[test]
fn std_marker_fs_failed_replace_removes_temporary_file() {
    let dir = tempfile::tempdir().unwrap();
    let target_directory = dir.path().join("marker-target");
    std::fs::create_dir(&target_directory).unwrap();
    let result = StdMarkerFs.write_marker(&target_directory.to_string_lossy(), "new marker");
    assert!(result.is_err(), "普通文件不得原子替换现有目录");

    let entries = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(entries, vec![std::ffi::OsString::from("marker-target")]);
}

// ── strip_self 防自指（维度7 死端口断网防护）──

#[test]
fn strip_self_returns_none_when_points_to_our_address() {
    let status = SystemProxyStatus {
        enabled: true,
        http_proxy: Some("127.0.0.1:8080".into()),
        ..Default::default()
    };
    // 当前代理正是我们自己的 → 视为无原始（否则 disable 会恢复死端口）。
    let r = strip_self(Some(&status), "127.0.0.1", 8080, None);
    assert!(r.is_none());
}

#[test]
fn strip_self_returns_none_when_points_to_marker_host() {
    let status = SystemProxyStatus {
        enabled: true,
        https_proxy: Some("127.0.0.1:8080".into()),
        ..Default::default()
    };
    // 指向 marker 记录的 our_host_port → 自指。
    let r = strip_self(Some(&status), "0.0.0.0", 9999, Some("127.0.0.1:8080"));
    assert!(r.is_none());
}

#[test]
fn strip_self_preserves_real_external_proxy() {
    let status = SystemProxyStatus {
        enabled: true,
        http_proxy: Some("proxy.corp:3128".into()),
        ..Default::default()
    };
    // 真正的第三方代理 → 保留为原始。
    let r = strip_self(Some(&status), "127.0.0.1", 8080, None);
    assert_eq!(r.unwrap().http_proxy.as_deref(), Some("proxy.corp:3128"));
}

#[test]
fn strip_self_preserves_disabled_status() {
    let status = SystemProxyStatus {
        enabled: false,
        ..Default::default()
    };
    // enabled=false → 不判自指，原样返回。
    let r = strip_self(Some(&status), "127.0.0.1", 8080, None);
    assert!(r.is_some());
}

#[test]
fn strip_self_none_when_status_none() {
    assert!(strip_self(None, "127.0.0.1", 8080, None).is_none());
}

#[test]
fn complete_snapshot_strips_active_self_but_preserves_other_services() {
    let self_service = MacProxyServiceSnapshot {
        service_id: "wifi".into(),
        service_name: "Wi-Fi".into(),
        service_enabled: true,
        had_proxy_protocol: true,
        protocol_enabled: true,
        configuration_plist: Some("<plist>polaris</plist>".into()),
        status: SystemProxyStatus {
            enabled: true,
            socks_proxy: Some("127.0.0.1:1080".into()),
            ..Default::default()
        },
        touched: None,
        clear_on_restore: false,
    };
    let external_service = MacProxyServiceSnapshot {
        service_id: "ethernet".into(),
        service_name: "Ethernet".into(),
        service_enabled: true,
        had_proxy_protocol: true,
        protocol_enabled: true,
        configuration_plist: Some("<plist>external</plist>".into()),
        status: SystemProxyStatus {
            enabled: true,
            http_proxy: Some("proxy.corp:3128".into()),
            ..Default::default()
        },
        touched: None,
        clear_on_restore: false,
    };

    let stripped = ProxyOriginalSettings {
        fallback: None,
        mac_services: vec![self_service, external_service.clone()],
        linux_gsettings: None,
        windows_registry: None,
    }
    .strip_self("127.0.0.1", 8080, 1080, None, None);

    assert!(stripped.mac_services[0].clear_on_restore);
    assert!(stripped.mac_services[0].configuration_plist.is_none());
    assert_eq!(
        stripped.mac_services[0].status,
        SystemProxyStatus::default()
    );
    assert_eq!(stripped.mac_services[1], external_service);
}

#[test]
fn repeated_takeover_reuses_previous_real_original_by_service_id() {
    let previous_service = MacProxyServiceSnapshot {
        service_id: "wifi".into(),
        service_name: "Wi-Fi".into(),
        service_enabled: true,
        had_proxy_protocol: true,
        protocol_enabled: true,
        configuration_plist: Some("<plist>external-original</plist>".into()),
        status: SystemProxyStatus {
            enabled: true,
            http_proxy: Some("proxy.corp:3128".into()),
            ..Default::default()
        },
        touched: None,
        clear_on_restore: false,
    };
    let previous = ProxyOriginalSettings {
        fallback: Some(previous_service.status.clone()),
        mac_services: vec![previous_service.clone()],
        linux_gsettings: None,
        windows_registry: None,
    };
    let captured_self = ProxyOriginalSettings {
        fallback: Some(SystemProxyStatus {
            enabled: true,
            http_proxy: Some("127.0.0.1:8080".into()),
            ..Default::default()
        }),
        mac_services: vec![MacProxyServiceSnapshot {
            service_id: "wifi".into(),
            status: SystemProxyStatus {
                enabled: true,
                http_proxy: Some("127.0.0.1:8080".into()),
                ..Default::default()
            },
            ..Default::default()
        }],
        linux_gsettings: None,
        windows_registry: None,
    };

    let stripped = captured_self.strip_self(
        "127.0.0.1",
        8080,
        1080,
        Some("127.0.0.1:8080"),
        Some(&previous),
    );

    assert_eq!(stripped, previous);
}

#[test]
fn complete_snapshot_preserves_disabled_self_shaped_values() {
    let service = MacProxyServiceSnapshot {
        service_id: "wifi".into(),
        configuration_plist: Some("<plist>disabled</plist>".into()),
        status: SystemProxyStatus {
            enabled: false,
            http_proxy: Some("127.0.0.1:8080".into()),
            ..Default::default()
        },
        ..Default::default()
    };
    let stripped = ProxyOriginalSettings {
        fallback: None,
        mac_services: vec![service.clone()],
        linux_gsettings: None,
        windows_registry: None,
    }
    .strip_self("127.0.0.1", 8080, 1080, None, None);
    assert_eq!(stripped.mac_services, vec![service]);
}

// ── restore_plan / split_host_port（Linux gsettings 恢复）──

#[test]
fn split_host_port_plain() {
    let hp = split_host_port(Some("proxy.lan:3128")).unwrap();
    assert_eq!(hp.host, "proxy.lan");
    assert_eq!(hp.port, 3128);
}

#[test]
fn split_host_port_bare_ipv6() {
    // 裸 IPv6 ::1:8080 → host=::1, port=8080（lastIndexOf ':'）
    let hp = split_host_port(Some("::1:8080")).unwrap();
    assert_eq!(hp.host, "::1");
    assert_eq!(hp.port, 8080);
}

#[test]
fn split_host_port_none_when_no_port() {
    assert!(split_host_port(Some("proxy")).is_none());
    assert!(split_host_port(None).is_none());
    assert!(split_host_port(Some(":8080")).is_none()); // 无 host
}

#[test]
fn split_host_port_none_when_port_out_of_range() {
    assert!(split_host_port(Some("h:0")).is_none());
    assert!(split_host_port(Some("h:65536")).is_none());
    assert!(split_host_port(Some("h:abc")).is_none());
}

#[test]
fn restore_plan_capture_three() {
    let snap = SystemProxyStatus {
        enabled: true,
        http_proxy: Some("h:80".into()),
        https_proxy: Some("h2:443".into()),
        socks_proxy: None, // 原本未设
        bypass_domains: None,
    };
    let plan = restore_plan(Some(&snap));
    assert_eq!(plan[0].schema, "http");
    assert_eq!(plan[0].hp.as_ref().unwrap().port, 80);
    assert_eq!(plan[1].hp.as_ref().unwrap().host, "h2");
    assert!(plan[2].hp.is_none()); // socks 原本未设 → None（清空）
}

#[test]
fn restore_plan_all_none_when_no_snap() {
    let plan = restore_plan(None);
    assert!(plan.iter().all(|e| e.hp.is_none()));
}

// ── 维度7 #8：marker 崩溃恢复场景编排（read_calls 验证读路径触发）──

#[test]
fn crash_recovery_marker_survives_and_is_readable() {
    // 模拟：enable 写 marker → 进程崩溃（marker 残留）→ 重启读 marker 判定有残留代理 → 清除。
    let fs = MemFs::new();
    let fs_clone = fs.clone();
    let marker = ProxyMarker::new(fs, "/m");

    // 会话1：enable 在系统修改前写完整 marker，尚未 disable 即崩溃。
    write_legacy(&marker, "127.0.0.1:8080", None);
    assert!(matches!(marker.read_checked(), ProxyMarkerRead::Legacy(_)));

    // 重启（新会话）：marker 文件仍在磁盘 → 读到 → 判定需恢复。
    let recovered = read_present(&marker);
    assert_eq!(recovered.our_host_port, "127.0.0.1:8080");
    // 确认确实读了 FS（崩溃恢复路径真触发了读取）。
    assert!(fs_clone.read_calls() >= 1);

    // 恢复成功后清 marker，下次启动不再误恢复。
    assert_eq!(
        marker.clear_legacy_if_current(&recovered),
        ProxyMarkerMutationOutcome::Updated
    );
    assert_eq!(marker.read_checked(), ProxyMarkerRead::Missing);
}

// ── 生产 MarkerFs（真实 FS；tempfile 隔离，不碰用户数据目录）──

#[test]
fn std_marker_fs_roundtrip_write_read_remove() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("system-proxy.marker.json");
    let p = path.to_str().unwrap();
    let fs = StdMarkerFs;

    assert_eq!(fs.read_marker(p), None, "未写入 → None");
    fs.write_marker(p, r#"{"ourHostPort":"127.0.0.1:8080"}"#)
        .unwrap();
    assert_eq!(
        fs.read_marker(p).as_deref(),
        Some(r#"{"ourHostPort":"127.0.0.1:8080"}"#)
    );
    fs.remove_marker(p).unwrap();
    assert_eq!(fs.read_marker(p), None, "删后 → None");
}

/// `force` 语义：删不存在的 marker 必须 Ok —— 这是 `ensure_cleared` 幂等性的地基。
/// 若此处返 Err，重复清理会把错误一路冒到终态点。
#[test]
fn std_marker_fs_remove_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("never-existed.json");
    let p = p.to_str().unwrap();
    StdMarkerFs
        .remove_marker(p)
        .expect("不存在不得报错（force 语义）");
    StdMarkerFs.remove_marker(p).expect("重复删仍 Ok");
}

#[test]
fn std_marker_fs_creates_missing_parent_dir() {
    // userData 目录首次运行可能不存在 → 写 marker 不得因此失败。
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested/sub/dir/marker.json");
    let p = path.to_str().unwrap();
    StdMarkerFs.write_marker(p, "{}").expect("须自动建父目录");
    assert_eq!(StdMarkerFs.read_marker(p).as_deref(), Some("{}"));
}

#[test]
fn std_marker_fs_replaces_existing_content_without_temp_residue() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("marker.json");
    let p = path.to_str().unwrap();

    StdMarkerFs.write_marker(p, "old").unwrap();
    StdMarkerFs
        .write_marker(p, "new-complete-snapshot")
        .unwrap();

    assert_eq!(
        StdMarkerFs.read_marker(p).as_deref(),
        Some("new-complete-snapshot")
    );
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        1,
        "成功替换后不得留下临时文件"
    );
}

#[test]
fn std_marker_fs_corrupt_content_yields_invalid_marker() {
    // 损坏内容 → strict read 明确阻断，不能折成 Missing。
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("m.json");
    std::fs::write(&path, "{not json").unwrap();
    let marker = ProxyMarker::new(StdMarkerFs, path.to_str().unwrap());
    assert!(matches!(marker.read_checked(), ProxyMarkerRead::Invalid(_)));
}

/// 端到端：生产 FS 上的 marker 跨「进程」存活（崩溃恢复的真实载体）。
#[test]
fn std_marker_fs_survives_across_marker_instances() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("system-proxy.marker.json");
    let p = path.to_str().unwrap();

    // 会话1：写 marker 后「崩溃」。
    let original = SystemProxyStatus {
        enabled: true,
        http_proxy: Some("proxy.corp:3128".into()),
        ..Default::default()
    };
    write_legacy(
        &ProxyMarker::new(StdMarkerFs, p),
        "127.0.0.1:8080",
        Some(&original),
    );

    // 会话2（「重启」）：读回同一磁盘文件，含原始快照。
    let m2 = ProxyMarker::new(StdMarkerFs, p);
    let data = read_present(&m2);
    assert_eq!(data.our_host_port, "127.0.0.1:8080");
    assert_eq!(
        data.original_settings
            .as_ref()
            .unwrap()
            .http_proxy
            .as_deref(),
        Some("proxy.corp:3128")
    );
    assert_eq!(
        m2.clear_legacy_if_current(&data),
        ProxyMarkerMutationOutcome::Updated
    );
    assert_eq!(m2.read_checked(), ProxyMarkerRead::Missing);
}
