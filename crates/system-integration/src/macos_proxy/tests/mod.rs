use super::*;

const EMPTY_DICT: &str = r#"<plist version="1.0"><dict/></plist>"#;
const ONE: &str = r#"<plist version="1.0"><integer>1</integer></plist>"#;

fn service(id: &str, present: bool) -> MacProxyServiceSnapshot {
    MacProxyServiceSnapshot {
        service_id: id.into(),
        service_name: format!("service-{id}"),
        service_enabled: true,
        had_proxy_protocol: present,
        protocol_enabled: present,
        configuration_plist: present.then(|| EMPTY_DICT.into()),
        touched: Some(MacProxyTouchedSnapshot {
            protocol_present: present,
            protocol_enabled: present,
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn enabled_service(id: &str) -> MacProxyServiceSnapshot {
    let mut snapshot = service(id, true);
    let touched = snapshot.touched.as_mut().unwrap();
    touched.http_enabled = MacProxyPropertyValue::PropertyListXml(ONE.into());
    touched.http_host = MacProxyPropertyValue::PropertyListXml(
        r#"<plist version="1.0"><string>127.0.0.1</string></plist>"#.into(),
    );
    touched.http_port = MacProxyPropertyValue::PropertyListXml(
        r#"<plist version="1.0"><integer>7890</integer></plist>"#.into(),
    );
    snapshot
}

#[test]
fn helper_payload_roundtrips_without_raw_newlines() {
    let request = ProxyEnableRequest {
        address: "127.0.0.1".into(),
        http_port: 7890,
        socks_port: 7891,
        bypass_list: vec!["localhost".into(), "*.example.com".into()],
    };
    let encoded = enable_transaction_payload(&request, vec!["service-1".into()]).unwrap();
    assert!(encoded.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(matches!(
        decode_transaction(&encoded).unwrap(),
        HelperTransaction::Enable {
            address,
            http_port: 7890,
            socks_port: 7891,
            service_ids,
            ..
        } if address == "127.0.0.1" && service_ids == ["service-1"]
    ));
}

#[test]
fn helper_payload_rejects_empty_service_scope_and_malformed_hex() {
    let request = ProxyEnableRequest {
        address: "127.0.0.1".into(),
        http_port: 7890,
        socks_port: 7890,
        bypass_list: Vec::new(),
    };
    assert!(enable_transaction_payload(&request, Vec::new()).is_err());
    assert!(decode_transaction("abc").is_err());
    assert!(decode_transaction("zz").is_err());
}

#[test]
fn restore_payload_preserves_complete_plist_snapshot() {
    let snapshot = MacProxyServiceSnapshot {
        service_id: "service-1".into(),
        service_name: "Wi-Fi".into(),
        service_enabled: true,
        had_proxy_protocol: true,
        protocol_enabled: true,
        configuration_plist: Some(EMPTY_DICT.into()),
        touched: Some(MacProxyTouchedSnapshot {
            protocol_present: true,
            protocol_enabled: true,
            ..Default::default()
        }),
        ..Default::default()
    };
    let encoded = restore_transaction_payload(std::slice::from_ref(&snapshot)).unwrap();
    let HelperTransaction::Restore { snapshots } = decode_transaction(&encoded).unwrap() else {
        panic!("expected restore payload");
    };
    assert_eq!(snapshots, vec![snapshot]);
}

#[test]
fn ownership_is_one_to_one_by_stable_id_and_touched_members() {
    let a = enabled_service("a");
    let b = enabled_service("b");
    assert!(ownership_matches(
        &[a.clone(), b.clone()],
        &[a.clone(), b.clone()]
    ));
    assert!(ownership_matches(
        &[a.clone(), b.clone()],
        &[b.clone(), a.clone()]
    ));
    assert!(!ownership_matches(
        &[a.clone(), b.clone()],
        std::slice::from_ref(&a)
    ));
    assert!(!ownership_matches(
        std::slice::from_ref(&a),
        &[a.clone(), b]
    ));
}

#[test]
fn relation_ignores_unowned_pac_auto_and_full_plist_for_existing_protocol() {
    let from = enabled_service("a");
    let to = from.clone();
    let mut current = to.clone();
    current.configuration_plist = Some(
        r#"<plist version="1.0"><dict><key>ProxyAutoConfigEnable</key><true/></dict></plist>"#
            .into(),
    );

    assert_eq!(
        mac_snapshot_relation(&[from], &[to], &[current]),
        ProxySnapshotRelation::Exact
    );
}

#[test]
fn absent_protocol_removal_rejects_concurrent_user_pac() {
    let original = service("a", false);
    let expected = enabled_service("a");
    let mut current = expected.clone();
    current.configuration_plist = Some(
        r#"<plist version="1.0"><dict><key>ProxyAutoConfigURLString</key><string>https://pac.example/proxy.pac</string></dict></plist>"#
            .into(),
    );

    assert!(ownership_matches(
        std::slice::from_ref(&expected),
        std::slice::from_ref(&current)
    ));
    assert!(validate_absent_protocol_removal(&[original], &[expected], &[current]).is_err());
}

#[test]
fn v2_payloads_accept_reorder_but_reject_wrong_scope_and_invalid_bypass() {
    let a = service("a", false);
    let b = service("b", false);
    let request = ProxyEnableRequest {
        address: "127.0.0.1".into(),
        http_port: 7890,
        socks_port: 7891,
        bypass_list: vec!["bad\nentry".into()],
    };
    assert!(enable_transaction_payload_v2(
        &request,
        std::slice::from_ref(&a),
        std::slice::from_ref(&a),
    )
    .is_err());

    let valid_request = ProxyEnableRequest {
        bypass_list: vec!["localhost".into()],
        ..request
    };
    assert!(enable_transaction_payload_v2(
        &valid_request,
        &[a.clone(), b.clone()],
        &[b.clone(), a.clone()],
    )
    .is_ok());
    assert!(
        restore_transaction_payload_v2(&[a.clone(), b.clone()], &[b.clone(), a.clone()],).is_ok()
    );
    assert!(
        restore_transaction_payload_v2(std::slice::from_ref(&a), std::slice::from_ref(&b),)
            .is_err()
    );
}

#[test]
fn v2_compare_enable_and_restore_payloads_roundtrip_through_codec() {
    let base = service("a", false);
    let desired = enabled_service("a");
    let request = ProxyEnableRequest {
        address: "127.0.0.1".into(),
        http_port: 7890,
        socks_port: 7891,
        bypass_list: vec!["localhost".into()],
    };

    let enable = enable_transaction_payload_v2(
        &request,
        std::slice::from_ref(&base),
        std::slice::from_ref(&desired),
    )
    .unwrap();
    assert!(matches!(
        decode_transaction(&enable).unwrap(),
        HelperTransaction::CompareEnable {
            address,
            expected_base,
            desired: decoded_desired,
            ..
        } if address == "127.0.0.1" && expected_base == [base.clone()] && decoded_desired == [desired.clone()]
    ));

    let restore =
        restore_transaction_payload_v2(std::slice::from_ref(&base), std::slice::from_ref(&desired))
            .unwrap();
    assert!(matches!(
        decode_transaction(&restore).unwrap(),
        HelperTransaction::CompareRestore {
            originals,
            expected_current,
        } if originals == [base] && expected_current == [desired]
    ));
}

#[test]
fn compare_codec_rejects_invalid_payload_and_every_invalid_bypass_shape() {
    for payload in ["", "0", "zz", "7b7d"] {
        assert!(execute_transaction(payload).is_err());
    }

    let base = service("a", false);
    let desired = enabled_service("a");
    for invalid in [
        "nul\0entry".to_string(),
        "cr\rentry".to_string(),
        "lf\nentry".to_string(),
        "x".repeat(4097),
    ] {
        let request = ProxyEnableRequest {
            address: "127.0.0.1".into(),
            http_port: 7890,
            socks_port: 7891,
            bypass_list: vec![invalid],
        };
        assert!(enable_transaction_payload_v2(
            &request,
            std::slice::from_ref(&base),
            std::slice::from_ref(&desired),
        )
        .is_err());
    }

    let wrong_scope = encode_transaction(&HelperTransaction::CompareRestore {
        originals: vec![service("a", false)],
        expected_current: vec![enabled_service("b")],
    })
    .unwrap();
    assert!(
        execute_transaction(&wrong_scope).is_err(),
        "pair validation must reject before opening SCPreferences"
    );
}

fn preferences_failure(kind: PreferencesFailureKind) -> PreferencesFailure {
    PreferencesFailure {
        kind,
        detail: format!("{kind:?}"),
    }
}

#[test]
fn preferences_lock_retries_only_busy_before_any_mutation() {
    let mut attempts = 0;
    let mut waits = Vec::new();
    let result = retry_preferences_lock_with(
        || {
            attempts += 1;
            if attempts < PREFERENCES_LOCK_MAX_ATTEMPTS {
                Err(preferences_failure(PreferencesFailureKind::LockBusy))
            } else {
                Ok("locked")
            }
        },
        |delay| waits.push(delay),
    );
    assert_eq!(result.unwrap(), "locked");
    assert_eq!(attempts, 3);
    assert_eq!(waits, vec![PREFERENCES_LOCK_RETRY_DELAY; 2]);
    assert!(waits.into_iter().sum::<Duration>() <= PREFERENCES_LOCK_TOTAL_TIMEOUT);
}

#[test]
fn preferences_lock_never_retries_other_or_commit_unknown() {
    for kind in [
        PreferencesFailureKind::Other,
        PreferencesFailureKind::CommitUnknown,
    ] {
        let mut attempts = 0;
        let result = retry_preferences_lock_with(
            || {
                attempts += 1;
                Err::<(), _>(preferences_failure(kind))
            },
            |_| panic!("non-busy failures must not wait"),
        );
        assert_eq!(result.unwrap_err().kind, kind);
        assert_eq!(attempts, 1);
    }
}

#[test]
fn preferences_lock_busy_exhausts_at_explicit_attempt_cap() {
    let mut attempts = 0;
    let result = retry_preferences_lock_with(
        || {
            attempts += 1;
            Err::<(), _>(preferences_failure(PreferencesFailureKind::LockBusy))
        },
        |_| {},
    );
    assert_eq!(result.unwrap_err().kind, PreferencesFailureKind::LockBusy);
    assert_eq!(attempts, PREFERENCES_LOCK_MAX_ATTEMPTS);
}
