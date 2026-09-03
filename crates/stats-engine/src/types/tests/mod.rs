use super::*;

/// 出 IPC 的 JSON 键名必须逐字等于 TS 契约 `ConnectionEntry.metadata`
/// （`ui/src/contracts/types/runtime.ts`）。
///
/// 这条门存在的理由是它抓到过的那次回归：整个结构漏了 serde 重命名，八个字段只有
/// `host`/`network` 送达，前端「目标」「进程」两列恒 `—`。**没有任何既有门会红** ——
/// Rust 侧类型自洽、TS 侧类型自洽，错的只是两侧对同一个 JSON 的命名约定，
/// 而那份 JSON 从不被任何一侧的类型系统看见。
///
/// 判据是**全等**而非「包含」：多出的键同样是错（前端读不到 = 白送流量，
/// 且说明两侧又对不上了）。
#[test]
fn connection_metadata_json_keys_match_ts_contract() {
    let m = ConnectionMetadata {
        host: Some("example.com".into()),
        destination_ip: Some("1.2.3.4".into()),
        network: Some("tcp".into()),
        inbound_type: Some("Tun".into()),
        source_ip: Some("192.168.1.2".into()),
        source_port: Some("54321".into()),
        destination_port: Some("443".into()),
        process_path: Some("/usr/bin/curl".into()),
    };
    let v = serde_json::to_value(&m).expect("metadata 应可序列化");
    let mut got: Vec<&str> = v
        .as_object()
        .expect("metadata 应是 JSON 对象")
        .keys()
        .map(String::as_str)
        .collect();
    got.sort_unstable();
    let mut want = [
        "host",
        "destinationIP",
        "network",
        "type",
        "sourceIP",
        "sourcePort",
        "destinationPort",
        "processPath",
    ];
    want.sort_unstable();
    assert_eq!(got, want, "metadata 的 JSON 键名与 TS 契约不一致");
}

/// 🔴 出 IPC 的 JSON 键名必须逐字等于 TS 契约 `TrafficStats`
/// （`ui/src/contracts/types/runtime.ts:257`）。
///
/// 与 `connection_metadata_json_keys_match_ts_contract` 同一类风险，只是这条更晚才成立：
/// 本结构此前从不出 IPC（`runtime/stats.rs` 手拼 `json!` 逐个写 camelCase 键），改成直接
/// `Serialize` 之后，缺 `rename_all` 就会整帧变成 `upload_speed` 这类下划线名 ——
/// **Rust 侧与 TS 侧各自自洽、两边类型系统都不报错**，表现只是状态栏五个数字全空。
///
/// 判据是**全等**而非「包含」：多出的键同样是错（前端读不到 = 白送流量）。
#[test]
fn traffic_stats_json_keys_match_ts_contract() {
    let v = serde_json::to_value(TrafficStats::zeroed()).expect("TrafficStats 应可序列化");
    let mut got: Vec<&str> = v
        .as_object()
        .expect("TrafficStats 应是 JSON 对象")
        .keys()
        .map(String::as_str)
        .collect();
    got.sort_unstable();
    let mut want = [
        "uploadSpeed",
        "downloadSpeed",
        "totalUpload",
        "totalDownload",
        "activeConnections",
    ];
    want.sort_unstable();
    assert_eq!(got, want, "TrafficStats 的 JSON 键名与 TS 契约不一致");
}

#[test]
fn closed_update_json_keys_match_ts_contract() {
    let v = serde_json::to_value(ConnectionsClosedUpdate {
        reset: false,
        connections: Vec::new(),
        removed_ids: vec!["gone".into()],
        at: 1,
    })
    .expect("ConnectionsClosedUpdate 应可序列化");
    let mut got: Vec<&str> = v
        .as_object()
        .expect("closed update 应是 JSON 对象")
        .keys()
        .map(String::as_str)
        .collect();
    got.sort_unstable();
    let mut want = ["reset", "connections", "removedIds", "at"];
    want.sort_unstable();
    assert_eq!(got, want, "closed update 的 JSON 键名与 TS 契约不一致");
}

#[test]
fn detail_update_json_keys_match_ts_contract() {
    let v = serde_json::to_value(ConnectionsDetailUpdate {
        reset: false,
        generation: 2,
        sequence: 3,
        connections: Vec::new(),
        counters: vec![ConnectionCounters {
            id: "live".into(),
            upload: 1,
            download: 2,
        }],
        removed_ids: vec!["gone".into()],
        at: 4,
    })
    .expect("ConnectionsDetailUpdate 应可序列化");
    let object = v.as_object().expect("detail update 应是 JSON 对象");
    let mut got: Vec<&str> = object.keys().map(String::as_str).collect();
    got.sort_unstable();
    let mut want = [
        "reset",
        "generation",
        "sequence",
        "connections",
        "counters",
        "removedIds",
        "at",
    ];
    want.sort_unstable();
    assert_eq!(got, want, "detail update 的 JSON 键名与 TS 契约不一致");
    assert_eq!(
        object["counters"][0],
        serde_json::json!({ "id": "live", "upload": 1, "download": 2 })
    );
}

/// 重命名后**反序列化仍认得自己写出去的键**（Serialize/Deserialize 对称）。
/// 不对称的话，任何「序列化落盘 → 读回」的路径都会静默丢字段。
#[test]
fn connection_metadata_roundtrips_through_json() {
    let m = ConnectionMetadata {
        host: Some("a.example".into()),
        destination_ip: Some("9.9.9.9".into()),
        inbound_type: Some("HTTP".into()),
        source_ip: Some("10.0.0.1".into()),
        ..Default::default()
    };
    let back: ConnectionMetadata =
        serde_json::from_value(serde_json::to_value(&m).unwrap()).unwrap();
    assert_eq!(back, m);
}
