use super::super::*;

#[test]
fn unsaved_config_only_blocks_starting_from_stopped_state() {
    assert!(!should_block_unsaved_start(false, false));
    assert!(should_block_unsaved_start(false, true));
    assert!(!should_block_unsaved_start(true, false));
    assert!(!should_block_unsaved_start(true, true));
}

// ── C10 pure 决策面（对齐 上游 custom-protocol-probe.test.ts 的包裹/判定断言）──

#[test]
fn validate_rejects_non_object_and_missing_or_nonstring_type() {
    // 对象 + string type → Ok。
    assert!(validate_probe_outbound(&json!({ "type": "snell", "server": "1.2.3.4" })).is_ok());
    // 空串 type 仍是 string → 放行到 check（check 会拒），= 上游 `typeof type === 'string'`。
    assert!(validate_probe_outbound(&json!({ "type": "" })).is_ok());
    // 非对象（数组 / 标量 / 串）→ Err，不触发 check。
    assert!(validate_probe_outbound(&json!([1, 2, 3])).is_err());
    assert!(validate_probe_outbound(&json!("snell")).is_err());
    assert!(validate_probe_outbound(&json!(42)).is_err());
    // 对象但无 type / type 非串 → Err。
    assert!(validate_probe_outbound(&json!({ "server": "1.2.3.4" })).is_err());
    assert!(validate_probe_outbound(&json!({ "type": 4 })).is_err());
    // 错误文案含 "type"（前端据此提示）。
    assert!(validate_probe_outbound(&json!({}))
        .unwrap_err()
        .contains("type"));
}

#[test]
fn build_probe_config_outbound_path_wraps_probe_and_direct() {
    let ob = json!({ "type": "snell", "server": "1.2.3.4", "psk": "k", "version": 4 });
    let cfg = build_probe_config(&ob, false);
    // outbounds:[{...snell, tag:'probe'}, {direct}]，route.final='direct'，log.level='fatal'。
    assert_eq!(cfg["outbounds"][0]["type"], "snell");
    assert_eq!(cfg["outbounds"][0]["tag"], "probe");
    assert_eq!(cfg["outbounds"][0]["psk"], "k", "原字段须保留");
    assert!(cfg["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .any(|o| o["type"] == "direct"));
    assert_eq!(cfg["route"]["final"], "direct");
    assert_eq!(cfg["log"]["level"], "fatal");
    // 非 endpoint 路径不产 endpoints 键。
    assert!(cfg.get("endpoints").is_none());
}

#[test]
fn build_probe_config_endpoint_path_uses_endpoints_and_direct_only_outbounds() {
    let ep = json!({ "type": "wireguard", "server": "1.2.3.4" });
    let cfg = build_probe_config(&ep, true);
    assert_eq!(cfg["endpoints"][0]["type"], "wireguard");
    assert_eq!(cfg["endpoints"][0]["tag"], "probe");
    // endpoint 路径 outbounds 仅兜底 direct（无 probe 节点混入 outbounds）。
    let obs = cfg["outbounds"].as_array().unwrap();
    assert!(obs.iter().all(|o| o["type"] == "direct"));
    assert_eq!(cfg["route"]["final"], "direct");
}

#[test]
fn probe_verdict_maps_three_states_distinctly() {
    // Supported → {ok:true}，无 indeterminate/error。
    let ok = probe_verdict(ProbeCheck::Supported);
    assert_eq!(ok["ok"], true);
    assert!(ok.get("indeterminate").is_none());
    assert!(ok.get("error").is_none());
    // Indeterminate → {ok:false, indeterminate:true}（中性无法判定，**非** error-only 的红色不支持）。
    let ind = probe_verdict(ProbeCheck::Indeterminate);
    assert_eq!(ind["ok"], false);
    assert_eq!(ind["indeterminate"], true);
    // Unsupported → {ok:false, error, errorRaw}，**无 indeterminate**（红色不支持，透传诊断）。
    let no = probe_verdict(ProbeCheck::Unsupported(ProbeDiagnostic {
        path: None,
        message: "unknown outbound type: snell".to_string(),
        raw: "unknown outbound type: snell".to_string(),
    }));
    assert_eq!(no["ok"], false);
    assert!(
        no.get("indeterminate").is_none(),
        "不支持不得带 indeterminate"
    );
    assert!(no["error"]
        .as_str()
        .unwrap()
        .contains("unknown outbound type"));
    assert_eq!(no["errorRaw"], "unknown outbound type: snell");
    // path=None → `errorPath` 键整个不下发（不是空串）：前端用 `in`/`?.` 判「没有」才不会
    // 把 "" 误当成一个（空的）键路径展示出来。
    assert!(
        no.get("errorPath").is_none(),
        "未解析出键路径时 errorPath 不得下发"
    );
}

/// `probe_verdict` 对带路径的 Unsupported：`errorPath` 逐字带回。
#[test]
fn probe_verdict_unsupported_carries_error_path_when_present() {
    let v = probe_verdict(ProbeCheck::Unsupported(ProbeDiagnostic {
        path: Some("outbounds[0].tls.utls.fingerprint".to_string()),
        message: "json: cannot unmarshal number into Go struct field \
                      OutboundUTLSOptions.OutboundTLSOptionsContainer.tls.utls.fingerprint \
                      of type string"
            .to_string(),
        raw: "FATAL[0000] decode config at /tmp/x.json: outbounds[0].tls.utls.fingerprint: \
                  json: cannot unmarshal number into Go struct field \
                  OutboundUTLSOptions.OutboundTLSOptionsContainer.tls.utls.fingerprint of type string"
            .to_string(),
    }));
    assert_eq!(v["errorPath"], "outbounds[0].tls.utls.fingerprint");
    assert!(v["error"].as_str().unwrap().contains("cannot unmarshal"));
    assert!(v["errorRaw"].as_str().unwrap().contains("decode config at"));
}

/// **failOpen 门**：核缺失（spawn 失败）→ Indeterminate（不碰网络、不需真核；确定性可跑）。
/// 打断 `Ok(Err(_)) => Indeterminate`（改成 Unsupported）→ 本测转红：把「核缺失」谎报成「不支持」。
#[tokio::test]
async fn run_probe_check_core_missing_is_indeterminate_not_unsupported() {
    let check = run_probe_check(
        std::path::Path::new("/nonexistent/polaris-sing-box-xyz"),
        std::path::Path::new("/nonexistent/probe.json"),
    )
    .await;
    assert!(
        matches!(check, ProbeCheck::Indeterminate),
        "核缺失（spawn ENOENT）必须 failOpen → Indeterminate，绝不谎报 Unsupported"
    );
    // verdict 形态：indeterminate:true（中性）。
    assert_eq!(probe_verdict(check)["indeterminate"], true);
}

// ── A1 起核失败 → 信封映射（码来自 Err 自身，绝不回读全局 status）───────────────────────

/// 带码腿：分类原样落进信封 `code`，渲染端据此分流可操作引导。
#[test]
fn start_err_response_carries_code_from_the_error_itself() {
    let r = start_err_response(StartError::from("x".to_string()));
    assert!(!r.success);
    // 无码腿必须**没有** code：`HomeScreen` 的取消腿按 code 命中，编一个码 = 把真错误伪装成用户取消。
    assert_eq!(r.code, None, "无码腿不得凭空补码");
    assert_eq!(r.error.as_deref(), Some("x"));
}

/// 有码腿：逐字带回（变异：改成 `ApiResponse::err(e.message)` 丢码 → 红，前端只能拿 message 猜分类）。
#[test]
fn start_err_response_preserves_structured_code() {
    use crate::runtime::proxy::code;
    let e = StartError {
        message: "已取消".to_string(),
        code: Some(code::HELPER_GATE_ABORTED),
    };
    let r = start_err_response(e);
    assert_eq!(r.code.as_deref(), Some(code::HELPER_GATE_ABORTED));
    assert_eq!(r.error.as_deref(), Some("已取消"));
}
