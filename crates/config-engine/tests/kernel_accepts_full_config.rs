//! 🔴 **随包核真的收得下完整生成配置吗**。
//!
//! 这是出站面门的补集：不剥 `inbounds` / `route` / `dns.rules` / `experimental`，用仓内真实
//! `resources/data/*.srs` 逐份喂给 `sing-box check`。它不替代运行时的
//! `core-supervisor::config_gate`：后者面向用户真实配置、起核时可 fail-open/剥节点；本文件是
//! 固定 37 份生成 fixture 的 fail-closed 回归门。
//!
//! `check` 只 decode + initialize，绝不 Start：不绑端口、不启动 TUN、不联网。因此 selector 的
//! Start-only missing tag 仍是已知边界，继续由运行时配置闸门与引用修剪链负责。

mod support;

use std::collections::BTreeMap;
use std::path::Path;

use polaris_config_engine::builder::generate_sing_box_config;
use polaris_config_engine::user_config::proxy_mode::ProxyModeType;
use serde_json::{json, Value};
use support::core_locator::{
    bundled_core_candidates_for, command_for_core_target, kernel_gate_target, target_needs_rosetta,
};
use support::kernel_gate::{
    check, core_or_skip, full_config_deps, load_cases, FixtureRatchet, SnapshotCase,
};
use tempfile::tempdir;

const OUTBOUNDS_GATE: &str = "cargo test -p polaris-config-engine --test kernel_accepts_outbounds";
const FULL_CONFIG_GATE: &str =
    "cargo test -p polaris-config-engine --test kernel_accepts_full_config";

fn workflow(name: &str) -> String {
    let path = support::kernel_gate::repo_root().join(format!(".github/workflows/{name}.yml"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("读不到 {}: {e}", path.display()))
}

fn assert_hardened_full_gate_after_outbounds(raw: &str, workflow_name: &str) {
    let outbounds = raw
        .find(OUTBOUNDS_GATE)
        .unwrap_or_else(|| panic!("{workflow_name} 缺出站真核门"));
    let full = raw
        .find(FULL_CONFIG_GATE)
        .unwrap_or_else(|| panic!("{workflow_name} 缺完整配置真核门"));
    assert!(
        outbounds < full,
        "{workflow_name} 的完整配置门必须排在出站真核门之后"
    );
    let step_start = raw[..full]
        .rfind("\n      - name:")
        .unwrap_or_else(|| panic!("{workflow_name} 完整配置门前缺 workflow step 边界"));
    let after_step = &raw[step_start..];
    let step_end = after_step[1..]
        .find("\n      - name:")
        .map_or(after_step.len(), |offset| offset + 1);
    let step = &after_step[..step_end];
    assert!(
        step.contains("POLARIS_REQUIRE_KERNEL_GATE: '1'"),
        "{workflow_name} 的完整配置门必须硬化：缺随包核不得静默跳过"
    );
}

/// Production management API requires exactly one API service in every full configuration.
fn assert_api_service_shape(case: &SnapshotCase, value: &Value) -> (bool, bool) {
    let services = value["services"]
        .as_array()
        .unwrap_or_else(|| panic!("{} 未生成 services；完整门被静默削面", case.name));
    assert_eq!(
        services.len(),
        1,
        "{} 必须恰有一个 service，实际 services：{services:?}",
        case.name
    );
    let api: Vec<&Value> = services
        .iter()
        .filter(|service| service["type"].as_str() == Some("api"))
        .collect();
    assert_eq!(
        api.len(),
        1,
        "{} 必须恰有一个 api service，实际 services：{services:?}",
        case.name
    );
    assert_eq!(
        api[0]["listen_port"].as_u64(),
        Some(19090),
        "{} 的 api service 必须下发固定测试端口 19090",
        case.name
    );
    let expected_dashboard = case.input.singbox_dashboard == Some(true);
    let actual_dashboard = api[0].get("dashboard").is_some_and(Value::is_object);
    assert_eq!(
        actual_dashboard, expected_dashboard,
        "{} 的 dashboard presence 未跟随 singboxDashboard 真值",
        case.name
    );
    (expected_dashboard, actual_dashboard)
}

/// CI 每次只在当前宿主执行一支，故用纯函数锁全部打包目标、宿主 fallback 与 x64 Rosetta wrapper。
#[test]
fn bundled_core_target_resolution_contract() {
    assert_eq!(
        bundled_core_candidates_for("linux"),
        &["resources/linux/sing-box"]
    );
    assert_eq!(
        bundled_core_candidates_for("windows"),
        &["resources/win/sing-box.exe"]
    );
    assert_eq!(
        bundled_core_candidates_for("macos-arm64"),
        &["resources/mac-arm64/sing-box"]
    );
    assert_eq!(
        bundled_core_candidates_for("macos-x64"),
        &["resources/mac-x64/sing-box"]
    );
    assert!(matches!(
        kernel_gate_target().as_str(),
        "linux" | "windows" | "macos-arm64" | "macos-x64"
    ));
    assert!(!target_needs_rosetta("linux"));
    assert!(!target_needs_rosetta("windows"));
    assert!(!target_needs_rosetta("macos-arm64"));
    assert!(target_needs_rosetta("macos-x64"));
    let command = command_for_core_target("macos-x64", Path::new("resources/mac-x64/sing-box"));
    assert_eq!(command.get_program(), "/usr/bin/arch");
    assert_eq!(
        command.get_args().collect::<Vec<_>>(),
        ["-x86_64", "resources/mac-x64/sing-box"]
    );
}

/// 打包腿才有刚下载的核与 cronet；CI 常规腿不拉核，在那里挂 REQUIRE=1 是永久假红。
#[test]
fn package_workflow_runs_full_gate_after_cronet_and_outbounds_gate() {
    let raw = workflow("package");
    assert!(
        raw.contains("POLARIS_KERNEL_GATE_TARGET: ${{ matrix.label }}"),
        "package 的真核门必须接收 matrix.label；macos-x64 不能按 arm64 宿主误选核"
    );
    let cronet_linux = raw
        .find("run: node scripts/fetch-cronet.mjs --platform=linux")
        .expect("package.yml 缺 Linux Cronet SO 拉取；Linux 真核门不能初始化 naive");
    let cronet_windows = raw
        .find("run: node scripts/fetch-cronet.mjs --platform=win")
        .expect("package.yml 缺 Windows Cronet DLL 拉取；Windows 真核门不能初始化 naive");
    let outbounds = raw.find(OUTBOUNDS_GATE).expect("package.yml 缺出站真核门");
    let full = raw
        .find(FULL_CONFIG_GATE)
        .expect("package.yml 缺完整配置真核门");
    assert!(
        cronet_linux < outbounds && cronet_windows < outbounds,
        "Linux SO 与 Windows DLL 的拉取都必须早于第一道出站真核门"
    );
    assert!(outbounds < full, "完整配置门必须位于出站真核门之后");
    assert!(
        raw.contains(
            "- name: Fetch cronet library (Linux, SHA256-pinned)\n        if: runner.os == 'Linux'\n        run: node scripts/fetch-cronet.mjs --platform=linux"
        ),
        "package.yml 的 Linux 腿必须只拉 libcronet.so"
    );
    assert!(
        raw.contains(
            "- name: Fetch cronet library (Windows, SHA256-pinned)\n        if: runner.os == 'Windows'\n        run: node scripts/fetch-cronet.mjs --platform=win"
        ),
        "package.yml 的 Windows 腿必须只拉 libcronet.dll"
    );
    assert_eq!(
        raw.matches("run: node scripts/fetch-cronet.mjs").count(),
        2,
        "package.yml 只能有 Linux/Windows 两个动态 Cronet 拉取步骤；macOS 的 cronet 静态编入核心"
    );
    assert_hardened_full_gate_after_outbounds(&raw, "package.yml");
}

/// release-risk 禁用 package.yml 的 `POLARIS_RUN_KERNEL_GATES`，故自身的 mandatory 步必须显式执行完整门。
#[test]
fn release_risk_runs_hardened_full_gate_after_cronet_and_outbounds_gate() {
    let raw = workflow("release-risk");
    let cronet = raw
        .find("run: node scripts/fetch-cronet.mjs --platform=linux")
        .expect("release-risk.yml 缺 Linux Cronet SO 拉取；Ubuntu 真核门不能初始化 naive");
    let full = raw
        .find(FULL_CONFIG_GATE)
        .expect("release-risk.yml 缺完整配置真核门");
    assert!(
        cronet < full,
        "release-risk 的完整配置门必须位于 Linux Fetch cronet 之后"
    );
    assert_eq!(
        raw.matches("run: node scripts/fetch-cronet.mjs").count(),
        1,
        "release-risk 的 Ubuntu 预检只应拉 Linux Cronet SO"
    );
    assert!(
        raw.contains(
            "- name: Fetch cronet library (Linux)\n        if: needs.classify.outputs.kernel == 'true'\n        run: node scripts/fetch-cronet.mjs --platform=linux"
        ),
        "release-risk 的 Ubuntu 预检必须显式只拉 Linux Cronet SO"
    );
    assert!(
        raw.contains("Run mandatory bundled-core gates")
            && raw.contains("if: needs.classify.outputs.kernel == 'true'"),
        "release-risk 的完整配置门必须留在 kernel 影响触发的 mandatory job"
    );
    assert_hardened_full_gate_after_outbounds(&raw, "release-risk.yml");
}

/// 全量 37 个 fixture 必须逐一生成、使用真实 `.srs` 资源并由同一凭据棘轮判定。
#[test]
fn bundled_core_accepts_every_full_generated_config() {
    let Some(core) = core_or_skip("完整生成配置加载门") else {
        return;
    };
    let temp = tempdir().expect("建 TempDir");
    let mut ratchet = FixtureRatchet::default();
    let mut tun_cases = 0usize;
    let mut expected_dashboards = 0usize;
    let mut actual_dashboards = 0usize;

    for case in load_cases() {
        let deps = full_config_deps(&case, &temp);
        let cfg = generate_sing_box_config(&case.input, &BTreeMap::new(), &deps)
            .unwrap_or_else(|e| panic!("{} 生成完整配置失败: {e}", case.name));
        let value = serde_json::to_value(&cfg).expect("完整配置序列化");
        let (expected_dashboard, actual_dashboard) = assert_api_service_shape(&case, &value);
        expected_dashboards += usize::from(expected_dashboard);
        actual_dashboards += usize::from(actual_dashboard);
        let path = temp.path().join(format!("full-{}.json", ratchet.checked));
        std::fs::write(&path, serde_json::to_vec_pretty(&value).expect("JSON 编码"))
            .expect("写完整配置到 TempDir");
        let (ok, diag) = check(&core, &path);
        if case.input.proxy_mode_type == ProxyModeType::Tun {
            tun_cases += 1;
            assert!(
                ok,
                "TUN case 不得豁免或落入凭据 artifact：{} → {diag}",
                case.name
            );
        }
        ratchet.record(&case.name, ok, &diag);
    }

    assert_eq!(
        tun_cases, 8,
        "fixture 的 TUN 覆盖缩水，完整配置门失去权限无关的 TUN 初始化面"
    );
    assert_eq!(
        actual_dashboards, expected_dashboards,
        "37 个 fixture 的 dashboard 形状累计失配"
    );
    ratchet.assert_exact("完整生成配置加载门");
}

/// fixture 未必开启 dashboard；两条显式真核样例锁住 services 的 dashboard None/local-path 分支。
#[test]
fn bundled_core_accepts_dashboard_services_with_none_and_local_serve_dir() {
    let Some(core) = core_or_skip("dashboard services 真核门") else {
        return;
    };
    let temp = tempdir().expect("建 TempDir");
    let base = load_cases()
        .into_iter()
        .find(|case| case.name == "systemProxy+smart+vless（基线）")
        .expect("基线 fixture 不得丢失");
    let local_dir = temp.path().join("dashboard-static");
    std::fs::create_dir_all(&local_dir).expect("建 dashboard 临时目录");
    let variants = [
        ("none", None),
        ("local", Some(local_dir.display().to_string())),
    ];
    let mut expected_dashboards = 0usize;
    let mut actual_dashboards = 0usize;

    for (name, serve_dir) in variants {
        let mut case = SnapshotCase {
            name: format!("dashboard services ({name})"),
            platform: base.platform.clone(),
            input: base.input.clone(),
        };
        case.input.singbox_dashboard = Some(true);
        let mut deps = full_config_deps(&case, &temp);
        deps.dashboard_serve_dir = serve_dir.clone();
        let cfg = generate_sing_box_config(&case.input, &BTreeMap::new(), &deps)
            .unwrap_or_else(|error| panic!("{name} dashboard 配置生成失败: {error}"));
        let value = serde_json::to_value(&cfg).expect("dashboard 配置序列化");
        let (expected_dashboard, actual_dashboard) = assert_api_service_shape(&case, &value);
        expected_dashboards += usize::from(expected_dashboard);
        actual_dashboards += usize::from(actual_dashboard);

        let api = value["services"]
            .as_array()
            .expect("services 已由形状断言验证")[0]
            .clone();
        let dashboard = &api["dashboard"];
        assert_eq!(dashboard["enabled"].as_bool(), Some(true));
        assert_eq!(
            dashboard.get("path").and_then(Value::as_str),
            serve_dir.as_deref(),
            "{name} dashboard path 未按 deps 下发"
        );
        let path = temp.path().join(format!("dashboard-{name}.json"));
        std::fs::write(&path, serde_json::to_vec_pretty(&value).expect("JSON 编码"))
            .expect("写 dashboard 配置");
        let (ok, diag) = check(&core, &path);
        assert!(ok, "{name} dashboard 配置被真核拒绝：{diag}");
    }

    assert_eq!(
        expected_dashboards, 2,
        "两条 dashboard 真核样例都必须请求 dashboard"
    );
    assert_eq!(
        actual_dashboards, expected_dashboards,
        "dashboard shape 累计失配"
    );
}

/// 正向变异：未知 inbound 键必须被完整配置门打红。
///
/// 用内存 `Value` 做 mutation，最后逐值恢复，绝不改 fixture；所有落盘仍在 `TempDir`。
#[test]
fn full_config_gate_rejects_unknown_inbound_field_mutation() {
    let Some(core) = core_or_skip("完整配置未知 inbound 字段变异") else {
        return;
    };
    let temp = tempdir().expect("建 TempDir");
    let case = load_cases()
        .into_iter()
        .next()
        .expect("37 个 fixture 不得为空");
    let deps = full_config_deps(&case, &temp);
    let cfg = generate_sing_box_config(&case.input, &BTreeMap::new(), &deps).expect("生成配置");
    let mut value = serde_json::to_value(&cfg).expect("序列化");
    let original = value.clone();
    value["inbounds"][0]["kernel_gate_unknown_inbound_field"] = json!(true);
    let path = temp.path().join("unknown-inbound.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&value).expect("JSON 编码"))
        .expect("写变异配置");
    let (ok, diag) = check(&core, &path);
    assert!(!ok, "未知 inbound 字段被核收下，本完整配置门没有牙");
    assert!(
        diag.contains("kernel_gate_unknown_inbound_field"),
        "变异没有命中目标字段，拒绝原因不可信：{diag}"
    );
    value = original;
    assert_eq!(
        value,
        serde_json::to_value(&cfg).expect("重序列化"),
        "变异未精确还原"
    );
}

/// 正向变异：真实已引用 `.srs` 路径失踪时，完整配置门必须转红。
#[test]
fn full_config_gate_rejects_missing_srs_path_mutation() {
    let Some(core) = core_or_skip("完整配置缺失 .srs 路径变异") else {
        return;
    };
    let temp = tempdir().expect("建 TempDir");
    let case = load_cases()
        .into_iter()
        .find(|case| case.name == "systemProxy+smart+vless（基线）")
        .expect("基线 fixture 不得丢失");
    let deps = full_config_deps(&case, &temp);
    let cfg = generate_sing_box_config(&case.input, &BTreeMap::new(), &deps).expect("生成配置");
    let mut value = serde_json::to_value(&cfg).expect("序列化");
    let original = value.clone();
    let rules = value["route"]["rule_set"]
        .as_array_mut()
        .expect("完整基线必须带真实 route.rule_set");
    let target = rules
        .iter_mut()
        .find(|rule| {
            rule["path"]
                .as_str()
                .is_some_and(|path| path.ends_with(".srs"))
        })
        .expect("完整基线必须引用真实 .srs，缺此项则 mutation 没有射程");
    target["path"] = Value::String(temp.path().join("missing.srs").display().to_string());
    let path = temp.path().join("missing-srs.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&value).expect("JSON 编码"))
        .expect("写变异配置");
    let (ok, diag) = check(&core, &path);
    assert!(!ok, "缺失的 .srs 路径被核收下，本完整配置门没有牙");
    assert!(
        diag.contains("missing.srs"),
        "变异没有因缺失 .srs 转红，拒绝原因不可信：{diag}"
    );
    value = original;
    assert_eq!(
        value,
        serde_json::to_value(&cfg).expect("重序列化"),
        "变异未精确还原"
    );
}
