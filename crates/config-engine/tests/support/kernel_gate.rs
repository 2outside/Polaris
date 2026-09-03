//! `sing-box check` 回归门的共用底座。
//!
//! 这里故意只放「如何造同一批 fixture、如何找核、如何调用 check、如何判夹具凭据棘轮」：
//! 出站面门与完整配置门的**射程**不同，绝不能在此把后者削回前者的 surface。

use std::collections::BTreeMap;
use std::path::Path;

use polaris_config_engine::builder::GenerateConfigDeps;
use polaris_config_engine::user_config::app_config::UserConfig;
use polaris_config_engine::user_config::builtin_geo_rulesets::is_valid_srs_file;
use polaris_config_engine::user_config::LogLevel;
use serde::Deserialize;
use tempfile::TempDir;

pub use super::core_locator::{core_or_skip, repo_root};

#[derive(Debug, Deserialize)]
struct SnapshotFixture {
    cases: Vec<SnapshotCase>,
}

#[derive(Debug, Deserialize)]
pub struct SnapshotCase {
    pub name: String,
    #[serde(default = "default_platform")]
    pub platform: String,
    pub input: UserConfig,
}

pub fn default_platform() -> String {
    "win32".to_string()
}

/// `sing-box --disable-color check -c <path>` → `(rc==0, 诊断原文)`。
pub fn check(core: &Path, config_path: &Path) -> (bool, String) {
    let out = super::core_locator::command_for_core(core)
        .arg("--disable-color")
        .arg("check")
        .arg("-c")
        .arg(config_path)
        .output()
        .unwrap_or_else(|e| panic!("跑 {} 失败: {e}", core.display()));
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let diag = if stderr.is_empty() { stdout } else { stderr };
    (out.status.success(), diag)
}

pub fn load_cases() -> Vec<SnapshotCase> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/config-snapshot.json");
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("fixtures/config-snapshot.json 读不到: {e}"));
    let fixture: SnapshotFixture =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("fixture 解析失败: {e}"));
    assert_eq!(
        fixture.cases.len(),
        37,
        "完整 fixture 数量漂移：本真核门要求恰好 37 个生成配置"
    );
    fixture.cases
}

fn scenario_deps(name: &str) -> (Option<u16>, Option<u16>, Option<u16>, Option<String>) {
    match name {
        "probe 端口注入" => (Some(21001), Some(21002), None, None),
        "DNS lanResolverForDns 注入" => (None, None, None, Some("192.168.1.1".to_string())),
        "update-in 端口注入（smart）" | "update-in 端口注入（direct）" => {
            (None, None, Some(21003), None)
        }
        _ => (None, None, None, None),
    }
}

/// 出站面门的冻结依赖：保留其原有「所有 SRS 视为已落盘」的隔离语义。
#[allow(dead_code)] // 另一条 integration test 单独编译，本模块在那一侧只供完整配置门使用。
pub fn outbound_deps(case: &SnapshotCase) -> GenerateConfigDeps {
    let (probe_direct_port, probe_proxy_port, update_in_port, lan_resolver_for_dns) =
        scenario_deps(&case.name);
    let mut deps = outbound_deps_for(&case.platform);
    deps.probe_direct_port = probe_direct_port;
    deps.probe_proxy_port = probe_proxy_port;
    deps.update_in_port = update_in_port;
    deps.lan_resolver_for_dns = lan_resolver_for_dns;
    deps
}

#[allow(dead_code)] // 见上；出站门的手造场景复用此冻结依赖。
pub fn outbound_deps_for(platform: &str) -> GenerateConfigDeps {
    GenerateConfigDeps {
        platform: platform.into(),
        arch: "x86_64".into(),
        race_server_port: 0,
        probe_direct_port: None,
        probe_proxy_port: None,
        update_in_port: None,
        subscription_update_in_port: None,
        probe_pool_ports: vec![],
        lan_resolver_for_dns: None,
        race_upstream_ips: vec![],
        race_upstream_ports: vec![],
        has_cronet: true,
        cronet_copy_failed: false,
        has_management_api: false,
        privacy_mode: false,
        log_level: LogLevel::Info,
        disable_log_file: false,
        dashboard_serve_dir: None,
        tailscale_api_port: 0,
        cache_path: "/fake/userData/cache.db".into(),
        log_file_path: Some("/fake/userData/singbox.log".into()),
        runtime_rules_dir: "/fake/userData/rules".into(),
        rule_resources_path: "/fake/userData/rule-resource".into(),
        custom_rules_dir: "/fake/userData/custom-rules".into(),
        tailscale_state_dir_prefix: "/fake/userData/tailscale".into(),
        is_valid_srs_fn: |_| true,
        own_lan_cidrs: vec![],
        log: |_, _| {},
        on_degraded: || {},
    }
}

/// 完整配置门的运行时依赖：规则集一定来自仓内真实 `resources/data`，所有可写路径收进 `TempDir`。
#[allow(dead_code)] // 另一条 integration test 单独编译，本模块在那一侧只供出站门使用。
pub fn full_config_deps(case: &SnapshotCase, temp: &TempDir) -> GenerateConfigDeps {
    let (probe_direct_port, probe_proxy_port, update_in_port, lan_resolver_for_dns) =
        scenario_deps(&case.name);
    let root = repo_root();
    let data = root.join("resources/data");
    assert!(
        data.is_dir(),
        "真实 resources/data 不存在：{}",
        data.display()
    );
    let tmp = temp.path();
    GenerateConfigDeps {
        platform: case.platform.clone(),
        arch: "x86_64".into(),
        race_server_port: 0,
        probe_direct_port,
        probe_proxy_port,
        update_in_port,
        subscription_update_in_port: None,
        probe_pool_ports: vec![],
        lan_resolver_for_dns,
        race_upstream_ips: vec![],
        race_upstream_ports: vec![],
        has_cronet: true,
        cronet_copy_failed: false,
        // 生产 generate_deps 以随包 1.14 恒有 services schema 为前提，恒注入 management API；
        // 本门须同样带上 services，不能把该完整面静默削掉。
        has_management_api: true,
        privacy_mode: false,
        log_level: LogLevel::Info,
        disable_log_file: false,
        // package.yml 在本门之后才 Fetch dashboard，故这里不能伪造本地目录；dashboard path/None
        // 两分支由 explicit_http_client_gate 覆盖。本门仍覆盖 services 的完整配置形状。
        dashboard_serve_dir: None,
        // 生产由端口分配器注入；check 不绑定，仅需非零来覆盖 services.listen_port 下发。
        tailscale_api_port: 19090,
        cache_path: tmp.join("cache.db").display().to_string(),
        log_file_path: Some(tmp.join("singbox.log").display().to_string()),
        runtime_rules_dir: data.display().to_string(),
        rule_resources_path: data.display().to_string(),
        custom_rules_dir: tmp.join("custom-rules").display().to_string(),
        tailscale_state_dir_prefix: tmp.join("tailscale").display().to_string(),
        is_valid_srs_fn: real_srs,
        own_lan_cidrs: vec![],
        log: |_, _| {},
        on_degraded: || {},
    }
}

#[allow(dead_code)] // 仅由完整配置门的函数指针使用。
fn real_srs(path: &str) -> bool {
    is_valid_srs_file(Path::new(path))
}

/// 允许的唯一 initialize 凭据 artifact。每项锁**整条**随包 1.14 `check` 诊断，而非只认
/// 一个子串：同一 fixture 冒出另一个 initialize 错误、或在既有原因后再拼尾因，都会不匹配并转红。
#[derive(Clone, Copy)]
pub struct FixtureCredentialArtifact {
    pub name: &'static str,
    pub diagnostic: &'static str,
}

pub const FIXTURE_CREDENTIAL_ARTIFACTS: &[FixtureCredentialArtifact] = &[
    FixtureCredentialArtifact {
        name: "多协议 outbound",
        diagnostic: "FATAL[0000] initialize outbound[1]: invalid uuid: uuid: incorrect UUID length",
    },
    FixtureCredentialArtifact {
        name: "vless reality + shadowsocks shadow-tls",
        diagnostic: "FATAL[0000] initialize outbound[0]: invalid public_key",
    },
    FixtureCredentialArtifact {
        name: "抗封增强（ECH+TLS fragment+multiplex）",
        diagnostic: "FATAL[0000] initialize outbound[0]: invalid ECH configs pem",
    },
    FixtureCredentialArtifact {
        name: "ssh outbound",
        diagnostic: "FATAL[0000] initialize outbound[0]: parse private key: ssh: no key found",
    },
];

pub fn is_decode_stage(diag: &str) -> bool {
    diag.contains("decode config at")
}

#[derive(Default)]
pub struct FixtureRatchet {
    pub checked: usize,
    pub accepted: usize,
    decode_failures: Vec<String>,
    unlisted_init_failures: Vec<String>,
    artifacts_seen: BTreeMap<&'static str, usize>,
}

impl FixtureRatchet {
    pub fn record(&mut self, name: &str, ok: bool, diag: &str) {
        self.checked += 1;
        if ok {
            self.accepted += 1;
            return;
        }
        if is_decode_stage(diag) {
            self.decode_failures.push(format!("  · {name} → {diag}"));
            return;
        }
        match FIXTURE_CREDENTIAL_ARTIFACTS
            .iter()
            .find(|artifact| artifact.name == name && artifact.diagnostic == diag)
        {
            Some(artifact) => *self.artifacts_seen.entry(artifact.name).or_default() += 1,
            None => self
                .unlisted_init_failures
                .push(format!("  · {name} → {diag}")),
        }
    }

    pub fn assert_exact(self, gate: &str) {
        assert_eq!(
            FIXTURE_CREDENTIAL_ARTIFACTS.len(),
            4,
            "{gate}：凭据 artifact 白名单必须精确为 4 项；新增豁免须先证明是不可由 builder 决定的 fixture 凭据"
        );
        assert_eq!(self.checked, 37, "{gate} 未逐一 check 37 个 fixture");
        assert!(
            self.decode_failures.is_empty(),
            "{gate}：随包核在 decode 阶段拒绝了配置；这是 builder 形状错误，零容忍：\n{}",
            self.decode_failures.join("\n")
        );
        assert!(
            self.unlisted_init_failures.is_empty(),
            "{gate}：随包核在 initialize 阶段拒绝了未登记配置：\n{}",
            self.unlisted_init_failures.join("\n")
        );
        assert_eq!(
            self.accepted, 33,
            "{gate}：成功数必须精确为 33（四项夹具凭据 artifact 外不得有失败）"
        );
        for artifact in FIXTURE_CREDENTIAL_ARTIFACTS {
            assert_eq!(
                self.artifacts_seen
                    .get(artifact.name)
                    .copied()
                    .unwrap_or_default(),
                1,
                "{gate}：凭据 artifact {:?} 必须精确触发一次；失效就删棘轮，重复则不是单一夹具 artifact",
                artifact.name,
            );
        }
    }
}
