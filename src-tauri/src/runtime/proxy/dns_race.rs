//! 节点域名 DNS race sidecar owner。
//!
//! 本模块独占「活 sidecar + 生成配置投影 + DoH transport」三者，并持有与 [`ProxyRuntime`] 相同的
//! [`LifecycleGate`] `Arc` 做锁内世代判权。sidecar 本体与配置投影始终按 `sidecar → state` 的固定锁序
//! 同刻翻转，避免运行核引用死端口或旧起核腿覆盖新会话。

use std::path::Path;
use std::sync::{Arc, Mutex};

use polaris_config_engine::user_config::app_config::UserConfig;
use polaris_core_supervisor::LifecycleGate;
use polaris_dns_race::{
    plan_upstreams, DecoySet, DefaultUpstreamQuery, DohPost, NodeDnsRaceServer, OnRaceServerDead,
    DEFAULT_RACE_BUDGET,
};

use super::startup::rule_resource_dir;
use super::ProxyRuntime;

/// 生成配置消费的 race sidecar 投影。`port == 0` 即 race off。
#[derive(Debug, Clone, Default)]
struct RaceServerState {
    port: u16,
    upstream_ips: Vec<String>,
    upstream_ports: Vec<u16>,
}

/// DNS race sidecar 的唯一状态 owner。
pub(super) struct DnsRaceRuntime {
    gate: Arc<LifecycleGate>,
    state: Mutex<RaceServerState>,
    sidecar: Mutex<Option<NodeDnsRaceServer>>,
    doh: Arc<dyn DohPost>,
}

impl DnsRaceRuntime {
    pub(super) fn new(gate: Arc<LifecycleGate>, doh: Arc<dyn DohPost>) -> Self {
        Self {
            gate,
            state: Mutex::new(RaceServerState::default()),
            sidecar: Mutex::new(None),
            doh,
        }
    }

    /// 配置生成腿一次性读取三轴同源快照。
    pub(super) fn config_projection(&self) -> (u16, Vec<String>, Vec<u16>) {
        self.state
            .lock()
            .map(|state| {
                (
                    state.port,
                    state.upstream_ips.clone(),
                    state.upstream_ports.clone(),
                )
            })
            .unwrap_or((0, Vec::new(), Vec::new()))
    }

    #[cfg(test)]
    fn port(&self) -> u16 {
        self.state.lock().map(|state| state.port).unwrap_or(0)
    }

    #[cfg(test)]
    fn set_projection(&self, port: u16, upstream_ips: Vec<String>, upstream_ports: Vec<u16>) {
        if let Ok(mut state) = self.state.lock() {
            state.port = port;
            state.upstream_ips = upstream_ips;
            state.upstream_ports = upstream_ports;
        }
    }

    /// sidecar 收口的唯一实现。`owner_generation=None` 表示当前调用方是无条件权威（主动 stop）。
    pub(super) fn clear_owned(&self, owner_generation: Option<u64>) -> bool {
        let (Ok(mut sidecar), Ok(mut state)) = (self.sidecar.lock(), self.state.lock()) else {
            log::error!("race sidecar 锁中毒 → 跳过清理（生成侧可能仍带旧端口）");
            return false;
        };
        if let Some(my_generation) = owner_generation {
            let current_generation = self.gate.generation();
            if current_generation != my_generation {
                log::info!(
                    "[dns-race] 起核腿已被接管（世代 {my_generation}→{current_generation}）→ 不动 sidecar，交接管方收口"
                );
                return false;
            }
        }
        if let Some(server) = sidecar.take() {
            log::info!("[dns-race] 停止 sidecar（原端口 {}）", server.port());
            server.stop();
            let stats = polaris_dns_race::stats::take_session();
            if !stats.is_empty() {
                log::info!(
                    "[dns-race] 本次会话：识别并丢弃投毒应答 {} 条，回包时无 socket {} 条",
                    stats.poisoned_dropped,
                    stats.reply_no_socket
                );
            }
        }
        *state = RaceServerState::default();
        true
    }

    /// 刚起好的 sidecar 与其配置投影在同一复合临界区内提交。
    fn commit(
        &self,
        server: NodeDnsRaceServer,
        upstream_ips: Vec<String>,
        upstream_ports: Vec<u16>,
        my_generation: u64,
    ) -> u16 {
        let port = server.port();
        let (Ok(mut sidecar), Ok(mut state)) = (self.sidecar.lock(), self.state.lock()) else {
            log::error!("race sidecar 锁中毒 → 放弃本次 sidecar（降级单上游）");
            return 0;
        };
        let current_generation = self.gate.generation();
        if current_generation != my_generation {
            log::info!(
                "[dns-race] 提交时已被接管（世代 {my_generation}→{current_generation}）→ 丢弃本腿 sidecar"
            );
            return 0;
        }
        *sidecar = Some(server);
        state.port = port;
        state.upstream_ips = upstream_ips;
        state.upstream_ports = upstream_ports;
        port
    }

    /// watchdog 彻底放弃重建时清本 owner 的注入态。回调只持 `Weak`，不存在引用环。
    fn dead_callback(self: &Arc<Self>, my_generation: u64) -> OnRaceServerDead {
        let weak = Arc::downgrade(self);
        Arc::new(move |dead_port: u16| {
            let Some(runtime) = weak.upgrade() else {
                log::info!(
                    "[dns-race] sidecar 端口 {dead_port} 失效时 owner 已析构 → 无注入态需清"
                );
                return;
            };
            if runtime.clear_owned(Some(my_generation)) {
                log::error!(
                    "[dns-race] sidecar 端口 {dead_port} 已彻底失效（watchdog 放弃重建）→ 已清注入态，\
                     节点域名解析降级为单上游(dns-bootstrap)；重连可重建"
                );
            } else {
                log::info!(
                    "[dns-race] 死亡回调让位（世代 {my_generation} 已被接管）→ 注入态属接管方，不动"
                );
            }
        })
    }

    const DECOY_OVERRIDE_FILE: &'static str = "gfw-decoy-cidr.txt";

    /// 规则资源覆盖清单优先，缺失/全坏时回落内置 decoy 表。
    fn load_decoy_set(data_dir: &Path) -> Arc<DecoySet> {
        let path = rule_resource_dir(data_dir).join(Self::DECOY_OVERRIDE_FILE);
        let Ok(text) = std::fs::read_to_string(&path) else {
            log::info!("decoy 段表：未提供覆盖清单（{}），用内置表", path.display());
            return Arc::new(DecoySet::builtin());
        };
        let parsed = DecoySet::parse(&text);
        if !parsed.bad_lines.is_empty() {
            let shown: Vec<String> = parsed
                .bad_lines
                .iter()
                .take(5)
                .map(|(line_number, line)| format!("L{line_number}:{line}"))
                .collect();
            log::warn!(
                "decoy 覆盖清单有 {} 行无法解析（已跳过）：{}",
                parsed.bad_lines.len(),
                shown.join(" / ")
            );
        }
        let (v4, v6) = parsed.set.len();
        if parsed.fell_back {
            log::warn!("decoy 覆盖清单未解析出任何有效段 → 回落内置表（{v4} v4 / {v6} v6）");
        } else {
            log::info!("decoy 段表：覆盖清单生效，{v4} 条 v4 / {v6} 条 v6");
        }
        Arc::new(parsed.set)
    }

    /// 按本轮配置起 sidecar；竞速关闭、绑口失败均 fail-open 到单上游。
    pub(super) async fn start(
        self: &Arc<Self>,
        user_config: &UserConfig,
        data_dir: &Path,
        my_generation: u64,
    ) {
        if !self.clear_owned(Some(my_generation)) {
            return;
        }
        let Some(upstreams) =
            plan_upstreams(user_config.dns_config.as_ref(), user_config.proxy_mode_type)
        else {
            log::info!("节点域名竞速解析已关闭 → 走单上游路径，不起 sidecar");
            return;
        };
        let (tier1_count, tier2_count) = (upstreams.tier1.len(), upstreams.tier2.len());
        let direct_ips = upstreams.direct_ips.clone();
        let direct_ports = upstreams.direct_ports.clone();
        let query = Arc::new(DefaultUpstreamQuery::new(Arc::clone(&self.doh)));
        let on_dead = self.dead_callback(my_generation);
        let decoys = Self::load_decoy_set(data_dir);
        match NodeDnsRaceServer::start(
            upstreams,
            query,
            DEFAULT_RACE_BUDGET,
            Some(on_dead),
            decoys,
        )
        .await
        {
            Ok(server) => match self.commit(
                server,
                direct_ips,
                direct_ports,
                my_generation,
            ) {
                0 => log::warn!("race sidecar 提交失败 / 已被接管 → 降级单上游(dns-bootstrap)"),
                port => log::info!(
                    "节点域名 race 解析就绪：127.0.0.1:{port}（Tier1 {tier1_count} / Tier2 {tier2_count}）"
                ),
            },
            Err(error) => {
                log::warn!("race server 启动失败，降级单上游(dns-bootstrap): {error}");
            }
        }
    }
}

impl ProxyRuntime {
    /// 公开 facade：当前 race sidecar 端口，`0` 表示 race off。
    #[must_use]
    #[cfg(test)]
    pub fn race_server_port(&self) -> u16 {
        self.dns_race.port()
    }

    /// 测试/装配 facade：注入生成配置消费的三轴投影。
    #[cfg(test)]
    pub fn set_race_server(&self, port: u16, upstream_ips: Vec<String>, upstream_ports: Vec<u16>) {
        self.dns_race
            .set_projection(port, upstream_ips, upstream_ports);
    }

    /// 主动 stop facade：当前调用方是权威，无条件清 sidecar 与配置投影。
    pub fn clear_race_server(&self) {
        let _ = self.dns_race.clear_owned(None);
    }
}

#[cfg(test)]
mod tests;
