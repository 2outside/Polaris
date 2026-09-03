//! 通用网络变化 watcher 域：三平台事件源订阅（Windows IP Helper 回调 / macOS `route -n monitor` /
//! Linux `ip monitor`）、去抖合流，以及去抖后那一次网络变化的完整处置。
//!
//! L3：向下调 [`super::route_replan`] 的绑定失效判据与 [`super::platform_contracts`] 的平台探测，
//! 被 façade 的起核/停核腿挂载（依赖方向见设计 §B.4）。

use std::sync::Arc;
use std::time::Duration;

use polaris_config_engine::builder::outbounds::required_bind_interfaces;
use polaris_config_engine::user_config::app_config::UserConfig;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use polaris_helper_proto::Platform;
// 谓词里的 `test` 原子随代码一起走了（那批测试已迁进 `polaris-platform-events`），
// 但**平台原子必须留**：跨 crate 的 `pub` 治的是 `dead_code`，治不了导入侧的 `unused_imports`。
#[cfg(any(target_os = "macos", target_os = "linux"))]
use polaris_platform_events::{
    monitor_line_impact as network_monitor_line_impact, MacRouteMonitorParser,
};
// `NetworkMonitorUpdate` 只被 `route_network_watcher_once` 消费（macOS/Linux 专有）。
#[cfg(any(target_os = "macos", target_os = "linux"))]
use polaris_platform_events::NetworkMonitorUpdate;
use polaris_platform_events::{debounced_network_change, NetworkChangeImpact};

use crate::runtime::route_binding::needs_runtime_binding_plan;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use super::platform_contracts::linux_ip_monitor_binary;
use super::route_replan::{inferred_binding_replan_needed, required_interfaces_unavailable};
use super::{code, ProxyRuntime};

/// 通用网络变化 watcher 去抖窗口（合并 burst 链路变化）。沿用既有 `DnsInterfaceWatcher`
/// 默认去抖（`crates/system-integration` `dns_watcher` 单测锚定同值）。
const NETWORK_WATCHER_DEBOUNCE_MS: u64 = 1500;
const NETWORK_WATCHER_RESTART_MAX: Duration = Duration::from_secs(30);

pub(super) fn network_watcher_restart_delay(consecutive_failures: u32) -> Duration {
    let shift = consecutive_failures.saturating_sub(1).min(5);
    Duration::from_secs(1u64 << shift).min(NETWORK_WATCHER_RESTART_MAX)
}

impl ProxyRuntime {
    /// 起通用网络变化 watcher。三平台均在核就绪后启动；已在跑则先停旧再起新（幂等）。
    pub(super) fn spawn_network_watcher(self: &Arc<Self>, managed_tun_interface: Option<String>) {
        if !cfg!(any(target_os = "macos", target_os = "linux", windows)) {
            return;
        }
        let this = Arc::clone(self);
        let handle =
            tokio::spawn(async move { this.network_watcher_loop(managed_tun_interface).await });
        if let Ok(mut g) = self.network_watcher.lock() {
            if let Some(old) = g.replace(handle) {
                old.abort(); // 幂等：替换前停旧；Unix kill_on_drop 杀旧子进程，Windows Drop 注销回调。
            }
        }
    }

    /// 停通用网络变化 watcher（停核 / 崩溃复位调）。
    pub(super) fn stop_network_watcher(&self) {
        if let Ok(mut g) = self.network_watcher.lock() {
            if let Some(h) = g.take() {
                h.abort();
            }
        }
    }

    /// 一次去抖后的网络变化：DNS 重灌先走独立门控，再处理绑定状态与出口恢复。
    /// 显式绑定失效 fail-closed（保留当前核、告警、不改默认出口）；推断绑定失效或路由变化则重启
    /// TUN，在接口撤销后重新读取真实物理路由。
    async fn handle_network_change(self: &Arc<Self>, impact: NetworkChangeImpact) {
        self.reconcile_system_dns_best_effort().await;
        let Some(config) = self
            .current_config
            .read()
            .ok()
            .and_then(|config| config.clone())
            .and_then(|config| serde_json::from_value::<UserConfig>(config).ok())
        else {
            self.schedule_network_recovery_refresh();
            return;
        };
        let previous = self
            .runtime_binding_state
            .lock()
            .map(|state| state.clone())
            .unwrap_or_default();
        let observed = self.observe_network_interfaces().await;
        let required = required_bind_interfaces(&config);
        let unavailable = observed
            .as_ref()
            .map(|fingerprint| required_interfaces_unavailable(&required, fingerprint))
            .unwrap_or_else(|| previous.explicit_unavailable.clone());
        let explicit_recovered =
            !previous.explicit_unavailable.is_empty() && unavailable.is_empty();

        if unavailable != previous.explicit_unavailable {
            if unavailable.is_empty() {
                self.clear_nonfatal_error_if(code::OUTBOUND_INTERFACE_UNAVAILABLE);
                log::info!("显式绑定网卡已恢复，准备重启以重新建立受约束连接");
            } else {
                let message = unavailable.diagnostic();
                log::warn!("运行期显式绑定网卡不可用：{message}");
                self.set_nonfatal_error(&message, code::OUTBOUND_INTERFACE_UNAVAILABLE);
            }
        }

        if let Ok(mut state) = self.runtime_binding_state.lock() {
            if let Some(fingerprint) = observed.clone() {
                state.interface_fingerprint = Some(fingerprint);
            }
            state.explicit_unavailable = unavailable.clone();
        }

        if !unavailable.is_empty() {
            // 重启的启动前置门也会拒绝同一显式绑定；此时拆掉仍可服务其它节点的旧核只会扩大断流。
            self.schedule_network_recovery_refresh();
            return;
        }

        let inferred_binding_changed = inferred_binding_replan_needed(
            &impact,
            &previous.plan,
            previous.interface_fingerprint.as_ref(),
            observed.as_ref(),
            None,
        );
        let inferred_replan = config.proxy_mode_type.is_tun()
            && needs_runtime_binding_plan(&config)
            && inferred_binding_changed;
        if explicit_recovered || inferred_replan {
            // 活 TUN 下查节点目的路由只会命中 Polaris 自己；必须由既有重启编排先撤 TUN，再规划。
            log::info!(
                "网络绑定事实变化：route={} routeUnknown={} routePrefixes={} inferredBindingChanged={} explicitRecovered={} → 调度重启重规划",
                impact.route,
                impact.route_unknown,
                impact.route_prefixes.len(),
                inferred_binding_changed,
                explicit_recovered
            );
            self.schedule_restart();
        } else {
            self.schedule_network_recovery_refresh();
        }
    }

    /// watcher 主循环：macOS 长驻 `route -n monitor`，Linux 长驻带 label 的 `ip monitor`；逐行分类
    /// 接口/路由影响，去抖窗口（[`NETWORK_WATCHER_DEBOUNCE_MS`]）合并 burst 后统一处理。
    ///
    /// 注：`crates/system-integration::dns_watcher::DnsInterfaceWatcher` 封装同款「行缓冲 + 去抖 + 门控」状态机
    /// 并有离线单测；此处 async 子进程驱动用 `tokio` 原生去抖（`BufReader::lines` 已按行切分 → 无需其行缓冲；
    /// 其借用闭包设计 `!Send`、不宜跨 await 持有于长驻任务）。macOS 分类仍复用该 crate 的纯函数。
    ///
    async fn network_watcher_loop(self: Arc<Self>, managed_tun_interface: Option<String>) {
        let mut consecutive_failures = 0u32;
        loop {
            let started = std::time::Instant::now();
            let error = match self
                .network_watcher_once(managed_tun_interface.as_deref())
                .await
            {
                Ok(()) => "事件源意外结束".to_owned(),
                Err(error) => error,
            };
            consecutive_failures = if started.elapsed() >= Duration::from_secs(60) {
                1
            } else {
                consecutive_failures.saturating_add(1)
            };
            let delay = network_watcher_restart_delay(consecutive_failures);
            log::warn!(
                "网络变化 watcher 已退出：{error}；{}ms 后重建（连续失败 {consecutive_failures} 次）",
                delay.as_millis()
            );
            tokio::time::sleep(delay).await;
        }
    }

    async fn network_watcher_once(
        self: &Arc<Self>,
        managed_tun_interface: Option<&str>,
    ) -> Result<(), String> {
        #[cfg(windows)]
        {
            let (subscription, mut events) =
                crate::runtime::windows_network_change::subscribe(managed_tun_interface)
                    .map_err(|error| format!("订阅 Windows 接口/路由变化失败：{error}"))?;
            let debounce = std::time::Duration::from_millis(NETWORK_WATCHER_DEBOUNCE_MS);
            let mut deadline: Option<tokio::time::Instant> = None;
            loop {
                let debounce_elapsed = async {
                    match deadline {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending::<()>().await,
                    }
                };
                tokio::select! {
                    event = events.recv() => match event {
                        Some(()) => deadline = Some(tokio::time::Instant::now() + debounce),
                        None => return Err("Windows IP 接口事件流已关闭".to_owned()),
                    },
                    () = debounce_elapsed => {
                        deadline = None;
                        let pending = subscription.take_pending();
                        if let Some(impact) = debounced_network_change(NetworkChangeImpact {
                            interface: pending.interface,
                            route: pending.route,
                            route_prefixes: pending.route_prefixes,
                            route_unknown: pending.route_unknown,
                        }) {
                            self.handle_network_change(impact).await;
                        }
                    }
                }
            }
        }

        #[cfg(any(target_os = "macos", target_os = "linux"))]
        return self.route_network_watcher_once(managed_tun_interface).await;

        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        Ok(())
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    async fn route_network_watcher_once(
        self: &Arc<Self>,
        managed_tun_interface: Option<&str>,
    ) -> Result<(), String> {
        use std::process::Stdio;
        use tokio::io::{AsyncBufReadExt, BufReader};

        let (program, args): (&str, &[&str]) = if cfg!(target_os = "linux") {
            (
                linux_ip_monitor_binary(),
                &["monitor", "link", "address", "route", "label"],
            )
        } else {
            ("route", &["-n", "monitor"])
        };
        let mut child = tokio::process::Command::new(program)
            .args(args)
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| format!("起 `{program} {}` 失败：{error}", args.join(" ")))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| format!("`{program}` 未提供 stdout"))?;
        let mut lines = BufReader::new(stdout).lines();
        let debounce = std::time::Duration::from_millis(NETWORK_WATCHER_DEBOUNCE_MS);
        let mut deadline: Option<tokio::time::Instant> = None;
        let mut pending_impact = NetworkChangeImpact::default();
        let mut mac_parser = MacRouteMonitorParser::default();
        loop {
            let debounce_elapsed = async {
                match deadline {
                    Some(d) => tokio::time::sleep_until(d).await,
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::select! {
                line = lines.next_line() => match line {
                    Ok(Some(l)) => {
                        // macOS 的 route monitor 把一条路由拆成事件头、sockaddrs 字段和地址值三行；
                        // 必须聚合后才能取得 DST/NETMASK/IFP。Linux 每行已经是完整 netlink 文本。
                        let update = if cfg!(target_os = "macos") {
                            mac_parser.push_line(&l, managed_tun_interface)
                        } else {
                            let impact = network_monitor_line_impact(
                                Platform::current(),
                                &l,
                                managed_tun_interface,
                            );
                            NetworkMonitorUpdate {
                                observed_event: impact.is_some(),
                                impact,
                            }
                        };
                        if let Some(impact) = update.impact {
                            pending_impact.merge(impact);
                        }
                        if update.observed_event {
                            deadline = Some(tokio::time::Instant::now() + debounce);
                        }
                    }
                    Ok(None) => {
                        let status = child.try_wait().ok().flatten();
                        return Err(format!("`{program}` 输出流 EOF（status={status:?}）"));
                    }
                    Err(error) => return Err(format!("读取 `{program}` 事件流失败：{error}")),
                },
                () = debounce_elapsed => {
                    deadline = None;
                    if cfg!(target_os = "macos") {
                        if let Some(impact) = mac_parser.take_incomplete() {
                            pending_impact.merge(impact);
                        }
                    }
                    let impact = std::mem::take(&mut pending_impact);
                    if let Some(impact) = debounced_network_change(impact) {
                        self.handle_network_change(impact).await;
                    }
                }
            }
        }
    }
}
