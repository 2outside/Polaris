//! 系统代理接管 owner。
//!
//! 本模块持有系统代理 controller、marker 生命周期与「残留提示每会话一次」门闩。controller API 是
//! 同步且可能执行系统命令，因此全部在这里统一隔离到 `spawn_blocking`；[`ProxyRuntime`] 只保留
//! 生命周期世代校验、错误事件投影和公开 facade。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use polaris_config_engine::user_config::app_config::UserConfig;
use polaris_config_engine::user_config::system_proxy_bypass::{effective_bypass_lan, BypassConfig};
use polaris_config_engine::user_config::ProxyModeType;
use polaris_system_integration::proxy::MarkerFs;
use polaris_system_integration::proxy_ops::{
    ProxyEnableRequest, SystemProxyController, SystemProxyOps,
};

use super::{code, ProxyRuntime, ProxyStatus, StartError};

/// 系统代理「清理收口」能力——失败腿的最小注入面。
///
/// 生产控制器会执行 `networksetup`/`gsettings`/`reg`；trait 让单测注入只记录调用的替身，保证本机测试
/// 不触碰宿主系统代理。`Send` 是 controller 跨 `spawn_blocking` 线程的结构约束。
pub(crate) trait SystemProxyClearer: Send {
    /// 系统代理确由我们设置且仍指向我们（已死的）端口 → 清并返回 `true`；否则幂等 no-op。
    fn ensure_cleared(&mut self) -> bool;

    /// 检测「不是我们设的」系统代理，返回其 `host:port`（无则 `None`）。只读不动手。
    fn detect_foreign_proxy(&self) -> Option<String>;

    /// 把 OS 系统代理指向本地 mixed 入站。
    fn enable_system_proxy(&mut self, req: &ProxyEnableRequest) -> Result<(), String>;

    /// 上次会话遗留 marker 时恢复代理并清 marker；无 marker 返回 `Ok(false)`。
    fn recover_from_marker(&mut self) -> Result<bool, String>;
}

impl<Ops, Fs> SystemProxyClearer for SystemProxyController<Ops, Fs>
where
    Ops: SystemProxyOps + Send,
    Fs: MarkerFs + Send,
{
    fn ensure_cleared(&mut self) -> bool {
        SystemProxyController::ensure_cleared(self)
    }

    fn detect_foreign_proxy(&self) -> Option<String> {
        SystemProxyController::detect_foreign_proxy(self)
    }

    fn enable_system_proxy(&mut self, req: &ProxyEnableRequest) -> Result<(), String> {
        SystemProxyController::enable(self, req).map_err(|e| e.to_string())
    }

    fn recover_from_marker(&mut self) -> Result<bool, String> {
        SystemProxyController::recover_from_marker(self)
            .map(|marker| marker.is_some())
            .map_err(|error| error.to_string())
    }
}

/// 同步 controller 与会话门闩的唯一 owner。
pub(super) struct SystemProxyTakeover {
    controller: Arc<Mutex<Box<dyn SystemProxyClearer>>>,
    residual_warned: AtomicBool,
}

impl SystemProxyTakeover {
    pub(super) fn new(controller: Box<dyn SystemProxyClearer>) -> Self {
        Self {
            controller: Arc::new(Mutex::new(controller)),
            residual_warned: AtomicBool::new(false),
        }
    }

    /// marker 门控清理。无 marker 时 controller 自身幂等 no-op。
    async fn clear(&self) -> bool {
        let controller = Arc::clone(&self.controller);
        let outcome = tokio::task::spawn_blocking(move || {
            controller
                .lock()
                .map(|mut guard| guard.ensure_cleared())
                .unwrap_or_else(|error| {
                    log::error!("system proxy controller 锁中毒: {error} → 跳过系统代理清理");
                    false
                })
        })
        .await;
        match outcome {
            Ok(true) => {
                log::info!("系统代理曾指向我们（已死的）端口，已清（维度7 #8 收口）");
                true
            }
            Ok(false) => false,
            Err(error) => {
                log::error!("系统代理收口 spawn_blocking join 失败: {error}");
                false
            }
        }
    }

    /// 启动期 marker 恢复。返回是否真恢复过上次会话残留。
    async fn recover(&self) -> bool {
        let controller = Arc::clone(&self.controller);
        let outcome = tokio::task::spawn_blocking(move || {
            controller
                .lock()
                .map(|mut guard| guard.recover_from_marker())
                .unwrap_or_else(|error| {
                    log::error!("system proxy controller 锁中毒: {error} → 跳过启动期系统代理恢复");
                    Err("system proxy controller 锁中毒".to_string())
                })
        })
        .await;
        match outcome {
            Ok(Ok(true)) => {
                log::info!(
                    "启动期检测到上次未清的系统代理 marker（上次崩溃/强杀）→ 已清残留（维度7 #8）"
                );
                true
            }
            Ok(Ok(false)) => false,
            Ok(Err(error)) => {
                log::error!("启动期系统代理恢复失败，marker 已保留供重试：{error}");
                false
            }
            Err(error) => {
                log::error!("启动期系统代理恢复 spawn_blocking join 失败: {error}");
                false
            }
        }
    }

    /// 同步 enable 经 blocking 池执行；外层保留错误事件投影，因为事件/status 属于 runtime facade。
    async fn enable(
        &self,
        request: ProxyEnableRequest,
    ) -> Result<Result<(), String>, tokio::task::JoinError> {
        let controller = Arc::clone(&self.controller);
        tokio::task::spawn_blocking(move || {
            controller
                .lock()
                .map(|mut guard| guard.enable_system_proxy(&request))
                .unwrap_or_else(|error| {
                    log::error!("system proxy controller 锁中毒: {error} → 跳过系统代理启用");
                    Err("system proxy controller 锁中毒".to_string())
                })
        })
        .await
    }

    /// 同步只读残留探测经 blocking 池执行。
    async fn detect_foreign_proxy(&self) -> Result<Option<String>, tokio::task::JoinError> {
        let controller = Arc::clone(&self.controller);
        tokio::task::spawn_blocking(move || {
            controller
                .lock()
                .map(|guard| guard.detect_foreign_proxy())
                .unwrap_or_else(|error| {
                    log::error!("system proxy controller 锁中毒: {error} → 跳过系统代理残留检测");
                    None
                })
        })
        .await
    }

    fn residual_warning_claimed(&self) -> bool {
        self.residual_warned.load(Ordering::SeqCst)
    }

    /// 只有第一条仍有效的探测结果取得发射权；陈旧世代在调用本方法前已被 facade 丢弃。
    fn claim_residual_warning(&self) -> bool {
        !self.residual_warned.swap(true, Ordering::SeqCst)
    }
}

/// 仅 `systemProxy` 模式需把 OS 系统代理指向本地 mixed 入站。
fn should_enable_system_proxy(mode: ProxyModeType) -> bool {
    matches!(mode, ProxyModeType::SystemProxy)
}

/// 重启空窗里仅 `SystemProxy → Tun/Manual` 需要收掉旧会话系统代理。
pub(super) fn should_clear_system_proxy_between_restart(
    old_mode: Option<ProxyModeType>,
    new_mode: Option<ProxyModeType>,
) -> bool {
    old_mode.is_some_and(should_enable_system_proxy)
        && new_mode.is_some_and(|mode| !should_enable_system_proxy(mode))
}

impl ProxyRuntime {
    /// start 失败腿的系统代理收口；成功腿与已被新世代接管的腿均让位。
    pub(super) async fn maybe_clear_system_proxy_on_start_failure(
        &self,
        result: &Result<ProxyStatus, StartError>,
        my_generation: u64,
    ) {
        if result.is_ok() {
            return;
        }
        let current_generation = self.gate.generation();
        if current_generation != my_generation {
            log::info!(
                "起核失败但已被更新的 stop/start 接管（世代 {my_generation}→{current_generation}）→ 不清系统代理，交接管方收口"
            );
            return;
        }
        self.clear_system_proxy().await;
    }

    /// marker 门控的公开清理 facade，供 stop、失败腿与 command 复用。
    pub async fn clear_system_proxy(&self) -> bool {
        self.system_proxy.clear().await
    }

    /// 启动期恢复系统代理 marker，并在同一启动汇流点恢复系统 DNS marker。
    pub async fn recover_system_proxy_on_startup(self: &Arc<Self>) -> bool {
        let recovered = self.system_proxy.recover().await;
        self.restore_system_dns_best_effort().await;
        recovered
    }

    /// `systemProxy` 起核成功后把 OS 代理指向本地 mixed 入站；失败只落非终态错误。
    pub(super) async fn maybe_enable_system_proxy(
        &self,
        user_config: &UserConfig,
        mixed_port: u16,
    ) {
        if !should_enable_system_proxy(user_config.proxy_mode_type) {
            return;
        }

        struct BypassCfg<'a>(&'a UserConfig);
        impl BypassConfig for BypassCfg<'_> {
            fn bypass_lan(&self) -> Option<bool> {
                self.0.bypass_lan
            }

            fn bypass_lan_list(&self) -> Option<&[String]> {
                self.0.bypass_lan_list.as_deref()
            }
        }

        let request = ProxyEnableRequest {
            address: "127.0.0.1".to_string(),
            http_port: mixed_port,
            socks_port: mixed_port,
            bypass_list: effective_bypass_lan(&BypassCfg(user_config)),
        };
        match self.system_proxy.enable(request).await {
            Ok(Ok(())) => {
                log::info!(
                    "系统代理已指向本地 mixed 入站（127.0.0.1:{mixed_port}）→ 流量经本地核（A1）"
                );
            }
            Ok(Err(error)) => {
                self.set_nonfatal_error(
                    &format!("系统代理启用失败，流量未经代理（当前为直连）：{error}"),
                    code::SYSTEM_PROXY_FAILED,
                );
            }
            Err(error) => {
                self.set_nonfatal_error(
                    &format!("系统代理启用结果未知，流量可能未经代理：{error}"),
                    code::SYSTEM_PROXY_FAILED,
                );
            }
        }
    }

    /// TUN 起核后检测无 marker 的第三方系统代理；每会话只允许一条仍有效的结果发提示。
    pub(super) async fn maybe_warn_system_proxy_residual(
        &self,
        mode: ProxyModeType,
        my_generation: Option<u64>,
    ) {
        if !mode.is_tun() || self.system_proxy.residual_warning_claimed() {
            return;
        }
        let found = self.system_proxy.detect_foreign_proxy().await;
        if my_generation.is_some_and(|generation| {
            self.gate.generation() != generation || !self.status().running
        }) {
            log::debug!("系统代理残留检测完成时起核世代已失效或核已停止 → 丢弃陈旧结果");
            return;
        }
        if !self.system_proxy.claim_residual_warning() {
            return;
        }
        match found {
            Ok(Some(proxy)) => {
                log::info!("TUN 模式下检测到非 Polaris 设置的系统代理（{proxy}）→ 提示用户");
                match self.error_emitter.get() {
                    Some(emitter) => emitter.emit_system_proxy_residual(&proxy),
                    None => log::debug!("emitter 未接线 → 跳过 event:systemProxyResidual"),
                }
            }
            Ok(None) => {}
            Err(error) => {
                log::error!("系统代理残留检测 spawn_blocking join 失败: {error}");
            }
        }
    }

    /// advisory 探测移出起核关键路径；世代守卫在探测完成后裁掉陈旧结果。
    pub(super) fn spawn_system_proxy_residual_warning(
        self: &Arc<Self>,
        mode: ProxyModeType,
        my_generation: u64,
    ) {
        if !mode.is_tun() {
            return;
        }
        let runtime = Arc::clone(self);
        tokio::spawn(async move {
            let started = std::time::Instant::now();
            runtime
                .maybe_warn_system_proxy_residual(mode, Some(my_generation))
                .await;
            log::info!(
                "后台系统代理残留检测耗时={}ms（不阻塞起核）",
                started.elapsed().as_millis()
            );
        });
    }
}

#[cfg(test)]
mod tests;
