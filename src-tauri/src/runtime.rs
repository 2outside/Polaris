//! 运行时层：把 18 个纯逻辑/trait crate 装配为持有真实 I/O 实现的运行时实例。
//!
//! 架构（见系统设计 §B.2 / §H）：各 domain crate 是纯逻辑 + trait 抽象（`ConfigFs` / `SingBoxSpawner`
//! / `ManagementApi` / `HttpClient` / `SysOps` 等），src-tauri 在此注入真实实现——
//! `tokio` runtime、`std::fs`、真 TCP/UDS socket、真 HTTP 客户端——构成可被 `#[tauri::command]`
//! 直接调用的运行时管理器。
//!
//! 模块：
//! - [`config`]：`ConfigManager`（`store::ConfigStore` + `StdFs` + currentConfig 缓存，Polaris ConfigManager 等价）。
//! - [`proxy`]：`ProxyRuntime`（sing-box 进程编排：spawn + 系统代理 + clash_api 管理；Polaris ProxyManager 等价）。
//! - [`stats`]：`StatsRelay`（stats-engine 订阅注册表 + 流 relay 到 Tauri event）。
//! - [`geo_seed`]：随包内置 geo `.srs` 播种到运行时 rules 目录（上游 `seedBuiltinRuleSets` 等价）。
//! - [`helper`]：`HelperRuntime`（helper-client + 平台 helper 装配）。
//! - [`mesh`]：`MeshRuntime`（warp 注册 / tailscale 登录 / exit route，mesh crate 装配）。
//!
//! 注：各运行时的访问器（dir / path / platform / config 等）为后续 actor 批次（crash-recovery /
//! stats-worker / mesh-warp）预留注入点；当前仅 command 层用到子集，`dead_code` 全模块放行。

pub mod auto_switch;
pub mod config;
pub mod core_paths;
pub mod core_promote;
pub mod core_swap;
pub mod core_update_scheduler;
pub mod core_validation;
/// 路径型环境逃生门的信任级判定单点（`POLARIS_SINGBOX_PATH` / `POLARIS_HELPER_PATH`）。
pub(crate) mod env_trust;
pub mod geo_seed;
pub mod helper;
pub mod http;
pub mod management_api;
pub mod mesh;
/// pending `modified`（全维）与测速 dirty（5 维）两条判据的单点定义 + 包含关系不变式。
pub mod node_fingerprints;
pub mod proxy;
pub mod route_binding;
pub mod rule_resource_scheduler;
pub mod speedtest;
/// 单节点测速的 **CONNECT 隧道**探针（建隧道 + 隧道内两次 GET；`commands/speedtest.rs` 的传输面）。
pub mod speedtest_tunnel;
pub mod startup_tasks;
pub mod stats;
pub mod subscription_create;
pub mod subscription_parse;
pub mod subscription_scheduler;
pub mod taildrop;
pub mod tailscale_login_core;
pub mod tailscale_status;
pub mod uninstall;
pub mod unlock;
pub mod update_install;
pub mod update_popup;
pub mod updater;
pub mod vpn_status;
pub mod win_console;
#[cfg(windows)]
pub(crate) mod windows_network_change;
#[cfg(windows)]
pub(crate) mod windows_process;
#[cfg(windows)]
pub(crate) mod windows_proxy_registry;
pub mod x25519;

/// 真内核 ignored tests 会扫描/清扫同一路径的 sing-box；默认并行执行会互相误判为孤儿。
/// 异步锁只存在于测试构建，统一串行 proxy、speedtest 与 stats 三个模块的真实进程用例。
#[cfg(test)]
pub(crate) static REAL_CORE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

use std::sync::Arc;

use crate::runtime::{
    config::ConfigManager, helper::HelperRuntime, http::HttpRuntime, mesh::MeshRuntime,
    proxy::ProxyRuntime, stats::StatsRelay, taildrop::TaildropRuntime, unlock::UnlockRuntime,
    updater::UpdaterRuntime,
};

/// 聚合所有运行时实例的根（注入 Tauri `State`）。
///
/// 各字段用 `Arc<...>` 以便后台任务（stats relay / 事件广播）克隆持有、跨 `tokio::spawn` 边界。
/// 单实例（`manage` 一次），command 经 `State<'_, AppRuntime>` 取引用。
pub struct AppRuntime {
    pub config: Arc<ConfigManager>,
    pub proxy: Arc<ProxyRuntime>,
    pub stats: Arc<StatsRelay>,
    pub helper: Arc<HelperRuntime>,
    pub mesh: Arc<MeshRuntime>,
    /// 更新运行时（App 自更新 + 内核更新 + mini 弹窗会话）。
    pub updater: Arc<UpdaterRuntime>,
    /// 传输层单点：**全 App 唯一**的真实 HTTP/TLS 客户端（见 `runtime/http.rs`）。
    /// 订阅拉取 / 内核下载 / 解锁检测 / WARP 全部经它注入既有窄 trait。
    pub http: Arc<HttpRuntime>,
    /// 解锁检测编排（run/get/快照/事件/出口 pin/TTL/归属 bracket；见 `runtime/unlock.rs`）。
    pub unlock: Arc<UnlockRuntime>,
    /// Taildrop 发件任务所有者（有界快照、取消与终态保留；窗口关闭后仍可重新附着）。
    pub taildrop: Arc<TaildropRuntime>,
    /// 订阅原子创建任务所有者（operationId 幂等、可取消、renderer 重建后可重附）。
    pub subscription_create: Arc<subscription_create::SubscriptionCreateRuntime>,
    /// 订阅正文的固定容量 CPU executor；独立线程、逻辑取消、退出不 join。
    pub subscription_parse: Arc<subscription_parse::SubscriptionParseExecutor>,
}

impl AppRuntime {
    /// 装配全部运行时（main 启动期调用一次）。
    ///
    /// 路径锚 `<app_config_dir>/polaris/`（Tauri `path::app_config_dir`，对齐 上游 `app.getPath('userData')`）。
    ///
    /// # Errors
    ///
    /// 传输层 client 初始化失败（TLS 后端异常）。**报错退出优于带残缺网络栈硬跑**：
    /// 无 HTTP client 则订阅/更新/解锁/WARP 全不可用，早失败比运行期到处报「未接线」清晰。
    pub fn new(config_dir: std::path::PathBuf) -> Result<Self, String> {
        let config = Arc::new(ConfigManager::new(config_dir.clone()));
        let helper = Arc::new(HelperRuntime::new(config_dir.clone()));
        // 生产装配：注入 helper → mesh 出口路由 op 启用（真三平台 route 手术）。测试路径用 `MeshRuntime::new`（禁用 op）。
        let mesh = Arc::new(MeshRuntime::new_with_helper(
            config_dir.clone(),
            helper.clone(),
        ));
        let stats = Arc::new(StatsRelay::default());
        let updater = Arc::new(UpdaterRuntime::new(config_dir.clone()));
        let http = Arc::new(HttpRuntime::new()?);
        let unlock = Arc::new(UnlockRuntime::default());
        let taildrop = Arc::new(TaildropRuntime::default());
        let subscription_create =
            Arc::new(subscription_create::SubscriptionCreateRuntime::default());
        let subscription_parse = Arc::new(subscription_parse::SubscriptionParseExecutor::default());
        // 系统代理清理收口器（维度7 #8）：生产装配真实控制器（本机平台命令 + 真实 FS marker）。
        // marker 路径 = `<userData>/system-proxy.marker.json`（对齐 上游 `SystemProxyBase.getMarkerPath`）。
        // 无 marker（fresh start）时 `ensure_cleared` 门控 1 即返、零系统调用 → 挂每个失败腿都安全。
        let proxy_marker_path = config_dir.join(polaris_system_integration::PROXY_MARKER_FILENAME);
        #[cfg(target_os = "macos")]
        let proxy_clearer: Box<
            dyn crate::runtime::proxy::system_takeover::SystemProxyClearer,
        > = Box::new(
            polaris_system_integration::production_proxy_controller_with_macos_writer(
                proxy_marker_path.to_string_lossy().into_owned(),
                helper.clone(),
            ),
        );
        #[cfg(target_os = "windows")]
        let proxy_clearer: Box<
            dyn crate::runtime::proxy::system_takeover::SystemProxyClearer,
        > = Box::new(
            polaris_system_integration::production_proxy_controller_with_windows_writer(
                proxy_marker_path.to_string_lossy().into_owned(),
                Arc::new(windows_proxy_registry::WindowsNativeProxyRegistryWriter),
                polaris_system_integration::proxy_ops::windows_quic_cleanup_prewarmed(),
            ),
        );
        #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
        let proxy_clearer: Box<
            dyn crate::runtime::proxy::system_takeover::SystemProxyClearer,
        > = Box::new(polaris_system_integration::production_proxy_controller(
            proxy_marker_path.to_string_lossy().into_owned(),
        ));
        let proxy = Arc::new(ProxyRuntime::new(
            config.clone(),
            helper.clone(),
            mesh.clone(),
            proxy_clearer,
            // C11：竞速 sidecar 的 DoH 上游走同一个 `HttpRuntime`（workspace 唯一真实 HTTP/TLS 客户端）。
            http.clone(),
        ));
        Ok(Self {
            config,
            proxy,
            stats,
            helper,
            mesh,
            updater,
            http,
            unlock,
            taildrop,
            subscription_create,
            subscription_parse,
        })
    }

    /// 配置运行时（命令层便捷访问）。
    #[must_use]
    pub fn config(&self) -> &ConfigManager {
        &self.config
    }

    /// 代理运行时。
    #[must_use]
    pub fn proxy(&self) -> &ProxyRuntime {
        &self.proxy
    }

    /// stats 运行时。
    #[must_use]
    pub fn stats(&self) -> &StatsRelay {
        &self.stats
    }

    /// helper 运行时。
    #[must_use]
    pub fn helper(&self) -> &HelperRuntime {
        &self.helper
    }

    /// mesh 运行时。
    #[must_use]
    pub fn mesh(&self) -> &MeshRuntime {
        &self.mesh
    }

    /// 更新运行时。
    #[must_use]
    pub fn updater(&self) -> &UpdaterRuntime {
        &self.updater
    }

    /// 传输层单点（真实 HTTP client）。
    #[must_use]
    pub fn http(&self) -> &Arc<HttpRuntime> {
        &self.http
    }

    /// 解锁检测编排运行时。
    #[must_use]
    pub fn unlock(&self) -> &UnlockRuntime {
        &self.unlock
    }

    /// Taildrop 发件任务运行时。
    #[must_use]
    pub fn taildrop(&self) -> &Arc<TaildropRuntime> {
        &self.taildrop
    }

    /// 订阅原子创建任务运行时。
    #[must_use]
    pub fn subscription_create(&self) -> &Arc<subscription_create::SubscriptionCreateRuntime> {
        &self.subscription_create
    }

    /// 订阅解析 CPU executor。
    #[must_use]
    pub fn subscription_parse(&self) -> &Arc<subscription_parse::SubscriptionParseExecutor> {
        &self.subscription_parse
    }
}
