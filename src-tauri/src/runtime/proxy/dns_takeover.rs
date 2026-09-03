//! C7 系统 DNS 接管 owner：接管/还原/热插拔重灌的同步核与 async 包装、OS DNS 缓存刷新、
//! `takeoverSystemDns` 用户开关的三态读取。
//!
//! 底层操作（mac `networksetup`/`scutil`、Linux helper→`resolvectl`、Windows no-op）由
//! system-integration/helper 承担；本模块是**接线**层（L1，只依赖 façade 定义与 `set_nonfatal_error`）。

use std::sync::Arc;

use polaris_config_engine::user_config::app_config::UserConfig;
use polaris_helper_proto::Platform;
use serde_json::Value;

use super::{code, ProxyRuntime};

impl ProxyRuntime {
    // ── C7 系统 DNS 接管/还原/刷缓存（装配 + 命令收口 + 生命周期接线）─────────────────────────
    //
    // 底层操作（mac `networksetup`/`scutil`、Linux helper→`resolvectl`、Windows no-op）由
    // system-integration/helper 承担。本层是**接线**：控制器装配 + 命令/生命周期收口。

    /// C7：系统 DNS 接管的同步核（持锁 → `set_dns` → 报告是否留下接管 marker）。
    ///
    /// best-effort：`set_dns` 内部失败仅告警 + 回滚，**绝不抛**（DNS 治理降级不阻断 TUN 启动）。锁中毒 → 跳过。
    /// 命令层直调；async 生命周期经 [`set_system_dns_best_effort`](Self::set_system_dns_best_effort) 的 spawn_blocking 包。
    pub(crate) fn set_system_dns_locked(&self) -> bool {
        if Platform::current() == Platform::Linux {
            return match self.linux_resolved_controller.lock() {
                Ok(mut controller) => match controller.takeover() {
                    Ok(()) => true,
                    Err(error) => {
                        self.set_nonfatal_error(
                            &format!("Linux 系统 DNS 接管失败：{error}"),
                            code::SYSTEM_DNS_TAKEOVER_FAILED,
                        );
                        false
                    }
                },
                Err(error) => {
                    self.set_nonfatal_error(
                        &format!("Linux DNS 控制器锁中毒：{error}"),
                        code::SYSTEM_DNS_TAKEOVER_FAILED,
                    );
                    false
                }
            };
        }
        match self.dns_controller.lock() {
            Ok(mut c) => {
                c.set_dns();
                c.has_marker()
            }
            Err(e) => {
                log::error!("dns_controller 锁中毒: {e} → 跳过系统 DNS 接管");
                false
            }
        }
    }

    /// C7：系统 DNS 还原的同步核（持锁 → `restore_dns` → 报告 marker 是否已清）。
    pub(crate) fn restore_system_dns_locked(&self) -> bool {
        if Platform::current() == Platform::Linux {
            return match self.linux_resolved_controller.lock() {
                Ok(mut controller) => match controller.restore() {
                    Ok(()) => true,
                    Err(error) => {
                        log::error!("Linux 系统 DNS 还原失败（保留 marker 供下次重试）：{error}");
                        false
                    }
                },
                Err(error) => {
                    log::error!("Linux DNS 控制器锁中毒，无法还原：{error}");
                    false
                }
            };
        }
        match self.dns_controller.lock() {
            Ok(mut c) => {
                c.restore_dns();
                !c.has_marker()
            }
            Err(e) => {
                log::error!("dns_controller 锁中毒: {e} → 跳过系统 DNS 还原");
                false
            }
        }
    }

    /// C7：是否存在系统 DNS 接管 marker（命令层/诊断查询）。
    #[must_use]
    pub(crate) fn system_dns_has_marker(&self) -> bool {
        if Platform::current() == Platform::Linux {
            return self
                .linux_resolved_controller
                .lock()
                .map(|controller| controller.has_marker())
                .unwrap_or(false);
        }
        self.dns_controller
            .lock()
            .map(|c| c.has_marker())
            .unwrap_or(false)
    }

    /// C7：TUN 起核尾接管系统 DNS（best-effort，失败不阻断起核）。
    /// 同步控制器（mac exec / Linux helper IPC）挪进 `spawn_blocking`，锁绝不跨 await；调用方等待结果，
    /// 只在接管成功时启动链路 watcher。
    pub(super) async fn set_system_dns_best_effort(self: &Arc<Self>) -> bool {
        let this = Arc::clone(self);
        match tokio::task::spawn_blocking(move || this.set_system_dns_locked()).await {
            Ok(applied) => applied,
            Err(error) => {
                log::error!("系统 DNS 接管 spawn_blocking join 失败: {error}");
                false
            }
        }
    }

    /// C7：停核/启动自愈尾还原系统 DNS（best-effort）。无 marker（fresh / 已还原）→ 惰性。
    pub(super) async fn restore_system_dns_best_effort(self: &Arc<Self>) {
        let this = Arc::clone(self);
        if let Err(e) = tokio::task::spawn_blocking(move || this.restore_system_dns_locked()).await
        {
            log::error!("系统 DNS 还原 spawn_blocking join 失败: {e}");
        }
    }

    /// row33：DNS 热插拔重灌的门控判定（纯逻辑，便于单测 + 变异）。`should_reconcile_dns` 的运行时适配：
    /// 仅当前配置仍 TUN 模式（切走 TUN → 虽 marker 在也不再重灌）+ **用户未关 `takeoverSystemDns`** +
    /// 有接管 marker 才放行。三条与起核尾的接管门（[`dns_takeover_enabled`] + `is_tun`）同口径。
    pub(super) fn dns_reconcile_should_run(
        is_tun: bool,
        takeover: Option<bool>,
        has_marker: bool,
    ) -> bool {
        polaris_system_integration::dns_watcher::should_reconcile_dns(
            if is_tun { Some("tun") } else { None },
            takeover,
            has_marker,
        )
    }

    /// row33：DNS 接口热插拔重灌的同步核（持锁 → 门控 → `reconcile_dns`）。best-effort，绝不抛。
    /// 门控（[`Self::dns_reconcile_should_run`]）：当前配置 TUN + 接管 marker 在。锁中毒 / 门未过 → 跳过。
    pub(crate) fn reconcile_system_dns_locked(&self) -> bool {
        let raw = self.config.current().ok();
        let is_tun = raw
            .clone()
            .and_then(|v| serde_json::from_value::<UserConfig>(v).ok())
            .is_some_and(|c| c.proxy_mode_type.is_tun());
        // 用户开关活态（从**原始 JSON** 读：`dnsConfig.takeoverSystemDns` 不在 `DnsConfig` 结构体里，
        // 同 `restartOnNodeChange` / `autoSwitchNode` / `meshLoginFallbackDirect` 的既定手法）。
        let takeover = raw.as_ref().and_then(dns_takeover_enabled);
        let has_marker = self.system_dns_has_marker();
        if !Self::dns_reconcile_should_run(is_tun, takeover, has_marker) {
            return false;
        }
        if Platform::current() == Platform::Linux {
            return match self.linux_resolved_controller.lock() {
                Ok(mut controller) => match controller.reconcile() {
                    Ok(()) => true,
                    Err(error) => {
                        self.set_nonfatal_error(
                            &format!("Linux 系统 DNS 热切换重放失败：{error}"),
                            code::SYSTEM_DNS_TAKEOVER_FAILED,
                        );
                        false
                    }
                },
                Err(error) => {
                    log::error!("Linux DNS 控制器锁中毒，跳过热切换重放：{error}");
                    false
                }
            };
        }
        match self.dns_controller.lock() {
            Ok(mut c) => {
                c.reconcile_dns();
                true
            }
            Err(e) => {
                log::error!("dns_controller 锁中毒: {e} → 跳过 DNS 热插拔重灌");
                false
            }
        }
    }

    /// row33：DNS 热插拔重灌（async 包装，spawn_blocking 持锁；锁绝不跨 await）。watcher 去抖后调。
    pub(super) async fn reconcile_system_dns_best_effort(self: &Arc<Self>) {
        let this = Arc::clone(self);
        if let Err(e) =
            tokio::task::spawn_blocking(move || this.reconcile_system_dns_locked()).await
        {
            log::error!("DNS 热插拔重灌 spawn_blocking join 失败: {e}");
        }
    }

    /// C7：核 start/stop 尾刷 OS DNS 缓存（fire-and-forget、best-effort、永不阻塞代理生命周期）。
    ///
    /// 语义对齐 上游 `flushOsDnsCacheBestEffort`：mac 优先 root helper（`flush-dns`：dscacheutil + HUP
    /// mDNSResponder 两层全清）→ 不可用降级用户级 `dscacheutil`；win `ipconfig /flushdns`；linux `resolvectl
    /// flush-caches`。动机：核 start/stop 跨越「系统解析器受控/还原」边界时清缓存里残留另一侧记录（TUN+FakeIP
    /// 会话期假 IP 停核后仍命中 → 直连撞墙，反向同理）。
    ///
    /// **真机门**：真刷宿主 DNS 缓存**触碰宿主**（本机 Linux 会真跑 `resolvectl`）——故仅在**真跑 app** 时发生，
    /// 单测/gate 不触发（本方法只被 start/stop 生命周期调，不被测试直调）。
    pub(super) fn flush_os_dns_cache_best_effort(self: &Arc<Self>, context: &'static str) {
        let this = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            // mac helper flush 通道（其它平台不经此腿，见 `flush_os_dns_cache` 平台分派）。
            let helper_flush = || this.helper.flush_dns();
            let flushed = polaris_system_integration::production_flush_os_dns_cache(
                Some(&helper_flush),
                &mut |m| log::info!("[dns-flush:{context}] {m}"),
            );
            if Platform::current() == Platform::Linux && !flushed {
                this.set_nonfatal_error(
                    "Linux 系统 DNS 缓存刷新失败；旧的失败缓存可能继续影响域名解析",
                    code::SYSTEM_DNS_TAKEOVER_FAILED,
                );
            }
        });
    }
}

/// **C7 用户开关**：原始 config JSON 的 `dnsConfig.takeoverSystemDns` 三态读取（纯函数）。
///
/// **为何从裸 JSON 读**：该字段不在 config-engine 的 `DnsConfig` 结构体里（前端契约
/// `ui/src/contracts/types.ts:324` 有、Rust 侧无建模），与 `restartOnNodeChange` / `autoSwitchNode` /
/// `meshLoginFallbackDirect` 同法 —— 不为一个纯运行期开关去改共享的配置结构体（那会波及 norm/生成/快照
/// 四条链，而它一条都不该影响：接管与否不改 sing-box config 一个字节）。
///
/// 返回**三态**而非 bool：调用方一律按 上游的 `!== false` 口径判（`Some(false)` 才算关），
/// 缺省与非布尔都等价于「未显式关」。若在此折成 bool，`None`（缺省=开）与 `Some(true)` 的区别就没了，
/// 下游想改默认方向时会误把「用户没表态」当成「用户选了开」。
pub(super) fn dns_takeover_enabled(config: &Value) -> Option<bool> {
    config
        .get("dnsConfig")
        .and_then(|d| d.get("takeoverSystemDns"))
        .and_then(Value::as_bool)
}
