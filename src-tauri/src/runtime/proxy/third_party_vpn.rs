//! OpenConnect / OpenVPN 原生状态 relay（第三方 VPN 协议 STATUS 帧接线）。

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use polaris_singbox_grpc::{Endpoint, ReconnectConfig, SingBoxApiClient};

use crate::runtime::vpn_status::{decode_openconnect_status, decode_openvpn_status};

use super::recovery::CRASH_MONITOR_POLL_MS;
use super::ProxyRuntime;

impl ProxyRuntime {
    /// **A3**：核就绪后挂 Tailscale STATUS relay（`spawn_crash_monitor` 的世代范式）。
    ///
    /// 订阅运行核管理 API 的 `SubscribeTailscaleStatus` 流（自动重连），每帧解码 → 更新末帧缓存 +
    /// `event:tailscaleStatus`。**世代守卫**：`my_gen ≠ 当前世代`（被更新的 start/stop 接管）→ 退场并
    /// drop 流（停订阅、停重连），绝不让旧核的 relay 污染新核。因 `ReconnectingStream` 永不自行结束
    /// （断开即退避重连），必须有独立的周期 tick 兜底世代检查——否则「核停了但一直没帧」时 relay 会
    /// 泄漏、对死端口无限重连。tick 复用 `spawn_crash_monitor` 的 1s 量级。
    ///
    /// # 停流自愈（2026-08-02 真机实证）
    ///
    pub(super) fn apply_openconnect_status_frame(
        &self,
        update: &polaris_singbox_grpc::daemon::OpenConnectStatusUpdate,
        tag_to_id: &BTreeMap<String, String>,
    ) {
        let events = decode_openconnect_status(update, tag_to_id);
        self.mesh.update_openconnect_status(events.clone());
        if let Some(emitter) = self.error_emitter.get() {
            for event in &events {
                emitter.emit_openconnect_status(event);
            }
        }
    }

    pub(super) fn apply_openvpn_status_frame(
        &self,
        update: &polaris_singbox_grpc::daemon::OpenVpnStatusUpdate,
        tag_to_id: &BTreeMap<String, String>,
    ) {
        let events = decode_openvpn_status(update, tag_to_id);
        self.mesh.update_openvpn_status(events.clone());
        if let Some(emitter) = self.error_emitter.get() {
            for event in &events {
                emitter.emit_openvpn_status(event);
            }
        }
    }

    /// OpenConnect rc.2 原生状态 relay。日志只记录 endpoint/state/challengeID，绝不展开浏览器 URL、
    /// cookie/header 名值或表单初值；具体认证材料只进入内存事件载荷。
    pub(super) fn spawn_openconnect_status_relay(
        self: &Arc<Self>,
        my_gen: u64,
        api_port: u16,
        tag_to_id: Arc<BTreeMap<String, String>>,
    ) {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let client = match SingBoxApiClient::connect(
                Endpoint::new("127.0.0.1", api_port),
                me.clash_api_secret(),
            )
            .await
            {
                Ok(client) => client,
                Err(error) => {
                    log::warn!(
                        "OpenConnect STATUS relay 连接管理 API 失败（apiPort={api_port}）: {error}"
                    );
                    return;
                }
            };
            let mut stream = client.subscribe_openconnect_status(ReconnectConfig::default());
            let tick = Duration::from_millis(CRASH_MONITOR_POLL_MS);
            let mut last: BTreeMap<String, (String, Option<String>)> = BTreeMap::new();
            log::info!("OpenConnect STATUS relay 起（世代 {my_gen}，apiPort={api_port}）");
            loop {
                if me.gate.generation() != my_gen {
                    return;
                }
                match tokio::time::timeout(tick, stream.recv()).await {
                    Ok(Some(update)) => {
                        if me.gate.generation() != my_gen {
                            return;
                        }
                        for endpoint in &update.endpoints {
                            let challenge_id = endpoint
                                .auth_challenge
                                .as_ref()
                                .map(|challenge| challenge.id.clone());
                            let current = (endpoint.state.clone(), challenge_id);
                            if last.get(&endpoint.endpoint_tag) != Some(&current) {
                                log::info!(
                                    "OpenConnect 端点状态：tag={} state={} challengeID={}",
                                    endpoint.endpoint_tag,
                                    endpoint.state,
                                    current.1.as_deref().unwrap_or("-")
                                );
                                last.insert(endpoint.endpoint_tag.clone(), current);
                            }
                        }
                        me.apply_openconnect_status_frame(&update, &tag_to_id);
                    }
                    Ok(None) => return,
                    Err(_) => {}
                }
            }
        });
    }

    /// OpenVPN rc.2 原生状态 relay。与 OpenConnect 同样只记状态与 challengeID，challenge URL/消息
    /// 不进入日志；WireGuard 没有等价结构化 RPC，继续由统一核日志 relay 覆盖。
    pub(super) fn spawn_openvpn_status_relay(
        self: &Arc<Self>,
        my_gen: u64,
        api_port: u16,
        tag_to_id: Arc<BTreeMap<String, String>>,
    ) {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let client = match SingBoxApiClient::connect(
                Endpoint::new("127.0.0.1", api_port),
                me.clash_api_secret(),
            )
            .await
            {
                Ok(client) => client,
                Err(error) => {
                    log::warn!(
                        "OpenVPN STATUS relay 连接管理 API 失败（apiPort={api_port}）: {error}"
                    );
                    return;
                }
            };
            let mut stream = client.subscribe_openvpn_status(ReconnectConfig::default());
            let tick = Duration::from_millis(CRASH_MONITOR_POLL_MS);
            let mut last: BTreeMap<String, (String, Option<String>)> = BTreeMap::new();
            log::info!("OpenVPN STATUS relay 起（世代 {my_gen}，apiPort={api_port}）");
            loop {
                if me.gate.generation() != my_gen {
                    return;
                }
                match tokio::time::timeout(tick, stream.recv()).await {
                    Ok(Some(update)) => {
                        if me.gate.generation() != my_gen {
                            return;
                        }
                        for endpoint in &update.endpoints {
                            let challenge_id = endpoint
                                .challenge
                                .as_ref()
                                .map(|challenge| challenge.id.clone());
                            let current = (endpoint.state.clone(), challenge_id);
                            if last.get(&endpoint.endpoint_tag) != Some(&current) {
                                log::info!(
                                    "OpenVPN 端点状态：tag={} state={} challengeID={}",
                                    endpoint.endpoint_tag,
                                    endpoint.state,
                                    current.1.as_deref().unwrap_or("-")
                                );
                                last.insert(endpoint.endpoint_tag.clone(), current);
                            }
                        }
                        me.apply_openvpn_status_frame(&update, &tag_to_id);
                    }
                    Ok(None) => return,
                    Err(_) => {}
                }
            }
        });
    }
}
