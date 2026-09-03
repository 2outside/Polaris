//! 管理 API 客户端与 dashboard 连接信息。
//!
//! 建 gRPC 管理客户端、取 Bearer secret、按节点解析管理面落点、`endpointTag ↔ serverId` 逆映射、
//! dashboard 连接信息（供前端 `app:getSingboxDashboardConnection`）。

use std::collections::BTreeMap;

use polaris_config_engine::builder::build_id_to_tag_map;
use polaris_config_engine::builder::helpers::ServerLike;
use polaris_config_engine::user_config::app_config::UserConfig;
use polaris_singbox_grpc::{Endpoint, SingBoxApiClient};
use serde_json::Value;

use crate::runtime::management_api::GrpcManagementApi;

use super::ProxyRuntime;

impl ProxyRuntime {
    /// 建管理 API 客户端（h2c gRPC）。核未起 / 端口未解析 / 连不上 → `not_ready()`（→ 退回重启）。
    ///
    /// 每次热切换现连：tonic channel 是 lazy 的，建连成本低；持久化客户端需处理换核/换端口后的
    /// 失效重建，属 stats-worker 批次的连接管理范畴，本批不引入该状态。
    pub(super) async fn management_api(&self) -> GrpcManagementApi {
        let status = self.status();
        if !status.running || status.clash_api_port == 0 {
            return GrpcManagementApi::not_ready();
        }
        let secret = self.clash_api_secret();
        match SingBoxApiClient::connect(Endpoint::new("127.0.0.1", status.clash_api_port), secret)
            .await
        {
            Ok(c) => GrpcManagementApi::new(c),
            Err(e) => {
                log::warn!("管理 API 连接失败（热切换将退回重启）: {e}");
                GrpcManagementApi::not_ready()
            }
        }
    }

    /// 管理 API 的 Bearer secret（`clashApiSecret`，缺失/空 → 空串免认证）。热切换与 TS STATUS relay 共用。
    ///
    /// **必须走 `with_current` 投影，不得用 `current()`**：后者恒 clone **整份**用户配置（含全部
    /// `servers` 与规则，`runtime/config.rs:181-189` 明写），而本方法只要一个字符串字段。调用链是
    /// `probe_select_slot → hot_switch_selector → management_api → 本方法` —— **测速一轮 = N 次整份配置
    /// 深拷贝**（200 节点级配置下不是小数目），此外所有热切节点的路径都付这笔账。
    ///
    /// 闭包内禁忌（持读锁，禁再调 `ConfigManager` 任何方法）在此满足：只读一个字符串字段、无 I/O、
    /// 无回调。debug 构型下该禁忌由 `ReentrancyProbe` 有牙。
    pub(super) fn clash_api_secret(&self) -> String {
        self.config
            .with_current(|c| {
                c.get("clashApiSecret")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    /// 某个节点在**当前运行核**里的管理 API 落点：`(端口, secret, 该节点的 endpoint tag)`。
    ///
    /// `None` 有两种成因，调用方对用户的表述必须一致（都是「现在做不了」而不是「出错了」）：
    /// 核没在跑；或该 serverId 不在运行快照的 `id_to_tag` 里 —— 后者意味着**核吃进去的那份配置里
    /// 没有这个节点**（刚加还没重启、或已被删）。
    ///
    /// 🔴 **tag 解不到时不得回落成 `server.name` 猜一个**。热重设 exit_node 那条腿有这个回落，
    /// 是因为它猜错只是「热切失败、退回重启」；而 Taildrop 侧猜错的后果是**静默空结果**：核对
    /// 未知 endpointTag 返回的是一帧空收件箱而非错误（`daemon/started_service_taildrop.go:90-97`，
    /// 判据见 `SingBoxApiClient::first_taildrop_inbox_snapshot` 文档）⇒ 用户看到「收件箱是空的」，
    /// 而真实的收件箱在另一个端点上。宁可明说「取不到」。
    pub(crate) fn management_target_for(&self, server_id: &str) -> Option<(u16, String, String)> {
        let status = self.status();
        if !status.running {
            return None;
        }
        let tag = self
            .switch_snapshot
            .read()
            .ok()
            .and_then(|g| g.as_ref().and_then(|s| s.id_to_tag.get(server_id).cloned()))?;
        Some((status.clash_api_port, self.clash_api_secret(), tag))
    }

    /// 起核配置的 `endpointTag → serverId` 逆映射（`build_id_to_tag_map` 的逆）。
    ///
    /// TS STATUS 帧里端点以 `endpointTag`（= 节点显示名去重后的 outbound tag）标识；解码时据此逆映回
    /// `serverId`。**在起核时刻从核实际启动的那份配置构建**（而非读 `current_config`）：核发的 tag 恒是它
    /// 启动时的 tag，rename-without-restart 也不改运行核 tag，故 start 快照才与核 wire 一致。tag 唯一 →
    /// 逆映射 1:1；撞名（`build_id_to_tag_map` 追加 `(n)`）后仍唯一。
    pub(super) fn endpoint_tag_to_id(user_config: &UserConfig) -> BTreeMap<String, String> {
        struct SrvLike<'a>(&'a polaris_config_engine::user_config::server_config::ServerConfig);
        impl ServerLike for SrvLike<'_> {
            fn id(&self) -> &str {
                &self.0.id
            }
            fn name(&self) -> &str {
                &self.0.name
            }
        }
        let wrappers: Vec<SrvLike> = user_config.servers.iter().map(SrvLike).collect();
        build_id_to_tag_map(&wrappers)
            .into_iter()
            .map(|(id, tag)| (tag, id))
            .collect()
    }

    /// 取 dashboard 连接信息（上游 `app:getSingboxDashboardConnection`，:2377-2389）。
    ///
    /// 端口取运行期管理 API 端口（动态解析，渲染端构造不出）；secret 取 currentConfig.clashApiSecret。
    pub fn dashboard_connection(&self) -> Value {
        let s = self.status();
        if !s.running || s.clash_api_port == 0 {
            return serde_json::json!({ "ok": false, "url": "", "apiUrl": "", "secret": "" });
        }
        let secret = self
            .config
            .current()
            .ok()
            .and_then(|c| {
                c.get("clashApiSecret")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_default();
        serde_json::json!({
            "ok": true,
            "url": format!("http://127.0.0.1:{}/dashboard/", s.clash_api_port),
            "apiUrl": format!("http://127.0.0.1:{}", s.clash_api_port),
            "secret": secret,
        })
    }
}
