//! 热切换执行 —— 上游 `ProxyManager.hotSwitchSelector`（L2451-2470）+ `switchMode` 热切腿
//! 的 PUT 循环（L1791-1841）。
//!
//! 消费 config-engine 的 [`HotSwitchPlan`]（planHotSwitch 产物），把 `plan.puts` 逐条下发到
//! sing-box 管理 API 的 `SelectOutbound`（clash 等价热切换）。PUT 成功后触发精准断连（关旧成员
//! 存量连接）。
//!
//! # trait 抽象（移植纪律 #1：gRPC/进程操作 trait 抽象，测试 mock）
//!
//! Polaris 直接持有 `SingBoxApiClient`（gRPC 客户端实例）。本 crate 把「热切换一个 selector」
//! 与「关单条连接」/「订阅连接首帧」抽到 [`ManagementApi`] trait——生产实现转发到
//! `polaris-singbox-grpc` 的 `SingBoxApiClient`，测试用 `MockManagementApi`（测试替身）注入任意行为
//! （成功 / 失败 / 连接列表）。
//!
//! # 失败语义（Polaris L1789-1841）
//!
//! plan.puts 的 PUT 逐条执行，任一失败 → 整体退回去抖重启兜底（保证一定能应用）。Polaris
//! 原文用 `allOk` 布尔 + break：第一条失败即停（后续 PUT 不再尝试）。本 executor 忠实
//! 复刻——返回 [`HotSwitchOutcome::Failed`]，由上层决策退回去抖重启。
//!
//! # 精准断连开关（维度7 #19）
//!
//! `interrupt_connections_on_switch` 开关关闭 → 热切换成功后**不断**旧成员连接（用户明确接受
//! 存量连接继续走旧路径直到自然结束）。开关开 → PUT 全成功后调 `precision_disconnect`。
//! 与 sing-box selector 的 `interrupt_exist_connections`（对 routed 连接 no-op）正交——
//! 那是内核侧无效，本侧是应用侧显式关。

#![forbid(unsafe_code)]

use async_trait::async_trait;

use polaris_config_engine::builder::hotswitch::HotSwitchPlan;

use crate::precision_disconnect::{
    select_connections_to_close, switched_pairs_from_puts, ConnectionSnapshot,
    PrecisionDisconnectOutcome, SwitchedMemberPair,
};

/// sing-box 管理 API 的最小契约（热切换 + 连接管理）。
///
/// 生产实现转发到 `polaris-singbox-grpc::SingBoxApiClient`：
/// - [`ManagementApi::select_outbound`] → `SingBoxApiClient::select_outbound`（SelectOutbound PUT）。
/// - [`ManagementApi::close_connection`] → `SingBoxApiClient::close_connection`。
/// - [`ManagementApi::first_connection_snapshot`] → `subscribe_connections` 首帧（reset 全量）。
///
/// trait 化是为可测：`MockManagementApi`（测试替身）注入任意成功/失败/连接列表，不依赖真实 gRPC。
/// 返回 `Result<(), ManagementError>`：成功 Ok，失败 Err（调用方据此退回重启兜底）。
#[async_trait]
pub trait ManagementApi: Send + Sync {
    /// 热切换一个 selector 到指定成员（clash SelectOutbound 等价）。
    /// 上游 `hotSwitchSelector` → `client.selectOutbound(selectorTag, memberTag)`。
    async fn select_outbound(
        &self,
        selector_tag: &str,
        member_tag: &str,
    ) -> Result<(), ManagementError>;

    /// 关闭单条连接（精准断连逐条关）。
    /// 上游 `client.closeConnection(id)`。best-effort：失败仅记日志（不阻断断连流程）。
    async fn close_connection(&self, id: &str) -> Result<(), ManagementError>;

    /// 取连接列表首帧快照（精准断连用）。
    ///
    /// 上游 `subscribeConnections(1_000_000_000, cb)` 的首帧（reset 帧 = 内核当前全量连接）。
    /// 带 3s 兜底超时（上游 `guard = setTimeout(..., 3000)`）：首帧不来时返回空（跳过断连，
    /// 宁可漏关不泄漏订阅）。返回当前全量连接快照（含已关闭的死连接历史环，由本层过滤）。
    async fn first_connection_snapshot(&self) -> Result<Vec<ConnectionSnapshot>, ManagementError>;
}

/// 管理 API 错误（gRPC status / 超时 / 客户端未就绪）。
///
/// Polaris 把 gRPC SelectOutbound 的 throw 包成 `false`（退去抖重启兜底）。本 crate 保留错误
/// 上下文（trait 调用方可记日志），决策层据 `Err` 退回重启。
#[derive(Debug, Clone, thiserror::Error)]
pub enum ManagementError {
    /// gRPC 调用失败（tonic::Status / transport error 的字符串化）。
    #[error("management API call failed: {0}")]
    Call(String),
    /// 客户端未就绪（核未起 / API 未连）。上游 `管理 API 客户端未就绪` 路径。
    #[error("management API client not ready")]
    NotReady,
    /// 连接首帧订阅超时（3s 兜底）。
    #[error("connection snapshot first-frame timeout")]
    SnapshotTimeout,
}

/// 热切换执行结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HotSwitchOutcome {
    /// 全部 PUT 成功（精准断连结果附带）。
    ///
    /// `disconnect` 仅在 `interrupt_connections_on_switch=true` 时非空（开关关 → outcome 为 None）。
    Applied {
        /// 精准断连结果（关掉的旧成员连接 id 列表）。None = 开关关、未执行断连。
        disconnect: Option<PrecisionDisconnectOutcome>,
    },
    /// 任一 PUT 失败 → 退回去抖重启兜底（保证一定能应用）。
    ///
    /// `failed_selector` / `failed_member` 标识失败的 PUT 项（日志用）。
    Failed {
        failed_selector: String,
        failed_member: String,
        error: String,
    },
    /// 客户端未就绪（核未起 / 管理 API 未连）→ 退回重启。
    ///
    /// 单独一态：上游 `hotSwitchSelector` 在 client=null 时返 false（退去抖重启）。
    /// 与 `Failed` 区分以便上层日志区分「未就绪」vs「PUT 报错」。
    ClientNotReady,
}

/// 热切换执行器：把 [`HotSwitchPlan`] 的 puts 逐条下发到管理 API。
///
/// 上游 `ProxyManager` 的热切腿（L1786-1841）+ `hotSwitchSelector`（L2451）。
/// 无实例态——每次 [`SwitchExecutor::execute`] 读取注入的 `api`，可并发安全共享。
#[derive(Debug, Default)]
pub struct SwitchExecutor;

impl SwitchExecutor {
    /// 执行热切换：逐条 PUT `plan.puts`，全成功后按开关触发精准断连。
    ///
    /// 上游 `switchMode` 热切腿（L1791-1841）：
    /// 1. 逐条 `hotSwitchSelector(p.selector_tag, p.member_tag)`；任一 false → 退回重启。
    /// 2. 全成功 → `closeOldNodeConnectionsAfterHotSwitch(new_config, plan)`（开关门控）。
    ///
    /// `interrupt_connections_on_switch`：精准断连开关。false → 跳过断连（outcome.disconnect=None）。
    /// true → 调 `precision_disconnect` 关旧成员存量连接。
    ///
    /// 返回 [`HotSwitchOutcome`]：Applied（含断连结果）/ Failed / ClientNotReady。
    pub async fn execute(
        &self,
        api: &dyn ManagementApi,
        plan: &HotSwitchPlan,
        interrupt_connections_on_switch: bool,
    ) -> HotSwitchOutcome {
        // 腿 1：逐条 PUT（Polaris L1791-1796）。第一条失败即停（break）。
        for p in &plan.puts {
            match api.select_outbound(&p.selector_tag, &p.member_tag).await {
                Ok(()) => {}
                // 客户端未就绪 → ClientNotReady（Polaris client=null 路径）。
                Err(ManagementError::NotReady) => return HotSwitchOutcome::ClientNotReady,
                // PUT 报错 → Failed（退回重启兜底）。
                Err(e) => {
                    return HotSwitchOutcome::Failed {
                        failed_selector: p.selector_tag.clone(),
                        failed_member: p.member_tag.clone(),
                        error: e.to_string(),
                    };
                }
            }
        }

        // 腿 2：精准断连（Polaris L1810 closeOldNodeConnectionsAfterHotSwitch）。
        let disconnect = if interrupt_connections_on_switch {
            Some(self.precision_disconnect(api, &plan.puts).await)
        } else {
            None
        };

        HotSwitchOutcome::Applied { disconnect }
    }

    /// 精准断连：取连接首帧 → 筛命中 pair 的活连接 → 逐条关。
    ///
    /// 上游 `closeOldNodeConnectionsAfterHotSwitch`（L2015-2068）。pair 从 puts 现算
    /// （实际改变了指向的 selector 的 (selector, 旧成员) 对）。
    ///
    /// best-effort：连接首帧超时 / 关连接失败 → 不阻断热切换（已 PUT 成功），仅影响断连计数。
    async fn precision_disconnect(
        &self,
        api: &dyn ManagementApi,
        puts: &[polaris_config_engine::builder::hotswitch::HotSwitchPut],
    ) -> PrecisionDisconnectOutcome {
        let pairs: Vec<SwitchedMemberPair> = switched_pairs_from_puts(puts);
        if pairs.is_empty() {
            return PrecisionDisconnectOutcome::default();
        }
        // 连接首帧（3s 兜底超时由 trait 实现负责）。超时 / 失败 → 空列表（跳过断连，不阻断热切）。
        let snapshot = match api.first_connection_snapshot().await {
            Ok(s) => s,
            Err(_) => return PrecisionDisconnectOutcome::default(),
        };
        let outcome = select_connections_to_close(&snapshot, &pairs);
        // 逐条关（best-effort：失败仅忽略，不阻断——上游 `void client.closeConnection(id).catch(()=>{})`）。
        for id in &outcome.closed_ids {
            let _ = api.close_connection(id).await;
        }
        outcome
    }
}

/// 测试用 mock 管理 API：可预设 PUT 成功/失败 + 连接快照。
#[cfg(test)]
pub struct MockManagementApi {
    /// 预设的 PUT 结果队列：每个 (selector, member) 对应一个结果。未预设的默认 Ok。
    pub put_results: std::sync::Mutex<Vec<MockPut>>,
    /// 预设的连接首帧快照。
    pub connections: std::sync::Mutex<Vec<ConnectionSnapshot>>,
    /// 是否未就绪（select_outbound 返 NotReady）。
    pub not_ready: bool,
    /// 记录所有 select_outbound 调用（顺序）。
    pub put_calls: std::sync::Mutex<Vec<(String, String)>>,
    /// 记录所有 close_connection 调用。
    pub close_calls: std::sync::Mutex<Vec<String>>,
}

#[cfg(test)]
#[derive(Clone)]
pub struct MockPut {
    pub selector: String,
    pub member: String,
    pub result: Result<(), ManagementError>,
}

#[cfg(test)]
impl Default for MockManagementApi {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl MockManagementApi {
    pub fn new() -> Self {
        Self {
            put_results: std::sync::Mutex::new(Vec::new()),
            connections: std::sync::Mutex::new(Vec::new()),
            not_ready: false,
            put_calls: std::sync::Mutex::new(Vec::new()),
            close_calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn with_connections(self, conns: Vec<ConnectionSnapshot>) -> Self {
        *self.connections.lock().unwrap() = conns;
        self
    }

    pub fn with_put(
        self,
        selector: &str,
        member: &str,
        result: Result<(), ManagementError>,
    ) -> Self {
        self.put_results.lock().unwrap().push(MockPut {
            selector: selector.into(),
            member: member.into(),
            result,
        });
        self
    }

    pub fn not_ready(mut self) -> Self {
        self.not_ready = true;
        self
    }
}

#[cfg(test)]
#[async_trait]
impl ManagementApi for MockManagementApi {
    async fn select_outbound(
        &self,
        selector_tag: &str,
        member_tag: &str,
    ) -> Result<(), ManagementError> {
        if self.not_ready {
            return Err(ManagementError::NotReady);
        }
        self.put_calls
            .lock()
            .unwrap()
            .push((selector_tag.into(), member_tag.into()));
        let results = self.put_results.lock().unwrap();
        for put in results.iter() {
            if put.selector == selector_tag && put.member == member_tag {
                return put.result.clone();
            }
        }
        Ok(())
    }

    async fn close_connection(&self, id: &str) -> Result<(), ManagementError> {
        self.close_calls.lock().unwrap().push(id.into());
        Ok(())
    }

    async fn first_connection_snapshot(&self) -> Result<Vec<ConnectionSnapshot>, ManagementError> {
        Ok(self.connections.lock().unwrap().clone())
    }
}

#[cfg(test)]
mod tests;
