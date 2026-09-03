//! H3/A4 热切与 selector 校正域：`switch_mode` 判定—执行两段式、selector 运行态校正与自证。
//!
//! 本模块的两条主线互不化简：**热切判定**（[`ProxyRuntime::classify_switch`] → [`ClassifiedSwitch`]，
//! 纯判定不含动作）与 **selector 校正**（H3：起核后把核里被 `cache_file.store_selected` 覆盖的
//! selector 选择拨回 config 意图）。前者回答「这次配置变更要不要重启」，后者回答「核当下真正选中的
//! 出口是不是 config 说的那个」——两个物理问题，各自的世代协调也各成一套（`generation` 是核世代、
//! `intent_generation` 是 selector 意图世代，latest-wins 由 [`super::selector_reconcile`] 持有）。

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::Ordering;
use std::sync::Arc;
// `TestPutSink` 的记账原语（调用序 / 失败回放 / panic 注入）只在测试编译单元里存在。
#[cfg(test)]
use std::sync::atomic::{AtomicBool, AtomicU32};
#[cfg(test)]
use std::sync::Mutex;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::MutexGuard as AsyncMutexGuard;

use polaris_config_engine::builder::helpers::ServerLike;
use polaris_config_engine::builder::hotswitch::{
    can_skip_restart_for_added_unreferenced, plan_hot_switch, HotSwitchDeps, RuleTargetEntry,
};
use polaris_config_engine::builder::orchestration::{config_generation_norm, stable_stringify};
use polaris_config_engine::builder::outbounds::{build_outbounds, OutboundsDeps};
use polaris_config_engine::builder::{build_id_to_tag_map, GenerateConfigDeps};
use polaris_config_engine::singbox::SingBoxConfig;
use polaris_config_engine::user_config::app_config::UserConfig;
use polaris_config_engine::user_config::dns_constants::{
    is_direct_selection, DIRECT_TAG, PROXY_SELECTOR_TAG,
};
use polaris_config_engine::user_config::rule::RuleAction;
use polaris_config_engine::user_config::ProxyModeType;
use polaris_switch_engine::{
    decide, DecisionInput, HotSwitchOutcome, ManagementApi, ManagementError, SwitchDecision,
    SwitchExecutor,
};

use crate::commands::speedtest::current_server_fingerprints;
use crate::runtime::management_api::{GroupSelection, GrpcManagementApi};
use crate::runtime::node_fingerprints;

use super::network_settle::NetworkSettleGuard;
use super::route_replan::runtime_binding_roots_covered;
use super::selector_reconcile::{SelectorReconcileOutcome, SelectorReconcileRequest};
use super::{code, ProxyRuntime};
// `TestPutSink` 的解锁失效记录句柄按 §A.3 归 `unlock_refresh.rs`（尚未搬），当前仍在 façade。
#[cfg(test)]
use super::UnlockInvalidationProbe;

/// `config:classifyStaged` 的返回体（spec §2.3.4）：候选配置若落盘会走哪条腿。
///
/// `decision` 用 `&'static str` 而非枚举：它是**前端契约的字面量联合**
/// （`'hotSwitch' | 'noOp' | 'defer' | 'restart'`），派生 `Serialize` 的枚举会引入 tag 重命名这层
/// 无谓的间接。四个取值由 [`ProxyRuntime::classify_staged`] 单点产生，跨语言一致性由
/// `ui/src/contracts/staged-classification.test.ts` 从本文件解析后锁死。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StagedClassification {
    pub decision: &'static str,
    /// 恒等式：`restart_required == decision != noOp`。
    /// “保存”策略不允许修改运行核，因此本性可热切的改动也要等“立即应用”（当前实现 force-restart）
    /// 才进入运行态；字段名为兼容既有 IPC 保留，语义是“保存后是否仍待应用”。
    pub restart_required: bool,
}

/// [`ProxyRuntime::classify_switch`] 的产物：判定结果，不含任何执行动作。
///
/// 四个变体一一对应 `switch_mode` 里**除 lifecycle 忙态之外**的全部早退腿 + 正式决策。
/// 变体本身携带执行侧需要的载荷（`new_cfg`），使执行侧无需重新解析一遍配置。
pub(super) enum ClassifiedSwitch {
    /// 核未运行：无核可切，配置留给下次 start 生成。
    NotRunning,
    /// 与运行核当前配置逐字节全等（键序无关）：什么都不用做。
    Unchanged,
    /// 判不出来 → 保守重启。载荷是**给日志用的原因**，不参与判定。
    Fallback(&'static str),
    /// 正式决策（switch-engine `decide` 的产物）+ 已解析的新配置。
    Decided {
        decision: SwitchDecision,
        /// `Box` 是因为 `UserConfig` 远大于其余变体，不装箱会把整个枚举撑到它的大小
        /// （clippy `large_enum_variant`）。
        new_cfg: Box<UserConfig>,
    },
}

/// 纯谓词：config 的 `selectedServerId` 是否指向 `servers` 里**真实存在**的节点。
///
/// 1:1 对齐 上游 `AutoSwitchService.runHeartbeat` 的 `config.servers.find(s => s.id === selectedServerId)`
/// 守卫。返回 `false` 的三种形态（自动换节点心跳据此**跳过**本 tick，防 direct 网络抖动误切走）：
/// - 无选中（`selectedServerId` 缺失）；
/// - direct 哨兵（`__direct__` 从不在 `servers` 数组里，故 find 不到 → false）；
/// - 选中节点已被删（订阅刷新 / 手动删）→ 悬挂 id 找不到。
pub(super) fn selected_server_present(config: &Value) -> bool {
    let Some(selected) = config.get("selectedServerId").and_then(Value::as_str) else {
        return false;
    };
    config
        .get("servers")
        .and_then(Value::as_array)
        .is_some_and(|arr| {
            arr.iter()
                .any(|s| s.get("id").and_then(Value::as_str) == Some(selected))
        })
}

/// 起核时刻的热切换基准快照（上游 ProxyManager 的三个 `this.*` 运行态字段的合并镜像）。
///
/// **只在起核路径刷新**（上游 :672 注释「仅此起核路径刷新（switchMode 的 defer/no-op 分支不刷）」）——
/// 热切换/defer 腿绝不动它：它描述的是「运行中的核实际起于什么」，而非「用户最新想要什么」。
/// 停核清空（上游 :1386-1388）。
#[derive(Debug, Clone, Default)]
pub(super) struct SwitchSnapshot {
    /// id → outbound tag（上游 `currentIdToTagMap`，:3480 = `buildIdToTagMap(config.servers)`）。
    pub(super) id_to_tag: BTreeMap<String, String>,
    /// ruleKey → rule-sel 元数据（上游 `currentRuleTargetMap`，:3607）。
    pub(super) rule_target: BTreeMap<String, RuleTargetEntry>,
    /// id → **全维**指纹（[`modified_fingerprint`]，上游 `runningServersFingerprint`，:672）。
    ///
    /// 两个消费面，同一个问题的两种问法：
    /// - `switch-engine` 的重启判据（喂 `HotSwitchDeps::running_servers_fingerprint` 与
    ///   `can_skip_restart_for_added_unreferenced`）——「这改动会不会改变生成产物」。
    /// - `pending_changes().modified`——「运行核里跑的还是不是用户当前配置」。
    ///
    /// **与 [`Self::dirty_fingerprints`] 不可合并**：那一张回答「池里那个出口还能不能代表这个节点」，
    /// 是另一个问题，正确粒度本就更粗（改 `name` 要重启、但出口没变，测速值仍准）。
    ///
    /// [`modified_fingerprint`]: crate::runtime::node_fingerprints::modified_fingerprint
    pub(super) fingerprints: BTreeMap<String, String>,
    /// id → **5 维**指纹（[`dirty_fingerprint`]），测速 dirty 判据的「旧」侧。
    ///
    /// 与 `fingerprints` **同刻同源**（同一份 `user_config`、同一次 `build_switch_snapshot`），只是投影更粗。
    ///
    /// **为什么必须单独存一张而不是复用 `fingerprints`**：`partition_dirty` 的「新」侧
    /// （`commands/speedtest::current_server_fingerprints`）算的是 5 维串；拿全维表当「旧」侧 ⇒ 两种串永不相等
    /// ⇒ 凡在快照里的节点一律判 dirty ⇒ **整个测速波前每次都被免测**。收口前正是这个形态。
    ///
    /// [`dirty_fingerprint`]: crate::runtime::node_fingerprints::dirty_fingerprint
    pub(super) dirty_fingerprints: BTreeMap<String, String>,
    /// **§15**：运行核的测速探测池端口（`probe-in-k`，起核分配）。空 = 池未注入（分配失败/回滚）。
    /// 与 `running` 同生共死（起核就绪时随本快照置、停核清）→「有池端口 ⟺ 运行核有池」；`server_speed_test`
    /// 据此裁定走「主核 K 槽分波测速」还是回退「仅活跃出口」。`poolPorts[k] ↔ probe-selector-k`（1:1 槽绑定）。
    pub(super) probe_pool_ports: Vec<u16>,
}

/// `switch_mode` 的结果（供 command 层 / 测试断言；上游 switchMode 返 void，此处显式化以便可测）。
///
/// **可测性即门的射程**：上游的 switchMode 吞掉了走哪条腿的信息，测试只能从副作用反推；
/// 显式返回让「切节点走了热切腿而非重启腿」成为可直接断言的事实（§K7：门要能看见它守的东西）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchOutcome {
    /// 热切换成功（selector PUT 全成功，核进程未重启）。
    HotSwitched,
    /// 生成无关变更（norm 等价 + 节点未变）→ 零热切零重启。
    NoOp,
    /// 仅变更未引用节点 → 免整核重启（下次被选中/重启时生效）。
    Deferred,
    /// 走去抖重启（结构性变更 / 热切换失败回退 / 热切换不适用）。
    Restarting,
    /// lifecycle 在飞（depth>0）→ 暂存，由 `end()` 排空时重放。
    Pending,
    /// 核未运行 → 仅更新配置引用（下次 start 按新配置生成）。
    NotRunning,
    /// 配置逐字节全等 → 仅更新引用即返回（上游 bug#5：防外化规则写失败时的无限重启循环）。
    Unchanged,
}

/// 自动故障切换比普通热切多一条运行态自证要求：PUT 成功后还要读回 selector 的真实选择。
/// 把这条最小能力抽象出来，生产接真实 gRPC，事务测试接内存替身；否则只能分别测试 executor 和
/// gRPC wire，中间“落盘但未自证/夹带完整 D 重启”的缝仍不可观测。
#[async_trait::async_trait]
pub(super) trait RuntimeSelectionApi: ManagementApi {
    async fn groups_snapshot(&self) -> Result<Vec<GroupSelection>, ManagementError>;
}

#[async_trait::async_trait]
impl RuntimeSelectionApi for GrpcManagementApi {
    async fn groups_snapshot(&self) -> Result<Vec<GroupSelection>, ManagementError> {
        GrpcManagementApi::groups_snapshot(self).await
    }
}

/// 单测用管理 API PUT 落点：**按调用序**记录 `(selectorTag, memberTag)` + 回放预置失败 + 可注入 panic。
///
/// 绝不碰宿主网络（不连 gRPC、不开端口）—— 真 PUT 属真机门。装配见
/// [`ProxyRuntime::management_api_stub`]。
#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestPutSink {
    /// 全部 PUT 的调用序（含失败那几次 —— 重试腿的行为正是靠它断言的）。
    pub(super) calls: Mutex<Vec<(String, String)>>,
    /// 前 N 次 PUT 返回失败（模拟「管理 API 刚起还没接上」），其后成功。
    pub(super) fail_first: AtomicU32,
    /// 置真 → PUT 直接 panic（验续延的 `.finally()` 语义：panic 展开也必跑续延）。
    pub(super) panic_on_put: AtomicBool,
    /// 续延探针：装上 `RecordingErrorEmitter` 的解锁失效记录句柄后，每次 PUT 都抄一份**当时**的长度。
    ///
    /// 「续延必须晚于校正」是一条**时序**不变式 —— 只看终态（两件事都发生了）验不出顺序。抄这个长度
    /// 等于在 PUT 那一刻给续延拍一张照：全为 0 ⟺ 每一次 PUT 都发生在续延之前。
    pub(super) invalidation_probe: Mutex<Option<UnlockInvalidationProbe>>,
    /// 每次 PUT 时观测到的续延次数（见 `invalidation_probe`）。
    pub(super) observed_invalidations: Mutex<Vec<usize>>,
    /// 运行期 selector **读回**的预置快照（`SubscribeGroups` 首帧的桩）。
    ///
    /// `None`（默认）= 读不到 → 自证本轮不判定，与生产「管理 API 读失败」同一条码路 —— 于是既有
    /// H3 用例不必逐个预置也不会凭空多出告警。要驱动「运行期与意图分叉」必须显式摆上快照。
    pub(super) groups: Mutex<Option<Vec<GroupSelection>>>,
}

#[cfg(test)]
impl TestPutSink {
    fn put(&self, selector_tag: &str, member_tag: &str) -> Result<(), String> {
        if let Some(probe) = self.invalidation_probe.lock().unwrap().as_ref() {
            let n = probe.lock().unwrap().len();
            self.observed_invalidations.lock().unwrap().push(n);
        }
        if self.panic_on_put.load(Ordering::SeqCst) {
            panic!("单测注入：PUT panic");
        }
        // 先记录再判失败：失败轮同样要留在序列里，否则「重试跟最新选中节点」这条断言无从取证。
        self.calls
            .lock()
            .unwrap()
            .push((selector_tag.to_string(), member_tag.to_string()));
        if self.fail_first.load(Ordering::SeqCst) > 0 {
            self.fail_first.fetch_sub(1, Ordering::SeqCst);
            return Err("单测注入：PUT 失败（管理 API 未就绪）".into());
        }
        Ok(())
    }

    /// 已记录的 PUT 序列快照。
    pub(super) fn calls(&self) -> Vec<(String, String)> {
        self.calls.lock().unwrap().clone()
    }

    /// 预置的运行期 group 快照（见 `groups` 字段）。
    fn groups(&self) -> Option<Vec<GroupSelection>> {
        self.groups.lock().unwrap().clone()
    }
}

/// **H3 selector 校正的续延守卫** = 上游 `reassertSelectorSelection(...).finally(...)` 的 Rust 等价物。
///
/// 校正腿的任一出口（正常跑完 / 中途 `return` 放弃 / panic 展开）都必须跑续延
/// （[`ProxyRuntime::after_selector_reasserted`]）。写成「`await` 之后跟一行调用」在 panic 展开时会被
/// 跳过 —— 后果是解锁缓存永不失效，boot 窗口那轮经旧出口探到的脏结果永久留在缓存里，且零可见迹象。
struct ReassertSettledGuard {
    runtime: Arc<ProxyRuntime>,
    generation: u64,
    mode: ProxyModeType,
    api_port: u16,
    /// 只为把 network-settle RAII 生命期延长到 selector reassert 终局；Drop 即是它的消费点。
    _network_settle_guard: Option<NetworkSettleGuard>,
}
impl Drop for ReassertSettledGuard {
    fn drop(&mut self) {
        self.runtime
            .after_selector_reasserted(self.generation, self.mode, self.api_port);
    }
}

struct SelectorReconcileTaskGuard {
    runtime: Arc<ProxyRuntime>,
    armed: bool,
}

impl SelectorReconcileTaskGuard {
    fn new(runtime: Arc<ProxyRuntime>) -> Self {
        Self {
            runtime,
            armed: true,
        }
    }

    /// 正常退出已在状态锁内原子释放所有权；解除 panic/取消兜底，避免旧 guard 覆盖接班 worker。
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SelectorReconcileTaskGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // 正常退出前 worker 已在同锁内把 active=false。这里处理 panic/取消：先释放所有权；若期间
        // 已有新请求，重新走 enqueue 启动接班 worker，不能让一次 task 展开永久卡死单飞位。
        let pending = self.runtime.selector_reconcile.abort_active();
        if let Some(request) = pending {
            self.runtime
                .spawn_selector_reconciliation(request.generation, request.intent_generation);
        }
    }
}

/// **H3 校正腿的终局**——「运行期 selector 与生成产物分叉」这条轴上唯一有信息量的那一刻。
///
/// 校正腿此前是纯 best-effort：成功、放弃、PUT 全失败在调用方眼里**完全一样**（都是返回 `()`）。
/// 而「放弃 / PUT 全失败」恰恰就是 `cache_file` 旧选择原样留任的那个状态 —— 本 bug 的现场。
/// 把终局显式带回来，才谈得上告诉用户。
pub(super) struct ReassertOutcome {
    pub(super) stage1: Stage1Outcome,
    /// 阶段 2 **尝试过**的 `(selector_tag, member_tag)`。PUT 成败不记：成败由读回来的运行期值裁决，
    /// 记 PUT 返回值等于又退回「拿意图对账意图」。
    pub(super) rule_intents: Vec<(String, String)>,
}

/// [`ReassertOutcome`] 的阶段 1（`proxy-selector` 全局出口）终局。
pub(super) enum Stage1Outcome {
    /// PUT 成功，目标成员 tag（**已折入登录期让位**：未登录 TS 出口时这里是 `direct`，那是设计语义）。
    Applied { member_tag: String },
    /// 选中节点不在运行核 tag 映射里 ⇒ 从未 PUT（上游 bug#5 的那条腿）。
    UnresolvedTag { selected_id: String },
    /// 跑满 [`ProxyRuntime::REASSERT_MAX_ROUNDS`] 轮，每轮 PUT 都失败（管理 API 不可用/恒拒）。
    PutExhausted { member_tag: String },
    /// 核已停 / 世代已变 → **主动退场，不是缺陷**：那个核已经不是用户在看的那个了。
    Abandoned,
}

/// 运行期 selector 自证的判定（纯值；[`Self::user_message`] 是它唯一的用户可见形态）。
///
/// 与 [`ExitAttestation`](super::startup::ExitAttestation) 的分工（**别合并**）：那个量的是「生成产物解出的出口」对「盘上选中节点」，
/// 两边都是**意图**，故对 `cache_file` 在起核时覆盖运行期选择这层恒盲 —— 真机血证下它必判 `Match`。
/// 本枚举量的是「核**现在实际**指着谁」对「校正腿的意图」，是唯一能看见那层覆盖的轴。
pub(super) enum SelectorAttestation {
    /// 运行期选择与校正意图一致，或本轮无从判定（见 [`attest_runtime_selection`] 的「没证据」约定）。
    Match,
    /// 校正腿**从未 PUT**：选中节点不在运行核 tag 映射里 ⇒ selector 原样停在 cache_file 的旧选择上。
    NeverReasserted { selected_id: String },
    /// 校正腿 PUT 跑满重试仍全失败 ⇒ 同上，selector 停在旧选择上。
    ReassertFailed { member_tag: String },
    /// PUT 成功了，但读回来的**全局**出口仍不是意图那个（核未采纳 / 被别的东西改回去了）。
    GlobalDrift {
        want: String,
        got: String,
        /// 同一快照里另有多少条分流规则也不一致（并进同一条文案，别刷屏）。
        rule_drifts: usize,
    },
    /// 全局出口对上了，但有 N 条分流规则的 selector 停在别处。
    RuleDrift {
        count: usize,
        sample_tag: String,
        want: String,
        got: String,
    },
}

impl SelectorAttestation {
    /// 用户可见文案。**统一以「未走/未按设置走」开头**，与 [`ExitAttestation::user_message`](super::startup::ExitAttestation::user_message) 同语气 ——
    /// 两者共用 [`code::EXIT_MISMATCH`]，渲染端归在同一条「出口误导腿」，文案风格不该分家。
    ///
    /// 三条放弃腿都以「请重新连接」收尾：校正腿是 best-effort，重连是用户手上**真能收敛**这件事的动作
    /// （下一次起核重跑整条校正），而不是一句无处着力的「请检查」。
    pub(super) fn user_message(&self) -> String {
        match self {
            Self::Match => String::new(),
            Self::NeverReasserted { selected_id } => format!(
                "启动后未能把出口切到选中节点（{selected_id} 不在本次启动的节点表中），流量可能仍走上一次的出口。请重新连接。"
            ),
            Self::ReassertFailed { member_tag } => format!(
                "启动后未能把出口切到选中节点「{member_tag}」（管理接口无响应），流量可能仍走上一次的出口。请重新连接。"
            ),
            Self::GlobalDrift {
                want,
                got,
                rule_drifts,
            } => {
                let tail = if *rule_drifts > 0 {
                    format!("，另有 {rule_drifts} 条分流规则的出口也不一致")
                } else {
                    String::new()
                };
                format!("流量未走选中节点「{want}」，核实际出口为「{got}」{tail}。请重新连接。")
            }
            Self::RuleDrift {
                count,
                sample_tag,
                want,
                got,
            } => format!(
                "有 {count} 条分流规则未走设定的节点（如「{sample_tag}」实际走「{got}」，应为「{want}」）。请重新连接。"
            ),
        }
    }
}

/// 运行期 selector 自证的**纯判定**（零 I/O）：拿校正腿的终局 + 读回来的运行期快照出结论。
///
/// # 「没证据」与「有问题」必须分开
///
/// `groups = None`（读不到：管理 API 连不上 / 首帧超时 / 核正在停）→ 判 [`SelectorAttestation::Match`]，
/// 只留日志。理由不是宽容，是**告警一旦有假就会被整体无视**（同 [`attest_effective_exit`](super::startup::attest_effective_exit) 门② 的取舍）：
/// 「没读到」根本不是「出口错了」的证据，而「读不到」这一侧本来就已经被
/// [`Stage1Outcome::PutExhausted`] 那条腿覆盖了 —— 管理 API 真的不可用时，PUT 早就先一步跑满重试并
/// 报出来了。两条腿一读一写盯同一件事，不需要在读侧再造一次同因异名的告警。
///
/// 同理，快照里**查不到** `proxy-selector` 这个 group（`sel(...) == None`）也只当没证据：能走到
/// `Applied` 说明这个 group 刚刚还接受过 PUT，读不到它属于核状态自身的异常，不是出口走错。
pub(super) fn attest_runtime_selection(
    outcome: &ReassertOutcome,
    groups: Option<&[GroupSelection]>,
) -> SelectorAttestation {
    let member_tag = match &outcome.stage1 {
        // 主动退场：那个核已被停/被换，读它、报它都是对着一个不存在的对象说话。
        Stage1Outcome::Abandoned => return SelectorAttestation::Match,
        Stage1Outcome::UnresolvedTag { selected_id } => {
            return SelectorAttestation::NeverReasserted {
                selected_id: selected_id.clone(),
            }
        }
        Stage1Outcome::PutExhausted { member_tag } => {
            return SelectorAttestation::ReassertFailed {
                member_tag: member_tag.clone(),
            }
        }
        Stage1Outcome::Applied { member_tag } => member_tag,
    };
    let Some(groups) = groups else {
        return SelectorAttestation::Match; // 没证据 ≠ 有问题，见上方
    };
    let selected_of = |tag: &str| {
        groups
            .iter()
            .find(|g| g.tag == tag)
            .map(|g| g.selected.as_str())
    };
    // 分流规则侧：只统计**读得到且值不对**的，读不到的一律不计（同上「没证据」约定）。
    let rule_drifts: Vec<(&str, &str, &str)> = outcome
        .rule_intents
        .iter()
        .filter_map(|(tag, want)| match selected_of(tag) {
            Some(got) if got != want => Some((tag.as_str(), want.as_str(), got)),
            _ => None,
        })
        .collect();
    // 全局出口优先报：它决定「所有未命中规则的流量从哪出去」，量级压过单条规则。
    if let Some(got) = selected_of(PROXY_SELECTOR_TAG) {
        if got != member_tag {
            return SelectorAttestation::GlobalDrift {
                want: member_tag.clone(),
                got: got.to_string(),
                rule_drifts: rule_drifts.len(),
            };
        }
    }
    match rule_drifts.first() {
        Some((tag, want, got)) => SelectorAttestation::RuleDrift {
            count: rule_drifts.len(),
            sample_tag: (*tag).to_string(),
            want: (*want).to_string(),
            got: (*got).to_string(),
        },
        None => SelectorAttestation::Match,
    }
}

impl ProxyRuntime {
    /// 起核时刻建热切换基准快照（上游 在 generateSingBoxConfig / startInternal 内回填三个 `this.*`）。
    ///
    /// 三份基准各自的真值来源（**逐条对齐 上游，不自创**）：
    /// - `id_to_tag`：`build_id_to_tag_map(servers)` —— 与 上游 :3480 同一函数、同一入参。
    ///   注：`build_outbounds` 内部另持一份**可变**副本（detour 死引用剔除会删 entry），但 上游的
    ///   `currentIdToTagMap` 存的正是**未剔除**的那份，且 config-engine 的 `generate.rs:204` 也用它
    ///   喂 route/dns → 此处保持一致。
    /// - `rule_target`：`build_outbounds` 产的 `pending_rule_selectors`，**再按「该 selector 是否真的
    ///   存在于生成出来的 outbounds」过滤** —— 1:1 复刻 上游 :3601-3610 的 `liveSelectorTags` 过滤
    ///   （detour 死引用剔除可能删空 rule-sel → 该 entry 不进 map）。
    /// - `fingerprints`：`server_fingerprint` 逐节点（上游 :672 `computeServersFingerprint`）。
    ///
    /// **为什么要重跑一次 `build_outbounds`**：`generate_sing_box_config` 只返回 `SingBoxConfig`，
    /// 不外露 `pending_rule_selectors`（上游 靠 `this.pendingRuleSelectors` 实例态取，Rust 侧是纯函数
    /// 无实例态），而 config-engine 本批**只读复用不可改签名** → 只能用其公开的 `build_outbounds` 重算。
    /// 重算与生成的唯一入参差异是 `with_race_off`（私有，无法调用），它只改
    /// `dnsConfig.resolveNodeDomainsAhead` → 仅影响节点 outbound 的 `domain_resolver`，**不改任何 tag
    /// 集合**，故 `pending_rule_selectors` 不受影响。这个「不受影响」不靠推断背书：live-selector 过滤
    /// 拿**真实生成产物**当裁判，重算若与产物不一致，对应 entry 直接出局。
    pub(super) fn build_switch_snapshot(
        user_config: &UserConfig,
        singbox_config: &SingBoxConfig,
        deps: &GenerateConfigDeps,
    ) -> SwitchSnapshot {
        // ── id→tag ──
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
        let id_to_tag = build_id_to_tag_map(&wrappers);

        // ── 节点指纹（两张表，两个问题；公式单点在 runtime::node_fingerprints，见其模块文档）──
        // ① 全维：喂 switch-engine 重启判据 + pending_changes().modified。
        let fingerprints = node_fingerprints::modified_table(&user_config.servers);
        // ② 5 维：喂测速 partition_dirty 的「旧」侧。必须与 speedtest 的「新」侧同公式，否则恒不等。
        let dirty_fingerprints = node_fingerprints::dirty_table(&user_config.servers);

        // ── rule-sel 映射（重算 + live 过滤）──
        // OutboundsDeps 逐字段镜像 config-engine `generate.rs:208-219`；漏一个字段就可能算出与运行核
        // 不同的 selector 集合（→ 被 live 过滤兜住，退化为「该规则不热切」而非 PUT 到错的 selector）。
        let system_interface_available = matches!(
            user_config.proxy_mode_type,
            polaris_config_engine::user_config::ProxyModeType::Tun
        )
            && polaris_config_engine::builder::endpoint_routes::mesh_system_supported_on_platform(
                &deps.platform,
            );
        let mut outbounds_deps = OutboundsDeps {
            platform: deps.platform.clone(),
            arch: deps.arch.clone(),
            // 类型随 `OutboundsDeps` 由 `BTreeSet<String>` 改为 `BTreeMap<String, &'static str>`
            // （值 = 剔除原因 token，供 UI 说清「这个节点为什么不可用」）。此处是**预置为空**的
            // 入参，语义未变：`build_outbounds` 只往里写，不读预置内容。
            gate_invalid_nodes: std::collections::BTreeMap::new(),
            system_interface_available,
            probe_pool_ports: deps.probe_pool_ports.clone(),
            tailscale_state_dir_prefix: deps.tailscale_state_dir_prefix.clone(),
            has_cronet_lib: deps.has_cronet,
            log: deps.log,
        };
        let rule_target = match build_outbounds(user_config, &mut outbounds_deps) {
            Ok(res) => {
                // live 裁判：真实生成产物里仍在的 selector tag（上游 liveSelectorTags）。
                let live: BTreeSet<&str> = singbox_config
                    .outbounds
                    .iter()
                    .filter(|o| o.type_field == "selector")
                    .map(|o| o.tag.as_str())
                    .collect();
                res.pending_rule_selectors
                    .into_iter()
                    .filter(|r| live.contains(r.selector_tag.as_str()))
                    .map(|r| {
                        (
                            r.rule_key,
                            RuleTargetEntry {
                                selector_tag: r.selector_tag,
                                member_tag: r.member_tag,
                            },
                        )
                    })
                    .collect()
            }
            // 重算失败（生成已成功却重算报错 = 二者已分叉）→ 空 map。空 map ≠ None：
            // 空 map 下规则热切换查不到 entry → 跳过该规则（上游 同款语义）；而 id_to_tag 仍在 →
            // 全局切节点仍可热切。分叉本身响亮记日志。
            Err(e) => {
                log::warn!("rule-sel 快照重算失败（规则热切换将退化为跳过）: {e}");
                BTreeMap::new()
            }
        };

        SwitchSnapshot {
            id_to_tag,
            rule_target,
            fingerprints,
            dirty_fingerprints,
            // §15：与运行核 config 同源（deps.probe_pool_ports 正是本次 generate 注入的池端口）→ 快照即池真值。
            probe_pool_ports: deps.probe_pool_ports.clone(),
        }
    }

    /// 应用一次配置变更（上游 `ProxyManager.switchMode`，:1746-1890）。
    ///
    /// **本仓此前无此路径** —— `server:switch` 等命令只落盘 + 广播 UI 事件，从不触达运行核；
    /// 唯一的入核手段是 `apply_pending`（恒全量重启）。本方法把既有的三腿决策接上生产路径：
    ///
    /// 1. lifecycle 在飞（depth>0）→ 暂存 + `set_switch_pending`，由 `end()` 排空重放（上游 :1752）。
    ///    **必须先于「核未运行」判**：restart 的 stop→start 空窗内核看起来没在跑，先判会把本次变更
    ///    永久丢弃（与 `apply_pending` 的 H-1 同型陷阱）。
    /// 2. 核未运行 → 仅更新 `current_config`（下次 start 按新配置生成）（上游 :1757）。
    /// 3. 与 `current_config` 逐字节全等 → 仅更新引用（上游 bug#5，:1767）。
    /// 4. `plan_hot_switch` + `decide` 三腿分发（switch-engine 既有纯逻辑，本处只喂参数 + 执行）。
    ///
    /// 返回 [`SwitchOutcome`] 供 command 层与测试断言走了哪条腿。
    #[cfg(test)]
    pub async fn switch_mode(self: &Arc<Self>, new_config: Value) -> SwitchOutcome {
        self.switch_mode_with(new_config, false).await
    }

    /// `Self::switch_mode` 带「保存只持久化」标志的形态（暂存层「保存」腿）。
    ///
    /// `defer_restart=true` 把所有会改变运行核的腿（selector PUT、must-restart、普通结构重启）
    /// 统一降为 Defer：磁盘已更新，但运行快照与 `current_config` 仍代表旧核，直到用户点击「立即应用」。
    /// 生成无关的 NoOp 保持原样，不凭空制造待应用提示。完整因果见 [`DecisionInput::defer_restart`]。
    ///
    /// **默认入口仍是 `Self::switch_mode`**（等价于本方法传 `false`）：配置写的十余个生产路径
    /// 全部经 `broadcast_config_changed` 汇流，只有那一处会按前端是否传 `deferRestart` 决定传什么。
    /// 新增写路径若直接调本方法并硬编码 `true`，等于绕过用户意图 —— 不要这么做。
    pub async fn switch_mode_with(
        self: &Arc<Self>,
        new_config: Value,
        defer_restart: bool,
    ) -> SwitchOutcome {
        let intent_generation = self.register_selector_intent();
        // 管理 API PUT、current_config commit 与重启判定必须是一个串行事务。尤其要排在 lifecycle
        // busy 判定之前：等待期间可能恰好进入/退出重启，拿锁后必须重新看当下 gate，而非沿用旧快照。
        let switch_guard = self.switch_serial.lock().await;
        self.switch_mode_locked(new_config, defer_restart, intent_generation, &switch_guard)
            .await
    }

    pub(super) fn selector_operation_is_current(
        &self,
        generation: u64,
        intent_generation: u64,
    ) -> bool {
        self.gate.generation() == generation
            && self.core_running()
            && self.selector_reconcile.intent_generation() == intent_generation
    }

    /// 持久配置广播的专用入口。后端 writer 虽已串行落盘，解锁后各自 spawn 的 `switchMode`
    /// task 仍可能乱序。候选在取得 `switch_serial` 后已不是当前磁盘真值时必须作废；否则
    /// “新配置先入核、旧广播后入核”会让运行态最终退回旧版，而前端/磁盘都显示新版。
    pub async fn switch_persisted_config_if_current<F>(
        self: &Arc<Self>,
        mut candidate: Value,
        defer_restart: bool,
        intent_generation: u64,
        on_current: F,
    ) -> Option<SwitchOutcome>
    where
        F: FnOnce(&Value) + Send,
    {
        let switch_guard = self.switch_serial.lock().await;
        if self.selector_reconcile.intent_generation() != intent_generation {
            log::info!("switchMode：过期配置意图已被更新代次取代 → 作废");
            return None;
        }
        let mut latest = match self.config.current() {
            Ok(latest) => latest,
            Err(error) => {
                log::warn!("switchMode 落盘真值复核失败 → 保守作废本次广播: {error}");
                return None;
            }
        };
        // 隐私锁字段不参与代理生成，而广播入核侧一直剥除它们。两侧同投影后再判等，
        // 不能因磁盘有 hash、候选无 hash 就把每条合法广播都误判为过期。
        crate::commands::config::strip_privacy_secrets(&mut latest);
        crate::commands::config::strip_privacy_secrets(&mut candidate);
        if stable_stringify(&latest) != stable_stringify(&candidate) {
            log::info!("switchMode：过期配置广播已被更新磁盘版本取代 → 作废");
            return None;
        }
        // 应用侧投影（日志级别/原生主题）与入核共用同一个过期判定点。若留在命令层
        // 同步执行，旧广播虽不再退核，仍可最后把原生窗口主题/日志级别退回旧值。
        on_current(&candidate);
        Some(
            self.switch_mode_locked(candidate, defer_restart, intent_generation, &switch_guard)
                .await,
        )
    }

    /// 调用方已持有 `switch_serial` 的执行半边。
    async fn switch_mode_locked(
        self: &Arc<Self>,
        new_config: Value,
        defer_restart: bool,
        intent_generation: u64,
        switch_guard: &AsyncMutexGuard<'_, ()>,
    ) -> SwitchOutcome {
        let switch_generation = self.gate.generation();
        // ── 腿 0：lifecycle 在飞 → 暂存重放（顺序门，见方法文档）──
        if self.gate.is_busy() {
            let id = self.switch_seq.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut g) = self.pending_switch.write() {
                *g = Some((id, new_config, defer_restart));
            }
            self.gate.set_switch_pending(id);
            log::info!("switchMode：lifecycle 在飞（depth>0）→ 暂存，settle 后重放");
            return SwitchOutcome::Pending;
        }

        // 网卡绑定是 fail-closed 变更：目标接口不存在 / down 时，运行核继续保留旧配置，磁盘改动进入
        // 待应用态并提醒用户；绝不为了让热切换“成功”而把 bind_interface 去掉、静默走系统默认出口。
        // 解析失败仍交给既有 classify_switch 的保守重启腿，避免本门扩大自己的判定范围。
        if let Ok(candidate) = serde_json::from_value::<UserConfig>(new_config.clone()) {
            if let Err(message) = self.validate_required_bind_interfaces(&candidate).await {
                self.set_nonfatal_error(&message, code::OUTBOUND_INTERFACE_UNAVAILABLE);
                self.restart_deferred.store(true, Ordering::SeqCst);
                self.push_pending_changes();
                return SwitchOutcome::Deferred;
            }
        }

        // ── 腿 0.5 起的**判定**全部下沉 [`Self::classify_switch`]（纯读，无副作用）──
        // 本方法自此只负责「执行」：判据与 `config:classifyStaged` 逐字共用同一份。
        let (decision, new_cfg) = match self.classify_switch(&new_config, defer_restart) {
            ClassifiedSwitch::NotRunning => {
                if let Ok(mut g) = self.current_config.write() {
                    *g = Some(new_config);
                }
                // 停核时磁盘期望态天然就是下一次运行态；保存/订阅刷新写下的不可逆删除不应悬到
                // 下次连接才完成。journal 内仍按最新配置复核，重新加入的实体不会被误删。
                self.process_deferred_config_deletions();
                self.selector_reconcile.clear_required();
                log::info!("switchMode：核未运行 → 仅更新配置（下次 start 生效）");
                return SwitchOutcome::NotRunning;
            }
            ClassifiedSwitch::Unchanged => {
                if let Ok(mut g) = self.current_config.write() {
                    *g = Some(new_config.clone());
                }
                self.reassert_if_selector_reconcile_required_locked(
                    &new_config,
                    switch_generation,
                    intent_generation,
                    switch_guard,
                )
                .await;
                return SwitchOutcome::Unchanged;
            }
            ClassifiedSwitch::Fallback(why) => {
                log::warn!("switchMode：{why} → 保守走重启");
                self.apply_restart(new_config);
                return SwitchOutcome::Restarting;
            }
            ClassifiedSwitch::Decided { decision, new_cfg } => (decision, *new_cfg),
        };

        // ── 腿 3：三腿分发（决策全在 switch-engine，本处只执行）──
        let outcome = match decision {
            SwitchDecision::HotSwitch(plan) => {
                let api = self.management_api().await;
                let interrupt = new_cfg.interrupt_connections_on_switch == Some(true);
                log::info!(
                    "switchMode：热切换腿（kind={:?}，{} 个 selector PUT，断连开关={interrupt}）",
                    plan.kind,
                    plan.puts.len()
                );
                match SwitchExecutor.execute(&api, &plan, interrupt).await {
                    HotSwitchOutcome::Applied { disconnect } => {
                        if !self.selector_operation_is_current(switch_generation, intent_generation)
                        {
                            self.selector_reconcile.mark_required();
                            log::info!(
                                "switchMode：selector PUT 后发现更新配置意图/内核世代 → 交给新所有者收敛"
                            );
                            self.push_pending_changes();
                            return SwitchOutcome::Pending;
                        }
                        self.commit_applied(&new_config);
                        self.selector_reconcile.clear_required();
                        // C5：热切换可能切换了全局出口节点（到/离 TS System 全隧道出口）→ 对齐出口路由。
                        // 重启腿的出口路由由重启后 start_inner 的就绪后 reconcile 覆盖，故仅热切腿需在此显式对齐。
                        self.mesh
                            .exit_route_reconcile(&new_cfg, new_cfg.enable_ipv6.unwrap_or(false))
                            .await;
                        log::info!(
                            "switchMode：热切换成功（核未重启），精准断连 {} 条",
                            disconnect.map_or(0, |d| d.closed_ids.len())
                        );
                        // M1（上游 `proxyManager.on('unlock-invalidate')`，`index.ts:2006-2008`）：**任何**热切换
                        // ——切全局节点 / 改规则目标节点 / 两者——都可能换掉解锁检测走的出口或分流，故一律失效重测。
                        // 与 `commands/config.rs` 的 `selected_exit_changed` 腿的分工：那条只覆盖「选中出口变」，
                        // **kind=rules 的纯规则热切换它看不见**（selectedServerId 没动）→ 漏失效，正是 上游 M1 要堵的洞。
                        // 两条重叠触发无害：1500ms 去抖窗把它们合并成一轮（这正是去抖存在的理由之一）。
                        self.invalidate_unlock_cache(true, false);
                        // 同理（上游「节点热切换」触发点）：热切换换掉的正是出口本身 ⇒ 状态栏 IP + 旗面
                        // + 伴测延迟全部作废，须重探。留着旧值 = 用上一个出口冒充当前出口。
                        self.schedule_exit_ip_refresh(true);
                        SwitchOutcome::HotSwitched
                    }
                    // 失败/未就绪 → 退回去抖重启兜底（executor 契约：「任一失败 → 整体退回去抖重启，
                    // 保证一定能应用」）。**刻意偏离 上游**：上游 热切失败后 fall-through 到 no-op 腿，
                    // kind=rules 的失败会因 norm 等价 + 节点未变而被 no-op **静默吞掉**（变更永不生效）。
                    // 见交付说明「边界声明」。
                    other => {
                        log::warn!("switchMode：热切换失败（{other:?}）→ 退回重启式切换");
                        self.apply_restart(new_config);
                        SwitchOutcome::Restarting
                    }
                }
            }
            SwitchDecision::NoOp => {
                log::info!("switchMode：生成无关变更（norm 等价 + 节点未变）→ 零重启");
                self.commit_applied(&new_config);
                SwitchOutcome::NoOp
            }
            SwitchDecision::Defer => {
                if defer_restart {
                    // 记账：这次落盘没进核。**不得**调用 commit_applied——current_config 是后续热切
                    // 规划的旧侧，必须继续代表真实运行核；把磁盘期望态写进去会让下一次后台变更基于
                    // 一个从未入核的中间态规划 PUT。节点差集看不见非节点变更，故另留 debt 标志。
                    self.restart_deferred.store(true, Ordering::SeqCst);
                    log::info!(
                        "switchMode：「保存只持久化」→ 运行核保持原样，等用户点「立即应用」"
                    );
                } else {
                    log::info!("switchMode：仅变更未引用节点 → 免重启（下次启动/被选中时生效）");
                    self.commit_applied(&new_config);
                }
                SwitchOutcome::Deferred
            }
            SwitchDecision::Restart => {
                log::info!("switchMode：结构性变更 → 调度去抖重启");
                self.apply_restart(new_config);
                SwitchOutcome::Restarting
            }
        };
        // A4 触发点②：非重启腿提交后对账登录期出口让位。覆盖两类驱动——
        //  · 切出口（HotSwitched）：切走原让位出口 → stale 复位（清 flag，不 PUT，selector 已被 planHotSwitch 移走）；
        //  · 切「meshLoginFallbackDirect 开关」（NoOp：该字段排除出 norm → 走 no-op 腿）：关开关须即刻 disengage 切回出口。
        // 重启腿不在此对账——重启后 start_inner 的预置 + 首帧 reconcile 覆盖。
        if !matches!(outcome, SwitchOutcome::Restarting)
            && !(defer_restart && matches!(outcome, SwitchOutcome::Deferred))
        {
            // L3 外化规则「值」热更：norm 排除了外化规则的值 → 结构相等但值可能变（如「切节点 + 改外化规则
            // 值」同一次 save）。非重启腿（热切/no-op/defer）补一次文件对账（通常零 diff、幂等）。降级态文件
            // 无消费者 → 改走去抖重启重落盘（对齐 上游 三腿 :1806-1807/:1850-1851/:1877-1878）。
            if self.custom_rule_files_degraded() {
                self.schedule_restart();
            } else {
                self.sync_custom_rule_files(&new_cfg).await;
            }
            if let Some(reconcile_config) = self
                .current_config
                .read()
                .ok()
                .and_then(|guard| guard.clone())
            {
                self.reassert_if_selector_reconcile_required_locked(
                    &reconcile_config,
                    switch_generation,
                    intent_generation,
                    switch_guard,
                )
                .await;
            }
            self.reconcile_login_fallback_locked(switch_guard).await;
        }
        // R2 待应用差集 PUSH（单点，最小 runtime 面）：任何经 switch_mode 的落盘（增/删/改节点、排序、
        // `server:switch`）= 上游 `configChanged` 触发点 → 推当下差集给 UI。Defer 腿 added 非空 → 操作条现；
        // 重启腿此刻起核快照未刷、added 仍非空 = **真·待应用**（重启落地后由前端 onStarted pull 清），与 上游
        // 「configChanged 显示、started 清空」同型，非 bug。emitter 未接线（单测）静默跳过，不打断本腿。
        self.push_pending_changes();
        outcome
    }

    /// 双不自证后的最小恢复事务：只把 D.selectedServerId 对应的 clean 运行成员写回
    /// `proxy-selector`，绝不把 D 中其它待 Apply 字段送入运行核，也绝不以整核重启兜底。
    pub(super) async fn reconcile_persisted_selector_with_api(
        self: &Arc<Self>,
        generation: u64,
        intent_generation: u64,
        api: &dyn RuntimeSelectionApi,
    ) -> SelectorReconcileOutcome {
        let switch_guard = self.switch_serial.lock().await;
        if !self.selector_operation_is_current(generation, intent_generation) {
            return SelectorReconcileOutcome::Superseded;
        }
        if self.gate.is_busy() {
            return SelectorReconcileOutcome::Failed;
        }

        let disk = match self.config.current() {
            Ok(config) => config,
            Err(error) => {
                log::warn!("selector 后台对账读取 D 失败：{error}");
                return SelectorReconcileOutcome::Failed;
            }
        };
        let Some(target_id) = disk
            .get("selectedServerId")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        else {
            return SelectorReconcileOutcome::NotEligible;
        };
        let Some(mut reconciled_runtime) = self
            .current_config
            .read()
            .ok()
            .and_then(|guard| guard.clone())
        else {
            return SelectorReconcileOutcome::NotEligible;
        };
        if reconciled_runtime
            .get("selectedServerId")
            .and_then(Value::as_str)
            == Some(target_id)
        {
            return SelectorReconcileOutcome::Converged;
        }

        let staged = self.config.staged_node_mask();
        if staged.pending && (!staged.scope_known || staged.node_ids.contains(target_id)) {
            return SelectorReconcileOutcome::NotEligible;
        }
        let Some((target_tag, running_fingerprint)) =
            self.switch_snapshot.read().ok().and_then(|guard| {
                guard.as_ref().and_then(|snapshot| {
                    Some((
                        snapshot.id_to_tag.get(target_id)?.clone(),
                        snapshot.dirty_fingerprints.get(target_id)?.clone(),
                    ))
                })
            })
        else {
            return SelectorReconcileOutcome::NotEligible;
        };
        if current_server_fingerprints(&disk).get(target_id) != Some(&running_fingerprint) {
            return SelectorReconcileOutcome::NotEligible;
        }
        let Some(runtime_object) = reconciled_runtime.as_object_mut() else {
            return SelectorReconcileOutcome::NotEligible;
        };
        runtime_object.insert(
            "selectedServerId".to_string(),
            Value::String(target_id.to_string()),
        );
        let Ok(reconciled_user_config) =
            serde_json::from_value::<UserConfig>(reconciled_runtime.clone())
        else {
            return SelectorReconcileOutcome::NotEligible;
        };

        if api
            .select_outbound(PROXY_SELECTOR_TAG, &target_tag)
            .await
            .is_err()
        {
            if !self.selector_operation_is_current(generation, intent_generation) {
                return SelectorReconcileOutcome::Superseded;
            }
            return SelectorReconcileOutcome::Failed;
        }
        if !self.selector_operation_is_current(generation, intent_generation) {
            return SelectorReconcileOutcome::Superseded;
        }
        let attested = api.groups_snapshot().await.ok().is_some_and(|groups| {
            groups
                .iter()
                .any(|group| group.tag == PROXY_SELECTOR_TAG && group.selected == target_tag)
        });
        if !self.selector_operation_is_current(generation, intent_generation) {
            return SelectorReconcileOutcome::Superseded;
        }
        if !attested {
            return SelectorReconcileOutcome::Failed;
        }

        self.commit_applied(&reconciled_runtime);
        self.selector_reconcile.clear_required();
        self.mesh
            .exit_route_reconcile(
                &reconciled_user_config,
                reconciled_user_config.enable_ipv6.unwrap_or(false),
            )
            .await;
        if !self.selector_operation_is_current(generation, intent_generation) {
            return SelectorReconcileOutcome::Superseded;
        }
        self.invalidate_unlock_cache(true, false);
        self.schedule_exit_ip_refresh(true);
        self.reconcile_login_fallback_locked(&switch_guard).await;
        if !self.selector_operation_is_current(generation, intent_generation) {
            return SelectorReconcileOutcome::Superseded;
        }
        self.push_pending_changes();
        self.clear_nonfatal_error_if(code::EXIT_MISMATCH);
        if let Some(emitter) = self.error_emitter.get() {
            emitter.emit_config_changed();
        }
        SelectorReconcileOutcome::Applied
    }

    pub(super) fn spawn_selector_reconciliation(
        self: &Arc<Self>,
        generation: u64,
        intent_generation: u64,
    ) {
        let request = SelectorReconcileRequest {
            generation,
            intent_generation,
        };
        let should_spawn = self.selector_reconcile.enqueue(request);
        if !should_spawn {
            return;
        }
        let me = Arc::clone(self);
        tauri::async_runtime::spawn(async move {
            let mut active = SelectorReconcileTaskGuard::new(Arc::clone(&me));
            let mut delay = Duration::from_millis(200);
            let mut retry = None;
            loop {
                let Some(request) = me.selector_reconcile.take_latest_or_finish(retry.take())
                else {
                    active.disarm();
                    break;
                };
                let api = me.management_api().await;
                match me
                    .reconcile_persisted_selector_with_api(
                        request.generation,
                        request.intent_generation,
                        &api,
                    )
                    .await
                {
                    SelectorReconcileOutcome::Applied => {
                        log::info!("selector 后台对账完成：D/R 已收敛");
                    }
                    SelectorReconcileOutcome::Converged
                    | SelectorReconcileOutcome::Superseded
                    | SelectorReconcileOutcome::NotEligible => {}
                    SelectorReconcileOutcome::Failed => {
                        retry = Some(request);
                    }
                }
                if retry.is_some() {
                    // Notify 保存单个 permit；新请求即使发生在 select 建 waiter 之前，也会让这一轮立即
                    // 返回并在循环顶部以 pending 覆盖旧 retry，不会白等当前退避。
                    if me.selector_reconcile.wait_for_retry_or_newer(delay).await {
                        delay = Duration::from_millis(200);
                        continue;
                    }
                    delay = std::cmp::min(delay.saturating_mul(2), Duration::from_secs(5));
                } else {
                    delay = Duration::from_millis(200);
                }
            }
        });
    }

    /// [`Self::switch_mode_with`] 的**纯判定半边**：候选配置会落哪条腿，不产生任何副作用。
    ///
    /// # 为什么抽出来
    ///
    /// `config:classifyStaged`（spec §2.3.4）要在**保存之前**告诉用户「这批改动保存后是否仍待应用」。
    /// 若它自己再实现一遍判定，那么「核未起 / 无基准 / 解析失败 / 逐字节全等」这四条兜底腿就有了
    /// 第二份实现 —— 它们的分歧只会在真机上以「预告说不重启、实际断了流」的形态暴露，
    /// 而这恰恰是最难归因的一类。共用同一函数后，预告与实际**在构造上**不可能分歧。
    ///
    /// # 不含 lifecycle 在飞那一腿（腿 0）
    ///
    /// 「lifecycle 在飞 → 暂存重放」是**时机**而非判据：暂存的那份配置排空后仍会走完整判定。
    /// 把瞬时的忙态算进预告，会让同一批改动在核重启窗口内被预告成另一种结果。
    pub(super) fn classify_switch(
        &self,
        new_config: &Value,
        defer_restart: bool,
    ) -> ClassifiedSwitch {
        // 腿 0.5：核未运行 → 无核可切（下次 start 按新配置生成）。
        if !self.core_running() {
            return ClassifiedSwitch::NotRunning;
        }

        // 核在跑却无 current_config = 不可能态（start 就绪时必置）。保守走重启，绝不猜。
        let Some(old_value) = self.current_config.read().ok().and_then(|g| g.clone()) else {
            return ClassifiedSwitch::Fallback("核在跑但无 current_config 基准");
        };

        // 腿 1：逐字节全等 → 仅更新引用（上游 bug#5）。
        // 键序无关比较：ConfigManager 落盘/回读可能改键序，裸 == 会把「没变」误判成「变了」→ 无谓重启。
        if stable_stringify(new_config) == stable_stringify(&old_value) {
            return ClassifiedSwitch::Unchanged;
        }

        // 腿 2：解析 + 规划。
        // 任一侧解析失败 → 保守重启（fail-closed）：热切换靠精确 diff，解析不出就无从判断，
        // 宁可多断一次流，也不能把「没看懂的变更」当成「无需动作」静默吞掉。
        let (Ok(old_cfg), Ok(new_cfg)) = (
            serde_json::from_value::<UserConfig>(old_value),
            serde_json::from_value::<UserConfig>(new_config.clone()),
        ) else {
            return ClassifiedSwitch::Fallback("配置解析失败");
        };

        // TUN 的逐目的网卡事实只在起核前（TUN 尚未接管路由时）可信。当前会话未覆盖的 automatic
        // physical root 不能靠 selector PUT 临时补算：活 TUN 下查询会命中 Polaris 自己，得到错误接口。
        // 因此切全局/规则到未覆盖根必须先走 stop→start，由 start_inner 在撤 TUN 后重新规划。
        if new_cfg.proxy_mode_type.is_tun() {
            let binding_plan = self
                .runtime_binding_state
                .lock()
                .map(|state| state.plan.clone())
                .unwrap_or_default();
            if !runtime_binding_roots_covered(&new_cfg, &binding_plan) {
                return ClassifiedSwitch::Fallback("目标包含本核未规划的自动物理出口");
            }
        }

        // 核在跑却无基准 → 无法判热切换（PUT 目标 tag 无从解析）→ 重启（今日行为）。
        let Some(snapshot) = self.switch_snapshot.read().ok().and_then(|g| g.clone()) else {
            return ClassifiedSwitch::Fallback("无热切换基准快照");
        };

        let deps = HotSwitchDeps {
            current_id_to_tag_map: Some(snapshot.id_to_tag.clone()),
            running_servers_fingerprint: Some(snapshot.fingerprints.clone()),
            current_rule_target_map: Some(snapshot.rule_target.clone()),
            // 登录期出口让位（TS 未就绪时 proxy-selector 实指 direct）属 mesh 批次，未接线 → false。
            // 保守方向正确：false 时旧成员 tag 按 config 选中节点解析，最坏是精准断连漏关几条旧连接
            // （它们会自然结束），绝不影响 PUT 正确性。
            bootstrap_fallback_engaged: false,
        };
        let plan = plan_hot_switch(&old_cfg, &new_cfg, &deps);

        // 决策输入：三个布尔全部由 config-engine 的纯函数现算（不缓存、不自己判等价）。
        let input = DecisionInput {
            norm_equal: config_generation_norm(&old_cfg, None)
                == config_generation_norm(&new_cfg, None),
            selected_server_id_equal: old_cfg.selected_server_id == new_cfg.selected_server_id,
            only_added_unreferenced: can_skip_restart_for_added_unreferenced(
                &old_cfg,
                &new_cfg,
                &snapshot.fingerprints,
            ),
            // `restartOnNodeChange` **不在 Polaris 的 UserConfig 结构体里**（config-engine 的 norm 排除
            // 清单 `orchestration.rs:119` 列了它，但结构体从未建模该字段 → 那条排除对它恒是空转）。
            // 故只能从原始 JSON 读。语义对齐 上游 `validateConfig`（ConfigManager.ts:916）：
            // **非 true 一律 false**（缺键/null/非布尔都按 false=进待应用差集）。
            restart_on_node_change: new_config
                .get("restartOnNodeChange")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            defer_restart,
        };

        ClassifiedSwitch::Decided {
            decision: decide(&plan, &input),
            new_cfg: Box::new(new_cfg),
        }
    }

    /// `config:classifyStaged`（spec §2.3.4）的运行时半边：候选配置**若现在落盘**会走哪条腿。
    ///
    /// 判定复用 [`Self::classify_switch`]，`defer_restart` 恒传 `false` —— 本接口回答的是
    /// 「这批改动**本性上**走哪条入核腿」。`deferRestart` 是保存动作的执行政策，
    /// 不是配置分类；若在分类时传 `true`，除 NoOp 外全部都会变成 Defer，便无法诊断原生热切/重启路径。
    ///
    /// 三条兜底腿的映射（与执行侧同源，不另立判据）：
    /// - 核未运行 → `noOp` / 不需重启：落盘不触发任何核动作，改动在下次起核时自然生效；
    /// - 逐字节全等 → `noOp`；
    /// - 无基准 / 解析失败 → `restart`：执行侧此时正是保守重启，预告不得比实际乐观。
    pub fn classify_staged(&self, candidate: &Value) -> StagedClassification {
        let decision = match self.classify_switch(candidate, false) {
            ClassifiedSwitch::NotRunning | ClassifiedSwitch::Unchanged => "noOp",
            ClassifiedSwitch::Fallback(_) => "restart",
            ClassifiedSwitch::Decided { decision, .. } => match decision {
                SwitchDecision::HotSwitch(_) => "hotSwitch",
                SwitchDecision::NoOp => "noOp",
                SwitchDecision::Defer => "defer",
                SwitchDecision::Restart => "restart",
            },
        };
        StagedClassification {
            decision,
            // 保存不改变运行核：hotSwitch/defer/restart 三腿落盘后都仍待 Apply；只有 NoOp 没有运行差集。
            restart_required: decision != "noOp",
        }
    }

    /// 非重启腿（热切/no-op/defer）的收尾：对账 `current_config` + 刷新待决 force-restart 快照。
    ///
    /// H-1（上游 :1792-1801/1846-1847/1875-1876）：这三条腿都不重启，但若有 `apply_pending` 已排程的
    /// 待决 force-restart，其快照仍是**旧** cfg → timer 到点会把核重启回旧节点，把刚热切的结果吃掉。
    /// 故必须把快照**值**刷新到 newConfig，同时**保留 force-restart 意图与 id**（不清空、不换号）。
    pub(super) fn commit_applied(&self, new_config: &Value) {
        if let Ok(mut g) = self.current_config.write() {
            *g = Some(new_config.clone());
        }
        if let Ok(mut g) = self.pending_force_restart.write() {
            if let Some((id, _)) = g.take() {
                *g = Some((id, new_config.clone()));
            }
        }
    }

    /// 重启腿收尾：对账 `current_config` + **丢弃**待决 force-restart 快照 + 调度去抖重启。
    ///
    /// 上游 :1886-1889：结构性重启用的是最新完整 config → 超代任何待决 force-restart 快照
    /// （newer 胜，避免旧 force cfg 反 shadow 本次变更）。快照清空后，去抖回调按 id 取不到载荷 →
    /// 自然回落 `config.current()`（磁盘上的最新配置）。
    fn apply_restart(self: &Arc<Self>, new_config: Value) {
        if let Ok(mut g) = self.current_config.write() {
            *g = Some(new_config);
        }
        if let Ok(mut g) = self.pending_force_restart.write() {
            *g = None;
        }
        self.schedule_restart();
    }

    /// A4：热切 selector（`select_outbound` PUT，零重启）。核未起/未就绪 → `management_api` 返 not_ready →
    /// `select_outbound` Err → false（不改 flag，下次 tick 重试）。上游 `hotSwitchSelector`。
    pub(super) async fn hot_switch_selector(&self, selector_tag: &str, member_tag: &str) -> bool {
        if member_tag.is_empty() {
            return false;
        }
        match self.put_outbound(selector_tag, member_tag).await {
            Ok(()) => {
                log::info!("已热切换 {selector_tag} → {member_tag}（管理 API，无重启）");
                true
            }
            Err(e) => {
                log::warn!("管理 API 热切换 {selector_tag} 失败：{e}");
                false
            }
        }
    }

    /// `proxy-selector` / `rule-sel-*` 的唯一锁内 PUT 原语。`probe-selector-*` 属独立测速槽，仍走
    /// [`Self::hot_switch_selector`]；任何会改变用户流量选择的写者必须把 guard 显式传进来。
    pub(super) async fn hot_switch_selector_locked(
        &self,
        _switch_guard: &AsyncMutexGuard<'_, ()>,
        selector_tag: &str,
        member_tag: &str,
    ) -> bool {
        self.hot_switch_selector(selector_tag, member_tag).await
    }

    /// PUT 落点：生产 = 真管理 API gRPC `SelectOutbound`；单测经 `management_api_stub` 注入
    /// （同 [`core_binary_for_start`](Self::core_binary_for_start) 的先例，见该字段文档）。
    ///
    /// 只替换**最末端的那一次调用**，成败映射 / 日志 / 上层决策全部走生产同一条码路。
    async fn put_outbound(&self, selector_tag: &str, member_tag: &str) -> Result<(), String> {
        #[cfg(test)]
        if let Some(sink) = self
            .management_api_stub
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(Arc::clone))
        {
            return sink.put(selector_tag, member_tag);
        }
        self.management_api()
            .await
            .select_outbound(selector_tag, member_tag)
            .await
            .map_err(|e| e.to_string())
    }

    // ══════════════ H3：起核后把 selector 选择校正回 config 意图 ══════════════
    //
    // 1:1 移植 上游 `reassertSelectorSelection` + `reassertRuleSelectors`（`ProxyManager.ts:1176-1237`）
    // 与其调用点的 `.finally()` 串接（:1144-1165）。
    //
    // **根因**：sing-box 1.14 的 `experimental.cache_file` 默认 `store_selected` —— 它把 selector 的
    // **运行期**选择持久化进 `cache.db` 的 `selected` bucket，起核时用它**覆盖**新生成 config 里的
    // `default`。于是「盘上选 Hk01、生成的 `proxy-selector.default = "Hk01"`」与「核实际跑上一轮残留的
    // `Tailscale`」可以同时成立，且**全链路零告警**（`attest_selected_exit` 是纯静态自证，量的是生成
    // 产物不是运行态，看不见这层覆盖）。
    //
    // **为什么不是关掉 `store_selected`**：那要往生成产物里下发 `cache_file.store_selected:false`，
    // 而 上游 不下发该键 ⇒ `golden_config_snapshot` 的 37 例逐字对拍立刻红。金样门是对的——修法必须是
    // 「起核后用管理 API 把 selector 拨回 config 意图」，让 config 成为单一真值、压过缓存。

    /// H3 selector 校正阶段 1 的最大轮数（上游 `for (let i = 0; i < 10; i++)`）。
    ///
    /// 重试的对象是「管理 API 刚起可能未就绪」：核进程已就绪 ≠ 它的 api service 已能接 gRPC。
    pub(super) const REASSERT_MAX_ROUNDS: usize = 10;

    /// H3 selector 校正阶段 1 的轮间退避（上游 `await new Promise((r) => setTimeout(r, 300))`）。
    const REASSERT_RETRY_DELAY_MS: u64 = 300;

    /// **H3 修复的后台腿 + 续延**（= 上游 `void this.reassertSelectorSelection(config).finally(...)`）。
    ///
    /// # 为什么是 spawn 而不是 `.await` 在起核主链上
    ///
    /// 阶段 1 最坏 10 轮 × 300ms ≈ 3s（管理 API 迟迟不就绪时）。挂在 `start_inner` 主链上 = 每次起核
    /// 都可能凭空多等 3s，而校正**不是起核成功的前提**（校正失败时 cache/default 仍是一个有效节点，
    /// 只是可能不是用户选的那个）。best-effort 的东西不该卡住关键路径。
    ///
    /// # 为什么续延用 Drop 守卫而不是「跑完再调一行」
    ///
    /// 上游 那里是 `.finally()`：**reassert 抛异常也要跑续延**。Rust 里等价物就是 Drop 守卫——把续延
    /// 写在 `await` 之后，一旦 reassert 内部 panic，展开会跳过它，解锁缓存永远不失效（症状：boot 窗口
    /// 内那轮解锁检测的脏结果永久留在缓存里，且没有任何可见迹象）。
    ///
    /// # 世代守卫
    ///
    /// `my_gen` 是起核那一刻的世代快照。这条 `'static` 任务能活过停核/换核/新 start，而它的每个动作
    /// （PUT 到当前核、广播 `{running:true}`）都是**对着那个核**的 —— 世代变了必须整腿退场。
    pub(super) fn spawn_reassert_selector_selection(
        self: &Arc<Self>,
        user_config: UserConfig,
        my_gen: u64,
        api_port: u16,
    ) {
        let me = Arc::clone(self);
        // 在 task 入队前冻结所有权；若用户配置先于 task 首次 poll 前进，旧起核校正必须直接退场。
        let intent_generation = self.selector_reconcile.intent_generation();
        // 模式取**核实际启动的那份配置**（与 flush 自身守卫同源），在 move 前抄下。
        let mode = user_config.proxy_mode_type;
        // TUN 成功腿在 public start guard 归还前同步接棒；该 guard 经 reassert 的 finally 守卫延续到
        // schedule_connection_flush 接棒。非 TUN 没有无差别 RST，不额外延长稳定门。
        let network_settle = mode
            .is_tun()
            .then(|| self.network_settle.begin("tun-selector-reassert"));
        // `tauri::async_runtime::spawn` 而非裸 `tokio::spawn`：同 `spawn_ts_exit_recovery` 的理由
        // （两者在 tauri 运行时下等价，但前者在无 tokio 上下文时不当场 panic）。
        tauri::async_runtime::spawn(async move {
            // 内层作用域：守卫在**这一行**（而不是整个 task 末尾）drop ⇒ 三条续延仍严格晚于每一次
            // PUT、且**不被自证的那次 gRPC 读回拖慢**。读回最坏要等满 `SNAPSHOT_TIMEOUT`（3s），而
            // 连接 flush / 解锁失效 / 出口 IP 重探一条都不该为一次只读观测多等 3s。
            let outcome = {
                let _settled = ReassertSettledGuard {
                    runtime: Arc::clone(&me),
                    generation: my_gen,
                    mode,
                    api_port,
                    _network_settle_guard: network_settle,
                };
                me.reassert_selector_selection_for_intent(&user_config, my_gen, intent_generation)
                    .await
            };
            // reassert 内部 panic 时展开会跳过这一行 —— 那是对的：守卫已把续延跑掉（`.finally()` 语义），
            // 而自证是**观测**，观测不到就该沉默，不该在展开路径上再造一条半截结论。
            me.attest_runtime_selector(&outcome, my_gen).await;
        });
    }

    /// H3 校正的**续延**：校正完成 / 放弃 / panic 后都必跑（见 [`ReassertSettledGuard`]）。
    ///
    /// **F-C 解锁污染根治**（上游 同名修复）：校正可能**真的翻转** selector（cache_file 复活的旧选择
    /// 被拨回 config 选中节点，含 rule-sel）。这次翻转不经 `switch_mode`，原本**不在解锁失效契约内**
    /// ⇒ boot 窗口内起跑的解锁检测轮经的是**旧出口**，其结果会被当成新鲜数据 commit 进缓存（epoch
    /// 守卫对它失明）。此处把校正补进契约：作废 boot 窗口那批在飞轮，让它们在校正后的出口上重跑。
    ///
    /// 校正是同值 no-op 时也会多失效一次 —— 与前端自身的去抖合并，无害（宁可多重跑一轮，不可留脏值）。
    ///
    /// **出口 IP 重探同理，也必须排在校正之后**（`exit_ip_wiring_guard` 的配对契约在此处成立）：它量的
    /// 就是「我现在从哪出去」。留在起核主链上则校正一旦真翻转 selector，那次探测拿到的是**旧出口**的
    /// 公网 IP，并被当成当前出口写进 ipinfo 缓存。上游 那边这条是靠 S1 `whenSelectorSettled` 让探测
    /// 自己等校正落定（Polaris 未港该门）；把排程本身挂到续延上是同一条保证的等价形态。
    ///
    /// **世代守卫是本移植的有意加强，不是 上游的逐字形态**：上游的 `finally` 里 `emit('unlock-invalidate')`
    /// 无守卫。但 Polaris 这两条都带 `running:true` 参数，而「校正在飞时核已被停/换」这个窗口是**把它们
    /// 从主链挪进异步续延才产生的**（原来就在主链上、紧跟 status 提交，不存在这个窗口）。不守卫等于亲手
    /// 造一个「核已停却广播 running:true / 对着死核排一次 4s 后的出口探测」的假信号。
    /// **连接 flush 也必须排在校正之后**（上游的「时序修 E」，逐字同源）：flush 干的是无差别
    /// `CloseAllConnections`，被 RST 的连接会**立刻重连**——重连走的是重连那一刻的 selector。
    /// flush 若早于校正落定，这批重连全部按 cache_file 的旧选择建链，本 bug 的症状在这个窄窗里
    /// 原样复现，而且是**我们亲手把用户所有连接踢过去的**，比自然漂移更糟。
    ///
    /// flush 自身的两条守卫（仅 TUN / 世代+核在跑）原样保留、不放宽：这里只改「什么时候开枪」，
    /// 不改「该不该开枪」。
    fn after_selector_reasserted(
        self: &Arc<Self>,
        my_gen: u64,
        mode: ProxyModeType,
        api_port: u16,
    ) {
        if self.gate.generation() != my_gen {
            log::debug!(
                "selector 校正续延：世代已变（{my_gen}→{}）→ 退场",
                self.gate.generation()
            );
            return;
        }
        self.invalidate_unlock_cache(true, false);
        self.schedule_exit_ip_refresh(true);
        self.schedule_connection_flush(mode, my_gen, api_port);
    }

    /// **H3 阶段 1**：把 `proxy-selector` 校正回用户意图（带短重试，等管理 API 就绪）。成功/放弃后跑阶段 2。
    ///
    /// 逐条时序都有来历，别自己发明顺序：
    /// - **每轮重读最新 `selectedServerId`**（而不是复用起核那刻的值）：起核窗口内用户完全可能已经热切到
    ///   别的节点，此时校正必须跟最新意图，绝不能把它 revert 回起核时那个（上游 同处注释明写）。
    /// - **tag 从起核那刻的 `switch_snapshot.id_to_tag` 解析**：PUT 的成员必须是**运行核里真实存在**的
    ///   tag，而运行核的 tag 集合定格在它启动的那份 config 上（`current_config` 可能已被并发推进）。
    /// - **解析不出 tag 不静默 break**（上游 bug#5）：选中节点不在运行核的 tag 映射里（config 被并发
    ///   推进）时，静默放弃会让 selector 无声地停在 cache_file 的旧选择上 —— 那正是本 bug 的症状放大器。
    ///   留 warn 日志，收敛交给后续的对账重启。
    /// - **停核 / 被接管中直接放弃**：别在杀核窗口里重连一个将死的管理 API（上游 `this.stopping` 守卫，
    ///   Polaris 侧等价物是「`running` 已假」或「世代已变」两条腿的析取）。
    ///
    /// # 返回值：为什么不再是 `()`
    ///
    /// 「PUT 成功」「解析不出 tag 就放弃」「跑满重试仍全失败」这三种终局，对**用户**的意义完全不同：
    /// 后两种就是 selector 原样停在 `cache_file` 旧选择上的那个状态 —— 即本 bug 的现场 —— 而它们此前
    /// 只落一行 `log::warn`，用户什么都看不到。把终局带回给调用方（[`Self::attest_runtime_selector`]），
    /// 才谈得上经 `set_nonfatal_error` 告知。
    async fn reassert_if_selector_reconcile_required_locked(
        &self,
        raw_config: &Value,
        my_gen: u64,
        intent_generation: u64,
        switch_guard: &AsyncMutexGuard<'_, ()>,
    ) {
        if !self.selector_reconcile.is_required() {
            return;
        }
        let Ok(config) = serde_json::from_value::<UserConfig>(raw_config.clone()) else {
            self.set_nonfatal_error(
                "selector 所有权交接后无法解析运行配置，请重新应用配置以完成对账",
                code::EXIT_MISMATCH,
            );
            return;
        };
        let outcome = self
            .reassert_selector_selection_locked(&config, my_gen, intent_generation, switch_guard)
            .await;
        if matches!(outcome.stage1, Stage1Outcome::Applied { .. }) {
            self.selector_reconcile.clear_required();
        } else if !matches!(outcome.stage1, Stage1Outcome::Abandoned) {
            let attestation = attest_runtime_selection(&outcome, None);
            self.set_nonfatal_error(&attestation.user_message(), code::EXIT_MISMATCH);
        }
    }

    #[cfg(test)]
    pub(super) async fn reassert_selector_selection(
        &self,
        config: &UserConfig,
        my_gen: u64,
    ) -> ReassertOutcome {
        let intent_generation = self.selector_reconcile.intent_generation();
        self.reassert_selector_selection_for_intent(config, my_gen, intent_generation)
            .await
    }

    async fn reassert_selector_selection_for_intent(
        &self,
        config: &UserConfig,
        my_gen: u64,
        intent_generation: u64,
    ) -> ReassertOutcome {
        let switch_guard = self.switch_serial.lock().await;
        if !self.selector_operation_is_current(my_gen, intent_generation) {
            return ReassertOutcome {
                stage1: Stage1Outcome::Abandoned,
                rule_intents: Vec::new(),
            };
        }
        self.reassert_selector_selection_locked(config, my_gen, intent_generation, &switch_guard)
            .await
    }

    async fn reassert_selector_selection_locked(
        &self,
        config: &UserConfig,
        my_gen: u64,
        intent_generation: u64,
        switch_guard: &AsyncMutexGuard<'_, ()>,
    ) -> ReassertOutcome {
        // 循环跑满 ⟺ 每轮 PUT 都失败；`member_tag` 逐轮覆盖为**当轮**意图，故落到循环外时它是最后一轮
        // 的意图（重试腿每轮重读最新选中节点，最后一轮才是最新的那个）。初值只在
        // `REASSERT_MAX_ROUNDS == 0` 这个构型下逃逸，而该常量恒 10。
        let mut stage1 = Stage1Outcome::PutExhausted {
            member_tag: String::new(),
        };
        for _ in 0..Self::REASSERT_MAX_ROUNDS {
            if !self.selector_operation_is_current(my_gen, intent_generation) {
                // 主动 stop/restart 接管中：勿在杀核窗口里 PUT，也别对着将死的核出自证结论。
                return ReassertOutcome {
                    stage1: Stage1Outcome::Abandoned,
                    rule_intents: Vec::new(),
                };
            }
            // 每轮现读 `current_config`（**最新意图**）；读不到/解析不出则退回起核那份。
            let raw = self.current_config.read().ok().and_then(|g| g.clone());
            let latest: Option<UserConfig> = raw
                .as_ref()
                .and_then(|v| serde_json::from_value(v.clone()).ok());
            let cur = latest.as_ref().unwrap_or(config);
            let target_id = cur.selected_server_id.clone().filter(|s| !s.is_empty());
            let tag = if is_direct_selection(target_id.as_deref()) {
                Some(DIRECT_TAG.to_string())
            } else {
                target_id.as_deref().and_then(|id| {
                    self.switch_snapshot
                        .read()
                        .ok()
                        .and_then(|g| g.as_ref().and_then(|s| s.id_to_tag.get(id).cloned()))
                })
            };
            let Some(tag) = tag else {
                log::warn!(
                    "selector 校正放弃：选中节点 {} 不在运行核 tag 映射，待启动后对账收敛",
                    target_id.as_deref().unwrap_or("<未选中>")
                );
                stage1 = Stage1Outcome::UnresolvedTag {
                    selected_id: target_id.unwrap_or_else(|| "<未选中>".to_string()),
                };
                break;
            };
            // 登录期出口让位【预置】折入本阶段（上游 同款）：选中的是账号制 TS 全隧道出口且**未登录过**
            // （state 目录不存在）→ 本轮 PUT `direct` 而不是那个连不上的 TS tag，消除「核起→首帧」黑洞。
            // 判据用 fresh 值（eligible + !stateExists）而非读 flag；且**只在 PUT 成功后**才 markEngaged
            // —— flag 与 selector 必须同进退，否则会出现「flag 说已让位、selector 指着未登录的 TS 出口」。
            // `raw` 缺失时按 `Value::Null` 求值：`meshLoginFallbackDirect` 取不到键 ⇒ 缺省开，与 上游
            // 回退到 `config` 对象的语义一致。
            let null = Value::Null;
            let raw_ref = raw.as_ref().unwrap_or(&null);
            let want_direct = self.login_fallback_eligible(cur, raw_ref)
                && target_id.as_ref().is_some_and(|id| {
                    !self
                        .mesh
                        .tailscale_state_exists(std::slice::from_ref(id))
                        .get(id)
                        .copied()
                        .unwrap_or(false)
                });
            let member_tag = if want_direct {
                DIRECT_TAG
            } else {
                tag.as_str()
            };
            // 先记「本轮意图」，PUT 成功再升级成 `Applied`：跑满退出时它就是最后一轮的意图。
            stage1 = Stage1Outcome::PutExhausted {
                member_tag: member_tag.to_string(),
            };
            if self
                .hot_switch_selector_locked(switch_guard, PROXY_SELECTOR_TAG, member_tag)
                .await
            {
                if !self.selector_operation_is_current(my_gen, intent_generation) {
                    self.selector_reconcile.mark_required();
                    return ReassertOutcome {
                        stage1: Stage1Outcome::Abandoned,
                        rule_intents: Vec::new(),
                    };
                }
                if want_direct {
                    if let Some(id) = target_id.as_deref() {
                        self.mark_login_fallback_engaged(id, cur);
                    }
                }
                stage1 = Stage1Outcome::Applied {
                    member_tag: member_tag.to_string(),
                };
                break;
            }
            // 管理 API 未就绪 / 瞬时失败 → 短退避后重试。
            tokio::time::sleep(std::time::Duration::from_millis(
                Self::REASSERT_RETRY_DELAY_MS,
            ))
            .await;
            if !self.selector_operation_is_current(my_gen, intent_generation) {
                return ReassertOutcome {
                    stage1: Stage1Outcome::Abandoned,
                    rule_intents: Vec::new(),
                };
            }
        }
        let Ok(rule_intents) = self
            .reassert_rule_selectors_locked(config, my_gen, intent_generation, switch_guard)
            .await
        else {
            return ReassertOutcome {
                stage1: Stage1Outcome::Abandoned,
                rule_intents: Vec::new(),
            };
        };
        ReassertOutcome {
            stage1,
            rule_intents,
        }
    }

    /// **H3 阶段 2**：把各 `rule-sel-<id>` 校正回对应规则的 `targetServerId`（防 cache_file 把规则选择
    /// 回弹到旧节点）。
    ///
    /// - **无 `targetServerId` 的规则跳过**：它们生成时 `default = proxy-selector`（嵌套跟随全局），
    ///   而 sing-box 重载不擦 selector 的 default ⇒ 跟随关系本身不需要校正（上游 同处注释明写此语义）。
    /// - **不重试**：阶段 1 成功已经证明管理 API 可用；失败由 cache/default 兜底。
    /// - **selector tag 取自 `switch_snapshot.rule_target`**，绝不自己 `format!("rule-sel-{id}")`：生成侧
    ///   撞名时会追加 ` (n)` 后缀（`builder/outbounds.rs` 的 `emit`），手拼模板会 PUT 到一个不存在的 tag。
    ///   那份快照本身还经「该 selector 是否真在生成产物里」过滤过，是运行核 rule-sel 的唯一真值。
    /// - **逐条串行 await**（上游 是 fire-and-forget 并发）：best-effort 语义等价（`hot_switch_selector`
    ///   已把失败吞成 `false`），但顺序确定 ⇒ 可断言、可复现。
    ///
    /// 返回**尝试过**的 `(selector_tag, member_tag)` 序列，交给 [`Self::attest_runtime_selector`] 读回对账
    /// （PUT 返回值不带出去：那是意图侧的东西，成败以核里读回来的运行期值为准）。
    async fn reassert_rule_selectors_locked(
        &self,
        config: &UserConfig,
        my_gen: u64,
        intent_generation: u64,
        switch_guard: &AsyncMutexGuard<'_, ()>,
    ) -> Result<Vec<(String, String)>, ()> {
        let mut intents: Vec<(String, String)> = Vec::new();
        let Some(snapshot) = self.switch_snapshot.read().ok().and_then(|g| g.clone()) else {
            return Ok(intents); // 无快照（核未起/已停）→ 无从解析 rule-sel tag
        };
        let latest: Option<UserConfig> = self
            .current_config
            .read()
            .ok()
            .and_then(|g| g.clone())
            .and_then(|v| serde_json::from_value(v).ok());
        let cur = latest.as_ref().unwrap_or(config);

        for rule in &cur.custom_rules {
            if !rule.enabled || rule.action != RuleAction::Proxy {
                continue;
            }
            let Some(target) = rule.target_server_id.as_deref() else {
                continue; // 无目标 → default=proxy-selector 嵌套跟随全局，无须校正
            };
            intents.extend(
                self.reassert_one_rule_selector_locked(
                    &snapshot,
                    &format!("custom:{}", rule.id),
                    target,
                    my_gen,
                    intent_generation,
                    switch_guard,
                )
                .await?,
            );
        }
        for app_rule in &cur.app_rules {
            if !app_rule.enabled || app_rule.action != RuleAction::Proxy {
                continue;
            }
            let Some(target) = app_rule.target_server_id.as_deref() else {
                continue;
            };
            intents.extend(
                self.reassert_one_rule_selector_locked(
                    &snapshot,
                    &format!("app:{}", app_rule.app_id),
                    target,
                    my_gen,
                    intent_generation,
                    switch_guard,
                )
                .await?,
            );
        }
        Ok(intents)
    }

    /// 单条 rule-sel 的校正 PUT。快照里查不到该规则的 selector（生成时被剔除）或查不到目标节点的 tag
    /// （目标被 gate 剔除 / 已删除）→ 跳过，**不是 FATAL**：该 selector 的 default 仍是有效成员。
    ///
    /// 返回 `Some((selector_tag, member_tag))` ⟺ **确实 PUT 过**（不论成败）；跳过的两条腿返 `None`，
    /// 它们没有可对账的意图。
    async fn reassert_one_rule_selector_locked(
        &self,
        snapshot: &SwitchSnapshot,
        rule_key: &str,
        target_server_id: &str,
        my_gen: u64,
        intent_generation: u64,
        switch_guard: &AsyncMutexGuard<'_, ()>,
    ) -> Result<Option<(String, String)>, ()> {
        if !self.selector_operation_is_current(my_gen, intent_generation) {
            return Err(());
        }
        let Some(entry) = snapshot.rule_target.get(rule_key) else {
            return Ok(None);
        };
        let Some(member_tag) = snapshot.id_to_tag.get(target_server_id) else {
            return Ok(None);
        };
        let _ = self
            .hot_switch_selector_locked(switch_guard, &entry.selector_tag, member_tag)
            .await;
        if !self.selector_operation_is_current(my_gen, intent_generation) {
            self.selector_reconcile.mark_required();
            return Err(());
        }
        Ok(Some((entry.selector_tag.clone(), member_tag.clone())))
    }

    /// **H3 阶段 3：运行期出口自证** —— 把「实际生效出口 ≠ 选中节点」这条轴变成可观测的。
    ///
    /// # 为什么非有这一步不可
    ///
    /// [`attest_selected_exit`](Self::attest_selected_exit) 自述「纯函数、零 I/O、不用探针 / 不查
    /// selector」，它比的是**生成 config 解出的出口**对**盘上 `selectedServerId`** —— 本 bug 下这两个
    /// 都写着选中节点，故必判 `Match`。真机血证（盘上 Hk01、生成的 `proxy-selector.default = "Hk01"`、
    /// 核实走 `Tailscale`）就是从它眼皮底下走过去并打了「通过」的那一次。**两份同源的意图对账，
    /// 永远量不出运行期的分叉。**
    ///
    /// 本方法是它的读侧对偶：一半靠校正腿的终局（写侧：PUT 到底做成了没有），一半靠
    /// [`SingBoxApiClient::first_groups_snapshot`](polaris_singbox_grpc::SingBoxApiClient::first_groups_snapshot)
    /// 读回核**此刻实际**指着谁（读侧）。
    ///
    /// # 为什么不是「起核后探一次出口 IP」
    ///
    /// 那条腿仓里已经有了（[`schedule_exit_ip_refresh`](Self::schedule_exit_ip_refresh)，且已挂在校正
    /// 续延上），再探一次既重复又慢一整个网络 RTT。本方法零网络出站：只对 loopback 上的管理 API 读一帧。
    ///
    /// # 世代/存活守卫
    ///
    /// 读回来的是**当前核**的状态，而这条 `'static` 任务能活过停核/换核。世代已变或核已停 → 整段退场：
    /// 此时无论读到什么，它都不是「用户正在看的那个核」的事实，报出来就是假信号。
    ///
    /// # 射程外：`probe-selector-*`（**有意不接线**）
    ///
    /// 真机 `cache.db` 的 `selected` bucket 里除了 `proxy-selector → Tailscale`，还躺着
    /// `probe-selector-0..15 →` 上一轮测速残留的节点 —— 它们同样在分叉。但那 16 个槽是**测速探测池**，
    /// 起核时校正腿一次都不 PUT（槽位由 `probe_select_slot` 在每次测速临选临用），此刻**没有可对账的
    /// 意图**：拿「上一轮残留」去比「本轮还没发生的选择」只会得出一堆无意义的告警。真要覆盖，正确的
    /// 位置是测速自己选槽之后，不是起核自证这里。快照本身是全量的（`SubscribeGroups` 返回所有 group），
    /// 将来要接线不必再动读侧。
    pub(super) async fn attest_runtime_selector(
        self: &Arc<Self>,
        outcome: &ReassertOutcome,
        my_gen: u64,
    ) {
        if self.gate.generation() != my_gen || !self.status().running {
            log::debug!("运行期出口自证：世代已变 / 核已停 → 退场");
            return;
        }
        // 只有「PUT 成功」这一支需要读回来对账：另外三支的结论不依赖运行期值（放弃腿本身就是结论，
        // 主动退场则不出结论），此时再去连一次管理 API 纯属多余。
        let groups = match outcome.stage1 {
            Stage1Outcome::Applied { .. } => self.read_selector_groups().await,
            _ => None,
        };
        match attest_runtime_selection(outcome, groups.as_deref()) {
            SelectorAttestation::Match => {
                log::info!("运行期出口自证通过：selector 实际选择 == 校正意图");
            }
            other => self.set_nonfatal_error(&other.user_message(), code::EXIT_MISMATCH),
        }
    }

    /// 读回各 group 的运行期选择。读不到（管理 API 连不上 / 首帧超时 / 核正在停）→ `None`
    /// （**不是**空 `Vec`：空 `Vec` 是「核确实没有 group」，两者在
    /// [`attest_runtime_selection`] 里处置相同但语义不同，别在这一层就抹平）。
    ///
    /// 单测经 `management_api_stub` 注入（同 [`put_outbound`](Self::put_outbound) 的先例）：
    /// 桩未预置 → `None` → 自证本轮不判定，与生产读失败**同一条码路**，测试环境不比生产宽容。
    async fn read_selector_groups(&self) -> Option<Vec<GroupSelection>> {
        #[cfg(test)]
        if let Some(sink) = self
            .management_api_stub
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(Arc::clone))
        {
            return sink.groups();
        }
        match self.management_api().await.groups_snapshot().await {
            Ok(groups) => Some(groups),
            Err(e) => {
                log::warn!("运行期 selector 读回失败（本轮不判定）：{e:?}");
                None
            }
        }
    }

    /// 取出并清除 pending switch 配置（id 对得上才取；对不上回落 None）。与 force-restart 同构。
    ///
    /// 返回 `(config, defer_restart)` —— 两者必须一起取，理由见 [`Self::pending_switch`] 字段注释。
    pub(super) fn take_pending_switch(&self, id: Option<u64>) -> Option<(Value, bool)> {
        let mut g = self.pending_switch.write().ok()?;
        match (&*g, id) {
            (Some((sid, _, _)), Some(want)) if *sid == want => {
                g.take().map(|(_, c, defer)| (c, defer))
            }
            _ => None,
        }
    }
}
