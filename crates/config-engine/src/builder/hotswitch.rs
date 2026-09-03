//! 热切换判定纯逻辑（上游 `ProxyManager.ts` planHotSwitch / planRuleHotSwitch /
//! canSkipRestartForAddedUnreferenced / isServerDirty / resolveGlobalExitTag 移植，并按真机收据修正
//! Windows TUN 的过时禁用条件）。
//!
//! 所有运行态（currentConfig / currentIdToTagMap / bootstrapFallbackEngaged /
//! currentRuleTargetMap / runningServersFingerprint）经 [`HotSwitchDeps`] 注入 ——
//! 原始 ProxyManager 读 `this.*`，此处全抽到参数，无 I/O、无实例态、可单测。
//!
//! 前提：norm(old) === norm(new)（由调用方经 [`super::orchestration::config_generation_norm`]
//! 保证，本模块内部亦复检一次）。

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use crate::builder::endpoint_routes::{
    endpoint_forced_route_cidrs, mesh_always_routes_subnets, referenced_server_ids,
};
use crate::builder::orchestration::{config_generation_norm, server_fingerprint};
use crate::builder::route::mesh_selected_exit_falls_back_to_direct;
use crate::user_config::app_config::UserConfig;
use crate::user_config::dns_constants::{
    is_block_selection, is_direct_selection, DIRECT_TAG, PROXY_SELECTOR_TAG,
};
use crate::user_config::server_config::{is_mesh_node, ServerConfig};

// ============================================================================
// 类型
// ============================================================================

/// planHotSwitch 注入的运行态依赖（上游 `this.*` 态的纯化镜像）。
#[derive(Debug, Clone, Default)]
pub struct HotSwitchDeps {
    /// id → outbound tag（启动时映射；结构等价 ⇒ 不变，热切可复用）。
    /// 上游 `this.currentIdToTagMap`。None = 未注入（规则目标无法解析 → 规则热切返 None）。
    pub current_id_to_tag_map: Option<BTreeMap<String, String>>,
    /// id → serverFingerprint 运行核快照（启动时 serverFingerprint）。
    /// 上游 `this.runningServersFingerprint`。None = 核未起（dirty 判定返 false）。
    pub running_servers_fingerprint: Option<BTreeMap<String, String>>,
    /// ruleKey → RuleTargetEntry（生成时 rule-sel 元数据）。
    /// 上游 `this.currentRuleTargetMap`。None = 启动无 rule-sel（规则热切返空 Vec）。
    pub current_rule_target_map: Option<BTreeMap<String, RuleTargetEntry>>,
    /// 登录期出口让位态：proxy-selector 实际指 direct（非 config 选中节点 tag）。
    /// 上游 `this.bootstrapFallbackEngaged`。
    pub bootstrap_fallback_engaged: bool,
}

/// currentRuleTargetMap 的条目：生成时 rule-sel 的 selectorTag + memberTag(default)。
/// 上游 `{ selectorTag, memberTag }`。memberTag 仅展示用（planRuleHotSwitch 从 oldTarget 现算旧 tag）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleTargetEntry {
    /// 该规则对应的 rule-sel selector tag（如 "rule-sel-r1"）。
    pub selector_tag: String,
    /// 生成时的 default memberTag（启动时 targetServerId 解析；planRuleHotSwitch 不依赖，仅兼容结构）。
    pub member_tag: String,
}

/// 热切换规划结果四态分类。上游 `kind: 'none'|'global'|'rules'|'both'`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HotSwitchKind {
    /// 无热切换可行（结构变更/目标不在 selector）→ 退回去抖重启或正常分流。
    #[default]
    None,
    /// 仅 selectedServerId 变 → PUT proxy-selector。
    Global,
    /// 仅规则 targetServerId 变 → PUT 各 rule-sel-`<id>`。
    Rules,
    /// 全局 + 规则同时变 → PUT proxy-selector + 各 rule-sel。
    Both,
}

/// 一条 selector PUT 操作（热切换下发项）。上游 `{ selectorTag, memberTag, oldMemberTag? }`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotSwitchPut {
    /// 目标 selector tag（proxy-selector 或 rule-sel-`<id>`）。
    pub selector_tag: String,
    /// 新成员 tag（PUT 目标）。
    pub member_tag: String,
    /// 旧成员 tag（精准断连 pair 用；缺失→该 pair 断连跳过）。Polaris oldMemberTag（可选）。
    pub old_member_tag: Option<String>,
}

/// planHotSwitch 规划结果。上游 `planHotSwitch` 返回值。
#[derive(Debug, Clone, Default)]
pub struct HotSwitchPlan {
    /// 四态分类。
    pub kind: HotSwitchKind,
    /// 需 PUT 的 selector 列表。
    pub puts: Vec<HotSwitchPut>,
    /// §2 P2-B review F1：kind=None 但规则目标无法热切（目标 dirty/不在 selector）→ 必须重启
    /// （防 no-op/canSkip 腿吞掉 targetServerId 出 norm 的规则变更、静默不生效）。仅此路径置 true。
    pub must_restart: bool,
}

impl HotSwitchPlan {
    /// 构造 kind=None 的空规划（norm 前提失败/结构变更等正常退回路径）。
    fn none() -> Self {
        HotSwitchPlan {
            kind: HotSwitchKind::None,
            puts: Vec::new(),
            must_restart: false,
        }
    }

    /// 构造 kind=None + mustRestart=true 的强制重启规划（规则目标 dirty/不在 selector）。
    fn none_must_restart() -> Self {
        HotSwitchPlan {
            kind: HotSwitchKind::None,
            puts: Vec::new(),
            must_restart: true,
        }
    }
}

// ============================================================================
// planHotSwitch（Polaris L1923-2000）
// ============================================================================

/// 该节点是否「只在被选中时才发布其内网段」（force-route engaged 型组网节点）。
///
/// 判据三项缺一不可，逐字同 2026-09 前 [`plan_hot_switch`] 内的同名局部闭包：
/// 具备组网资格（[`is_mesh_node`]）× 不恒发段（`alwaysRouteSubnets=false`）× 确有段可发
/// （[`endpoint_forced_route_cidrs`] 非空）。`None`（无选中 / 选中不在 servers）→ false。
///
/// 唯一消费点是 [`plan_hot_switch`] 的 route 投影 guard：切到/离开这类节点 → 段规则增删 →
/// 退回重启。表达的是**热切可行性**，不是「探测无意义」—— 三项判据里没有 `allow_internet`，
/// 故一个 `allowInternet=true` 的 WireGuard 节点照样可能命中它，而那是承载公网的全隧道节点，
/// 心跳探针探的就是用户在走的那条路。2026-09 曾被自动故障切换借去当「本世代整体停摆」的第二条
/// 原因，等于把这类节点的心跳整条静音（探不到故障 → 不上报 → 三面静默）；已撤回，在此登记
/// 以免再被同样地误用。这类节点切不过去的正确处置在 [`plan_hot_switch`]：心跳照跑、探到故障、
/// 候选被本 guard 全部剔掉 → 由「需重启」上报腿告诉用户手动换。
///
/// 由 [`plan_hot_switch`] 内的同名局部闭包提为模块级函数；语义未变（提取前后逐格对差见
/// `sel_only_forces_subnets_matches_pre_extraction_formula`）。
#[must_use]
fn sel_only_forces_subnets(s: Option<&ServerConfig>) -> bool {
    match s {
        Some(srv) => {
            is_mesh_node(srv)
                && !mesh_always_routes_subnets(srv)
                && !endpoint_forced_route_cidrs(srv).is_empty()
        }
        None => false,
    }
}

/// 热切换规划：判 `new` 相对 `old` 能否走 clash_api 热切换，并产出需 PUT 的 selector 列表。
///
/// - norm(old) === norm(new) 是前提（targetServerId/selectedServerId 已移出 norm → 改这俩值不翻转 norm）。
/// - kind=Global：仅 selectedServerId 变 → PUT proxy-selector。
/// - kind=Rules：仅规则 targetServerId 变 → PUT 各 rule-sel-`<id>`。
/// - kind=Both：全局 + 规则同时变 → PUT proxy-selector + 各 rule-sel。
/// - kind=None：无热切换可行 → `must_restart` 区分「正常退回（false）」与「规则目标 dirty/不在 selector 须强制重启（true）」。
///
/// 上游 `ProxyManager.planHotSwitch`（this.currentConfig/this.currentIdToTagMap/
/// this.bootstrapFallbackEngaged 经 `deps` 注入；old 替代 this.currentConfig）。
pub fn plan_hot_switch(old: &UserConfig, new: &UserConfig, deps: &HotSwitchDeps) -> HotSwitchPlan {
    // norm 前提：结构等价（targetServerId/selectedServerId 均已移出 norm → 仅这俩值变不翻转 norm）。
    if config_generation_norm(old, None) != config_generation_norm(new, None) {
        return HotSwitchPlan::none();
    }
    // 进出阻断一律整核重启（2026-08-13）。
    //
    // 阻断改由**规则级** `action:"reject"` 表达（见 `builder::route` 末尾那段），不再是
    // 「selector 的 default 指向 block 出站」。热切换能表达的只有「PUT 一个 selector 的 default」，
    // 表达不了「整份 route 规则从全 reject 变回正常路由」⇒ 两个方向都必须重下发。
    //
    // 这是那次迁移**唯一**的行为代价，如实记在这里：切出阻断此前是热切（毫秒、不断流），
    // 现在会断掉阻断期间仍然活着的直连连接（LAN/NAS/本地 SSH）。换到的是「阻断态不再每拦一条
    // 连接就打一行 ERROR 把核日志历史挤掉」。
    if is_block_selection(old.selected_server_id.as_deref())
        != is_block_selection(new.selected_server_id.as_deref())
    {
        return HotSwitchPlan::none();
    }

    let mut puts: Vec<HotSwitchPut> = Vec::new();
    let mut global_changed = false;

    // 全局节点变化（含切到/切出 direct 哨兵：memberTag=direct，direct 恒是 proxy-selector 成员→可热切不重启）。
    // Polaris: old.selectedServerId !== newConfig.selectedServerId && newConfig.selectedServerId
    if old.selected_server_id != new.selected_server_id && new.selected_server_id.is_some() {
        let new_id = new.selected_server_id.as_deref().unwrap();
        let to_direct = is_direct_selection(Some(new_id));
        // 目标节点必须已存在于运行中的 selector（= 启动时 old.servers），否则 PUT 指向不存在的成员；
        // direct 豁免（恒为成员）。
        if !to_direct && !old.servers.iter().any(|s| s.id == new_id) {
            return HotSwitchPlan::none();
        }
        // §2 P2-B dirty 闸门：目标节点已编辑未生效（config 参数 ≠ 运行核快照）→ 热切到它会 PUT 到
        // 运行核里的旧参数成员、流量走旧参数且不自愈 → 退回重启。direct 哨兵无参数、不受影响。
        if !to_direct && is_server_dirty(new_id, new, deps) {
            return HotSwitchPlan::none();
        }
        // 选中节点 route 投影 guard（ICMP 已恒走 direct 静态、不再依赖选中节点，但其【其它】route 投影
        // 仍随之变，而 norm 已剔除 selectedServerId → 这些差异 PUT 不重生成，必须退回重启）：
        //   (1) 全隧道兜底：meshSelectedExitFallsBackToDirect 翻转 → final/smart-geo 的 userExitTag
        //       (proxy-selector↔direct) 翻转（补 ICMP 改静态后漏的 off-mesh↔普通代理 同款翻转）。
        //   (2) force-route engaged：alwaysRouteSubnets=false 的 endpoint 仅被选中时发其内网段；
        //       切到/离开它 → 段规则增删（保守：任一端是此类节点即重启）。
        let old_sel = old
            .servers
            .iter()
            .find(|s| Some(s.id.as_str()) == old.selected_server_id.as_deref());
        let new_sel = new
            .servers
            .iter()
            .find(|s| Some(s.id.as_str()) == new.selected_server_id.as_deref());
        if mesh_selected_exit_falls_back_to_direct(old)
            != mesh_selected_exit_falls_back_to_direct(new)
            || sel_only_forces_subnets(old_sel)
            || sel_only_forces_subnets(new_sel)
        {
            return HotSwitchPlan::none();
        }
        // 目标 tag：选中节点 id → tag（经 idToTagMap）。direct 哨兵 → 'direct'。解析不到 → 退回重启。
        let target_tag =
            match resolve_global_exit_tag(Some(new_id), deps.current_id_to_tag_map.as_ref()) {
                Some(t) => t,
                None => return HotSwitchPlan::none(),
            };
        // 旧全局出口 tag（供精准断连 pair）：登录期出口让位态下 proxy-selector 实际指 direct
        // （非 config 选中节点 tag），否则解析旧选中节点 tag。缺失（解析不到）→ 该 pair 断连跳过（宁可漏关不误杀）。
        let old_global_tag = if deps.bootstrap_fallback_engaged {
            Some(DIRECT_TAG.to_string())
        } else {
            resolve_global_exit_tag(
                old.selected_server_id.as_deref(),
                deps.current_id_to_tag_map.as_ref(),
            )
        };
        puts.push(HotSwitchPut {
            selector_tag: PROXY_SELECTOR_TAG.to_string(),
            member_tag: target_tag,
            old_member_tag: old_global_tag,
        });
        global_changed = true;
    }

    // 规则目标变化：diff customRules + appRules 的 targetServerId，对每条变化的规则从
    // currentRuleTargetMap 查 selectorTag、从 newConfig 的 idToTagMap（结构等价不变）解析新 memberTag。
    let rule_puts = match plan_rule_hot_switch(old, new, deps) {
        RuleHotSwitchResult::Puts(p) => p,
        // 任一规则目标节点不在 selector（新节点未入核）或 dirty（已编辑未生效）→ 无法热切 → 必须重启
        // （mustRestart 防被 no-op/canSkip 腿吞：targetServerId 出 norm，no-op 看不到规则目标变更）。
        RuleHotSwitchResult::CannotHotSwitch => return HotSwitchPlan::none_must_restart(),
    };
    puts.extend(rule_puts.iter().cloned());

    if puts.is_empty() {
        return HotSwitchPlan::none();
    }
    let kind = if global_changed && !rule_puts.is_empty() {
        HotSwitchKind::Both
    } else if global_changed {
        HotSwitchKind::Global
    } else {
        HotSwitchKind::Rules
    };
    HotSwitchPlan {
        kind,
        puts,
        must_restart: false,
    }
}

// ============================================================================
// planRuleHotSwitch（Polaris L2075-2132）
// ============================================================================

/// planRuleHotSwitch 的结果（Polaris 返回 `puts[] | null` 的三态）。
enum RuleHotSwitchResult {
    /// 可热切的 PUT 列表（含空 Vec = 无规则目标变化）。
    Puts(Vec<HotSwitchPut>),
    /// 任一目标节点不在运行 selector（新节点未入核）或 dirty（已编辑未生效）→ 无法热切。
    /// 上游 `return null`。
    CannotHotSwitch,
}

/// 规则 targetServerId diff → rule-sel PUT 列表。
///
/// 返回 [`RuleHotSwitchResult::CannotHotSwitch`] 表示任一目标节点不在运行中 selector（应整体退回重启）。
/// currentRuleTargetMap 的 memberTag 是【生成时】的 default（启动时 targetServerId 解析）；此处按 newConfig
/// 重解析新 targetServerId → 新 memberTag（currentIdToTagMap 结构等价不变，可复用）。
///
/// 上游 `ProxyManager.planRuleHotSwitch`（this.currentRuleTargetMap/this.currentIdToTagMap 经 deps 注入）。
fn plan_rule_hot_switch(
    old: &UserConfig,
    new: &UserConfig,
    deps: &HotSwitchDeps,
) -> RuleHotSwitchResult {
    let map = match &deps.current_rule_target_map {
        None => return RuleHotSwitchResult::Puts(Vec::new()), // 启动时无 rule-sel → 无规则热切换
        Some(m) => m,
    };
    let id_to_tag = match &deps.current_id_to_tag_map {
        None => return RuleHotSwitchResult::CannotHotSwitch, // 无法解析节点 tag → 退回重启
        Some(m) => m,
    };

    let mut puts: Vec<HotSwitchPut> = Vec::new();

    // visit 单条规则的 target 变化。返回 true=可继续，false=该规则目标无法热切（调用方返 CannotHotSwitch）。
    // Polaris 内层 `visit(ruleKey, oldTarget, newTarget): boolean`。
    let visit = |rule_key: &str,
                 old_target: Option<&str>,
                 new_target: Option<&str>,
                 puts: &mut Vec<HotSwitchPut>|
     -> bool {
        if old_target == new_target.map(|s| s.to_string()).as_deref() {
            return true; // 未变
        }
        let entry = match map.get(rule_key) {
            None => return true, // currentRuleTargetMap 无此条（启动时该规则未生成 rule-sel，如被 gate 剔除）→ 跳过
            Some(e) => e,
        };
        // 新目标有→解析节点 tag；无（节点切回默认/跟全局）→ proxy-selector（rule-sel 嵌套 default）。
        let member_tag: Option<String> = match new_target {
            Some(t) => id_to_tag.get(t).cloned(),
            None => Some(PROXY_SELECTOR_TAG.to_string()),
        };
        let member_tag = match member_tag {
            Some(t) => t,
            None => return false, // 新目标节点不在 selector → 退回重启
        };
        // §2 P2-B dirty 闸门：规则新目标节点已编辑未生效（config 参数 ≠ 运行核快照）→ 退回重启
        // （防规则热切到旧参数成员）。上游 `newTarget && this.isServerDirty(newTarget, newConfig)`。
        if let Some(t) = new_target {
            if is_server_dirty(t, new, deps) {
                return false;
            }
        }
        // 旧成员 tag（供精准断连 pair）：旧目标节点 tag，无旧目标（跟全局）→ proxy-selector。
        // 必须从 oldTarget 现算，禁用 currentRuleTargetMap.memberTag（那是生成时 default，首次规则热切后即陈旧）。
        let old_member_tag: String = match old_target {
            Some(t) => id_to_tag
                .get(t)
                .cloned()
                .unwrap_or_else(|| PROXY_SELECTOR_TAG.to_string()),
            None => PROXY_SELECTOR_TAG.to_string(),
        };
        puts.push(HotSwitchPut {
            selector_tag: entry.selector_tag.clone(),
            member_tag, // 上游 `memberTag || 'proxy-selector'`（此处已非空，等价）
            old_member_tag: Some(old_member_tag),
        });
        true
    };

    // 一等 trafficRules（缺省兼容 policyRules/customRules）：按 id 配对。仅 enabled + 有流量效果。
    let old_rules_by_id: BTreeMap<&str, &_> = old
        .effective_traffic_rules()
        .iter()
        .filter(|r| r.enabled && r.route_action().is_some())
        .map(|r| (r.id.as_str(), r))
        .collect();
    for r in new.effective_traffic_rules() {
        if !r.enabled || r.route_action().is_none() {
            continue;
        }
        let old_r = match old_rules_by_id.get(r.id.as_str()) {
            None => continue,
            Some(o) => *o,
        };
        let rule_key = format!("custom:{}", r.id);
        if !visit(
            &rule_key,
            old_r.route_target_server_id(),
            r.route_target_server_id(),
            &mut puts,
        ) {
            return RuleHotSwitchResult::CannotHotSwitch;
        }
    }

    // appRules：按 appId 配对（无 enabled 过滤——Polaris appRules 全量投影，但 visit 仍按 appId 配对）。
    // 注：Polaris planRuleHotSwitch 的 appRules 分支 `filter((a) => a.enabled)`，与 customRules 一致。
    let old_apps_by_app_id: BTreeMap<&str, &_> = old
        .app_rules
        .iter()
        .filter(|a| a.enabled)
        .map(|a| (a.app_id.as_str(), a))
        .collect();
    for a in &new.app_rules {
        if !a.enabled {
            continue;
        }
        let old_a = match old_apps_by_app_id.get(a.app_id.as_str()) {
            None => continue,
            Some(o) => *o,
        };
        let rule_key = format!("app:{}", a.app_id);
        if !visit(
            &rule_key,
            old_a.target_server_id.as_deref(),
            a.target_server_id.as_deref(),
            &mut puts,
        ) {
            return RuleHotSwitchResult::CannotHotSwitch;
        }
    }

    RuleHotSwitchResult::Puts(puts)
}

// ============================================================================
// canSkipRestartForAddedUnreferenced（Polaris L2327-2350）
// ============================================================================

/// 判 `next` 相对 `old` 是否「仅变更了不影响活流量的节点」——是则免整核重启（defer）。
/// 覆盖：新增未引用节点（P2-A，订阅刷新）+ 编辑/删除未引用节点（P2-B）。
///
/// 非对称安全模型：未引用节点（非选中/非规则目标/非 endpoint/不在 detour 链）仅作 selector 惰性成员、
/// 不承载流量，增/改/删对运行核行为无影响 → 可 defer；被引用节点改/删 → 运行核残留陈旧条目或用旧参数承载流量 → 必须重启。
///
/// 全部满足才放行（缺一即重启）：
/// ① selectedServerId 未变；② 非 servers 生成字段全等（混入 DNS/mode 变更即重启=正交守卫）；
/// ③ 所有被引用（refOld∪refNext）旧节点原样保留（无删除、无改动）；④ 新增节点全部未被引用。
///
/// 上游 `ProxyManager.canSkipRestartForAddedUnreferenced`。
pub fn can_skip_restart_for_added_unreferenced(
    old: &UserConfig,
    next: &UserConfig,
    running_servers_fingerprint: &BTreeMap<String, String>,
) -> bool {
    can_skip_restart_for_added_unreferenced_impl(old, next, Some(running_servers_fingerprint))
}

/// canSkipRestart 的内部实现：running_servers_fingerprint 参数化以便单测注入 None（核未起）。
/// 公开签名恒传 Some（调用方保证核起）；Polaris 走 this.runningServersFingerprint（私有同源）。
fn can_skip_restart_for_added_unreferenced_impl(
    old: &UserConfig,
    next: &UserConfig,
    _running_servers_fingerprint: Option<&BTreeMap<String, String>>,
) -> bool {
    // ① selectedServerId 未变。
    if old.selected_server_id != next.selected_server_id {
        return false;
    }
    // ② 非 servers 字段逐字节一致（servers 投影到空 → 仅比对路由/规则/DNS/端口/模式 等非节点字段；
    //   混入 DNS/mode 变更即重启=正交守卫，节点 defer 绝不吞其它字段的重启）。
    let empty: BTreeSet<String> = BTreeSet::new();
    if config_generation_norm(old, Some(&empty)) != config_generation_norm(next, Some(&empty)) {
        return false;
    }
    let old_by_id: BTreeMap<&str, &ServerConfig> =
        old.servers.iter().map(|s| (s.id.as_str(), s)).collect();
    let new_by_id: BTreeMap<&str, &ServerConfig> =
        next.servers.iter().map(|s| (s.id.as_str(), s)).collect();
    let ref_old = referenced_server_ids(old);
    let ref_next = referenced_server_ids(next);
    // ③ P2-B：被引用（旧或新）的旧节点必须原样保留——删/改被引用节点影响活流量→重启；
    //   未引用旧节点的删/改放行（defer）。
    for s in &old.servers {
        if !ref_old.contains(&s.id) && !ref_next.contains(&s.id) {
            continue; // 未引用 → 删/改放行
        }
        let n = match new_by_id.get(s.id.as_str()) {
            None => return false, // 被引用节点被删 → 重启
            Some(n) => *n,
        };
        if server_fingerprint(n) != server_fingerprint(s) {
            return false; // 被引用节点参数变 → 重启
        }
    }
    // ④ 新增节点全部未被引用。
    for s in &next.servers {
        if !old_by_id.contains_key(s.id.as_str()) && ref_next.contains(&s.id) {
            return false; // 新增且被引用 → 重启
        }
    }
    true
}

// ============================================================================
// isServerDirty（Polaris L2308-2315）
// ============================================================================

/// 节点是否 dirty：config 里的参数 ≠ 运行核快照（= 已编辑未生效）。
///
/// planHotSwitch 禁热切到 dirty 节点——否则 PUT 到运行核里的旧参数成员、流量走旧参数且不自愈
/// （§2 P2-B 唯一新增风险的堵法）。不在快照（新增未入核）返 false——那由 planHotSwitch
/// 「目标不在运行 selector」既有判据挡（退回重启）。
///
/// 上游 `ProxyManager.isServerDirty`（this.runningServersFingerprint 经 deps 注入）。
pub fn is_server_dirty(id: &str, config: &UserConfig, deps: &HotSwitchDeps) -> bool {
    let snap = match &deps.running_servers_fingerprint {
        None => return false, // 核未起 → 非 dirty
        Some(s) => s,
    };
    let fp = match snap.get(id) {
        None => return false, // 不在快照（新增未入核）→ false（由「目标不在 selector」判据挡）
        Some(f) => f,
    };
    let s = match config.servers.iter().find(|x| x.id == id) {
        Some(s) => s,
        None => return false,
    };
    fp != &server_fingerprint(s)
}

// ============================================================================
// resolveGlobalExitTag（Polaris shared/direct-selection.ts L22-28）
// ============================================================================

/// 全局出口的 proxy-selector 成员 tag（单一真值，收口「selectedServerId → memberTag」）：
/// 直连哨兵 → 'direct'，否则查 idToTagMap 得节点 tag。未知节点返回 None，由调用方按场景兜底
/// （planHotSwitch → 退回重启）。
///
/// 上游 `resolveGlobalExitTag`（shared/direct-selection.ts）。
pub fn resolve_global_exit_tag(
    selected_server_id: Option<&str>,
    id_to_tag_map: Option<&BTreeMap<String, String>>,
) -> Option<String> {
    if is_direct_selection(selected_server_id) {
        return Some(DIRECT_TAG.to_string());
    }
    // 阻断**没有对应的成员 tag**（2026-08-13 起它由规则级 reject 表达，不再是一个出站）⇒ 返回 None。
    // 调用方两处的退化方向都正确：目标侧 None ⇒ 整核重启；旧出口侧 None ⇒ 跳过那一对精准断连
    // （宁可漏关不误杀），而进出阻断本来就走重启，不依赖精准断连。
    if is_block_selection(selected_server_id) {
        return None;
    }
    let id = selected_server_id?;
    let map = id_to_tag_map?;
    map.get(id).cloned()
}

// ============================================================================
// 测试（移植 Polaris proxy-manager-{platform,norm,p2a}-hotswitch.test.ts 的纯逻辑子集）
// ============================================================================

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests;
