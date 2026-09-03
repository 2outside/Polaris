//! 选择性备份 / 恢复的类别模型 + 纯函数（零副作用、零 IO）。
//!
//! Polaris 锚点：`shared/backup-categories.ts`(246) + `main/ipc/handlers/backup-handlers.ts` 的纯逻辑部分
//! （`parseBackupContent` / `sanitizeCrossPlatformRules` / `buildBackupInfo`）。
//!
//! 8 类（前 7 类对应「数据备份与恢复」卡的统计维度，第 8 类是通用设置）：
//!   manualNodes     手动节点   —— servers（无 subscriptionId、非 endpoint 协议）
//!   meshNodes       组网节点   —— servers（无 subscriptionId、endpoint 协议，如 Tailscale/WireGuard）
//!   subscriptions   订阅源     —— subscriptions[] + 其展开节点（servers 有 subscriptionId）；两者一体进出
//!   customRules     流量规则   —— trafficRules[] + routeRuleOrder（兼容镜像 policyRules/customRules）
//!   dnsRules        DNS 规则   —— dnsRules[] + dnsRuleOrder（自动闭包 DNS 资源）
//!   dnsResources    DNS 资源   —— dnsServers[] + dnsServerGroups[] + dnsDefaults
//!   appRules        应用分流   —— appRules[]（+ appRulesSeeded / customAppPresets 同族）
//!   generalSettings 通用设置   —— 其余所有 config 字段，用**排除法**（自动涵盖未来新增设置）
//!
//! 导出 [`pick_categories`]：只抽选中类的字段。
//! 导入 [`merge_categories`]：选中类**整类替换** current，未选类保留；**空跳过**（选了但备份该类为空 →
//! 不用空覆盖、保留 current、记 skipped），防误删。
//!
//! ## 为什么在 `Value` 上做而不是强类型 `UserConfig`
//!
//! `generalSettings` 的定义是**排除法**（「不在 DATA_FIELDS / EXCLUDED_FROM_BACKUP 里的其余所有键」），
//! 其价值正是「自动涵盖未来新增设置」。强类型 struct 需逐字段列举 → 新增字段必漏，把排除法退化成白名单。
//! 且本 crate 的 [`crate::store::ConfigStore`] 全链路（load/sanitize/migrate/save）本就以 `Value` 为载体。
//!
//! ## 单一真值
//!
//! 前端 `ui/src/shared/backup-categories.ts` 只保留 `BackupCategory` 类型 + `BACKUP_CATEGORIES` 有序清单
//! （跨语言边界的枚举对应物，UI 勾选列表 + IPC 类型用）；分类/计数/合并**逻辑只此一份**，前端经
//! `backup:importPick` 拿后端算好的 available/counts，不在渲染端重算 → 结构上不存在漂移面。
//! 顺序不变式由 `tests::backup_categories_order_matches_frontend` 锁住。

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use polaris_config_engine::user_config::dns_constants::is_sentinel_selection;
use polaris_config_engine::user_config::server_config::{is_mesh_protocol, Protocol};

/// 备份类别（上游 `BackupCategory`）。序列化形 = 前端字符串（camelCase）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BackupCategory {
    ManualNodes,
    MeshNodes,
    Subscriptions,
    CustomRules,
    DnsRules,
    DnsResources,
    AppRules,
    GeneralSettings,
}

/// 有序类别清单（UI 展示顺序 + 全选基准）。上游 `BACKUP_CATEGORIES`。
///
/// **顺序是契约**：`detect_categories` 按此序返回，前端 `SettingsBackup.tsx` 按同序渲染勾选行。
pub const BACKUP_CATEGORIES: [BackupCategory; 8] = [
    BackupCategory::ManualNodes,
    BackupCategory::MeshNodes,
    BackupCategory::Subscriptions,
    BackupCategory::CustomRules,
    BackupCategory::DnsRules,
    BackupCategory::DnsResources,
    BackupCategory::AppRules,
    BackupCategory::GeneralSettings,
];

impl BackupCategory {
    /// 前端字符串形（IPC 传输值）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ManualNodes => "manualNodes",
            Self::MeshNodes => "meshNodes",
            Self::Subscriptions => "subscriptions",
            Self::CustomRules => "customRules",
            Self::DnsRules => "dnsRules",
            Self::DnsResources => "dnsResources",
            Self::AppRules => "appRules",
            Self::GeneralSettings => "generalSettings",
        }
    }

    /// 从前端字符串解析。未知值 → `None`（调用方按「忽略未知类」处理，不 throw）。
    ///
    /// 刻意不叫 `from_str`/不实现 `FromStr`：那是「可失败的通用解析」语义（返回 `Result`），
    /// 而本函数是 IPC 线格式的窄映射，未知值属**正常输入**（前端版本漂移）非错误 → `Option` 更贴切。
    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        BACKUP_CATEGORIES.into_iter().find(|c| c.as_str() == s)
    }
}

impl serde::Serialize for BackupCategory {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(self.as_str())
    }
}

/// 节点类（manualNodes / meshNodes / subscriptions 三选一）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeCategory {
    Manual,
    Mesh,
    Subscription,
}

impl NodeCategory {
    const fn as_backup(self) -> BackupCategory {
        match self {
            Self::Manual => BackupCategory::ManualNodes,
            Self::Mesh => BackupCategory::MeshNodes,
            Self::Subscription => BackupCategory::Subscriptions,
        }
    }
}

/// 不属于 generalSettings 的「数据字段」（随各自类别走，不进通用设置）。generalSettings = config 其余键。
///
/// - `customRuleSets` / `ruleResources` 是两类规则共享的匹配资源（ruleSet 规则按 `res:<id>`
///   引用它们）；`customAppPresets` 随应用分流类（`appRule.appId` 引用它）。
/// - `selectedServerId` 跟节点走、不随通用设置导入；导入节点后若失效，[`merge_categories`] 末尾主动归零
///   （[`crate::validate::validate_config`] 对失效 selectedServerId 是 **Err、非归零**，不兜底会令整份导入失败）。
const DATA_FIELDS: [&str; 19] = [
    "servers",
    "subscriptions",
    "customRules",
    "policyRules",
    "trafficRules",
    "dnsRules",
    "routeRuleOrder",
    "dnsRuleOrder",
    "customRuleSets",
    "ruleResources",
    "dnsServers",
    "dnsServerGroups",
    "dnsDefaults",
    "routeDefaults",
    "configSchemaVersion",
    "appRules",
    "appRulesSeeded",
    "customAppPresets",
    "selectedServerId",
];

/// 敏感 / 临时态字段：既不进任何类别、也不进通用设置（**绝不写入备份文件**）。
///
/// 与诊断脱敏（`polaris_stats_engine::redact`）是两条独立防线，覆盖面刻意不同：备份文件是「跨机搬运」，
/// clashApiSecret / privacyPassword 是本机凭据，不该跨机；诊断报告是「贴公开 issue」，那边打码即可。
/// 曾有第七项 `diagnosticCapture`（临时诊断态）。整条机制已删除，且旧配置里的残留在 `load` 的
/// 迁移链里就被 [`crate::migrate::migrate_diagnostic_capture`] 清掉 ⇒ 走到备份这一层时该键已不存在，
/// 再留一个排除位就是为一个不可能出现的键守门。**旧备份文件里带着它也无妨**：导入侧同样过迁移链。
const EXCLUDED_FROM_BACKUP: [&str; 5] = [
    "clashApiSecret",      // clash_api 明文密钥，不跨机
    "privacyPassword",     // 隐私解锁密码（legacy 明文残留），绝不入备份
    "privacyPasswordHash", // 隐私解锁密码 salted hash，本机凭据，绝不入备份
    "builtinGeoMeta",      // 内置 geo 元数据（随包，无需备份）
    // 托盘「节点·最近」MRU：**本机使用痕迹**，跨机无意义（外机 id 在本机多半解析不出节点，
    // 白占 3 个槽位之一）；且它是「后端权威」字段（前端零写入权，见 `commands/config.rs`
    // 的 `BACKEND_AUTHORITATIVE_KEYS`），不该经备份这条前端全量提交路径被改写。
    "recentServerIds",
];

/// 是否通用设置键（排除法）。上游 `isGeneralKey`。
fn is_general_key(key: &str) -> bool {
    !DATA_FIELDS.contains(&key) && !EXCLUDED_FROM_BACKUP.contains(&key)
}

/// JS 真值语义：`if (s.subscriptionId)` —— null/undefined/"" 皆为假。
fn truthy_str(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::String(s)) if !s.is_empty())
}

/// 取数组长度（非数组/缺省 → 0）。对齐 TS `config.x?.length ?? 0`。
fn arr_len(config: &Value, key: &str) -> usize {
    config
        .get(key)
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

fn traffic_rule_len(config: &Value) -> usize {
    if config.get("trafficRules").is_some_and(Value::is_array) {
        arr_len(config, "trafficRules")
    } else if config.get("policyRules").is_some_and(Value::is_array) {
        arr_len(config, "policyRules")
    } else {
        arr_len(config, "customRules")
    }
}

fn dns_rule_len(config: &Value) -> usize {
    arr_len(config, "dnsRules")
}

fn has_dns_resources(config: &Value) -> bool {
    arr_len(config, "dnsServers") > 0
        || arr_len(config, "dnsServerGroups") > 0
        || config.get("dnsDefaults").is_some_and(Value::is_object)
}

/// config.servers 视图（非数组/缺省 → 空）。对齐 TS `config.servers ?? []`。
fn servers(config: &Value) -> &[Value] {
    config
        .get("servers")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
}

/// 单个 server 归到哪个节点类（订阅节点 > 组网节点 > 手动节点）。上游 `classifyServer`。
///
/// 协议解析失败（未知/缺失/非串）→ 非组网（对齐 TS `isMeshProtocol(undefined)` = false），
/// 即归手动节点：**宁可把坏节点算进手动类也不丢**（备份类别是搬运分桶，不是校验门）。
///
/// 判据与前端的组网页签同源（`is_mesh_node` 的节点级口径）：openconnect / openvpn-client 只在用户
/// 声明了 `meshRoutes` 时才算组网。这里直接读 JSON 而不反序列化整个 `ServerConfig` —— 备份搬的是
/// 用户磁盘上的原始 config，其中可能有本仓当前建模不了的字段，整体反序列化失败就会把整个节点丢掉。
fn classify_server(server: &Value) -> NodeCategory {
    if truthy_str(server.get("subscriptionId")) {
        return NodeCategory::Subscription;
    }
    let proto = server
        .get("protocol")
        .and_then(Value::as_str)
        .and_then(|p| serde_json::from_value::<Protocol>(Value::String(p.to_string())).ok());
    let declares_mesh_routes = || {
        server
            .get("meshRoutes")
            .and_then(Value::as_array)
            .is_some_and(|a| {
                a.iter()
                    .any(|c| c.as_str().is_some_and(|s| !s.trim().is_empty()))
            })
    };
    let is_mesh = proto.is_some_and(|p| {
        is_mesh_protocol(p)
            || (matches!(p, Protocol::Openconnect | Protocol::OpenvpnClient)
                && declares_mesh_routes())
    });
    if is_mesh {
        NodeCategory::Mesh
    } else {
        NodeCategory::Manual
    }
}

/// 某 config 是否含通用设置字段（排除法：存在任一非数据键）。上游 `hasGeneralSettings`。
fn has_general_settings(config: &Value) -> bool {
    config
        .as_object()
        .is_some_and(|m| m.keys().any(|k| is_general_key(k)))
}

/// 某类在 config 中的数量。上游 `countCategory`。
///
/// generalSettings 恒计 1 = 整组；订阅源计**订阅源数**（节点随源不单列）。
#[must_use]
pub fn count_category(config: &Value, cat: BackupCategory) -> usize {
    match cat {
        BackupCategory::ManualNodes => count_nodes(config, NodeCategory::Manual),
        BackupCategory::MeshNodes => count_nodes(config, NodeCategory::Mesh),
        BackupCategory::Subscriptions => arr_len(config, "subscriptions"),
        BackupCategory::CustomRules => traffic_rule_len(config) + arr_len(config, "customRuleSets"),
        BackupCategory::DnsRules => dns_rule_len(config),
        BackupCategory::DnsResources => {
            let resources = arr_len(config, "dnsServers") + arr_len(config, "dnsServerGroups");
            if resources == 0 && config.get("dnsDefaults").is_some_and(Value::is_object) {
                1
            } else {
                resources
            }
        }
        BackupCategory::AppRules => arr_len(config, "appRules"),
        BackupCategory::GeneralSettings => usize::from(has_general_settings(config)),
    }
}

fn count_nodes(config: &Value, cat: NodeCategory) -> usize {
    servers(config)
        .iter()
        .filter(|s| classify_server(s) == cat)
        .count()
}

/// config / 备份里「有数据」的类（导入时只列这些供勾选）。上游 `detectCategories`。
///
/// subscriptions 特判：**订阅源为空但存在展开节点**（离线备份/订阅已删而节点还在）也算有数据 —— 否则
/// 那些节点会因「该类不可勾选」而永远导不回来。
#[must_use]
pub fn detect_categories(config: &Value) -> Vec<BackupCategory> {
    BACKUP_CATEGORIES
        .into_iter()
        .filter(|&cat| {
            if cat == BackupCategory::Subscriptions {
                return arr_len(config, "subscriptions") > 0
                    || servers(config)
                        .iter()
                        .any(|s| classify_server(s) == NodeCategory::Subscription);
            }
            count_category(config, cat) > 0
        })
        .collect()
}

/// 导出：从完整 config 抽出选中类的字段（其余字段不进备份）。上游 `pickCategories`。
#[must_use]
pub fn pick_categories(config: &Value, selected: &[BackupCategory]) -> Value {
    // DNS 规则可引用 DNS Server / Group；导出时后端强制带上依赖，不能只靠 UI 联动。
    let sel = |c: BackupCategory| {
        selected.contains(&c)
            || (c == BackupCategory::DnsResources && selected.contains(&BackupCategory::DnsRules))
    };
    let mut out = Map::new();

    // 三个节点类共用 servers[]：任一被选 → 发射 servers，内容 = 被选类的节点并集。
    let picked_node_cats: Vec<NodeCategory> = [
        NodeCategory::Manual,
        NodeCategory::Mesh,
        NodeCategory::Subscription,
    ]
    .into_iter()
    .filter(|c| sel(c.as_backup()))
    .collect();
    if !picked_node_cats.is_empty() {
        let picked: Vec<Value> = servers(config)
            .iter()
            .filter(|s| picked_node_cats.contains(&classify_server(s)))
            .cloned()
            .collect();
        out.insert("servers".into(), Value::Array(picked));
    }

    if sel(BackupCategory::Subscriptions) {
        if let Some(v) = config.get("subscriptions") {
            out.insert("subscriptions".into(), v.clone());
        }
    }
    if sel(BackupCategory::CustomRules) {
        let policies = config
            .get("trafficRules")
            .filter(|value| value.is_array())
            .or_else(|| config.get("policyRules").filter(|value| value.is_array()))
            .or_else(|| config.get("customRules").filter(|value| value.is_array()));
        if let Some(v) = policies {
            out.insert("trafficRules".into(), v.clone());
            out.insert("policyRules".into(), v.clone());
            out.insert("customRules".into(), v.clone());
        }
        out.insert(
            "routeRuleOrder".into(),
            arr_or_empty(config, "routeRuleOrder"),
        );
    }
    if sel(BackupCategory::DnsRules) {
        out.insert("dnsRules".into(), arr_or_empty(config, "dnsRules"));
        out.insert("dnsRuleOrder".into(), arr_or_empty(config, "dnsRuleOrder"));
    }
    if sel(BackupCategory::CustomRules) || sel(BackupCategory::DnsRules) {
        out.insert(
            "customRuleSets".into(),
            config
                .get("customRuleSets")
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new())),
        );
        if truthy(config.get("ruleResources")) {
            out.insert("ruleResources".into(), config["ruleResources"].clone());
        }
    }
    if sel(BackupCategory::DnsResources) {
        out.insert("dnsServers".into(), arr_or_empty(config, "dnsServers"));
        out.insert(
            "dnsServerGroups".into(),
            arr_or_empty(config, "dnsServerGroups"),
        );
        if let Some(v) = config.get("dnsDefaults").filter(|value| value.is_object()) {
            out.insert("dnsDefaults".into(), v.clone());
        }
    }
    if sel(BackupCategory::CustomRules)
        || sel(BackupCategory::DnsRules)
        || sel(BackupCategory::DnsResources)
    {
        out.insert(
            "configSchemaVersion".into(),
            config
                .get("configSchemaVersion")
                .cloned()
                .unwrap_or_else(|| Value::from(3)),
        );
    }
    if sel(BackupCategory::AppRules) {
        if truthy(config.get("appRules")) {
            out.insert("appRules".into(), config["appRules"].clone());
        }
        if let Some(v) = config.get("appRulesSeeded") {
            out.insert("appRulesSeeded".into(), v.clone());
        }
        if truthy(config.get("customAppPresets")) {
            out.insert(
                "customAppPresets".into(),
                config["customAppPresets"].clone(),
            );
        }
    }
    if sel(BackupCategory::GeneralSettings) {
        if let Some(m) = config.as_object() {
            for (k, v) in m {
                if is_general_key(k) {
                    out.insert(k.clone(), v.clone());
                }
            }
        }
    }
    Value::Object(out)
}

/// JS 真值语义（对象/非空数组/非空串/非零数 → 真；null/undefined/false/0/"" → 假）。
/// 用在 TS 写 `if (config.x)` 的位置；`[]` 在 JS 里是**真值**，故空数组 → 真。
fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(_) => true, // 对象 / 数组（含 []）在 JS 里恒真
    }
}

/// [`merge_categories`] 的结果。
#[derive(Debug, Clone)]
pub struct MergeOutcome {
    /// 合并后的新 config。
    pub config: Value,
    /// 选了但备份该类为空、被跳过的类（供 UI 提示）。
    pub skipped: Vec<BackupCategory>,
}

/// 把 1.0/1.1/裸配置的共享规则临时提升为当前独立集合，供选择性导入读取。
///
/// 只在内存副本上跑；DNS 资源是否导入仍以原备份是否显式携带该类别为准，避免旧“仅规则”备份
/// 生成的默认服务器覆盖本机已有资源。
fn normalize_policy_backup(backup: &Value) -> Value {
    let mut normalized = backup.clone();
    // 选择性 v3 备份只携带被选中的平面；任一显式集合存在就已经是独立模型，不能再用
    // 缺失的共享 policyRules 反向拆分，否则 DNS-only 备份会被空集合覆盖。
    if normalized.get("trafficRules").is_some_and(Value::is_array)
        || normalized.get("dnsRules").is_some_and(Value::is_array)
    {
        crate::migrate::migrate_dns_connection_ownership(&mut normalized);
        return normalized;
    }
    if !normalized.get("policyRules").is_some_and(Value::is_array) {
        crate::migrate::migrate_dns_policy_v2(&mut normalized);
    }
    crate::migrate::migrate_split_policy_rules(&mut normalized);
    crate::migrate::migrate_dns_connection_ownership(&mut normalized);
    normalized
}

/// 导入：把 backup 的选中类合并进 current（**整类替换 + 空跳过**），未选类保留 current。
/// 上游 `mergeCategories`。
///
/// 空跳过是防误删的红线：用户勾了「手动节点」但备份里一个手动节点都没有 → 保留 current 的手动节点、
/// 记 skipped，**绝不用空数组覆盖**。
#[must_use]
pub fn merge_categories(
    current: &Value,
    backup: &Value,
    selected: &[BackupCategory],
) -> MergeOutcome {
    let sel = |c: BackupCategory| selected.contains(&c);
    let mut skipped: Vec<BackupCategory> = Vec::new();
    let mut result = current.clone();
    if !result.is_object() {
        result = Value::Object(Map::new());
    }

    let cur_servers = servers(current).to_vec();
    let bak_servers = servers(backup).to_vec();
    let mut new_servers: Vec<Value> = Vec::new();

    let take = |src: &[Value], cat: NodeCategory| -> Vec<Value> {
        src.iter()
            .filter(|s| classify_server(s) == cat)
            .cloned()
            .collect()
    };

    // manualNodes / meshNodes：各自整类替换 / 空跳过 / 未选保留
    for cat in [NodeCategory::Manual, NodeCategory::Mesh] {
        let cur_nodes = take(&cur_servers, cat);
        let bak_nodes = take(&bak_servers, cat);
        if !sel(cat.as_backup()) {
            new_servers.extend(cur_nodes); // 未选：保留
        } else if !bak_nodes.is_empty() {
            new_servers.extend(bak_nodes); // 替换
        } else {
            new_servers.extend(cur_nodes); // 空跳过：保留 current
            skipped.push(cat.as_backup());
        }
    }

    // subscriptions：订阅源字段 + 订阅节点一体处理（离线也能恢复）
    let cur_sub_nodes = take(&cur_servers, NodeCategory::Subscription);
    let bak_sub_nodes = take(&bak_servers, NodeCategory::Subscription);
    if sel(BackupCategory::Subscriptions) {
        let has_data = arr_len(backup, "subscriptions") > 0 || !bak_sub_nodes.is_empty();
        if has_data {
            new_servers.extend(bak_sub_nodes);
            let subs = backup
                .get("subscriptions")
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new()));
            set(&mut result, "subscriptions", subs);
        } else {
            new_servers.extend(cur_sub_nodes); // 空跳过：保留
            skipped.push(BackupCategory::Subscriptions);
        }
    } else {
        new_servers.extend(cur_sub_nodes); // 未选：保留订阅节点 + result.subscriptions 已 = current
    }
    set(&mut result, "servers", Value::Array(new_servers));

    // 流量规则独立整类替换；旧字段同步为回滚兼容镜像。
    if sel(BackupCategory::CustomRules) {
        let normalized = normalize_policy_backup(backup);
        let has_data = traffic_rule_len(&normalized) > 0 || arr_len(backup, "customRuleSets") > 0;
        if has_data {
            let policies = arr_or_empty(&normalized, "trafficRules");
            set(&mut result, "trafficRules", policies.clone());
            set(&mut result, "policyRules", policies.clone());
            set(&mut result, "customRules", policies);
            set(
                &mut result,
                "routeRuleOrder",
                arr_or_empty(&normalized, "routeRuleOrder"),
            );
        } else {
            skipped.push(BackupCategory::CustomRules);
        }
    }

    // 自定义规则集与下载资源是两个规则平面共享的匹配依赖。流量规则保持旧导入语义
    // （字段缺失按空数组处理）；DNS-only 导入只在备份显式携带时替换，避免旧备份误清空。
    if sel(BackupCategory::CustomRules) {
        set(
            &mut result,
            "customRuleSets",
            arr_or_empty(backup, "customRuleSets"),
        );
        set(
            &mut result,
            "ruleResources",
            arr_or_empty(backup, "ruleResources"),
        );
    } else if sel(BackupCategory::DnsRules) {
        if backup.get("customRuleSets").is_some_and(Value::is_array) {
            set(
                &mut result,
                "customRuleSets",
                arr_or_empty(backup, "customRuleSets"),
            );
        }
        if backup.get("ruleResources").is_some_and(Value::is_array) {
            set(
                &mut result,
                "ruleResources",
                arr_or_empty(backup, "ruleResources"),
            );
        }
    }

    // DNS 规则拥有独立生命周期；旧共享备份先在内存中拆分再导入。
    if sel(BackupCategory::DnsRules) {
        let normalized = normalize_policy_backup(backup);
        if dns_rule_len(&normalized) > 0 {
            set(
                &mut result,
                "dnsRules",
                arr_or_empty(&normalized, "dnsRules"),
            );
            set(
                &mut result,
                "dnsRuleOrder",
                arr_or_empty(&normalized, "dnsRuleOrder"),
            );
        } else {
            skipped.push(BackupCategory::DnsRules);
        }
    }

    // DNS Server / Group / 默认解析策略独立成类；策略规则选中且备份显式带资源时自动闭包导入。
    let dns_selected = sel(BackupCategory::DnsResources)
        || (sel(BackupCategory::DnsRules) && has_dns_resources(backup));
    if dns_selected {
        if has_dns_resources(backup) {
            set(
                &mut result,
                "dnsServers",
                arr_or_empty(backup, "dnsServers"),
            );
            set(
                &mut result,
                "dnsServerGroups",
                arr_or_empty(backup, "dnsServerGroups"),
            );
            if let Some(v) = backup.get("dnsDefaults").filter(|value| value.is_object()) {
                set(&mut result, "dnsDefaults", v.clone());
            }
        } else {
            skipped.push(BackupCategory::DnsResources);
        }
    }

    // appRules（+ appRulesSeeded / customAppPresets 同族）
    if sel(BackupCategory::AppRules) {
        if arr_len(backup, "appRules") > 0 {
            set(&mut result, "appRules", backup["appRules"].clone());
            if let Some(v) = backup.get("appRulesSeeded") {
                set(&mut result, "appRulesSeeded", v.clone());
            }
            set(
                &mut result,
                "customAppPresets",
                arr_or_empty(backup, "customAppPresets"),
            );
        } else {
            skipped.push(BackupCategory::AppRules);
        }
    }

    // generalSettings：排除法覆盖所有非数据键
    if sel(BackupCategory::GeneralSettings) {
        let mut applied = false;
        if let Some(m) = backup.as_object() {
            let pairs: Vec<(String, Value)> = m
                .iter()
                .filter(|(k, _)| is_general_key(k))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            for (k, v) in pairs {
                set(&mut result, &k, v);
                applied = true;
            }
        }
        if !applied {
            skipped.push(BackupCategory::GeneralSettings);
        }
    }

    // 导入节点类后选中节点可能已不在新 servers → 主动归零（validate_config 对失效 selectedServerId 是 Err、
    // 非归零，不兜底会令整份导入失败）。null 与 direct/block 哨兵不动 —— 哨兵压根不是节点 id，
    // 拿它去 servers 里找必然找不到，归零会把用户选的「直连 / 阻断」出口在导入备份时静默改掉。
    let selected_id = result
        .get("selectedServerId")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(id) = selected_id {
        let still_exists = servers(&result)
            .iter()
            .any(|s| s.get("id").and_then(Value::as_str) == Some(id.as_str()));
        if !id.is_empty() && !is_sentinel_selection(Some(&id)) && !still_exists {
            set(&mut result, "selectedServerId", Value::Null);
        }
    }

    MergeOutcome {
        config: result,
        skipped,
    }
}

fn set(target: &mut Value, key: &str, value: Value) {
    if let Some(m) = target.as_object_mut() {
        m.insert(key.to_string(), value);
    }
}

fn arr_or_empty(src: &Value, key: &str) -> Value {
    match src.get(key) {
        Some(v @ Value::Array(_)) => v.clone(),
        _ => Value::Array(Vec::new()),
    }
}

// ════════════════════════════════════════════════════════════════════════════
// 备份文件格式 + 跨平台 sanitize + 摘要（backup-handlers.ts 的纯逻辑部分）
// ════════════════════════════════════════════════════════════════════════════

/// 备份文件版本。1.2 增加独立 trafficRules/dnsRules 类；解析器继续兼容 1.0/1.1/裸配置。
pub const BACKUP_FILE_VERSION: &str = "1.2";

/// 解析结果：备份 config（Partial）+ 导出平台。
#[derive(Debug, Clone)]
pub struct ParsedBackup {
    /// 备份里的 config（选择性导出后可能只含部分类别字段）。
    pub config: Value,
    /// 导出平台（`process.platform` 口径：win32 / darwin / linux）。旧备份无此字段 → None = 视为同平台。
    pub platform: Option<String>,
}

/// 解析备份文件内容。上游 `parseBackupContent`。
///
/// 兼容新格式 `{version, config}` 与**旧版直接导出的裸 UserConfig**（以 `servers` 存在为标志）。
/// 错误码原样对齐 TS（`invalid_json` / `invalid_format`），前端按码出文案。
///
/// # Errors
/// 坏 JSON → `invalid_json`；既非新格式也非旧格式 → `invalid_format`。
pub fn parse_backup_content(raw: &str) -> Result<ParsedBackup, &'static str> {
    let parsed: Value = serde_json::from_str(raw).map_err(|_| "invalid_json")?;
    if truthy(parsed.get("version")) && truthy(parsed.get("config")) {
        return Ok(ParsedBackup {
            config: parsed["config"].clone(),
            platform: parsed
                .get("platform")
                .and_then(Value::as_str)
                .map(str::to_owned),
        });
    }
    if parsed.get("servers").is_some() {
        // 旧版直接导出的 UserConfig（TS 判据 `parsed.servers !== undefined`）
        return Ok(ParsedBackup {
            config: parsed,
            platform: None,
        });
    }
    Err("invalid_format")
}

/// 一条规则是否含进程匹配条件（processName / processPath）。上游 `ruleHasProcessCondition`。
///
/// 覆盖**首条件镜像**（`rule.type`）与**多条件**（`rule.conditions[].type`）两种承载。
fn rule_has_process_condition(rule: &Value) -> bool {
    let is_proc = |t: Option<&str>| matches!(t, Some("processName" | "processPath"));
    if is_proc(rule.get("type").and_then(Value::as_str)) {
        return true;
    }
    rule.get("conditions")
        .and_then(Value::as_array)
        .is_some_and(|cs| {
            cs.iter()
                .any(|c| is_proc(c.get("type").and_then(Value::as_str)))
        })
}

/// 跨平台 sanitize：进程规则（processName / processPath）平台特定（chrome.exe / Google Chrome / chrome），
/// 跨平台会静默失效 → **禁用而非移除**（`enabled=false`，保留供用户重映射）。上游 `sanitizeCrossPlatformRules`。
///
/// 就地改 v3 权威 `config.trafficRules`（缺省时回退旧 `policyRules/customRules`），并同步兼容镜像。
/// 返回被禁用条数。同平台 / 旧备份（无 platform）→ 0，不动。
pub fn sanitize_cross_platform_rules(
    config: &mut Value,
    backup_platform: Option<&str>,
    current_platform: &str,
) -> usize {
    let Some(bp) = backup_platform else { return 0 };
    if bp == current_platform {
        return 0;
    }
    let authoritative_key = if config.get("trafficRules").is_some_and(Value::is_array) {
        "trafficRules"
    } else if config.get("policyRules").is_some_and(Value::is_array) {
        "policyRules"
    } else {
        "customRules"
    };
    let Some(rules) = config
        .get_mut(authoritative_key)
        .and_then(Value::as_array_mut)
    else {
        return 0;
    };
    let mut n = 0;
    for rule in rules.iter_mut() {
        // TS `rule.enabled !== false`：缺省 / true 都算启用中。
        let enabled = rule.get("enabled") != Some(&Value::Bool(false));
        if enabled && rule_has_process_condition(rule) {
            if let Some(m) = rule.as_object_mut() {
                m.insert("enabled".into(), Value::Bool(false));
            }
            n += 1;
        }
    }
    if authoritative_key != "customRules" {
        let mirror = config.get(authoritative_key).cloned().unwrap_or_default();
        set(config, "trafficRules", mirror.clone());
        set(config, "policyRules", mirror.clone());
        set(config, "customRules", mirror);
    }
    n
}

/// 将备份里当前设备不存在的网卡绑定回退为「自动 / 继承」。
///
/// 该处理只覆盖本次实际导入（且未被空跳过）的类别，避免导入一类数据时改动本机其它类别：
/// - `generalSettings`：全局直连 / 代理默认网卡；
/// - `subscriptions`：订阅级代理网卡及订阅展开节点；
/// - `manualNodes` / `meshNodes`：对应节点自己的网卡覆盖。
///
/// `available_interfaces` 必须包含当前设备**所有已发现接口**（包括暂时 down 的接口）。接口只是 down
/// 不应在导入时丢失配置；运行期再由启动门禁阻止静默改走其它出口。调用方若枚举失败，应跳过本函数，
/// 不能把「枚举结果为空」误判成「所有绑定都失效」。返回被清除的绑定数量，供导入预览与完成提醒使用。
pub fn sanitize_unavailable_interface_bindings(
    config: &mut Value,
    available_interfaces: &BTreeSet<String>,
    categories: &[BackupCategory],
) -> usize {
    if available_interfaces.is_empty() {
        return 0;
    }

    fn clear_missing(
        object: &mut Map<String, Value>,
        key: &str,
        available: &BTreeSet<String>,
    ) -> usize {
        let missing = object
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .is_some_and(|name| !name.is_empty() && !available.contains(name));
        if missing {
            object.remove(key);
            1
        } else {
            0
        }
    }

    let selected = |category| categories.contains(&category);
    let mut cleared = 0;

    if selected(BackupCategory::GeneralSettings) {
        if let Some(defaults) = config
            .get_mut("networkInterfaces")
            .and_then(Value::as_object_mut)
        {
            cleared += clear_missing(defaults, "direct", available_interfaces);
            cleared += clear_missing(defaults, "proxy", available_interfaces);
            if defaults.is_empty() {
                if let Some(root) = config.as_object_mut() {
                    root.remove("networkInterfaces");
                }
            }
        }
    }

    if selected(BackupCategory::Subscriptions) {
        if let Some(subscriptions) = config
            .get_mut("subscriptions")
            .and_then(Value::as_array_mut)
        {
            for subscription in subscriptions {
                if let Some(object) = subscription.as_object_mut() {
                    cleared += clear_missing(object, "proxyBindInterface", available_interfaces);
                }
            }
        }
    }

    if let Some(nodes) = config.get_mut("servers").and_then(Value::as_array_mut) {
        for node in nodes {
            let category = classify_server(node).as_backup();
            if selected(category) {
                if let Some(object) = node.as_object_mut() {
                    cleared += clear_missing(object, "bindInterface", available_interfaces);
                }
            }
        }
    }

    cleared
}

/// 配置摘要（上游 `BackupInfo`，`ui/src/ipc/api-client.ts` 1:1 镜像）。
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupInfo {
    pub server_count: usize,
    pub manual_server_count: usize,
    pub mesh_server_count: usize,
    pub subscription_count: usize,
    pub rule_count: usize,
    pub rule_set_count: usize,
    pub app_rule_count: usize,
    /// 跨平台导入时被禁用的进程规则数。0 / 同平台 → 不发射（对齐 TS `|| undefined`）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_platform_disabled_rules: Option<usize>,
}

/// 构建摘要。上游 `buildBackupInfo`。
#[must_use]
pub fn build_backup_info(config: &Value, cross_platform_disabled_rules: usize) -> BackupInfo {
    BackupInfo {
        server_count: servers(config).len(),
        manual_server_count: count_nodes(config, NodeCategory::Manual),
        mesh_server_count: count_nodes(config, NodeCategory::Mesh),
        subscription_count: arr_len(config, "subscriptions"),
        rule_count: traffic_rule_len(config),
        rule_set_count: arr_len(config, "customRuleSets"),
        app_rule_count: arr_len(config, "appRules"),
        cross_platform_disabled_rules: (cross_platform_disabled_rules > 0)
            .then_some(cross_platform_disabled_rules),
    }
}

#[cfg(test)]
mod tests;
