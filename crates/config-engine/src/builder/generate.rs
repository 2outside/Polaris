//! generateSingBoxConfig 编排逻辑 —— 上游 `ProxyManager.generateSingBoxConfig`（L3470-3637）1:1 移植。
//!
//! 装配六 builder（log/dns/inbounds/outbounds/route）+ experimental.cache_file + 1.14 services
//! （management API / dashboard）。纯函数 + 依赖注入：Polaris 所有 `this.*` 实例态经 `GenerateConfigDeps`
//! 注入（raceServerPort / probe 端口 / lanResolverForDns / hasCronet / hasManagementApi / FS 路径 …）。
//!
//! 装配顺序（Polaris 时序严格保持）：
//!  1. withRaceOff：raceServerPort==0 → clone config 清 dnsConfig.resolveNodeDomainsAhead。
//!  2. selectedServer 校验：isDirect 跳过；naive 缺 libcronet → Err。
//!  3. buildOutbounds（先）→ 产 pendingEndpoints / pendingRuleSelectors（route/dns 消费）。
//!  4. buildLogConfig / buildDnsConfig / buildInbounds / buildRouteConfig（消费 pendingEndpoints）。
//!  5. 装配顶层 SingBoxConfig（log/dns/inbounds/outbounds/route/experimental.cache_file）。
//!  6. endpoints 注入顶层（pendingEndpoints 非空）。
//!  7. services 注入（has_management_api 门控：api service + 可选 dashboard）。
//!  8. fixRouteDeadReferences（route 死引用兜底）。

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use polaris_helper_proto::Platform;
use serde::Serialize;

use crate::builder::custom_rules::{resolve_resource_rule_set, CustomRulesDeps};
use crate::builder::dns::{build_dns_config, DnsConfigDeps};
use crate::builder::endpoint_routes::mesh_system_supported_on_platform;
use crate::builder::helpers::{build_id_to_tag_map, ServerLike};
use crate::builder::inbounds::{build_inbounds, InboundsDeps};
use crate::builder::log::{build_log_config, LogBuildDeps, LogConfigInput};
use crate::builder::orchestration::fix_route_dead_references;
use crate::builder::outbounds::OutboundsDeps;
use crate::builder::route::{
    add_local_geo_rule_set, build_route_config_with_report, RouteConfigDeps,
};
use crate::singbox::{
    ApiDashboard, ApiService, CacheFile, DnsConfig, DnsRule, Experimental, HttpClient, OneOrMany,
    RouteConfig, SingBoxConfig,
};
use crate::user_config::app_config::UserConfig;
use crate::user_config::dns_constants::is_sentinel_selection;
use crate::user_config::log_level::LogLevel;
use crate::user_config::proxy_mode::ProxyModeType;
use crate::user_config::server_config::Protocol;

/// cache_id 品牌归一化值（§D.2）：上游 用 上游的 dns cache_id，Polaris 改 'polaris-dns-v2'。
///
/// `store_dns` 把 DNS 应答持久化，bump 本值令旧条目不可达（逻辑清库）。
///
/// # 射程边界：**bump 它对 `store_fakeip` 无效**
///
/// 这里原本写的是「store_dns/store_fakeip 把投毒条目持久化，bump cache_id 令旧条目不可达」，
/// 从 上游 逐字继承（那边同样的话写在 `ProxyManager.ts` 的 cache_id bump 注释里）。**对 fakeip
/// 那半句不成立**：内核的 `experimental/cachefile/fakeip.go` 全程直操作 `fakeip_address` /
/// `fakeip_domain4` / `fakeip_domain6` 三个**顶层 bucket**，不经 `cacheID` 命名空间；`cache.go` 的
/// 前缀白名单还把它们从清理里豁免掉。⇒ 换 cache_id 清得掉 DNS 缓存，清不掉 FakeIP 的地址表与计数器。
///
/// 留这段是因为「换个 cache_id 就能把 FakeIP 投毒/错配洗掉」是个很自然、且**试了也不会报错**的
/// 猜想 —— 它只是静默无效。FakeIP 错配的实际缓解在 `builder::dns` 的 `FAKEIP_REWRITE_TTL`。
///
/// **已对随包内核亲验**（2026-08-10，此前标注的「未重新验证」可撤）：首次核于 v1.14.0-beta.7
/// （`3001f038`），抬核到 v1.14.0-beta.12（`426c5faf`）后复核 `experimental/cachefile/cache.go`
/// 在两版之间**逐字未变**，故下述行号与判据在随包核上继续成立。
/// `experimental/cachefile/cache.go:215` 的启动清理判据逐字是
/// `if !(common.Contains(bucketNameList, bucketName) || strings.HasPrefix(bucketName, fakeipBucketPrefix))`
/// —— fakeip 前缀被**显式豁免**，且 `bucketNameList` 本就不含它们。三个桶是顶层桶，不经 `cacheID`。
const CACHE_ID: &str = "polaris-dns-v2";

/// 上游 `ProxyManager.withRaceOff`：race off 时 clone config，强制 dnsConfig.resolveNodeDomainsAhead=false。
///
/// race server 未就绪（off/起失败/snapshot/preflight/诊断）→ getNodeResolverTag/buildDnsConfig 一致走
/// 单上游、不引用 dns-node-race（防 FATAL，快照零变化）。clone 后仅清该字段，其余 dns_config 原样保留。
fn with_race_off(config: &UserConfig) -> UserConfig {
    let mut cfg = config.clone();
    if let Some(dns) = cfg.dns_config.as_mut() {
        dns.resolve_node_domains_ahead = Some(false);
    } else {
        // 上游 `{ ...config.dnsConfig, resolveNodeDomainsAhead: false }`：dnsConfig 为 undefined 时
        // spread 空对象 → 结果 { resolveNodeDomainsAhead: false }。Rust 侧 Some(默认 + 该字段)。
        cfg.dns_config = Some(crate::user_config::dns_config::DnsConfig {
            resolve_node_domains_ahead: Some(false),
            ..Default::default()
        });
    }
    cfg
}

/// 选中节点不可用（naive 缺 libcronet）的用户可见原因。上游 `naiveUnavailableReason`。
///
/// 移植为纯函数：Polaris 读 resourceManager.getCronetLibStatus()（'copy-failed' 分支）+ process.platform。
/// 此处注入 has_cronet（恒 false 触发）+ platform + 可选 copy_failed 标志（对拍/生产可省）。
fn naive_unavailable_reason(server_name: &str, copy_failed: bool, platform: &str) -> String {
    if copy_failed {
        return format!(
            "选中的节点「{server_name}」是 NaiveProxy：libcronet 核心库已内置，但拷贝到核心目录失败\
             （可能是权限/磁盘空间/杀软占用）。请重启应用重试或检查目录权限；如仍失败，请改用其它协议的节点。"
        );
    }
    if platform.eq_ignore_ascii_case("darwin") {
        return format!(
            "选中的节点「{server_name}」是 NaiveProxy，但当前 macOS 核心未内置 cronet\
             （暂无官方预编译库）。请选择其它协议的节点。"
        );
    }
    format!(
        "选中的节点「{server_name}」是 NaiveProxy，但未找到 libcronet 核心库。请选择其它协议的节点。"
    )
}

/// 上游 `isNodeUsable`：naive 需要 libcronet，缺库不可用（其余恒可用）。
fn is_node_usable(
    server: &crate::user_config::server_config::ServerConfig,
    has_cronet: bool,
) -> bool {
    // !(naive && !has_cronet) ⟺ naive != Naive || has_cronet。
    server.protocol != Protocol::Naive || has_cronet
}

/// dashboard 的显式 HTTP client：`detour` 取 `route.final`。
///
/// **为什么是 `route.final`（而非 direct，也非顶层 `http_clients` + `route.default_http_client`）**：
///
/// 1. **等价性**：被替换掉的隐式回落在核里是 `DefaultOutbound = true`（`box.go` 的
///    `httpClientManager.Initialize` 回落工厂）→ `NewDefaultOutboundDetour(outboundManager)`
///    → `outboundManager.Default()`，而默认出站正是 `route.final` 指的那个 tag。写死 `direct`
///    会把 dashboard 的下载腿从「走代理」改成「走直连」——在 `dashboard_serve_dir=None` 的
///    联网兜底路径上，这是**用户可见的行为回退**（GitHub 直连在墙内拉不动）。
/// 2. **不选顶层 `http_clients` + `route.default_http_client`**：那是上游文档给的通用写法，但
///    (a) 它给**每一份**配置都加顶层键，而本仓 37 例金样无一含 `services`，等于为零消费者付
///    全量夹具 delta；(b) `httpclient.Manager.Start()` 在 `defaultTag != ""` 时**急切**解析默认
///    transport——dashboard 关着（本仓默认 `singboxDashboard=false`）的用户本来一个 transport
///    都不建，加了反而白建一个。作用域收到真实消费点上，两笔成本都不付。
///
/// `route.final` 缺省（理论上不可达：`build_route_config` 恒 `Some`）时回落 `"direct"` ——
/// 空 `detour` 会让核把 `http_client` 判成 `IsEmpty()` 而**重新落回隐式默认**，等于本改动失效，
/// 故必须给非空 tag 而不是留空。
fn dashboard_http_client(singbox: &SingBoxConfig) -> HttpClient {
    let detour = singbox
        .route
        .as_ref()
        .and_then(|r| r.final_outbound.clone())
        .unwrap_or_else(|| "direct".to_string());
    HttpClient { detour }
}

/// generateSingBoxConfig 依赖注入：Polaris 所有 `this.*` 实例态。
///
/// 对拍：FS 路径注入固定假路径（如 "/fake/cache.db"），回调为 no-op。生产由 ProxyManager 等价层填真值。
#[derive(Debug, Clone)]
pub struct GenerateConfigDeps {
    /// process.platform（neighbor match / mesh system 门控 / log output 谓词）。
    pub platform: String,
    /// 编译目标 arch（outbound tls_spoof 门控）。
    pub arch: String,
    /// 本地 race DNS server 端口（>0 = race 就绪；0 = race off → withRaceOff）。
    pub race_server_port: u16,
    pub probe_direct_port: Option<u16>,
    pub probe_proxy_port: Option<u16>,
    pub update_in_port: Option<u16>,
    pub subscription_update_in_port: Option<u16>,
    /// §15 主核测速探测池：K 个 probe-selector-k 端口。空 = 不注入池。
    pub probe_pool_ports: Vec<u16>,
    pub lan_resolver_for_dns: Option<String>,
    /// race 就绪时的自定义上游 IP（route 直连放行防 TUN 回环）。Polaris L3556 raceServerPort>0 才传。
    pub race_upstream_ips: Vec<String>,
    /// 上面那些上游**实际在用的端口**（`polaris-dns-race` 的 `ResolvedUpstreams::direct_ports` 下发）。
    /// 与 [`race_upstream_ips`](Self::race_upstream_ips) 同源同命：同样只在 `race_server_port > 0` 时透传，
    /// 缺省空 = race off。route 侧只消费不复算（见 `RouteConfigDeps::race_upstream_ports`）。
    pub race_upstream_ports: Vec<u16>,
    /// libcronet 库已内置（naive 协议可用性）。has_cronet=false 时选中 naive 节点 → Err。
    pub has_cronet: bool,
    /// libcronet 拷贝失败（copy-failed 状态）：naive_unavailable_reason 选对应文案。
    pub cronet_copy_failed: bool,
    /// sing-box 1.14 management API 可用（coreVersionAtLeast 1.14）。false → 不注入 services。
    pub has_management_api: bool,
    /// privacyProvider()：隐私模式（buildLogConfig 抬 ≥warn）。
    pub privacy_mode: bool,
    /// buildLogConfig 输入：日志级别（Polaris config.logLevel || 'info'）。UserConfig 增量子集未含此字段。
    pub log_level: crate::user_config::LogLevel,
    /// buildLogConfig 输入：禁用日志写盘（Polaris config.disableLogFile）。UserConfig 增量子集未含此字段。
    pub disable_log_file: bool,
    /// sing-box 核心 dashboard 服务目录解析结果（resolveDashboardServeDir）。None = 不注入 dashboard.path。
    /// Polaris resolveDashboardServeDir 返回 override 或 bundled 或 null（两者皆无）。
    pub dashboard_serve_dir: Option<String>,
    /// tailscale management API 监听端口（`services[0].listen_port`）。
    pub tailscale_api_port: u16,
    /// experimental.cache_file.path（Polaris getCachePath = `<userData>`/cache.db）。
    pub cache_path: String,
    /// TUN 模式 sing-box 日志文件路径（buildLogConfig output）。None = TUN 时 output 留空。
    pub log_file_path: Option<String>,
    // ── FS/路径注入（子 builder 共用，对拍固定假路径）──
    pub runtime_rules_dir: String,
    pub rule_resources_path: String,
    pub custom_rules_dir: String,
    pub tailscale_state_dir_prefix: String,
    /// FS 存在性 + SRS 魔数检查（dns/route geo rule_set fail-closed）。对拍 fixture 注入固定 true/false。
    pub is_valid_srs_fn: fn(&str) -> bool,
    /// 本机所有非回环接口 CIDR（buildInbounds own_lan_cidrs）。Polaris getOwnLanCidrs。
    pub own_lan_cidrs: Vec<String>,
    /// 日志回调（子 builder log）。Polaris (level, message) => this.logToManager —— 此处降级为单参 message。
    pub log: fn(LogLevel, &str),
    /// customRuleFiles 降级回调（route onDegraded）。Polaris () => this.customRuleFilesDegraded = true。
    pub on_degraded: fn(),
}

/// sing-box 配置生成。上游 `ProxyManager.generateSingBoxConfig`（L3470-3637）1:1 移植。
///
/// 纯函数 + 依赖注入：所有实例态经 `deps` 传入。返回完整 `SingBoxConfig` 或用户可见错误（选中节点
/// 不存在 / naive 缺 libcronet / detour 死引用命中选中节点）。
///
/// **与 Polaris 的有意差异**：
/// - cache_id = "polaris-dns-v2"（Polaris "polaris-dns-v2"）—— §D.2 品牌归一化。
/// - 不写回 `this.currentIdToTagMap` / `this.pendingRuleSelectors` / `this.currentRuleTargetMap`：
///   这些是 ProxyManager 实例态（热切换用），config-engine 是纯库无实例态。调用方（Polaris ProxyManager
///   等价层）从返回的 SingBoxConfig + idToTagMap 自行维护。本函数仅返回最终 config。
/// - `currentRuleTargetMap` 回填逻辑（L3618-3628，过滤 liveSelectorTags）属热切换态，不在此移植。
pub fn generate_sing_box_config(
    config: &UserConfig,
    resolved_ips: &BTreeMap<String, String>,
    deps: &GenerateConfigDeps,
) -> Result<SingBoxConfig, String> {
    generate_sing_box_config_with_report(config, resolved_ips, deps).map(|o| o.config)
}

/// 启动 gate 剔除的单个非法节点（前端 `InvalidNodeInfo` 的 1:1 镜像）。
///
/// 仅会话内存语义：每次起核重判，换核自动复活（对齐前端契约注释）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InvalidNode {
    /// 节点 id（`ServerConfig.id`）。
    pub id: String,
    /// 该节点在生成集合里本该占的 outbound tag（**剔除前**的 tag，供日志/tooltip 对人可读）。
    pub tag: String,
    /// 成因判别符，取值见 [`crate::builder::outbounds::INVALID_REASON_DETOUR_CASCADE`] 等同级 const。
    pub reason: String,
}

/// [`generate_sing_box_config_with_report`] 的产物：最终 config + 本次 gate 的剔除报告。
#[derive(Debug, Clone)]
pub struct GenerateOutcome {
    /// 生成的 sing-box config（与 [`generate_sing_box_config`] 返回值逐字节相同）。
    pub config: SingBoxConfig,
    /// 本次生成被 gate 剔除的节点。**空 Vec 是有意义的值**（= 本次无非法节点 → 渲染端据此清陈旧标灰），
    /// 调用方不得因「空就跳过」而吞掉它。
    pub invalid_nodes: Vec<InvalidNode>,
    /// 因本地 `.srs` 缺失/损坏被 fail-closed 剪枝的 rule_set tag（见 [`crate::builder::route::RouteConfigOutcome`]）。
    ///
    /// **空 = 规则集完整**。非空 ⟺ 本次生成真的丢了分流规则 → 运行时层据此发用户可见信号
    /// （`RULE_RESOURCES_MISSING`）并收紧出口自证白名单。资源齐全时恒空 ⇒ 不产生噪音。
    pub pruned_rule_set_tags: Vec<String>,
}

/// [`generate_sing_box_config`] + 剔除报告。
///
/// **为什么另开一个入口而非改原签名**：`generate_sing_box_config` 有 202/202 golden 对拍
/// （`tests/golden_config_snapshot.rs`）+ 多处调用方，改返回类型会把纯粹的「多返回一个副产物」
/// 变成全仓签名 churn。原函数保留为本函数的薄 wrapper（同一条代码路径，绝无第二份生成逻辑
/// → 不存在「两个入口算出不同 config」的分叉面）。
pub fn generate_sing_box_config_with_report(
    config: &UserConfig,
    resolved_ips: &BTreeMap<String, String>,
    deps: &GenerateConfigDeps,
) -> Result<GenerateOutcome, String> {
    generate_sing_box_config_with_report_and_runtime_bindings(
        config,
        resolved_ips,
        deps,
        &BTreeMap::new(),
    )
}

/// [`generate_sing_box_config_with_report`] + 会话级、低于用户显式策略的节点网卡绑定。
/// 映射不进入配置 schema，也不持久化；调用方每次起核都从当前 OS 路由重新计算。
pub fn generate_sing_box_config_with_report_and_runtime_bindings(
    config: &UserConfig,
    resolved_ips: &BTreeMap<String, String>,
    deps: &GenerateConfigDeps,
    runtime_bind_interfaces: &BTreeMap<String, String>,
) -> Result<GenerateOutcome, String> {
    // ── 1. withRaceOff（L3473）──────────────────────────────────────────────────
    // race server 就绪（raceServerPort>0）才走 race 解析；否则强制 race off。
    let cfg = if deps.race_server_port > 0 {
        config.clone()
    } else {
        with_race_off(config)
    };

    // ── 2. selectedServer 校验（L3475-3487）─────────────────────────────────────
    // direct / block 哨兵都不是节点 id：其出口由 proxy-selector 的 default 直接接到内置出站
    // （`direct` / `block`），没有节点承载 ⇒ 必须豁免存在性与可用性校验，否则 0 节点或纯哨兵
    // 配置会在这里报 "Selected server not found" 而**根本起不了核**。
    let is_sentinel = is_sentinel_selection(config.selected_server_id.as_deref());
    let selected_server = if is_sentinel {
        None
    } else {
        config
            .servers
            .iter()
            .find(|s| Some(s.id.as_str()) == config.selected_server_id.as_deref())
    };
    if !is_sentinel {
        let server = selected_server.ok_or_else(|| "Selected server not found".to_string())?;
        if !is_node_usable(server, deps.has_cronet) {
            return Err(naive_unavailable_reason(
                &server.name,
                deps.cronet_copy_failed,
                &deps.platform,
            ));
        }
    }

    // ── 3. idToTagMap（L3495）───────────────────────────────────────────────────
    // 预生成 ID→Tag 唯一映射（节点名作 tag，拓扑/日志友好）。dns/route/outbounds 共用单一真值。
    // ServerLike 包装：build_id_to_tag_map 接受 trait，ServerConfig 需薄包装（与 outbounds.rs 一致）。
    struct SrvLike<'a>(&'a crate::user_config::server_config::ServerConfig);
    impl<'a> ServerLike for SrvLike<'a> {
        fn id(&self) -> &str {
            &self.0.id
        }
        fn name(&self) -> &str {
            &self.0.name
        }
    }
    let wrappers: Vec<SrvLike> = config.servers.iter().map(SrvLike).collect();
    let id_to_tag_map = build_id_to_tag_map(&wrappers);

    // ── 4. buildOutbounds（L3501-3515，先行）────────────────────────────────────
    // 产 pendingEndpoints / pendingRuleSelectors，供 route/dns 消费。
    let system_interface_available = matches!(config.proxy_mode_type, ProxyModeType::Tun)
        && mesh_system_supported_on_platform(&deps.platform);
    let mut outbounds_deps = OutboundsDeps {
        platform: deps.platform.clone(),
        arch: deps.arch.clone(),
        gate_invalid_nodes: std::collections::BTreeMap::new(),
        system_interface_available,
        probe_pool_ports: deps.probe_pool_ports.clone(),
        tailscale_state_dir_prefix: deps.tailscale_state_dir_prefix.clone(),
        has_cronet_lib: deps.has_cronet,
        log: deps.log,
    };
    let outbounds_result = crate::builder::outbounds::build_outbounds_with_runtime_bindings(
        &cfg,
        &mut outbounds_deps,
        runtime_bind_interfaces,
    )?;
    let pending_endpoints = outbounds_result.pending_endpoints.clone();

    // ── 5. buildLogConfig（L3518）───────────────────────────────────────────────
    // proto Platform::parse 兼容 "darwin"/"win32"，未知串 → Other；log builder 视 Other 同 Linux
    // （TUN 下三平台 + Other 均写文件），故与原 `_ => Linux` 行为等价。
    let log_platform = Platform::parse(deps.platform.as_str());
    let log_input = LogConfigInput {
        log_level: deps.log_level,
        disable_log_file: deps.disable_log_file,
        proxy_mode_type: config.proxy_mode_type,
    };
    let log = build_log_config(
        &log_input,
        &LogBuildDeps {
            privacy_mode: deps.privacy_mode,
            platform: log_platform,
            log_file_path: deps.log_file_path.as_deref(),
        },
    );

    // ── 6. buildDnsConfig（L3519-3533）──────────────────────────────────────────
    // selectedServerTag 恒 'proxy-selector'（Polaris L3521 硬编码）。
    let dns_deps = DnsConfigDeps {
        lan_resolver_for_dns: deps.lan_resolver_for_dns.clone(),
        pending_endpoints: pending_endpoints.clone(),
        log: deps.log,
        // DNS 侧的 detour 必须跟随 route 侧**同一条**出口回退（2026-08-11 修）。
        //
        // 此前这里是字面量 `"proxy-selector"`。选中「关外网的组网节点」时 route 侧整体回退 direct
        // （`route.rs` 的 D4/D7 块），而 selector 的 `default` 仍是那个组网节点 ⇒ `dns-remote`
        // 的 DoH 查询被送进它，再被 WireGuard 的 cryptokey routing 按 `allowed_ips` 丢掉。
        //
        // 实测取证（本地探针，非推断）：该状态下生成的配置里
        //   route.final = "direct"
        //   proxy-selector = { default: "wg1", outbounds: ["wg1","direct"] }
        //   dns-remote     = { server: "dns.google", detour: "proxy-selector" }
        // 而 wg1 的 allowed_ips 是 10.0.0.0/24 —— dns.google 不在该段 ⇒ **每一次远程解析必然超时**。
        //
        // 改为跟随回退**严格不劣于现状**：现状是 100% 丢包；改后只在「DoH 端点本身被直连屏蔽」时失败。
        // 不改 selector 的 `default`（那会让用户在面板/Clash API 里看到自己选的节点被换掉），
        // 只改 DNS 这一处的 detour —— 与 route 侧的回退同源同时机。
        selected_server_tag: if crate::builder::route::mesh_selected_exit_falls_back_to_direct(
            config,
        ) {
            "direct".to_string()
        } else {
            "proxy-selector".to_string()
        },
        race_server_port: deps.race_server_port,
        probe_pool_ports: deps.probe_pool_ports.clone(),
        probe_proxy_port: deps.probe_proxy_port,
        platform: deps.platform.clone(),
        custom_rules_dir: deps.custom_rules_dir.clone(),
        runtime_rules_dir: deps.runtime_rules_dir.clone(),
        rule_resources_path: deps.rule_resources_path.clone(),
        is_valid_srs_fn: deps.is_valid_srs_fn,
        // ext JSON source 存在性走 existsSync 等价（生产真 FS）。见 RouteConfigDeps 处同款说明。
        exists_fn: crate::builder::custom_rule_files::ext_rule_file_exists,
    };
    let mut dns = build_dns_config(&cfg, &id_to_tag_map, &dns_deps);

    // ── 7. buildInbounds（L3534-3541）───────────────────────────────────────────
    let inbounds_deps = InboundsDeps {
        probe_direct_port: deps.probe_direct_port,
        probe_proxy_port: deps.probe_proxy_port,
        update_in_port: deps.update_in_port,
        subscription_update_in_port: deps.subscription_update_in_port,
        probe_pool_ports: deps.probe_pool_ports.clone(),
        platform: deps.platform.clone(),
        own_lan_cidrs: deps.own_lan_cidrs.clone(),
        log: deps.log,
    };
    let inbounds = build_inbounds(config, Some(resolved_ips), &inbounds_deps);

    // ── 8. buildRouteConfig（L3543-3557）────────────────────────────────────────
    // race 就绪时把上游 IP **与端口**一起传 route 直连放行（防 TUN 回环，两轴缺一规则匹配不上）；
    // 未就绪两轴恒 []（`race_server_port == 0` ⟺ race off ⟺ 端口集回 `[53,443]` 基线，金样不动）。
    let (race_upstream, race_upstream_ports) = if deps.race_server_port > 0 {
        (
            deps.race_upstream_ips.clone(),
            deps.race_upstream_ports.clone(),
        )
    } else {
        (Vec::new(), Vec::new())
    };
    let route_deps = RouteConfigDeps {
        probe_direct_port: deps.probe_direct_port,
        probe_proxy_port: deps.probe_proxy_port,
        update_in_port: deps.update_in_port,
        subscription_update_in_port: deps.subscription_update_in_port,
        probe_pool_ports: deps.probe_pool_ports.clone(),
        lan_resolver_for_dns: deps.lan_resolver_for_dns.clone(),
        pending_endpoints: &pending_endpoints,
        log: deps.log,
        on_degraded: deps.on_degraded,
        race_upstream_ips: race_upstream,
        race_upstream_ports,
        runtime_rules_dir: deps.runtime_rules_dir.clone(),
        rule_resources_path: deps.rule_resources_path.clone(),
        custom_rules_dir: deps.custom_rules_dir.clone(),
        arch: deps.arch.clone(),
        platform: deps.platform.clone(),
        is_valid_srs_fn: deps.is_valid_srs_fn,
    };
    let route_outcome = build_route_config_with_report(config, &id_to_tag_map, &route_deps);
    let mut route = route_outcome.route;

    // DNS 规则独立于流量模式：global/direct 会裁掉流量规则，但 DNS 仍可引用本地
    // rule_set。故不能再把 `route.rule_set` 当作「流量规则的私有副产物」；以 DNS 已实际
    // 生成的引用为准补齐定义，保证交给 sing-box 的图闭合。无法投影的未知引用则 fail-closed
    // 剪掉对应 DNS 规则，宁可回落默认 DNS 策略也绝不让整核因 `rule-set not found` 退出。
    let dns_pruned_rule_set_tags =
        close_dns_rule_set_graph(&cfg, &mut dns, &mut route, &route_deps);

    // ── 9. 装配顶层 SingBoxConfig + experimental.cache_file（L3517-3571）────────
    let mut singbox = SingBoxConfig {
        log,
        dns: Some(dns),
        inbounds,
        outbounds: outbounds_result.outbounds.clone(),
        endpoints: None,
        route: Some(route),
        experimental: Some(Experimental {
            cache_file: Some(CacheFile {
                enabled: true,
                path: deps.cache_path.clone(),
                cache_id: Some(CACHE_ID.to_string()),
                store_fakeip: Some(true),
                store_dns: Some(true),
            }),
        }),
        services: None,
    };

    // ── 10. endpoints 注入顶层（L3575-3577）─────────────────────────────────────
    if !pending_endpoints.is_empty() {
        singbox.endpoints = Some(pending_endpoints.clone());
    }

    // ── 11. services 注入（L3581-3600，has_management_api 门控）──────────────────
    if deps.has_management_api {
        let secret = config.clash_api_secret.clone();
        let mut api_service = ApiService {
            type_field: "api".to_string(),
            listen: "127.0.0.1".to_string(),
            listen_port: deps.tailscale_api_port,
            secret,
            dashboard: None,
        };
        // dashboard opt-in：仅 config.singboxDashboard==true 时注入。
        if config.singbox_dashboard == Some(true) {
            let http_client = Some(dashboard_http_client(&singbox));
            api_service.dashboard = Some(match &deps.dashboard_serve_dir {
                Some(dir) => ApiDashboard {
                    enabled: true,
                    path: Some(dir.clone()),
                    http_client,
                },
                None => ApiDashboard {
                    enabled: true,
                    path: None,
                    http_client,
                },
            });
        }
        singbox.services = Some(vec![api_service]);
    }

    // ── 12. fixRouteDeadReferences（L3605）──────────────────────────────────────
    // route 规则指向「已被跳过/不存在的出站」→ sing-box "outbound not found" 启动失败。改写为 proxy-selector。
    if let Some(route) = singbox.route.as_mut() {
        fix_route_dead_references(&singbox.outbounds, &pending_endpoints, &mut route.rules);
    }

    // ── 13. 调试日志（L3631-3634）───────────────────────────────────────────────
    let rule_set_count = singbox
        .route
        .as_ref()
        .and_then(|r| r.rule_set.as_ref())
        .map(|v| v.len())
        .unwrap_or(0);
    (deps.log)(
        LogLevel::Info,
        &format!(
            "配置已生成: inbounds={}, outbounds={}, rule_set={}",
            singbox.inbounds.len(),
            singbox.outbounds.len(),
            rule_set_count
        ),
    );

    // ── gate 剔除报告（EVENT_PROXY_INVALID_NODES 的真值源）────────────────────────
    // `build_outbounds` 把被剔的 id 记进 `outbounds_deps.gate_invalid_nodes`（`&mut` 出参）；此前它
    // 随 deps 一起在函数末尾被丢弃 → 「哪些节点被剔」这个真值**产生了却没人拿得到**，渲染端的
    // `invalidNodes` store 因此恒空。此处把它连同 tag/reason 一并交回调用方。
    //
    // tag 取自 `id_to_tag_map`（步骤 3 生成，**剔除前**的全量映射）：`prune_detour_dead_references`
    // 只从它自己的局部 `id_to_tag` 里 remove，不动这份 → 被剔节点的 tag 在此仍查得到，正是 tooltip 要的。
    //
    // reason **随剔除点记录**（`BTreeMap<id, token>`），不在此处写死：成因已不止 detour 级联一种
    // （control_url 非法是第二种），写死会让 tooltip 报出与真实成因无关的那一个。
    let invalid_nodes: Vec<InvalidNode> = outbounds_deps
        .gate_invalid_nodes
        .iter()
        .map(|(id, reason)| InvalidNode {
            id: id.clone(),
            tag: id_to_tag_map.get(id).cloned().unwrap_or_default(),
            reason: (*reason).to_string(),
        })
        .collect();

    Ok(GenerateOutcome {
        config: singbox,
        invalid_nodes,
        pruned_rule_set_tags: route_outcome
            .pruned_rule_set_tags
            .into_iter()
            .chain(dns_pruned_rule_set_tags)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    })
}

/// 把 DNS 已发射的 rule_set 引用和顶层 `route.rule_set` 定义闭合。
///
/// sing-box 把 rule_set 定义放在 route 平面，但 DNS 平面也能引用它。流量规则在 global/direct
/// 被刻意裁掉时，DNS 规则仍有效；若定义只由流量侧生成，就会得到「引用在、定义没了」的 FATAL 配置。
/// 这里以**最终 DNS 输出**为唯一需求集：只补它真正引用的本地定义，绝不把无关规则资源预先塞进配置。
fn close_dns_rule_set_graph(
    config: &UserConfig,
    dns: &mut DnsConfig,
    route: &mut RouteConfig,
    route_deps: &RouteConfigDeps<'_>,
) -> Vec<String> {
    let referenced = dns_rule_set_references(dns);
    if referenced.is_empty() {
        return vec![];
    }

    let definitions = route.rule_set.get_or_insert_with(Vec::new);
    let mut defined: BTreeSet<String> = definitions.iter().map(|entry| entry.tag.clone()).collect();
    let custom_deps = CustomRulesDeps {
        runtime_rules_dir: route_deps.runtime_rules_dir.clone(),
        rule_resources_path: route_deps.rule_resources_path.clone(),
        custom_rules_dir: route_deps.custom_rules_dir.clone(),
        arch: route_deps.arch.clone(),
        platform: route_deps.platform.clone(),
        is_valid_srs_fn: route_deps.is_valid_srs_fn,
        exists_fn: crate::builder::custom_rule_files::ext_rule_file_exists,
        log: route_deps.log,
    };
    for tag in &referenced {
        if defined.contains(tag) {
            continue;
        }
        if let Some(resource_id) = tag.strip_prefix("local-rs-") {
            if let Some(resolved_tag) = resolve_resource_rule_set(
                resource_id,
                &config.rule_resources,
                definitions,
                &custom_deps,
            ) {
                defined.insert(resolved_tag);
            }
        } else {
            add_local_geo_rule_set(tag, definitions, &mut defined, config, route_deps);
        }
    }

    let pruned = prune_unresolved_dns_rule_sets(dns, &defined);
    if !pruned.is_empty() {
        (route_deps.log)(
            LogLevel::Warn,
            &format!(
                "DNS 规则资源：{} 缺少可用定义，已跳过引用它的 DNS 规则以避免代理启动失败",
                pruned.join(", ")
            ),
        );
    }
    pruned
}

/// 收集 DNS 规则实际引用的 tag；只看已生成的结果，因而天然遵守 DNS builder 的模式/条件/文件有效性门。
fn dns_rule_set_references(dns: &DnsConfig) -> BTreeSet<String> {
    dns.rules
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .flat_map(|rule| match rule.rule_set.as_ref() {
            Some(OneOrMany::One(tag)) => vec![tag.clone()],
            Some(OneOrMany::Many(tags)) => tags.clone(),
            None => vec![],
        })
        .collect()
}

/// 最后一层 fail-closed：若今后 DNS builder 新增了无法投影的引用，也只能丢掉该 DNS 规则，
/// 绝不能把悬空 tag 交给 sing-box 并让整个核心启动失败。
fn prune_unresolved_dns_rule_sets(dns: &mut DnsConfig, defined: &BTreeSet<String>) -> Vec<String> {
    let Some(rules) = dns.rules.as_mut() else {
        return vec![];
    };
    let mut pruned = BTreeSet::new();
    rules.retain_mut(|rule| retain_defined_dns_rule_sets(rule, defined, &mut pruned));
    pruned.into_iter().collect()
}

fn retain_defined_dns_rule_sets(
    rule: &mut DnsRule,
    defined: &BTreeSet<String>,
    pruned: &mut BTreeSet<String>,
) -> bool {
    let Some(rule_set) = rule.rule_set.as_ref() else {
        return true;
    };
    let tags: &[String] = match rule_set {
        OneOrMany::One(tag) => std::slice::from_ref(tag),
        OneOrMany::Many(tags) => tags,
    };
    let missing: Vec<&String> = tags.iter().filter(|tag| !defined.contains(*tag)).collect();
    if missing.is_empty() {
        true
    } else {
        pruned.extend(missing.into_iter().cloned());
        false
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests;
