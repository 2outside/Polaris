//! 生成 outbounds 主循环（上游 `buildOutbounds` + `generateRuleSelectors` 1:1 移植）。
//!
//! 节点出站 + selector + rule-sel + direct/block + probe pool + shadow-tls 后处理 + detour 死引用预校验。

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use crate::builder::endpoint_routes::active_physical_root_ids;
use crate::builder::endpoints::{
    build_tailscale_endpoint, build_vpn_client_endpoint, build_wireguard_endpoint,
};
use crate::builder::helpers::{
    build_id_to_tag_map, effective_app_rules, effective_custom_rules, get_domestic_resolver_tag,
    get_node_dial_domain_resolver, get_node_resolver_tag, NodeResolverCtx, ServerLike,
};
use crate::builder::outbound::{build_proxy_outbound, custom_passthrough_parts};
use crate::singbox::{DomainResolver, Endpoint, Outbound};
use crate::user_config::app_config::UserConfig;
use crate::user_config::dns_constants::{
    is_block_selection, is_direct_selection, DIRECT_TAG, PROXY_SELECTOR_TAG,
};
use crate::user_config::log_level::LogLevel;
use crate::user_config::server_config::{lands_in_endpoints, Protocol, ServerConfig};

/// 「detour 级联剔除」的 reason 判别符（`InvalidNodeInfo.reason` 的稳定机器 token）。
///
/// **为什么是 token 而非人话**：reason 要进渲染端 tooltip（系统设计 §F.3「无效节点原因悬浮」），
/// 文案须按用户语言 i18n → 后端给稳定判别符、UI 端查表，绝不从后端下发已定死语言的句子。
///
/// **为什么当前只有这一个**：前端契约（`ui/src/contracts/types/runtime.ts`）声明 reason 区分
/// 「直接被 check 标中」/「detour 级联剔除」两腿，但本仓**只实现了后者**——主代理起核路径没有
/// 「跑 `sing-box check` → 解析输出标出坏节点」的 gate（`sing-box check` 在本仓仅用于
/// `tailscale_login_core.rs` 的登录配置形状校验，二值 pass/fail，不逐节点归因）。
/// 那一腿缺的是**gate 本身**，不是 emit：没有节点被它剔除 → 没有可诚实上报的内容。
/// 补齐 check gate 时在此加同级 const，勿把两种成因塞进同一个 token。
pub const INVALID_REASON_DETOUR_CASCADE: &str = "detour-cascade";

/// 自定义（custom）逃生舱的 outbound JSON **形状非法**的 reason token。
///
/// 判据 = [`custom_outbound_type`](crate::user_config::protocol_settings::custom_outbound_type)：
/// 必须是带 string `type` 的 JSON 对象，与 C10 probe 同一个谓词。
///
/// **为什么补这一格**：此前 custom 的两条腿在失败时都不说话——endpoint 腿是
/// `if let Ok(ep) = from_value::<Endpoint>(val)`（Err 分支空实现，节点静默消失），outbound 腿是
/// `unwrap_or_else(|_| 空壳)`（下发 `{"type":"custom"}`，随包 sing-box 判 `unknown outbound type:
/// custom` ⇒ **整份配置**起不来，而用户拿到的信息只有「启动失败」）。两种都属「产生了真值却没人
/// 交出去」，故并入 detour 级联那条既有上报通道（`gate_invalid_nodes` → `generate.rs` 的
/// `InvalidNode` → `EVENT_PROXY_INVALID_NODES` → 节点卡标灰 + tooltip）。
///
/// 渲染端 `ui/src/domain/invalid-node-reason.ts` 未登记本 token 时**只渲染通用句**（「节点配置无效，
/// 已在启动时跳过」），绝不把 token 原样拼给用户——那张表的回落语义就是为这种情况留的。补人话文案
/// 需要动 `ui/src/i18n/locales/*.json`，不在本批射程内。
pub const INVALID_REASON_CUSTOM_MALFORMED: &str = "custom-outbound-malformed";

/// Tailscale `control_url` 非法（IP 字面量 / 缺 scheme / host 畸形）的 reason token 前缀族。
///
/// 具体取值由 [`crate::user_config::control_url::reject_token`] 给出（`control-url-ip` /
/// `control-url-scheme` / `control-url-invalid`），**本处不再复制一份常量**——两份会漂移。
///
/// 这是主起核路径上**第一条真正的「下发前校验」gate**：上游 sing-box 对 IP 形式的 `control_url`
/// 会在 `protocol/tailscale/endpoint.go:195` 无条件类型断言处 **panic**（判据与机制见
/// `control_url` 模块头注）。panic 是最差的失败形态 —— 主核起核腿只会把它归成
/// 「sing-box 启动期退出」，Go 堆栈一个字都到不了用户眼前，用户看到的就是「启动失败」四个字。
/// 故必须在这里把节点剔掉、把成因交出去，而不是把配置下发给核去炸。
///
/// **只剔该节点、不 FATAL 整份配置**：一个坏 Tailscale 节点不应让其余节点跟着连不上。
pub use crate::user_config::control_url::reject_token as control_url_reject_token;

/// rule-sel 载体。上游 `PendingRuleSelector`。
#[derive(Debug, Clone)]
pub struct PendingRuleSelector {
    pub rule_key: String,
    pub selector_tag: String,
    pub member_tag: String,
    pub target_server_id: Option<String>,
}

/// buildOutbounds 依赖注入。
pub struct OutboundsDeps {
    pub platform: String,
    pub arch: String,
    /// 被启动 gate 剔除的节点 `id` → reason token（[`INVALID_REASON_DETOUR_CASCADE`] 等）。
    ///
    /// 曾是 `BTreeSet<String>`：那时只有 detour 级联一种成因，`generate.rs` 便把 reason 写死成
    /// `detour-cascade`。加入 `control_url` gate 后成因不止一种，reason 必须**随剔除点一起记**，
    /// 否则用户会在 tooltip 里看到与真实成因无关的那一个。
    pub gate_invalid_nodes: std::collections::BTreeMap<String, &'static str>,
    pub system_interface_available: bool,
    pub probe_pool_ports: Vec<u16>,
    /// Tailscale state 目录前缀（生产 UserData/tailscale，对拍固定假路径）。
    pub tailscale_state_dir_prefix: String,
    pub has_cronet_lib: bool,
    pub log: fn(LogLevel, &str),
}

/// buildOutbounds 输出。
#[derive(Debug, Clone, Default)]
pub struct OutboundsResult {
    pub outbounds: Vec<Outbound>,
    pub pending_endpoints: Vec<Endpoint>,
    pub pending_rule_selectors: Vec<PendingRuleSelector>,
}

fn dns_resolve_ahead(config: &UserConfig) -> Option<bool> {
    config
        .dns_config
        .as_ref()
        .and_then(|d| d.resolve_node_domains_ahead)
}

fn node_resolver_dial_tag(config: &UserConfig) -> String {
    get_node_resolver_tag(
        dns_resolve_ahead(config),
        config
            .dns_config
            .as_ref()
            .and_then(|d| d.node_resolver_single.as_deref()),
        config
            .dns_config
            .as_ref()
            .and_then(|d| d.node_domain_resolver.as_deref()),
        match config.proxy_mode_type {
            crate::user_config::ProxyModeType::Tun => "tun",
            crate::user_config::ProxyModeType::SystemProxy => "systemProxy",
            crate::user_config::ProxyModeType::Manual => "manual",
        },
        NodeResolverCtx::Dial,
    )
}

fn domestic_resolver_tag(config: &UserConfig) -> String {
    get_domestic_resolver_tag(dns_resolve_ahead(config), "dns-domestic")
}

fn non_empty_interface(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
}

/// 节点代理出口的本地策略：手动节点覆盖 → 订阅覆盖 → 全局代理默认。
///
/// 订阅节点有意忽略节点对象里的 `bindInterface`：订阅刷新会整体替换节点，且供应方数据不应拥有
/// 本机网卡策略。带 detour 的节点最终由最外层物理拨号出站决定接口；这里仍保留节点声明，便于其在
/// 取消 detour 后立即恢复原策略，sing-box 对 detoured child 的 dial field 不会误开第二条物理连接。
pub fn effective_proxy_bind_interface(
    server: &ServerConfig,
    config: &UserConfig,
) -> Option<String> {
    let local = if let Some(subscription_id) = server.subscription_id.as_deref() {
        config
            .subscriptions
            .iter()
            .find(|sub| sub.id == subscription_id)
            .and_then(|sub| non_empty_interface(sub.proxy_bind_interface.as_deref()))
    } else {
        non_empty_interface(server.bind_interface.as_deref())
    };
    local.or_else(|| {
        config
            .network_interfaces
            .as_ref()
            .and_then(|policy| non_empty_interface(policy.proxy.as_deref()))
    })
}

/// 返回当前活跃出站实际会引用到的显式物理网卡名。
///
/// 运行时启动 / 热切换门禁复用本函数，避免在编排层重新抄一份「节点覆盖 → 订阅覆盖 → 全局默认」
/// 的优先级。节点腿只检查 [`active_physical_root_ids`]：闲置节点即使保存了当前不存在的本机网卡，也
/// 不应阻断 A 节点启动；当 selector/rule 真切到它时，新 active roots 会在持久化/热切换前重新校验。
/// 全局直连出口恒会生成且确实承流，因此只要配置就会进入集合。
#[must_use]
pub fn required_bind_interfaces(config: &UserConfig) -> BTreeSet<String> {
    let mut required = BTreeSet::new();
    if let Some(interface) = config
        .network_interfaces
        .as_ref()
        .and_then(|defaults| non_empty_interface(defaults.direct.as_deref()))
    {
        required.insert(interface);
    }
    let by_id: BTreeMap<&str, &ServerConfig> = config
        .servers
        .iter()
        .map(|server| (server.id.as_str(), server))
        .collect();
    for root_id in active_physical_root_ids(config) {
        let Some(server) = by_id.get(root_id.as_str()).copied() else {
            continue;
        };
        if let Some(interface) = effective_proxy_bind_interface(server, config) {
            required.insert(interface);
        }
    }
    required
}

fn apply_bind_interface(
    extra: &mut serde_json::Map<String, serde_json::Value>,
    interface: Option<&str>,
) {
    if let Some(interface) = interface {
        extra.insert(
            "bind_interface".into(),
            serde_json::Value::String(interface.to_owned()),
        );
    } else {
        extra.remove("bind_interface");
    }
}

/// 为带 `shadowTlsSettings` 的节点构造真正负责公网拨号的 ShadowTLS 外层。
///
/// 主内核和停核测速的临时内核共用这一处，避免两条生成链在端口回退、SNI、uTLS 指纹和
/// `bind_interface` 的归属上漂移。返回 `None` 表示该节点没有 ShadowTLS 外层。
#[must_use]
pub fn build_shadow_tls_outbound(
    server: &ServerConfig,
    bind_interface: Option<&str>,
) -> Option<Outbound> {
    use crate::singbox::outbound::{OutboundTls, Utls};

    let stls = server.shadow_tls_settings.as_ref()?;
    let stls_port = match stls.port {
        Some(port) if port != 0 => port,
        _ => server.port,
    };
    let server_name = (!stls.sni.is_empty()).then(|| stls.sni.clone());
    let mut outbound = Outbound::shell("shadowtls", &format!("stls-out-{}", server.id));
    outbound.server = Some(server.address.clone());
    outbound.server_port = Some(stls_port);
    outbound.version = Some(crate::singbox::OutboundVersion::Num(3));
    outbound.password = Some(stls.password.clone());
    outbound.tls = Some(OutboundTls {
        enabled: true,
        server_name,
        insecure: None,
        alpn: None,
        engine: None,
        spoof: None,
        spoof_method: None,
        utls: Some(Utls {
            enabled: true,
            fingerprint: stls
                .fingerprint
                .as_deref()
                .and_then(crate::user_config::normalize::normalize_token)
                .unwrap_or_else(|| "chrome".to_string()),
        }),
        reality: None,
        ech: None,
        fragment: None,
    });
    apply_bind_interface(&mut outbound.extra, bind_interface);
    Some(outbound)
}

/// 生成 outbounds。上游 `buildOutbounds`。
///
/// 返回 `Result`：detour 死引用命中选中节点 → Err（调用方转用户可见错误）。
pub fn build_outbounds(
    config: &UserConfig,
    deps: &mut OutboundsDeps,
) -> Result<OutboundsResult, String> {
    build_outbounds_with_runtime_bindings(config, deps, &BTreeMap::new())
}

/// [`build_outbounds`] + 本次运行期按目的路由推导出的低优先级网卡绑定。
///
/// 显式节点/订阅/全局策略始终优先；运行时映射只填补未配置项，且不写回用户配置。
pub fn build_outbounds_with_runtime_bindings(
    config: &UserConfig,
    deps: &mut OutboundsDeps,
    runtime_bind_interfaces: &BTreeMap<String, String>,
) -> Result<OutboundsResult, String> {
    let mut pending_endpoints: Vec<Endpoint> = Vec::new();
    let mut pending_rule_selectors: Vec<PendingRuleSelector> = Vec::new();
    let mut outbounds: Vec<Outbound> = Vec::new();
    let mut node_tags: Vec<String> = Vec::new();
    // 节点 dial 解析器：tag 选谁（race / dnspod / system / 基线）与「要不要覆盖 strategy」是两件事——
    // 前者按 DNS 设置选，后者只看 enableIPv6（#335）。故在此合成一次，逐 outbound / endpoint 透传。
    let dial_resolver = get_node_dial_domain_resolver(
        &node_resolver_dial_tag(config),
        config.enable_ipv6 == Some(true),
    );

    // id→tag 映射（build_id_to_tag_map 的副本，buildOutbounds 内可变——detour 死引用剔除时删 entry）。
    let mut id_to_tag: BTreeMap<String, String> = BTreeMap::new();
    {
        struct SrvLike<'a>(&'a ServerConfig);
        impl<'a> ServerLike for SrvLike<'a> {
            fn id(&self) -> &str {
                &self.0.id
            }
            fn name(&self) -> &str {
                &self.0.name
            }
        }
        let wrappers: Vec<SrvLike> = config.servers.iter().map(SrvLike).collect();
        let map = build_id_to_tag_map(&wrappers);
        for (k, v) in map {
            id_to_tag.insert(k, v);
        }
    }

    for server in &config.servers {
        let tag = id_to_tag
            .get(&server.id)
            .cloned()
            .unwrap_or_else(|| format!("proxy-{}", server.id));
        // detour child 不创建物理 socket：它自己的 bindInterface 既约束不了最终拨号，也不能成为运行时
        // fail-closed 的依据。真正的根节点无 detour，显式策略优先于本会话推断。
        let bind_interface = server
            .detour
            .is_none()
            .then(|| {
                effective_proxy_bind_interface(server, config).or_else(|| {
                    runtime_bind_interfaces
                        .get(&server.id)
                        .and_then(|interface| non_empty_interface(Some(interface.as_str())))
                })
            })
            .flatten();
        if node_tags.contains(&tag) {
            continue;
        }
        // 不可用节点（naive 缺 libcronet）。
        if server.protocol == Protocol::Naive && !deps.has_cronet_lib {
            continue;
        }
        if deps.gate_invalid_nodes.contains_key(&server.id) {
            continue;
        }

        let downgrade_mesh = crate::builder::endpoint_routes::mesh_uses_system_interface(server)
            && !deps.system_interface_available;

        // WireGuard endpoint。
        if server.protocol == Protocol::Wireguard {
            if crate::builder::endpoint_routes::is_mesh_node_unroutable(server) {
                continue;
            }
            // 前置代理（对 上游的有意偏离，见 `singbox/endpoint.rs` 的 `Endpoint::detour`）。
            // WARP 也走这条腿（WARP = reverseMesh 的 WireGuard 节点），故三种 endpoint 里两种在此发射。
            let detour_tag = resolve_detour_tag(server, config, &id_to_tag);
            if let Ok(mut ep) = build_wireguard_endpoint(
                server,
                &tag,
                Some(&dial_resolver),
                &deps.platform,
                detour_tag.as_deref(),
            ) {
                if downgrade_mesh {
                    ep.system = Some(false);
                    ep.name = None;
                }
                apply_bind_interface(&mut ep.extra, bind_interface.as_deref());
                pending_endpoints.push(ep);
                node_tags.push(tag);
            }
            continue;
        }

        // Tailscale endpoint。
        if server.protocol == Protocol::Tailscale {
            // ── control_url 下发前校验（fail-closed）──────────────────────────────────
            // IP 形式的 control_url 会让内核在 `NewEndpoint` 里**直接 panic**（机制见
            // `user_config::control_url` 头注），而 panic 在主起核腿只会归成「sing-box 启动期退出」，
            // 用户拿不到任何可行动信息。故在**下发之前**剔掉该节点并记下成因 token。
            //
            // 判据取 `server.tailscale_settings`（用户填的原值），不是 `build_tailscale_endpoint`
            // 的产物 —— 必须在构造之前判，否则坏值已经进了 `pending_endpoints`。
            if let Some(reject) = server
                .tailscale_settings
                .as_ref()
                .and_then(|ts| ts.control_url.as_deref())
                .and_then(crate::user_config::control_url::tailscale_control_url_reject)
            {
                let token = control_url_reject_token(reject);
                deps.gate_invalid_nodes.insert(server.id.clone(), token);
                (deps.log)(
                    LogLevel::Warn,
                    &format!(
                        "启动前配置校验：节点「{tag}」的 control_url 非法（{token}），已剔除 —— \
                         该写法会让 sing-box 在初始化 tailscale endpoint 时 panic"
                    ),
                );
                continue;
            }

            let state_dir = format!("{}/{}", deps.tailscale_state_dir_prefix, server.id);
            // 前置代理：TS 侧经它的是控制面 / DERP 的 **TCP** 拨号（异于 WG 的 UDP ASSOCIATE）。
            let detour_tag = resolve_detour_tag(server, config, &id_to_tag);
            let mut ep = build_tailscale_endpoint(
                server,
                &tag,
                &state_dir,
                &deps.platform,
                detour_tag.as_deref(),
            );
            if downgrade_mesh {
                ep.system_interface = Some(false);
                ep.system_interface_name = None;
            }
            apply_bind_interface(&mut ep.extra, bind_interface.as_deref());
            pending_endpoints.push(ep);
            node_tags.push(tag);
            continue;
        }

        // ── 自定义协议（逃生舱）：两条腿共用一条形状判据 ────────────────────────────────
        //
        // 判据 = `custom_outbound_type`，与 C10「测试内核兼容性」按钮
        // （`src-tauri/src/commands/proxy.rs::validate_probe_outbound`）**同一个谓词**：按钮把用户
        // JSON 原样送 `sing-box check`，生成路径把同一份 JSON 原样下发；判据分叉 = 按钮报 ok 而真
        // 起核时那份配置根本不是同一个东西。
        //
        // 形状不合法 → **剔除并上报**（`gate_invalid_nodes` → `InvalidNode` → `EVENT_PROXY_INVALID_NODES`
        // → 节点卡标灰 + tooltip）。此前 endpoint 腿写的是 `if let Ok(ep) = from_value::<Endpoint>(val)`，
        // Err 分支**无 push、无 log、无上报** ⇒ 节点在配置里凭空消失，用户侧只看到「这个节点没了」。
        // 节点消失而不告知比报错更坏。
        // ── 端点族 VPN 客户端（2026-08-11）：openconnect / openvpn-client ──
        //
        // 二者在内核里只存在于 `$defs/Endpoint`，塞进 `outbounds[]` 得 `unknown outbound type`（实测）
        // ⇒ 必须走本腿，不能落到下面的 `build_proxy_outbound`。
        //
        // 载荷取自**用户设置结构的序列化**：那些结构的 serde 名就是 sing-box 的键名，
        // 故整体 flatten 进 `Endpoint::extra` 即为下发内容 —— 不给 wire struct 加 139 个具名字段。
        // 缺设置时**仍发一个只有 type/tag 的空壳**并上报：与 custom 腿同口径（节点凭空消失比报错更坏），
        // 内核会在 initialize 阶段明确拒绝（openvpn 缺 tls / openconnect 缺 server），
        // 用户拿到的是一条能对症的错，而不是「这个节点没了」。
        if matches!(
            server.protocol,
            Protocol::Openconnect | Protocol::OpenvpnClient
        ) {
            let has_settings = match server.protocol {
                Protocol::Openconnect => server.openconnect_settings.is_some(),
                _ => server.openvpn_client_settings.is_some(),
            };
            if !has_settings {
                (deps.log)(
                        LogLevel::Warn,
                        &format!(
                            "启动前配置校验：节点「{tag}」缺少 {} 设置，已按空壳下发（内核会在 initialize 阶段拒绝并给出缺失项）",
                            crate::builder::outbound::protocol_str(server.protocol)
                        ),
                    );
            }
            // dial 级解析器**必须给**：server 是域名时 1.14 initialize 会硬失败。
            let mut endpoint = build_vpn_client_endpoint(server, &tag, Some(&dial_resolver))?;
            apply_bind_interface(&mut endpoint.extra, bind_interface.as_deref());
            pending_endpoints.push(endpoint);
            node_tags.push(tag);
            continue;
        }

        if server.protocol == Protocol::Custom {
            let is_custom_endpoint = server
                .custom_settings
                .as_ref()
                .and_then(|c| c.is_endpoint)
                .unwrap_or(false);
            match server
                .custom_settings
                .as_ref()
                .and_then(|cs| custom_passthrough_parts(&cs.outbound))
            {
                None => {
                    deps.gate_invalid_nodes
                        .insert(server.id.clone(), INVALID_REASON_CUSTOM_MALFORMED);
                    (deps.log)(
                        LogLevel::Warn,
                        &format!(
                            "启动前配置校验：自定义节点「{tag}」的 outbound JSON 不是带 string `type` 的\
                             对象，已剔除并上报"
                        ),
                    );
                    continue;
                }
                // 自定义 endpoint：raw JSON 逐键原样进 `endpoints[]`（`Endpoint::extra` flatten 回顶层）。
                // 这条腿是 `openvpn-client` / `openconnect` 一族的**唯一**通路——实测把它们塞进
                // `outbounds[]` 是 `unknown outbound type`，它们只在 `$defs/Endpoint/oneOf` 里。
                Some((type_field, extra)) if is_custom_endpoint => {
                    let mut endpoint = Endpoint {
                        type_field,
                        tag: tag.clone(),
                        extra,
                        ..Default::default()
                    };
                    apply_bind_interface(&mut endpoint.extra, bind_interface.as_deref());
                    pending_endpoints.push(endpoint);
                    node_tags.push(tag);
                    continue;
                }
                // 非 endpoint 的 custom：落到下面的通用代理腿，由 `build_proxy_outbound` 的 custom
                // 分支用**同一个** `custom_passthrough_parts` 构造 —— 不在此另立第二份透传逻辑
                // （两份必漂移），代价只是把那个小 map 多算一次。
                Some(_) => {}
            }
        }

        // 普通代理 outbound。
        let mut ob = build_proxy_outbound(server, &tag, &dial_resolver, &deps.arch, &deps.platform);
        // detour 代理链。
        ob.detour = resolve_detour_tag(server, config, &id_to_tag);
        apply_bind_interface(&mut ob.extra, bind_interface.as_deref());
        outbounds.push(ob);
        node_tags.push(tag);
    }

    // 全局 TLS 分片。
    if config.tls_fragment == Some(true) {
        for ob in &mut outbounds {
            if matches!(ob.type_field.as_str(), "hysteria2" | "tuic" | "naive") {
                continue;
            }
            if let Some(tls) = ob.tls.as_mut() {
                tls.fragment = Some(true);
                continue;
            }
            // custom 逃生舱：tls 块在 `extra` 里（raw 透传，不进具名字段），同样要吃到全局分片。
            //
            // 这不是新行为，是**保住既有的**：上游 这段是 `if (ob.tls && …) ob.tls.fragment = true`
            // ——那边 custom outbound 就是用户 raw 对象的浅拷贝，`ob.tls` 即用户自己那个 tls 块，
            // 全局开关对它是生效的。本仓把 raw 换了个载体（`extra`），若不跟着走这一条，
            // 「全局 TLS 分片」这颗开关会对 custom 节点静默失效。
            //
            // 只认对象形态：非对象的 `tls`（如 `true`）往里塞键没有意义，原样留着交给内核判。
            if let Some(serde_json::Value::Object(tls)) = ob.extra.get_mut("tls") {
                tls.insert("fragment".into(), serde_json::Value::Bool(true));
            }
        }
    }

    // proxy-selector。
    let is_direct = is_direct_selection(config.selected_server_id.as_deref());
    let is_block = is_block_selection(config.selected_server_id.as_deref());
    let selected_tag = config
        .selected_server_id
        .as_deref()
        .and_then(|sid| {
            if is_direct_selection(Some(sid)) {
                Some(DIRECT_TAG.to_string())
            } else {
                id_to_tag.get(sid).cloned()
            }
        })
        .unwrap_or_else(|| "proxy".to_string());

    // 出口选阻断**不再经 selector 表达**（2026-08-13）：改由 `builder::route` 把所有「→代理」
    // 的规则整体改写成 `action:"reject"` + 一条无 matcher 兜底。此处 default 落到 direct 只是
    // 让 selector 保持结构合法 —— 阻断态下没有任何规则会路由到它（全被改写成 reject 了）。
    let selector_default = if is_direct || is_block {
        DIRECT_TAG.to_string()
    } else if node_tags.contains(&selected_tag) {
        selected_tag
    } else {
        node_tags
            .first()
            .cloned()
            .unwrap_or_else(|| DIRECT_TAG.to_string())
    };

    let mut selector_members: Vec<String> = node_tags.clone();
    selector_members.push(DIRECT_TAG.to_string());
    // 不再往成员表里塞 `block`：阻断已不经 selector 表达。
    let proxy_selector = Outbound {
        type_field: "selector".into(),
        tag: PROXY_SELECTOR_TAG.into(),
        outbounds: Some(selector_members),
        default: Some(selector_default),
        interrupt_exist_connections: Some(config.interrupt_connections_on_switch == Some(true)),
        extra: serde_json::Map::new(),
        detour: None,
        server: None,
        server_port: None,
        override_address: None,
        method: None,
        password: None,
        username: None,
        plugin: None,
        plugin_opts: None,
        uuid: None,
        security: None,
        alter_id: None,
        flow: None,
        packet_encoding: None,
        up_mbps: None,
        down_mbps: None,
        obfs: None,
        auth_str: None,
        executable_path: None,
        data_directory: None,
        extra_args: None,
        torrc: None,
        bbr_profile: None,
        disable_chrome_parrot: None,
        network: None,
        quic: None,
        congestion_control: None,
        udp_relay_mode: None,
        zero_rtt_handshake: None,
        heartbeat: None,
        version: None,
        psk: None,
        userkey: None,
        reuse: None,
        obfs_mode: None,
        obfs_host: None,
        mode: None,
        idle_session_check_interval: None,
        idle_session_timeout: None,
        min_idle_session: None,
        path: None,
        headers: None,
        tls: None,
        transport: None,
        multiplex: None,
        server_ports: None,
        hop_interval: None,
        domain_resolver: None,
        udp_over_tcp: None,
        udp_fragment: None,
        user: None,
        private_key: None,
        private_key_path: None,
        private_key_passphrase: None,
        host_key: None,
        host_key_algorithms: None,
        client_version: None,
        cipher: None,
        mac: None,
        kex_algorithm: None,
    };
    // selector 是逻辑分发器，不发起 socket，绝不能携带 dial field。
    outbounds.push(proxy_selector);

    // rule-sel（仅 smart）。
    if config.proxy_mode == crate::user_config::ProxyMode::Smart {
        generate_rule_selectors(
            config,
            &id_to_tag,
            &node_tags,
            &mut outbounds,
            &mut pending_rule_selectors,
        );
    }

    // direct + block。
    let mut direct_outbound = Outbound {
        type_field: "direct".into(),
        tag: DIRECT_TAG.into(),
        // **刻意保持纯 tag 形态**（与 #335 的 dial 侧修复相反）：direct 拨的是**目标站点**域名，
        // 顶层 `ipv4_only` 掐掉它们的 AAAA 正是 #57 想要的收益，不是要修的 bug。上游
        // `a942c60` 的金样 delta 里 direct 这一路也一处未动。
        domain_resolver: Some(DomainResolver::Tag(domestic_resolver_tag(config))),
        detour: None,
        server: None,
        server_port: None,
        override_address: None,
        method: None,
        password: None,
        username: None,
        plugin: None,
        plugin_opts: None,
        uuid: None,
        security: None,
        alter_id: None,
        flow: None,
        packet_encoding: None,
        up_mbps: None,
        down_mbps: None,
        obfs: None,
        auth_str: None,
        executable_path: None,
        data_directory: None,
        extra_args: None,
        torrc: None,
        bbr_profile: None,
        disable_chrome_parrot: None,
        network: None,
        quic: None,
        congestion_control: None,
        udp_relay_mode: None,
        zero_rtt_handshake: None,
        heartbeat: None,
        version: None,
        psk: None,
        userkey: None,
        reuse: None,
        obfs_mode: None,
        obfs_host: None,
        mode: None,
        idle_session_check_interval: None,
        idle_session_timeout: None,
        min_idle_session: None,
        path: None,
        headers: None,
        tls: None,
        transport: None,
        multiplex: None,
        server_ports: None,
        hop_interval: None,
        udp_over_tcp: None,
        udp_fragment: None,
        user: None,
        private_key: None,
        private_key_path: None,
        private_key_passphrase: None,
        host_key: None,
        host_key_algorithms: None,
        client_version: None,
        cipher: None,
        mac: None,
        kex_algorithm: None,
        outbounds: None,
        default: None,
        interrupt_exist_connections: None,
        extra: serde_json::Map::new(),
    };
    let direct_interface = config
        .network_interfaces
        .as_ref()
        .and_then(|policy| non_empty_interface(policy.direct.as_deref()));
    apply_bind_interface(&mut direct_outbound.extra, direct_interface.as_deref());
    outbounds.push(direct_outbound);
    // 【已删除：legacy `{type:"block"}` 出站】（2026-08-13）
    //
    // 它此前唯一的用途是承载「出口选阻断」：`proxy-selector.default = "block"`。现在阻断由
    // `builder::route` 在规则级表达（所有「→代理」改写成 `action:"reject"` + 无 matcher 兜底），
    // 这个出站就没有引用者了。
    //
    // 删而不是留着不用：留着就还有第二条能走通的路 —— `fix_dead_references` 的兜底是「outbound
    // 指向不存在的 tag ⇒ 改指 proxy-selector」，即将来若某处又误发 `outbound:"block"` 而出站不在，
    // **用户想阻断的流量会被静默改成走代理**。靠门正面钉死「不得再出现 block 出站/引用」，
    // 而不是靠保留一个死出站兜底。
    //
    // 触发这次迁移的是一条运行期事实（真核实测）：legacy block 每拦一条连接打一行
    // `ERROR ... outbound/block[block]: operation not permitted`，`log.level=warn` 过滤不掉；
    // 本仓核日志单文件 + 满则轮转一次，停在阻断态会把之前的排障线索挤出去。`reject` 只在 DEBUG 打。

    // probe pool selectors。
    for (k, _port) in deps.probe_pool_ports.iter().enumerate() {
        let mut members = node_tags.clone();
        members.push(DIRECT_TAG.to_string());
        outbounds.push(selector_outbound(
            &format!("probe-selector-{k}"),
            "selector",
            members,
            Some(DIRECT_TAG),
            true,
        ));
    }

    // ── Shadow-TLS 后处理（Polaris L1055-1093）──
    // 遍历已生成 outbounds，有 shadowTlsSettings 的节点 → 创建外层 `stls-out-<id>` shadowtls outbound，
    // 主 outbound 的 detour 指向它（内层 SS 经 detour 走 shadowtls 拨号）。
    apply_shadow_tls_postprocess(config, &id_to_tag, &mut outbounds);

    // ── detour 死引用迭代修剪（Polaris L1095-1178）──
    // 任何 outbound.detour / endpoint.detour 指向「生成集合内不存在的 tag」→ 剔除引用方 +
    // selector 成员清理 + gateInvalidNodes 记录。
    // 选中节点死引用 → 抛错（调用方转用户可见错误）。迭代收敛到无死引用。
    let selected_server = config
        .selected_server_id
        .as_deref()
        .and_then(|sid| config.servers.iter().find(|s| s.id == sid));
    prune_detour_dead_references(
        deps,
        &mut id_to_tag,
        &mut outbounds,
        &mut pending_endpoints,
        selected_server,
    )?;

    Ok(OutboundsResult {
        outbounds,
        pending_endpoints,
        pending_rule_selectors,
    })
}

/// `server.detour`（**节点 id**）→ 生成集合里的 **outbound tag**；不可用一律 `None`。
///
/// 三条排除，逐条与本函数抽出前的代理 outbound 腿逐字等价（行为保持，不是新策略）：
///  1. 目标 id 不在 `config.servers` 里 → `None`；
///  2. 沿 `detour` 链走成环（含自指）→ `None`；
///  3. **目标是 endpoint 协议 → `None`**。
///
/// # 为什么抽出来（不是整洁癖）
///
/// 本轮给 WG / WARP / Tailscale 三种 endpoint 也接上了 detour（对 上游的有意偏离，见
/// `singbox/endpoint.rs` 的 `Endpoint::detour`）。若各腿各写一份解析，「代理腿排除了 endpoint 目标、
/// endpoint 腿忘了排」这种偏斜就只能靠人眼守。同一个函数 ⇒ 排除 3 对四条腿（代理 / WG / WARP / TS）
/// 同时成立，`endpoint_detour_target_endpoint_excluded` 那道门测的也是它。
///
/// # 排除 3 为什么在这一批保持保守
///
/// endpoint→endpoint 是否可行**没有结论**：`sing-box check` 根本不做 detour 的引用解析（指向不存在
/// 的 tag 也 rc=0），拿它验只能得出「schema 接受」，阴性对照立不住。故沿用代理腿早就在用的同一条
/// 排除，不在这一批放开。要放开须先有真核实测。
fn resolve_detour_tag(
    server: &ServerConfig,
    config: &UserConfig,
    id_to_tag: &BTreeMap<String, String>,
) -> Option<String> {
    let detour_id = server.detour.as_ref()?;
    let detour_srv = config.servers.iter().find(|s| &s.id == detour_id)?;
    // 环检测：从 server 出发沿 detour 链走，撞到已见过的 id 即成环。
    let mut seen = std::collections::BTreeSet::new();
    seen.insert(server.id.clone());
    let mut cur = Some(detour_id.clone());
    while let Some(c) = cur {
        if seen.contains(&c) {
            return None;
        }
        seen.insert(c.clone());
        cur = config
            .servers
            .iter()
            .find(|s| s.id == c)
            .and_then(|s| s.detour.clone());
    }
    // 判据是 `lands_in_endpoints`：endpoint 腿的节点其 tag 根本不在 `outbounds[]` 里，指向它的 detour
    // 是悬空引用 —— 引用方整个节点会被剪掉并上报 invalid。从前这里只认 WG/TS，openconnect /
    // openvpn-client 漏在外面。
    if lands_in_endpoints(detour_srv.protocol) {
        return None;
    }
    id_to_tag.get(detour_id).cloned()
}

/// Shadow-TLS 后处理：为带 shadowTlsSettings 的节点创建外层 shadowtls outbound 并链接 detour。
/// 上游 `buildOutbounds` L1055-1093。
fn apply_shadow_tls_postprocess(
    config: &UserConfig,
    id_to_tag: &BTreeMap<String, String>,
    outbounds: &mut Vec<Outbound>,
) {
    let mut stls_outbounds: Vec<Outbound> = Vec::new();
    for ob in outbounds.iter_mut() {
        // 根据 tag 反查 ServerConfig（selector/direct/block 等非节点出站匹配不到 → 跳过）。
        let srv_id = id_to_tag
            .iter()
            .find(|(_, t)| *t == &ob.tag)
            .map(|(id, _)| id.clone());
        let Some(srv_id) = srv_id else { continue };
        let Some(srv) = config.servers.iter().find(|s| s.id == srv_id) else {
            continue;
        };
        if srv.shadow_tls_settings.is_none() {
            continue;
        }

        // 创建独立的外层 ShadowTLS outbound（issue #147：外层是真正 TCP 拨号目标）。
        // ShadowTLS 外层才是真正对公网 server 发起 TCP 拨号的一跳；bind 留在内层 Shadowsocks
        // 不会约束物理 socket。把同一份显式/运行时绑定转交外层，避免“配置里有键但实际未生效”。
        let bind_interface = ob
            .extra
            .remove("bind_interface")
            .and_then(|value| value.as_str().map(str::to_owned));
        let stls_outbound = build_shadow_tls_outbound(srv, bind_interface.as_deref())
            .expect("shadow_tls_settings was checked above");
        let stls_tag = stls_outbound.tag.clone();
        stls_outbounds.push(stls_outbound);

        // 主 outbound（原本的 shadowsocks）保留为 proxy，detour 指向新增的 shadowtls outbound。
        ob.detour = Some(stls_tag);
    }
    outbounds.extend(stls_outbounds);
}

/// 把某个已被剔除的 tag 从所有 selector（proxy-selector + 各 rule-sel）的成员表里摘掉，
/// 并在它恰好是某个 selector 的 `default` 时重算 default。
fn drop_tag_from_selectors(outbounds: &mut [Outbound], removed_tag: &str) {
    use crate::builder::outbound_helpers::pruned_selector_default;
    for sel in outbounds.iter_mut() {
        if sel.type_field != "selector" {
            continue;
        }
        if let Some(members) = sel.outbounds.as_mut() {
            members.retain(|t| t != removed_tag);
        }
        if sel.default.as_deref() == Some(removed_tag) {
            let remaining = sel.outbounds.clone().unwrap_or_default();
            sel.default = pruned_selector_default(Some(&sel.tag), &remaining);
        }
    }
}

/// detour 死引用迭代修剪。上游 `buildOutbounds` L1095-1178（**endpoint 腿是 Polaris 增补**）。
///
/// 反复扫描：剔一个引用方可能让别的 detour 链断裂，收敛到不再有死引用。
/// 选中节点的 detour 死引用 → 返回 Err（调用方转用户可见错误）。
///
/// # 射程为什么必须含 `pending_endpoints`（本轮扩的那一格）
///
/// 抽出前它只扫 `outbounds`，因为**当时 endpoint 不可能带 detour**：`Endpoint` 结构体没有这个字段，
/// 自定义 endpoint 腿又显式 `obj.remove("detour")`。本轮给 WG/WARP/TS 接上 detour 后，
/// 「endpoint.detour 指向一个生成集合里不存在的 tag」立刻成为可达状态 —— 而 sing-box 对
/// **未解析的 detour 引用是起核即 FATAL**，不是忽略。故 endpoint 必须同样被扫。
///
/// # 有效 tag 集为什么仍只取自 `outbounds`（不含 endpoint tag）
///
/// 这不是遗漏，是把 `resolve_detour_tag` 的排除 3（detour 目标不得是 endpoint）在剪枝层再兑现一次：
/// endpoint tag 不进 `valid_tags` ⇒ 任何指向 endpoint 的 detour 天然算死引用。两层同向，
/// 绕过发射层排除（例如自定义 endpoint 的 raw JSON）也兜得住。
///
/// # 为什么 endpoint 只需在 outbound 收敛**之后**扫一遍（而不是混进同一个 while）
///
/// `valid_tags` 只由 outbound tag 构成 ⇒ **剔除 endpoint 不改变 `valid_tags`** ⇒ 剔 endpoint 不可能
/// 制造出新的 outbound 死引用。反向则会（剔 outbound 会让指向它的 endpoint 变死引用），故顺序是
/// 「outbound 收敛 → endpoint 单遍」，两趟即到不动点，无需嵌套迭代。
fn prune_detour_dead_references(
    deps: &mut OutboundsDeps,
    id_to_tag: &mut BTreeMap<String, String>,
    outbounds: &mut Vec<Outbound>,
    pending_endpoints: &mut Vec<Endpoint>,
    selected_server: Option<&ServerConfig>,
) -> Result<(), String> {
    // tag → server_id 反查（stls-out-<id> 前缀直接提取，其余查 idToTagMap）。
    let tag_to_server_id = |tag: &str, map: &BTreeMap<String, String>| -> Option<String> {
        if let Some(rest) = tag.strip_prefix("stls-out-") {
            return Some(rest.to_string());
        }
        map.iter()
            .find(|(_, t)| *t == tag)
            .map(|(id, _)| id.clone())
    };
    let selected_tag = selected_server.and_then(|s| id_to_tag.get(&s.id).cloned());
    let mut mutated = false;

    loop {
        // 当前有效 tag 集合。
        let valid_tags: std::collections::BTreeSet<String> = outbounds
            .iter()
            .map(|o| o.tag.clone())
            .filter(|t| !t.is_empty())
            .collect();
        // 找第一个 detour 死引用（detour 非 None 且不在 valid_tags 中，且非 proxy-selector）。
        let dead_idx = outbounds.iter().position(|ob| {
            ob.tag != PROXY_SELECTOR_TAG
                && match &ob.detour {
                    Some(d) => !valid_tags.contains(d),
                    None => false,
                }
        });
        let Some(dead_idx) = dead_idx else { break };

        let removed_tag = outbounds[dead_idx].tag.clone();

        // 选中节点的 detour 死引用 → 抛错。
        if selected_tag.as_deref() == Some(&removed_tag) {
            return Err(format!(
                "选中节点「{removed_tag}」的代理链依赖的前置节点不存在，无法启动，请更换节点后重试"
            ));
        }

        let sid = tag_to_server_id(&removed_tag, id_to_tag);
        // 删该引用方 outbound。
        outbounds.remove(dead_idx);
        // 同步剔除所有 selector（proxy-selector + 各 rule-sel）的成员引用 + default 命中重算。
        drop_tag_from_selectors(outbounds, &removed_tag);
        // gateInvalidNodes 记录（id → reason token）。
        if let Some(sid) = &sid {
            id_to_tag.remove(sid);
            deps.gate_invalid_nodes
                .insert(sid.clone(), INVALID_REASON_DETOUR_CASCADE);
        }
        (deps.log)(
            LogLevel::Warn,
            &format!("启动前配置校验：节点「{removed_tag}」的 detour 引用无效，已剔除"),
        );
        mutated = true;
    }

    // ── endpoint 腿（Polaris 增补）：outbound 已收敛，`valid_tags` 自此不再变化，单遍即到不动点。
    {
        let valid_tags: std::collections::BTreeSet<String> = outbounds
            .iter()
            .map(|o| o.tag.clone())
            .filter(|t| !t.is_empty())
            .collect();
        // 先把要剔的 endpoint tag 收齐再统一处理：`retain` 里不能借 `outbounds`。
        let dead_ep_tags: Vec<String> = pending_endpoints
            .iter()
            .filter(|ep| match &ep.detour {
                Some(d) => !valid_tags.contains(d),
                None => false,
            })
            .map(|ep| ep.tag.clone())
            .collect();
        for removed_tag in dead_ep_tags {
            // 选中节点的 detour 死引用 → 抛错（与 outbound 腿同一条文案与语义）。
            if selected_tag.as_deref() == Some(&removed_tag) {
                return Err(format!(
                    "选中节点「{removed_tag}」的代理链依赖的前置节点不存在，无法启动，请更换节点后重试"
                ));
            }
            let sid = tag_to_server_id(&removed_tag, id_to_tag);
            pending_endpoints.retain(|ep| ep.tag != removed_tag);
            drop_tag_from_selectors(outbounds, &removed_tag);
            if let Some(sid) = &sid {
                id_to_tag.remove(sid);
                // 与 outbound 腿同一个 reason token：成因确实是同一个（前置节点不在生成集合里），
                // 用户看到的 tooltip 也该是同一句，不该因为「被剔的是 endpoint」就换个说法。
                deps.gate_invalid_nodes
                    .insert(sid.clone(), INVALID_REASON_DETOUR_CASCADE);
            }
            (deps.log)(
                LogLevel::Warn,
                &format!("启动前配置校验：组网节点「{removed_tag}」的 detour 引用无效，已剔除"),
            );
            mutated = true;
        }
    }

    // selector 剔空 → 抛错（无可用代理节点）。
    if mutated {
        if let Some(selector) = outbounds.iter().find(|o| o.tag == PROXY_SELECTOR_TAG) {
            if selector
                .outbounds
                .as_ref()
                .map(|m| m.is_empty())
                .unwrap_or(true)
            {
                return Err("没有可用的代理节点出站（节点代理链依赖无效）".to_string());
            }
        }
        // rule-sel 剔空（members 全被 detour 死引用剔除）→ 删该 selector outbound。
        // 对应 route 规则的 outbound（rule-sel-<id>）成死引用 → fixRouteDeadReferences 兜底。
        outbounds.retain(|o| {
            !(o.type_field == "selector"
                && o.tag != PROXY_SELECTOR_TAG
                && o.tag.starts_with("rule-sel")
                && o.outbounds.as_ref().map(|m| m.is_empty()).unwrap_or(true))
        });
    }

    Ok(())
}

fn selector_outbound(
    tag: &str,
    type_field: &str,
    members: Vec<String>,
    default: Option<&str>,
    interrupt: bool,
) -> Outbound {
    Outbound {
        type_field: type_field.to_string(),
        tag: tag.to_string(),
        outbounds: if members.is_empty() {
            None
        } else {
            Some(members)
        },
        default: default.map(String::from),
        interrupt_exist_connections: if interrupt { Some(true) } else { None },
        extra: serde_json::Map::new(),
        detour: None,
        server: None,
        server_port: None,
        override_address: None,
        method: None,
        password: None,
        username: None,
        plugin: None,
        plugin_opts: None,
        uuid: None,
        security: None,
        alter_id: None,
        flow: None,
        packet_encoding: None,
        up_mbps: None,
        down_mbps: None,
        obfs: None,
        auth_str: None,
        executable_path: None,
        data_directory: None,
        extra_args: None,
        torrc: None,
        bbr_profile: None,
        disable_chrome_parrot: None,
        network: None,
        quic: None,
        congestion_control: None,
        udp_relay_mode: None,
        zero_rtt_handshake: None,
        heartbeat: None,
        version: None,
        psk: None,
        userkey: None,
        reuse: None,
        obfs_mode: None,
        obfs_host: None,
        mode: None,
        idle_session_check_interval: None,
        idle_session_timeout: None,
        min_idle_session: None,
        path: None,
        headers: None,
        tls: None,
        transport: None,
        multiplex: None,
        server_ports: None,
        hop_interval: None,
        domain_resolver: None,
        udp_over_tcp: None,
        udp_fragment: None,
        user: None,
        private_key: None,
        private_key_path: None,
        private_key_passphrase: None,
        host_key: None,
        host_key_algorithms: None,
        client_version: None,
        cipher: None,
        mac: None,
        kex_algorithm: None,
    }
}

/// rule-sel selector 生成。上游 `generateRuleSelectors`。
fn generate_rule_selectors(
    config: &UserConfig,
    id_to_tag: &BTreeMap<String, String>,
    node_tags: &[String],
    outbounds: &mut Vec<Outbound>,
    pending: &mut Vec<PendingRuleSelector>,
) {
    let mode_str = match config.proxy_mode {
        crate::user_config::ProxyMode::Smart => "smart",
        crate::user_config::ProxyMode::Global => "global",
        crate::user_config::ProxyMode::Direct => "direct",
    };
    let custom = effective_custom_rules(mode_str, config.effective_traffic_rules());
    let app = effective_app_rules(
        config.app_routing_enabled == Some(true),
        mode_str,
        &config.app_rules,
    );
    let interrupt = config.interrupt_connections_on_switch == Some(true);

    let mut existing_tags: std::collections::BTreeSet<String> =
        outbounds.iter().map(|o| o.tag.clone()).collect();

    let emit = |rule_key: &str,
                selector_tag: &str,
                target_server_id: Option<&str>,
                existing_tags: &mut std::collections::BTreeSet<String>,
                outbounds: &mut Vec<Outbound>,
                pending: &mut Vec<PendingRuleSelector>| {
        let mut tag = selector_tag.to_string();
        let mut n = 1;
        while existing_tags.contains(&tag) {
            tag = format!("{selector_tag} ({n})");
            n += 1;
        }
        existing_tags.insert(tag.clone());
        let target_tag = target_server_id.and_then(|tid| id_to_tag.get(tid));
        let default_tag = if let Some(tt) = target_tag {
            if node_tags.contains(tt) {
                tt.clone()
            } else {
                PROXY_SELECTOR_TAG.to_string()
            }
        } else {
            PROXY_SELECTOR_TAG.to_string()
        };
        let mut members = node_tags.to_vec();
        members.push(PROXY_SELECTOR_TAG.to_string());
        // 上游 `generateRuleSelectors`（outbound-builder.ts:762）恒写 interrupt_exist_connections
        // （true|false），非条件省略——rule-sel selector 与 proxy-selector 同形态。此处对齐。
        outbounds.push(Outbound {
            type_field: "selector".into(),
            tag: tag.clone(),
            outbounds: Some(members),
            default: Some(default_tag.clone()),
            interrupt_exist_connections: Some(interrupt),
            extra: serde_json::Map::new(),
            detour: None,
            server: None,
            server_port: None,
            override_address: None,
            method: None,
            password: None,
            username: None,
            plugin: None,
            plugin_opts: None,
            uuid: None,
            security: None,
            alter_id: None,
            flow: None,
            packet_encoding: None,
            up_mbps: None,
            down_mbps: None,
            obfs: None,
            auth_str: None,
            executable_path: None,
            data_directory: None,
            extra_args: None,
            torrc: None,
            bbr_profile: None,
            disable_chrome_parrot: None,
            network: None,
            quic: None,
            congestion_control: None,
            udp_relay_mode: None,
            zero_rtt_handshake: None,
            heartbeat: None,
            version: None,
            psk: None,
            userkey: None,
            reuse: None,
            obfs_mode: None,
            obfs_host: None,
            mode: None,
            idle_session_check_interval: None,
            idle_session_timeout: None,
            min_idle_session: None,
            path: None,
            headers: None,
            tls: None,
            transport: None,
            multiplex: None,
            server_ports: None,
            hop_interval: None,
            domain_resolver: None,
            udp_over_tcp: None,
            udp_fragment: None,
            user: None,
            private_key: None,
            private_key_path: None,
            private_key_passphrase: None,
            host_key: None,
            host_key_algorithms: None,
            client_version: None,
            cipher: None,
            mac: None,
            kex_algorithm: None,
        });
        pending.push(PendingRuleSelector {
            rule_key: rule_key.to_string(),
            selector_tag: tag,
            member_tag: default_tag,
            target_server_id: target_server_id.map(String::from),
        });
    };

    for rule in &custom {
        if !rule.enabled || rule.route_action() != Some(crate::user_config::rule::RuleAction::Proxy)
        {
            continue;
        }
        emit(
            &format!("custom:{}", rule.id),
            &format!("rule-sel-{}", rule.id),
            rule.route_target_server_id(),
            &mut existing_tags,
            outbounds,
            pending,
        );
    }
    for app_rule in &app {
        if !app_rule.enabled || app_rule.action != crate::user_config::rule::RuleAction::Proxy {
            continue;
        }
        emit(
            &format!("app:{}", app_rule.app_id),
            &format!("rule-sel-app-{}", app_rule.app_id),
            app_rule.target_server_id.as_deref(),
            &mut existing_tags,
            outbounds,
            pending,
        );
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests;
