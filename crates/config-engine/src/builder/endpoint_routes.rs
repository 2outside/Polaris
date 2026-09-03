//! 组网 endpoint 路由纯逻辑（上游 `shared/endpoint-routes.ts` 1:1 移植）。
//!
//! endpointForcedRouteCidrs / meshAllowsInternet / meshAlwaysRoutesSubnets /
//! shouldForceRouteSubnets / collectRuleTargetedServerIds / meshForceRoutedServers /
//! meshForcedRouteCidrs（buildInbounds 依赖的核心子集）。

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use crate::user_config::app_config::UserConfig;
use crate::user_config::collections::{dedupe, dedupe_trim};
use crate::user_config::dns_constants::is_sentinel_selection;
use crate::user_config::rule::{Rule, RuleAction};
use crate::user_config::server_config::{is_mesh_node, lands_in_endpoints, Protocol, ServerConfig};

/// 全网段（catch-all）。上游 `FULL_TUNNEL_CIDRS`。
pub const FULL_TUNNEL_CIDRS: &[&str] = &["0.0.0.0/0", "::/0"];

/// Tailscale tailnet v4 段（CGNAT）。上游 `TAILNET_CGNAT`。
pub const TAILNET_CGNAT: &str = "100.64.0.0/10";

/// Tailscale v6 tailnet 段（ULA 前缀）。上游 `TAILNET_ULA_V6`。
pub const TAILNET_ULA_V6: &str = "fd7a:115c:a1e0::/48";

/// System 模式内核接口固定名（TS）。原 上游 `polaris-ts`，改名 `polaris-ts`（§D.2 品牌改名）。
pub const TS_SYSTEM_INTERFACE_NAME: &str = "polaris-ts";

/// System 模式内核接口固定名（WG）。原 上游 `polaris-wg`，改名 `polaris-wg`。
pub const WG_SYSTEM_INTERFACE_NAME: &str = "polaris-wg";

fn is_catch_all(c: &str) -> bool {
    FULL_TUNNEL_CIDRS.contains(&c.trim())
}

/// 剥离全网段（catch-all），仅留具体段。上游 `stripCatchAll`。
pub fn strip_catch_all(cidrs: &[String]) -> Vec<String> {
    cidrs.iter().filter(|c| !is_catch_all(c)).cloned().collect()
}

/// CIDR 列表是否含任一全网段。上游 `hasCatchAll`。
pub fn has_catch_all(cidrs: &[String]) -> bool {
    cidrs.iter().any(|c| is_catch_all(c))
}

/// 该组网节点应被「强制路由到自身 tag」的具体 CIDR。上游 `endpointForcedRouteCidrs`。
///
/// 三个来源，都是**配置期已知**的段（这正是 `is_mesh_protocol` / `is_mesh_node` 的判据）：
///  - WireGuard：`allowedIPs` 去 catch-all；WARP 没有子网广播能力，恒为空；
///  - Tailscale：tailnet 两族段 + `routes` 去 catch-all；
///  - openconnect / openvpn-client：用户在 `meshRoutes` 里显式声明的段（这两个协议的段本由服务端
///    运行期 push、配置期不可知，故只认用户手填的那份）。
///
/// 非组网协议 → `[]`。
pub fn endpoint_forced_route_cidrs(server: &ServerConfig) -> Vec<String> {
    let raw: Vec<String> = match server.protocol {
        Protocol::Wireguard => {
            if crate::warp::is_warp_server(server) {
                return vec![];
            }
            let allowed = server
                .wireguard_settings
                .as_ref()
                .map(|w| w.allowed_ips.clone())
                .unwrap_or_default();
            strip_catch_all(&allowed)
        }
        Protocol::Tailscale => {
            let routes = server
                .tailscale_settings
                .as_ref()
                .map(|t| t.routes.clone())
                .unwrap_or_default();
            let mut raw = vec![TAILNET_CGNAT.to_string(), TAILNET_ULA_V6.to_string()];
            raw.extend(strip_catch_all(&routes));
            raw
        }
        // 用户手填的内网段。去 catch-all 与另两支同理：0/0 属「全隧道」意图，由各自的出网开关
        // 表达（OpenVPN 是 `redirect_gateway`），混进 force-route 会绕过那个开关。
        Protocol::Openconnect | Protocol::OpenvpnClient => strip_catch_all(&server.mesh_routes),
        _ => return vec![],
    };
    dedupe_trim(raw)
}

/// 组网节点是否允许作外网出口（缺省 true）。上游 `meshAllowsInternet`。
/// WG：allowInternet !== false；WARP 恒为云出口；TS：!!exitNode（allowInternet 由 exit_node 派生）。
pub fn mesh_allows_internet(server: &ServerConfig) -> bool {
    match server.protocol {
        Protocol::Wireguard => {
            crate::warp::is_warp_server(server)
                || server
                    .wireguard_settings
                    .as_ref()
                    .and_then(|w| w.allow_internet)
                    .unwrap_or(true)
        }
        Protocol::Tailscale => server
            .tailscale_settings
            .as_ref()
            .and_then(|t| t.exit_node.as_deref())
            .map(|e| !e.trim().is_empty())
            .unwrap_or(false),
        // OpenVPN 的全隧道开关。**缺省判 true**（同 WG 的 `allow_internet` 那支）：判 false 的后果是
        // 用户选了该节点作出口、流量却被兜底回 direct —— 静默走明文，比多一次黑洞更坏。故只在用户
        // **显式**关掉时才认为它不承载全隧道，而那恰是「只走公司内网段」的表达。
        // OpenConnect 无对应开关（本就是全隧道），落 `_ => true`。
        Protocol::OpenvpnClient => server
            .openvpn_client_settings
            .as_ref()
            .and_then(|o| o.redirect_gateway)
            .unwrap_or(true),
        _ => true,
    }
}

/// 组网节点是否「始终路由其内网段」（缺省 true）。上游 `meshAlwaysRoutesSubnets`。
pub fn mesh_always_routes_subnets(server: &ServerConfig) -> bool {
    match server.protocol {
        Protocol::Wireguard => server
            .wireguard_settings
            .as_ref()
            .and_then(|w| w.always_route_subnets)
            .unwrap_or(true),
        Protocol::Tailscale => server
            .tailscale_settings
            .as_ref()
            .and_then(|t| t.always_route_subnets)
            .unwrap_or(true),
        _ => true,
    }
}

/// 组网节点是否启用 system 内核接口（reverseMesh）。上游 `meshUsesSystemInterface`。
/// WG：reverseMesh（WARP 否决）；TS：reverseMesh。
pub fn mesh_uses_system_interface(server: &ServerConfig) -> bool {
    match server.protocol {
        Protocol::Wireguard => {
            // WARP 恒否决：它是 anycast 出口、不是子网路由器，不可被反向访问，system 对它无意义；
            // 而 `system:true` 会与主 TUN / 另一 System 接口抢内核 utun →
            // `post-start endpoint/wireguard[Cloudflare WARP]: Connect: resource busy` **FATAL**。
            // 判据与前端 `isWarpServer` 同源（见 crate::warp）——导入配置 / 手改 config.json /
            // 上游 迁移这三条腿不经渲染端，前端那道否决在这里挡不住。
            if crate::warp::is_warp_server(server) {
                return false;
            }
            server
                .wireguard_settings
                .as_ref()
                .and_then(|w| w.reverse_mesh)
                .unwrap_or(false)
        }
        Protocol::Tailscale => server
            .tailscale_settings
            .as_ref()
            .and_then(|t| t.reverse_mesh)
            .unwrap_or(false),
        _ => false,
    }
}

/// 组网节点是否承载全隧道默认出口（= 允许外网）。上游 `meshNodeCarriesFullTunnel`。
pub fn mesh_node_carries_full_tunnel(server: &ServerConfig) -> bool {
    mesh_allows_internet(server)
}

/// WireGuard peer.allowed_ips（Layer A cryptokey）。上游 `wireguardPeerAllowedIps`。
/// allowInternet=on → specific ∪ {0/0,::/0}；off → specific（空则 None=FATAL）。
pub fn wireguard_peer_allowed_ips(server: &ServerConfig) -> Option<Vec<String>> {
    let specific = endpoint_forced_route_cidrs(server);
    if mesh_node_carries_full_tunnel(server) {
        let mut all = specific;
        all.extend(FULL_TUNNEL_CIDRS.iter().map(|s| s.to_string()));
        Some(crate::user_config::collections::dedupe(all))
    } else if specific.is_empty() {
        None
    } else {
        Some(specific)
    }
}

/// 组网节点是否「关外网且无可路由网段」→ 不可发射。上游 `isMeshNodeUnroutable`。
pub fn is_mesh_node_unroutable(server: &ServerConfig) -> bool {
    if server.protocol == Protocol::Wireguard {
        wireguard_peer_allowed_ips(server).is_none()
    } else {
        false
    }
}

/// 平台是否支持组网 System 内核接口（Windows 禁）。上游 `meshSystemSupportedOnPlatform`。
pub fn mesh_system_supported_on_platform(platform: &str) -> bool {
    !platform.eq_ignore_ascii_case("win32")
}

/// 该组网节点的 force-route 段本轮是否应发射。上游 `shouldForceRouteSubnets`。
/// alwaysRouteSubnets ON → 恒发；OFF → 仅 engaged（选中/被规则指向）时发。
pub fn should_force_route_subnets(
    server: &ServerConfig,
    selected_server_id: Option<&str>,
    rule_targeted_server_ids: &BTreeSet<String>,
) -> bool {
    if mesh_always_routes_subnets(server) {
        return true;
    }
    if Some(server.id.as_str()) == selected_server_id {
        return true;
    }
    rule_targeted_server_ids.contains(&server.id)
}

/// 收集「显式指向某节点」的规则目标 id（enabled && proxy && targetServerId）。
/// 上游 `collectRuleTargetedServerIds`。接受 Rule + AppRule 混合。
pub fn collect_rule_targeted_server_ids(rules: &[Rule]) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for r in rules {
        if r.enabled && r.route_action() == Some(RuleAction::Proxy) {
            if let Some(tid) = r.route_target_server_id() {
                ids.insert(tid.to_string());
            }
        }
    }
    ids
}

/// 本轮「实际会发射 force-route」的组网节点。上游 `meshForceRoutedServers`。
pub fn mesh_force_routed_servers(
    servers: &[ServerConfig],
    selected_server_id: Option<&str>,
    rule_targeted_server_ids: &BTreeSet<String>,
) -> Vec<ServerConfig> {
    servers
        .iter()
        .filter(|s| is_mesh_node(s))
        .filter(|s| should_force_route_subnets(s, selected_server_id, rule_targeted_server_ids))
        .cloned()
        .collect()
}

/// 全部节点的 mesh force-route 段并集（去重）。上游 `meshForcedRouteCidrs`。
pub fn mesh_forced_route_cidrs(servers: &[ServerConfig]) -> Vec<String> {
    let all: Vec<String> = mesh_force_routed_servers(servers, None, &BTreeSet::new())
        .iter()
        .flat_map(endpoint_forced_route_cidrs)
        .collect();
    dedupe(all)
}

/// custom-endpoint 的 raw JSON（`customSettings.outbound`）是否含「独立承载流量」语义键。
///
/// 深度扫（递归任意嵌套，含 peers[].allowed_ips），命中任一即真。
/// 上游 `customEndpointCarriesTraffic`（endpoint-routes.ts L163-172）。
fn custom_endpoint_carries_traffic(raw: &serde_json::Value) -> bool {
    match raw {
        serde_json::Value::Array(arr) => arr.iter().any(custom_endpoint_carries_traffic),
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if CARRY_TRAFFIC_KEYS.contains(&k.as_str()) {
                    return true;
                }
                if custom_endpoint_carries_traffic(v) {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

/// custom-endpoint 承载流量的语义键集合。上游 `CARRY_TRAFFIC_KEYS`。
///
/// ⚠️ **这个集合的覆盖面由「内核支持哪些端点类型」决定，不由「写它时手边有哪些类型」决定。**
/// 2026-08-11 补 OpenVPN 三键前，全表都是 WireGuard / Tailscale 的词汇 —— 而随包核
/// （1.14.0-beta.12，tags 含 `with_openvpn` / `with_openconnect`）的 `$defs/Endpoint` 有 5 支：
/// wireguard / tailscale / openconnect / openvpn-client / openvpn-server。逐支对过：
///   · openconnect —— 路由类键只有 `system`，**原表已覆盖**；
///   · openvpn-client —— 另有 `redirect_gateway`（OpenVPN 的全隧道开关，等价 WG 的
///     `allowed_ips: 0.0.0.0/0`）、`redirect_private`、`route_no_pull`，**原表一个都不认**。
///
/// 补进来**不要求**先证明「`redirect_gateway:true` 且 `system:false` 时内核是否真独立导流」：
/// 本判据的既定安全方向是「过度纳入只多一次重启、绝不错跳」，而漏纳入的后果写在调用点
/// （`can_skip_restart_for_added_unreferenced` 那段）—— 走 defer 腿不重启、核继续用旧参数出网
/// 且无任何提示。不确定时按方向站队，不是按证据强弱站队。
const CARRY_TRAFFIC_KEYS: &[&str] = &[
    "system",
    "system_interface",
    "allowed_ips",
    "routes",
    "route_address",
    "route_exclude_address",
    "accept_routes",
    "advertise_routes",
    "exit_node",
    // ── OpenVPN（2026-08-11）──
    "redirect_gateway",
    "redirect_private",
    "route_no_pull",
];

/// 选中该节点时，成功生成的配置是否**必定**把它发射为 outbound/endpoint。
///
/// **Sound under-approximation**：返回 `true` ⇒ 一定发射；返回 `false` ⇒ **不确定**（可能发射、
/// 也可能被跳过），调用方须按保守方向处理。逐条对应 `builder/outbounds.rs` 发射循环（:127-234）：
/// - naive 缺 libcronet 时，`generate.rs` 的 selected-server 前置校验会在构建 selector **之前**终止
///   整次生成；有 libcronet 时必定发射。因此它不存在“成功生成但 selector 静默落到其它节点”的腿；
/// - WireGuard（:147-161）：无可路由段、或缺 privateKey/peerPublicKey/localAddress → 不发射。
///   这些判据全是 `ServerConfig` 的纯函数，故**直接调 `build_wireguard_endpoint` 取真判据**，
///   不在此复刻条件清单——复刻会随构建腿改动静默漂移，而漂移方向恰好是「误判必定发射」＝错跳。
///   tag / resolver / platform 三个参数不影响 Ok/Err，传占位值；
/// - custom（两条腿）：`customSettings.outbound` 不是**带 string `type` 的对象**就会被发射循环剔除
///   并记进 `invalid_nodes`（`INVALID_REASON_CUSTOM_MALFORMED`）→ 故此处同判
///   [`custom_outbound_type`](crate::user_config::protocol_settings::custom_outbound_type)。
///   注意这条从前写的是「endpoint 腿反序列化可能失败 → 恒不确定」——那个失败腿已随 raw 透传消失，
///   取而代之的是形状判据；而**非** endpoint 的 custom 从前恒记「必定发射」，那在补上形状 gate
///   之后是**不成立**的（形状坏的 custom outbound 现在会被剔），故必须一并收紧，否则这个
///   sound under-approximation 就朝「误判必定发射」＝错跳重启的方向破了；
/// - Tailscale 的非法 `control_url` 会在发射循环中被剔除；其余 Tailscale 与普通代理 outbound
///   无失败腿 → 必定发射。
///
/// 外部注入的 `gate_invalid_nodes` 不建模：两个生成入口都传空集。发射循环自身会写入的
/// Tailscale / custom 静态剔除门已在上面逐项复用；detour 剪枝若命中选中节点则返回 `Err`，不会形成
/// “成功生成但 selector 静默回退”的第三条腿。
fn selected_server_precludes_selector_fallback(s: &ServerConfig) -> bool {
    match s.protocol {
        Protocol::Naive => true,
        Protocol::Wireguard => {
            crate::builder::endpoints::build_wireguard_endpoint(s, "", None, "", None).is_ok()
        }
        Protocol::Tailscale => s
            .tailscale_settings
            .as_ref()
            .and_then(|settings| settings.control_url.as_deref())
            .and_then(crate::user_config::control_url::tailscale_control_url_reject)
            .is_none(),
        Protocol::Custom => s.custom_settings.as_ref().is_some_and(|c| {
            crate::user_config::protocol_settings::custom_outbound_type(&c.outbound).is_some()
        }),
        _ => true,
    }
}

/// `proxy-selector` 的 default 是否**可能**落到「非选中节点」的兜底节点上。
///
/// `build_outbounds`（`outbounds.rs:262-271`）在「选中节点的 tag 不在本轮已发射 tag 集合里」时，
/// 把 default 落到 `node_tags.first()`——那个节点随即承载**全部**代理流量，但它的 id 无法从
/// `UserConfig` 静态算出（取决于生成期跳过了谁，而那依赖运行期能力）。本谓词只回答
/// 「是否处于该状态」，把「是谁」交给调用方按保守方向兜。
///
/// 返回 `false` 仅两条：① 直连哨兵（default 恒 = `direct` 出站，无节点承载）；
/// ② 选中节点存在**且** `selected_server_precludes_selector_fallback`（此时成功生成的配置里
/// default 恒 = 选中节点 tag）。
/// 其余一律 `true`——含「未选节点」（`selected_tag` 是字面量 `"proxy"`，匹配不到任何节点）
/// 与「悬空选中」（id→tag 解析不到）。
///
/// **同型第二处一并覆盖**：`prune_detour_dead_references` 经 `pruned_selector_default`
/// 重算 default（`outbounds.rs:568-578`）只在「被剔 tag == 当前 default」时触发；而 default ==
/// 选中节点 tag 时该路径返回 Err（`outbounds.rs:558`）而非静默重算 ⇒ 静默重算必然发生在本谓词
/// 已为 `true` 的状态下，无需第二道判据。
pub fn selector_default_may_fall_back(config: &UserConfig) -> bool {
    let Some(sid) = config.selected_server_id.as_deref() else {
        return true; // 未选节点 → selected_tag 恒为字面量 "proxy" → 必落兜底
    };
    if is_sentinel_selection(Some(sid)) {
        return false; // direct / block 哨兵 → default 恒 = 内置出站（direct / block），无节点承载
    }
    match config.servers.iter().find(|s| s.id == sid) {
        None => true, // 悬空选中 → id→tag 解析不到 → 必落兜底
        Some(s) => !selected_server_precludes_selector_fallback(s),
    }
}

/// 「被引用节点」id 集——其定义变化会影响运行核实际行为、故必须随之重启。
///
/// = {选中节点} ∪ {所有启用规则(custom/app)目标}，按 detour（前置代理链）传递闭包展开
/// ＋ 保守纳入全部 endpoint 协议节点（WireGuard/Tailscale 可能 force-route 子网/mesh）
/// ＋ [`selector_default_may_fall_back`] 成立时纳入**全部**节点（兜底 default 承载全部流量、
/// 但它是谁静态算不出）。
/// 安全方向：过度纳入只多一次重启、绝不错跳。上游 `referencedServerIds`。
pub fn referenced_server_ids(config: &UserConfig) -> BTreeSet<String> {
    let by_id: std::collections::BTreeMap<&str, &ServerConfig> =
        config.servers.iter().map(|s| (s.id.as_str(), s)).collect();
    let mut result: BTreeSet<String> = BTreeSet::new();
    let mut stack: Vec<String> = Vec::new();

    let seed = |id: Option<&str>, stack: &mut Vec<String>| {
        if let Some(id) = id {
            // direct / block 哨兵不是节点 id：进了引用集就会当成「悬空选中」被 detour 闭包展开，
            // 白白把全部节点纳入 → 每次配置改动都误判需重启。
            if !is_sentinel_selection(Some(id)) {
                stack.push(id.to_string());
            }
        }
    };
    seed(config.selected_server_id.as_deref(), &mut stack);
    let smart = config.proxy_mode == crate::user_config::proxy_mode::ProxyMode::Smart;
    if smart {
        for r in config.effective_traffic_rules() {
            if r.enabled && r.route_action() == Some(RuleAction::Proxy) {
                seed(r.route_target_server_id(), &mut stack);
            }
        }
    }
    if smart && config.app_routing_enabled == Some(true) {
        for a in &config.app_rules {
            if a.enabled && a.action == RuleAction::Proxy {
                seed(a.target_server_id.as_deref(), &mut stack);
            }
        }
    }
    for s in &config.servers {
        // 判据是 `lands_in_endpoints` 而非组网资格：本播种问的是「谁独立承载流量」，而 endpoint 腿的
        // 节点无论有没有声明网段都自成一条出网路径。漏纳入的后果写在 `CARRY_TRAFFIC_KEYS` 的调用点 ——
        // 走 defer 腿不重启、核继续用旧参数出网且无任何提示。
        if lands_in_endpoints(s.protocol) {
            stack.push(s.id.clone());
        } else if let Some(cs) = &s.custom_settings {
            if cs.is_endpoint.unwrap_or(false) && custom_endpoint_carries_traffic(&cs.outbound) {
                stack.push(s.id.clone());
            }
        }
    }
    // selector default 兜底节点（`outbounds.rs:262-271`）：它承载**全部**代理流量，却不在上面任何
    // 一条播种里——它是「生成期第一个成功发射的节点」，id 取决于生成期跳过了谁（naive 缺 cronet /
    // WG 构建失败 / custom-endpoint 解析失败），`UserConfig` 静态算不出。
    // 漏纳入的后果不是「少一次重启」而是**静默失效**：编辑它会被 `can_skip_restart_for_added_unreferenced`
    // 第③步判「未引用 → 放行」→ 走 defer 腿不重启 → 核继续用旧参数出网且无任何提示
    // （热切腿有 `is_server_dirty` 闸门，defer 腿没有）。
    // 故按本函数的既定安全方向（过度纳入只多一次重启、绝不错跳）：兜底**可能**触发时全员纳入。
    // 该状态本身是降级态（用户选中的出口没进核 / 还没选出口），常态（选中节点必定被发射）不受影响。
    if selector_default_may_fall_back(config) {
        for s in &config.servers {
            stack.push(s.id.clone());
        }
    }
    while let Some(id) = stack.pop() {
        if result.contains(&id) {
            continue; // 成环/重复保护
        }
        result.insert(id.clone());
        if let Some(s) = by_id.get(id.as_str()) {
            if let Some(detour) = &s.detour {
                if by_id.contains_key(detour.as_str()) {
                    stack.push(detour.clone());
                }
            }
        }
    }
    result
}

fn physical_root_ids(
    config: &UserConfig,
    seeds: impl IntoIterator<Item = String>,
) -> BTreeSet<String> {
    let by_id: std::collections::BTreeMap<&str, &ServerConfig> =
        config.servers.iter().map(|s| (s.id.as_str(), s)).collect();

    let resolve_root = |id: &str| -> Option<String> {
        let mut current = *by_id.get(id)?;
        let mut seen = BTreeSet::new();
        loop {
            if !seen.insert(current.id.as_str()) {
                return None;
            }
            let Some(detour) = current.detour.as_deref() else {
                return Some(current.id.clone());
            };
            current = *by_id.get(detour)?;
        }
    };

    let mut roots = BTreeSet::new();
    let mut uncertain = false;
    for id in seeds {
        match resolve_root(&id) {
            Some(root) => {
                roots.insert(root);
            }
            None => uncertain = true,
        }
    }
    if uncertain {
        roots.extend(
            config
                .servers
                .iter()
                .filter_map(|server| resolve_root(&server.id)),
        );
    }
    roots
}

/// 当前运行配置真正可能发起物理公网拨号的根节点 id。
///
/// 播种严格复用 [`referenced_server_ids`]（选中出口、有效流量/应用规则目标、承流 endpoint 与 selector
/// fallback），再沿 detour 收敛到唯一物理根。运行时显式网卡 fail-closed 只检查本集合：闲置节点的本机
/// 网卡策略不得阻断当前出口启动；detour child 自己的 `bindInterface` 也不代表一条物理 socket。
///
/// 活跃链出现环/死引用时无法证明物理根是谁，按保守方向纳入所有可解析物理根。正常配置不付这笔成本；
/// 真正的死引用仍由生成 gate 给出精确错误。
#[must_use]
pub fn active_physical_root_ids(config: &UserConfig) -> BTreeSet<String> {
    physical_root_ids(config, referenced_server_ids(config))
}

/// 当前配置中所有可由 selector / 规则切入的物理拨号根。
///
/// 与 [`active_physical_root_ids`] 的职责刻意分开：前者回答“现在谁承流”，本集合回答“本核存续期间可能
/// 热切到谁”。TUN 必须在接管系统路由前把这些根的逐目的出口一次规划完；否则目标虽已生成在 selector
/// 中，第一次选择仍会因缺路由事实被迫重启，名义热切换退化为冷切换。
#[must_use]
pub fn hot_switch_physical_root_ids(config: &UserConfig) -> BTreeSet<String> {
    physical_root_ids(
        config,
        config.servers.iter().map(|server| server.id.clone()),
    )
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests;
