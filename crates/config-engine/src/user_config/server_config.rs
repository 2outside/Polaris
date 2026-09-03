//! ServerConfig 节点配置（上游 `shared/types.ts ServerConfig` 子集）。
//!
//! 增量定义：仅 endpoint/mesh 相关字段（WG/Tailscale endpoint 路由用）。
//! 协议设置子类型最小投影。随 builder 移植扩展。

#![forbid(unsafe_code)]

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::user_config::normalize::normalize_token;

/// 传输层安全模式（上游 `Security = 'none' | 'tls' | 'reality'`，上游 `shared/types.ts:129`）。
///
/// **为什么是枚举而不是 `Option<String>`**（落地要求 R3）：
/// 裸串 + 严格比较（`security.as_deref() == Some("tls")`）下，任何写入路径塞进 `"TLS"` /
/// `"Reality"` / `"tls "` 变体都会让分支静默不命中 → **TLS/Reality 不启用、无任何报错，
/// 用户以为加密实际明文出站**。这是本类型存在的唯一理由。
///
/// 归一只发生在反序列化边界一次（[`SecurityMode::from_raw`]），之后类型系统保证
/// 不可能再出现大小写变体 —— 不依赖后人记得调归一函数。
///
/// **为什么这个字段类型化、而 `fingerprint`/`flow` 不**：本字段取值集由 Polaris 自身闭合
/// （`none|tls|reality`），类型化无上游漂移风险；且它的误判是**静默**的（分支不命中，
/// sing-box 根本看不到意图）。反观 `fingerprint`/`flow` 取值集由 sing-box 拥有且开放，
/// 且实测误判即 `FATAL`（fail-closed）→ 保留 String + 边界归一即可，见 [`normalize`]。
///
/// [`normalize`]: crate::user_config::normalize
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityMode {
    /// 不启用传输层安全。
    None,
    Tls,
    Reality,
    /// 未知值（订阅脏数据 / 未来新增模式）：保留原文，语义按「非 TLS、非 Reality」处理。
    ///
    /// **刻意不报错**：单个脏字段不应让整个节点反序列化失败而从列表里消失。
    Unknown(String),
}

impl SecurityMode {
    /// 边界归一：trim + ASCII 小写后匹配；未知值保留 trim 后原文。
    ///
    /// 空/缺省视作 [`SecurityMode::None`]（未设置 ≡ 不启用），与订阅里 `security: ""` 的实际语义一致。
    pub fn from_raw(raw: &str) -> Self {
        match normalize_token(raw).as_deref() {
            None | Some("none") => Self::None,
            Some("tls") => Self::Tls,
            Some("reality") => Self::Reality,
            Some(_) => Self::Unknown(raw.trim().to_string()),
        }
    }

    /// 规范文本表示（序列化用）。未知值原样吐回 → 往返不丢用户数据。
    pub fn as_str(&self) -> &str {
        match self {
            Self::None => "none",
            Self::Tls => "tls",
            Self::Reality => "reality",
            Self::Unknown(s) => s,
        }
    }

    /// 是否启用 TLS。**判定唯一入口** —— 禁止在别处写 `== "tls"` 字符串比较。
    pub fn is_tls(&self) -> bool {
        matches!(self, Self::Tls)
    }

    /// 是否启用 Reality。**判定唯一入口** —— 禁止在别处写 `== "reality"` 字符串比较。
    pub fn is_reality(&self) -> bool {
        matches!(self, Self::Reality)
    }
}

impl Serialize for SecurityMode {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SecurityMode {
    /// 大小写不敏感反序列化。
    ///
    /// 不用 `#[serde(rename_all = "lowercase")]`（只管序列化方向，反序列化仍严格匹配），
    /// 也不用 `#[serde(alias)]` 穷举（`"reality"` 需 2^7=128 条别名，不可维护）。
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        Ok(Self::from_raw(&String::deserialize(de)?))
    }
}

/// 节点协议（上游 `Protocol`，子集——仅当前 builder 所需 + endpoint 全集）。
///
/// 🔴 **反序列化必须保持严格小写、不得加别名或大小写不敏感解析**（同文件的 [`SecurityMode`] 恰好是
/// 宽容解析的活先例，别照抄过来）。`polaris::runtime::proxy` 的 A4 早退闸有一条**廉价判据**
/// （`ProxyRuntime::selected_exit_is_tailscale`）绕过本类型、直接在原始 JSON 上比 `protocol ==
/// "tailscale"`；它与 `login_fallback_eligible` 的等价性正建立在「本类型只认小写」之上。一旦这里
/// 放宽，`"Tailscale"` 会变成 `eligible=true` 而廉价判据为假 ⇒ **engage 帧被闸吃掉**，未登录的
/// Tailscale 出口永远等不到让位。
///
/// 要改这里，先去改那条判据（并在其文档里对着改回来）。`protocol_deserialization_is_case_strict`
/// 是这条契约的绊线。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Vless,
    Trojan,
    Hysteria2,
    Shadowsocks,
    Anytls,
    Tuic,
    Vmess,
    Naive,
    Snell,
    Socks,
    Http,
    Ssh,
    Wireguard,
    Tailscale,
    // ── 2026-08-11 补：随包核支持而本仓此前无表单的三个出站 ──
    // 判据是「随包核 check 收不收」而不是「schema 里有没有」——`sing-box generate schema` 实测
    // 漏了 `snell`（它接受 snell 出站），故全集从实测来。
    //
    // ⚠️ **`shadowtls` 不在这里，且不是遗漏**：它在本仓是 shadowsocks 的**插件设置**
    // （`ShadowTlsSettings`），生成侧自动造外层 `stls-out-<id>` 出站并把主出站的 detour 指过去
    // （`builder/outbounds.rs` 的 Shadow-TLS 后处理段）。那才是它的正确形态 —— 它是传输层不是出口，
    // 建成独立协议只会让用户建完选中它、然后握手得上却出不去网。
    // 判「支不支持」的判据是**生成侧能不能产出该 outbound type**，不是「协议白名单里有没有它」。
    /// Hysteria **v1**（与既有 `Hysteria2` 是两个协议，不是版本字段）。
    Hysteria,
    /// 内嵌 Tor 客户端：**无 server/port**（实测传 `server` 得 `unknown field "server"`），
    /// 与 `Tailscale` 同属「无地址协议」。
    Tor,
    // ── 端点族 VPN 客户端（2026-08-11）──
    // 二者在内核里属 `$defs/Endpoint`，塞进 `outbounds[]` 会 `unknown outbound type`（实测）
    // ⇒ 进 [`lands_in_endpoints`]。
    //
    // 是否进 [`is_mesh_protocol`] 则**不由协议决定，由节点决定**（见 `is_mesh_node`）：那条判据是
    // 「配置期能否声明可达网段」，而这两个协议的网段是服务端在隧道建立后 push 的，配置期不可知。
    // 用户在 `meshRoutes` 里显式声明了段，该节点才具备组网能力。
    // 2026-08-13 前这里写的是「语义上是普通 VPN 出口，不是组网」—— 那是不可验证的主观表述，
    // 已换成上面这条代码可推、可写门的判据。
    /// OpenConnect：一个类型覆盖六家商用 VPN，由 `flavor` 区分
    /// （anyconnect / gp / fortinet / f5 / pulse / nc）。
    Openconnect,
    /// OpenVPN 客户端。`tls` 是**必填**——缺了内核判 `initialize endpoint[0]: missing \`tls\` options`。
    /// 只做 client；server 端不做（用户裁定）。
    ///
    /// **本变体是全枚举里唯一需要 per-variant rename 的**：枚举级 `rename_all = "lowercase"` 会把它
    /// 折成 `openvpnclient`，而**内核类型名、store 白名单、UI `NodeProto` 三处都是 `openvpn-client`**。
    /// 少了这行的后果实测过，两个方向都是用户可见故障：
    /// · UI 建的节点写 `"openvpn-client"` → `UserConfig` 反序列化 `unknown variant` →
    ///   **整份配置解析失败**（不是丢这一个节点，是全部节点连同设置一起没了）；
    /// · 导入侧产出序列化成 `"openvpnclient"` → 不在 `ALLOWED_PROTOCOLS` 里 → sanitize **静默丢节点**。
    /// `alias` 收下折叠拼法，让任何已经落过盘的旧值仍读得回来。
    /// 三处登记表的一致性由 `crates/store/tests/protocol_registries_agree.rs` 钉住。
    #[serde(rename = "openvpn-client", alias = "openvpnclient")]
    OpenvpnClient,
    Custom,
}

/// WireGuard 设置（上游 `WireGuardSettings`）。sing-box 1.11+ endpoint，默认 gVisor 用户态。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireGuardSettings {
    #[serde(rename = "privateKey", skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(
        rename = "localAddress",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub local_address: Vec<String>,
    #[serde(rename = "peerPublicKey", skip_serializing_if = "Option::is_none")]
    pub peer_public_key: Option<String>,
    #[serde(rename = "preSharedKey", skip_serializing_if = "Option::is_none")]
    pub pre_shared_key: Option<String>,
    #[serde(rename = "allowedIPs", default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_ips: Vec<String>,
    #[serde(rename = "allowInternet", skip_serializing_if = "Option::is_none")]
    pub allow_internet: Option<bool>,
    #[serde(rename = "alwaysRouteSubnets", skip_serializing_if = "Option::is_none")]
    pub always_route_subnets: Option<bool>,
    #[serde(
        rename = "persistentKeepalive",
        skip_serializing_if = "Option::is_none"
    )]
    pub persistent_keepalive: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reserved: Vec<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    #[serde(rename = "reverseMesh", skip_serializing_if = "Option::is_none")]
    pub reverse_mesh: Option<bool>,
    #[serde(rename = "warpDevice", skip_serializing_if = "Option::is_none")]
    pub warp_device: Option<crate::user_config::protocol_settings::WarpDevice>,
}

/// Tailscale 设置（上游 `TailscaleSettings`）。账号制 mesh，sing-box endpoint。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleSettings {
    #[serde(rename = "authKey", skip_serializing_if = "Option::is_none")]
    pub auth_key: Option<String>,
    #[serde(rename = "allowInternet", skip_serializing_if = "Option::is_none")]
    pub allow_internet: Option<bool>,
    #[serde(rename = "alwaysRouteSubnets", skip_serializing_if = "Option::is_none")]
    pub always_route_subnets: Option<bool>,
    #[serde(rename = "exitNode", skip_serializing_if = "Option::is_none")]
    pub exit_node: Option<String>,
    #[serde(
        rename = "exitNodeAllowLanAccess",
        skip_serializing_if = "Option::is_none"
    )]
    pub exit_node_allow_lan_access: Option<bool>,
    #[serde(rename = "acceptRoutes", skip_serializing_if = "Option::is_none")]
    pub accept_routes: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<String>,
    #[serde(rename = "controlUrl", skip_serializing_if = "Option::is_none")]
    pub control_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<bool>,
    #[serde(
        rename = "advertiseRoutes",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub advertise_routes: Vec<String>,
    #[serde(rename = "reverseMesh", skip_serializing_if = "Option::is_none")]
    pub reverse_mesh: Option<bool>,
    #[serde(
        rename = "advertiseTags",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub advertise_tags: Vec<String>,
    #[serde(rename = "sshServer", skip_serializing_if = "Option::is_none")]
    pub ssh_server: Option<bool>,
    #[serde(rename = "relayServerPort", skip_serializing_if = "Option::is_none")]
    pub relay_server_port: Option<u16>,
    /// WireGuard / P2P 流量的 UDP 监听端口（sing-box 1.14.0-beta.15 新增 `listen_port`）。
    ///
    /// 缺省由 tsnet 随机选。固定它才能在上游路由/防火墙上做端口映射 —— 这直接决定能不能与对端
    /// 直连打洞，还是恒回落 DERP 中继。与 [`Self::relay_server_port`] 是**两件事**：那个是本机作
    /// peer relay 时的**入站中继**监听口，本字段是自己这条 WireGuard 腿的出/入口。
    #[serde(rename = "listenPort", skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    #[serde(rename = "resolveByName", skip_serializing_if = "Option::is_none")]
    pub resolve_by_name: Option<bool>,
    #[serde(
        rename = "acceptDefaultResolvers",
        skip_serializing_if = "Option::is_none"
    )]
    pub accept_default_resolvers: Option<bool>,
}

/// 节点配置（上游 `ServerConfig` 全字段）。buildOutbounds 消费。
/// CustomSettings 含 serde_json::Value（非 Eq）→ 不 derive Eq。
///
/// # 为什么少数几个 `*_settings` 是 `Option<Box<T>>` 而其余是 `Option<T>`
///
/// 本结构体是**按值**装进 `UserConfig::servers: Vec<ServerConfig>` 的，故 `size_of::<Self>()`
/// 直接乘以节点数：每次 `from_value::<UserConfig>` 都要为这个 `Vec` 连续分配 `n × size_of`
/// （Vec 增长期峰值再翻一倍），每次 `ServerConfig::clone` 都要按这个宽度 memcpy。而 20+ 个协议
/// 设置子结构**全部内联**时，一个节点无论实际用哪个协议都得背上全部协议的宽度。
///
/// 装箱的判据是 **体积大 × 极少出现**（2026-08-17 实测 `size_of` 逐个量过，牙在本文件的
/// `server_config_stays_narrow`）：openvpnClient 280 B / ssh 264 B / openconnect 232 B /
/// [`WireGuardSettings`] 216 B / [`TailscaleSettings`] 192 B / hysteria2 184 B / hysteria 160 B /
/// snell 128 B / tor 120 B / http 104 B / shadowsocks 96 B / ws 88 B —— 合计 2064 B，
/// 占装箱前 3096 B 的 67%，而它们对应的协议/传输在真实配置里近乎不出现。
/// 装箱后各占 8 B，只有真正带该协议设置的节点才付一次堆分配。
/// 实测口径：3096 B → 1904 B（前六项）→ 1512 B（补 wireguard / tailscale）→
/// 1128 B（补 snell / http / shadowsocks / ws）。
///
/// **两者的出现率证据不同强度，分开记**（真机 60 节点配置实测均 0/60，但那只是一台机器一份配置）：
///
/// - `tailscaleSettings` 有**近似结构性的上限**：`store/src/sanitize.rs` 的 `first_tailscale`
///   只留第一个 tailscale 节点、其余整条剔除（前端 `tailscaleSlotTaken` 同源）。
///   ⚠️ 该闸**只按 `protocol == "tailscale"` 计数**，且同函数里那段 `tailscaleSettings` 清洗对**所有**
///   保留节点都跑、只洗 CIDR 不剥键 ⇒ 一个协议不是 tailscale 却挂着该键的脏节点既不占槽也不被清掉。
///   所以准确说法是「**tailscale 协议节点**恒 ≤ 1」，不是「该键的出现率恒 ≤ 1/n」。实践上后者仍成立
///   （没有写入路径会给非 TS 节点造这个键），但它是经验而非闸门保证。
///
/// - `wireguardSettings` **能被订阅量产，N 无界** —— 这条别再写成「量产腿产不出它」：
///   三条量产导入腿里，分享链接侧 `wireguard://` 不在 `is_supported_share_url`（实测）、Clash 侧
///   `clash_parser.rs` 恒填 `None`（WG 不在 Clash proxies 支持面），**但 sing-box JSON 订阅这条腿能**：
///   `subscription.rs` 的 `SingboxJson` 分支无条件把 `endpoints[]` 交给 `parse_singbox_endpoints`，
///   那里的 `"wireguard"` 臂**不看 `origin`**（隔壁 `openconnect`/`openvpn-client` 臂才有
///   `if origin != ImportOrigin::LocalFile` 闸），直接进 `map_wireguard_endpoint` 填本字段；而订阅刷新
///   正是以 `ImportOrigin::RemoteSubscription` 调进来的。前端批量准入 `meshSingletonConflict` 也只挡
///   WARP 与 tailscale，普通 WG **不占槽、无上限**。「机场下发 WireGuard 组网」本就是这条腿的立项理由
///   （见 `parse_subscription` 头注）。
///
/// **即便如此仍该装**，因为盈亏平衡点极高：WG 内联 216 B，装箱后在场节点付 `8 B + 224 B` glibc chunk
/// （`align16(216+8)`）= 232 B ⇒ 每节点亏 **16 B**；缺席节点省 `216−8 = 208 B` ⇒
/// `p* = 208/224 ≈ 92.9%`。也就是说**哪怕全库 100% 是 WG 节点，代价也只有 16 B/节点加一次 malloc**，
/// 而常见的「一个 WG 都没有」直接省 208 B/节点。TS 同法：chunk `align16(192+8)` = 208，
/// 在场亏 24 B、缺席省 184 B，`p* = 184/208 ≈ 88.5%`。判据的「罕见」在这两项上不是必要条件，
/// 只是把收益放大 —— 这与 `tlsSettings` 那种 `p*` 只有 87.5–95.5% 却实测 60/60 的情形是两回事。
///
/// **第三批（snell / http / shadowsocks / ws）的账同法逐项算**（glibc chunk = `align16(size + 8)`，
/// 在场亏 `8 + chunk − size`、缺席省 `size − 8`、`p* = (size − 8) / chunk`；四项真机实测均 **0/60**）：
///
/// | 字段 | 内联 | chunk | 在场亏 | 缺席省 | `p*` |
/// |---|---|---|---|---|---|
/// | `snellSettings` | 128 B | 144 B | 24 B | 120 B | 83.3% |
/// | `httpSettings` | 104 B | 112 B | 16 B | 96 B | 85.7% |
/// | `shadowsocksSettings` | 96 B | 112 B | 24 B | 88 B | 78.6% |
/// | `wsSettings` | 88 B | 96 B | 16 B | 80 B | 83.3% |
///
/// 四项的 `p*` 都在 78–86%，而实测出现率 0% —— 离盈亏平衡点远得不构成取舍。
/// 其中 `wsSettings` 的出现率最不牢靠（`ws` 是最常见的传输之一，换一份订阅源就可能不是 0），
/// 但即便**全库 100% 走 ws**，代价也只有 16 B/节点加一次 malloc。
///
/// **`tlsSettings` 刻意不装箱**（176 B）：它是**最常出现**的那个 —— 绝大多数 vless/trojan/vmess
/// 节点都带它（真机实测 60/60）。装箱后每个 TLS 节点省下 168 B 内联却多付 176 B 堆加一次 malloc，
/// 字节上近乎打平甚至更差，且它的调用面是全部协议设置里最大的一个（2026-08-17 `\btls_settings\b`
/// 全仓实测 80 处，次大的 wireguard 42 / tailscale 32）。判据是「大 × 罕见」，不是「大」。
/// 它在**本文件 + `protocol_settings.rs` 全部 21 个子结构**里排第 7，只在 `protocol_settings.rs`
/// 单独排序时才是第 5 —— 别引用后一个排名做取舍。装箱面补到 12 项后它仍是**最大的未装箱项**，
/// 也就是「为压数字而装箱」最诱人的那个目标，故门里有一条**独立的内联断言**无条件钉住它
/// （`size_of_val(&s.tls_settings) > 8`）。登记表里那条 `Exempt` 理由是**说明**，不是牙 ——
/// 登记表只查「登记与代码一致」，把字段装箱、同时把登记改成 `Boxed` 它就自洽了（实测全绿）。
///
/// ⚠️ **取样面教训（同一根因复发过三次，第三次的处方不是文档而是门）**：
/// wireguard / tailscale 是第一批漏掉的 —— 那次按**定义所在模块**枚举候选，只扫了
/// `protocol_settings.rs` 里的子结构，而这两个定义在本文件，整个不在取样面内；
/// snell / http / shadowsocks / ws 是第二批漏掉的 —— 那次改按字段枚举，但清单仍是**人写的**。
/// 后果都是「判据没错、清单不全」，且漏掉的项都比当时装的某些项更该装
/// （`snellSettings` 128 B > 已装的 `torSettings` 120 B，出现率同为 0/60）。
/// **前两次的处方都是「在文档里留一份清单」，而那正是失败过两次的方案。**
/// 第三次改成自曝式：`server_config_stays_narrow` 里的登记表，判据面由 serde 交出全部字段名，
/// 表不会自己长而探针会 ⇒ 下一个漏网的大字段当场转红。要增删协议设置，先读那道门的文档注释。
///
/// 🔴 **桌上还剩什么（按字段枚举，2026-08-17 `size_of_val` 逐个实测，按宽度降序）**：
///
/// | 未装箱字段 | 宽度 | 备注 |
/// |---|---|---|
/// | `tlsSettings` | 176 B | **刻意内联**，账见上文；不是候选（门里登记为 `Exempt`） |
/// | ~~`snellSettings` 128 / `httpSettings` 104 / `shadowsocksSettings` 96 / `wsSettings` 88~~ | — | ✅ 已装箱（第三批，省 384 B） |
/// | `tuicSettings` / `shadowTlsSettings` | 各 80 B | **仍在桌上，共 144 B**：`p* = 75%`、实测 0/60，账是正的 |
/// | 其余（custom 64 / anyTls 56 / multiplex 48 / reality 48 / grpc 32 / naive 1） | ≤64 B | 收益递减；`reality` 边缘可做（`p* = 62.5%` vs 实测 50%） |
///
/// 之所以第三批不顺手连 tuic/shadowTls 一起做：每项都要各自过一遍调用面 + 各自进三态透明门，
/// 夹带会让 diff 失去可审性。**这是排期，不是否决。**
/// ⚠️ 这段清单**不许在补装后删掉改写成回顾** —— 第二批就是把它写成回顾性教训、前瞻内容随之消失，
/// 下一个人读到的是「清单已补齐」而不是「还有 X B 在桌上」，于是同一根因连着复发了三次。
/// 补装某项时**只划掉那一行**（像上面第二行那样），别动整段。
/// 三个仍在桌上的候选各自的账已经登记在 `server_config_stays_narrow` 的 `Considered` 行里，
/// 那里是**有牙的**一份：门槛一旦降到它们以下就会转红。本段与那张表任一处改动都要对着改另一处。
///
/// 装箱**不改变任何序列化产物**：`Box<T>` 的 `Serialize`/`Deserialize` 逐字转发给 `T`，
/// `skip_serializing_if = "Option::is_none"` 语义不变，`Debug`/`PartialEq` 同样转发。
///
/// ⚠️ **钉住这件事的只有本文件那条 `boxed_protocol_settings_serialize_transparently`**，
/// 别以为「反正还有几道既有门兜着」就可以删它 —— 2026-08-17 逐条实测过那三道对**十二个**装箱键的射程：
/// `tests/serde_roundtrip.rs` 全文件只碰 `singbox::*`，`UserConfig`/`ServerConfig` **零出现**
/// （唯一一处是 `servers: vec![]`）；
/// `tests/user_config_key_contract.rs` 的夹具同样是 `"servers": []`，十二个键 **0 命中**；
/// `tests/golden_config_snapshot.rs` 的 `fixtures/config-snapshot.json`（37 case）命中六个：
/// `hysteria2Settings` × 1 / `sshSettings` × 1 / `wireguardSettings` × 1 /
/// `snellSettings` × 2 / `shadowsocksSettings` × 2 / `wsSettings` × 2，
/// 另外六个（含 `tailscaleSettings` / `httpSettings`）**0 命中**。
/// 即：两道射程为零、一道覆盖 12 个里的 6 个，且那一道只走**生成侧**（UserConfig → sing-box 配置），
/// 磁盘往返与订阅导入导出这两条腿一条都不碰。删掉本文件那条 = 保护归零。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServerConfig {
    pub id: String,
    pub name: String,
    pub protocol: Protocol,
    /// 🔴 `default` 不可去（2026-07-31 真机阻断级缺陷）：**账号制协议本就没有服务器地址**。
    ///
    /// 契约在 `crates/store/src/sanitize.rs:271` —— 那里 `tailscale` / `custom` **豁免**
    /// address/port 校验、有意保留这类节点；其余协议缺 address 或 port∉1..=65535 直接剔除。
    /// 此处若必填，就是在下一层用**协议盲**的判据把上一层特意放行的东西再拒一次，两层契约打架。
    ///
    /// 后果不是「那个节点用不了」而是整机不可用：`proxy_start` 反序列化的是**整份 UserConfig**，
    /// 一个无 address 的 TS 节点 ⇒ `missing field \`address\`` ⇒ 127 个节点的配置全体解析失败 ⇒
    /// 连接按钮恒失败。真机日志实证：``[home] connect toggle failed: 配置解析失败（UserConfig）:
    /// missing field `address` ``，而磁盘上那个 TS 节点的键只有
    /// id/name/protocol/tailscaleSettings/createdAt/updatedAt。
    ///
    /// 「那非账号协议缺 address 岂不静默变空串」—— 那道门没丢，只是留在 sanitize（它知道 protocol，
    /// 这里不知道）。**别把它挪回来**：挪回来就重现本缺陷。
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub port: u16,
    /// 代理链（前置代理）ID。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detour: Option<String>,
    /// 手动节点的物理出口网卡覆盖。订阅节点忽略本字段，改读订阅级策略。
    #[serde(rename = "bindInterface", skip_serializing_if = "Option::is_none")]
    pub bind_interface: Option<String>,
    /// 用户声明的「经该节点可达的内网段」（CIDR）。**仅 endpoint 腿的 VPN 客户端
    /// （openconnect / openvpn-client）读它**，是这两个协议获得组网资格的唯一途径
    /// （见 [`is_mesh_node`]）。
    ///
    /// # 为什么它们需要用户手填，而 WG/TS 不用
    ///
    /// WireGuard 的段是用户填的 `allowedIPs`、Tailscale 的是协议固定的 tailnet 段 —— 生成配置那一刻
    /// 就已知。OpenVPN / OpenConnect 的段由**服务端在隧道建立后 push**，配置期不可知，内核侧对应的
    /// 是 `redirect_private` / `route_no_pull` 这类「要不要收下服务端下发的路由」的开关，不是网段本身。
    /// 所以「连公司 VPN，只走公司网段，其余直连」这个用法，WG 用户填个 allowedIPs 就有，而这两个协议
    /// 此前只能去规则页手写 CIDR 指向该节点。本字段补的就是这条不对称。
    ///
    /// # 为什么在 ServerConfig 顶层而不在各自的 settings 结构里
    ///
    /// `OpenconnectSettings` / `OpenvpnClientSettings` 的 **serde 名 = sing-box 键名**，整体序列化后
    /// flatten 进 `Endpoint::extra` 下发。往里加一个内核不认识的键 = 给内核发未知字段（实测硬报错），
    /// 且会破坏那两个结构写在头注里的既定契约。顶层字段不进下发载荷，`detour` 是同型先例。
    ///
    /// 与 WG 的 `allowedIPs` 有一处**语义差别**：`allowedIPs` 兼任栈内 cryptokey 过滤（不在表里的包
    /// 被丢），两处生效；本字段只喂 `route.rules`，OpenVPN/OpenConnect 客户端侧没有对应的过滤层。
    #[serde(rename = "meshRoutes", default, skip_serializing_if = "Vec::is_empty")]
    pub mesh_routes: Vec<String>,
    #[serde(rename = "subscriptionId", skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    #[serde(rename = "providerName", skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,
    // VLESS
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<String>,
    /// XTLS flow（`xtls-rprx-vision` 等）。取值集由 sing-box 拥有 → 保留 String，边界归一。
    #[serde(
        default,
        deserialize_with = "crate::user_config::normalize::de_opt_token",
        skip_serializing_if = "Option::is_none"
    )]
    pub flow: Option<String>,
    #[serde(rename = "packetEncoding", skip_serializing_if = "Option::is_none")]
    pub packet_encoding: Option<String>,
    // Trojan/Hysteria2 通用
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    // Naive
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(rename = "naiveSettings", skip_serializing_if = "Option::is_none")]
    pub naive_settings: Option<crate::user_config::protocol_settings::NaiveSettings>,
    // VMess
    #[serde(rename = "alterId", skip_serializing_if = "Option::is_none")]
    pub alter_id: Option<u32>,
    /// VMess 加密方式（`auto`/`aes-128-gcm`/...）。sing-box 拥有取值集 → String + 边界归一。
    #[serde(
        rename = "vmessSecurity",
        default,
        deserialize_with = "crate::user_config::normalize::de_opt_token",
        skip_serializing_if = "Option::is_none"
    )]
    pub vmess_security: Option<String>,
    // 协议设置子结构
    #[serde(rename = "hysteria2Settings", skip_serializing_if = "Option::is_none")]
    pub hysteria2_settings: Option<Box<crate::user_config::protocol_settings::Hysteria2Settings>>,
    #[serde(rename = "tuicSettings", skip_serializing_if = "Option::is_none")]
    pub tuic_settings: Option<crate::user_config::protocol_settings::TuicSettings>,
    /// Hysteria **v1**（与 `hysteria2_settings` 是两个协议，不是同一协议的版本字段）。
    #[serde(rename = "hysteriaSettings", skip_serializing_if = "Option::is_none")]
    pub hysteria_settings: Option<Box<crate::user_config::protocol_settings::HysteriaSettings>>,
    /// 内嵌 Tor（无 server/port）。
    #[serde(rename = "torSettings", skip_serializing_if = "Option::is_none")]
    pub tor_settings: Option<Box<crate::user_config::protocol_settings::TorSettings>>,
    /// OpenConnect（端点族，非组网）。
    #[serde(
        rename = "openconnectSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub openconnect_settings:
        Option<Box<crate::user_config::protocol_settings::OpenconnectSettings>>,
    /// OpenVPN 客户端（端点族，非组网）。
    #[serde(
        rename = "openvpnClientSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub openvpn_client_settings:
        Option<Box<crate::user_config::protocol_settings::OpenvpnClientSettings>>,
    #[serde(rename = "wireguardSettings", skip_serializing_if = "Option::is_none")]
    pub wireguard_settings: Option<Box<WireGuardSettings>>,
    #[serde(rename = "tailscaleSettings", skip_serializing_if = "Option::is_none")]
    pub tailscale_settings: Option<Box<TailscaleSettings>>,
    #[serde(rename = "customSettings", skip_serializing_if = "Option::is_none")]
    pub custom_settings: Option<crate::user_config::protocol_settings::CustomSettings>,
    #[serde(rename = "anyTlsSettings", skip_serializing_if = "Option::is_none")]
    pub any_tls_settings: Option<crate::user_config::protocol_settings::AnyTlsSettings>,
    #[serde(rename = "multiplexSettings", skip_serializing_if = "Option::is_none")]
    pub multiplex_settings: Option<crate::user_config::protocol_settings::MultiplexSettings>,
    #[serde(
        rename = "shadowsocksSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub shadowsocks_settings:
        Option<Box<crate::user_config::protocol_settings::ShadowsocksSettings>>,
    #[serde(rename = "snellSettings", skip_serializing_if = "Option::is_none")]
    pub snell_settings: Option<Box<crate::user_config::protocol_settings::SnellSettings>>,
    #[serde(rename = "sshSettings", skip_serializing_if = "Option::is_none")]
    pub ssh_settings: Option<Box<crate::user_config::protocol_settings::SshSettings>>,
    #[serde(rename = "shadowTlsSettings", skip_serializing_if = "Option::is_none")]
    pub shadow_tls_settings: Option<crate::user_config::protocol_settings::ShadowTlsSettings>,
    // 传输层
    /// 传输层类型（`tcp`/`ws`/`grpc`/`http`/`h2`/`httpupgrade`）。R3 覆盖项 → 边界归一。
    /// 未归一时 `"WS"` 会走到 `generate_transport_config` 的 `_ => None` 分支静默丢传输层。
    #[serde(
        default,
        deserialize_with = "crate::user_config::normalize::de_opt_token",
        skip_serializing_if = "Option::is_none"
    )]
    pub network: Option<String>,
    /// 传输层安全模式。类型化根治静默 TLS/Reality 降级，见 [`SecurityMode`]。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<SecurityMode>,
    #[serde(rename = "tlsSettings", skip_serializing_if = "Option::is_none")]
    pub tls_settings: Option<crate::user_config::protocol_settings::TlsSettings>,
    #[serde(rename = "realitySettings", skip_serializing_if = "Option::is_none")]
    pub reality_settings: Option<crate::user_config::protocol_settings::RealitySettings>,
    #[serde(rename = "wsSettings", skip_serializing_if = "Option::is_none")]
    pub ws_settings: Option<Box<crate::user_config::protocol_settings::WebSocketSettings>>,
    #[serde(rename = "grpcSettings", skip_serializing_if = "Option::is_none")]
    pub grpc_settings: Option<crate::user_config::protocol_settings::GrpcSettings>,
    #[serde(rename = "httpSettings", skip_serializing_if = "Option::is_none")]
    pub http_settings: Option<Box<crate::user_config::protocol_settings::HttpSettings>>,
    // 元数据
    #[serde(rename = "createdAt", skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(rename = "updatedAt", skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// 组网协议。上游 `isEndpointProtocol`（本仓改名，理由见下）。
///
/// # 判据：配置期就能声明可达网段
///
/// 命中者，生成侧能在**生成配置的那一刻**为它发 force-route 规则，让它的网段常驻可达：
/// WireGuard 的段是用户填的 `allowedIPs`，Tailscale 的是协议固定的 tailnet 两族段 + `routes`。
/// 判据的唯一实现是 [`crate::builder::endpoint_routes::endpoint_forced_route_cidrs`]，
/// 那个函数有来源的协议就该在这里命中，没有的就不该 —— 两者由 `mesh_protocol_matches_cidr_source`
/// 对拍，加协议时漏改一边即红。
///
/// # 这**不是**「落在 `endpoints[]` 里的协议」
///
/// 那是内核的数据模型形态，openconnect / openvpn-client 同样落在 `endpoints[]`（塞
/// `outbounds[]` 得 `unknown outbound type`，实测），但它们的网段由服务端在隧道建立后 push，
/// 配置期不可知 ⇒ 不属本判据。**这个函数从前叫 `is_endpoint_protocol`，名字说的是数据模型、
/// 成员集给的是组网 —— 两者不重合的那两个协议上，消费点按名字选谓词就选错了，实际造成过三处缺陷**
/// （临时测速核把它们塞进 `outbounds[]` 致整核 FATAL、detour 指向它们成悬空引用、
/// 承流播种漏掉它们致该重启时不重启）。要判数据模型形态用 [`lands_in_endpoints`]。
pub fn is_mesh_protocol(p: Protocol) -> bool {
    matches!(p, Protocol::Wireguard | Protocol::Tailscale)
}

/// 落 sing-box 顶层 `endpoints[]`（而非 `outbounds[]`）的协议 —— **内核的数据模型形态**。
///
/// 与 [`is_mesh_protocol`] 是两件事：那个判「能不能声明网段」（产品能力），这个判「JSON 该塞哪个数组」
/// （内核形态）。四个协议命中，前两个两者皆是，后两个只是形态。
///
/// 射程：`custom` 协议的 endpoint 腿（`customSettings.isEndpoint`）也落 `endpoints[]`，但那要看
/// 节点的设置而非协议，本函数看不到 ⇒ 调用点若需覆盖它，须自行并上那一支（`speedtest.rs` 的
/// `build_temp_node` 就是先判 custom-endpoint 再走本判据）。
pub fn lands_in_endpoints(p: Protocol) -> bool {
    matches!(
        p,
        Protocol::Wireguard | Protocol::Tailscale | Protocol::Openconnect | Protocol::OpenvpnClient
    )
}

/// 该**节点**是否具备组网能力 —— [`is_mesh_protocol`] 的节点级形态。
///
/// 判据仍是「配置期能否声明可达网段」，只是对 openconnect / openvpn-client 而言，这件事由**用户填没填
/// [`ServerConfig::mesh_routes`]** 决定，不由协议决定：填了，生成侧就能为它发 force-route 规则，它
/// 与一个填了 `allowedIPs` 的 WireGuard 节点在路由上再无分别；没填，它就只是个普通出口。
///
/// 分组、force-route 发射、热切换判定这些**看能力**的消费点用本函数；判 JSON 该塞哪个数组用
/// [`lands_in_endpoints`]；只在拿不到整个节点时才退回 [`is_mesh_protocol`]。
pub fn is_mesh_node(s: &ServerConfig) -> bool {
    is_mesh_protocol(s.protocol)
        || (matches!(s.protocol, Protocol::Openconnect | Protocol::OpenvpnClient)
            && s.mesh_routes.iter().any(|c| !c.trim().is_empty()))
}

#[cfg(test)]
mod tests;
