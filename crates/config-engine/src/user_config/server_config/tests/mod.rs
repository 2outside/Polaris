use super::*;

#[test]
fn endpoint_protocol_classification() {
    assert!(is_mesh_protocol(Protocol::Wireguard));
    assert!(is_mesh_protocol(Protocol::Tailscale));
    assert!(!is_mesh_protocol(Protocol::Vless));
    assert!(!is_mesh_protocol(Protocol::Trojan));
}

/// 判据分离后二者必须是**真子集**关系：组网 ⊂ endpoint 腿。
/// 全协议逐条归档见 `crates/store/tests/protocol_registries_agree.rs`
/// （那边的变体清单有源码对差的完整性门，不必在此再写第二份）。
#[test]
fn mesh_protocols_are_a_strict_subset_of_the_endpoint_leg() {
    for p in [Protocol::Wireguard, Protocol::Tailscale] {
        assert!(is_mesh_protocol(p) && lands_in_endpoints(p), "{p:?}");
    }
    for p in [Protocol::Openconnect, Protocol::OpenvpnClient] {
        assert!(!is_mesh_protocol(p) && lands_in_endpoints(p), "{p:?}");
    }
}

/// endpoint 腿的 VPN 客户端：**声明了内网段才算组网节点**。
///
/// 这条是「组网资格由能力而非协议决定」的唯一判据。空白项不算声明 —— 表单里删干净一行留下的
/// 空串若算数，用户就会得到一个「是组网但没有任何网段」的节点，分组进组网页签却什么都路由不了。
#[test]
fn endpoint_leg_vpn_is_a_mesh_node_only_when_it_declares_routes() {
    let mk = |proto: Protocol, routes: Vec<String>| ServerConfig {
        id: "x".into(),
        protocol: proto,
        mesh_routes: routes,
        ..Default::default()
    };
    for proto in [Protocol::Openconnect, Protocol::OpenvpnClient] {
        assert!(!is_mesh_node(&mk(proto, vec![])), "{proto:?} 未声明");
        assert!(
            !is_mesh_node(&mk(proto, vec!["  ".into()])),
            "{proto:?} 只有空白项 —— 不算声明"
        );
        assert!(
            is_mesh_node(&mk(proto, vec!["10.0.0.0/8".into()])),
            "{proto:?} 已声明"
        );
    }
    // 组网协议与 meshRoutes 无关：WG/TS 的段有自己的来源。
    assert!(is_mesh_node(&mk(Protocol::Wireguard, vec![])));
    assert!(is_mesh_node(&mk(Protocol::Tailscale, vec![])));
    // 普通出站协议即使被塞了 meshRoutes 也不是组网节点（那个字段对它无意义）。
    assert!(!is_mesh_node(&mk(
        Protocol::Vless,
        vec!["10.0.0.0/8".into()]
    )));
}

#[test]
fn server_config_deserialize() {
    let json = r#"{"id":"s1","name":"HK","protocol":"wireguard","address":"1.2.3.4","port":443}"#;
    let s: ServerConfig = serde_json::from_str(json).unwrap();
    assert_eq!(s.protocol, Protocol::Wireguard);
    assert!(s.wireguard_settings.is_none());
}

/// 🔴 账号制节点（tailscale）磁盘上就是没有 address/port —— 键名逐字取自 2026-07-31 真机
/// `config.json`。把 `#[serde(default)]` 去掉 ⇒ 本条报 `missing field \`address\``。
#[test]
fn account_based_node_without_address_or_port_deserializes() {
    let json = r#"{"id":"802f47bd-8c91-47a3-97f6-6ab38964ac20","name":"Sway-Tailscale",
                       "protocol":"tailscale","tailscaleSettings":{},
                       "createdAt":"2026-06-19T17:31:35.564Z","updatedAt":"2026-06-28T07:01:40.490Z"}"#;
    let s: ServerConfig = serde_json::from_str(json).expect("账号制节点必须能反序列化");
    assert_eq!(s.protocol, Protocol::Tailscale);
    assert_eq!(s.address, "");
    assert_eq!(s.port, 0);
}

/// 🔴 真正的爆炸半径：整份 `servers[]` 里**一个**无 address 的节点，不许把其余节点一起带走。
/// 这是真机症状「connect toggle failed: 配置解析失败（UserConfig）」的最小复现 ——
/// 127 个节点里只有一个 TS 节点缺字段，结果整份配置解析失败、连接按钮恒失败。
#[test]
fn one_account_based_node_does_not_break_the_whole_server_list() {
    let json = r#"[
            {"id":"a","name":"VLESS","protocol":"vless","address":"1.2.3.4","port":443},
            {"id":"ts1","name":"Tailscale","protocol":"tailscale","tailscaleSettings":{}},
            {"id":"b","name":"WG","protocol":"wireguard","address":"5.6.7.8","port":51820}
        ]"#;
    let list: Vec<ServerConfig> = serde_json::from_str(json).expect("一个节点不许拖垮整表");
    assert_eq!(list.len(), 3);
    assert_eq!(list[1].address, "");
    // 反向对照：其余节点的 address 必须**原样保留**，不能被 default 抹平 ——
    // 否则这条 default 就从「容忍缺席」滑成「静默丢值」。
    assert_eq!(list[0].address, "1.2.3.4");
    assert_eq!(list[2].port, 51820);
}

// ── SecurityMode 归一（R3）──────────────────────────────────────────────
// 锁死事故形态：大小写变体必须归一到同一枚举，否则 TLS/Reality 静默不启用。

#[test]
fn security_tls_case_variants_all_normalize() {
    for raw in ["tls", "TLS", "Tls", "tLs", " tls ", "\tTLS\n"] {
        assert_eq!(
            SecurityMode::from_raw(raw),
            SecurityMode::Tls,
            "{raw:?} 必须归一为 Tls"
        );
        assert!(
            SecurityMode::from_raw(raw).is_tls(),
            "{raw:?} is_tls 必须真"
        );
    }
}

#[test]
fn security_reality_case_variants_all_normalize() {
    for raw in ["reality", "REALITY", "Reality", "ReAlItY", "  Reality  "] {
        assert_eq!(
            SecurityMode::from_raw(raw),
            SecurityMode::Reality,
            "{raw:?} 必须归一为 Reality"
        );
        assert!(SecurityMode::from_raw(raw).is_reality());
    }
}

#[test]
fn security_none_variants_and_empty() {
    for raw in ["none", "NONE", "None", "", "   "] {
        assert_eq!(SecurityMode::from_raw(raw), SecurityMode::None, "{raw:?}");
    }
    // none 既非 tls 也非 reality。
    assert!(!SecurityMode::None.is_tls());
    assert!(!SecurityMode::None.is_reality());
}

#[test]
fn security_unknown_preserved_and_not_tls() {
    // 脏值/未来模式：保留原文（往返不丢），语义按非 TLS 处理，且**不报错**。
    let m = SecurityMode::from_raw(" xtls ");
    assert_eq!(m, SecurityMode::Unknown("xtls".into()));
    assert_eq!(m.as_str(), "xtls");
    assert!(!m.is_tls(), "未知值不得被当作 TLS");
    assert!(!m.is_reality());
}

#[test]
fn security_deserialize_is_case_insensitive() {
    let json = r#"{"id":"s1","name":"HK","protocol":"vless","address":"a.com","port":443,"security":"TLS"}"#;
    let s: ServerConfig = serde_json::from_str(json).unwrap();
    assert_eq!(s.security, Some(SecurityMode::Tls));
}

#[test]
fn security_dirty_value_does_not_fail_whole_node() {
    // 回归：单个脏 security 不得让整个节点反序列化失败（否则节点从列表消失）。
    let json = r#"{"id":"s1","name":"HK","protocol":"vless","address":"a.com","port":443,"security":"bogus-mode"}"#;
    let s: ServerConfig = serde_json::from_str(json).expect("脏 security 不得导致解析失败");
    assert_eq!(s.security, Some(SecurityMode::Unknown("bogus-mode".into())));
    assert_eq!(s.name, "HK", "其余字段必须完好");
}

#[test]
fn security_serialize_is_canonical_lowercase() {
    // "TLS" 存入 → 序列化出 "tls"（归一后写回，消除存量变体）。
    let json = r#"{"id":"s1","name":"HK","protocol":"vless","address":"a.com","port":443,"security":"Reality"}"#;
    let s: ServerConfig = serde_json::from_str(json).unwrap();
    let out = serde_json::to_value(&s).unwrap();
    assert_eq!(out["security"], serde_json::json!("reality"));
}

#[test]
fn security_unknown_roundtrips_verbatim() {
    let json = r#"{"id":"s1","name":"HK","protocol":"vless","address":"a.com","port":443,"security":"xtls"}"#;
    let s: ServerConfig = serde_json::from_str(json).unwrap();
    let out = serde_json::to_value(&s).unwrap();
    assert_eq!(out["security"], serde_json::json!("xtls"), "未知值往返不丢");
}

#[test]
fn security_absent_stays_absent() {
    let json = r#"{"id":"s1","name":"HK","protocol":"vless","address":"a.com","port":443}"#;
    let s: ServerConfig = serde_json::from_str(json).unwrap();
    assert_eq!(s.security, None);
    let out = serde_json::to_value(&s).unwrap();
    assert!(out.get("security").is_none(), "未设置不得凭空出现");
}

// ── R4 指纹 / flow / network / vmessSecurity 边界归一 ────────────────────

#[test]
fn r4_tokens_normalized_at_deserialize() {
    let json = r#"{"id":"s1","name":"HK","protocol":"vless","address":"a.com","port":443,
            "flow":"XTLS-RPRX-Vision","network":"WS","vmessSecurity":"AES-128-GCM",
            "tlsSettings":{"fingerprint":"Chrome"}}"#;
    let s: ServerConfig = serde_json::from_str(json).unwrap();
    assert_eq!(s.flow.as_deref(), Some("xtls-rprx-vision"));
    assert_eq!(s.network.as_deref(), Some("ws"));
    assert_eq!(s.vmess_security.as_deref(), Some("aes-128-gcm"));
    assert_eq!(
        s.tls_settings.unwrap().fingerprint.as_deref(),
        Some("chrome")
    );
}

/// 🔴 **绊线：`Protocol` 的反序列化必须严格小写**（见该枚举文档的跨 crate 契约）。
///
/// 守的不是本 crate 的行为，而是 `polaris::runtime::proxy` 那条绕过本类型、直接在原始 JSON 上
/// 比 `"tailscale"` 的 A4 早退闸廉价判据。给本类型加宽容解析/别名，会让 `"Tailscale"` 这类写法
/// 变成「完整判据说符合、廉价判据说不符合」⇒ engage 帧被早退闸吃掉，未登录的 TS 出口永不让位。
/// 那条链路上**没有任何测试会因此转红**（等价性测试只喂现存形态），所以绊线必须落在这里。
///
/// **变异探针**：给 `Protocol` 换成 `SecurityMode` 那样的大小写不敏感 `Deserialize` 手写实现
/// （或加 `#[serde(alias = "Tailscale")]`）⇒ 本条转红。
#[test]
fn protocol_deserialization_is_case_strict() {
    assert_eq!(
        serde_json::from_value::<Protocol>(serde_json::json!("tailscale")).unwrap(),
        Protocol::Tailscale,
        "线上字面量恒为小写（`rename_all = \"lowercase\"`）"
    );
    for wrong in ["Tailscale", "TAILSCALE", "TailScale"] {
        assert!(
            serde_json::from_value::<Protocol>(serde_json::json!(wrong)).is_err(),
            "`{wrong}` 必须解析失败 —— 一旦被接受，proxy.rs 那条按 `\"tailscale\"` 比对的 A4 \
                 早退闸就会静默假阴性，engage 帧被吃掉（见 Protocol 的文档注释）"
        );
    }
    // 同文件的宽容解析先例就在隔壁，正向对照一下**它确实宽容** —— 免得日后 `SecurityMode` 也收严
    // 时，上面那组断言被误读成「本文件一律严格」而顺手推广。
    assert_eq!(
        serde_json::from_value::<SecurityMode>(serde_json::json!("REALITY")).unwrap(),
        SecurityMode::from_raw("reality"),
        "对照：SecurityMode 是大小写不敏感的（两者刻意不同口径，别统一）"
    );
}

// ── 装箱协议设置的两道门（结构体头注给的是判据，这里是它的牙）──────────────

/// 🟡 **宽度门**：`ServerConfig` 是**按值**装进 `UserConfig::servers: Vec<ServerConfig>` 的，
/// 它的 `size_of` 直接乘节点数 —— 每次 `from_value::<UserConfig>` 都要为那个 `Vec` 连续分配
/// `n × size_of`（增长期峰值再翻一倍），每次 `ServerConfig::clone` 都按这个宽度 memcpy。
/// 于是「又内联进来一个 200 B 的协议设置」这件事的代价是 `200 × 节点数`，而它**不会让任何
/// 行为测试转红**：序列化产物一个字节不变、全仓功能照常。本门就是补这个盲区。
///
/// 基线（2026-08-17 实测）：装箱前 3096 B，把 12 个「体积大 × 极少出现」的协议设置改
/// `Option<Box<T>>` 后 1128 B（分三批落地：前 6 项 → 1904 B，补 wireguard / tailscale
/// 两项 → 1512 B，再补 snell / http / shadowsocks / ws 四项省
/// `(128−8)+(104−8)+(96−8)+(88−8) = 384 B` → 1128 B）；按真机 119 节点算，单次反序列化的
/// `Vec` 底层分配 368,424 B → 134,232 B。
///
/// **红了不等于有 bug，红了等于「该看一眼」**。字段尺寸之和 = 1124 B，`size_of` = 1128 B ⇒
/// **仍只剩 4 B 尾隙**（装箱不改变尾隙：换掉的字段本就 8 字节对齐）。所以两种情形都会
/// 让上界那条红，处方**完全相反**，先分清是哪一种：
///
/// - **本仓有意新增了一个 ≥8 B 的标量 / 字符串字段**（`meshRoutes` / `disableChromeParrot`
///   就是这个形态，也是本结构体最常见的演进方式）：4 B 尾隙吃不下，**必红**。
///   2026-08-17 逐档实测（当时 1512 B 基线）：`Option<u32>`（8 B）⇒ **1520 红**；
///   `Option<String>`（24 B）⇒ **1536 红**。
///   处方是**重新实测 `size_of` 并连同日期更新常量** —— 不是把那个 24 B 的 String 装箱
///   （那毫无意义，只多一次 malloc）。工具链换版改了布局而本仓一字未动，同理。
///   ⚠️ **≤4 B 的小标量塞得进尾隙，上界那条会保持绿**：同批实测
///   `bool` / `Option<bool>`（1 B）与 `Option<u16>`（4 B）加进来后 `size_of` 不变。
///   那 4 B 是真空位（当前 `protocol` 1 + `port` 2 + `naive_settings` 1 = 4 B 已占的另一半），
///   而 `Option<u16>` 不是假想形态 —— `TailscaleSettings` 里就有两个端口字段是它。
///   这类字段不在**上界**的射程内（它量的是按节点数放大的宽度，4 B 塞进既有空位等于零成本），
///   但**仍会被下面那条登记表拦下**：任何新字段都得在表里露个面。那是登记，不是反对。
///   （例外：`#[serde(skip)]` 的字段不进 `FIELDS`，见漏报面第 6 条。）
/// - **有人又内联了一个大结构体**（几十上百 B 的协议设置）：这才是本门要拦的那一类。
///   按结构体头注的判据（体积大 × 罕见）决定它该不该装箱，**不得为了让它过门而调大常量**。
///
/// 只在 64 位靶子上断言：指针宽度直接进 `Option<Box<_>>` / `String` / `Vec` 的尺寸，32 位上
/// 这个常量没有意义。本仓四条打包腿（mac-arm64 / mac-x64 / linux-x64 / win-x64）全是 64 位。
/// ⚠️ 注意 `cfg` 挂在**整个测试**上：32 位靶子上这道门**等于不存在，不是等于绿**，
/// 且 `cargo test` 不会提示「有测试没编进来」。
///
/// # 🔴 为什么光有上界不够：上界是一个**可以重新基线的**门
///
/// 上界只守判据的「大」那一半，而且守得很软 —— 它的失败文案自己就写着「重新实测并连同日期
/// 更新 MEASURED」。谁新内联一个大结构体，照做一遍常量就绿了。
/// **`snell`(128) / `http`(104) / `shadowsocks`(96) / `ws`(88) 四个字段共 416 B 就是这么在
/// 门全绿的情况下躺过了两批**：它们从来没被枚举到，而上界的常量正是**含着它们**实测出来的。
///
/// 另一半同样漏：把 `tlsSettings` 装箱能让 `size_of` 更小、上界**更绿** —— 而按判据那恰恰
/// 不该做（它 60/60 出现，装箱等于每节点多一次 malloc 换字节打平）。只有上界的门不但不拦
/// 这种「压数字」的改法，还给它发绿灯。**这一半由紧跟其后的那条内联断言接住**，
/// 不是由登记表接住 —— 两者射程不同，见漏报面第 4 条。
///
/// 而「又内联了一个没人注意到的大字段」那一半，上面两条都接不住：**上界是个标量，
/// 看不见「哪些字段、各多宽、谁装了谁没装」**；内联断言只认它点名的那一个字段。
/// 故下面补一张按字段的登记表，判据面由 serde 自己给（见 `FieldProbe`）。
///
/// # 登记表怎么用（改本结构体的人只需读这一段）
///
/// 加字段 ⇒ 表里加一行，四选一：
/// - `Decision::Plain` —— 普通字段，宽度必须**低于门槛**（= 已装箱项里最小的那个）；
/// - `Decision::Boxed(size_of::<T>())` —— 已改 `Option<Box<T>>`，附**被指向结构体**的宽度；
/// - `Decision::Exempt("理由")` —— 宽度已达门槛但刻意保持内联，**理由是硬要求**；
/// - `Decision::Considered("账")` —— 低于门槛但算过账的候选，把结论留下；门槛降到它以下会转红。
///
/// 不加行 ⇒ 完整性断言当场红（表不会自己长，而探针会）。这就是这一批要补的那件事：
/// 前两批的候选面是**人肉枚举**出来的，于是「判据没错、清单不全」连着复发了三次。
///
/// # 目前唯一的豁免项与它的理由强度
///
/// `tlsSettings`（176 B）：真机 60 节点实测 **60/60**，且有独立机制解释（几乎所有
/// vless/trojan/vmess 都带 TLS），调用面也是全部协议设置里最大的（80 处）。
/// 它是唯一一个 ≥ 门槛却保持内联的字段，也是「为压数字而装箱」最诱人的目标 ——
/// 故它另有一条**独立的内联断言**（在登记表之前），那才是钉住这个决定的牙；
/// 本行的 `Exempt` 理由只保证「这个决定被写下来过」。
///
/// 另有三行登记为 `Considered`（低于门槛、账已算过、暂不装）：`tuicSettings` /
/// `shadowTlsSettings` 各 80 B（p\* = 75%、真机 0/60，账是正的，共 144 B 还在桌上，属排期）、
/// `realitySettings` 48 B（p\* = 62.5%、实测 50% ⇒ 净赚仅 8 B/节点，**边缘取舍**，
/// 本仓明确决定不用门冻结它）。**`Considered` 不是禁令**：要装其中任何一个，把那行改成
/// `Boxed` 即可；门槛会随之降低，另外两行会跟着转红要求重新表态 —— 那正是判据一致性该有的连锁。
/// 真要按出现率翻案，先把样本面补厚（多机器 / 多订阅源），别照 `size_of` 排序扩。
///
/// # 🔴 本门登记在案的漏报面（别把它读成「全都守住了」）
///
/// 1. **门槛是相对量**：取「已装箱项的最小宽度」。把当前最小的那个改回内联，门槛会跟着抬高 ⇒
///    自洽地放过它自己（2026-08-17 实测：去掉下限后这一步 20/20 全绿）。故另取一个**下限**
///    `FLOOR`。⚠️ **危险方向是 `FLOOR` 上浮，不是下沉**：`threshold = min(boxed_min, FLOOR)`，
///    `FLOOR` 变小只会让门更严（且被断言强制显式改），而 `FLOOR` 变大会**静默放松门槛**。
///    所以 `FLOOR` 写死字面量而非 `size_of::<WebSocketSettings>()` —— 后者会被一次与装箱无关的
///    正常演进（ws 加个字段）抬上去，实测那样改之后「把 shadowsocks 改回内联」这条本该红的
///    变异会**全绿**。字面量的收益还不只「更严」，**还有归因正确**：同一现场下派生量版会把红
///    打在与本次改动毫无关系的 `tuicSettings` 上（门槛浮到 104 后先撞上它），字面量版则精确
///    指向真正被改回内联的那个字段。剩下两条残留面：
///    ① `FLOOR` 是人写的常量，**装了比它更小的项时不会自动下调**（门槛此时由 `boxed_min`
///    接管，仍正确，只是 `FLOOR` 这条兜底会落后于事实）；
///    ② 上面那条「不得下穿」断言同时给了 `FLOOR` 一个**跟着 ws 走的上限** —— ws 长到 112 之后，
///    把 `FLOOR` 显式改到 112 就不再触发它。与派生量的本质区别是：**那需要一次可 review 的
///    常量编辑，而不是随别人改 `WebSocketSettings` 自动漂移**。门在这里守的是「有人为此负责」，
///    不是「不可能发生」。
/// 2. **`Boxed(w)` 那个 `w` 没有第二处交叉校验**。布局对差只用得上「实际宽度」（装箱项恒 8），
///    看不见被指向类型写没写对。某一行把类型写成一个更大的结构 ⇒ 门槛被抬高 ⇒ 漏报。
/// 3. **只量宽度，不量出现率**。判据的另一半「极少同时出现」没有任何自动来源 —— 门只能逼人
///    「登记 + 写理由」，判断不了那条理由是真是假。一条空洞理由同样能让它变绿。
/// 4. **登记表守的是「登记与代码一致」，不是某个具体决定**。把 `tls_settings` 装箱、同时把
///    它那行从 `Exempt` 改成 `Boxed`，整张表**自洽 ⇒ 全绿**（2026-08-17 实测）。
///    「tlsSettings 必须保持内联」这个决定由上面那条**独立的**内联断言无条件守住，
///    不是由登记表守的。别把两者读成一回事，也别以为删了那条还有登记表兜着。
/// 5. **射程只到本结构体一层**。子结构自己内联了什么（如 `TlsSettings` 里再塞一个大结构）、
///    `UserConfig` 其它 `Vec<T>` 的元素类型，都不在内。
/// 6. **`#[serde(skip)]` / `#[serde(skip_deserializing)]` 的字段不进 `FIELDS`**（本结构体当前
///    一个都没有）⇒ **完整性那条看不见它**。但它并非完全隐形：这类字段不进登记表的宽度和、
///    却实打实占 `size_of`，只要宽于 4 B 尾隙就会被**布局对差那条**接住 ——
///    2026-08-17 实测加一个 176 B 的 `#[serde(skip)]` 字段（并按失败文案调大 `MEASURED`），
///    布局对差当场红。真正隐形的只有 **≤4 B 的 skip 字段**，而那一档本就不在本门射程内
///    （量的是按节点数放大的宽度，塞进既有空位等于零成本）。
///    反过来 `#[serde(flatten)]` 会让 serde 改走 `deserialize_map`、探针一个名字都拿不到 ——
///    那是 fail-loud（完整性那条的第一句断言就红）。
/// 7. 量的是 `size_of`，**不是真实内存占用**：堆上的 `String` / `Vec` 内容不在内。
/// 8. **整道门一次只报第一个失败的断言**，不止 ⑤/⑥ 那两个循环。`assert!` 一红即 panic，
///    后面的一律不执行 —— 尤其：**`tlsSettings` 那条独立内联断言排在登记表之前，它红的时候
///    整张登记表一行都没跑过**（探针、完整性、布局对差、自曝全部未执行）。所以「只报了一条」
///    绝不等于「只有一条有问题」，修完第一条必须重跑，直到绿为止。⑤/⑥ 的 `for` 循环同理：
///    一批新增多个宽字段时要逐个修、逐次重跑，不会一次列全。
/// 9. **32 位靶子上整道门等于不存在，不是等于绿**：整个 `#[cfg(target_pointer_width = "64")]`，
///    `cargo test` 也不会提示「有测试没编进来」。本仓四条打包腿全 64 位，故可接受；
///    哪天有 32 位靶子，这里是零保护。
///
/// 另有一道**不在本门里、但同向**的编译期兜底：`net-stack/clash_parser.rs:649` 那处
/// `ServerConfig` 字面量是**穷举**写法（不带 `..Default::default()`），新增字段会让它编译不过。
/// 那是第二道「新字段不许悄悄溜进来」的牙，只是它报的是编译错误而非门红，且它随时可能被
/// 改成 `..Default::default()` 而消失 —— 不能替代本门的完整性断言。
///
/// **变异探针**（双向对照见提交说明）：
/// - 把 `snell_settings` 改回 `Option<T>` 并把它那行改成 `Plain`（再按实测调小 MEASURED，
///   模拟「照失败文案重新基线」）⇒ 加门前全绿，加门后**自曝那条**红；
/// - 新增一个 ≥ 门槛的未装箱字段 ⇒ 表里缺行，**完整性那条**红；补上行改 `Plain` ⇒ 自曝那条红；
/// - 给 `WebSocketSettings` 加个字段（88 → 112）后再把 `shadowsocks_settings` 改回内联 ⇒
///   `FLOOR` 若是派生量则全绿，写死字面量后**自曝那条**红；
/// - 加一个 176 B 的 `#[serde(skip)]` 字段 ⇒ **布局对差那条**红；
/// - 把 `tls_settings` 改成 `Option<Box<TlsSettings>>` ⇒ 上界照绿（size 更小），
///   **内联断言那条**红；若同时把登记行改成 `Boxed` 则登记表全绿 —— 那正是第 4 条漏报面。
#[test]
#[cfg(target_pointer_width = "64")]
fn server_config_stays_narrow() {
    use crate::user_config::protocol_settings as ps;
    use std::collections::BTreeSet;
    use std::mem::{size_of, size_of_val};

    /// 2026-08-26 实测值（新增一个有意的小字符串字段 `bindInterface` 后 1128 → 1152 B；
    /// 装箱前 3096 B；只装 6 项时 1904 B，8 项时 1512 B）。
    const MEASURED: usize = 1152;
    let actual = size_of::<ServerConfig>();
    assert!(
        actual <= MEASURED,
        "size_of::<ServerConfig>() = {actual} B > {MEASURED} B。\
             若这是本仓有意新增的小标量/字符串字段 ⇒ 重新实测并连同日期更新 MEASURED；\
             若是又内联了一个大结构体 ⇒ 按 ServerConfig 头注的判据（大 × 罕见）装箱它，\
             不得为此调大常量。两者的分辨方法见本测试的文档注释。"
    );

    // 「罕见」那一半：高频字段必须保持内联，不得靠装箱它们来压上面那个数字。
    // `Option<Box<_>>` 恒为 8 B（指针 + niche），故 `> 8` 精确等价于「没被装箱」，
    // 且不随子结构增删字段漂移 —— 不写死 176 就是为了不要一条会自己过期的断言。
    //
    // 🔴 **与下面登记表的 `Exempt` 自查刻意并存，不是重复**：射程不同。
    // 登记表守的是「**登记与代码一致**」—— 把 `tls_settings` 装箱、同时把那一行从
    // `Exempt("…")` 改成 `Boxed(size_of::<ps::TlsSettings>())`，登记表全绿（2026-08-17 实测），
    // 因为它此刻是自洽的。本条守的是「**tlsSettings 这个具体决定**」，对装箱 tls 无条件成立。
    // 一般化 ≠ 更强：这一格恰好是一般化更弱的那格，故不得用登记表取代本条。
    let s = ServerConfig::default();
    assert!(
        size_of_val(&s.tls_settings) > 8,
        "tlsSettings 被装箱了 —— 它 60/60 出现，装箱只是把内联宽度换成每节点一次 malloc，\
             字节上打平甚至更差。上界断言看不见这件事（size 反而变小 ⇒ 更绿），\
             登记表也只查「登记与代码一致」（改成 Boxed 就自洽了），故由本条无条件接住。\
             判据是「体积大 × 极少出现」，不是「体积大」。"
    );

    // ── 判据面：由 serde 自己交出全部字段名，不是人写的清单 ────────────────
    //
    // `#[derive(Deserialize)]` 生成的代码会把**全部**字段名以 `&'static [&'static str]`
    // 传给 `Deserializer::deserialize_struct`。下面这个探针就在那一跳把它截下来。
    // 于是「本结构体有哪些字段」的来源是**类型本身**：新增字段 ⇒ 探针立刻多一项，
    // 而登记表不会自己长 ⇒ 完整性断言当场红。前三次翻车缺的正是这一半。
    #[derive(Debug)]
    struct ProbeDone;
    impl std::fmt::Display for ProbeDone {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("字段名已截获（探针恒以 Err 收尾，不真的反序列化）")
        }
    }
    impl std::error::Error for ProbeDone {}
    impl serde::de::Error for ProbeDone {
        fn custom<T: std::fmt::Display>(_: T) -> Self {
            ProbeDone
        }
    }
    struct FieldProbe<'a> {
        out: &'a mut Vec<&'static str>,
    }
    impl<'de> Deserializer<'de> for FieldProbe<'_> {
        type Error = ProbeDone;
        fn deserialize_any<V: serde::de::Visitor<'de>>(
            self,
            _v: V,
        ) -> Result<V::Value, Self::Error> {
            Err(ProbeDone)
        }
        fn deserialize_struct<V: serde::de::Visitor<'de>>(
            self,
            _name: &'static str,
            fields: &'static [&'static str],
            _v: V,
        ) -> Result<V::Value, Self::Error> {
            self.out.extend_from_slice(fields);
            Err(ProbeDone)
        }
        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
            bytes byte_buf option unit unit_struct newtype_struct seq tuple
            tuple_struct map enum identifier ignored_any
        }
    }

    /// 对一个字段作过的决定。
    enum Decision {
        /// 普通字段：宽度小到没有可讨论的，必须**低于门槛**。
        Plain,
        /// `Option<Box<T>>`：附**被指向结构体**的宽度 `size_of::<T>()`（不是装箱后的 8 B）——
        /// 门槛正是从这一列取最小值来的。
        Boxed(usize),
        /// 宽度**已达门槛**但刻意保持内联，附理由。
        /// **只留名字的豁免表 = 又一份后人读不出为什么的清单**，故理由是硬要求。
        Exempt(&'static str),
        /// 低于门槛、但**算过账**的候选：把结论留在这里，免得下一个人从头再算一遍。
        /// 门槛一旦降到它以下（有人装了更小的项），本行会转红，逼作者重新表态。
        Considered(&'static str),
    }
    struct FieldRow {
        /// serde 名（探针给的就是这个）。
        key: &'static str,
        /// 该字段**实际**占的宽度（`size_of_val`，装箱项恒 8 B）。
        actual: usize,
        decision: Decision,
    }

    macro_rules! rows {
        ($( $key:literal => $field:ident : $decision:expr ),* $(,)?) => {
            [$( FieldRow {
                key: $key,
                actual: size_of_val(&s.$field),
                decision: $decision,
            } ),*]
        };
    }
    use Decision::{Boxed, Considered, Exempt, Plain};
    let table = rows![
        "id" => id: Plain,
        "name" => name: Plain,
        "protocol" => protocol: Plain,
        "address" => address: Plain,
        "port" => port: Plain,
        "detour" => detour: Plain,
        "meshRoutes" => mesh_routes: Plain,
        "subscriptionId" => subscription_id: Plain,
        "bindInterface" => bind_interface: Plain,
        "providerName" => provider_name: Plain,
        "uuid" => uuid: Plain,
        "encryption" => encryption: Plain,
        "flow" => flow: Plain,
        "packetEncoding" => packet_encoding: Plain,
        "password" => password: Plain,
        "username" => username: Plain,
        "naiveSettings" => naive_settings: Plain,
        "alterId" => alter_id: Plain,
        "vmessSecurity" => vmess_security: Plain,
        "hysteria2Settings" => hysteria2_settings: Boxed(size_of::<ps::Hysteria2Settings>()),
        "tuicSettings" => tuic_settings: Considered(
            "80 B、真机 0/60。glibc 下 80 B 载荷落 96 B chunk（align16(80+8)）⇒ 在场亏 24 B、\
                 缺席省 72 B、p* = 72/96 = 75%，账是正的。本批不做只因它低于门槛、且每装一项都要\
                 各自过一遍调用面 —— 是排期，不是否决。桌上还剩它与 shadowTlsSettings 共 144 B。"
        ),
        "hysteriaSettings" => hysteria_settings: Boxed(size_of::<ps::HysteriaSettings>()),
        "torSettings" => tor_settings: Boxed(size_of::<ps::TorSettings>()),
        "openconnectSettings" => openconnect_settings:
            Boxed(size_of::<ps::OpenconnectSettings>()),
        "openvpnClientSettings" => openvpn_client_settings:
            Boxed(size_of::<ps::OpenvpnClientSettings>()),
        "wireguardSettings" => wireguard_settings: Boxed(size_of::<WireGuardSettings>()),
        "tailscaleSettings" => tailscale_settings: Boxed(size_of::<TailscaleSettings>()),
        "customSettings" => custom_settings: Plain,
        "anyTlsSettings" => any_tls_settings: Plain,
        "multiplexSettings" => multiplex_settings: Plain,
        "shadowsocksSettings" => shadowsocks_settings:
            Boxed(size_of::<ps::ShadowsocksSettings>()),
        "snellSettings" => snell_settings: Boxed(size_of::<ps::SnellSettings>()),
        "sshSettings" => ssh_settings: Boxed(size_of::<ps::SshSettings>()),
        "shadowTlsSettings" => shadow_tls_settings: Considered(
            "80 B、真机 0/60，账与 tuicSettings 完全同型（chunk 96、p* = 75%）。同样是排期，不是否决。"
        ),
        "network" => network: Plain,
        "security" => security: Plain,
        "tlsSettings" => tls_settings: Exempt(
            "真机 60 节点实测 60/60 出现（被装箱的那些同批 0/60），且有独立机制解释：\
                 几乎所有 vless/trojan/vmess 节点都带 TLS。装箱后每个 TLS 节点省下 168 B 内联却\
                 多付一次 malloc 加 176 B 堆，字节上近乎打平甚至更差；调用面也是全部协议设置里\
                 最大的一个（80 处）。判据是「体积大 × 极少出现」，不是「体积大」。"
        ),
        "realitySettings" => reality_settings: Considered(
            "48 B、真机 30/60 = 50%。落 64 B chunk ⇒ 在场亏 24 B、缺席省 40 B、p* = 62.5% ⇒ \
                 装箱净赚仅 8 B/节点外加一次 malloc，属**边缘取舍**。本仓已明确决定不用门冻结它 —— \
                 这行是结论存档，不是禁令：真要装它，把本行改 Boxed 即可（门槛会随之降到 48，\
                 tuic/shadowTls 两行会跟着转红，那正是判据一致性该有的连锁）。"
        ),
        "wsSettings" => ws_settings: Boxed(size_of::<ps::WebSocketSettings>()),
        "grpcSettings" => grpc_settings: Plain,
        "httpSettings" => http_settings: Boxed(size_of::<ps::HttpSettings>()),
        "createdAt" => created_at: Plain,
        "updatedAt" => updated_at: Plain,
    ];

    // ① 完整性：登记表 ≡ serde 交出来的字段集。表不会自己长，探针会。
    let mut declared: Vec<&'static str> = Vec::new();
    let _ = ServerConfig::deserialize(FieldProbe { out: &mut declared });
    assert!(
        !declared.is_empty(),
        "探针一个字段名都没拿到。最可能的原因：有人给 ServerConfig 加了 \
             `#[serde(flatten)]` —— 那会让 serde 改走 `deserialize_map`，本探针的 \
             `deserialize_struct` 再也不被调用。此时整张登记表失去判据面，必须先换探针形态。"
    );
    let declared_set: BTreeSet<&str> = declared.iter().copied().collect();
    let registered: BTreeSet<&str> = table.iter().map(|r| r.key).collect();
    assert_eq!(
        registered.len(),
        table.len(),
        "登记表里有重复键（同一个 key 写了两行）"
    );
    let missing: Vec<&str> = declared_set.difference(&registered).copied().collect();
    assert!(
        missing.is_empty(),
        "ServerConfig 新增了字段但没在登记表里露面：{missing:?}。\
             按本测试文档「登记表怎么用」那段补一行（Plain / Boxed / Exempt / Considered 四选一）。\
             这一条就是为了不让「清单不全」再发生第四次 —— 别绕过它。"
    );
    let stale: Vec<&str> = registered.difference(&declared_set).copied().collect();
    assert!(
        stale.is_empty(),
        "登记表里有 ServerConfig 已经没有的键：{stale:?}（字段被删或被改名）"
    );

    // ② 布局对差：每一行确实读到了它自己那个字段。
    // 复制粘贴时「键名换了、`size_of_val` 里的字段没换」是本表最现实的失手方式 ——
    // 那会让另一个字段的宽度从未被量过，下面两条对它就瞎了。
    let sum: usize = table.iter().map(|r| r.actual).sum();
    assert!(
        sum <= actual && actual - sum <= 8,
        "登记表量到的字段宽度之和 = {sum} B，而 size_of::<ServerConfig>() = {actual} B，\
             差值超出尾隙上限 8 B。两种可能：\
             ① 某一行的 `size_of_val(&s.X)` 读错了字段（复制粘贴时键名换了、字段没换）；\
             ② 有人加了 `#[serde(skip)]` / `#[serde(skip_deserializing)]` 字段 —— 那类字段\
             不进 serde 的 `FIELDS`，上面那条完整性断言看不见它，本条是它唯一的绊线。"
    );

    // ③ 装箱行自查：登记为 Boxed 的必须真的是 `Option<Box<_>>`（恒 8 B）。
    for r in &table {
        if let Boxed(pointee) = r.decision {
            assert_eq!(
                r.actual, 8,
                "{} 登记为 Boxed 却占 {} B —— 它被改回内联了（或这行标错了）。\
                     改回内联是可以的，但要连同这一行改成 Plain/Exempt，让下面那条自曝断言看得见它。",
                r.key, r.actual
            );
            assert!(
                pointee > 8,
                "{}: 被指向结构体只有 {pointee} B，装箱它只是多一次 malloc",
                r.key
            );
        }
    }

    // ④ 门槛 = 已装箱项的最小宽度，取与 FLOOR 的更小者。
    //
    // 为什么要 FLOOR：门槛若纯粹相对，「把当前最小的那个改回内联」会顺手把门槛抬上去、
    // 自洽地给自己发绿灯（实测：去掉 FLOOR 后把 ws 改回内联 + 登记改 Plain + 按失败文案
    // 调小 MEASURED ⇒ 全绿）。FLOOR 钉住「本仓装过的最小项」这个历史事实，堵住那一步。
    //
    // 🔴 **写死字面量，不写 `size_of::<ps::WebSocketSettings>()`**：后者是**派生量**，
    // 与装箱毫无关系的一次正常演进（给 `WebSocketSettings` 加个 `Option<String>`，88 → 112）
    // 就会把 FLOOR 一起抬上去 ⇒ 防绕能力静默失效。2026-08-17 实测：那样改之后，
    // 「把 shadowsocks(96) 改回内联 + 登记改 Plain + 调大 MEASURED」这条本该红的变异
    // **全绿**（boxed_min 104、FLOOR 112、门槛升到 104）。字面量不会跟着漂。
    /// 本仓历史上装过的最小项的宽度（2026-08-17 实测 `WebSocketSettings` = 88 B）。
    const FLOOR: usize = 88;
    assert!(
        size_of::<ps::WebSocketSettings>() >= FLOOR,
        "WebSocketSettings 现在只有 {} B < FLOOR {FLOOR} B。FLOOR 可以（也应该）跟着**下调** ——\
             门槛更低 = 门更严，是安全方向。请重新实测并连同日期更新 FLOOR。\
             （反方向恒不需要动：ws 长大时 FLOOR 必须**留在原地**，否则门槛被静默抬松。）",
        size_of::<ps::WebSocketSettings>()
    );
    let boxed_min = table
        .iter()
        .filter_map(|r| match r.decision {
            Boxed(w) => Some(w),
            _ => None,
        })
        .min()
        .expect("装箱面不该为空");
    let threshold = boxed_min.min(FLOOR);

    // ⑤ 🔴 自曝：未装箱字段里不得存在宽度 ≥ 门槛者，除非显式登记豁免。
    for r in &table {
        if matches!(r.decision, Plain | Considered(_)) {
            assert!(
                r.actual < threshold,
                "`{}` 内联占 {} B ≥ 门槛 {} B（= 已装箱项里最小的那个），\
                     既没装箱也没登记豁免。按 ServerConfig 头注的判据（体积大 × 极少同时出现）二选一：\
                     ① 改成 `Option<Box<T>>`，本行改 `Boxed(size_of::<T>())`；\
                     ② 若它在真实配置里常出现（装箱净亏），本行改 `Exempt(\"理由\")`，\
                     理由里写清出现率证据。**不许**为了让本条变绿去动门槛或删行 —— \
                     同一个根因已经复发过三次，这条断言就是为它写的。\
                     （本行若原本是 `Considered`，说明门槛刚被降到它以下 —— 那条旧结论是在更高的\
                     门槛下算的，得重新表态。）",
                r.key,
                r.actual,
                threshold
            );
        }
    }

    // ⑥ 豁免行自查：豁免必须仍然内联、必须真的够宽、必须带理由。
    // 「把 tlsSettings 装箱来压 size_of」这条错误做法由本条接住 —— 上界看不见它（size 反而更小）。
    for r in &table {
        match r.decision {
            Exempt(why) => {
                assert!(
                    !why.trim().is_empty(),
                    "{}: 豁免必须写理由，不能只留名字",
                    r.key
                );
                assert!(
                    r.actual >= threshold,
                    "{} 登记了豁免却只占 {} B（< 门槛 {}）。两种情形：\
                         它被装箱了（豁免项必须保持内联，装箱等于推翻这条豁免本身的理由）；\
                         或者这条豁免本就多余，降回 Considered/Plain。",
                    r.key,
                    r.actual,
                    threshold
                );
            }
            Considered(why) => assert!(
                !why.trim().is_empty(),
                "{}: 登记为「算过账、暂不装」就必须把账留下来",
                r.key
            ),
            Plain | Boxed(_) => {}
        }
    }
}

/// 🔴 **透明门**：`Option<Box<T>>` 的序列化产物必须与 `Option<T>` **逐字节相同**。
///
/// 这是宽度门成立的前提：装箱只是内存布局手术，磁盘配置、订阅导入导出、下发给内核的载荷
/// 一个字节都不该变。裸 `Box<T>` 的 `Serialize`/`Deserialize` 确实逐字转发给 `T` —— 但那是
/// **当前**这个类型的性质，不是本仓写下的契约。若日后有人把它换成自己的包装类型（挂懒加载 /
/// 版本迁移 / 引用计数），转发就没了，磁盘上的配置会**静默**多出一层 `{"inner": …}`：
/// 老配置读不回来，新配置内核不认，而这条链路上没有任何行为测试会因此转红。
///
/// 断言逐键写死（而非 round-trip 自证）：round-trip 对「两侧一起改坏」是瞎的。
///
/// ⚠️ **首条断言的射程比标题大**：它是**整份 JSON 相等**，于是顺带钉住了 `ServerConfig`
/// **全部**字段的 skip 行为。将来有人加一个不带 `skip_serializing_if` 的字段，红的会是这一条，
/// 而它的失败文案说的是装箱 —— 指向错误方向。文案里已就此留了分辨提示。
///
/// **变异探针**：给任一装箱字段套一层非 `transparent` 的 newtype、或删掉它的
/// `skip_serializing_if` / `rename` ⇒ 下面的整份 JSON 断言转红。
#[test]
fn boxed_protocol_settings_serialize_transparently() {
    use crate::user_config::protocol_settings as ps;
    let s = ServerConfig {
        id: "s1".into(),
        name: "n1".into(),
        protocol: Protocol::Vless,
        address: "a.com".into(),
        port: 443,
        hysteria2_settings: Some(Box::new(ps::Hysteria2Settings {
            up_mbps: Some(50),
            ..Default::default()
        })),
        hysteria_settings: Some(Box::new(ps::HysteriaSettings {
            auth_str: Some("hy1".into()),
            ..Default::default()
        })),
        tor_settings: Some(Box::new(ps::TorSettings {
            executable_path: Some("/usr/bin/tor".into()),
            ..Default::default()
        })),
        openconnect_settings: Some(Box::new(ps::OpenconnectSettings {
            server: Some("vpn.example.com:443".into()),
            ..Default::default()
        })),
        openvpn_client_settings: Some(Box::new(ps::OpenvpnClientSettings {
            server_port: Some(1194),
            ..Default::default()
        })),
        ssh_settings: Some(Box::new(ps::SshSettings {
            private_key: Some("KEY".into()),
            ..Default::default()
        })),
        // WG/TS 各多填一个 `Vec` 字段，钉住装箱后**数组仍是数组**、不多包一层。
        // 注意这一态给不了 `skip_serializing_if = "Vec::is_empty"` 任何牙（这里它们恒非空）
        // —— 那半边由下面第三态接住。
        wireguard_settings: Some(Box::new(WireGuardSettings {
            private_key: Some("PRIV".into()),
            allowed_ips: vec!["0.0.0.0/0".into()],
            ..Default::default()
        })),
        tailscale_settings: Some(Box::new(TailscaleSettings {
            auth_key: Some("tskey-auth-X".into()),
            advertise_routes: vec!["192.168.1.0/24".into()],
            ..Default::default()
        })),
        // snell 带一个**无 `skip_serializing_if` 的必填标量**（`version`），
        // ws/http 各带一个容器（`BTreeMap` / `Vec<String>`）——
        // 钉住装箱后 map 仍是 map、数组仍是数组，不多包一层。
        snell_settings: Some(Box::new(ps::SnellSettings {
            version: 6,
            userkey: Some("uk".into()),
            ..Default::default()
        })),
        shadowsocks_settings: Some(Box::new(ps::ShadowsocksSettings {
            method: "aes-256-gcm".into(),
            password: "pw".into(),
            ..Default::default()
        })),
        ws_settings: Some(Box::new(ps::WebSocketSettings {
            path: Some("/ws".into()),
            headers: Some(
                std::iter::once(("Host".to_string(), "h.example.com".to_string())).collect(),
            ),
            ..Default::default()
        })),
        http_settings: Some(Box::new(ps::HttpSettings {
            path: Some("/p".into()),
            host: Some(vec!["h.example.com".into()]),
            ..Default::default()
        })),
        ..Default::default()
    };
    let v = serde_json::to_value(&s).expect("节点应可序列化");
    assert_eq!(
        v,
        serde_json::json!({
            "id": "s1",
            "name": "n1",
            "protocol": "vless",
            "address": "a.com",
            "port": 443,
            "hysteria2Settings": { "upMbps": 50 },
            "hysteriaSettings": { "authStr": "hy1" },
            "torSettings": { "executablePath": "/usr/bin/tor" },
            "openconnectSettings": { "server": "vpn.example.com:443" },
            "openvpnClientSettings": { "server_port": 1194 },
            "sshSettings": { "privateKey": "KEY" },
            "wireguardSettings": { "privateKey": "PRIV", "allowedIPs": ["0.0.0.0/0"] },
            "tailscaleSettings": {
                "authKey": "tskey-auth-X",
                "advertiseRoutes": ["192.168.1.0/24"]
            },
            "snellSettings": { "version": 6, "userkey": "uk" },
            "shadowsocksSettings": { "method": "aes-256-gcm", "password": "pw" },
            "wsSettings": { "path": "/ws", "headers": { "Host": "h.example.com" } },
            "httpSettings": { "path": "/p", "host": ["h.example.com"] },
        }),
        "装箱字段的键名/嵌套形状必须与未装箱时逐字节一致 —— 多一层包装 = 老配置读不回来。\
             ⚠️ 本条是整份 JSON 相等，射程覆盖全部字段：若红在一个**新增字段**上（左侧多出一个键），\
             那不是装箱问题 —— 先确认该字段该不该带 `skip_serializing_if`，再更新下面的期望 JSON。"
    );
    let back: ServerConfig = serde_json::from_value(v).expect("应能读回");
    assert_eq!(back, s, "反序列化侧同样必须透明");
    // 缺席仍不进 JSON：装箱不该让 `skip_serializing_if = "Option::is_none"` 失效
    // （`Option<Box<T>>` 的 `is_none` 与 `Option<T>` 同义，但这条得有牙）。
    let bare = ServerConfig {
        id: "s2".into(),
        name: "n2".into(),
        protocol: Protocol::Vless,
        address: "b.com".into(),
        port: 443,
        ..Default::default()
    };
    assert_eq!(
        serde_json::to_value(&bare).expect("节点应可序列化"),
        serde_json::json!({
            "id": "s2", "name": "n2", "protocol": "vless", "address": "b.com", "port": 443
        }),
        "十二个装箱字段缺席时一个键都不该出现"
    );
    // 第三态：装箱字段**在场、但内容全缺省**。前两态都盖不到它，而它才是两个谓词分岔的地方：
    // 字段级的 `Option::is_none` 只看**字段在不在**、与内容无关；一旦有人把它换成内容相关的
    // 谓词（图省事写成「空对象就别发了」），一个只建了没填的节点就会**静默丢键**，
    // 而前两态一条都不红。顺带这也是子结构里那些 `skip_serializing_if = "Vec::is_empty"`
    // 唯一有牙的一态 —— 满字段态里那些 `Vec` 恒非空，碰不到该谓词。
    //
    // 🔴 **十二个装箱字段一个都不能少**：本态的判据是「字段级谓词是否与内容无关」，那是**每个**
    // 装箱字段各自的属性，不是可以抽样的共性。少写一个，同一个变异换到那个字段上就一态不红。
    // 本态初版只放了 wireguard/tailscale 两个（补装它俩那批顺手加的），另外六个在三态里的形态
    // 是「填了个标量 / 缺席 / 缺席」—— 恰好绕开本态要拦的那件事，等于门只补到 2/8。
    // 期望值是**实测**来的（十二个结构 `Default` 逐个序列化确认），不是「反正全带
    // skip_serializing_if 所以应该是空」的推断 —— 这一批就当场证伪了那个推断：
    // `snellSettings` 实测是 `{"version":0}`、`shadowsocksSettings` 是
    // `{"method":"","password":""}`，因为它们各有不带 skip 的必填标量。
    // 哪天有人再给某个结构加一个这样的字段，该改的是这里的期望值，而本条会先红出来提醒。
    let empty_boxed = ServerConfig {
        id: "s3".into(),
        name: "n3".into(),
        protocol: Protocol::Wireguard,
        address: "c.com".into(),
        port: 51820,
        hysteria2_settings: Some(Box::new(ps::Hysteria2Settings::default())),
        hysteria_settings: Some(Box::new(ps::HysteriaSettings::default())),
        tor_settings: Some(Box::new(ps::TorSettings::default())),
        openconnect_settings: Some(Box::new(ps::OpenconnectSettings::default())),
        openvpn_client_settings: Some(Box::new(ps::OpenvpnClientSettings::default())),
        ssh_settings: Some(Box::new(ps::SshSettings::default())),
        wireguard_settings: Some(Box::new(WireGuardSettings::default())),
        tailscale_settings: Some(Box::new(TailscaleSettings::default())),
        snell_settings: Some(Box::new(ps::SnellSettings::default())),
        shadowsocks_settings: Some(Box::new(ps::ShadowsocksSettings::default())),
        ws_settings: Some(Box::new(ps::WebSocketSettings::default())),
        http_settings: Some(Box::new(ps::HttpSettings::default())),
        ..Default::default()
    };
    assert_eq!(
        serde_json::to_value(&empty_boxed).expect("节点应可序列化"),
        serde_json::json!({
            "id": "s3", "name": "n3", "protocol": "wireguard",
            "address": "c.com", "port": 51820,
            "hysteria2Settings": {}, "hysteriaSettings": {}, "torSettings": {},
            "openconnectSettings": {}, "openvpnClientSettings": {}, "sshSettings": {},
            "wireguardSettings": {}, "tailscaleSettings": {},
            // 这两个**不是** `{}`，且这正是本态期望值必须实测、不能靠「反正都带 skip」推断的
            // 活证据：`SnellSettings::version` 与 `ShadowsocksSettings::{method,password}`
            // 是必填标量，没有 `skip_serializing_if`，缺省值照发。
            "snellSettings": { "version": 0 },
            "shadowsocksSettings": { "method": "", "password": "" },
            "wsSettings": {}, "httpSettings": {}
        }),
        "在场的装箱字段即使内容全缺省，键也必须在、值恰为实测形状 —— 空对象与缺席是两回事：\
             真机上「新建了 TS 节点还没填任何设置」就是这个形态（`tailscaleSettings: {{}}`），\
             丢了它，节点回读时会当成从没配过。子结构里的 `Vec` / `BTreeMap` 字段也不得因为空就\
             冒出 `[]` / `{{}}`。"
    );
}

#[test]
fn r4_absent_token_fields_stay_none() {
    // 回归 serde 陷阱：deserialize_with 会吃掉 Option 的隐式缺键行为，靠 `default` 兜住。
    let json = r#"{"id":"s1","name":"HK","protocol":"vless","address":"a.com","port":443}"#;
    let s: ServerConfig = serde_json::from_str(json).unwrap();
    assert_eq!(s.flow, None);
    assert_eq!(s.network, None);
    assert_eq!(s.vmess_security, None);
}
