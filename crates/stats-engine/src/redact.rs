//! 诊断报告脱敏 —— 纯函数，零 IO、零网络。
//!
//! Polaris 锚点：`shared/diagnostic-redact.ts`(560) 的 `redactDeep` / `redactUrlValue` /
//! `collectNodeIdentifiers` / `redactIdentifiers`。
//!
//! # 红线（不变量）
//!
//! **诊断报告会被贴到公开 issue，绝不含明文密钥。**
//!
//! 脱敏走「单一真值」：UserConfig 与生成的 sing-box 配置都过同一个 [`redact_deep`]，避免某处漏掉。
//! 这是**安全功能，不是格式化功能** —— 任何「让报告更好看」的想法都不得以放宽打码为代价。
//!
//! # 策略
//!
//! 键名黑名单（命中即整值打码）+ url 仅留 origin + custom 协议 `secretKeys` 叠加；**未命中键原样保留**
//! （诊断需看形态）。
//!
//! 注意：**无值层启发式**（不按 base64 / 熵猜密钥）。custom 协议（raw-JSON 透传）的自定义密钥键若既不在
//! 黑名单、用户又未在表单声明 `secretKeys`，则不会被打码 —— 故 custom 节点务必声明 `secretKeys`
//! （snell psk 等常见键已黑名单兜底）。
//!
//! # 两层脱敏的分工
//!
//! 1. [`redact_deep`]：**键名**层 —— 打码「密钥键」的值（password / uuid / privateKey…）。只管结构化 JSON。
//! 2. [`redact_identifiers`]：**值**层 —— 把节点身份（域名 / IP / SNI / 节点名）在**全报告文本**（配置块
//!    + 日志 tail）统一替换为稳定占位。日志 tail 是原文，第 1 层管不到，非它不可。

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::sync::OnceLock;

use regex::{Captures, Regex};
use serde_json::{Map, Value};

use polaris_config_engine::user_config::ip::is_ipv4;

/// 打码占位符（定长，不泄露原值长度信息）。上游 `REDACTED`。
pub const REDACTED: &str = "<redacted>";

/// 密钥键名黑名单（**已归一**：小写、去 `_`/`-`，故 camelCase 与 snake_case 同时命中：
/// `privateKey` / `private_key` 都归一为 `privatekey`）。命中即整值打码。
///
/// 仅收「凭据 / 密钥」类。**刻意排除**可公开的结构字段：reality `public_key`（公钥本就公开）、`short_id`、
/// `server_name` / `sni`、`method`（SS 加密算法名非密钥）、`fingerprint`、`alpn` —— 这些保留以判形态。
/// `username` 保留（naive 用户名单独不可用，且有助定位），仅 password 类打码。
///
/// **改这张表 = 改红线**。新增协议若引入新密钥键，必须同步加进来 + 补 `tests` 里的穷举用例。
pub const SECRET_KEYS: [&str; 15] = [
    "password",
    "uuid",
    "privatekey",
    "privatekeypassphrase",
    "presharedkey",
    "authkey",
    "secret",
    "clashapisecret",
    "token",
    "pluginopts", // ss plugin_opts 常含 host;password
    "pluginoptions",
    "privacypassword",
    "privacypasswordhash", // 隐私密码 salted hash（诊断报告贴公开 issue，hash 可离线爆破 → 打码）
    "psk",                 // snell 等第三方协议主密钥（无 customSettings.secretKeys 时的兜底）
    "userkey",             // snell 多用户服务器鉴权 key
];

/// url 类键名（值按 url 处理：仅保留 origin，path/query 都打码 —— 订阅 token 可能在 path 或 query）。
pub const URL_KEYS: [&str; 1] = ["url"];

/// 归一键名：小写 + 去 `_`/`-`，使 `privateKey` / `private_key` / `private-key` 等价比较。
/// 导出供调用方构造叠加密钥集。上游 `normalizeKey`。
#[must_use]
pub fn normalize_key(key: &str) -> String {
    key.chars()
        .filter(|c| *c != '_' && *c != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_secret_key(nk: &str, extra: &BTreeSet<String>) -> bool {
    SECRET_KEYS.contains(&nk) || extra.contains(nk)
}

/// url 脱敏：仅保留 origin（scheme + host\[:port\]），path / query / fragment / userinfo 一律丢弃或打码。
/// 上游 `redactUrlValue`。
///
/// 机场订阅 token 既可能在 query(`?token=`) 也可能嵌在 path 段（如 `/abcTOKEN/clash`）→ **宁过勿漏**（红线）；
/// origin 已足够判「订阅源主机是否可达」。
///
/// # 与 TS `new URL()` 的实现差异（均在**更严**方向，已实测锁在 `tests`）
///
/// - **userinfo**：`https://user:tok@h/p` → TS 的 `.origin` 天然丢 userinfo；本实现显式取 `@` 之后的
///   authority，等价。
/// - **默认端口**：TS `.origin` 会归一掉 `:443`/`:80`（`https://h:443/` → `https://h`）；本实现保留
///   `:443`。端口非密钥，差异纯属外观。
/// - **fragment**：TS 对 `https://h#frag` 判 `hasPathOrQuery=false` → 回 origin；本实现回
///   `origin/<redacted>`（**更严**，fragment 也可能藏 token）。
/// - **非特殊 scheme**：TS `new URL("vless://uu@h")`.origin = `"null"`（不透明源）；本实现回
///   `vless://h/<redacted>`（丢 uuid、留主机形态）。二者都不泄漏凭据；本实现保留的主机形态另由
///   [`redact_identifiers`] 兜底打码。
/// - **无 scheme 时**（TS 里 `new URL` 抛 → catch 分支）：截断到 `?` 前，与 TS 逐字一致。
#[must_use]
pub fn redact_url_value(raw: &str) -> String {
    let Some(sep) = raw.find("://") else {
        // TS catch 分支：非法 url 退化为截断到 ? 前。
        return match raw.find('?') {
            Some(q) => format!("{}?{REDACTED}", &raw[..q]),
            None => raw.to_string(),
        };
    };
    let scheme = &raw[..sep];
    let after = &raw[sep + 3..];
    let end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let authority = &after[..end];
    // userinfo（user:pass@host）是凭据 → 只留最后一个 '@' 之后的 host[:port]。
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let origin = format!("{scheme}://{host}");
    let rest = &after[end..];
    if rest.is_empty() || rest == "/" {
        origin
    } else {
        format!("{origin}/{REDACTED}")
    }
}

fn log_private_key_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?is)(?:-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|-----BEGIN OPENVPN STATIC KEY V1-----.*?-----END OPENVPN STATIC KEY V1-----|<key>.*?</key>|<tls-auth>.*?</tls-auth>|<tls-crypt>.*?</tls-crypt>|<secret>.*?</secret>)",
        )
        .expect("固定 private-key 日志脱敏正则必须有效")
    })
}

fn log_sensitive_tail_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?im)(\b(?:authorization|proxy-authorization|cookie|set-cookie|headers|cookies|requestHeaders|responseHeaders|responses|formData)\b[\"']?\s*[:=]\s*)[^\r\n]*"#,
        )
        .expect("固定认证头/容器日志脱敏正则必须有效")
    })
}

fn log_secret_assignment_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?ix)
            \b(
                password|passwd|uuid|secret|otp|pin|psk|license|
                token|access[_-]?token|refresh[_-]?token|id[_-]?token|
                auth[_-]?key|private[_-]?key(?:[_-]?passphrase)?|
                pre[_-]?shared[_-]?key|static[_-]?key|challenge[_-]?response|
                plugin[_-]?(?:opts|options)
            )\b
            ([\"']?\s*[:=]\s*)
            (
                \"(?:\\.|[^\"])*\"|
                '(?:\\.|[^'])*'|
                (?:bearer|basic)\s+[^\s]+|
                [^\s]+
            )"#,
        )
        .expect("固定密钥赋值日志脱敏正则必须有效")
    })
}

fn log_authorization_value_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(bearer|basic)\s+[^\s]+")
            .expect("固定 HTTP authorization 日志脱敏正则必须有效")
    })
}

fn log_url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\bhttps?://[^\s<>\"'`]+"#).expect("固定 URL 日志脱敏正则必须有效")
    })
}

/// 脱敏非结构化日志里的认证材料。
///
/// 这是 [`redact_deep`] 的日志侧补集：AnyConnect/OpenConnect、OpenVPN、Tailscale、WARP、WireGuard
/// 的原生日志经 stdout/stderr 或 `SubscribeLog` 到达时已经失去 JSON 键树，不能再靠结构化配置脱敏。
/// 本函数在日志 sink 入口统一处理，并在历史/helper 日志导出时再处理一次，避免任一协议新增日志调用点时
/// 各自复制一套黑名单。
///
/// 安全取舍：日志里的 HTTP(S) URL 一律只留 origin；企业 VPN 的 SSO token 既可能在 query，也可能在
/// path/userinfo，保留完整 path 会把调试便利建立在凭据泄漏之上。主机、端口、级别和非敏感网络事实仍保留。
#[must_use]
pub fn redact_log_secrets(raw: &str) -> String {
    // PEM 私钥可跨行，必须先整块收掉；后续逐行规则无法可靠识别中间的 base64 行。
    let without_private_keys = log_private_key_re().replace_all(raw, REDACTED);

    // 认证头和 auth RPC 容器可能包含调用方自定义的字段名，无法枚举其内部 key；命中容器后宁可把该行
    // 余部整体打码。普通的 `headers received`（无 `:`/`=`）不会命中。
    let without_sensitive_tails = log_sensitive_tail_re()
        .replace_all(&without_private_keys, |caps: &Captures<'_>| {
            format!("{}{REDACTED}", &caps[1])
        });

    let without_assignments =
        log_secret_assignment_re().replace_all(&without_sensitive_tails, |caps: &Captures<'_>| {
            let value = &caps[3];
            let replacement = if value.starts_with('"') {
                format!("\"{REDACTED}\"")
            } else if value.starts_with('\'') {
                format!("'{REDACTED}'")
            } else {
                REDACTED.to_string()
            };
            format!("{}{}{replacement}", &caps[1], &caps[2])
        });

    // `Bearer abc` 偶尔没有 Authorization 键（例如 reqwest/内核的简写 debug），仍须兜底。
    let without_authorization = log_authorization_value_re()
        .replace_all(&without_assignments, |caps: &Captures<'_>| {
            format!("{} {REDACTED}", &caps[1])
        });

    log_url_re()
        .replace_all(&without_authorization, |caps: &Captures<'_>| {
            let matched = &caps[0];
            // 正则为免漏掉 URL token 会吞进常见句末标点；它们不是 URL 内容，脱敏后原位补回。
            let url_len = matched
                .trim_end_matches([')', ']', '}', ',', ';', '.'])
                .len();
            let (url, suffix) = matched.split_at(url_len);
            format!("{}{suffix}", redact_url_value(url))
        })
        .into_owned()
}

/// 递归脱敏任意 JSON 值。上游 `redactDeep`。不就地修改，返回新副本。
///
/// `extra_secret_keys`：额外打码的「**已归一**」键名（custom 协议 `secretKeys` 叠加用）。
#[must_use]
pub fn redact_deep(value: &Value, extra_secret_keys: &BTreeSet<String>) -> Value {
    match value {
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|v| redact_deep(v, extra_secret_keys))
                .collect(),
        ),
        Value::Object(src) => {
            let mut out = Map::new();

            // custom 协议：outbound 内按该节点声明的 secretKeys 额外打码（归一化后并入黑名单传给子层）。
            let mut child_extra = extra_secret_keys.clone();
            if let Some(keys) = src
                .get("customSettings")
                .and_then(|cs| cs.get("secretKeys"))
                .and_then(Value::as_array)
            {
                for k in keys {
                    if let Some(s) = k.as_str() {
                        child_extra.insert(normalize_key(s));
                    }
                }
            }

            for (k, v) in src {
                let nk = normalize_key(k);
                if v.is_null() {
                    out.insert(k.clone(), Value::Null);
                } else if is_secret_key(&nk, extra_secret_keys) {
                    // 命中密钥：标量打码；**对象 / 数组整体打码**（不向下递归，杜绝嵌套泄漏）。
                    out.insert(k.clone(), Value::String(REDACTED.to_string()));
                } else if URL_KEYS.contains(&nk.as_str()) && v.is_string() {
                    out.insert(
                        k.clone(),
                        Value::String(redact_url_value(v.as_str().unwrap_or_default())),
                    );
                } else if v.is_object() || v.is_array() {
                    out.insert(k.clone(), redact_deep(v, &child_extra));
                } else {
                    out.insert(k.clone(), v.clone());
                }
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// 汇总所有 custom 节点声明的 `secretKeys`（**已归一**），供生成配置段的 `extra_secret_keys` 用。
///
/// **为什么必须单独汇总**：custom 协议在生成 sing-box config 时已把 `customSettings.outbound` 展平进
/// outbound 顶层、剥离 `customSettings` 包装 → [`redact_deep`] 在**生成配置**里就地读不到 `secretKeys`。
/// 不预先汇总，第三方协议的自定义密钥键会在生成配置段裸奔（红线：零明文密钥）。
#[must_use]
pub fn collect_custom_secret_keys(config: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Some(servers) = config.get("servers").and_then(Value::as_array) else {
        return out;
    };
    for s in servers {
        if let Some(keys) = s
            .get("customSettings")
            .and_then(|cs| cs.get("secretKeys"))
            .and_then(Value::as_array)
        {
            for k in keys {
                if let Some(v) = k.as_str() {
                    out.insert(normalize_key(v));
                }
            }
        }
    }
    out
}

/// 节点标识符 → 稳定占位符。上游 `NodeIdentifier`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentifier {
    /// 原值（节点域名 / IP / SNI / 节点名）。
    pub value: String,
    /// 占位符（`<domain-N>` / `<ip-N>` / `<node-N>`）。
    pub placeholder: String,
}

/// 主机类键名（**已归一**：小写去 `_`）：custom 透传 outbound 里这些键的字符串值是节点身份。
const HOST_KEYS: [&str; 5] = ["server", "servername", "sni", "host", "hostname"];

/// IPv4 严格判定（复用 config-engine 单一真值）；IPv6 仅作脱敏**形态粗判**（含 ':' 即归 IP），无需精确
/// —— 判错只是占位符标签选成 `<domain-N>` 而非 `<ip-N>`，**不构成泄漏**。
fn looks_like_ip(s: &str) -> bool {
    is_ipv4(s) || s.contains(':')
}

/// 递归收集对象里主机类键的字符串值。
///
/// custom 协议（raw-JSON 透传）的 outbound 原样下发到生成 config，身份字段可能嵌套
/// （如 `tls.server_name` 伪装 SNI、`transport.headers.Host`），只扫顶层会漏 → **全深度遍历**。
fn collect_hosts_deep(obj: &Value, out: &mut Vec<String>) {
    match obj {
        Value::Array(items) => {
            for x in items {
                collect_hosts_deep(x, out);
            }
        }
        Value::Object(m) => {
            for (k, v) in m {
                if let Some(s) = v.as_str() {
                    if HOST_KEYS.contains(&normalize_key(k).as_str()) {
                        out.push(s.to_string());
                    }
                } else if v.is_object() || v.is_array() {
                    collect_hosts_deep(v, out);
                }
            }
        }
        _ => {}
    }
}

/// 收集 transport headers 里的 Host 值（节点伪装域名）。大小写不敏感匹配 `host` 键；值兼容
/// string（`WebSocketSettings.headers`）与 string[]（`HttpSettings.headers`）。ws / http 共用。
fn add_host_headers(headers: Option<&Value>, out: &mut Vec<String>) {
    let Some(Value::Object(m)) = headers else {
        return;
    };
    for (k, v) in m {
        if !k.eq_ignore_ascii_case("host") {
            continue;
        }
        match v {
            Value::String(s) => out.push(s.clone()),
            Value::Array(items) => {
                for x in items {
                    if let Some(s) = x.as_str() {
                        out.push(s.to_string());
                    }
                }
            }
            _ => {}
        }
    }
}

/// 从 `config.servers` 收集本用户节点标识符 + 稳定占位符。上游 `collectNodeIdentifiers`。
///
/// 涵盖一切会进生成 config / 日志的节点身份字段：地址 / SNI / WS-Host / ShadowTLS-sni /
/// Tailscale-hostname·exitNode / HTTP-host[]·headers.Host / custom outbound 的 server·sni·host。
///
/// 地址类：域名 → `<domain-N>`、IP → `<ip-N>`（保留「域名 vs IP」诊断信号）；节点名 → `<node-N>`。
/// 去重（同值一占位，大小写不敏感）。
///
/// **节点名 < 4 字符跳过**（防误伤日志普通词，如节点名叫 "hk" 会把日志里所有 "hk" 替掉）；地址类不设长度
/// 阈值（靠 [`redact_identifiers`] 的主机边界锚定防误替）。
///
/// `extra_addresses`：#57 resolve-ahead —— 节点域名被预解析成 IP 写进生成 config 的 `outbound.server`，
/// 这些 IP 不在 `config.servers` 里、否则会以明文漏进诊断报告 → 调用方传入，一并按节点 IP 身份打码。
#[must_use]
pub fn collect_node_identifiers(config: &Value, extra_addresses: &[String]) -> Vec<NodeIdentifier> {
    let mut out: Vec<NodeIdentifier> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let (mut domain_n, mut ip_n, mut name_n) = (0u32, 0u32, 0u32);

    let mut add = |raw: &str, is_name: bool| {
        let v = raw.trim();
        if v.is_empty() {
            return;
        }
        // 长度阈值按 **UTF-16 码元**计（`encode_utf16().count()`），逐字对齐 TS `v.length < 4`。
        // 不用 `chars().count()`：机场节点名常带国旗 emoji（如 "🇭🇰🇯🇵"），JS 里每个旗帜 = 4 码元 → length=8 保留，
        // 而 scalar 计数只有 4 → 若阈值判据不同，短 emoji 名会被**漏打码**（错在不安全方向）。
        if is_name && v.encode_utf16().count() < 4 {
            return;
        }
        let key = v.to_lowercase();
        if !seen.insert(key) {
            return;
        }
        let placeholder = if is_name {
            name_n += 1;
            format!("<node-{name_n}>")
        } else if looks_like_ip(v) {
            ip_n += 1;
            format!("<ip-{ip_n}>")
        } else {
            domain_n += 1;
            format!("<domain-{domain_n}>")
        };
        out.push(NodeIdentifier {
            value: v.to_string(),
            placeholder,
        });
    };

    let str_at = |s: &Value, path: &[&str]| -> Option<String> {
        let mut cur = s;
        for p in path {
            cur = cur.get(p)?;
        }
        cur.as_str().map(str::to_owned)
    };

    if let Some(servers) = config.get("servers").and_then(Value::as_array) {
        for s in servers {
            if let Some(v) = str_at(s, &["address"]) {
                add(&v, false);
            }
            if let Some(v) = str_at(s, &["tlsSettings", "serverName"]) {
                add(&v, false);
            }
            // ws/http transport 的 Host 头（伪装域名）：仅匹配精确 `host` 键（**刻意不走 collect_hosts_deep
            // 的 HOST_KEYS 全集**）——transport headers 只有 Host 头承载身份，用全集会把恰好叫 server/sni
            // 的自定义 HTTP 头误收为节点身份；collect_hosts_deep 仅用于 custom raw-JSON outbound（键名不可控、
            // 需广撒网）。
            let mut hosts: Vec<String> = Vec::new();
            add_host_headers(
                s.get("wsSettings").and_then(|w| w.get("headers")),
                &mut hosts,
            );
            add_host_headers(
                s.get("httpSettings").and_then(|h| h.get("headers")),
                &mut hosts,
            );
            for h in &hosts {
                add(h, false);
            }
            if let Some(v) = str_at(s, &["shadowTlsSettings", "sni"]) {
                add(&v, false);
            }
            if let Some(v) = str_at(s, &["tailscaleSettings", "hostname"]) {
                add(&v, false);
            }
            if let Some(v) = str_at(s, &["tailscaleSettings", "exitNode"]) {
                add(&v, false);
            }
            if let Some(arr) = s
                .get("httpSettings")
                .and_then(|h| h.get("host"))
                .and_then(Value::as_array)
            {
                for h in arr {
                    if let Some(v) = h.as_str() {
                        add(v, false);
                    }
                }
            }
            // custom 透传 outbound 原样下发 → 递归收主机类键（含嵌套 tls.server_name / transport.headers.Host）
            if let Some(o) = s.get("customSettings").and_then(|c| c.get("outbound")) {
                let mut deep: Vec<String> = Vec::new();
                collect_hosts_deep(o, &mut deep);
                for h in &deep {
                    add(h, false);
                }
            }
            if let Some(v) = str_at(s, &["name"]) {
                add(&v, true);
            }
        }
    }
    // resolve-ahead 预解析得到的节点 IP（在 config.servers 之外）：按 IP 身份打码。
    for ip in extra_addresses {
        add(ip, false);
    }
    out
}

/// 主机边界字符集：节点标识符前后若是这些字符，说明它只是更长主机名的一段 → 不替。
/// 对齐 TS 正则 `(?<![\w.-])` / `(?![\w.-])`（`\w` = ASCII 字母数字 + `_`）。
///
/// **Rust `regex` crate 不支持 lookbehind/lookahead**，故手写边界判定 —— 顺带免掉正则编译与 ReDoS 面。
fn is_host_boundary_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-'
}

/// 在任意文本（日志 tail / 序列化后的配置）里把节点标识符替换为占位符。上游 `redactIdentifiers`。
///
/// - **长值优先**（防短值先替坏长值）
/// - **大小写不敏感**（日志域名常小写）
/// - **主机边界锚定**：防节点标识符作为子串误替无关串（节点 `a.com` 不碰 `cdn.a.com`；节点 IP
///   `104.18.8.8` 不把 `104.18.8.83` 切成 `<ip-1>3`）
/// - 占位符为 `<...>` 不含原值，不会自我再匹配
#[must_use]
pub fn redact_identifiers(text: &str, ids: &[NodeIdentifier]) -> String {
    if text.is_empty() || ids.is_empty() {
        return text.to_string();
    }
    let mut sorted: Vec<&NodeIdentifier> = ids.iter().collect();
    sorted.sort_by_key(|id| std::cmp::Reverse(id.value.len()));

    let mut out = text.to_string();
    for id in sorted {
        out = replace_bounded_ci(&out, &id.value, &id.placeholder);
    }
    out
}

/// 大小写不敏感 + 主机边界锚定的全量替换。
fn replace_bounded_ci(haystack: &str, needle: &str, replacement: &str) -> String {
    if needle.is_empty() {
        return haystack.to_string();
    }
    let hay_lower = haystack.to_lowercase();
    let need_lower = needle.to_lowercase();
    // to_lowercase 可能改变字节长度（如 'İ'）→ 会让 lower 上的下标对不回原串。
    // 主机名/IP 是 ASCII，退化到「不替」比错切安全（占位符没打上顶多多留一个已在别处覆盖的主机名，
    // 而错切会破坏报告结构）。
    if hay_lower.len() != haystack.len() || need_lower.len() != needle.len() {
        return haystack.to_string();
    }

    let bytes = haystack.as_bytes();
    let mut out = String::with_capacity(haystack.len());
    let mut cursor = 0usize;
    while let Some(rel) = hay_lower[cursor..].find(&need_lower) {
        let start = cursor + rel;
        let end = start + needle.len();
        // 前边界：start 前一个字符不得是主机字符
        let prev_ok = start == 0
            || !haystack[..start]
                .chars()
                .next_back()
                .is_some_and(is_host_boundary_char);
        // 后边界：end 处字符不得是主机字符
        let next_ok = end >= bytes.len()
            || !haystack[end..]
                .chars()
                .next()
                .is_some_and(is_host_boundary_char);
        if prev_ok && next_ok {
            out.push_str(&haystack[cursor..start]);
            out.push_str(replacement);
            cursor = end;
        } else {
            // 不满足边界 → 原样保留到 start+1，从 start+1 继续找（避免死循环）
            let step = haystack[start..].chars().next().map_or(1, char::len_utf8);
            out.push_str(&haystack[cursor..start + step]);
            cursor = start + step;
        }
        if cursor >= haystack.len() {
            break;
        }
    }
    out.push_str(&haystack[cursor.min(haystack.len())..]);
    out
}

#[cfg(test)]
mod tests;
