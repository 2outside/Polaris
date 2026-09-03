//! 系统代理 bypass 纯逻辑（上游 `shared/system-proxy-bypass.ts` 1:1 移植）。
//!
//! 仅作用于系统代理模式（OS proxy 例外列表）；TUN 模式直连由 sing-box route 规则负责。
//! bypassLanCidrs / effectiveBypassLan 先行（buildInbounds 依赖）；formatBypassForWindows/mac/Linux
//! 后续 H2（系统代理写入侧）补。

#![forbid(unsafe_code)]

use crate::user_config::collections::dedupe_trim;

/// 默认 bypass 清单（业内聚合：私网/保留段 + Apple 连通性 + 国内 App/网银）。
/// 上游 `DEFAULT_BYPASS_LAN`。
pub const DEFAULT_BYPASS_LAN: &[&str] = &[
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "233.252.0.0/24",
    "240.0.0.0/4",
    "fc00::/7",
    "fe80::/10",
    "localhost",
    "*.local",
    "sequoia.apple.com",
    "seed-sequoia.siri.apple.com",
    "captive.apple.com",
    "e.crashlytics.com",
    "www.baidu.com",
    "passenger.t3go.cn",
    "yunbusiness.ccb.com",
    "wxh.wo.cn",
    "gate.lagou.com",
    "www.abchina.com.cn",
    "login-service.mobile-bank.psbc.com",
    "mobile-bank.psbc.com",
];

/// bypass 配置投影。
pub trait BypassConfig {
    fn bypass_lan(&self) -> Option<bool>;
    fn bypass_lan_list(&self) -> Option<&[String]>;
}

/// 「绕过局域网」生效清单：开关关→[]，开→用户清单/缺省 DEFAULT_BYPASS_LAN。
/// 上游 `effectiveBypassLan`。
pub fn effective_bypass_lan<C: BypassConfig>(config: &C) -> Vec<String> {
    if config.bypass_lan() == Some(false) {
        return vec![];
    }
    match config.bypass_lan_list() {
        Some(list) => list.to_vec(),
        None => DEFAULT_BYPASS_LAN.iter().map(|s| s.to_string()).collect(),
    }
}

/// **配置读取边界补齐 `bypassLANList`（F1 防默认坍塌）**。
///
/// # 为什么必须在边界注入
///
/// `bypassLANList` 缺省时，内核侧由 [`effective_bypass_lan`] 补 27 条 `DEFAULT_BYPASS_LAN`
/// （私网/CGNAT/组播/Apple 连通性/国内网银 …）。但 UI 的旁路 / route_exclude 编辑器直接绑
/// `config.bypassLANList`，缺省时只能退到前端硬编码兜底 —— **首个按键（ListEditor 逐字符 onChange）
/// 就把这份错误兜底当成用户清单持久化，静默丢弃 24 条真实默认**（win32 TUN route_exclude 丢
/// 10/8+172.16/12+CGNAT；route 直连规则 & 系统代理旁路丢网银/Apple 域名）。
///
/// 修法：在 `config:get` 唯一读取边界，把 UI 收到的 `bypassLANList` **补成其生效值**，使前端永远
/// 编辑真实清单、兜底成为死代码。语义与 [`effective_bypass_lan`] 严格对齐（由 `mirrors_effective_*`
/// 测试锁死），故对 builder 完全透明：注入后再交给 builder，`effective_bypass_lan` 拿到同一份清单，
/// 生成结果不变。
///
/// 幂等且尊重用户意图：字段**已是具体数组**（含用户清空后的 `[]`）→ 用户拥有，原样保留；仅
/// 缺省 / `null` 才注入。`bypassLAN == Some(false)`（用户显式关旁路）→ 注入 `[]`，避免 UI 展示
/// 一份看似生效实则被总开关否决的清单。
pub fn ensure_bypass_lan_list(cfg: &mut serde_json::Value) {
    let Some(obj) = cfg.as_object_mut() else {
        return;
    };
    // 已是具体数组（含用户清空的 []）→ 用户拥有，不覆盖。
    if matches!(obj.get("bypassLANList"), Some(serde_json::Value::Array(_))) {
        return;
    }
    // 缺省 / null → 注入生效默认（严格镜像 effective_bypass_lan 的 None 分支 + 总开关分支）。
    let effective: Vec<serde_json::Value> =
        if obj.get("bypassLAN").and_then(serde_json::Value::as_bool) == Some(false) {
            vec![]
        } else {
            DEFAULT_BYPASS_LAN
                .iter()
                .map(|s| serde_json::Value::from(*s))
                .collect()
        };
    obj.insert(
        "bypassLANList".to_string(),
        serde_json::Value::Array(effective),
    );
}

/// 是否 IPv4 CIDR 字面量（`\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}/\d{1,2}`）。
/// 上游 `isIpv4Cidr`。
pub fn is_ipv4_cidr(s: &str) -> bool {
    let t = s.trim();
    let Some((addr, prefix)) = t.split_once('/') else {
        return false;
    };
    if addr.is_empty() || prefix.is_empty() || prefix.len() > 2 {
        return false;
    }
    if !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let octets: Vec<&str> = addr.split('.').collect();
    octets.len() == 4 && octets.iter().all(|o| is_cidr_octet(o))
}

fn is_cidr_octet(o: &str) -> bool {
    !o.is_empty() && o.len() <= 3 && o.bytes().all(|b| b.is_ascii_digit())
}

/// 是否 IPv6 CIDR 字面量（粗判：hex+冒号地址 + /0-128 前缀）。上游 `isIpv6Cidr`。
pub fn is_ipv6_cidr(s: &str) -> bool {
    let t = s.trim();
    let Some((addr, prefix)) = t.split_once('/') else {
        return false;
    };
    if prefix.is_empty() || prefix.len() > 3 {
        return false;
    }
    if !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let prefix_n: u32 = prefix.parse().unwrap_or(999);
    if prefix_n > 128 {
        return false;
    }
    addr.contains(':')
        && !addr.is_empty()
        && addr.bytes().all(|b| b.is_ascii_hexdigit() || b == b':')
}

/// 是否 IP CIDR（v4 或 v6）。上游 `isIpCidr`。
pub fn is_ip_cidr(s: &str) -> bool {
    is_ipv4_cidr(s) || is_ipv6_cidr(s)
}

/// 从 bypass 清单筛 IP CIDR 条目（滤掉域名/通配/localhost）。
/// 上游 `bypassLanCidrs`。
pub fn bypass_lan_cidrs(list: &[String]) -> Vec<String> {
    list.iter()
        .map(|s| s.trim().to_string())
        .filter(|s| is_ip_cidr(s))
        .collect()
}

/// IPv4 CIDR → Windows ProxyOverride 通配（/8/16/24/12 枚举）。上游 `ipv4CidrToWindowsPatterns`。
pub fn ipv4_cidr_to_windows_patterns(cidr: &str) -> Vec<String> {
    let t = cidr.trim();
    let Some((addr, prefix)) = t.split_once('/') else {
        return vec![];
    };
    let octets: Vec<&str> = addr.split('.').collect();
    if octets.len() != 4 || !octets.iter().all(|o| is_cidr_octet(o)) {
        return vec![];
    }
    let o: Vec<u32> = octets
        .iter()
        .map(|s| s.parse::<u32>().unwrap_or(999))
        .collect();
    if o.iter().any(|&x| x > 255) {
        return vec![];
    }
    let prefix_n: u32 = prefix.parse().unwrap_or(999);
    match prefix_n {
        8 => vec![format!("{}.*", o[0])],
        16 => vec![format!("{}.{}.*", o[0], o[1])],
        24 => vec![format!("{}.{}.{}.*", o[0], o[1], o[2])],
        12 => {
            // /12 第二段对齐到 16 倍数，覆盖 base..base+15。
            let base = o[1] & 0xf0;
            (base..=base + 15)
                .take_while(|&i| i <= 255)
                .map(|i| format!("{}.{i}.*", o[0]))
                .collect()
        }
        _ => vec![],
    }
}

/// macOS networksetup 参数（CIDR + 域名 + 通配原样去重）。上游 `formatBypassForMac`。
pub fn format_bypass_for_mac(list: &[String]) -> Vec<String> {
    dedupe_trim(list.iter().cloned())
}

/// Linux gsettings ignore-hosts（CIDR + 域名原样去重）。上游 `formatBypassForLinux`。
pub fn format_bypass_for_linux(list: &[String]) -> Vec<String> {
    dedupe_trim(list.iter().cloned())
}

#[cfg(test)]
mod tests;
