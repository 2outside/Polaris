//! ipip.net `myip.ipip.net/json` 解析 —— direct 腿**专用**本地直连出口探测。
//!
//! 1:1 移植自 上游 `IpInfoService.parseJson`（ipip 分支）+ `ccFromIpipLocation`。
//! direct 腿**只用国内** ipip：旁路由/软路由透明分流会把国外端点（cloudflare/ip-api/ipify）劫持走代理
//! 出口 → 本地直连出口被误标为境外节点 IP。ipip 走真实大陆出口，是这类环境下唯一测得对本地直连出口的
//! 办法。与 [`crate::trace`]（cloudflare cdn-cgi/trace，仅 proxy 腿）互斥。

use serde_json::Value;

/// 解析后的 ipip 出口信息（对齐渲染端 `IpInfo`：ip 必有，country/countryCode 可缺）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpipInfo {
    pub ip: String,
    /// 地区展示串（location 各非空段以空格连接）；无 location / 全空 → `None`。
    pub country: Option<String>,
    /// ISO alpha-2 国别码（ipip 库无 ISO 码，仅中国系派生）；见 [`cc_from_ipip_location`]。
    pub country_code: Option<String>,
}

/// ipip location → countryCode：中国 → cn（港澳台细分 hk/mo/tw），其余 `None`（渲染端 Globe 兜底）。
///
/// 1:1 移植 上游 `ccFromIpipLocation`：只认 `loc[0] == "中国"`，据 `loc[1]` 细分港澳台。
pub fn cc_from_ipip_location(loc: &[String]) -> Option<String> {
    if loc.first().map(String::as_str) != Some("中国") {
        return None;
    }
    match loc.get(1).map(String::as_str) {
        Some("香港") => Some("hk".to_string()),
        Some("澳门") => Some("mo".to_string()),
        Some("台湾") => Some("tw".to_string()),
        _ => Some("cn".to_string()),
    }
}

/// 解析 `myip.ipip.net/json` body。对应 上游 `parseJson` 的 ipip 分支。
///
/// 期望形态 `{ret:"ok", data:{ip, location:[国,省,市,区,ISP]}}`；缺 `ret=="ok"` / `data` / `data.ip`
/// 或非法 JSON → `None`（劫持页/HTML/截断响应解析失败即弃，防假数据污染直连出口）。
///
/// `country` = location **非空段**以空格连接（对齐 上游 `parts.join(' ')`）；`countryCode` 用**含空段**的
/// 原始 location 派生（对齐 上游 `ccFromIpipLocation(raw)`，其判据只看 `loc[0]`/`loc[1]` 位置）。
pub fn parse_ipip(body: &str) -> Option<IpipInfo> {
    let j: Value = serde_json::from_str(body).ok()?;
    if j.get("ret").and_then(Value::as_str) != Some("ok") {
        return None;
    }
    let data = j.get("data")?;
    let ip = data.get("ip").and_then(Value::as_str)?.to_string();
    // raw：location 里全部字符串段（含空串，对齐 上游 `raw`）；派生 countryCode 用它（判位置）。
    let raw: Vec<String> = data
        .get("location")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    // parts：非空段（对齐 上游 `parts`）；拼展示串。
    let parts: Vec<&str> = raw
        .iter()
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .collect();
    let country = if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    };
    let country_code = cc_from_ipip_location(&raw);
    Some(IpipInfo {
        ip,
        country,
        country_code,
    })
}

#[cfg(test)]
mod tests;
