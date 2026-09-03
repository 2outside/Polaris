//! outbound builder 叶子工具（Polaris singbox-outbound-builder.ts 顶部 + duration/ws-early-data/direct-selection）。

#![forbid(unsafe_code)]

/// Go duration 规整（裸毫秒整数补 ms）。上游 `normalizeDuration`。
pub fn normalize_duration(v: Option<&str>) -> Option<String> {
    let t = v?.trim();
    if t.is_empty() {
        return None;
    }
    // 纯数字（含小数）→ ms；否则透传（已带单位）。
    let is_pure_num = !t.is_empty()
        && t.bytes()
            .enumerate()
            .all(|(i, b)| b.is_ascii_digit() || (b == b'.' && i > 0));
    if is_pure_num {
        Some(format!("{t}ms"))
    } else {
        Some(t.to_string())
    }
}

/// v2ray/xray 默认早数据头。上游 `DEFAULT_EARLY_DATA_HEADER`。
pub const DEFAULT_EARLY_DATA_HEADER: &str = "Sec-WebSocket-Protocol";

/// WS 早数据解析结果。上游 `WsEarlyData`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WsEarlyData {
    pub path: String,
    pub max_early_data: Option<u32>,
    pub early_data_header_name: Option<String>,
}

/// 解析 WS path 的 ?ed=N(&eh=name) 约定。上游 `parseWsEarlyData`。
/// 无 ed 或非法 → 原样返回 path。
pub fn parse_ws_early_data(raw_path: &str) -> WsEarlyData {
    let path = if raw_path.is_empty() { "/" } else { raw_path };
    let q_idx = match path.find('?') {
        Some(i) => i,
        None => {
            return WsEarlyData {
                path: path.to_string(),
                max_early_data: None,
                early_data_header_name: None,
            }
        }
    };
    let pathname = &path[..q_idx];
    let query = &path[q_idx + 1..];

    // 手写 query 解析（避免 url crate）。
    let mut params: Vec<(String, String)> = Vec::new();
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            params.push((url_decode(k), url_decode(v)));
        } else if !pair.is_empty() {
            params.push((url_decode(pair), String::new()));
        }
    }

    let ed_raw = params
        .iter()
        .find(|(k, _)| k == "ed")
        .map(|(_, v)| v.as_str());
    let ed_raw = match ed_raw {
        Some(e) => e,
        None => {
            return WsEarlyData {
                path: path.to_string(),
                max_early_data: None,
                early_data_header_name: None,
            }
        }
    };
    let ed: u32 = match ed_raw.parse() {
        Ok(n) if n > 0 => n,
        _ => {
            return WsEarlyData {
                path: path.to_string(),
                max_early_data: None,
                early_data_header_name: None,
            }
        }
    };

    let eh = params
        .iter()
        .find(|(k, _)| k == "eh")
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| DEFAULT_EARLY_DATA_HEADER.to_string());

    // 重建 path（去掉 ed/eh，保留其它 query）。
    let rest: Vec<String> = params
        .iter()
        .filter(|(k, _)| k != "ed" && k != "eh")
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let new_path = if rest.is_empty() {
        pathname.to_string()
    } else {
        format!("{}?{}", pathname, rest.join("&"))
    };

    WsEarlyData {
        path: new_path,
        max_early_data: Some(ed),
        early_data_header_name: Some(eh),
    }
}

fn url_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(b as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// 协议 TLS 是否在 QUIC 内自管（hy2/tuic）。上游 `isQuicManagedTls`。
pub fn is_quic_managed_tls(protocol: &str) -> bool {
    let p = protocol.to_ascii_lowercase();
    // hysteria（**v1**）2026-08-11 并入：三者在上游走**同一个** `tls.NewClient`
    // （protocol/{hysteria,hysteria2,tuic}/outbound.go），TLS 同由 QUIC 栈接管。
    p == "hysteria2" || p == "tuic" || p == "hysteria"
}

/// TLS engine 是否应在当前平台下发。上游 `shouldEmitTlsEngine`。
pub fn should_emit_tls_engine(engine: Option<&str>, platform: &str) -> bool {
    match engine {
        Some("windows") => platform == "win32",
        Some("apple") => platform == "darwin",
        _ => false,
    }
}

/// selector default 被剔除后的兜底。上游 `prunedSelectorDefault`。
pub fn pruned_selector_default(tag: Option<&str>, remaining: &[String]) -> Option<String> {
    match tag {
        Some(t) if t.starts_with("rule-sel-") => Some("proxy-selector".to_string()),
        _ => remaining.first().cloned(),
    }
}

#[cfg(test)]
mod tests;
