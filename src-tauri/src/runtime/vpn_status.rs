//! OpenConnect / OpenVPN 原生状态帧投影。
//!
//! StartedService 两条订阅都是全量 endpoint 快照。本模块只做 wire 类型 → 稳定 UI/domain 类型的
//! 投影，并用运行配置生成的 `endpointTag → serverId` 过滤不在册端点；认证提交仍由命令层回到
//! `SingBoxApiClient`，这里不持有凭据，也不记录 URL、cookie、header 或密码。

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use polaris_singbox_grpc::daemon;

fn optional(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenConnectFormChoice {
    pub value: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenConnectFormField {
    pub submission_key: String,
    pub name: String,
    pub label: String,
    pub kind: String,
    pub value: String,
    pub options: Vec<OpenConnectFormChoice>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenConnectBrowserRequest {
    #[serde(rename = "url")]
    pub url: String,
    #[serde(rename = "finalURL", skip_serializing_if = "Option::is_none")]
    pub final_url: Option<String>,
    pub cookie_names: Vec<String>,
    pub header_names: Vec<String>,
    #[serde(rename = "callbackURLPrefixes")]
    pub callback_url_prefixes: Vec<String>,
    pub early_cookie_names: Vec<String>,
    #[serde(rename = "cacheID", skip_serializing_if = "Option::is_none")]
    pub cache_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenConnectAuthChallenge {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// `form` / `browser` / `unknown`（原生 oneof 的稳定判别值，不是展示文案）。
    pub kind: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<OpenConnectFormField>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser: Option<OpenConnectBrowserRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenConnectTunnelInfo {
    pub server: String,
    pub flavor: String,
    pub transport: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub dns: Vec<String>,
    pub mtu: u32,
    pub connected_since: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenConnectStatusEvent {
    pub server_id: String,
    pub state: String,
    pub state_text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_challenge: Option<OpenConnectAuthChallenge>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel_info: Option<OpenConnectTunnelInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenVpnChallenge {
    pub id: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "url")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_message: Option<String>,
    pub echo: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_error: Option<String>,
    pub deadline: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenVpnTunnelInfo {
    pub server: String,
    pub network: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub dns: Vec<String>,
    pub mtu: u32,
    pub connected_since: i64,
    pub cipher: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenVpnStatusEvent {
    pub server_id: String,
    pub state: String,
    pub state_text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<OpenVpnChallenge>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel_info: Option<OpenVpnTunnelInfo>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnStatusSnapshot {
    pub connected: bool,
    pub open_connect: Vec<OpenConnectStatusEvent>,
    pub open_vpn: Vec<OpenVpnStatusEvent>,
}

fn decode_openconnect_challenge(
    challenge: &daemon::OpenConnectAuthChallenge,
) -> OpenConnectAuthChallenge {
    use daemon::open_connect_auth_challenge::Challenge;

    let (kind, fields, browser) = match &challenge.challenge {
        Some(Challenge::Form(form)) => (
            "form".to_string(),
            form.fields
                .iter()
                .map(|field| OpenConnectFormField {
                    submission_key: field.submission_key.clone(),
                    name: field.name.clone(),
                    label: field.label.clone(),
                    kind: field.kind.clone(),
                    value: field.value.clone(),
                    options: field
                        .options
                        .iter()
                        .map(|choice| OpenConnectFormChoice {
                            value: choice.value.clone(),
                            label: choice.label.clone(),
                        })
                        .collect(),
                })
                .collect(),
            None,
        ),
        Some(Challenge::Browser(request)) => (
            "browser".to_string(),
            Vec::new(),
            Some(OpenConnectBrowserRequest {
                url: request.url.clone(),
                final_url: optional(&request.final_url),
                cookie_names: request.cookie_names.clone(),
                header_names: request.header_names.clone(),
                callback_url_prefixes: request.callback_url_prefixes.clone(),
                early_cookie_names: request.early_cookie_names.clone(),
                cache_id: optional(&request.cache_id),
            }),
        ),
        None => ("unknown".to_string(), Vec::new(), None),
    };
    OpenConnectAuthChallenge {
        id: challenge.id.clone(),
        banner: optional(&challenge.banner),
        message: optional(&challenge.message),
        error: optional(&challenge.error),
        kind,
        fields,
        browser,
    }
}

#[must_use]
pub fn decode_openconnect_status(
    update: &daemon::OpenConnectStatusUpdate,
    tag_to_id: &BTreeMap<String, String>,
) -> Vec<OpenConnectStatusEvent> {
    update
        .endpoints
        .iter()
        .filter_map(|endpoint| {
            Some(OpenConnectStatusEvent {
                server_id: tag_to_id.get(&endpoint.endpoint_tag)?.clone(),
                state: endpoint.state.clone(),
                state_text: endpoint.state_text.clone(),
                auth_challenge: endpoint
                    .auth_challenge
                    .as_ref()
                    .map(decode_openconnect_challenge),
                error: optional(&endpoint.error),
                tunnel_info: endpoint
                    .tunnel_info
                    .as_ref()
                    .map(|tunnel| OpenConnectTunnelInfo {
                        server: tunnel.server.clone(),
                        flavor: tunnel.flavor.clone(),
                        transport: tunnel.transport.clone(),
                        ipv4: tunnel.ipv4.clone(),
                        ipv6: tunnel.ipv6.clone(),
                        dns: tunnel.dns.clone(),
                        mtu: tunnel.mtu,
                        connected_since: tunnel.connected_since,
                    }),
            })
        })
        .collect()
}

#[must_use]
pub fn decode_openvpn_status(
    update: &daemon::OpenVpnStatusUpdate,
    tag_to_id: &BTreeMap<String, String>,
) -> Vec<OpenVpnStatusEvent> {
    update
        .endpoints
        .iter()
        .filter_map(|endpoint| {
            Some(OpenVpnStatusEvent {
                server_id: tag_to_id.get(&endpoint.endpoint_tag)?.clone(),
                state: endpoint.state.clone(),
                state_text: endpoint.state_text.clone(),
                challenge: endpoint
                    .challenge
                    .as_ref()
                    .map(|challenge| OpenVpnChallenge {
                        id: challenge.id.clone(),
                        kind: challenge.kind.clone(),
                        username: optional(&challenge.username),
                        message: optional(&challenge.message),
                        url: optional(&challenge.url),
                        secret_message: optional(&challenge.secret_message),
                        echo: challenge.echo,
                        previous_error: optional(&challenge.previous_error),
                        deadline: challenge.deadline,
                    }),
                error: optional(&endpoint.error),
                tunnel_info: endpoint
                    .tunnel_info
                    .as_ref()
                    .map(|tunnel| OpenVpnTunnelInfo {
                        server: tunnel.server.clone(),
                        network: tunnel.network.clone(),
                        ipv4: tunnel.ipv4.clone(),
                        ipv6: tunnel.ipv6.clone(),
                        dns: tunnel.dns.clone(),
                        mtu: tunnel.mtu,
                        connected_since: tunnel.connected_since,
                        cipher: tunnel.cipher.clone(),
                    }),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests;
