//! OpenConnect / OpenVPN rc.2 原生状态与交互式认证命令。
//!
//! UI 只传 `serverId + challengeID`；endpointTag 必须由运行快照在后端解析，且 challengeID 必须仍是
//! STATUS 末帧里的当前挑战。这样旧弹窗、核重启后的陈旧挑战或跨节点提交都会在触达内核前被拒绝。

use std::collections::HashMap;

use polaris_singbox_grpc::{daemon, Endpoint, SingBoxApiClient};
use serde::Deserialize;
use serde_json::{json, Value};
use tauri::State;

use crate::response::{ok_void, ApiResponse};
use crate::runtime::AppRuntime;

const ERR_UNAVAILABLE: &str = "VPN_ENDPOINT_UNAVAILABLE";
const ERR_STALE: &str = "VPN_CHALLENGE_STALE";
const ERR_API: &str = "VPN_API_UNREACHABLE";
const ERR_CALL: &str = "VPN_CALL_FAILED";

async fn connect_for(
    state: &State<'_, AppRuntime>,
    server_id: &str,
) -> Result<(SingBoxApiClient, String), ApiResponse<()>> {
    let (port, secret, endpoint_tag) =
        state
            .proxy()
            .management_target_for(server_id)
            .ok_or_else(|| {
                ApiResponse::err_with_code(
                    format!("no running endpoint for server {server_id}"),
                    ERR_UNAVAILABLE,
                )
            })?;
    let client = SingBoxApiClient::connect(Endpoint::new("127.0.0.1", port), secret)
        .await
        .map_err(|error| {
            ApiResponse::err_with_code(format!("management api connect failed: {error}"), ERR_API)
        })?;
    Ok((client, endpoint_tag))
}

fn call_failed(error: impl std::fmt::Display) -> ApiResponse<()> {
    ApiResponse::err_with_code(
        format!("native VPN challenge call failed: {error}"),
        ERR_CALL,
    )
}

fn stale() -> ApiResponse<()> {
    ApiResponse::err_with_code("the VPN challenge is no longer current", ERR_STALE)
}

/// 拉两条原生状态流的缓存末帧。`connected` 仅表示主核/状态流是否 live。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn vpn_get_status(state: State<'_, AppRuntime>) -> ApiResponse<Value> {
    let snapshot = state
        .mesh()
        .vpn_status_snapshot(state.proxy().status().running);
    ApiResponse::ok(
        serde_json::to_value(snapshot)
            .unwrap_or_else(|_| json!({ "connected": false, "openConnect": [], "openVpn": [] })),
    )
}

#[tauri::command]
pub async fn openconnect_submit_auth_form(
    state: State<'_, AppRuntime>,
    server_id: String,
    challenge_id: String,
    values: HashMap<String, String>,
) -> Result<ApiResponse<()>, ()> {
    if !state
        .mesh()
        .has_openconnect_challenge(&server_id, &challenge_id)
    {
        return Ok(stale());
    }
    let (client, endpoint_tag) = match connect_for(&state, &server_id).await {
        Ok(value) => value,
        Err(error) => return Ok(error),
    };
    client
        .submit_openconnect_auth_response(daemon::OpenConnectAuthResponseSubmission {
            endpoint_tag,
            challenge_id,
            response: Some(
                daemon::open_connect_auth_response_submission::Response::Form(
                    daemon::OpenConnectAuthFormResponse { values },
                ),
            ),
        })
        .await
        .map_or_else(|error| Ok(call_failed(error)), |_| Ok(ok_void()))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenConnectBrowserCookieInput {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenConnectBrowserHeaderInput {
    pub name: String,
    pub values: Vec<String>,
}

#[tauri::command]
pub async fn openconnect_submit_auth_browser(
    state: State<'_, AppRuntime>,
    server_id: String,
    challenge_id: String,
    final_url: String,
    cookies: Vec<OpenConnectBrowserCookieInput>,
    headers: Vec<OpenConnectBrowserHeaderInput>,
) -> Result<ApiResponse<()>, ()> {
    if !state
        .mesh()
        .has_openconnect_challenge(&server_id, &challenge_id)
    {
        return Ok(stale());
    }
    let (client, endpoint_tag) = match connect_for(&state, &server_id).await {
        Ok(value) => value,
        Err(error) => return Ok(error),
    };
    client
        .submit_openconnect_auth_response(daemon::OpenConnectAuthResponseSubmission {
            endpoint_tag,
            challenge_id,
            response: Some(
                daemon::open_connect_auth_response_submission::Response::Browser(
                    daemon::OpenConnectBrowserResult {
                        final_url,
                        cookies: cookies
                            .into_iter()
                            .map(|cookie| daemon::OpenConnectBrowserCookie {
                                name: cookie.name,
                                value: cookie.value,
                            })
                            .collect(),
                        headers: headers
                            .into_iter()
                            .map(|header| daemon::OpenConnectBrowserHeader {
                                name: header.name,
                                values: header.values,
                            })
                            .collect(),
                    },
                ),
            ),
        })
        .await
        .map_or_else(|error| Ok(call_failed(error)), |_| Ok(ok_void()))
}

#[tauri::command]
pub async fn openconnect_cancel_auth(
    state: State<'_, AppRuntime>,
    server_id: String,
    challenge_id: String,
) -> Result<ApiResponse<()>, ()> {
    if !state
        .mesh()
        .has_openconnect_challenge(&server_id, &challenge_id)
    {
        return Ok(stale());
    }
    let (client, endpoint_tag) = match connect_for(&state, &server_id).await {
        Ok(value) => value,
        Err(error) => return Ok(error),
    };
    client
        .cancel_openconnect_auth_challenge(daemon::OpenConnectAuthChallengeCancel {
            endpoint_tag,
            challenge_id,
        })
        .await
        .map_or_else(|error| Ok(call_failed(error)), |_| Ok(ok_void()))
}

#[tauri::command]
pub async fn openvpn_submit_challenge(
    state: State<'_, AppRuntime>,
    server_id: String,
    challenge_id: String,
    username: String,
    password: String,
    secret: String,
) -> Result<ApiResponse<()>, ()> {
    if !state
        .mesh()
        .has_openvpn_challenge(&server_id, &challenge_id)
    {
        return Ok(stale());
    }
    let (client, endpoint_tag) = match connect_for(&state, &server_id).await {
        Ok(value) => value,
        Err(error) => return Ok(error),
    };
    client
        .submit_openvpn_challenge_response(daemon::OpenVpnChallengeSubmission {
            endpoint_tag,
            challenge_id,
            username,
            password,
            secret,
        })
        .await
        .map_or_else(|error| Ok(call_failed(error)), |_| Ok(ok_void()))
}

#[tauri::command]
pub async fn openvpn_cancel_challenge(
    state: State<'_, AppRuntime>,
    server_id: String,
    challenge_id: String,
) -> Result<ApiResponse<()>, ()> {
    if !state
        .mesh()
        .has_openvpn_challenge(&server_id, &challenge_id)
    {
        return Ok(stale());
    }
    let (client, endpoint_tag) = match connect_for(&state, &server_id).await {
        Ok(value) => value,
        Err(error) => return Ok(error),
    };
    client
        .cancel_openvpn_challenge(daemon::OpenVpnChallengeCancel {
            endpoint_tag,
            challenge_id,
        })
        .await
        .map_or_else(|error| Ok(call_failed(error)), |_| Ok(ok_void()))
}
