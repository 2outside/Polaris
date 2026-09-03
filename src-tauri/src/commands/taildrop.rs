//! Taildrop 收件箱命令（sing-box 1.14.0-beta.15 起）。
//!
//! # 这组命令为什么必须存在
//!
//! 核从 beta.15 起在 `Start(StartStateInitialize)` 里**无条件**建收件目录并注册收件 handler
//! （`protocol/tailscale/endpoint.go:253-263`）⇒ 只要 tailnet 授了 `cap/file-sharing`，对端发来的
//! 文件**已经在往盘上落**。没有这组命令，用户拥有的是一个看不见、也清不掉的收件箱。
//!
//! # 为什么是一次性快照而不是常驻订阅
//!
//! 收件箱面板的生命周期以分钟计；而**角标要的三个计数**（未读 / 待处理 / 接收中）本来就随
//! `SubscribeTailscaleStatus` 每帧下发（`TailscaleStatusEvent` 的 `unreadFileCount` 等），
//! 走的是已有的 STATUS relay，不需要新流。故这里只做「打开面板时读一次、操作后再读一次」，
//! 判据见 [`SingBoxApiClient::first_taildrop_inbox_snapshot`]（上游在等待信号前先发一帧）。
//!
//! # 错误一律回稳定 code，不回中文
//!
//! `error` 字段里的串会被直接显示，写中文就等于把文案钉死在 Rust 侧、绕开 i18n。故本模块的失败
//! 一律 [`ApiResponse::err_with_code`]：`error` 放**给日志看的英文诊断**，`code` 放前端查表用的
//! 稳定 token（对照表见 `ui/src/domain/taildrop.ts` 的 `TAILDROP_ERROR_KEY`）。

use polaris_singbox_grpc::{
    Endpoint, SingBoxApiClient, TaildropDownload, TaildropOutgoingFile, TaildropSendInput,
    TaildropSendOutput, TaildropSendUpdate,
};
use serde::Serialize;
use tauri::{AppHandle, Manager, State, WebviewWindow};
use tauri_plugin_dialog::DialogExt;
use tokio::io::AsyncReadExt;

use crate::response::{ok_void, ApiResponse};
use crate::runtime::taildrop::{
    BroadcastTaildropTaskSink, TaildropRuntime, TaildropTaskEventSink, TaildropTaskSnapshot,
    TaildropTaskStartError, MAX_TAILDROP_FILES_PER_TASK,
};
use crate::runtime::AppRuntime;

/// 核没在跑，或该节点不在运行核吃进去的那份配置里（刚加未重启 / 已删）。
const ERR_UNAVAILABLE: &str = "TAILDROP_ENDPOINT_UNAVAILABLE";
/// 连管理 API 失败（核刚起还没 bind / 端口被占）。
const ERR_API: &str = "TAILDROP_API_UNREACHABLE";
/// RPC 本身失败（核拒绝 / 超时 / 文件已不在）。
const ERR_CALL: &str = "TAILDROP_CALL_FAILED";
/// 落盘失败（目标路径不可写 / 空间不足）。
const ERR_WRITE: &str = "TAILDROP_WRITE_FAILED";
/// 待读取的本地文件打不开、读取失败或发送期间大小变化。
const ERR_READ: &str = "TAILDROP_READ_FAILED";
/// 同时发送任务已到资源上限。
const ERR_BUSY: &str = "TAILDROP_BUSY";
/// 一次选择的文件数超过有界任务快照上限。
const ERR_TOO_MANY_FILES: &str = "TAILDROP_TOO_MANY_FILES";
/// 取消时 taskId 已被有界终态缓存驱逐，或从未存在。
const ERR_TASK_NOT_FOUND: &str = "TAILDROP_TASK_NOT_FOUND";

/// 单个请求块。64 KiB 足以摊平 IPC/HTTP2 帧开销，又不会让取消/背压响应粗到以 MiB 为单位。
const SEND_CHUNK_SIZE: usize = 64 * 1024;

/// 收件箱里已落盘、等待处理的一个文件（前端 `contracts/taildrop.ts` 镜像）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaildropFile {
    pub name: String,
    pub size: i64,
    pub sender_name: String,
    /// Unix 秒。前端负责按本地时区与语言格式化 —— Rust 侧不产生任何面向用户的时间文案。
    pub modified_at: i64,
}

/// 正在接收中的一个文件。`sender_id` + `name` 是取消操作的定位键（缺一不可：
/// 两个发件人可以同时发同名文件）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaildropReceiving {
    pub name: String,
    pub size: i64,
    pub received_bytes: i64,
    #[serde(rename = "senderID")]
    pub sender_id: String,
    pub sender_name: String,
}

/// 一次收件箱快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TaildropInbox {
    pub files: Vec<TaildropFile>,
    pub receiving: Vec<TaildropReceiving>,
}

/// 建一条到运行核管理 API 的连接 + 解出该节点的 endpoint tag。
///
/// 两段失败分别给不同 code：**「拿不到落点」与「连不上」不是一回事** —— 前者是「现在做不了」
/// （核没跑 / 节点没进核），后者是「本该能做但连不上」，用户的下一步动作不同。
fn management_target_for(
    state: &State<'_, AppRuntime>,
    server_id: &str,
) -> Result<(u16, String, String), (String, &'static str)> {
    state
        .proxy()
        .management_target_for(server_id)
        .ok_or_else(|| {
            (
                format!("no running endpoint for server {server_id}"),
                ERR_UNAVAILABLE,
            )
        })
}

async fn connect_for(
    state: &State<'_, AppRuntime>,
    server_id: &str,
) -> Result<(SingBoxApiClient, String), (String, &'static str)> {
    let (port, secret, tag) = management_target_for(state, server_id)?;
    let client = SingBoxApiClient::connect(Endpoint::new("127.0.0.1", port), secret)
        .await
        .map_err(|e| (format!("management api connect failed: {e}"), ERR_API))?;
    Ok((client, tag))
}

/// 读一次该节点的 Taildrop 收件箱。
///
/// 🔴 **空结果不等于「tag 正确且没有文件」**：核对未知 endpointTag 回的是一帧空收件箱而非错误。
/// 本命令用 [`crate::runtime::proxy::ProxyRuntime::management_target_for`] 解 tag，解不到就直接
/// 报 `TAILDROP_ENDPOINT_UNAVAILABLE` 而**不猜**，正是为了让「空」只剩一种含义。
#[tauri::command]
pub async fn taildrop_list(
    state: State<'_, AppRuntime>,
    server_id: String,
) -> Result<ApiResponse<TaildropInbox>, ()> {
    let (client, tag) = match connect_for(&state, &server_id).await {
        Ok(v) => v,
        Err((msg, code)) => return Ok(ApiResponse::err_with_code(msg, code)),
    };
    match client.first_taildrop_inbox_snapshot(tag).await {
        Ok(inbox) => Ok(ApiResponse::ok(TaildropInbox {
            files: inbox
                .files
                .into_iter()
                .map(|f| TaildropFile {
                    name: f.name,
                    size: f.size,
                    sender_name: f.sender_name,
                    modified_at: f.modified_at,
                })
                .collect(),
            receiving: inbox
                .receiving
                .into_iter()
                .map(|r| TaildropReceiving {
                    name: r.name,
                    size: r.size,
                    received_bytes: r.received_bytes,
                    sender_id: r.sender_id,
                    sender_name: r.sender_name,
                })
                .collect(),
        })),
        Err(e) => Ok(ApiResponse::err_with_code(
            format!("SubscribeTaildropInbox failed: {e}"),
            ERR_CALL,
        )),
    }
}

/// 把收件箱标记为已读（清未读角标）。**不删文件** —— 待处理数不变。
#[tauri::command]
pub async fn taildrop_mark_read(
    state: State<'_, AppRuntime>,
    server_id: String,
) -> Result<ApiResponse<()>, ()> {
    let (client, tag) = match connect_for(&state, &server_id).await {
        Ok(v) => v,
        Err((msg, code)) => return Ok(ApiResponse::err_with_code(msg, code)),
    };
    match client.mark_taildrop_inbox_read(tag).await {
        Ok(()) => Ok(ok_void()),
        Err(e) => Ok(ApiResponse::err_with_code(
            format!("MarkTaildropInboxRead failed: {e}"),
            ERR_CALL,
        )),
    }
}

/// 删除收件箱里的一个文件。
#[tauri::command]
pub async fn taildrop_delete(
    state: State<'_, AppRuntime>,
    server_id: String,
    name: String,
) -> Result<ApiResponse<()>, ()> {
    let (client, tag) = match connect_for(&state, &server_id).await {
        Ok(v) => v,
        Err((msg, code)) => return Ok(ApiResponse::err_with_code(msg, code)),
    };
    match client.delete_taildrop_file(tag, name).await {
        Ok(()) => Ok(ok_void()),
        Err(e) => Ok(ApiResponse::err_with_code(
            format!("DeleteTaildropFile failed: {e}"),
            ERR_CALL,
        )),
    }
}

/// 取消一个**接收中**的文件。定位键是 `sender_id` + `name` 两个一起。
#[tauri::command]
pub async fn taildrop_cancel(
    state: State<'_, AppRuntime>,
    server_id: String,
    sender_id: String,
    name: String,
) -> Result<ApiResponse<()>, ()> {
    let (client, tag) = match connect_for(&state, &server_id).await {
        Ok(v) => v,
        Err((msg, code)) => return Ok(ApiResponse::err_with_code(msg, code)),
    };
    match client.cancel_taildrop_receiving(tag, sender_id, name).await {
        Ok(()) => Ok(ok_void()),
        Err(e) => Ok(ApiResponse::err_with_code(
            format!("CancelTaildropReceiving failed: {e}"),
            ERR_CALL,
        )),
    }
}

struct SelectedFile {
    file: tokio::fs::File,
    name: String,
    size: u64,
}

type SendFailure = (String, &'static str);

/// Taildrop 诊断只保留用户已经会在任务清单里看到的文件名，不记录完整本地目录。
fn selected_file_label(path: &std::path::Path) -> String {
    path.file_name()
        .filter(|name| !name.is_empty())
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<selected-file>".to_owned())
}

async fn open_selected_files(
    paths: Vec<std::path::PathBuf>,
) -> Result<Vec<SelectedFile>, SendFailure> {
    let mut selected = Vec::with_capacity(paths.len());
    for path in paths {
        let label = selected_file_label(&path);
        let file = tokio::fs::File::open(&path).await.map_err(|e| {
            (
                format!("open selected file {label:?} failed: {e}"),
                ERR_READ,
            )
        })?;
        let metadata = file.metadata().await.map_err(|e| {
            (
                format!("stat selected file {label:?} failed: {e}"),
                ERR_READ,
            )
        })?;
        if !metadata.is_file() {
            return Err((
                format!("selected item {label:?} is not a regular file"),
                ERR_READ,
            ));
        }
        let name = path
            .file_name()
            .filter(|name| !name.is_empty())
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or_else(|| (format!("{} has no file name", path.display()), ERR_READ))?;
        if metadata.len() > i64::MAX as u64 {
            return Err((
                format!("selected file {label:?} is too large for Taildrop"),
                ERR_READ,
            ));
        }
        selected.push(SelectedFile {
            file,
            name,
            size: metadata.len(),
        });
    }
    Ok(selected)
}

async fn write_taildrop_input(
    input: TaildropSendInput,
    files: Vec<SelectedFile>,
) -> Result<u64, SendFailure> {
    let mut total = 0u64;
    let mut buffer = vec![0u8; SEND_CHUNK_SIZE];
    for mut selected in files {
        let mut file_bytes = 0u64;
        loop {
            let read = selected.file.read(&mut buffer).await.map_err(|e| {
                (
                    format!(
                        "read {} failed after {file_bytes} bytes: {e}",
                        selected.name
                    ),
                    ERR_READ,
                )
            })?;
            if read == 0 {
                break;
            }
            input
                .send_chunk(buffer[..read].to_vec())
                .await
                .map_err(|e| (format!("SendTaildropFiles request failed: {e}"), ERR_CALL))?;
            file_bytes = file_bytes.saturating_add(read as u64);
        }
        // Start 帧先声明了长度；发送途中被别的进程改短/改长时继续提交会让核把下一文件的边界读错。
        if file_bytes != selected.size {
            return Err((
                format!(
                    "{} changed size while sending: declared {}, read {file_bytes}",
                    selected.name, selected.size
                ),
                ERR_READ,
            ));
        }
        input
            .finish_file()
            .await
            .map_err(|e| (format!("SendTaildropFiles request failed: {e}"), ERR_CALL))?;
        total = total.saturating_add(file_bytes);
    }
    // input 在返回时 drop，关闭请求流；这是服务端完成本次 RPC 的终止信号。
    Ok(total)
}

async fn drain_taildrop_output(
    mut output: TaildropSendOutput,
    runtime: &std::sync::Weak<TaildropRuntime>,
    task_id: &str,
    sink: &BroadcastTaildropTaskSink,
) -> Result<(), SendFailure> {
    while let Some(update) = output
        .next_update()
        .await
        .map_err(|e| (format!("SendTaildropFiles response failed: {e}"), ERR_CALL))?
    {
        let Some(runtime) = runtime.upgrade() else {
            return Ok(());
        };
        match update {
            TaildropSendUpdate::Progress {
                file_index,
                sent_bytes,
                file_completed,
            } => runtime.record_progress(task_id, file_index, sent_bytes, file_completed, sink),
            TaildropSendUpdate::ReceivedBytes(bytes) => {
                runtime.record_acknowledged(task_id, bytes, sink);
            }
        }
    }
    Ok(())
}

struct ManagedTaildropSend {
    port: u16,
    secret: String,
    endpoint_tag: String,
    peer_stable_id: String,
    declarations: Vec<TaildropOutgoingFile>,
    files: Vec<SelectedFile>,
}

async fn perform_managed_send(
    request: ManagedTaildropSend,
    runtime: &std::sync::Weak<TaildropRuntime>,
    task_id: &str,
    sink: &BroadcastTaildropTaskSink,
) -> Result<(), SendFailure> {
    let client =
        SingBoxApiClient::connect(Endpoint::new("127.0.0.1", request.port), request.secret)
            .await
            .map_err(|e| (format!("management api connect failed: {e}"), ERR_API))?;
    let session = client
        .start_taildrop_send(
            request.endpoint_tag,
            request.peer_stable_id,
            request.declarations,
        )
        .await
        .map_err(|e| (format!("SendTaildropFiles failed: {e}"), ERR_CALL))?;
    if let Some(runtime) = runtime.upgrade() {
        runtime.mark_sending(task_id, sink);
    } else {
        return Ok(());
    }

    let (input, output) = session.into_parts();
    let send = write_taildrop_input(input, request.files);
    let receive = drain_taildrop_output(output, runtime, task_id, sink);
    tokio::pin!(send);
    tokio::pin!(receive);

    // 双向流必须并发驱动。任一半先失败就 drop 另一半，取消核侧 RPC；正常先完成的一半等待另一半收尾。
    tokio::select! {
        sent = &mut send => match sent {
            Ok(_) => receive.await,
            Err(error) => Err(error),
        },
        received = &mut receive => match received {
            Ok(()) => send.await.map(drop),
            Err(error) => Err(error),
        },
    }
}

async fn cancellation_requested(cancel: &mut tokio::sync::watch::Receiver<bool>) {
    if *cancel.borrow() {
        return;
    }
    loop {
        // sender 被 AppRuntime Drop 一并释放，也等价于 owner 要求退出。
        if cancel.changed().await.is_err() || *cancel.borrow() {
            return;
        }
    }
}

async fn run_managed_send(
    request: ManagedTaildropSend,
    runtime: std::sync::Weak<TaildropRuntime>,
    task_id: String,
    mut cancel: tokio::sync::watch::Receiver<bool>,
    sink: BroadcastTaildropTaskSink,
) {
    let transfer = perform_managed_send(request, &runtime, &task_id, &sink);
    tokio::pin!(transfer);
    let outcome = tokio::select! {
        biased;
        () = cancellation_requested(&mut cancel) => None,
        result = &mut transfer => Some(result),
    };

    let Some(runtime) = runtime.upgrade() else {
        return;
    };
    match outcome {
        None => runtime.canceled(&task_id, &sink),
        Some(Ok(())) => runtime.complete(&task_id, &sink),
        Some(Err((message, code))) => {
            log::warn!("Taildrop send task {task_id} failed [{code}]: {message}");
            runtime.fail(&task_id, code, &sink);
        }
    }
}

/// Taildrop 发件结果。`canceled=true` 仅表示用户关闭了原生文件选择框，不是失败。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TaildropSendResult {
    pub canceled: bool,
    pub file_count: usize,
    /// 声明总字节（任务此刻只是已受理，不代表已经传完）。
    pub bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
}

/// 选择一个或多个本地文件，经当前 Tailscale endpoint 发给指定 peer stableID。
#[tauri::command]
pub async fn taildrop_send(
    state: State<'_, AppRuntime>,
    window: WebviewWindow,
    server_id: String,
    peer_stable_id: String,
) -> Result<ApiResponse<TaildropSendResult>, ()> {
    if peer_stable_id.trim().is_empty() {
        return Ok(ApiResponse::err_with_code(
            "Taildrop peer stable ID is empty",
            ERR_UNAVAILABLE,
        ));
    }
    if !state.taildrop().can_start() {
        return Ok(ApiResponse::err_with_code(
            "too many active Taildrop send tasks",
            ERR_BUSY,
        ));
    }

    // 先选文件、打开句柄并锁定声明长度，再连 RPC；用户在选择框里停留时不占一条管理 API 双向流。
    let lang = crate::i18n::app_lang(window.app_handle());
    let (tx, rx) = tokio::sync::oneshot::channel();
    window
        .dialog()
        .file()
        .set_title(crate::i18n::t(
            lang,
            crate::i18n::key::NATIVE_TAILDROP_SEND_TITLE,
        ))
        .pick_files(move |paths| {
            let _ = tx.send(paths);
        });
    let Some(picked) = rx.await.ok().flatten() else {
        return Ok(ApiResponse::ok(TaildropSendResult {
            canceled: true,
            ..Default::default()
        }));
    };
    if picked.is_empty() {
        return Ok(ApiResponse::ok(TaildropSendResult {
            canceled: true,
            ..Default::default()
        }));
    }
    if picked.len() > MAX_TAILDROP_FILES_PER_TASK {
        return Ok(ApiResponse::err_with_code(
            format!(
                "too many selected files: {} (max {MAX_TAILDROP_FILES_PER_TASK})",
                picked.len()
            ),
            ERR_TOO_MANY_FILES,
        ));
    }
    let paths = match picked
        .into_iter()
        .map(|p| {
            p.into_path()
                .map_err(|e| (format!("selected file is not a local path: {e}"), ERR_READ))
        })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(paths) => paths,
        Err((msg, code)) => return Ok(ApiResponse::err_with_code(msg, code)),
    };
    let files = match open_selected_files(paths).await {
        Ok(files) => files,
        Err((msg, code)) => return Ok(ApiResponse::err_with_code(msg, code)),
    };
    let declarations = files
        .iter()
        .map(|file| TaildropOutgoingFile {
            name: file.name.clone(),
            size: file.size as i64,
        })
        .collect();
    let file_count = files.len();
    let bytes = files
        .iter()
        .fold(0u64, |sum, file| sum.saturating_add(file.size));
    let task_files = files
        .iter()
        .map(|file| (file.name.clone(), file.size))
        .collect();

    let (port, secret, endpoint_tag) = match management_target_for(&state, &server_id) {
        Ok(v) => v,
        Err((msg, code)) => return Ok(ApiResponse::err_with_code(msg, code)),
    };
    let started = match state
        .taildrop()
        .start_task(server_id, peer_stable_id.clone(), task_files)
    {
        Ok(started) => started,
        Err(TaildropTaskStartError::Busy) => {
            return Ok(ApiResponse::err_with_code(
                "too many active Taildrop send tasks",
                ERR_BUSY,
            ));
        }
        Err(TaildropTaskStartError::TooManyFiles) => {
            return Ok(ApiResponse::err_with_code(
                format!("too many selected files (max {MAX_TAILDROP_FILES_PER_TASK})"),
                ERR_TOO_MANY_FILES,
            ));
        }
    };
    let task_id = started.snapshot.task_id.clone();
    let sink = BroadcastTaildropTaskSink::new(window.app_handle().clone());
    sink.updated(&started.snapshot);
    let runtime = std::sync::Arc::downgrade(state.taildrop());
    tauri::async_runtime::spawn(run_managed_send(
        ManagedTaildropSend {
            port,
            secret,
            endpoint_tag,
            peer_stable_id,
            declarations,
            files,
        },
        runtime,
        task_id.clone(),
        started.cancel,
        sink,
    ));

    Ok(ApiResponse::ok(TaildropSendResult {
        canceled: false,
        file_count,
        bytes,
        task_id: Some(task_id),
    }))
}

/// 拉取有界任务快照。`server_id=None` 用于主窗口重建水合全部任务。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn taildrop_tasks(
    state: State<'_, AppRuntime>,
    server_id: Option<String>,
) -> Result<ApiResponse<Vec<TaildropTaskSnapshot>>, ()> {
    Ok(ApiResponse::ok(
        state.taildrop().snapshots(server_id.as_deref()),
    ))
}

/// 取消一个在途发件任务。终态重复取消幂等返回原快照。
#[allow(
    clippy::needless_pass_by_value,
    reason = "Tauri IPC command owns its deserialized payload across the call"
)]
#[tauri::command]
pub fn taildrop_task_cancel(
    state: State<'_, AppRuntime>,
    app: AppHandle,
    task_id: String,
) -> Result<ApiResponse<TaildropTaskSnapshot>, ()> {
    let sink = BroadcastTaildropTaskSink::new(app);
    Ok(match state.taildrop().cancel(&task_id, &sink) {
        Some(snapshot) => ApiResponse::ok(snapshot),
        None => ApiResponse::err_with_code(
            format!("Taildrop task not found: {task_id}"),
            ERR_TASK_NOT_FOUND,
        ),
    })
}

/// 取件：把收件箱里的一个文件写到用户选定的路径。
///
/// # 为什么先写 `.part` 再改名
///
/// 下载流**不重连**（见 [`SingBoxApiClient::download_taildrop_file`]）：中途断开会让已写出的字节
/// 成为半截文件。直接写目标路径的话，用户在文件管理器里看到的是一个大小对不上、却完全像回事的
/// 文件；写 `.part` + 成功才改名，则失败路径上目标位置**从来没有出现过**这个名字。
/// 临时文件与目标**同目录**（同卷），改名才是原子的；失败路径必删。
async fn write_stream_to(
    mut stream: TaildropDownload,
    dest: &std::path::Path,
) -> std::io::Result<u64> {
    use std::io::Write;

    let part = dest.with_extension(format!(
        "{}part",
        dest.extension()
            .map(|e| format!("{}.", e.to_string_lossy()))
            .unwrap_or_default()
    ));
    let mut file = std::fs::File::create(&part)?;
    let mut written = 0u64;
    let outcome = async {
        // 首帧只带 size（总字节、data 空）—— 把它当数据块写进去会在文件头多出内容。
        while let Some(chunk) = stream
            .message()
            .await
            .map_err(|e| std::io::Error::other(format!("DownloadTaildropFile stream: {e}")))?
        {
            if chunk.data.is_empty() {
                continue;
            }
            file.write_all(&chunk.data)?;
            written += chunk.data.len() as u64;
        }
        file.flush()?;
        Ok::<(), std::io::Error>(())
    }
    .await;
    drop(file);
    match outcome {
        Ok(()) => {
            std::fs::rename(&part, dest)?;
            Ok(written)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&part);
            Err(e)
        }
    }
}

/// 取件结果。`canceled` = 用户在原生保存框里按了取消（**不是错误**）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TaildropSaveResult {
    pub canceled: bool,
    /// 实际写入的目标路径（取消时缺省）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// 实际写出的字节数（取消时缺省）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
}

/// 取件：选一个保存位置，把收件箱里的该文件写过去。
///
/// **保存框开在 Rust 侧**，与 `local_import_pick_file` 同一范式 —— 前端因此不需要
/// `@tauri-apps/plugin-dialog` 这个 JS 依赖（本仓 UI 至今没有它，为一个按钮引进来不划算），
/// 框的标题也就自然走 Rust 侧 i18n 表（`native.taildropSaveTitle`，五语齐备由
/// `rust-i18n-coverage.test.ts` 守）。
///
/// 默认文件名取 `name`（收件箱里的原名），用户可改。
#[tauri::command]
pub async fn taildrop_save(
    state: State<'_, AppRuntime>,
    window: WebviewWindow,
    server_id: String,
    name: String,
) -> Result<ApiResponse<TaildropSaveResult>, ()> {
    let (client, tag) = match connect_for(&state, &server_id).await {
        Ok(v) => v,
        Err((msg, code)) => return Ok(ApiResponse::err_with_code(msg, code)),
    };

    // 先问路径再开流：反过来的话，用户在保存框里犹豫的这几十秒里流一直挂着，
    // 而取消之后那条流还得额外收一次尾。
    let lang = crate::i18n::app_lang(window.app_handle());
    let (tx, rx) = tokio::sync::oneshot::channel();
    window
        .dialog()
        .file()
        .set_title(crate::i18n::t(
            lang,
            crate::i18n::key::NATIVE_TAILDROP_SAVE_TITLE,
        ))
        .set_file_name(&name)
        .save_file(move |p| {
            let _ = tx.send(p);
        });
    let Some(dest) = rx.await.ok().flatten().and_then(|p| p.into_path().ok()) else {
        return Ok(ApiResponse::ok(TaildropSaveResult {
            canceled: true,
            ..Default::default()
        }));
    };

    let stream = match client.download_taildrop_file(tag, &name).await {
        Ok(s) => s,
        Err(e) => {
            return Ok(ApiResponse::err_with_code(
                format!("DownloadTaildropFile failed: {e}"),
                ERR_CALL,
            ))
        }
    };
    match write_stream_to(stream, &dest).await {
        Ok(n) => Ok(ApiResponse::ok(TaildropSaveResult {
            canceled: false,
            path: Some(dest.to_string_lossy().into_owned()),
            bytes: Some(n),
        })),
        Err(e) => Ok(ApiResponse::err_with_code(
            format!(
                "write selected file {:?} failed: {e}",
                selected_file_label(&dest)
            ),
            ERR_WRITE,
        )),
    }
}

#[cfg(test)]
mod tests;
