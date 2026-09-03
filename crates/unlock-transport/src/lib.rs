//! polaris-unlock-transport —— 解锁检测的**指纹伪装传输层**（`UnlockHttp` 的唯一生产实现）。
//!
//! 见 `~/docs/polaris/design/polaris-unlock-detection-cf.md`（根因与选型定案）。
//!
//! # 解决什么问题（根因 (b)：TLS/H2 指纹）
//!
//! 调研 §3.2 判定**主因**：上游 走 Electron `net.request` = Chromium 的 BoringSSL，ClientHello / HTTP2
//! SETTINGS / 伪头序都是**真 Chrome 形态**，Cloudflare 压根不对它出挑战；Polaris 走 `reqwest + rustls`，
//! ClientHello 是 rustls 默认形态，在 WAF 侧高度可识别 → 1020/403。
//!
//! **同仓已有实证**：`src-tauri/src/runtime/http.rs` 的 `warp_client` 文档记录过同一类问题 ——
//! 共享 rustls client 被 `api.cloudflareclient.com` 按 TLS 指纹判「自动化」。WARP 那条腿靠降级
//! TLS1.2+HTTP/1.1 绕过；解锁检测面对的是通用 CF 边缘，同招不管用，只能上真指纹伪装。
//!
//! 本 crate 用 `wreq` + `wreq_util::Profile::Chrome{N}`（`N` = [`CHROME_MAJOR`]）提供
//! **该版 Chrome 的 TLS(JA3/JA4) + HTTP/2 + 默认头形态**。
//! 能力边界 = **指纹，无 JS 执行** —— 这**恰好就是 上游的能力边界**
//! （调研 §5 已校正：上游 也不执行 JS，它是「没被出挑战」而非「解开了挑战」）。故本 crate 达成的是
//! **与 上游 严格对齐，不多不少**。
//!
//! # 为什么单独一个 crate（而不是塞进 `src-tauri/src/runtime/http.rs`）
//!
//! 任务硬要求：**指纹客户端不得泄漏到其它 HTTP 路径**（订阅拉取 / 内核下载 / 更新 / WARP 注册都不需要
//! 伪装，也不该承担这个依赖的风险）。放进 `src-tauri` 只能靠**约定**守边界 —— 任何模块都能
//! `use wreq`。独立 crate 把它变成**结构性**约束：`wreq` 只是本 crate 的依赖，
//! 其它 crate 想用必须先改 Cargo.toml（review 时看得见）。
//!
//! 代价如实记：进程内会有**两套 TLS 栈**（rustls-ring + BoringSSL）。这是指纹伪装的固有成本，
//! 调研 §4.B「代价」栏已列明并被接受。
//!
//! # 依赖选型（版本与理由）
//!
//! | 项 | 结论 |
//! |---|---|
//! | `rquest` | **已弃**。crates.io `max_version = 0.0.0`（全撤），最后真实版本 5.2.0 停在 2025-07-11；上游仓已归档为 `rquest-deprecated`。**不可用**。 |
//! | `wreq` **6.0.0-rc.31** | 当前可与指纹模板配套的最新版本。稳定版 0.16.1 已发布，但唯一模板包 `wreq-util` 3.0.0-rc.14 仍声明 `wreq = ^6.0.0-rc`；单升稳定版会形成两套不兼容的 `IntoEmulation` 类型并失去 Chrome 指纹，属于实际功能退化，故等待两者发布兼容稳定组合。 |
//! | `wreq-util` **3.0.0-rc.14** | 浏览器指纹模板，其 `wreq` 约束是 `^6.0.0-rc` ⇒ **与上面绑定升**（升 util 必然把 wreq 拖到 RC）。Chrome 模板覆盖 100~**149**，本 crate 按 [`CHROME_MAJOR`] const 派生选用（与 [`UA`](polaris_unlock::endpoints::UA) **精确同版**）。 |
//! | Tauri WebView | **不选**。mac/Linux 是 WebKit 非 Chromium → 配 Chrome UA 反成**更强** bot 信号（比现状更糟）；另有 macOS 14+ / `macos-proxy` 门槛与远程源 IPC 安全面。 |
//! | cronet | **不选**。仓内 `libcronet.*` 只是随 sing-box 内核分发的 so/dylib，**无任何 Rust 绑定**；复用成本 = 从零写 FFI，换来的能力与 `wreq` 同级（指纹，无 JS）。严格劣于 `wreq`。 |
//!
//! **敢钉 RC 的前提 = 爆炸半径已封死**：`wreq`/`wreq-util` 只被本 crate 依赖（由
//! `wreq_is_declared_only_by_this_crate` 门守）；主代理数据面是 sing-box 外部进程 + hyper/tonic gRPC 控制面，
//! 其余 HTTP（订阅拉取 / 更新检查 / 规则资源）走 `src-tauri` 的 reqwest+rustls。**都不经过 `wreq`**
//! ⇒ RC 引擎出问题的后果是「解锁徽章不准」，不是「代理不通」。
//!
//! **构建链代价（三平台 CI 必读）**：`wreq` 6 的 TLS 后端从 `boring2`/`boring-sys2`/`tokio-boring2`
//! 换成 `btls`/`btls-sys`/`tokio-btls`（同为 **vendored BoringSSL**），HTTP/2 从 `hyper2` 换成
//! `http2`+`wreq-proto`+`wreq-rt`。构建前置**没变**：`cmake` + C 工具链 + `libclang`（`bindgen`）。
//! 本机实测：缺 `cmake` 直接失败；缺 clang builtin headers 报 `'stddef.h' file not found`，
//! 需 `BINDGEN_EXTRA_CLANG_ARGS` 指向 gcc include 目录。
//! **交叉编译（Windows/macOS 产物）须重新验**——这是本依赖最大的落地风险面。
//!
//! # 6.x / 3.x 的破坏性变更（本 crate 逐条跟进过的）
//!
//! | 变更 | 处理 |
//! |---|---|
//! | `wreq_util::Emulation` 枚举更名 `Profile`；`Emulation` 变成 profile+platform 的 builder | 派生表返回 [`wreq_util::Profile`]；`Emulation::ChromeNNN` 别名仍编译得过，故源码扫描门同时拦两种写法 |
//! | `Response::chunk()` **删除**，流式读只剩 `bytes_stream()`（`stream` feature） | 开 `stream`；`read_body_truncating` 改按值接管 `Response`，截断 + 停滞看门狗逐字保留 |
//! | `wreq::Url` **不再 re-export**（改 `http::Uri` + `IntoUri`） | 直接依赖 `url` crate（wreq 6 内部解 `Location` 用的同一个），零新增 lock 包 |
//! | `RequestBuilder::header()` 从「覆盖同名」变成 **`append`**（文档没跟上，代码是 `headers_mut().append`） | 本实现的每个 header 名在单次请求里只设一次（源是 `BTreeMap`），append 后再由客户端层 `replace_headers` 覆盖 emulation 默认头；并加了**线级不重复**断言把这条钉死 |
//! | `wreq-util` 的 `emulation` feature 不再转发 `wreq/gzip\|brotli\|deflate\|zstd` | 四个压缩 feature 改由本 crate **直接**声明（漏声明 = 解压静默失效 = marker 全落空的静默误判） |
//! | `wreq` 默认 feature 集变化（`charset`/`macos-system-configuration` 出，`tokio-rt` 入） | 无影响：body 一律 `from_utf8_lossy` 不走 charset；代理由 `.proxy()`/`.no_proxy()` 显式指定 |
//! | `Policy::none()` 语义 | **未变**（仍是「一跳都不跟」），逐跳 `redirect_chain` 仍由本实现自己跑 |
//!
//! # 模板漂移风险 / 三处身份的同源约束
//!
//! 指纹模板的价值 100% 取决于它跟不跟得上真 Chrome。Chrome 版本推进后若不同步升级，
//! 指纹会变成「旧版 Chrome」这一**可疑信号**。
//!
//! 但**更糟的失效形态是「只升一处」**：TLS 指纹说 137、UA 说 131 ⇒ 自相矛盾，
//! 指纹服务专抓这种，比单纯陈旧更强的 bot 信号。故浏览器身份收口在
//! [`CHROME_MAJOR`] 一个常量上：
//!
//! - 本 crate 的 emulation **由它 const 派生**（`chrome_emulation`）——**没有第二处版本字面量可改**，
//!   且 `wreq-util` 无对应模板时 const 求值 panic ⇒ **编译失败**；
//! - `Profile::Chrome…`（含 `Emulation::Chrome…` 这个 3.x 别名）字面量只准出现在派生表里，
//!   由 `emulation_variant_is_derived_not_hardcoded` 源码扫描门守（绕过派生直接写死 = 转红）；
//! - UA / `sec-ch-ua` 那半边由 unlock crate 的 `sec_ch_ua_major_version_matches_ua` 守。

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use polaris_unlock::endpoints::{CHROME_MAJOR, MAX_BODY_BYTES, MAX_REDIRECTS, REQ_TIMEOUT_MS};
use polaris_unlock::http::{HttpMethod, RedirectHop, UnlockHttp, UnlockRequest, UnlockResponse};

/// 单请求超时（= 上游 `unlock-http.ts` 8s，经 unlock crate 常量单点取）。
const UNLOCK_TIMEOUT: Duration = Duration::from_millis(REQ_TIMEOUT_MS);

/// Chrome 主版本号 → `wreq-util` 指纹模板。**这是本 crate 唯一允许写 `Profile::Chrome…` 的地方。**
///
/// 每行形如 `NNN => wreq_util::Profile::ChromeNNN,`，左右两个数字必须相等 ——
/// 由 `emulation_variant_is_derived_not_hardcoded` 源码扫描门逐行校验（写错行号即转红）。
///
/// `_` 分支 `panic!` 在 const 上下文求值 ⇒ 把 [`CHROME_MAJOR`] 升到 `wreq-util` 没有模板的版本
/// 是**编译错误**，绝不会静默退回旧模板（也就不会出现「以为升了、其实没升」）。
///
/// **wreq-util 3.x 的类型改名**：带 `ChromeNNN` 变体的枚举从 `Emulation` 更名为
/// [`wreq_util::Profile`]；`Emulation` 现在是「profile + platform + http2/headers 开关」的
/// builder 结构体。`wreq_util::Emulation::ChromeNNN` 作为**同类型关联常量**仍然编译得过
/// （`define_enum!` 给 `Emulation` 补了一批 `pub const ChromeNNN: Profile`），故上面那扇源码扫描门
/// 两种写法都拦（只放行本表的 `wreq_util::Profile::ChromeNNN` 形态）。
const fn chrome_emulation(major: u32) -> wreq_util::Profile {
    match major {
        131 => wreq_util::Profile::Chrome131,
        132 => wreq_util::Profile::Chrome132,
        133 => wreq_util::Profile::Chrome133,
        134 => wreq_util::Profile::Chrome134,
        135 => wreq_util::Profile::Chrome135,
        136 => wreq_util::Profile::Chrome136,
        137 => wreq_util::Profile::Chrome137,
        138 => wreq_util::Profile::Chrome138,
        139 => wreq_util::Profile::Chrome139,
        140 => wreq_util::Profile::Chrome140,
        141 => wreq_util::Profile::Chrome141,
        142 => wreq_util::Profile::Chrome142,
        143 => wreq_util::Profile::Chrome143,
        144 => wreq_util::Profile::Chrome144,
        145 => wreq_util::Profile::Chrome145,
        146 => wreq_util::Profile::Chrome146,
        147 => wreq_util::Profile::Chrome147,
        148 => wreq_util::Profile::Chrome148,
        149 => wreq_util::Profile::Chrome149,
        _ => panic!(
            "wreq-util 3.0.0-rc.14 无此 Chrome 指纹模板（其 Chrome 模板止于 149）——\
             升 CHROME_MAJOR 前须先确认 wreq-util 已支持该版本并在此表补行"
        ),
    }
}

/// 本 client 使用的指纹模板 —— 由 [`CHROME_MAJOR`] 派生，**不是**独立可改的第二处版本钉子。
const EMULATION: wreq_util::Profile = chrome_emulation(CHROME_MAJOR);

/// 指纹伪装的解锁检测客户端 —— [`UnlockHttp`] 的**唯一生产实现**。
///
/// 出口 pin 语义与原 `HttpRuntime::via_local_proxy` 等价（经本机 mixed 口的 HTTP CONNECT 代理），
/// 故检测请求走用户当前分流出口 —— 与 上游的 socks5 session pin 同效。
pub struct UnlockClient {
    client: wreq::Client,
}

/// 建带 Chrome 指纹（版本 = [`CHROME_MAJOR`]）的 client 骨架（`redirect` 关死：解锁要逐跳 `redirect_chain`）。
fn base_builder() -> wreq::ClientBuilder {
    wreq::Client::builder()
        // 指纹本体：TLS(JA3/JA4) + HTTP/2 SETTINGS/伪头序 + Chrome 默认头集与**发送顺序**。
        // 版本由 `EMULATION` 派生自 `CHROME_MAJOR` —— 此处**不得**写死 `Profile::Chrome…`。
        //
        // wreq-util 3.x 起可另配 `Platform`（`Emulation::builder().profile(..).platform(..)`），
        // 默认 `MacOS`。**刻意不配 `Platform::Windows`**：本实现逐请求覆盖 emulation 的每一条默认头
        // （UA / sec-ch-ua* / accept* / sec-fetch* / priority 全在 `browser_headers` 里），platform
        // 到不了线上；而把它设成 Windows 会让 `browser_headers_reach_the_wire` 那扇门失去鉴别力
        // ——该门正是靠「线上 UA 是我们的 Windows Chrome 而**不是** emulation 默认的 macOS UA」
        // 来证明覆盖是**完全**的。两者同为 Windows 后，覆盖漏一条也测不出来。
        .emulation(EMULATION)
        // 逐跳记录 Location 由本实现自己跑（checker 的判据之一是完整 redirect_chain）。
        .redirect(wreq::redirect::Policy::none())
        // **cookie jar**：补齐「像浏览器」的最后一块行为面（与 TLS/头指纹正交）。
        //
        // 没有它时：一个 cookie 都不发，且**跨重定向跳丢 `Set-Cookie`** —— 而我们恰恰是手动逐跳跟随的，
        // 首跳响应 `Set-Cookie` 后第二跳照样裸奔。真 Chrome 全新 profile 打 `netflix.com/title/X` 的行为是
        // 「首请求无 cookie → 拿到 `Set-Cookie` → 跟随跳转时带上」，我们与之的差别是一条**独立于指纹**的信号。
        //
        // 为什么这里加是安全的（不会引入跨轮/跨出口污染）：`UnlockClient` 在
        // `src-tauri/src/commands/unlock.rs` 里**每轮检测新建**（warm 补测也各建一个），
        // jar 随 client 一起丢弃 ⇒ 不存在「上一轮 / 上一个出口的 cookie 影响这一轮判定」。
        // 轮内 6 个 checker 并发打不同域，cookie 按域隔离，互不串。
        //
        // 该行为由 `set_cookie_is_carried_across_manual_redirect_hops` 回环门守（删掉本行即转红）。
        .cookie_store(true)
}

impl UnlockClient {
    /// 经本机 mixed 端口的检测客户端（**生产路径**：走用户当前分流出口）。
    ///
    /// # Errors
    ///
    /// 代理地址非法或 client 构建失败（BoringSSL 初始化）。
    pub fn via_local_proxy(port: u16) -> Result<Self, String> {
        let proxy = wreq::Proxy::all(format!("http://127.0.0.1:{port}"))
            .map_err(|e| format!("本机代理地址非法（port={port}）: {e}"))?;
        let client = base_builder()
            .proxy(proxy)
            .build()
            .map_err(|e| format!("建解锁检测客户端失败: {e}"))?;
        Ok(Self { client })
    }

    /// 直连检测客户端（**不经代理**）。
    ///
    /// 仅供本 crate 的回环单测使用；生产检测**必须**走 [`Self::via_local_proxy`] ——
    /// 直连会测到宿主 IP 而给出完全错误的结论（上游 对这个陷阱有显式防御：
    /// `UnlockDetectionService.ts:9`「setProxy reject → 本轮放弃，绝不落 default session」）。
    ///
    /// # Errors
    ///
    /// client 构建失败。
    pub fn direct() -> Result<Self, String> {
        base_builder()
            .no_proxy()
            .build()
            .map(|client| Self { client })
            .map_err(|e| format!("建解锁检测客户端失败: {e}"))
    }
}

/// 流式读 body 并**截断**到上限（解锁语义：截断后仍要判，与订阅相反）。返回 `(bytes, truncated)`。
///
/// 每个 chunk 单独计时 = 停滞看门狗（整请求超时管不了「一直有数据但极慢」）。
///
/// **wreq 6 破坏性变更**：`Response::chunk()` 被删，流式读只剩 `bytes_stream()`（`stream` feature）。
/// 故本函数改为**按值接管** `Response`（`bytes_stream(self)` 消费它），调用方须先把 status/headers 取走。
/// 逐 chunk 的截断与停滞看门狗语义**逐字保留** —— 换成 `Response::bytes()` 会同时丢掉这两条
/// （整包缓冲 = 无上限内存 + 慢速流拖满整请求超时）。
async fn read_body_truncating(
    resp: wreq::Response,
    max: usize,
    stall: Duration,
) -> Result<(Vec<u8>, bool), String> {
    let mut stream = Box::pin(resp.bytes_stream());
    let mut buf = Vec::new();
    loop {
        let next = tokio::time::timeout(stall, stream.next())
            .await
            .map_err(|_| format!("读取响应体停滞超过 {}ms", stall.as_millis()))?;
        match next
            .transpose()
            .map_err(|e| format!("读取响应体失败: {e}"))?
        {
            None => return Ok((buf, false)),
            Some(chunk) => {
                if buf.len() + chunk.len() > max {
                    buf.extend_from_slice(&chunk[..max.saturating_sub(buf.len())]);
                    return Ok((buf, true));
                }
                buf.extend_from_slice(&chunk);
            }
        }
    }
}

#[async_trait]
impl UnlockHttp for UnlockClient {
    /// **永不 panic、永不 Err**：失败落 `status=0 + error`（契约：由 checker 兜底为 Timeout）。
    ///
    /// # 头集与 emulation 的关系（诚实边界）
    ///
    /// `EMULATION` 已在 client 级设了一套 Chrome 默认头（含**发送顺序**）。本实现把
    /// [`UnlockRequest`] 携带的头（来自 `polaris_unlock::browser`）逐条 `header()` 覆盖上去：
    /// **值**因此被钉死为我们自己的常量（不随 `wreq-util` 补丁版漂移，且 UA/平台自洽由
    /// unlock crate 单测保证），**代价**是这批头会被提到发送序前部，不再是 Chrome 的原生顺序。
    ///
    /// **wreq 6 的 `header()` 语义变了**：5.x 是「覆盖同名」，6.x 实现是 `headers_mut().append`
    /// （其 doc 注释仍写 replaced，**以代码为准**）。本实现仍然安全，靠两条：
    /// ① [`UnlockRequest::headers`] 是 `BTreeMap` ⇒ 单次请求里每个头名只会被 `header()` 设**一次**；
    /// ② 客户端层合并默认头走 `replace_headers`（请求头**按名整体替换**掉 emulation 的默认值，
    ///    见 `wreq-6.0.0-rc.31/src/client/layer/config.rs`）。
    /// 二者叠加后净效果与 5.x 的覆盖一致。**但这是隐式的**，故 `browser_headers_reach_the_wire`
    /// 里加了一条「线上同名头不得出现两次」的断言——真退化成 append 时（例如日后有人给同一名字
    /// 大小写各设一次）会立刻转红，而不是安静地发出两个自相矛盾的 UA。
    ///
    /// 权衡：header **顺序**是次级信号，TLS/H2 指纹（本 crate 的主要收益）不受影响；而**值的可控性**
    /// 关系到「UA 与 sec-ch-ua 是否自洽」这条已被单测钉死的硬不变量。故取「值自持、序让步」。
    async fn request(&self, req: &UnlockRequest) -> UnlockResponse {
        let mut current = req.url.clone();
        let mut chain: Vec<RedirectHop> = Vec::new();

        for _ in 0..=MAX_REDIRECTS {
            let mut builder = match req.method {
                HttpMethod::Get => self.client.get(&current),
                HttpMethod::Post => self.client.post(&current),
            };
            for (k, v) in &req.headers {
                builder = builder.header(k.as_str(), v.as_str());
            }
            if let Some(body) = &req.body {
                builder = builder.body(body.clone());
            }

            let sent = match tokio::time::timeout(UNLOCK_TIMEOUT, builder.send()).await {
                Err(_) => {
                    return UnlockResponse::err(format!(
                        "请求超时（{}ms）",
                        UNLOCK_TIMEOUT.as_millis()
                    ))
                }
                Ok(Err(e)) => return UnlockResponse::err(format!("请求失败: {e}")),
                Ok(Ok(r)) => r,
            };
            let resp = sent;
            let status = resp.status().as_u16();

            if (300..400).contains(&status) {
                if let Some(loc) = resp
                    .headers()
                    .get(wreq::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
                {
                    chain.push(RedirectHop {
                        status,
                        location: loc.clone(),
                    });
                    // wreq 6 不再 re-export `Url`（`wreq::Url` 没了）；`http::Uri` 无相对引用解析。
                    // 直接用 `url` crate —— 与 wreq 5 的 `wreq::Url` 同一实现，也是 wreq 6 内部解
                    // `Location` 用的同一条路径（`src/client/layer/redirect/future.rs:196`），语义不变。
                    // 注意：链里存的仍是**原始 Location 串**（上面 `loc.clone()`），checker 按原样解析。
                    match url::Url::parse(&current).and_then(|b| b.join(&loc)) {
                        Ok(next) => {
                            current = next.to_string();
                            continue;
                        }
                        Err(e) => return UnlockResponse::err(format!("重定向目标非法 {loc}: {e}")),
                    }
                }
                // 30x 无 Location → 当终态（与 net-stack 同口径）。
            }

            // 终态响应头：JS 挑战识别（cf-mitigated / server）的判据来源。
            // HeaderName 本就小写规范化 → 直接照填（契约要求小写键）。
            // 多值头**取首值**（`or_insert`，非后值覆盖）：unlock 只读单值头。
            let mut headers: BTreeMap<String, String> = BTreeMap::new();
            for (k, v) in resp.headers().iter() {
                if let Ok(s) = v.to_str() {
                    headers
                        .entry(k.as_str().to_string())
                        .or_insert_with(|| s.to_string());
                }
            }

            let (body, truncated) =
                match read_body_truncating(resp, MAX_BODY_BYTES, UNLOCK_TIMEOUT).await {
                    Ok(v) => v,
                    Err(e) => return UnlockResponse::err(e),
                };
            return UnlockResponse {
                status,
                body: String::from_utf8_lossy(&body).into_owned(),
                truncated,
                redirect_chain: chain,
                error: None,
                headers,
            };
        }
        UnlockResponse::err(format!("重定向次数超过上限（{MAX_REDIRECTS}）"))
    }
}

#[cfg(test)]
mod tests;
