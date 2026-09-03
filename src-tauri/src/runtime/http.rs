//! 传输层单点 —— **整个 workspace 唯一的真实 HTTP/TLS 客户端**。
//!
//! 各 domain crate 只声明窄 trait（端口），真实传输在此注入（见 `runtime.rs` 模块文档的注入架构）。
//! 本模块用一个共享 [`reqwest::Client`] 适配四个既有窄 trait；订阅直连为了把 SSRF guard 的同次
//! DNS 结果 pin 到 dial，会按跳构建窄 client（代理腿仍复用共享 client，保留 remote-DNS）。
//!
//! | trait | 所有者 crate | 本模块适配点 |
//! |---|---|---|
//! | [`polaris_net_stack::safe_redirect::HttpClient`] | net-stack（`safe_redirect.rs`） | [`HttpRuntime`]（manual redirect + 流式限长） |
//! | [`UpdateDownloader`] | updater（`traits.rs`） | [`CoreDownloader`]（**唯一**下载适配器） |
//! | ~~`UnlockHttp`~~ | unlock（`http.rs`） | **已迁出** → `polaris-unlock-transport`（wreq 指纹伪装，见适配③处注释） |
//! | [`WarpHttp`] | mesh（`warp_http.rs`） | [`HttpRuntime`]（json/status 双语义） |
//! | [`DohPost`](polaris_dns_race::DohPost) | dns-race（`query.rs`） | [`HttpRuntime`]（C11 节点域名竞速的 DoH 上游） |
//!
//! 另补 [`SystemDnsLookup`]：net-stack `DnsLookup` 的**首个生产实现**（此前全仓仅测试 mock，
//! 意味着 SSRF guard 在生产路径上根本没有解析器可用）。
//!
//! # 编排不在这里（上游 双份编排的病根）
//!
//! 上游的 `core-downloader.ts` 与 `UpdateService.ts` 各写了约 170 行同构下载编排，两文件注释
//! 互指重复。Rust 侧编排**已经各归其位**：updater 守 staged 周期、net-stack 守 SSRF + 逐跳重定向。
//! 故本模块**只有传输**，且把 `UpdateDownloader` doc 划给「实现侧」的那几件事
//! （停滞看门狗 / 镜像回退 / 403 限流分类 / 16MiB 闸 / 15s 超时 / Content-Length 完整性）
//! **全部收在 [`CoreDownloader`] 这一个适配器里** —— 订阅路径的 [`polaris_net_stack::safe_redirect::HttpClient`] 适配器不得复制它们。
//!
//! # rustls provider：一个「编译过 ≠ 能跑」的陷阱（实证）
//!
//! `reqwest` 的 `rustls` feature 会拉 `aws-lc-rs`（需 cmake/NASM，破坏交叉编译干净），故本仓用
//! `rustls-no-provider` + 手动选 `ring`。代价是 **reqwest 不再自带 provider**：
//! `reqwest-0.13.4/src/async_impl/client.rs:2482 default_rustls_crypto_provider()` 在
//! 未安装 provider 时**直接 `panic!`** —— 而且是在 `Client::build()` 运行期，不是编译期。
//!
//! 即：漏掉 [`install_ring_provider`] 的代码**编译完全通过、类型完全正确、第一次建 client 就炸**。
//! 这正是 §K7.1「组合面无门」的形态。故 [`HttpRuntime::new`] 无条件先装 provider，
//! 并由 `http_runtime_builds_a_real_client_without_panicking` 钉死（该测试若删掉 provider 安装即 panic 转红）。

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use polaris_mesh::warp_http::{WarpHttp, WarpHttpMethod, WarpHttpRequest, WarpHttpResponse};
use polaris_updater::traits::{DownloadError, UpdateDownloader};

// ── 传输层常量（单点定义，各消费族不得自造第二份）───────────────────────────────

/// 应用自标识 UA（= 上游 `APP_USER_AGENT`）。
///
/// **与订阅 UA 是两回事**：订阅走 `net_stack::subscription::default_subscription_user_agent`
/// （中性 `Polaris/<ver>`，由调用方按订阅偏好覆盖）；本 UA 用于 GitHub API / 资源下载。
/// **勿与 mesh 的 `WARP_USER_AGENT` 共用** —— 那个是伪装 okhttp 的特例。
pub fn app_user_agent() -> String {
    format!("Polaris/{}", env!("CARGO_PKG_VERSION"))
}

/// 响应头超时（连接 + 首字节）。= Polaris 下载链路 15s。
/// **不是**整请求超时：大文件下载正常会超过 15s，整请求超时会把正常下载判死。
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);

/// 停滞看门狗：body 流式读取时**两个 chunk 之间**的最大间隔（= 上游 `createIdleTimeout` 30s）。
/// 对付 slow-loris / 半死连接：整请求超时管不了「一直有数据但极慢」，idle 才管得了「彻底没数据」。
const STALL_TIMEOUT: Duration = Duration::from_secs(30);

/// **内存型**下载的体积硬闸（16 MiB）。核二进制 ~10MiB 量级；超此即拒，防 OOM。
///
/// # 它是「内存闸」，不是「文件闸」
///
/// 两条内核腿（手动换核 / 自动换核）走的是 `download` → `Vec<u8>` → 解归档，字节全程在堆上，
/// 故上限就该按**内存**定。App 安装包腿改成流式落盘后内存占用与包体积解耦，再拿 16 MiB 卡它
/// 只会把所有正常安装包拒之门外 —— 那条腿的闸值改由调用方按「清单声明大小 + 裕度」注入
/// （见 [`CoreDownloader::with_max_bytes`]）。
///
/// `pub(crate)`：三个 `updater_downloader` 调用点里的两条内核腿要**逐字传这个值**
/// （语义与形参化之前完全一致）；各写一份字面量必然漂移。
pub(crate) const MAX_DOWNLOAD_BYTES: usize = 16 * 1024 * 1024;

/// 下载路径的重定向上限（GitHub release 资产必然 302 到 objects.githubusercontent.com）。
const MAX_DOWNLOAD_REDIRECTS: usize = 5;

/// WARP 请求超时（= 上游 `WarpService` 15s）。
const WARP_TIMEOUT: Duration = Duration::from_secs(15);

/// WARP 响应体截断上限（register 错误信息 ~200B / unregister 的 body-code-1020 检测需前 512B）。
const WARP_MAX_BODY_BYTES: usize = 8 * 1024;

// ── rustls crypto provider ────────────────────────────────────────────────────

/// 安装 `ring` 作为 rustls 默认 CryptoProvider（进程级，幂等）。
///
/// 见模块文档「rustls provider 陷阱」：不装 → `Client::build()` 运行期 panic。
fn install_ring_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if rustls::crypto::ring::default_provider()
            .install_default()
            .is_err()
        {
            // 已由他处安装（例如测试进程内先建过 client）：沿用既有，不是错误。
            log::debug!("rustls CryptoProvider 已安装，沿用既有");
        }
    });
}

// ── WARP 注册专用 client（TLS 指纹规避）─────────────────────────────────────────

/// 建 WARP 注册专用 client：**TLS1.2-only + HTTP/1.1-only**，对齐 上游 `WarpService` 的 node-`https`
/// （`minVersion=maxVersion=TLSv1.2`，默认走 HTTP/1.1、不提供 h2）指纹规避。
///
/// # 为什么单独一个 client（不复用共享 `client`）
///
/// 共享 client 走 rustls-default：ClientHello 提供 **TLS1.3（supported_versions 含 0x0304）+ h2 ALPN**。
/// `api.cloudflareclient.com` 的 Cloudflare WAF 按 TLS 指纹判「非浏览器/自动化」→ 返 **1020/403**
/// （见 mesh crate `warp_http.rs` 文档）。用 rustls 现有能力复刻 上游的**同一形态**：
/// - [`tls_version_max`](reqwest::ClientBuilder::tls_version_max)`(TLS_1_2)` → reqwest 把 `rustls::ALL_VERSIONS`
///   retain 到 ≤TLS1.2 → ClientHello 不再宣告 TLS1.3；
/// - [`http1_only`](reqwest::ClientBuilder::http1_only) → ALPN 只报 `http/1.1`（不报 `h2`）。
///
/// # 忠实边界：收窄形态，**非**字节级 okhttp JA3
///
/// rustls 只带 AEAD cipher（无 CBC）、扩展集固定，**无法**字节级仿 okhttp 的 JA3。但 oracle 实证 上游 **本身也没仿**：
/// 它用 node-OpenSSL 的 TLS1.2 ClientHello（≠ okhttp 真 JA3，okhttp=Android Conscrypt/BoringSSL）就过了 CF，
/// 说明 CF 判的是**粗形态**（TLS1.2/HTTP1.1 vs TLS1.3/h2），非精确 JA3 白名单。故收窄形态在忠实迁移口径上足矣。
/// **残余风险**：rustls 的 TLS1.2 指纹仍是第三种（既非 node-OpenSSL 亦非 okhttp）——若 CF 恰把它列黑，则仅钉版本不够。
/// 这只能真打 `api.cloudflareclient.com` 验证（见 WarpHttp impl 文档的**真机门**）。失败形态是明确的 403+body-1020，
/// 已被 `classify_deregister_result` 分类，不会伪装成成功。
///
/// no_proxy + redirect-none 同共享 client：WARP 注册须直连 CF（自举友好，且 mesh 契约「无重定向」）。
/// **不设默认 UA**：okhttp UA 由 mesh 层随请求头逐条下发（`warp_http.rs` 的 `build_reg_headers`）。
fn build_warp_client() -> Result<reqwest::Client, String> {
    install_ring_provider();
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .http1_only()
        .tls_version_min(reqwest::tls::Version::TLS_1_2)
        .tls_version_max(reqwest::tls::Version::TLS_1_2)
        .build()
        .map_err(|e| format!("建 WARP 客户端失败: {e}"))
}

mod subscription_transport;

use subscription_transport::HttpResolutionMode;
pub use subscription_transport::SystemDnsLookup;

// ── 传输层单点 ────────────────────────────────────────────────────────────────

/// 真实 HTTP 客户端（进程内单实例，经 `AppRuntime` 注入各 command）。
///
/// # 为什么 redirect 关死
///
/// 四个消费族**全部**要 manual redirect 语义：
/// - net-stack `HttpClient`：doc 明写「不得自动跟随（须原样返回 30x + Location）」——
///   自动跟随会让首 URL 过 guard 后被跳到内网而不复检 = SSRF 绕过；
/// - unlock：要逐跳 `redirect_chain`（判定依据之一）；
/// - WARP：无重定向；
/// - 下载：要自管链以便镜像回退。
///
/// 裁决文档设想的「同一 client per-request 关/开 redirect」在 reqwest 上**不成立**
/// （`redirect::Policy` 只在 `ClientBuilder` 上，`RequestBuilder` 无 per-request 覆盖）。
/// 故取「client 全局关 redirect + 需要跟随者自己跑循环」——**唯一**需要跟随的是
/// [`CoreDownloader`]，而它本就要为镜像回退跑自己的循环。仍是一个 client。
///
/// # 为什么禁用代理
///
/// 本 App **自己就是设置系统代理的那一方**。若 reqwest 继承系统/环境代理，订阅拉取会绕回
/// 我们自己的核 —— 起核前拉订阅直接死锁（鸡生蛋）。故 `no_proxy()` + 编译期关掉
/// `system-proxy` feature 双保险。确需经代理的路径（订阅 `viaProxy`）走
/// [`HttpRuntime::via_local_proxy`] 显式建第二个 client，**显式优于隐式**。
pub struct HttpRuntime {
    client: reqwest::Client,
    resolution_mode: HttpResolutionMode,
    /// WARP 注册专用 client（**TLS1.2-only + HTTP/1.1-only**）。
    ///
    /// 共享 `client` 走 rustls-default（ClientHello 提供 TLS1.3 + h2 ALPN），会被 `api.cloudflareclient.com`
    /// 的 Cloudflare WAF 按 TLS 指纹判「自动化」→ **1020/403**。此 client 用 rustls 现有能力收窄 ClientHello
    /// 形态、对齐 上游 `WarpService` 的 node-`https`（TLS1.2 pin + HTTP/1.1）规避。见 [`build_warp_client`]。
    ///
    /// **仅** [`warp_send`] 用 —— 订阅拉取 / 内核下载 / 解锁 / 更新等其它消费族继续走共享 `client`（它们不面对 CF WAF，
    /// 且钉 TLS1.2 会牺牲这些路径本可用的 TLS1.3/h2）。隔离由 `warp_send(self.warp_client()?, ..)` 单点保证。
    ///
    /// # 为什么**惰性**（`OnceLock` 而非构造期就建）
    ///
    /// [`Self::via_local_proxy`] 是**测速热路径**（每个被测节点一次），而它此前每次都白建一个 rustls client：
    /// reqwest 0.13.4 在 `build()` 里调 `rustls_platform_verifier::Verifier::new`，
    /// **Linux 走 `rustls_native_certs::load_native_certs()`，每个 client 读一次系统信任库**
    /// （`rustls-platform-verifier-0.7.0/src/verification/others.rs:88-100`，十几到几十毫秒）；
    /// macOS（`apple.rs:59-66`）/ Windows（`windows.rs:557-564`）只存字段不加载证书，便宜。
    /// 即在 Mac/Win 上这不是主要耗时，但**在任何平台上都是纯浪费** —— WARP 注册与测速毫无关系。
    ///
    /// **代价（如实登记）**：建这个 client 的错误（rustls 配置非法）此前在 [`Self::new`] 处冒泡、
    /// App 起不来就报错退出；改惰性后推迟到**首次 WARP 请求**才冒泡。那条路径本就返回 `Result<_, String>`
    /// 且有明确失败形态，故不会被吞；反过来说，WARP 客户端建不出来也不再拖垮整个 App 启动。
    warp_client: std::sync::OnceLock<reqwest::Client>,
}

impl HttpRuntime {
    /// 建传输层单点。
    ///
    /// # Errors
    ///
    /// TLS 后端初始化失败（`rustls` 配置非法）。**不 panic**：起不来 App 也要能报错退出。
    pub fn new() -> Result<Self, String> {
        install_ring_provider();
        let client = reqwest::Client::builder()
            // 见类型文档：四个消费族全要 manual redirect。
            .redirect(reqwest::redirect::Policy::none())
            // 见类型文档：绝不继承我们自己设的系统代理。
            .no_proxy()
            .user_agent(app_user_agent())
            .build()
            .map_err(|e| format!("建 HTTP 客户端失败: {e}"))?;
        Ok(Self {
            client,
            resolution_mode: HttpResolutionMode::DirectPinned,
            warp_client: std::sync::OnceLock::new(),
        })
    }

    /// 建传输层单点，并把指定 host 的 DNS 解析**钉死**到给定 socket 地址。
    ///
    /// 生产用途：DNS 固定（防解析漂移 / 内部服务寻址）。
    /// 生产组合面门用途：让**真实** reqwest client 连到回环测试服务器，而 SSRF guard 仍对
    /// **真实公网 hostname** 走真实 `SystemDnsLookup` 判定 —— 二者分层（guard 判 hostname、
    /// 传输落点由 client 决定），故这不是「绕过 guard」。
    ///
    /// # Errors
    ///
    /// TLS 后端初始化失败。
    #[cfg(test)]
    pub fn with_resolve_overrides(
        overrides: &[(&str, std::net::SocketAddr)],
    ) -> Result<Self, String> {
        install_ring_provider();
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .user_agent(app_user_agent());
        for (host, addr) in overrides {
            builder = builder.resolve(host, *addr);
        }
        let client = builder
            .build()
            .map_err(|e| format!("建 HTTP 客户端失败: {e}"))?;
        Ok(Self {
            client,
            resolution_mode: HttpResolutionMode::TestOverride,
            warp_client: std::sync::OnceLock::new(),
        })
    }

    // ── 经本机 sing-box 入站的两个构造器：**scheme 必须与入站类型对上** ──────────────
    //
    // `config-engine/builder/inbounds.rs` 建的本机入站有三种，**不是同一种协议**：
    //   | 入站 | type | 消费者 |
    //   |---|---|---|
    //   | `mixed-in`            | `mixed`（HTTP+SOCKS 同口，按首字节分流） | 测速回退腿 / ipinfo 出口探测 |
    //   | `probe-in-k` / `probe-{direct,proxy}-in` | **`http`（纯 HTTP）** | 测速探测池（`speedtest.rs`） |
    //   | `update-in`           | **`socks`（纯 SOCKS）**                  | 订阅 viaProxy / icon 远端代理 |
    //
    // 故**不能**用一个 scheme 通吃：socks5 打不通 `probe-in-k`（纯 http），http 打不通 `update-in`
    // （纯 socks）。两个构造器按消费端入站类型分别取用 —— 选错的后果都是真机才可见的静默失效
    // （测速全超时 / 订阅更新恒失败），故这里把对应关系写死在文档里。

    /// 经本机 **HTTP** 入站的 client（`mixed-in` / `probe-in-k` / `probe-*-in`）。
    ///
    /// 消费者：`speedtest.rs`（探测池 `probe-in-k` 与 mixed 回退腿）、`misc.rs`（ipinfo 出口探测，mixed 口）。
    /// **不得**用于 `update-in`（那是纯 socks 入站，见 [`Self::via_local_socks_proxy`]）。
    ///
    /// 每次调用新建（低频路径；缓存一个按端口 key 的池收益不抵复杂度）。
    ///
    /// # Errors
    ///
    /// 代理 URL 非法或 client 构建失败。
    pub fn via_local_proxy(port: u16) -> Result<Self, String> {
        Self::with_local_proxy_url(&format!("http://127.0.0.1:{port}"), port)
    }

    /// 经本机 **SOCKS5** 入站的 client（`update-in`）。
    ///
    /// 消费者：订阅 `viaProxy` 拉取（`commands/subscription.rs`）、图标远端代理（`icon_cache.rs`）。
    /// 二者都 pin 到 `update-in` —— `config-engine/builder/inbounds.rs` 里它是
    /// **`type:"socks"`** 入站，纯 socks、压根不说 HTTP。
    ///
    /// 此前这两条链都错用了 [`Self::via_local_proxy`]（`http://`）：reqwest 向 socks 服务器发明文
    /// `CONNECT`/绝对 URI，首字节不是 `0x05` → sing-box 直接断连 → **「经代理更新订阅」整条链恒失败**
    /// （单测发现不了：建 client 本来就成功，失败在握手）。行为对齐 上游
    /// `UpdateNetwork.getProxiedSession`（Chromium `proxyRules: socks5://127.0.0.1:<update-in>`
    /// = SOCKS5 + **代理端**解析）—— 字面 scheme 不同（见下方「域名解析归属」），行为同。
    ///
    /// 需 reqwest `socks` feature（见 `Cargo.toml`：`socks = []`，零新依赖）；未开时本函数在
    /// `Proxy::all` 处 Err「unknown proxy scheme」——**不是** panic，两个调用方各自有直连回退。
    ///
    /// # `socks5h://` 而非 `socks5://` —— 域名解析归属（这条改错等于把功能反着做）
    ///
    /// reqwest 0.13.4 `connect.rs:540-541` 按 scheme 分派解析位置：`socks5` → `DnsResolve::Local`
    /// （**本机**解析出 IP 再把 IP 塞进 socks 请求 ATYP=0x01），`socks5h` → `DnsResolve::Proxy`
    /// （原样发域名，ATYP=0x03，由**代理端**解析）。上游 那边 Electron 用的
    /// `proxyRules: socks5://127.0.0.1:<update-in>` 走的是 **Chromium** 的 scheme 语义 ——
    /// Chromium 的 `socks5://` 恒发域名（remote DNS，`socks4://` 才是本地解析）。故要与 上游
    /// **行为**对齐，reqwest 侧必须写 `socks5h://`；照抄它的字面 scheme 反而把语义写反。
    ///
    /// 为什么这条是功能性的、不是洁癖：用户勾「经代理更新订阅」的典型动机就是订阅域名在本地
    /// **解析不了或被污染**。system-proxy（非 TUN）模式下本机 DNS 不经核，本地解析走的就是被污染的
    /// resolver —— 本地解析会让「经代理更新」连向毒 IP 或直接失败，且把订阅域名泄漏给本地 resolver。
    ///
    /// ## guard 与传输各自的解析归属（改这里前先读完）
    ///
    /// | 谁 | 解析在哪 | 拿解析结果干什么 |
    /// |---|---|---|
    /// | SSRF guard（`safe_redirect_fetch` + `SystemDnsLookup`） | **本机** | 只做**判定**：解析得内网/回环 → 拒；否则放行 |
    /// | 传输（本函数的 `socks5h`） | **代理端**（sing-box） | 真正**连接**目标 |
    ///
    /// 两者**刻意不共用同一次解析**：guard 必须先在本地拿到一个 IP 才有东西可判，而连接必须交给
    /// 代理端才能绕开被污染的本地视图。**代价（如实登记）**：判定对象与连接目标可以分家 ——
    /// 本地解析得公网 IP（guard 放行）而代理端解析得内网 IP 的情形，guard 拦不住。该残留与 上游
    /// 同构（`SubscriptionService` 明写 guard 键于本地解析、`exemptFakeIp` 只在真走 proxied 时开），
    /// 兜底靠 update-in 出站本身经核 route，而非靠 guard。**不要**为了「自洽」把这里改回 `socks5://`：
    /// 那会用一次已知不可信的本地解析去决定真实连接目标，把上面那条动机整个抵消。
    ///
    /// FakeIP 场景两种 scheme 都成立：`socks5h` 直接把域名交给核（核自己 FakeIP 映射），无需本机先拿
    /// `198.18.x.x`。
    ///
    /// # Errors
    ///
    /// 代理 URL 非法（或 `socks` feature 未启用）或 client 构建失败。
    pub fn via_local_socks_proxy(port: u16) -> Result<Self, String> {
        Self::with_local_proxy_url(&format!("socks5h://127.0.0.1:{port}"), port)
    }

    /// 两个 scheme 变体的共同实现（除代理 URL 外配置**逐字相同**，不容许两处漂移）。
    fn with_local_proxy_url(proxy_url: &str, port: u16) -> Result<Self, String> {
        install_ring_provider();
        let proxy = reqwest::Proxy::all(proxy_url)
            .map_err(|e| format!("本机代理地址非法（port={port}）: {e}"))?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .proxy(proxy)
            .user_agent(app_user_agent())
            .build()
            .map_err(|e| format!("建经代理 HTTP 客户端失败: {e}"))?;
        Ok(Self {
            client,
            resolution_mode: HttpResolutionMode::ProxyRemoteDns,
            warp_client: std::sync::OnceLock::new(),
        })
    }

    /// 底层 client（供本模块内适配器共用）。
    #[must_use]
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// WARP 专用 client（**首次调用时才建**，见 [`Self::warp_client`] 字段文档）。
    ///
    /// 竞态无害：两个线程同时未命中时都会各建一个，`OnceLock` 只留先到的那个，另一个立即析构。
    /// 幂等构造 + 极低频（WARP 注册），不值得为它上 `Mutex`。
    ///
    /// # Errors
    ///
    /// rustls 配置非法 / TLS 后端初始化失败。
    fn warp_client(&self) -> Result<&reqwest::Client, String> {
        if let Some(c) = self.warp_client.get() {
            return Ok(c);
        }
        let built = build_warp_client()?;
        Ok(self.warp_client.get_or_init(|| built))
    }
}

// ── C19：更新链路「经代理」决策（上游 `shared/update-proxy.ts` 1:1 移植）────────────────
//
// **msvp 是生成无关**：不进 config-engine 生成侧，只在**运行期 HTTP 抓取处**决定「走 update-in socks 口
// vs 直连」。消费者 = UpdateNetwork（App/内核更新检查+下载）/ icon-protocol（图标远端代理）/ RuleResource
// （规则资源下载）。**订阅走独立 `subscriptionProxyPolicy`，不经此**（见 `commands/subscription.rs`）。

/// 更新链路「经代理」生效求值（单一真值）。上游 `resolveMainSessionViaProxy`。
///
/// = 代理运行中 `AND` `mainSessionViaProxy` 未显式关闭（默认开）。代理未运行 → 直连（自举友好：
/// 启动期代理未起时更新检查/资源拉取走直连，不卡死）。
#[must_use]
pub fn resolve_main_session_via_proxy(
    proxy_running: bool,
    main_session_via_proxy: Option<bool>,
) -> bool {
    proxy_running && main_session_via_proxy != Some(false)
}

/// 更新链路会话目标求值（viaProxy + 有效 update-in 端口），单一真值。上游 `resolveUpdateProxyTarget`。
///
/// 把易漂移的「端口闸」收口到一处：`resolve_main_session_via_proxy` 决定经代理；端口不可用（`0`，未运行/
/// 未分配）→ 强制直连（不 pin 无效口）。返回 `(via_proxy, port)` 自洽（`via_proxy=true ⟹ port>0`）。
/// UpdateNetwork（选走 update-in 口 vs 直连）与 icon-protocol（喂 `{viaProxy,port}` 给 SSRF guard）共用，
/// 避免端口闸规则在两处分叉。
#[must_use]
pub fn resolve_update_proxy_target(
    proxy_running: bool,
    main_session_via_proxy: Option<bool>,
    update_in_port: u16,
) -> (bool, u16) {
    let mut via_proxy = resolve_main_session_via_proxy(proxy_running, main_session_via_proxy);
    // port==0 → 强制直连（对齐 TS `if (viaProxy && port <= 0) viaProxy = false`）。
    if via_proxy && update_in_port == 0 {
        via_proxy = false;
    }
    (via_proxy, update_in_port)
}

/// 收集响应头为 `(name, value)` 列（非 UTF-8 头值跳过 —— 契约里 header 是 String）。
fn collect_headers(resp: &reqwest::Response) -> Vec<(String, String)> {
    resp.headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|s| (k.as_str().to_string(), s.to_string()))
        })
        .collect()
}

/// body 流式读取的失败形态。
///
/// 分三态而非一个 String，是因为**三个调用方的映射目标不同**：`HttpClient` 全归 String 冒泡给
/// `safe_redirect_fetch` 归类；[`CoreDownloader`] 要把 `Io{received}` 判成
/// [`DownloadError::Incomplete`]、把 `Stalled` 判成 [`DownloadError::Stalled`]。
/// 若压成一个 String，下载侧就只能靠**串匹配**回头猜自己刚抛的错 —— §R1 明令禁止。
#[derive(Debug)]
enum BodyReadError {
    /// 两个 chunk 之间超过看门狗间隔。
    Stalled,
    /// 超过上限（**已中断连接**，不返回截断内容）。
    TooLarge(usize),
    /// 传输/解码失败。`received` = 断掉前已收字节数（下载侧据此判 Incomplete）。
    Io { received: usize, message: String },
    /// **落盘**失败（仅流式腿可能出现：磁盘满 / 权限 / 卷被拔）。
    ///
    /// 与 [`Self::Io`] 分开是因为映射目标不同：`Io` 在已知 Content-Length 时会被还原成
    /// [`DownloadError::Incomplete`]（「网络把包送少了」），而写盘失败**不是**下载不完整 ——
    /// 把磁盘满报成「下载不完整」会让用户一遍遍重下一个永远装不满的盘。
    Sink {
        received: usize,
        source: std::io::Error,
    },
}

impl std::fmt::Display for BodyReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stalled => write!(f, "读取响应体停滞"),
            Self::TooLarge(limit) => write!(f, "响应体超过上限 {limit} 字节，已中断"),
            Self::Io { message, .. } => write!(f, "读取响应体失败: {message}"),
            Self::Sink { source, .. } => write!(f, "写入下载文件失败: {source}"),
        }
    }
}

/// 下载进度回调：`(已收字节, Content-Length)`。`None` = 服务端没给长度 ⇒ **算不出百分比**
/// （调用方须保持 indeterminate，不许拿已收字节瞎凑一个分母）。
///
/// `Send + Sync`：回调在 [`CoreDownloader::download_inner`] spawn 出的 tokio task 里跑，
/// 而调用方在 blocking 线程等结果 —— 跨线程边界。
pub type DownloadProgressFn = dyn Fn(u64, Option<u64>) + Send + Sync;

/// 流式读 body，**超限即中断并 Err**（不截断）。
///
/// 截断后返回会把「超大订阅」变成「解析出半截节点」的坏数据 —— 比明确失败更糟
/// （net-stack `MinimalResponse` doc 的硬契约）。
async fn read_body_capped(
    resp: &mut reqwest::Response,
    max: Option<usize>,
    stall: Duration,
) -> Result<Vec<u8>, BodyReadError> {
    read_body_capped_with_progress(resp, max, stall, None, None).await
}

/// [`read_body_capped`] + 逐 chunk 进度回调。
///
/// 独立成函数（而非给 `read_body_capped` 加参数）是为让订阅 / WARP 两条不需要进度的调用点
/// 保持零改动、零成本：它们仍走上面那个三参版本。
///
/// `expected` 由调用方从 `Content-Length` 注入（本函数不重读 header）——回调要的分母与
/// 下载侧做完整性比对用的是**同一个值**，各读一次必然漂移。
async fn read_body_capped_with_progress(
    resp: &mut reqwest::Response,
    max: Option<usize>,
    stall: Duration,
    expected: Option<u64>,
    on_progress: Option<&DownloadProgressFn>,
) -> Result<Vec<u8>, BodyReadError> {
    let mut buf = Vec::new();
    loop {
        // 每个 chunk 单独计时 = 停滞看门狗（整请求超时管不了「极慢但有数据」）。
        let next = tokio::time::timeout(stall, resp.chunk())
            .await
            .map_err(|_| BodyReadError::Stalled)?;
        match next.map_err(|e| BodyReadError::Io {
            received: buf.len(),
            message: e.to_string(),
        })? {
            None => return Ok(buf),
            Some(chunk) => {
                if let Some(limit) = max {
                    if buf.len() + chunk.len() > limit {
                        // 中断连接（drop resp 即断）+ Err —— **不返回截断的 buf**。
                        return Err(BodyReadError::TooLarge(limit));
                    }
                }
                buf.extend_from_slice(&chunk);
                if let Some(cb) = on_progress {
                    cb(buf.len() as u64, expected);
                }
            }
        }
    }
}

/// [`read_body_capped_with_progress`] 的**落盘版姊妹函数**：字节直接进 `sink`，不在内存里攒。
///
/// # 为什么是姊妹函数而不是就地改造
///
/// 上面那个是 App 腿与内核腿**唯一共用**的字节累积点。把它改成泛型/多一个 sink 参数，等于让
/// 两条内核腿（手动换核 / 自动换核）跟着换一条代码路径 —— 而它们的语义一个字都不该变。
/// 故上面那份**原样保留**给内核腿与订阅腿，本函数只服务流式落盘的 App 腿。
///
/// 三项语义与上面**逐字对齐**（漂了就是两条腿的失败面分叉）：
///  - 停滞看门狗：`tokio::time::timeout(stall, resp.chunk())`，**每个 chunk 单独计时**；
///  - 进度回调时机：每个 chunk **落定之后**以累计 `received` + 同一个 `expected` 触发；
///  - 超限判定：`已收 + 本 chunk > limit` 即 [`BodyReadError::TooLarge`] 并**中断连接**
///    （drop `resp`），绝不把已写出的部分当成功 —— 落盘版由调用方负责删残件。
///
/// 唯一新增的失败形态是 [`BodyReadError::Sink`]（写盘失败），它**不能**折叠进
/// [`BodyReadError::Io`]：后者在已知 Content-Length 时会被还原成
/// [`DownloadError::Incomplete`]，而磁盘满不是「下载不完整」。
///
/// 返回累计写出的字节数（内存版返回 `Vec` 的位置）。
async fn read_body_to_sink_with_progress(
    resp: &mut reqwest::Response,
    max: Option<usize>,
    stall: Duration,
    expected: Option<u64>,
    on_progress: Option<&DownloadProgressFn>,
    // `+ Send`：本函数的 future 要被 spawn 到 tokio runtime（见 `try_candidates`），
    // 跨 await 持有的引用必须 Send。
    sink: &mut (dyn std::io::Write + Send),
) -> Result<u64, BodyReadError> {
    let mut received: usize = 0;
    loop {
        // 每个 chunk 单独计时 = 停滞看门狗（整请求超时管不了「极慢但有数据」）。
        let next = tokio::time::timeout(stall, resp.chunk())
            .await
            .map_err(|_| BodyReadError::Stalled)?;
        match next.map_err(|e| BodyReadError::Io {
            received,
            message: e.to_string(),
        })? {
            None => return Ok(received as u64),
            Some(chunk) => {
                if let Some(limit) = max {
                    if received + chunk.len() > limit {
                        // 中断连接（drop resp 即断）+ Err —— **不把已写出的部分当成功**。
                        return Err(BodyReadError::TooLarge(limit));
                    }
                }
                sink.write_all(&chunk)
                    .map_err(|source| BodyReadError::Sink { received, source })?;
                received += chunk.len();
                if let Some(cb) = on_progress {
                    cb(received as u64, expected);
                }
            }
        }
    }
}

/// 流式读 body 并**截断**到上限（解锁检测语义：截断后仍要判定，与订阅相反）。
/// 返回 `(body, truncated)`。
async fn read_body_truncating(
    resp: &mut reqwest::Response,
    max: usize,
    stall: Duration,
) -> Result<(Vec<u8>, bool), String> {
    let mut buf = Vec::new();
    loop {
        let next = tokio::time::timeout(stall, resp.chunk())
            .await
            .map_err(|_| format!("读取响应体停滞超过 {}ms", stall.as_millis()))?;
        match next.map_err(|e| format!("读取响应体失败: {e}"))? {
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

// ── 适配 ②：updater UpdateDownloader（**唯一**下载适配器）────────────────────

/// GitHub 域名表（镜像回退的判定面）。
///
/// **注意**：审计 §C9 裁决 gh-proxy 的 URL 重写（5 域名表 + `applyGhProxy`）应归 net-stack
/// 纯函数模块，消费方为本适配器。那个模块**尚未落地**（全仓 grep 零命中）。`ghProxyPrefix` 现经通用
/// config 保存路径落盘（`update({ghProxyPrefix})` → config_save）。故此处**只做最小可用的镜像前缀拼接**，且刻意不建第二份 5 域名表 ——
/// §A3 血证：`RuleResourceManager` 曾有 2 份 `GITHUB_HOSTS` 副本漂移，令三级兜底自相矛盾。
/// gh-proxy 模块落地后，本函数应改为调它，见任务报告边界声明。
const GITHUB_ASSET_HOSTS: [&str; 2] = ["github.com", "objects.githubusercontent.com"];

/// 该 URL 是否是可经 gh 镜像加速的 GitHub 资产地址。
fn is_github_asset(url: &str) -> bool {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .is_some_and(|h| GITHUB_ASSET_HOSTS.contains(&h.as_str()))
}

/// 把 HTTP 状态映射为下载错误；2xx → `None`。**纯函数**（可单测，无 IO）。
///
/// 403 限流分类：GitHub 在限流时返 403 且 `x-ratelimit-remaining: 0`。它与「403 无权限」
/// 表象相同但处置相反（前者等一会就好，后者永远不好），故消息里带出来 ——
/// 变体仍用 [`DownloadError::HttpStatus`]（枚举无专用限流变体，**不新造**：
/// trait 是 updater 的，接线批不改编排）。
fn classify_download_status(status: u16, headers: &[(String, String)]) -> Option<DownloadError> {
    if (200..300).contains(&status) {
        return None;
    }
    if status == 403 {
        let rate_limited = headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("x-ratelimit-remaining") && v.trim() == "0");
        if rate_limited {
            return Some(DownloadError::Other(
                "GitHub API 限流（x-ratelimit-remaining=0）：稍后重试或配置 gh 加速前缀".into(),
            ));
        }
    }
    Some(DownloadError::HttpStatus(status))
}

/// body 读取失败 → 下载错误的**唯一**映射（两个消费端共用，避免失败分类在两条腿上分叉）。
///
/// 逐条与形参化之前的 `download_once` 内联 match 一致：
///  - `Stalled` → [`DownloadError::Stalled`]（看门狗间隔，非请求超时）；
///  - `TooLarge` → [`DownloadError::Other`]（带上限数字）；
///  - `Io` + 已知 Content-Length → [`DownloadError::Incomplete`]。hyper 会先于我们发现
///    「连接早于 Content-Length 关闭」并报成解码错，故靠 received + expected 还原成结构化
///    Incomplete，而非泛化 Other；长度未知时才回落 Other。
///  - `Sink` → [`DownloadError::Io`]（**写盘失败原样透传**，不冒充「下载不完整」）。
///
/// **纯函数**（无 IO）⇒ 可单测。
fn map_body_error(e: BodyReadError, expected: Option<u64>) -> DownloadError {
    match e {
        BodyReadError::Stalled => DownloadError::Stalled(STALL_TIMEOUT.as_millis() as u64),
        BodyReadError::TooLarge(limit) => {
            DownloadError::Other(format!("下载体积超过上限 {limit} 字节，已中断"))
        }
        BodyReadError::Io { received, message } => match expected {
            Some(n) => DownloadError::Incomplete {
                received: received as u64,
                expected: n,
            },
            None => DownloadError::Other(message),
        },
        // `received` 在此**真被消费**（不是死字段）：磁盘满的诊断价值一半在「写到第几字节才满」，
        // 而 `DownloadError::Io` 只装得下一个 `io::Error` ⇒ 把它并进消息里，
        // `kind` 原样保留（上层若按 kind 分流不受影响）。
        BodyReadError::Sink { received, source } => DownloadError::Io(std::io::Error::new(
            source.kind(),
            format!("写入下载文件失败（已写出 {received} 字节）: {source}"),
        )),
    }
}

/// 完整性：实收 vs 一个**声明值**（= 上游 `parseExpectedBytes`）。**纯函数**。
///
/// 覆盖「连接干净关闭但字节偏少/偏多」的情形（[`map_body_error`] 的 `Io` 分支覆盖「连接异常断」）。
///
/// **三个消费端共用同一条判据**（各写一份 ⇒ 某条腿会少一道完整性门）：
///  1. 内存腿传 `bytes.len()` vs `Content-Length`；
///  2. 落盘腿传实际写出的字节数 vs `Content-Length`；
///  3. App 更新腿（`commands/updater.rs` 的 `check_declared_size`）传实收字节 vs
///     **发布清单声明的 `fileSize`**。第 3 条与前两条的信任根不同：`Content-Length` 是
///     「撒谎方自己给的数」，对撒谎方零约束；`fileSize` 来自 GitHub release 清单，
///     镜像/中间人改不动它。故它是无摘要腿（旧 release）唯一有牙的等值判据。
///
/// `pub(crate)`：第 3 个消费端在 `commands/` 层，但判据不该因此复制一份。
pub(crate) fn check_content_length(
    received: u64,
    expected: Option<u64>,
) -> Result<(), DownloadError> {
    if let Some(n) = expected {
        if received != n {
            return Err(DownloadError::Incomplete {
                received,
                expected: n,
            });
        }
    }
    Ok(())
}

/// 流式落盘下载的结果：写出的字节数 + **边写边算**出来的 sha256。
///
/// 摘要随下载一遍算完（不是落盘后再读一遍文件），故「校验」这一步零额外 IO、零额外内存。
#[derive(Debug, Clone)]
pub struct StreamedDownload {
    /// 实际写出的字节数。
    pub bytes: u64,
    /// 全部字节的 sha256（小写 hex）。
    pub sha256_hex: String,
}

/// 建写句柄的工厂：**每个候选 URL 试一次就要一个新句柄**。
///
/// 镜像回退会换一个候选重下，那时已写出的部分必须被丢弃、从头写起 —— 传一个句柄进去做不到
/// （句柄已被写脏），传工厂才能让每次尝试都拿到截断过的干净句柄。
pub type DownloadSinkFactory =
    dyn Fn() -> std::io::Result<Box<dyn std::io::Write + Send>> + Send + Sync;

/// 边写边算 sha256 的写入包装：一遍数据流同时喂给文件与 hasher。
///
/// 落盘后再读回来算摘要 = 把刚省下的那次全量 IO 又花掉；先攒内存再算 = 把刚省下的内存又占回来。
struct HashingSink {
    inner: Box<dyn std::io::Write + Send>,
    hasher: polaris_updater::verify::Sha256Stream,
}

impl HashingSink {
    fn new(inner: Box<dyn std::io::Write + Send>) -> Self {
        Self {
            inner,
            hasher: polaris_updater::verify::Sha256Stream::new(),
        }
    }

    /// flush 底层句柄并交出 `(喂进 hasher 的累计字节数, 摘要)`。
    ///
    /// # `flush` 覆盖什么、**不**覆盖什么（别把它当持久化）
    ///
    /// **必须 flush**：`BufWriter` 之类的包装在 drop 里吞掉写错误，不 flush 就可能出现
    /// 「摘要算对了、盘上少一截」——而后续 rename 会把这个残包提升成 dest。
    ///
    /// 但生产注入的是 `StdFs::open_write` 给的**裸 `std::fs::File`**，对它
    /// `Write::flush` 是 **no-op**（`File` 无用户态缓冲）—— 即这一句在生产路径上什么都没做，
    /// 它守的是「将来有人在中间塞一层带缓冲的包装」。**且本类型全程没有 `sync_all`**：
    /// 字节只到 page cache，随后的 rename 先于数据持久化落地，断电后 dest 可能是半截文件，
    /// 而 `update_install` 只做 `is_file()`、不复核摘要。这条**不是本批引入的回归**
    /// （旧的 `atomic_replace` 同样无 fsync），故此处只如实标注、不擅自加 fsync。
    ///
    /// 返回累计字节数是为让调用方与**网络侧**独立维护的 `received` 互校：两个数分别回答
    /// 「网络收了多少」与「sink 真吃下多少」，对不上就说明摘要算在了一份与盘上不同的内容上。
    fn finish(mut self) -> std::io::Result<(u64, String)> {
        self.inner.flush()?;
        let hashed = self.hasher.len();
        Ok((hashed, self.hasher.finish()))
    }
}

impl std::io::Write for HashingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // 先落盘再喂 hasher：写失败时 hasher 不能已经吃进这段，否则重试路径的摘要会脏。
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// **唯一**的下载适配器（= `UpdateDownloader` 的生产实现，取代 `UnavailableDownloader`）。
///
/// 收口 `UpdateDownloader` doc 划给「实现侧」的全部细节：重定向跟随 / UA /
/// Content-Length 完整性 / 停滞看门狗 / 镜像回退 / 16MiB 闸 / 15s 响应超时。
/// **订阅路径不得复制这些**（那正是 上游 双份编排的成因）。
///
/// # sync trait 的 async 桥
///
/// `UpdateDownloader::download` 是**同步**签名（staged 周期整条是同步纯逻辑），而 reqwest 是
/// async。桥法：把 future `spawn` 到 tokio runtime，同步线程 `recv` 等结果。
///
/// **调用方必须在 blocking 线程上调**（`spawn_blocking` / 非 async command）：
/// 在 async 上下文里直接调会阻塞 executor 线程。Tauri 的同步 command 跑在**主线程**上 ——
/// 15s 下载会冻 UI，故消费该适配器的 command 一律 `async fn` + `spawn_blocking`。
///
/// # 为什么 `derive(Clone)` 而不是手抄一个克隆器
///
/// [`Self::try_candidates`] 要把一份自身移进 spawn 出去的 task（`&self` 借用不能跨 spawn）。
/// 原先那份手写的 `for_task` 逐字段抄一遍，四个字段全是 `Clone` —— 手抄版的唯一「能力」
/// 是**漏抄新字段而编译得过**：`max_bytes` 形参化那次就差点漏掉，漏了的话 App 腿会静默地
/// 拿 16 MiB 内存闸去下几十 MiB 的安装包。派生版漏字段直接编译不过。
#[derive(Clone)]
pub struct CoreDownloader {
    http: Arc<HttpRuntime>,
    handle: tokio::runtime::Handle,
    /// gh 加速前缀（如 `https://ghproxy.net/`）；空 = 不用镜像。
    gh_proxy_prefix: String,
    /// 单次下载体积硬闸。默认 [`MAX_DOWNLOAD_BYTES`]（内存腿口径），由
    /// [`Self::with_max_bytes`] 按腿覆盖。
    max_bytes: usize,
}

impl CoreDownloader {
    /// 新建。`handle` 须是活着的 tokio runtime handle（command 层 `Handle::current()`）。
    ///
    /// 体积闸默认取 [`MAX_DOWNLOAD_BYTES`]（= 形参化之前的行为）；流式落盘腿须显式
    /// [`Self::with_max_bytes`] 覆盖。
    #[must_use]
    pub fn new(http: Arc<HttpRuntime>, handle: tokio::runtime::Handle) -> Self {
        Self {
            http,
            handle,
            gh_proxy_prefix: String::new(),
            max_bytes: MAX_DOWNLOAD_BYTES,
        }
    }

    /// 设 gh 加速前缀（镜像回退用）。
    #[must_use]
    pub fn with_gh_proxy(mut self, prefix: impl Into<String>) -> Self {
        self.gh_proxy_prefix = prefix.into().trim().to_string();
        self
    }

    /// 覆盖单次下载的体积硬闸。
    ///
    /// **闸值属于「这一腿下多大的东西」，不属于传输层**：内核腿把整包收进内存（`Vec<u8>`）
    /// ⇒ 闸就是内存闸，恒取 [`MAX_DOWNLOAD_BYTES`]；App 安装包腿流式落盘 ⇒ 内存不随包体积长，
    /// 闸改由「清单声明大小 + 裕度」注入。写死一个常量给两条腿共用，必然是「要么卡死大安装包、
    /// 要么给换核腿开一个 OOM 口子」二选一。
    #[must_use]
    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// 候选 URL 列表：原址优先，GitHub 资产且配了前缀时追加镜像作为**回退**。
    fn candidates(&self, url: &str) -> Vec<String> {
        let mut out = vec![url.to_string()];
        if !self.gh_proxy_prefix.is_empty() && is_github_asset(url) {
            let prefix = self.gh_proxy_prefix.trim_end_matches('/');
            out.push(format!("{prefix}/{url}"));
        }
        out
    }

    /// 请求 + 跟随重定向 + 状态分类 + Content-Length 预检；返回**就绪待读**的响应与期望字节数。
    ///
    /// # 为什么抽出来
    ///
    /// 两个消费端（[`Self::download_once`] 整包入内存 / [`Self::download_once_to_sink`] 流式落盘）
    /// 在「读 body」之前要做的事**一模一样**：重定向跟随（GitHub 资产必然 302）、非 http/https 拒绝、
    /// 403 限流分类、超上限早拒。复制第二份必然漂移 —— 上游 `core-downloader.ts` 与
    /// `UpdateService.ts` 两份同构编排就是前车之鉴（见模块文档）。
    async fn open_download_response(
        &self,
        url: &str,
    ) -> Result<(reqwest::Response, Option<u64>), DownloadError> {
        let mut current = url.to_string();
        for _ in 0..=MAX_DOWNLOAD_REDIRECTS {
            let resp =
                tokio::time::timeout(RESPONSE_TIMEOUT, self.http.client().get(&current).send())
                    .await
                    .map_err(|_| DownloadError::Stalled(RESPONSE_TIMEOUT.as_millis() as u64))?
                    .map_err(|e| DownloadError::Other(format!("请求失败: {e}")))?;

            let status = resp.status().as_u16();

            // 30x：自己跟随（client 全局关了 redirect，见 HttpRuntime doc）。
            if (300..400).contains(&status) {
                let Some(loc) = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
                else {
                    return Err(DownloadError::Other(format!(
                        "HTTP {status} 缺 Location 头"
                    )));
                };
                let base = reqwest::Url::parse(&current)
                    .map_err(|e| DownloadError::Other(format!("URL 非法 {current}: {e}")))?;
                let next = base
                    .join(&loc)
                    .map_err(|e| DownloadError::Other(format!("重定向目标非法 {loc}: {e}")))?;
                if next.scheme() != "http" && next.scheme() != "https" {
                    return Err(DownloadError::Other(format!(
                        "重定向目标协议不支持（仅 http/https）: {}",
                        next.scheme()
                    )));
                }
                current = next.to_string();
                continue;
            }

            let headers = collect_headers(&resp);
            if let Some(e) = classify_download_status(status, &headers) {
                return Err(e);
            }

            // Content-Length 预检（体积闸的早拒腿：不用先下完才发现超）。
            let expected = resp.content_length();
            if let Some(n) = expected {
                if n > self.max_bytes as u64 {
                    let limit = self.max_bytes;
                    return Err(DownloadError::Other(format!(
                        "下载体积 {n} 字节超过上限 {limit}，已拒绝"
                    )));
                }
            }
            return Ok((resp, expected));
        }
        Err(DownloadError::Other(format!(
            "重定向次数超过上限（{MAX_DOWNLOAD_REDIRECTS}）"
        )))
    }

    /// 真实下载一个 URL 到内存（含重定向跟随 + 完整性 + 看门狗 + 可选逐 chunk 进度）。
    async fn download_once(
        &self,
        url: &str,
        on_progress: Option<&DownloadProgressFn>,
    ) -> Result<Vec<u8>, DownloadError> {
        let (mut resp, expected) = self.open_download_response(url).await?;
        // 流式读 + 停滞看门狗 + 硬闸（content-length 可缺失/撒谎 → 读取侧必须再拦一次）。
        let bytes = read_body_capped_with_progress(
            &mut resp,
            Some(self.max_bytes),
            STALL_TIMEOUT,
            expected,
            on_progress,
        )
        .await
        .map_err(|e| map_body_error(e, expected))?;
        check_content_length(bytes.len() as u64, expected)?;
        Ok(bytes)
    }

    /// 真实下载一个 URL **直接写进 `sink`**（字节不在内存里攒）。
    ///
    /// 与 [`Self::download_once`] 共用 [`Self::open_download_response`]（重定向 / 状态分类 /
    /// 预检）、[`map_body_error`]（失败分类）与 [`check_content_length`]（完整性）——
    /// **没有第二份平行编排**。差别只有一处：body 走 [`read_body_to_sink_with_progress`]。
    ///
    /// 返回实际写出的字节数。**失败时 sink 里可能已有部分内容**（本函数不知道 sink 是什么，
    /// 清理残件是调用方的责任）。
    async fn download_once_to_sink(
        &self,
        url: &str,
        sink: &mut (dyn std::io::Write + Send),
        on_progress: Option<&DownloadProgressFn>,
    ) -> Result<u64, DownloadError> {
        let (mut resp, expected) = self.open_download_response(url).await?;
        let received = read_body_to_sink_with_progress(
            &mut resp,
            Some(self.max_bytes),
            STALL_TIMEOUT,
            expected,
            on_progress,
            sink,
        )
        .await
        .map_err(|e| map_body_error(e, expected))?;
        check_content_length(received, expected)?;
        Ok(received)
    }

    /// 同步下载 **+ 逐 chunk 进度回调**（见类型文档「sync trait 的 async 桥」：须在 blocking 线程调用）。
    ///
    /// [`UpdateDownloader::download`] 的签名是 trait 定的（无进度参数），故细粒度进度只能走这条
    /// 固有方法。二者共用 [`Self::download_inner`] —— **不复制第二份镜像回退/重定向编排**。
    ///
    /// **当前无生产调用点**（如实登记，2026-08-16 全仓反查：定义 + 一条单测，无第三处）——
    /// App 安装包腿改流式落盘后已换走 [`Self::download_to_sink_with_progress`]，两条内核腿走
    /// 无进度的 trait 方法。保留为「内存腿 + 进度」的**成对 API**，理由有二：
    ///  1. 它与 [`Self::download_to_sink_with_progress`] 是同一条 `read_body_*_with_progress`
    ///     语义的两个形态，流式腿那条门（`streaming_download_reports_progress_like_the_memory_leg`）
    ///     声称「与内存腿同时机同分母」，删掉这一半就没有参照物了；
    ///  2. 删它要连带把 `download_inner` / `read_body_capped_with_progress` 的进度参数一并摘掉，
    ///     那是动内核腿的代码路径 —— 收益（少一个未调用的 pub 方法）与半径不成比例。
    ///
    /// 回调在每个 chunk 到达时触发，可能高频（几百次）；**限频归调用方**（发 IPC 前按整数百分比
    /// 去重），此处不替调用方决定节流策略。镜像回退时回调会从新候选的 0 重新开始 —— 这是真值
    /// （确实在重下），调用方若不想让进度条倒退需自行取 max。
    #[cfg(test)]
    pub fn download_with_progress(
        &self,
        url: &str,
        on_progress: Arc<DownloadProgressFn>,
    ) -> Result<Vec<u8>, DownloadError> {
        self.download_inner(url, Some(on_progress))
    }

    /// 下载编排**单点**：候选列表（原址→镜像）逐个试，首个成功即返；全败返最后一个错。
    ///
    /// 泛型化是为让内存腿与流式落盘腿共用**同一条**候选编排 —— 「镜像何时回退、失败如何记账、
    /// runtime 关掉怎么算」各写一份必然漂移。`attempt` 收到的是一份可移进 task 的
    /// `self.clone()`（`&self` 借用不能跨 spawn）与该次候选 URL。
    fn try_candidates<T, F, Fut>(&self, url: &str, attempt: F) -> Result<T, DownloadError>
    where
        T: Send + 'static,
        F: Fn(Self, String) -> Fut + Clone + Send + 'static,
        Fut: Future<Output = Result<T, DownloadError>> + Send + 'static,
    {
        let mut last: Option<DownloadError> = None;
        for cand in self.candidates(url) {
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            let dl = self.clone();
            let attempt = attempt.clone();
            let url_owned = cand.clone();
            self.handle.spawn(async move {
                let _ = tx.send(attempt(dl, url_owned).await);
            });
            match rx.recv() {
                Ok(Ok(v)) => return Ok(v),
                Ok(Err(e)) => {
                    log::warn!("下载失败（{cand}）: {e}");
                    last = Some(e);
                }
                Err(_) => {
                    last = Some(DownloadError::Other(
                        "下载任务被取消（runtime 已关闭？）".into(),
                    ));
                }
            }
        }
        Err(last.unwrap_or_else(|| DownloadError::Other("无可用下载地址".into())))
    }

    /// 整包入内存的下载（[`UpdateDownloader::download`] 与 `Self::download_with_progress` 共用）。
    fn download_inner(
        &self,
        url: &str,
        on_progress: Option<Arc<DownloadProgressFn>>,
    ) -> Result<Vec<u8>, DownloadError> {
        self.try_candidates(url, move |dl, cand| {
            let cb = on_progress.clone();
            async move { dl.download_once(&cand, cb.as_deref()).await }
        })
    }

    /// **流式落盘**下载 + 逐 chunk 进度 + 增量 sha256（见类型文档「sync trait 的 async 桥」：
    /// 须在 blocking 线程调用）。
    ///
    /// 与 `Self::download_with_progress` 的差别只有「字节去哪」：那条把整包攒进 `Vec<u8>`
    /// （内存峰值 = 包体积），本条把每个 chunk 直接写进 `new_sink()` 给出的句柄，
    /// 内存占用与包体积**解耦**。摘要随写一遍算完（[`HashingSink`]），故校验不需要再读一遍。
    ///
    /// `new_sink` 是**工厂**不是句柄：镜像回退换候选重下时要拿一个截断过的干净句柄，
    /// 否则第二次的字节会接在第一次的残料后面（长度对不上、摘要也对不上）。
    ///
    /// **失败时句柄里可能已有部分内容** —— 本方法不知道 sink 背后是什么，**清理残件是调用方的责任**。
    ///
    /// # Errors
    ///
    /// 除 `Self::download_with_progress` 的全部失败形态外，多一条建句柄/写盘失败
    /// （[`DownloadError::Io`]，**不冒充** `Incomplete`）。
    pub fn download_to_sink_with_progress(
        &self,
        url: &str,
        new_sink: Arc<DownloadSinkFactory>,
        on_progress: Arc<DownloadProgressFn>,
    ) -> Result<StreamedDownload, DownloadError> {
        self.try_candidates(url, move |dl, cand| {
            let new_sink = new_sink.clone();
            let cb = on_progress.clone();
            async move {
                // 每个候选各拿一个新句柄（截断已写出的残料）。
                let mut sink = HashingSink::new(new_sink().map_err(DownloadError::Io)?);
                let bytes = dl
                    .download_once_to_sink(&cand, &mut sink, Some(cb.as_ref()))
                    .await?;
                let (hashed, sha256_hex) = sink.finish().map_err(DownloadError::Io)?;
                // 网络侧的 `bytes` 与 hasher 侧的 `hashed` 是**两个独立维护的计数**：前者由
                // `read_body_to_sink_with_progress` 按 chunk 累加，后者由 `HashingSink::write`
                // 按**实际写出的 n** 累加。二者相等才证明「摘要算的就是盘上那份」——不等意味着
                // 某个 `write` 短写了却被当成全写（`write_all` 之外的路径），此时摘要会对着一份
                // 与文件不同的内容成立，而它正是落位前的唯一校验。零成本换一条硬证据。
                if hashed != bytes {
                    return Err(DownloadError::Other(format!(
                        "下载内部不一致：sink 收下 {hashed} 字节、网络侧记 {bytes} 字节"
                    )));
                }
                Ok(StreamedDownload { bytes, sha256_hex })
            }
        })
    }
}

impl UpdateDownloader for CoreDownloader {
    /// 同步下载（见类型文档「sync trait 的 async 桥」：**须在 blocking 线程调用**）。
    /// 需要进度的调用点走固有方法 `CoreDownloader::download_with_progress`。
    fn download(&self, url: &str) -> Result<Vec<u8>, DownloadError> {
        self.download_inner(url, None)
    }
}

// ── 适配 ③（已迁出）：unlock UnlockHttp ───────────────────────────────────────
//
// **解锁检测的传输层已迁到独立 crate `polaris-unlock-transport`**（`wreq` + Chrome 131 指纹伪装）。
//
// 迁出理由（见该 crate 模块文档）：CF 按 **TLS/JA3 指纹**判自动化 → rustls 形态吃 1020/403，
// 这正是本文件 `warp_client` 文档记录过的同一类问题。解锁面对通用 CF 边缘，只能上真指纹伪装。
//
// **本文件（reqwest + rustls）刻意不再实现 `UnlockHttp`**：指纹客户端与 BoringSSL 构建链的
// 爆炸半径被限制在那一个 crate 内，订阅拉取 / 内核下载 / WARP 注册**继续走这里**，不受影响。
// 若此处再加回一个 `impl UnlockHttp for HttpRuntime`，就等于给解锁检测开了一条绕过指纹伪装的后门。

// ── 适配 ④：mesh WarpHttp ─────────────────────────────────────────────────────

/// 发一个 WARP 请求，返回 (status, 截断后的 body)。
async fn warp_send(
    client: &reqwest::Client,
    req: &WarpHttpRequest,
) -> Result<WarpHttpResponse, String> {
    let mut builder = match req.method {
        WarpHttpMethod::Post => client.post(&req.url),
        WarpHttpMethod::Put => client.put(&req.url),
        WarpHttpMethod::Delete => client.delete(&req.url),
    };
    for (k, v) in &req.headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    if let Some(body) = &req.body {
        builder = builder.body(body.clone());
    }
    let mut resp = tokio::time::timeout(WARP_TIMEOUT, builder.send())
        .await
        .map_err(|_| format!("WARP 请求超时（{}ms）", WARP_TIMEOUT.as_millis()))?
        .map_err(|e| format!("WARP 请求失败: {e}"))?;
    let status = resp.status().as_u16();
    // 响应流错误（对端 RST / 提前关闭）显式映射 Err —— 契约明写：否则上游 Promise 永挂。
    let (body, _truncated) =
        read_body_truncating(&mut resp, WARP_MAX_BODY_BYTES, WARP_TIMEOUT).await?;
    Ok(WarpHttpResponse {
        status,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

/// # TLS 指纹规避：走**专用** [`build_warp_client`]（TLS1.2-only + HTTP/1.1）
///
/// `warp_http.rs` 模块文档明写：**Cloudflare WAF 校验 TLS 指纹**，rustls-default 的 ClientHello（TLS1.3 + h2）
/// ≠ Node/okhttp → **1020/403**。故本 impl 的两条路径**都用 `self.warp_client`**（钉 TLS1.2 + `http1_only`），
/// **不**用共享 `self.client` —— 对齐 上游 `WarpService` 的 node-`https`(TLS1.2 pin) 形态。选型理由见
/// [`build_warp_client`]：oracle 实证 上游 靠的是**粗形态**（TLS1.2/HTTP1.1）而非精确 okhttp JA3，
/// 故用 rustls 现有能力收窄形态即可，**零新依赖**（不引 boring/native-tls 的 C 构建重量）。
///
/// # ⚠️ 真机门 —— **未经真实 CF 验证**
///
/// rustls 的 TLS1.2 ClientHello 仍是**第三种**指纹（既非 node-OpenSSL 亦非 okhttp）。若 CF 判的不止是粗形态、
/// 而是把 rustls 的具体 TLS1.2 指纹也列黑，则仅钉版本不足以过 1020。这**只能**向 `api.cloudflareclient.com`
/// 发真实注册请求（创建真实设备账户，有副作用）验证——本批遵「禁本机碰宿主网络」未做，如实登记为未验。
/// 若真机 1020，处置是**升级到精确 JA3 指纹栈**（如 `boring`/`tokio-boring`，代价见任务报告的跨平台构建成本），
/// **不是**改本适配器的重试逻辑。失败形态是明确的 403+body-1020，已由 `classify_deregister_result` 分类，不会伪装成成功。
#[async_trait]
impl WarpHttp for HttpRuntime {
    /// register/applyLicense：2xx → Ok(body)；非 2xx / 网络错 → Err（带 status + 截断 body）。
    async fn json_request(&self, req: &WarpHttpRequest) -> Result<String, String> {
        let resp = warp_send(self.warp_client()?, req).await?;
        if (200..300).contains(&resp.status) {
            Ok(resp.body)
        } else {
            // 契约：非 2xx 即 Err，带 status + 截断 body（body 里可能有 CF 的 error 1020）。
            Err(format!("WARP API {}: {}", resp.status, resp.body))
        }
    }

    /// unregister：**保留 4xx 状态**返回（供 `classify_deregister_result` 做 done/drop/retry 分类）；
    /// 仅网络层错误（无 HTTP 状态）才 Err。
    async fn status_request(&self, req: &WarpHttpRequest) -> Result<WarpHttpResponse, String> {
        warp_send(self.warp_client()?, req).await
    }
}

// ── 适配 ⑤：dns-race DohPost（C11 节点域名竞速的 DoH 上游）────────────────────

/// DoH 单请求超时（含连接 + 首字节 + 读完 body）。
///
/// **必须显著小于 `polaris_dns_race::PER_UPSTREAM_TIMEOUT`(1500ms)**：单上游超时是竞速层的最后一道
/// 兜底，若传输层自己不超时就全靠它，日志里只会看到「上游超时」而分不清是慢还是挂。
/// 取 1200ms —— 国内 DoH（223.5.5.5 / 1.12.12.12）正常 RTT 在几十毫秒量级，1.2s 已是极宽裕。
const DOH_TIMEOUT: Duration = Duration::from_millis(1200);

/// DoH 响应体上限。DNS over HTTPS 单条响应远小于此（UDP 侧宣告的 EDNS0 payload 一般 1232/4096）；
/// 设闸是防「上游被劫持成一个大文件」把内存吃穿。
const DOH_MAX_BODY_BYTES: usize = 8 * 1024;

/// 节点域名竞速 sidecar 的 DoH 上游传输。
///
/// 走**共享** `self.client`（rustls-default + `no_proxy()`）：
/// - `no_proxy()` 是硬要求 —— sidecar 起在**起核路径上**，若这里的请求继承我们自己设的系统代理，
///   就成了「解析节点域名要先连上代理，而连代理要先解析节点域名」的自举死锁。
/// - 目标 URL 的 host 恒为**字面 IP**（`parse_custom_upstream` 拒绝域名上游、内置上游是 IP DoH），
///   故不需要也不会触发第二层 DNS 解析；证书按 IP SAN 校验。
///
/// **真机门**：对 `223.5.5.5` / `1.12.12.12` 的真实 DoH POST（IP-SAN 证书链是否被 rustls+webpki
/// 接受、境内 RTT 是否落在预算内）本机不可验 —— 本仓禁止测试触碰宿主网络。此处只保证形态正确
/// （方法/头/超时/体积闸/错误映射），端到端见任务报告的真机验证项。
#[async_trait]
impl polaris_dns_race::DohPost for HttpRuntime {
    async fn post_dns_message(&self, url: &str, body: Vec<u8>) -> Result<Vec<u8>, String> {
        let req = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
            .header(reqwest::header::ACCEPT, "application/dns-message")
            .body(body);
        let mut resp = tokio::time::timeout(DOH_TIMEOUT, req.send())
            .await
            .map_err(|_| format!("DoH 超时（{}ms）: {url}", DOH_TIMEOUT.as_millis()))?
            .map_err(|e| format!("DoH 请求失败 {url}: {e}"))?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            // 非 2xx 一律 Err = 竞速层的 FAIL（**不是** EMPTY）：上游故障绝不能被当成「域名无记录」。
            return Err(format!("DoH {status}: {url}"));
        }
        read_body_capped(&mut resp, Some(DOH_MAX_BODY_BYTES), DOH_TIMEOUT)
            .await
            .map_err(|e| format!("DoH 读响应失败 {url}: {e}"))
    }
}

#[cfg(test)]
mod tests;
