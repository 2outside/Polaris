//! 管理 API 端口簿记 —— 上游 `resolveTailscaleApiPort` / `resolveFreeLocalPort` / `resolveTailscaleLoginApiPort`
//! 的 Rust 移植（源 `ProxyManager.ts:3006-3057` + `proxy-ports.ts`）。
//!
//! 不变式：
//! - 每次 start 重新解析一个空闲 127.0.0.1 端口（避硬编 clash+1 被占 → services bind FATAL，A1）。
//! - 排除 control_api / http / socks / mixed 端口集（避 listen(0) 偶撞用户端口段）。
//! - 5 次重试仍撞 exclude → 返回 fallback（control_api + 1，与旧行为一致）。
//! - 登录核 api 端口额外排除主核 api 端口（避两个 api service bind 撞），fallback = control_api + 2。
//!
//! 不触碰宿主网络：真实 bind 探测经 [`FreePortProvider`] trait 抽象，测试用 `SeededPortProvider`
//! 确定性桩；生产用 [`TokioPortProvider`]（bind 0 → 取端口 → drop）。

use std::collections::HashSet;

/// 默认 control_api 端口（对齐 上游 `DEFAULT_CONTROL_PORT = 9090`，proxy-ports.ts:11）。
pub const DEFAULT_CONTROL_PORT: u16 = 9090;

/// control_api 端口解析（上游 `controlApiPort(config)`，proxy-ports.ts:17）。
/// `Some(>0)` 用之；否则默认 9090。
pub fn control_api_port(config_control_port: Option<u16>) -> u16 {
    match config_control_port {
        Some(p) if p > 0 => p,
        _ => DEFAULT_CONTROL_PORT,
    }
}

/// 端口排除集（resolveTailscaleApiPort / resolveFreeLocalPort 共用）。
///
/// 对齐 上游 `exclude = new Set([controlApiPort, httpPort, socksPort, mixedPort].filter(p=>p>0))`（:3007-3011）。
/// `0`/`None` 视作未设（不排除）。
#[derive(Debug, Default, Clone)]
pub struct PortExclusions {
    pub control_api: u16,
    pub http: u16,
    pub socks: u16,
    pub mixed: u16,
    /// 主核 api 端口（仅登录核解析时排除，:3024）。
    pub primary_api: u16,
}

impl PortExclusions {
    /// 主核 api 端口解析用的排除集（resolveTailscaleApiPort，:3007-3011）。
    /// primary_api 不排除（它就是要解析的目标）。
    pub fn for_primary_api(
        control: Option<u16>,
        http: Option<u16>,
        socks: Option<u16>,
        mixed: Option<u16>,
    ) -> Self {
        Self {
            control_api: control_api_port(control),
            http: http.unwrap_or(0),
            socks: socks.unwrap_or(0),
            mixed: mixed.unwrap_or(0),
            primary_api: 0,
        }
    }

    /// 登录核 api 端口解析用的排除集（resolveTailscaleLoginApiPort，:3022-3031）。
    /// 额外排除主核 api 端口（运行中已占）。
    pub fn for_login_api(
        primary_api: u16,
        control: Option<u16>,
        http: Option<u16>,
        socks: Option<u16>,
        mixed: Option<u16>,
    ) -> Self {
        Self {
            control_api: control_api_port(control),
            http: http.unwrap_or(0),
            socks: socks.unwrap_or(0),
            mixed: mixed.unwrap_or(0),
            primary_api,
        }
    }

    /// 返回排除端口集合（去 0）。
    pub fn as_set(&self) -> HashSet<u16> {
        [
            self.control_api,
            self.http,
            self.socks,
            self.mixed,
            self.primary_api,
        ]
        .into_iter()
        .filter(|p| *p != 0)
        .collect()
    }
}

/// 解析结果（携带 fallback 标记便于诊断）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedPort {
    pub port: u16,
    /// true = 5 次重试仍撞 exclude → 用了 fallback（极少见）。
    pub used_fallback: bool,
}

/// bind 0 → 取端口 → 立即关的抽象（resolveFreeLocalPort 内核，:3040-3046）。
///
/// 生产用 [`TokioPortProvider`]；测试用 `SeededPortProvider`（手写确定性桩，见 tests 模块）。
/// 返回 `None` = bind 失败（极少见，对应 TS 的 catch 分支 :3048）。
pub trait FreePortProvider: Send + Sync {
    /// bind 127.0.0.1:0 → 返回系统分配端口 → drop listener。
    fn try_allocate(&self) -> Option<u16>;
}

/// Tokio 实现的空闲端口探测（对应 TS `net.createServer().listen(0,'127.0.0.1')`）。
///
/// 在 blocking pool 上 bind（tokio::net 是 async，但 listen+drop 极快，用 block_in_place 不合适；
/// 这里要求运行时在调用方，提供 async 入口 `PortAllocator::resolve_free_local_port_async`）。
pub struct TokioPortProvider;

impl FreePortProvider for TokioPortProvider {
    fn try_allocate(&self) -> Option<u16> {
        // 阻塞 spin：tokio::net::TcpListener::bind 是 async，本 trait 是同步。
        // 真正的 async 路径在 PortAllocator::resolve_free_local_port_async；本 impl 仅供非 async 兼容。
        // 用标准库同步 listener（零依赖、与 Polaris net.createServer 同语义）。
        std::net::TcpListener::bind(("127.0.0.1", 0))
            .and_then(|l| l.local_addr())
            .map(|addr| addr.port())
            .ok()
    }
}

/// 端口分配器：封装 resolveFreeLocalPort 的 5 次重试 + exclude 过滤 + fallback 逻辑（:3038-3057）。
pub struct PortAllocator<P: FreePortProvider> {
    provider: P,
    /// 最大重试次数（Polaris 固定 5，:3039）。
    max_attempts: u32,
}

impl<P: FreePortProvider> PortAllocator<P> {
    pub const DEFAULT_MAX_ATTEMPTS: u32 = 5;

    pub fn new(provider: P) -> Self {
        Self {
            provider,
            max_attempts: Self::DEFAULT_MAX_ATTEMPTS,
        }
    }

    pub fn with_max_attempts(mut self, max: u32) -> Self {
        self.max_attempts = max.max(1);
        self
    }

    /// resolveFreeLocalPort（:3038-3057）：至多 max_attempts 次拿系统分配口，
    /// 不在 exclude 集才采用；全撞 → fallback。
    pub fn resolve_free_local_port(&self, exclude: &PortExclusions, fallback: u16) -> ResolvedPort {
        let set = exclude.as_set();
        for _ in 0..self.max_attempts {
            // bind 失败（catch 分支）→ 继续下一轮（:3048）。
            let Some(port) = self.provider.try_allocate() else {
                continue;
            };
            if !set.contains(&port) {
                return ResolvedPort {
                    port,
                    used_fallback: false,
                };
            }
        }
        ResolvedPort {
            port: fallback,
            used_fallback: true,
        }
    }

    /// resolveTailscaleApiPort（:3006）：排除 control+http+socks+mixed，fallback = control_api + 1。
    pub fn resolve_tailscale_api_port(&self, exclusions: &PortExclusions) -> ResolvedPort {
        let fallback = exclusions.control_api.wrapping_add(1);
        self.resolve_free_local_port(exclusions, fallback)
    }

    /// resolveTailscaleLoginApiPort（:3020）：额外排除 primary_api，fallback = control_api + 2。
    pub fn resolve_tailscale_login_api_port(&self, exclusions: &PortExclusions) -> ResolvedPort {
        let fallback = exclusions.control_api.wrapping_add(2);
        self.resolve_free_local_port(exclusions, fallback)
    }

    /// 批量分配 `count` 个**互不相同**的空闲 127.0.0.1 端口（上游 `allocateProbePorts` 的 `3+K` 批分配腿，
    /// :3059-3080）：主核测速探测池 `probe-in-k` 需 K 个独立回环端口。
    ///
    /// 语义严格对齐 oracle：
    /// - 每槽至多 `max_attempts` 次重绑，命中 `exclude` 或**已选中的池端口**（`!ports.includes(port)`，:3070）→ 重滚。
    /// - **整批原子失败**（任一槽 `max_attempts` 次仍撞 → 返回空 `vec![]`，:3078 throw→catch→`probePoolPorts=[]`）：
    ///   探测池是叠加能力，分配失败即不注入、测速回退（绝不阻断代理启动）。
    ///
    /// 去重靠「已选端口累进排除集」：`FreePortProvider::try_allocate` 立即 drop listener，同口可能被立刻重发；
    /// 把已选端口并入排除集再滚，等价 oracle 靠持有 listener 保证的互异性（此处更可测：`SeededPortProvider` 可喂重复序列）。
    pub fn resolve_distinct_free_ports(&self, exclude: &PortExclusions, count: usize) -> Vec<u16> {
        let mut taken = exclude.as_set();
        let mut out: Vec<u16> = Vec::with_capacity(count);
        for _ in 0..count {
            let mut got = None;
            for _ in 0..self.max_attempts {
                let Some(port) = self.provider.try_allocate() else {
                    continue; // bind 失败（catch 分支）→ 下一轮
                };
                if !taken.contains(&port) {
                    got = Some(port);
                    break;
                }
            }
            match got {
                Some(port) => {
                    taken.insert(port);
                    out.push(port);
                }
                // 任一槽拿不到互异空闲口 → 整批放弃（回退语义），绝不返回部分池。
                None => return Vec::new(),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests;
