//! 平台契约：三胞胎自由函数（同名跨 cfg 分叉的最小平台差异面）——本机 own-LAN 网段枚举、
//! IP 监视器二进制探测、config-engine 平台标签映射、内核平台子目录候选。
//!
//! 纯函数/纯 I/O 枚举，零 [`super::ProxyRuntime`] 状态依赖（L0，`proxy` 依赖拓扑的叶）。

#[cfg(any(unix, windows))]
use polaris_config_engine::user_config::own_lan::{dedupe_own_lan, own_lan_cidr};

/// 桌面会话 PATH 不保证含 sbin；优先使用常见绝对路径，最后才交给 PATH 解析。
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) fn linux_ip_monitor_binary() -> &'static str {
    for candidate in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"] {
        if std::path::Path::new(candidate).is_file() {
            return candidate;
        }
    }
    "ip"
}

/// **C12**：枚举本机**所有非回环接口**的连接网段（CIDR，含主机位）——注入 `buildInbounds own_lan_cidrs`。
///
/// = 上游 `getOwnLanCidrs`（`singbox-inbounds-builder.ts:57-69`）的 Rust 等价：Node 用
/// `os.networkInterfaces()` 取 `!internal && cidr` dedupe，Rust 用 `getifaddrs` 拿 addr+netmask 分离态，
/// netmask→prefix / 格式化 / dedupe / 滤回环的**纯逻辑**下沉 config-engine `own_lan`（确定性单测），
/// 本函数只做 I/O 枚举。
///
/// **只读 `getifaddrs` 系统调用，非破坏性**（不改路由 / iptables / 网络接管，非宿主网络禁区）。best-effort：
/// 取不到接口 / 掩码非法 → 跳过（对齐 上游的 catch→空，「宁漏排也不误破」）。
///
/// 消费面：macOS「连入来源排除」guard（排除物理 LAN 会触发 NE 反向路由丢包）、Windows bypassLAN carve
/// guard（保护物理子网不被 mesh carve）、Linux mesh/own-lan 重叠告警。
#[cfg(unix)]
pub(super) fn enumerate_own_lan_cidrs() -> Vec<String> {
    use nix::ifaddrs::getifaddrs;
    use nix::net::if_::InterfaceFlags;

    let Ok(addrs) = getifaddrs() else {
        // 枚举失败（罕见）→ 空（macOS guard 退化为不额外剔除，交真机验证兜底）。
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for ifa in addrs {
        let is_loopback = ifa.flags.contains(InterfaceFlags::IFF_LOOPBACK);
        let (Some(address), Some(netmask)) = (ifa.address, ifa.netmask) else {
            continue; // 无 addr 或无 netmask 的接口帧（如 AF_PACKET）跳过。
        };
        // IPv4：addr + netmask（u32，大端主机序）→ prefix → "addr/prefix"（含主机位）。
        if let (Some(a4), Some(m4)) = (address.as_sockaddr_in(), netmask.as_sockaddr_in()) {
            let prefix = own_lan_v4_addr_prefix(u32::from(a4.ip()), u32::from(m4.ip()));
            if let Some((ip, pfx)) = prefix {
                if let Some(cidr) = own_lan_cidr(&ip, pfx, is_loopback) {
                    out.push(cidr);
                }
            }
        } else if let (Some(a6), Some(m6)) = (address.as_sockaddr_in6(), netmask.as_sockaddr_in6())
        {
            // IPv6：SockaddrIn6::ip() → Ipv6Addr；netmask 同。
            if let Some(pfx) = polaris_config_engine::user_config::own_lan::prefix_from_netmask_v6(
                u128::from(m6.ip()),
            ) {
                if let Some(cidr) = own_lan_cidr(&a6.ip().to_string(), pfx, is_loopback) {
                    out.push(cidr);
                }
            }
        }
    }
    dedupe_own_lan(out)
}

/// v4 helper：addr(u32)+netmask(u32) → (点分地址串, prefix)。掩码非法 → None（best-effort 丢弃）。
#[cfg(unix)]
fn own_lan_v4_addr_prefix(addr: u32, mask: u32) -> Option<(String, u8)> {
    let pfx = polaris_config_engine::user_config::own_lan::prefix_from_netmask_v4(mask)?;
    Some((std::net::Ipv4Addr::from(addr).to_string(), pfx))
}

/// **C12**（Windows）：`GetAdaptersAddresses` 枚举单播地址 + `OnLinkPrefixLength`（`polaris_helper` 的
/// [`netinfo`] 模块，只读免提权），再喂**同一套** config-engine 纯逻辑（`own_lan_cidr` 滤回环 + 组串、
/// `dedupe_own_lan` 去重）——与 unix 腿结构逐条对称，判定逻辑单一真值、不复制。
///
/// **为何 FFI 在 `polaris-helper` 而不在此**：本文件 `#![forbid(unsafe_code)]`（`forbid` 不可被内层
/// `allow` 覆盖），unix 腿能写在这里是因为 `nix` 提供 `getifaddrs` 的 safe wrapper，Windows 侧依赖树
/// 里没有等价物。而 `polaris-helper` 已有 `windows-sys` 的 IpHelper feature **且已在调同一个
/// `GetAdaptersAddresses`**（`wintun::WinAdapterProbe`），`src-tauri` 也已依赖它 ⇒ 复用既有能力，
/// 不给 `src-tauri` 加 `windows-sys`（简约阶梯：workspace 里有等价能力就不再引一份）。
///
/// best-effort：枚举失败 / 前缀哨兵值 → 该条跳过（对齐 unix 腿与 上游 `getOwnLanCidrs` 的 catch→空）。
/// 消费面：Windows bypassLAN carve guard（保护物理子网不被 mesh carve）。
///
/// [`netinfo`]: polaris_helper::platform::windows::netinfo
#[cfg(windows)]
pub(super) fn enumerate_own_lan_cidrs() -> Vec<String> {
    use polaris_helper::platform::windows::netinfo::enumerate_local_unicast_addrs;
    let out: Vec<String> = enumerate_local_unicast_addrs()
        .into_iter()
        .filter_map(|a| own_lan_cidr(&a.ip, a.prefix, a.is_loopback))
        .collect();
    dedupe_own_lan(out)
}

/// **C12**（既非 unix 也非 windows 的假想平台）：无枚举实现 → 空。与 上游 `getOwnLanCidrs` catch→空
/// 的 best-effort 语义一致（少一层物理子网保护，非破坏、不断网）。
#[cfg(not(any(unix, windows)))]
pub(super) fn enumerate_own_lan_cidrs() -> Vec<String> {
    Vec::new()
}

/// 平台标签：config-engine 沿用 上游/Node 约定（`linux` / `darwin` / `win32`），
/// 与 Rust 的 `std::env::consts::OS`（`linux` / `macos` / `windows`）**不同名** → 必须映射。
/// 漏映射会让 inbounds/route 的平台分支（如 `platform == "win32"`）全部落空。
pub(super) fn platform_tag() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    }
}

/// 解析 sing-box 二进制路径。
///
/// 顺序：`POLARIS_SINGBOX_PATH` 环境变量（开发/测试逃生门）→ 可执行文件同级 `resources/<平台>/`
/// （打包态，fetch-core.mjs 的落地处）→ 仓内 `resources/<平台>/`（开发态）。
///
/// 内核平台子目录候选（**必须与 `fetch-core.mjs` 的落地目录逐字一致**：linux / win / mac-arm64 / mac-x64）。
///
/// 抽成纯函数是为了钉住一个真机 bug：此前 macOS 硬编码 "mac"，而 fetch-core 落 "mac-arm64"/"mac-x64"
/// 且 tauri.conf.json 也按这俩打包 → mac 上即便内核在包里也永远找不到。macOS 按运行架构优先
/// （aarch64→arm64），另一架构作回退（Rosetta / 异架构包兜底）。
pub(super) fn core_platform_dirs(os: &str, arch: &str) -> Vec<&'static str> {
    match os {
        "macos" => {
            if arch == "aarch64" {
                vec!["mac-arm64", "mac-x64"]
            } else {
                vec!["mac-x64", "mac-arm64"]
            }
        }
        "windows" => vec!["win"],
        _ => vec!["linux"],
    }
}
