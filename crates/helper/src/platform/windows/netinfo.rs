//! 本机网络接口**只读**信息枚举（Windows `GetAdaptersAddresses` 的单播地址 + `OnLinkPrefixLength`）。
//!
//! ## 职责边界：零策略，只做枚举
//!
//! 本模块只回答「这台机器上有哪些单播地址、各自前缀多长、是不是回环」，**不做任何取舍**
//! （不滤回环、不去重、不拼 CIDR 串）—— 那些是 `polaris-config-engine::user_config::own_lan`
//! 的纯逻辑，已有确定性单测。调用方（`runtime/proxy::enumerate_own_lan_cidrs`）拿本模块的
//! 原始三元组喂那套纯逻辑，与 unix 腿（`getifaddrs` → 同一套纯逻辑）结构逐条对称。
//!
//! ## 为什么住在 helper crate 而不是 src-tauri
//!
//! 三条硬约束的交集，只剩这一个位置：
//!
//! 1. `GetAdaptersAddresses` 是 FFI ⇒ 必须 `unsafe`；而 `src-tauri/src/runtime/proxy.rs` 是
//!    `#![forbid(unsafe_code)]`（`forbid` 不可被内层 `allow` 覆盖），unix 腿之所以能写在那里，
//!    是因为 `nix` 提供了 `getifaddrs` 的 safe wrapper —— Windows 侧依赖树里没有等价物。
//! 2. 本 crate 已经有 `windows-sys` 的 `Win32_NetworkManagement_IpHelper`（target-specific 依赖）
//!    **且同一个 `GetAdaptersAddresses` 已在 [`super::wintun`] 里被调用** ⇒ 复用既有能力，
//!    不给 `src-tauri` 加新依赖（简约阶梯：workspace 里已有等价能力就不再引一份）。
//! 3. `src-tauri` 已依赖 `polaris-helper`，`platform::windows` 在 `cfg(any(windows, test))` 下可见 ⇒
//!    跨 crate 调用零新增接线。
//!
//! **免提权**：`GetAdaptersAddresses` 是普通用户 API（与 helper 的 SYSTEM 身份无关），app 进程直调即可，
//! 无需经命名管道走 helper 协议。放在本 crate 是**依赖复用**，不是「这件事需要特权」。
//!
//! ## 不触碰宿主
//!
//! 纯读（枚举），不改任何接口/路由/DNS。纯逻辑部分（八位组→地址串、前缀合法性、缓冲区容量换算、
//! 重试预算判据）无 cfg，Linux 可测；FFI 腿本身（`cfg(windows)`）只能靠交叉编译 + Windows 真机覆盖。

/// 一条本机单播地址（原始枚举结果）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalUnicastAddr {
    /// 地址串（v4 点分 / v6 冒号分，压缩形）。
    pub ip: String,
    /// on-link 前缀长度（v4 ≤32 / v6 ≤128）。
    pub prefix: u8,
    /// 是否回环接口（`IfType == IF_TYPE_SOFTWARE_LOOPBACK`）。
    pub is_loopback: bool,
}

/// 一张 Windows 网络适配器的只读摘要。`name` 是 sing-box `bind_interface` 实际接受的
/// InterfaceAlias（`FriendlyName`）；`display_name` 优先使用适配器描述，仅供 UI 展示。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkAdapterInfo {
    pub name: String,
    pub display_name: String,
    pub is_up: bool,
    pub is_loopback: bool,
    pub addresses: Vec<String>,
}

/// `IF_TYPE_SOFTWARE_LOOPBACK`（IANA ifType 24）。本地常量而非从 `windows-sys` 取：
/// 该常量在不同 feature 组合下的模块路径会变，而值是 IANA 注册号、永不变。
pub const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;

/// v4 八位组 → 点分串（纯逻辑，跨平台可测）。
#[must_use]
pub fn v4_octets_to_string(o: [u8; 4]) -> String {
    std::net::Ipv4Addr::from(o).to_string()
}

/// v6 十六字节 → 压缩冒号串（纯逻辑，跨平台可测）。
#[must_use]
pub fn v6_octets_to_string(o: [u8; 16]) -> String {
    std::net::Ipv6Addr::from(o).to_string()
}

/// 前缀长度合法性（纯逻辑，跨平台可测）。合法域 **v4 `1..=32` / v6 `1..=128`**。
///
/// **必须校验**：`IP_ADAPTER_UNICAST_ADDRESS_LH.OnLinkPrefixLength` 在部分接口（隧道 / 尚未配置完成的
/// 适配器）上会给出 `255` 之类的哨兵值；不校验就会拼出 `192.168.1.5/255` 这种下游 CIDR 解析器直接
/// 拒收（或更糟：解析成别的东西）的串。越界 → 整条丢弃，对齐 unix 腿「掩码非法即跳过」的 best-effort。
///
/// **为什么 0 与 255 同列哨兵**：同一批接口（隧道 / 未配置完成态）也会报 `OnLinkPrefixLength = 0`。
/// 0 不是「本机 LAN 段」的合法描述而是默认路由：这条一旦混进 own_lan，
/// `builder::tun_route_exclude::compute_win_bypass_exclude` 拿 own_lan 当 carve guard 时，`/0` 与**一切**
/// mesh 段相交 ⇒ 全部 mesh 段进 `mesh_skipped_own_lan`、一条都不 carve ⇒ bypassLAN 下组网段整体绕 TUN
/// 静默失效。此处早丢弃是第一道；汇流点 `own_lan_cidr` 还有第二道（unix 腿共用）。
#[must_use]
pub fn prefix_is_valid(prefix: u8, is_v6: bool) -> bool {
    if is_v6 {
        (1..=128).contains(&prefix)
    } else {
        (1..=32).contains(&prefix)
    }
}

/// 两步法（探大小 → 按 size 填充）**共用**的重试上限（接口在两次调用之间增减 → size 变大 → 重来）。
pub const SIZE_PROBE_MAX_RETRIES: u32 = 3;

/// 还能不能再重试一次（纯逻辑，跨平台可测）。`retries` = 已消耗的重试次数。
///
/// **为什么探大小与填充共用一个预算**：填充调用同样会返回 `ERROR_BUFFER_OVERFLOW`（两次调用之间
/// 适配器增多），此时 API 已把新的 size 回写。填充腿若直接放弃，本次起核的 own_lan 整体缺位 ——
/// 而 own_lan 是 Windows bypassLAN carve 的 guard，缺位 = 物理子网保护失效。两条腿各记一套预算则最坏
/// 翻倍系统调用，故共用同一个 `retries` 计数。
///
/// **测试诚实说明**：FFI 腿（`cfg(windows)` + 真 `GetAdaptersAddresses`）本机测不到，本函数抽出来供
/// Linux 直测的是**重试预算判据**（第几次该放弃），不是 FFI 行为本身。
#[must_use]
pub fn should_retry_after_overflow(retries: u32) -> bool {
    retries < SIZE_PROBE_MAX_RETRIES
}

/// 承载 `GetAdaptersAddresses` 输出所需的 `u64` 槽数（纯逻辑，跨平台可测）。
///
/// **为什么用 `Vec<u64>` 而不是 `Vec<u8>`**：填充结果要按 `&IP_ADAPTER_ADDRESSES_LH` 解引用，该结构体
/// 含指针 / u64 ⇒ align = 8，而 `Vec<u8>` 只保证 align 1 —— 从未对齐的地址造引用按语言规则即 UB
/// （实践上 Windows 堆分配恰好 16 字节对齐所以不炸，但 Miri 判红，且这是「靠分配器实现细节」而非靠语言
/// 保证）。`Vec<u64>` 的 align = 8 == 目标 align，由各 `win_impl` 里的 `const _` 断言编译期钉死。
///
/// 向上取整（`size` 不是 8 的倍数时多分配一个槽），保证容量**不缩水**。
#[must_use]
pub fn u64_cells_for(size: u32) -> usize {
    (size as usize).div_ceil(std::mem::size_of::<u64>())
}

#[cfg(windows)]
#[allow(unsafe_code)] // windows-sys FFI（GetAdaptersAddresses + 链表遍历）必须 unsafe；每处附 SAFETY。
mod win_impl {
    use super::{
        prefix_is_valid, should_retry_after_overflow, u64_cells_for, v4_octets_to_string,
        v6_octets_to_string, LocalUnicastAddr, NetworkAdapterInfo, IF_TYPE_SOFTWARE_LOOPBACK,
    };
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6};

    /// 承载缓冲区用 `Vec<u64>` 的**前提**：目标结构体的 align 不得超过 u64 的 align。
    /// 编译期钉死而非写注释 —— windows-sys 将来改 layout（比如塞进 align(16) 字段）时这里就红，
    /// 而不是留一个「实践上没炸」的未对齐引用（UB）。
    const _: () = assert!(
        std::mem::align_of::<IP_ADAPTER_ADDRESSES_LH>() <= std::mem::align_of::<u64>(),
        "IP_ADAPTER_ADDRESSES_LH 的对齐已超过 u64，Vec<u64> 承载不再安全"
    );

    /// 枚举本机全部单播地址（v4 + v6）。失败 → 空 Vec（best-effort，对齐 unix 腿的 `getifaddrs` 失败腿）。
    pub fn enumerate_local_unicast_addrs() -> Vec<LocalUnicastAddr> {
        // 只跳过用不到的族；**绝不能带 GAA_FLAG_SKIP_UNICAST**（本函数要的正是它）。
        let flags: u32 = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        let mut size: u32 = 0;
        let mut retries = 0u32;
        // 探大小与填充在**同一个** retries 预算里循环：填充调用也会 overflow（两次调用之间适配器增多），
        // 那时 API 已回写新 size，直接返空等于本次 own_lan 整体缺位（carve guard 失效）。
        let buf: Vec<u64> = loop {
            // SAFETY: 探大小形态（pAdapterAddresses = NULL），API 契约保证此形态只写 size。
            let rc = unsafe {
                GetAdaptersAddresses(0, flags, std::ptr::null(), std::ptr::null_mut(), &mut size)
            };
            if rc == NO_ERROR {
                return Vec::new(); // 无适配器（size=0）或系统直接给全（罕见）→ 无从遍历，诚实返空
            }
            if rc != ERROR_BUFFER_OVERFLOW {
                if !should_retry_after_overflow(retries) {
                    return Vec::new();
                }
                retries += 1;
                continue;
            }
            let mut cells: Vec<u64> = vec![0u64; u64_cells_for(size)];
            // SAFETY: cells 容量 ≥ size 字节（u64_cells_for 向上取整），且 Vec<u64> 的 align 满足
            // IP_ADAPTER_ADDRESSES_LH（上方 const 断言编译期保证）；API 只写 cells 内，不持有它。
            let rc = unsafe {
                GetAdaptersAddresses(
                    0,
                    flags,
                    std::ptr::null(),
                    cells.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                    &mut size,
                )
            };
            if rc == NO_ERROR {
                break cells;
            }
            // 填充期 overflow：API 已回写更大的 size，共用预算重来；其余错误 → 诚实返空。
            if rc == ERROR_BUFFER_OVERFLOW && should_retry_after_overflow(retries) {
                retries += 1;
                continue;
            }
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut ptr = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // SAFETY: 链表由 GetAdaptersAddresses 填充在 buf 内，Next 为 NULL 终止；仅读不写。
        while !ptr.is_null() {
            let entry: &IP_ADAPTER_ADDRESSES_LH = unsafe { &*ptr };
            let is_loopback = entry.IfType == IF_TYPE_SOFTWARE_LOOPBACK;
            let mut ua = entry.FirstUnicastAddress;
            // SAFETY: 单播地址子链表同样在 buf 内、Next 为 NULL 终止。
            while !ua.is_null() {
                let addr = unsafe { &*ua };
                if let Some(item) = read_unicast(
                    addr.Address.lpSockaddr.cast(),
                    addr.OnLinkPrefixLength,
                    is_loopback,
                ) {
                    out.push(item);
                }
                ua = addr.Next;
            }
            ptr = entry.Next.cast_const();
        }
        out
    }

    /// 枚举可供 sing-box `bind_interface` 使用的适配器名与展示信息。
    pub fn enumerate_network_adapters() -> Vec<NetworkAdapterInfo> {
        let flags: u32 = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        let mut size = 0u32;
        let rc = unsafe {
            GetAdaptersAddresses(0, flags, std::ptr::null(), std::ptr::null_mut(), &mut size)
        };
        if rc != ERROR_BUFFER_OVERFLOW || size == 0 {
            return Vec::new();
        }
        let mut cells = vec![0u64; u64_cells_for(size)];
        let rc = unsafe {
            GetAdaptersAddresses(
                0,
                flags,
                std::ptr::null(),
                cells.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                &mut size,
            )
        };
        if rc != NO_ERROR {
            return Vec::new();
        }

        let mut out = Vec::new();
        let mut ptr = cells.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !ptr.is_null() {
            let entry = unsafe { &*ptr };
            let adapter_name = if entry.AdapterName.is_null() {
                String::new()
            } else {
                unsafe { std::ffi::CStr::from_ptr(entry.AdapterName.cast()) }
                    .to_string_lossy()
                    .into_owned()
            };
            // Go `net.InterfaceByName`（sing-box `bind_interface` 的 Windows 查找路径）使用
            // InterfaceAlias/FriendlyName，不接受 AdapterName GUID。真机用同一随包核拨号验证：
            // Alias 成功，GUID 报 `no such network interface`。
            let name = wide_string(entry.FriendlyName).unwrap_or_else(|| adapter_name.clone());
            if !name.is_empty() {
                let display_name = wide_string(entry.Description).unwrap_or_else(|| name.clone());
                let mut addresses = Vec::new();
                let mut ua = entry.FirstUnicastAddress;
                while !ua.is_null() {
                    let addr = unsafe { &*ua };
                    if let Some(item) = read_unicast(
                        addr.Address.lpSockaddr.cast(),
                        addr.OnLinkPrefixLength,
                        entry.IfType == IF_TYPE_SOFTWARE_LOOPBACK,
                    ) {
                        addresses.push(item.ip);
                    }
                    ua = addr.Next;
                }
                addresses.sort();
                addresses.dedup();
                out.push(NetworkAdapterInfo {
                    name,
                    display_name,
                    // IF_OPER_STATUS::IfOperStatusUp 的稳定 Win32 数值。
                    is_up: entry.OperStatus == 1,
                    is_loopback: entry.IfType == IF_TYPE_SOFTWARE_LOOPBACK,
                    addresses,
                });
            }
            ptr = entry.Next.cast_const();
        }
        out.sort_by(|a, b| {
            b.is_up
                .cmp(&a.is_up)
                .then_with(|| a.display_name.cmp(&b.display_name))
        });
        out
    }

    fn wide_string(ptr: *const u16) -> Option<String> {
        if ptr.is_null() {
            return None;
        }
        let mut len = 0usize;
        while unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ptr, len) });
        (!text.trim().is_empty()).then_some(text)
    }

    /// 读一条 `SOCKADDR`（v4/v6）→ [`LocalUnicastAddr`]。非 IP 族 / 前缀越界 / 空指针 → `None`。
    ///
    /// SAFETY 契约：`sa` 要么为 NULL，要么指向 API 填充的、按 `sa_family` 对应大小的合法 sockaddr。
    fn read_unicast(
        sa: *const windows_sys::Win32::Networking::WinSock::SOCKADDR,
        prefix: u8,
        is_loopback: bool,
    ) -> Option<LocalUnicastAddr> {
        if sa.is_null() {
            return None;
        }
        // SAFETY: 非空即指向合法 sockaddr（见上方契约）；只读 sa_family 这一个定长头字段。
        let family = unsafe { (*sa).sa_family };
        if family == AF_INET {
            if !prefix_is_valid(prefix, false) {
                return None;
            }
            // SAFETY: sa_family == AF_INET ⇒ 该缓冲区是 SOCKADDR_IN（Win32 契约）。
            let v4 = unsafe { &*sa.cast::<SOCKADDR_IN>() };
            // SAFETY: S_un 是 in_addr 的 union，S_addr（u32，网络序）与四字节数组同一块存储。
            let octets = unsafe { v4.sin_addr.S_un.S_addr }.to_ne_bytes();
            Some(LocalUnicastAddr {
                ip: v4_octets_to_string(octets),
                prefix,
                is_loopback,
            })
        } else if family == AF_INET6 {
            if !prefix_is_valid(prefix, true) {
                return None;
            }
            // SAFETY: sa_family == AF_INET6 ⇒ 该缓冲区是 SOCKADDR_IN6（Win32 契约）。
            let v6 = unsafe { &*sa.cast::<SOCKADDR_IN6>() };
            // SAFETY: u 是 in6_addr 的 union，Byte 成员即 16 字节网络序地址。
            let octets = unsafe { v6.sin6_addr.u.Byte };
            Some(LocalUnicastAddr {
                ip: v6_octets_to_string(octets),
                prefix,
                is_loopback,
            })
        } else {
            None
        }
    }
}

#[cfg(windows)]
pub use win_impl::{enumerate_local_unicast_addrs, enumerate_network_adapters};

#[cfg(test)]
mod tests;
