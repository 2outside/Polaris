//! 路由事件携带的目标前缀 —— 纯 `std::net` 上的前缀运算，零依赖。
//!
//! 三种来源共用它：macOS/Linux 的 `route monitor` 文本（[`RoutePrefix::parse`] /
//! [`RoutePrefix::from_netmask`]）与 Windows IP Helper 的结构化 row（[`RoutePrefix::new`]）。

use std::net::IpAddr;

/// 路由事件携带的目标前缀。只保留标准库 IP + 前缀长度，避免为了一个热路径判定引入新依赖。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RoutePrefix {
    address: IpAddr,
    prefix_len: u8,
}

impl RoutePrefix {
    #[must_use]
    pub fn new(address: IpAddr, prefix_len: u8) -> Option<Self> {
        let width = if address.is_ipv4() { 32 } else { 128 };
        (prefix_len <= width).then_some(Self {
            address,
            prefix_len,
        })
    }

    /// 只有 macOS/Linux 的 route monitor 文本解析需要从字符串恢复前缀；Windows 走 IP Helper 的
    /// 结构化 row（[`RoutePrefix::new`]）。
    ///
    /// **没有 cfg 门**：下沉前这里挂着 `#[cfg(any(target_os = "macos", target_os = "linux", test))]`，
    /// 而那个谓词描述的不是平台语义（这段纯字符串解析在任何平台都成立），是「Windows 构建里
    /// 没人调用它」这个编译期事实 —— 判据与它要表达的东西对不上。跨 crate 的 `pub` 项不触发
    /// `dead_code`，下沉即消。
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let (address, prefix_len) = match value.split_once('/') {
            Some((address, prefix_len)) => (address.parse().ok()?, prefix_len.parse::<u8>().ok()?),
            None => {
                let address: IpAddr = value.parse().ok()?;
                let prefix_len = if address.is_ipv4() { 32 } else { 128 };
                (address, prefix_len)
            }
        };
        Self::new(address, prefix_len)
    }

    /// 从 BSD route socket 文本里的目标地址 + 掩码恢复前缀。只接受连续掩码，畸形掩码返回
    /// `None`，让上层按“未知路由事件”保守处理，不能误判成无关事件。
    ///
    /// 无 cfg 门，理由同 [`RoutePrefix::parse`]。
    #[must_use]
    pub fn from_netmask(address: IpAddr, netmask: IpAddr) -> Option<Self> {
        let prefix_len = match (address, netmask) {
            (IpAddr::V4(_), IpAddr::V4(mask)) => {
                let mask = u32::from(mask);
                let prefix_len = mask.leading_ones() as u8;
                let expected = if prefix_len == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix_len)
                };
                (mask == expected).then_some(prefix_len)?
            }
            (IpAddr::V6(_), IpAddr::V6(mask)) => {
                let mask = u128::from(mask);
                let prefix_len = mask.leading_ones() as u8;
                let expected = if prefix_len == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix_len)
                };
                (mask == expected).then_some(prefix_len)?
            }
            _ => return None,
        };
        Self::new(address, prefix_len)
    }

    #[must_use]
    pub const fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    #[must_use]
    pub fn contains(self, candidate: IpAddr) -> bool {
        match (self.address, candidate) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                prefix_contains(u32::from(network), u32::from(candidate), self.prefix_len)
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                prefix_contains(u128::from(network), u128::from(candidate), self.prefix_len)
            }
            _ => false,
        }
    }
}

fn prefix_contains<T>(network: T, candidate: T, prefix_len: u8) -> bool
where
    T: Copy + PartialEq + std::ops::BitXor<Output = T> + std::ops::Shr<u32, Output = T> + From<u8>,
{
    let width = (std::mem::size_of::<T>() * 8) as u32;
    prefix_len == 0 || ((network ^ candidate) >> (width - u32::from(prefix_len))) == T::from(0)
}

#[cfg(test)]
mod tests;
