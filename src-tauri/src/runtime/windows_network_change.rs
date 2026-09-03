//! Windows 网络变化订阅。
//!
//! 同时使用 `NotifyIpInterfaceChange` 与 `NotifyRouteChange2`。容量 1 通道只承担唤醒，本窗事实全部
//! 落在一份互斥保护的 [`PendingNetworkChanges`] 上，避免接口/路由 burst 在通道满时丢失语义。

use std::collections::BTreeSet;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Mutex, PoisonError};

use polaris_platform_events::RoutePrefix;
use tokio::sync::mpsc::{self, Receiver, Sender};
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex,
    NotifyIpInterfaceChange, NotifyRouteChange2, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW,
    MIB_NOTIFICATION_TYPE,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};

/// 两个注销句柄与回调 context 的共同所有者。句柄用 `usize` 保存，使 guard 可安全跨 Tokio worker；
/// context 在 Box 内地址稳定，且只在两个订阅都取消后释放。
struct CallbackContext {
    sender: Sender<()>,
    /// 本去抖窗口内累计的全部网络事实。**只此一份、只此一把锁**：事件类型位与其前缀集合是同一条
    /// 事实的两半，拆成两个同步原语（原子位 + 另一把锁）后，任何一侧先写完就出现「有前缀但没有
    /// route 位」或「有 route 位但前缀已被上一窗取走」的撕裂窗口，两窗都会被 `route_replan_needed`
    /// 判成无关而整条丢掉路由信号。合并成一个类型后，撕裂在类型层面不可表达——读侧拿到的永远是
    /// 某次回调**写完之后**的完整快照，不依赖任何跨原语的顺序推理。
    pending: Mutex<PendingNetworkChanges>,
    /// 本次 Polaris TUN 的接口索引。该接口自身批量安装/删除的 /1、DNS 与 LAN 路由不能反过来
    /// 触发 Polaris 重启；物理接口及其它 VPN 的事件仍完整上送。
    ignored_interface_index: Option<u32>,
}

#[derive(Debug, Default)]
pub(crate) struct PendingNetworkChanges {
    pub(crate) interface: bool,
    pub(crate) route: bool,
    pub(crate) route_prefixes: BTreeSet<RoutePrefix>,
    pub(crate) route_unknown: bool,
}

pub(crate) struct NetworkChangeSubscription {
    interface_handle: usize,
    route_handle: usize,
    context: Option<Box<CallbackContext>>,
}

impl NetworkChangeSubscription {
    /// 取走当前去抖窗口累计的接口/路由事实；回调与读取并发时，新位会留给下一窗口。
    pub(crate) fn take_pending(&self) -> PendingNetworkChanges {
        let context = self
            .context
            .as_ref()
            .expect("subscription context exists until drop");
        let mut guard = context
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        std::mem::take(&mut *guard)
    }

    /// 回调 context 的稳定地址。测试用它以**生产同一条路径**驱动 `unsafe extern "system"` 回调，
    /// 而不是绕开回调直接改状态。
    #[cfg(test)]
    fn context_ptr(&self) -> *const c_void {
        let context: &CallbackContext = self
            .context
            .as_ref()
            .expect("subscription context exists until drop");
        (context as *const CallbackContext).cast::<c_void>()
    }
}

#[allow(
    unsafe_code,
    reason = "cancels each Windows notification HANDLE before freeing callback context"
)]
impl Drop for NetworkChangeSubscription {
    fn drop(&mut self) {
        let mut cancelled = true;
        for handle in [self.interface_handle, self.route_handle] {
            let handle = handle as HANDLE;
            if !handle.is_null() {
                // SAFETY: 两个 handle 仅由对应 Notify* API 创建，并由本 guard 唯一取消一次；全部取消
                // 返回后才释放共同 context，回调不会访问悬空地址。
                let result = unsafe { CancelMibChangeNotify2(handle) };
                if result != ERROR_SUCCESS {
                    cancelled = false;
                    log::error!(
                        "CancelMibChangeNotify2 失败（win32={result}）→ 为防回调悬空保留 context 至进程退出"
                    );
                }
            }
        }
        if !cancelled {
            // 注销失败意味着 OS 仍可能持有 callback context；释放会形成 UAF。此时只能把这份很小的
            // context 提升为进程级资源，随进程退出由 OS 回收。正常注销路径零泄漏。
            if let Some(context) = self.context.take() {
                let _ = Box::leak(context);
            }
        }
    }
}

#[allow(
    unsafe_code,
    reason = "Windows callback context points to the Arc held by the subscription"
)]
unsafe extern "system" fn interface_changed(
    context: *const c_void,
    row: *const MIB_IPINTERFACE_ROW,
    _notification_type: MIB_NOTIFICATION_TYPE,
) {
    if context.is_null() {
        return;
    }
    // SAFETY: context 来自 `Box<CallbackContext>` 的稳定内存，guard 在两个订阅都取消前持有它。
    let context = unsafe { &*context.cast::<CallbackContext>() };
    // SAFETY: 非空 row 由 NotifyIpInterfaceChange 在本次同步回调期间提供完整结构体。
    if !row.is_null()
        && should_ignore_interface(context.ignored_interface_index, unsafe {
            (*row).InterfaceIndex
        })
    {
        return;
    }
    {
        let mut pending = context
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        pending.interface = true;
    }
    // 唤醒必须在锁外：`try_send` 会走 tokio 的通道内部同步，持 Windows 回调栈上的锁去调它，等于
    // 把两把无序关系的锁叠在同一个 OS 回调线程上。
    let _ = context.sender.try_send(());
}

#[allow(
    unsafe_code,
    reason = "Windows callback context points to the Arc held by the subscription"
)]
unsafe extern "system" fn route_changed(
    context: *const c_void,
    row: *const MIB_IPFORWARD_ROW2,
    _notification_type: MIB_NOTIFICATION_TYPE,
) {
    if context.is_null() {
        return;
    }
    // SAFETY: 同 `interface_changed`；两类回调共享一个由 guard 管理的稳定 context。
    let context = unsafe { &*context.cast::<CallbackContext>() };
    let prefix = if row.is_null() {
        None
    } else {
        // SAFETY: 非空 row 由 NotifyRouteChange2 在本次同步回调期间提供完整结构体。
        if should_ignore_interface(context.ignored_interface_index, unsafe {
            (*row).InterfaceIndex
        }) {
            return;
        }
        // SAFETY: 与上句相同；只在同步回调存活期复制目标前缀，不保留 OS 指针。
        unsafe { route_prefix_from_row(&*row) }
    };
    {
        let mut pending = context
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        pending.route = true;
        match prefix {
            Some(prefix) => {
                pending.route_prefixes.insert(prefix);
            }
            None => pending.route_unknown = true,
        }
    }
    // 同 `interface_changed`：唤醒在锁外。
    let _ = context.sender.try_send(());
}

#[allow(
    unsafe_code,
    reason = "copies the typed destination prefix supplied synchronously by NotifyRouteChange2"
)]
unsafe fn route_prefix_from_row(row: &MIB_IPFORWARD_ROW2) -> Option<RoutePrefix> {
    let prefix = &row.DestinationPrefix;
    // SAFETY: SOCKADDR_INET 的活动成员由 si_family 指示；结构体来自 Windows IP Helper API。
    match unsafe { prefix.Prefix.si_family } {
        AF_INET => {
            // SAFETY: family=AF_INET，读取 Ipv4 union member 与其中网络字节序地址有效。
            let raw = unsafe { prefix.Prefix.Ipv4.sin_addr.S_un.S_addr };
            RoutePrefix::new(
                IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes())),
                prefix.PrefixLength,
            )
        }
        AF_INET6 => {
            // SAFETY: family=AF_INET6，读取 Ipv6 union member与 16 字节地址有效。
            let bytes = unsafe { prefix.Prefix.Ipv6.sin6_addr.u.Byte };
            RoutePrefix::new(IpAddr::V6(Ipv6Addr::from(bytes)), prefix.PrefixLength)
        }
        _ => None,
    }
}

fn should_ignore_interface(ignored_interface_index: Option<u32>, changed_index: u32) -> bool {
    ignored_interface_index == Some(changed_index)
}

#[allow(
    unsafe_code,
    reason = "converts a live Windows interface alias to its stable index before subscribing"
)]
fn interface_alias_to_index(alias: &str) -> Result<u32, String> {
    let alias = alias.trim();
    if alias.is_empty() {
        return Err("TUN 接口别名为空".to_owned());
    }
    let wide: Vec<u16> = alias.encode_utf16().chain(std::iter::once(0)).collect();
    let mut luid = NET_LUID_LH::default();
    // SAFETY: wide 是 NUL 结尾、在同步调用期间稳定的 UTF-16；luid 是完整可写输出。
    let result = unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &raw mut luid) };
    if result != ERROR_SUCCESS {
        return Err(format!(
            "无法解析 TUN 接口 `{alias}`（win32={result}）：{}",
            std::io::Error::from_raw_os_error(result as i32)
        ));
    }
    let mut index = 0u32;
    // SAFETY: luid 已由上一步初始化，index 是完整可写输出；API 不保留指针。
    let result = unsafe { ConvertInterfaceLuidToIndex(&raw const luid, &raw mut index) };
    if result != ERROR_SUCCESS {
        return Err(format!(
            "无法取得 TUN 接口 `{alias}` 的索引（win32={result}）：{}",
            std::io::Error::from_raw_os_error(result as i32)
        ));
    }
    if index == 0 {
        return Err(format!("TUN 接口 `{alias}` 返回了无效索引 0"));
    }
    Ok(index)
}

/// 订阅全部 IPv4/IPv6 接口与路由变化，返回 RAII guard 与事件接收端。
#[allow(
    unsafe_code,
    reason = "registers typed callbacks and owns both returned notification HANDLEs"
)]
pub(crate) fn subscribe(
    ignored_interface_alias: Option<&str>,
) -> Result<(NetworkChangeSubscription, Receiver<()>), String> {
    let (sender, receiver) = mpsc::channel(1);
    let ignored_interface_index = ignored_interface_alias
        .map(interface_alias_to_index)
        .transpose()?;
    let context = Box::new(CallbackContext {
        sender,
        pending: Mutex::new(PendingNetworkChanges::default()),
        ignored_interface_index,
    });
    let context_ptr = (&*context as *const CallbackContext).cast::<c_void>();
    let mut interface_handle: HANDLE = std::ptr::null_mut();
    // SAFETY: callback ABI 与 windows-sys 声明一致；context 在 Box 内地址稳定，并由返回 guard 持有；
    // initialNotification=false 避免把订阅动作本身误当一次网络恢复。
    let result = unsafe {
        NotifyIpInterfaceChange(
            AF_UNSPEC,
            Some(interface_changed),
            context_ptr,
            false,
            &mut interface_handle,
        )
    };
    if result != ERROR_SUCCESS {
        return Err(format!(
            "NotifyIpInterfaceChange 失败（win32={result}）：{}",
            std::io::Error::from_raw_os_error(result as i32)
        ));
    }
    let mut route_handle: HANDLE = std::ptr::null_mut();
    // SAFETY: 与上面的接口订阅相同；context 在两个订阅的 guard 内保持稳定。
    let route_result = unsafe {
        NotifyRouteChange2(
            AF_UNSPEC,
            Some(route_changed),
            context_ptr,
            false,
            &mut route_handle,
        )
    };
    if route_result != ERROR_SUCCESS {
        // SAFETY: 接口订阅已成功且 handle 尚未转交，失败回滚后才释放 context。
        let cancel_result = unsafe { CancelMibChangeNotify2(interface_handle) };
        if cancel_result != ERROR_SUCCESS {
            log::error!(
                "NotifyRouteChange2 失败后的接口订阅回滚也失败（win32={cancel_result}）→ 为防回调悬空保留 context 至进程退出"
            );
            let _ = Box::leak(context);
        }
        return Err(format!(
            "NotifyRouteChange2 失败（win32={route_result}）：{}",
            std::io::Error::from_raw_os_error(route_result as i32)
        ));
    }
    Ok((
        NetworkChangeSubscription {
            interface_handle: interface_handle as usize,
            route_handle: route_handle as usize,
            context: Some(context),
        },
        receiver,
    ))
}

#[cfg(test)]
mod tests;
