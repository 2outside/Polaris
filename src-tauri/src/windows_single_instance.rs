//! Windows 单实例插件的启动串行闸门。
//!
//! `tauri-plugin-single-instance 2.4.3` 先创建命名 mutex、后创建接收 `WM_COPYDATA` 的隐藏窗。
//! 两个进程在这段间隙并发启动时，第二个会看到 mutex 已存在但 `FindWindowW` 为空；上游当前会
//! 直接继续完整启动，并且不为这个新进程创建监听窗，最终形成多个不可召回的托盘实例。
//!
//! 本闸门不替代官方插件，也不复制它的 argv/IPC 协议；只用另一个短生命周期 mutex 把
//! `Builder::build`（插件 setup 在其中执行）串行化。首实例建好官方监听窗后才释放，后续实例再进入
//! 官方插件时就能稳定找到监听窗、转发并退出。放行前再查一次官方监听窗，避免制造“无监听主实例”。

use std::{ffi::OsStr, io, os::windows::ffi::OsStrExt, ptr, time::Duration};

use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    },
    System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject},
    UI::WindowsAndMessaging::FindWindowW,
};

const STARTUP_GATE_TIMEOUT: Duration = Duration::from_secs(10);

/// 已取得所有权的启动闸门。释放发生在官方插件 setup 完成且监听窗验证通过之后。
#[derive(Debug)]
pub struct StartupGate {
    handle: HANDLE,
}

impl StartupGate {
    pub fn acquire(identifier: &str) -> io::Result<Self> {
        Self::acquire_with_timeout(identifier, STARTUP_GATE_TIMEOUT)
    }

    fn acquire_with_timeout(identifier: &str, timeout: Duration) -> io::Result<Self> {
        let name = wide(&format!("{identifier}-single-instance-startup-gate"));
        // SAFETY: name 是以 NUL 结尾且在调用期间存活的 UTF-16；安全属性为空，句柄由 Drop 收回。
        let handle = unsafe { CreateMutexW(ptr::null(), 1, name.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }

        // GetLastError 必须紧跟 CreateMutexW；已存在时 bInitialOwner 被系统忽略，须显式等待所有权。
        let already_exists = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
        if already_exists {
            let timeout_ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
            // SAFETY: handle 是本函数刚取得的有效 mutex 句柄。
            match unsafe { WaitForSingleObject(handle, timeout_ms) } {
                WAIT_OBJECT_0 | WAIT_ABANDONED => {}
                WAIT_TIMEOUT => {
                    // SAFETY: 本分支未取得 mutex 所有权，只关闭自己的句柄。
                    unsafe { CloseHandle(handle) };
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Windows single-instance startup gate timed out",
                    ));
                }
                _ => {
                    let error = io::Error::last_os_error();
                    // SAFETY: 等待失败时未取得所有权，只关闭自己的句柄。
                    unsafe { CloseHandle(handle) };
                    return Err(error);
                }
            }
        }

        Ok(Self { handle })
    }
}

impl Drop for StartupGate {
    fn drop(&mut self) {
        // SAFETY: 构造成功即拥有 mutex；Drop 仅执行一次，先释放所有权再关闭句柄。
        unsafe {
            ReleaseMutex(self.handle);
            CloseHandle(self.handle);
        }
    }
}

/// 官方插件监听窗必须在释放启动闸门前存在；类名/窗名与 2.4.3 的公开源码派生规则一致。
pub fn verify_listener(identifier: &str) -> io::Result<()> {
    let class_name = wide(&format!("{identifier}-sic"));
    let window_name = wide(&format!("{identifier}-siw"));
    // SAFETY: 两个字符串均以 NUL 结尾并在调用期间存活；只读查询，不接管句柄。
    let listener = unsafe { FindWindowW(class_name.as_ptr(), window_name.as_ptr()) };
    if listener.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "tauri single-instance listener window was not created",
        ));
    }
    Ok(())
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(test)]
mod tests;
