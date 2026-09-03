//! Windows System 模式的 HKCU 原生窄写入口。
//!
//! 值生成与接管状态机仍在 `polaris-system-integration`；本模块只隔离 `windows-sys` FFI，把原来
//! 三次 `reg.exe` 子进程合成一次打开 key + 三次 `RegSetValueExW`。任何一值失败都会向上返回，继续
//! 走既有 retry / marker 回滚，绝不把部分写入报成成功。

use polaris_system_integration::proxy::{
    WindowsProxyRegistrySnapshot, WindowsRegistryDwordValue, WindowsRegistryStringValue,
};
use polaris_system_integration::proxy_ops::{
    WindowsProxyRegistryValues, WindowsProxyRegistryWriter, WindowsProxyWriterError, WIN_REG_PATH,
};
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS};
use windows_sys::Win32::Networking::WinInet::{
    InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD, REG_SZ,
};

#[derive(Debug, Default)]
pub struct WindowsNativeProxyRegistryWriter;

struct RegistryKey(HKEY);

#[allow(
    unsafe_code,
    reason = "RegistryKey exclusively owns the HKEY closed on drop"
)]
impl Drop for RegistryKey {
    fn drop(&mut self) {
        // SAFETY: 句柄只在 `open_internet_settings` 成功后构造，并由本 guard 唯一关闭一次。
        unsafe { RegCloseKey(self.0) };
    }
}

fn wide_null(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    value
        .as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn registry_error(operation: &str, code: u32) -> WindowsProxyWriterError {
    WindowsProxyWriterError::win32(
        operation,
        code,
        std::io::Error::from_raw_os_error(code as i32).to_string(),
    )
}

#[allow(
    unsafe_code,
    reason = "RegOpenKeyExW returns the owned Internet Settings HKEY"
)]
fn open_internet_settings_with_access(access: u32) -> Result<RegistryKey, WindowsProxyWriterError> {
    let subkey = WIN_REG_PATH
        .strip_prefix("HKCU\\")
        .ok_or_else(|| WindowsProxyWriterError::other("Windows Internet Settings 路径不是 HKCU"))?;
    let subkey = wide_null(subkey);
    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: subkey 为 null 终止 UTF-16；输出指针指向有效 HKEY，成功后交 RegistryKey 管理。
    let code = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, subkey.as_ptr(), 0, access, &mut key) };
    if code != ERROR_SUCCESS {
        return Err(registry_error("打开 Internet Settings", code));
    }
    Ok(RegistryKey(key))
}

fn open_internet_settings_read() -> Result<RegistryKey, WindowsProxyWriterError> {
    open_internet_settings_with_access(KEY_QUERY_VALUE)
}

fn open_internet_settings_write() -> Result<RegistryKey, WindowsProxyWriterError> {
    open_internet_settings_with_access(KEY_QUERY_VALUE | KEY_SET_VALUE)
}

#[allow(
    unsafe_code,
    reason = "RegQueryValueExW fills bounded buffers whose type and byte length are validated"
)]
fn query_raw(key: HKEY, name: &str) -> Result<Option<(u32, Vec<u8>)>, WindowsProxyWriterError> {
    let name_wide = wide_null(name);
    let mut value_type = 0_u32;
    let mut byte_len = 0_u32;
    // SAFETY: key/name are live; null data requests the required byte length.
    let first = unsafe {
        RegQueryValueExW(
            key,
            name_wide.as_ptr(),
            std::ptr::null_mut(),
            &mut value_type,
            std::ptr::null_mut(),
            &mut byte_len,
        )
    };
    if first == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if first != ERROR_SUCCESS && first != ERROR_MORE_DATA {
        return Err(registry_error(&format!("查询注册表值 {name}"), first));
    }
    let mut bytes = vec![0_u8; byte_len as usize];
    // SAFETY: buffer has exactly the length requested by the first query.
    let second = unsafe {
        RegQueryValueExW(
            key,
            name_wide.as_ptr(),
            std::ptr::null_mut(),
            &mut value_type,
            bytes.as_mut_ptr(),
            &mut byte_len,
        )
    };
    if second != ERROR_SUCCESS {
        return Err(registry_error(&format!("读取注册表值 {name}"), second));
    }
    bytes.truncate(byte_len as usize);
    Ok(Some((value_type, bytes)))
}

fn query_string(
    key: HKEY,
    name: &str,
) -> Result<WindowsRegistryStringValue, WindowsProxyWriterError> {
    let Some((value_type, bytes)) = query_raw(key, name)? else {
        return Ok(WindowsRegistryStringValue::Absent);
    };
    if value_type != REG_SZ || !bytes.len().is_multiple_of(2) {
        return Err(WindowsProxyWriterError::other(format!(
            "注册表值 {name} 不是 REG_SZ"
        )));
    }
    let mut words = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u16::from_le_bytes(*chunk))
        .collect::<Vec<_>>();
    if words.last() == Some(&0) {
        words.pop();
    }
    let value = String::from_utf16(&words).map_err(|error| {
        WindowsProxyWriterError::other(format!("注册表值 {name} 含非法 UTF-16：{error}"))
    })?;
    if value.is_empty() {
        Ok(WindowsRegistryStringValue::PresentEmpty)
    } else {
        Ok(WindowsRegistryStringValue::PresentValue(value))
    }
}

fn query_dword(
    key: HKEY,
    name: &str,
) -> Result<WindowsRegistryDwordValue, WindowsProxyWriterError> {
    let Some((value_type, bytes)) = query_raw(key, name)? else {
        return Ok(WindowsRegistryDwordValue::Absent);
    };
    if value_type != REG_DWORD || bytes.len() != std::mem::size_of::<u32>() {
        return Err(WindowsProxyWriterError::other(format!(
            "注册表值 {name} 不是 4-byte REG_DWORD"
        )));
    }
    Ok(WindowsRegistryDwordValue::PresentValue(u32::from_le_bytes(
        bytes.try_into().expect("length checked"),
    )))
}

#[allow(
    unsafe_code,
    reason = "RegDeleteValueW borrows one NUL-terminated value name"
)]
fn delete_value(key: HKEY, name: &str) -> Result<(), WindowsProxyWriterError> {
    let name_wide = wide_null(name);
    // SAFETY: key/name are valid for the duration of the call.
    let code = unsafe { RegDeleteValueW(key, name_wide.as_ptr()) };
    if code == ERROR_SUCCESS || code == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        Err(registry_error(&format!("删除注册表值 {name}"), code))
    }
}

fn restore_string(
    key: HKEY,
    name: &str,
    value: &WindowsRegistryStringValue,
) -> Result<(), WindowsProxyWriterError> {
    match value {
        WindowsRegistryStringValue::Absent => delete_value(key, name),
        WindowsRegistryStringValue::PresentEmpty => set_string(key, name, ""),
        WindowsRegistryStringValue::PresentValue(value) => set_string(key, name, value),
    }
}

fn restore_dword(
    key: HKEY,
    name: &str,
    value: WindowsRegistryDwordValue,
) -> Result<(), WindowsProxyWriterError> {
    match value {
        WindowsRegistryDwordValue::Absent => delete_value(key, name),
        WindowsRegistryDwordValue::PresentValue(value) => set_dword(key, name, value),
    }
}

#[allow(
    unsafe_code,
    reason = "RegSetValueExW borrows bounded NUL-terminated UTF-16 buffers"
)]
fn set_string(key: HKEY, name: &str, value: &str) -> Result<(), WindowsProxyWriterError> {
    let name_wide = wide_null(name);
    let value_wide = wide_null(value);
    // SAFETY: key 在 guard 生命周期内有效；name/value 均为 null 终止 UTF-16，字节数覆盖终止符。
    let code = unsafe {
        RegSetValueExW(
            key,
            name_wide.as_ptr(),
            0,
            REG_SZ,
            value_wide.as_ptr().cast::<u8>(),
            (value_wide.len() * std::mem::size_of::<u16>()) as u32,
        )
    };
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(registry_error(&format!("写注册表值 {name}"), code))
    }
}

#[allow(
    unsafe_code,
    reason = "RegSetValueExW borrows one initialized u32 value"
)]
fn set_dword(key: HKEY, name: &str, value: u32) -> Result<(), WindowsProxyWriterError> {
    let name_wide = wide_null(name);
    // SAFETY: key 在 guard 生命周期内有效；data 指向本栈 u32，长度精确为 4 字节。
    let code = unsafe {
        RegSetValueExW(
            key,
            name_wide.as_ptr(),
            0,
            REG_DWORD,
            (&value as *const u32).cast::<u8>(),
            std::mem::size_of::<u32>() as u32,
        )
    };
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(registry_error(&format!("写注册表值 {name}"), code))
    }
}

#[allow(
    unsafe_code,
    reason = "InternetSetOptionW broadcasts settings with no borrowed payload"
)]
impl WindowsProxyRegistryWriter for WindowsNativeProxyRegistryWriter {
    fn capture(&self) -> Result<WindowsProxyRegistrySnapshot, WindowsProxyWriterError> {
        let key = open_internet_settings_read()?;
        Ok(WindowsProxyRegistrySnapshot {
            proxy_server: query_string(key.0, "ProxyServer")?,
            proxy_override: query_string(key.0, "ProxyOverride")?,
            proxy_enable: query_dword(key.0, "ProxyEnable")?,
        })
    }

    fn write(&self, values: &WindowsProxyRegistryValues) -> Result<(), WindowsProxyWriterError> {
        let key = open_internet_settings_write()?;
        // 两个配置值先落盘，最后写 ProxyEnable 作为生效门；顺序与 reg.exe 回退一致。
        set_string(key.0, "ProxyServer", &values.proxy_server)?;
        set_string(key.0, "ProxyOverride", &values.proxy_override)?;
        set_dword(key.0, "ProxyEnable", values.proxy_enable)
    }

    fn restore(
        &self,
        snapshot: &WindowsProxyRegistrySnapshot,
    ) -> Result<(), WindowsProxyWriterError> {
        let key = open_internet_settings_write()?;
        // Values first, activation DWORD last. Every prefix is therefore classifiable and resumable.
        restore_string(key.0, "ProxyServer", &snapshot.proxy_server)?;
        restore_string(key.0, "ProxyOverride", &snapshot.proxy_override)?;
        restore_dword(key.0, "ProxyEnable", snapshot.proxy_enable)
    }

    fn notify_settings_changed(&self) -> Result<(), WindowsProxyWriterError> {
        for (name, option) in [
            (
                "INTERNET_OPTION_SETTINGS_CHANGED",
                INTERNET_OPTION_SETTINGS_CHANGED,
            ),
            ("INTERNET_OPTION_REFRESH", INTERNET_OPTION_REFRESH),
        ] {
            // SAFETY: NULL handle + NULL buffer + 0 length 是这两个全局通知 option 的官方调用形态；
            // 不持有也不转移任何外部指针。
            let ok = unsafe { InternetSetOptionW(std::ptr::null(), option, std::ptr::null(), 0) };
            if ok == 0 {
                let error = std::io::Error::last_os_error();
                return Err(error.raw_os_error().map_or_else(
                    || {
                        WindowsProxyWriterError::other(format!(
                            "发布 Windows 系统代理通知 {name} 失败：{error}"
                        ))
                    },
                    |code| {
                        registry_error(&format!("发布 Windows 系统代理通知 {name}"), code as u32)
                    },
                ));
            }
        }
        Ok(())
    }
}
