//! Windows 系统目录的窄 FFI 边界。
//!
//! 提权载体不能交给 PATH / 当前目录解析：否则普通用户可把同名 `powershell.exe` 放在搜索顺序更前处，
//! 再借应用预期中的 UAC 提示把攻击者选中的二进制抬到管理员权限。

use crate::ClientError;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

#[allow(
    unsafe_code,
    reason = "GetSystemDirectoryW is the sole system-directory FFI boundary"
)]
pub(crate) fn powershell_executable() -> Result<String, ClientError> {
    // MAX_PATH 足够覆盖正常系统目录；API 若报告更长所需长度则按返回值扩容重试。
    let mut buffer = vec![0u16; 260];
    loop {
        // SAFETY: buffer 是一段连续、可写的 u16 存储；传入长度与其当前容量一致，且调用期间不移动。
        // API 成功返回写入的 UTF-16 单元数（不含 NUL）；不足时返回所需长度，下面扩容后重试。
        let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
        if length == 0 {
            return Err(ClientError::Connect(format!(
                "GetSystemDirectoryW 失败: {}",
                std::io::Error::last_os_error()
            )));
        }
        let length = length as usize;
        if length < buffer.len() {
            let system_dir = String::from_utf16(&buffer[..length]).map_err(|error| {
                ClientError::Connect(format!("Windows 系统目录不是有效 UTF-16: {error}"))
            })?;
            return Ok(format!(
                r"{system_dir}\WindowsPowerShell\v1.0\powershell.exe"
            ));
        }
        buffer.resize(length.saturating_add(1), 0);
    }
}
