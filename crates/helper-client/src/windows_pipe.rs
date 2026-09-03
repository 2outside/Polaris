//! Windows 同步命名管道客户端。
//!
//! 与 helper 服务端 `platform/windows/service/win.rs` 使用同一组同步 Win32 原语。
//! 该模块是 crate 中唯一允许 unsafe 的边界；上层仍只看 `ConnectionStream`。

use crate::transport::ConnectionStream;
use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_BROKEN_PIPE, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows_sys::Win32::System::Pipes::PeekNamedPipe;

/// 管道空读时的轮询间隔。
///
/// 命名管道客户端没有「读超时」原语：`SetCommTimeouts` 只管串口，重叠 IO 要另起事件 + `CancelIoEx`
/// 取消腿（与服务端「同一组同步 Win32 原语」的约束冲突）。故以非阻塞 [`PeekNamedPipe`] 探可读量 +
/// 轮询，把整段读约束在 deadline 内。
///
/// **数值可调，无契约源**：取与同 crate `PipeConnector` 的 `ERROR_PIPE_BUSY` 重试同一节拍（10ms）；
/// 相对真机单次往返 ~0.2s 可忽略，且仅在「无数据可读」时才付这份等待。
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// 独占拥有一条双向同步命名管道连接。
pub(crate) struct WinPipeStream {
    handle: OwnedHandle,
    /// 当前读预算：初值 [`crate::transport::READ_TIMEOUT`]，随后由
    /// [`ConnectionStream::set_read_timeout`] 改写为调用方单请求预算的剩余量。
    read_timeout: Duration,
}

#[allow(
    unsafe_code,
    reason = "owns the CreateFileW HANDLE returned for this pipe instance"
)]
impl WinPipeStream {
    /// 以与真机原生探针相同的 access/share/flags 打开现有管道实例。
    pub(crate) fn connect(path: &Path) -> io::Result<Self> {
        let wide: Vec<u16> = OsStr::new(path).encode_wide().chain(Some(0)).collect();
        // SAFETY: `wide` 在调用期间存活且以 NUL 结尾；security/template 均为空；返回的有效
        // HANDLE 立即转交 OwnedHandle 独占，失败值不进入所有权包装。
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateFileW 成功返回一枚尚未被任何 Rust 所有者接管的独占 HANDLE。
        let handle = unsafe { OwnedHandle::from_raw_handle(handle.cast()) };
        Ok(Self {
            handle,
            read_timeout: crate::transport::READ_TIMEOUT,
        })
    }

    fn raw(&self) -> HANDLE {
        self.handle.as_raw_handle().cast()
    }

    /// 非阻塞探测管道中当前可读字节数（不消费数据）。对端已关闭时回 `ERROR_BROKEN_PIPE`。
    fn peek_available(&self) -> io::Result<u32> {
        let mut avail = 0u32;
        // SAFETY: handle 由 self 独占且在调用期间有效；除 lpTotalBytesAvail 外全部传 NULL
        // （PeekNamedPipe 明确允许），avail 为可写的本栈对象；本调用不读走管道数据。
        let ok = unsafe {
            PeekNamedPipe(
                self.raw(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut avail,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            // SAFETY: 紧邻失败的 PeekNamedPipe，线程未穿插其它 Win32 调用。
            let error = unsafe { GetLastError() };
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        Ok(avail)
    }
}

#[allow(
    unsafe_code,
    reason = "synchronous ReadFile/WriteFile calls borrow the owned pipe HANDLE"
)]
impl ConnectionStream for WinPipeStream {
    fn read_until_timeout(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        // 契约（transport.rs）：整段读受当前读预算约束。同步 ReadFile 一旦发出就不可中断，
        // 故先 PeekNamedPipe 非阻塞探可读量、只在确有数据时才发 ReadFile —— 于是「helper 服务侧
        // 挂住」表现为轮询到 deadline 后 TimedOut，而不是这次调用永不返回。
        let deadline = Instant::now() + self.read_timeout;
        let mut total = 0;
        loop {
            // deadline 检查必须在 loop **顶部**（peek 之前），不能挂在 `avail == 0` 那条分支里：
            // 挂在分支里时「对端持续快写、但一直不发 `\n`」的读永远走不到检查点 —— 整段读不返回、
            // `buf` 无界增长，正是 trait 契约（transport.rs「约束的是整段读」）要挡的那件事。
            // 与 Unix 姊妹腿（`connector.rs` 每字节循环顶部检查）同形。
            if Instant::now() >= deadline {
                return Err(io::Error::from(io::ErrorKind::TimedOut));
            }
            let avail = match self.peek_available() {
                Ok(n) => n,
                // 对端已关闭 = EOF（与下方 ReadFile 的同码分支一致）。
                Err(e) if e.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) => return Ok(total),
                Err(e) => return Err(e),
            };
            if avail == 0 {
                std::thread::sleep(POLL_INTERVAL);
                continue;
            }
            // avail > 0 ⇒ 以下每次 1 字节 ReadFile 都有数据可取，不会阻塞。
            for _ in 0..avail {
                let mut byte = 0u8;
                let mut read = 0u32;
                // SAFETY: handle 由 self 独占且在调用期间有效；byte/read 均为可写的本栈对象；
                // lpOverlapped=NULL 明确选择同步 ReadFile，与服务端及真机探针一致。
                let ok =
                    unsafe { ReadFile(self.raw(), &mut byte, 1, &mut read, std::ptr::null_mut()) };
                if ok == 0 {
                    // SAFETY: 紧邻失败的 ReadFile，线程未穿插其它 Win32 调用。
                    let error = unsafe { GetLastError() };
                    if error == ERROR_BROKEN_PIPE {
                        return Ok(total);
                    }
                    return Err(io::Error::from_raw_os_error(error as i32));
                }
                if read == 0 {
                    return Ok(total);
                }
                buf.push(byte);
                total += 1;
                if byte == b'\n' {
                    return Ok(total);
                }
            }
        }
    }

    fn set_read_timeout(&mut self, timeout: Duration) -> io::Result<()> {
        self.read_timeout = timeout;
        Ok(())
    }

    fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        let len = u32::try_from(data.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
        let mut written = 0u32;
        // SAFETY: handle 由 self 独占且有效；data 在调用期间不可变且长度为 len；written 可写；
        // lpOverlapped=NULL 明确选择同步单次 WriteFile，满足服务端“一次写完整帧”的 wire 约束。
        let ok = unsafe {
            WriteFile(
                self.raw(),
                data.as_ptr(),
                len,
                &mut written,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if written != len {
            return Err(io::ErrorKind::WriteZero.into());
        }
        Ok(())
    }

    fn shutdown(&mut self) -> io::Result<()> {
        // Windows duplex pipe 无写半关闭；服务端按单次完整帧读取，不依赖 EOF。
        Ok(())
    }
}
