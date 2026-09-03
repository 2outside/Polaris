//! 跨进程日志文件的硬预算 writer。
//!
//! 单一职责：把任意字节流写入 `file` + `file.1` 两代文件，并保证每代都不超过给定预算。
//! app 日志 sink 与三平台 helper 的 sing-box stdout/stderr 共用本实现，避免各平台复制一份
//! 「何时轮转 / Windows 先关句柄 / 超长单条如何处理」的判据。

#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

// 同一 helper 进程的快速 stop/start 可能让旧 pipe 的尾部排空与新 session 短暂重叠。
// 新 session 完成 fresh 初始化后接管；旧 reader 仍 drain，但不再污染新代日志。
static PREOPENED_LOG_LOCK: Mutex<()> = Mutex::new(());
static PREOPENED_LOG_NEXT_SESSION: AtomicU64 = AtomicU64::new(1);
static PREOPENED_LOG_ACTIVE_SESSION: AtomicU64 = AtomicU64::new(0);

/// Polaris 管理日志的单代预算；两代文件的总硬上限为其两倍。
pub const DEFAULT_GENERATION_BYTES: u64 = 5 * 1024 * 1024;

/// 打开时是否把现有 current 先滚入 `.1`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// 延续当前代；app 常驻 sink 使用。
    Append,
    /// 新会话从空 current 开始；helper 每次起核使用，保证启动失败诊断不会串到旧会话。
    Fresh,
}

/// 两代有界文件 writer。调用方需要并发写时在外层用 `Mutex` 串行化。
#[derive(Debug)]
pub struct RotatingFile {
    file: File,
    path: PathBuf,
    bytes: u64,
    generation_bytes: u64,
}

/// 特权 helper 已在自己的路径信任边界内打开的两代日志文件。
///
/// writer 接管后只操作这两个已持有的 inode/Windows file object；轮转不会关闭后再按路径重开，
/// 因而用户可写父目录的 rename/symlink/junction 替换不会把高权限写入重定向到第三个对象。
#[derive(Debug)]
pub struct PreopenedLogFiles {
    current: File,
    rotated: File,
}

impl PreopenedLogFiles {
    #[must_use]
    pub fn new(current: File, rotated: File) -> Self {
        Self { current, rotated }
    }
}

#[derive(Debug)]
struct PreopenedRotatingFile {
    current: File,
    rotated: File,
    bytes: u64,
    generation_bytes: u64,
    session: u64,
}

impl PreopenedRotatingFile {
    fn open(
        files: PreopenedLogFiles,
        generation_bytes: u64,
        mode: OpenMode,
    ) -> std::io::Result<Self> {
        if generation_bytes == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "log generation budget must be greater than zero",
            ));
        }
        let _operation = PREOPENED_LOG_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A new helper start supersedes the previous session even when fresh initialization fails.
        // Otherwise a late writer from the stopped core could remain active while the new core is
        // already running with logging intentionally drained.
        let session = PREOPENED_LOG_NEXT_SESSION.fetch_add(1, Ordering::Relaxed);
        PREOPENED_LOG_ACTIVE_SESSION.store(session, Ordering::Release);
        let PreopenedLogFiles {
            mut current,
            mut rotated,
        } = files;
        trim_open_file_to_tail(&mut rotated, generation_bytes)?;
        trim_open_file_to_tail(&mut current, generation_bytes)?;
        if mode == OpenMode::Fresh && current.metadata()?.len() > 0 {
            replace_with_tail(&mut rotated, &mut current, generation_bytes)?;
            truncate_open_file(&mut current)?;
        }
        let bytes = current.metadata()?.len();
        current.seek(SeekFrom::End(0))?;
        rotated.seek(SeekFrom::End(0))?;
        Ok(Self {
            current,
            rotated,
            bytes,
            generation_bytes,
            session,
        })
    }

    fn write_chunk(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let _operation = PREOPENED_LOG_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if PREOPENED_LOG_ACTIVE_SESSION.load(Ordering::Acquire) != self.session {
            return Ok(());
        }
        if bytes.is_empty() {
            return Ok(());
        }
        let max = usize::try_from(self.generation_bytes).unwrap_or(usize::MAX);
        let bounded = if bytes.len() > max {
            &bytes[bytes.len() - max..]
        } else {
            bytes
        };
        let append_len = u64::try_from(bounded.len()).unwrap_or(u64::MAX);
        // 每次从已持有对象重取长度/EOF：即使同账户外部 writer 或旧 session 曾移动游标，
        // 当前 managed write 也不会在截断后的旧 offset 制造稀疏超限文件。
        trim_open_file_to_tail(&mut self.current, self.generation_bytes)?;
        self.bytes = self.current.metadata()?.len();
        self.current.seek(SeekFrom::End(0))?;
        if self.bytes > 0 && self.bytes.saturating_add(append_len) > self.generation_bytes {
            self.rotate()?;
        }
        self.current.write_all(bounded)?;
        self.bytes = self.bytes.saturating_add(append_len);
        Ok(())
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        self.current.flush()?;
        replace_with_tail(&mut self.rotated, &mut self.current, self.generation_bytes)?;
        truncate_open_file(&mut self.current)?;
        self.bytes = 0;
        Ok(())
    }
}

#[derive(Debug)]
enum PipeLogWriter {
    Path(RotatingFile),
    Preopened(PreopenedRotatingFile),
}

impl PipeLogWriter {
    fn write_chunk(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Path(writer) => writer.write_chunk(bytes),
            Self::Preopened(writer) => writer.write_chunk(bytes),
        }
    }
}

impl RotatingFile {
    /// 打开一个有界 writer。
    ///
    /// `Fresh` 会先轮转非空 current；`Append` 会续写。旧版本留下的超限 managed 文件会就地
    /// 保留最近一代预算，避免它继续绕过新上限。任何 IO 错误显式返回给调用方，由日志调用链降级。
    pub fn open(
        path: impl Into<PathBuf>,
        generation_bytes: u64,
        mode: OpenMode,
    ) -> std::io::Result<Self> {
        if generation_bytes == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "log generation budget must be greater than zero",
            ));
        }
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let rotated = rotated_path(&path);
        reject_symlink(&rotated)?;
        reject_symlink(&path)?;
        trim_file_to_tail(&rotated, generation_bytes)?;
        trim_file_to_tail(&path, generation_bytes)?;
        if mode == OpenMode::Fresh && std::fs::symlink_metadata(&path).is_ok_and(|m| m.len() > 0) {
            rotate(&path)?;
        }
        let file = open_append(&path)?;
        let bytes = file.metadata().map_or(0, |m| m.len());
        Ok(Self {
            file,
            path,
            bytes,
            generation_bytes,
        })
    }

    /// 写一个完整字节块。超出单代预算的块只保留其末尾（日志 tail 语义）；current 与 `.1`
    /// 在本方法返回时均不超过预算。
    pub fn write_chunk(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let max = usize::try_from(self.generation_bytes).unwrap_or(usize::MAX);
        let bounded = if bytes.len() > max {
            &bytes[bytes.len() - max..]
        } else {
            bytes
        };
        let append_len = u64::try_from(bounded.len()).unwrap_or(u64::MAX);
        if self.bytes > 0 && self.bytes.saturating_add(append_len) > self.generation_bytes {
            self.rotate()?;
        }
        self.file.write_all(bounded)?;
        self.bytes = self.bytes.saturating_add(append_len);
        Ok(())
    }

    /// 写一条文本日志并补换行；整条作为一个预算单元，避免正文与换行被拆到两代。
    pub fn write_line(&mut self, line: &str) -> std::io::Result<()> {
        let mut record = Vec::with_capacity(line.len().saturating_add(1));
        record.extend_from_slice(line.as_bytes());
        record.push(b'\n');
        self.write_chunk(&record)
    }

    /// 刷新当前文件。
    pub fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        self.file.flush()?;
        // Windows 不能 rename 本进程仍打开的文件：先用一个临时空句柄替换并 drop 旧句柄。
        let replacement = open_sink()?;
        let old = std::mem::replace(&mut self.file, replacement);
        drop(old);
        rotate(&self.path)?;
        self.file = open_append(&self.path)?;
        self.bytes = 0;
        Ok(())
    }
}

/// 把 child 的 stdout/stderr 持续排入同一个有界文件。即使文件打不开，也会起线程把管道读空，
/// 避免 child 因 pipe buffer 填满而卡死。
pub fn spawn_pipe_loggers<O, E>(
    stdout: Option<O>,
    stderr: Option<E>,
    path: impl Into<PathBuf>,
    generation_bytes: u64,
) where
    O: Read + Send + 'static,
    E: Read + Send + 'static,
{
    spawn_pipe_loggers_with_file(stdout, stderr, path, generation_bytes, |_| {});
}

/// 与 [`spawn_pipe_loggers`] 相同，但在 reader 线程启动前把**实际 writer 的文件描述符**交给回调。
///
/// Linux 特权 helper 用它对 writer 已打开的同一 fd 执行 `fchown`；不能在外层按路径再次 `open`，否则
/// 用户可写目录中的路径替换会让“日志写入对象”和“root 修正属主对象”分叉。writer 打不开时回调收到
/// `None`，随后仍会排空 pipe，保持基础函数的不卡 child 语义。
pub fn spawn_pipe_loggers_with_file<O, E, F>(
    stdout: Option<O>,
    stderr: Option<E>,
    path: impl Into<PathBuf>,
    generation_bytes: u64,
    after_open: F,
) where
    O: Read + Send + 'static,
    E: Read + Send + 'static,
    F: FnOnce(Option<&File>),
{
    let writer = RotatingFile::open(path.into(), generation_bytes, OpenMode::Fresh).ok();
    after_open(writer.as_ref().map(|opened| &opened.file));
    let shared = Arc::new(Mutex::new(writer.map(PipeLogWriter::Path)));
    spawn_pipe_readers(stdout, stderr, shared);
}

/// 使用特权侧预开的 current/`.1` 文件持续排空 child stdout/stderr。
///
/// 与路径版相同，打开/初始化失败时仍排空管道；不同之处是 fresh rotate 与后续运行期轮转均只
/// 操作传入的两个文件对象，从不再解析原路径。helper 的单核生命周期允许快速重启重叠排空：
/// 较新的调用完成初始化后成为进程内 active session，较旧 reader 仍 drain、但迟到字节会丢弃。
pub fn spawn_pipe_loggers_with_preopened_files<O, E>(
    stdout: Option<O>,
    stderr: Option<E>,
    files: PreopenedLogFiles,
    generation_bytes: u64,
) where
    O: Read + Send + 'static,
    E: Read + Send + 'static,
{
    let writer = PreopenedRotatingFile::open(files, generation_bytes, OpenMode::Fresh)
        .map(PipeLogWriter::Preopened)
        .ok();
    let shared = Arc::new(Mutex::new(writer));
    spawn_pipe_readers(stdout, stderr, shared);
}

/// 日志对象无法安全打开时仍持续排空 child stdout/stderr，避免 pipe buffer 反压卡死 child。
pub fn spawn_pipe_drainers<O, E>(stdout: Option<O>, stderr: Option<E>)
where
    O: Read + Send + 'static,
    E: Read + Send + 'static,
{
    spawn_pipe_readers(stdout, stderr, Arc::new(Mutex::new(None)));
}

fn spawn_pipe_readers<O, E>(
    stdout: Option<O>,
    stderr: Option<E>,
    shared: Arc<Mutex<Option<PipeLogWriter>>>,
) where
    O: Read + Send + 'static,
    E: Read + Send + 'static,
{
    if let Some(reader) = stdout {
        spawn_pipe_logger(reader, Arc::clone(&shared));
    }
    if let Some(reader) = stderr {
        spawn_pipe_logger(reader, shared);
    }
}

fn spawn_pipe_logger(
    mut reader: impl Read + Send + 'static,
    writer: Arc<Mutex<Option<PipeLogWriter>>>,
) {
    std::thread::spawn(move || {
        let mut buf = [0_u8; 16 * 1024];
        loop {
            let Ok(read) = reader.read(&mut buf) else {
                return;
            };
            if read == 0 {
                return;
            }
            if let Ok(mut guard) = writer.lock() {
                if let Some(file) = guard.as_mut() {
                    if file.write_chunk(&buf[..read]).is_err() {
                        *guard = None;
                    }
                }
            }
        }
    });
}

fn trim_open_file_to_tail(file: &mut File, max_bytes: u64) -> std::io::Result<()> {
    let len = file.metadata()?.len();
    if len <= max_bytes {
        file.seek(SeekFrom::End(0))?;
        return Ok(());
    }
    let take = len.min(max_bytes);
    let capacity = usize::try_from(take).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "log generation budget does not fit in address space",
        )
    })?;
    let mut tail = Vec::with_capacity(capacity);
    file.seek(SeekFrom::Start(len.saturating_sub(take)))?;
    file.take(take).read_to_end(&mut tail)?;
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&tail)?;
    file.seek(SeekFrom::End(0))?;
    Ok(())
}

fn replace_with_tail(
    destination: &mut File,
    source: &mut File,
    max_bytes: u64,
) -> std::io::Result<()> {
    trim_open_file_to_tail(source, max_bytes)?;
    destination.set_len(0)?;
    destination.seek(SeekFrom::Start(0))?;
    source.seek(SeekFrom::Start(0))?;
    std::io::copy(&mut source.take(max_bytes), destination)?;
    destination.flush()?;
    destination.seek(SeekFrom::End(0))?;
    source.seek(SeekFrom::End(0))?;
    Ok(())
}

fn truncate_open_file(file: &mut File) -> std::io::Result<()> {
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(())
}

/// 读取 current + `.1` 组成的逻辑日志尾部，按旧代→当前代顺序返回，合计不超过 `max_bytes`。
pub fn read_rotated_tail(path: &Path, max_bytes: u64) -> std::io::Result<Vec<u8>> {
    if max_bytes == 0 {
        return Ok(Vec::new());
    }
    let current_len = std::fs::metadata(path).map_or(0, |m| m.len());
    let current_take = current_len.min(max_bytes);
    let old_take = max_bytes.saturating_sub(current_take);
    let mut out = if old_take > 0 {
        read_file_tail(&rotated_path(path), old_take).unwrap_or_default()
    } else {
        Vec::new()
    };
    out.extend(read_file_tail(path, current_take).unwrap_or_default());
    if out.is_empty() && !path.exists() && !rotated_path(path).exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "log file not found",
        ));
    }
    Ok(out)
}

/// `.1` 路径（`foo.log` → `foo.log.1`）。
#[must_use]
pub fn rotated_path(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(".1");
    PathBuf::from(os)
}

fn rotate(path: &Path) -> std::io::Result<()> {
    let rotated = rotated_path(path);
    reject_symlink(path)?;
    reject_symlink(&rotated)?;
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }
    match std::fs::symlink_metadata(&rotated) {
        Ok(_) => std::fs::remove_file(&rotated)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    std::fs::rename(path, rotated)
}

fn trim_file_to_tail(path: &Path, max_bytes: u64) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    no_follow(&mut options);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    secure_file_permissions(&file)?;
    let meta = file.metadata()?;
    if meta.len() <= max_bytes {
        return Ok(());
    }
    let take = meta.len().min(max_bytes);
    file.seek(SeekFrom::Start(meta.len().saturating_sub(take)))?;
    let cap = usize::try_from(take).unwrap_or(usize::MAX);
    let mut tail = Vec::with_capacity(cap);
    (&mut file).take(take).read_to_end(&mut tail)?;
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&tail)?;
    file.flush()
}

fn read_file_tail(path: &Path, max_bytes: u64) -> std::io::Result<Vec<u8>> {
    if max_bytes == 0 {
        return Ok(Vec::new());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    no_follow(&mut options);
    let mut file = options.open(path)?;
    let len = file.metadata()?.len();
    let take = len.min(max_bytes);
    file.seek(SeekFrom::Start(len.saturating_sub(take)))?;
    let cap = usize::try_from(take).unwrap_or(usize::MAX);
    let mut out = Vec::with_capacity(cap);
    file.take(take).read_to_end(&mut out)?;
    Ok(out)
}

fn open_append(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    no_follow(&mut options);
    let file = options.open(path)?;
    // `mode` only governs newly created files. Older releases may have left 0644 logs; tighten the
    // already-open fd before any caller writes a byte so secrets never regain a world-readable window.
    secure_file_permissions(&file)?;
    Ok(file)
}

#[cfg(unix)]
fn secure_file_permissions(file: &File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn secure_file_permissions(_: &File) -> std::io::Result<()> {
    Ok(())
}

fn reject_symlink(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing symlink log path: {}", path.display()),
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn no_follow(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_NOFOLLOW);
}

#[cfg(not(unix))]
fn no_follow(_: &mut OpenOptions) {}

#[cfg(unix)]
fn open_sink() -> std::io::Result<File> {
    OpenOptions::new().write(true).open("/dev/null")
}

#[cfg(windows)]
fn open_sink() -> std::io::Result<File> {
    OpenOptions::new().write(true).open("NUL")
}

#[cfg(not(any(unix, windows)))]
fn open_sink() -> std::io::Result<File> {
    let path = std::env::temp_dir().join("polaris-log-budget-sink");
    OpenOptions::new().create(true).append(true).open(path)
}

#[cfg(test)]
mod tests;
