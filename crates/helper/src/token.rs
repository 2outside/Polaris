//! token 行鉴权（合并自 `helper-mac/src/token.rs` + `helper-win/src/token.rs`，移植自 Polaris
//! `helper/helper.go:87-90,403-408` 与 `helper-win/helper.go:74-77,169`）。
//!
//! ## 为何合并
//!
//! mac/win 两份 `token.rs` 的 `TOKEN_FILENAME` / [`TokenStore`] trait / [`FileTokenStore`] /
//! `StaticTokenStore`（测试桩）逐字等价（架构穷举报告确认）。本模块抽公共、**特权侧（mac/win helper）
//! 的单一真值**；差异（mac 自实现常量时间比对 vs win 用 `==`）统一到**常量时间比对**——mac 的
//! 加固版推广到 win，零成本安全升级。
//!
//! ## 合并范围的诚实边界（勿再误读为「全仓单一真值」）
//!
//! 本模块**只覆盖特权 helper 侧**。非特权侧（`helper-client`）现状核对**没有**独立的 token 比对
//! 函数——客户端只经 `helper-client` 发送 token 副本，鉴权判定全在 helper 侧读自身文件后完成。
//! 此前本节曾记述一个非特权侧的独立实现 `helper-client/src/token.rs::is_authorized`，该文件里没有
//! 该符号；按现状更正，不再复述已不成立的「第三个独立实现」框架：
//!
//! - `helper-client` 不依赖 `helper-common`（本 crate 带 `sha2`/`hex`，非特权侧不该为一个
//!   比对函数牵连进来）——这条依赖图取舍与该符号是否存在无关，仍然成立。
//! - `helper-common` 不依赖 `helper-proto`（见 [`crate::core_install`] 里 `is_valid_sha256_hex`
//!   同款取舍）—— 故也无法借零依赖的 proto 作公共落点。
//!
//! ## 威胁模型（逐字对照 Go 源 `helper.go:4-9` / `helper-win/helper.go:8-13`）
//!
//! token 是 helper 的**主鉴权边界**：
//! - macOS：helper 监听 0666 unix socket，任何本地进程都能连，token 是唯一安全边界（socket 权限只防远程）。
//! - Windows：命名管道虽有 SDDL ACL（纵深防御），但 token 仍是主边界。
//!
//! token 文件 `helper.token` 仅特权账户可读（mac 600/root，win SYSTEM）；app 持自身副本经 socket/管道
//! 第 1 行发送，helper 读自身文件比对。残余风险：能读到 app 配置目录内 token 的同用户进程可驱动 helper
//!（Polaris 未签名 → 无法做 SMJobBless 客户端证书校验）。token + 二进制路径锁定 + 配置目录约束为
//! 现实可行的缓解组合。
//!
//! ## 协议形态（`helper.go:403-404` / `helper-win/helper.go:167-168`）
//!
//! ```text
//! 行1: <token>   ← 客户端发送的副本
//! 行2: <command>
//! ```
//! helper 读行1 与 [`TokenStore::token_value`] 比对，不等立即 `ERR auth`。
//!
//! ## 移植纪律
//!
//! Go `tokenValue()` 读 `supportDir/helper.token` 全文 trim。本模块把「读 token 文件」抽象为
//! [`TokenStore`] trait —— 测试可注入内存副本（不触碰宿主真 token 文件），生产 impl 读真实路径。
//! 鉴权判定本身（[`check_token`]）是常量时间比对，纯逻辑、跨平台可测。
//!
//! ## 读侧信任判据（unix；对齐 `platform::linux::auth` 的 authfile 处置）
//!
//! Go 原版 `os.ReadFile` 读即信任 —— 信任的来源是「写时设过 0600 + root 属主」，读时没验过。
//! 部署一旦权限漂移（升级脚本半途失败、手工 chmod、还原备份丢属主），helper 会把一份
//! 非特权用户可读写的文件当作主鉴权凭据。故 unix 读腿改 `open` → `fstat(fd)` → `read` 同一 fd，
//! 判据（属主须 root、`mode & 0o077 == 0`）与写侧契约同源，由纯函数 [`trusted_token_value`] 持有，
//! 不过则 fail-closed（视同 token 不可用 → [`TokenCheck::EmptyStored`] → `ERR auth`）。
//! Windows 无对应语义、等价 ACL 校验另属一批，见 `FileTokenStore::read_token_value` 的
//! `cfg(not(unix))` 腿。
//!
//! ## 常量时间比对
//!
//! [`const_time_eq`] 自实现、不依赖 `subtle` 等 crate：token 长度短且固定，纯算术异或累计足够。
//! helper-common 是 `#![forbid(unsafe_code)]`——本函数纯算术、无 unsafe。

use std::path::{Path, PathBuf};

/// token 文件名（`helper.go:88` / `helper-win/helper.go:75`：`filepath.Join(supportDir, "helper.token")`
/// 的末段）。常量单一真值，跨平台逐字同。
pub const TOKEN_FILENAME: &str = "helper.token";

/// token 存储抽象 —— 生产读文件，测试注入内存值。
///
/// 对应 Go `tokenValue()` 的「读 supportDir/helper.token 并 trim」语义。trait 化是为测试可注入
/// （不触碰宿主真 token 文件，本机 Linux CI 也不需 root）。
pub trait TokenStore: Send + Sync {
    /// 返回当前 token 值（已 trim）。读失败 / 文件不存在返回空串（等价 Go `b, _ := os.ReadFile(...)`
    /// 忽略 err）；unix 生产实现另有读侧信任判据，不过亦返回空串（见 [`FileTokenStore`]）。
    fn token_value(&self) -> String;
}

/// 文件系统 token 存储生产实现（对应 Go `os.ReadFile(filepath.Join(supportDir, "helper.token"))`）。
///
/// 构造时存 `support_dir`，读取时 join `helper.token`（Go `filepath.Join` 语义）。
/// trim 后返回；失败 / 不存在 → 空串（Go `_` 吞错误同款）。任何非空客户端 token 与空存储比对 →
/// [`TokenCheck::EmptyStored`] → 永远拒，安全失败。
///
/// **unix 上还要过读侧信任判据**（属主 root + `mode & 0o077 == 0`，判据见 [`trusted_token_value`]）：
/// 不过 → 同样返回空串（fail-closed，走上面那条 `EmptyStored` 拒绝路径）。
///
/// 注意：本类型在所有平台编译（读文件本身跨平台），生产侧由各 helper 在各自平台实例化
///（mac LaunchDaemon 路径 / win SCM 路径）。
#[derive(Debug, Clone)]
pub struct FileTokenStore {
    support_dir: PathBuf,
}

impl FileTokenStore {
    /// 构造：`support_dir` 即 Go `--support` flag 值（mac 默认
    /// `/Library/Application Support/Polaris`，win 默认 `C:\ProgramData\Polaris`）。token 文件路径
    /// 延迟 join（[`token_path`](Self::token_path)），与 Go `filepath.Join(supportDir, "helper.token")` 一致。
    #[must_use]
    pub fn new(support_dir: impl AsRef<Path>) -> Self {
        Self {
            support_dir: support_dir.as_ref().to_path_buf(),
        }
    }

    /// token 文件完整路径（`support_dir/helper.token`，诊断 / 日志 / 安装期写入用）。
    #[must_use]
    pub fn token_path(&self) -> PathBuf {
        self.support_dir.join(TOKEN_FILENAME)
    }

    /// token 文件完整路径的引用视图（win 既有 `path()` 习惯的兼容别名，等价
    /// `self.token_path()` 但免 alloc）。
    ///
    /// 注意：本方法借用 `&self`，返回 `PathBuf` 的 clone 之外的零拷贝路径需经 [`token_path`](Self::token_path)。
    /// 为兼容 win 旧调用点（`store.path()`），此处返回完整路径。
    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.token_path()
    }
}

/// token 文件元数据不可信的原因（拒绝时写日志：说清**谁的文件 / 什么权限 / 期望什么**）。
///
/// 日志与 `Display` 一律**不带文件内容** —— 内容就是要保护的 token 本身。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TokenFileDistrust {
    /// 属主非 root：该属主可任意改写 token 值 —— 写一份自己知道的 token 进去，
    /// 再拿它连 helper 即得 root 服务（token 是主鉴权边界，见模块威胁模型）。
    #[error(
        "token file owner uid={owner_uid} (mode {mode:04o}); expected owner root (uid=0), mode 0600 or stricter"
    )]
    NotRootOwned {
        /// 实际属主 uid。
        owner_uid: u32,
        /// 实际权限位（已剥掉文件类型位）。
        mode: u32,
    },
    /// 权限含 group/other 位：组内/全体成员可**读**到 token 即可冒充 app 驱动 helper；
    /// 可写则可直接把 token 换成自己的值。
    #[error(
        "token file mode {mode:04o} (owner uid={owner_uid}) grants group/other access; expected mode 0600 or stricter (mode & 0o077 == 0)"
    )]
    GroupOrOtherAccessible {
        /// 实际属主 uid（此分支下恒为 0）。
        owner_uid: u32,
        /// 实际权限位（已剥掉文件类型位）。
        mode: u32,
    },
}

/// `st_mode` 的权限位掩码 —— `MetadataExt::mode()` 返回完整 `st_mode`（含 `S_IFREG` 等文件类型位），
/// 判据与日志都只该看权限位。
///
/// 与 `platform::linux::auth` 的同名常量重复而非复用：那个模块整体 `cfg(target_os = "linux")`，
/// 本模块要在 mac/win 上编译，借不到（把常量上提会动 auth.rs，本批不碰）。
const PERMISSION_BITS: u32 = 0o7777;
/// group + other 的 rwx 位。token 文件上任一位置位即不可信（0600 或更严才作数）。
const GROUP_OTHER_BITS: u32 = 0o077;

/// 判定 token 文件可信后返回其 token 值 —— **纯逻辑判据，不碰文件系统**。
///
/// 入参就是生产腿从**同一个 fd** 取到的三元组：属主 uid / `st_mode`（完整或仅权限位皆可）/ 文件全文。
/// 判据由本函数持有，[`FileTokenStore::token_value`] 只负责取数 —— 于是「非 root 属主拒绝」
/// 「group/other 可读拒绝」「root+0600 通过」在**非特权测试环境里也能逐条钉住**
/// （真造一份 root 属主的文件是做不到的）。判据与写侧契约同源：安装脚本
/// `chown root:wheel` + `chmod 600`（`helper-client/src/manager.rs`），此处验的就是它。
///
/// 顺序：先验属主、再验权限（任一不过 → `Err`，一律不给 token 值），最后才 trim 内容。
///
/// 返回 `Ok(token)` = 文件可信，值已 trim（Go `strings.TrimSpace` 语义）；`Err` = 文件本身不可信。
pub fn trusted_token_value(
    owner_uid: u32,
    mode: u32,
    contents: &[u8],
) -> Result<String, TokenFileDistrust> {
    let mode = mode & PERMISSION_BITS;
    // 属主非 root ⇒ token 值由非特权方掌握，读它等于让对方自己发自己的通行证。
    if owner_uid != 0 {
        return Err(TokenFileDistrust::NotRootOwned { owner_uid, mode });
    }
    // group/other 任一位 ⇒ root 之外还有人能看到（或改写）这份主鉴权凭据。
    if mode & GROUP_OTHER_BITS != 0 {
        return Err(TokenFileDistrust::GroupOrOtherAccessible { owner_uid, mode });
    }
    // Go: return strings.TrimSpace(string(b))
    Ok(String::from_utf8_lossy(contents).trim().to_owned())
}

impl FileTokenStore {
    /// unix 读腿：`open` → `fstat(fd)` → `read` **同一个 fd**，元数据可信才认内容。
    ///
    /// 与 `platform::linux::auth::owned_by` / `read_auth_file` 同一条 TOCTOU 纪律：`fstat(fd)` 而非
    /// `stat(path)`，且属主/权限与随后读出的字节来自**同一个已打开的 inode** —— 不给「校验通过后把
    /// 路径换成攻击者的文件」（symlink swap / rename）留缝。
    ///
    /// 拒绝 = fail-closed：返回空串，等价「token 不可用」，走既有 [`TokenCheck::EmptyStored`] 路径
    /// （任何非空客户端 token 都不匹配 → `ERR auth`）。不 panic；拒绝原因写 stderr
    /// （mac helper 是 LaunchDaemon，stderr 进系统日志），**不含文件内容**。
    #[cfg(unix)]
    fn read_token_value(&self) -> String {
        use std::io::Read;
        use std::os::unix::fs::MetadataExt;
        let path = self.token_path();
        // Go `os.ReadFile` 的 open 段；失败（缺文件 / 无权限）→ 空串，与修前一致。
        let Ok(mut f) = std::fs::File::open(&path) else {
            return String::new();
        };
        // File::metadata() 走 fstat(fd)（非 stat(path)）—— 校验对象 == 随后被读的 inode。
        let Ok(meta) = f.metadata() else {
            return String::new();
        };
        let (owner_uid, mode) = (meta.uid(), meta.mode());
        let mut contents = Vec::new();
        if f.read_to_end(&mut contents).is_err() {
            return String::new();
        }
        match trusted_token_value(owner_uid, mode, &contents) {
            Ok(token) => token,
            Err(distrust) => {
                eprintln!(
                    "polaris-helper: refusing token file {}: {distrust}",
                    path.display()
                );
                String::new()
            }
        }
    }

    /// 非 unix（Windows）读腿：**逐字保真**修前实现（`std::fs::read` + trim）。
    ///
    /// 不套 unix 判据：`fstat`/uid/mode 在 Windows 上无对应语义（`MetadataExt::mode()` 不存在，
    /// `st_uid` 恒 0 是模拟值，照搬会得到一个恒真的假判据）。等价校验须读文件 DACL
    /// （`GetSecurityInfo` + 逐 ACE 枚举，判定除 SYSTEM/Administrators 外无主体有访问权），
    /// 依赖 `windows-sys` 且「哪些 SID 算可接受」本身是一套需单独拍板的判据 —— 成本与误判风险
    /// 都远高于本批射程，**登记不硬造**（写侧现状：安装脚本 `icacls /inheritance:r` +
    /// 仅授 `SYSTEM`/`Administrators` `(OI)(CI)(F)`，token 出生即 SYSTEM/Admin 私有）。
    #[cfg(not(unix))]
    fn read_token_value(&self) -> String {
        // Go: b, _ := os.ReadFile(...); return strings.TrimSpace(string(b))
        match std::fs::read(self.token_path()) {
            Ok(b) => String::from_utf8_lossy(&b).trim().to_owned(),
            Err(_) => String::new(),
        }
    }
}

impl TokenStore for FileTokenStore {
    fn token_value(&self) -> String {
        self.read_token_value()
    }
}

/// 静态 token 存储桩（测试用内存副本，移植自 `helper-win` 的同名类型）。
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct StaticTokenStore {
    token: String,
}

#[cfg(test)]
impl StaticTokenStore {
    #[must_use]
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }
}

#[cfg(test)]
impl TokenStore for StaticTokenStore {
    fn token_value(&self) -> String {
        self.token.clone()
    }
}

/// token 比对结果（移植自 `helper-mac` 的 `TokenCheck`，扩展为四分支以提供更细粒度的失败诊断）。
///
/// 严格对照 Go `helper.go:405-407` / `helper-win/helper.go:169`：
/// `if tok == "" || tok != tokenValue() { ERR auth }`。两条件任一成立即拒。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenCheck {
    /// token 匹配，继续处理命令。
    Authed,
    /// 客户端发空行 → 拒（防无 token 进程连上即通过耗资源）。
    EmptyClient,
    /// 服务端无 token（文件缺失 / 读失败 / 空文件）→ 拒（安装期未就绪的安全失败）。
    EmptyStored,
    /// 两端非空但不等 → 拒（token 不匹配）。
    Mismatch,
}

impl TokenCheck {
    /// 是否鉴权通过（便利判定，等价 `matches!(self, TokenCheck::Authed)`）。
    #[must_use]
    pub fn is_authed(self) -> bool {
        matches!(self, Self::Authed)
    }
}

/// 比对客户端发送的 token 行与存储值，返回细粒度结果（移植自 `helper-mac` 的 `verify_token`）。
///
/// 双重拒空 + 常量时间比对：
/// - 客户端空 → [`TokenCheck::EmptyClient`]。
/// - 存储空 → [`TokenCheck::EmptyStored`]。
/// - 两端非空 → [`const_time_eq`] 比对，匹配 → [`TokenCheck::Authed`]，否则 [`TokenCheck::Mismatch`]。
pub fn check_token(client_token: &str, stored_token: &str) -> TokenCheck {
    if client_token.is_empty() {
        return TokenCheck::EmptyClient;
    }
    if stored_token.is_empty() {
        return TokenCheck::EmptyStored;
    }
    if const_time_eq(client_token.as_bytes(), stored_token.as_bytes()) {
        TokenCheck::Authed
    } else {
        TokenCheck::Mismatch
    }
}

/// 鉴权判定（bool 版便利函数，取代 `helper-win` 旧 `is_authed` 的 `==` 版本，**升级为常量时间比对**）。
///
/// 双重拒空：客户端 token 为空 → 拒；服务端无 token → 拒。两端非空走 [`const_time_eq`]。
///
/// # 参数
///
/// - `client_tok`：客户端发来的 token 行（已 trim `\r\n`，对应 Go `readLine`）。
/// - `expected`：服务端真值（来自 [`TokenStore::token_value`]）。
///
/// # 返回
///
/// `true` = 鉴权通过；`false` = 拒（helper 应回 `ERR auth`）。
///
/// # 常量时间比对
///
/// 本实现**升级**为常量时间比对（[`const_time_eq`]）——原 `helper-win` 用 `==` 非常量时间。token 不是
/// 密码而是「持有者即授权」凭据，非常数时间比对的增量风险低，但常量时间无额外成本（token 长度短且固定），
/// 故统一采用作为纵深防御。等价 [`check_token`] 返回 [`TokenCheck::Authed`]。
#[must_use]
pub fn is_authed_constant_time(client_tok: &str, expected: &str) -> bool {
    check_token(client_tok, expected).is_authed()
}

/// 常量时间字节比对（防计时侧信道，移植自 `helper-mac` 自实现，下沉到公共层）。
///
/// 不依赖第三方 crate（`subtle` 等）—— token 长度短且固定，纯算术自实现足够。算法：长度不等直接返回
/// false（本地 socket 场景攻击者已知自己发的长度，长度泄漏无增量风险），等长则累计所有字节异或，
/// 全零才相等。本函数防的是字节值差导致的提前退出计时差（朴素 `==` 短路逻辑）。
///
/// helper-common 是 `#![forbid(unsafe_code)]`——本函数纯算术、零 unsafe。
pub fn const_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 便利：判断给定 support_dir 下 token 文件是否存在（安装期检查用，移植自 `helper-mac`）。
#[must_use]
pub fn token_file_exists(support_dir: &Path) -> bool {
    support_dir.join(TOKEN_FILENAME).exists()
}

#[cfg(test)]
mod tests;
