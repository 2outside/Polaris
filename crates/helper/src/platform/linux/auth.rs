//! SO_PEERCRED 鉴权 + 授权 uid 列表（移植自 上游 `helper-linux/helper.go:77-115`）。
//!
//! Linux 无 token 行：对端进程身份经内核 `SO_PEERCRED` 取得（uid/gid 在 connect 时锁定、不可伪造），
//! 再查 root-owned authfile 的 uid 允许列表。
//!
//! ## 移植纪律
//! - Go 源 `peerCred(conn)` 经 `syscall.GetsockoptUcred(SOL_SOCKET, SO_PEERCRED)` 取凭据；本实现
//!   经 `tokio::net::UnixListener` 的 `peer_cred()`（标准库 `UCred` 的一等原生 API，无 unsafe）。
//! - Go 源 `isAuthorized(uid)` 逐行解析 authfile；本实现读文件后按行 split + parse，行为等价。
//! - 安全模型：root(0) 恒授权；authfile 缺失时非 root 一律失败安全（返回 false）。
//! - **authfile 可信性**：内容只有在文件 owner==root(0) 且权限不含 group/other 位（0600 或更严）
//!   时才作数。否则非特权用户可预置/篡改这份列表把任意 uid 写进去，helper 会照单授权 —— 提权向量。
//!   判据由 [`authorize_uid`] 这个纯函数持有（生产腿 [`is_authorized`] 只负责取数）。
//!
//! 所有系统操作经 [`PeerCredProvider`] trait 抽象，测试用 `StaticPeerCred`（测试桩）注入伪造 uid。

use std::path::Path;

/// 对端进程凭据（uid/gid），移植自 Go `syscall.Ucred`（内核在 connect 时锁定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    /// 对端进程 uid（鉴权与 setuid 的唯一依据）。
    pub uid: u32,
    /// 对端进程 gid（setuid 拉核时 setgid 目标）。
    pub gid: u32,
}

/// 取对端凭据的抽象（trait 便于测试 mock；生产用 [`TokioPeerCred`]）。
///
/// 等价 Go `peerCred(conn)`：经 SO_PEERCRED 取不可伪造的 uid/gid。
pub trait PeerCredProvider {
    /// 返回对端 uid/gid；失败（非 unix conn / Getsockopt 失败）返回 None → 上层报 `ERR peercred`。
    fn peer_cred(&self) -> Option<PeerCred>;
}

/// 鉴权错误码（对应 wire 协议 `ERR peercred` / `ERR unauthorized`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// 取不到对端凭据（非 unix conn / Getsockopt 失败）—— `helper-linux/helper.go:339`。
    #[error("peercred")]
    Peercred,
    /// uid 不在授权列表 —— `helper-linux/helper.go:355`。
    #[error("unauthorized")]
    Unauthorized,
}

impl AuthError {
    /// 对应的 wire 错误码 token（逐字对照 Go 源 `ERR peercred` / `ERR unauthorized`）。
    #[must_use]
    pub const fn wire_token(self) -> &'static str {
        match self {
            Self::Peercred => "peercred",
            Self::Unauthorized => "unauthorized",
        }
    }
}

/// 静态凭据桩（测试用：注入伪造 uid/gid 验证授权逻辑，不碰真实 socket）。
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub struct StaticPeerCred {
    cred: PeerCred,
}

#[cfg(test)]
impl StaticPeerCred {
    #[must_use]
    pub const fn new(uid: u32, gid: u32) -> Self {
        Self {
            cred: PeerCred { uid, gid },
        }
    }
}

#[cfg(test)]
impl PeerCredProvider for StaticPeerCred {
    fn peer_cred(&self) -> Option<PeerCred> {
        Some(self.cred)
    }
}

/// 取不到凭据的桩（模拟 SO_PEERCRED 失败分支，验证 `ERR peercred` 路径）。
#[cfg(test)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NoPeerCred;

#[cfg(test)]
impl PeerCredProvider for NoPeerCred {
    fn peer_cred(&self) -> Option<PeerCred> {
        None
    }
}

/// tokio::net::UnixStream 的 SO_PEERCRED 实现（生产用）。
#[derive(Debug, Clone)]
pub struct TokioPeerCred<'a> {
    stream: &'a tokio::net::UnixStream,
}

impl<'a> TokioPeerCred<'a> {
    #[must_use]
    pub const fn new(stream: &'a tokio::net::UnixStream) -> Self {
        Self { stream }
    }
}

impl PeerCredProvider for TokioPeerCred<'_> {
    fn peer_cred(&self) -> Option<PeerCred> {
        // tokio::net::UnixStream::peer_cred() 内部走 SO_PEERCRED（Linux）/ getpeereid（macOS）。
        // 返回 tokio::net::unix::UCred —— 内核背书，不可伪造。
        self.stream.peer_cred().ok().map(|c| PeerCred {
            uid: c.uid(),
            gid: c.gid(),
        })
    }
}

/// 已捕获的对端凭据（生产 accept 循环用）。
///
/// 生产连接处理器在 accept 时先从 tokio `UnixStream` 取 SO_PEERCRED（[`TokioPeerCred`]），再把 async 流
/// 转 std 阻塞流交给同步 [`handle`](crate::platform::linux::handle)。转换后原 stream 已被消费，无法再取凭据，
/// 故把凭据**捕获**进本类型随 `handle` 下发。`None` = 取凭据失败（非 unix conn / getsockopt 失败）→
/// `handle` 走 `ERR peercred` 分支（与 Go `peerCred(conn)` 失败一致）。
#[derive(Debug, Clone, Copy)]
pub struct CapturedPeerCred(pub Option<PeerCred>);

impl PeerCredProvider for CapturedPeerCred {
    fn peer_cred(&self) -> Option<PeerCred> {
        self.0
    }
}

// ===== 授权 uid 列表（移植自 Go isAuthorized）=====

/// authfile 元数据不可信的原因（拒绝时写日志：说清**谁的文件 / 什么权限 / 期望什么**）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthFileDistrust {
    /// 属主非 root：该属主可任意改写授权 uid 列表 → 把自己（或任何人）写进去即得 root helper 服务。
    #[error(
        "authfile owner uid={owner_uid} (mode {mode:04o}); expected owner root (uid=0), mode 0600 or stricter"
    )]
    NotRootOwned {
        /// 实际属主 uid。
        owner_uid: u32,
        /// 实际权限位（已剥掉文件类型位）。
        mode: u32,
    },
    /// 权限含 group/other 位：组内/全体成员可读该授权列表，可写则可直接改判定结果。
    #[error(
        "authfile mode {mode:04o} (owner uid={owner_uid}) grants group/other access; expected mode 0600 or stricter (mode & 0o077 == 0)"
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
const PERMISSION_BITS: u32 = 0o7777;
/// group + other 的 rwx 位。authfile 上任一位置位即不可信（0600 或更严才作数）。
///
/// 🔴 **本判据与 provisioning 侧是同一份跨侧契约的两半，禁止单侧改**：写侧在
/// `crates/helper-client/src/manager.rs` 的 `build_linux_install_script` —— `(umask 077; touch …)`
/// 子壳让 `/var/lib/polaris/authorized-uids` 出生即 0600（不依赖继承来的 umask，无宽权限瞬窗），
/// 随后的 `chmod 0600` 负责收紧老版本装出来的既存宽权限文件；repair 复用同一份脚本。
/// 脚本侧形态由 helper-client manager 测试
/// `linux_install_script_chmods_authfile_0600_matching_helper_auth_contract` 钉住。
///
/// 历史缺陷：脚本侧曾是 `touch` + `chmod 0644`，正落在本常量的拒绝分支上 —— 读侧硬化后，
/// 装完 helper 对文件里**任何非 root uid 恒判 unauthorized**，整条 Linux SO_PEERCRED 授权腿
/// 装完即不可用。故：动这里的 `0o077`（无论放宽还是收紧）必须同步看脚本侧，改脚本侧的 authfile
/// 权限也必须回看这里 —— 单侧改动即破契约。
const GROUP_OTHER_BITS: u32 = 0o077;

/// 判定 uid 是否被 authfile 授权 —— **纯逻辑判据，不碰文件系统**。
///
/// 入参就是生产腿从**同一个 fd** 取到的三元组：属主 uid / `st_mode`（完整或仅权限位皆可）/ 文件全文。
/// 判据由本函数持有，[`is_authorized`] 只负责取数 —— 于是「非 root 属主拒绝」「group/other 可读拒绝」
/// 「root+0600 通过」在**非特权测试环境里也能逐条钉住**（真造一份 root-owned 文件是做不到的）。
///
/// 顺序：先验属主、再验权限（任一不过 → `Err`，一律不授权），最后才逐行匹配 uid。
/// root(0) 的恒授权短路**不在这里** —— root 不依赖 authfile 存在性，取数之前就已返回（见 [`is_authorized`]）。
///
/// 返回 `Ok(true)` = 授权；`Ok(false)` = 文件可信但 uid 不在列表；`Err` = 文件本身不可信。
pub fn authorize_uid(
    uid: u32,
    owner_uid: u32,
    mode: u32,
    contents: &str,
) -> Result<bool, AuthFileDistrust> {
    let mode = mode & PERMISSION_BITS;
    // 属主非 root ⇒ 内容由非特权方掌握，读它等于让对方自己批自己。
    if owner_uid != 0 {
        return Err(AuthFileDistrust::NotRootOwned { owner_uid, mode });
    }
    // group/other 任一位 ⇒ root 之外还有人能看/能改这份授权列表。
    if mode & GROUP_OTHER_BITS != 0 {
        return Err(AuthFileDistrust::GroupOrOtherAccessible { owner_uid, mode });
    }
    Ok(contents
        .lines()
        .any(|line| parse_uid_line(line) == Some(uid)))
}

/// 打开 authfile 并从**同一个 fd** 取 (属主 uid, `st_mode`, 全文)。
///
/// 与 [`owned_by`] 同一条 TOCTOU 纪律：`fstat(fd)` 而非 `stat(path)`，且元数据与随后读出的字节来自
/// **同一个已打开的 inode** —— 不给「校验通过后把路径换成攻击者的文件」（symlink swap / rename）留缝。
fn read_auth_file(path: &Path) -> std::io::Result<(u32, u32, String)> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    let mut f = std::fs::File::open(path)?;
    let meta = f.metadata()?;
    let (owner_uid, mode) = (meta.uid(), meta.mode());
    let mut contents = String::new();
    f.read_to_string(&mut contents)?;
    Ok((owner_uid, mode, contents))
}

/// 判定 uid 是否在授权列表。root(0) 恒授权（`helper-linux/helper.go:97-99`）。
///
/// authfile 每行一个十进制 uid；缺失/读取失败时非 root 一律未授权（失败安全，:101）。
/// 空行与非法行静默跳过（:104-113）。
///
/// **本函数只做取数**：打开文件 → 同 fd 取属主/权限/内容 → 交 [`authorize_uid`] 判定。文件不可信时
/// 拒绝授权并把原因写 stderr（helper 是 systemd 服务，stderr 进 journal，与 `daemon.rs` 的失败播报同路）。
#[must_use]
pub fn is_authorized(uid: u32, auth_file: &Path) -> bool {
    // root 恒授权（Go: if uid == 0 { return true }）—— 不读文件，故不依赖 authfile 存在性。
    if uid == 0 {
        return true;
    }
    let Ok((owner_uid, mode, contents)) = read_auth_file(auth_file) else {
        // 缺文件 / 打不开 / 非 UTF-8 → 非 root 失败安全（Go: err != nil → return false）。
        return false;
    };
    match authorize_uid(uid, owner_uid, mode, &contents) {
        Ok(authorized) => authorized,
        Err(distrust) => {
            eprintln!(
                "polaris-helper (linux): refusing authfile {}: {distrust}",
                auth_file.display()
            );
            false
        }
    }
}

/// 解析单行为 uid；空行/非法行返回 None（对照 Go TrimSpace + Atoi + >=0 校验）。
fn parse_uid_line(line: &str) -> Option<u32> {
    let t = line.trim();
    if t.is_empty() {
        return None;
    }
    // 仅接受纯非负十进制（Go: strconv.Atoi + n >= 0；负号已被 parse 拒绝）。
    let n: u32 = t.parse().ok()?;
    Some(n)
}

/// 校验路径属主 == uid（移植自 Go `ownedBy`，:117-133）。
///
/// 用 `open` + `fstat`（而非 `stat(path)`）防 TOCTOU：`stat(path)` 校验通过后、拉核 execve 读 config 前，
/// 攻击者把 path 换成别人的文件（symlink swap / rename）→ helper 会以对端 uid 拉核读到本不属于它的配置。
/// `File::open` 拿到 fd 后 `fstat` 该 **fd**（非 path），校验的属主与后续被读的是同一 inode，杜绝换靶。
/// `File::open` 默认跟随 symlink 到目标（与 Go `os.Open` 一致）。
///
/// 返回 `Ok(true)` = 属主匹配；`Ok(false)` = 属主不匹配；`Err` = open/fstat 失败（路径不存在等）。
pub fn owned_by(path: &Path, uid: u32) -> Result<bool, std::io::Error> {
    use std::os::unix::fs::MetadataExt;
    // Go: f, err := os.Open(path); ...; fi, err := f.Stat()（对 *os.File 的 Stat = fstat(fd)）。
    let f = std::fs::File::open(path)?;
    // File::metadata() 走 fstat(fd)（非 stat(path)）—— TOCTOU 关键：校验对象 == 后续被读的 inode。
    let meta = f.metadata()?;
    Ok(meta.uid() == uid)
}

/// 登录用户 `uid` 的补充组 gid 列表（移植自 Go `supplementaryGroups`，:135-155）。
///
/// setuid 拉核时随 [`SpawnCoreRequest`](crate::platform::linux::state::SpawnCoreRequest) 下发给 `setgroups`：
/// 否则降权后默认 `setgroups(0)` 清空补充组，核读不到 group-only 资源（ssl-cert 组证书 / 组共享规则文件等），
/// 而 app 直起路径（保留补充组）能读，造成 mode-specific 破坏。
///
/// 经 `nix::unistd::User::from_uid`（getpwuid_r）取登录名 + 主组，再 `getgrouplist` 取全部所属组
/// （Go `user.LookupId(uid).GroupIds()` 的 `user::*` 等价）。查不到 → 空 Vec（Go 返回 nil：退化为
/// `setgroups(&[])` 清空，不比修前差）。**在 fork 前于父进程解析**（结果进 request）—— 拉核子进程的
/// `pre_exec` 只做 syscall、不碰 NSS/分配，降低 fork-child async-signal-safety 风险。
///
/// **合理差异（Go oracle 对照）**：Go 注释注明 CGO 关时 `GroupIds()` 纯解析 `/etc/group`（不含 NSS/SSSD）；
/// 本实现 `getgrouplist` 走 libc NSS。是**跨编译约束**（Go 的 CGO-off）非安全要求，NSS 解析对 LDAP/SSSD
/// 部署更正确（严于原版，非缺陷）；语义（返回用户所属全部组）一致。
#[must_use]
pub fn supplementary_groups(uid: u32) -> Vec<u32> {
    // Go: u, err := user.LookupId(uid); if err != nil { return nil }
    let Ok(Some(user)) = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)) else {
        return Vec::new();
    };
    // getgrouplist 需 &CStr 登录名；含 NUL（真实用户名不可能）→ 退化空。
    let Ok(name) = std::ffi::CString::new(user.name) else {
        return Vec::new();
    };
    // Go: gidStrs, err := u.GroupIds(); if err != nil { return nil }
    match nix::unistd::getgrouplist(&name, user.gid) {
        Ok(gids) => gids.into_iter().map(nix::unistd::Gid::as_raw).collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests;
