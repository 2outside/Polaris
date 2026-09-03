//! Unix 特权 helper 的日志对象固定。
//!
//! 这里的 lexical component 处理只用于算出 `conf_dir` 内的相对名字；真正的安全边界是从 `/`
//! 开始逐级 `openat(O_NOFOLLOW)`，再只把已打开的 current/`.1` fd 交给日志 writer。路径在任一时刻
//! 被 rename/symlink 替换，都不会把后续 root 写入重定向到另一个 inode。

#![forbid(unsafe_code)]

use nix::errno::Errno;
use nix::fcntl::{open, openat, OFlag};
use nix::sys::stat::{fstat, Mode, SFlag};
use polaris_log_budget::PreopenedLogFiles;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path};

const DIR_FLAGS: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_DIRECTORY)
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC);
const FILE_FLAGS: OFlag = OFlag::O_RDWR
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC);

/// 从根目录 fd 逐级固定 `conf_dir`，并相对该 fd 打开日志 current/`.1`。
pub(crate) fn preopen_log_files(
    conf_dir: &str,
    log_path: &str,
) -> std::io::Result<PreopenedLogFiles> {
    let conf = normalized_absolute_components(Path::new(conf_dir))?;
    let log = normalized_absolute_components(Path::new(log_path))?;
    let relative = log.strip_prefix(conf.as_slice()).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "log path is outside the configured directory",
        )
    })?;
    let (file_name, relative_parents) = relative.split_last().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "log path must name a file below the configured directory",
        )
    })?;

    let mut parent = open_directory_from_root(&conf)?;
    let conf_stat = nix_io(fstat(&parent))?;
    if conf_stat.st_uid == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "configured directory must belong to the login user",
        ));
    }
    for component in relative_parents {
        parent = nix_io(openat(
            &parent,
            Path::new(component),
            DIR_FLAGS,
            Mode::empty(),
        ))?;
    }

    let current = open_regular_log(&parent, file_name, conf_stat.st_uid, conf_stat.st_gid)?;
    let mut rotated_name = file_name.clone();
    rotated_name.push(".1");
    let rotated = open_regular_log(&parent, &rotated_name, conf_stat.st_uid, conf_stat.st_gid)?;
    Ok(PreopenedLogFiles::new(current, rotated))
}

fn normalized_absolute_components(path: &Path) -> std::io::Result<Vec<OsString>> {
    let mut rooted = false;
    let mut out = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => rooted = true,
            Component::CurDir => {}
            Component::Normal(name) if rooted => out.push(name.to_owned()),
            Component::ParentDir if rooted && out.pop().is_some() => {}
            Component::ParentDir | Component::Normal(_) | Component::Prefix(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "log paths must be absolute and stay below their root",
                ));
            }
        }
    }
    if !rooted {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "log paths must be absolute",
        ));
    }
    Ok(out)
}

fn open_directory_from_root(components: &[OsString]) -> std::io::Result<std::os::fd::OwnedFd> {
    let mut directory = nix_io(open("/", DIR_FLAGS, Mode::empty()))?;
    for component in components {
        directory = nix_io(openat(
            &directory,
            Path::new(component),
            DIR_FLAGS,
            Mode::empty(),
        ))?;
    }
    Ok(directory)
}

fn open_regular_log(
    parent: &impl std::os::fd::AsFd,
    name: &OsStr,
    owner_uid: u32,
    owner_gid: u32,
) -> std::io::Result<File> {
    let fd = open_existing_or_create(parent, name)?;
    let stat = nix_io(fstat(&fd))?;
    let kind = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT;
    if kind != SFlag::S_IFREG || stat.st_nlink != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "log object must be a single-link regular file",
        ));
    }
    // 兼容旧 helper 留下的 root-owned 日志；nlink==1 已排除借 hardlink 修改另一个 root 文件。
    if stat.st_uid != owner_uid && stat.st_uid != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "existing log object has an unexpected owner",
        ));
    }

    let file = File::from(fd);
    std::os::unix::fs::fchown(&file, Some(owner_uid), Some(owner_gid))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

fn open_existing_or_create(
    parent: &impl std::os::fd::AsFd,
    name: &OsStr,
) -> std::io::Result<std::os::fd::OwnedFd> {
    loop {
        match openat(parent, Path::new(name), FILE_FLAGS, Mode::empty()) {
            Ok(fd) => return Ok(fd),
            Err(Errno::ENOENT) => match openat(
                parent,
                Path::new(name),
                FILE_FLAGS | OFlag::O_CREAT | OFlag::O_EXCL,
                Mode::from_bits_truncate(0o600),
            ) {
                Ok(fd) => return Ok(fd),
                Err(Errno::EEXIST) => continue,
                Err(error) => return Err(errno_io(error)),
            },
            Err(error) => return Err(errno_io(error)),
        }
    }
}

fn nix_io<T>(result: nix::Result<T>) -> std::io::Result<T> {
    result.map_err(errno_io)
}

fn errno_io(error: Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error as i32)
}

#[cfg(test)]
mod tests;
