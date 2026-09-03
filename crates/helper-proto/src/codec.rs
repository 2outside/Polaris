//! 帧编解码 + 安全约束（移植自 Polaris Go helper 的 line framing 与白名单校验）。
//!
//! ## 帧结构（逐平台对照）
//!
//! Polaris helper 用 **line-based 文本协议**（Go `bufio.Reader.ReadString('\n')`，每行以 `\n` 结尾）。
//! 三平台的帧差异**仅在首行**：
//! - mac/win：行1 = `<token>`（鉴权），行2 = `<command>`，行3.. = 参数行。
//! - linux：行1 = `<command>`（无 token 行，鉴权经 SO_PEERCRED 在 socket 层完成）。
//!
//! 本模块按 [`Platform`] 决定是否在头部加 token 行，让上层 [`Request`] 与鉴权机制解耦。
//!
//! ## 安全约束（逐行移植 Go 源的白名单函数）
//!
//! - [`is_valid_cidr`]：移植自 Go `net.ParseCIDR`（防 route-add/del 参数注入）。
//! - [`is_mac_iface_allowed`]：移植自 `helper.go:255-272`（polaris-ts/polaris-wg/utunN）。
//! - [`is_win_iface_allowed`]：移植自 `helper-win/helper.go:50-60`（polaris-* 前缀）。
//!
//! 这些校验在 helper 侧与（可选的）client 侧**都跑** —— 双侧一致校验是纵深防御（client 早失败省一轮 RTT，
//! helper 侧是权威边界，绝不依赖 client）。

use std::net::{IpAddr, Ipv4Addr};

use crate::{Platform, Request};

/// 单帧最大字节数（防御恶意客户端发超长行耗尽内存；Go `bufio.Reader` 默认无上限，本协议加保守护栏）。
///
/// 选 512KB：通常请求仍远小于 64KB；macOS 系统代理恢复事务需要携带完整的逐服务
/// Proxies plist（hex 后体积翻倍），上限留足多网卡与较长 bypass/PAC 配置，同时继续阻止无界读取。
pub const MAX_FRAME_BYTES: usize = 512 * 1024;

/// 单连接读超时（秒）—— 移植自 Go `conn.SetReadDeadline(time.Now().Add(5 * time.Second))`
///（`helper.go:401` / `helper-win/helper.go:165` / `helper-linux/helper.go:335`）。
///
/// 防止无 token 进程连上后不发数据耗尽 fd/goroutine，或持 token 客户端发一半卡死、在 mu.Lock() 之后阻塞读
/// → 永久持锁拖垮整个 helper。
pub const READ_TIMEOUT_SECS: u64 = 5;

/// 把一个 [`Request`] 编码为完整帧的行序列（每行不含 `\n`，由调用方 IO 层统一加 `\n`）。
///
/// 返回的 Vec 即将写入 socket/pipe 的全部行：
/// - mac/win：`[token, command, arg1, arg2, ...]`
/// - linux：`[command, arg1, arg2, ...]`（无 token 行）
///
/// `token` 在 linux 下被忽略（传 `""` 即可）。
#[must_use]
pub fn encode_frame(platform: Platform, token: &str, req: &Request) -> Vec<String> {
    let mut lines = Vec::new();
    // mac/win：行1 = token（Go handle() 首个 readLine；linux 经 SO_PEERCRED 鉴权，无此行）
    if platform != Platform::Linux {
        lines.push(token.to_owned());
    }
    // 命令行
    lines.push(req.command_name().to_owned());
    // 参数行（命令特定）
    req.write_args(&mut lines);
    lines
}

/// 把帧行序列拼接为单字节串（每行尾加 `\n`），用于直接 write 到 socket/pipe。
///
/// 调用方负责控制写超时（本函数纯内存拼装，不阻塞）。
#[must_use]
pub fn frame_to_bytes(lines: &[String]) -> Vec<u8> {
    let mut out = Vec::with_capacity(lines.iter().map(|l| l.len() + 1).sum());
    for l in lines {
        out.extend_from_slice(l.as_bytes());
        out.push(b'\n');
    }
    out
}

/// 便利：一步编码为字节串（`encode_frame` + `frame_to_bytes`）。
#[must_use]
pub fn encode(platform: Platform, token: &str, req: &Request) -> Vec<u8> {
    frame_to_bytes(&encode_frame(platform, token, req))
}

// ===== 安全约束（逐行移植 Go 源白名单函数）=====

/// 校验 IPv4/IPv6 CIDR（移植自 Go `net.ParseCIDR`，`helper.go:470` / `helper-win/helper.go:231`）。
///
/// 非法 CIDR 在 Go 源里被**静默跳过**（`continue`）—— 本函数返回 false 等价语义，helper/client 侧据此过滤。
/// 接受 `a.b.c.d/N`（N ∈ 0..=32）与 `::/N`（N ∈ 0..=128）两族。
///
/// CIDR 的 `/` 前缀由本函数剥离，**地址本体交 stdlib [`IpAddr`] 的 `FromStr`**：`IpAddr::from_str`
/// 不吃 CIDR 形式，故前缀须先剥 —— 但剥完之后地址解析是 stdlib 已完全覆盖的功能，无需手写。
/// stdlib 另内置前导零拒绝（CVE-2021-29922 那类八进制歧义加固）与单 `::` 约束，严于原手写版。
#[must_use]
pub fn is_valid_cidr(s: &str) -> bool {
    let Some((addr, prefix)) = s.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => prefix <= 32,
        Ok(IpAddr::V6(_)) => prefix <= 128,
        Err(_) => false,
    }
}

/// 校验 IPv4 地址（移植自 Go `net.ParseIP(gw).To4() != nil`，`helper.go:486`）。
///
/// stdlib [`Ipv4Addr`] 的 `FromStr` 只认点分十进制 `a.b.c.d`（拒前导零/八进制），语义即 Go 的
/// `ParseIP(...).To4() != nil`（IPv6 串在此返回 false）。
#[must_use]
pub fn is_valid_ipv4(s: &str) -> bool {
    s.parse::<Ipv4Addr>().is_ok()
}

/// macOS 接口白名单（移植自 `helper.go:255-272` 的 `ifaceAllowed`）。
///
/// 仅允许 `polaris-ts` / `polaris-wg` / `utunN`（N 为 1-3 位数字）。杜绝任意接口名注入 route 命令。
#[must_use]
pub fn is_mac_iface_allowed(s: &str) -> bool {
    if s == "polaris-ts" || s == "polaris-wg" {
        return true;
    }
    let Some(rest) = s.strip_prefix("utun") else {
        return false;
    };
    // rest 须为 1-3 位纯数字（Go: `rest == "" || len(rest) > 3` → false）
    !rest.is_empty() && rest.len() <= 3 && rest.bytes().all(|b| b.is_ascii_digit())
}

/// Windows 接口白名单（移植自 `helper-win/helper.go:50-60` 的 `ifaceAllowed`）。
///
/// 仅允许 `polaris-` 前缀 + 小写字母/数字/连字符，长度 ≤ 24。
#[must_use]
pub fn is_win_iface_allowed(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("polaris-") else {
        return false;
    };
    if s.len() > 24 {
        return false;
    }
    rest.bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// 校验 install-core 的 want_hash（移植自 `helper.go:137` 的 `len(wantHash) != 64`）。
///
/// 须为 64 字符的 hex sha256。Go 源用 `strings.EqualFold(hex.EncodeToString(sum[:]), wantHash)` 比对，
/// 即大小写不敏感 —— 本函数同样接受大小写混用。
#[must_use]
pub fn is_valid_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests;
