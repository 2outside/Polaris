//! Linux 系统代理（GNOME gsettings）：命令构造 + 输出解析。

use super::model::ProxyEnableRequest;
use crate::exec::Command;
use crate::proxy::{LinuxGSettingsSnapshot, SystemProxyStatus};
use polaris_config_engine::user_config::system_proxy_bypass::format_bypass_for_linux;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxGSettingsValueKind {
    String,
    Port,
    Boolean,
    StringArray,
    Mode,
}

/// Linux exact proxy transaction 的唯一九键表。顺序同时约束 capture、apply 与 restore；`mode`
/// 必须最后写，避免前八键尚未完整时 GNOME 已开始使用半套 manual 配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LinuxGSettingsKey {
    pub(crate) schema: &'static str,
    pub(crate) key: &'static str,
    kind: LinuxGSettingsValueKind,
}

pub(crate) const LINUX_GSETTINGS_KEYS: [LinuxGSettingsKey; 9] = [
    LinuxGSettingsKey {
        schema: "org.gnome.system.proxy.http",
        key: "host",
        kind: LinuxGSettingsValueKind::String,
    },
    LinuxGSettingsKey {
        schema: "org.gnome.system.proxy.http",
        key: "port",
        kind: LinuxGSettingsValueKind::Port,
    },
    LinuxGSettingsKey {
        schema: "org.gnome.system.proxy.http",
        key: "enabled",
        kind: LinuxGSettingsValueKind::Boolean,
    },
    LinuxGSettingsKey {
        schema: "org.gnome.system.proxy.https",
        key: "host",
        kind: LinuxGSettingsValueKind::String,
    },
    LinuxGSettingsKey {
        schema: "org.gnome.system.proxy.https",
        key: "port",
        kind: LinuxGSettingsValueKind::Port,
    },
    LinuxGSettingsKey {
        schema: "org.gnome.system.proxy.socks",
        key: "host",
        kind: LinuxGSettingsValueKind::String,
    },
    LinuxGSettingsKey {
        schema: "org.gnome.system.proxy.socks",
        key: "port",
        kind: LinuxGSettingsValueKind::Port,
    },
    LinuxGSettingsKey {
        schema: "org.gnome.system.proxy",
        key: "ignore-hosts",
        kind: LinuxGSettingsValueKind::StringArray,
    },
    LinuxGSettingsKey {
        schema: "org.gnome.system.proxy",
        key: "mode",
        kind: LinuxGSettingsValueKind::Mode,
    },
];

// ── Linux 读取命令构造 + gsettings 输出解析（Polaris LinuxSystemProxy.getProxyStatus）──

/// Linux 读 gsettings 某 schema 某 key。
pub fn linux_gsettings_get_command(schema: &str, key: &str) -> Command {
    Command::new(
        "gsettings",
        ["get", &format!("org.gnome.system.proxy.{schema}"), key],
    )
}

/// 解析 `gsettings get ...proxy.<schema> host` 输出 → host（空 → None）。
/// gsettings 字符串是 canonical GVariant literal；必须解码转义，不能直接删掉所有单引号。
pub fn parse_gsettings_host(stdout: &str) -> Option<String> {
    parse_gsettings_string(stdout).filter(|host| !host.trim().is_empty())
}

pub(crate) fn parse_gsettings_string(stdout: &str) -> Option<String> {
    parse_gvariant_string(stdout)
}

/// 解析 `gsettings get ...proxy.<schema> port` 输出 → 端口串。
///
/// 当前 GNOME schema 的 port 类型为 `i`，canonical 输出是裸十进制（如 `8080`）。兼容解析器仍剥
/// 历史 `uint16`/`uint32` 前缀；V2 exact validator 只接受当前 schema 可回写的裸十进制。
pub fn parse_gsettings_port(stdout: &str) -> String {
    let s = stdout.trim();
    // 剥 `uint32 ` / `uint16 ` 等前缀（上游正则 `/^uint\d+\s+/i`）。
    let stripped = s
        .strip_prefix("uint")
        .and_then(|rest| {
            let digits_end = rest.find(|c: char| !c.is_ascii_digit())?;
            if digits_end == 0 {
                return None; // `uint` 后无数字 → 非该前缀
            }
            let after = &rest[digits_end..];
            after.starts_with(char::is_whitespace).then(|| after.trim())
        })
        .unwrap_or(s);
    stripped.to_string()
}

/// Linux 读全局代理 `mode`（`gsettings get org.gnome.system.proxy mode`）。
///
/// `get_proxy_status` 与活态查询都先读 mode；mode≠manual 时 GNOME 不下发静态代理，即使 host/port
/// 留有 dormant 值也必须报告 disabled。exact carrier 仍保留这些 dormant raw。
pub fn linux_gsettings_mode_get_command() -> Command {
    Command::new("gsettings", ["get", "org.gnome.system.proxy", "mode"])
}

/// 解析 `gsettings get org.gnome.system.proxy mode` 输出 → 模式串（`manual` / `none` / `auto`）。
/// gsettings 返回带单引号（`'manual'`）→ 剥引号 + trim（与 [`parse_gsettings_host`] 同口径，
/// 但本函数**不**把空串折成 None：空 mode 就是「读不出模式」，由调用方判为非 manual）。
pub fn parse_gsettings_mode(stdout: &str) -> String {
    parse_gsettings_string(stdout).unwrap_or_default()
}

// ── Linux 命令构造（Polaris LinuxSystemProxy）──

/// 把 Rust 字符串编码成 canonical GVariant string literal。
pub(crate) fn encode_gvariant_string(value: &str) -> Result<String, String> {
    if value.contains('\0') {
        return Err("GVariant string cannot contain NUL".into());
    }
    // GVariant print uses double quotes when the value contains an apostrophe; otherwise it uses
    // single quotes. Exact transaction snapshots must match that output byte-for-byte so an
    // applied value is not later misclassified as foreign merely because gsettings re-quoted it.
    let quote = if value.contains('\'') { '"' } else { '\'' };
    let mut encoded = String::with_capacity(value.len() + 2);
    encoded.push(quote);
    for character in value.chars() {
        match character {
            '\\' => encoded.push_str("\\\\"),
            '\'' if quote == '\'' => encoded.push_str("\\'"),
            '"' if quote == '"' => encoded.push_str("\\\""),
            '\n' => encoded.push_str("\\n"),
            '\r' => encoded.push_str("\\r"),
            '\t' => encoded.push_str("\\t"),
            '\u{0008}' => encoded.push_str("\\b"),
            '\u{000c}' => encoded.push_str("\\f"),
            character if character.is_control() => {
                use std::fmt::Write;
                if u32::from(character) <= 0xffff {
                    let _ = write!(encoded, "\\u{:04x}", u32::from(character));
                } else {
                    let _ = write!(encoded, "\\U{:08x}", u32::from(character));
                }
            }
            character => encoded.push(character),
        }
    }
    encoded.push(quote);
    Ok(encoded)
}

/// 由 enable 请求生成 `gsettings get` 将返回的 canonical raw，而不是旧 set argv 的输入形态。
pub(crate) fn linux_applied_snapshot(
    req: &ProxyEnableRequest,
) -> Result<LinuxGSettingsSnapshot, String> {
    let hosts = format_bypass_for_linux(&req.bypass_list);
    let ignore_hosts = if hosts.is_empty() {
        "@as []".to_string()
    } else {
        let encoded = hosts
            .iter()
            .map(|host| encode_gvariant_string(host))
            .collect::<Result<Vec<_>, _>>()?;
        format!("[{}]", encoded.join(", "))
    };
    Ok(LinuxGSettingsSnapshot {
        http_host: encode_gvariant_string(&req.address)?,
        http_port: req.http_port.to_string(),
        http_enabled: "true".into(),
        https_host: encode_gvariant_string(&req.address)?,
        https_port: req.http_port.to_string(),
        socks_host: encode_gvariant_string(&req.address)?,
        socks_port: req.socks_port.to_string(),
        ignore_hosts,
        mode: "'manual'".into(),
    })
}

/// exact 九键向旧 marker 的有损静态投影。旧格式无法表达 mode/`http.enabled`/raw
/// GVariant；这里只投影可解析的非零 host:port，供 downgrade binary best-effort 恢复。
pub(crate) fn linux_snapshot_projection(snapshot: &LinuxGSettingsSnapshot) -> SystemProxyStatus {
    let host_port = |host_raw: &str, port_raw: &str| {
        let host = parse_gsettings_string(host_raw)?;
        let port = port_raw.parse::<u16>().ok().filter(|port| *port != 0)?;
        (!host.is_empty()).then(|| format!("{host}:{port}"))
    };
    let http_proxy = host_port(&snapshot.http_host, &snapshot.http_port);
    let https_proxy = host_port(&snapshot.https_host, &snapshot.https_port);
    let socks_proxy = host_port(&snapshot.socks_host, &snapshot.socks_port);
    SystemProxyStatus {
        enabled: parse_gsettings_string(&snapshot.mode).as_deref() == Some("manual")
            && (http_proxy.is_some() || https_proxy.is_some() || socks_proxy.is_some()),
        http_proxy,
        https_proxy,
        socks_proxy,
        bypass_domains: None,
    }
}

/// exact restore 命令；任一 raw 与键类型不符即整体拒绝，不把损坏 marker 下发给 gsettings。
pub(crate) fn linux_exact_restore_commands(
    snapshot: &LinuxGSettingsSnapshot,
) -> Result<Vec<Command>, String> {
    validate_linux_gsettings_snapshot(snapshot)?;
    Ok(LINUX_GSETTINGS_KEYS
        .iter()
        .zip(snapshot.raw_values())
        .map(|(entry, raw)| Command::new("gsettings", ["set", entry.schema, entry.key, raw]))
        .collect())
}

/// Linux gsettings enable argv。apply 与 exact restore 共用九键验证/构造，且 mode 最后。
pub fn linux_enable_commands(req: &ProxyEnableRequest) -> Result<Vec<Command>, String> {
    linux_exact_restore_commands(&linux_applied_snapshot(req)?)
}

pub(crate) fn validate_linux_gsettings_snapshot(
    snapshot: &LinuxGSettingsSnapshot,
) -> Result<(), String> {
    for (entry, raw) in LINUX_GSETTINGS_KEYS.iter().zip(snapshot.raw_values()) {
        let valid = match entry.kind {
            LinuxGSettingsValueKind::String => decode_canonical_gvariant_string(raw).is_some(),
            LinuxGSettingsValueKind::Port => valid_gsettings_port(raw),
            LinuxGSettingsValueKind::Boolean => matches!(raw, "true" | "false"),
            LinuxGSettingsValueKind::StringArray => valid_gvariant_string_array(raw),
            LinuxGSettingsValueKind::Mode => decode_canonical_gvariant_string(raw)
                .is_some_and(|mode| matches!(mode.as_str(), "none" | "manual" | "auto")),
        };
        if !valid {
            return Err(format!(
                "invalid GVariant raw for {} {}",
                entry.schema, entry.key
            ));
        }
    }
    Ok(())
}

fn valid_gsettings_port(raw: &str) -> bool {
    raw.parse::<u32>()
        .is_ok_and(|port| port <= u32::from(u16::MAX) && port.to_string() == raw)
}

fn valid_gvariant_string_array(raw: &str) -> bool {
    if raw == "@as []" {
        return true;
    }
    let Some(mut rest) = raw.strip_prefix('[') else {
        return false;
    };
    let Some(without_end) = rest.strip_suffix(']') else {
        return false;
    };
    rest = without_end.trim();
    if rest.is_empty() {
        return false;
    }
    let mut decoded = Vec::new();
    loop {
        let Some((value, consumed)) = parse_gvariant_string_prefix(rest) else {
            return false;
        };
        decoded.push(value);
        rest = rest[consumed..].trim_start();
        if rest.is_empty() {
            break;
        }
        let Some(after_comma) = rest.strip_prefix(',') else {
            return false;
        };
        rest = after_comma.trim_start();
        if rest.is_empty() {
            return false;
        }
    }
    let Ok(encoded) = decoded
        .iter()
        .map(|value| encode_gvariant_string(value))
        .collect::<Result<Vec<_>, _>>()
    else {
        return false;
    };
    format!("[{}]", encoded.join(", ")) == raw
}

fn decode_canonical_gvariant_string(raw: &str) -> Option<String> {
    let (decoded, consumed) = parse_gvariant_string_prefix(raw)?;
    if consumed != raw.len() || encode_gvariant_string(&decoded).ok()?.as_str() != raw {
        return None;
    }
    Some(decoded)
}

fn parse_gvariant_string(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let (decoded, consumed) = parse_gvariant_string_prefix(raw)?;
    (consumed == raw.len()).then_some(decoded)
}

fn parse_gvariant_string_prefix(raw: &str) -> Option<(String, usize)> {
    let quote = raw.chars().next()?;
    if !matches!(quote, '\'' | '"') {
        return None;
    }
    let mut decoded = String::new();
    let mut chars = raw[quote.len_utf8()..].char_indices();
    while let Some((offset, character)) = chars.next() {
        if character == quote {
            return Some((decoded, quote.len_utf8() + offset + character.len_utf8()));
        }
        if character != '\\' {
            if character.is_control() {
                return None;
            }
            decoded.push(character);
            continue;
        }
        let (_, escaped) = chars.next()?;
        match escaped {
            '\\' => decoded.push('\\'),
            '\'' => decoded.push('\''),
            '"' => decoded.push('"'),
            'n' => decoded.push('\n'),
            'r' => decoded.push('\r'),
            't' => decoded.push('\t'),
            'b' => decoded.push('\u{0008}'),
            'f' => decoded.push('\u{000c}'),
            'u' | 'U' => {
                let digits = if escaped == 'u' { 4 } else { 8 };
                let mut value = 0_u32;
                for _ in 0..digits {
                    let (_, digit) = chars.next()?;
                    value = value.checked_mul(16)?.checked_add(digit.to_digit(16)?)?;
                }
                let decoded_character = char::from_u32(value)?;
                if decoded_character == '\0' {
                    return None;
                }
                decoded.push(decoded_character);
            }
            _ => return None,
        }
    }
    None
}

/// Linux 简单禁用（无原始可恢复时）：mode none。
/// 上游 `LinuxSystemProxy.disableProxy` else 分支。
pub fn linux_disable_command() -> Command {
    Command {
        program: "gsettings".into(),
        args: vec![
            "set".into(),
            "org.gnome.system.proxy".into(),
            "mode".into(),
            "none".into(),
        ],
    }
}

/// Linux 恢复单 schema 的 argv 序列（set：host+port[+enabled]；clear：host=''[+enabled false]）。
/// 上游 `LinuxSystemProxy.restoreOriginalProxyAsync` / `disableProxySync` gset 块。
pub fn linux_restore_schema_commands(entry: &crate::proxy::RestorePlanEntry) -> Vec<Command> {
    let base = format!("org.gnome.system.proxy.{}", entry.schema);
    match &entry.hp {
        Some(hp) => {
            let mut cmds = vec![
                Command {
                    program: "gsettings".into(),
                    args: vec!["set".into(), base.clone(), "host".into(), hp.host.clone()],
                },
                Command {
                    program: "gsettings".into(),
                    args: vec![
                        "set".into(),
                        base.clone(),
                        "port".into(),
                        hp.port.to_string(),
                    ],
                },
            ];
            // 仅 http schema 有 enabled 键。
            if entry.schema == "http" {
                cmds.push(Command {
                    program: "gsettings".into(),
                    args: vec!["set".into(), base, "enabled".into(), "true".into()],
                });
            }
            cmds
        }
        None => {
            let mut cmds = vec![Command {
                program: "gsettings".into(),
                args: vec!["set".into(), base.clone(), "host".into(), String::new()],
            }];
            if entry.schema == "http" {
                cmds.push(Command {
                    program: "gsettings".into(),
                    args: vec!["set".into(), base, "enabled".into(), "false".into()],
                });
            }
            cmds
        }
    }
}

/// Linux 恢复前先置 mode manual（若有任一 schema 有值）。
pub fn linux_set_mode_manual_command() -> Command {
    Command {
        program: "gsettings".into(),
        args: vec![
            "set".into(),
            "org.gnome.system.proxy".into(),
            "mode".into(),
            "manual".into(),
        ],
    }
}
