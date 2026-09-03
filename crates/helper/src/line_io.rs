//! 行协议 IO 原语（mac/linux helper 共用）。
//!
//! ## 为何合并
//!
//! Polaris helper 用 line-based 文本协议（Go `bufio.Reader.ReadString('\n')`，每行以 `\n` 结尾）。
//! 读方向原本两份：`helper-mac/src/server.rs` 的 `read_line`（`Option<String>`，EOF→None）与
//! `helper-linux/src/handler.rs` 的 `LineConn::read_line`（`String`，EOF→""）。二者都泛型于
//! `std::io::{Read, Write}`、trim 同一字符集（`\r`/`\n`）、EOF 判定同一条件 —— **是假差异**
//! （只是返回值形状不同），故读逻辑上提至此单一真值，各 crate 只留自己的返回形状适配。
//!
//! ## win 为何不用本模块
//!
//! win helper 走裸 Win32 `HANDLE` 的**整帧读**（命名管道，一次 `ReadFile` 取整个请求帧再切行），
//! 不经 `std::io::BufRead` —— 是**真平台差异**，不强行归一。

use std::io::{BufRead, Write};

/// 有界行读取结果。`TooLong` 在消费第 `limit + 1` 个字节时立即返回，绝不继续扫描尾部。
#[derive(Debug)]
pub enum BoundedLineError {
    Io(std::io::Error),
    TooLong { limit: usize },
}

/// 有界读取一行并 trim 尾部 `\r\n`。
///
/// 与 [`BufRead::read_line`] 不同，本函数逐块查看缓冲区且至多保留 `limit` 字节，因而攻击者
/// 不能靠一个永不换行的 socket 帧让 root helper 无界扩容。超限时只消费到第 `limit + 1` 字节，
/// 尾部仍留给 reader；这是调用方可观测、可测试的硬停止点。
pub fn read_line_trimmed_bounded<R: BufRead>(
    buf: &mut R,
    limit: usize,
) -> Result<Option<String>, BoundedLineError> {
    let mut line = Vec::with_capacity(limit.min(8 * 1024));
    loop {
        let available = buf.fill_buf().map_err(BoundedLineError::Io)?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            break;
        }

        let newline = available.iter().position(|byte| *byte == b'\n');
        let available_before_newline = newline.unwrap_or(available.len());
        let remaining = limit.saturating_sub(line.len());
        if available_before_newline > remaining {
            let consume = remaining + 1;
            buf.consume(consume);
            return Err(BoundedLineError::TooLong { limit });
        }

        line.extend_from_slice(&available[..available_before_newline]);
        let consumed = available_before_newline + usize::from(newline.is_some());
        buf.consume(consumed);
        if newline.is_some() {
            break;
        }
    }

    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line).map(Some).map_err(|error| {
        BoundedLineError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
    })
}

/// 读一行并 trim 尾部 `\r\n`（移植自 Go `readLine`，`helper/helper.go:92-95`）。
///
/// - `None` = EOF 或读失败（含读超时）—— 调用方据此判「连接关闭/无数据」。
/// - `Some(s)` = 一行内容，已剥尾部 `\r`/`\n`（Go: `strings.TrimRight(s, "\r\n")`）。
///   空行（仅 `\n`）返回 `Some("")`，与 EOF 的 `None` **可区分**（Go 源同样区分：
///   EOF 时 `ReadString` 带 err，空行不带）。
///
/// 需要「EOF 与空行都当空串」的调用方（linux `Conn::read_line` 的契约）用
/// `read_line_trimmed(..).unwrap_or_default()`。
#[must_use]
pub fn read_line_trimmed<R: BufRead>(buf: &mut R) -> Option<String> {
    let mut line = String::new();
    match buf.read_line(&mut line) {
        // Ok(0) = EOF；Err = 读失败/超时。二者对调用方等价（无更多行可读）。
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim_end_matches(['\r', '\n']).to_owned()),
    }
}

/// 写一行（自动补 `\n`）并 flush —— 对齐 Go `fmt.Fprintln(conn, ...)`。
///
/// flush 对裸 socket（`UnixStream`）是 no-op，对缓冲 writer 是必需 —— 统一 flush 保证
/// 「响应写完即可读」，不依赖调用方传的 writer 是否带缓冲。
pub fn write_line<W: Write>(w: &mut W, line: &str) -> std::io::Result<()> {
    w.write_all(line.as_bytes())?;
    w.write_all(b"\n")?;
    w.flush()
}

#[cfg(test)]
mod tests;
