//! `set_read_timeout` 覆写门（D13 登记项）。
//!
//! # 守的是什么
//!
//! `ConnectionStream::set_read_timeout`（transport.rs）带 **no-op 默认实现**——那是给
//! `MockStream` / `IoAdapter` 这类本身没有 OS 超时语义的流准备的。生产流（Unix socket /
//! Windows 命名管道）一旦**没有覆写**它，编译照过、全部行为测试照绿，而运行期退回 fail-open：
//! [`HelperClient::send_with_timeout`](crate::client::HelperClient::send_with_timeout) 每次读前
//! 下发的「单请求预算剩余量」被 no-op 吞掉，实际读预算硬顶建连默认
//! [`READ_TIMEOUT`](crate::transport::READ_TIMEOUT)（5s）——
//! install-core（30s）/ linux-resolved（45s）/ start（15s）三个预算全部不可达，
//! helper 侧仍会把动作做完 ⇒「app 报失败、系统状态已改」的分叉（复审 2026-08-31 High，
//! `connector.rs:83`）。
//!
//! # 为什么是源码级门
//!
//! 这个缺陷类在本机没有运行期观察面：`cfg(windows)` 腿不编译；Unix 腿要真 socket 且对端
//! 恰好拖过 5s 才暴露。「覆写还在」是纯源码事实，源码级门是唯一常绿守法。
//!
//! # 取材与判据
//!
//! 取材走净化面（[`polaris_source_probe::mask_comments_and_strings`]：注释与字符串抹空）——
//! 注释里的 `fn set_read_timeout` 不得给肯定型断言充数。判据：两个生产文件里**每个**
//! `impl ConnectionStream for <Type>` 块（花括号配平切块）都必须含 `fn set_read_timeout`。
//! **fail-closed**：取材面切不出任何 impl 块（trait 改名 / 文件搬家 / 锚点漂移）即红，
//! 不会静默退化成「扫了个空集、断言恒真」。
//!
//! **变异有牙**（2026-08-31 实测，收据见批 B 报告）：删掉 `connector.rs` 里
//! `UnixConnStream` 的 `fn set_read_timeout` 覆写 —— 编译照过（默认实现顶上），本门转红。

/// 净化面里逐个切出 `impl ConnectionStream for <Type>` 块（从块首 `{` 花括号配平到闭合）。
///
/// 净化面里花括号不会出现在字符串/注释里，配平计数可靠。
fn connection_stream_impl_blocks(masked: &str) -> Vec<String> {
    const HEAD: &str = "impl ConnectionStream for ";
    let mut blocks = Vec::new();
    let mut from = 0usize;
    while let Some(offset) = masked[from..].find(HEAD) {
        let at = from + offset;
        let open = masked[at..]
            .find('{')
            .map(|o| at + o)
            .expect("impl 头之后必须有块首 `{`");
        let mut depth = 0usize;
        let mut end = None;
        for (i, c) in masked[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let end = end.expect("impl 块花括号不配平——取材面坏了");
        blocks.push(masked[at..=end].to_string());
        from = end;
    }
    blocks
}

#[test]
fn every_production_connection_stream_impl_overrides_set_read_timeout() {
    let faces = [
        (
            "connector.rs",
            polaris_source_probe::crate_source!("connector.rs"),
            // 取材自检锚点：确认拿到的是这个文件，不是搬家后的同名邻居。
            "struct UnixConnStream",
        ),
        (
            "windows_pipe.rs",
            polaris_source_probe::crate_source!("windows_pipe.rs"),
            "struct WinPipeStream",
        ),
    ];
    for (file, raw, anchor) in faces {
        assert!(raw.contains(anchor), "{file}：取材面错位，缺锚点 {anchor}");
        let masked = polaris_source_probe::mask_comments_and_strings(&raw);
        let blocks = connection_stream_impl_blocks(&masked);
        // fail-closed：一个 impl 块都切不出来 = 判据失去对象，必须红，不许静默恒真。
        assert!(
            !blocks.is_empty(),
            "{file}：切不出任何 `impl ConnectionStream for` 块——trait 改名或生产流搬家了，\
             本门失去判据"
        );
        for block in &blocks {
            assert!(
                block.contains("fn set_read_timeout"),
                "{file}：有生产 `impl ConnectionStream` 块没有覆写 `fn set_read_timeout`——\
                 trait 的 no-op 默认实现会吞掉调用方下发的单请求预算，读超时 fail-open 回 5s 硬顶\
                 （install-core 30s / linux-resolved 45s / start 15s 全部不可达）：\n{block}"
            );
        }
    }
}
