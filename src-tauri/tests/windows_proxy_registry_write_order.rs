//! Windows 原生系统代理 writer 的 Linux-host 源码级强门。
//!
//! `windows_proxy_registry` 在 Linux 不参与运行期编译，因此普通单测无法防止原生写序与
//! `reg.exe` 回退分叉。本门使用 `polaris-source-probe` 的等长净化面精确截取 writer impl 及
//! `write` 方法，只在该射程内锁定 Server → Override → Enable 的三步顺序。

fn unique_braced_scope<'a>(source: &'a str, anchor: &str) -> &'a str {
    let masked = polaris_source_probe::mask_comments_and_strings(source);
    let hits = masked.match_indices(anchor).collect::<Vec<_>>();
    assert_eq!(
        hits.len(),
        1,
        "源码门锚点必须唯一：{anchor:?}，实际命中={}",
        hits.len()
    );
    let anchor_start = hits[0].0;
    let open = masked[anchor_start..]
        .find('{')
        .map(|offset| anchor_start + offset)
        .unwrap_or_else(|| panic!("锚点后找不到开始大括号：{anchor:?}"));

    let mut depth = 0usize;
    for (offset, byte) in masked.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1).expect("大括号深度不得下溢");
                if depth == 0 {
                    return &source[anchor_start..=open + offset];
                }
            }
            _ => {}
        }
    }
    panic!("锚点的大括号作用域未闭合：{anchor:?}");
}

/// 在剔除注释和字符串的真实语法面上唯一定位一条调用，再回到 raw 源码的同一
/// byte range 逐字校验完整调用表达式。这样注释/字符串里的同形串无法为生产调用充数，
/// 键名字面量本身也不能漂移。
fn exact_call_offset(raw: &str, syntax: &str, expected: &str) -> usize {
    let expected_syntax = polaris_source_probe::mask_comments_and_strings(expected);
    let hits = syntax.match_indices(&expected_syntax).collect::<Vec<_>>();
    assert_eq!(
        hits.len(),
        1,
        "writer::write 真实语法面上的调用必须唯一：{expected:?}，实际命中={}",
        hits.len()
    );
    let offset = hits[0].0;
    let end = offset + expected.len();
    assert_eq!(
        raw.get(offset..end),
        Some(expected),
        "语法面定位到调用后，raw 同区间必须逐字匹配完整调用（含注册表键字面量）"
    );
    offset
}

#[test]
fn native_windows_proxy_writer_keeps_enable_as_the_last_write() {
    let source = polaris_source_probe::crate_source!("runtime/windows_proxy_registry.rs");
    let writer_impl = unique_braced_scope(
        &source,
        "impl WindowsProxyRegistryWriter for WindowsNativeProxyRegistryWriter",
    );
    let write = unique_braced_scope(writer_impl, "fn write(");
    let syntax = polaris_source_probe::mask_comments_and_strings(write);

    assert_eq!(
        syntax.matches("set_string(key.0").count(),
        2,
        "writer::write 真实语法面必须只有 Server/Override 两条 REG_SZ 写"
    );
    assert_eq!(
        syntax.matches("set_dword(key.0").count(),
        1,
        "writer::write 真实语法面必须只有 Enable 一条 DWORD 写"
    );

    let server = exact_call_offset(
        write,
        &syntax,
        r#"set_string(key.0, "ProxyServer", &values.proxy_server)"#,
    );
    let override_value = exact_call_offset(
        write,
        &syntax,
        r#"set_string(key.0, "ProxyOverride", &values.proxy_override)"#,
    );
    let enable = exact_call_offset(
        write,
        &syntax,
        r#"set_dword(key.0, "ProxyEnable", values.proxy_enable)"#,
    );
    assert!(
        server < override_value && override_value < enable,
        "原生 writer 必须先写完两个配置值，再以 ProxyEnable 作为最后生效门"
    );
}
