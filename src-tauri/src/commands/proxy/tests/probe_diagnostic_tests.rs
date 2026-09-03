use super::super::*;

/// 真机：`decode config at`「cannot unmarshal」类，最深的一条（4 级键路径 + 长 go 消息）。
/// 命令：对 `{"outbounds":[{"type":"vless",...,"tls":{"utls":{"fingerprint":123}}},{"direct"}]}`
/// 跑 `sing-box check`。
#[test]
fn decode_cannot_unmarshal_extracts_nested_keypath() {
    let raw = "\x1b[31mFATAL\x1b[0m[0000] decode config at /tmp/psb/a.json: \
                    outbounds[0].tls.utls.fingerprint: json: cannot unmarshal number into Go \
                    struct field OutboundUTLSOptions.OutboundTLSOptionsContainer.tls.utls.fingerprint \
                    of type string\n";
    let diag = parse_probe_diagnostic(raw);
    assert_eq!(
        diag.path.as_deref(),
        Some("outbounds[0].tls.utls.fingerprint")
    );
    assert_eq!(
        diag.message,
        "json: cannot unmarshal number into Go struct field \
             OutboundUTLSOptions.OutboundTLSOptionsContainer.tls.utls.fingerprint of type string"
    );
    // raw 兜底：ANSI 已剥离（不含 `\x1b`），但文件路径 / FATAL 标签原样保留（全貌兜底）。
    assert!(!diag.raw.contains('\u{1b}'), "raw 不得残留 ANSI 转义字节");
    assert!(diag.raw.contains("FATAL[0000] decode config at"));
}

/// 真机：`decode config at`「unknown field」类（keypath 落在字段名本身，不再往下嵌套）。
#[test]
fn decode_unknown_field_extracts_keypath() {
    let raw = "\x1b[31mFATAL\x1b[0m[0000] decode config at /tmp/psb/b.json: \
                    outbounds[0].bogus_field: json: unknown field \"bogus_field\"\n";
    let diag = parse_probe_diagnostic(raw);
    assert_eq!(diag.path.as_deref(), Some("outbounds[0].bogus_field"));
    assert_eq!(diag.message, "json: unknown field \"bogus_field\"");
}

/// 真机：`dns.servers[0].server_port` —— 验证 keypath 判据在**顶层非 outbounds 的**路径
/// （dns 而非 outbounds/endpoints）上同样成立，不是针对 outbounds 专写的特判。
#[test]
fn decode_cannot_unmarshal_under_dns_path() {
    let raw = "\x1b[31mFATAL\x1b[0m[0000] decode config at /tmp/psb/c.json: \
                    dns.servers[0].server_port: json: cannot unmarshal string into Go struct \
                    field RemoteDNSServerOptions.DNSServerAddressOptions.server_port of type \
                    uint16\n";
    let diag = parse_probe_diagnostic(raw);
    assert_eq!(diag.path.as_deref(), Some("dns.servers[0].server_port"));
    assert!(diag.message.starts_with("json: cannot unmarshal string"));
}

/// 真机：`initialize` 类（语义校验期，非 decode）——单层 keypath `outbound[0]`，message 是
/// go 侧一整句人话，不含更多冒号可切。命令：reality 开启但缺 uTLS 必需项。
#[test]
fn initialize_class_extracts_coarse_keypath() {
    let raw = "\x1b[31mFATAL\x1b[0m[0000] initialize outbound[0]: uTLS is required by \
                    reality client\n";
    let diag = parse_probe_diagnostic(raw);
    assert_eq!(diag.path.as_deref(), Some("outbound[0]"));
    assert_eq!(diag.message, "uTLS is required by reality client");
}

/// 真机：`initialize` 类嵌套阶段（`initialize router: parse rule-set[0]: open …`）。
/// 只切一层——`path="router"`（粗粒度），`parse rule-set[0]: open …` 整段留在 message，
/// 不强行再切一次（第二段 `parse rule-set[0]` 带空格，`looks_like_keypath` 本就会挡住）。
/// 命令：`route.rule_set` 指向不存在的本地 `.srs` 文件。
#[test]
fn initialize_class_nested_stage_keeps_coarse_granularity() {
    let raw = "FATAL[0000] initialize router: parse rule-set[0]: open \
                    /nonexistent/rs1.srs: no such file or directory";
    let diag = parse_probe_diagnostic(raw);
    assert_eq!(diag.path.as_deref(), Some("router"));
    assert_eq!(
        diag.message,
        "parse rule-set[0]: open /nonexistent/rs1.srs: no such file or directory"
    );
}

/// 真机：`duplicate outbound/endpoint tag: dup` —— decode 类里「冒号+空格切出来的候选其实不是
/// keypath」的假阳性防线。若没有 `looks_like_keypath` 判据，朴素两刀切会把
/// `path="duplicate outbound/endpoint tag"`、`message="dup"` 错误地拆出来（`dup` 单独看没有
/// 任何诊断价值）。命令：两个 outbound 撞了同一个 tag。
#[test]
fn decode_class_message_with_colon_is_not_misparsed_as_keypath() {
    let raw = "FATAL[0000] decode config at /tmp/psb/e.json: duplicate outbound/endpoint \
                    tag: dup";
    let diag = parse_probe_diagnostic(raw);
    assert_eq!(
        diag.path, None,
        "「duplicate ... tag」带空格/斜杠，不是键路径"
    );
    assert_eq!(
        diag.message, "duplicate outbound/endpoint tag: dup",
        "整段原样回落，不腰斩"
    );
}

/// 真机：纯 JSON 语法错误（decode 类但压根没有 keypath 可言，候选串带空格/引号）。
/// 命令：config 文件内容不是合法 JSON（`{ this is not json`）。
#[test]
fn decode_class_json_syntax_error_has_no_keypath() {
    let raw = "FATAL[0000] decode config at /tmp/psb/f.json: invalid character 't' \
                    looking for beginning of object key string: row 1, column 3";
    let diag = parse_probe_diagnostic(raw);
    assert_eq!(diag.path, None);
    // message 保留完整句子，含末尾 "row 1, column 3"（没有被第二次误切掉）。
    assert_eq!(
        diag.message,
        "invalid character 't' looking for beginning of object key string: row 1, column 3"
    );
}

/// 构造：Windows 盘符路径（`C:\Users\...`）——冒号后紧跟反斜杠，不是空格，故不会被
/// `split_once(": ")` 误当成「文件路径与后续内容」的分隔符。真机验证过等价场景（Linux 下
/// 目录名本身含冒号 `weird:dir/`，输出为 `decode config at .../weird:dir/t12.json:
/// outbounds[0].bogus_field: json: unknown field "bogus_field"`，切分结果与本用例同构）——
/// 本机不能跑 `sing-box.exe` 才退而按已验证的分隔符规律构造，非拍脑袋编。
#[test]
fn decode_class_file_path_with_windows_drive_colon_does_not_break_split() {
    let raw = r#"FATAL[0000] decode config at C:\Users\sway\AppData\Local\Temp\probe-1.json: outbounds[0].bogus_field: json: unknown field "bogus_field""#;
    let diag = parse_probe_diagnostic(raw);
    assert_eq!(
        diag.path.as_deref(),
        Some("outbounds[0].bogus_field"),
        "盘符冒号不得被误判为 keypath 分隔边界"
    );
    assert_eq!(diag.message, "json: unknown field \"bogus_field\"");
}

/// 完全不认识的行（既非 decode 也非 initialize 前缀）：`path` 必须是 `None`，`message` 必须是
/// **整行原文**（不裁剪、不猜测键路径）——这是「吃不下就如实回落」的字面验证。
#[test]
fn unrecognized_line_falls_back_to_raw_with_no_fabricated_path() {
    let raw = "some future sing-box error format nobody has seen yet: whatever happened here";
    let diag = parse_probe_diagnostic(raw);
    assert_eq!(diag.path, None);
    assert_eq!(diag.message, raw, "陌生格式必须原样回落，不得编造结构");
}

/// 多行输出：取**最后一条非空行**（见 [`parse_probe_diagnostic`] 文档「多行输出取哪一条」）。
/// 构造场景：真机 6 组坏 config 均只吐一行，故用手工拼的多行样本覆盖「防未来加前置 WARN 噪声」
/// 这条防御性选择——首行是无关噪声，真正的 FATAL 诊断在最后一行，且首尾都不能是空行干扰。
#[test]
fn multiline_output_picks_the_last_non_empty_line() {
    let raw = "\nWARN[0000] some deprecated option, ignoring\n\
                    FATAL[0000] initialize outbound[0]: uTLS is required by reality client\n\n";
    let diag = parse_probe_diagnostic(raw);
    assert_eq!(diag.path.as_deref(), Some("outbound[0]"));
    assert_eq!(diag.message, "uTLS is required by reality client");
    // raw 兜底保留全部行（含被跳过的 WARN 噪声），不是只留被选中的那一行。
    assert!(
        diag.raw.contains("WARN[0000]"),
        "raw 兜底须留存完整多行原文"
    );
}

/// 双流全空的病态腿（check 非零退出但 stdout/stderr 都没写东西）：回落既有文案 "check failed"，
/// 不 panic、不产生空字符串消息。
#[test]
fn empty_output_falls_back_to_check_failed() {
    let diag = parse_probe_diagnostic("   \n  \n");
    assert_eq!(diag.path, None);
    assert_eq!(diag.message, "check failed");
    assert_eq!(diag.raw, "");
}

// ── looks_like_keypath 判据本体 ──────────────────────────────────────────────────

#[test]
fn looks_like_keypath_accepts_dotted_segments_with_optional_index() {
    assert!(looks_like_keypath("outbounds[0].tls.utls.fingerprint"));
    assert!(looks_like_keypath("outbounds[0].bogus_field"));
    assert!(looks_like_keypath("dns.servers[0].server_port"));
    assert!(looks_like_keypath("outbound[0]"));
    assert!(looks_like_keypath("router")); // initialize 类的单段粗粒度路径。
}

#[test]
fn looks_like_keypath_rejects_prose_and_malformed_indices() {
    assert!(!looks_like_keypath(""));
    assert!(
        !looks_like_keypath("duplicate outbound/endpoint tag"),
        "带空格带斜杠"
    );
    assert!(
        !looks_like_keypath("invalid character 't' looking for beginning of object key string"),
        "带空格带引号"
    );
    assert!(!looks_like_keypath("outbounds[]"), "空下标");
    assert!(!looks_like_keypath("outbounds[abc]"), "下标非数字");
    assert!(!looks_like_keypath("0utbound"), "首字符是数字");
    assert!(!looks_like_keypath("a..b"), "空分节");
}

// ── strip_ansi ────────────────────────────────────────────────────────────────

/// 真机字节级验证：`strip_ansi` 后不得残留 `\x1b`，且非转义内容（含方括号日志级别标签
/// `[0000]`，它不是转义序列，不能被连带吃掉）逐字保留。
#[test]
fn strip_ansi_removes_real_sing_box_color_codes_verbatim() {
    let raw = "\x1b[31mFATAL\x1b[0m[0000] decode config at /tmp/x.json: a.b: msg";
    let cleaned = strip_ansi(raw);
    assert_eq!(
        cleaned,
        "FATAL[0000] decode config at /tmp/x.json: a.b: msg"
    );
    assert!(!cleaned.contains('\u{1b}'));
}

#[test]
fn strip_ansi_is_noop_on_plain_text() {
    let raw = "no escapes here at all";
    assert_eq!(strip_ansi(raw), raw);
}
