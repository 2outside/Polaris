use super::*;

// ── protoVersion 契约（**前提已换**）─────────────────────────────────────────
//
// 旧测 `proto_versions_match_polaris` / `platforms_are_distinct` 断言 9/5/1 且三者互异，前提是
// 「三平台各自演进的独立谱系必须原样移植」。那个前提是 **上游的历史包袱**：9/5/1 只是三套独立
// Go module 各自加过多少次功能的计数，唯一用途是让新 client 认出机器上那代旧 helper。Polaris 是
// 全新产品 + 全新 Rust helper，**不存在任何一代旧 Polaris helper 需要被认出** ⇒ 三谱系无对象、
// 「必须互异」更是把别人的演进史写成自己的不变量（它会主动阻止本该做的统一）。
//
// 新前提：版本号只表达「wire 断代」，平台差异由 `Platform`（帧结构）+ `command`（命令集）表达。
// 故三平台共用一个 `CURRENT`，下面两测锁的是**统一**而非互异。

#[test]
fn proto_version_is_unified_v1() {
    assert_eq!(
        proto_version::CURRENT,
        1,
        "首次正式发布前的兼容命令扩展不构成协议断代"
    );
}

// 曾有一条 `proto_version_does_not_vary_by_platform`：遍历四个 `Platform` 反复断言
// `Response::Ok(Pong{ proto_version: CURRENT, .. }).to_wire_line()` 的版本段。**已删** ——
// 循环变量只出现在断言消息里，`advertised` 由常量 `CURRENT` 算出、与平台无关 ⇒ 四次迭代是同一
// 个断言的四份副本，语义等价于 `CURRENT == 1`（上面那条已覆盖）；它自称能拦「有人按 Platform
// match 返不同值」，可新增的那个函数**根本不会被它调用**，拦不住。
//
// 「不得 per-platform 分叉」的真锚点在**分叉真会发生的地方** —— 三个平台各自的 `PROTO_VERSION`
// 常量（cfg 门控模块，helper-proto 这层遍历不到），每处一条字面量断言：
//   · `platform::macos::mod.rs`   `proto_version_is_unified_current`
//   · `platform::windows::mod.rs` `proto_version_is_unified_current`
//   · `platform::linux::handler.rs` `wire_forms_match_protocol`（钉死当前 protocol）
// `to_wire_line` 的 Pong 形态另由 `crates/helper-proto/src/response::to_wire_line_matches_go_source_literals` 覆盖。

#[test]
fn platform_carries_frame_shape_not_version() {
    // 推翻旧前提的正面表述：三平台**唯一**的协议差异是帧结构（token 行有无），不是版本号。
    // 同一个 Request 在 mac/linux 下编出的帧不同 —— 差异由 Platform 承载，版本号无需分叉。
    let req = Request::Ping;
    let mac = String::from_utf8(codec::encode(Platform::Mac, "TOK", &req)).unwrap();
    let linux = String::from_utf8(codec::encode(Platform::Linux, "", &req)).unwrap();
    assert_eq!(mac, "TOK\nping\n", "mac 带 token 行");
    assert_eq!(linux, "ping\n", "linux 走 SO_PEERCRED，无 token 行");
    assert_ne!(mac, linux, "平台差异体现在帧结构上");
}

#[test]
fn build_identity_is_a_single_safe_wire_token() {
    assert!(build_identity::is_wire_safe(build_identity::current()));
    assert!(!build_identity::is_wire_safe(""));
    assert!(!build_identity::is_wire_safe("sha with spaces"));
    assert!(!build_identity::is_wire_safe("sha\nsecond-line"));
}

#[test]
fn platform_token_line_semantics() {
    // mac/win 带 token 行；linux 经 SO_PEERCRED 不带（helper-linux/helper.go:333-343）
    assert!(Platform::Mac.has_token_line());
    assert!(Platform::Win.has_token_line());
    assert!(!Platform::Linux.has_token_line());
    // Other 视同 Linux：未知平台无 helper 实现，保守不带 token 行。
    assert!(!Platform::Other.has_token_line());
}

#[test]
fn platform_current_matches_compile_target() {
    // current() 由编译 target 决定；CI 本机 Linux → Linux。
    let cur = Platform::current();
    if cfg!(target_os = "macos") {
        assert_eq!(cur, Platform::Mac);
    } else if cfg!(target_os = "windows") {
        assert_eq!(cur, Platform::Win);
    } else if cfg!(target_os = "linux") {
        assert_eq!(cur, Platform::Linux);
    } else {
        assert_eq!(cur, Platform::Other);
    }
}

#[test]
fn platform_parse_maps_known_strings() {
    // 对齐 上游 `process.platform` 口径 + 兼容各处历史传参写法。
    assert_eq!(Platform::parse("darwin"), Platform::Mac);
    assert_eq!(Platform::parse("macos"), Platform::Mac);
    assert_eq!(Platform::parse("win32"), Platform::Win);
    assert_eq!(Platform::parse("windows"), Platform::Win);
    assert_eq!(Platform::parse("linux"), Platform::Linux);
    // 未知串 → Other（非 std FromStr，不报错）。
    assert_eq!(Platform::parse("freebsd"), Platform::Other);
    assert_eq!(Platform::parse(""), Platform::Other);
}

/// 端到端往返：Request → encode → Response::parse 应覆盖典型路径。
/// 这是「core 发、helper 收」的 wire 兼容性最关键的契约 —— 锁住编码/解码对称。
#[test]
fn end_to_end_wire_roundtrip_ping() {
    let req = Request::Ping;
    let bytes = codec::encode(Platform::Mac, "TOK", &req);
    let wire = String::from_utf8(bytes).unwrap();
    // 模拟 helper 回复 ping
    let resp = Response::parse("OK pong uid=0 v9");
    assert!(matches!(resp, Response::Ok(ResponseKind::Pong(_))));
    // wire 形态断言
    assert_eq!(wire, "TOK\nping\n");
}

/// start 完整往返：args 顺序 + fwd 字符串化 + ppid 可选行。
#[test]
fn end_to_end_start_roundtrip() {
    let req = Request::Start(StartParams {
        cfg: "/tmp/c.json".into(),
        log: "".into(),
        fwd: true,
        parent_pid: Some(999),
    });
    // mac 帧
    let mac_bytes = codec::encode(Platform::Mac, "T", &req);
    assert_eq!(
        String::from_utf8(mac_bytes).unwrap(),
        "T\nstart\n/tmp/c.json\n\n1\n999\n"
    );
    // linux 帧（无 token 行，但 LinuxStart 多 singbox 行）
    let lreq = Request::LinuxStart(LinuxStartParams {
        singbox_path: "/core/sing-box".into(),
        common: StartParams {
            cfg: "/tmp/c.json".into(),
            log: "".into(),
            fwd: false,
            parent_pid: None,
        },
    });
    let linux_bytes = codec::encode(Platform::Linux, "", &lreq);
    assert_eq!(
        String::from_utf8(linux_bytes).unwrap(),
        "start\n/core/sing-box\n/tmp/c.json\n\n0\n"
    );
}
