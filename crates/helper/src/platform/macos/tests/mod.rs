use super::*;

/// **字面量锚点**（与 `platform::windows::mod.rs` 的同名测对称）。
///
/// 缺了它 mac 侧对本常量零覆盖：`handler.rs:562/578/588` 与 `server.rs:983/1008` 的断言两侧都从
/// `PROTO_VERSION` 派生 ⇒ 全是恒真式，把本常量改回 上游的 9，151 条 macOS 用例无一转红。
/// Linux 有 `linux/handler.rs` 的 `wire_forms_match_protocol` 钉死当前 protocol、
/// Windows 有 `windows/mod.rs` 对称断言，唯独 mac 没有 —— 补上，三平台覆盖对称。
///
/// 版本字面量由 helper-proto 单测锁定；这里仅锁定 mac 未形成独立谱系。
#[test]
fn proto_version_is_unified_current() {
    assert_eq!(PROTO_VERSION, polaris_helper_proto::proto_version::CURRENT);
    assert_eq!(PROTO_VERSION, 1);
}
