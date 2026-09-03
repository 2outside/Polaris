mod exit_route_pure_tests;
mod exit_route_wiring_tests;
mod ts_status_cache_tests;
mod warp_drain_tests;
mod warp_tests;

/// A4 登录期出口让位纯谓词门：`mesh_login_fallback_should_engage` 六条件穷举。
///
/// 变异有牙：从「全命中」基线出发，逐一翻转每个入参 → 结果必翻假（覆盖 6 条逃逸路径，防碰巧真数据对）。
mod login_fallback_predicate_tests;
