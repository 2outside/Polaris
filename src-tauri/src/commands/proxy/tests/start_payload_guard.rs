use crate::commands::guard_scan::top_level_fn_body;
use crate::test_support::crate_code;

/// **起核配置必须由后端读盘**（接线守卫，锚点失配自带 panic）。
///
/// 缺陷原形：签名收 `config: Value`，渲染端传 `app-store.config` —— 一份只靠
/// `event:configChanged` → `loadConfig(true)` 异步刷新的内存副本。而 `start_inner` 从不读盘，
/// 逐字用调用方给的那份 ⇒ 「写盘 → 立刻点启动」用的是**写之前**的配置（连带
/// `attest_selected_exit` 从盘读 `selectedServerId` 而生成用陈旧值 → 可撞 `EXIT_MISMATCH`）。
///
/// 本守卫钉两件事：① 命令体内真的向 `state.config()` 取值 —— **只断言取值来源，不锁具体方法**
/// （`current()` 与 `load_full()` 都是合法的「读盘」，锁死其中一个会让另一种写法误红）；
/// ② 签名里**不得**再出现 `config: Value`。
///
/// ②「重新加回参数」这个变异形态其实**编译器已经先拦下了**（内部调用点不再传第三个实参 ⇒
/// E0061）—— 实跑确认过。故 ② 真正独立覆盖的是「加回参数**并且**把各调用点重新接上」那种
/// 能编译的退化；留着它是因为那种退化恰恰会静默恢复本缺陷。
///
/// 射程边界：**只管命令层**。[`ProxyRuntime::start`] 的 `Value` 参数是刻意保留的 ——
/// `commands/updater::swap_core_with_restart` 要在停核**之前**钉住配置（「停完再读若失败
/// 就没法把用户的代理恢复回去」），起核失败腿的单测也要注入压根无法落盘的配置
/// （`bad_config()` 是非对象 JSON）。把读盘下沉进 `start_inner` 会同时砸掉这两者。
///
/// 端到端那一半（真点一次启动、核真拿到新配置）需要真核，列为真机确认项，不在此假装覆盖。
///
/// D14：原覆盖 `proxy_start`/`proxy_restart` 两个签名；`proxy_restart`（死 IPC command，D12 已删
/// 前端调用点）已退役，现只钉 `proxy_start`。
#[test]
fn start_reads_the_config_from_disk_not_from_the_caller() {
    let src = crate_code("commands/proxy.rs");
    let sig = "pub async fn proxy_start(";
    let body = top_level_fn_body(&src, sig);
    assert!(
        body.contains("state.config()"),
        "{sig} 必须自己向 state.config() 取起核配置 —— 信调用方传的那份就是本缺陷"
    );
    assert!(
        !body.contains("config: Value"),
        "{sig} 不得再收 `config: Value` 参数：留着它，渲染端的陈旧副本就还能被喂进来"
    );
}
