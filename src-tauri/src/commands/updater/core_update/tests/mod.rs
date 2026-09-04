//! 内核腿下载闸的门：闸值取法（纯函数）+ 两条下载腿的接线（源码扫描）。
//!
//! **零网络**：真实资产体积以 checked-in 常量入夹具，不在测试里发任何请求。

use super::{core_update_size_limit, CORE_UPDATE_MAX_BYTES};
use crate::commands::guard_scan::top_level_fn_body;
use crate::runtime::http::MAX_DOWNLOAD_BYTES;
use crate::test_support::module_code;

/// sing-box **官方 release 资产的真实字节数**（v1.14.0，`gh api
/// repos/SagerNet/sing-box/releases/latest` 实测于 2026-09-04），覆盖
/// [`find_suitable_singbox_asset`](polaris_updater::github::find_suitable_singbox_asset)
/// 在三平台上选得中的全部形态，外加**整个 release 里最小的**那个桌面归档。
///
/// # 为什么必须是真数字，不能编
///
/// 这道门唯一的意义就是「拿真实世界的体积对一次」：闸值合不合适，只有跟上游今天实际发出来的
/// 包比过才知道。编一个 1000 字节的夹具能让任何闸值都绿 —— 包括那个把在线换核整条打死的
/// 16 MiB。全仓此前没有任何一处做过这次比对，于是 P0 一直藏在「`bundledCoreVersion` 恰好
/// 等于官方最新 ⇒ 压根不提供更新」后面。
///
/// 数字会随上游发版变旧：变旧只会让它**更保守**（新版只会更大），不会让门变松。
const REAL_SINGBOX_ASSETS: [(&str, u64); 5] = [
    ("sing-box-1.14.0-linux-amd64.tar.gz", 31_639_897),
    ("sing-box-1.14.0-windows-amd64.zip", 32_809_391),
    ("sing-box-1.14.0-darwin-arm64.tar.gz", 29_123_654),
    ("sing-box-1.14.0-darwin-amd64.tar.gz", 31_432_770),
    // 整个 release 里**最小**的桌面归档：连它都过不去，就没有任何平台过得去。
    (
        "sing-box-1.14.0-darwin-amd64-legacy-macos-10.13.tar.gz",
        26_335_501,
    ),
];

/// 🔴 **正面 + 真实夹具**：今天上游真发出来的每一个资产，派生出的闸都必须容得下。
///
/// 顺带把 P0 的成因钉死：同一批体积在通用内存闸（16 MiB）下**无一**过得去 —— 那不是
/// 「余量偏紧」，是在线换核结构性不可能成功。
#[test]
fn core_download_gate_admits_every_real_singbox_asset() {
    for (name, size) in REAL_SINGBOX_ASSETS {
        let want = usize::try_from(size).expect("64 位宿主（见 app_update.rs 的绊线）");
        assert!(
            core_update_size_limit(Some(size)) >= want,
            "{name} 声明 {size} B，派生出的闸只有 {} B —— Content-Length 预检会当场拒掉它",
            core_update_size_limit(Some(size))
        );
        assert!(
            CORE_UPDATE_MAX_BYTES >= size,
            "{name}（{size} B）已经顶穿绝对上限 {CORE_UPDATE_MAX_BYTES} B —— \
             上限该跟着上游体积抬，而不是让每次换核都栽在预检上"
        );
        assert!(
            size > MAX_DOWNLOAD_BYTES as u64,
            "{name} 只有 {size} B、竟然塞得进 16 MiB 的通用内存闸 —— \
             这批夹具已经不是真实资产体积了，本门失去判据"
        );
    }
}

/// 🔴 **正面**：声明值缺失 / 为 0 ⇒ 闸等于上限。**不是 0，也不是那个 16 MiB 的通用默认。**
///
/// `fileSize` 为 0 不等于「包是空的」：`GithubAsset::size` 是 `#[serde(default)]`，GitHub 少给
/// 字段就填 0。直接拿它当闸 ⇒ 任何包都过不去，且失败长得像「下载超限」。
#[test]
fn core_download_gate_falls_back_to_the_ceiling_when_the_declared_size_is_absent_or_zero() {
    let ceiling = usize::try_from(CORE_UPDATE_MAX_BYTES).expect("64 位宿主");
    assert_eq!(
        core_update_size_limit(None),
        ceiling,
        "缺声明值必须回落上限"
    );
    assert_eq!(
        core_update_size_limit(Some(0)),
        ceiling,
        "声明 0 是「字段缺失」的同义词，不是「包是空的」——拿它当闸等于把闸关死"
    );
    // 正面：回落值得真的装得下今天的包，否则「回落」只是换一种方式拒绝所有更新。
    for (name, size) in REAL_SINGBOX_ASSETS {
        assert!(
            core_update_size_limit(None) >= usize::try_from(size).expect("64 位宿主"),
            "回落到的上限装不下 {name}（{size} B）"
        );
    }
    assert!(
        ceiling > MAX_DOWNLOAD_BYTES,
        "回落值退回到了通用内存闸（16 MiB）—— 那正是本批要修掉的那个闸"
    );
}

/// 🔴 **反向对照**：声明值是**服务端给的数**，闸不能由它单方面顶到任意高。
///
/// 没有这一条，「闸 = 声明值」就等于没有闸：一个报 2 GiB / 100 GiB 的 `fileSize` 会让
/// Content-Length 预检形同不设，整包一路读进堆里。
///
/// 末尾那格是**这道门报得出「过大」而不是一律放行**的证明：正常声明值必须原样透传，
/// 上限不得把所有输入都夹成同一个数。
#[test]
fn core_download_gate_caps_a_lying_declared_size() {
    let ceiling = usize::try_from(CORE_UPDATE_MAX_BYTES).expect("64 位宿主");
    assert_eq!(
        core_update_size_limit(Some(2 * 1024 * 1024 * 1024)),
        ceiling,
        "声明 2 GiB 必须被上限压住"
    );
    assert_eq!(
        core_update_size_limit(Some(u64::MAX)),
        ceiling,
        "声明 u64::MAX 必须被上限压住（且不得回绕成一个小值）"
    );
    assert_eq!(
        core_update_size_limit(Some(CORE_UPDATE_MAX_BYTES)),
        ceiling,
        "恰好等于上限不该被多夹一次"
    );
    let (name, normal) = REAL_SINGBOX_ASSETS[0];
    assert_eq!(
        core_update_size_limit(Some(normal)),
        usize::try_from(normal).expect("64 位宿主"),
        "{name} 这种正常声明值必须原样生效 —— 一律返回上限的实现同样能过前三格，\
         那种闸只剩「别把堆撑爆」、不再对服务端的声明值收紧半分"
    );
}

/// 🔴 **源码级**：`fileSize` 出得来、两条内核腿都用派生闸、都不再传通用内存闸。
///
/// 三段缺一不可：check 腿不吐 `fileSize` ⇒ 两条下载腿的声明值恒为 `None`、闸恒取上限，
/// 派生函数本身再对也没有输入；下载腿改回 [`MAX_DOWNLOAD_BYTES`] ⇒ P0 原样复发。
///
/// **回放历史缺陷**：把任一 `core_update_size_limit(declared_size)` 改回
/// `MAX_DOWNLOAD_BYTES` ⇒ 本条转红（正面锚点消失 + 负面禁词命中，两侧同时报）。
#[test]
fn core_download_gate_is_wired_into_both_core_legs() {
    let updater = module_code("commands/updater");

    let check = top_level_fn_body(&updater, "pub(super) async fn core_update_check_inner(");
    assert!(
        check.contains("\"fileSize\": asset.size"),
        "check 腿不回报资产体积 —— 两条下载腿只能恒取上限，闸对服务端声明值完全失聪"
    );

    let manual = top_level_fn_body(&updater, "pub async fn core_update_run(");
    assert!(
        manual.contains("core_update_size_limit(declared_size)"),
        "手点换核腿没用派生闸"
    );
    assert!(
        !manual.contains("MAX_DOWNLOAD_BYTES"),
        "手点换核腿又传回了 16 MiB 的通用内存闸 —— 官方资产全部 26 MiB 以上，必被预检早拒"
    );

    let scheduler = module_code("runtime/core_update_scheduler");

    let decide = top_level_fn_body(&scheduler, "pub fn decide_cycle(");
    assert!(
        decide.contains("\"fileSize\""),
        "决策层丢掉了体积声明 ⇒ 自动腿的闸恒取上限，与手点腿的闸就此分叉"
    );

    // 自动腿是**顶层**函数（不是 impl 方法），故用 `top_level_fn_body`；它自己带列 0 自检。
    let auto = top_level_fn_body(&scheduler, "async fn run_download_and_stage(");
    assert!(
        auto.contains("core_update_size_limit(declared_size)"),
        "自动换核腿没用派生闸"
    );
    assert!(
        !auto.contains("MAX_DOWNLOAD_BYTES"),
        "自动换核腿又传回了 16 MiB 的通用内存闸"
    );
}
