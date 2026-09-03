use super::*;
use super::{app_update::*, core_update::*};

use std::sync::Arc;

use crate::runtime::core_paths;
use crate::test_support::{crate_code, module_code, repo_file, TestDir};
use polaris_updater::github::{check_app_update, AppUpdateCheck, AssetArch, AssetPlatform};
use polaris_updater::popup::{UpdateErr, UpdateErrCode};
use polaris_updater::state::PopupPhase;
use serde_json::{json, Value};

/// 本模块的**生产源码**（调用点守卫共用）。
///
/// 原先是 `concat!(include_str!("shared.rs"), …)` 手列四个文件——那份清单与
/// `src/commands/updater/` 的真实内容是两份事实：往这个模块里新加一个 `.rs`，下面
/// 二十多条调用点守卫会静默漏掉它（门不报错，只是不再看那个文件）。改成按目录取材后，
/// 新增文件自动进扫描面；`module_source` 排除 `tests/`，所以测试代码不会给生产扫描面充数。
fn src() -> &'static str {
    static SRC: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SRC.get_or_init(|| module_code("commands/updater")).as_str()
}

fn scratch(tag: &str) -> TestDir {
    TestDir::new(&format!("polaris-updater-test-{tag}-"))
}

// ── GitHub releases API 状态码 → 成因 ────────────────────────────────────

/// 🟡 **变异锁：404 = 更新源仓库不可见，且必须仍是错误。**
///
/// 真机成因（2026-07-28 Mac）：`update_check` 恒报「检查更新失败: GitHub API 返回错误: 404」。
/// GitHub 对不存在或当前请求不可见的仓库都以 404 掩盖存在性。裸状态码文案会把这一成因与
/// 「URL 写错 / owner-repo 迁移后仍指向旧地址」混为一谈，因此错误必须保留 owner/repo。
///
/// **变异探针**：删掉 `404 =>` 分支让它落回 `s =>` 兜底 ⇒ 第 2、3 条转红；
/// 把 404 改成返回 `None`（伪装成 2xx ⇒ 前端显示「已是最新」）⇒ 第 1 条 `expect` 转红；
/// 从文案里去掉 `{owner}/{repo}` ⇒ 第 3 条转红。
#[test]
fn github_404_reports_unreachable_repo_not_a_generic_status() {
    let e = github_status_error(404, "2outside", "Polaris")
        .expect("404 必须是错误：更新通道整条不通，绝不能伪装成「无更新 / 已是最新」");
    assert!(e.contains("404"), "状态码要留在文案里供日志比对：{e}");
    assert!(
        e.contains("不存在") && e.contains("私有"),
        "releases **列表**端点上的 404 只意味着仓库不可见（零 release 是 `200 []`），\
             文案必须说准成因而不是甩一个裸状态码：{e}"
    );
    assert!(
        e.contains("2outside/Polaris"),
        "app 腿与 core 腿共用同一个取数函数，不带 owner/repo 的日志分不清是哪条腿挂了：{e}"
    );
}

/// 🟡 **变异锁：2xx 放行 / 403 限流成因保留 / 其余状态码走兜底。**
///
/// 403 与 404 的处置**相反**（前者等一会儿或配加速就好，后者是仓库根本不可见），合并成一条
/// 文案会把用户引去做无用的重试。
///
/// **变异探针**：把 `200..=299` 改窄成 `200` ⇒ 第 2 条转红；删 `403 =>` 分支 ⇒ 第 3 条转红；
/// 把兜底 `s =>` 改成 `None` ⇒ 第 4 条 `expect` 转红。
#[test]
fn github_status_error_truth_table() {
    assert!(github_status_error(200, "o", "r").is_none(), "2xx 放行");
    assert!(
        github_status_error(204, "o", "r").is_none(),
        "放行的是整个 2xx 段（原实现即 `200..300`），不是只有 200"
    );
    let e403 = github_status_error(403, "o", "r").expect("403 必须是错误");
    assert!(
        e403.contains("频率限制"),
        "403 的处置是等/配加速，与 404 的「仓库不可见」不可合并：{e403}"
    );
    let e500 = github_status_error(500, "o", "r").expect("5xx 必须是错误");
    assert!(
        e500.contains("500"),
        "未特殊化的状态码走兜底并保留码值：{e500}"
    );
}

// ── #311：「查看更新日志」直达当前版本 release 页 ──────────────────────────

/// 🟡 **变异锁：有版本号 → 拼 `/releases/tag/v<version>`，且不重复补 `v`。**
///
/// **变异探针**：把 `format!` 里的 `v` 删掉 ⇒ 第 1 条转红；去掉
/// `trim_start_matches('v')` ⇒ 第 2 条转红（拼出 `vv0.1.0`）。
#[test]
fn releases_url_for_version_targets_tag_page() {
    assert_eq!(
        releases_url_for(Some("v0.2.0")),
        "https://github.com/2outside/Polaris/releases/tag/v0.2.0"
    );
    // 调用方将来若改传裸 semver（无 `v`），也不能拼错——两种输入形态幂等。
    assert_eq!(
        releases_url_for(Some("0.2.0")),
        "https://github.com/2outside/Polaris/releases/tag/v0.2.0"
    );
}

/// 🟡 **变异锁：version 为空/仅空白/`None` → 回落泛列表页，绝不拼出可能 404 的链接。**
///
/// **变异探针**：把 `filter(|v| !v.is_empty())` 删掉 ⇒ 第 2、3 条转红
/// （会拼出 `.../tag/v`）。
#[test]
fn releases_url_for_missing_version_falls_back_to_list_page() {
    assert_eq!(
        releases_url_for(None),
        "https://github.com/2outside/Polaris/releases"
    );
    assert_eq!(
        releases_url_for(Some("")),
        "https://github.com/2outside/Polaris/releases"
    );
    assert_eq!(
        releases_url_for(Some("   ")),
        "https://github.com/2outside/Polaris/releases"
    );
}

// ── 「绝不主动断流」硬不变量（H1）─────────────────────────────────────────

/// 🟡 **变异锁：自动路径 + 代理在跑 ⇒ 必须拦下。**
///
/// **变异探针**：把 [`swap_blocked_by_no_interrupt`] 改成恒 false / 只看 `interrupt` /
/// 只看 `was_running` ⇒ 逐条转红。
#[test]
fn no_interrupt_invariant_truth_table() {
    assert!(
        swap_blocked_by_no_interrupt(SwapInterrupt::Forbidden, true),
        "自动路径遇到运行中的代理 → 必须放弃换核（绝不无同意断流）"
    );
    assert!(
        !swap_blocked_by_no_interrupt(SwapInterrupt::Forbidden, false),
        "代理没跑 → 自动路径照常落位（这是唯一的安全窗口，不能一并堵死）"
    );
    assert!(
        !swap_blocked_by_no_interrupt(SwapInterrupt::Allowed, true),
        "用户亲手点的换核 → 允许停/起核，否则「立即应用」永远应用不了"
    );
    assert!(!swap_blocked_by_no_interrupt(SwapInterrupt::Allowed, false));
}

/// 🟡 **调用点守卫：不断流判定必须夹在「读 `was_running`」与「`proxy.stop()`」之间。**
///
/// 判定放在别处（比如只留在调度器里）就会重新撑开 TOCTOU 窗口：从调度器判 `running == false`
/// 到这里真 stop，中间隔着读簿记 + 读几十 MB 暂存核 + sha 复核，用户点一下连接就断流了。
///
/// **变异探针**：删掉 `swap_blocked_by_no_interrupt(` / 把它挪到 `proxy.stop()` 之后 /
/// 在判定与 stop 之间插入一个 `.await` ⇒ 逐条转红。
#[test]
fn no_interrupt_check_precedes_any_proxy_stop() {
    let body =
        crate::commands::guard_scan::top_level_fn_body(src(), "async fn swap_core_with_restart(");
    let read_at = body
        .find("proxy.status().running")
        .expect("锚点消失：守卫已失去判据");
    let gate_at = body
        .find("swap_blocked_by_no_interrupt(")
        .expect("不断流硬不变量的校验被删了 —— 自动换核会在用户未同意时停掉正在跑的代理");
    // 找 `proxy.stop().await`（带 await）而非裸 `proxy.stop()`：后者在本函数的注释里也出现。
    let stop_at = body
        .find("proxy.stop().await")
        .expect("锚点消失：守卫已失去判据");
    assert!(
        read_at < gate_at && gate_at < stop_at,
        "顺序必须是 读 was_running → 判定 → stop（实得 {read_at} / {gate_at} / {stop_at}）"
    );
    // 判定与 stop 之间不得有 await：有的话 `was_running` 就又是一张过期快照了。
    assert!(
        !body[gate_at..stop_at].contains(".await"),
        "判定与 proxy.stop() 之间出现了 await —— TOCTOU 窗口被重新撑开"
    );
}

/// 🟡 **不变量：空核绝不落位（落位 0 字节的核 = 直接 brick，起核必失败）。**
///
/// 三条读字节的腿都必须在把字节交给 `swap_core_with_restart` 之前拒绝空文件。
///
/// **为什么这道门长在这里**：此前这条不变量的唯一书面证据是
/// `core_swap::install_core_from_file` 的单测 —— 而那个函数**没有任何生产调用点**
/// （2026-08-09 全仓反查：定义 + 它自己两条单测，无第三处）。删它时若顺手把测试一并删掉，
/// 不变量就一处都不剩了；故把门搬到**活路径**上。删函数不该连带删掉它守着的东西。
///
/// 顺带补齐：回滚腿此前**没有**这道校验（`.bak` 由非空字节产出，空只会来自外部截断），
/// 而后果与另两条腿完全相同。
///
/// **变异探针**：任一腿的 `Ok(b) if !b.is_empty()` 退回 `Ok(b)` ⇒ 该腿转红。
#[test]
fn empty_core_bytes_never_reach_the_swap() {
    for leg in [
        "pub async fn core_replace_manual(",
        "pub async fn core_reset_factory(",
        "pub async fn core_rollback(",
    ] {
        let body = crate::commands::guard_scan::top_level_fn_body(src(), leg);
        let guard_at = body.find("Ok(b) if !b.is_empty()").unwrap_or_else(|| {
            panic!("{leg} 少了空文件校验 —— 0 字节的核会被落位，起核必失败且旧核已被覆盖")
        });
        let swap_at = body
            .find("swap_core_with_restart(")
            .unwrap_or_else(|| panic!("{leg} 锚点消失：守卫已失去判据"));
        assert!(
            guard_at < swap_at,
            "{leg} 的空文件校验必须早于落位（实得 校验={guard_at} / 落位={swap_at}）"
        );
    }
}

/// 🟡 **调用点守卫：wire 契约对拍必须在换核路径上、且早于停核与落盘。**
///
/// `verdict_for_core_bytes` 的单测测的是**判据本身**；判据再对，不被调用就什么也守不到 ——
/// 而这条路径（在线换核 / 用户自带 fork）恰恰是 `build.rs` 那道 release 硬门够不着的一格
/// （它只看 `resources/*/sing-box` 四条路径）。故此处立源码级守卫。
///
/// 顺序判据不是形式主义：拦在 `proxy.stop()` 之前 ⇒ 拒绝时用户的代理毫发无损；
/// 拦在 `install_core_bytes(` 之前 ⇒ 不会先把一份注定要拒的核落到盘上。
///
/// **变异探针**：删掉调用 / 把它挪到 `proxy.stop().await` 之后 / 挪到 `install_core_bytes(`
/// 之后 ⇒ 逐条转红。
#[test]
fn wire_contract_check_precedes_stop_and_install() {
    let body =
        crate::commands::guard_scan::top_level_fn_body(src(), "async fn swap_core_with_restart(");
    let check_at = body
        .find("verdict_for_core_bytes(core_bytes)")
        .expect("换核路径没有对拍 wire 契约 —— 非随包核的字段号漂移会让管理 API 整条流静默死掉");
    let stop_at = body
        .find("proxy.stop().await")
        .expect("锚点消失：守卫已失去判据");
    let install_at = body
        .find("install_core_bytes(")
        .expect("锚点消失：守卫已失去判据");
    assert!(
        check_at < stop_at && check_at < install_at,
        "对拍必须早于停核与落盘（实得 对拍={check_at} / stop={stop_at} / 落盘={install_at}）"
    );
    // 只有 Mismatch 一档拦。判据不能只查「两个分支名在不在」—— 那样把 Unobservable 分支体
    // 改成 return 也照样绿（写第一版时正是这个形态，变异编译不过才暴露出来）。
    // 故直接查 **Unobservable 分支体里不得有 return**。
    let unobs_at = body
        .find("WireVerdict::Unobservable(")
        .expect("Unobservable 分支没了 —— 取不到判据时会走进拒绝档");
    let mismatch_at = body
        .find("WireVerdict::Mismatch(")
        .expect("Mismatch 分支没了 —— 真正该拦的那一档没人拦");
    assert!(
        unobs_at < mismatch_at,
        "分支顺序变了，下面这段取不准 Unobservable 的分支体"
    );
    assert!(
        !body[unobs_at..mismatch_at].contains("return"),
        "Unobservable 分支里出现了 return —— 把「没观测到」当成「观测到有问题」，\
             一次读失败就会剥夺用户装自己那份核的能力"
    );
    // 回滚必须豁免：`core_rollback` 走的是同一条编排，在这里拦住等于把用户困在坏核上
    // （回滚的触发场景恰恰是「新核不可用」）。
    let exempt_at = body
        .find("SwapSource::Rollback")
        .expect("回滚豁免没了 —— 备份核若对不上号，用户将无路可退");
    assert!(
        exempt_at < check_at,
        "回滚豁免必须在对拍之前生效（实得 豁免={exempt_at} / 对拍={check_at}）"
    );
}

/// 🟡 **调用点守卫：换核成功后必须挂上稳定观察窗，且挂在起核之后。**
///
/// 观察窗是 上游 `armPendingValidation` + `startStabilityWatch` 的对等物，补的是同步验证闩
/// 看不见的那一类失败：新核**起得来**、几十秒后才崩。删掉 `arm_core_validation(` 这一行，
/// 全仓没有任何其它测试会红 —— 判据（`core_validation`）的单测测的是判据本身，
/// 而这条腿一旦不被调用，判据再对也不会被执行到。故此处立源码级守卫。
///
/// **变异探针**：删掉 `arm_core_validation(` / 把它挪到 `proxy.start(` 之前 /
/// 去掉 `swap.backed_up` 前置 ⇒ 逐条转红。
#[test]
fn stability_watch_is_armed_after_a_successful_restart() {
    let body =
        crate::commands::guard_scan::top_level_fn_body(src(), "async fn swap_core_with_restart(");
    let arm_at = body.find("arm_core_validation(").expect(
        "换核后的稳定观察窗没被挂上 —— 新核「起得来、几十秒后崩」将无人回滚，\
             备份原样躺在盘上，用户得自己发现并手动回滚",
    );
    // 起核在前：没起过核就没有「首次运行」可观察。
    let start_at = body.find("proxy.start(").expect("锚点消失：守卫已失去判据");
    assert!(
        start_at < arm_at,
        "观察窗必须挂在起核之后（实得 start={start_at} / arm={arm_at}）"
    );
    // 两个前置条件必须与 arm 同处一个判定：漏掉 backed_up 会在无备份时白挂一个
    // 「观察到失败也回滚不了」的窗口，且窗口内抑制了自愈重启 = 纯的负收益。
    let gate = &body[..arm_at];
    let cond_at = gate
        .rfind("if was_running && swap.backed_up")
        .expect("观察窗的前置条件（was_running + backed_up）被改了或删了");
    let between = gate[cond_at..].lines().count();
    assert!(
        between <= 3,
        "前置条件与 arm 调用之间隔了 {between} 行 —— 守卫已无法确认二者仍是同一个判定"
    );
}

/// 🟡 **调用点守卫：簿记回写必须接在验证闩之后，且喂的是「探测失败返空」那个读法。**
///
/// 纯逻辑由 `core_swap::marker_rewrite_line` 的真值表锁；这里锁**接线**——
/// 逻辑再对，没人调它就等于没修。三条各锁一个真实退化：
///  1. 回写整段被删 ⇒ 空簿记原样回归 ⇒ 从设置页更新过内核的机器被永久钉住（静默）。
///  2. 回写挪到验证闩**之前** ⇒ 闩内失败会 `rollback_core` 把盘上换回旧核，而此刻已按
///     「新核」的实读写过簿记 ⇒ 簿记记的是新版本、盘上是旧核，判据与实况反向。
///  3. 喂 `read_core_version()` 而非 `read_core_version_line()` ⇒ 探测失败时它**回落随包
///     基线**，于是「读不出版本」被伪装成「版本就是基线」写进簿记 ⇒ 后续升级判同版不播种。
///
/// **变异探针**：删 `rewrite_marker_from_probe(` / 把它挪到 `if let Some(c) = config` 之前 /
/// 把 `read_core_version_line()` 改成 `read_core_version()` ⇒ 逐条转红。
#[test]
fn marker_rewrite_is_wired_after_verify_latch_with_nonfallback_read() {
    let body =
        crate::commands::guard_scan::top_level_fn_body(src(), "async fn swap_core_with_restart(");
    let latch_at = body
        .find("proxy.start(c.clone()).await")
        .expect("锚点消失：守卫已失去判据（验证闩变形了）");
    let rewrite_at = body.find("rewrite_marker_from_probe(").expect(
        "换核后的簿记回写被删了 —— 声明值为空的两条主路径（core_update_run 前端传 \
             downloadUrl / core_rollback 传 \"\"）会写空簿记，这个核从此不再被随包基线重播种",
    );
    assert!(
        latch_at < rewrite_at,
        "簿记回写必须在验证闩之后（实得 latch={latch_at} / rewrite={rewrite_at}）：\
             闩内失败会回滚成旧核，闩前回写会把新核版本写到旧核的簿记上"
    );
    // 取材必须是「探测失败返空串」那个读法。`read_core_version(` 是 `read_core_version_line(`
    // 的前缀，故先把带 `_line` 的出现全部剔掉再找裸的，避免自己骗自己。
    let probe_seg = &body[..rewrite_at];
    assert!(
        probe_seg.contains("read_core_version_line()"),
        "簿记回写的取材必须是 read_core_version_line()（探测失败返空串）"
    );
    assert!(
        !probe_seg
            .replace("read_core_version_line()", "")
            .contains("read_core_version()"),
        "回写取材段出现了 read_core_version() —— 它探测失败会回落随包基线，\
             把「读不到」写成「就是基线」"
    );
}

/// 🟡 **调用点守卫：自动落位入口必须传 `Forbidden`，手动入口必须传 `Allowed`。**
#[test]
fn auto_entry_forbids_interruption_manual_entry_allows_it() {
    let auto = crate::commands::guard_scan::top_level_fn_body(
        src(),
        "pub(crate) async fn core_update_apply_staged_auto(",
    );
    assert!(
        auto.contains("SwapInterrupt::Forbidden"),
        "自动落位入口必须是「绝不断流」档"
    );
    let manual = crate::commands::guard_scan::top_level_fn_body(
        src(),
        "pub async fn core_update_apply_staged(",
    );
    assert!(
        manual.contains("SwapInterrupt::Allowed"),
        "用户点「立即应用」必须允许停/起核，否则该按钮永远无效"
    );
}

/// 🟡 **调用点守卫：`deferred` 绝不清 staged。**
///
/// `deferred` 的信封是 `success: true`（它是一次合法的「本轮不落位」，不是错误），
/// 落在 `resp.success` 那条分支上就会把一个字节都没换的轮次当成功、把已下好的核删掉。
///
/// **变异探针**：删掉 `swap_result_code(&resp) == Some("deferred")` 那段早退 /
/// 把它挪到 `if resp.success` 之后 ⇒ 转红。
#[test]
fn deferred_outcome_never_clears_staged() {
    let body =
        crate::commands::guard_scan::top_level_fn_body(src(), "async fn apply_staged_inner(");
    let deferred_at = body
        .find(r#"swap_result_code(&resp) == Some("deferred")"#)
        .expect("deferred 分支被删了 —— 自动路径被拦下时会把已下好的 staged 核误删");
    let success_at = body
        .find("if resp.success {")
        .expect("锚点消失：守卫已失去判据");
    assert!(
        deferred_at < success_at,
        "deferred 早退必须在 `resp.success` 分支**之前**（deferred 的信封正是 success:true）"
    );
}

// ── 暂存核完整性复核（L9）────────────────────────────────────────────────

#[test]
fn check_staged_integrity_truth_table() {
    let core = b"fake-sing-box";
    let good = polaris_updater::verify::sha256_hex(core);
    assert_eq!(
        check_staged_integrity(core, Some(&good)),
        StagedIntegrity::Ok
    );
    // 大小写不敏感（verify_bytes 的既有语义）。
    assert_eq!(
        check_staged_integrity(core, Some(&good.to_uppercase())),
        StagedIntegrity::Ok
    );
    // 字节被改（位腐 / 篡改）→ 必须拦。
    assert_eq!(
        check_staged_integrity(b"tampered", Some(&good)),
        StagedIntegrity::Mismatch
    );
    // 旁挂文件本身坏了（非法 hex）→ 同目录的核不可信 → 也拦。
    assert_eq!(
        check_staged_integrity(core, Some("not-a-hash")),
        StagedIntegrity::Mismatch
    );
    // 无记录 / 空记录（旧版本 App 暂存的核、或旁挂文件写了一半）→ 放行，不倒退。
    assert_eq!(
        check_staged_integrity(core, None),
        StagedIntegrity::Unrecorded
    );
    assert_eq!(
        check_staged_integrity(core, Some("  \n")),
        StagedIntegrity::Unrecorded
    );
}

/// 旁挂文件必须与被校验的核**同目录**（`stage` 重建目录时一起被清掉 ⇒ 不会错配）。
#[test]
fn staged_sha_sidecar_sits_next_to_the_core() {
    let dir = std::path::Path::new("/some/core-staged");
    let p = staged_core_sha_path(dir);
    assert_eq!(p.parent(), Some(dir), "摘要必须与核同目录");
    assert_eq!(
        p.file_name().unwrap().to_string_lossy(),
        format!("{}.sha256", core_paths::core_filename())
    );
}

/// 🟡 **调用点守卫：完整性复核必须发生在换核之前。**
#[test]
fn staged_integrity_is_checked_before_the_swap() {
    let body =
        crate::commands::guard_scan::top_level_fn_body(src(), "async fn apply_staged_inner(");
    let check_at = body.find("check_staged_integrity(").expect(
        "暂存核完整性复核被删了 —— 位腐/篡改的核会被原样换入（起核闩拦不住「起得来但行为坏」）",
    );
    let swap_at = body
        .find("swap_core_with_restart(")
        .expect("锚点消失：守卫已失去判据");
    assert!(check_at < swap_at, "复核必须在换核**之前**");
}

// ── 下载单飞（H2）───────────────────────────────────────────────────────

/// 同一个 dest 拿到同一把闸；不同 dest 互不影响（否则两个不相干的下载会互相排队）。
#[test]
fn download_gate_is_keyed_by_destination() {
    let a = std::path::Path::new("/cache/updates/a.dmg");
    let b = std::path::Path::new("/cache/updates/b.dmg");
    assert!(Arc::ptr_eq(&download_gate(a), &download_gate(a)));
    assert!(
        !Arc::ptr_eq(&download_gate(a), &download_gate(b)),
        "不同目标文件必须各有各的闸"
    );
}

/// 单飞表只拥有在途锁：旧目标的最后一个强引用释放后，下次取锁必须驱逐旧键。
#[test]
fn download_gate_map_prunes_finished_destinations() {
    let mut map = DownloadGateMap::new();
    let first_path = std::path::Path::new("/cache/updates/old.dmg");
    let first = keyed_download_gate(&mut map, first_path);
    assert_eq!(map.len(), 1);
    assert!(Arc::ptr_eq(
        &first,
        &keyed_download_gate(&mut map, first_path)
    ));

    drop(first);
    let current_path = std::path::Path::new("/cache/updates/current.dmg");
    let current = keyed_download_gate(&mut map, current_path);
    assert_eq!(map.len(), 1, "已结束目标不应在进程内永久占位");
    assert!(!map.contains_key(first_path));
    assert!(Arc::ptr_eq(
        &current,
        &keyed_download_gate(&mut map, current_path)
    ));
}

/// 🟡 **变异锁：同一个 dest 同时只允许一条下载腿在临界区内。**
///
/// 复现的是默认流程：`autoDownloadUpdate` 的后台下载腿 + 用户在 mini 弹窗点「更新」。
/// **变异探针**：把 `download_gate(...).lock().await` 从 `update_download` 里拿掉
/// （或让 [`download_gate`] 每次返回新 Arc）⇒ 本条转红。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn download_gate_serialises_concurrent_downloads_of_one_destination() {
    use std::sync::atomic::AtomicUsize;
    let dest = std::path::PathBuf::from("/cache/updates/concurrent.pkg");
    let inside = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (dest, inside, peak) = (dest.clone(), inside.clone(), peak.clone());
        tasks.push(tokio::spawn(async move {
            let gate = download_gate(&dest);
            let _permit = gate.lock().await;
            let n = inside.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            peak.fetch_max(n, std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            inside.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert_eq!(
        peak.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "同一个 dest 同时有多条下载腿在写 —— 两个进度游标互相顶，且白下一份流量"
    );
}

/// 复用只认 sha256：有摘要且相符才复用；不符 / 无摘要 / 文件不在 → 老老实实重下。
#[test]
fn cached_download_is_reusable_only_with_a_matching_digest() {
    let dir = scratch("reuse");
    let dest = dir.join("update.pkg");
    std::fs::write(&dest, b"package-bytes").unwrap();
    let good = polaris_updater::verify::sha256_hex(b"package-bytes");

    assert!(cached_download_is_reusable(&dest, Some(&good)));
    assert!(
        !cached_download_is_reusable(&dest, Some(&"a".repeat(64))),
        "摘要不符必须重下（磁盘上那份可能是上次被截断的）"
    );
    assert!(
        !cached_download_is_reusable(&dest, None),
        "没有摘要判据就不能声称「磁盘上这份就是你要的包」——不拿文件名当身份"
    );
    assert!(
        !cached_download_is_reusable(&dest, Some("")),
        "空摘要等同没有摘要"
    );
    assert!(!cached_download_is_reusable(
        &dir.join("missing.pkg"),
        Some(&good)
    ));
}

// ── App 更新包：写入体积闸（D4）─────────────────────────────────────────

/// 🟡 **`fileSize` 为 0 / 缺失时必须回落宽松上限，绝不能拿 0 当闸。**
///
/// `AppUpdateInfo.file_size` 在 GitHub asset 缺 `size` 字段时按 **0** 填
/// （`github.rs` 的 `#[serde(default)]`）。直接拿它当闸 ⇒ 闸值 = 0，
/// **任何包都过不去**，且失败长得像「下载超限」，成因（清单少个字段）无从追起。
///
/// **变异探针**：把 `declared.filter(|n| *n > 0)` 改回 `declared` ⇒ 后三条转红。
#[test]
fn app_update_size_limit_falls_back_when_the_declared_size_is_absent_or_zero() {
    // 声明值有效 → 闸就等于声明值（**无裕度**，2026-08-17 删）。
    //
    // 本条原是一对断言：`== declared + MARGIN` 与 `> declared`（「闸不得小于等于声明值本身」）。
    // 随裕度一并订正为**等值**：三处体积闸都是**严格大于**才拒（预检 `n > limit`、两条读侧
    // `已收 + 本 chunk > limit`），故 `limit == declared` 时一个恰好 `declared` 字节的包
    // **仍然过得去**。那条边界不是推断，由 `runtime::http` 的
    // `size_limit_boundary_admits_a_body_of_exactly_the_limit` 逐处拿等长响应体撞过。
    let declared = 40 * 1024 * 1024;
    assert_eq!(
        app_update_size_limit(Some(declared)),
        declared as usize,
        "有声明值时闸 = 声明值本身：等长包靠三处闸的严格大于语义放行，不靠裕度"
    );

    // 声明为 0（GitHub asset 缺 size 的真实形态）→ 回落宽松绝对上限。
    assert_eq!(
        app_update_size_limit(Some(0)),
        APP_UPDATE_MAX_BYTES as usize,
        "fileSize=0 是「清单没给」，不是「包是空的」——拿 0 当闸会拒掉一切"
    );
    // 字段整个缺失 → 同上。
    assert_eq!(app_update_size_limit(None), APP_UPDATE_MAX_BYTES as usize);
    // 回落上限必须容得下真实量级的安装包（几十 MiB）。
    assert!(
        app_update_size_limit(None) > 200 * 1024 * 1024,
        "回落上限卡得比真实安装包还紧 = 换了个姿势拒掉一切"
    );
}

/// 🟡 **声明分支必须有天花板：闸值绝不由服务端单方面顶到任意高。**
///
/// 本条**推翻了**它的前身（`app_update_size_limit_saturates_instead_of_wrapping`）：那条断言
/// `Some(u64::MAX) → usize::MAX`，即**把洞当成期望固化了下来** —— 只防「回绕成一个极小的闸」，
/// 完全不防「闸大到形同不设」。而 `APP_UPDATE_MAX_BYTES` 的文档写的正是「别让一个撒谎的
/// 服务端把盘写满」：`fileSize` 报 100 GiB ⇒ 闸值 100 GiB ⇒ Content-Length 预检放行 ⇒
/// 一路写到 ENOSPC，用户的系统盘被写满。
///
/// **变异探针**（2026-08-17 实测订正，原写「前三条逐条转红」是错的）：去掉
/// `.min(APP_UPDATE_MAX_BYTES)` ⇒ **第 1 条**转红（断言在此中止，故一次运行只看得到这一条）；
/// 单独摘掉第 1、2 条后重跑，**第 3、4 条仍绿** —— 第 3 条的声明值恰好等于天花板，`min`
/// 在那一点是恒等映射，本就落不到差异上；第 4 条在天花板之下同理。
/// 即本条真正的判据是**第 1、2 条**，第 3 条只钉 `min` 的等值分支不越界。
#[test]
fn app_update_size_limit_is_capped_by_the_absolute_ceiling() {
    // 极端声明值（前身守的那一半，保留）。裕度删掉后 `saturating_add` 也一并没了 ⇒
    // 「回绕成极小值」这条失效形态结构性不存在，只剩「顶到天上」要防。
    assert_eq!(
        app_update_size_limit(Some(u64::MAX)),
        APP_UPDATE_MAX_BYTES as usize,
        "u64::MAX 的声明值必须被压回绝对上限"
    );
    // 撒谎的服务端：100 GiB 的声明值必须被压回天花板。
    assert_eq!(
        app_update_size_limit(Some(100 * 1024 * 1024 * 1024)),
        APP_UPDATE_MAX_BYTES as usize,
        "声明值再大也不得把闸顶上去——那正是本闸要防的那件事"
    );
    // 边界：声明值恰好等于天花板 → 就取天花板（`min` 的等值分支）。
    assert_eq!(
        app_update_size_limit(Some(APP_UPDATE_MAX_BYTES)),
        APP_UPDATE_MAX_BYTES as usize
    );
    // 天花板之下的正常量级不受影响（封顶不得把正常包一起卡掉）。
    let normal = 40 * 1024 * 1024;
    assert_eq!(app_update_size_limit(Some(normal)), normal as usize);
}

// ── U2：打包体积门 ↔ 客户端写入闸的一致性（D5）───────────────────────────

/// 打包体积门源码（`scripts/verify-packaging.mjs`），只为**逐字读出它那行常量**。
fn packaging_gate_js() -> &'static str {
    static JS: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    JS.get_or_init(|| repo_file("scripts/verify-packaging.mjs"))
        .as_str()
}

/// 打包体积门阈值在本仓的**第二份**（单位 MiB），真值在
/// `scripts/verify-packaging.mjs` 的 `MAX_UPDATE_ASSET_BYTES`。
///
/// D5 拍板的形态是「维护两份 + 一条一致性测试钉死」。两份不是冗余：Rust 侧这一份让本文件能
/// 提出一条 JS 侧**提不出**的断言 —— 打包阈值必须待在 [`APP_UPDATE_MAX_BYTES`] 之下。
///
/// 为什么不反过来「让 JS 去读 Rust 那份、只留一份」：本文件对 [`APP_UPDATE_MAX_BYTES`] 是
/// **按符号引用**的（改名 / 改类型 / 删掉都在编译期红），而 JS 侧只能拿正则去扒 Rust 源码，
/// 那种引用会**静默漂移**（正则扒不着就退化成「没变」）。把跨语言那一跳放在有编译器的这一侧，
/// 漂移面才最小 —— 也正因为如此，下面这个解析函数必须把「扒不准」一律判成失败。
const PACKAGING_MAX_UPDATE_ASSET_MIB: u64 = 200;

/// 从打包门源码里读出 `MAX_UPDATE_ASSET_BYTES = N * 1024 * 1024` 的 `N`。
///
/// 取不到就返回 `None` ⇒ 调用方**转红**。这是刻意的失败方向：判据取不到时若默认「没变」，
/// 一次 JS 侧改写形态（比如换成裸字面量）就会让这条一致性测试**静默失效**，
/// 而它看起来还是绿的 —— 那正是本测试要防的那类事。
///
/// # 「出现多次」同样是不可判定，必须一并判成失败（2026-08-17 复审修）
///
/// 原实现取**首个**匹配（`split_once`），于是「解析失败会红」防不住「解析到错的那一行」：
/// 本仓的注释风格就是大段引用代码 —— 调门时在常量文档里补一行
/// `const MAX_UPDATE_ASSET_BYTES = 96 * 1024 * 1024;  // 旧值` 作沿革记录、同时把真值升到 256，
/// 首个匹配读到注释里那个 96、与镜像相等 ⇒ **绿**，而两份常量已经漂开 160 MiB。
/// 故先数命中数，`!= 1` 直接 `None`：与 `checkSha256Sums` 对同名资产的处置同一条纪律
/// ——**不可判定就必须红，不能挑一个继续**。
///
/// # 数的是「以 marker 开头的**行**」，不是子串出现次数（2026-08-17 二次复审修）
///
/// 只数子串的话，「恰好 1 次、但那 1 次不是真声明」照样会被取值 —— 复审逐字复刻本函数跑了
/// 14 组输入，三组假绿全长一个样：**真声明因换行/改名不再匹配（0 次）+ 注释里那处同形（1 次）
/// = 合计 1 次**。最现实的一种是有人按更窄行宽把常量折成
/// `= \n  256 * 1024 * 1024;`，而文件里某处注释还留着一句一行形态的引用 ⇒ 读到注释里的旧值 96、
/// 与镜像相等 ⇒ 绿，两份实际已漂开 160 MiB。
///
/// 按行判把两侧一起堵上：注释行（`//` / ` * ` 开头）结构上不以 marker 起头，不再参与计数；
/// 真声明一旦折行就 0 命中 ⇒ `None` ⇒ 红（fail-closed，方向正确）。
/// `trim_start_matches("export ")` 是给「将来这行改成 `export const`」留的等价形态，不是通配。
fn packaging_gate_mib_from_js(src: &str) -> Option<u64> {
    const MARKER: &str = "const MAX_UPDATE_ASSET_BYTES = ";
    let hits: Vec<&str> = src
        .lines()
        .map(|l| l.trim_start().trim_start_matches("export "))
        .filter(|l| l.starts_with(MARKER))
        .collect();
    if hits.len() != 1 {
        return None;
    }
    hits[0]
        .strip_prefix(MARKER)?
        .split_once(';')?
        .0
        .trim()
        .strip_suffix(" * 1024 * 1024")?
        .trim()
        .parse()
        .ok()
}

/// 🟡 **解析函数对「扒不准」的三类输入都必须交白卷，而不是猜一个数出来。**
///
/// 上一条测试的全部效力都建立在「`js` 这个数确实是 CI 上拦包的那个数」之上。本条把这个前提
/// 本身钉住，覆盖三类：
///  - **形态变了**（裸字面量 / 改名 / 折行）⇒ `None`，调用方 `expect` 转红；
///  - **真声明出现多次**⇒ `None`（读哪一处不确定）；
///  - **注释里有同形文本**⇒ 不得被当成声明取值 —— 这一类是二次复审逐字复刻跑出来的假绿：
///    真声明折行后 0 命中、注释那处 1 命中，只数子串的实现合计得 1 ⇒ 静默读注释里的旧值。
///
/// **变异探针**（2026-08-17 实测）：把命中判据换回 `src.matches(MARKER).count()` ⇒ 注释组
/// ①②③ **三条各自都会转红**（断言在首条中止，故一次运行只看得到 ①）。三组在旧判据下逐字返回
/// `Some(96)` —— 即注释里那份旧值被当成了真值，而真值其实是 256。
/// 两条正向对照（唯一真声明 / `export` + 缩进）在新旧实现下都返回 `Some(96)`，
/// 故本条不是靠「把什么都判红」换来的。
#[test]
fn packaging_gate_parser_refuses_ambiguous_or_reshaped_sources() {
    // 正向对照：唯一一处、形态如约 ⇒ 读得出（否则下面几条「读不出」毫无信息量）。
    assert_eq!(
        packaging_gate_mib_from_js("const MAX_UPDATE_ASSET_BYTES = 96 * 1024 * 1024;\n"),
        Some(96)
    );
    // 形态变了 ⇒ 交白卷。
    assert_eq!(
        packaging_gate_mib_from_js("const MAX_UPDATE_ASSET_BYTES = 100663296;\n"),
        None,
        "裸字面量读不出，必须让调用方红"
    );
    assert_eq!(
        packaging_gate_mib_from_js("const MAX_UPDATE_ASSET_LIMIT = 96 * 1024 * 1024;\n"),
        None,
        "常量改名 = 判据消失"
    );
    // 真声明出现两次 ⇒ 读哪一处不确定，交白卷。
    assert_eq!(
        packaging_gate_mib_from_js(concat!(
            "const MAX_UPDATE_ASSET_BYTES = 96 * 1024 * 1024;\n",
            "const MAX_UPDATE_ASSET_BYTES = 256 * 1024 * 1024;\n"
        )),
        None,
        "两条真声明 ⇒ 不可判定；挑首个会把「已漂开」判成绿"
    );
    // ── 注释里的同形文本不得被当成声明（只数子串的实现在这三组上全是假绿）──
    // ① 真声明折行 ⇒ 应 0 命中；注释那处不参与计数 ⇒ 合计 0 ⇒ None。
    assert_eq!(
        packaging_gate_mib_from_js(concat!(
            "// 沿革：const MAX_UPDATE_ASSET_BYTES = 96 * 1024 * 1024;（旧值）\n",
            "const MAX_UPDATE_ASSET_BYTES =\n  256 * 1024 * 1024;\n"
        )),
        None,
        "真声明折行 ⇒ 判据取不到，绝不能回落去读注释里的旧值"
    );
    // ② 真声明改名 + 注释留旧形态。
    assert_eq!(
        packaging_gate_mib_from_js(concat!(
            " * 旧写法：const MAX_UPDATE_ASSET_BYTES = 96 * 1024 * 1024;\n",
            "const MAX_UPDATE_ASSET_LIMIT = 256 * 1024 * 1024;\n"
        )),
        None,
        "块注释里的同形行同样不得顶替判据"
    );
    // ③ 真声明换裸字面量并改名 + 注释留旧形态。
    assert_eq!(
        packaging_gate_mib_from_js(concat!(
            "// const MAX_UPDATE_ASSET_BYTES = 96 * 1024 * 1024;\n",
            "const ASSET_CEILING = 268435456;\n"
        )),
        None,
        "注释掉的旧行 + 换形态的新声明 ⇒ 必须交白卷"
    );
    // 反向对照：真声明前有缩进 / 将来改成 `export const` 仍读得出（本条不是「越严越好」，
    // 把等价形态一并判红会让门在无害改动上假红）。
    assert_eq!(
        packaging_gate_mib_from_js("  export const MAX_UPDATE_ASSET_BYTES = 96 * 1024 * 1024;\n"),
        Some(96)
    );
}

/// 🟡 **打包体积门的两份常量不得漂开，且它必须待在客户端绝对写入闸之下。**
///
/// 两条断言各防一件事：
///  - **漂开**：只改 JS 那一份 ⇒ 本条转红。没有它，「两份」就是两个各说各话的数；
///  - **越顶**：把打包门调到 [`APP_UPDATE_MAX_BYTES`] 之上 ⇒ 本条转红。那种配置下打包门会
///    放行一个**客户端结构性下不动**的包（写入闸在 512 MiB 处拒，用户侧表现为更新永远失败），
///    等于把 U1 那个缺陷换了个数量级重来一遍。
///
/// 还有一条**下界**：门不得低于真实产物量级（实测最大 122.58 MiB，linux AppImage，
/// run 32109475236；2026-08-18 二次定标前是 51.72 的 mac dmg），否则每次 linux 发布都假红
/// —— 一道恒红的门与一道没有的门，信息量一样是零。下界取 128：大于实测最大值的最小
/// 二进制整数档，给「AppImage 以后瘦身、想跟着降门」留一步余量，但降破它必须连同实测依据一起改。
///
/// **变异探针**：把 `MAX_UPDATE_ASSET_BYTES` 改成 `128 * 1024 * 1024` 而不动这里 ⇒ 第 1 条转红；
/// 改成 `1024 * 1024 * 1024` 并同步改这里 ⇒ 第 2 条转红；同步改成 `32` ⇒ 第 3 条转红。
#[test]
fn packaging_size_gate_is_mirrored_and_stays_under_the_client_write_gate() {
    let js = packaging_gate_mib_from_js(packaging_gate_js()).expect(
        "读不出 verify-packaging.mjs 的 MAX_UPDATE_ASSET_BYTES —— \
             判据取不到时必须红，不能默认「没变」（形态要求：`N * 1024 * 1024`）",
    );
    assert_eq!(
            js, PACKAGING_MAX_UPDATE_ASSET_MIB,
            "打包体积门的两份常量漂开了：JS 侧 {js} MiB / 本文件 {PACKAGING_MAX_UPDATE_ASSET_MIB} MiB。\
             D5 的形态是「维护两份 + 本条钉死」，改一处必须同步改另一处"
        );
    // 下面两条一律拿**从 JS 读出来的那个数**去判，不拿本文件的镜像：真正在 CI 上拦包的是
    // JS 那一份，镜像只是用来发现漂开。拿镜像判等于自己判自己（clippy 也会直接指出这是
    // 一条常量断言）。
    assert!(
        js * 1024 * 1024 < APP_UPDATE_MAX_BYTES,
        "打包门（{js} MiB）越过了客户端绝对写入闸（{} MiB）：\
             那样打包门会放行一个客户端根本下不动的包，用户侧表现为更新永远失败",
        APP_UPDATE_MAX_BYTES / 1024 / 1024
    );
    assert!(
        js >= 128,
        "打包门（{js} MiB）卡到了真实产物量级（实测最大 122.58 MiB，linux AppImage）附近：\
             那会让每次发布都假红，与没有这道门等价"
    );
}

// ── App 更新包：期望摘要的来源（D1）─────────────────────────────────────

/// 摘要来源按优先级挑；全无 → `Ok(None)`（**不拒装**，降级为弱校验并如实标记未校验）。
#[test]
fn expected_digest_is_resolved_by_source_priority_and_degrades_honestly() {
    let sha = "a".repeat(64);
    let got = resolve_expected_digest(&json!({ "sha256": sha }))
        .expect("合法字符串不该报错")
        .expect("应挑出 asset digest");
    assert_eq!(got.hex, sha);
    assert_eq!(got.source, DigestSource::GithubAssetDigest);
    assert_eq!(got.source.as_str(), "githubAssetDigest");

    // 无摘要 / 空串 / 纯空白 → Ok(None)（旧 release 的真实形态：`AppUpdateInfo.sha256` 带
    // `skip_serializing_if = "Option::is_none"`，故缺摘要时**字段整个不出现**）。
    assert_eq!(resolve_expected_digest(&json!({})), Ok(None));
    assert_eq!(resolve_expected_digest(&json!({ "sha256": "" })), Ok(None));
    assert_eq!(
        resolve_expected_digest(&json!({ "sha256": "   " })),
        Ok(None)
    );

    // 格式非法的摘要**不得**在此静默丢弃 —— 那会把「摘要写坏了」伪装成「本来就没摘要」而放行。
    // 它要一路走到校验步，才分得出「发布方写坏了」与「包被篡改」两种文案。
    let bad = resolve_expected_digest(&json!({ "sha256": "not-a-hash" }))
        .expect("非法 hex 是字符串，不在本函数报错")
        .expect("格式非法也要挑出来，交给校验步报错");
    assert_eq!(bad.hex, "not-a-hash");
}

/// 🟡 **字段在、但不是字符串 ⇒ 显式早退，绝不静默降级成「本来就没摘要」。**
///
/// 原实现三种形态（`123` / `null` / `["…"]`）全走 `Value::as_str` → `None` → 与「字段缺失」
/// 合流 → `verified:false` 放行。即一个把 `sha256` 序列化成数字的发布流程，会让**全体用户**
/// 静默地少一道校验，而返回体上只显示 `verified:false`（长得和旧 release 一模一样）。
/// 这与 [`resolve_expected_digest`] 自己文档写的「静默丢弃会把『摘要写坏了』伪装成
/// 『本来就没摘要』而放行」正相反。
///
/// **变异探针**：把非字符串分支改回 `continue`（或退回 `and_then(Value::as_str)`）⇒ 三条转红。
#[test]
fn a_non_string_digest_field_is_rejected_not_silently_dropped() {
    for bad in [json!(123), json!(null), json!(["a".repeat(64)]), json!({})] {
        let err = resolve_expected_digest(&json!({ "sha256": bad }))
            .expect_err("非字符串的 sha256 必须显式早退");
        assert!(err.contains("sha256"), "错误必须点名是哪个字段坏了：{err}");
    }
    // 反向对照：字段**整个缺失**仍是合法的「本来就没摘要」，不得被一起拒掉
    // （否则所有旧 release 立刻更新不了）。
    assert_eq!(resolve_expected_digest(&json!({ "other": 1 })), Ok(None));
}

/// 摘要来源表：**当前只有一级**，且每一级都必须自报字段名与对外标识。
///
/// # 本条不再声称「加一级只改一处」（2026-08-16 订正）
///
/// 前身叫 `digest_source_table_is_ordered_and_extensible`，配的文档说「U3 只需在表最前面
/// 插一行」。那是**自相矛盾**的：本条自己就 `assert_eq!` 死了当前表，U3 必然要改它 ——
/// 一个声称「只改一处」的断言，本身就是必然要改的第二处。真正的成因是
/// [`DigestSource::field`] 把取法锁死成「`update_info` 顶层字符串字段」，而 `SHA256SUMS`
/// 是另一次网络下载 + 按资产名查表（详见 [`DigestSource`] 文档）。
///
/// 所以本条现在只钉两件**今天为真**的事：表是单元素的（不留假接线），以及每一级都自报身份。
///
/// # U3 落地后本条**仍然为真**（2026-08-17）
///
/// 前身预期「U3 落地时本条会被改」。实际落地的是「发布侧产出 `SHA256SUMS` + 门」，
/// 消费侧经判断**不接**（三条依据见 [`resolve_expected_digest`] 文档末节），故表仍是单元素。
/// 这条断言因此从「本批还没做」变成「做过判断后的现状」—— 将来真要接第 2 个来源时它才会红。
#[test]
fn digest_source_table_is_the_single_current_source() {
    assert_eq!(
        EXPECTED_DIGEST_SOURCES,
        [DigestSource::GithubAssetDigest],
        "消费侧只认 GitHub asset digest 一级（随包 SHA256SUMS 已产出但经判断不接，不留假接线）"
    );
    // 每个来源都必须自报字段名与标识（新增一级时忘了补 → 编译期就红）。
    for src in EXPECTED_DIGEST_SOURCES {
        assert!(!src.field().is_empty());
        assert!(!src.as_str().is_empty());
    }
}

/// 🟡 **清单声明的 `fileSize` 是等值判据（无摘要腿的主防线）。**
///
/// 无摘要腿此前**只有** Content-Length 兜底，而那个数是撒谎方自己给的：服务端/镜像返
/// `Content-Length: 1000` 且真发 1000 字节 ⇒ 完整性校验过 ⇒ 无摘要不校验 ⇒ 1000 字节的
/// 假包被 promote，返 `{success:true, verified:false}`，UI 给出安装入口。
/// 极端版 `Content-Length: 0` ⇒ 0 字节文件「下载成功」。
///
/// `fileSize` 来自 GitHub release 清单，镜像改不动 —— 零成本堵上这条。
///
/// **变异探针**：把 [`check_declared_size`] 改成恒 `Ok(())` ⇒ 第 2、3 条转红；
/// 去掉 `.filter(|n| *n > 0)` ⇒ 第 4 条转红（缺 size 的旧 release 会被全部拒掉）。
#[test]
fn declared_file_size_is_enforced_as_an_equality_criterion() {
    use polaris_updater::traits::DownloadError;

    // 声明值匹配 → 放行。
    assert!(check_declared_size(1000, Some(1000)).is_ok());

    // 不匹配 → Incomplete（结构化，带两个数）。收得少（截断）与收得多（掉包/注入）都算。
    assert!(matches!(
        check_declared_size(1000, Some(52_000_000)),
        Err(DownloadError::Incomplete {
            received: 1000,
            expected: 52_000_000
        })
    ));
    assert!(
        check_declared_size(0, Some(52_000_000)).is_err(),
        "`Content-Length: 0` + 真发 0 字节的假包必须被这一级拦下"
    );
    assert!(check_declared_size(52_000_001, Some(52_000_000)).is_err());

    // 声明为 0 / 缺失 = 「清单没给」，**不判**（旧 release 的正常形态；判了就全拒）。
    assert!(check_declared_size(1000, Some(0)).is_ok());
    assert!(check_declared_size(1000, None).is_ok());
}

/// 🟡 **调用点守卫：单飞闸必须早于「发进度」与「真下载」。**
///
/// 闸拿在后面 = 等待中的那条腿照样先发一发 `downloading(0)`，把已在跑的另一条腿的百分比顶回 0。
#[test]
fn update_download_takes_the_gate_before_emitting_or_downloading() {
    let body =
        crate::commands::guard_scan::top_level_fn_body(src(), "pub async fn update_download(");
    let gate_at = body
        .find("download_gate(&dest)")
        .expect("下载单飞闸被删了 —— 后台自动下载与弹窗「更新」会同时写同一个 dest");
    let emit_at = body
        .find("emit(ProgressStage::Downloading {")
        .expect("锚点消失：守卫已失去判据");
    // 锚点随 U1（整包入内存 → 流式落盘）从 `download_with_progress(` 换成
    // `download_to_sink_with_progress(`：守的东西**一个字没变**（闸必须早于发进度与真下载），
    // 只是「真下载」那一句的名字变了。
    let dl_at = body
        .find("download_to_sink_with_progress(")
        .expect("锚点消失：守卫已失去判据");
    assert!(
            gate_at < emit_at && gate_at < dl_at,
            "单飞闸必须在「发 downloading(0)」与「真下载」之前拿到（实得 {gate_at} / {emit_at} / {dl_at}）"
        );
}

/// 🟡 **调用点守卫：落位只许 rename，绝不许把刚流式写完的文件读回内存。**
///
/// `atomic_replace` 吃 `&[u8]`。谁要是图省事把落位写回 `atomic_replace(&StdFs, &dest, &bytes)`，
/// 就等于在流式下载之后又做一次「整包读回内存 + 整包重写」—— 本次改造的收益**当场归零**，
/// 而且四条 gate 全绿、行为完全正确，只有真机上几十 MiB 的内存峰值会告诉你。
/// 源码扫描是这条不变式**唯一**够得着的判据。
///
/// **变异探针**：把 `promote_staged(...)` 换回 `atomic_replace(...)` ⇒ 两条断言同时转红。
#[test]
fn payload_is_promoted_by_rename_not_re_read_into_memory() {
    let body =
        crate::commands::guard_scan::top_level_fn_body(src(), "pub async fn update_download(");
    assert!(
        body.contains("land_payload("),
        "落位必须走 `land_payload` → `verify::promote_staged`（tmp 已在盘 → 只 rename）"
    );
    // ── 「整包回内存」按**族**禁，不按单个字面量禁 ──────────────────────────
    //
    // 前身只禁 `atomic_replace(` 与 `verify_bytes(` 两个字面量，而被守的语义面远大于这两项：
    // 在落位前插一行 `let bytes = std::fs::read(&tmp)?;`（动机很自然 —— 落位前补一次大小复核）
    // 内存峰值就回到包体积、整个改造收益归零，而两条断言**全绿**。
    // 故改为禁掉「先把字节攒齐」这一族的全部入口。
    for banned in [
        "std::fs::read(",
        ".read(&tmp",
        "read_to_end(",
        "atomic_replace(",
        "verify_bytes(",
    ] {
        assert!(
                !body.contains(banned),
                "`{banned}` 属「整包入内存」族 —— 流式下载之后再把文件读回内存，本次改造的收益当场归零，\
                 而四条 gate 会全绿、行为完全正确，只有真机上几十 MiB 的内存峰值会告诉你"
            );
    }
}

/// 🟡 **调用点守卫：全程只碰 tmp，dest 只在最后一次 rename 时出现。**
///
/// dest 一旦被中途写入（哪怕只是 `open_write(&dest)` 建个空文件），并发单飞的**后到者**
/// 就会经 [`cached_download_is_reusable`] 读到一个半截包 —— 而它的判据是 sha256，
/// 半截包会被判「不可复用」从而重下，看起来还挺正常；真正的坏形态是 dest 上留下一个
/// 长度不对的文件，`update_install` 拿它去装。
///
/// **变异探针**：把 sink 的目标从 tmp 改成 dest ⇒ 白名单计数对不上 ⇒ 转红。
#[test]
fn streaming_download_only_ever_touches_the_tmp_path() {
    let body =
        crate::commands::guard_scan::top_level_fn_body(src(), "pub async fn update_download(");
    assert!(
        body.contains("verify::tmp_name(&dest)"),
        "tmp 必须由 `verify::tmp_name` 生成（同目录同卷 = 原子 rename 的前提）"
    );
    assert!(
        body.contains("open_write(&sink_path)")
            && body.contains("let sink_path = partial.path().to_path_buf()"),
        "写句柄必须指向 tmp（经 RAII 守卫持有的那条路径）"
    );

    // ── dest 侧改**白名单计数**（前身是单字面量黑名单 `!contains("open_write(&dest")`）──
    //
    // 黑名单挡不住同一语义的任何别的写法：`File::create(&dest)` / `StdFs.write(&dest, ..)` /
    // `open_write(dest.as_path())` 全都绕得过去，而后果一样 —— dest 上留下一个长度不对的文件，
    // `update_install` 拿它去装。故反过来：**列出 dest 的全部合法用法**，
    // 出现次数钉死；新增任何一处对 dest 的引用都必须显式改这张表，并在改的时候回答
    // 「它会不会在落位之前碰 dest」。
    const DEST_USES: [&str; 9] = [
        "let dest = dir.join(&file_name);",
        "let gate = download_gate(&dest);",
        "let dest = dest.clone();",
        "cached_download_is_reusable(&dest, sha.as_deref())",
        "dest.display()",
        "dest.to_string_lossy()",
        "verify::tmp_name(&dest)",
        "land_payload(&polaris_updater::traits::StdFs, partial.path(), &dest)",
        // 两处 `ProgressStage::Downloaded { path: &dest, .. }`（复用腿 / 落位成功腿）。
        // 逐条回答本白名单要求回答的那个问题：**都在落位之后**（复用腿的前提是
        // `cached_download_is_reusable` 已认下盘上那份完整包，落位腿在 `Landed` 臂内），
        // 且两处都只是**读**路径去拼事件载荷，一个字节都不写。
        "path: &dest,",
    ];
    /// dest 在 `update_download` 里的**总出现次数**（含上表每一项各自的出现次数之和）。
    const DEST_MENTIONS: usize = 13;
    let total = body.matches("dest").count();
    let covered: usize = DEST_USES
        .iter()
        .map(|p| body.matches(p).count() * p.matches("dest").count())
        .sum();
    assert_eq!(
        total, DEST_MENTIONS,
        "对 dest 的引用数变了（实得 {total}，钉死 {DEST_MENTIONS}）—— \
             新增/删除任何一处都必须显式改白名单，并复核它没有在落位之前碰 dest"
    );
    assert_eq!(
        covered, total,
        "出现了不在白名单里的 dest 用法（白名单覆盖 {covered} / 实得 {total}）—— \
             dest 必须从「不存在」瞬间变为「完整文件」，中途碰它就会让后到者读到半截包"
    );

    // ── `downloaded` 的位置：**降级为弱断言**（真正的门是运行时的
    //    `landing_reports_failure_and_leaves_dest_untouched_when_rename_fails`）。
    //
    // 文本下标比较表达不了「rename **成功**才发」：把落位失败的早退降级成「只 log 不早退」，
    // 文本序照样成立。故这里只钉一件文本层面**确实**表达得了的事：下载腿的 `downloaded`
    // 落在 `LandingOutcome::Landed` 那一支里。
    //
    // 注意 `downloaded` 在本函数里有**两个**合法产地：① 复用分支（文件已在盘且 sha256 复核过，
    // 此时根本没下载）② 本次下载落位成功之后。故不能拿首个匹配比大小 —— 那只会量到 ①。
    let landed_at = body
        .find("LandingOutcome::Landed =>")
        .expect("落位成功分支消失：守卫已失去判据");
    let download_began_at = body
        .find("emit(ProgressStage::Downloading {")
        .expect("锚点消失：守卫已失去判据");
    let downloaded_after_start: Vec<usize> = body
        .match_indices("ProgressStage::Downloaded {")
        .map(|(i, _)| i)
        .filter(|i| *i > download_began_at)
        .collect();
    assert!(
        !downloaded_after_start.is_empty(),
        "锚点消失：守卫已失去判据（下载腿一发 `downloaded` 都不发？）"
    );
    for at in downloaded_after_start {
        assert!(
                at > landed_at,
                "`downloaded` 必须落在 `LandingOutcome::Landed` 分支内（实得 Landed {landed_at} / downloaded {at}）"
            );
    }
}

/// 🟡 **调用点守卫：残件清理必须是**类型**（RAII），不是「数一数清理调用」。**
///
/// # 前身（计数守卫）为什么是假的
///
/// 它数「`ApiResponse::err(` 出现次数 == `discard_partial_download(&tmp)` 出现次数」。
/// 三条独立反例，每条都能让「漏清理」照样全绿：
///  1. 把落位失败的早退降级成「只 log 不早退」⇒ 两侧计数**同减**，仍相等；
///  2. 给一条早退配**两次**清理即可把另一条漏掉的配平；
///  3. 它**不匹配** `ApiResponse::err_with_code(` ⇒ tmp 之后新增一条带 code 且漏清理的早退，
///     守卫全盲。
///
/// 根因是它守错了对象：不变量是「控制流离开这个作用域时残件不在」——那是**作用域**的性质，
/// 计数表达不了。换成 [`PartialDownload`] 之后，`?` / panic / 将来新增的任何早退都自动覆盖，
/// 也就没有「配平」这回事。
///
/// 本条因此只守**形态**（真正的行为门是运行时的
/// [`partial_download_deletes_the_tmp_on_drop_and_keeps_it_after_disarm`]）：
///
/// **变异探针**：删掉 `PartialDownload::new(` ⇒ 第 1 条转红；把 `partial.disarm()` 挪出
/// `Landed` 分支（例如提到 match 之前，失败路径就不再清残件了）⇒ 第 3 条转红；
/// 再引入一个手工清理函数 ⇒ 第 2 条转红。
#[test]
fn the_partial_tmp_is_owned_by_an_raii_guard_not_by_counted_cleanup_calls() {
    let body =
        crate::commands::guard_scan::top_level_fn_body(src(), "pub async fn update_download(");
    assert!(
            body.contains("PartialDownload::new("),
            "残件必须由 RAII 守卫持有 —— 计数守卫守不住「离开作用域时残件不在」（三条反例见本测试文档）"
        );
    assert!(
        !body.contains("discard_partial_download("),
        "回到了手工清理 ⇒ 又要靠「每条早退都记得配一行」，而那正是被推翻的形态"
    );
    let disarms = body.matches("disarm()").count();
    assert_eq!(
        disarms, 1,
        "`disarm()` 只该有一处（落位成功那一支），实得 {disarms} 处 —— \
             多一处就意味着某条失败路径也把守卫解除了，残件从此无人清"
    );
    assert!(
        body.contains("LandingOutcome::Landed => {")
            && body[body
                .find("LandingOutcome::Landed => {")
                .expect("锚点消失：守卫已失去判据")..]
                .contains("partial.disarm()"),
        "`disarm()` 必须在**落位成功**分支内：提到分支之外（哪怕只是 match 之前一行），\
             落位失败时残件就不再被清"
    );
}

/// 🟡 **调用点守卫：`update_download` 的每一条失败早退都必须先发 `error` 进度事件。**
///
/// 弹窗被 `force progress(0)` 推进 Progress 后，只有 `error` / `downloaded` 能把它推出去；
/// 静默 return 会让它永远转圈（只剩 Cancel 可点）。原实现的三条前置校验早退正是这样。
///
/// 按**计数**锁而不是逐条锁：新增任何一条失败早退却忘了配一发 error 事件，
/// 两个计数立刻对不上 ⇒ 转红。
///
/// # 计数用**前缀** `ApiResponse::err`（2026-08-16 订正）
///
/// 前身数的是 `ApiResponse::err(` —— 它**不匹配** `ApiResponse::err_with_code(`（`err` 后面是
/// `_` 不是 `(`），于是新增一条带 code 的早退时守卫全盲。改成前缀后，代价是
/// BackendUnavailable 那条分支（一个 `match` 里两个 `ApiResponse::err*` **共用同一发**
/// error 事件）会被多数一次；把它作为**具名常数**扣掉，而不是把 `err_with_code` 排除在
/// 计数之外 —— 后者等于把射程重新缩回去。
#[test]
fn every_failure_path_emits_an_error_progress_event() {
    /// 「一条早退里出现两个 `ApiResponse::err*`、但只发一发 error 事件」的已知分支数。
    /// U1 起为 0：`BackendUnavailable` 分支改为自带一发 emit（与信封配对），其余早退
    /// 全部经 `fail` 闭包（emit + 信封在同一函数体内，结构性配对）。
    const SHARED_ERR_BRANCHES: usize = 0;

    let body =
        crate::commands::guard_scan::top_level_fn_body(src(), "pub async fn update_download(");
    let errors = body.matches("ApiResponse::err").count();
    let emits = body.matches("emit(ProgressStage::Failed(").count();
    assert!(errors > 0, "锚点消失：守卫已失去判据");
    assert_eq!(
        errors,
        emits + SHARED_ERR_BRANCHES,
        "失败信封 {errors} 处、error 进度事件 {emits} 发（另计 {SHARED_ERR_BRANCHES} 处共用分支）\
             —— 对不上的那条会让弹窗永远转圈"
    );
    // U1 后带 code 的信封是**常态**（fail 闭包 + Backend 分支各一），不再逐个数；
    // 配对改由结构保证：fail 闭包体内必须 emit 与 err_with_code 同体。
    assert!(
        body.contains("let fail = |e: UpdateErr<'_>|"),
        "fail 统一出口被改形 —— 它体内 emit+信封的配对是本守卫的前提"
    );
}

// ── 随行事实：态与它依赖的数据同帧同行 ──────────────────────────────────

/// 🟡 **行为门：每一帧都带着它那个态所依赖的全部随行事实。**
///
/// `update:progress` 走 `events::broadcast` fan-out 给**所有**窗口 ⇒ 把设置页推进
/// downloading / downloaded / error 的路径大多**不是设置页发起的**（启动自动下载腿
/// `startup_tasks::spawn_auto_download`、弹窗「更新·重试」腿 `update_popup_action`），
/// 那几条腿上设置页拿不到任何 invoke 回包 ⇒ 这一帧是它**唯一**的事实来源。少一样就静默
/// 少一样：已核实的三条后果是「重启并安装」哑键（无 `filePath`）、「重试」哑键
/// （无 `updateInfo`）、卡片上的版本号与体积写的是上一次检查的另一个版本。
///
/// # 判据由**类型**穷尽，不由夹具点名
///
/// 「哪个变体该带哪些键」写在 `required` 的穷尽 `match` 里 ⇒ [`ProgressStage`] 新增变体
/// **编译不过**，作者必须回到这里显式回答它带得起哪些事实。
///
/// 「样本有没有覆盖到每个变体」则由**从源码派生的臂数**兜底，不是手写常数：前身写
/// `assert_eq!(samples.len(), VARIANTS)`（两个手写数字互比），2026-08-17 复审实测 ——
/// 加第 4 变体 + 补齐两处生产 match + **只**补一条 `required` 臂、不动样本 ⇒ 全量 4181 全绿，
/// 那个变体的载荷一次都没跑过。现改为数 [`stage_facts`] 那个**编译器强制穷尽**的 match
/// 有几条臂，臂数即变体数，两个数字都不再由人手维护。
/// 每格还反向断言「白名单之外不得夹带」——两个方向合起来是**逐变体的集合相等**，
/// 而不是「至少有这几个键」这种只挡得住删除的弱判据。
///
/// 跨语言那一半（Rust 键集 ↔ TS `UpdateProgress` 字段集）由
/// `ui/src/contracts/update-progress-payload.test.ts` 双向对拍，与本门正交。
///
/// **变异探针**：删掉 `payload["filePath"] = …` ⇒ Downloaded 那格转红；把
/// `"updateInfo": info` 换成 `Value::Null` ⇒ 三格同时转红；把 `Downloaded` 的百分比从
/// 100 改成别的 ⇒ 转红；多写一个键 ⇒ 「夹带」那条转红。
#[test]
fn progress_frame_carries_the_facts_its_state_depends_on() {
    /// 每个变体的帧里**必须**存在、且不得多于此的键（穷尽 match ⇒ 新增变体即编译错误）。
    ///
    /// 逐字段解构（不写 `..`）：给已有变体加字段时这里也必须表态，否则「加变体被挡住了、
    /// 加字段没有」那个不对称会从生产代码搬到门里来。
    const fn required(stage: ProgressStage<'_>) -> &'static [&'static str] {
        match stage {
            ProgressStage::Downloading {
                percentage: _,
                received: _,
            } => &["status", "percentage", "updateInfo", "receivedBytes"],
            ProgressStage::Downloaded {
                path: _,
                verified: _,
            } => &["status", "percentage", "updateInfo", "filePath", "verified"],
            ProgressStage::Failed { .. } => &[
                "status",
                "percentage",
                "errorCode",
                "errorDetail",
                "updateInfo",
            ],
        }
    }

    /// [`ProgressStage`] 的变体数，**从源码派生**：[`stage_facts`] 的 match 由编译器强制
    /// 穷尽 ⇒ 它有几条臂就有几个变体。数 `ProgressStage::` 而不数 `=>`：签名里的
    /// `ProgressStage<'a>` 不含冒号，不会被误计。
    ///
    /// 射程边界（如实登记，两条）：
    ///  1. 臂头若写成 or-pattern（`A::X { .. } | A::Y { .. } =>`），本计数会**高于**臂数
    ///     ⇒ 断言转红（安全方向：宁可误红也不放过没样本的变体）。
    ///  2. **给 `stage_facts` 与 `required` 同时补一条 `_ => …` 通配臂时，本门静默失效**：
    ///     计数停在通配那一刻的臂数，而 `match` 也不再被编译器强制穷尽 ⇒ 新变体既不编译红、
    ///     也不被本门抓到。今天两处都是穷举、无通配臂，故不可达；谁要加通配臂，请连同本门
    ///     一起重新设计判据（通配臂本身就是「新变体不必表态」的宣言）。
    fn variant_count() -> usize {
        // 锚取无泛型的前缀（U1 起 stage_facts 不再带生命周期参数；锚写死旧签名会在
        // 「锚消失」时掉进下方测试模块的字面量自匹配——本函数自己的锚串就在那）。
        let body = crate::commands::guard_scan::top_level_fn_body(src(), "const fn stage_facts(");
        let n = body.matches("ProgressStage::").count();
        assert!(
                n >= 3,
                "`stage_facts` 的臂形状变了（一条 ProgressStage:: 臂都没解析到）—— 本门已失去变体数的真值源"
            );
        n
    }

    let path = std::path::Path::new("/tmp/updates/polaris.dmg");
    let info = json!({
        "version": "v1.2.0",
        "fileSize": 52_000_000_u64,
        "isPrerelease": true,
        // 两个**必须被剥掉**的字段：样本里没有它们，下面那条「剥掉了」的断言就无信息量。
        "releaseNotes": "## v1.2.0\n- 大段更新说明……",
        "title": "Polaris v1.2.0",
        // 契约将来加字段时，这一格证明其余字段是**原样**带过去的，不是被逐字段抄了一遍。
        "futureField": "kept",
    });
    // 期望的投影：从样本清单里**逐个删掉**登记为剥除的键，其余一个不动。
    // 表驱动 ⇒ 剥除表加一项时，本断言的两个方向（该没的没了、该在的逐字还在）自动跟着长。
    let expected_manifest = {
        let mut m = info.as_object().expect("样本清单必须是对象").clone();
        for key in PROGRESS_MANIFEST_OMITTED {
            assert!(
                m.remove(key).is_some(),
                "样本清单里没有 `{key}` ⇒ 「它被剥掉了」这条断言无信息量（假绿）"
            );
        }
        Value::Object(m)
    };

    let samples = [
        ProgressStage::Downloading {
            percentage: 37,
            received: 19_240_000,
        },
        ProgressStage::Downloaded {
            path,
            verified: true,
        },
        ProgressStage::Failed(UpdateErr::with_detail(
            UpdateErrCode::DownloadFailed,
            "net down",
        )),
    ];
    let variants = variant_count();
    assert_eq!(
        samples.len(),
        variants,
        "样本表没跟上变体数（`stage_facts` 有 {variants} 条臂）—— 新增的那个变体的载荷一次都没跑过"
    );
    let tags: std::collections::BTreeSet<&str> =
        samples.iter().map(|s| stage_facts(*s).0).collect();
    assert_eq!(
        tags.len(),
        samples.len(),
        "样本里有重复变体 —— 有一格根本没被测到"
    );

    for stage in samples {
        let (status, percentage) = stage_facts(stage);
        let payload = progress_payload(&info, stage);
        let obj = payload.as_object().expect("载荷必须是 JSON 对象");
        for key in required(stage) {
            assert!(obj.contains_key(*key), "{status} 帧缺随行事实 `{key}`");
            assert!(!obj[*key].is_null(), "{status} 帧的 `{key}` 是 null");
        }
        let extra: Vec<&String> = obj
            .keys()
            .filter(|k| !required(stage).contains(&k.as_str()))
            .collect();
        assert!(extra.is_empty(), "{status} 帧夹带了未登记的键: {extra:?}");
        assert_eq!(obj["status"], json!(status));
        assert_eq!(obj["percentage"], json!(percentage));
        // 「剥掉的真没了」——先单独判，失败消息才指得出是哪个字段。
        for key in PROGRESS_MANIFEST_OMITTED {
            assert!(
                obj["updateInfo"].get(key).is_none(),
                "{status} 帧仍带着 `{key}` —— 它无上限且 progress 可达态一律不渲染，\
                     每帧广播给所有窗口是纯粹的主线程开销"
            );
        }
        // 「该在的逐字还在」——**整对象相等**，不是「有几个字段」：少带一个字段就是
        // 「重试」重新变哑键 / 卡片又开始显示别的版本，正是本批立项要修的那三条。
        assert_eq!(
            obj["updateInfo"], expected_manifest,
            "{status} 帧的清单投影与「原样减去剥除表」不符 —— 卡片会拿它渲染版本号/体积/档次，\
                 「重试」也要拿它重下"
        );
    }

    // 逐值对账（上面只管「在不在」，这里管「是不是那个数」）。
    let landed = progress_payload(
        &info,
        ProgressStage::Downloaded {
            path,
            verified: false,
        },
    );
    assert_eq!(landed["filePath"], json!(path.to_string_lossy()));
    assert_eq!(landed["verified"], json!(false));
    assert_eq!(landed["percentage"], json!(100), "落位帧的百分比由类型定死");
    let mid = progress_payload(
        &info,
        ProgressStage::Downloading {
            percentage: 37,
            received: 19_240_000,
        },
    );
    assert_eq!(
        mid["receivedBytes"],
        json!(19_240_000),
        "已收字节必须是回调原值 —— 从百分比反推的数每一帧都是错的"
    );
    let failed = progress_payload(
        &info,
        ProgressStage::Failed(UpdateErr::with_detail(
            UpdateErrCode::DownloadFailed,
            "net down",
        )),
    );
    assert_eq!(failed["errorCode"], json!("downloadFailed"));
    assert_eq!(failed["errorDetail"], json!("net down"));
    // 无细节的那发不夹带 errorDetail（None 不进载荷，前端按可选处理）。
    let bare = progress_payload(
        &info,
        ProgressStage::Failed(UpdateErr::new(UpdateErrCode::DownloadFailed)),
    );
    assert!(bare.get("errorDetail").is_none());
    assert_eq!(failed["percentage"], json!(0), "失败帧的百分比由类型定死");
}

/// 🟡 **调用点守卫：本次下载的随行事实只由一处附着。**
///
/// `update_download` 里有十余处发进度的地方（每条失败早退各一发 + 三处正常帧）。若每处
/// 各自调 `emit_progress(&app, <某个清单>, …)`，失守形态有二：漏传（编译红，无所谓）与
/// **传成另一个对象**（编译绿、gate 全绿，而设置页显示的版本号是别的包的）。故本函数体内
/// `emit_progress(` 只许出现一次 —— 就是那条把 `update_info` 绑死的闭包定义本身。
///
/// 中间帧（下载回调）跑在另一个线程上、借不了栈，故它经 `download_progress_emitter` 按值
/// 收清单；本门连带钉住它收的是**同一份** `update_info`。
///
/// **变异探针**：把任一处 `emit(ProgressStage::Failed(&msg))` 改回
/// `emit_progress(&app, &Value::Null, ProgressStage::Failed(&msg))` ⇒ 计数变 2 ⇒ 转红；
/// 把 `download_progress_emitter(&app, update_info.clone())` 的第二个实参换成
/// `Value::Null` ⇒ 转红。
#[test]
fn every_progress_frame_of_this_download_carries_this_downloads_manifest() {
    let body =
        crate::commands::guard_scan::top_level_fn_body(src(), "pub async fn update_download(");
    assert!(
        body.contains(
            "let emit = |stage: ProgressStage<'_>| emit_progress(&app, &update_info, stage);"
        ),
        "单一发事件入口没了 —— 十余个调用点各自带清单，迟早有一处带成另一个版本的"
    );
    let direct = body.matches("emit_progress(").count();
    assert_eq!(
        direct, 1,
        "`emit_progress(` 在本函数里出现 {direct} 次（只该是那条闭包定义）—— \
             绕过 `emit` 直发就等于给这一处附着的清单开了个后门"
    );
    // 正向对照：三种帧确实都还在发（否则上面那条在「一发都不发」时也绿）。
    for anchor in [
        "emit(ProgressStage::Downloading {",
        "emit(ProgressStage::Downloaded {",
        "emit(ProgressStage::Failed(",
    ] {
        assert!(
            body.contains(anchor),
            "锚点消失：守卫已失去判据（{anchor}）"
        );
    }
    assert!(
        body.contains("download_progress_emitter(&app, update_info.clone())"),
        "中间帧的清单必须是**同一份** `update_info` —— 另造一个对象会让下载中卡片的\
             版本号与首尾两帧不符"
    );
}

// ── 残件所有权：RAII（H1）───────────────────────────────────────────────

/// 🟡 **运行时门：drop 即删；`disarm` 之后 drop 什么都不删。**
///
/// 这是把「失败即清理」从**源码计数**换成**类型**之后，真正有牙的那条门 ——
/// 它测的是行为（离开作用域时文件在不在），不是「代码里写没写那一行」。
///
/// **变异探针**：删掉 `impl Drop for PartialDownload` ⇒ 第 1 条转红；
/// 把 `disarm` 改成不置 `None`（或直接删掉这个方法体的赋值）⇒ 第 2 条转红
/// （落位成功后会把刚下好的包删掉）。
#[test]
fn partial_download_deletes_the_tmp_on_drop_and_keeps_it_after_disarm() {
    let dir = scratch("partial-raii");

    // ① 未解除 → drop 即删（= 每一条失败早退）。
    let armed = dir.join("armed.pkg.polaris-new-1-0");
    std::fs::write(&armed, b"half-written").unwrap();
    {
        let guard = PartialDownload::new(armed.clone());
        assert_eq!(guard.path(), armed, "守卫必须原样交出它持有的那条路径");
        assert!(armed.is_file(), "守卫存活期间不得提前删");
    }
    assert!(
        !armed.exists(),
        "守卫 drop 后残件必须消失 —— 否则每次下载失败都在缓存目录里攒一个几十 MiB 的垃圾"
    );

    // ② 已解除 → drop 什么都不做（= 落位成功，那个 inode 现在叫 dest 了）。
    let landed = dir.join("landed.pkg");
    std::fs::write(&landed, b"complete").unwrap();
    PartialDownload::new(landed.clone()).disarm();
    assert!(
        landed.is_file(),
        "disarm 之后 drop 绝不能删 —— 那删掉的是刚落位成功的更新包本身"
    );
    assert_eq!(std::fs::read(&landed).unwrap(), b"complete");

    // ③ 文件本来就不存在（「还没来得及建就失败」）→ drop 不得 panic。
    drop(PartialDownload::new(dir.join("never-created")));
}

// ── 落位：可注入的运行时判据（H2）──────────────────────────────────────

/// 🟡 **运行时门：rename 失败 ⇒ `Failed` 且 dest 不存在；成功 ⇒ `Landed` 且 tmp 消失。**
///
/// 这条替掉的是一条**表达不了自己声称之事**的文本守卫（`promote_at < downloaded_at` 的下标
/// 比较）：把落位失败的早退降级成「只 log 不早退」，文本序照样成立，而运行时会广播
/// `downloaded(100)` 外加一个根本不存在的 `filePath`。
///
/// [`land_payload`] 吃 `&dyn UpdateFs` ⇒ 可注入 `MockFailOp::Rename`，
/// 于是「rename 成功才算落位」变成一条真跑得起来的断言。
///
/// **变异探针**：把 [`land_payload`] 的 `Err(e) =>` 改成 `Ok(())` 一样返回
/// `LandingOutcome::Landed`（即「只 log 不早退」那个降级）⇒ 第 1 条转红。
#[test]
fn landing_reports_failure_and_leaves_dest_untouched_when_rename_fails() {
    use polaris_updater::traits::{MockFailOp, MockFs, StdFs};

    let dir = scratch("landing");

    // ① rename 失败 → Failed(_)，且 dest **不存在**（绝不广播一个不存在的 filePath）。
    let dest_fail = dir.join("fail.pkg");
    let tmp_fail = polaris_updater::verify::tmp_name(&dest_fail);
    std::fs::write(&tmp_fail, b"streamed").unwrap();
    let mut fs = MockFs::new(&dir);
    fs.fail_next(MockFailOp::Rename);
    let outcome = land_payload(&fs, &tmp_fail, &dest_fail);
    assert!(
        matches!(outcome, LandingOutcome::Failed(_)),
        "rename 失败必须报 Failed，实得 {outcome:?}"
    );
    assert!(
        !dest_fail.exists(),
        "落位失败时 dest 必须仍不存在 —— 否则 `update_install` 会拿一个半截文件去装"
    );
    if let LandingOutcome::Failed(msg) = outcome {
        assert!(
            msg.contains("rename to"),
            "失败文案须与同文件其它早退一致：{msg}"
        );
    }

    // ② 成功 → Landed，dest 是完整内容，tmp 消失。
    let dest_ok = dir.join("ok.pkg");
    let tmp_ok = polaris_updater::verify::tmp_name(&dest_ok);
    std::fs::write(&tmp_ok, b"streamed-bytes").unwrap();
    assert_eq!(
        land_payload(&StdFs, &tmp_ok, &dest_ok),
        LandingOutcome::Landed
    );
    assert_eq!(std::fs::read(&dest_ok).unwrap(), b"streamed-bytes");
    assert!(!tmp_ok.exists(), "落位成功后 tmp 必须已被 rename 掉");
}

/// 🟡 **运行时门：rename **之前**必须先 `fsync`；刷盘失败 ⇒ `Failed` 且 dest 不存在。**
///
/// 没有这一步时，rename 只保证目录项的原子替换，不保证那个 inode 的**数据**已离开 page
/// cache ⇒ 断电/内核崩溃后可能出现「dest 名字在、内容是零或半截」，而 dest 一旦存在
/// [`update_install`] 就会**直接拿去装**。
///
/// **变异探针**（2026-08-17 逐条实测，两条各红一处、互不重叠）：
///  - 删掉 `land_payload` 里的 `sync_file` 调用（或把失败改成「只 log 不早退」）
///    ⇒ **第 1 条**转红（注入的刷盘失败无处可发，结论成了 `Landed`）；
///  - 把 `sync_file` 挪到 `promote_staged` **之后** ⇒ **第 2 条**转红（结论仍是 `Failed`，
///    但 rename 已经发生 ⇒ dest 已存在）。顺序因此也在射程内，不是只靠注释声明。
///
/// **不是探针、是运行期后果**（本仓 CI 只跑 Linux/macOS/Windows 的 64 位构建，但**没有**
/// 任何门会因它转红，故不列在上面）：把
/// [`StdFs::sync_file`](polaris_updater::traits::StdFs) 的 `OpenOptions::write(true)`
/// 改成 `File::open`（只读句柄），Linux 上照常绿，**Windows 上落位会全线失败** ——
/// `FlushFileBuffers` 对只读句柄直接报错。这条只能靠 trait 文档里的那句约束守住。
#[test]
fn landing_fsyncs_the_payload_before_renaming_it_into_place() {
    use polaris_updater::traits::{MockFailOp, MockFs};

    let dir = scratch("landing-fsync");
    let dest = dir.join("synced.pkg");
    let tmp = polaris_updater::verify::tmp_name(&dest);
    std::fs::write(&tmp, b"streamed").unwrap();

    let mut fs = MockFs::new(&dir);
    fs.fail_next(MockFailOp::SyncFile);
    // 残件的清理归 RAII 守卫（`land_payload` 自己不删）——照生产的形态过一遍：
    // 失败分支**不** disarm，守卫在离开作用域时把 tmp 收掉。
    let outcome = {
        let partial = PartialDownload::new(tmp.clone());
        land_payload(&fs, partial.path(), &dest)
    };

    assert!(
        matches!(outcome, LandingOutcome::Failed(_)),
        "刷盘失败必须报 Failed（内容可能还在 page cache 里），实得 {outcome:?}"
    );
    assert!(
        !dest.exists(),
        "刷盘失败时绝不能已经 rename —— dest 一旦存在就会被 `update_install` 当成完整包"
    );
    assert!(
        !tmp.exists(),
        "失败路径上的残件必须由 RAII 守卫收掉（`land_payload` 不负责删）"
    );
}

// ── 孤儿 tmp 清扫（H3）──────────────────────────────────────────────────

/// 把文件的 mtime 往前拨 `age`（测跨进程残件的 24h 阈值；不引第三方 crate）。
fn backdate(path: &std::path::Path, age: std::time::Duration) {
    let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    f.set_modified(std::time::SystemTime::now() - age).unwrap();
}

/// 🟡 **运行时门：本资产 + 本 pid 的孤儿直接收；其余一律只按 mtime 阈值收；无关文件不碰。**
///
/// 主触发器是「下载途中退出 App」：`update_download` 是 async command，tmp 建立后唯一的
/// await 点是 `spawn_blocking(...).await`，退出 App 会让 runtime **drop 掉那个 future** ⇒
/// RAII 守卫连同三条早退全被绕过，而 blocking 线程不可取消、可能把 tmp 写完。开着
/// `autoDownloadUpdate` 时每个「启动 → 后台下载 → 提前关 App」周期必留一个几十 MiB 的孤儿，
/// 而唯一的回收点是完全卸载。
///
/// # 第 ⑤ 条已**反向**（2026-08-17）
///
/// 它原先钉的是「别的资产的残件不归本次清扫管」—— 而那正是缺陷本身：App 更新的资产名带版本号，
/// 版本一换前缀就变，于是上面那个主触发器留下的残件（必然是**旧版本名**）永远收不回来。
/// 现在钉的是「别资产残件：新鲜保留、陈旧收」，并由第 ⑥ 条做真实缺陷回放。
///
/// **变异探针**（2026-08-17 逐条实测，末条原写「去掉它 ⇒ 第 4 条转红」是错的）：
/// 把本资产+本 pid 那一档也改成走 mtime 阈值 ⇒ 第 1 条转红；
/// 把匹配面缩回 `{file_name}.polaris-new-` ⇒ 第 6 条转红（旧版本名的陈旧残件又收不回来了）；
/// 把即时档改成只看 pid、不看资产名 ⇒ 第 5 条转红；
/// 把 `>= ORPHAN_TMP_MAX_AGE` 改成 `<` ⇒ 第 2、3、5、6 条同时转红。
///
/// `is_orphan_tmp_name` 无论**放宽成「只看中缀」还是整个去掉**，转红的都是**第 7 条**，
/// 不是第 4 条：第 4 条的 `dest` 夹具是新鲜写的，判据没了它只是落进 mtime 档 → 保留 → 仍绿。
/// 真正被这条判据护住的是「陈旧的非 tmp 文件」，而夹具里那个正是 `not_a_tmp`。
#[test]
fn orphan_sweep_collects_only_what_it_can_prove_is_abandoned() {
    use polaris_updater::traits::StdFs;

    let dir = scratch("orphan-sweep");
    let file_name = "polaris-0.2.0.dmg";
    let pid = std::process::id();

    // ① 本资产 + 本进程留下的残件：调用点在单飞闸内 ⇒ 此刻绝无第二条腿在写它 ⇒ 直接收（不看 mtime）。
    let mine = dir.join(format!("{file_name}.polaris-new-{pid}-7"));
    // ② 其它进程 + 陈旧（> 24h）：跨进程兜底，收。
    let stale = dir.join(format!("{file_name}.polaris-new-{}-0", pid.wrapping_add(1)));
    // ③ 其它进程 + 新鲜：可能正有另一个实例在写 ⇒ **不收**（失败安全的那一侧）。
    let fresh = dir.join(format!("{file_name}.polaris-new-{}-1", pid.wrapping_add(2)));
    // ④ 落位好的成品：绝不能碰。
    let dest = dir.join(file_name);
    // ⑤ 别的资产名 + 新鲜：**保留**。单飞闸只按 dest 串行，管不到别的资产名 ——
    //    本进程完全可能有另一条腿正在下它，故别资产不许走即时档（哪怕 pid 是自己的）。
    let other_fresh = dir.join(format!("polaris-0.1.9.dmg.polaris-new-{pid}-0"));
    // ⑥ **真实缺陷回放**：上次运行下到一半被关掉，留下的是**旧版本名**的残件（资产名含版本号，
    //    这次要下的是新版本 ⇒ 前缀必然不同）。陈旧了就必须收，否则每次版本更迭攒一个几十 MiB
    //    的垃圾，直到完全卸载才回收。
    let stale_old_version = dir.join(format!(
        "polaris-0.1.9.dmg.polaris-new-{}-4",
        pid.wrapping_add(3)
    ));
    // ⑦ 含中缀但**形态不符**（`{pid}-{seq}` 不是纯数字）：不是 `tmp_name` 的产物，一律不碰。
    let not_a_tmp = dir.join("notes.polaris-new-draft");

    for p in [
        &mine,
        &stale,
        &fresh,
        &dest,
        &other_fresh,
        &stale_old_version,
        &not_a_tmp,
    ] {
        std::fs::write(p, b"x").unwrap();
    }
    let over_age = ORPHAN_TMP_MAX_AGE + std::time::Duration::from_secs(60);
    backdate(&stale, over_age);
    backdate(&stale_old_version, over_age);
    backdate(&not_a_tmp, over_age); // 陈旧也不该被收：判据是命名形态，不是年龄
    backdate(&mine, std::time::Duration::from_secs(1)); // 新鲜也照收（判据是 pid 不是时间）

    sweep_orphan_downloads(&StdFs, &dir, file_name);

    assert!(
        !mine.exists(),
        "本资产 + 本进程留下的残件必须被收（闸已保证无人在写它）"
    );
    assert!(!stale.exists(), "超过 24h 的跨进程残件必须被收");
    assert!(
        fresh.exists(),
        "新鲜的跨进程残件必须保留 —— 另一个实例可能正在写它，而 pid 存活探测跨平台不可靠"
    );
    assert!(dest.exists(), "落位好的更新包绝不能被当成残件删掉");
    assert!(
        other_fresh.exists(),
        "别的资产名的**新鲜**残件必须保留 —— 单飞闸只按 dest 串行，管不到别的资产名"
    );
    assert!(
        !stale_old_version.exists(),
        "旧版本名的陈旧残件必须被收 —— 资产名含版本号，只收本次资产名等于这条腿永不回收"
    );
    assert!(
        not_a_tmp.exists(),
        "含 `.polaris-new-` 但不是 `{{pid}}-{{seq}}` 形态的文件不是清扫的对象"
    );

    // 交叉核对：上面五个夹具的名字是**手搓**的，与 `sweep_orphan_downloads` 的前缀判据同出一人
    // ⇒ 二者可以互相印证却**双双跑偏于真实命名**（`verify::tmp_name` 改个后缀就全盲）。
    // 故再用真产物过一遍：这条是「判据被自己污染」的唯一报警。
    let real_tmp = polaris_updater::verify::tmp_name(&dest);
    std::fs::write(&real_tmp, b"x").unwrap();
    sweep_orphan_downloads(&StdFs, &dir, file_name);
    assert!(
        !real_tmp.exists(),
        "`verify::tmp_name` 的真实产物落在清扫的前缀判据之外 —— 手搓夹具全绿也没有意义"
    );
    assert!(dest.exists(), "第二次清扫同样不得碰成品");

    // 目录不存在也不得 panic（best-effort，绝不改变本次下载的结论）。
    sweep_orphan_downloads(&StdFs, &dir.join("nope"), file_name);
}

/// 🟡 **调用点守卫：清扫必须夹在「拿到单飞闸」与「生成本次 tmp」之间。**
///
/// 两侧都是硬要求：
///  - 早于闸 ⇒ 本进程可能有另一条腿正在写同名 tmp，那一档是**不看 mtime 直接删**的，会删掉在飞的下载；
///  - 晚于 `tmp_name` ⇒ 本次自己的 tmp 也带着本进程 pid，会被当场删掉。
///
/// **变异探针**：删掉调用 / 挪到 `gate.lock()` 之前 / 挪到 `verify::tmp_name(&dest)` 之后
/// ⇒ 逐条转红。
#[test]
fn orphan_sweep_runs_inside_the_gate_and_before_this_download_stages_its_tmp() {
    let body =
        crate::commands::guard_scan::top_level_fn_body(src(), "pub async fn update_download(");
    let lock_at = body
        .find("gate.lock().await")
        .expect("锚点消失：守卫已失去判据");
    let sweep_at = body.find("sweep_orphan_downloads(").expect(
        "孤儿清扫被删了 —— 下载途中退出 App 会绕过 RAII 守卫，每个周期攒一个几十 MiB 的残件",
    );
    let tmp_at = body
        .find("verify::tmp_name(&dest)")
        .expect("锚点消失：守卫已失去判据");
    assert!(
        lock_at < sweep_at,
        "清扫必须在单飞闸**之内**（实得 lock={lock_at} / sweep={sweep_at}）：\
             闸外清扫会删掉本进程另一条腿正在写的 tmp"
    );
    assert!(
        sweep_at < tmp_at,
        "清扫必须在生成本次 tmp **之前**（实得 sweep={sweep_at} / tmp={tmp_at}）：\
             之后清扫会把自己这一次的 tmp 当孤儿删掉"
    );
}

/// 🟡 **调用点守卫：复查回来「没有可下的东西」时，既不广播假的 `downloaded`，也不对弹窗
/// 自己谎称「已下载」。**
///
/// # 这道门此前只守住了一半
///
/// 旧判据是「函数体里必须出现 `push_popup_state(&app, UpdatePopupState::done())`」+「函数体里
/// 不得出现 `ProgressStage::Downloaded`」。它守的是**广播给设置页的那一份**（后半条），而
/// 前半条**要求**把 `done()` 推给弹窗自己 —— 于是「一个字节都没下」在发起本次动作的那一屏上
/// 被渲染成 `updatePopup.downloaded`（「下载完成」）+ 满格进度条。门在，守的方向漏了发起方。
///
/// 新判据把「推出 progress」与「推的是哪一档」拆开：仍必须把弹窗推出 progress（否则永远转圈），
/// 但那一档必须是 `no_update`；`done` 在本臂**一次都不许出现**。`UpdatePopupState::done` 现在
/// 是必填落位路径的构造函数，本臂根本没有路径可传 —— 源码门与类型闸在此重合，两道都留着：
/// 类型挡「拿不出路径」，本门挡「随手编一个路径喂给它」。
///
/// # 判据必须收到**分支**，臂一级还不够
///
/// 射程收紧走过三级，每一级都是被同一形态咬出来的（「取材面宽于意图面」）：
///  1. **整函数**：把推送搬进别的臂就能替本臂作证 —— 本仓在同一个函数上栽过两次
///     （见 `guard_scan::match_arm_body` 文档）。
///  2. **臂**（`match_arm_body`）：仍不够。`Update | Retry` 臂内有 **5 条早退分支**，而
///     `arm.contains(…)` 只问「臂内某处有没有这句话」。实测：把本分支的推送**整个删掉**
///     （⇒ 弹窗永远停在 progress 转圈，正是本门自称要防的那件事）、把它挪进下面的
///     `Renegotiate` 分支 ⇒ **全仓 1428 passed / 0 failed，本门全绿**。
///  3. **分支**（现判据）：用**位置区间**钉死 —— 那两发推送的 offset 必须落在
///     「`let Some(info) = data.get("updateInfo")` 这一行」与「本分支自己的
///     `"hasUpdate": false` 早退」之间。同款先例见本文件
///     [`the_user_action_forces_the_popup_into_progress_before_rechecking`] 的 `force_at < check_at`。
///
/// 「我要判的是什么位置的什么形状」：形状 = 那两发推送，位置 = **那一条 `let-else` 的 else 体内**。
/// 计数不是位置（把推送搬进 helper 里计数纹丝不动），故这里判的是区间不是次数；但两个锚点
/// 各自的**唯一性**要单独断言，否则「区间」本身可以被第二处同名锚点重新划定。
///
/// 负向断言（不得广播 `ProgressStage::Downloaded`）**故意保持全函数**：任何一条臂都不许广播，
/// 那是更强的形态，与 `recheck_failures_settle_the_popup_without_broadcasting` 同一取向。
/// `done(` 的负向断言保持**臂级**：本臂任何一条分支都不许推 done，同样严于分支级。
///
/// **变异探针**：把 `no_update(...)` 改回 `done(popup.version.clone(), "")` ⇒ 转红；
/// 把两发推送挪进 `Renegotiate` 分支 ⇒ 区间判定转红（臂级判据在此**全绿**，见上面第 2 条）；
/// 把它挪进 `ViewLog` 臂 ⇒ 臂内找不到，转红。
#[test]
fn the_no_download_path_never_claims_a_download() {
    let body =
        crate::commands::guard_scan::top_level_fn_body(src(), "pub async fn update_popup_action(");
    let arm = crate::commands::guard_scan::match_arm_body(
        &body,
        "PopupAction::Update | PopupAction::Retry =>",
        "PopupAction::",
    );

    // ── 区间的两个端点：先证明它们各自唯一，否则「落在区间内」可以被第二处锚点重新划定 ──
    const BRANCH_HEAD: &str = "let Some(info) = data.get(\"updateInfo\")";
    const BRANCH_EXIT: &str = "\"hasUpdate\": false";
    // 🟡 #3（confirm 轮登记）：`BRANCH_EXIT` 曾要求**全臂恰 1**——正当的分支细分（把 no-update
    // 拆成「平台不受支持」与「其它」，两边都各自 `hasUpdate:false` 早退）会误红。安全方向，
    // 但留给后人的最省事修法就是把判据放宽跑 —— 这里先行改到**不随细分复制**的形态：
    // 头锚保持恰 1（let-else 那一行不该重样）；尾锚取**最后一次**出现且至少一次，区间 =
    // 头..最后一次。细分出的每一条子分支都被区间罩住，推送落在任一条里都判绿。
    // ⚠️ 残余缺口如实登记（相对「恰 1」版弱了一格，复审 F3 校正口径）：推送若被挪进
    // `updateInfo` **存在**的路径、且其后还存在更晚的 `hasUpdate:false`，旧判据会红、新判据
    // 不红。**没有自动姊妹门覆盖这个缺口**（本臂三道门都不钉「no_update 推送必须在该
    // 分支」），暴露途径只剩 code review 与真机（转圈窗）；补门方向 = 对 else 块子区间
    // 逐分支计数 no_update 推送 ≥1——真被咬到再做。
    // 锚点先收集后断言（🟢#7/F4 的修法，消灭 n=0 误归因与两条不可达 expect）。
    let heads: Vec<usize> = arm.match_indices(BRANCH_HEAD).map(|(i, _)| i).collect();
    assert!(
        !heads.is_empty(),
        "头锚 {BRANCH_HEAD:?} 在本臂里一次都没有 —— let-else 的形状变了，守卫失去判据"
    );
    assert_eq!(
        heads.len(),
        1,
        "头锚 {BRANCH_HEAD:?} 在本臂里出现 {} 处 —— let-else 那一行被复制了，\
             「落在分支内」这句话就不再指同一段代码",
        heads.len()
    );
    let head = heads[0];
    let exits: Vec<usize> = arm.match_indices(BRANCH_EXIT).map(|(i, _)| i).collect();
    assert!(
        !exits.is_empty(),
        "尾锚 {BRANCH_EXIT:?} 在本臂里一次都没有 —— no-update 早退的形状变了，守卫失去判据"
    );
    let exit = *exits.last().unwrap();

    // ── 那两发推送必须落在这条 `let-else` 的 else 体内 ──
    for (needle, why) in [
            (
                "push_popup_state(&app, UpdatePopupState::no_update(",
                "「没有可下的东西」仍须把弹窗推出 progress（否则永远转圈），且必须推 `no_update` 那一档",
            ),
            (
                "schedule_popup_auto_close(&app, NO_UPDATE_AUTO_CLOSE_MS)",
                "`noupdate` 终态没有排自动关窗，或沿用了 done 的 800ms —— 后者一闪而过，等于没说",
            ),
        ] {
            // 🔴 唯一性断言（confirm 轮 #2 的修法）：`top_level_fn_body` 只剥**整行**注释
            // （射程在 `commands.rs:47-50` 登记），**行尾注释携带同形串可以喂饱 `find`**。
            // 剥行尾注释要先认字符串字面量（`commands.rs:51-53` 既有裁决：不划算），故两层兜：
            //   ① `count == 1`：真调用 + 注释各一份 ⇒ 计数 2 ⇒ 红；
            //   ② 行级拒绝：命中的那一行若 needle 之前就有 `//`（= needle 落在行尾注释里）不算数
            //      ——「删掉真调用、只留一行注释」时计数仍 1，①抓不住，②让「找不到真调用」转红
            //      （confirm 轮原始收据正是这个形态）。
            // ② 的真实射程（复审 F2 校正口径，别照旧登记读反）：**未设防面 = 同形串出现在无先行
            // `//` 的任何非调用文本里**（典型：字符串字面量 `let s = "push_popup_state(…"` 且真调用
            // 已删 ⇒ ①计数 1、②当真 ⇒ 假绿——要防得认字符串=parser，不做）；串内带 `//` 且在
            // 同形串之前的形态反而会被 ② 拒绝转红（安全方向，panic 文案归因略偏但响亮）；真调用
            // 与行内更早的 `//` 同屏会被误拒（误红，安全）。
            let n = arm.matches(needle).count();
            assert_eq!(
                n, 1,
                "needle {needle:?} 在本臂里出现 {n} 次（须恰好 1）—— 大概率是行尾注释携带了\
                 同形串替真调用作证（`find` 命中哪一处全凭先后）：{why}"
            );
            // 命中行若在 needle 前就有 `//`，那是行尾注释不是代码——继续找代码行里的那一处。
            let mut real_at = None;
            let mut offset = 0usize;
            for line in arm.lines() {
                if line.contains(needle) {
                    let before = line.split(needle).next().unwrap_or("");
                    if !before.contains("//") {
                        real_at = Some(offset + before.len());
                        break;
                    }
                }
                offset += line.len() + 1;
            }
            let at = real_at.unwrap_or_else(|| {
                panic!("{why}（本臂里只剩行尾注释在携带这个串 —— 真调用没了，注释在替它作证）")
            });
            assert!(
                head < at && at < exit,
                "{why}。实得 offset：分支头={head} / 本句={at} / 分支早退={exit} —— \
                 它不在「复查回来没有 updateInfo」那条分支里。搬到臂内别的分支上，\
                 这条路径就一发都不推，而弹窗停在 progress 永远转圈"
            );
        }

    assert!(
        !arm.contains("UpdatePopupState::done("),
        "本臂一个字节都没下 —— 推 `done` 就是在发起本次动作的那一屏上谎称「下载完成」\
             （2026-08-17 前的现状）。落位路径是 `done` 的必填参数，本臂拿不出真的那一个"
    );
    assert!(
        !body.contains("ProgressStage::Downloaded"),
        "「没有可下的东西」不得广播 downloaded —— 无文件、无 filePath，设置页会显示假的「已下载」"
    );
}

// ── 弹窗邀请 ↔ 真正下载：同一个版本 ────────────────────────────────────

/// 两个 App 更新通道都由同一份 GitHub release 选择逻辑解释；稳定版过滤 prerelease，测试版纳入。
#[test]
fn app_update_channel_selects_the_expected_release_line() {
    const RELEASES: &str = r#"[
          {"tag_name":"v0.3.0-beta.1","prerelease":true,"published_at":"2024-06-01T00:00:00Z",
           "assets":[{"name":"Polaris-0.3.0-mac-arm64.dmg","browser_download_url":"https://x/beta","size":1}]},
          {"tag_name":"v0.2.0","prerelease":false,"published_at":"2024-05-01T00:00:00Z",
           "assets":[{"name":"Polaris-0.2.0-mac-arm64.dmg","browser_download_url":"https://x/stable","size":1}]}
        ]"#;
    let pick = |include_pre: bool| match check_app_update(
        RELEASES,
        "0.1.0",
        include_pre,
        None,
        AssetPlatform::Macos,
        AssetArch::Arm64,
        false,
    )
    .expect("样本 JSON 必须可解析")
    {
        AppUpdateCheck::Available(i) => i,
        AppUpdateCheck::NoUpdate => panic!("样本里有更新，不该判成无更新"),
    };

    assert_eq!(pick(false).version, "v0.2.0");
    assert_eq!(pick(true).version, "v0.3.0-beta.1");
}

/// 递归收集 `src-tauri/src` 下的全部 Rust 源码；读取失败必须 fail-loud。
fn rust_sources_under(dir: &std::path::Path, out: &mut Vec<(std::path::PathBuf, String)>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("读不到目录 {}: {e}", dir.display()));
    for entry in entries {
        let p = entry.expect("目录项读取失败").path();
        if p.is_dir() {
            rust_sources_under(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            let s = std::fs::read_to_string(&p)
                .unwrap_or_else(|e| panic!("读不到 {}: {e}", p.display()));
            out.push((p, s));
        }
    }
}

/// 从函数调用左括号取顶层实参；足以覆盖 `update_check` 当前四个简单实参。
fn call_args(src: &str, open: usize) -> Vec<String> {
    let mut depth = 0usize;
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut in_comment = false;
    let mut it = src[open..].chars().peekable();
    while let Some(c) = it.next() {
        if in_comment {
            if c == '\n' {
                in_comment = false;
            }
            continue;
        }
        if c == '/' && it.peek() == Some(&'/') {
            in_comment = true;
            it.next();
            continue;
        }
        match c {
            '(' | '[' | '{' => {
                depth += 1;
                if depth > 1 {
                    cur.push(c);
                }
            }
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    if !cur.trim().is_empty() {
                        args.push(cur.split_whitespace().collect());
                    }
                    return args;
                }
                cur.push(c);
            }
            ',' if depth == 1 => {
                args.push(cur.split_whitespace().collect());
                cur.clear();
            }
            _ if depth >= 1 => cur.push(c),
            _ => {}
        }
    }
    panic!("update_check 调用括号未配平")
}

/// 启动和托盘从当前配置产出提醒；弹窗复查必须使用会话保存的口径。三条内部调用都不得启用
/// `include_current`，同版本重下只能由设置页的显式 IPC 动作触发。
#[test]
fn every_internal_update_check_preserves_channel_and_disables_current_version_resolution() {
    const NEEDLE: &str = "update_check(";
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_sources_under(&root, &mut files);

    let expected: std::collections::BTreeMap<&str, &str> = [
        ("runtime/startup_tasks.rs", "Some(include_prerelease)"),
        ("tray/commands.rs", "Some(include_prerelease)"),
        ("commands/updater/app_update.rs", "popup.include_prerelease"),
    ]
    .into_iter()
    .collect();
    let mut seen = std::collections::BTreeMap::new();

    for (path, raw) in &files {
        let src = crate::commands::guard_scan::strip_line_comments(raw);
        let mut from = 0usize;
        while let Some(rel) = src[from..].find(NEEDLE) {
            let at = from + rel;
            from = at + NEEDLE.len();
            let before = &src[..at];
            if before
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
                || before.trim_end().ends_with("fn")
            {
                continue;
            }
            let line_start = before.rfind('\n').map_or(0, |i| i + 1);
            if before[line_start..].matches('"').count() % 2 == 1 {
                continue;
            }

            let rel_path = path
                .strip_prefix(&root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            let args = call_args(&src, at + "update_check".len());
            assert_eq!(
                args.len(),
                4,
                "{rel_path} 的 update_check 应有四个实参：{args:?}"
            );
            let expected_channel = expected
                .get(rel_path.as_str())
                .unwrap_or_else(|| panic!("出现未登记的内部 update_check 调用：{rel_path}"));
            assert_eq!(&args[2], expected_channel, "{rel_path} 的通道来源漂移");
            assert_eq!(args[3], "None", "{rel_path} 不得解析同版本安装包");
            assert!(
                seen.insert(rel_path, args[2].clone()).is_none(),
                "同一文件出现重复调用"
            );
        }
    }

    assert_eq!(
        seen.len(),
        expected.len(),
        "三条更新入口必须全部处于守卫射程"
    );
}
/// 🟡 **真值表：对账判定本身（`reconcile_recheck`）。**
///
/// 与它配套的接线由 [`popup_recheck_reconciles_the_version_against_what_the_popup_showed`] 守：
/// 那条守「有没有调用、结论有没有被执行」，本条守「判对没判对」。缺任一条都只有一半。
///
/// **变异探针**：把 `advertised == Some(rechecked)` 改成 `!=`、或把空串那条早退删掉
/// ⇒ 逐条转红。
#[test]
fn reconcile_recheck_only_proceeds_on_a_verbatim_match() {
    // 逐字相同 ⇒ 照下（唯一放行档）。
    assert_eq!(
        reconcile_recheck(Some("v1.2.0"), "v1.2.0"),
        RecheckVerdict::Proceed
    );
    // 复查期间上游又发了一版（两端都是正式版，口径常量对此无能为力）⇒ 重新征求同意。
    assert_eq!(
        reconcile_recheck(Some("v1.2.0"), "v1.3.0"),
        RecheckVerdict::Renegotiate
    );
    // 大小写 / 前缀 / 空白差异一律不算「相同」——版本号是标识符，不是自然语言。
    assert_eq!(
        reconcile_recheck(Some("v1.2.0"), "V1.2.0"),
        RecheckVerdict::Renegotiate
    );
    assert_eq!(
        reconcile_recheck(Some("v1.2.0"), "1.2.0"),
        RecheckVerdict::Renegotiate
    );
    assert_eq!(
        reconcile_recheck(Some("v1.2.0"), " v1.2.0"),
        RecheckVerdict::Renegotiate
    );
    // 不知道当初承诺了什么 ⇒ 不能声称对上了（失败安全，不是 Proceed）。
    assert_eq!(
        reconcile_recheck(None, "v1.3.0"),
        RecheckVerdict::Renegotiate
    );
    // 复查回包没有版本号 = 契约破损：既不下也不弹空版本号。
    assert_eq!(
        reconcile_recheck(Some("v1.2.0"), ""),
        RecheckVerdict::Unusable
    );
    assert_eq!(reconcile_recheck(None, ""), RecheckVerdict::Unusable);
}

/// 🟡 **调用点守卫：兑现腿必须拿复查回来的版本与弹窗上写着的那串字逐字对账。**
///
/// 上面那道门统一的是候选集**规则**；这道守的是**内容**。两次 check 之间隔着用户的思考时间，
/// 上游随时可能再发一版 —— 那时两端都是正式版、口径完全相同，「按 A 邀请、下到 B」照样发生。
/// 而弹窗上真写着的那串字就在同一作用域里（`popup.version`，Skip / ManualDownload 一直在读它）。
///
/// 顺序判据不是形式主义：对账必须夹在**复查之后、下载之前**，且不一致时必须**提前返回** ——
/// 只推个 `remind` 却继续往下走 = 弹窗回到提醒态、包照下，比不改还糟。
///
/// **变异探针**：删掉比较 / 删掉 `remind` / 把 `return` 去掉让它继续往下走 / 把对账挪到
/// `update_download` 之后 ⇒ 逐条转红。
#[test]
fn popup_recheck_reconciles_the_version_against_what_the_popup_showed() {
    let body =
        crate::commands::guard_scan::top_level_fn_body(src(), "pub async fn update_popup_action(");
    // 锚点限定在 `Update | Retry` 臂内：在整个函数体上 find 时，别的臂里出现同形代码就会
    // 替本臂作证（同文件两道门都栽在这个形态上，见 `guard_scan::match_arm_body` 头注）。
    let arm = crate::commands::guard_scan::match_arm_body(
        &body,
        "PopupAction::Update | PopupAction::Retry =>",
        "PopupAction::",
    );
    let check_at = arm.find("update_check(").expect("锚点消失：守卫已失去判据");
    let cmp_at = arm
        .find("reconcile_recheck(popup.version.as_deref(), rechecked)")
        .expect("版本对账被删了 —— 复查换了目标也会照下，而弹窗上仍写着旧版本号");
    let remind_at = arm.find("UpdatePopupState::remind_with_channel(").expect(
        "不一致时没有退回 remind —— 换个目标接着下只是「告知」，不是「征求同意」\
             （何况 progress 态根本不渲染版本号，连告知都不成立）",
    );
    let download_at = arm
        .find("update_download(")
        .expect("锚点消失：守卫已失去判据");
    assert!(
            check_at < cmp_at && cmp_at < download_at,
            "对账必须夹在复查与下载之间（实得 check={check_at} / cmp={cmp_at} / download={download_at}）"
        );
    assert!(
            cmp_at < remind_at && remind_at < download_at,
            "退回 remind 必须在下载之前（实得 cmp={cmp_at} / remind={remind_at} / download={download_at}）"
        );
    assert!(
        arm[remind_at..download_at].contains("return Ok("),
        "退回 remind 之后没有 return —— 弹窗回到提醒态，下载却照跑"
    );
}

/// 🟡 **调用点守卫：`ManualDownload` 必须把会话记住的版本喂给 release 页。**
///
/// 这条钉的是一次**用户可见行为变更**：`PopupSession::send_state` 开始跨 phase 继承版本号后，
/// error 态的「手动下载」从「回落 GitHub 泛 releases 列表页」变成「直达该版本 tag 页」
/// （`releases_url_for(Some(v))`）。改进是真的，但它**不能顺带发生、也不能顺带消失** ——
/// 有人把这里改成传 `None`，用户又会掉回列表页而没有任何门说话。
///
/// 分工：数据侧（版本号跨 phase 还在不在）由 `polaris_updater::popup` 的
/// `the_invited_version_survives_phase_changes` 守；映射侧（版本号 → tag 页 URL）由
/// [`releases_url_for_version_targets_tag_page`] 守；本条只守中间那根线还接着。
///
/// **变异探针**：把 `popup.version.clone()` 改成 `None` ⇒ 转红。
#[test]
fn manual_download_opens_the_release_page_of_the_invited_version() {
    let body =
        crate::commands::guard_scan::top_level_fn_body(src(), "pub async fn update_popup_action(");
    const NEEDLE: &str = "update_open_releases(app, popup.version.clone())";
    const HEAD: &str = "PopupAction::ManualDownload =>";
    // 切片封到下一条臂头（[`guard_scan::match_arm_body`]，那里有它自己的合成样本单测）：
    // 切到函数体尾时，`ViewLog` 臂里有一句**逐字相同**的调用会替本条作证 —— 实测把
    // ManualDownload 臂整体移到 ViewLog 之前、实参保持 `None`，编译通过、全仓测试全绿，
    // 而用户行为退回 #311 原形。
    let arm = crate::commands::guard_scan::match_arm_body(&body, HEAD, "PopupAction::");
    assert!(
        arm.contains(NEEDLE),
        "ManualDownload 没有把会话记住的版本喂给 release 页 —— 用户会掉回泛列表页（#311 的原形）"
    );
    // 位置判据 + 计数判据合起来才闭合：位置判据挡「臂被搬走」，计数判据挡「某一臂的调用被删」
    // （ViewLog 与 ManualDownload 各一处，两者都得在）。单用计数挡不住「两处都在同一臂里」，
    // 单用位置挡不住「另一臂悄悄丢了」。
    //
    // ⚠️ **登记一处今天等价、将来不等价的形态**：`ManualDownload` 是末臂，切片因而一路延伸到
    // 函数的右花括号。今天无害（`match act { … }` 是尾表达式，其后没有代码）；一旦改成
    // `let resp = match act { … };` 再加后续处理，match **之后**的代码就落进本切片 ⇒ 上面那条
    // `contains(NEEDLE)` 可被它喂饱。封顶挡不住（那里没有臂头）、`match_arm_body` 的输出自检
    // 也挡不住（没有 `PopupAction::`），届时只剩下面的 `count == 2` 部分设防。
    assert_eq!(
        body.matches(NEEDLE).count(),
        2,
        "`{NEEDLE}` 应恰好两处（ViewLog + ManualDownload），实得 {}",
        body.matches(NEEDLE).count()
    );
}

/// 🟡 **调用点守卫：复查之前必须先把弹窗**强制**推进 progress(0)。**
///
/// 两件事都压在这一行上：
///  1. **窗内反馈**：复查可跑满 15s，其间没有任何进度事件 ⇒ 用户点完「更新」看着 remind 发呆；
///  2. **后续所有 `push_popup_state` 的前提**：闸 [`should_mirror_to_popup`] 只放行 `Progress`。
///     这一发若换成带闸的 `push_popup_state`，phase 会停在 `Remind` ⇒ 闸对之后每一发都判否
///     ⇒ 对账退回 remind、两条复查失败早退推 error、下载进度镜像**全部变成 no-op**，
///     而 `PopupAction::Cancel`（仅 Progress 合法）结构性不可达。
///
/// 本批删掉全局广播之后，这条的后果被放大了：改动前设置页至少还会亮一条（虽然那条本身是误报），
/// 现在两条复查失败腿在任何地方都不再有反馈。
///
/// **此前唯一拦住它的是偶然**：改成 `push_popup_state` 会让 `force_popup_state` 变成零调用点
/// ⇒ clippy `-D warnings` 报 never used。那是**夹具级**保护 —— 再多一处 `force_popup_state`
/// 调用它就消失。实测：直接改成 `push_popup_state` ⇒ 编译通过、全仓测试全绿。
///
/// **变异探针**：改成 `push_popup_state` / 删掉这一行 / 把它挪到 `update_check(` 之后 ⇒ 逐条转红。
#[test]
fn the_user_action_forces_the_popup_into_progress_before_rechecking() {
    let body =
        crate::commands::guard_scan::top_level_fn_body(src(), "pub async fn update_popup_action(");
    // **两个锚点都必须限定在 `Update | Retry` 臂内**。在整个函数体上 `find()` 时，把这发
    // `force_popup_state` 挪进 `ViewLog` 臂（位置更靠前）再从本臂删掉 ⇒ 两个 `find` 依旧命中、
    // 顺序依旧成立、本门全绿，而上面列的后果一条不少地发生。实测：全仓 4178 全绿。
    // 这与同文件 `manual_download_...` 那道门踩的是同一形态（别的臂替本臂作证）。
    let arm = crate::commands::guard_scan::match_arm_body(
        &body,
        "PopupAction::Update | PopupAction::Retry =>",
        "PopupAction::",
    );
    let force_at = arm
        .find("force_popup_state(&app, UpdatePopupState::progress(0, None, None))")
        .expect(
            "复查前那发强制 progress(0) 没了 —— 窗内 15s 零反馈，且之后每一发状态推送都会被闸拦掉",
        );
    let check_at = arm.find("update_check(").expect("锚点消失：守卫已失去判据");
    assert!(
        force_at < check_at,
        "强制 progress(0) 必须在复查**之前**（实得 force={force_at} / check={check_at}）：\
             之后才推等于那 15s 里窗内仍是零反馈"
    );
}

/// 🟡 **不变量：复查阶段的失败只推弹窗，绝不广播 `update:progress`。**
///
/// 这条路径一个字节都没下、没有 filePath。`emit_progress` 会把事件**全局广播**，让设置页
/// 弹一条它从未发起过的下载错误（`SettingsUpdate` 的 `onProgress` 直接置 error 态 + 错误文案）。
/// 同函数「已是最新」那档早就写着「只推弹窗、不广播」，两条复查失败腿此前却在广播 ——
/// 同一个函数里两种取向。行为对**弹窗**逐字不变：`emit_progress` 的弹窗镜像就是
/// `push_popup_state(UpdatePopupState::error(msg))` 这一发（见 `popup_state_for`）。
///
/// **变异探针**：任一条早退改回 `emit_progress(&app, &info, ProgressStage::Failed(..))` ⇒ 转红。
#[test]
fn recheck_failures_settle_the_popup_without_broadcasting() {
    let body =
        crate::commands::guard_scan::top_level_fn_body(src(), "pub async fn update_popup_action(");
    assert!(
        !body.contains("emit_progress("),
        "复查腿又开始广播 update:progress —— 设置页会显示一条它从未发起过的下载错误"
    );
    // 正向对照：两条早退确实各自把弹窗推进了 error（不广播 ≠ 什么都不做）。
    // 负向断言（上面那条）**故意保持全函数**：任何一条臂都不许广播，那是更强的形态。
    // 正向计数则限定到本臂 —— 否则把某条早退搬去别的臂，计数照样是 2。
    let arm = crate::commands::guard_scan::match_arm_body(
        &body,
        "PopupAction::Update | PopupAction::Retry =>",
        "PopupAction::",
    );
    // U1 起锚定码形（rustfmt 折行后旧串形不再逐字命中）。
    assert_eq!(
        arm.matches("UpdatePopupState::error(UpdateErrCode::RecheckFailed")
            .count(),
        2,
        "复查失败的两条早退（请求失败 / 回包缺版本号）必须各自把弹窗推进 error，否则窗内永远转圈"
    );
}

// ── 解归档工作目录（M7）─────────────────────────────────────────────────

/// 🟡 **变异锁：并发的解归档腿必须各占各的工作目录，且退出即自清。**
///
/// 固定名 `core-staged/extract` 时，调度器的自动下载腿与用户点的 `core_update_run` 会互相
/// `rm -rf` / 覆盖，一方可能读到**对方**的核字节并以自己的版本号 stage/换入。
///
/// **变异探针**：把 [`ExtractWorkDir::create`] 的唯一后缀去掉 ⇒ 「路径互不相同」转红；
/// 删掉 `Drop` 实现 ⇒ 「退出即自清」转红。
#[test]
fn extract_work_dirs_are_unique_and_self_cleaning() {
    let base = scratch("extract");
    let paths: Vec<std::path::PathBuf> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let base = base.clone();
                s.spawn(move || {
                    let w = ExtractWorkDir::create(&base).unwrap();
                    let p = w.path().to_path_buf();
                    // 还持着守卫时目录必须存在（并发的另一条腿不得把它删掉）。
                    assert!(p.is_dir(), "工作目录被别人删了：{}", p.display());
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    assert!(p.is_dir(), "并发期间工作目录被 rm 掉了：{}", p.display());
                    p
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    let unique: std::collections::HashSet<_> = paths.iter().collect();
    assert_eq!(
        unique.len(),
        paths.len(),
        "并发的解归档腿拿到了同一个工作目录"
    );
    for p in &paths {
        assert!(!p.exists(), "守卫 drop 后必须清掉工作目录：{}", p.display());
        assert_eq!(
            p.parent(),
            Some(core_paths::staged_dir_in(&base).as_path()),
            "工作目录必须落在 core-staged 下（不污染现役核目录）"
        );
    }
    std::fs::remove_dir_all(&base).unwrap();
}

/// 便携形态判定：**有标记 = loose，无标记 = installed**。
///
/// 这条是修复的另一半。修好选包器却让本函数恒返回 `false`（旧实现读的
/// `PORTABLE_EXECUTABLE_DIR` 在本仓恒不存在），便携用户照样被推安装器 ——
/// 变异探针：把判据改回任何一个 env 读取 ⇒ 「有标记」那条转红。
#[test]
fn portable_layout_is_decided_by_marker_file_next_to_exe() {
    let base = std::env::temp_dir().join(format!("polaris-portable-probe-{}", std::process::id()));
    let portable_dir = base.join("portable");
    let installed_dir = base.join("installed");
    std::fs::create_dir_all(&portable_dir).unwrap();
    std::fs::create_dir_all(&installed_dir).unwrap();
    std::fs::write(portable_dir.join(PORTABLE_MARKER), b"portable\n").unwrap();

    // 有标记 ⇒ 便携。
    assert!(
        is_portable_layout(&portable_dir.join("polaris.exe")),
        "exe 同级有 {PORTABLE_MARKER} 时必须判成便携形态，否则便携用户会被推 NSIS 安装器"
    );
    // 无标记 ⇒ 安装态（NSIS 装出来的目录里没有这个文件）。
    assert!(!is_portable_layout(&installed_dir.join("polaris.exe")));
    // 标记是**目录**不算数（`is_file` 而非 `exists`）。
    std::fs::create_dir_all(installed_dir.join(PORTABLE_MARKER)).unwrap();
    assert!(!is_portable_layout(&installed_dir.join("polaris.exe")));
    // 无父目录的退化路径不得 panic。
    assert!(!is_portable_layout(std::path::Path::new("polaris.exe")));

    std::fs::remove_dir_all(&base).unwrap();
}

/// 标记文件名是**跨文件契约**（`package.yml` 写它、本模块读它），钉死字面值。
#[test]
fn portable_marker_name_matches_packaging_contract() {
    assert_eq!(PORTABLE_MARKER, "portable.marker");
}

// ── 下载进度（此前只有 0% / 100% 两点）───────────────────────────────────

/// 🟡 **进度百分比的三条规则各有牙**：无分母不发 / 夹在 1..=99 / 同值去重。
///
/// **变异探针**：去掉 `clamp(1, 99)` ⇒ 「0 与 100 不由中段发」两条断言转红；
/// 去掉 `pct != last_pct` ⇒ 「同百分比不重发」转红；
/// 把 `expected` 缺失时回落成 `received` ⇒ 「无 Content-Length 不发」转红。
#[test]
fn progress_percent_rules() {
    // 无 Content-Length / 为 0 → 一律不发（不拿已收字节凑假分母）。
    assert_eq!(progress_percent(5_000, None, 0), None);
    assert_eq!(progress_percent(5_000, Some(0), 0), None);

    // 正常中段。
    assert_eq!(progress_percent(50, Some(100), 0), Some(50));
    // 同百分比不重发（IPC 洪水防线）。
    assert_eq!(progress_percent(50, Some(100), 50), None);
    assert_eq!(progress_percent(509, Some(1000), 50), None, "50.9% 仍是 50");
    assert_eq!(progress_percent(510, Some(1000), 50), Some(51));

    // 下界：0% 不由中段发（那一发由下载开始前独占）。
    assert_eq!(
        progress_percent(0, Some(1000), 0),
        Some(1),
        "首个 chunk 前的 0 会被夹到 1；last_pct=0 故仍发一次"
    );
    assert_eq!(progress_percent(3, Some(1000), 1), None, "夹到 1，与上次同");
    // 上界：100% 不由中段发（那一发由 downloaded 独占，否则出现倒退帧）。
    assert_eq!(progress_percent(1000, Some(1000), 50), Some(99));
    // received 超过 total（服务端 Content-Length 撒谎）→ 仍夹在 99，不溢出。
    assert_eq!(progress_percent(9_999, Some(1000), 50), Some(99));
}

// ── 弹窗各档（此前只有 remind 一档可达）─────────────────────────────────

/// 🟡 **弹窗镜像与广播载荷读的是同一帧：三种帧各自带齐自己那一屏要的事实。**
///
/// 本函数此前吃的是压平后的 `(status, percentage, error)`，落位路径与版本号在那层压平里丢了
/// ⇒ `done` 只剩一个状态字。改吃 [`ProgressStage`] + 同一份清单后，两屏结构上不可能各说各话。
///
/// **变异探针**：把 `Downloaded` 那臂的 `path.to_string_lossy()` 换成常量串 ⇒ 落位路径那条转红；
/// 把 `info.get("fileSize")` 换成 `None` ⇒ 分母那条转红；
/// 把 `Downloading` 的 `Some(received)` 换成 `None` ⇒ 已收字节那条转红。
#[test]
fn progress_frames_map_to_popup_phases_with_their_facts() {
    let info = json!({ "version": "v1.2.0", "fileSize": 52_000_000_u64 });
    let path = std::path::Path::new("/tmp/updates/polaris.dmg");

    let downloading = popup_state_for(
        &info,
        ProgressStage::Downloading {
            percentage: 42,
            received: 19_240_000,
        },
    );
    assert_eq!(downloading.phase, PopupPhase::Progress);
    assert_eq!(downloading.percentage, Some(42));
    assert_eq!(
        downloading.received_bytes,
        Some(19_240_000),
        "已收字节必须是回调原值 —— 从百分比反推的数每一帧都是错的"
    );
    assert_eq!(
        downloading.total_bytes,
        Some(52_000_000),
        "分母取本帧随行清单的 fileSize（与设置页下载卡同源）"
    );

    let done = popup_state_for(
        &info,
        ProgressStage::Downloaded {
            path,
            verified: true,
        },
    );
    assert_eq!(done.phase, PopupPhase::Done);
    assert_eq!(
        done.file_path.as_deref(),
        Some("/tmp/updates/polaris.dmg"),
        "「完成」得说得出包落在哪儿 —— 没有它，它与「什么都没下」长得一模一样"
    );
    assert_eq!(
        done.version.as_deref(),
        Some("v1.2.0"),
        "得说得出下的是哪一版"
    );

    let err = popup_state_for(
        &info,
        ProgressStage::Failed(UpdateErr::with_detail(
            UpdateErrCode::DownloadFailed,
            "net down",
        )),
    );
    assert_eq!(err.phase, PopupPhase::Error);
    // U1：弹窗 error 态带码 + 诊断串，正文本地化在渲染端。
    assert_eq!(err.error_code.as_deref(), Some("downloadFailed"));
    assert_eq!(err.error_detail.as_deref(), Some("net down"));
    // 无细节 → 空 detail 而非缺键（弹窗渲染端按可选处理）。
    let bare = popup_state_for(
        &info,
        ProgressStage::Failed(UpdateErr::new(UpdateErrCode::DownloadFailed)),
    );
    assert_eq!(bare.error_code.as_deref(), Some("downloadFailed"));
    assert_eq!(bare.error_detail.as_deref(), Some(""));

    // 清单缺 `fileSize` / 给 0 ⇒ 分母未知，只报已收量，**不拿已收字节凑假分母**。
    for blind in [json!({}), json!({ "fileSize": 0 })] {
        let s = popup_state_for(
            &blind,
            ProgressStage::Downloading {
                percentage: 42,
                received: 19_240_000,
            },
        );
        assert_eq!(s.received_bytes, Some(19_240_000));
        assert_eq!(s.total_bytes, None, "分母未知时不得编一个出来：{blind}");
    }
    // 清单缺 `version` ⇒ 不编版本号（会话继承会补上弹窗邀请的那一版，见 PopupSession）。
    assert_eq!(
        popup_state_for(
            &json!({}),
            ProgressStage::Downloaded {
                path,
                verified: false,
            }
        )
        .version,
        None
    );
}

/// 🟡 **后台下载不得顶掉用户面前的 remind 提示。**
///
/// `autoDownloadUpdate` 开启时，启动检查会「弹 remind 窗」+「后台下载」并行；若进度事件无条件
/// 镜像进弹窗，用户**再也看不到**「要不要更新」那一屏。闸只放行 `Progress`（= 用户亲手点过
/// 「更新」的弹窗）。
///
/// 判据面**遍历 [`PopupPhase::ALL`]**，不点名几个 phase：新加一档而闸忘了表态时，点名式清单
/// 静默漏掉那一格（且全绿），遍历式必判。`ALL` 自己与枚举由 `state.rs` 的门对账。
///
/// **变异探针**：把闸改成恒 true / 放行任意一个非 Progress 档 ⇒ 本条转红并点名那一档。
#[test]
fn popup_only_follows_progress_it_was_put_into_by_the_user() {
    for phase in PopupPhase::ALL {
        let expected = phase == PopupPhase::Progress;
        assert_eq!(
            should_mirror_to_popup(phase),
            expected,
            "{phase} 档的跟随判定错了 —— 只有用户亲手推进 progress 的弹窗才跟随后台下载；\
                 remind 被顶掉用户就再也看不到「要不要更新」那一屏，终态被顶掉则是拿一次无关\
                 下载改写一个已经落定的结论"
        );
    }
    // 正向对照：闸不是恒 false（那样弹窗里点「更新」后窗内零反馈）。
    assert!(should_mirror_to_popup(PopupPhase::Progress));
}

// ── 请求级总超时 ─────────────────────────────────────────────────────────

/// 🟡 **总超时必须严格小于「逐跳超时 × 最大跳数」，否则它不是兜底而是装饰。**
///
/// `safe_redirect_fetch` 最多跟 5 跳（`max_redirects: Some(5)`），逐跳 15s ⇒ 最坏 90s。
/// 契约要求 20s 整体兜底。**变异探针**：把总超时调到 ≥ 90s ⇒ 本条转红。
#[test]
fn core_check_total_timeout_actually_caps_multi_hop_worst_case() {
    const MAX_HOPS: u64 = 5 + 1; // 5 次重定向 + 最终一跳
    assert_eq!(CORE_CHECK_TOTAL_TIMEOUT_MS, 20_000, "契约要求 20s");
    // 读进局部再断言：clippy 的 assertions-on-constants 不许直接比较两个常量，
    // 但这两个值本来就是**编译期契约**，比的就是它们。
    let (total, per_hop) = (CORE_CHECK_TOTAL_TIMEOUT_MS, GITHUB_FETCH_TIMEOUT_MS);
    assert!(
        total < per_hop * MAX_HOPS,
        "总超时 {total}ms 没有比逐跳叠加的最坏值 {}ms 更紧 —— 它就没在兜任何底",
        per_hop * MAX_HOPS
    );
    // 超时码必须与其它失败码可区分（处置不同：超时该引导配加速，网络失败该重试）。
    for other in [
        CODE_HTTP_UNAVAILABLE,
        CODE_NO_BACKUP,
        CODE_FORK_BLOCKED,
        CODE_CORE_DIR_UNAVAILABLE,
    ] {
        assert_ne!(CODE_CHECK_TIMEOUT, other);
    }
}

/// 🟡 **调用点守卫**：`core_update_check` 必须被总超时包着。
///
/// 纯单测测不到（命令持 `State<'_, AppRuntime>`，且真超时要 20s 挂钟）。
/// **变异探针**：把 `tokio::time::timeout(...)` 从命令体里删掉 ⇒ 本条转红。
#[test]
fn core_update_check_is_wrapped_in_a_total_timeout() {
    let core_update_rs = crate_code("commands/updater/core_update.rs");
    let body = crate::commands::guard_scan::top_level_fn_body(
        &core_update_rs,
        "pub async fn core_update_check(",
    );
    assert!(
        body.contains("tokio::time::timeout"),
        "总超时被摘掉了 —— 逐跳 15s × 6 跳可跑到 90s，契约要求 20s 兜底"
    );
    assert!(
        body.contains("CORE_CHECK_TOTAL_TIMEOUT_MS"),
        "超时时长必须取自具名常量（写死字面量会与常量/测试漂移）"
    );
    assert!(
        body.contains("CODE_CHECK_TIMEOUT"),
        "超时必须返回可辨识错误码，不得折叠进泛化网络失败"
    );
}

// ── W8：「跳过此版本」存的与比的必须同口径 ─────────────────────────────

/// 🟡 **存储口径本体 = trim + strip_v，与比较侧同形。**
///
/// **变异探针**：把 helper 里的 `strip_v` 删掉 ⇒ 第 1 条红；把 `trim` 删掉 ⇒ 第 3 条红。
#[test]
fn stored_skip_version_matches_the_compare_side_form() {
    assert_eq!(stored_skip_version("v0.2.0"), "0.2.0");
    assert_eq!(
        stored_skip_version("0.2.0"),
        "0.2.0",
        "已归一化的输入必须幂等"
    );
    assert_eq!(
        stored_skip_version("  v0.2.0 "),
        "0.2.0",
        "顺带 trim：比较侧的 strip_v 不会碰空白"
    );
    assert_eq!(
        stored_skip_version("v1.2.3-beta.1"),
        "1.2.3-beta.1",
        "strip_v 只去前导一个 v，预发布后缀原样保留"
    );
    // 与比较侧的闭环另一半在 github.rs：check_app_update_skipped_version_is_no_update
    // 里带「原始 tag ⇒ Available」反例，钉死不许把比较侧改回原始 tag 来「修」跳过。
}

/// 🟡 **调用点守卫：生产写点恰两处（update_skip / PopupAction::Skip），且都过归一化点。**
///
/// 第三个写点若直写 `.skipped_version = …`，跳过功能会静默失效回 W8 前的形态
/// （用户按了跳过，下次照样被提醒）。
///
/// 计数是**全仓**的（`src-tauri/src` + `crates/updater/src` 递归、带点形态 `.skipped_version = `，
/// 不依赖闭包参数名）：首版只扫本文件 + `s.` 前缀，跨文件或 `|st| st.` 形态的第三写点
/// 会把它喂饱（复审 F1 实证）。`mutate_state` 是这条状态唯一可变入口，生产赋值必然以
/// `.skipped_version = ` 文本出现 ⇒ 文本扫描无漏。
///
/// **变异探针**：`update_skip` 里 `stored_skip_version(&v)` 换回 `v` ⇒ 第 1 条红；
/// Skip 臂删掉 `.map(|v| stored_skip_version(&v))` ⇒ 第 2 条红；
/// 在**任何文件**（含 runtime/updater.rs）新增生产赋值 ⇒ 第 3 条红；
/// 改用异参数名（`|st| st.skipped_version = …`）⇒ 仍第 3 条红（带点形态不分参数名）。
#[test]
fn skipped_version_write_points_all_go_through_the_normalizer() {
    let cmd = crate::commands::guard_scan::top_level_fn_body(src(), "pub fn update_skip(");
    assert!(
        cmd.contains("stored_skip_version(&v)"),
        "update_skip 的写点绕过了归一化 —— 存原始 tag 与比较侧（strip_v 后）永不相等，W8 原发病理"
    );
    let act =
        crate::commands::guard_scan::top_level_fn_body(src(), "pub async fn update_popup_action(");
    assert!(
        act.contains(".map(|v| stored_skip_version(&v))"),
        "弹窗 Skip 臂的写点绕过了归一化 —— 同上"
    );

    // 全仓命中清单：`路径` → `.skipped_version = ` 出现次数（**不剔测试区**，见 helper 头注）。
    let mut writes: Vec<(String, usize)> = vec![];
    let manifest = env!("CARGO_MANIFEST_DIR");
    for root in [
        format!("{manifest}/src"),
        format!("{manifest}/../crates/updater/src"),
    ] {
        collect_skip_writes(std::path::Path::new(&root), &root, &mut writes);
    }
    // 今天的构成：生产 2（update_skip / PopupAction::Skip）+ 测试与 doc 示例 10
    // （本文件 8、runtime/updater.rs 测试 2）。任何**新增**命中——生产第三写点、新测试写
    // state、doc 示例串——都先红：红了就过目定性，属生产写点必须过 stored_skip_version
    // 并两处体内断言，其余 bump 常量登记。（常量自己就咬过一次：helper 头注里的示例串
    // 让首版钉 11 立刻红，正是「全响无哑」的实证。）
    const PINNED_TOTAL: usize = 12;
    let total: usize = writes.iter().map(|(_, n)| n).sum();
    let locations = writes
        .iter()
        .filter(|(_, n)| *n > 0)
        .map(|(p, n)| format!("{p}×{n}"))
        .collect::<Vec<_>>()
        .join(", ");
    assert_eq!(
            total, PINNED_TOTAL,
            "全仓 `.skipped_version = ` 命中数漂了（期望 {PINNED_TOTAL}，实得 {total}：[{locations}]）。\
             多了：生产第三写点必须先过 stored_skip_version；测试/doc 新增也在此登记后 bump 常量。\
             少了：写点被删/搬走 —— 两处体内断言应同步红，一并修"
        );
}

/// 递归收集 `dir` 下 `.rs` 文件里 `.skipped_version = ` 的出现次数（**全文件**计数）。
///
/// ⚠️ **不剔测试区**（复审 F2 实证的教训）：本仓存在三类打破「测试置尾」假设的合法布局——
/// 文件头部的 `#[cfg(test)] mod guard_scan`（commands.rs，93% 内容在首锚之后）、中部的具名
/// sub 测试 mod（commands/proxy.rs 的 `mod probe_tests`，其后还有 472 行）、inline
/// `#[cfg(test)]` 项（runtime/proxy.rs 的 `TEST_CORE_NOT_INJECTED` const、runtime.rs 的
/// TmpDir）。「按第一个锚截断」会让这些文件锚后的生产代码
/// 整段免扫——哑绿。安全截断需要 cfg(test) 块的完整花括号解析（半个 parser），不成比例；
/// 故改为全文件计数 + 总数钉扎（调用处断言），新增命中一律先红后登记，全响无哑。
fn collect_skip_writes(dir: &std::path::Path, root: &str, out: &mut Vec<(String, usize)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        panic!(
            "守卫扫描不到目录 {} —— 仓库布局变了，先修守卫再改代码",
            dir.display()
        );
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_skip_writes(&p, root, out);
            continue;
        }
        if p.extension().is_none_or(|x| x != "rs") {
            continue;
        }
        let src =
            std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("读不了 {}: {e}", p.display()));
        let n = src.matches(".skipped_version = ").count();
        let rel = p
            .strip_prefix(root)
            .unwrap_or(&p)
            .to_string_lossy()
            .into_owned();
        out.push((format!("{}/{}", root.trim_end_matches('/'), rel), n));
    }
}

/// 🟡 **调用点守卫（#4）：自动关窗定时器必须带代次核对。**
///
/// `schedule_popup_auto_close` 服务 done（800ms）与 noupdate（3000ms）两个终态。窗口拉长后，
/// 「用户手动关掉 noupdate 卡 → 3s 内另一条腿开出新弹窗 → 陈旧定时器把新窗关掉」从理论
/// 竞态变成现实可达。解法 = 调度时捕获 `popup_generation`、fire 时核对不等即跳过。
/// 本守卫钉住这三件都在，删任何一件（= 退回无守卫形态）转红。
///
/// **变异探针**：删 `let scheduled_gen = popup_generation(app);` ⇒ 第 1 条红；
/// 删 `if popup_generation(&app) != scheduled_gen` 那个分支 ⇒ 第 2 条红；
/// 把核对挪到 `close_update_popup` **之后**（先关再核对，守卫失效）⇒ 第 3 条红。
#[test]
fn auto_close_timer_is_generation_guarded() {
    let body =
        crate::commands::guard_scan::top_level_fn_body(src(), "fn schedule_popup_auto_close(");
    let capture_at = body
        .find("let scheduled_gen = popup_generation(app);")
        .expect("锚点消失：调度时的代次捕获没了 —— 定时器退回无守卫形态（🟡#4）");
    let check_at = body
        .find("if popup_generation(&app) != scheduled_gen {")
        .expect("锚点消失：fire 时的代次核对没了 —— 陈旧定时器会关掉新窗");
    let close_at = body
        .find("close_update_popup(&app, rt.updater().popup())")
        .expect("锚点消失：自动关窗的关闭调用没了");
    assert!(
        capture_at < check_at,
        "代次捕获必须在 fire 核对之前（实得 capture={capture_at} / check={check_at}）"
    );
    assert!(
            check_at < close_at,
            "代次核对必须在关闭调用之前 —— 先关再核对等于没守（实得 check={check_at} / close={close_at}）"
        );
}

/// 🔴 detached spawn 失败时，任何退出副作用都不能发生；成功后必须严格 Quit → Exit，各一次。
///
/// **变异探针**：在 `?` 前先调 `mark_quit()` ⇒ 错误腿的 effects 非空，行为门转红。
#[test]
fn complete_detached_install_owns_success_effects_and_leaves_errors_untouched() {
    let effects = std::cell::RefCell::new(Vec::new());
    let failed: Result<(), &str> = complete_detached_install(
        Err("spawn failed"),
        || effects.borrow_mut().push("quit"),
        || effects.borrow_mut().push("exit"),
    );
    assert_eq!(failed, Err("spawn failed"), "错误必须原样交回调用者");
    assert!(
        effects.borrow().is_empty(),
        "detached spawn 失败时不得宣告退出或退出进程"
    );

    let completed: Result<&str, &str> = complete_detached_install(
        Ok("detached-script"),
        || effects.borrow_mut().push("quit"),
        || effects.borrow_mut().push("exit"),
    );
    assert_eq!(completed, Ok("detached-script"));
    assert_eq!(
        effects.into_inner(),
        vec!["quit", "exit"],
        "成功路径必须严格先 Quit、再 Exit，且两者各一次"
    );
}

/// 调用点只负责执行 spawn 并提供两条同步副作用；控制流、错误隔离与先后次序都归
/// [`complete_detached_install`]。这个接线契约防止 command 重新在 helper 外越权置状态或 exit。
#[test]
fn update_install_delegates_detached_spawn_to_completion_helper() {
    let body =
        crate::commands::guard_scan::top_level_fn_body(src(), "pub async fn update_install(");
    assert!(
        body.contains("let detached_spawn = update_install::spawn_detached_script(&dir, &spec);"),
        "command 必须先实际执行 detached spawn，再把它的 Result 交控制流 helper"
    );
    assert_eq!(
        body.matches("complete_detached_install(").count(),
        1,
        "update_install 必须只把这一处 spawn Result 交给 completion helper"
    );
    assert!(
        body.contains("|| mark_explicit_update_quit(&app)")
            && body.contains("|| exit_after_detached_update(&app)"),
        "command 只能注入 Quit/Exit 副作用，不得自管成功控制流"
    );
    assert!(
        !body.contains("app.state::<QuitState>()") && !body.contains("app.exit(0)"),
        "QuitState 与 app.exit 均不得在 command helper 外直接执行"
    );
}
