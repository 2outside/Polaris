use super::*;

#[test]
fn tmp_path_format_matches_sweep_regex() {
    let base = Path::new("/data/polaris/config.json");
    let p = tmp_path(base, "abcdef012345");
    // 不比整串：`tmp_path` 走 `set_file_name`（pop+push），Windows 上 push 补的是
    // `MAIN_SEPARATOR`（`\`）→ 整串必不等。而 sweep 正则匹配的本来就只是文件名，
    // 故分开钉「文件名形态」+「仍在同一目录」。
    assert_eq!(
        p.file_name().unwrap().to_string_lossy(),
        "config.json.abcdef012345.tmp"
    );
    assert_eq!(p.parent(), base.parent());
}

// ── random_tmp_suffix：兑现「生产侧注入随机 12hex」的契约 ──

/// ①：形状恒合法（len==12 且全小写 hex）。
///
/// 直接锁 debug 构型那条：`tmp_path` 的 `debug_assert!` 正是判这两条，
/// 不满足即**首启 abort**。1000 次覆盖低位前导零等边界（48bit 掩码后小值会补零）。
#[test]
fn random_tmp_suffix_is_always_12_lowercase_hex() {
    for _ in 0..1000 {
        let s = random_tmp_suffix();
        assert_eq!(s.len(), 12, "后缀必须恰好 12 位，实得 {s:?}");
        assert!(
            s.bytes().all(|b| b.is_ascii_hexdigit()),
            "后缀必须全 hex，实得 {s:?}"
        );
        assert!(
            s.bytes().all(|b| !b.is_ascii_uppercase()),
            "后缀必须小写（sweep 正则是 [0-9a-f]），实得 {s:?}"
        );
    }
}

/// ②：连续调用不得相同 —— 防「退化成同进程内常量」（那等于没修：并发保存仍撞同一 tmp）。
#[test]
fn random_tmp_suffix_differs_across_calls() {
    let a = random_tmp_suffix();
    let b = random_tmp_suffix();
    assert_ne!(a, b, "连续两次生成不得相同（撞常量 = 唯一 tmp 名失效）");
    // 再压一轮：100 次应几乎全不重复（48bit 空间，碰撞概率可忽略）。
    let set: std::collections::HashSet<String> = (0..100).map(|_| random_tmp_suffix()).collect();
    assert!(
        set.len() >= 99,
        "100 次生成应几乎无重复，实得 {} 个唯一",
        set.len()
    );
}

/// ③ **最关键**：生成的 tmp 名必须被 [`is_stale_tmp`] 认出。
///
/// 这条锁的正是 **release 下那个静默失效**：断言被编掉后，坏后缀不会崩、不会报错，
/// 只是 tmp 名永远匹配不上清扫正则 → 孤儿 tmp 无声堆积。生成器与 sweep 谓词的
/// **round-trip** 是唯一能抓住它的门。
#[test]
fn random_tmp_suffix_produces_sweepable_tmp_name() {
    for _ in 0..200 {
        let suffix = random_tmp_suffix();
        let p = tmp_path(Path::new("/data/polaris/config.json"), &suffix);
        let candidate = p.file_name().unwrap().to_str().unwrap();
        assert!(
            is_stale_tmp("config.json", candidate),
            "生成的 tmp 名必须匹配清扫锚点 ^config\\.json\\.[0-9a-f]{{12}}\\.tmp$，实得 {candidate:?}"
        );
    }
}

/// 反证：字面量 `"polaris"`（修复前生产侧真传的值）**不**可清扫 —— 固化 bug 的形状，
/// 防「换个字面量又混进去」。
#[test]
fn literal_suffix_is_not_sweepable_regression_anchor() {
    let p = Path::new("/data/polaris/config.json.polaris.tmp");
    let candidate = p.file_name().unwrap().to_str().unwrap();
    assert!(
        !is_stale_tmp("config.json", candidate),
        "字面量后缀本就不该被清扫——这正是 release 下孤儿 tmp 堆积的机理"
    );
}

#[test]
fn should_sweep_requires_both_name_match_and_age() {
    let base = "config.json";
    let stale = "config.json.abcdef012345.tmp";
    // 名匹配 + 龄期 > 60s → 删。
    assert!(should_sweep_stale_tmp(base, stale, 61));
    assert!(should_sweep_stale_tmp(base, stale, 10_000));
    // 名匹配但太新（≤60s）→ 不删（守卫在途并发 saveConfig 的 tmp）。
    assert!(!should_sweep_stale_tmp(base, stale, 60));
    assert!(!should_sweep_stale_tmp(base, stale, 0));
    // 名不匹配（真实配置文件 / 备份）无论多老都不删。
    assert!(!should_sweep_stale_tmp(base, "config.json", 10_000));
    assert!(!should_sweep_stale_tmp(
        base,
        "config.json.pre-rule-migration.bak",
        10_000
    ));
    assert!(!should_sweep_stale_tmp(
        base,
        "config.corrupt-2026.json",
        10_000
    ));
}

#[test]
fn is_stale_tmp_matches() {
    assert!(is_stale_tmp("config.json", "config.json.abcdef012345.tmp"));
    assert!(!is_stale_tmp("config.json", "config.json.abcdef01234.tmp")); // 11hex
    assert!(!is_stale_tmp("config.json", "config.json.abcdef012345.txt")); // .txt
    assert!(!is_stale_tmp(
        "config.json",
        "config.json.abcdef012345Z.tmp"
    )); // 非 hex
    assert!(!is_stale_tmp("config.json", "other.json.abcdef012345.tmp")); // 不同 base
    assert!(!is_stale_tmp(
        "config.json",
        "config.json.pre-rule-migration.bak"
    )); // 备份不匹配
}

#[test]
fn atomic_plan_execute_writes_tmp_then_renames() {
    use crate::MockFs;
    let fs = MockFs::default();
    let base = Path::new("/d/config.json");
    let plan = atomic_write_plan(base, "abcdef012345", "{}");
    plan.execute(&fs).unwrap();
    let ops = fs.operations();
    // tmp 文件名形如 <base>.<12hex>.tmp（单文件名组件，故用字符串后缀而非 Path::ends_with）。
    assert!(ops.iter().any(|o| matches!(
        o,
        crate::FsOp::Write(p, _) if p.to_string_lossy().ends_with("abcdef012345.tmp")
    )));
    assert!(ops.iter().any(|o| matches!(
        o,
        crate::FsOp::Rename(from, to) if from.to_string_lossy().ends_with("abcdef012345.tmp") && to == base
    )));
    assert_eq!(fs.snapshot(base).as_deref(), Some("{}"));
}
