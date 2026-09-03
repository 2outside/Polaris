use super::*;

mod resolve_tests;

const SRS: &[u8] = b"SRS\x01payload";

fn tmp_root(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "polaris-geoseed-{}-{}-{name}",
        std::process::id(),
        SEED_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("建临时目录");
    d
}

/// 造一个只含指定文件名的「随包目录」。
fn bundled_with(root: &Path, files: &[&str], bytes: &[u8]) -> PathBuf {
    let dir = root.join("bundled");
    std::fs::create_dir_all(&dir).expect("建随包目录");
    for f in files {
        std::fs::write(dir.join(f), bytes).expect("写随包文件");
    }
    dir
}

fn all_builtin_files() -> Vec<String> {
    builtin_geo_rulesets()
        .into_iter()
        .map(|b| b.file_name)
        .collect()
}

/// 空运行时目录 + 齐全随包 → 全部播种，且播种后 route builder 的同一判据（SRS 魔数）全部为真。
/// 变异锁：`seed_one` 若不做 rename（只写 tmp）→ still_missing 非空 → 转红。
#[test]
fn seeds_all_builtin_into_empty_runtime_dir() {
    let root = tmp_root("empty");
    let files = all_builtin_files();
    let refs: Vec<&str> = files.iter().map(String::as_str).collect();
    let bundled = bundled_with(&root, &refs, SRS);
    let runtime = root.join("rules");

    let report = seed_builtin_rule_sets(&bundled, &runtime, &SeedOptions::default());

    assert_eq!(report.seeded.len(), files.len(), "全部随包文件都该被播种");
    assert!(
        report.still_missing.is_empty(),
        "播种后不该有缺失：{:?}",
        report.still_missing
    );
    for f in &files {
        assert!(is_valid_srs_file(&runtime.join(f)), "{f} 应落盘且魔数有效");
    }
    // 播种目录里不得残留 tmp（原子写必须收尾干净）。
    let leftovers: Vec<String> = std::fs::read_dir(&runtime)
        .expect("读运行时目录")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".seed-"))
        .collect();
    assert!(leftovers.is_empty(), "不得残留 tmp：{leftovers:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// **绝不覆盖已有有效副本**（用户经「规则资源」页下载的更新版）。
/// 变异锁：删 `is_valid_srs_file(&dest)` 早退 → 用户版被出厂版覆盖 → 转红。
#[test]
fn never_overwrites_valid_existing_copy() {
    let root = tmp_root("keep");
    let bundled = bundled_with(&root, &["geosite-cn.srs"], SRS);
    let runtime = root.join("rules");
    std::fs::create_dir_all(&runtime).expect("建运行时目录");
    let user_version = b"SRS\x02user-downloaded-newer";
    std::fs::write(runtime.join("geosite-cn.srs"), user_version).expect("写用户版");

    let report = seed_builtin_rule_sets(&bundled, &runtime, &SeedOptions::default());

    assert!(
        !report.seeded.contains(&"geosite-cn.srs".to_string()),
        "已有有效副本不得重播"
    );
    assert_eq!(
        std::fs::read(runtime.join("geosite-cn.srs")).expect("读回"),
        user_version,
        "用户下载的版本必须原样保留"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// 已存在但**损坏**（无 SRS 魔数，半写/截断）→ 必须重播覆盖。
/// 变异锁：把 dest 判据从「魔数有效」弱化成「文件存在」→ 坏文件永不被修 → 转红。
#[test]
fn reseeds_over_invalid_existing_copy() {
    let root = tmp_root("broken");
    let bundled = bundled_with(&root, &["geoip-cn.srs"], SRS);
    let runtime = root.join("rules");
    std::fs::create_dir_all(&runtime).expect("建运行时目录");
    std::fs::write(runtime.join("geoip-cn.srs"), b"\x00\x00truncated").expect("写坏文件");

    let report = seed_builtin_rule_sets(&bundled, &runtime, &SeedOptions::default());

    assert!(
        report.seeded.contains(&"geoip-cn.srs".to_string()),
        "损坏副本必须重播"
    );
    assert_eq!(
        std::fs::read(runtime.join("geoip-cn.srs")).expect("读回"),
        SRS
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// 随包文件**损坏**（打包污染）→ 不种，如实报 still_missing。
/// 变异锁：删 `is_valid_srs_file(src)` 守卫 → 坏文件被种进运行时目录 + still_missing 变空 → 转红。
#[test]
fn skips_invalid_bundled_source() {
    let root = tmp_root("badsrc");
    let bundled = bundled_with(&root, &["geosite-cn.srs"], b"<!DOCTYPE html>404");
    let runtime = root.join("rules");

    let report = seed_builtin_rule_sets(&bundled, &runtime, &SeedOptions::default());

    assert!(report.seeded.is_empty(), "损坏的随包文件不得播种");
    assert!(
        report.still_missing.contains(&"geosite-cn".to_string()),
        "应如实报告仍缺失"
    );
    assert!(!runtime.join("geosite-cn.srs").exists(), "坏文件不得落盘");
    let _ = std::fs::remove_dir_all(&root);
}

/// 随包目录整体缺失 → 全部 still_missing，且不 panic（best-effort）。
#[test]
fn missing_bundled_dir_reports_all_missing() {
    let root = tmp_root("nosrc");
    let report = seed_builtin_rule_sets(
        &root.join("nonexistent"),
        &root.join("rules"),
        &SeedOptions::default(),
    );
    assert!(report.seeded.is_empty());
    assert_eq!(report.still_missing.len(), builtin_geo_rulesets().len());
    let _ = std::fs::remove_dir_all(&root);
}

/// 幂等：连播两次，第二次零落盘（跳过已有效项），结果集恒稳。
#[test]
fn second_run_is_noop() {
    let root = tmp_root("idem");
    let files = all_builtin_files();
    let refs: Vec<&str> = files.iter().map(String::as_str).collect();
    let bundled = bundled_with(&root, &refs, SRS);
    let runtime = root.join("rules");

    let first = seed_builtin_rule_sets(&bundled, &runtime, &SeedOptions::default());
    let second = seed_builtin_rule_sets(&bundled, &runtime, &SeedOptions::default());

    assert!(!first.seeded.is_empty());
    assert!(
        second.seeded.is_empty(),
        "第二次不该再落盘：{:?}",
        second.seeded
    );
    assert!(second.still_missing.is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

// ───────── 出厂态刷新（refreshOutOfBox，上游 builtin-geo-rulesets.ts:170-186 补齐） ─────────

/// 造「已装过 v1」的运行时目录：runtime 里是旧出厂版，bundled 里是新出厂版（大小不同）。
fn upgraded_layout(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let root = tmp_root(name);
    let bundled = bundled_with(&root, &["geosite-cn.srs"], b"SRS\x01new-factory-data-v2");
    let runtime = root.join("rules");
    std::fs::create_dir_all(&runtime).expect("建运行时目录");
    std::fs::write(runtime.join("geosite-cn.srs"), b"SRS\x01old-v1").expect("写旧出厂版");
    (root, bundled, runtime)
}

/// **R5 主场景**：装 v1 → 播种 → 升 v2（随包带新 geo 数据）→ 启动刷新腿必须把它换成新出厂版。
/// 不修这条，出厂态用户跨 app 升级永久冻结在首装版（dest 一直有效 ⇒ 老逻辑恒 `continue`）。
///
/// 变异锁：删 `seed_reason` 的 Refresh 腿（恒返 None）→ 内容仍是 old-v1 → 转红。
/// 变异锁：`seed_one` 的 `!overwrite_valid_dest &&` 去掉 → 刷新被落地前复查挡住 → 转红。
#[test]
fn refreshes_out_of_box_copy_when_bundled_size_differs() {
    let (root, bundled, runtime) = upgraded_layout("refresh");
    let opts = SeedOptions {
        refresh_out_of_box: true,
        ..SeedOptions::default()
    };

    let report = seed_builtin_rule_sets(&bundled, &runtime, &opts);

    assert!(
        report.refreshed.contains(&"geosite-cn.srs".to_string()),
        "出厂态 + 大小不一致必须刷新：{report:?}"
    );
    assert_eq!(
        std::fs::read(runtime.join("geosite-cn.srs")).expect("读回"),
        b"SRS\x01new-factory-data-v2",
        "刷新后内容必须是新出厂版"
    );
    // 刷新成功的那个 tag 绝不能进 still_missing（其余 27 个随包缺失是本夹具的刻意留白）。
    assert!(
        !report.still_missing.contains(&"geosite-cn".to_string()),
        "刷新腿不得把已有有效副本报成 still_missing：{report:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// **已网络更新过的副本永不被出厂版覆盖**（`builtinGeoMeta[tag].updatedAt` 存在 ⇒ 非出厂态）。
/// 变异锁：删 `!opts.network_updated_tags.contains(tag)` 条件 → 网络版被刷回出厂版 → 转红。
#[test]
fn refresh_skips_network_updated_tags() {
    let (root, bundled, runtime) = upgraded_layout("refresh-skip-net");
    let opts = SeedOptions {
        network_updated_tags: ["geosite-cn".to_string()].into_iter().collect(),
        refresh_out_of_box: true,
    };

    let report = seed_builtin_rule_sets(&bundled, &runtime, &opts);

    assert!(
        report.refreshed.is_empty(),
        "有网络更新记录的 tag 不得刷新：{report:?}"
    );
    assert_eq!(
        std::fs::read(runtime.join("geosite-cn.srs")).expect("读回"),
        b"SRS\x01old-v1",
        "网络更新过的副本必须原样保留"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// **刷新只在启动那次开**（起核前那次 `refresh_out_of_box=false`，不与并发更新争抢）。
/// 变异锁：把 `opts.refresh_out_of_box &&` 删掉（恒开）→ 转红。
#[test]
fn refresh_is_off_by_default() {
    let (root, bundled, runtime) = upgraded_layout("refresh-off");

    let report = seed_builtin_rule_sets(&bundled, &runtime, &SeedOptions::default());

    assert!(
        report.refreshed.is_empty(),
        "默认（起核前）不得刷新：{report:?}"
    );
    assert_eq!(
        std::fs::read(runtime.join("geosite-cn.srs")).expect("读回"),
        b"SRS\x01old-v1"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// 大小**相同** → 视作同一份出厂数据，不做无谓 IO（刷新判据是大小，不是「只要开了就刷」）。
/// 变异锁：把大小比较改成恒真 → `refreshed` 非空 → 转红。
#[test]
fn refresh_noop_when_sizes_match() {
    let root = tmp_root("refresh-same");
    // 两份内容不同但**等长** ⇒ 判据（大小）说「同一份出厂数据」。
    let bundled = bundled_with(&root, &["geosite-cn.srs"], b"SRS\x01AAAA");
    let runtime = root.join("rules");
    std::fs::create_dir_all(&runtime).expect("建运行时目录");
    std::fs::write(runtime.join("geosite-cn.srs"), b"SRS\x01BBBB").expect("写等长副本");

    let opts = SeedOptions {
        refresh_out_of_box: true,
        ..SeedOptions::default()
    };
    let report = seed_builtin_rule_sets(&bundled, &runtime, &opts);

    assert!(report.refreshed.is_empty(), "大小相同不该刷新：{report:?}");
    assert_eq!(
        std::fs::read(runtime.join("geosite-cn.srs")).expect("读回"),
        b"SRS\x01BBBB"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// **R8 tmp 清扫**：他进程崩在 copy 与 rename 之间留下的 `*.seed-<pid>-<n>` 必须被清掉；
/// **本进程**的在途 tmp 必须保留（两个调用点可重叠，删了会让对方 rename 失败）。
/// 变异锁：去掉 `!name.contains(&mine)` → 本进程 tmp 被误删 → 转红。
/// 变异锁：删掉 `sweep_stale_tmp` 调用 → 陈旧 tmp 永久残留 → 转红。
#[test]
fn sweeps_only_foreign_stale_tmp() {
    let root = tmp_root("sweep");
    let bundled = bundled_with(&root, &["geosite-cn.srs"], SRS);
    let runtime = root.join("rules");
    std::fs::create_dir_all(&runtime).expect("建运行时目录");
    let foreign = runtime.join(format!("geoip-cn.srs{TMP_MARK}999999-3"));
    let mine = runtime.join(format!("geoip-cn.srs{TMP_MARK}{}-7", std::process::id()));
    std::fs::write(&foreign, b"SRS\x01crashed-run").expect("写他进程残留");
    std::fs::write(&mine, b"SRS\x01in-flight").expect("写本进程在途");

    let _ = seed_builtin_rule_sets(&bundled, &runtime, &SeedOptions::default());

    assert!(!foreign.exists(), "他进程的陈旧 tmp 必须被清掉");
    assert!(
        mine.exists(),
        "本进程在途 tmp 绝不能删（会让并发那轮 rename 失败）"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// `builtinGeoMeta` 解析：只有 `updatedAt` 真有值的 tag 才算「已网络更新」。
/// 这条同时是 `commands/rules.rs` 「清 builtinGeoMeta ⇒ 下次启动按出厂态处理」契约的读侧证明
/// ——此前全仓无人读该字段，那条自陈契约是空的。
#[test]
fn parses_network_updated_tags_from_raw_config() {
    let raw = r#"{"builtinGeoMeta":{
            "geosite-cn":{"updatedAt":"2026-07-01T00:00:00Z"},
            "geoip-cn":{},
            "geosite-google":{"updatedAt":null},
            "geosite-github":{"updatedAt":""}
        }}"#;
    let tags = network_updated_tags_from_raw(Some(raw));
    assert_eq!(
        tags,
        ["geosite-cn".to_string()]
            .into_iter()
            .collect::<BTreeSet<_>>(),
        "只有 updatedAt 有实值的才算已更新（缺键/null/空串都是出厂态）"
    );
    assert!(network_updated_tags_from_raw(None).is_empty());
    assert!(network_updated_tags_from_raw(Some("{ 坏 json")).is_empty());
    assert!(network_updated_tags_from_raw(Some(r#"{"builtinGeoMeta":[]}"#)).is_empty());
}
