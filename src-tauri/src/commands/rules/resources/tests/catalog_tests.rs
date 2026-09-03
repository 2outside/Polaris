use super::super::*;
use crate::commands::rules::icons::icon_gallery_tests::{MockHttp, PublicLookup};
use polaris_config_engine::user_config::rule_resource_catalog;
use std::collections::HashMap;

const GEO_SHA: &str = "1111111111111111111111111111111111111111";
const LITE_SHA: &str = "2222222222222222222222222222222222222222";

fn root_url() -> String {
    format!("{MRD_TREE_API_BASE}{MRD_CATALOG_REF}")
}
fn subtree_url(sha: &str) -> String {
    format!("{MRD_TREE_API_BASE}{sha}?recursive=1")
}

/// 根树 JSON（geo / geo-lite 两个子树 + 一个无关文件）。
fn root_json(geo_sha: &str, lite_sha: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({ "tree": [
        { "path": "README.md", "type": "blob", "sha": "3333333333333333333333333333333333333333" },
        { "path": "geo", "type": "tree", "sha": geo_sha },
        { "path": "geo-lite", "type": "tree", "sha": lite_sha },
    ]}))
    .unwrap()
}

/// 子树 JSON：`entries` = (type, path)。
fn subtree_json(entries: &[(&str, &str)], truncated: bool) -> Vec<u8> {
    let tree: Vec<Value> = entries
        .iter()
        .map(|(ty, p)| json!({ "type": ty, "path": p }))
        .collect();
    serde_json::to_vec(&json!({ "truncated": truncated, "tree": tree })).unwrap()
}

/// 生成 n 条 geosite 叶子（用于凑过 `CATALOG_MIN_ITEMS` 闸）。
fn many_geosite(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("geosite/site{i}.srs")).collect()
}

/// 一套「远端一切正常」的 mock（geo 60 条 + geo-lite 2 条）。
fn healthy_mock() -> MockHttp {
    let geo_paths = many_geosite(60);
    let mut geo: Vec<(&str, &str)> = geo_paths.iter().map(|p| ("blob", p.as_str())).collect();
    geo.push(("blob", "geosite/youtube.srs"));
    geo.push(("blob", "geoip/cn.srs"));
    let lite = [("blob", "geosite/cn.srs"), ("blob", "geoip/cn.srs")];
    let mut responses = HashMap::new();
    responses.insert(root_url(), (200u16, root_json(GEO_SHA, LITE_SHA)));
    responses.insert(subtree_url(GEO_SHA), (200u16, subtree_json(&geo, false)));
    responses.insert(subtree_url(LITE_SHA), (200u16, subtree_json(&lite, false)));
    MockHttp { responses }
}

/// 什么都答不上来的 client（= 全网不通）。
fn dead_mock() -> MockHttp {
    MockHttp {
        responses: HashMap::new(),
    }
}

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "polaris-catalog-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |x| x.as_nanos())
    ));
    let _ = std::fs::remove_dir_all(&d);
    d
}

// ── 派生口径 ──────────────────────────────────────────────────────────────

/// **同构门**：远程 collect 派生出的条目必须与内置清单逐字相同（id/category/name/path）。
/// 破了它，同一资源在「内置」与「刷新后」两态会算出两个下载 URL / 两个落盘名。
///
/// 只对**内置清单里有的、且 tag 与上游文件名同名的** id 成立。两处例外各自单列：
/// `geo-lite/` 那支不随包（→ `lite_tree_path_*`）；`geosite-category-ai` 的 tag 与文件名分岔
/// （→ `category_ai_is_the_one_id_remote_cannot_reproduce`）。
#[test]
fn tree_path_matches_builtin_derivation() {
    for id in ["geosite-youtube", "geoip-cn", "geosite-geolocation-!cn"] {
        let builtin = find_catalog_item(id).expect("内置清单应有此条目");
        let (base, rel) = builtin.path.split_once('/').unwrap();
        let derived = catalog_item_from_tree_path(base, rel).expect("远程派生应成立");
        assert_eq!(derived, builtin, "{id} 的远程派生与内置清单不一致");
    }
}

/// `geo-lite/` 支的派生：目录 `geo-lite/geosite` → category `geosite-lite`（不是 `geosite`），
/// 且**不得**被判成随包（内置清单里没有它，判真会让外置 tab 把它标成「已内置」且不可下载）。
#[test]
fn lite_tree_path_derives_lite_category_and_is_not_bundled() {
    let i = catalog_item_from_tree_path("geo-lite", "geosite/cn.srs").expect("派生应成立");
    assert_eq!(i.id, "geosite-lite-cn");
    assert_eq!(i.category, "geosite-lite");
    assert_eq!(i.path, "geo-lite/geosite/cn.srs");
    assert!(!i.bundled, "lite 变体从不随包");
    assert!(
        find_catalog_item(&i.id).is_none(),
        "lite 变体不得在内置清单里"
    );
}

/// 全表唯一一条远程派生复刻不出内置形态的 id：随包 tag 是 `geosite-category-ai`，上游文件却叫
/// `category-ai-!cn.srs`，而远程只看得见文件名 —— 于是「外置」tab 会把这份**已随包**的数据
/// 列成一条未随包的 `geosite-category-ai-!cn`，用户下回来是第二份同内容副本。
///
/// 不修：修法是给随包表加一张「tag ↔ 上游文件名」的反查表，只为一条数据的展示口径，不划算；
/// 且真下回来也只是多占一份盘，不影响路由（生效的恒是随包那份，见 `route.rs` 注入顺序）。
/// 这条断言把「已知且接受」钉死，免得下次有人当 bug 排查一轮。
#[test]
fn category_ai_is_the_one_id_remote_cannot_reproduce() {
    let builtin = find_catalog_item("geosite-category-ai").expect("内置清单应有此条目");
    let derived = catalog_item_from_tree_path("geo", "geosite/category-ai-!cn.srs").unwrap();
    assert_eq!(
        derived.path, builtin.path,
        "path 仍须同址（下载 URL 不分家）"
    );
    assert_ne!(derived.id, builtin.id);
    assert!(!derived.bundled, "远程侧按文件名判，认不出它已随包");
}

#[test]
fn tree_path_rejects_non_ruleset_and_injection_shapes() {
    // 非 .srs / 非 geosite|geoip 前缀 / 嵌套子目录 / 点开头 / 控制字符与 URL 语义字符。
    for (base, rel) in [
        ("geo", "geosite/cn.txt"),
        ("geo", "other/cn.srs"),
        ("geo", "cn.srs"),
        ("geo", "geosite/sub/cn.srs"),
        ("geo", "geosite/../../evil.srs"),
        ("geo", "geosite/.srs"),
        ("geo", "geosite/a?b.srs"),
        ("geo", "geosite/a#b.srs"),
        ("geo", "geosite/a%2e.srs"),
        ("geo", "geosite/a\\b.srs"),
        ("evil", "geosite/cn.srs"),
    ] {
        assert!(
            catalog_item_from_tree_path(base, rel).is_none(),
            "应拒收: {base}/{rel}"
        );
    }
}

#[test]
fn collect_skips_trees_and_keeps_blobs() {
    let tree = serde_json::from_slice::<Value>(&subtree_json(
        &[
            ("tree", "geosite"),
            ("blob", "geosite/cn.srs"),
            ("blob", "geosite/nested/x.srs"),
            ("blob", "LICENSE"),
        ],
        false,
    ))
    .unwrap();
    let mut out = Vec::new();
    collect_catalog_items(&tree, "geo", &mut out);
    assert_eq!(out.len(), 1, "只应收下 geosite/cn.srs");
    assert_eq!(out[0].id, "geosite-cn");
}

#[test]
fn tree_sha_must_be_hex_of_git_length() {
    assert!(is_valid_tree_sha(GEO_SHA));
    assert!(is_valid_tree_sha(&"a".repeat(64)), "sha256 = 64 位");
    // 远端可控值直接拼进下一跳 URL 的路径段 → 非 hex 一律拒。
    assert!(!is_valid_tree_sha("../../../repos/evil/x/git/trees/main"));
    assert!(!is_valid_tree_sha("short"));
    assert!(!is_valid_tree_sha(&"a".repeat(65)));
    // **长度收敛为「恰好 40 或 64」**：git object id 只有这两种长度，中间那 23 种长度全是
    // 「不可能是 sha 的东西」，放行它们没有任何合法用例。变异锁：改回 `(40..=64).contains(..)`
    // → 下面三条转红。
    for n in [41, 50, 63] {
        assert!(
            !is_valid_tree_sha(&"a".repeat(n)),
            "长度 {n} 不是 git object id 的合法长度"
        );
    }
    let root: Value = serde_json::from_slice(&root_json("../../evil", LITE_SHA)).unwrap();
    assert!(
        tree_child_sha(&root, "geo").is_none(),
        "被注入的 sha 不得被采信"
    );
}

// ── 远程腿 ────────────────────────────────────────────────────────────────

/// **变异锁 #1**：把 [`refresh_catalog_core`] 的远程腿改回恒等降级（直接返
/// `builtin_catalog_result()`）→ 本用例三条断言全红（source / 条数 / 内置表外的 id）。
#[tokio::test]
async fn remote_refresh_returns_remote_source_and_full_list() {
    let dir = tmp_dir("remote");
    let res = refresh_catalog_core(&healthy_mock(), &PublicLookup, &dir, "").await;
    assert_eq!(res.source, "remote", "远程成功必须自述 remote");
    assert!(
        res.fetched_at.is_some_and(|t| t > 0),
        "remote 必须带真时间戳"
    );
    assert_eq!(
        res.items.len(),
        64,
        "60 条填充 + youtube + geoip-cn + lite 两条"
    );
    assert!(
        res.items.len() > rule_resource_catalog().len(),
        "全量必须多于内置清单（恒等降级会让这条转红）"
    );
    assert!(
        res.items.iter().any(|i| i.id == "geosite-site0"),
        "必须含内置表**没有**的条目（证明清单真来自远端）"
    );
    assert!(res.items.iter().any(|i| i.id == "geosite-lite-cn"));
    assert!(catalog_cache_path(&dir).is_file(), "远程成功必须落盘缓存");
    let _ = std::fs::remove_dir_all(&dir);
}

/// **变异锁 #2**：缓存腿。第一轮远程成功落盘，第二轮全网不通 → 必须命中缓存（`source:"cache"`），
/// 且条目与时间戳与第一轮逐字相同。删掉 [`write_catalog_cache`] 或 [`read_catalog_cache`] 任一侧 → 转红。
#[tokio::test]
async fn cache_is_reachable_after_a_successful_refresh() {
    let dir = tmp_dir("cache");
    let first = refresh_catalog_core(&healthy_mock(), &PublicLookup, &dir, "").await;
    assert_eq!(first.source, "remote");
    let second = refresh_catalog_core(&dead_mock(), &PublicLookup, &dir, "").await;
    assert_eq!(second.source, "cache", "有缓存时不得回落到 builtin");
    assert_eq!(second.items, first.items, "缓存回读须与落盘内容逐字相同");
    assert_eq!(
        second.fetched_at, first.fetched_at,
        "fetchedAt 须是落盘那次的真时间"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// 远程失败 + 无缓存 → 诚实降级到内置（与改动前逐字一致：33 条 / builtin / fetchedAt=null）。
#[tokio::test]
async fn remote_failure_without_cache_degrades_to_builtin() {
    let dir = tmp_dir("builtin");
    let res = refresh_catalog_core(&dead_mock(), &PublicLookup, &dir, "").await;
    assert_eq!(res.source, "builtin");
    assert!(res.fetched_at.is_none(), "内置回落不得谎报拉取时间");
    assert_eq!(res.items, rule_resource_catalog());
    assert!(
        !catalog_cache_path(&dir).exists(),
        "失败不得写出任何缓存文件"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// 限流（403/429）与普通网络错分流：消息里必须能看出是限流（60 次/小时是本功能最常见的失败因）。
#[tokio::test]
async fn rate_limited_status_is_distinguished() {
    let mut responses = HashMap::new();
    responses.insert(root_url(), (403u16, b"{}".to_vec()));
    let err = fetch_catalog_from_github(&MockHttp { responses }, &PublicLookup, "")
        .await
        .expect_err("403 必须失败");
    assert!(err.contains("限流"), "限流须可辨识，实得: {err}");

    let mut responses = HashMap::new();
    responses.insert(root_url(), (429u16, b"{}".to_vec()));
    let err = fetch_catalog_from_github(&MockHttp { responses }, &PublicLookup, "")
        .await
        .expect_err("429 必须失败");
    assert!(err.contains("限流"), "二级限流须可辨识，实得: {err}");
}

/// 畸形远端响应（截断 / 条目过少 / 根树结构变了）一律失败，且**不得污染既有缓存**。
#[tokio::test]
async fn malformed_remote_response_fails_and_leaves_cache_intact() {
    let dir = tmp_dir("nopollute");
    let good = refresh_catalog_core(&healthy_mock(), &PublicLookup, &dir, "").await;
    assert_eq!(good.source, "remote");
    let cached_bytes = std::fs::read(catalog_cache_path(&dir)).unwrap();

    // ① truncated:true —— 半份清单不得覆盖好缓存。
    let mut responses = HashMap::new();
    responses.insert(root_url(), (200u16, root_json(GEO_SHA, LITE_SHA)));
    let geo_paths = many_geosite(60);
    let geo: Vec<(&str, &str)> = geo_paths.iter().map(|p| ("blob", p.as_str())).collect();
    responses.insert(subtree_url(GEO_SHA), (200u16, subtree_json(&geo, true)));
    responses.insert(
        subtree_url(LITE_SHA),
        (200u16, subtree_json(&[("blob", "geosite/cn.srs")], false)),
    );
    let res = refresh_catalog_core(&MockHttp { responses }, &PublicLookup, &dir, "").await;
    assert_eq!(res.source, "cache", "截断响应须失败并回落缓存");
    assert_eq!(
        std::fs::read(catalog_cache_path(&dir)).unwrap(),
        cached_bytes,
        "截断响应不得改写缓存"
    );

    // ② 条目过少（< CATALOG_MIN_ITEMS）。
    let mut responses = HashMap::new();
    responses.insert(root_url(), (200u16, root_json(GEO_SHA, LITE_SHA)));
    responses.insert(
        subtree_url(GEO_SHA),
        (200u16, subtree_json(&[("blob", "geosite/cn.srs")], false)),
    );
    responses.insert(subtree_url(LITE_SHA), (200u16, subtree_json(&[], false)));
    let err = fetch_catalog_from_github(&MockHttp { responses }, &PublicLookup, "")
        .await
        .expect_err("条目过少必须失败");
    assert!(err.contains("过少"), "实得: {err}");

    // ③ 根树没有 geo / geo-lite（上游改目录名）。
    let mut responses = HashMap::new();
    responses.insert(
        root_url(),
        (200u16, serde_json::to_vec(&json!({ "tree": [] })).unwrap()),
    );
    assert!(
        fetch_catalog_from_github(&MockHttp { responses }, &PublicLookup, "")
            .await
            .is_err(),
        "根树结构不符必须失败"
    );

    // ④ 非法 JSON。
    let mut responses = HashMap::new();
    responses.insert(root_url(), (200u16, b"<html>rate limited</html>".to_vec()));
    assert!(
        fetch_catalog_from_github(&MockHttp { responses }, &PublicLookup, "")
            .await
            .is_err(),
        "非 JSON 响应必须失败"
    );

    assert_eq!(
        std::fs::read(catalog_cache_path(&dir)).unwrap(),
        cached_bytes,
        "以上畸形响应全程不得改写缓存"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ── 缓存文件本身的畸形面 ───────────────────────────────────────────────────

#[test]
fn malformed_cache_file_is_rejected_wholesale() {
    let dir = tmp_dir("badcache");
    std::fs::create_dir_all(&dir).unwrap();
    let ok_items: Vec<Value> = (0..60)
        .map(|i| {
            json!({
                "id": format!("geosite-site{i}"),
                "category": "geosite",
                "name": format!("site{i}"),
                "path": format!("geo/geosite/site{i}.srs"),
            })
        })
        .collect();
    let write = |v: &Value| std::fs::write(catalog_cache_path(&dir), v.to_string()).unwrap();

    // 基准：合法缓存能读出来（防下面的断言变成「怎么写都读不出」的假绿）。
    write(&json!({ "schemaVersion": 1, "fetchedAt": 1_700_000_000_000i64, "items": ok_items }));
    let (items, at) = read_catalog_cache(&dir).expect("合法缓存必须可读");
    assert_eq!(items.len(), 60);
    assert_eq!(at, 1_700_000_000_000i64);

    // schemaVersion 不符 → 整份作废（不做迁移）。
    write(&json!({ "schemaVersion": 2, "fetchedAt": 1i64, "items": ok_items }));
    assert!(read_catalog_cache(&dir).is_none());

    // fetchedAt 缺失 / 非正 → 作废（否则 UI 会显示 1970）。
    write(&json!({ "schemaVersion": 1, "items": ok_items }));
    assert!(read_catalog_cache(&dir).is_none());
    write(&json!({ "schemaVersion": 1, "fetchedAt": 0i64, "items": ok_items }));
    assert!(read_catalog_cache(&dir).is_none());

    // 条数不够 → 作废（= 远程侧同一道闸）。
    write(&json!({ "schemaVersion": 1, "fetchedAt": 1i64, "items": [ok_items[0].clone()] }));
    assert!(read_catalog_cache(&dir).is_none());

    // 单条被篡改（id 与 path 不自洽）→ **整份**作废，不是跳过那一条。
    let mut tampered = ok_items.clone();
    tampered[3] = json!({
        "id": "geosite-evil", "category": "geosite", "name": "evil",
        "path": "geo/geosite/site3.srs",
    });
    write(&json!({ "schemaVersion": 1, "fetchedAt": 1i64, "items": tampered }));
    assert!(
        read_catalog_cache(&dir).is_none(),
        "id/path 不自洽的条目必须让整份缓存作废"
    );

    // path 里塞穿越 → 作废。
    let mut traversal = ok_items.clone();
    traversal[0] = json!({
        "id": "geosite-x", "category": "geosite", "name": "x",
        "path": "geo/geosite/../../../x.srs",
    });
    write(&json!({ "schemaVersion": 1, "fetchedAt": 1i64, "items": traversal }));
    assert!(read_catalog_cache(&dir).is_none());

    // 非 JSON / 空文件 → 作废（不 panic）。
    std::fs::write(catalog_cache_path(&dir), b"{not json").unwrap();
    assert!(read_catalog_cache(&dir).is_none());
    std::fs::write(catalog_cache_path(&dir), b"").unwrap();
    assert!(read_catalog_cache(&dir).is_none());

    // 文件不存在 → None（不是 panic）。
    std::fs::remove_file(catalog_cache_path(&dir)).unwrap();
    assert!(read_catalog_cache(&dir).is_none());
    assert_eq!(cached_or_builtin_catalog(&dir).source, "builtin");

    let _ = std::fs::remove_dir_all(&dir);
}

// ── 零出站回读缓存（外置 tab 打开即有清单）────────────────────────────────

/// **变异锁**：删掉 [`refresh_catalog_core`] 里的 [`write_catalog_cache`] 调用（或把
/// [`cached_catalog`] 改成恒 `None`）→ 本用例转红 = 外置 tab 又退回「每次打开都得手点刷新」。
#[tokio::test]
async fn cached_catalog_serves_the_list_after_one_successful_refresh() {
    let dir = tmp_dir("cache-only");
    assert!(cached_catalog(&dir).is_none(), "前提：起始无缓存");
    let first = refresh_catalog_core(&healthy_mock(), &PublicLookup, &dir, "").await;
    assert_eq!(first.source, "remote");

    // 第二次「打开弹窗」：不碰网络（本函数签名里根本没有 client），仍拿到同一份清单。
    let preload = cached_catalog(&dir).expect("刷新过一次后必须能零出站读回");
    assert_eq!(preload.source, "cache");
    assert_eq!(preload.items, first.items, "回读须与落盘内容逐字相同");
    assert_eq!(preload.fetched_at, first.fetched_at);
    let _ = std::fs::remove_dir_all(&dir);
}

/// 无缓存 → `None`，**不得**借 `cached_or_builtin_catalog` 那档回落内置：那一档的语义是
/// 「远程拉过且失败了」，而本腿一次网都没打，借它会让 UI 报一个没发生过的失败。
#[test]
fn cached_catalog_without_cache_is_none_not_builtin_fallback() {
    let dir = tmp_dir("cache-only-empty");
    assert!(cached_catalog(&dir).is_none());
    // 正向对照：同目录下带回落的那条腿仍返内置 —— 证明上面的 None 不是「读缓存整体坏了」的假绿。
    assert_eq!(cached_or_builtin_catalog(&dir).source, "builtin");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 缓存里的 `bundled` **不被采信**，一律按当前版本的随包表现算。
///
/// 为什么这条必须有门：缓存是上一个版本落的盘，随包 `.srs` 却随版本增删。信缓存 = 让旧版本的
/// 随包清单决定新版本的 UI —— 新增随包项仍被标成「可下载」（白下一份被 route.rs 挡住的副本），
/// 移除的随包项被标成「已内置」（用户以为在手，配置生成时该 tag 无处可寻，规则静默失效）。
#[test]
fn cached_bundled_flag_is_recomputed_not_trusted() {
    let dir = tmp_dir("bundled-cache");
    std::fs::create_dir_all(&dir).unwrap();
    let mut items: Vec<Value> = (0..60)
        .map(|i| {
            json!({
                "id": format!("geosite-site{i}"),
                "category": "geosite",
                "name": format!("site{i}"),
                "path": format!("geo/geosite/site{i}.srs"),
            })
        })
        .collect();
    // 两条撒谎的条目：随包的自称不随包，未随包的自称随包。
    items.push(json!({
        "id": "geosite-youtube", "category": "geosite", "name": "youtube",
        "path": "geo/geosite/youtube.srs", "bundled": false,
    }));
    items.push(json!({
        "id": "geoip-us", "category": "geoip", "name": "us",
        "path": "geo/geoip/us.srs", "bundled": true,
    }));
    std::fs::write(
        catalog_cache_path(&dir),
        json!({ "schemaVersion": 1, "fetchedAt": 1_700_000_000_000i64, "items": items })
            .to_string(),
    )
    .unwrap();

    let res = cached_catalog(&dir).expect("合法缓存必须可读");
    let bundled_of = |id: &str| res.items.iter().find(|i| i.id == id).unwrap().bundled;
    assert!(
        bundled_of("geosite-youtube"),
        "随包项须判真（缓存说 false 不作数）"
    );
    assert!(
        !bundled_of("geoip-us"),
        "未随包项须判假（缓存说 true 不作数）"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn atomic_write_leaves_no_tmp_residue() {
    let dir = tmp_dir("atomic");
    let items = rule_resource_catalog();
    write_catalog_cache(&dir, 42, &items).expect("写缓存应成功");
    let residue: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
        .filter(|n| n.ends_with(".tmp"))
        .collect();
    assert!(residue.is_empty(), "不得残留 .tmp: {residue:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

// ── gh-proxy 复用（与下载腿同一决策点）────────────────────────────────────

/// 加速前缀命中 GitHub 域时：先打镜像址，镜像失败自动回退原址 —— 与下载腿
/// [`download_and_store`] 逐字同一语义，且都由 [`apply_gh_proxy`] 单点决策。
#[tokio::test]
async fn catalog_json_fetch_prefers_mirror_then_falls_back_to_origin() {
    const PREFIX: &str = "https://gh-proxy.org";
    let origin = "https://raw.githubusercontent.com/o/r/sing/index.json";
    let mirror = apply_gh_proxy(PREFIX, origin).expect("raw 域应被加速");

    // 两条腿都返**合法 git-trees 结构**（否则会被结构闸拦下，那是另一条用例的事），
    // 靠 `tree[0].path` 分辨走了哪条腿。
    let leg = |who: &str| format!(r#"{{"tree":[{{"path":"{who}","type":"tree"}}]}}"#).into_bytes();

    // 镜像可用 → 用镜像的响应。
    let mut responses = HashMap::new();
    responses.insert(mirror.clone(), (200u16, leg("mirror")));
    responses.insert(origin.to_string(), (200u16, leg("origin")));
    let v = fetch_catalog_json(&MockHttp { responses }, &PublicLookup, origin, PREFIX)
        .await
        .unwrap();
    assert_eq!(v["tree"][0]["path"], "mirror", "配了前缀就该先打镜像");

    // 镜像挂了 → 回退原址（设置页对「加速」的承诺：失败自动回退直连）。
    let mut responses = HashMap::new();
    responses.insert(origin.to_string(), (200u16, leg("origin")));
    let v = fetch_catalog_json(&MockHttp { responses }, &PublicLookup, origin, PREFIX)
        .await
        .unwrap();
    assert_eq!(v["tree"][0]["path"], "origin", "镜像失败须回退原址");
}

/// **镜像返「200 + 合法 JSON + 不是 git-trees」时必须仍然回退原址。**
///
/// 变异锁：删掉 `fetch_catalog_json_once` 里的 `tree` 结构闸 → 本用例转红。
/// 触发形态是真实的：gh-proxy 类镜像在限流/未授权时回 `{"code":403,"msg":"..."}`（200 状态 +
/// 合法 JSON）。没有结构闸时，镜像腿被判「成功」→ **原址一次都不打** → 上层
/// `tree_child_sha` 找不到 geo → 整次刷新失败落缓存，而原址其实是好的。
#[tokio::test]
async fn catalog_json_falls_back_when_mirror_returns_json_that_is_not_a_tree() {
    const PREFIX: &str = "https://gh-proxy.org";
    let origin = "https://raw.githubusercontent.com/o/r/sing/index.json";
    let mirror = apply_gh_proxy(PREFIX, origin).expect("raw 域应被加速");

    let mut responses = HashMap::new();
    // 镜像：200 + 能解析的 JSON，但不是 trees 响应。
    responses.insert(
        mirror.clone(),
        (200u16, br#"{"code":403,"msg":"rate limited"}"#.to_vec()),
    );
    responses.insert(
        origin.to_string(),
        (
            200u16,
            br#"{"tree":[{"path":"geo","type":"tree"}]}"#.to_vec(),
        ),
    );
    let v = fetch_catalog_json(&MockHttp { responses }, &PublicLookup, origin, PREFIX)
        .await
        .expect("原址是好的 → 整体必须成功");
    assert!(
        v.get("tree").is_some(),
        "必须拿到原址那份 trees 响应，而不是镜像那份垃圾 JSON"
    );

    // 原址也不是 trees 结构 → 如实 Err（不把垃圾当清单往上送）。
    let mut responses = HashMap::new();
    responses.insert(origin.to_string(), (200u16, br#"{"msg":"nope"}"#.to_vec()));
    assert!(
        fetch_catalog_json(&MockHttp { responses }, &PublicLookup, origin, "")
            .await
            .is_err(),
        "非 trees 结构必须报错"
    );
    // `tree` 存在但不是数组（被换成对象/字符串）同样拒。
    let mut responses = HashMap::new();
    responses.insert(origin.to_string(), (200u16, br#"{"tree":"x"}"#.to_vec()));
    assert!(
        fetch_catalog_json(&MockHttp { responses }, &PublicLookup, origin, "")
            .await
            .is_err(),
        "`tree` 必须是数组"
    );
}

/// **现状登记（不是期望）**：trees API 的 `api.github.com` 不在 `GH_PROXY_HOSTS` 5 域表里，
/// 故清单刷新实际拿不到加速 —— 与 上游（`shared/gh-proxy.ts:58`）和本仓前端
/// （`ui/src/domain/gh-proxy.ts:56`）明写的口径一致。该表补上 `api.github.com` 之日，本用例转红，
/// 提醒把这条注释和文档一起更新（届时刷新腿无需改代码即自动吃上加速）。
#[test]
fn api_github_is_not_mirrored_by_current_host_table() {
    assert_eq!(
        apply_gh_proxy("https://gh-proxy.org", &root_url()),
        None,
        "api.github.com 当前不在加速域表（前后端两侧同口径）"
    );
}

// ── 与下载腿的衔接 ────────────────────────────────────────────────────────

/// 刷新拿到的条目必须能被下载：`plan_from_item` 要能从「刷新后的清单」里解析出 URL/落盘名。
/// **变异锁 #3**：把 [`resolve_catalog_item`] 的第二跳去掉（退回只查内置表）→ 本用例转红
/// （= 用户在外置 tab 勾中任何精选之外的资源都下不下来）。
#[test]
fn download_plan_resolves_ids_that_only_exist_in_refreshed_catalog() {
    let remote_only = catalog_item_from_tree_path("geo", "geosite/discord.srs").unwrap();
    assert!(
        find_catalog_item(&remote_only.id).is_none(),
        "前提：该 id 不在内置 33 条里"
    );
    let extra = vec![remote_only.clone()];

    let plan = plan_from_item(&json!({ "catalogId": "geosite-discord" }), &extra)
        .expect("刷新后的条目应可解析");
    assert_eq!(plan.id, "geosite-discord");
    assert_eq!(
        plan.url,
        "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/discord.srs"
    );
    assert_eq!(plan.file_name, "geosite-discord.srs");

    // 内置表优先级仍在前：同 id 时以内置表为准。
    let shadow = vec![RuleResourceCatalogItem {
        id: "geosite-youtube".into(),
        category: "geosite".into(),
        name: "youtube".into(),
        path: "geo/geosite/EVIL.srs".into(),
        bundled: true,
    }];
    let plan = plan_from_item(&json!({ "catalogId": "geosite-youtube" }), &shadow).unwrap();
    assert!(
        plan.url.ends_with("/geo/geosite/youtube.srs"),
        "内置表必须优先于刷新清单，实得 {}",
        plan.url
    );

    // 两边都没有 → 仍然报错（不静默编一个 URL）。
    assert!(plan_from_item(&json!({ "catalogId": "geosite-nope" }), &extra).is_err());
}

// ── 落盘名：清洗的多对一 + 与目录缓存同名 ──────────────────────────────────

/// **干净 id 的落盘名逐字不变**（零回归底线）——否则已下载的文件全变孤儿、UI 一片「未下载」。
#[test]
fn clean_ids_keep_their_exact_file_name() {
    assert_eq!(
        resource_file_name("geosite-youtube", RuleResourceFormat::Binary),
        "geosite-youtube.srs"
    );
    assert_eq!(
        resource_file_name("res_9f2c.d-1", RuleResourceFormat::Source),
        "res_9f2c.d-1.json"
    );
}

/// **有损清洗必须仍是单射**（reviewer #17）。
///
/// 变异锁：把 `resource_file_name` 改回 `format!("{}.{}", sanitize_file_stem(id), ext)`
/// → 下面的 `assert_ne!` 转红：`a:b` 与 `a*b` 会落到同一个 `a_b.srs`，后下的静默覆盖先下的，
/// 而 config 里两条记录都指向这一个文件 → 其中一条规则集内容必然是错的。
#[test]
fn lossy_sanitisation_still_maps_distinct_ids_to_distinct_files() {
    let f = |id: &str| resource_file_name(id, RuleResourceFormat::Binary);
    assert_ne!(
        f("geosite-a:b"),
        f("geosite-a*b"),
        "折叠字符不同 → 文件必须不同"
    );
    assert_ne!(f("a b"), f("a_b"), "空格 vs 下划线：清洗后同形，哈希须区分");
    // 同一个 id 恒定映射（重下载/更新必须命中同一个文件，不能每次换名）。
    assert_eq!(f("geosite-a:b"), f("geosite-a:b"));
    // 仍然只含安全字符（消歧后缀不得把路径语义带回来）。
    assert!(f("geosite-a/../b")
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')));
}

/// **用户资源不得与目录缓存 `catalog.json` 撞名**（reviewer #13）。
///
/// 变异锁：删掉 `RESERVED_RESOURCE_FILE_NAMES` 判定 → 下面两条转红。
/// 双向危害：下载该资源冲掉目录缓存（下次刷新失去兜底）；刷新目录把用户资源文件写成一份
/// 清单 JSON（该规则集当场失效，而 UI 仍显示「已下载」——`fileExists` 只校 JSON 是对象）。
#[test]
fn user_resource_never_collides_with_the_catalog_cache_file() {
    let name = resource_file_name("catalog", RuleResourceFormat::Source);
    assert_ne!(name, CATALOG_CACHE_FILE, "不得与目录缓存同名");
    assert!(name.starts_with("catalog-") && name.ends_with(".json"));

    // 存量 config 里已登记 `fileName:"catalog.json"` 的资源，重下载时也必须改道。
    let r = RuleResource {
        id: "catalog".into(),
        name: "catalog".into(),
        category: "custom".into(),
        source_url: "https://example.com/catalog.json".into(),
        file_name: CATALOG_CACHE_FILE.into(),
        format: RuleResourceFormat::Source,
        size: 1,
        downloaded_at: "now".into(),
    };
    assert_ne!(
        plan_from_resource(&r).file_name,
        CATALOG_CACHE_FILE,
        "存量登记的撞名也必须改道，否则重下载直接冲掉缓存"
    );

    // 反向：`catalog` 之外的 id 不受影响（保留名单不得误伤）。
    assert_eq!(
        resource_file_name("catalog-cn", RuleResourceFormat::Source),
        "catalog-cn.json"
    );
}

/// 短哈希必须是**确定性**的（写进 config 的 `fileName` 会落盘）：
/// 换编译器/换进程都不得变，否则每次升级都让已下资源变孤儿。
/// 变异锁：改用 `DefaultHasher`（其算法不保证跨版本稳定）→ 本用例仍绿，但注释里的理由失效；
/// 故这里钉的是**具体值**，实现一换即红。
#[test]
fn short_id_hash_is_deterministic_fnv1a() {
    assert_eq!(
        short_id_hash(""),
        format!("{:08x}", {
            let h: u64 = 0xcbf2_9ce4_8422_2325;
            (h ^ (h >> 32)) as u32
        })
    );
    assert_eq!(short_id_hash("a"), short_id_hash("a"));
    assert_ne!(short_id_hash("a"), short_id_hash("b"));
    assert_eq!(short_id_hash("abc").len(), 8);
}
