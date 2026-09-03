use super::super::*;

const PREFIX: &str = "https://gh-proxy.org/";
const RAW: &str =
    "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/youtube.srs";

/// 有前缀 + GitHub 域 → 拼成 `<prefix 去尾斜杠>/<完整原 URL>`（与 `CoreDownloader::candidates` 同口径）。
#[test]
fn applies_prefix_to_github_hosts() {
    assert_eq!(
        apply_gh_proxy(PREFIX, RAW).as_deref(),
        Some(
            "https://gh-proxy.org/https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/youtube.srs"
        )
    );
    // 前缀不带尾斜杠 / 带多余空白 → 结果一致（不出现 `//` 也不丢分隔符）。
    assert_eq!(
        apply_gh_proxy("  https://gh-proxy.org  ", RAW),
        apply_gh_proxy(PREFIX, RAW)
    );
    // raw.githubusercontent.com **不在** updater 那张 2 域名 release 资产表里，必须由本表覆盖，
    // 否则规则资源（唯一默认源就是它）恒不加速 —— 本任务的核心断言。
    assert!(apply_gh_proxy(PREFIX, RAW).is_some());
    for host in [
        "github.com",
        "codeload.github.com",
        "gist.githubusercontent.com",
    ] {
        assert!(
            apply_gh_proxy(PREFIX, &format!("https://{host}/a/b.srs")).is_some(),
            "{host} 应可加速"
        );
    }
}

/// 无前缀 / 非 GitHub 域 / URL 不可解析 → None（原样直连，绝不把非 GitHub 地址塞给加速器）。
#[test]
fn skips_when_no_prefix_or_not_github() {
    assert_eq!(apply_gh_proxy("", RAW), None, "空前缀 = 不加速");
    assert_eq!(apply_gh_proxy("   ", RAW), None, "纯空白前缀 = 不加速");
    assert_eq!(
        apply_gh_proxy(PREFIX, "https://example.com/my.srs"),
        None,
        "非 GitHub 域不得套加速前缀"
    );
    assert_eq!(
        apply_gh_proxy(PREFIX, "https://raw.githubusercontent.com.evil.tld/x.srs"),
        None,
        "同后缀的钓鱼域名不得命中（须整串等值比对 host）"
    );
    assert_eq!(apply_gh_proxy(PREFIX, "not a url"), None);
}

/// plan 阶段套前缀：**`fetch_url` 变、`url` 不变**（`url` 会持久化成 `sourceUrl`）。
///
/// **变异锁**：若把 `with_gh_proxy` 改成就地改写 `self.url`（= 把镜像址写进 config），
/// 下面 `plan.url` 的断言转红。
#[test]
fn plan_carries_mirror_in_fetch_url_only() {
    let plan = plan_from_item(&json!({ "catalogId": "geosite-youtube" }), &[])
        .expect("catalog 条目应解析")
        .with_gh_proxy(PREFIX);
    assert_eq!(plan.url, RAW, "登记用的 sourceUrl 必须保持原址");
    assert_eq!(
        plan.fetch_url,
        format!("https://gh-proxy.org/{RAW}"),
        "本次请求须走镜像"
    );
}

/// 无前缀（默认态）：`fetch_url == url`，行为与接线前逐字一致（不给未配置加速的用户引入变化）。
#[test]
fn plan_without_prefix_is_identity() {
    let plan = plan_from_item(&json!({ "catalogId": "geosite-youtube" }), &[])
        .expect("catalog 条目应解析")
        .with_gh_proxy("");
    assert_eq!(plan.fetch_url, plan.url);
    assert_eq!(plan.url, RAW);
}

/// 已登记资源（redownload / update_all 腿）同样套前缀，且 `sourceUrl` 原址不被改写。
#[test]
fn registered_resource_plan_also_mirrors() {
    let r = RuleResource {
        id: "geosite-youtube".into(),
        name: "YouTube".into(),
        category: "geosite".into(),
        source_url: RAW.into(),
        file_name: "geosite-youtube.srs".into(),
        format: RuleResourceFormat::Binary,
        size: 1,
        downloaded_at: "t".into(),
    };
    let plan = plan_from_resource(&r).with_gh_proxy(PREFIX);
    assert_eq!(plan.url, RAW);
    assert!(plan.fetch_url.starts_with("https://gh-proxy.org/"));
    // 自定义（非 GitHub）源不受影响。
    let mut custom = r.clone();
    custom.source_url = "https://cdn.example.com/x.srs".into();
    let p2 = plan_from_resource(&custom).with_gh_proxy(PREFIX);
    assert_eq!(p2.fetch_url, p2.url);
}
