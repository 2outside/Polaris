//! 内置 geo 规则集（geosite-cn / geosite-geolocation-!cn / geoip-cn 等）的单一真值表。
//! 上游 `main/services/builtin-geo-rulesets.ts` 纯逻辑部分。
//!
//! FS I/O（seedBuiltinRuleSets / resourceManager / 运行时目录）属运行时层，不属 config-engine 纯逻辑。
//! config-engine 只消费：tag→fileName 映射 + res:builtin:`<tag>` 引用解析。
//! SRS 魔数校验（isValidSrsFile）是纯字节判定，可注入路径在 config-engine 做。

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::io::Read;
use std::sync::OnceLock;

/// `builtin:` id 前缀。上游 `BUILTIN_ID_PREFIX`。
pub const BUILTIN_ID_PREFIX: &str = "builtin:";

/// 私有/本地域名直连腿引用的 tag（`route.rs` 的固定规则，补 bypass-LAN ip_cidr 的域名盲区）。
///
/// 提成常量而非在 route.rs 写字面量：它是**除地区分流基线和内置应用预设之外**唯一一条硬编码
/// geo 引用，`tests/builtin_geo_alignment.rs` 那道「随包必须有消费点」的门要把它算进消费面 ——
/// 留成字面量的话，门只能跟着抄一份，抄错就是门自己给自己开后路。
pub const PRIVATE_DOMAIN_DIRECT_TAG: &str = "geosite-private";

/// 内置 geo 规则集定义。上游 `BuiltinGeoRuleSet`（纯逻辑子集：tag/fileName/category；bundledPath/sourceUrl 属运行时层）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltinGeoRuleSet {
    pub tag: String,
    pub file_name: String,
    pub category: GeoCategory,
}

impl BuiltinGeoRuleSet {
    /// 该内置集的**上游原址**（网络更新腿用）。
    ///
    /// 此前这层被认为「缺失、需要随包 manifest 才能补」，复核后不成立：地址完全由 tag 推导得出，
    /// 两个源各自的拼法都已在仓内有据 ——
    /// - CN 三件套（`CN_BASELINE_TAGS`）→ SagerNet 的 release 资产，资产名逐字等于 `file_name`
    ///   （`docs/geo-rulesets.md:31` 的 curl 示例就是这条 URL）；
    /// - 其余 → MetaCubeX `meta-rules-dat@sing`，目录已带分类、**文件名是裸名**
    ///   （`rule_resource_catalog.rs:114` 派生 `geo/<kind>/<name>.srs`，非 `geo/<kind>/<kind>-<name>.srs`）。
    ///   裸名由 `file_name` 去掉 `<kind>-` 前缀得到，`category-ai → category-ai-!cn` 这类改名
    ///   已在 `app_geo_entry` 处理过并固化进 `file_name`，此处不必再判一次。
    ///
    /// 返回 `String` 而非 `&'static str`：MRD 那支要拼接。
    #[must_use]
    pub fn source_url(&self) -> String {
        let kind = match self.category {
            GeoCategory::Geosite => "geosite",
            GeoCategory::Geoip => "geoip",
        };
        if CN_BASELINE_TAGS.contains(&self.tag.as_str()) {
            let base = match self.category {
                GeoCategory::Geosite => SAGERNET_GEOSITE_RELEASE,
                GeoCategory::Geoip => SAGERNET_GEOIP_RELEASE,
            };
            return format!("{base}/{}", self.file_name);
        }
        let bare = self
            .file_name
            .strip_prefix(&format!("{kind}-"))
            .unwrap_or(&self.file_name);
        format!("{MRD_GEO_RAW_BASE}/{kind}/{bare}")
    }
}

/// geo 分类。上游 `RuleResourceCategory`（geo 部分）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoCategory {
    Geosite,
    Geoip,
}

/// 内置应用分流预设引用的 geo 标签（随包本地优先）。上游 `APP_GEOSITE_TAGS`（builtin-geo-rulesets.ts:42）。
const APP_GEOSITE_TAGS: &[&str] = &[
    "youtube",
    "netflix",
    "tiktok",
    "telegram",
    "twitter",
    "instagram",
    "openai",
    "anthropic",
    "category-ai",
    "google",
    "github",
    "spotify",
    "steam",
    "epicgames",
    "riot",
    "disney",
    "private",
];
/// 上游 `APP_GEOIP_TAGS`（builtin-geo-rulesets.ts:61）。
const APP_GEOIP_TAGS: &[&str] = &["netflix", "telegram", "twitter", "private"];
/// 地区分流场景的 geo（伊朗/俄罗斯，随包本地优先；CN 已在上方三件套）。上游 `REGION_GEOSITE_TAGS`。
const REGION_GEOSITE_TAGS: &[&str] = &["category-ir", "category-ru"];
/// 上游 `REGION_GEOIP_TAGS`。
const REGION_GEOIP_TAGS: &[&str] = &["ir", "ru"];
const MRD_GEO_RAW_BASE: &str =
    "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo";

/// 国内基线三件套：**源不是 MetaCubeX 而是 SagerNet**（`docs/geo-rulesets.md:10` 登记的出处），
/// 且它们走 release 资产而非仓库 raw 路径 —— 混用会 404。
const CN_BASELINE_TAGS: &[&str] = &["geosite-cn", "geosite-geolocation-!cn", "geoip-cn"];
const SAGERNET_GEOSITE_RELEASE: &str =
    "https://github.com/SagerNet/sing-geosite/releases/latest/download";
const SAGERNET_GEOIP_RELEASE: &str =
    "https://github.com/SagerNet/sing-geoip/releases/latest/download";

/// 构建 app/region geo 条目。上游 `appGeoEntry`（仅 tag/fileName/category 部分）。
fn app_geo_entry(cat: GeoCategory, tag: &str) -> BuiltinGeoRuleSet {
    // category-ai 在 MetaCubeX 用 category-ai-!cn（裸 category-ai 不单独成 .srs）；
    // tag 仍为 geosite-category-ai（与 app-rule 生成对齐）。
    let src_name = if matches!(cat, GeoCategory::Geosite) && tag == "category-ai" {
        "category-ai-!cn"
    } else {
        tag
    };
    let cat_str = match cat {
        GeoCategory::Geosite => "geosite",
        GeoCategory::Geoip => "geoip",
    };
    BuiltinGeoRuleSet {
        tag: format!("{cat_str}-{tag}"),
        file_name: format!("{cat_str}-{src_name}.srs"),
        category: cat,
    }
}

/// 完整内置 geo 规则集表。上游 `BUILTIN_GEO_RULESETS`。
pub fn builtin_geo_rulesets() -> Vec<BuiltinGeoRuleSet> {
    let mut v = Vec::new();
    // CN 三件套（SagerNet 源，非 MetaCubeX；tag/fileName 固定）
    v.push(BuiltinGeoRuleSet {
        tag: "geosite-cn".into(),
        file_name: "geosite-cn.srs".into(),
        category: GeoCategory::Geosite,
    });
    v.push(BuiltinGeoRuleSet {
        tag: "geosite-geolocation-!cn".into(),
        file_name: "geosite-geolocation-!cn.srs".into(),
        category: GeoCategory::Geosite,
    });
    v.push(BuiltinGeoRuleSet {
        tag: "geoip-cn".into(),
        file_name: "geoip-cn.srs".into(),
        category: GeoCategory::Geoip,
    });
    // 内置应用分流预设的 geo（随包，本地优先）。上游 `...APP_GEOSITE_TAGS`（builtin-geo-rulesets.ts:106）。
    for t in APP_GEOSITE_TAGS {
        v.push(app_geo_entry(GeoCategory::Geosite, t));
    }
    for t in APP_GEOIP_TAGS {
        v.push(app_geo_entry(GeoCategory::Geoip, t));
    }
    // 地区分流场景的 geo（伊朗/俄罗斯，随包本地优先；CN 已在上方三件套）。
    // 上游 `...REGION_GEOSITE_TAGS`（builtin-geo-rulesets.ts:109）——app geo 与 region geo 各自先 geosite 后 geoip。
    for t in REGION_GEOSITE_TAGS {
        v.push(app_geo_entry(GeoCategory::Geosite, t));
    }
    for t in REGION_GEOIP_TAGS {
        v.push(app_geo_entry(GeoCategory::Geoip, t));
    }
    v
}

/// 上游 `isBuiltinId`。
pub fn is_builtin_id(id: &str) -> bool {
    id.starts_with(BUILTIN_ID_PREFIX)
}

/// 上游 `builtinIdFor`。
pub fn builtin_id_for(tag: &str) -> String {
    format!("{BUILTIN_ID_PREFIX}{tag}")
}

/// 上游 `builtinTagFromId`。
pub fn builtin_tag_from_id(id: &str) -> &str {
    &id[BUILTIN_ID_PREFIX.len()..]
}

/// 上游 `findBuiltin`。
pub fn find_builtin(tag: &str) -> Option<BuiltinGeoRuleSet> {
    builtin_geo_rulesets().into_iter().find(|b| b.tag == tag)
}

/// 该 geo tag 是否**随包出厂**（本表全量 tag 的集合判定）。
///
/// 存在的理由：资源库条目的 id 与本表 tag **同形**（`rule_resource_catalog.rs` 模块头明记的有意设计），
/// 于是「这条资源要不要下载」可以由本表直接回答 —— 随包项在 `route.rs` 里恒被优先注入
/// （`builtin_defined` 先于 `add_local_geo_rule_set`），下载副本只在随包 `.srs` 缺失/损坏时才顶上，
/// 正常态下**下载它是空动作**。这个判定就是给 UI 用来把这类条目标成「已内置」而非「可下载」的。
///
/// 用集合而非 [`find_builtin`] 线性找：调用点是全量清单（2000+ 条）的逐条判定，
/// 每条都重建一次 28 条 Vec 是纯浪费；`OnceLock` 让它进程内只算一次。
pub fn is_bundled_geo_tag(tag: &str) -> bool {
    static TAGS: OnceLock<HashSet<String>> = OnceLock::new();
    TAGS.get_or_init(|| builtin_geo_rulesets().into_iter().map(|b| b.tag).collect())
        .contains(tag)
}

/// 解析 `res:builtin:<tag>` 引用为 rule_set 定义所需元数据。
///
/// **纯函数（不查 FS）**：非内置 id / 未知 tag → None。FS 守卫由调用方在拼出 runtime 路径后施加。
/// 上游 `resolveBuiltinRuleSetRefMeta`。
pub fn resolve_builtin_rule_set_ref_meta(res_id: &str) -> Option<(String, String)> {
    if !is_builtin_id(res_id) {
        return None;
    }
    let tag = builtin_tag_from_id(res_id);
    find_builtin(tag).map(|b| (b.tag, b.file_name))
}

/// SRS 文件魔数校验（'SRS' = 0x53 0x52 0x53），拦半写/损坏文件。
///
/// 纯字节判定：读前 3 字节比对魔数。上游 `isValidSrsFile`。
/// 路径由调用方注入（config-engine 不直接操作 FS，但此函数属纯字节校验，接受 reader）。
pub fn is_valid_srs_bytes(first3: [u8; 3]) -> bool {
    first3[0] == 0x53 && first3[1] == 0x52 && first3[2] == 0x53
}

/// SRS 文件校验（读文件前 3 字节）。路径不存在/读失败 → false。
/// config-engine 测试不触碰宿主 FS，此函数仅由运行时层（system-integration crate）消费。
pub fn is_valid_srs_file(path: &std::path::Path) -> bool {
    let mut buf = [0u8; 3];
    match std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut buf)) {
        Ok(()) => is_valid_srs_bytes(buf),
        Err(_) => false,
    }
}

/// 计算应用分流预设引用的 geo 标签集合（geosite + geoip），用于随包 bundle 判定。
/// 上游 `APP_GEOSITE_TAGS` + `APP_GEOIP_TAGS`（getLocalGeoRuleSets 消费）。
pub fn app_geo_tags() -> (HashSet<String>, HashSet<String>) {
    let geosite: HashSet<String> = APP_GEOSITE_TAGS
        .iter()
        .map(|s| format!("geosite-{s}"))
        .collect();
    let geoip: HashSet<String> = APP_GEOIP_TAGS
        .iter()
        .map(|s| format!("geoip-{s}"))
        .collect();
    (geosite, geoip)
}

/// MRD geo raw 基址（运行时层网络更新用，config-engine 暴露供 sourceUrl 拼装）。
pub fn mrd_geo_raw_base() -> &'static str {
    MRD_GEO_RAW_BASE
}

#[cfg(test)]
mod tests;
