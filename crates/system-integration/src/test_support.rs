//! 源码级门的**取材锚点**（本 crate 唯一入口）。
//!
//! 实现单点在 `polaris-source-probe`，锚点单点必须在**本 crate**：`env!("CARGO_MANIFEST_DIR")`
//! 在哪个 crate 里展开就解析到哪个 crate 根，写进 `polaris-source-probe` 内部会解析成
//! `crates/source-probe`，全部取材当场跑偏。
//!
//! 收成 wrapper 而不是让每道门各写一次 `polaris_source_probe::module_source!(..)`：取材面的
//! **形状**（模块 = 根文件 + 目录递归、排除 `tests/`）是这一族门共用的判据前提，写在一处才有
//! 唯一的地方解释它、也才有唯一的地方改它。Phase 3 会把 `proxy_ops.rs` 拆进 `proxy_ops/*.rs`，
//! 那之后「取材面覆不覆盖子模块」是多道门共同的存亡条件。

/// `crates/system-integration/src/<rel>` 的全文（**单个文件**）。
///
/// 只在判据确实针对**一个文件**时用（如 `macos_proxy.rs` 这条与 `proxy_ops` 并列的独立实现腿）。
/// 判据针对一个**模块**时一律用 [`module_source`]：单文件形态在模块被拆进子文件的那天会静默
/// 丢掉另一半取材面，建在上面的否定型断言随之恒真 —— 本 crate 正是为此改的锚。
pub(crate) fn crate_source(rel: &str) -> String {
    polaris_source_probe::crate_source_in(env!("CARGO_MANIFEST_DIR"), rel)
}

/// 模块 `<dir_rel>` 的全部生产 `.rs`：根文件 `<dir_rel>.rs` + `<dir_rel>/**` 递归，排除 `tests/`。
///
/// 新增子模块**自动进取材面** —— 这正是手写文件清单缺的那条：清单式取材在「有人加了个文件」
/// 的那天无声失去覆盖，而它守的否定型断言不会喊。
///
/// 取材面为空（目录/根文件都不在）时直接 panic，不返回空串：空串会让否定型断言恒真。
pub(crate) fn module_source(dir_rel: &str) -> String {
    polaris_source_probe::module_source_in(env!("CARGO_MANIFEST_DIR"), dir_rel)
}

/// blob 必须含该来源的独有标识，否则 panic。守的是 [`module_source`] 自己看不出的塌陷：
/// 取材非空、但读到的**不是那个模块**（锚点解析错 / 模块改名搬走）。
pub(crate) use polaris_source_probe::expect_marker;

/// 取材面的**代码面**：注释与字符串/字符字面量按字节抹成空格（偏移与行号不变）。
///
/// 判据针对**符号**（标识符 / 路径 / 类型名）时用它：注释里提到的名字不再喂饱肯定型断言，
/// 也不再绊倒否定型断言。实现单点在 `polaris-source-probe`，此处只收名字。
pub(crate) use polaris_source_probe::mask_comments_and_strings as code_face;

/// 取材面的**字面量面**：只抹注释，字符串/字符字面量原样保留。实现单点在
/// `polaris-source-probe`，此处只收名字（射程与已知边界见 `mask_comments` 的文档）。
///
/// # 为什么不能一律用 [`code_face`]
///
/// 「某文件不得出现 `networksetup` 字面量」这类判据的**对象就是字符串字面量**：连字符串一起抹掉，
/// 针在净化面上永远命中不到 —— 判据不是变弱，是消失（把 `Command::new("networksetup", …)` 整行
/// 复制进去也照样绿，变异收据当场证伪）。故这一族判据只剥注释：注释才是会喂饱 / 绊倒它的散文
/// （`macos_proxy.rs:4` 的模块注释今天就写着 `networksetup`，不剥则该门到货即红）。
///
/// # 与旧的本地实现的差别
///
/// 此前这里是**第二份**手写实现：先跑一遍 `code_face`，再按下标反推哪些区是字面量。那条路带着
/// 一条只往假红走的保守边界（字面量后紧跟的注释可能残留在面上）。现在两个面共用同一份词法扫描，
/// 边界消失，也不再有两份实现各自漂移的余地。
pub(crate) use polaris_source_probe::mask_comments as literal_face;
