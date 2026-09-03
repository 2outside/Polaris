#!/usr/bin/env node

/**
 * 把一次提交的路径差集分类为发布风险面。
 *
 * 输出是稳定 JSON：
 *   - kernel: 是否必须下载真实随包核并执行强制内核门；
 *   - platforms: 必须实际构建安装包的平台腿；
 *   - preflight: 是否需要静态打包/内核预检；
 *   - hasPackage: 是否存在安装包构建腿；
 *   - unregisteredScopes: 落在登记根内、却在两张登记表里都查不到的 scope（fail-closed 的自曝面）。
 *
 * 路径判据由代码持有，workflow 只负责取得 diff 并消费输出。
 * 无法取得可靠 diff 时由调用方传 --full，故障关闭为四平台 + 内核门。
 *
 * ── 两级默认（2026-08-30）：为什么 `crates/` / `src-tauri/` / `resources/` 之内是 fail-closed ──
 *
 * 此前**全部**路径共用一条默认：「未命中任何判据 ⇒ 什么都不加」。它对 ui/、docs/ 是对的，
 * 对 `crates/`、`src-tauri/` 与 `resources/` 是 **fail-open**：新增一个 crate、新建一个 src 子树、
 * 往 `resources/` 加一个随包子目录，它就永久落在全部打包门之外，且没有任何东西会提醒。实测形态（2026-08-30）：改
 * `crates/system-integration/`、`crates/helper-client/`、`crates/stats-engine/`、
 * `src-tauri/src/runtime/` 得到 `kernel=false platforms=[] preflight=false hasPackage=false`
 * ⇒ release-risk.yml 的 preflight / package 两个 job 全 skip ⇒ gate 的三条断言在 required
 * 为 false 时全不生效 ⇒ **绿，但零信息量**。
 *
 * 修法是把「有没有判过」和「判成什么」拆开：登记根之内的每个 scope 必须显式出现在
 * [`PACKAGE_IMPACT_SCOPES`]（影响打包，附平台/内核门）或 [`NO_PACKAGE_IMPACT_SCOPES`]
 * （已判定不影响，附理由）之一。两张表都查不到 ⇒ 按内核门 + 四平台处理，并把 scope 写进
 * `unregisteredScopes` + stderr 自曝。完备性由
 * `ui/src/contracts/ci-impact-coverage-contract.test.ts` 在文件系统侧硬钉：新增 crate /
 * 新建 src 子树而没登记 ⇒ 该门红。
 *
 * 登记根之外（ui/、scripts/、packaging/、.github/、仓库根文件）仍是枚举表 + 未命中不加腿：
 * 那一侧没有可枚举的边界，改用两条反向断言兜（同一个契约测试）：打包 workflow 真正
 * `run:` 的每个仓库脚本、以及 verify-packaging 当判据读的每个源文件，都必须触发打包腿。
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ALL_PACKAGE_PLATFORMS = Object.freeze([
  'linux',
  'windows',
  'macos-arm64',
  'macos-x64',
]);

const ALL = ALL_PACKAGE_PLATFORMS;
const MACOS = Object.freeze(['macos-arm64', 'macos-x64']);
const NO_LEG = Object.freeze([]);

/**
 * fail-closed 的作用域根。这三棵树的内容全部编译进安装包、随包分发或参与打包契约，
 * 且 scope 数量有限可枚举 —— 所以「没登记」在这里是错误，不是默认放行。
 *
 * `resources/` 是 2026-08-30 补上的第三条姊妹腿：`resources/data/` 的 28 个 `.srs` **入库**
 * （`git ls-files resources/data` = 28；.gitignore 以 `/resources/*` + `!/resources/data/` 放行），
 * 四份 conf 的 `bundle.resources` 都含 `../resources/data/` ⇒ 改一个字节，四个安装包的字节都变，
 * 而此前分类器对 `resources/**` 输出 `kernel=false platforms=[] hasPackage=false`（实测），
 * 与改 `crates/`、改 `src-tauri/` 是同一个 fail-open。
 */
export const REGISTRY_ROOTS = Object.freeze(['crates/', 'src-tauri/', 'resources/']);

/**
 * scope 粒度：`crates/<name>/`、`src-tauri/<entry>`、`src-tauri/src/<entry>`。
 * 顺序即优先级（长根先匹配）。
 */
const SCOPE_DEPTH = Object.freeze([
  ['src-tauri/src/', 3],
  ['src-tauri/', 2],
  ['crates/', 2],
  // `resources/<子树>/`：data/ dashboard/ 与四个平台目录各自一个 scope；
  // 根下的散文件（.gitkeep / .fetch-stamp.json）按单文件 scope 归一。
  ['resources/', 2],
]);

/**
 * 把登记根内的任意路径归到它所属的 scope key。
 * 目录 scope 带尾斜杠，单文件 scope 就是文件路径本身；不在登记根内返回 null。
 *
 * 契约测试用同一个函数把文件系统条目翻成 key —— 两侧共用一份归一，避免
 * 「测试期望 `crates/x/`、表里写的是 `crates/x`」这种只在改判据时才暴露的错配。
 */
export function scopeOf(rawPath) {
  const path = normalized(rawPath);
  for (const [root, depth] of SCOPE_DEPTH) {
    if (!path.startsWith(root)) continue;
    const parts = path.split('/');
    if (parts.length < depth) return null;
    if (parts.length === depth) return parts.join('/');
    return `${parts.slice(0, depth).join('/')}/`;
  }
  return null;
}

/**
 * ── 表一：影响打包 ──
 *
 * `kernel` = 必须下载真核跑强制内核门；`platforms` = 必须真出安装包的腿；`why` = 判据。
 * key 比 scope 更细的条目（如 `crates/helper/src/platform/windows/`）按最长前缀胜出，
 * 用来把「整棵树四平台」收窄成单腿。
 */
export const PACKAGE_IMPACT_SCOPES = Object.freeze({
  'crates/config-engine/': {
    kernel: true,
    platforms: NO_LEG,
    why:
      'sing-box config 的生成与 schema 真值；四道强制内核门（core_dep_fingerprint / core_schema_surface / '
      + 'core_build_matrix / kernel_accepts_outbounds）都是本 crate 的 tests，必须拿真核回放。不改包内容 ⇒ 不加腿。',
  },
  'crates/singbox-grpc/': {
    kernel: true,
    platforms: NO_LEG,
    why: '随包核的 gRPC(h2c) API 面，核换版即断 ⇒ 走内核门；纯 lib，不改包内容 ⇒ 不加腿。',
  },
  'crates/helper/': {
    kernel: false,
    platforms: ALL,
    why:
      '随包特权 helper 二进制本体：package.yml 单独 `cargo build -p polaris-helper --target …` 后铺进 '
      + 'resources/<平台>/，是包内资产（2026-08-10 三平台出过不含它的包）。',
  },
  'crates/helper/src/platform/linux/': {
    kernel: false,
    platforms: Object.freeze(['linux']),
    why: 'helper 的 linux 平台实现，只改 linux 那份二进制。',
  },
  'crates/helper/src/platform/windows/': {
    kernel: false,
    platforms: Object.freeze(['windows']),
    why: 'helper 的 windows 平台实现，只改 windows 那份二进制。',
  },
  'crates/helper/src/platform/macos/': {
    kernel: false,
    platforms: MACOS,
    why: 'helper 的 macOS 平台实现，只改两条 mac 腿的二进制。',
  },
  'crates/helper-proto/': {
    kernel: false,
    platforms: ALL,
    why:
      'app ↔ 随包 helper 的线协议。协议改动要求包内 helper 与 app 同版（package.yml 用同一 checkout '
      + 'commit 做构建身份），只有真出一次包才能验到 staging 与协议同版。',
  },
  'crates/updater/': {
    kernel: false,
    platforms: ALL,
    why:
      'verify-packaging.mjs 的「产物命名 ↔ updater 选包」与体积门以 github.rs::find_suitable_update_asset '
      + '为口径 —— 判据源改了必须四平台重跑产物命名断言。',
  },

  'src-tauri/core-manifest.json': {
    kernel: true,
    platforms: ALL,
    why: '随包核版本与资产钉扎的唯一真值：既换核（内核门）又换包内资产（四平台）。',
  },
  'src-tauri/Cargo.toml': {
    kernel: false,
    platforms: ALL,
    why: '主二进制的依赖与 feature 面，四平台的包都变。',
  },
  'src-tauri/build.rs': {
    kernel: false,
    platforms: ALL,
    why:
      '构建期钩子（随包 dashboard / geo 完整性断言、Windows manifest 嵌入），直接决定构建能否出包；'
      + '且它把 tauri.conf.json 的 productName 用 cargo:rustc-env 注入，是 Rust 侧那个值的唯一来源 '
      + '（Linux deb/AppImage 的 /usr/lib/<productName>/ 资源目录名靠它）。'
      + 'verify-packaging inventory 还读它的 EXPECTED_SRS_COUNT 当 .srs 份数判据。',
  },
  'src-tauri/tauri.conf.json': {
    kernel: false,
    platforms: ALL,
    why: 'base bundle 配置（resources / targets / 图标 / CSP），四平台 conf 都以它为底。',
  },
  'src-tauri/capabilities/': {
    kernel: false,
    platforms: ALL,
    why: 'Tauri ACL 能力清单，随包生效且构建期校验。',
  },
  'src-tauri/icons/': {
    kernel: false,
    platforms: ALL,
    why: '包内图标资产（含 NSIS installerIcon / icns / ico）。',
  },
  'src-tauri/permissions/': {
    kernel: false,
    platforms: ALL,
    why: '自定义权限定义，随 capabilities 参与构建期 ACL 校验。',
  },
  'src-tauri/tauri.linux.conf.json': {
    kernel: false,
    platforms: Object.freeze(['linux']),
    why: 'linux 腿的 conf（含该腿的内核目录），只影响 linux 包。',
  },
  'src-tauri/nsis-hooks.nsh': {
    kernel: false,
    platforms: Object.freeze(['windows']),
    why: 'NSIS 安装/卸载钩子，只进 windows 安装器。',
  },
  'src-tauri/nsis-installer.nsi': {
    kernel: false,
    platforms: Object.freeze(['windows']),
    why: 'NSIS 安装器模板，只进 windows 安装器。',
  },
  'src-tauri/nsis-languages/': {
    kernel: false,
    platforms: Object.freeze(['windows']),
    why:
      'tauri.conf.json 的 nsis.customLanguageFiles 指向本目录（Farsi.nsh），既是包内安装器语言资产，'
      + '又被 verify-packaging.mjs 的 confs 模式按 conf 解析后读取。',
  },
  'src-tauri/tauri.windows.conf.json': {
    kernel: false,
    platforms: Object.freeze(['windows']),
    why: 'windows 腿的 conf（含该腿的内核目录），只影响 windows 包。',
  },
  'src-tauri/Info.plist': {
    kernel: false,
    platforms: MACOS,
    why: 'macOS bundle 的 Info.plist，只进两条 mac 腿。',
  },
  'src-tauri/tauri.macos-arm64.conf.json': {
    kernel: false,
    platforms: MACOS,
    why:
      'mac 腿的 conf。两份 mac conf 一起选两条 mac 腿：产物命名/内核目录的对称性错配只有把另一条腿'
      + '一起打出来才看得见（收窄成单腿属独立取舍，改判据时一并改）。',
  },
  'src-tauri/tauri.macos-x64.conf.json': {
    kernel: false,
    platforms: MACOS,
    why: '同上（mac 两条腿成对验证）。',
  },
  // ── resources/：随包资源载荷树（2026-08-30 纳入登记根）──
  'resources/data/': {
    kernel: true,
    platforms: ALL,
    why:
      '内置 geo 规则集的**入库**出厂种子（28 个 .srs，`git ls-files resources/data` 可查）。四份 conf 的 '
      + 'bundle.resources 都含 `../resources/data/` ⇒ 改/增/删一个文件，四个安装包的字节都变。观测面确实挂在打包腿上：'
      + 'verify-packaging inventory 的 `geo-srs` 规则按 min=max=build.rs::EXPECTED_SRS_COUNT 清点（多一个少一个都红），'
      + 'build.rs 的 release 断言再逐个校 SRS 魔数。缺失/损坏的后果是 runtime_rules_dir 种不满 → route builder '
      + 'fail-closed 剪掉全部 geo 规则 → 叠加回国模式即全量明文直连（真机 2026-07-20）。'
      + '完整配置真核门 `kernel_accepts_full_config` 逐份读取这些真实 `.srs` 并在 check 初始化 route.rule_set，'
      + '故必须 kernel=true：缺失、损坏或格式版本漂移会在 release-risk 的 Fetch core/cronet 后立刻转红。',
  },
  'resources/dashboard/': {
    kernel: false,
    platforms: ALL,
    why:
      '随包 sing-box 面板静态站，四份 conf 都 bundle 它。目录被 .gitignore（`/resources/*`），CI 由 '
      + 'scripts/fetch-dashboard.mjs 现拉 ⇒ 正常 diff 里不会出现；一旦出现（`git add -f` 往包里塞文件），'
      + '要判的正是四条腿的 inventory 白名单（dashboard-entry / assets / licenses / icons 四条规则）。',
  },
  'resources/linux/': {
    kernel: false,
    platforms: Object.freeze(['linux']),
    why:
      'linux 腿的随包内核 / libcronet / polaris-helper 落位目录（.gitignore，CI 由 fetch-core、fetch-cronet '
      + '与 helper 构建现铺）。只有 tauri.linux.conf.json 引它 ⇒ 只改 linux 包，由该腿的 inventory 白名单逐条对账。'
      + '核本身的版本真值在 core-manifest.json（已单列 kernel:true），这里只是落位目录 ⇒ 不重复挂内核门。',
  },
  'resources/win/': {
    kernel: false,
    platforms: Object.freeze(['windows']),
    why: '同 resources/linux/，windows 腿的随包二进制落位目录（sing-box.exe / libcronet.dll / polaris-helper.exe）。',
  },
  'resources/mac-arm64/': {
    kernel: false,
    platforms: Object.freeze(['macos-arm64']),
    why:
      '同 resources/linux/，macos-arm64 腿的落位目录。这里**不成对选两条 mac 腿**（与两份 mac conf 的取舍不同）：'
      + 'conf 之间有产物命名/内核目录的对称性要一起验，而资源目录各自只进各自那个包，inventory 也只清点本腿那棵树。',
  },
  'resources/mac-x64/': {
    kernel: false,
    platforms: Object.freeze(['macos-x64']),
    why: '同上，macos-x64 腿的落位目录。',
  },
});

/** 全 crate/子树共享的默认理由：纯应用逻辑，正确性由 ci.yml 三平台 fmt+clippy+build+test 覆盖。 */
const APP_LOGIC = (what) =>
  `${what}；纯 Rust 逻辑，编译进主二进制，不改安装包结构 / 包内资产 / 随包核契约，`
  + '正确性由 ci.yml 三平台 fmt+clippy+build+test 覆盖。';

/**
 * ── 表二：已判定不影响打包 ──
 *
 * value 是理由。在这里 = 「有人看过、判过」，不是「没人管过」。
 */
export const NO_PACKAGE_IMPACT_SCOPES = Object.freeze({
  'crates/core-supervisor/': APP_LOGIC('sing-box 进程 spawn / readiness / 崩溃自愈；核路径由调用方传入'),
  'crates/dns-race/': APP_LOGIC('节点域名解析竞速 sidecar（UDP server + DNS wire 编解码）'),
  'crates/helper-client/': APP_LOGIC(
    'app 侧的 helper 客户端（连接/装卸/token）。线协议真值在 helper-proto（已在影响表），本 crate 不产出包内二进制',
  ),
  'crates/log-budget/': APP_LOGIC('日志预算限流'),
  'crates/mesh/': APP_LOGIC('Tailscale / WARP 组网状态与出口路由；不随包任何第三方二进制'),
  'crates/net-stack/': APP_LOGIC('订阅拉取与分享链接/配置导入解析'),
  'crates/platform-events/': APP_LOGIC(
    '平台网络事件的解析与归一（macOS/Linux route monitor 文本、Linux ip monitor label、'
    + 'Windows IP Helper row → RoutePrefix / NetworkChangeImpact）与运行期绑定计划的数据模型；'
    + '从 src-tauri/src/runtime/ 下沉（E2②），纯 Rust 文本解析，不产出包内二进制、不碰随包核契约',
  ),
  'crates/stats-engine/': APP_LOGIC('连接统计聚合、诊断报告与脱敏'),
  'crates/source-probe/':
    '测试取材锚点 helper（按 CARGO_MANIFEST_DIR / workspace 根读源码）。**dev-only**：只被各 crate 的 '
    + '`[dev-dependencies]` 引用，不进任何 lib/bin 依赖图 ⇒ 不编译进主二进制、不产出包内资产、不碰随包核契约；'
    + '零第三方依赖（只用 std）⇒ Cargo.lock 与 THIRD-PARTY-LICENSES 均无新增。正确性由 ci.yml 三平台 '
    + '`cargo test --workspace` 覆盖。',
  'crates/store/': APP_LOGIC('用户配置持久化、迁移与备份（运行期用户目录，非包内资产）'),
  'crates/switch-engine/': APP_LOGIC('节点切换决策与热切执行'),
  'crates/system-integration/': APP_LOGIC(
    '系统代理 / DNS / 路由的平台操作（macos/windows/linux 子模块按 cfg 编译进主二进制，不是独立随包二进制）',
  ),
  'crates/unlock/': APP_LOGIC('流媒体解锁检测'),
  'crates/unlock-transport/': APP_LOGIC('解锁检测的传输端口抽象'),

  'src-tauri/gen/':
    'tauri-build 在构建期重生成的 ACL/schema 产物，不是包内资产；生成源 capabilities/ 与 permissions/ 已在影响表。',
  'src-tauri/tests/':
    'app crate 的集成测试，只进测试二进制、不进包；由 ci.yml 三平台 `cargo test` 覆盖。',
  'src-tauri/windows-test-manifest.xml':
    'build.rs 只用 `rustc-link-arg-tests` 把它嵌进**测试**二进制（应用 exe 的 manifest 由 tauri-build 的 winres 给），'
    + '不进包；由 ci.yml windows 腿覆盖。',

  'src-tauri/src/app_language.rs': APP_LOGIC('应用内语言与 macOS AppleLanguages 写入'),
  'src-tauri/src/app_tray.rs': APP_LOGIC('托盘装配'),
  'src-tauri/src/clean_exit.rs': APP_LOGIC('退出清理'),
  'src-tauri/src/commands/': APP_LOGIC('IPC command 层'),
  'src-tauri/src/commands.rs': APP_LOGIC('IPC command 模块根'),
  'src-tauri/src/events.rs': APP_LOGIC('事件通道定义'),
  'src-tauri/src/exit_lifecycle.rs': APP_LOGIC('退出生命周期'),
  'src-tauri/src/graphics_compat.rs': APP_LOGIC('图形后端兼容开关'),
  'src-tauri/src/i18n.rs': APP_LOGIC('主进程 i18n（include_str! 前端 locale，编译期内联）'),
  'src-tauri/src/icon_cache.rs': APP_LOGIC('应用图标缓存（运行期用户目录）'),
  'src-tauri/src/idle_lightweight.rs': APP_LOGIC('空闲轻量态'),
  'src-tauri/src/lib.rs': APP_LOGIC('app crate 装配根'),
  'src-tauri/src/logging.rs': APP_LOGIC('日志初始化'),
  'src-tauri/src/main.rs': APP_LOGIC('可执行入口'),
  'src-tauri/src/response.rs': APP_LOGIC('IPC 响应包装'),
  'src-tauri/src/runtime/':
    '运行期实现层（进程/网络/文件系统注入）；纯 Rust 逻辑，编译进主二进制，不改安装包结构。'
    + '**此前的例外已消失**：`proxy.rs` 的 LINUX_BUNDLE_PRODUCT_DIR 曾是 productName 的第二份字面量、'
    + '被 verify-packaging confs 正则抓来对拍，于是整棵子树被钉在打包判据面上。现在 productName 由 '
    + '`src-tauri/build.rs` 从 tauri.conf.json 读出并用 cargo:rustc-env 注入（Rust 侧是 `env!`），'
    + '事实只剩一份、对拍门已删 ⇒ 本子树诚实地退出打包判据面。'
    + '将来若又出现「被打包脚本读取的源码常量」，必须重新单列 —— '
    + 'ui/src/contracts/ci-impact-coverage-contract.test.ts 会按 verify-packaging 的实际读取面反向校验。',
  'src-tauri/src/runtime.rs': APP_LOGIC('runtime 模块根'),
  'src-tauri/src/startup.rs': APP_LOGIC('启动编排'),
  'src-tauri/src/test_support.rs': APP_LOGIC('测试夹具（cfg(test) 面）'),
  'src-tauri/src/tests/':
    'app crate 根模块（`main.rs` 的 `#[cfg(test)] mod tests;`）的测试实体。纯 `cfg(test)` 面：\n    不进任何构建产物、不碰随包资产与内核契约。**没有 `tests.rs` 兄弟**，故不吃模块别名，须显式登记。',
  'src-tauri/src/test_support/':
    '测试夹具的测试实体（`test_support/tests/`）。只在 `cfg(test)` 下编译，不进 lib/bin、不进包；'
    + '由 ci.yml 三平台 `cargo test` 覆盖。',
  'src-tauri/src/tray.rs': APP_LOGIC('托盘窗口'),
  'src-tauri/src/window_health.rs': APP_LOGIC('主窗白屏自愈'),
  'src-tauri/src/windows_single_instance.rs': APP_LOGIC('Windows 单实例'),

  'resources/.gitkeep':
    '唯一入库的 resources 根文件（.gitignore 的 `!/resources/.gitkeep`），作用只是让 resources/ 目录在 clone 里存在。'
    + '四份 conf 的 bundle.resources 只列 data/ 、dashboard/ 与本平台目录三类条目，**resources/ 根下的散文件不进任何包** '
    + '⇒ 不影响打包（同理它也进不了 inventory 的清点面）。',
  'resources/.fetch-stamp.json':
    'scripts/fetch-*.mjs 的本机拉取戳，被 .gitignore 覆盖 ⇒ 永远不会出现在 diff 里、分类器实际判不到它。'
    + '登记它是为了让完备性门在**已 fetch 过的开发机**上枚举到它时不误红；同样不在任何 bundle.resources 条目内。',
});

const CORE_PATHS = new Set(['scripts/fetch-core.mjs', 'scripts/fetch-cronet.mjs']);

/**
 * 随包拉取脚本**被导入的共享模块**面。
 *
 * 取的是**前缀（整个目录）**而不是逐文件枚举：`scripts/lib/*.mjs` 全部由 `scripts/fetch-*.mjs`
 * import（extract-zip 解随包内核/cronet/dashboard/protoc 的 zip，fetch-stamp 决定要不要重拉），
 * 改坏它们与改坏 fetch-core.mjs 本身的后果逐字相同。2026-08-31 前它们两张表都查不到、又不在
 * REGISTRY_ROOTS 内 ⇒ kernel=false platforms=[] 且不进 unregisteredScopes：改随包解包实现零信号，
 * 与本文件头注自称已封堵的 `scripts/fetch-protoc.mjs` fail-open 是同一形态的姊妹腿。
 *
 * 逐文件枚举会原样重造这个盲区（下一个抽出来的共享模块又落表外），故按目录整取；
 * 只被非内核脚本引用的将来模块因此被**从严**判为内核门 —— 方向是 fail-closed，可接受。
 */
const CORE_PATH_PREFIXES = ['scripts/lib/'];

const SHARED_PACKAGE_PATHS = new Set([
  '.cargo/config.toml',
  '.github/workflows/package.yml',
  '.github/workflows/release-risk.yml',
  'Cargo.lock',
  'Cargo.toml',
  'THIRD-PARTY-LICENSES.md',
  'scripts/classify-ci-impact.mjs',
  'scripts/classify-ci-impact.test.mjs',
  'scripts/gate-node-test.sh',
  'scripts/fetch-dashboard.mjs',
  // package.yml 的 `Install protoc` 步骤真跑它（钉扎常量与版本依据的唯一真值）；
  // 它挂了整条打包链就编不出 singbox-grpc。2026-08-30 前它不在任何表里 = 同一 fail-open。
  'scripts/fetch-protoc.mjs',
  'scripts/verify-packaging.mjs',
  'ui/package.json',
  'ui/pnpm-lock.yaml',
]);

const LINUX_PACKAGE_PATHS = new Set(['scripts/postprocess-appimage.mjs']);

function normalized(path) {
  return String(path).replaceAll('\\', '/').replace(/^\.\//, '').trim();
}

function startsWithAny(path, prefixes) {
  return prefixes.some((prefix) => path.startsWith(prefix));
}

function isUiBuildConfig(path) {
  return (
    /^ui\/(vite|postcss|tailwind)\.config\.[^/]+$/.test(path) ||
    /^ui\/tsconfig(?:\.[^/]+)?\.json$/.test(path)
  );
}

/** 两张表里对 `path` 最具体的那条登记（最长 key 胜出）；没有则 null。 */
function directLookup(path) {
  let best = null;
  for (const table of [PACKAGE_IMPACT_SCOPES, NO_PACKAGE_IMPACT_SCOPES]) {
    for (const key of Object.keys(table)) {
      const hit = key.endsWith('/') ? path.startsWith(key) : path === key;
      if (!hit) continue;
      if (best === null || key.length > best.key.length) best = { key, table };
    }
  }
  return best;
}

/**
 * 同一个 Rust 模块的两种路径形态互为别名：`foo.rs` ↔ `foo/`。
 *
 * Rust 里模块 `foo` 的源码天然分布在 `foo.rs`（或 `foo/mod.rs`）**与** `foo/` 两处。把测试实体
 * 外移成 `foo/tests/mod.rs` 会凭空造出 `foo/` 这个 scope key —— 它不是新子系统，打包影响与
 * `foo.rs` 逐字相同。要求为它再登记一遍，等于每拆一次模块就往表里补一条同义条目：判断没变，
 * 表却在长，而每条同义条目都是一次可以填错的机会。
 *
 * **不放松 fail-closed**：别名只在同名兄弟**已登记**时生效。没有 `.rs` 兄弟的全新子树
 * （如 `src-tauri/src/tests/`）依旧两张表都查不到 ⇒ 内核门 + 四平台 + 自曝。
 */
export function moduleAliasesOf(scopeKey) {
  if (scopeKey.endsWith('/')) return [`${scopeKey.slice(0, -1)}.rs`];
  if (scopeKey.endsWith('.rs')) return [`${scopeKey.slice(0, -3)}/`];
  return [];
}

/** 直接登记优先；查不到时回落到同模块的另一种路径形态（见 [`moduleAliasesOf`]）。 */
function lookupScope(path) {
  const direct = directLookup(path);
  if (direct !== null) return direct;
  const scope = scopeOf(path);
  if (scope === null) return null;
  for (const alias of moduleAliasesOf(scope)) {
    const hit = directLookup(alias);
    if (hit !== null) return hit;
  }
  return null;
}

/**
 * 某个 scope key 是否已被两张表覆盖。完备性契约用它算「谁没登记」。
 *
 * 走的是 [`lookupScope`] 本身 —— 与 [`classifyImpact`] 判「要不要 fail-closed」用的**同一个**
 * 函数，而不是照着别名规则再抄一遍。抄一遍就会有一天两边不一致：门说「没登记」而分类器说
 * 「登记了」（假红），或者门说「登记了」而分类器 fail-closed（假绿，漏登记从此不再被门抓到）。
 */
export function isScopeRegistered(scopeKey) {
  const probe = scopeKey.endsWith('/') ? `${scopeKey}__scope_probe__.rs` : scopeKey;
  return lookupScope(probe) !== null;
}

export function classifyImpact(rawPaths, { forceFull = false } = {}) {
  const paths = [...new Set(rawPaths.map(normalized).filter(Boolean))].sort();
  const platforms = new Set();
  const unregistered = new Set();
  let kernel = forceFull;

  const addAll = () => {
    for (const platform of ALL_PACKAGE_PLATFORMS) platforms.add(platform);
  };
  const addMac = () => {
    platforms.add('macos-arm64');
    platforms.add('macos-x64');
  };

  if (forceFull) addAll();

  for (const path of paths) {
    // ── 登记根内：表说了算，没登记就 fail-closed ──
    const scope = lookupScope(path);
    if (scope !== null) {
      if (scope.table === PACKAGE_IMPACT_SCOPES) {
        const decision = PACKAGE_IMPACT_SCOPES[scope.key];
        if (decision.kernel) kernel = true;
        for (const platform of decision.platforms) platforms.add(platform);
      }
      continue;
    }
    if (startsWithAny(path, REGISTRY_ROOTS)) {
      unregistered.add(scopeOf(path) ?? path);
      kernel = true;
      addAll();
      continue;
    }

    // ── 登记根外：枚举表；未命中交给 ci.yml / ui.yml ──
    if (CORE_PATHS.has(path) || startsWithAny(path, CORE_PATH_PREFIXES)) {
      kernel = true;
      addAll();
      continue;
    }
    if (SHARED_PACKAGE_PATHS.has(path)) {
      addAll();
      continue;
    }
    if (LINUX_PACKAGE_PATHS.has(path) || isUiBuildConfig(path)) {
      platforms.add('linux');
      continue;
    }
    if (path.startsWith('packaging/macos-')) {
      addMac();
      continue;
    }
    if (path.startsWith('packaging/')) addAll();
  }

  const orderedPlatforms = ALL_PACKAGE_PLATFORMS.filter((platform) => platforms.has(platform));
  return {
    kernel,
    platforms: orderedPlatforms,
    preflight: kernel || orderedPlatforms.length > 0,
    hasPackage: orderedPlatforms.length > 0,
    unregisteredScopes: [...unregistered].sort(),
    paths,
  };
}

function stdinPaths() {
  const input = readFileSync(0);
  if (input.length === 0) return [];
  const separator = input.includes(0) ? '\0' : '\n';
  return input.toString('utf8').split(separator);
}

function main() {
  const forceFull = process.argv.includes('--full');
  const result = classifyImpact(forceFull ? [] : stdinPaths(), { forceFull });
  // 自曝：未登记 scope 已经按内核门 + 四平台处理，但「为什么这次全量」必须能在日志里读出来。
  for (const scope of result.unregisteredScopes) {
    process.stderr.write(
      `未登记的影响面 scope：${scope} —— 已 fail-closed 为内核门 + 四平台。`
        + '请在 scripts/classify-ci-impact.mjs 的 PACKAGE_IMPACT_SCOPES 或 NO_PACKAGE_IMPACT_SCOPES 里显式判定。\n',
    );
  }
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) main();
