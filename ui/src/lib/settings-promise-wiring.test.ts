/**
 * G13 —— 空承诺守卫：设置页常驻 `desc` 与悬浮 `tip` 文案里的**行为承诺**必须有对应实现。
 *
 * # 守什么
 *
 * 「界面承诺了但没做」是最伤信任的一类缺陷，而它在类型系统和单测里**完全不可见**：文案是字符串，
 * 开关照样写得进配置，只是没人读那个键、也没人起那个计时器。原型侧就有活样本 —— `proto:2090`
 * 写着「闲置 10 分钟后用密码锁定界面」、`proto:2108` 写着轻量模式同款承诺，而原型全文**没有任何计时器**
 * （`openLock` 的调用点只有托盘和演示菜单）。实现侧把这两条兑现了；本门是为了防同病在实现侧长出来。
 *
 * # 判据面
 *
 * 设置屏及其直属呈现 owner 里全部 `desc=` / `tip=` 的取值 —— 内联字符串、
 * `t('key')` / `t('key', '兜底')`（key 经 `i18n/locales/zh-CN.json` 解析）、以及三元表达式原文。
 * 命中**承诺词典**（`自动` / `启动时` / `闲置` / `下次打开` / `N 分钟` / `N 秒` / `每天`）的每一条，
 * 必须在下方登记表里，且登记的兑现证据必须在磁盘上真的成立。
 *
 * # 两条腿
 *
 *  - **腿 A（定量承诺，全自动）**：文案里写了「N 分钟 / N 秒」，就必须在前端或 Rust 源码里找得到
 *    一个**数值相等且真被引用**的计时常量。改文案的数字而不改常量 ⇒ 转红。
 *  - **腿 B（登记表）**：每条承诺登记它的兑现证据 —— `config-key`（机器自查该键在设置屏之外有没有消费方）
 *    或 `anchor`（指定文件里必须出现的源码片段）。**表外命中 → 转红**（新写一句承诺文案必须一起登记）。
 *
 * # 为什么这里守的是措辞
 *
 * 别处的 `*-wiring.test.ts` 都写着「守形态不守措辞」。**本门相反、且必须相反**：
 * 承诺就在措辞里，改文案 = 改承诺 = 该重新举证。这不是例外，是判据面本身不同。
 *
 * # 射程之外（如实标注，不假装覆盖）
 *
 *  - 非设置页的承诺文案（空状态、toast、弹窗说明）不在射程内 —— 判据面需人工圈定，本批只圈了设置页。
 *  - 「消费方存在」≠「行为正确」。本门证明的是「那个键/计时器有人读」，不是「读了以后做对了」。
 *    后者要真机看。
 */
import { describe, it, expect } from 'vitest';

import { moduleSource, moduleSourceWithTests } from '@/contracts/rust-source.test-support';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const SRC = fileURLToPath(new URL('..', import.meta.url));
const REPO = fileURLToPath(new URL('../../..', import.meta.url));
const SETTINGS_DIR = join(SRC, 'components/screens/settings');

/** 去注释（注释里逐字引用文案与旧承诺，直接扫会误判）。 */
function code(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

function walk(dir: string, ext: RegExp, acc: string[] = []): string[] {
  for (const e of readdirSync(dir)) {
    if (e === 'node_modules' || e === 'dist' || e === 'target') continue;
    const full = join(dir, e);
    if (statSync(full).isDirectory()) walk(full, ext, acc);
    else if (ext.test(e) && !/\.(test|spec)\.tsx?$/.test(e)) acc.push(full);
  }
  return acc;
}

// ── 判据面 1：设置屏的常驻说明与信息提示 ────────────────────────────────────

const ZH = JSON.parse(
  readFileSync(join(SRC, 'i18n/locales/zh-CN.json'), 'utf8'),
) as Record<string, unknown>;

function i18n(key: string): string | undefined {
  const v = key.split('.').reduce<unknown>((a, c) => (a && typeof a === 'object' ? (a as Record<string, unknown>)[c] : undefined), ZH);
  return typeof v === 'string' ? v : undefined;
}

/** 承诺词典 —— 命中即「这句话向用户许诺了某个行为」。 */
const PROMISE_LEXICON = /自动|启动时|闲置|下次打开|每天|停止记录|\d+\s*(分钟|秒)/;

interface DescHit {
  file: string;
  text: string;
}

/**
 * 把表达式里的 `t('key')` / `t('key', '兜底')` 就地换成 zh-CN 译文。
 *
 * 三元 desc（`desc={cond ? t('a') : t('b')}`）落在最后那条 `\{([^}]*)\}` 分支上，拿到的是**源码原文**。
 * 文案还是内联中文时这没问题；收口进 locale 之后，原文里只剩键名 ⇒ 承诺词典一条都命中不了，
 * 整条承诺**从判据面上消失**（登记表那侧表现为「孤儿行」）。这一步把键还原成文案，
 * 让本门看穿三元，比只认单个 `t()` 的旧抽取器射程更大。
 */
function resolveT(expr: string): string {
  return expr.replace(/\bt\(\s*'([^']+)'(?:\s*,\s*'([^']*)')?\s*\)/g, (whole, key: string, fallback?: string) =>
    i18n(key) ?? fallback ?? whole,
  );
}

function collectDescs(): DescHit[] {
  const out: DescHit[] = [];
  for (const f of readdirSync(SETTINGS_DIR).filter((n) =>
    /^Settings.*\.tsx$/.test(n) || ['AppUpdateCard.tsx', 'CoreUpdateCard.tsx'].includes(n),
  )) {
    const src = code(readFileSync(join(SETTINGS_DIR, f), 'utf8'));
    const re = /(?:desc|tip)=(?:"([^"]*)"|\{t\('([^']+)'(?:,\s*'([^']*)')?[\s\S]*?\}|\{([^}]*)\})/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(src))) {
      const raw = m[1] ?? (m[2] ? (i18n(m[2]) ?? m[3] ?? `<未解析 ${m[2]}>`) : m[4]) ?? '';
      out.push({ file: f, text: resolveT(raw).replace(/\s+/g, ' ').trim() });
    }
  }
  return out;
}

const DESCS = collectDescs();
const PROMISES = DESCS.filter((d) => PROMISE_LEXICON.test(d.text));

// ── 判据面 2：前端 / Rust 的消费方语料 ──────────────────────────────────────

const UI_FILES = walk(SRC, /\.tsx?$/).map((f) => ({
  rel: relative(SRC, f).split(sep).join('/'),
  src: code(readFileSync(f, 'utf8')),
}));

/**
 * 消费方语料：**排掉设置屏本身**（写进配置不算读；空承诺的定义就是「只有设置页动它」）与
 * `contracts/`（纯类型声明），Rust 侧再排掉 `crates/store` 与 `user_config`
 * ——那两处是「存得下这个键」的 schema / 默认值层，不是「读来用」。
 */
const CONSUMER_TS = UI_FILES.filter(
  (f) => !f.rel.startsWith('components/screens/settings/') && !f.rel.startsWith('contracts/'),
)
  .map((f) => f.src)
  .join('\n');

const CONSUMER_RS = [...walk(join(REPO, 'src-tauri', 'src'), /\.rs$/), ...walk(join(REPO, 'crates'), /\.rs$/)]
  .filter((f) => !f.includes(`${sep}store${sep}`) && !f.includes('user_config'))
  .map((f) => code(readFileSync(f, 'utf8')))
  .join('\n');

/** camelCase → snake_case（Rust 侧可能用 serde 重命名后的字段名读）。 */
const snake = (k: string) => k.replace(/([A-Z])/g, (c) => `_${c.toLowerCase()}`);

/** 该配置键在设置屏之外有没有真正的消费方。 */
function hasConsumer(key: string): boolean {
  return (
    CONSUMER_TS.includes(key) || CONSUMER_RS.includes(key) || CONSUMER_RS.includes(snake(key))
  );
}

/** 全前端的「毫秒数值常量」表：`值 → 声明它的文件与名字`。 */
function msConstants(): Map<number, { rel: string; name: string }[]> {
  const out = new Map<number, { rel: string; name: string }[]>();
  for (const f of UI_FILES) {
    for (const m of f.src.matchAll(/const\s+([A-Z][A-Z0-9_]*)\s*=\s*([\d\s*+]+);/g)) {
      const expr = m[2].trim();
      if (!/^[\d\s*+]+$/.test(expr)) continue;
      const v = Number(new Function(`return (${expr});`)());
      if (!Number.isFinite(v)) continue;
      const list = out.get(v) ?? [];
      list.push({ rel: f.rel, name: m[1] });
      out.set(v, list);
    }
  }
  return out;
}

const MS_CONSTANTS = msConstants();

/** Rust 源码全文（含 store/user_config —— 那两处被 `CONSUMER_RS` 排除，但常量声明可能落在里面）。 */
const ALL_RS = [...walk(join(REPO, 'src-tauri', 'src'), /\.rs$/), ...walk(join(REPO, 'crates'), /\.rs$/)]
  .map((f) => readFileSync(f, 'utf8'))
  .join('\n');

/**
 * 按名字取一个常量的**毫秒值**，取不到返回 null。单位由名字后缀判定（`_SECS`/`_SEC` → ×1000，
 * 其余按毫秒），这是本仓既有的命名约定；后缀之外的写法一律判取不到，宁可红也不猜。
 *
 * 两种语言分开扫而不是合并成一张表：合并回到「按数值查」的老路，就又会出现一个常量顶两条承诺。
 * 这里只按**名字**取值，调用方拿它和文案里的数字比。
 */
function constantValueMs(lang: 'ts' | 'rs', name: string): number | null {
  const src =
    lang === 'ts' ? UI_FILES.map((f) => f.src).join('\n') : ALL_RS;
  // ts: `const NAME = 10 * 60 * 1000;`  rs: `const NAME: u64 = 10 * 60;`
  const re = new RegExp(`const\\s+${name}\\s*(?::\\s*[A-Za-z0-9_]+\\s*)?=\\s*([\\d\\s*+]+)\\s*;`);
  const m = src.match(re);
  if (!m) return null;
  const expr = m[1].trim();
  if (!/^[\d\s*+]+$/.test(expr)) return null;
  const v = Number(new Function(`return (${expr});`)());
  if (!Number.isFinite(v)) return null;
  return /_SECS?$/.test(name) ? v * 1000 : v;
}

/** 某个毫秒时长有没有「等值常量 + 该常量真被引用 + 声明它的模块真被别处 import」。 */
function timerFor(ms: number): { rel: string; name: string } | null {
  for (const c of MS_CONSTANTS.get(ms) ?? []) {
    const uses = UI_FILES.reduce(
      (n, f) => n + (f.src.match(new RegExp(`\\b${c.name}\\b`, 'g'))?.length ?? 0),
      0,
    );
    const mod = c.rel.replace(/\.tsx?$/, '');
    const importedElsewhere = UI_FILES.some(
      (f) => f.rel !== c.rel && (f.src.includes(`/${mod}'`) || f.src.includes(`@/${mod}'`)),
    );
    if (uses >= 2 && importedElsewhere) return c;
  }
  // renderer 被回收后前端计时器会停，窗口/托盘生命周期阈值因此住在 Rust。这里把 Rust 常量纳入
  // 宽口径存在性门；下方 REGISTRY 仍按名字逐条绑定，防同值常量互相顶绿。
  for (const m of ALL_RS.matchAll(/const\s+([A-Z][A-Z0-9_]*)\s*:\s*[A-Za-z0-9_]+\s*=\s*([\d\s*+]+)\s*;/g)) {
    const name = m[1];
    const value = constantValueMs('rs', name);
    const uses = ALL_RS.match(new RegExp(`\\b${name}\\b`, 'g'))?.length ?? 0;
    if (value === ms && uses >= 2) return { rel: '<rust>', name };
  }
  return null;
}

// ── 自曝：任一判据面塌了就在模块加载期炸 ────────────────────────────────────

if (DESCS.length < 30) {
  throw new Error(`[settings-promise-wiring] 只抽到 ${DESCS.length} 条说明 —— 抽取器塌了`);
}
if (PROMISES.length === 0) {
  throw new Error('[settings-promise-wiring] 一条承诺文案都没命中 —— 词典或抽取器塌了，登记表会恒绿');
}
if (CONSUMER_TS.length < 100_000 || CONSUMER_RS.length < 100_000) {
  throw new Error(
    `[settings-promise-wiring] 消费方语料过小（ts=${CONSUMER_TS.length} rs=${CONSUMER_RS.length}）—— hasConsumer 会恒假`,
  );
}
if (MS_CONSTANTS.size === 0) {
  throw new Error('[settings-promise-wiring] 一个毫秒常量都没解析出来 —— 腿 A 会恒红/恒绿');
}

// ── 登记表 ─────────────────────────────────────────────────────────────────

/**
 * 锚点取材面：带扩展名 ⇒ 单文件；不带 ⇒ Rust 模块源码，**默认只取生产**（递归覆盖
 * `<模块>/**`、剔除 `tests/`），`withTests` 才把 `tests/` 并进来。
 *
 * 为什么默认必须剔除 `tests/`：本表登记的绝大多数是「生产实现还在」的**正向**断言，而 Rust
 * 测试里常有逐字引用生产签名的字符串字面量 —— `proxy/tests/process_supervision.rs` 就把
 * `"    fn spawn_crash_monitor(self: &Arc<Self>, my_gen: u64) {"` 写成了 `const HEAD`。
 * 含 `tests/` 的取材面上，生产侧那个方法被删干净、本门照样全绿（2026-08-30 实测复现：
 * 生产定义改名后 12/12 仍绿）。
 *
 * 为什么不干脆写死那一个 `.rs`：生产实现会随模块拆分搬进 `<模块>/xxx.rs`，写死 `<模块>.rs`
 * 会让锚点凭空「消失」，被本门报成「实现被删/改名」（2026-08-30 真实误报）。
 */
function anchorSource(file: string, withTests = false): string {
  if (/\.[A-Za-z0-9]+$/.test(file)) return readFileSync(join(REPO, file), 'utf8');
  return withTests ? moduleSourceWithTests(file) : moduleSource(file);
}

/**
 * 一条锚点证据。`file` 两种写法（见 [`anchorSource`]）：
 * - **文件路径**（带扩展名）：只读那一个文件；
 * - **Rust 模块路径**（不带扩展名）：读该模块源码，取材面由 `withTests` 决定。
 */
interface AnchorItem {
  file: string;
  needle: string;
  /**
   * 唯一合法理由：needle 钉的是一条 `#[test]`（测试实体外移到 `<模块>/tests/` 之后，生产
   * 取材面里根本没有它）。**不得**用它来「让断言别红」——那正是本门 2026-08-30 的假绿口子，
   * 下方「`withTests` 只许用在生产面确实没有的锚点上」一条会把这种滥用当场判红。
   */
  withTests?: true;
}

type Evidence =
  | { kind: 'config-key'; key: string }
  | ({ kind: 'anchor' } & AnchorItem)
  | { kind: 'anchors'; items: readonly AnchorItem[] }
  | { kind: 'not-a-promise'; reason: string };

interface PromiseRow {
  /** desc 文案里能唯一定位这条承诺的片段（承诺原文，不是形态）。 */
  snippet: string;
  evidence: Evidence;
  /**
   * 定量承诺（文案含「N 分钟 / N 秒」）必须显式登记**兑现它的那一个**常量。
   *
   * 为什么不能只按数值查「存不存在等值常量」（腿 A 的原实现）：设置页现有两条 10 分钟承诺
   * （自动轻量模式、自动隐私锁），一个 600000 常量就能同时把两条顶绿。2026-07-30 轻量模式的
   * 阈值挪进 Rust（`idle_lightweight.rs`）后前端已无对应常量，腿 A 却仍绿 —— 靠隐私锁那个
   * `IDLE_PRIVACY_LOCK_MS` 顶着。门看着在防守，实际对这条已完全失效：Rust 那边把 600 改成
   * 300，文案还写 10 分钟，门不会红。
   *
   * `lang:'rs'` 那档扫 Rust 源码，因为阈值本就该待在真正计时的那一侧（renderer 在窗口隐藏时
   * 会被 WebKit 节流，计时器留在那儿等于不计时）。单位由常量名后缀判定，见 `constantValueMs`。
   */
  timer?: { lang: 'ts' | 'rs'; name: string };
}

/**
 * 设置页全部行为承诺 ↔ 兑现证据。**表外命中 → 转红**：新写一句「自动 X」而不举证，门会拦。
 *
 * `config-key` 的兑现由机器自查（该键在设置屏之外必须有读它的地方）；
 * `anchor` 用于「不绑配置键」的承诺（纯说明行、或行为由固定实现兜底），指定必须存在的源码片段。
 */
const REGISTRY: readonly PromiseRow[] = [
  {
    snippet: '下次打开时还原上次的窗口布局',
    evidence: { kind: 'config-key', key: 'rememberWindowSize' },
  },
  {
    snippet: '界面隐藏或最小化 10 分钟后释放内存',
    evidence: { kind: 'config-key', key: 'autoLightweightMode' },
    // 阈值在 Rust 侧：这条要销毁的正是 renderer 自己，计时器不能留在被销毁方（且隐藏窗的
    // setTimeout 会被 WebKit 节流）。见 `src-tauri/src/idle_lightweight.rs`。
    timer: { lang: 'rs', name: 'HIDDEN_RECLAIM_SECS' },
  },
  {
    snippet: '默认开启。应用启动后会在后台预建托盘菜单',
    evidence: {
      kind: 'anchors',
      items: [
        {
          file: 'crates/store/src/store.rs',
          needle: '"keepTrayMenuWarm": true',
        },
        {
          file: 'src-tauri/src/main.rs',
          needle: 'tray::prewarm_overlay_if_enabled(app.handle());',
        },
        {
          // 模块形（不带扩展名）：`prewarm_overlay_if_enabled` 按拆分设计要进 `tray/window.rs`，
          // 写死 `tray.rs` 会在那天把这条正向锚点报成「实现被删/改名」。
          file: 'src-tauri/src/tray',
          needle: 'lifecycle.request_prewarm(window_exists)',
        },
      ],
    },
  },
  {
    snippet: '关闭后改为按需创建，隐藏 2 分钟会自动释放',
    // 配置消费方在 Rust 托盘生命周期：打开 warm 取消在飞回收，关闭时隐藏窗恢复 120s 计时；
    // `config-key` 门会要求设置屏之外存在真实读取，避免只长出一个无效开关。
    evidence: { kind: 'config-key', key: 'keepTrayMenuWarm' },
    timer: { lang: 'rs', name: 'TRAY_IDLE_RECLAIM_SECS' },
  },
  {
    snippet: '崩溃或断电后自动恢复原系统 DNS',
    evidence: {
      kind: 'anchor',
      file: 'crates/system-integration/src/dns_watcher.rs',
      needle: 'takeover_system_dns',
    },
  },
  {
    snippet: '保留域名时由出站按协议能力处理；本地解析会执行完整 DNS 规则链',
    evidence: {
      kind: 'anchors',
      items: [
        {
          file: 'crates/config-engine/src/builder/route.rs',
          needle: 'if uses_dns_connection_resolution(config)',
        },
        {
          file: 'crates/config-engine/src/builder/route.rs',
          needle: 'action: Some("resolve".to_string())',
        },
        {
          file: 'crates/config-engine/tests/kernel_accepts_outbounds.rs',
          needle: 'fn bundled_core_accepts_dns_owned_connection_resolution_with_fakeip()',
        },
      ],
    },
  },
  {
    snippet: '启动时不显示主窗口',
    evidence: { kind: 'config-key', key: 'silentStart' },
  },
  {
    snippet: '闲置 10 分钟后用密码锁定界面',
    evidence: { kind: 'config-key', key: 'autoPrivacyMode' },
    // 与上一条相反，这个阈值**应该**留在 renderer：它锁的就是这个界面，界面不存在时锁它没意义，
    // 而窗口可见时 renderer 恒不被节流 —— 判断者与被判断者同生共死正是它成立的前提。
    timer: { lang: 'ts', name: 'IDLE_PRIVACY_LOCK_MS' },
  },
  {
    snippet: '已设置 · 闲置后需密码',
    evidence: {
      kind: 'not-a-promise',
      reason:
        '这是密码**当前状态**的回显（已设置 / 未设置），不是行为承诺；真正的承诺是同屏「自动隐私锁」' +
        '那行的「闲置 10 分钟后用密码锁定界面」，已单独登记并举证。',
    },
  },
  {
    snippet: '停止记录 sing-box 日志',
    evidence: { kind: 'config-key', key: 'disableLogFile' },
  },
  {
    snippet: '内核异常退出时自动重启',
    evidence: {
      kind: 'anchor',
      file: 'src-tauri/src/runtime/proxy',
      needle: 'fn spawn_crash_monitor',
    },
  },
  {
    snippet: '当前节点检测到故障时自动切到可用节点',
    evidence: { kind: 'config-key', key: 'autoSwitchNode' },
  },
  {
    snippet: '开启后所有节点变动都会自动应用',
    evidence: {
      kind: 'anchors',
      items: [
        {
          file: 'src-tauri/src/runtime/proxy',
          needle: '.get("restartOnNodeChange")',
        },
        {
          file: 'crates/switch-engine/src/decision.rs',
          needle: 'if !input.restart_on_node_change && input.only_added_unreferenced',
        },
      ],
    },
  },
  {
    snippet: '默认自动分配，可固定',
    evidence: {
      kind: 'anchor',
      file: 'crates/store/src/validate.rs',
      needle: 'obj.insert("controlPort".into()',
    },
  },
  {
    snippet: '自动生成，加载面板时校验',
    evidence: {
      kind: 'anchor',
      file: 'ui/src/components/screens/settings/SettingsNetwork.tsx',
      needle: 'function generateSecret()',
    },
  },
  {
    snippet: '内核运行时自动连接',
    evidence: {
      kind: 'anchor',
      file: 'ui/src/components/screens/settings/SettingsNetwork.tsx',
      needle: 'async function openDashboard()',
    },
  },
  {
    snippet: '按平台自动处理局域网 / 组网的路由放行',
    evidence: { kind: 'config-key', key: 'autoRoute' },
  },
  {
    snippet: '每行一个后缀（自动补前导点）',
    evidence: {
      kind: 'anchor',
      // 模块取材面**含 tests/**：锚点是一条 `#[test]`，它住在 `dns/tests/`，生产面里没有。
      file: 'crates/config-engine/src/builder/dns',
      needle: 'fn neighbor_domains_attached_to_dns_local_on_linux',
      withTests: true,
    },
  },
  {
    // 承诺是「留空即自动，按协议栈与平台取推荐值」——兑现方是生成期那条派生，不是某个配置键
    // （恰恰相反：留空意味着**磁盘上没有那个键**，config-key 这条腿在这里天然举不出证）。
    snippet: '留空即自动，按协议栈与平台取推荐值',
    evidence: {
      kind: 'anchor',
      file: 'crates/config-engine/src/user_config/tun_stack.rs',
      needle: 'pub fn default_mtu_for',
    },
  },
  {
    snippet: '启动时检查到新版本即在后台下载安装包',
    evidence: { kind: 'config-key', key: 'autoDownloadUpdate' },
  },
  {
    snippet: '每天后台检查一次内核更新',
    evidence: { kind: 'config-key', key: 'autoUpdateCore' },
  },
  {
    snippet: '自动更新时跳过',
    evidence: { kind: 'config-key', key: 'restrictCoreUpdateToCompatibleMinor' },
  },
  {
    snippet: 'Polaris 启动时检查并在需要时补更',
    evidence: { kind: 'config-key', key: 'autoUpdateSubscriptionOnStart' },
  },
  {
    snippet: '订阅与规则资源按此周期在后台刷新',
    evidence: {
      kind: 'anchors',
      items: [
        {
          file: 'ui/src/components/screens/settings/SettingsUpdate.tsx',
          needle: 'ruleResourceUpdateIntervalHours: Number(event.target.value)',
        },
        {
          file: 'src-tauri/src/runtime/subscription_scheduler.rs',
          needle: '.get("subscriptionUpdateIntervalHours")',
        },
        {
          file: 'src-tauri/src/runtime/rule_resource_scheduler.rs',
          needle: '.get("ruleResourceUpdateIntervalHours")',
        },
      ],
    },
  },
  {
    snippet: '按「后台检查间隔」自动重新下载规则资源',
    evidence: {
      kind: 'anchor',
      file: 'src-tauri/src/runtime/rule_resource_scheduler.rs',
      needle: 'select_due_resources(',
    },
  },
] as const;

// ── 断言 ────────────────────────────────────────────────────────────────────

describe('守卫自检：判据面与解析器都真的在工作（防空集合恒绿）', () => {
  it('desc 抽取器解得开四种写法（内联串 / t(key) / t(key, 兜底) / 三元里的 t）', () => {
    expect(DESCS.length).toBeGreaterThanOrEqual(30);
    expect(DESCS.some((d) => d.text.includes('闲置 10 分钟'))).toBe(true);
    // i18n key 全部解析得开（留下 `<未解析 …>` 说明 key 改了或文件路径变了）。
    expect(DESCS.filter((d) => d.text.startsWith('<未解析')).map((d) => d.text)).toEqual([]);
    // 三元分支：两侧文案都要被还原出来，否则承诺会从判据面上整条消失（登记表那侧只会表现为孤儿行）。
    expect(
      DESCS.some((d) => d.text.includes('已设置 · 闲置后需密码') && d.text.includes('未设置 · 任何人可解锁')),
      '三元 desc 的两个分支没被还原 —— resolveT 塌了',
    ).toBe(true);
    // 反向：编一个不存在的键，必须原样留着（证明 resolveT 不是「凡 t() 都吞掉」）。
    expect(resolveT("t('zzz.no.such.key')")).toBe("t('zzz.no.such.key')");
  });

  it('hasConsumer 正反两向都判得动（否则「有消费方」恒真或恒假）', () => {
    expect(hasConsumer('autoPrivacyMode'), '已知有消费方的键判成了没有').toBe(true);
    expect(hasConsumer('zzzNoSuchConfigKeyEver'), '不存在的键也判成有消费方 —— 本门恒绿').toBe(
      false,
    );
  });

  it('timerFor 正反两向都判得动（本该命中的命中、编造的时长找不到）', () => {
    // 正向：10 分钟 = 600000ms，实现里确有等值常量且被引用。
    expect(timerFor(10 * 60 * 1000), '10 分钟的计时常量找不到了').not.toBeNull();
    // 反向：编一个没人写过的时长，必须解析失败 —— 证明它不是「恒返回一个东西」。
    expect(timerFor(7 * 60 * 1000 + 137), '编造的时长也能解析出常量 —— 本门恒绿').toBeNull();
  });

  it('去注释真的生效（注释里引用的旧文案不该被当成在用的承诺）', () => {
    expect(code('// desc="闲置 99 分钟后自动关机"\nconst a = 1;')).not.toContain('闲置 99 分钟');
  });
});

describe('G13-A：定量时间承诺必须有等值计时常量', () => {
  it('每条「N 分钟 / N 秒」承诺都能对上一个真被引用的毫秒常量', () => {
    // 变异对照：把 SettingsGeneral 的「闲置 10 分钟」改成「闲置 12 分钟」→ 本条转红
    //（12 分钟没有等值常量），且不会被别的门抓到。
    const bad: string[] = [];
    for (const p of PROMISES) {
      for (const m of p.text.matchAll(/(\d+)\s*(分钟|秒)/g)) {
        const ms = Number(m[1]) * (m[2] === '分钟' ? 60_000 : 1_000);
        if (!timerFor(ms)) bad.push(`${p.file} 「${m[0]}」(${ms}ms)`);
      }
    }
    expect(bad, '文案许诺了这个时长，但前端找不到等值且被引用的计时常量 —— 空承诺').toEqual([]);
  });

  /**
   * 上一条只验「存在等值常量」，同为 10 分钟的两条承诺共用一个常量也算过 —— 轻量模式阈值搬进
   * Rust 之后，它就是靠隐私锁那个 `IDLE_PRIVACY_LOCK_MS` 顶绿的，对自己那条已零约束。
   * 本条按登记表逐条比对**指定的那个**常量，让每条承诺各自负责。
   */
  it('每条定量承诺都登记了 timer，且该常量的值与文案数字一致', () => {
    const bad: string[] = [];
    for (const row of REGISTRY) {
      const m = row.snippet.match(/(\d+)\s*(分钟|秒)/);
      if (!m) continue;
      const want = Number(m[1]) * (m[2] === '分钟' ? 60_000 : 1_000);
      if (!row.timer) {
        bad.push(`「${row.snippet}」没登记 timer —— 它会被别条承诺的同值常量顶绿`);
        continue;
      }
      const got = constantValueMs(row.timer.lang, row.timer.name);
      if (got === null) {
        bad.push(`「${row.snippet}」登记的 ${row.timer.lang} 常量 ${row.timer.name} 找不到（改名/删了？）`);
      } else if (got !== want) {
        bad.push(`「${row.snippet}」文案说 ${want}ms，但 ${row.timer.name} 是 ${got}ms`);
      }
    }
    expect(bad, '定量承诺与它自己那个计时常量对不上').toEqual([]);
  });

  it('确实有定量承诺登记了 timer（否则上一条在扫空集）', () => {
    const n = REGISTRY.filter((r) => r.timer).length;
    expect(n, '一条 timer 都没登记 —— 逐条比对在空转').toBeGreaterThanOrEqual(2);
    // 两种语言都要有活样本：只剩一种时，另一档的扫描器塌了也不会被发现。
    expect(new Set(REGISTRY.filter((r) => r.timer).map((r) => r.timer!.lang)).size).toBe(2);
  });

  it('确实有定量承诺被检到（否则上一条断言在扫空集）', () => {
    const n = PROMISES.filter((p) => /(\d+)\s*(分钟|秒)/.test(p.text)).length;
    expect(n, '一条定量承诺都没扫到 —— 腿 A 在空转').toBeGreaterThanOrEqual(2);
  });
});

describe('G13-B：每条承诺文案都必须登记并举证', () => {
  it('承诺文案集合与登记表双向覆盖（新增承诺 / 删掉承诺都说话）', () => {
    // 变异对照：往任一设置屏加一行 `desc="自动清理三个月前的日志"` → 本条转红并点名该文案。
    const unregistered = PROMISES.filter(
      (p) => !REGISTRY.some((r) => p.text.includes(r.snippet)),
    ).map((p) => `${p.file} :: ${p.text.slice(0, 40)}`);
    expect(unregistered, '设置页出现了未登记的行为承诺 —— 见 REGISTRY 头注的登记规则').toEqual([]);

    const orphanRows = REGISTRY.filter((r) => !PROMISES.some((p) => p.text.includes(r.snippet))).map(
      (r) => r.snippet,
    );
    expect(orphanRows, '登记表里有磁盘上已不存在的文案 —— 文案改了就把登记一起改').toEqual([]);
  });

  it('登记为 config-key 的承诺，那个键在设置屏之外真有消费方（空承诺的定义）', () => {
    // 变异对照：把 `use-idle-privacy-lock.ts` 里读 autoPrivacyMode 的那条腿删掉 → 本条转红。
    const empty = REGISTRY.filter(
      (r) => r.evidence.kind === 'config-key' && !hasConsumer(r.evidence.key),
    ).map((r) => `${r.snippet} → ${(r.evidence as { key: string }).key}`);
    expect(empty, '界面承诺了这个行为，但那个配置键在设置屏之外没人读 —— 空承诺').toEqual([]);
  });

  it('登记为 anchor / anchors 的承诺，所有锚点源码片段真的还在', () => {
    // 变异对照：把生产侧 `fn spawn_crash_monitor` 改名 → 本条转红（2026-08-30 实测；改名前
    // 取材面含 tests/，同一变异下本条仍绿 —— 见 `anchorSource` 头注）。
    const gone = REGISTRY.flatMap((r) => {
      const evidence = r.evidence;
      if (evidence.kind !== 'anchor' && evidence.kind !== 'anchors') return [];

      const items = evidence.kind === 'anchor' ? [evidence] : evidence.items;
      const missing = items.some(
        (entry) => !anchorSource(entry.file, entry.withTests).includes(entry.needle),
      );
      return missing ? [r.snippet] : [];
    });
    expect(gone, '承诺的兑现锚点消失了 —— 实现被删/改名而文案没跟').toEqual([]);
  });

  /**
   * `withTests` 的牙：它把 `tests/` 并进取材面，于是一条「生产实现还在」的正向断言可以被
   * 测试里逐字引用生产签名的字符串字面量喂饱（2026-08-30 实测：`fn spawn_crash_monitor`
   * 在 `proxy/tests/process_supervision.rs` 有 `const HEAD` 残留，生产定义删掉本门仍 12/12 绿）。
   *
   * 因此它只许用在**生产面确实没有**的锚点上（即 needle 真是一条 `#[test]`）。生产面已经能
   * 找到这个串却仍挂着 `withTests` ⇒ 这个口子对它是纯负债，当场转红。
   *
   * 变异对照：给任意一条生产锚点（如 `fn spawn_crash_monitor`）加上 `withTests: true` → 本条转红。
   */
  it('`withTests` 只许用在生产取材面确实没有的锚点上（否则就是给假绿开口子）', () => {
    const items = REGISTRY.flatMap((r) => {
      const e = r.evidence;
      if (e.kind === 'anchor') return [{ snippet: r.snippet, item: e as AnchorItem }];
      if (e.kind === 'anchors') return e.items.map((item) => ({ snippet: r.snippet, item }));
      return [];
    }).filter(({ item }) => item.withTests === true);

    const abused = items
      .filter(({ item }) => anchorSource(item.file).includes(item.needle))
      .map(({ snippet, item }) => `${snippet} → ${item.file} :: ${item.needle}`);
    expect(
      abused,
      '这些锚点在生产取材面里就找得到 —— `withTests` 对它们只会放过「生产被删、测试残留」这一种缺陷，删掉该标记',
    ).toEqual([]);
  });

  it('判为「非承诺」的条目必须写清为什么，且不许诉诸「本仓先例」', () => {
    const rows = REGISTRY.filter((r) => r.evidence.kind === 'not-a-promise');
    expect(rows.length, '一条 not-a-promise 都没有也没关系，但有就必须带理由').toBeGreaterThanOrEqual(
      0,
    );
    for (const r of rows) {
      const why = (r.evidence as { reason: string }).reason;
      expect(why.length, `${r.snippet} 的理由太短`).toBeGreaterThan(20);
      expect(why, `${r.snippet} 的理由是自我循环`).not.toMatch(/本仓先例|既有惯例|历来如此/);
    }
  });
});
