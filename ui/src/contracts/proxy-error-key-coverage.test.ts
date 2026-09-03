/**
 * 代理错误码 → i18n 键的**跨语言覆盖门**：Rust `src-tauri/src/runtime/proxy::code` ↔ 前端映射表 ↔ 五份 locale。
 *
 * # 这道门守的是什么
 *
 * 缺陷原形：渲染端六处写成 `data.message || t('home.proxyCrashed', '代理已断开')`，而后端
 * `emit_proxy_error(message, error_code)` 两参皆非可选 ⇒ `||` 右边**永远短路不到**。那些 i18n key
 * 名义上存在、实际是死键，俄语/波斯语用户在最高频的错误路径上看到 Rust 侧写死的中文。
 * 这是一个**全绿的缺陷**：`tsc` 过、`vitest` 过、`locale-parity` 过（键确实五语齐备，只是没人渲染），
 * 只有非中文用户会撞上。修法是让前端按 `errorCode` 取键（`domain/proxy-error-text.ts`），
 * 而修完之后立刻出现两条新的、**同样静默**的漂移面：
 *
 *  1. **Rust 新增一个 `error_code`、前端映射表没跟** ⇒ 该码只能落到通用本地化句。
 *     TypeScript 抓不到（`errorCode` 运行期就是个 string），任何纯前端测试也抓不到
 *     （前端表自己跟自己比永远一致）。
 *  2. **映射表指向的键在某个语种里不存在** ⇒ i18next 回落到键名，用户看到 `home.proxyCrashed`
 *     这串开发者标识符。`locale-parity` 的 ru/fa 是**棘轮**（允许 451 个缺口），故它**不会**
 *     替这几个键说话 —— 它们必须被单独钉死为「零缺口」。
 *
 * 两条都只有把 Rust 源码与五份 locale 同时读进来才判得了，这就是本文件。
 *
 * # 为什么读 Rust 源码而不是抄一份镜像常量
 *
 * 抄镜像只是把漂移面往后挪一格（改了源不改镜像 = 门在守一个假真值）。范式照抄同目录的
 * `rust-i18n-coverage.test.ts` / `protocol-settings-coverage.test.ts` 与
 * `components/layout/nonfatal-error-codes.test.ts`：把 Rust 源码当真值读进来解析。
 *
 * # 五条判据
 *
 *  G1 **码集双向精确相等**：Rust `mod code` 的常量集 = 映射表键集。
 *     正向抓「新增码没配键」，反向抓「码删了/改名了，前端表里留着死项」。
 *  G2 **键在五语种都有真译文**：映射表的每个 value 在五份 locale 里都必须是非空字符串。
 *  G3 **接线**（双向）：正向——`App.tsx` 里被 `errorCode === '…'` 路由的码，必须全在映射表里；
 *     反向——[`MUST_BE_ROUTED_IN_APP`] 点名的码必须在 `App.tsx` 里真有分腿（没有分腿 = 落到
 *     函数末尾的「其余码：忽略」被静默丢弃，后端半条链齐备而用户一个字看不到）；
 *     且七处 toast 文案确实走 `proxyErrorText(`，不是又在组件里手写一套。
 *  G4 **raw 零容忍**：解析器不得读取 `message`；全仓不得让 raw message 压过 i18n。
 *
 * 另有行为断言锁定「已知码 → locale，未知/缺码 → 通用 locale」，并确认 raw `message`
 * 不参与可见文案。
 *
 * # 读不到就抛，不跳过
 *
 * 所有解析（`mod code` 段、App.tsx 分腿、locale 文件、源码清单）解析不到一律 `throw`。
 * 「扫到 0 条于是 0 个断言全绿」是假门 —— 那样 Rust 模块一改名，门就静默消失，
 * 「没检查」与「检查通过」的输出不可区分。
 *
 * # 抓不到什么（射程自曝）
 *
 *  a. **译文对不对**：只管「有没有、空不空」，不管译得准不准。
 *  b. **Rust 是否真的会发某个码**：判据是 `mod code` 里**声明**了哪些常量，不是哪些有活的
 *     `set_error`/`set_nonfatal_error` 调用点。声明了却没人发的码会被要求配键（多配一个键无害）。
 *  c. **码被路由到哪条腿**（toast 等级 / 发不发桌面通知）：那是 `App.test.ts` 的射程。
 *     本门只管「这个码有没有一句能给用户看的、本地化的话」。
 *  d. **`ApiResponse::err_with_code` 那一套 `code`**（`PRIVACY_LOCKED` / `WARP_*` / `TAILSCALE_*` …）：
 *     它们走的是 IPC 信封的 `code` 字段 → `IpcError`，由各调用点的 `catch` 自行处理，
 *     与 `event:proxyError` 的 `errorCode` 不是同一个取值集，不在本门射程内。
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { SUPPORTED_LANGUAGES } from '../domain/language';
import {
  PROXY_ERROR_TEXT_KEY,
  proxyErrorReason,
  proxyErrorText,
} from '../domain/proxy-error-text';

const SRC_DIR = fileURLToPath(new URL('..', import.meta.url));
const LOCALES_DIR = fileURLToPath(new URL('../i18n/locales', import.meta.url));

const read = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');

// B0 换锚例外：钉 façade 是判据本体（`pub mod code { … }` 按 A.5 硬约束永不外移），故意保留单文件
// 读取，不随 Rust 侧 35 条改宽锚。
const RUST_PROXY = read('../../../src-tauri/src/runtime/proxy.rs');
const APP_TSX = read('../App.tsx');

// ════════════════════════════════════════════════════════════════════════════
// 解析器（任何一处解析不到都抛）
// ════════════════════════════════════════════════════════════════════════════

/**
 * Rust `pub mod code { … }` 里声明的全部码字面量。
 *
 * 大括号配平取模块体（同 `nonfatal-error-codes.test.ts` 的做法）：按行数或正则截断都会在
 * 模块里出现嵌套块时静默取错段。
 */
function rustErrorCodes(): string[] {
  const start = RUST_PROXY.indexOf('pub mod code {');
  if (start < 0) {
    throw new Error(
      'proxy.rs 里找不到 `pub mod code {` —— 模块被改名/搬走（那么本门该跟着改），或解析器坏了。两种情况都不许静默放行。'
    );
  }
  const bodyStart = RUST_PROXY.indexOf('{', start);
  let depth = 0;
  let end = -1;
  for (let i = bodyStart; i < RUST_PROXY.length; i += 1) {
    if (RUST_PROXY[i] === '{') depth += 1;
    else if (RUST_PROXY[i] === '}') {
      depth -= 1;
      if (depth === 0) {
        end = i;
        break;
      }
    }
  }
  if (end < 0) throw new Error('`mod code` 大括号不配平 —— 解析器失效');
  const codes = [
    ...RUST_PROXY.slice(bodyStart, end).matchAll(/pub const [A-Z_0-9]+: &str = "([A-Z_0-9]+)";/g),
  ].map((m) => m[1]);
  if (codes.length === 0) throw new Error('`mod code` 里一个常量都没解析到 —— 写法变了？');
  return codes;
}

/** `App.tsx` 里被 `data.errorCode === 'X'` 路由的码。 */
function routedCodesInApp(): string[] {
  const codes = [...APP_TSX.matchAll(/data\.errorCode === '([A-Z_0-9]+)'/g)].map((m) => m[1]);
  if (codes.length === 0) {
    throw new Error(
      'App.tsx 里一条 `data.errorCode === \'…\'` 分腿都没解析到 —— 分腿写法变了，本门已失去判据'
    );
  }
  return codes;
}

const flatten = (o: unknown, p = '', out: Record<string, string> = {}) => {
  for (const [k, v] of Object.entries(o as Record<string, unknown>)) {
    const kk = p ? `${p}.${k}` : k;
    if (typeof v === 'string') out[kk] = v;
    else if (v !== null && typeof v === 'object') flatten(v, kk, out);
  }
  return out;
};

const LOCALES: Record<string, Record<string, string>> = Object.fromEntries(
  SUPPORTED_LANGUAGES.map((l) => [
    l,
    flatten(JSON.parse(readFileSync(join(LOCALES_DIR, `${l}.json`), 'utf8'))),
  ])
);

/** `ui/src/**` 的非测试 `.ts` / `.tsx`（G5 用）。 */
function collectSources(): string[] {
  const acc: string[] = [];
  const walk = (dir: string) => {
    for (const e of readdirSync(dir)) {
      if (e === 'node_modules' || e === 'dist') continue;
      const full = join(dir, e);
      if (statSync(full).isDirectory()) walk(full);
      else if (/\.tsx?$/.test(e) && !/\.(test|spec)\.tsx?$/.test(e)) acc.push(full);
    }
  };
  walk(SRC_DIR);
  if (acc.length < 100) throw new Error(`只收集到 ${acc.length} 个源码文件 —— 收集器失效`);
  return acc;
}

// ════════════════════════════════════════════════════════════════════════════
// G0 自检：本门不能空转
// ════════════════════════════════════════════════════════════════════════════

describe('G0 自检：语料与解析都非空', () => {
  it('Rust 码集 / 映射表 / locale 三者都解析到了东西', () => {
    expect(rustErrorCodes().length, 'Rust 码一个都没解析到').toBeGreaterThanOrEqual(8);
    expect(Object.keys(PROXY_ERROR_TEXT_KEY).length, '映射表为空').toBeGreaterThanOrEqual(6);
    expect(Object.keys(LOCALES).length, 'locale 语种不齐').toBe(5);
    for (const l of SUPPORTED_LANGUAGES) {
      expect(Object.keys(LOCALES[l]).length, `${l} 的语料为空`).toBeGreaterThan(100);
    }
    expect(routedCodesInApp().length, 'App.tsx 分腿一条都没解析到').toBeGreaterThanOrEqual(6);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// G1 码集双向精确相等
// ════════════════════════════════════════════════════════════════════════════

describe('G1 Rust `error_code` 取值集 = 前端映射表', () => {
  it('双向精确相等（正向抓漏配，反向抓死项）', () => {
    const rust = [...rustErrorCodes()].sort();
    const covered = Object.keys(PROXY_ERROR_TEXT_KEY).sort();
    // 变异实测（真跑过）：在 `mod code` 里加一条 `pub const FOO_BAR: &str = "FOO_BAR";`
    // 而不动前端映射表 ⇒ 本条转红。
    expect(
      covered,
      'Rust 的 error_code 取值集与前端映射表分叉 —— ' +
        '多出来的码只能落到通用提示，少掉的是改名后残留的死项'
    ).toEqual(rust);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// G2 五语映射完整性
// ════════════════════════════════════════════════════════════════════════════

// ════════════════════════════════════════════════════════════════════════════
// 映射键在五语种齐备
// ════════════════════════════════════════════════════════════════════════════

describe('G2 映射表指向的键在五份 locale 里都有真译文', () => {
  it('零缺口（这几个键不受 locale-parity 的 ru/fa 棘轮庇护）', () => {
    // `locale-parity` 允许 ru/fa 有 451 个缺口，故它**不会**替这几个键说话。缺一条的症状：
    // i18next 回落键名，用户看到 `home.proxyCrashed` 这串开发者标识符。
    // 变异实测（真跑过）：删掉 `ru.json` 里的 `home.proxyCrashed` ⇒ 本条转红。
    const missing: string[] = [];
    for (const [code, key] of Object.entries(PROXY_ERROR_TEXT_KEY)) {
      for (const l of SUPPORTED_LANGUAGES) {
        const v = LOCALES[l][key];
        if (typeof v !== 'string' || v.trim() === '') missing.push(`${l}: ${key} (← ${code})`);
      }
    }
    expect(missing.sort(), '错误码用到的 i18n 键没有五语种齐备').toEqual([]);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// G3 接线：判据面与渲染面都得真接上
// ════════════════════════════════════════════════════════════════════════════

/**
 * **必须被 `App.tsx` 显式路由**的码 —— 与 G3 正向那条方向相反。
 *
 * # 为什么不写成全称（「映射表里每个码都得被路由」）
 *
 * 那样会立刻红在三个与本表无关的既有决定上：`STARTUP_FAILED` 是**刻意**不路由的（它必然伴随
 * 某次 `proxy.start` 的 reject，发起方自己会 toast，此处重报 = 同一次失败弹两遍），
 * `CORE_BINARY_MISMATCH` / `TUN_ADDRESS_UNAVAILABLE` 现状也没有分腿（是否该有是另一个议题，
 * 本门不替它们说话）。为了让全称成立而去加三条无人要求的分腿，或反过来把断言改宽，
 * 都是把门磨钝 —— 故这里用点名表，并在每条旁边写清它为什么非报不可。
 *
 * # 点名的码为什么非报不可
 *
 * 它们的**唯一**送达路径就是 `handleProxyErrorEvent` 这条订阅：没有任何 command 在 await
 * （不像起核腿有连接按钮兜底），后端把码发出来、映射表也配了键，而这里没有对应分腿 ⇒ 落到函数
 * 末尾的「其余码：忽略」被静默丢弃。后端那半条链（落状态 + 发事件 + Rust 单测锁死）全绿，
 * 用户端一个字都看不到 —— 这一侧此前没有任何门。
 */
const MUST_BE_ROUTED_IN_APP = [
  // 自动换节点落空（可用节点都要整核重启才能切过去）：整件事全程在后台发生、用户完全无感。
  // 不上屏 = 用户只知道「网怎么突然不通了」，不知道自己其实可以手动换个节点或重启代理。
  'AUTO_SWITCH_NEEDS_RESTART',
] as const;

describe('G3 接线：App.tsx 的分腿与映射表对得上，且文案真的走解析器', () => {
  it('每个被路由的码都在映射表里', () => {
    const unmapped = [...new Set(routedCodesInApp())].filter(
      (c) => !Object.prototype.hasOwnProperty.call(PROXY_ERROR_TEXT_KEY, c)
    );
    expect(
      unmapped,
      'App.tsx 路由了未配 i18n 键的错误码'
    ).toEqual([]);
  });

  it('点名必须路由的码确实有分腿（反向：抓「后端发了、前端静默丢弃」）', () => {
    // 变异实测（真跑过）：把 App.tsx 里 `data.errorCode === 'AUTO_SWITCH_NEEDS_RESTART'`
    // 那条分腿整段删掉 ⇒ 本条转红（而 G1/G2 与 tsc 全都照绿 —— 那正是这条门存在的理由）。
    const routed = new Set(routedCodesInApp());
    const unrouted = MUST_BE_ROUTED_IN_APP.filter((c) => !routed.has(c));
    expect(
      unrouted,
      'App.tsx 缺少这些码的分腿 —— 后端已发码、映射表也配了键，前端却落到「其余码：忽略」被静默丢弃'
    ).toEqual([]);
  });

  it('六处 toast 文案都走 `proxyErrorText(`，不在组件里另写一套', () => {
    const stripped = APP_TSX.replace(/^\s*(\/\/|\*|\/\*).*$/gm, ''); // 注释里逐字写着反例
    const calls = [...stripped.matchAll(/proxyErrorText\(data, t\)/g)].length;
    expect(calls, 'handleProxyErrorEvent 的 toast 文案没有全部走解析器').toBeGreaterThanOrEqual(6);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// G4 缺陷形态零容忍
// ════════════════════════════════════════════════════════════════════════════

describe('G4 全仓不得再出现 `X.message || t(...)`', () => {
  it('零处（这是缺陷本身的形状，不是风格问题）', () => {
    // 上面四条盯的都是「表配没配全」；只有这条盯着「有没有人把优先级换回去」。
    // 变异实测（真跑过）：把 App.tsx 任一处改回 `data.message || t('home.proxyCrashed')` ⇒ 转红。
    const shape = /\.message\s*\|\|\s*(?:i18n\.)?t\(/;
    const bad: string[] = [];
    for (const f of collectSources()) {
      readFileSync(f, 'utf8')
        .split('\n')
        // 剔整行注释（同 `nonfatal-error-codes.test.ts` / `pending-bar-logic.test.ts` 的口径）：
        // 本门与被修的两个文件的头注里都**逐字引用**了这个反例，不剔就会红在自己的说明文字上
        // ——那是真阳性的判定逻辑打在假阳性的目标上。代价：行尾注释里写这个形状抓不到，无实害。
        .forEach((line, i) => {
          if (/^\s*(\/\/|\*|\/\*)/.test(line)) return;
          if (shape.test(line)) bad.push(`${f.slice(SRC_DIR.length)}:${i + 1}`);
        });
    }
    expect(
      bad.sort(),
      '后端 message 又压过了 i18n key —— 后端 message 是 Rust 侧写死的中文串，ru/fa 用户会看到中文'
    ).toEqual([]);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 行为断言：稳定码 → locale，未知/缺码 → 通用 locale
// ════════════════════════════════════════════════════════════════════════════

describe('用户可见代理错误不渲染 raw message', () => {
  const t = (key: string) => `T:${key}`;

  it('已知 errorCode 恒用 locale，即使同时带 raw message', () => {
    for (const [code, key] of Object.entries(PROXY_ERROR_TEXT_KEY)) {
      const got = proxyErrorReason({ errorCode: code, message: '后端的中文串' }, t);
      expect(got, `${code} 没走 locale`).toBe(`T:${key}`);
    }
  });

  it('缺码或未知码忽略 raw message，落通用 locale', () => {
    for (const input of [
      { message: 'sing-box 启动期退出: bad config' },
      { errorCode: 'SOME_NEW_CODE', message: '后端说的话' },
    ]) {
      expect(proxyErrorReason(input, t)).toBeNull();
      expect(proxyErrorText(input, t)).toBe('T:errors.operationFailed');
    }
  });

  it('原型链上的属性不得被当成键（errorCode 是从 IPC 收来的任意串）', () => {
    // 直接下标会让 `'toString'` / `'constructor'` 取到 Object.prototype 上的函数，
    // 落进 `t()` 就是一串 `[native code]`。
    expect(proxyErrorReason({ errorCode: 'toString', message: 'm' }, t)).toBeNull();
    expect(proxyErrorReason({ errorCode: 'constructor', message: 'm' }, t)).toBeNull();
  });

  it('通用兜底句本身五语齐备', () => {
    for (const l of SUPPORTED_LANGUAGES) {
      const v = LOCALES[l]['errors.operationFailed'];
      expect(typeof v === 'string' && v.trim() !== '', `${l} 缺 errors.operationFailed`).toBe(true);
    }
  });
});
