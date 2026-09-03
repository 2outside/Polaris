/**
 * `StagedDecision` 的**跨语言锁** —— 前端字面量联合 ↔ Rust `ProxyRuntime::classify_staged` 实际产生的四值。
 *
 * # 这道门守的是什么
 *
 * `classifyStaged` 的返回值只经 `decision` 这一个字符串表达。它的失效模式是**单侧改动**：
 *
 *  - **只改 Rust**（switch-engine 将来加第五条腿、classify 里多映射一个字面量）→ 前端 `switch`
 *    落到默认分支，把一条真实存在的腿显示成别的东西，且 TypeScript 一个字都不会说
 *    （`decision` 在运行期就是个 string）。
 *  - **只改前端**（联合里多写一个从未产生过的取值）→ 写出永远走不到的 UI 分支，看起来覆盖完整、
 *    实际上是死代码。
 *
 * # 为什么解析 Rust 源码而不是镜像常量
 *
 * 照抄本仓 `user-config-fields.test.ts` / `unlock-detection.test.ts` 的范式：把 Rust 源码当真值读进来。
 * 抄一份镜像常量只是把漂移面往后挪一格。
 *
 * # 自曝纪律
 *
 * 解析器抓不到 `classify_staged` 方法体必须**转红**，而不是拿到空集合让后面的断言恒真 ——
 * 「没检查」与「检查通过」的输出不可区分 = 没有这道门。
 */
import { describe, it, expect } from 'vitest';

import type { StagedDecision } from './types';
import { moduleSource } from './rust-source.test-support';

// B0 换锚：`classify_staged` 是 façade 的 28 行 pub 契约面，但方法**实现**会随 B1+ 搬进
// `hot_switch.rs`（生产职责子模块）——门要钉的是「实现」而不是「定义在哪」，改用 moduleSource
// 让取材面跟着生产码搬迁自动跟随（递归覆盖 `proxy/**`，排除 `tests/`）。
const RUST_PROXY = moduleSource('src-tauri/src/runtime/proxy');

/** 前端契约面：这里手写一遍是**故意**的 —— 类型只在编译期存在，运行期取不到它的成员。 */
const FRONTEND_DECISIONS: readonly StagedDecision[] = [
  'hotSwitch',
  'noOp',
  'defer',
  'restart',
];

/**
 * 从 `classify_staged` 的方法体里抽出所有被赋给 `decision` 的字面量。
 *
 * 锚点是方法签名到方法末尾的 `}` —— 用大括号配平而不是行数，改动方法长度不会让它悄悄读错范围。
 *
 * `src` 默认取真生产语料；显式传值只为下面那条**正向对照**用例服务 —— 对照必须喂**本函数本体**
 * 塌陷语料，否则它测的是用例里现写的 stub，本函数的自曝分支被改成「返回空集合」时对照仍绿。
 */
function decisionLiteralsInRust(src: string = RUST_PROXY): Set<string> {
  const start = src.indexOf('pub fn classify_staged(');
  if (start < 0) {
    throw new Error(
      'proxy.rs 里找不到 `pub fn classify_staged(` —— 锚点失配。' +
        '要么方法被改名/删除（那么本门该跟着改），要么本解析器坏了；两种情况都不允许静默放行。'
    );
  }
  const bodyStart = src.indexOf('{', start);
  let depth = 0;
  let end = -1;
  for (let i = bodyStart; i < src.length; i += 1) {
    if (src[i] === '{') depth += 1;
    else if (src[i] === '}') {
      depth -= 1;
      if (depth === 0) {
        end = i;
        break;
      }
    }
  }
  if (end < 0) throw new Error('classify_staged 方法体大括号不配平 —— 解析器失效');
  const body = src.slice(bodyStart, end);
  return new Set([...body.matchAll(/"([A-Za-z]+)"/g)].map((m) => m[1]));
}

describe('StagedDecision 跨语言锁', () => {
  it('Rust classify_staged 产生的字面量集合与前端联合逐一相等', () => {
    const rust = decisionLiteralsInRust();
    expect(rust.size).toBeGreaterThan(0);
    expect([...rust].sort()).toEqual([...FRONTEND_DECISIONS].sort());
  });

  it('锚点失配时抛错而非放行（自曝纪律的正向对照）', () => {
    // 喂的是**真解析器** `decisionLiteralsInRust`，不是用例内现写的 stub：把它的两条自曝分支改成
    // 「返回空集合」时本对照必须转红。此前的 stub 版控制组没牙 —— 它只证明了 stub 自己会抛。
    expect(() => decisionLiteralsInRust('fn something_else() {}')).toThrow(/classify_staged/);
    // 第二条自曝腿：找得到锚点但方法体大括号不配平（截断/搬迁把方法切成半截）也必须抛。
    expect(() => decisionLiteralsInRust('pub fn classify_staged(&self) -> Staged {')).toThrow(
      /不配平/
    );
  });

  it('restartRequired 是“保存后仍待应用”的投影，只有 noOp 为假', () => {
    // 保存策略禁止修改运行核：本性可热切的条目也要等“立即应用”。字段名为兼容 IPC 保留。
    const restartRequired = (d: StagedDecision) => d !== 'noOp';
    expect(FRONTEND_DECISIONS.filter(restartRequired)).toEqual([
      'hotSwitch',
      'defer',
      'restart',
    ]);
    expect(FRONTEND_DECISIONS.filter((d) => !restartRequired(d))).toEqual(['noOp']);
  });
});
