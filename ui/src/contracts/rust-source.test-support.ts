/**
 * TS 侧读 Rust 源码的唯一入口 —— `crates/source-probe` 的镜像。
 *
 * # 为什么要有这层
 *
 * 一个 Rust 模块 `foo` 的源码天然分布在两处：`foo.rs`（或 `foo/mod.rs`）与目录 `foo/`。
 * 把测试实体外移成 `foo/tests/mod.rs` 之后，任何写死 `readFileSync('…/foo.rs')` 的跨语言门
 * 都会**静默失去**它原本要扫的那一半：断言若是「必须包含 X」当场转红（还算体面），若是
 * 「不得包含 X」则变成恒真 —— 门还在、报告还是绿的，判据已经没了。
 *
 * 因此本模块不接受「文件路径」，只接受**模块路径**（不带扩展名），由它自己去解析这个模块
 * 到底落在哪些文件上。
 *
 * # 取材面二选一，必须显式选
 *
 * - [`moduleSource`]：只要生产源码（剔除 `tests/` 目录）。断言「生产代码里不得出现 X」用它 ——
 *   把测试代码混进来，测试里的一个同形串就能让判据假红。
 * - [`moduleSourceWithTests`]：模块的全部源码。断言「某个测试/夹具还在」用它。
 *
 * 两者都**故障关闭**：模块解析不到、或取材面为空，直接抛 —— 空取材面上的否定型断言恒真，
 * 那正是本模块要根除的失效形态。
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));

function collectRs(dir: string, out: string[]): void {
  for (const entry of readdirSync(dir).sort()) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) collectRs(full, out);
    else if (entry.endsWith('.rs')) out.push(full);
  }
}

/** 模块 `relModule`（仓库相对、**不带扩展名**）落在的全部 `.rs` 文件，已排序。 */
function moduleFiles(relModule: string, includeTests: boolean): string[] {
  const base = join(REPO_ROOT, relModule);
  const root = existsSync(`${base}.rs`)
    ? `${base}.rs`
    : existsSync(join(base, 'mod.rs'))
      ? join(base, 'mod.rs')
      : null;
  if (root === null) {
    throw new Error(
      `模块 \`${relModule}\` 解析不到：既没有 ${relModule}.rs 也没有 ${relModule}/mod.rs。` +
        `路径写错或模块被搬走了 —— 别把它当成「这个模块是空的」。`,
    );
  }
  const files = [root];
  if (existsSync(base) && statSync(base).isDirectory()) {
    const rest: string[] = [];
    collectRs(base, rest);
    for (const file of rest) {
      if (file === root) continue;
      const isTest = file.slice(base.length).replaceAll('\\', '/').includes('/tests/');
      if (isTest && !includeTests) continue;
      files.push(file);
    }
  }
  return files;
}

function read(relModule: string, includeTests: boolean, what: string): string {
  const files = moduleFiles(relModule, includeTests);
  const source = files.map((file) => readFileSync(file, 'utf8')).join('\n');
  if (source.trim() === '') {
    throw new Error(`模块 \`${relModule}\` 的${what}取材面是空的 —— 其上的否定型断言会恒真。`);
  }
  return source;
}

/** 模块的**生产**源码（剔除 `tests/` 目录下的一切）。 */
export function moduleSource(relModule: string): string {
  return read(relModule, false, '生产');
}

/**
 * 目录树 `relRoot`（仓库相对）下的全部**生产** `.rs` 文件（剔除任意层级的 `tests/`），已排序。
 *
 * 用于「整片代码区里不得出现 X」这类断言 —— 按模块逐个登记的白名单只堵住模块内搬家，
 * **跨模块新增一个消费点仍在射程外**；取材面必须是整片生产区，白名单只用来放行已知真值点。
 * 取材根解析不到直接抛：空文件表上的否定型断言恒真，正是本模块要根除的失效形态。
 */
export function productionRsFilesUnder(relRoot: string): string[] {
  const base = join(REPO_ROOT, relRoot);
  if (!existsSync(base) || !statSync(base).isDirectory()) {
    throw new Error(
      `取材根 \`${relRoot}\` 不是目录（不存在或已被搬走）—— 别把它当成「这片区域没有代码」。`,
    );
  }
  const all: string[] = [];
  collectRs(base, all);
  return all.filter((file) => !file.slice(base.length).replaceAll('\\', '/').includes('/tests/'));
}

/** 模块的**全部**源码（含 `tests/` 目录）。 */
export function moduleSourceWithTests(relModule: string): string {
  return read(relModule, true, '全量');
}

/**
 * Rust 源码 → **剥掉注释**的净化面（字符串/字符字面量整段跳过，不剥、也不被当成注释起笔）。
 *
 * # 为什么必须有这一层，而且必须是状态机
 *
 * TS 侧读 Rust 常量的门都长这样：「剥注释 → 正则抓 `const NAME: u64 = <数>;` → 命中数必须恰好 1」。
 * 剥注释那一步是**承重的**：本仓已实测被打穿过一次 —— 在常量的文档注释里写一行同形的
 * `const … = 10_000;`、同时把真常量改小，门读到的是注释里那个数，40/40 全绿。
 *
 * 但正则版的剥注释还漏了**另一个方向**：它不保护字符串。构造
 *
 * ```rust
 * const _X: &str = "const TEMP_CORE_UI_IDLE_TIMEOUT_MS: u64 = 20_000;";
 * ```
 *
 * 再把真常量改名 ⇒ 净化面上仍然恰好命中 1 次，门读到的是**字符串里那个假值**，全绿。
 * 今天两个被读的模块里恰好没有这种字符串（只有一条被截尾的 URL），**那是运气不是设计**，
 * 而这已经是本仓同族第三次栽在取材面上。
 *
 * 正则做不到这件事：它没有状态，分不清 `"…//…"` 里的 `//` 是注释起笔还是字符串内容。
 *
 * # 与 Rust 侧的关系：同一口径，不是第二份实现
 *
 * 本函数是 `crates/source-probe/src/lib.rs` 的 `mask_comments` 的**逐条移植**（那份是字节状态机，
 * 已在 Rust 侧全仓门上跑了 100+ 处）。移植而不是各写一份的判据：两侧读的是**同一批源文件**，
 * 能力一旦分叉，「Rust 侧的门挡得住、TS 侧的门挡不住」这种缝会静默存在，而缝的表现是绿的。
 * 实现按 UTF-8 **字节**扫（与 Rust 侧逐字同构：`>= 0x80` 一律当标识符字节、多字节字符按宽度跳过），
 * 不按 UTF-16 码元 —— 否则中文注释里的字符会把偏移算错。
 *
 * # 覆盖（射程如实登记，与 Rust 侧同）
 *
 * **剥**：行注释 `//`（含 `///` / `//!`，行首行尾同等对待）、块注释（`/*` 起、配对的结束标记止，
 * **支持嵌套**）。
 * **不剥、且整段跳过**：普通字符串（含转义）、原始字符串 `r"…"` / `r#"…"#`（任意个 `#`）、
 * 字节串 `b"…"` / `br#"…"#`、字符与字节字面量 `'x'` / `b'x'`。
 * **不做**：条件编译求值（`#[cfg(test)]` 的代码照留；排除测试代码靠 [`moduleSource`] 那一层）。
 *
 * 已知边界（同 Rust 侧）：生命周期标注 `'a` 与字符字面量 `'a'` 词法上只差一个收尾引号，判不出
 * 就当生命周期放过 —— 方向是「宁可少跳过」，后果是该处**当普通代码留在面上**，不是被误剥。
 *
 * 被剥掉的字节换成空格、换行原样保留 ⇒ 行号与偏移不变。
 */
export function maskRustComments(source: string): string {
  return maskRust(source, false);
}

/**
 * 同 [`maskRustComments`]，但**连字符串/字符字面量一起抹掉**（`crates/source-probe` 的
 * `mask_comments_and_strings`）。
 *
 * # 读常量的门必须用这一个
 *
 * 只跳过不抹掉，字面量的**内容**仍然留在净化面上 —— 于是
 * `const _X: &str = "const NAME: u64 = 20_000;";` 里那行假定义照样能被 [`rustConstU64`] 的正则命中，
 * 真常量改名之后门读到假值并全绿。判据的针是「代码里有没有这个常量定义」时，
 * 字符串里的同名文本是**伪证据**，一并抹掉才干净。
 *
 * 反过来，判据的针**本身就是字符串字面量**时（「这个文件里不得出现 `networksetup`」）必须用
 * [`maskRustComments`]：连字符串一起抹，针在净化面上永远命中不到，判据不是变弱是消失。
 * 两个面都是共享实现的一部分，**不是可以顺手统一成一个的重复**。
 */
export function maskRustCommentsAndStrings(source: string): string {
  return maskRust(source, true);
}

function maskRust(source: string, maskLiterals: boolean): string {
  const bytes = Buffer.from(source, 'utf8');
  const out = Buffer.from(bytes);
  const total = bytes.length;
  const SPACE = 0x20;
  const NL = 0x0a;
  const blank = (from: number, to: number): void => {
    for (let k = from; k < Math.min(to, total); k += 1) {
      if (out[k] !== NL) out[k] = SPACE;
    }
  };
  const isIdentStart = (b: number): boolean =>
    b === 0x5f || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) || b >= 0x80;
  const isIdentContinue = (b: number): boolean =>
    isIdentStart(b) || (b >= 0x30 && b <= 0x39);
  /** UTF-8 首字节 → 该字符的字节宽度。 */
  const utf8Width = (b: number): number => {
    if (b >= 0xf0) return 4;
    if (b >= 0xe0) return 3;
    if (b >= 0xc0) return 2;
    return 1;
  };
  /** 从开引号之后的 `from` 起，返回普通字符串结束偏移（开区间右端；未闭合则到文件尾）。 */
  const normalStringEnd = (from: number): number => {
    let k = from;
    while (k < total) {
      if (bytes[k] === 0x5c) {
        k += 2;
        continue;
      }
      if (bytes[k] === 0x22) return k + 1;
      k += 1;
    }
    return total;
  };
  /** `bytes[start..]` 若是原始字符串（可带 `b` 前缀），返回其结束偏移。 */
  const rawStringEnd = (start: number): number | null => {
    let k = start;
    if (bytes[k] === 0x62) k += 1; // b
    if (bytes[k] !== 0x72) return null; // r
    k += 1;
    const hashStart = k;
    while (bytes[k] === 0x23) k += 1; // #
    const hashes = k - hashStart;
    if (bytes[k] !== 0x22) return null; // "
    k += 1;
    while (k < total) {
      if (bytes[k] === 0x22) {
        let closing = 0;
        while (closing < hashes && bytes[k + 1 + closing] === 0x23) closing += 1;
        if (closing === hashes) return k + 1 + hashes;
      }
      k += 1;
    }
    return total;
  };
  /** 字符字面量结束偏移；判不出（多半是生命周期标注）返回 null。 */
  const charLiteralEnd = (open: number): number | null => {
    let k = open + 1;
    if (bytes[k] === 0x5c) {
      // 先越过被转义的那个字节：否则 `'\''` 会把 `\` 后面那个 `'` 当成收尾引号。
      k = open + 3;
      while (k < total && k < open + 12) {
        if (bytes[k] === 0x27) return k + 1;
        if (bytes[k] === NL) return null;
        k += 1;
      }
      return null;
    }
    if (k >= total) return null;
    const width = utf8Width(bytes[k]);
    if (bytes[k + width] === 0x27) return k + width + 1;
    return null;
  };

  let i = 0;
  while (i < total) {
    // 行注释
    if (bytes[i] === 0x2f && bytes[i + 1] === 0x2f) {
      let end = i;
      while (end < total && bytes[end] !== NL) end += 1;
      blank(i, end);
      i = end;
      continue;
    }
    // 块注释（嵌套）
    if (bytes[i] === 0x2f && bytes[i + 1] === 0x2a) {
      let depth = 1;
      let j = i + 2;
      while (j < total && depth > 0) {
        if (bytes[j] === 0x2f && bytes[j + 1] === 0x2a) {
          depth += 1;
          j += 2;
        } else if (bytes[j] === 0x2a && bytes[j + 1] === 0x2f) {
          depth -= 1;
          j += 2;
        } else {
          j += 1;
        }
      }
      blank(i, j);
      i = j;
      continue;
    }
    // 标识符整体消费：`r` / `b` / `br` 只有作为**独立**标识符时才是字面量前缀。
    // 逐字节扫会把 `foo_r"…"` 里的 `r"` 读成原始字符串起点，从此整段偏移错位。
    if (isIdentStart(bytes[i])) {
      let j = i;
      while (j < total && isIdentContinue(bytes[j])) j += 1;
      const ident = bytes.toString('latin1', i, j);
      if (ident === 'r' || ident === 'b' || ident === 'br') {
        const rawEnd = rawStringEnd(i);
        if (rawEnd !== null) {
          if (maskLiterals) blank(i, rawEnd);
          i = rawEnd;
          continue;
        }
        if ((ident === 'b' || ident === 'br') && bytes[j] === 0x22) {
          const end = normalStringEnd(j + 1);
          if (maskLiterals) blank(i, end);
          i = end;
          continue;
        }
        if (ident === 'b' && bytes[j] === 0x27) {
          const charEnd = charLiteralEnd(j);
          if (charEnd !== null) {
            if (maskLiterals) blank(i, charEnd);
            i = charEnd;
            continue;
          }
        }
      }
      i = j;
      continue;
    }
    // 普通字符串
    if (bytes[i] === 0x22) {
      const end = normalStringEnd(i + 1);
      if (maskLiterals) blank(i, end);
      i = end;
      continue;
    }
    // 字符字面量（与生命周期标注区分）
    if (bytes[i] === 0x27) {
      const charEnd = charLiteralEnd(i);
      if (charEnd !== null) {
        if (maskLiterals) blank(i, charEnd);
        i = charEnd;
        continue;
      }
    }
    i += 1;
  }
  return out.toString('utf8');
}

/**
 * 从**已净化**的 Rust 取材面上抓 `const NAME: u64 = 6_000;` 的数值（允许 `_` 分隔）。
 *
 * 三条纪律各堵一个已实测过的洞，缺一条门就会退化成恒绿：
 *
 *  1. 取材面来自 [`moduleSource`]（模块路径，不是文件路径）—— 写死 `foo.rs` 的门会在常量被挪进
 *     `foo/xxx.rs` 时静默失去那一半取材面；
 *  2. 取材面**先过 [`maskRustCommentsAndStrings`]** —— 注释里的同形常量与**字符串里的**同形常量
 *     都不算证据。只过 [`maskRustComments`] 会漏掉后者（字面量只被跳过、内容仍在面上）；
 *  3. 命中数**恰好 1** —— `.exec` 取首个匹配 ⇒ 面上出现第二处同形定义时判据指向哪一处全凭书写
 *     顺序；为 0 = 常量改名/搬走、门已失去判据。两个方向都当场抛，不许静默退化。
 */
export function rustConstU64(masked: string, name: string, gate: string): number {
  const hits = [
    ...masked.matchAll(new RegExp(`const\\s+${name}\\s*:\\s*u64\\s*=\\s*([0-9_]+)\\s*;`, 'g')),
  ];
  if (hits.length !== 1) {
    throw new Error(
      `[${gate}] 后端常量 ${name} 在净化后的取材面上命中 ${hits.length} 次（应为 1）` +
        ' —— 0 = 改名/搬走，本门已失去判据；>1 = 判据指向哪一处全凭书写顺序。'
    );
  }
  return Number(hits[0][1].replace(/_/g, ''));
}
