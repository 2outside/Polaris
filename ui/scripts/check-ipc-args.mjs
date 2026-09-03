#!/usr/bin/env node
/**
 * IPC 参数袋防回归门（BUG-2「missing required key」族的静态断言）。
 *
 * 背景：`invoke(cmd, args)` 的 `args` 是 **Tauri 参数袋**（`Record<string, unknown>`），Tauri 按
 * Rust `#[tauri::command]` 的**具名参数**去袋里取值。前端若把一个领域对象/裸标量**整个当参数袋**传
 * （`invoke(PROXY_START, config)` 而非 `invoke(PROXY_START, { config })`），Tauri 找不到 required key
 * → 运行期 `missing required key config` → 命令炸。这类错 **tsc 抓不到**（`invoke` 签名是 `args?: unknown`）。
 *
 * 本门直接对拍 **前端调用点**（`ui/src` 全量 `.ts`/`.tsx`，排掉 `.test`/`.spec` —— 取的是
 * **整棵渲染端源码树**而不是 `ui/src/ipc` 那一个子目录：`invoke(IPC_CHANNELS.*, {...})` 并不只出现在
 * api 层，`tray/`、`components/`、`store/`、`update-popup/` 等处同样直接调；只 walk `ui/src/ipc` 时
 * 这些调用点从未进过语料，塌不塌都不影响 checked 计数，FLOOR 也挡不住）与 **Rust 命令签名**
 * （递归扫描 `src-tauri/src/commands` 下所有 `.rs` 的 `#[tauri::command]` 具名参数，**外加
 * `generate_handler![]` 里路径限定注册项所指的模块源码面** —— 如 `tray::tray_quit` ⇒
 * `src-tauri/src/tray.rs` 与 `src-tauri/src/tray/`，两者都在 COMMANDS_DIR 之外）——两侧任一漂移都转红，
 * 不依赖手维护的映射表（自身即 ground truth 对拍）。
 *
 * 判定（只锁 crash 族，不苛求 extra key —— 大量未接线 stub 命令会忽略前端多传的键）：
 *   - 参数键集必须**覆盖** Rust 所有 **required**（非 `Option<_>`、非注入 State/AppHandle/Window）参数。
 *   - 参数键 = 前端调用点的对象字面量键（Tauri 默认 camelCase，对齐 Rust 参数名的 lowerCamelCase）；
 *     `invokeScalar(cmd, x)` 恒包成 `{ value }`；无参调用键集为空。
 *   - **裸标识符**参数（`invoke(cmd, foo)`，无法静态取键）在命令有 required 参数时直接判红：
 *     无法证明其包了参数袋，且这正是 BUG-2 的形态 —— 逼调用点写对象字面量。
 *
 * 无新增依赖（纯 node:fs + 正则）。CI：`node scripts/check-ipc-args.mjs`（已挂进 ui `build`）。
 *
 * 关键实现依据：tauri-macros 2.6.3 `src/command/wrapper.rs:484` —— 参数键 = 形参 ident 经
 * `to_lower_camel_case`（`_value` → `value`，`server_id` → `serverId`，前导下划线作分隔被吃掉）。
 */

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const ROOT = join(SCRIPT_DIR, '..', '..'); // <repo>/ui/scripts → <repo>
const UI_SRC = join(ROOT, 'ui', 'src');
const IPC_DIR = join(UI_SRC, 'ipc');
const CHANNELS = join(ROOT, 'ui', 'src', 'domain', 'ipc-channels.ts');
const RUST_SRC = join(ROOT, 'src-tauri', 'src');
const COMMANDS_DIR = join(RUST_SRC, 'commands');
const MAIN_RS = join(ROOT, 'src-tauri', 'src', 'main.rs');

/** snake/underscore → lowerCamelCase（对齐 tauri-macros `to_lower_camel_case`）。 */
function camel(name) {
  const parts = name.split('_').filter(Boolean);
  if (parts.length === 0) return '';
  return (
    parts[0].toLowerCase() +
    parts
      .slice(1)
      .map((p) => p.charAt(0).toUpperCase() + p.slice(1).toLowerCase())
      .join('')
  );
}

/** 深度感知的顶层逗号切分（尊重 <> () [] {}）。 */
function splitTop(s) {
  const out = [];
  let depth = 0;
  let cur = '';
  for (const ch of s) {
    if ('<([{'.includes(ch)) depth++;
    else if ('>)]}'.includes(ch)) depth--;
    if (ch === ',' && depth === 0) {
      out.push(cur);
      cur = '';
    } else cur += ch;
  }
  if (cur.trim()) out.push(cur);
  return out.map((x) => x.trim()).filter(Boolean);
}

/** 递归列出 command owner；领域拆分后的子目录与顶层入口必须处于同一门禁射程。 */
function rustCommandFiles(dir) {
  const files = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) files.push(...rustCommandFiles(path));
    else if (entry.isFile() && entry.name.endsWith('.rs')) files.push(path);
  }
  return files.sort();
}

/**
 * 定义扫描面 = COMMANDS_DIR ∪ `generate_handler![]` 里路径限定注册项所指的模块源码。
 *
 * `modules` 是形如 `['tray']` / `['a','b']` 的模块路径段（注册项去掉末尾函数名）。Rust 模块源码
 * **同时横跨 `foo.rs` 与 `foo/`**，两边都取；一个都不存在 ⇒ 抛（fail-closed：注册项指向的 owner
 * 找不到时不许静默把该族命令排除在射程外，那正是 tray::* 曾经两侧同时失明的形态）。
 */
function commandOwnerFiles(modules) {
  const files = new Set(rustCommandFiles(COMMANDS_DIR));
  for (const mod of modules) {
    const base = join(RUST_SRC, ...mod);
    let found = false;
    if (existsSync(base + '.rs')) {
      files.add(base + '.rs');
      found = true;
    }
    if (existsSync(base) && statSync(base).isDirectory()) {
      for (const f of rustCommandFiles(base)) files.add(f);
      found = true;
    }
    if (!found) {
      throw new Error(
        `main.rs generate_handler![] 注册了 \`${mod.join('::')}::*\`，但 src-tauri/src/${mod.join('/')}` +
          `{.rs,/} 都不存在 —— 定义扫描面无法覆盖该模块，本门此刻没有判据`
      );
    }
  }
  return [...files].sort();
}

// ── 1. Rust 命令签名 → required / optional 参数键集 ──────────────────────────────
function parseRustCommands(ownerFiles) {
  const map = new Map(); // cmd → { required:Set, optional:Set }
  for (const file of ownerFiles) {
    const src = readFileSync(file, 'utf8');
    const re =
      /#\[tauri::command\]\s*(?:#\[[^\]]*\]\s*)*pub\s+(?:async\s+)?fn\s+(\w+)\s*\(([\s\S]*?)\)\s*(?:->|\{)/g;
    let m;
    while ((m = re.exec(src))) {
      const cmd = m[1];
      if (map.has(cmd)) {
        throw new Error(`重复的 #[tauri::command] 定义：${cmd}（再次出现于 ${file}）`);
      }
      const required = new Set();
      const optional = new Set();
      for (const p of splitTop(m[2])) {
        const colon = p.indexOf(':');
        if (colon < 0) continue;
        const rawName = p.slice(0, colon).trim();
        const type = p.slice(colon + 1).trim();
        if (rawName === '_' || rawName === 'self') continue;
        // 注入参数（Tauri 自动填，不是 JS 参数袋键）。
        if (/\bAppHandle\b|\bState\s*<|\bWebviewWindow\b|\bWindow\b|\bAppRuntime\b/.test(type)) continue;
        const key = camel(rawName);
        if (!key) continue;
        if (/^Option\s*</.test(type)) optional.add(key);
        else required.add(key);
      }
      map.set(cmd, { required, optional });
    }
  }
  return map;
}

// ── 2. IPC_CHANNELS 名 → 命令串 ───────────────────────────────────────────────
function parseChannels() {
  const src = readFileSync(CHANNELS, 'utf8');
  const map = new Map();
  const re = /\b([A-Z0-9_]+):\s*'([^']+)'/g;
  let m;
  while ((m = re.exec(src))) map.set(m[1], m[2]);
  return map;
}

/**
 * `generate_handler![]` 的实际注册集；声明存在但未注册与 command not found 等价。
 *
 * 注册项**两种形态都收**：裸标识符（`proxy_start`）与路径限定（`tray::tray_quit`）。只认裸标识符的
 * 旧写法会静默丢掉后者 —— 命令名 = 末段函数名，前缀只决定 owner 在哪个模块（见 commandOwnerFiles）。
 * 任何**非空且不匹配这两种形态**的行直接抛：语料塌了不许当成「没有注册项」放过。
 */
function parseRegisteredCommands() {
  const src = readFileSync(MAIN_RS, 'utf8');
  const marker = 'invoke_handler(tauri::generate_handler![';
  const start = src.indexOf(marker);
  if (start < 0) throw new Error(`main.rs 缺少 ${marker}`);
  const rest = src.slice(start + marker.length);
  const end = rest.indexOf('])');
  if (end < 0) throw new Error('main.rs 的 generate_handler![] 未闭合');
  const body = rest.slice(0, end).replace(/\/\/.*$/gm, '');
  const names = new Set();
  const modules = new Map(); // 'tray' → ['tray']（去重用）
  const entry = /^([A-Za-z_][A-Za-z0-9_]*(?:\s*::\s*[A-Za-z_][A-Za-z0-9_]*)*)$/;
  for (const raw of body.split('\n')) {
    const line = raw.trim().replace(/,$/, '').trim();
    if (!line) continue;
    const m = entry.exec(line);
    if (!m) {
      throw new Error(
        `main.rs generate_handler![] 里有无法解析的注册项：\`${line}\` —— ` +
          `本门只认裸标识符与 \`mod::path::fn\` 两种形态，其余形态会静默逃过注册对拍`
      );
    }
    const segs = m[1].split('::').map((x) => x.trim());
    names.add(segs[segs.length - 1]);
    if (segs.length > 1) modules.set(segs.slice(0, -1).join('::'), segs.slice(0, -1));
  }
  return { names, modules: [...modules.values()] };
}

// ── 3. 前端 invoke / invokeScalar 调用点（ui/src 全量）──────────────────────────

/**
 * 调用点语料面：`ui/src` 下全部 `.ts`/`.tsx`，排掉 `.test`/`.spec`。
 *
 * 不再只 walk `ui/src/ipc`：api 层之外（`tray/`、`components/`、`store/`、`update-popup/`、`lib/`…）
 * 同样有直接 `invoke(IPC_CHANNELS.*, {...})` 的真实调用点，它们与 api 层的调用点是同一种 BUG-2 形态。
 */
function callSiteFiles() {
  const out = [];
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, e.name);
      if (e.isDirectory()) walk(path);
      else if (/\.tsx?$/.test(e.name) && !/\.(test|spec)\.tsx?$/.test(e.name)) out.push(path);
    }
  };
  walk(UI_SRC);
  return out.sort();
}

function parseCalls() {
  const calls = [];
  for (const file of callSiteFiles()) {
    const rel = file.slice(ROOT.length + 1).split('\\').join('/');
    const src = readFileSync(file, 'utf8');
    const lineOf = (idx) => src.slice(0, idx).split('\n').length;
    const re = /\b(invokeScalar|invoke)\s*(?:<[^>]*>)?\s*\(/g;
    let m;
    while ((m = re.exec(src))) {
      const fn = m[1];
      const open = re.lastIndex - 1; // '(' 位置
      let depth = 0;
      let j = open;
      for (; j < src.length; j++) {
        if (src[j] === '(') depth++;
        else if (src[j] === ')') {
          depth--;
          if (depth === 0) break;
        }
      }
      const inner = src.slice(open + 1, j);
      const parts = splitTop(inner);
      if (parts.length === 0) continue;
      const chMatch = /IPC_CHANNELS\.(\w+)|STATS_TOPIC_EVENT/.exec(parts[0]);
      if (!chMatch || !chMatch[1]) continue; // 非 IPC_CHANNELS.* 首参（如事件），跳过
      calls.push({
        fn,
        file: rel,
        channel: chMatch[1],
        arg: parts.length > 1 ? parts.slice(1).join(',').trim() : undefined,
        line: lineOf(open),
      });
    }
  }
  return { calls };
}

/** 对象字面量 `{ a, b: x }` → 顶层键；非对象字面量返回 null（未知）。 */
function objectKeys(expr) {
  const s = expr.trim();
  if (!s.startsWith('{')) return null;
  let depth = 0;
  let start = -1;
  let end = -1;
  for (let k = 0; k < s.length; k++) {
    if (s[k] === '{') {
      if (depth === 0) start = k;
      depth++;
    } else if (s[k] === '}') {
      depth--;
      if (depth === 0) {
        end = k;
        break;
      }
    }
  }
  if (start < 0 || end < 0) return null;
  const keys = [];
  for (let p of splitTop(s.slice(start + 1, end))) {
    p = p.trim();
    if (!p || p.startsWith('...')) continue;
    const key = p.split(':')[0].trim();
    if (key) keys.push(key);
  }
  return keys;
}

function main() {
  const { names: registered, modules } = parseRegisteredCommands();
  const rust = parseRustCommands(commandOwnerFiles(modules));
  const channels = parseChannels();
  const { calls } = parseCalls();

  const errors = [];
  let checked = 0;
  // 分桶计数：单一全局下界无法发现「小桶整块塌掉」（api 层 ~141 处会把 ui/src 其余 ~17 处淹掉）。
  const bucketOf = (rel) => (rel.startsWith('ui/src/ipc/') ? 'ui/src/ipc' : 'ui/src（api 层之外）');
  const buckets = new Map();

  for (const cmd of rust.keys()) {
    if (!registered.has(cmd)) {
      errors.push(`Rust command "${cmd}" 有 #[tauri::command] 定义，但未进入 main.rs generate_handler![]`);
    }
  }
  for (const cmd of registered) {
    if (!rust.has(cmd)) {
      errors.push(`main.rs generate_handler![] 注册了 "${cmd}"，但递归 command owner 中没有对应定义`);
    }
  }

  for (const c of calls) {
    const cmd = channels.get(c.channel);
    if (!cmd) {
      errors.push(`${c.file}:${c.line}  IPC_CHANNELS.${c.channel} 未在 ipc-channels.ts 定义`);
      continue;
    }
    if (cmd.includes(':')) continue; // event 名（不是 command），非 invoke 目标
    const sig = rust.get(cmd);
    if (!sig) {
      errors.push(
        `${c.file}:${c.line}  invoke("${cmd}") 目标命令在 src-tauri/src/commands/**/*.rs 无 #[tauri::command] 定义`
      );
      continue;
    }
    if (!registered.has(cmd)) {
      errors.push(
        `${c.file}:${c.line}  invoke("${cmd}") 有 #[tauri::command] 定义，但未进入 main.rs generate_handler![]`
      );
      continue;
    }
    checked++;
    const b = bucketOf(c.file);
    buckets.set(b, (buckets.get(b) ?? 0) + 1);
    const required = [...sig.required];

    // 计算前端传入的参数键集。
    let keys; // string[] | null(未知/裸标识符)
    if (c.fn === 'invokeScalar') keys = ['value'];
    else if (c.arg === undefined) keys = [];
    else keys = objectKeys(c.arg);

    if (keys === null) {
      // 裸标识符 / 非对象字面量：无法静态证明它是正确参数袋。
      if (required.length > 0) {
        errors.push(
          `${c.file}:${c.line}  invoke("${cmd}") 传入裸参数 \`${c.arg}\`（非对象字面量），` +
            `无法核对是否覆盖 required 参数 [${required.join(', ')}] —— 请写成 { ${required.join(', ')} }`
        );
      }
      continue;
    }
    const missing = required.filter((r) => !keys.includes(r));
    if (missing.length > 0) {
      errors.push(
        `${c.file}:${c.line}  invoke("${cmd}") 参数袋缺 required 键 [${missing.join(', ')}]` +
          `（实传 [${keys.join(', ') || '∅'}]，Rust required [${required.join(', ')}]）`
      );
    }
  }

  // 自曝：调用点语料塌掉（源码搬家、目录改名、正则失配）时不许打 ✓ 退 0 —— 那正是本门
  // 2026-08-30 之前的形态：`invoke` 全部搬进 `ipc/api/` 后「核对 0 处」照样通过。
  // **逐桶**下界（各取当前实测量的一半上下取整）：只设全局下界时，api 层那一百多处会把
  // 「ui/src 其余部分整块塌掉」淹没成一个仍然过线的总数。
  const FLOORS = { 'ui/src/ipc': 70, 'ui/src（api 层之外）': 8 };
  for (const [bucket, floor] of Object.entries(FLOORS)) {
    const got = buckets.get(bucket) ?? 0;
    if (got < floor) {
      errors.push(
        `前端 invoke 调用点在 ${bucket} 只核对到 ${got} 处（下界 ${floor}）—— 该桶语料面塌了：` +
          `调用点搬出了该目录、扩展名不再是 .ts/.tsx，或首参不再是 IPC_CHANNELS.*。本门此刻没有判据，不许判绿`
      );
    }
  }

  if (errors.length > 0) {
    console.error(`\n✗ IPC 参数袋门失败（${errors.length} 处）：\n`);
    for (const e of errors) console.error('  ' + e);
    console.error(
      `\n根因：Tauri 按 Rust 具名参数从参数袋取值；漏包/错包 required 键 → 运行期 missing key 崩。\n`
    );
    process.exit(1);
  }
  const detail = [...buckets.entries()].map(([b, n]) => `${b} ${n}`).join('，');
  console.log(
    `✓ IPC 参数袋门通过：核对 ${checked} 处 invoke 调用（${detail}）、${rust.size} 个 Rust 命令、` +
      `${registered.size} 个实际注册项；命令均已注册且 required 键全覆盖。`
  );
}

main();
