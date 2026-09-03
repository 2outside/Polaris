/**
 * Rust 初始化/eval 脚本与 TypeScript 间的 boot-global 契约。
 *
 * 这不是逐个字符串钉锚：先自动盘点 production Rust 字符串与 production TS 代码里的
 * `__POLARIS_*__`，再要求全集与显式 typed registry 相等；registry 负责记录方向与 owner，自动 inventory
 * 负责让新增/搬走任一全局先转红并要求裁定，二者缺一不可。
 */
import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { productionRsFilesUnder } from './rust-source.test-support';
import { rustCode, rustStringLiterals } from './rust-js.test-support';

const REPO = fileURLToPath(new URL('../../..', import.meta.url));
const UI_SRC = join(REPO, 'ui', 'src');
const GLOBAL = /__POLARIS_[A-Z0-9_]+__/g;

type ContractKind =
  | 'rust-seed-to-ts-read'
  | 'rust-raw-self-consume'
  | 'ts-callback-to-rust-call';

interface BootGlobalContract {
  name: `__POLARIS_${string}__`;
  kind: ContractKind;
  producer?: RustItemContract;
  wiring?: RustItemContract[];
  attachment?: RustItemContract;
}

interface RustItemContract {
  file: string;
  item: string;
  needles: readonly string[];
}

const BOOT_GLOBALS = [
  {
    name: '__POLARIS_INITIAL_THEME__',
    kind: 'rust-seed-to-ts-read',
    producer: {
      file: 'src-tauri/src/tray/model.rs',
      item: 'pub fn theme_boot_script(',
      needles: ['window.__POLARIS_INITIAL_THEME__ ='],
    },
    attachment: {
      file: 'src-tauri/src/main.rs',
      item: 'fn create_main_window(',
      needles: ['.initialization_script(tray::theme_boot_script(dark))'],
    },
  },
  {
    name: '__POLARIS_TRAY_SCREEN__',
    kind: 'rust-seed-to-ts-read',
    producer: {
      file: 'src-tauri/src/tray/commands.rs',
      item: 'pub fn tray_screen_boot_script(',
      needles: ['window.__POLARIS_TRAY_SCREEN__ ='],
    },
    attachment: {
      file: 'src-tauri/src/main.rs',
      item: 'fn create_main_window(',
      needles: ['.initialization_script(tray::tray_screen_boot_script(screen))'],
    },
  },
  {
    name: '__POLARIS_TRAY_GENERATION__',
    kind: 'rust-seed-to-ts-read',
    producer: {
      file: 'src-tauri/src/tray/window.rs',
      item: 'fn build_overlay(',
      needles: ['window.__POLARIS_TRAY_GENERATION__ ='],
    },
    attachment: {
      file: 'src-tauri/src/tray/window.rs',
      item: 'fn build_overlay(',
      needles: ['.initialization_script(initialization_script)'],
    },
  },
  {
    name: '__POLARIS_UPDATE_POPUP_INITIAL__',
    kind: 'rust-seed-to-ts-read',
    producer: {
      file: 'crates/updater/src/popup.rs',
      item: 'fn build_init_script(',
      needles: ['window.__POLARIS_UPDATE_POPUP_INITIAL__ ='],
    },
    wiring: [
      {
        file: 'crates/updater/src/popup.rs',
        item: 'pub fn open(',
        needles: ['let init_script = Self::build_init_script(&state);', 'PopupBootstrap {'],
      },
      {
        file: 'src-tauri/src/runtime/update_popup.rs',
        item: 'pub fn show_update_popup(',
        needles: ['let boot: PopupBootstrap = session.open(state);', 'build_popup_window(app, &boot)?;'],
      },
    ],
    attachment: {
      file: 'src-tauri/src/runtime/update_popup.rs',
      item: 'fn build_popup_window(',
      needles: ['.initialization_script(&boot.init_script)'],
    },
  },
  { name: '__POLARIS_TRAY_EDGE__', kind: 'rust-raw-self-consume' },
  { name: '__POLARIS_SET_TRAY_EDGE__', kind: 'rust-raw-self-consume' },
  { name: '__POLARIS_NATIVE_HOVER__', kind: 'ts-callback-to-rust-call' },
] as const satisfies readonly BootGlobalContract[];

interface Source {
  rel: string;
  code: string;
  raw?: string;
}

interface Usage {
  rustAssignments: string[];
  rustReads: string[];
  rustCalls: string[];
  tsAssignments: string[];
  tsReads: string[];
  tsCalls: string[];
  tsDeclarations: string[];
}

function collectTs(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir).sort()) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) collectTs(full, out);
    else if (/\.tsx?$/.test(entry) && !/\.(test|spec)\.tsx?$/.test(entry)) out.push(full);
  }
  return out;
}

/** 保留代码位置、抹掉注释与字符串内容；boot global 必须以属性访问出现，不应靠字符串反射。 */
function tsCode(src: string): string {
  let out = '';
  let i = 0;
  while (i < src.length) {
    if (src.startsWith('//', i)) {
      const end = src.indexOf('\n', i + 2);
      if (end < 0) return out;
      out += ' '.repeat(end - i) + '\n';
      i = end + 1;
      continue;
    }
    if (src.startsWith('/*', i)) {
      const end = src.indexOf('*/', i + 2);
      if (end < 0) throw new Error('[boot-global] TS block comment 未闭合');
      const body = src.slice(i, end + 2);
      out += body.replace(/[^\n]/g, ' ');
      i = end + 2;
      continue;
    }
    if (src[i] === "'" || src[i] === '"' || src[i] === '`') {
      const quote = src[i];
      out += ' ';
      i++;
      let escaped = false;
      while (i < src.length) {
        const ch = src[i++];
        out += ch === '\n' ? '\n' : ' ';
        if (escaped) escaped = false;
        else if (ch === '\\') escaped = true;
        else if (ch === quote || (ch === '\n' && quote !== '`')) break;
      }
      continue;
    }
    out += src[i++];
  }
  return out;
}

const TS_SOURCES: Source[] = collectTs(UI_SRC).map((file) => ({
  rel: relative(REPO, file).split(sep).join('/'),
  code: tsCode(readFileSync(file, 'utf8')),
}));

const RUST_SOURCES: Source[] = [
  ...productionRsFilesUnder('src-tauri/src'),
  ...productionRsFilesUnder('crates/updater/src'),
].map((file) => {
  const raw = readFileSync(file, 'utf8');
  return {
    rel: relative(REPO, file).split(sep).join('/'),
    raw,
    code: rustStringLiterals(raw).join('\n'),
  };
});

function rustItem({ file, item }: RustItemContract): string {
  const source = RUST_SOURCES.find((entry) => entry.rel === file);
  if (!source?.raw) throw new Error(`[boot-global] Rust owner 不在 production inventory：${file}`);
  const code = rustCode(source.raw);
  const hits = [...code.matchAll(new RegExp(item.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'))];
  if (hits.length !== 1) {
    throw new Error(`[boot-global] ${file} 的 item ${item} 命中 ${hits.length} 次，无法精确切片`);
  }
  const open = code.indexOf('{', hits[0].index! + item.length);
  if (open < 0) throw new Error(`[boot-global] ${file}::${item} 缺函数体`);
  let depth = 0;
  for (let at = open; at < code.length; at++) {
    if (code[at] === '{') depth++;
    else if (code[at] === '}' && --depth === 0) return source.raw.slice(hits[0].index, at + 1);
  }
  throw new Error(`[boot-global] ${file}::${item} 函数体未闭合`);
}

function assertRustItem(contract: RustItemContract, role: string): void {
  const body = rustItem(contract);
  for (const needle of contract.needles) {
    expect(body, `${role} ${contract.file}::${contract.item} 缺 ${needle}`).toContain(needle);
  }
}

function classify(sources: Source[], side: 'rust' | 'ts', usage: Map<string, Usage>): void {
  for (const source of sources) {
    for (const match of source.code.matchAll(GLOBAL)) {
      const name = match[0];
      const row = usage.get(name) ?? {
        rustAssignments: [],
        rustReads: [],
        rustCalls: [],
        tsAssignments: [],
        tsReads: [],
        tsCalls: [],
        tsDeclarations: [],
      };
      usage.set(name, row);
      const before = source.code.slice(Math.max(0, match.index! - 16), match.index!);
      const after = source.code.slice(match.index! + name.length).trimStart();
      const at = `${source.rel}:${source.code.slice(0, match.index).split('\n').length}`;
      if (side === 'ts' && /delete\s+window\.$/.test(before)) continue;
      if (/^=(?!=)/.test(after)) row[side === 'rust' ? 'rustAssignments' : 'tsAssignments'].push(at);
      else if (/^(?:\?\.)?\(/.test(after)) row[side === 'rust' ? 'rustCalls' : 'tsCalls'].push(at);
      else row[side === 'rust' ? 'rustReads' : 'tsReads'].push(at);
    }
  }
}

const usage = new Map<string, Usage>();
classify(RUST_SOURCES, 'rust', usage);
classify(TS_SOURCES, 'ts', usage);

for (const source of TS_SOURCES) {
  for (const match of source.code.matchAll(/(__POLARIS_[A-Z0-9_]+__)\?\s*:/g)) {
    const row = usage.get(match[1]);
    if (!row) throw new Error(`[boot-global] 只有声明没有使用：${match[1]}`);
    row.tsDeclarations.push(source.rel);
  }
}

describe('boot-global production inventory 与 typed registry 一致', () => {
  it('全量自动盘点：新增/删除/改名必须先裁定契约方向', () => {
    expect([...usage.keys()].sort()).toEqual(BOOT_GLOBALS.map((row) => row.name).sort());
    expect(TS_SOURCES.length).toBeGreaterThan(100);
    expect(RUST_SOURCES.length).toBeGreaterThan(100);
  });

  it('四条 Rust 首帧注入均有 TS 类型声明和真实读取，且 TS 不反向覆写', () => {
    const seeds = BOOT_GLOBALS.filter((row) => row.kind === 'rust-seed-to-ts-read');
    expect(seeds).toHaveLength(4);
    for (const { name } of seeds) {
      const row = usage.get(name)!;
      expect(row.rustAssignments, `${name} 缺 Rust 注入`).not.toEqual([]);
      expect(row.tsReads, `${name} 缺 TS 消费`).not.toEqual([]);
      expect(row.tsDeclarations, `${name} 缺 Window 类型声明`).not.toEqual([]);
      expect(row.tsAssignments, `${name} 是 Rust 单向种子，不得由 TS 抢 owner`).toEqual([]);
    }
  });

  it('四个 producer 均沿真实调用链接进 WebviewWindowBuilder::initialization_script', () => {
    const seeds = BOOT_GLOBALS.filter((row) => row.kind === 'rust-seed-to-ts-read');
    expect(seeds).toHaveLength(4);
    for (const seed of seeds) {
      const contract: BootGlobalContract = seed;
      expect(contract.producer, `${seed.name} 缺 producer owner`).toBeDefined();
      expect(contract.attachment, `${seed.name} 缺 initialization attachment owner`).toBeDefined();
      assertRustItem(contract.producer!, `${seed.name} producer`);
      for (const wiring of contract.wiring ?? []) assertRustItem(wiring, `${seed.name} wiring`);
      assertRustItem(contract.attachment!, `${seed.name} attachment`);
    }
  });

  it('Rust raw self-consume 全局在同一注入面内同时有赋值与消费', () => {
    for (const { name } of BOOT_GLOBALS.filter((row) => row.kind === 'rust-raw-self-consume')) {
      const row = usage.get(name)!;
      expect(row.rustAssignments, `${name} 缺 raw-JS 定义`).not.toEqual([]);
      expect(
        [...row.rustReads, ...row.rustCalls],
        `${name} 定义后无人消费`,
      ).not.toEqual([]);
      expect([...row.tsAssignments, ...row.tsReads, ...row.tsCalls]).toEqual([]);
    }
  });

  it('TS callback 由 TS 定义并声明类型，Rust eval 只调用、不反向赋值', () => {
    for (const { name } of BOOT_GLOBALS.filter((row) => row.kind === 'ts-callback-to-rust-call')) {
      const row = usage.get(name)!;
      expect(row.tsAssignments, `${name} 缺 TS callback 装配`).not.toEqual([]);
      expect(row.tsDeclarations, `${name} 缺 Window callback 类型`).not.toEqual([]);
      expect(row.rustCalls, `${name} 缺 Rust eval 调用`).not.toEqual([]);
      expect(row.rustAssignments, `${name} 的 owner 应在 TS`).toEqual([]);
    }
  });
});
