#!/usr/bin/env node
/**
 * verify-packaging.mjs — 打包链不变量检查（四模式）。
 *
 * 存在理由：「每个安装包只含且恰含本平台内核」这条核心交付契约，此前**全靠四个 conf 文件名拼对，
 * 零断言**。任一 per-platform conf 被改名 / 漏建 / 键名打错，合并结果仍是合法 JSON、bundler 照常
 * 出包，装出来的 app 没有内核 —— 只在用户机器上 `resolve_core_binary` → Err 才暴露。
 * 本脚本把那条契约变成**会转红的门**。
 *
 * 四个模式（各自独立、都可在任意平台的开发机上跑）：
 *
 *   node scripts/verify-packaging.mjs confs
 *     纯静态：只读 4 个平台 conf + core-manifest.json + package.yml。不需要构建产物。
 *     守：公共资源不丢 / 每个 conf 恰含一个平台内核 / base 不含任何平台内核 /
 *         每个 conf 都被 workflow 显式引用（改名即红）/
 *         **per-platform conf 不得含未登记条目**（不变量 E，反向；见下）。
 *
 *   node scripts/verify-packaging.mjs payload --label <label> --root <bundle 根>
 *     构建后：`--root` 收 **bundle 根**（`target/release/bundle`，传了 --target 时
 *     `target/<triple>/release/bundle`），对该 label 的**每个 bundle target 各自**断言
 *     「恰含本平台那一份内核、且字节大小与源 `resources/<平台>/` 一致」。
 *     ⚠️ 不可指向 `target/release`：那里的 `_up_/resources/` 是 **cargo build script 的 staging copy**，
 *        与 bundler 有没有把内核铺进包无关，打在它上面等于没有门（详见 BUNDLE_TREES 注释）。
 *     ⚠️ windows 腿是**例外**：NSIS 把资源从源路径直接编进 .exe，bundle 侧无副本可扫，
 *        该腿如实退化为 **staging 检查**（输出里明确标注），不冒充产物验证。
 *
 *   node scripts/verify-packaging.mjs assets --label <label> --dir <dir>
 *     构建后：把产物文件名喂给 `crates/updater/src/github.rs::find_suitable_update_asset`
 *     的同一套选包规则，断言本 job 产出的资产**恰好命中一个**。
 *     Windows 契约尤其脆，且**按形态分成两条互不相交的规则**：
 *       - installed → `.exe` 且名含 `win`。Tauri NSIS 默认名 `Polaris_<ver>_x64-setup.exe`
 *         **不含 win** ⇒ 不改名的话 Windows 用户永远收不到更新且静默。
 *       - loose（便携）→ `polaris-portable-*.zip`。便携产物是 zip，结构性进不了上面那条 `.exe`
 *         过滤；此前两个形态共用同一候选集 ⇒ 便携用户恒被发 NSIS 安装器（#72 形态错配本体，
 *         2026-07-22 修）。故这里两条规则各自断言，只镜像一半就等于没守住便携形态。
 *     `--label release` 是**聚合口径**（四 job 产物汇进同一 release 后跑）：断言两个架构的 dmg
 *     各恰一个 + win setup 恰一个 + 便携 zip 恰一个 + linux 双形态各恰一个（6 个平台交付物，
 *     聚合 release 另含 SHA256SUMS），
 *     且便携候选与安装态候选不相交。per-job 口径断言「不得出现另一架构」，
 *     聚合侧两架构本就都在，故必须分开，不能复用。
 *
 *     assets 模式除命名外还有**两道内容门**（射程都只覆盖 updater 会真正命中的那些资产）：
 *       - **体积门（U2）**：`> MAX_UPDATE_ASSET_BYTES` 即红。见该常量文档；
 *       - **摘要门（U3）**：`--label release` 下 `SHA256SUMS` 缺失、格式坏、覆盖面对不上或
 *         逐条摘要不符即红。见 [`checkSha256Sums`]。
 *     `--names-only` 供**发布后**那一遍用：那时喂进来的是按真实资产名造的**同名空文件**
 *     （不回下 ~600 MB 真产物），体积与摘要在其上不可判定，故显式跳过并在输出里如实标注 ——
 *     缺了这个开关，那一遍会用 0 字节的假文件去比摘要，得到一片恒红。
 *
 *   node scripts/verify-packaging.mjs inventory --label <label> (--root <bundle 根> | --static)
 *     **包内容白名单**：把「包里该有什么」从默认放行改成**逐条登记**，登记表以外的文件一律红。
 *     上面三个模式全部只问「**该在**的东西在不在」，没有一道问「**不该在**的东西在不在」——
 *     所以下面这些此前整条逃逸（2026-08-29 实证，见 [`payloadAllowRules`] 与不变量 E）。
 *       --root   产物/staging 清点：枚举资源载荷树的全部文件，逐条对账（含「该有的够不够」）。
 *       --static 静态推导清点：不需要构建产物，从 per-platform conf 的 `bundle.resources`
 *                × 工作树 `resources/` 推出「将进包的文件集合」再对账。**只判「多余」方向**
 *                （「缺失」方向此时不可判定：helper 由 CI 现编现铺，conf 检查跑在那之前），
 *                射程差额在输出里如实标注。
 *
 * 退出码：0 = 全部不变量成立；1 = 有违反（逐条打印）；2 = 用法错误（缺必填参数）。
 */

import { readFileSync, existsSync, statSync, readdirSync, openSync, readSync, closeSync } from 'fs';
import { createHash } from 'crypto';
import { execFileSync } from 'child_process';
import { join, dirname, resolve, basename, relative } from 'path';
import { fileURLToPath } from 'url';
import { appImageRuntimeViolations } from './postprocess-appimage.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SRC_TAURI = join(ROOT, 'src-tauri');
const WORKFLOW = join(ROOT, '.github/workflows/package.yml');

/**
 * label（CI matrix）→ 平台内核目录名（resources/ 下的目录 = core-manifest 的 key）。
 * 单一真值：平台集合本身取自 core-manifest.json 的 coreArchiveSha256 键，
 * 新增平台却忘了配 conf ⇒ confs 模式转红。
 */
const LABEL_TO_CORE = {
  linux: 'linux',
  windows: 'win',
  'macos-arm64': 'mac-arm64',
  'macos-x64': 'mac-x64',
};

/** 平台内核目录 → 该平台的 tauri conf 文件名（相对 src-tauri/）。 */
const CORE_TO_CONF = {
  linux: 'tauri.linux.conf.json',
  win: 'tauri.windows.conf.json',
  'mac-arm64': 'tauri.macos-arm64.conf.json',
  'mac-x64': 'tauri.macos-x64.conf.json',
};

const errors = [];
const notes = [];
const fail = (msg) => errors.push(msg);
const note = (msg) => notes.push(msg);

/**
 * 输入侧读取失败（文件缺失 / 坏 JSON）。与「不变量被违反」区分开：
 * 前者是**门自己读不到前置**，后者是门读到了并判红。两者都 exit 1，但措辞必须不同 ——
 * 否则 CI 日志里只有一坨 `node:fs` / `JSON.parse` 裸栈，看不出「哪个不变量因此无从断言」。
 */
class InputError extends Error {}

/**
 * @param {string} path 要读的文件
 * @param {string} why  读它是为了断言什么 —— 读失败时这句话就是 CI 日志里唯一的线索
 */
function readJson(path, why) {
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e) {
    throw new InputError(`读不到 ${path}（${e.code ?? e.message}）—— ${why}`);
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new InputError(`${path} 不是合法 JSON：${e.message} —— ${why}`);
  }
}

/**
 * resources 条目形如 `../resources/mac-x64/` → 取出 `mac-x64`；非平台条目返回 null。
 *
 * 判据是**前缀**（`../resources/<平台>/…`）而非「整串恰为目录」：`../resources/win/sing-box.exe`
 * 这种**文件粒度**条目照样把该平台内核塞进包里，只认目录形态会让它整条逃逸——
 * 即 §10.2「四平台内核死重」的文件粒度版本（实测变异 M2b：四份 conf + base 各加一条
 * `../resources/win/sing-box.exe`，旧判据 exit 0，四个包全部夹带 Windows 内核）。
 */
function coreDirOf(entry, platforms) {
  const m = /^\.\.\/resources\/([^/]+)(?:\/|$)/.exec(String(entry).replace(/\\/g, '/'));
  if (!m) return null;
  return platforms.includes(m[1]) ? m[1] : null;
}

// ───────────────────── workflow matrix 解析（不变量 D 用）─────────────────────
/** 剥掉行尾 YAML 注释（引号内的 `#` 不算注释起点）。 */
function stripYamlComment(line) {
  let quote = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === quote) quote = null;
    } else if (c === '"' || c === "'") {
      quote = c;
    } else if (c === '#' && (i === 0 || /\s/.test(line[i - 1]))) {
      return line.slice(0, i);
    }
  }
  return line;
}

/** 去掉标量外层的成对引号。 */
function unquoteScalar(v) {
  const t = v.trim();
  const paired = t.length >= 2 && ((t[0] === "'" && t.endsWith("'")) || (t[0] === '"' && t.endsWith('"')));
  return paired ? t.slice(1, -1) : t;
}

/**
 * 在 `[from, to)` 行区间里，按**兄弟层缩进**找名为 `key` 的映射键，返回它的块范围。
 *
 * 「兄弟层」= 区间内第一条非空行的缩进。更深的行一律跳过 ⇒ 不会把
 * `steps: - with: include:` 之类深层同名键误当成本层的。缩进 ≤ `parentIndent`
 * 即离开父块，直接判无。
 *
 * @returns {{start:number, indent:number, end:number}|null} start=该键所在行；end=块结束行（不含）
 */
function findKeyBlock(lines, from, to, parentIndent, key) {
  let siblingIndent = null;
  for (let i = from; i < to; i++) {
    const raw = stripYamlComment(lines[i]);
    if (raw.trim() === '') continue;
    const indent = raw.length - raw.trimStart().length;
    if (indent <= parentIndent) return null; // 已离开父块
    if (siblingIndent === null) siblingIndent = indent;
    if (indent !== siblingIndent) continue; // 更深层，不是本层的键
    const m = /^([A-Za-z0-9_.-]+):\s*(.*)$/.exec(raw.trim());
    if (!m || m[1] !== key) continue;
    let end = to;
    for (let j = i + 1; j < to; j++) {
      const r2 = stripYamlComment(lines[j]);
      if (r2.trim() === '') continue;
      const ind2 = r2.length - r2.trimStart().length;
      if (ind2 <= siblingIndent) {
        end = j;
        break;
      }
    }
    return { start: i, indent: siblingIndent, end };
  }
  return null;
}

/**
 * 解析 workflow 的平台矩阵，返回腿级平铺键值对（每条腿一个对象）。
 *
 * 🔴 **数据本体已不在 `jobs.package.strategy.matrix.include`**（2026-07-31 起）：矩阵改成运行时
 * 由 `jobs.setup` 解析（`include: ${ fromJSON(needs.setup.outputs.include) }`），JSON 数据搬进了
 * setup 那个 step 的 shell 里（`all='[...]'`）。本函数没跟着搬，于是从那天起它恒返回 null
 * ⇒ 不变量 D 恒判红 ⇒ **`Verify packaging conf invariants` 这一步拦住了所有平台的打包**
 * （它排在 `Build installers` 之前）。2026-08-05 首次跑 linux 打包腿时才暴露。
 *
 * 教训记在这里而不是 commit 里：把「数据本体」搬家时，**搬的不只是那段数据和它的注释，还有所有
 * 按路径锚定它的消费方**。那次搬家的注释写了「随数据本体原样搬来」，却没提还有一个脚本在按老路径找。
 *
 * 只覆盖本仓用到的形态（`- key: value` 的标量映射），**不是**通用 YAML 解析器——
 * 为它引一个 YAML 依赖不值得（本脚本零依赖，CI 里直接 `node scripts/verify-packaging.mjs` 跑）。
 *
 * 🔴 **必须按完整路径锚定，不能「全文件第一个 include:」**：后者靠「package 恰好是文件里第一个
 * 带 matrix 的 job」这个**位置巧合**成立。实测变异 Y2：在 `package` 之前插一个带 matrix 的诱饵
 * job（四腿 conf 全对）、同时把真 `macos-x64` 腿的 `--config` 删掉 ⇒ 旧实现 exit 0 **假绿**，
 * 整条不变量 D 被一个装饰性 job 顶替。现改为 jobs → package → strategy → matrix → include
 * 逐级下钻，认的是**那条 include**，不是「某条 include」。
 *
 * 🔴 **只收缩进恰等于腿首行键位的键**：解析器此前把任意深度的 `k: v` 平铺进当前腿。
 * 实测变异 Y1：把 `tauri_args` 下沉进腿内 `env:` 子块（YAML 上该腿根本没有腿级 `tauri_args`）
 * ⇒ 旧实现照样收进 `leg.tauri_args`，exit 0 **假绿**。现在深层键被跳过 ⇒ 该腿没有 `tauri_args`
 * ⇒ 不变量 D 判红。（锚点 Y7 / 多行块标量 Y8 本就 fail-closed，实测确认。）
 *
 * **注释必须先剥掉**：不变量 D 要断言的是「本腿真的传了自己那份 conf」这条**绑定关系**，
 * 而旧实现是对整份 YAML 文本（含注释）做 `includes` —— 注释里出现同名路径即可满足。
 *
 * 路径走不通（job 改名 / 结构变形）一律返回 null ⇒ 调用侧判红，不静默跳过不变量 D。
 */
function parseMatrixInclude(text) {
  const lines = text.split('\n');
  const jobs = findKeyBlock(lines, 0, lines.length, -1, 'jobs');
  if (!jobs) return null;
  // 锚在 `jobs.setup` 内，**不是**全文件搜 `all='` —— 同 Y2 变异那条纪律：全文件搜靠「本文件里
  // 只有一处这样的赋值」这个位置巧合成立，插一个诱饵 job 就能顶替整条不变量 D。
  const setup = findKeyBlock(lines, jobs.start + 1, jobs.end, jobs.indent, 'setup');
  if (!setup) return null;
  const block = lines.slice(setup.start, setup.end).join('\n');
  // 数据本体形如 `all='[ {...}, ... ]'`（shell 单引号串，JSON 内只有双引号，故非贪婪到第一个 `'` 即可）。
  const m = block.match(/\ball='(\[[\s\S]*?\])'/);
  if (!m) return null;
  let legs;
  try {
    legs = JSON.parse(m[1]);
  } catch {
    return null; // JSON 写坏 ⇒ 判红，不静默跳过不变量 D
  }
  if (!Array.isArray(legs) || legs.length === 0) return null;
  if (!legs.every((l) => l && typeof l === 'object' && !Array.isArray(l))) return null;
  return legs;
}

/**
 * 取出 `tauri_args` 里所有 `--config <path>` 的路径。
 *
 * 用**分词**而非 `includes(...)` 子串匹配：子串判据下 `--config src-tauri/tauri.linux.conf.json.bak`
 * （变异 Y3）与「本腿 conf 后再追加一个别平台 conf」（变异 Y4）都 exit 0。前者在 tauri 参数解析期
 * 硬失败、后者由 payload 门接住，影响有界 —— 但这条门自称断言的是「本腿真的传了**自己那份**
 * conf」，就该自己守住，不该把判定外包给下游。
 */
function configArgsOf(tauriArgs) {
  const toks = String(tauriArgs ?? '')
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  const out = [];
  for (let i = 0; i < toks.length; i++) {
    if (toks[i] === '--config' && i + 1 < toks.length) out.push(unquoteScalar(toks[i + 1]));
    else if (toks[i].startsWith('--config=')) out.push(unquoteScalar(toks[i].slice('--config='.length)));
  }
  return out;
}

// ───────────────────────── 模式 1：静态 conf 不变量 ─────────────────────────
/**
 * 递归找出 `abs` 下的「空内容」违规项，返回 `[仓库相对路径, 大小]`（目录为空时大小为 `null`）。
 *
 * 只看**内容**不看**名字**：不维护「哪些文件重要」的清单，任何 0 字节文件都算违规。
 * 之所以能这么严，是因为取材面被限定在 conf **显式引用**的路径上 —— 那里的每个文件都要进包。
 */
function nonEmptyViolations(abs) {
  const out = [];
  const walk = (path) => {
    const st = statSync(path);
    if (!st.isDirectory()) {
      if (st.size === 0) out.push([relative(ROOT, path), 0]);
      return;
    }
    const entries = readdirSync(path);
    if (entries.length === 0) {
      out.push([relative(ROOT, path), null]);
      return;
    }
    for (const name of entries) walk(join(path, name));
  };
  walk(abs);
  return out;
}

function checkConfs() {
  // 本分支自己的错误计数起点：末尾那句 note 只能在**本模式**没报错时打（同 checkAssets 的 release 分支）。
  const errorsBefore = errors.length;
  const manifest = readJson(
    join(SRC_TAURI, 'core-manifest.json'),
    '平台集合无真值来源 ⇒ conf 模式的全部不变量（A/B/C/D）都无从断言'
  );
  const platforms = Object.keys(manifest.coreArchiveSha256 ?? {});
  if (platforms.length === 0) {
    fail('core-manifest.json: coreArchiveSha256 为空 —— 平台集合无真值来源');
    return;
  }

  // 平台集合 ↔ conf 映射必须一一对应（新增平台忘了配 conf / conf 多余，都转红）。
  for (const p of platforms) {
    if (!CORE_TO_CONF[p]) {
      fail(`core-manifest 有平台 '${p}'，但 verify-packaging.mjs 的 CORE_TO_CONF 未登记对应 conf`);
    }
  }
  for (const p of Object.keys(CORE_TO_CONF)) {
    if (!platforms.includes(p)) {
      fail(`CORE_TO_CONF 登记了 '${p}'，但 core-manifest.coreArchiveSha256 里没有该平台`);
    }
  }

  const base = readJson(
    join(SRC_TAURI, 'tauri.conf.json'),
    '不变量 A（公共资源逐条同步到四份 conf）与「base 不得含平台内核」都无从断言'
  );
  const baseResources = base.bundle?.resources;
  if (!Array.isArray(baseResources)) {
    fail('tauri.conf.json: bundle.resources 缺失或不是数组');
    return;
  }

  // 【已删除：Rust 常量 ↔ productName 对拍】Linux 运行时按 `<root>/usr/bin` 反推
  // `<root>/usr/lib/<productName>/_up_/resources`，此前 Rust 侧存了第二份字面量
  // （`runtime/proxy::LINUX_BUNDLE_PRODUCT_DIR`），本模式便拿正则抓它跟这里的 productName 对拍。
  // 现在 `src-tauri/build.rs::export_product_name` 直接从本文件读 productName 并用
  // `cargo:rustc-env` 注入，Rust 侧是 `env!(...)` —— 事实只剩一份，没有可漂移的两侧，
  // 对拍门随之失去存在意义（它的成本是把整棵 `src-tauri/src/runtime/` 钉成打包判据面，
  // 且正则硬锚在 proxy.rs 一个文件上，该文件一拆就失锚）。
  // 注入链本身由 `runtime/proxy::injected_product_name_matches_tauri_conf` 守着（cargo test）。

  // base 不得含任何平台内核目录：含了就等于「四平台内核全塞进每个包」的老毛病复发
  // （§10.2：四平台内核 210MB 死重）。
  for (const entry of baseResources) {
    const core = coreDirOf(entry, platforms);
    if (core) {
      fail(`tauri.conf.json: base bundle.resources 不得含平台内核目录 '${entry}' —— 会让每个平台包都塞进它`);
    }
  }

  const workflow = existsSync(WORKFLOW) ? readFileSync(WORKFLOW, 'utf8') : null;
  if (workflow === null) fail(`找不到 workflow：${WORKFLOW}`);

  // matrix 解析失败一律判红（前置缺失 ⇒ 失败，不静默跳过不变量 D）。
  const legs = workflow === null ? null : parseMatrixInclude(workflow);
  if (workflow !== null && (legs === null || legs.length === 0)) {
    fail('.github/workflows/package.yml: 解析不到平台矩阵（jobs.setup 的 Resolve platform matrix 里那段 all=[...] JSON）—— 不变量 D（每条腿绑定自己那份 conf）无从断言');
  }
  const legByLabel = new Map();
  for (const leg of legs ?? []) {
    if (!leg.label) {
      fail(`.github/workflows/package.yml: matrix include 有一条腿没有 label：${JSON.stringify(leg)}`);
      continue;
    }
    if (!LABEL_TO_CORE[leg.label]) {
      fail(`.github/workflows/package.yml: matrix 腿 label '${leg.label}' 未登记在 LABEL_TO_CORE`);
      continue;
    }
    if (legByLabel.has(leg.label)) {
      fail(`.github/workflows/package.yml: matrix 里 label '${leg.label}' 重复出现`);
      continue;
    }
    legByLabel.set(leg.label, leg);
  }

  for (const p of platforms) {
    const confName = CORE_TO_CONF[p];
    if (!confName) continue;
    const confPath = join(SRC_TAURI, confName);
    if (!existsSync(confPath)) {
      fail(`平台 '${p}' 的 conf 缺失：src-tauri/${confName}`);
      continue;
    }
    let conf;
    try {
      conf = readJson(confPath, `平台 '${p}' 的不变量 A/B/C（公共资源不丢 / 恰含本平台内核 / 路径存在）无从断言`);
    } catch (e) {
      fail(e.message);
      continue;
    }

    // per-platform conf 的**顶层键白名单**：只准 `$schema` + `bundle`，`bundle` 下只准 `resources`。
    //
    // `--config` 传入的键按 RFC 7396 合并并**覆盖 base**。四份 per-platform conf 走的是同一条
    // 通路，因此不能把 version / productName 等职责混进来：实测变异 M10
    // （`tauri.linux.conf.json` 加 `"version": "9.9.9"` + `"productName": "Bogus"`）旧实现 exit 0。
    const confTopKeys = Object.keys(conf).filter((k) => k !== '$schema');
    if (confTopKeys.length !== 1 || confTopKeys[0] !== 'bundle') {
      fail(
        `src-tauri/${confName}: 顶层只应有 bundle（+$schema），实为 ${JSON.stringify(confTopKeys)} —— ` +
          `\`--config\` 按 RFC 7396 合并会**覆盖 base**（version / productName / identifier 尤其危险：` +
          `base 版本号一升，该平台包仍被打成旧版本号）`
      );
    }
    const confBundleKeys = Object.keys(conf.bundle ?? {});
    if (confBundleKeys.length !== 1 || confBundleKeys[0] !== 'resources') {
      fail(
        `src-tauri/${confName}: bundle 下只应有 resources，实为 ${JSON.stringify(confBundleKeys)} —— ` +
          `本仓四份 per-platform conf 的唯一职责是按平台筛内核，其余 bundle 配置归 base 单一真值`
      );
    }

    const res = conf.bundle?.resources;
    if (!Array.isArray(res)) {
      // Tauri 2 的 `bundle.resources` 另有合法的 map 形态（`{"src":"dest"}`），此处**故意**只放行数组：
      // 本仓四份 per-platform conf 全靠「数组整体替换」这条 RFC 7396 语义来按平台筛内核，
      // 混入 map 形态会让不变量 A/B 的判据失效。故这是**本仓房规**，不是 Tauri 的限制。
      fail(`src-tauri/${confName}: bundle.resources 缺失或不是数组 —— 本仓只用数组形态（RFC 7396 数组整体替换是按平台筛内核的机制本身；Tauri 的 map 形态在此不受支持）`);
      continue;
    }

    // 不变量 A：公共项必须**逐条**出现在每个平台 conf 里。
    // 数组是整体替换不是合并 ⇒ 往 base 加新公共资源而忘了同步四份，四个包全部静默不含它。
    for (const common of baseResources) {
      if (!res.includes(common)) {
        fail(`src-tauri/${confName}: 缺公共资源 '${common}'（base 有；数组整体替换 ⇒ 不同步就静默丢失）`);
      }
    }

    // 不变量 B：恰含一个平台内核目录，且就是本平台的。
    // 按**去重后的平台集合**判定（而非条目数）：coreDirOf 现在也认文件粒度条目，
    // 同平台多条（`../resources/win/a` + `../resources/win/b`）是合法的，跨平台才是死重。
    const cores = [...new Set(res.map((e) => coreDirOf(e, platforms)).filter(Boolean))];
    if (cores.length !== 1 || cores[0] !== p) {
      fail(
        `src-tauri/${confName}: 平台内核应恰为 ['${p}']，实为 ${JSON.stringify(cores)}` +
          ` —— 相关条目：${JSON.stringify(res.filter((e) => coreDirOf(e, platforms)))}`
      );
    }

    // 不变量 E（**反向**：不得有未登记条目）。A/B/C 全是「该在的在不在」，方向只有一个 ——
    // 于是「往 conf 里多塞一条」这类改动整条逃逸。实测（2026-08-29，隔离 worktree）：四份
    // per-platform conf 的 `bundle.resources` 各加一条 `"../ui/src/"`，`confs` 模式仍 **rc=0**，
    // 整份 `ui/src`（含 194 个测试文件）随四个安装包出货，全链零转红。
    //
    // 登记表 = base 公共资源 ∪ **本平台**内核条目。后者不写死成 `../resources/<p>/` 一种形态：
    // 不变量 B 已明确「同平台多条 / 文件粒度条目」是合法的（`coreDirOf` 认前缀），这里必须同口径，
    // 否则本条会把 B 认可的合法形态判红。跨平台内核条目由 B 拦，落到这里也一样红（双保险）。
    for (const entry of res) {
      if (baseResources.includes(entry)) continue;
      if (coreDirOf(entry, platforms) === p) continue;
      fail(
        `src-tauri/${confName}: bundle.resources 含未登记条目 ${JSON.stringify(entry)} —— ` +
          `per-platform conf 的唯一职责是「base 公共资源 + 本平台内核」，多出来的条目会被 bundler ` +
          `**整目录递归**铺进这个平台的安装包（源码 / 测试 / 文档都能这样进包，且现有 A/B/C/D 一条都不会红）。\n` +
          `  登记表：base 公共资源 ${JSON.stringify(baseResources)} ∪ 本平台内核（前缀 '../resources/${p}/'）\n` +
          `  要新增公共资源：先加进 src-tauri/tauri.conf.json 的 bundle.resources（不变量 A 会要求四份 conf 同步）`
      );
    }

    // 不变量 C：引用的目录必须真实存在（conf 写对了但目录没 fetch 也要红）。
    for (const entry of res) {
      const abs = resolve(SRC_TAURI, entry);
      if (!existsSync(abs)) {
        fail(`src-tauri/${confName}: 资源路径不存在 '${entry}' → ${abs}`);
        continue;
      }
      // 不变量 C2：存在 ≠ 有内容。
      //
      // fetch / 解压失败的典型形态不是「目录没了」，而是**留下一个空目录或一批 0 字节文件**：
      // 不变量 C 的 existsSync 对这两种都判绿，随后包被打出来、面板入口是 0 字节、
      // 核回落联网下载（离线不可用）。
      //
      // 这条性质继承自 `scripts/verify-dashboard-resources.mjs` —— 那个脚本断言
      // 「resources/dashboard/index.html 存在且非 0 字节」，但它挂的是 `beforeBundleCommand`，
      // 而 `tauri.conf.json` 里根本没有这个键（两份 docs 却仍描述它在跑，是「文档说有门、
      // 实际没门」）。孤儿脚本已删除，性质搬到这里，并从「硬编码一个文件路径」推广成
      // 「conf 引用面上的任何 0 字节」—— 不必再维护一份「哪些文件重要」的手写清单。
      for (const [file, size] of nonEmptyViolations(abs)) {
        fail(
          `src-tauri/${confName}: 资源 '${entry}' 下${size === null ? '目录为空' : '存在 0 字节文件'}：${file}\n` +
            `  存在 ≠ 有内容。fetch / 解压失败的常见形态就是留下空目录或 0 字节文件，` +
            `而只看 existsSync 的检查会放它进包。`
        );
      }
    }

    // 不变量 D：workflow 的 matrix 里，**本平台那条腿**必须在自己的 `tauri_args` 里显式传自己那份 conf。
    //
    // 只靠 Tauri 的「按平台名自动合并」= 文件一改名就静默失效（正是本检查要堵的失败面）；
    // 显式 --config 时改名会得到 `failed to read configuration file` 硬失败。
    //
    // 🔴 这里断言的是**绑定关系**，不是「文本里出现过这个字符串」。旧写法对整份 YAML（含注释）
    // 做 `includes`，两类真缺陷整条逃逸（均已实测 exit 0）：
    //   - 变异 M4：从 linux 腿删掉 `--config`、把路径留在注释里 ⇒ 子串仍在，静默放行；
    //   - 变异 M3b：两条 mac 腿的 conf **对调** ⇒ arm64 包塞 x64 核，两个字符串都还在，静默放行。
    const label = Object.keys(LABEL_TO_CORE).find((l) => LABEL_TO_CORE[l] === p);
    if (workflow !== null && legs !== null && legs.length > 0) {
      const leg = legByLabel.get(label);
      if (!leg) {
        fail(`.github/workflows/package.yml: matrix 里没有 label '${label}' 的腿 —— 平台 '${p}' 不会被构建`);
      } else {
        // 断言的是 `--config` 的**集合恰为 {本腿那份}**，不是「字符串里出现过它」：
        // 子串判据放行 `...conf.json.bak`（Y3）与「本腿 conf + 追加一个别平台 conf」（Y4）。
        const confs = configArgsOf(leg.tauri_args);
        if (confs.length !== 1 || confs[0] !== `src-tauri/${confName}`) {
          fail(
            `.github/workflows/package.yml: matrix 腿 '${label}' 的 \`--config\` 应恰为 ` +
              `['src-tauri/${confName}']，实为 ${JSON.stringify(confs)}（tauri_args = ` +
              `${JSON.stringify(leg.tauri_args ?? null)}）—— 少了它会退回隐式合并（改名即静默失效）；` +
              `多一个别平台 conf 会按 RFC 7396 数组整体替换，该腿打进错误平台的内核`
          );
        }
      }
    }
  }

  // matrix 腿必须覆盖全部平台（多出来的腿在上面 LABEL_TO_CORE 校验里已拦）。
  for (const l of Object.keys(LABEL_TO_CORE)) {
    if (legs !== null && legs.length > 0 && !legByLabel.has(l)) {
      fail(`.github/workflows/package.yml: matrix include 缺 label '${l}' 的腿`);
    }
  }

  checkWindowsInstallerHooks(base);
  checkMacOpenGuide();
  if (workflow !== null) {
    checkNamesOnlyDiscipline(workflow);
    checkLinuxAppImagePostprocess(workflow);
  }

  // 失败时**不得**打这句：它字面断言「各含 1 份内核」，与紧随其后的 FAILED 并存就是
  // 一句字面为假的 ok 断言（正是本轮反复在查的「note 声称的比它验的多」）。
  if (errors.length === errorsBefore) {
    note(
      `conf 不变量：平台 ${platforms.join(', ')}，各含 1 份内核 + ${baseResources.length} 项公共资源，` +
        `且无未登记条目（不变量 E）`
    );
  }
}

/** Linux AppImage 后处理必须只跑 Linux，并且夹在 Tauri 出包与 payload 产物门之间。 */
function checkLinuxAppImagePostprocess(workflow) {
  const needle = 'node scripts/postprocess-appimage.mjs --root target/release/bundle/appimage';
  const calls = workflow
    .split('\n')
    .map(stripYamlComment)
    .filter((line) => line.includes(needle));
  if (calls.length !== 1) {
    fail(`package.yml 应恰有 1 条 AppImage 后处理命令，实为 ${calls.length} 条：${JSON.stringify(calls)}`);
    return;
  }
  const callAt = workflow.indexOf(calls[0].trim());
  const buildAt = workflow.indexOf('- name: Build installers');
  const verifyAt = workflow.indexOf('- name: Verify bundled core payload (Linux)');
  if (buildAt < 0 || verifyAt < 0 || !(buildAt < callAt && callAt < verifyAt)) {
    fail('package.yml 的 AppImage 后处理必须位于 Build installers 之后、Linux payload 验证之前');
  }
  const stepAt = workflow.lastIndexOf('\n      - name:', callAt);
  const nextAt = workflow.indexOf('\n      - name:', callAt);
  const step = workflow.slice(stepAt < 0 ? 0 : stepAt, nextAt < 0 ? workflow.length : nextAt);
  if (!step.includes("if: runner.os == 'Linux'")) {
    fail('package.yml 的 AppImage 后处理步骤必须带 `if: runner.os == \'Linux\'`，不得污染其它平台产物');
  }
  if (!calls[0].includes('--tool "$HOME/.cache/tauri/linuxdeploy-plugin-appimage.AppImage" --arch x86_64')) {
    fail('AppImage 后处理必须显式复用 Tauri 已下载的官方输出插件并声明 x86_64 架构');
  }
}

/**
 * `--names-only` 的使用纪律：它**只准**出现在发布后那一遍。
 *
 * # 为什么这条必须由机器守
 *
 * 一个词就能把两道内容门（体积 + 摘要）降级成命名门，而降级后的日志与全口径跑过的日志**几乎一样**
 * ——只差一行 note，没人会看。真实场景：调试时给上传前那条加上它让 CI 转绿、事后忘了摘，
 * 此后每个 release 的体积门与摘要内容门都不再跑，而 CI 一直是绿的。
 * 这正是本仓「新路径可能绕开旧闸门」那条纪律的形态：开关本身就是那条新路径。
 *
 * # 判据形状（照抄不变量 D 的教训）
 *
 * 先**剥掉行尾注释**再判：对整份 YAML 做子串判断的话，注释里写一句 `--names-only` 就能顶替判据
 * （不变量 D 的变异 M4 就是这么逃逸的）。判的是**调用行本身**：
 *  - 两条 `--label release` 调用必须都在（少一条 = 有一遍没跑，或者判据认不出它了 ⇒ 红）；
 *  - 上传前那条（`--dir …/dist-release`）**不得**带 `--names-only`；
 *  - 发布后那条（`--dir "$outdir"`，喂的是同名空文件）**必须**带；
 *  - 全 workflow 里带 `--names-only` 的调用**恰好一条** —— 防它蔓延到 per-job 三条腿。
 *
 * 认不出（重命名了 `$outdir`、改了目录形态）一律判红：判据取不到时装作通过，等于把这条纪律删掉。
 *
 * # 射程边界（如实登记，不修）
 *
 * 判据看的是**调用行的字面**，故把开关藏进 shell 变量（`F=--names-only` … `node … $F`）能绕过去。
 * 那是**刻意规避**，不在本门自述的射程里 —— 它守的是「调试时加上、事后忘了摘」这类无意残留。
 * 一道门不可能同时防住健忘和防住存心，把射程写清楚比假装它两样都防更有用。
 */
function checkNamesOnlyDiscipline(workflow) {
  const calls = workflow
    .split('\n')
    .map(stripYamlComment)
    .filter((l) => l.includes('verify-packaging.mjs') && l.includes('assets --label'));
  const release = calls.filter((l) => l.includes('--label release'));
  if (release.length !== 2) {
    fail(
      `.github/workflows/package.yml: 应恰有 2 条 \`assets --label release\` 调用（上传前全口径 + 发布后仅命名），` +
        `实为 ${release.length} 条。\n` +
        `  <2 ⇒ 有一遍没跑，或判据认不出它（改了调用形态）—— 两种都让本纪律无从断言；\n` +
        `  >2 ⇒ 新增了 release 口径的调用，本纪律的射程没跟上：请把判据从「按条数」改成` +
        `「按 --dir 分类」（每个目标目录各自声明该不该带 --names-only），再把新那条登记进去。`
    );
    return;
  }
  const preUpload = release.filter((l) => l.includes('dist-release'));
  const published = release.filter((l) => l.includes('$outdir'));
  if (preUpload.length !== 1 || published.length !== 1) {
    fail(
      `.github/workflows/package.yml: 两条 release 口径的调用分不出「上传前（--dir …/dist-release）」与` +
        `「发布后（--dir "$outdir"）」，无从断言 \`--names-only\` 的使用纪律。实得：${JSON.stringify(release)}`
    );
    return;
  }
  if (preUpload[0].includes('--names-only')) {
    fail(
      `.github/workflows/package.yml: 上传前那条 release 口径带了 \`--names-only\` —— ` +
        `体积门与摘要内容门被降级成命名门，而它跑的是**真产物**，是唯一判得了这两件事的地方。`
    );
  }
  if (!published[0].includes('--names-only')) {
    fail(
      `.github/workflows/package.yml: 发布后那条 release 口径缺 \`--names-only\` —— ` +
        `那一遍喂的是同名空文件，会拿 0 字节去比摘要，得到一片与真实状态无关的恒红。`
    );
  }
  const withFlag = calls.filter((l) => l.includes('--names-only'));
  if (withFlag.length !== 1) {
    fail(
      `.github/workflows/package.yml: 全 workflow 里带 \`--names-only\` 的 assets 调用应恰有 1 条（发布后那遍），` +
        `实为 ${withFlag.length} 条 —— 它蔓延到别的腿就等于把那条腿的内容门静默关掉。`
    );
  }
}

/** 取 installerHooks 里一个 NSIS hook 宏的本体；缺失/未闭合一律返回 null。 */
function nsisHookBody(source, name) {
  const lines = source.split('\n');
  const start = lines.findIndex((line) => new RegExp(`^!macro ${name}(?:\\s|$)`).test(line.trim()));
  if (start < 0) return null;
  const endOffset = lines.slice(start + 1).findIndex((line) => line.trim() === '!macroend');
  return endOffset < 0 ? null : lines.slice(start + 1, start + 1 + endOffset).join('\n');
}

const NSIS_LANGUAGES = ['English', 'SimpChinese', 'TradChinese', 'Russian', 'Farsi'];
const FARSI_TAURI_MESSAGE_KEYS = [
  'addOrReinstall',
  'alreadyInstalled',
  'alreadyInstalledLong',
  'appRunning',
  'appRunningOkKill',
  'chooseMaintenanceOption',
  'choowHowToInstall',
  'createDesktop',
  'dontUninstall',
  'dontUninstallDowngrade',
  'failedToKillApp',
  'installingWebview2',
  'newerVersionInstalled',
  'older',
  'olderOrUnknownVersionInstalled',
  'silentDowngrades',
  'unableToUninstall',
  'uninstallApp',
  'uninstallBeforeInstalling',
  'unknown',
  'webview2AbortError',
  'webview2DownloadError',
  'webview2DownloadSuccess',
  'webview2Downloading',
  'webview2InstallError',
  'webview2InstallSuccess',
  'deleteAppData',
];

/** NSIS 五语 + Farsi Tauri 自定义消息的静态契约。 */
function checkWindowsNsisLocalization(base) {
  const nsis = base.bundle?.windows?.nsis;
  if (!nsis) {
    fail('tauri.conf.json: bundle.windows.nsis 缺失，无法断言 Windows NSIS 五语配置');
    return;
  }
  if (
    !Array.isArray(nsis.languages) ||
    nsis.languages.length !== NSIS_LANGUAGES.length ||
    nsis.languages.some((language, index) => language !== NSIS_LANGUAGES[index])
  ) {
    fail(
      `tauri.conf.json: bundle.windows.nsis.languages 应严格为 ${JSON.stringify(NSIS_LANGUAGES)}，实为 ${JSON.stringify(nsis.languages)}`
    );
  }
  if (nsis.displayLanguageSelector !== true) {
    fail('tauri.conf.json: bundle.windows.nsis.displayLanguageSelector 必须为 true（保留系统预选与人工选择）');
  }

  const expectedCustomLanguageFiles = { Farsi: 'nsis-languages/Farsi.nsh' };
  const customLanguageFiles = nsis.customLanguageFiles;
  if (
    !customLanguageFiles ||
    Object.keys(customLanguageFiles).length !== 1 ||
    customLanguageFiles.Farsi !== expectedCustomLanguageFiles.Farsi
  ) {
    fail(
      `tauri.conf.json: bundle.windows.nsis.customLanguageFiles 应严格为 ${JSON.stringify(expectedCustomLanguageFiles)}，实为 ${JSON.stringify(customLanguageFiles)}`
    );
    return;
  }

  const farsiPath = resolve(SRC_TAURI, customLanguageFiles.Farsi);
  if (!existsSync(farsiPath)) {
    fail(`Farsi Tauri 自定义消息文件不存在：${farsiPath}`);
    return;
  }
  const farsiSource = readFileSync(farsiPath, 'utf8');
  if (/LANG_PERSIAN/.test(farsiSource)) {
    fail('nsis-languages/Farsi.nsh: 不得使用 LANG_PERSIAN；NSIS 3.11 的有效 token 为 LANG_FARSI');
  }
  if (/\$\{LANG_(?!FARSI\})/.test(farsiSource)) {
    fail('nsis-languages/Farsi.nsh: 所有 Tauri LangString 都必须绑定 LANG_FARSI');
  }
  const messageKeys = [...farsiSource.matchAll(/^LangString\s+(\w+)\s+\$\{LANG_FARSI\}\s+"/gm)].map(
    (match) => match[1]
  );
  const actualKeys = new Set(messageKeys);
  const expectedKeys = new Set(FARSI_TAURI_MESSAGE_KEYS);
  const missing = FARSI_TAURI_MESSAGE_KEYS.filter((key) => !actualKeys.has(key));
  const unexpected = messageKeys.filter((key) => !expectedKeys.has(key));
  const duplicates = messageKeys.filter((key, index) => messageKeys.indexOf(key) !== index);
  if (missing.length || unexpected.length || duplicates.length || messageKeys.length !== FARSI_TAURI_MESSAGE_KEYS.length) {
    fail(
      `nsis-languages/Farsi.nsh: Tauri 消息键必须与 English.nsh 完全一致（缺 ${JSON.stringify(missing)}；` +
        `多 ${JSON.stringify(unexpected)}；重复 ${JSON.stringify([...new Set(duplicates)])}；总数 ${messageKeys.length}）`
    );
  }
  if (existsSync(join(dirname(farsiPath), 'Farsi.nlf'))) {
    fail('src-tauri/nsis-languages/Farsi.nlf 不应存在：NSIS 3.11 自带语言基础文件，仓内只维护 Tauri 自定义消息');
  }
}

/** Windows NSIS 三条自定义钩子的静态契约（安装前清 legacy；安装后归一形态；卸载后清 helper）。 */
function checkWindowsInstallerHooks(base) {
  const errorsBefore = errors.length;
  checkWindowsNsisLocalization(base);
  const configured = base.bundle?.windows?.nsis?.installerHooks;
  if (configured !== 'nsis-hooks.nsh') {
    fail(
      `tauri.conf.json: bundle.windows.nsis.installerHooks 应为 'nsis-hooks.nsh'，实为 ${JSON.stringify(configured)}`
    );
    return;
  }
  const hookPath = resolve(SRC_TAURI, configured);
  if (!existsSync(hookPath)) {
    fail(`Windows NSIS installerHooks 文件不存在：${hookPath}`);
    return;
  }
  const source = readFileSync(hookPath, 'utf8');
  if (/LANG_PERSIAN/.test(source)) {
    fail('nsis-hooks.nsh: 不得使用 LANG_PERSIAN；Farsi 的 LCID/token 必须保持为 1065/LANG_FARSI');
  }
  const selectorHeader = '!macro PolarisSelectLang OUT EN ZHCN ZHTW RU FA';
  const selector = nsisHookBody(source, 'PolarisSelectLang');
  if (!source.split('\n').some((line) => line.trim() === selectorHeader) || selector === null) {
    fail(`nsis-hooks.nsh: 缺五语选择宏 ${selectorHeader}`);
  } else {
    const requiredBranches = [
      ['2052', 'ZHCN'],
      ['1028', 'ZHTW'],
      ['1049', 'RU'],
      ['1065', 'FA'],
    ];
    if (!selector.includes('StrCpy ${OUT} "${EN}"')) {
      fail('nsis-hooks.nsh: PolarisSelectLang 必须以 English 作为未命中系统语言的回退');
    }
    for (const [lcid, argument] of requiredBranches) {
      if (!selector.includes(`$LANGUAGE == ${lcid}`) || !selector.includes(`StrCpy ${'${OUT}'} "${'${'}${argument}}"`)) {
        fail(`nsis-hooks.nsh: PolarisSelectLang 缺 LCID ${lcid} → ${argument} 分支`);
      }
    }
  }
  const selectorCalls = source.match(/!insertmacro PolarisSelectLang\s+\$R8/g) ?? [];
  if (selectorCalls.length !== 4) {
    fail(`nsis-hooks.nsh: 四处安装/卸载进度文案都必须经五语选择宏，实为 ${selectorCalls.length} 处`);
  }
  const pre = nsisHookBody(source, 'NSIS_HOOK_PREINSTALL');
  if (pre === null) {
    fail('nsis-hooks.nsh: 缺 NSIS_HOOK_PREINSTALL（升级不会清旧版裸 resources）');
  } else {
    const cleanup = 'RMDir /r "$INSTDIR\\resources"';
    const hasCleanup = pre.split('\n').some((line) => line.trim() === cleanup);
    if (!hasCleanup) {
      fail(`nsis-hooks.nsh: PREINSTALL 必须含逐字清理命令 ${cleanup}`);
    }
    if (/RMDir\s+\/r\s+"\$INSTDIR\\_up_/i.test(pre)) {
      fail('nsis-hooks.nsh: PREINSTALL 不得删除当前权威 `_up_` 资源目录');
    }
    const portableCleanup = 'Delete "$INSTDIR\\portable.marker"';
    const deletesPortableEarly = pre
      .split('\n')
      .some((line) => line.trim() === portableCleanup);
    if (deletesPortableEarly) {
      fail('nsis-hooks.nsh: PREINSTALL 不得提前删除 portable.marker（安装失败时会破坏旧便携副本形态）');
    }
  }
  const postInstall = nsisHookBody(source, 'NSIS_HOOK_POSTINSTALL');
  if (postInstall === null) {
    fail('nsis-hooks.nsh: 缺 NSIS_HOOK_POSTINSTALL（覆盖便携目录后会把安装版继续误判为 portable）');
  } else {
    const cleanup = 'Delete "$INSTDIR\\portable.marker"';
    const hasCleanup = postInstall.split('\n').some((line) => line.trim() === cleanup);
    if (!hasCleanup) {
      fail(`nsis-hooks.nsh: POSTINSTALL 必须含逐字清理命令 ${cleanup}`);
    }
  }
  if (nsisHookBody(source, 'NSIS_HOOK_POSTUNINSTALL') === null) {
    fail('nsis-hooks.nsh: 缺既有 NSIS_HOOK_POSTUNINSTALL（真卸载会遗留外置 helper）');
  }
  if (errors.length === errorsBefore) {
    note('Windows NSIS：English/简中/繁中/Russian/Farsi，系统预选+语言选择器；安装前清 legacy resources；安装后清 portable marker；真卸载后清外置 helper');
  }
}

/**
 * macOS 首次打开引导（#318）—— 三处文案/路径的一致性。
 *
 * # 为什么值得单独一条
 *
 * 这份引导是**用户在拿不到任何其它帮助时**唯一能看到的东西：他双击 app 报「已损坏」，
 * 此时他既没进过 README、也没进过应用（进不去）。而它的三个组成部分分别住在三个文件里：
 * 内容在 `packaging/`、注入与文件名在 `package.yml`、同一条命令的另一份在 `README.md`。
 * 任意一处改了名字或命令，症状都不是报错，而是「用户照着做但没用」。
 *
 * 本条在 **Linux 的 confs 腿**跑（打包前、1x 计费），不必等 mac 腿。mac 腿另有一条
 * 「把 dmg 挂回来看文件在不在」的开箱验 —— 两者管的是不同的东西：这里管**说得对不对**，
 * 那里管**塞没塞进去**。
 */
function checkMacOpenGuide() {
  const guidePath = join(ROOT, 'packaging', 'macos-dmg-open-guide.txt');
  if (!existsSync(guidePath)) {
    fail(`packaging/macos-dmg-open-guide.txt 不存在 —— dmg 内附引导那一步会直接失败`);
    return;
  }
  const guide = readFileSync(guidePath, 'utf8');
  const pkg = readFileSync(join(ROOT, '.github', 'workflows', 'package.yml'), 'utf8');
  const readme = readFileSync(join(ROOT, 'README.md'), 'utf8');

  // 唯一真值取 README（它是既有的、用户可见的那一份），引导必须照抄同一条命令。
  // 两处给不同命令 = 用户照着 dmg 里那份做完发现还是打不开，而 README 里写着另一条。
  const CMD = 'xattr -cr /Applications/Polaris.app';
  if (!readme.includes(CMD)) {
    fail(`README.md 里的 quarantine 命令不再是 \`${CMD}\` —— 真值变了，引导要跟着改（本门也要跟着改）`);
  }
  if (!guide.includes(CMD)) {
    fail(`引导里的命令与 README 不一致，应含 \`${CMD}\``);
  }
  // 开箱验也必须核对同一条命令；若仍搜旧命令/旧参数，DMG 明明正确却会在最后一步假红。
  if (!pkg.includes(`grep -Fc '${CMD}'`)) {
    fail(`package.yml 的 DMG 开箱验没有按完整新命令计数：应包含 \`grep -Fc '${CMD}'\``);
  }
  // 中英双语：dmg 是发给所有用户的，只有中文等于对一半用户没写。
  if (!/Applications folder/i.test(guide)) {
    fail('引导缺英文段 —— dmg 面向全部用户，单语等于对另一半人没写');
  }

  // 文件名：注入与开箱验两步各写一份，且必须使用产品约定的简短英文名。
  const names = [...pkg.matchAll(/guide_name="([^"]+)"/g)].map((m) => m[1]);
  if (names.length !== 2) {
    fail(`package.yml 里 guide_name 出现 ${names.length} 次，应恰好 2 次（注入 + 开箱验各一）`);
  } else if (names[0] !== names[1]) {
    fail(`package.yml 的两处 guide_name 不一致：${JSON.stringify(names)} —— 开箱验会去找一个不存在的名字`);
  } else if (names[0] !== 'README First.txt') {
    fail(`DMG 引导文件名应为 \`README First.txt\`，实为 \`${names[0]}\``);
  }

  // 指南是在 Tauri 生成 .DS_Store 后才注入的，必须显式写入图标坐标；默认窗口也必须容纳第二行。
  // 只检查文件存在会漏掉“必须手动放大窗口才看得到”的真实回归。
  if (!pkg.includes('guide_x=330') || !pkg.includes('guide_y=330')) {
    fail('package.yml 未固定 README First.txt 的 Finder 图标坐标（330,330）');
  }
  if (!pkg.includes('min_window_height=500')) {
    fail('package.yml 的最终 DMG 开箱验未检查至少 500px 的窗口高度');
  }
  const tauri = readJson(join(SRC_TAURI, 'tauri.conf.json'), 'DMG 窗口高度真值无从校验');
  const dmgWindow = tauri.bundle?.macOS?.dmg?.windowSize;
  if (dmgWindow?.width !== 660 || dmgWindow?.height !== 500) {
    fail(`tauri.conf.json 的 DMG 窗口应为 660x500，实为 ${JSON.stringify(dmgWindow)}`);
  }

  if (!pkg.includes('packaging/macos-dmg-open-guide.txt')) {
    fail('package.yml 不再引用 packaging/macos-dmg-open-guide.txt —— 引导不会进 dmg');
  }

  // 必须封印并复验**最终 dmg 内的 app**。只签 bundle/macos 中间目录没有意义：dmg 在 Tauri build
  // 时已复制旧 bundle；只验签一次也守不住后续 hdiutil convert 回写旧镜像。
  const SIGN = 'codesign --force --deep --sign - --timestamp=none "${apps[0]}"';
  const VERIFY = 'codesign --verify --deep --strict --verbose=2 "${apps[0]}"';
  const signCount = pkg.split(SIGN).length - 1;
  const verifyCount = pkg.split(VERIFY).length - 1;
  if (signCount !== 1) {
    fail(`package.yml 的最终 dmg app ad-hoc seal 应恰好 1 次，实为 ${signCount} 次`);
  }
  if (verifyCount !== 2) {
    fail(`package.yml 的 app strict verify 应恰好 2 次（封印后 + 最终 dmg 开箱），实为 ${verifyCount} 次`);
  }
  note('macOS dmg：首次打开引导一致，且最终 app bundle 已封印并经开箱 strict verify');
}

// ───────────────────────── 模式 2：构建产物载荷 ─────────────────────────

/**
 * 随包二进制家族：**每一个都必须逐个验**，不是「验内核就代表验了包」。
 *
 * 2026-08-10 实证：本门此前只扫 `sing-box`，于是三平台全部出货过**不含 `polaris-helper` 的安装包**，
 * 且四条腿全绿 —— package.yml 里从来没有构建/铺放 helper 的步骤，而门对它结构性失明，
 * 两个洞互相遮掩。取证方式是把 macos-arm64 的 dmg 拉下来解 UDIF 后在 HFS+ 目录里搜文件名：
 * `sing-box` 命中 2、`Polaris` 6、`Info.plist` 2，`polaris-helper` **0**（同一探针对存在的名字有命中 ⇒
 * 这个 0 是真缺失，不是探针坏）。后果不是少个可选件：`resolve_helper_binary` → Err ⇒ helper 装不上
 * ⇒ macOS/Windows 的 TUN 与特权网络操作整条不可用，而 app 照常启动、构建期与打包期零报错。
 *
 * 判据写成表而不是把 helper 硬编在内核那段里：再加第三个随包二进制时，漏掉它的默认后果是
 * 「表里没有 ⇒ 没人验」，与本次同型。故表本身也被 `payload_family_table_covers_all_bundled_bins`
 * 之外的东西约束不了 —— 这一条只能靠人，写在这里提醒下一个加二进制的人回来补一行。
 */
const PAYLOAD_FAMILIES = [
  {
    what: 'sing-box',
    names: new Set(['sing-box', 'sing-box.exe']),
    consequence: '用户机器上 resolve_core_binary → Err 才暴露的静默坏包',
  },
  {
    what: 'polaris-helper',
    names: new Set(['polaris-helper', 'polaris-helper.exe']),
    consequence:
      '用户机器上 resolve_helper_binary → Err ⇒ 特权 helper 装不上（TUN / 路由 / DNS 接管整条不可用），' +
      'app 仍能启动，故不装 TUN 试一次发现不了',
  },
  {
    what: 'Cronet sidecar',
    names: new Set(['libcronet.so', 'libcronet.dll']),
    requiredLabels: new Set(['linux', 'windows']),
    consequence:
      'Naive/H3 初始化时报 library not found；macOS 的 Cronet 已静态集成，故不要求动态库',
  },
];

// ── ELF Build ID（PKG-1）：仅作 appimage 腿「体积失配」时的豁免证据——linuxdeploy 对动态
// ELF 合法改写 rpath，体积必变；GNU Build ID（`.note.gnu.build-id`）是编译期烙进只读段的
// 构建指纹，patchelf 不动它。**不是普适判据**：Go 剥离产物（sing-box）整个 ELF 无 note 段，
// 返回 null 属合法形态（体积一致时根本不会走到这里）。用 `readelf -n` 而非手写 ELF 解析：
// runner 与本机都有 binutils，且自写解析器就是下一个会被注释/字符串喂饱的扫描器。
function elfBuildId(file) {
  try {
    const out = execFileSync('readelf', ['-n', file], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    const m = out.match(/Build ID:\s*([0-9a-f]+)/i);
    return m ? m[1].toLowerCase() : null;
  } catch {
    return null;
  }
}

/** 是否 ELF（魔数 \x7fELF）—— 非 ELF（.exe 等）不走 Build ID 分支。 */
function isElf(file) {
  try {
    const fd = openSync(file, 'r');
    const buf = Buffer.alloc(4);
    readSync(fd, buf, 0, 4, 0);
    closeSync(fd);
    return buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46;
  } catch {
    return false;
  }
}

// `names` 无默认值且排在 `out` 之前：漏传会当场 TypeError，而不是静默扫出空集合
// —— 空集合会一路走成「找不到 ⇒ 判红」，方向虽朝红，但红的理由是假的，排查要多绕一圈。
function walk(dir, names, out = [], depth = 0) {
  // 深度上限防意外深树 + 防 symlink 环路。留足余量：deb 的 staging 路径已到 10 层。
  //
  // 🔴 **symlink 必须跟进**（2026-08-05，首次 mac CI 实证驱动）：此前用 `Dirent.isDirectory()`，
  // 它对 symlink 恒为 false ⇒ 指向目录的软链整棵子树被跳过。macOS bundler 铺 `.app` 时
  // 资源很可能是软链（Linux 的 deb/AppImage 不是，所以 linux 腿一直是绿的，掩盖了这一点）。
  // 用 `statSync`（跟随软链）判类型；环路由 depth 上限兜住 —— 20 层内绕不回来就是真的深树。
  if (depth > 20) return out;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const full = join(dir, e.name);
    let st;
    try {
      st = statSync(full); // 跟随 symlink；断链会抛 → 跳过
    } catch {
      continue;
    }
    if (st.isDirectory()) walk(full, names, out, depth + 1);
    else if (st.isFile() && names.has(e.name)) out.push(full);
  }
  return out;
}

/**
 * 扫不到内核时的**布局取证**：列出该 scope 下的实际路径样本（标注类型），供一次跑就拿到真相。
 *
 * 没有它的话，失败消息只说「找到的 sing-box 文件：[]」—— 分不清是「bundler 没铺」「铺在别处」
 * 还是「扫描器进不去」。而 mac 腿每验证一次是 10x 计费的一整轮，猜错一次就是几百计费分钟。
 */
function layoutSample(dir, limit = 40) {
  const rows = [];
  const rec = (d, depth) => {
    if (depth > 6 || rows.length >= limit) return;
    let entries;
    try {
      entries = readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (rows.length >= limit) return;
      const full = join(d, e.name);
      const link = e.isSymbolicLink() ? ' →(symlink)' : '';
      let kind = '?';
      try {
        const st = statSync(full);
        kind = st.isDirectory() ? 'dir ' : `file ${st.size}B`;
      } catch {
        kind = 'broken-link';
      }
      rows.push(`    ${kind}${link}  ${relative(dir, full)}`);
      if (kind === 'dir ') rec(full, depth + 1);
    }
  };
  rec(dir, 0);
  return rows.length > 0 ? rows.join('\n') : '    （空目录）';
}

/**
 * label → 该 job 在 **bundle 根**下能被扫描的产物目录（bundler 真铺出来的目录树）。
 *
 * 为什么只列这几个：`.dmg` / NSIS 的 `.exe` / `.deb` / `.AppImage` 都是**压缩或编译后的单文件**，
 * `walk()` 进不去；能回答「装出来到底有没有内核」的只有 bundler 留下的目录树。
 *
 * 🔴 这份表是本模式从「staging 检查」变回「产物验证」的关键。此前 `--root` 收的是 `target/release`，
 * 而 `target/release/_up_/resources/<平台>/` 是 **cargo build script 的 staging copy**，
 * 与 bundler 有没有把内核铺进包**完全无关**（实证：本机 `target/debug/` 下同样有 `_up_/resources/`，
 * 却根本没有 `bundle/` 目录 ⇒ 那棵树纯由 `cargo build` 生成）。于是变异 P2（deb/AppImage 里零内核）
 * 与 P3（`Polaris.app` 里零内核）均 exit 0 —— 「装出来没核」这条压根没守住。
 *
 * 实证来源（tauri-cli 2.11.4 预编译二进制 `ui/node_modules/@tauri-apps/cli-linux-x64-gnu/
 * cli.linux-x64-gnu.node` 的字符串表 / 内嵌模板，`strings` 可复现）：
 *   - deb：`bundle/deb` + `crates/tauri-bundler/src/bundle/linux/debian.rs`
 *     + `Failed to copy resource files` + `Failed to tar/gzip data directory`
 *     ⇒ 先把资源铺进 `bundle/deb/<pkg>/data/…` 再打 tar，目录树留存可扫。
 *   - appimage：`bundle/appimage` + `_deb` + `.AppDir` ⇒ `bundle/appimage/<pkg>.AppDir/…` 留存可扫。
 *   - nsis：内嵌 installer.nsi 模板是 `File /a "/oname={{this.[1]}}" "{{no-escape @key}}"`，
 *     `@key` 是资源的**源路径** ⇒ NSIS 直接从 `resources/` 编进 `.exe`，
 *     **bundle 侧不存在任何副本**。故 windows 腿列空 —— 该腿只能是 staging 检查，
 *     本脚本**如实这么标注**，不冒充产物验证。
 *
 * ✅ macOS（`bundle/macos/<Product>.app/Contents/Resources/_up_/resources/mac-<arch>/`）**已实证**
 *    （2026-08-05 首次跑 macos-arm64 打包腿）。第一跑扫到的是**空目录** —— 因为
 *    `tauri.conf.json` 的 `bundle.targets` 当时只有 `dmg`，bundler 不保留 `.app`，
 *    `bundle/macos/` 自然是空的。已给 targets 补上 `app`：dmg 本就是从那个 `.app` 打出来的，
 *    保留它零成本（`Upload artifacts` 只收 `*.dmg`，`.app` 不进 artifact）。
 *
 *    **如实标注一处差额**：本门验的是 `.app`，不是 dmg 内部。要验 dmg 得 `hdiutil attach` 挂载，
 *    那条路只能在 macOS 上跑、且与「脚本三模式都可在任意平台开发机上跑」冲突。dmg 由该 `.app`
 *    打出，中间丢文件属 Tauri 内部行为，风险极低但**不是零** —— 这是本门当前的射程边界。
 *
 * ⚠️ 旧注（保留作教训）：此处曾写「未在本机实证：本机是 Linux，
 *    上面那份 CLI 二进制里 macOS bundler 被 cfg 掉，没有对应字符串，也跑不了真 mac build。
 *    它是 **fail-closed 假设**——布局若与此不符，该步是**转红**（目录不存在 / 扫不到内核），
 *    不会假绿；首次 mac CI 跑一次即可证实或证伪。
 */
const BUNDLE_TREES = {
  linux: ['deb', 'appimage'],
  'macos-arm64': ['macos'],
  'macos-x64': ['macos'],
  windows: [], // 空 = 无 bundle 侧副本可扫 ⇒ 退化为 staging 检查（见上方 nsis 实证）
};

function checkPayload(label, root) {
  // 本模式自己的错误计数起点：末尾两句 note 只能在**本模式**没报错时打。
  // 此前无条件打印 ⇒ 变异 D/E（某个 bundle target 缺失）的输出里
  // `ok: payload：…（deb 比字节，appimage 比 ELF Build ID…）`
  // 与紧随的 `FAILED` 并存 —— exit code 仍 1，门没坏，但 CI 日志里出现一句**字面为假**的断言。
  const errorsBefore = errors.length;
  const expected = LABEL_TO_CORE[label];
  if (!expected) {
    fail(`未知 label '${label}'，合法值：${Object.keys(LABEL_TO_CORE).join(', ')}`);
    return;
  }
  const trees = BUNDLE_TREES[label];
  if (!trees) {
    fail(`label '${label}' 未登记 BUNDLE_TREES —— 新增平台必须同时声明它的 bundle 产物目录`);
    return;
  }
  const rootDir = resolve(ROOT, root);
  if (!existsSync(rootDir)) {
    fail(
      `产物根不存在：${rootDir} —— payload 模式必须在构建之后跑。\n` +
        `  仓库根是 cargo workspace 根，产物不在 src-tauri/target/；` +
        `且本模式的 --root 要指向 **bundle 根**（target/release/bundle，传了 --target 时 target/<triple>/release/bundle）。`
    );
    return;
  }
  if (!statSync(rootDir).isDirectory()) {
    fail(`产物根不是目录：${rootDir}`);
    return;
  }

  // bundler 把 `../resources/x` 铺成 `_up_/resources/x`（tauri-utils::resource_relpath：ParentDir → `_up_`）。
  // 但**不把 `_up_` 写死进判据**：各平台 bundler 的中间 staging 目录布局未逐一实证过，写死会在
  // 布局不同的平台上假红。判据放宽为「路径里出现 `/resources/<manifest 里的平台名>/` 的 sing-box」——
  // 源码树的 resources/ 不在 bundle/ 下，不会被误判。日志里回打实际布局，布局变了肉眼可见。
  const platforms = Object.keys(
    readJson(join(SRC_TAURI, 'core-manifest.json'), '平台目录集合无真值来源 ⇒ payload 模式无从判定产物里的内核属于哪个平台')
      .coreArchiveSha256 ?? {}
  );
  const srcDir = join(ROOT, 'resources', expected);
  if (!existsSync(srcDir)) {
    // 前置缺失一律判红。此前体积断言被 `existsSync(src)` 包着 ⇒ 源不在就静默跳过，
    // 变异 P5（产物是 2 字节残包 + 源缺失）exit 0 —— 门自身前置缺失时静默跳步 = 没门。
    fail(`源内核目录不存在：${srcDir} —— 体积断言无从比对（前置缺失判红，不跳过）`);
  }

  // 断言口径：**每个 bundle target 各自命中**。少一个形态（deb 在、AppImage 掉了）也要红。
  const scopes =
    trees.length > 0
      ? trees.map((t) => ({ name: `bundle/${t}`, dir: join(rootDir, t), artifact: true }))
      : [{ name: root, dir: rootDir, artifact: false }];
  const payloadFamilies = PAYLOAD_FAMILIES.filter(
    (family) => !family.requiredLabels || family.requiredLabels.has(label)
  );

  for (const scope of scopes) {
    if (!existsSync(scope.dir)) {
      fail(
        `产物目录不存在：${scope.dir}\n` +
          `  期望它是 ${scope.name}（bundler 为 ${label} 铺出的产物树）。\n` +
          `  常见原因：① bundler 没产出该形态；② --root 指的不是 bundle 根` +
          `（应为 target/release/bundle 或 target/<triple>/release/bundle，不是 target/release）。`
      );
      continue;
    }

    for (const family of payloadFamilies) {
      const all = walk(scope.dir, family.names);
      const seen = new Map();
      for (const p of all) {
        // 取**最后**一处 `<...>/resources/<平台>/`：路径里可能先出现 resources/dashboard/ 之类的
        // 非平台段，用首个匹配会误判成「不是平台核」而漏掉。
        const segs = p.replace(/\\/g, '/').split('/');
        let core = null;
        for (let i = 0; i < segs.length - 1; i++) {
          if (segs[i] === 'resources' && platforms.includes(segs[i + 1])) core = segs[i + 1];
        }
        if (!core) continue;
        if (!seen.has(core)) seen.set(core, []);
        seen.get(core).push(p);
      }

      const hits = [...seen.values()].flat();
      if (hits.length === 0) {
        fail(
          `${scope.name} 里找不到任何 \`resources/<平台>/${family.what}*\` —— ` +
            `${scope.artifact ? `该产物装出来没有 ${family.what}` : `本平台 staging 里没有 ${family.what}`}` +
            `（${family.consequence}）。\n` +
            `  已扫描：${scope.dir}\n` +
            `  期望平台目录：${expected}（合法平台：${platforms.join(', ')}）\n` +
            `  该目录下找到的 ${family.what} 文件：${JSON.stringify(all.slice(0, 20))}\n` +
            `  实际布局样本（前 40 条，标注类型与软链）：\n${layoutSample(scope.dir)}`
        );
        continue;
      }

      const dirs = [...seen.keys()].sort();
      if (dirs.length !== 1 || dirs[0] !== expected) {
        fail(
          `${scope.name} 的 ${family.what} 平台应恰为 ['${expected}']，实为 ${JSON.stringify(dirs)} —— ` +
            `混进了别平台产物（§10.2 死重回潮）或缺本平台那份`
        );
      }

      // 完整性断言不用魔数：与源 resources/<平台>/ 里那份**先比体积**。源缺失 = 判红，不跳过。
      // ⚠️ 体积不等 ≠ 坏包（PKG-1，复审 F1 修正为 B 案）：appimage 腿的**动态链接 ELF** 会被
      // linuxdeploy 合法改写 rpath（本机 1-alpha-20251107-1 实测：helper 1222440B → 1230912B，
      // sha 变，**GNU Build ID 前后同值**）。故体积失配时，appimage 侧用 Build ID 作「合法改写」
      // 的豁免证据（同 ⇒ 绿）；任一侧读不出 Build ID 或不同 ⇒ 红。**不把 Build ID 当普适判据**：
      // 真内核 sing-box 是 Go 剥离产物，整个 ELF 无 note 段（readelf -n 输出为空、非失败）——
      // 它在 appimage 里体积与源一致（run 32063794443：只有 helper 失配），走体积分支即绿；
      // 若哪天它也开始失配且无 Build ID 可证 ⇒ 红（fail-loud，来龙去脉当场可查）。
      // deb / staging / mac 腿：tauri-bundler 是纯 fs::copy（fs_utils.rs），恒比体积。
      for (const p of seen.get(expected) ?? []) {
        const src = join(srcDir, basename(p));
        if (!existsSync(src)) {
          fail(`${scope.name}: 产物里有 ${p}，但源 ${src} 不存在 —— 完整性无从比对（前置缺失判红，不跳过）`);
          continue;
        }
        const got = statSync(p).size;
        const want = statSync(src).size;
        if (got === want) continue;
        if (scope.name === 'bundle/appimage' && isElf(p) && isElf(src)) {
          const gid = elfBuildId(p);
          const wid = elfBuildId(src);
          if (gid !== null && wid !== null && gid === wid) continue; // 合法 rpath 改写的豁免
          fail(
            `${scope.name}: 产物 ${family.what} 体积不符（${p} = ${got}B，源 ${src} = ${want}B）且` +
              ` Build ID 无法证明其为 linuxdeploy 的合法 rpath 改写（产物 ${gid ?? '无 note 段/读取失败'}，` +
              `源 ${wid ?? '无 note 段/读取失败'}）—— 装进去的可能不是同一次构建的产物`
          );
        } else {
          fail(`${scope.name}: 产物 ${family.what} 体积不符：${p} = ${got}B，源 ${src} = ${want}B`);
        }
      }

      for (const p of hits) console.log(`     ${p.replace(ROOT + '/', '')}`);
    }
  }

  if (label === 'linux') checkLinuxAppImageRuntime(rootDir);

  if (errors.length !== errorsBefore) return; // 有违反就不打「成立」的 note

  if (trees.length > 0) {
    note(
      `payload：${label} → 产物验证，${scopes.map((s) => s.name).join(' + ')} 各自命中 ${expected} 的 ` +
        `${payloadFamilies.map((f) => f.what).join(' + ')}（体积与源一致；appimage 内被 linuxdeploy 改写 rpath 的 ELF 以 Build ID 豁免）`
    );
  } else {
    // 如实标注，不冒充产物验证：NSIS 把资源从**源路径**直接编进 .exe，bundle 侧没有可扫的副本，
    // 故这条腿只能证明「cargo 侧 staging 恰好只有本平台那几份且体积对」，证明不了安装器内容。
    note(
      `payload：${label} → **staging 检查**（不是产物验证）：扫的是 cargo build 铺的 ${root}/_up_/resources/，` +
        `恰含 ${expected} 的 ${payloadFamilies.map((f) => f.what).join(' + ')} 且体积与源一致。` +
        `NSIS 从源路径直接编译资源进 .exe，bundle 侧无副本可扫 ⇒ ` +
        `「安装器内容是否含这些二进制」在本仓无自动门，由 Windows 真机安装验证覆盖。`
    );
  }
}

/**
 * Linux AppImage 运行时契约：不仅「包里有 payload」，还要保证新宿主图形栈可启动，且 payload 位于
 * `usr/bin/polaris` 的共享解析函数实际会尝试的 FHS/Tauri 路径。
 */
function checkLinuxAppImageRuntime(rootDir) {
  const appimageDir = join(rootDir, 'appimage');
  if (!existsSync(appimageDir)) return;
  const appDirs = readdirSync(appimageDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && entry.name.endsWith('.AppDir'))
    .map((entry) => join(appimageDir, entry.name));
  if (appDirs.length !== 1) {
    fail(`bundle/appimage 中应恰有 1 个 .AppDir，实为 ${appDirs.length} 个：${JSON.stringify(appDirs)}`);
    return;
  }
  for (const violation of appImageRuntimeViolations(appDirs[0])) {
    fail(`bundle/appimage host graphics 契约：${violation}`);
  }

  const base = readJson(join(SRC_TAURI, 'tauri.conf.json'), 'Linux AppImage FHS 资源路径无从取得 productName');
  const product = base.productName;
  if (typeof product !== 'string' || product.length === 0) {
    fail('tauri.conf.json productName 缺失，Linux AppImage FHS 资源路径无从判定');
    return;
  }
  const resources = join(appDirs[0], 'usr', 'lib', product, '_up_', 'resources');
  for (const relativePath of [
    join('linux', 'sing-box'),
    join('linux', 'polaris-helper'),
    join('data'),
    join('dashboard', 'index.html'),
  ]) {
    const path = join(resources, relativePath);
    if (!existsSync(path)) {
      fail(`bundle/appimage FHS 运行时资源缺失：${path}（包内扫描命中别处也不能证明运行期解析得到）`);
    }
  }

  const sourceDataDir = join(ROOT, 'resources', 'data');
  const bundledDataDir = join(resources, 'data');
  if (existsSync(bundledDataDir)) {
    const sourceRuleSets = readdirSync(sourceDataDir).filter((name) => name.endsWith('.srs'));
    for (const name of sourceRuleSets) {
      if (!existsSync(join(bundledDataDir, name))) {
        fail(`bundle/appimage FHS 规则集缺失：${join(bundledDataDir, name)}`);
      }
    }
  }
}

// ───────────────────────── 模式 3：产物命名 ↔ updater 选包契约 ─────────────────────────
/**
 * 与 `crates/updater/src/github.rs::find_suitable_update_asset` 同口径（**大小写敏感**）。
 *
 * Windows 侧那个函数按形态分两条**互不相交**的规则，故这里也是两个函数，别只镜像一半：
 *  - [`updaterWindowsCandidates`] ← installed 形态（`.exe` 且名含 `win`）；
 *  - [`updaterPortableCandidates`] ← loose 形态（`polaris-portable-` 前缀 + `.zip`）。
 *
 * 只镜像 installed 那条正是本轮修掉的缺陷得以长期存活的原因之一：便携形态在 release 里
 * 有没有可选的产物，此前**没有任何断言按 updater 的口径**去问。
 */
function updaterWindowsCandidates(names) {
  return names.filter((n) => n.endsWith('.exe') && n.includes('win'));
}
/** loose（便携）形态的候选集 = `github.rs` 的 `PORTABLE_ZIP_PREFIX` + `.zip`，逐字同口径。 */
function updaterPortableCandidates(names) {
  return names.filter((n) => n.startsWith('polaris-portable-') && n.endsWith('.zip'));
}
function updaterMacCandidates(names, archTag) {
  return names.filter((n) => n.includes(archTag) && n.endsWith('.dmg'));
}
/**
 * Linux 两形态的候选集 = `github.rs` 的 Linux 分支（`app_image.first()` / `deb.first()`），逐字同口径。
 *
 * 抽成函数而不是内联过滤：内联过的地方有**四处**（per-job 体积门、release 体积门、release 命名断言、
 * per-job `linux` 命名分支的 deb / AppImage 两条），与 mac/win 靠共享函数自动跟随选包规则不同，
 * 内联的那几处会在 `github.rs` 判据变化时**静默滞后**。
 * @param {string[]} names @param {'.deb'|'.AppImage'} [ext] 只要某一形态时传，缺省两形态都算
 */
function updaterLinuxCandidates(names, ext) {
  return names.filter((n) => (ext ? n.endsWith(ext) : n.endsWith('.deb') || n.endsWith('.AppImage')));
}

// ───────────── U2：updater 目标资产的体积门 ─────────────
/**
 * updater **真正会下载**的那个资产的体积上限。超过即红。
 *
 * # 为什么它不等于客户端的 `APP_UPDATE_MAX_BYTES`（512 MiB）
 *
 * 那个常量是客户端的**绝对写入闸**（`src-tauri/src/commands/updater/app_update.rs`），职责是「别让一个撒谎的
 * 服务端把用户的盘写满」，故留了一个数量级以上的余量。拿它当发布门等于**没有门**：安装包从
 * 52 MiB 涨到 300 MiB 照样全绿，而这道门的全部理由是「体积再涨在发布时自曝」——U1 那个缺陷
 * （产物 52 MiB 撞上 16 MiB 下载闸、构建 CI 一路绿、只有用户真机更新失败才暴露）正是这么长出来的。
 * 早警值必须**贴着真实量级**设，不是贴着灾难值设。
 *
 * # 200 MiB 是怎么定出来的（实测，非拍脑袋；2026-08-18 二次定标）
 *
 * 本机留存的真实 CI 产物逐个 `stat`（updater 目标资产口径）：
 *
 * | 资产 | 字节 | MiB | 出处 |
 * |---|---|---|---|
 * | `*_amd64.AppImage` | 128,530,936 | 122.58 | run 32109475236（PKG-1 收据 run，linux 全量打包**首次真跑**） |
 * | `*-mac-arm64.dmg` | 54,232,313（12 份留存里的最大值） | 51.72 | 本地 `/tmp/polaris-mac*` CI 产物 |
 * | `*-mac-x64.dmg`   | 51,102,510 | 48.73 | run 30990315709（记录在 vault `~/docs/polaris/design/polaris-windows-packaging-first-green-2026-08-05.md`，**不在本仓**） |
 * | `*-win-setup.exe` | 39,015,611 | 37.21 | run 31659532293 |
 * | `polaris-portable-*.zip` | 53,347,731 | 50.88 | run 31659532293 |
 * | `*_amd64.deb`     | —（字节未记录） | 53.42 | run 32109475236 |
 *
 * 取 **200 MiB ≈ 实测最大值（122.58 MiB，linux AppImage）的 1.63 倍**：
 *  - 常规增长（内核/cronet/dashboard 版本迭代，每次几 MiB）撞不到，不会假红；
 *  - 已知的两类**阶跃式**回潮仍落在门外：四平台内核死重（§10.2，约 210 MiB）、
 *    误把 WebView2 Runtime 打进安装包（历史实测负载会令主包达到约 277 MiB）；
 *  - 比客户端绝对闸早 2.56 倍触发 —— 它才是「早警」的那一份。
 *
 * # 二次定标纪要（2026-08-18；首轮数据不是陈旧噪声，是缺口被实测关闭的记录）
 *
 * 首轮定标取 96 MiB ≈ 51.72（mac dmg）× 1.86，当时 linux 两形态**无实测**，按「与 win/mac
 * 同一份 payload、量级同族」推断留的近一倍余量，并如实登记为判据缺口。run 32109475236 首次
 * 真跑 linux 全量打包：AppImage 实测 122.58 MiB 撞门 ⇒ 推断错了——**AppImage 内含 linuxdeploy
 * 拖入的 GTK/webkit 运行库，deb 走系统依赖不拖，两者体积本就差一倍量级**。缺口由实测关闭，
 * 门随之抬到新实测最大值的 1.63 倍。
 * AppImage 必须留在 updater 射程里（deb 只覆盖 dpkg 系，其余发行版用户的自动更新只有这一条腿）
 * ⇒ 解法是抬门，不是把 AppImage 踢出 updater 资产（2026-08-18 拍板）。
 * 代价如实登记：mac/win 腿的检测余量从 1.86 倍放宽到 3.86 倍，那两条腿上「多打进一份
 * ~60 MiB 级死资源」的失误本门不再抓，只能靠 payload 门（单文件口径）兜大头。
 * 真红时先看输出里印的实际字节数再决定是「产物真涨了」还是「门定紧了」，别直接调门。
 *
 * # 改这个值 = 改两处
 *
 * 另一份在 `src-tauri/src/commands/updater/tests/mod.rs`（`PACKAGING_MAX_UPDATE_ASSET_MIB`），
 * 由 `packaging_size_gate_is_mirrored_and_stays_under_the_client_write_gate` **从本文件源码里解析出
 * 这个数值再比数**（不是比文本），两份漂开即转红（D5：维护两份 + 一条一致性测试钉死）。
 * **改这里必须同步改那里**，且那条测试还会拦住「把它调到客户端写入闸之上」——那等于发一个
 * 客户端结构性下不动的包。
 *
 * ⚠️ 那条测试按「`const` + 本常量名 + ` = `」定位，要求**以它开头的行恰有一行**，且该行形态恒为
 * `N * 1024 * 1024;`（允许行首缩进与 `export `）。声明写两遍、把它折成两行、或换成裸字面量，
 * 一律判成「判据取不到」而转红 —— 因为「读到了对的那一行」与「读到了别处一句同形文本」在结果上
 * 无从分辨。注释里出现同形文本**不影响**判据（它不以 marker 起头），故本段可以照常引用它。
 */
const MAX_UPDATE_ASSET_BYTES = 200 * 1024 * 1024;

/** 随 release 一起发布的摘要清单（U3）。名字是**资产名**，不是路径。 */
const SHA256SUMS_NAME = 'SHA256SUMS';

const mib = (n) => `${(n / 1024 / 1024).toFixed(2)} MiB`;

/**
 * 定阈值时实测到的**最大** updater 目标资产（linux AppImage，128,530,936 B，run 32109475236；
 * 2026-08-18 二次定标时由 mac-arm64 dmg 的 54,232,313 换成这个新高）。
 *
 * 只用于失败文案：光看「201 MiB > 200 MiB」判不出这是常规漂移还是阶跃回潮，得有个基线才判得了
 * 「涨了多少倍」。它不参与任何断言 —— 参与断言就等于把一个会过期的历史值变成第三份需要维护的常量。
 */
const MEASURED_MAX_UPDATE_ASSET_BYTES = 128_530_936;

/**
 * 本 label 下 **updater 会真正命中**的资产名 —— 体积门的射程恰好是这些。
 *
 * 判据一律**复用**上面那四个候选函数（与 `github.rs::find_suitable_update_asset` 同口径），
 * 本函数只负责「哪个 label 该看哪几条规则」的装配，不另写一套过滤条件：选包规则一改，
 * 这里跟着改，不会出现「命名门还在绿、体积门量错了对象」。
 *
 * - `windows` 腿装配 installed + loose 两形态：便携 zip 自 2026-08-17 起打进 `dist-win/`
 *   （此前打在仓库根，本 job 量不到它，只有 tag 时的聚合口径量得到 —— 超限要等四条腿的构建
 *   成本全付完才发现）。射程里有它就必须有人保证它在场，故 windows 分支同时断言它恰有一个，
 *   否则体积门会变成一条恒为空的断言。
 * - `linux` 腿两形态都算：per-job 口径只断言「各至少一个」，故这里也不假设恰好一个。
 */
function updaterTargetNames(label, names) {
  switch (label) {
    case 'windows':
      return [...updaterWindowsCandidates(names), ...updaterPortableCandidates(names)];
    case 'macos-arm64':
    case 'macos-x64':
      return updaterMacCandidates(names, LABEL_TO_CORE[label]);
    case 'linux':
      return updaterLinuxCandidates(names);
    case 'release':
      return [
        ...updaterMacCandidates(names, 'mac-arm64'),
        ...updaterMacCandidates(names, 'mac-x64'),
        ...updaterWindowsCandidates(names),
        ...updaterPortableCandidates(names),
        ...updaterLinuxCandidates(names),
      ];
    default:
      return [];
  }
}

/**
 * 体积门本体。**逐个印出实际体积**（不只在超限时印）：这道门将来要不要调、调到哪，
 * 唯一的依据就是历次 CI 日志里的这些数 —— 只在红的时候才印，等于把定阈值的数据丢了。
 */
function checkUpdateAssetSizes(label, targets, pathOf) {
  for (const name of targets) {
    const p = pathOf(name);
    if (!p) continue; // 命名门已经在报这一条了，这里不重复报。
    const size = statSync(p).size;
    if (size > MAX_UPDATE_ASSET_BYTES) {
      fail(
        `体积门（U2）：updater 目标资产 '${name}' 为 ${mib(size)}（${size} B），超过上限 ${mib(MAX_UPDATE_ASSET_BYTES)}。\n` +
          `  定门时的实测基线是 ${mib(MEASURED_MAX_UPDATE_ASSET_BYTES)}（linux AppImage），本次相当于它的 ` +
          `${(size / MEASURED_MAX_UPDATE_ASSET_BYTES).toFixed(2)} 倍 —— 先据此判是常规漂移还是阶跃回潮。\n` +
          `  这道门是**早警**，不是客户端能力上限：客户端绝对写入闸是 512 MiB，走到那儿才炸就等于没警。\n` +
          `  先判定是「产物真的涨了」（查 payload：内核 / cronet / dashboard / 是否误把 WebView2 Runtime 打进主包）\n` +
          `  还是「上限定紧了」；确属预期增长再同步改两处常量（本文件 MAX_UPDATE_ASSET_BYTES +\n` +
          `  src-tauri/src/commands/updater/tests/mod.rs 的 PACKAGING_MAX_UPDATE_ASSET_MIB），否则一致性测试会红。`
      );
    } else {
      note(`体积：${label} → '${name}' ${mib(size)} ≤ 上限 ${mib(MAX_UPDATE_ASSET_BYTES)}`);
    }
  }
}

// ───────────── U3：随包 SHA256SUMS ─────────────
/**
 * `SHA256SUMS` 门：缺失 / 格式坏 / 覆盖面对不上 / 逐条摘要不符，任一即红。
 *
 * # 它守的是什么（别夸大）
 *
 * 守的是**发布流程**：生成步骤压根没跑、跑了但漏了某个平台的资产、或者清单与真实产物对不上。
 * 缺了这道门，「发布带摘要」就只是 workflow 里一句无人核对的 shell —— 而一个静默不产出的
 * 生成步骤，与产出正确的生成步骤，在 CI 日志里长得一模一样。
 *
 * 它**不是**安全边界：`SHA256SUMS` 与安装包走同一 HTTPS 通道、同一 release、同一发布账号，
 * 能替换安装包的人同样能替换它。它防的是**传输损坏与截断**，不防「GitHub 账号或 TLS 被攻破」。
 * 端到端完整性需要签名（公钥内置于应用），那是独立决策，本轮不做，也不假装 SHA 等价于它。
 *
 * # 起点是 `dist-release`，不是构建产出（如实登记的射程边界）
 *
 * 清单是在 `download-artifact` **之后**、拿 `dist-release` 里的字节算的，故它证明的传输完整性
 * 覆盖的是 **dist-release → 用户**那一段。**build job → actions artifact → dist-release 这一跳
 * 没有任何摘要判据**：那一跳若坏了字节，清单会忠实地把坏字节的摘要写下来，两道门全绿。
 * 补它要让每条腿各产局部清单、聚合侧再合并校验 —— 判定收益不抵那份复杂度，故不做，只登记。
 * （那一跳并非全无判据：命名门、payload 门、便携 zip 开箱验各自还在，只是都不看字节摘要。）
 *
 * # 判据不是「文件在不在」
 *
 * 逐条**重算** sha256 与清单比对，并要求清单与实际资产**双向**覆盖（少一条 = 有资产没被摘要，
 * 多一条 = 摘要指向一个不存在的资产）。只查在场的话，一个空文件、或者上一轮遗留的旧清单，
 * 照样能让门全绿。
 */
function checkSha256Sums(names, pathOf, namesOnly) {
  if (!names.includes(SHA256SUMS_NAME)) {
    fail(
      `摘要门（U3）：release 资产里缺 \`${SHA256SUMS_NAME}\` —— 发布流程的生成步骤没跑或产物没被上传。\n` +
        `  缺了它，「随包发布摘要」这条承诺在真实 release 上不成立（消费侧将来要不要接是另一回事）。`
    );
    return;
  }
  if (namesOnly) {
    note(`摘要：${SHA256SUMS_NAME} 在场（--names-only：内容比对不可判定，见文件头）`);
    return;
  }
  // 同名 basename 的保护已提到 [`checkAssets`] 里对**所有 label** 无条件跑（它与摘要无关，
  // 体积门同样是按名字回查路径的）。本函数依赖那条闸已经跑过：`names` 无重复 ⇒ 下面的
  // `listed` 与资产名之间是一一对应。
  const text = readFileSync(pathOf(SHA256SUMS_NAME), 'utf8');
  const listed = new Map();
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim() === '') continue;
    // `sha256sum` 的两种输出形态：文本模式两个空格、二进制模式 ` *`。两者都收。
    const m = /^([0-9a-f]{64}) [ *](.+)$/.exec(line);
    if (!m) {
      fail(`摘要门（U3）：${SHA256SUMS_NAME} 第 ${i + 1} 行不是 sha256sum 格式：${JSON.stringify(line)}`);
      return;
    }
    if (listed.has(m[2])) {
      fail(`摘要门（U3）：${SHA256SUMS_NAME} 里 '${m[2]}' 有重复条目 —— 取哪条不确定`);
      return;
    }
    listed.set(m[2], m[1]);
  }

  const assets = names.filter((n) => n !== SHA256SUMS_NAME);
  const missing = assets.filter((n) => !listed.has(n));
  const extra = [...listed.keys()].filter((n) => !assets.includes(n));
  if (missing.length > 0) {
    fail(
      `摘要门（U3）：${SHA256SUMS_NAME} 漏了 ${missing.length} 个资产 ${JSON.stringify(missing)}。\n` +
        `  漏掉的那个资产等于没随包发摘要 —— 生成步骤的过滤条件与实际产物集对不上。`
    );
  }
  if (extra.length > 0) {
    fail(
      `摘要门（U3）：${SHA256SUMS_NAME} 里有 ${extra.length} 条指向不存在的资产 ${JSON.stringify(extra)}。\n` +
        `  多半是上一轮的残留清单被当成本轮产物 —— 它会让「摘要齐了」这件事变成假的。`
    );
  }

  let checked = 0;
  for (const [name, want] of listed) {
    const p = pathOf(name);
    if (!p) continue; // 已由上面的 extra 报了。
    const got = createHash('sha256').update(readFileSync(p)).digest('hex');
    if (got !== want) {
      fail(
        `摘要门（U3）：'${name}' 的实际 sha256 与 ${SHA256SUMS_NAME} 不符。\n` +
          `  清单：${want}\n  实际：${got}\n` +
          `  清单是在产物落定**之后**生成的，对不上意味着两者之间还有一步在改产物（改名 / 重打 / 覆盖）。`
      );
    } else {
      checked++;
    }
  }
  if (missing.length === 0 && extra.length === 0 && checked === assets.length) {
    note(`摘要：${SHA256SUMS_NAME} 覆盖全部 ${checked} 个资产且逐条重算相符`);
  }
}

function checkAssets(label, dir, namesOnly = false) {
  const abs = resolve(ROOT, dir);
  if (!existsSync(abs)) {
    fail(`assets 模式：目录不存在 ${abs}`);
    return;
  }
  // --dir 指向文件时 readdirSync 会抛 ENOTDIR 裸栈（失败方向没错，但读不出所以然）。
  if (!statSync(abs).isDirectory()) {
    fail(`assets 模式：--dir 指向的不是目录：${abs}`);
    return;
  }
  // 命名契约按**文件名**判，体积/摘要两道内容门要按**路径**读 —— 故收全路径再投影出名字，
  // 而不是像原来那样只收名字（dist-release 下平铺与嵌套并存，名字回不去路径）。
  const paths = walk2(abs);
  const names = paths.map((p) => basename(p));
  const pathOf = (n) => paths.find((p) => basename(p) === n);
  if (names.length === 0) {
    fail(`assets 模式：${abs} 下没有任何文件`);
    return;
  }
  // 同名 basename ⇒ **不可判定**，判红（`pathOf` 取首个匹配，挑哪一份取决于遍历顺序）。
  //
  // 🔴 射程是**按名字被回查的那些文件**，不是目录下的全部文件。后者会在 linux 腿必然假红：
  //    该腿扫的 `target/release/bundle` 里有 bundler 留下的两棵 staging 树
  //    （`deb/<pkg>/data/…` 与 `appimage/<pkg>.AppDir/…`，见 [`BUNDLE_TREES`] 文档的实证），
  //    同一份资源在两棵树里各有一份 ⇒ 同名 basename 成片出现，而那与资产选取毫无关系。
  //
  // 故分两处按各自射程判：
  //   - **全 label**：updater 目标名（体积门就是拿这些名字回查路径的）。复审实测的形态正是这个 ——
  //     同名的两个 `*-win-setup.exe` 让体积门把同一份量了两遍，另一份 2 KB 的从未被 stat；
  //   - **仅 release**：全部资产名（摘要清单按名查表，且 release 侧是平铺的，本就不该有同名）。
  const dupesOf = (list) => [...new Set(list.filter((n, i) => list.indexOf(n) !== i))];
  const targets = updaterTargetNames(label, names);
  const dupeTargets = dupesOf(targets);
  if (dupeTargets.length > 0) {
    fail(
      `assets 模式：updater 目标资产出现同名 ${JSON.stringify(dupeTargets)}（分处不同子目录）。\n` +
        `  体积门按名字回查路径、取首个命中 ⇒ 量到的是哪一份取决于目录遍历顺序：\n` +
        `  一个 2 KB 的壳与一个真产物同名时，门可能量的正是那个壳而全绿。不可判定即红，不挑一个继续。`
    );
    return;
  }
  if (label === 'release') {
    const dupeAssets = dupesOf(names);
    if (dupeAssets.length > 0) {
      fail(
        `release 契约：出现同名资产 ${JSON.stringify(dupeAssets)} —— release 侧是平铺的（GitHub 只认名字），\n` +
          `  且摘要清单按资产名查表，同名即不可判定。`
      );
      return;
    }
  }

  if (label === 'windows') {
    const cands = updaterWindowsCandidates(names);
    if (cands.length !== 1) {
      fail(
        `Windows updater 契约：应恰有 1 个「.exe 且名含 win」的产物，实为 ${cands.length} 个 ${JSON.stringify(cands)}。\n` +
          `  0 个 ⇒ find_suitable_update_asset 恒返回 None，用户永远收不到更新且静默；\n` +
          `  >1 个 ⇒ 选哪个取决于 release 资产顺序，不确定。\n` +
          `  全部产物：${JSON.stringify(names)}`
      );
    } else if (!cands[0].includes('setup')) {
      fail(`Windows updater 契约：唯一候选 '${cands[0]}' 不含 'setup'，安装态用户会被判成非安装器产物`);
    } else {
      note(`assets：windows → updater 唯一命中 '${cands[0]}'`);
    }
    // loose（便携）形态：自 2026-08-17 起 zip 也打进 dist-win/，故本 job 就该断言它恰有一个。
    //
    // 这条不是可有可无的重复：便携 zip 进了 [`updaterTargetNames`] 的 windows 射程，而射程里
    // **没有**这个文件时，体积门只是「什么都没量」——一条恒为空的断言。有了本条，zip 被挪回
    // 仓库根（或打包步失败）会当场红，而不是让体积门静默空转到 tag 时才由聚合口径发现。
    const portable = updaterPortableCandidates(names);
    if (portable.length !== 1) {
      fail(
        `Windows updater 契约：dist-win/ 下 \`polaris-portable-*.zip\`（loose 形态唯一候选）应恰有 1 个，` +
          `实为 ${portable.length} 个 ${JSON.stringify(portable)}。\n` +
          `  0 个 ⇒ 便携产物没进本 job 的资产目录（多半是被打回仓库根）⇒ 本腿的体积门空转；\n` +
          `  >1 个 ⇒ updater 取首个命中，选谁取决于 release 资产顺序。\n` +
          `  全部产物：${JSON.stringify(names)}`
      );
    }
  } else if (label === 'macos-arm64' || label === 'macos-x64') {
    const mine = LABEL_TO_CORE[label]; // mac-arm64 / mac-x64
    const other = mine === 'mac-arm64' ? 'mac-x64' : 'mac-arm64';
    const cands = updaterMacCandidates(names, mine);
    if (cands.length !== 1) {
      fail(
        `macOS updater 契约：应恰有 1 个名含 '${mine}' 的 .dmg，实为 ${cands.length} 个 ${JSON.stringify(cands)}。\n` +
          `  0 个 ⇒ find_suitable_update_asset 对该架构恒返回 None，该架构用户永远收不到更新且静默\n` +
          `        （2026-07-21 起已取消「任意 .dmg」回落：宁可不更新，也不发错架构包）。\n` +
          `  >1 个 ⇒ 选哪个取决于 release 资产顺序，不确定。\n` +
          `  全部产物：${JSON.stringify(names)}`
      );
    }
    const wrong = updaterMacCandidates(names, other);
    if (wrong.length !== 0) {
      fail(`macOS updater 契约：本 job 不应产出名含 '${other}' 的 dmg，实为 ${JSON.stringify(wrong)}`);
    }
    if (cands.length === 1 && wrong.length === 0) note(`assets：${label} → updater 唯一命中 '${cands[0]}'`);
  } else if (label === 'release') {
    // 本分支自己的错误计数起点：末尾那句 note 只能在**本分支**没报错时打。
    // 读模块全局 `errors.length === 0` 今天碰巧对（release 是最后一项），
    // 一旦有别的检查排在它前面就静默失效。
    const errorsBefore = errors.length;
    // 聚合口径：四个 job 的产物汇到**同一个 release** 之后跑。
    // 与 per-job 口径的区别：per-job 断言「本 job 不得产出另一架构」，聚合侧两架构本就都在，
    // 故这里改断言「每个架构**恰好一个**」——少一个 = 该架构用户静默收不到更新
    // （github.rs 已取消跨架构回落），多一个 = updater 取首个命中，选谁看资产顺序。
    for (const archTag of ['mac-arm64', 'mac-x64']) {
      const cands = updaterMacCandidates(names, archTag);
      if (cands.length !== 1) {
        fail(
          `release 契约：名含 '${archTag}' 的 .dmg 应恰有 1 个，实为 ${cands.length} 个 ${JSON.stringify(cands)}。\n` +
            `  0 个 ⇒ 该架构用户 find_suitable_update_asset 恒 None，永远收不到更新且静默；\n` +
            `  >1 个 ⇒ updater 取首个命中，选谁取决于 release 资产顺序。`
        );
      }
    }
    const win = updaterWindowsCandidates(names);
    if (win.length !== 1) {
      fail(
        `release 契约：「.exe 且名含 win」应恰有 1 个，实为 ${win.length} 个 ${JSON.stringify(win)}。\n` +
          `  0 个 ⇒ Windows 安装态选不到更新；>1 个 ⇒ updater 取首个命中，选谁取决于资产顺序。`
      );
    } else if (!win[0].includes('setup')) {
      fail(`release 契约：唯一 win 候选 '${win[0]}' 不含 'setup'，安装态用户会被判成非安装器产物`);
    }
    // Linux 两形态各自可选包（loose→AppImage / installed→deb），口径与 dmg / win setup 一致：**恰好一个**。
    //
    // 为什么是 ==1 而不是 >=1：`github.rs::find_suitable_update_asset` 的 Linux 分支是
    // `app_image.first()` / `deb.first()`（`crates/updater/src/github.rs:360-370`）——
    // 与 mac/win 同款「取首个命中」，>1 个时选谁**取决于 release 资产顺序**，不确定。
    // 这正是另外三类产物立 ==1 的理由，Linux 没有理由例外。且 linux 只有一条 matrix 腿、
    // 每种形态各产一个 ⇒ ==1 是真实状态，不会假红。
    for (const [ext, form] of [
      ['.deb', 'installed'],
      ['.AppImage', 'loose'],
    ]) {
      const got = updaterLinuxCandidates(names, ext);
      if (got.length !== 1) {
        fail(
          `release 契约：\`${ext}\` 应恰有 1 个，实为 ${got.length} 个 ${JSON.stringify(got)}。\n` +
            `  0 个 ⇒ Linux ${form} 形态选不到包；\n` +
            `  >1 个 ⇒ updater 取首个命中（github.rs 的 \`${ext === '.deb' ? 'deb' : 'app_image'}.first()\`），选谁取决于资产顺序。`
        );
      }
    }

    // 便携 zip 不属于 `.exe` 候选，必须按 loose 形态选包规则单独断言。
    // 口径**就是 updater 的 loose 形态选包规则**（`updaterPortableCandidates`），
    // 不再是一条只问「有没有这个文件」的独立正则。两者今天等价，但把断言挂在 updater 口径上，
    // 选包判据一改这里就跟着改，不会出现「门还在绿、选包器已经选不到它」。
    //
    // 0 个 ⇒ 便携用户 `find_suitable_update_asset` 恒 None ⇒ 如实「无更新」（不再被推安装器，
    //        但也永远更新不了）；>1 个 ⇒ updater 取首个命中，选谁取决于 release 资产顺序。
    const portable = updaterPortableCandidates(names);
    if (portable.length !== 1) {
      fail(
        `release 契约：\`polaris-portable-*.zip\`（免安装绿色版 = updater loose 形态的唯一候选）应恰有 1 个，` +
          `实为 ${portable.length} 个 ${JSON.stringify(portable)}。\n` +
          `  0 个 ⇒ 便携用户恒收不到更新（github.rs 的 Windows loose 分支无回落，返回 None）；\n` +
          `  >1 个 ⇒ updater 取首个命中，选谁取决于 release 资产顺序。`
      );
    }
    // 注：两条 Windows 规则的「互不相交」**不在此断言** —— 判据是 `.zip` 与 `.exe` 两个互斥的
    // 后缀，同一个文件名不可能同时满足，写出来的检查恒为空、永远不可能转红。
    // 不可证伪的断言比没有断言更坏（它让人以为这条被守着），故这里只留这句说明。
    // 真正会变的是「判据本身被改宽」，那由 `updaterPortableCandidates` 与 github.rs 的
    // 逐字同口径 + 两侧各自的单测覆盖。

    // `--clobber` 失效时 GitHub 给同名资产追加 `.1` 后缀（`foo.dmg` + `foo.dmg.1` 并存）。
    // 这类重复项**逃过上面所有扩展名断言**（`foo.dmg.1` 不 endsWith('.dmg')），故单独查。
    const dupes = names.filter((n) => /\.\d+$/.test(n) && names.includes(n.replace(/\.\d+$/, '')));
    if (dupes.length > 0) {
      fail(
        `release 契约：出现 \`.N\` 后缀重复资产 ${JSON.stringify(dupes)} —— \`gh release upload --clobber\` 未生效。\n` +
          `  同一产物在 release 里存在两份，updater 命中哪个取决于资产顺序。`
      );
    }

    if (errors.length === errorsBefore) {
      note(`assets：release → 四平台命名契约成立（${names.length} 个资产）`);
    }
  } else if (label === 'linux') {
    const deb = updaterLinuxCandidates(names, '.deb');
    const appimage = updaterLinuxCandidates(names, '.AppImage');
    if (deb.length === 0) fail(`Linux updater 契约：缺 .deb（installed 形态选不到包）。全部产物：${JSON.stringify(names)}`);
    if (appimage.length === 0) fail(`Linux updater 契约：缺 .AppImage（loose 形态选不到包）。全部产物：${JSON.stringify(names)}`);
    if (deb.length > 0 && appimage.length > 0) note(`assets：linux → deb ${deb.length} 个 / AppImage ${appimage.length} 个`);
  } else {
    fail(`未知 label '${label}'，合法值：${Object.keys(LABEL_TO_CORE).join(', ')}, release`);
  }

  // ── 内容门（命名门之后跑：命名不成立时「哪个是 updater 目标」本身就不确定）──
  if (namesOnly) {
    // 如实标注跳过了什么。不打这条 note 的话，发布后那一遍看起来与内容门跑过的那遍一模一样。
    note(`assets：${label} → **仅命名口径**（--names-only）：喂进来的是同名空文件，体积门与摘要内容比对不可判定，已跳过`);
  } else {
    checkUpdateAssetSizes(label, targets, pathOf);
  }
  // 摘要门只挂**聚合口径**：`SHA256SUMS` 是四个 job 的产物汇进 dist-release 之后才生成的
  // （一个 release 一份，按资产名索引），per-job 目录里结构性不存在它 —— 在那儿断言它必然恒红。
  // `--names-only` 下仍验它**在场**（那一层用空文件也判得了），只跳过内容比对。
  if (label === 'release') checkSha256Sums(names, pathOf, namesOnly);
}

/**
 * 递归收集文件**全路径**（命名契约用 `basename` 投影，内容门直接拿路径读）。
 * 无名字过滤 —— 与 [`walk`]（按名字白名单收 6 个二进制）互补，inventory 模式要的正是全枚举。
 *
 * 🔴 **深度上限必须可调**：deb 的资源根在 bundle 根下第 6 层
 * （`deb/<pkg>/data/usr/lib/<Product>/`），再进 `_up_/resources/dashboard/assets/<file>` 就是第 11 层。
 * 旧写死的 `depth > 8` 对 assets 模式够用（那几个目录都很浅），换成清点整棵资源树就会**静默截断**——
 * 而截断的方向是「少看见文件」，正是白名单门最怕的假绿。故上限提到参数位，调用方按射程显式给。
 * 默认值保持 8：既有调用方（`checkAssets`）的行为一字不变。
 *
 * 🔴 **软链必须跟进**（与 [`walk`] 同一条教训，2026-08-05 mac CI 实证）：`Dirent.isDirectory()`
 * 对指向目录的软链恒为 false ⇒ 整棵子树被跳过。macOS 的 `.app` 里资源可能是软链，
 * 而「跳过一棵子树」在白名单门下就是「白名单外的东西没被看见」。改用 `statSync`（跟随软链）判类型，
 * 断链跳过（`statSync` 抛），环路由深度上限兜住。
 */
function walk2(dir, out = [], depth = 0, maxDepth = 8) {
  if (depth > maxDepth) return out;
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, e.name);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue; // 断链：不是文件也不是目录，两个模式都无从判定
    }
    if (st.isDirectory()) walk2(full, out, depth + 1, maxDepth);
    else if (st.isFile()) out.push(full);
  }
  return out;
}

// ─────────────────── 模式 4：包内容白名单（inventory）───────────────────
/**
 * **射程声明（如实标注，不冒充「整棵 bundle 树」）**：本模式清点的是**资源载荷树** ——
 * bundler 铺 `bundle.resources` 的那一片，也就是**这类缺陷的全部逃逸面**。
 *
 * 为什么不是整棵 bundle 树：windows 腿的 `--root` 就是 `target/release`（NSIS 无 bundle 侧副本，
 * 见 [`BUNDLE_TREES`]），那棵树里 `deps/` 一个目录就上万个文件，对 cargo 的产物做白名单没有意义；
 * deb/AppImage 那边 linuxdeploy 拖进 AppDir 的宿主共享库同理（内容随 runner 镜像滚动）。
 * 而这些**都不由 `bundle.resources` 决定** —— 它只能往资源根里写。
 * 本门会打印射程外的文件数，让「射程有多大」这件事本身可见，而不是让人以为它验了整棵树。
 *
 * 两侧口径：
 *   - **资源根定位**：树里出现 `_up_/` 段的那一层就是资源根（`tauri-utils::resource_relpath`
 *     把 `../x` 铺成 `_up_/x`）。一个都定位不到 ⇒ **红**（布局漂移/根传错，不静默跳过）。
 *   - **artifact**（`BUNDLE_TREES[label]` 非空）：资源根就是包内的资源目录（mac 的
 *     `Contents/Resources/`、deb/AppDir 的 `usr/lib/<Product>/`），整层枚举。
 *   - **staging**（windows）：资源根是 `target/release` 本身、与 cargo 产物混在一起，
 *     故只枚举 `_up_/` 子树 + conf 里那些**非 `../` 条目**落位的具体文件（如 `core-manifest.json`），
 *     并在输出里标注这是 staging 检查而非产物验证。
 */

/** 把字符串转义成正则字面量（平台目录名进正则前必过）。 */
const reQuote = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * 把 tauri 的 `bundle.resources` 条目映射成**资源根相对路径**。
 * 判据同 `tauri-utils::resources::resource_relpath`：`..` → `_up_`、`.` 丢弃、其余原样。
 */
function resourceRelpath(entry) {
  return String(entry)
    .replace(/\\/g, '/')
    .split('/')
    .filter((s) => s !== '' && s !== '.')
    .map((s) => (s === '..' ? '_up_' : s))
    .join('/');
}

/**
 * 把 Rust 源里的注释与字符串字面量**原地抹成等长空白**（保留换行 ⇒ 偏移量与行号不变）。
 *
 * 扫描型判据的固定纪律：取材面先剥注释与字符串再断言。此处尤其必要 —— `build.rs` 的文档注释里
 * 就写着「正则出这个常量」并逐字提到 `EXPECTED_SRS_COUNT`，不剥就会把注释里的字样当成定义命中。
 * 抹成等长空白（而不是删除）是为了让命中偏移仍能换算回**原文**的行号，供切片自检。
 */
function blankRustCommentsAndStrings(src) {
  const out = src.split('');
  const blank = (from, to) => {
    for (let k = from; k < to; k++) if (out[k] !== '\n') out[k] = ' ';
  };
  let i = 0;
  while (i < src.length) {
    const two = src.slice(i, i + 2);
    if (two === '//') {
      let j = src.indexOf('\n', i);
      if (j < 0) j = src.length;
      blank(i, j);
      i = j;
      continue;
    }
    if (two === '/*') {
      let depth = 1;
      let j = i + 2;
      while (j < src.length && depth > 0) {
        if (src.slice(j, j + 2) === '/*') {
          depth++;
          j += 2;
        } else if (src.slice(j, j + 2) === '*/') {
          depth--;
          j += 2;
        } else j++;
      }
      blank(i, j);
      i = j;
      continue;
    }
    // 原始字符串 r"…" / r#"…"# / br"…"：闭合符随 `#` 数量变化，必须按开头那串算
    const raw = /^b?r(#*)"/.exec(src.slice(i, i + 16));
    if (raw) {
      const close = `"${raw[1]}`;
      const found = src.indexOf(close, i + raw[0].length);
      const j = found < 0 ? src.length : found + close.length;
      blank(i, j);
      i = j;
      continue;
    }
    if (src[i] === '"' || (src[i] === 'b' && src[i + 1] === '"')) {
      let j = src[i] === '"' ? i + 1 : i + 2;
      while (j < src.length) {
        if (src[j] === '\\') {
          j += 2;
          continue;
        }
        if (src[j] === '"') {
          j++;
          break;
        }
        j++;
      }
      blank(i, j);
      i = j;
      continue;
    }
    i++;
  }
  return out.join('');
}

/**
 * `.srs` 应有的份数 —— 真值取自 `src-tauri/build.rs` 的 `EXPECTED_SRS_COUNT`，**不在本文件再抄一遍**
 * （那个常量自己又被 `geo_seed::build_rs_expected_count_matches_builtin_table` 与
 * `builtin_geo_rulesets()` 对账，故这条链一路回到单一真值）。
 *
 * 断言「恰有 1 处定义」的同时**报出它在第几行、原文长什么样**：计数不等于位置 ——
 * 只数到 1 处并不能说明数到的是不是同一个东西，剥注释又是按偏移原地抹白的，
 * 偏移算错时切片自检会当场炸，而不是安静地取到一个别处的数字。
 */
function expectedSrsCount() {
  const path = join(SRC_TAURI, 'build.rs');
  let src;
  try {
    src = readFileSync(path, 'utf8');
  } catch (e) {
    throw new InputError(`读不到 ${path}（${e.code ?? e.message}）—— inventory 的 .srs 份数断言无真值来源`);
  }
  const code = blankRustCommentsAndStrings(src);
  const hits = [...code.matchAll(/const\s+EXPECTED_SRS_COUNT\s*:\s*usize\s*=\s*(\d+)\s*;/g)];
  if (hits.length !== 1) {
    throw new InputError(
      `src-tauri/build.rs: 剥掉注释与字符串后，\`EXPECTED_SRS_COUNT\` 的定义应恰有 1 处，实为 ${hits.length} 处 ` +
        `—— inventory 的 geo 份数断言无从成立（不猜一个默认值继续）`
    );
  }
  const line = src.slice(0, hits[0].index).split('\n').length;
  const slice = src.split('\n')[line - 1] ?? '';
  if (!slice.includes('EXPECTED_SRS_COUNT')) {
    throw new InputError(
      `src-tauri/build.rs: 取材切片自检失败 —— 命中偏移 ${hits[0].index}（换算为第 ${line} 行）在**原文**里读回的是 ` +
        `${JSON.stringify(slice)}，不含 EXPECTED_SRS_COUNT。剥注释的偏移映射坏了，判据不可信。`
    );
  }
  return { count: Number(hits[0][1]), where: `src-tauri/build.rs:${line}`, slice: slice.trim() };
}

/**
 * **包内容登记表**（资源根相对路径）。每条都写明「为什么它该在包里」——
 * 白名单条目不写理由，下一个人就只会往里加；写了理由，加一条就得先答一次「用户拿它干什么」。
 *
 * `min`/`max` 是**份数**约束，只在 artifact/staging 清点里生效（`--static` 时源是工作树，
 * helper 由 CI 现编现铺、内核 gitignore 不入库，份数在那儿不可判定 ⇒ 显式跳过并标注，见 [`checkInventory`]）。
 * 它挡的是白名单门的经典假绿：**空目录也满足「没有多余文件」**。
 */
function payloadAllowRules(label, coreDir, srsCount) {
  const core = reQuote(coreDir);
  const rules = [
    {
      id: 'core-manifest',
      re: /^core-manifest\.json$/,
      min: 1,
      max: 1,
      why: '随包内核的版本与 sha256 清单：resolve_core_binary 认核、换核校验、更新检查都读它，缺了运行期认不出自己带的核。',
    },
    {
      id: 'third-party-licenses',
      re: /^_up_\/THIRD-PARTY-LICENSES\.md$/,
      min: 1,
      max: 1,
      why: '随二进制分发第三方依赖许可证正文是 MIT/Apache-2.0/OFL 的分发条件，缺了是许可证违规而不是少个文件。',
    },
    {
      id: 'geo-srs',
      re: /^_up_\/resources\/data\/[^/]+\.srs$/,
      min: srsCount,
      max: srsCount,
      why: '内置 geo 规则集的出厂种子：缺了 runtime_rules_dir 种不满 → route builder fail-closed 剪掉全部 geo 规则 → 叠加回国模式即全量明文直连（真机 2026-07-20）。份数真值 = build.rs::EXPECTED_SRS_COUNT。',
    },
    {
      id: 'dashboard-entry',
      re: /^_up_\/resources\/dashboard\/index\.html$/,
      min: 1,
      max: 1,
      why: '随包 sing-box 面板入口：核以 dashboard.path 直接 serve 本地目录，缺了面板只能回落联网下载（离线不可用）。',
    },
    {
      id: 'dashboard-assets',
      re: /^_up_\/resources\/dashboard\/assets\/[^/]+$/,
      min: 1,
      max: Infinity,
      why: '面板的 vite 内容哈希产物（JS/CSS/字体），index.html 逐个 <script>/<link> 引用。名字随上游 gh-pages 滚动，故按目录登记而不逐条钉死。',
    },
    {
      id: 'dashboard-licenses',
      re: /^_up_\/resources\/dashboard\/licenses\/[^/]+\.txt$/,
      min: 1,
      max: Infinity,
      why: '面板随包字体（Noto Color Emoji 等）的 OFL 许可证正文，与 assets/ 里的 woff2 成对分发；删了同样是许可证违规。',
    },
    {
      id: 'dashboard-icons',
      re: /^_up_\/resources\/dashboard\/(favicon\.ico|favicon\.svg|apple-touch-icon-180x180\.png)$/,
      min: 3,
      max: 3,
      why: 'index.html 里 <link rel="icon"> / <link rel="apple-touch-icon"> 的三个目标，webview 里就是面板页签图标；删文件不删引用就是三个 404。',
    },
    {
      id: 'core-binary',
      re: new RegExp(`^_up_/resources/${core}/sing-box(\\.exe)?$`),
      min: 1,
      max: 1,
      why: '本平台的 sing-box 内核本体 —— 整个产品的运行前提。恰 1 份：多一份别平台的就是 §10.2 的四平台内核死重回潮。',
    },
    {
      id: 'helper-binary',
      re: new RegExp(`^_up_/resources/${core}/polaris-helper(\\.exe)?$`),
      min: 1,
      max: 1,
      why: '特权 helper：缺了 resolve_helper_binary → Err ⇒ TUN / 路由 / DNS 接管整条不可用，而 app 照常启动（2026-08-10 出过三平台静默缺 helper 的货）。',
    },
    {
      id: 'main-binary',
      re: /^(polaris|Polaris)(\.exe)?$/,
      min: 0,
      max: 1,
      why: 'Linux 的 deb/AppDir 把主程序与资源铺在同一层（usr/lib/<Product>/）时它会落在射程里；mac 的 .app 把它放 Contents/MacOS/、不在资源根下，故下限是 0。',
    },
    {
      id: 'macos-app-icon',
      re: /^icon\.icns$/,
      min: 0,
      max: 1,
      why: 'macOS bundler 自己铺进 Contents/Resources/ 的 app 图标（来自 bundle.icon，不经 bundle.resources），只有 mac 那两棵树里有。',
    },
  ];
  // Cronet 只随 linux/windows 出货（macOS 已静态集成）：mac 侧多一份 libcronet 就是纯死重，
  // 故那两个 label **不登记这条规则** ⇒ 真出现了会以「未登记」判红，而不是被一条宽规则放行。
  if (label === 'linux' || label === 'windows') {
    rules.push({
      id: 'cronet-sidecar',
      re: new RegExp(`^_up_/resources/${core}/libcronet\\.(so|dll)$`),
      min: 1,
      max: 1,
      why: 'Naive/H3 出站的 Cronet 动态库，核在 initialize 阶段就要它、且必须与核同目录；缺了那两类节点直接起不来。',
    });
  }
  return rules;
}

/**
 * `--static`：从 per-platform conf 的 `bundle.resources` × 工作树 `resources/` 推出「将进包的文件集合」。
 *
 * 目录条目按 bundler 的语义**整目录递归**展开 —— 这正是 `"../ui/src/"` 那条逃逸能把 194 个测试文件
 * 带进包的机制。展开不了（路径不存在 / 是 glob）一律判红，不静默少算一条条目。
 */
function staticPayloadItems(confName, res) {
  const items = [];
  for (const entry of res) {
    if (/[*?[\]]/.test(String(entry))) {
      fail(
        `src-tauri/${confName}: bundle.resources 条目 ${JSON.stringify(entry)} 含 glob 通配符 —— ` +
          `inventory --static 不展开 glob（展不开就等于少算一条条目，那是假绿）。改用目录/文件条目，或改跑 inventory --root。`
      );
      continue;
    }
    const rel = resourceRelpath(entry);
    const abs = resolve(SRC_TAURI, entry);
    if (!existsSync(abs)) {
      fail(`src-tauri/${confName}: bundle.resources 条目 ${JSON.stringify(entry)} 的源路径不存在 → ${abs} —— 无从展开（前置缺失判红，不跳过）`);
      continue;
    }
    if (statSync(abs).isDirectory()) {
      for (const f of walk2(abs, [], 0, 24)) {
        const sub = relative(abs, f).replace(/\\/g, '/');
        items.push({ rel: `${rel}/${sub}`, abs: f, from: entry });
      }
    } else {
      items.push({ rel, abs, from: entry });
    }
  }
  return items;
}

function checkInventory(label, { root, isStatic }) {
  const errorsBefore = errors.length;
  const coreDir = LABEL_TO_CORE[label];
  if (!coreDir) {
    fail(`inventory 模式：未知 label ${JSON.stringify(label)}，合法值：${Object.keys(LABEL_TO_CORE).join(', ')}`);
    return;
  }
  const confName = CORE_TO_CONF[coreDir];
  const trees = BUNDLE_TREES[label];
  if (!trees) {
    fail(`label '${label}' 未登记 BUNDLE_TREES —— 新增平台必须同时声明它的 bundle 产物目录`);
    return;
  }
  const srs = expectedSrsCount(); // 读不出来会抛 InputError → 顶层转成一条可读的违反，不静默
  const rules = payloadAllowRules(label, coreDir, srs.count);

  /** @type {{rel:string, abs:string, from?:string}[]} */
  let items = [];
  let outOfScope = 0;
  let scopeLine;
  let enforceCounts;

  if (isStatic) {
    enforceCounts = false;
    const conf = readJson(join(SRC_TAURI, confName), `平台 '${coreDir}' 的包内容清单无来源 ⇒ inventory --static 无从对账`);
    const res = conf.bundle?.resources;
    if (!Array.isArray(res)) {
      fail(`src-tauri/${confName}: bundle.resources 缺失或不是数组 —— inventory --static 无从推导（不变量 A/B 也会红）`);
      return;
    }
    items = staticPayloadItems(confName, res).map((it) => ({ ...it, tree: `conf:${confName}` }));
    scopeLine =
      `静态推导（**不是产物验证**）：src-tauri/${confName} 的 bundle.resources × 工作树 resources/，` +
      `按 bundler 的整目录递归语义展开`;
  } else {
    enforceCounts = true;
    const rootDir = resolve(ROOT, root);
    if (!existsSync(rootDir)) {
      fail(
        `inventory 模式：--root 路径不存在：${rootDir} —— 清点无从进行（前置缺失判红，不跳过）。\n` +
          `  artifact 腿传 bundle 根（target/release/bundle，带 --target 时 target/<triple>/release/bundle）；\n` +
          `  windows 腿传 target/release（NSIS 无 bundle 侧副本 ⇒ staging 检查）。`
      );
      return;
    }
    if (!statSync(rootDir).isDirectory()) {
      fail(`inventory 模式：--root 指向的不是目录：${rootDir}`);
      return;
    }
    // 🔴 **按 bundle target 分别限定射程**，不是把整个 `--root` 一锅端（与 payload 模式同口径）。
    // 实证（tauri-cli 2.11.4 预编译二进制的字符串表，`strings` 可复现，相邻三条字面量是
    // `bundle/appimage` / `bundle/appimage_deb` / `.AppDir`）：AppImage 那条腿在 `bundle/` 下**另建**
    // 一个 `appimage_deb/` 中间 staging 目录，里面是一整棵 deb 形态的数据树 —— 也含 `_up_/resources/`。
    // 整根一锅端的话，linux 腿会扫出**三棵**资源树（deb / appimage_deb / AppDir），
    // 而 `appimage_deb` 只是造 AppDir 的中间产物、根本不出货 ⇒ 那会是一次纯噪声的 CI 红。
    // 收在 `bundle/deb` + `bundle/appimage` 里，射程就恰是**会被分发的那几棵**。
    const scopes =
      trees.length > 0
        ? trees.map((t) => ({ name: `bundle/${t}`, dir: join(rootDir, t), staging: false }))
        : [{ name: root, dir: rootDir, staging: true }];
    for (const scope of scopes) {
      if (!existsSync(scope.dir)) {
        fail(
          `inventory 模式：产物目录不存在：${scope.dir}\n` +
            `  期望它是 ${scope.name}（bundler 为 ${label} 铺出的产物树）。少一个形态也要红 —— ` +
            `「那个包里有没有夹带」在它缺席时不可判定，不是「没问题」。`
        );
        continue;
      }
      // 全枚举（复用 walk2；深度给足 —— deb 的 dashboard/assets 在 bundle/deb 下第 10 层）
      const all = walk2(scope.dir, [], 0, 24);
      if (all.length === 0) {
        fail(`inventory 模式：${scope.dir} 下一个文件都没有 —— 空树不该判绿（白名单门在空目录上恒成立，那是假绿）`);
        continue;
      }
      // 资源根定位：出现 `_up_/` 段的那一层。一个都没有 ⇒ 红（布局漂移或 --root 传错，不静默跳过）。
      const roots = new Set();
      for (const p of all) {
        const segs = relative(scope.dir, p).replace(/\\/g, '/').split('/');
        const i = segs.indexOf('_up_');
        if (i >= 0) roots.add(segs.slice(0, i).join('/'));
      }
      if (roots.size !== 1) {
        fail(
          `inventory 模式：${scope.name} 里的资源载荷树应恰有 1 棵（含 \`_up_/\` 段的那一层），实为 ${roots.size} 棵` +
            `${roots.size > 0 ? `：${JSON.stringify([...roots])}` : ''}。\n` +
            `  bundler 把 \`../resources/x\` 铺成 \`_up_/resources/x\`（tauri-utils::resource_relpath）。\n` +
            `  0 棵 ⇒ ① --root 不是 bundle 根 ② 该 bundle target 没铺资源 ③ 布局漂移；` +
            `>1 棵 ⇒ 混进了别的树（上一轮残留 / 中间 staging），此时「验的是哪一棵」不可判定。\n` +
            `  实际布局样本（前 40 条）：\n${layoutSample(scope.dir)}`
        );
        continue;
      }
      const resRoot = [...roots][0];
      const prefix = resRoot === '' ? '' : `${resRoot}/`;
      const treeId = scope.staging ? scope.name : `${scope.name}/${resRoot}`;
      let inScope = 0;
      for (const p of all) {
        const rel = relative(scope.dir, p).replace(/\\/g, '/');
        if (!rel.startsWith(prefix)) continue;
        const sub = rel.slice(prefix.length);
        // staging 口径（windows）：资源根就是 target/release 本身、与 cargo 产物混在一起 ⇒ 射程收到
        // `_up_/` 子树 + conf 里那些非 `../` 条目落位的具体文件（紧接着单独补），其余算射程外。
        if (scope.staging && !sub.startsWith('_up_/')) continue;
        items.push({ rel: sub, abs: p, tree: treeId });
        inScope++;
      }
      if (scope.staging) {
        // 非 `../` 条目（如 `core-manifest.json`）落在资源根**同层**，上面被射程规则排除了，这里逐条补回：
        // 不补的话它们既不在射程内也没人验，而 core-manifest 缺失就是「运行期认不出随包核」。
        const conf = readJson(
          join(SRC_TAURI, confName),
          `平台 '${coreDir}' 的包内容清单无来源 ⇒ staging 清点补不齐非 ../ 条目`
        );
        for (const entry of conf.bundle?.resources ?? []) {
          const rel = resourceRelpath(entry);
          if (rel.startsWith('_up_/')) continue;
          const abs = join(scope.dir, resRoot, rel);
          if (existsSync(abs) && statSync(abs).isFile()) {
            items.push({ rel, abs, tree: treeId });
            inScope++;
          } else {
            fail(`inventory 模式（staging）：conf 条目 ${JSON.stringify(entry)} 应落位到 ${abs}，实际不存在 —— staging 没铺全`);
          }
        }
      }
      outOfScope += all.length - inScope;
    }
    scopeLine =
      trees.length > 0
        ? `产物清点：${rootDir} 下 ${scopes.map((s) => s.name).join(' + ')} 各一棵资源载荷树`
        : `**staging 检查（不是产物验证）**：${rootDir} 的 cargo staging 资源树。` +
          `NSIS 把资源从源路径直接编进 .exe，bundle 侧无副本可扫 ⇒ 「安装器内容是否含这些文件」在本仓无自动门。`;
  }

  // ── 对账：每个文件必须命中恰一条登记规则 ──
  //
  // 🔴 份数按**每棵资源树各自**算，不是全局汇总（同 payload 模式「每个 bundle target 各自命中」）：
  // linux 一次出 deb + appimage 两棵树，汇总口径下「deb 里 2 份内核 + appimage 里 0 份」= 2 份，
  // 与「各 1 份」在数上无法区分 —— 那正是「计数不等于位置」的原型。
  const resTrees = [...new Set(items.map((it) => it.tree))].sort();
  // 两段拼 key 用 U+001F（单元分隔符）而不是裸 NUL：源码里出现裸 NUL 字节会让 grep / ripgrep
  // 把整个文件判成 binary 而「找不到也不报错」地跳过——
  // 任何以 grep 为基础的仓库级审计会静默漏掉本文件（打包判据的单点）。
  const hitsOf = new Map(); // `${tree}\u001f${ruleId}` → items[]
  const keyOf = (tree, id) => `${tree}\u001f${id}`;
  for (const t of resTrees) for (const r of rules) hitsOf.set(keyOf(t, r.id), []);
  const unregistered = [];
  for (const it of items) {
    const r = rules.find((x) => x.re.test(it.rel));
    if (r) hitsOf.get(keyOf(it.tree, r.id)).push(it);
    else unregistered.push(it);
  }

  if (unregistered.length > 0) {
    const lines = unregistered
      .slice(0, 60)
      .map((it) => `      ${it.rel}${it.from ? `   ← conf 条目 ${JSON.stringify(it.from)}` : ''}   (${it.abs.replace(ROOT + '/', '')})`)
      .join('\n');
    fail(
      `包内容白名单：${unregistered.length} 个文件**未登记**（${scopeLine}）。\n` +
        `  白名单以外的文件一律红：包体是要分发给用户的，进去的每一个文件都得有人答得出「用户拿它干什么」。\n` +
        `  处理方式二选一：① 让它不要进包（改 conf 条目 / 在生成它的那一步就剔掉，治本）；` +
        `② 确属交付内容 ⇒ 在 verify-packaging.mjs 的 payloadAllowRules() 里登记，**并写明为什么**。\n` +
        `  未登记清单（最多列 60 条，共 ${unregistered.length} 条）：\n${lines}` +
        (unregistered.length > 60 ? `\n      …… 另有 ${unregistered.length - 60} 条未列出` : '')
    );
  }

  if (enforceCounts) {
    for (const t of resTrees) {
      for (const r of rules) {
        const got = hitsOf.get(keyOf(t, r.id));
        if (got.length >= r.min && got.length <= r.max) continue;
        const want = r.min === r.max ? `恰 ${r.min}` : `${r.min}~${r.max === Infinity ? '不限' : r.max}`;
        const where =
          got.length === 0
            ? '（无 —— 该有的没有，正是白名单门单独跑会漏掉的那半边）'
            : JSON.stringify(got.slice(0, 12).map((g) => g.rel)) + (got.length > 12 ? ` …… 共 ${got.length} 条` : '');
        fail(
          `包内容清单：资源树 '${t || '(根)'}' 的登记项 '${r.id}' 应有 ${want} 份，实为 ${got.length} 份（${scopeLine}）。\n` +
            `  为什么它该在包里：${r.why}\n` +
            `  该树内命中的具体路径：${where}`
        );
      }
    }
  }

  if (errors.length !== errorsBefore) return; // 有违反就不打「成立」的 note

  const table = resTrees
    .map((t) => `${t || '(根)'}{${rules.map((r) => `${r.id}=${hitsOf.get(keyOf(t, r.id)).length}`).join(' ')}}`)
    .join('  ');
  note(
    `inventory：${label} → ${scopeLine}；清点 ${items.length} 个文件，全部命中登记表 [${table}]` +
      (enforceCounts
        ? `，且份数在登记区间内（.srs 份数真值 ${srs.count} 取自 ${srs.where}：\`${srs.slice}\`）`
        : `。⚠️ 本模式**只判「多余」方向**：源是工作树，helper 由 CI 现编现铺、内核 gitignore 不入库，` +
          `「份数够不够」在这里不可判定，由 payload / inventory --root 覆盖`) +
      (isStatic ? '' : `；射程外（bundler/cargo 自己铺的、不由 bundle.resources 决定）${outOfScope} 个文件未清点`)
  );
}

// ───────────────────────── 入口 ─────────────────────────
function argOf(flag) {
  const i = process.argv.indexOf(flag);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : null;
}

const mode = process.argv[2];
try {
  runMode();
} catch (e) {
  // 输入侧读取失败：转成一条**可读的**违反，而不是把 `node:fs` / `JSON.parse` 裸栈甩进 CI 日志。
  // 退出码不变（仍走下面的 errors.length > 0 → exit 1），只是让人看得出哪个文件、哪条不变量因此断不了。
  if (e instanceof InputError) fail(e.message);
  else throw e;
}

function runMode() {
switch (mode) {
  case 'confs':
    checkConfs();
    break;
  case 'payload': {
    // `--root` **必填，无默认值**：旧默认 `'target'` 会把整棵 target/ 树扫进来，
    // 命中的是 cargo build script 的 staging copy（`target/release/_up_/resources/`），
    // 与 bundler 是否铺进包无关 —— 正是本轮修掉的假绿。漏传一律硬失败，不回落到某个「差不多」的根。
    const root = argOf('--root');
    if (!root) {
      console.error(
        'payload 模式必须显式传 --root（bundle 根）：\n' +
          '  Linux/Windows: --root target/release/bundle\n' +
          '  macOS:         --root target/<triple>/release/bundle\n' +
          '  （windows 腿例外：NSIS 无 bundle 侧副本，传 target/release 作 staging 检查）'
      );
      process.exit(2);
    }
    checkPayload(argOf('--label'), root);
    break;
  }
  case 'assets':
    // `--names-only`：只跑命名口径（发布后那一遍喂的是同名空文件），见文件头。
    checkAssets(argOf('--label'), argOf('--dir') ?? '.', process.argv.includes('--names-only'));
    break;
  case 'inventory': {
    // `--root` / `--static` **二选一必填**：漏传一律硬失败，不回落到某个「差不多」的根，也不静默跳过。
    // （白名单门在「什么都没扫到」时天然成立 ⇒ 前置缺失时的静默跳过就是一条恒绿的假门。）
    const root = argOf('--root');
    const isStatic = process.argv.includes('--static');
    if (!root && !isStatic) {
      console.error(
        'inventory 模式必须显式传 --root（产物/staging 清点）或 --static（静态推导清点）：\n' +
          '  Linux:         --label linux       --root target/release/bundle\n' +
          '  macOS:         --label macos-arm64 --root target/<triple>/release/bundle\n' +
          '  Windows:       --label windows     --root target/release   （NSIS 无 bundle 侧副本 ⇒ staging 检查）\n' +
          '  无产物的开发机: --label <label>     --static                （从 conf × 工作树静态推导）'
      );
      process.exit(2);
    }
    if (root && isStatic) {
      console.error('inventory 模式：--root 与 --static 互斥（一个清点产物、一个静态推导，混着传说不清验的是哪一个）');
      process.exit(2);
    }
    checkInventory(argOf('--label'), { root, isStatic });
    break;
  }
  default:
    console.error(
      '用法: node scripts/verify-packaging.mjs <confs|payload|assets|inventory> [--label <label>] [--root <bundle 根>] [--dir <dir>] [--names-only] [--static]'
    );
    process.exit(2);
}
}

for (const n of notes) console.log(`ok: ${n}`);
if (errors.length > 0) {
  console.error(`\nFAILED: ${errors.length} 条打包不变量被违反：`);
  for (const e of errors) console.error(`  ✗ ${e}`);
  process.exit(1);
}
console.log(`ok: verify-packaging ${mode} 全部不变量成立。`);
