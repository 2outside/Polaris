#!/usr/bin/env node
/**
 * fetch-cronet.mjs — 下载各平台 NaiveProxy 核心库 libcronet 到 resources/{平台}/，
 * 供 Tauri bundle resources 随安装包打包（与 sing-box 二进制同模式）。
 *
 * 用法：node scripts/fetch-cronet.mjs [--platform=linux,win] [--force] [--check-only]
 *
 * ⚠️ macOS 不在此脚本范围：cronet 在 mac 上不走动态库。mac-arm64 与 mac-x64 的 sing-box 二进制**都已把
 *   cronet 静态编入（CGO）**，naive 两架构均开箱即用。strings 坐实：两架构 tags 同含 `with_naive_outbound`、
 *   cronet 符号计数均 1588、二进制 73/78MB（远大于走动态库的 linux 70/win 71MB）。详见 README。
 *
 * # 渠道：Go module proxy，**不是** GitHub Releases（2026-08-05 换）
 *
 * 此前从 `SagerNet/cronet-go` 的 **Releases 资产**（`libcronet-linux-amd64.so` 等）下载，版本 pin 是
 * release tag（如 `v148.0.7778.96-1`）。**那条渠道与核已经脱钩**：sing-box 自 1.14 起把 libcronet 作为
 * Go module 依赖（`github.com/sagernet/cronet-go/lib/<平台>`，伪版本 `v0.0.0-<时间戳>-<commit>`），
 * 而 cronet-go 的 Releases 页停在 2026-05-13 的 v148 —— 核要的 150.0.7871.63 那一版**根本没有对应的
 * Release**。继续走 Releases 只能拿到一个越来越旧的库。
 *
 * 实测（2026-08-05）：`1.14.0-beta.5` 的 `go.mod` 钉 `lib/linux_amd64 v0.0.0-20260731161755-38229fb700f6`，
 * 该模块 zip 18.9 MB，内含的 `libcronet.so` 版本串正是 `150.0.7871.63`；Windows 同伪版本、同版本串。
 *
 * # 版本唯一来源是随包 sing-box tag 的 go.mod
 *
 * 每次调用都拉 `sing-box@v<bundledCoreVersion>` 的 `go.mod`，同时取其中 `cronet-go/lib/linux_amd64` 与
 * `cronet-go/lib/windows_amd64` 的伪版本。脚本按目标平台直接下载对应版本，两个模块将来分叉也不需要改
 * manifest schema。`core-manifest.json` 不保存第二个 Cronet 版本真值，只保存下载后库本体的 SHA-256 pin。
 * 这避免了「核升了、cronet 版本漏跟」的双真值漂移；而 Cronet 走 C API（Chromium 稳定 ABI），错配多半不会
 * 当场报错，必须在下载边界把版本来源收窄到核自己的构建依赖。
 *
 * # 与 `fetch-core.mjs` 同一套做法（刻意对齐，勿各写各的）
 *
 * 下载走 `curl -fL --retry 3`（而非自写 https.get：`-f` 拦 404 页面冒充成功、`-L` 跟重定向、`--retry`
 * 抗瞬时抖动，全是白给的）、解压走共享的 `lib/extract-zip.mjs`（按平台选择可用后端）、临时产物落
 * `mkdtemp` 工作区并在 `finally` 里整个删掉、落地走 `.tmp` → `rename`。**唯一有意的差异是校验对象**：
 *
 * - `fetch-core` 校验**压缩包**（其 sha 就是 GitHub release API 给的 asset digest，可直接抄）；
 * - 本脚本校验**解压出来的库本体** —— module zip 的字节受 proxy 打包方式影响，而库本体才是运行期真正
 *   被 dlopen 的东西。故先解压再校验，manifest 里 `cronetLibrarySha256` 存的是库本体的 sha。
 *
 * 两个脚本相似归相似，**下载与原子落地不抽公共模块**：那两处一共两个调用点，抽出来的抽象比它消掉的
 * 重复更重。对齐的是**写法**，不是造一层共享代码。
 *
 * ⚠️ **解压是例外**（2026-08-05 收窄上面这条）：`lib/extract-zip.mjs` 确实抽了出来。判据不是「重复」——
 * 是「zip 用哪个解压器」变成了一条**跨平台判据**（Linux 的 GNU tar 不认 zip、Windows 没有 unzip），
 * 三个 fetch 脚本各写一遍必然各自漂，且漂了以后只在某一条 CI 腿上炸。判据本身需要单一真值点，
 * 与「省几行重复」无关。
 */
import { execFileSync } from 'child_process';
import { createHash } from 'crypto';

import { extractZip, findInZipRoot } from './lib/extract-zip.mjs';
import { isFresh, readStamps, recordStamp } from './lib/fetch-stamp.mjs';
import {
  CRONET_TARGETS,
  parseCronetGoModRequires,
  resolveCronetRequest,
  validateCronetLibraryPins,
} from './lib/cronet-contract.mjs';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
} from 'fs';
import { tmpdir } from 'os';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

const coreManifest = JSON.parse(readFileSync(join(ROOT, 'src-tauri/core-manifest.json'), 'utf-8'));
const CORE_VERSION = coreManifest.bundledCoreVersion;
let CRONET_SHA;
const MODULE_PROXY = 'https://proxy.golang.org';
const MODULE_BASE = 'github.com/sagernet/cronet-go/lib';

let request;
try {
  request = resolveCronetRequest(process.argv.slice(2));
} catch (e) {
  console.error(`FAILED: ${e.message}`);
  process.exit(1);
}
const TARGETS = CRONET_TARGETS;
const ONLY = request.selectedPlatforms;
const PICKED = request.targets;
const FORCE = request.force;
const CHECK_ONLY = request.checkOnly;
if (ONLY && !CHECK_ONLY) {
  const skipped = TARGETS.filter((t) => !ONLY.includes(t.key)).map((t) => t.key);
  console.log(
    `--platform=${ONLY.join(',')} ⇒ 本次只处理 ${ONLY.length} 个平台，` +
      `跳过（盘上文件原样保留）：${skipped.join(', ') || '无'}`
  );
}

const sha256 = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');

/**
 * 从核的 go.mod 取它真正依赖的两个 cronet-go lib 伪版本。
 *
 * 不能缓存或跳过这一步：它既是下载版本的唯一来源，也是防止 core manifest 与实际构建依赖分离的边界。
 */
function resolveCronetVersionsFromGoMod() {
  const url = `https://raw.githubusercontent.com/SagerNet/sing-box/v${CORE_VERSION}/go.mod`;
  const text = execFileSync('curl', ['-fsSL', '--retry', '3', url], { encoding: 'utf-8' });
  const versions = parseCronetGoModRequires(text);
  const platformVersions = `${MODULE_BASE}/linux_amd64=${versions.linux}；` +
    `${MODULE_BASE}/windows_amd64=${versions.win}`;
  console.log(
    `go.mod 已解析 Cronet 版本：sing-box v${CORE_VERSION} (${platformVersions})`
  );
  return versions;
}

try {
  CRONET_SHA = validateCronetLibraryPins(coreManifest.cronetLibrarySha256);
} catch (e) {
  console.error(`FAILED: ${e.message}`);
  process.exit(1);
}

// ── `--check-only`：解析双平台 go.mod 依赖并校验两个库 pin，不下载任何库（给 ci.yml 用）──
//
// 这不是「manifest 版本和 go.mod 是否一致」的旧式对拍；版本只来自 go.mod。它仍是独立门：确认
// bundledCoreVersion 的 tag 可读、两个目标模块均为精确 require、且两个平台都有可用的 SHA-256 pin。
// 正常下载也无条件执行同一解析，因此本地 stamp 无法决定是否检查源依赖。
let MODULE_VERSIONS;
try {
  MODULE_VERSIONS = resolveCronetVersionsFromGoMod();
} catch (e) {
  console.error(`FAILED: ${e.message}`);
  process.exit(1);
}
if (CHECK_ONLY) {
  process.exit(0);
}

// 「就位」= 产物在 **且** 指纹是当前 go.mod 依赖版本及完整性 pin 的组合，不是「文件在不在」。
// 每次调用在这里之前已从 go.mod 重新取得版本，故 core tag 变动或未来的跨平台版本分叉都不能被旧 stamp 隐藏。
const stamps = readStamps(ROOT);
const versionFor = (t) => MODULE_VERSIONS[t.key];
const fingerprintOf = (t) => `${versionFor(t)}|${CRONET_SHA[t.key]}`;
const isCurrent = (t) =>
  isFresh(stamps, `cronet:${t.key}`, fingerprintOf(t), existsSync(join(ROOT, t.dir, t.out)));

let ok = 0;
let failed = 0;
for (const t of PICKED) {
  const absDir = join(ROOT, t.dir);
  const dest = join(absDir, t.out);
  // 共用 `isCurrent`：产物在 **且** 是当前 go.mod 版本与 pin 对应的产物。
  if (!FORCE && isCurrent(t)) {
    console.log(`skip (up to date): ${t.dir}/${t.out} @ ${versionFor(t)}`);
    ok++;
    continue;
  }
  if (!FORCE && existsSync(dest)) {
    console.log(`stale: ${t.dir}/${t.out} 不是 ${versionFor(t)} 的产物，重新拉取`);
  }
  // 完整性 pin 是供应链防护核心：缺 pin 直接 fail（libcronet 是运行期 dlopen 执行的原生库，
  // 与 sing-box 核同级别，绝不无校验拉取）。
  const want = CRONET_SHA[t.key];
  mkdirSync(absDir, { recursive: true });
  const moduleVersion = versionFor(t);
  const url = `${MODULE_PROXY}/${MODULE_BASE}/${t.module}/@v/${moduleVersion}.zip`;
  const work = mkdtempSync(join(tmpdir(), 'polaris-cronet-'));
  try {
    const archive = join(work, 'mod.zip');
    console.log(`downloading ${MODULE_BASE}/${t.module}@${moduleVersion} → ${t.dir}/${t.out} ...`);
    execFileSync('curl', ['-fL', '--retry', '3', '-o', archive, url], { stdio: 'inherit' });

    // zip 内路径带 `<module>@<version>/` 前缀。此前用 `unzip -j '*/<member>'`（junk-paths +
    // 通配选成员）只解出要的那一个；改为全解 + JS 定位，因为那套 flag 在 Windows 唯一可用的
    // 解压器 bsdtar 上没有逐字对应物（见 lib/extract-zip.mjs 头注）。多解出来的字节全在
    // `work` 这个 mkdtemp 工作区里，finally 整个 rmSync，不留痕。
    const extractDir = join(work, 'x');
    mkdirSync(extractDir, { recursive: true });
    extractZip(archive, extractDir);
    const libPath = findInZipRoot(extractDir, t.member);
    if (!libPath) {
      throw new Error(`module zip (${t.module}) 里没有 ${t.member}（上游布局可能变化）`);
    }

    // 校验的是**库本体**不是 zip —— 理由见头注「与 fetch-core.mjs 同一套做法」一节。
    const got = sha256(libPath);
    if (got !== want) {
      throw new Error(`sha256 不符：期望 ${want}，实得 ${got}（版本漂移 / 投毒 / 截断）`);
    }

    // 原子落地：拷到 .tmp → rename 顶替（中断不会留下半个库被下次 skip-exists 当成好的）。
    const tmpDest = `${dest}.tmp`;
    rmSync(tmpDest, { force: true });
    copyFileSync(libPath, tmpDest);
    renameSync(tmpDest, dest);
    // 指纹在**产物 rename 之后**才记（理由同 fetch-core：先记会在落地失败时留下
    // 「指纹说是新的、盘上还是旧的」，下一趟直接 skip 掉，比没指纹更糟）。
    recordStamp(ROOT, `cronet:${t.key}`, fingerprintOf(t));
    console.log(`  ok (sha ${want.slice(0, 12)}…)`);
    ok++;
  } catch (e) {
    console.error(`  FAILED ${t.key}: ${e.message}`);
    failed++;
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}
const resolvedVersions = CRONET_TARGETS.map((target) => `${target.key}=${versionFor(target)}`).join(', ');
console.log(`\ncronet libs: ${ok} ready, ${failed} failed (${resolvedVersions}).`);
console.log('macOS: cronet 静态编入 mac-arm64 / mac-x64 核心，无需下载（见脚本头注）。');
process.exit(failed > 0 ? 1 : 0);
