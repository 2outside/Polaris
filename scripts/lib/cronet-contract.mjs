/**
 * Cronet 的机器合同：平台选择、sing-box go.mod 依赖解析和完整性 pin 校验。
 *
 * 保持纯函数，供 fetch 脚本和 Node 合同测试共用；这里不做网络、文件或下载操作。
 */

export const CRONET_TARGETS = Object.freeze([
  Object.freeze({
    key: 'linux',
    module: 'linux_amd64',
    dir: 'resources/linux',
    member: 'libcronet.so',
    out: 'libcronet.so',
  }),
  Object.freeze({
    key: 'win',
    module: 'windows_amd64',
    dir: 'resources/win',
    member: 'libcronet.dll',
    out: 'libcronet.dll',
  }),
]);
const MODULES = Object.freeze(
  Object.fromEntries(CRONET_TARGETS.map((target) => [target.key, `github.com/sagernet/cronet-go/lib/${target.module}`])),
);
const PLATFORM_KEYS = Object.freeze(Object.keys(MODULES));

/** `--platform=linux,win` 的严格解析；缺省时返回 null（即全平台）。 */
export function selectCronetPlatforms(argv) {
  const flags = argv.filter((arg) => arg === '--platform' || arg.startsWith('--platform='));
  if (flags.length > 1) {
    throw new Error(`--platform 只能给一次，收到：${flags.join(' ')}`);
  }
  if (flags.length === 0) return null;
  if (flags[0] === '--platform') {
    throw new Error(`--platform 必须写成 --platform=${PLATFORM_KEYS.join(',')}`);
  }

  const raw = flags[0].slice('--platform='.length);
  if (raw === '') {
    throw new Error(`--platform 值为空。可选：${PLATFORM_KEYS.join(' / ')}（不传该 flag = 全平台）`);
  }
  const keys = raw.split(',').map((part) => part.trim());
  const emptyAt = keys.findIndex((key) => key === '');
  if (emptyAt !== -1) {
    throw new Error(`--platform 含空分段（第 ${emptyAt + 1} 段）：${raw}`);
  }
  const unknown = keys.filter((key) => !PLATFORM_KEYS.includes(key));
  if (unknown.length > 0) {
    throw new Error(`未知平台 ${unknown.join(', ')}。可选：${PLATFORM_KEYS.join(' / ')}`);
  }
  const duplicate = keys.find((key, index) => keys.indexOf(key) !== index);
  if (duplicate) {
    throw new Error(`--platform 含重复平台 ${duplicate}：${raw}`);
  }
  return keys;
}

/** 解析 fetch 请求；目标、控制 flag 与互斥关系只在此处定义。 */
export function resolveCronetRequest(argv) {
  if (argv.includes('--skip-gomod-check')) {
    throw new Error('--skip-gomod-check 已移除：sing-box go.mod 是 Cronet 版本的唯一来源，不能跳过');
  }
  const unknown = argv.filter((arg) =>
    arg !== '--force' &&
    arg !== '--check-only' &&
    arg !== '--platform' &&
    !arg.startsWith('--platform='),
  );
  if (unknown.length > 0) {
    throw new Error(`未知参数：${unknown.join(' ')}`);
  }
  const selectedPlatforms = selectCronetPlatforms(argv);
  const checkOnly = argv.includes('--check-only');
  const force = argv.includes('--force');
  if (checkOnly && force) {
    throw new Error('--check-only 与 --force 互斥（前者不下载，后者强制下载）');
  }
  const targets = selectedPlatforms
    ? CRONET_TARGETS.filter((target) => selectedPlatforms.includes(target.key))
    : CRONET_TARGETS;
  return Object.freeze({
    targets,
    selectedPlatforms,
    force,
    checkOnly,
  });
}

function recordRequire(found, key, version) {
  if (found[key] !== undefined) {
    throw new Error(`go.mod 的 require 声明重复出现 ${MODULES[key]}，拒绝猜测该采用哪一条`);
  }
  found[key] = version;
}

/** 移除 Go 注释；保留同一行前面的代码，避免注释里的模块名变成合同输入。 */
function uncommentLines(goMod) {
  let inBlockComment = false;
  return goMod.split(/\r?\n/).map((line) => {
    let code = '';
    for (let at = 0; at < line.length;) {
      if (inBlockComment) {
        const close = line.indexOf('*/', at);
        if (close === -1) return code.trim();
        inBlockComment = false;
        at = close + 2;
        continue;
      }
      if (line.startsWith('//', at)) break;
      if (line.startsWith('/*', at)) {
        inBlockComment = true;
        at += 2;
        continue;
      }
      code += line[at];
      at += 1;
    }
    return code.trim();
  });
}

function targetKeyAtStart(code) {
  for (const [key, module] of Object.entries(MODULES)) {
    if (code === module || code.startsWith(`${module} `) || code.startsWith(`${module}\t`)) return key;
  }
  return null;
}

function containsTargetModule(code) {
  return Object.values(MODULES).some((module) => {
    const escaped = module.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(`(?:^|\\s)${escaped}(?=\\s|$)`).test(code);
  });
}

/** replace 会改变真实构建源；目标模块不能再按 require version 从 proxy 安全下载。 */
function rejectTargetReplaces(lines) {
  let inReplaceBlock = false;
  for (const code of lines) {
    if (!inReplaceBlock) {
      if (/^replace\s*\($/.test(code)) {
        inReplaceBlock = true;
        continue;
      }
      if (code.startsWith('replace ') && targetKeyAtStart(code.slice('replace '.length))) {
        throw new Error('go.mod 以 replace 改写 Cronet 目标模块；无法确认 proxy 下载物就是实际构建库');
      }
      continue;
    }
    if (code === ')') {
      inReplaceBlock = false;
      continue;
    }
    if (targetKeyAtStart(code)) {
      throw new Error('go.mod 的 replace (...) 改写 Cronet 目标模块；无法确认 proxy 下载物就是实际构建库');
    }
  }
}

/**
 * 只解析合法的 Go `require` 单行声明或 `require (...)` 块内声明。
 * 目标模块出现在其它语法位置一律拒绝：只有精确 require 才能证明 proxy 版本就是构建来源。
 */
export function parseCronetGoModRequires(goMod) {
  const found = {};
  let inRequireBlock = false;
  const singleRequire = /^require\s+(github\.com\/sagernet\/cronet-go\/lib\/(linux_amd64|windows_amd64))\s+(\S+)$/;
  const blockRequire = /^(github\.com\/sagernet\/cronet-go\/lib\/(linux_amd64|windows_amd64))\s+(\S+)$/;
  const lines = uncommentLines(goMod);
  rejectTargetReplaces(lines);

  for (const line of lines) {
    if (!inRequireBlock) {
      if (/^require\s*\($/.test(line)) {
        inRequireBlock = true;
        continue;
      }
      const match = line.match(singleRequire);
      if (match) recordRequire(found, match[2] === 'linux_amd64' ? 'linux' : 'win', match[3]);
      else if (containsTargetModule(line)) {
        throw new Error('Cronet 目标模块出现在非合法 require 声明中，拒绝猜测其实际构建来源');
      }
      continue;
    }

    if (line === ')') {
      inRequireBlock = false;
      continue;
    }
    const match = line.match(blockRequire);
    if (match) recordRequire(found, match[2] === 'linux_amd64' ? 'linux' : 'win', match[3]);
    else if (/^(require|replace|exclude|retract|module|go|toolchain)(?:\s|$)/.test(line)) {
      throw new Error(`require (...) 块内出现非法 directive：${line}`);
    } else if (containsTargetModule(line)) {
      throw new Error('Cronet 目标模块出现在非合法 require 声明中，拒绝猜测其实际构建来源');
    }
  }

  if (inRequireBlock) {
    throw new Error('go.mod 的 require (...) 块未闭合，拒绝把后续文本当作依赖声明');
  }
  const missing = PLATFORM_KEYS.filter((key) => found[key] === undefined).map((key) => MODULES[key]);
  if (missing.length > 0) {
    throw new Error(`go.mod 的 require 声明缺少 ${missing.join('、')}`);
  }
  return Object.freeze({ linux: found.linux, win: found.win });
}

/**
 * manifest 不保存 Cronet 版本，只保存运行期动态库的完整性 pin。
 *
 * 返回去掉可选 `sha256:` 前缀的 digest；缺项、额外项、类型或长度不对都拒绝，避免某个平台
 * 在本地碰巧不下载时把不完整的发行配置带进 CI。
 */
export function validateCronetLibraryPins(pins) {
  if (!pins || typeof pins !== 'object' || Array.isArray(pins)) {
    throw new Error('core-manifest.json 缺 cronetLibrarySha256 对象，拒绝无完整性校验拉取');
  }
  const actualKeys = Object.keys(pins).sort();
  const expectedKeys = [...PLATFORM_KEYS].sort();
  if (actualKeys.join(',') !== expectedKeys.join(',')) {
    throw new Error(
      `core-manifest.json 的 cronetLibrarySha256 平台集合不完整或含未知项：` +
        `期望 ${expectedKeys.join(', ')}；实际 ${actualKeys.join(', ') || '空'}`,
    );
  }

  const normalized = {};
  for (const key of PLATFORM_KEYS) {
    const raw = pins[key];
    const digest = typeof raw === 'string' ? raw.replace(/^sha256:/, '') : '';
    if (!/^[a-f0-9]{64}$/.test(digest)) {
      throw new Error(
        `core-manifest.json 的 cronetLibrarySha256[${key}] 不是 64 位小写 SHA-256，拒绝无完整性校验拉取`,
      );
    }
    normalized[key] = digest;
  }
  return Object.freeze(normalized);
}
