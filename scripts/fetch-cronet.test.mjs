import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  CRONET_TARGETS,
  parseCronetGoModRequires,
  resolveCronetRequest,
  selectCronetPlatforms,
  validateCronetLibraryPins,
} from './lib/cronet-contract.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const VERSION = 'v0.0.0-20260831030607-f80ef37265e5';
const LINUX = 'github.com/sagernet/cronet-go/lib/linux_amd64';
const WINDOWS = 'github.com/sagernet/cronet-go/lib/windows_amd64';

const block = (linux = VERSION, windows = VERSION) => `
require (
  ${LINUX} ${linux} // indirect
  ${WINDOWS} ${windows}
  go.uber.org/zap v1.27.1
)
`;

test('Cronet manifest pins extracted libraries, not a human Chromium label', () => {
  const manifest = JSON.parse(readFileSync(join(ROOT, 'src-tauri/core-manifest.json'), 'utf8'));
  assert.equal('cronetVersion' in manifest, false);
  assert.equal('cronetModuleVersion' in manifest, false);
  assert.deepEqual(Object.keys(manifest.cronetLibrarySha256).sort(), ['linux', 'win']);
  assert.equal('cronetArchiveSha256' in manifest, false);
  assert.deepEqual(validateCronetLibraryPins(manifest.cronetLibrarySha256), manifest.cronetLibrarySha256);
});

test('Cronet platform selection accepts an exact combination and defaults to all', () => {
  assert.equal(selectCronetPlatforms([]), null);
  assert.deepEqual(selectCronetPlatforms(['--platform=linux,win']), ['linux', 'win']);
});

test('Cronet request resolution maps each selected platform to its exact dynamic library', () => {
  const describe = (argv) => resolveCronetRequest(argv).targets.map(({ key, module, member, out }) => ({ key, module, member, out }));
  assert.deepEqual(CRONET_TARGETS.map(({ key }) => key), ['linux', 'win']);
  assert.deepEqual(describe(['--platform=linux']), [
    { key: 'linux', module: 'linux_amd64', member: 'libcronet.so', out: 'libcronet.so' },
  ]);
  assert.deepEqual(describe(['--platform=win']), [
    { key: 'win', module: 'windows_amd64', member: 'libcronet.dll', out: 'libcronet.dll' },
  ]);
  assert.deepEqual(describe(['--platform=linux,win']), [
    { key: 'linux', module: 'linux_amd64', member: 'libcronet.so', out: 'libcronet.so' },
    { key: 'win', module: 'windows_amd64', member: 'libcronet.dll', out: 'libcronet.dll' },
  ]);
});

test('Cronet platform selection is fail-closed for malformed choices', () => {
  const cases = [
    [['--platform='], /值为空/],
    [['--platform=linux,,win'], /空分段/],
    [['--platform=,linux'], /空分段/],
    [['--platform=linux,'], /空分段/],
    [['--platform=linux,linux'], /重复平台 linux/],
    [['--platform=mac'], /未知平台 mac/],
    [['--platform'], /必须写成/],
    [['--platform=linux', '--platform=bogus'], /只能给一次/],
    [['--platform', '--platform=linux'], /只能给一次/],
  ];
  for (const [argv, error] of cases) {
    assert.throws(() => selectCronetPlatforms(argv), error, argv.join(' '));
  }
  assert.throws(() => resolveCronetRequest(['--skip-gomod-check']), /已移除/);
  assert.throws(() => resolveCronetRequest(['--check-only', '--force']), /互斥/);
  assert.throws(() => resolveCronetRequest(['--unexpected']), /未知参数/);
});

test('Cronet go.mod contract accepts both legal require forms', () => {
  const goMod = `
module example.invalid

require ${LINUX} ${VERSION}
require (
  ${WINDOWS} ${VERSION}
)
`;
  assert.deepEqual(parseCronetGoModRequires(goMod), { linux: VERSION, win: VERSION });
});

test('Cronet go.mod parser accepts whitespace variants of a require block opener', () => {
  for (const opener of ['require  (', 'require\t(', 'require(']) {
    const goMod = `${opener}\n  ${LINUX} ${VERSION}\n  ${WINDOWS} ${VERSION}\n)\n`;
    assert.deepEqual(parseCronetGoModRequires(goMod), { linux: VERSION, win: VERSION }, opener);
  }
});

test('Cronet selected platforms and go.mod contract compose on the happy path', () => {
  assert.deepEqual(selectCronetPlatforms(['--platform=win']), ['win']);
  assert.deepEqual(parseCronetGoModRequires(block()), { linux: VERSION, win: VERSION });
});

test('Cronet library pins are complete, exact, and fail closed', () => {
  const pins = {
    linux: 'a'.repeat(64),
    win: `sha256:${'b'.repeat(64)}`,
  };
  assert.deepEqual(validateCronetLibraryPins(pins), {
    linux: 'a'.repeat(64),
    win: 'b'.repeat(64),
  });
  assert.throws(() => validateCronetLibraryPins({ linux: 'a'.repeat(64) }), /平台集合/);
  assert.throws(
    () => validateCronetLibraryPins({ linux: 'a'.repeat(64), win: 'B'.repeat(64) }),
    /64 位小写 SHA-256/,
  );
});

test('Cronet go.mod parser rejects a missing module but permits platform version divergence', () => {
  assert.throws(
    () => parseCronetGoModRequires(`require ${LINUX} ${VERSION}\n`),
    new RegExp(`缺少 ${WINDOWS}`),
  );
  assert.throws(
    () => parseCronetGoModRequires(`require ${WINDOWS} ${VERSION}\n`),
    new RegExp(`缺少 ${LINUX}`),
  );
  assert.deepEqual(parseCronetGoModRequires(block(VERSION, 'v0.0.0-other')), {
    linux: VERSION,
    win: 'v0.0.0-other',
  });
});

test('Cronet go.mod parser ignores comments, prefixes, and cross-line bait', () => {
  const decoys = [
    [`// require ${LINUX} ${VERSION}`, new RegExp(`缺少 ${LINUX}`)],
    [`require ${LINUX}-extra ${VERSION}`, new RegExp(`缺少 ${LINUX}`)],
    [`require\n${LINUX} ${VERSION}`, /非合法 require/],
  ];
  for (const [decoy, error] of decoys) {
    const goMod = `${decoy}\nrequire ${WINDOWS} ${VERSION}\n`;
    assert.throws(
      () => parseCronetGoModRequires(goMod),
      error,
      `不应把以下诱饵当作 require：${JSON.stringify(decoy)}`,
    );
  }
});

test('Cronet go.mod parser rejects nested directives and target replacements', () => {
  assert.throws(
    () => parseCronetGoModRequires(`require (\n  require ${LINUX} ${VERSION}\n  ${WINDOWS} ${VERSION}\n)\n`),
    /非法 directive/,
  );
  assert.throws(
    () => parseCronetGoModRequires(`require (\n  ${LINUX} ${VERSION}\n  replace example.invalid/other v1.0.0 => ./local-other\n  ${WINDOWS} ${VERSION}\n)\n`),
    /非法 directive/,
  );
  assert.throws(
    () => parseCronetGoModRequires(`${block()}replace ${LINUX} ${VERSION} => ./local-cronet\n`),
    /replace 改写 Cronet 目标模块/,
  );
  assert.throws(
    () => parseCronetGoModRequires(`${block()}replace (\n  ${WINDOWS} ${VERSION} => example.invalid/cronet ${VERSION}\n)\n`),
    /replace \(\.\.\.\) 改写 Cronet 目标模块/,
  );
});

test('Cronet go.mod parser allows unrelated replace and ignores target names in comments', () => {
  const goMod = `${block()}replace example.invalid/other v1.0.0 => ./local-other\n// replace ${LINUX} ${VERSION} => ./local-cronet\n`;
  assert.deepEqual(parseCronetGoModRequires(goMod), { linux: VERSION, win: VERSION });
});

test('Cronet go.mod parser rejects duplicate and unterminated require declarations', () => {
  assert.throws(
    () => parseCronetGoModRequires(`${block()}require ${LINUX} ${VERSION}\n`),
    /声明重复出现/,
  );
  assert.throws(
    () => parseCronetGoModRequires(`require (\n  ${LINUX} ${VERSION}\n  ${WINDOWS} ${VERSION}\n`),
    /未闭合/,
  );
});
