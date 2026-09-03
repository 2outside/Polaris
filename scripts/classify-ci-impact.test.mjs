import assert from 'node:assert/strict';
import test from 'node:test';
import { readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  ALL_PACKAGE_PLATFORMS,
  NO_PACKAGE_IMPACT_SCOPES,
  classifyImpact,
} from './classify-ci-impact.mjs';

function compact(paths, options) {
  const { kernel, platforms, preflight, hasPackage } = classifyImpact(paths, options);
  return { kernel, platforms, preflight, hasPackage };
}

test('普通 UI、语言与文档不构建安装包', () => {
  assert.deepEqual(compact(['ui/src/App.tsx', 'ui/src/i18n/locales/zh-CN.json', 'README.md']), {
    kernel: false,
    platforms: [],
    preflight: false,
    hasPackage: false,
  });
});

test('配置生成变更只开启真实内核门', () => {
  assert.deepEqual(compact(['crates/config-engine/src/builder/dns.rs']), {
    kernel: true,
    platforms: [],
    preflight: true,
    hasPackage: false,
  });
});

test('内核版本与资产钉扎变更强制四平台', () => {
  assert.deepEqual(compact(['src-tauri/core-manifest.json']), {
    kernel: true,
    platforms: [...ALL_PACKAGE_PLATFORMS],
    preflight: true,
    hasPackage: true,
  });
});

test('平台专用安装逻辑只选择对应腿', () => {
  assert.deepEqual(
    compact([
      'src-tauri/nsis-hooks.nsh',
      'scripts/postprocess-appimage.mjs',
      'packaging/macos-dmg-open-guide.txt',
    ]),
    {
      kernel: false,
      platforms: ['linux', 'windows', 'macos-arm64', 'macos-x64'],
      preflight: true,
      hasPackage: true,
    },
  );
});

test('共享 helper、Tauri、资源与前端依赖变更强制四平台', () => {
  for (const path of [
    'crates/helper/src/lib.rs',
    'src-tauri/tauri.conf.json',
    '.github/workflows/package.yml',
    'scripts/fetch-dashboard.mjs',
    'THIRD-PARTY-LICENSES.md',
    'ui/pnpm-lock.yaml',
  ]) {
    assert.deepEqual(compact([path]).platforms, [...ALL_PACKAGE_PLATFORMS], path);
  }
});

test('随包拉取脚本被导入的共享模块（scripts/lib/**）必须命中内核门 + 四平台', () => {
  // 取材是**真目录枚举**而非写死清单：往 scripts/lib/ 里新抽一个共享模块却漏登记时，
  // 这条用例会自己红——这正是它要防的那类盲区（改随包解包实现，合入前零信号）。
  const libDir = join(dirname(fileURLToPath(import.meta.url)), 'lib');
  const files = readdirSync(libDir).filter((name) => name.endsWith('.mjs'));
  assert.ok(files.length > 0, 'scripts/lib/ 里一个 .mjs 都没枚举到 —— 取材面塌了，本用例此刻没有判据');
  for (const name of files) {
    assert.deepEqual(compact([`scripts/lib/${name}`]), {
      kernel: true,
      platforms: [...ALL_PACKAGE_PLATFORMS],
      preflight: true,
      hasPackage: true,
    }, `scripts/lib/${name}`);
  }
});

test('平台中立的前端构建配置只跑 Linux 代表腿', () => {
  assert.deepEqual(compact(['ui/vite.config.ts']), {
    kernel: false,
    platforms: ['linux'],
    preflight: true,
    hasPackage: true,
  });
});

test('无法取得可靠 diff 时故障关闭为内核门加四平台', () => {
  assert.deepEqual(compact([], { forceFull: true }), {
    kernel: true,
    platforms: [...ALL_PACKAGE_PLATFORMS],
    preflight: true,
    hasPackage: true,
  });
});

// ── 登记根内的两级默认（门 4，2026-08-30）──
// 完备性（每个 crate / src 子树都登记过）由 ui/src/contracts/ci-impact-coverage-contract.test.ts
// 按文件系统实况断言；这里只钉分类器自身的行为，让 release-risk 的 classify job 也带上这一条。

test('同模块的 `foo.rs` 与 `foo/` 互为别名，测试外移不制造同义登记条目', () => {
  // 正向：`app_tray/tests/mod.rs` 走 `src-tauri/src/app_tray.rs` 的判定（不影响打包）。
  const moved = classifyImpact(['src-tauri/src/app_tray/tests/mod.rs']);
  assert.equal(moved.kernel, false);
  assert.deepEqual(moved.platforms, []);
  assert.deepEqual(moved.unregisteredScopes, []);
  // 与直接改 `app_tray.rs` 判定逐字相同 —— 别名不是「放行」，是「同一条判定」。
  // 只比判定四元组：`paths` 是入参回声，两边本来就不同。
  const decision = ({ kernel, platforms, preflight, hasPackage }) =>
    ({ kernel, platforms, preflight, hasPackage });
  assert.deepEqual(decision(moved), decision(classifyImpact(['src-tauri/src/app_tray.rs'])));

  // 反向：目录形态登记时，同名 `.rs` 也走它。`src-tauri/src/test_support/` 是表里现成的目录条目。
  assert.deepEqual(
    decision(classifyImpact(['src-tauri/src/test_support/anything.rs'])),
    decision(classifyImpact(['src-tauri/src/test_support.rs'])),
  );

  // 反向对照（别名**不得**变成万能放行）：没有 `.rs` 兄弟登记的全新子树照旧 fail-closed。
  const fresh = classifyImpact(['src-tauri/src/__no_sibling_registered__/x.rs']);
  assert.equal(fresh.kernel, true);
  assert.deepEqual(fresh.platforms, ALL_PACKAGE_PLATFORMS);
  assert.deepEqual(fresh.unregisteredScopes, ['src-tauri/src/__no_sibling_registered__/']);
});

test('别名只在同名兄弟已登记时生效：影响打包的判定不会被目录形态稀释', () => {
  // `crates/config-engine/` 是内核门条目；它下面的测试目录仍然点亮内核门（别名不改判定强度）。
  const inner = classifyImpact(['crates/config-engine/src/user_config/control_url/tests/mod.rs']);
  assert.equal(inner.kernel, true);
});

test('登记根内的未登记路径故障关闭为内核门加四平台并自曝', () => {
  const result = classifyImpact(['crates/__not_registered__/src/lib.rs']);
  assert.deepEqual(
    {
      kernel: result.kernel,
      platforms: result.platforms,
      preflight: result.preflight,
      hasPackage: result.hasPackage,
    },
    {
      kernel: true,
      platforms: [...ALL_PACKAGE_PLATFORMS],
      preflight: true,
      hasPackage: true,
    },
  );
  assert.deepEqual(result.unregisteredScopes, ['crates/__not_registered__/']);
});

test('已显式判定不影响打包的 crate 不加任何腿，且不进自曝表', () => {
  for (const scope of [
    'crates/system-integration/',
    'crates/helper-client/',
    'crates/stats-engine/',
  ]) {
    assert.ok(NO_PACKAGE_IMPACT_SCOPES[scope], `${scope} 必须在「已判定不影响」表里有理由`);
    assert.deepEqual(compact([`${scope}src/lib.rs`]), {
      kernel: false,
      platforms: [],
      preflight: false,
      hasPackage: false,
    }, scope);
    assert.deepEqual(classifyImpact([`${scope}src/lib.rs`]).unregisteredScopes, [], scope);
  }
});

// ── productName 塌成一份事实（F8）后，runtime/ 退出打包判据面 ──
// 此前 `proxy.rs::LINUX_BUNDLE_PRODUCT_DIR` 是 productName 的第二份字面量，被
// verify-packaging confs 正则抓来对拍 ⇒ 该文件被单列进影响表、每个碰它的 PR 多跑一条 linux 腿。
// 现在 build.rs 从 tauri.conf.json 读它并 cargo:rustc-env 注入，对拍门已删。

test('runtime/ 整棵子树不再点亮打包腿，且降级没把它变成漏登记', () => {
  for (const path of ['src-tauri/src/runtime/proxy.rs', 'src-tauri/src/runtime/http.rs']) {
    assert.deepEqual(
      compact([path]),
      { kernel: false, platforms: [], preflight: false, hasPackage: false },
      path,
    );
    // 降级 ≠ 漏登记：`src-tauri/src/runtime/` 仍显式在 NO_PACKAGE_IMPACT_SCOPES 里，
    // 故不进自曝表。真漏登记会走 fail-closed（另有专门用例覆盖）。
    assert.deepEqual(classifyImpact([path]).unregisteredScopes, [], path);
  }
  assert.ok(Object.hasOwn(NO_PACKAGE_IMPACT_SCOPES, 'src-tauri/src/runtime/'));
});

test('productName 的新真值面仍强制四平台（降级不是把观测面一起删掉）', () => {
  // 反向对照，防止把「降级」做成「什么都不影响」：能改动 Linux 包 /usr/lib/<productName>/
  // 目录名的两个文件——注入源 tauri.conf.json 与注入器 build.rs——必须仍点亮四条腿。
  for (const path of ['src-tauri/tauri.conf.json', 'src-tauri/build.rs']) {
    assert.deepEqual(
      compact([path]),
      {
        kernel: false,
        platforms: [...ALL_PACKAGE_PLATFORMS],
        preflight: true,
        hasPackage: true,
      },
      path,
    );
  }
});


// ── resources/：第三条登记根（2026-08-30）──
// 补这条之前，`resources/**` 的任何改动都得到 kernel=false platforms=[] hasPackage=false（实测），
// 而 resources/data/ 的 28 个 .srs 入库且被四份 conf 的 bundle.resources 带进每个安装包。

test('入库随包的 geo .srs 改动强制内核门与四平台', () => {
  assert.deepEqual(compact(['resources/data/geosite-cn.srs']), {
    kernel: true,
    platforms: [...ALL_PACKAGE_PLATFORMS],
    preflight: true,
    hasPackage: true,
  });
  // 观测面：verify-packaging inventory 的 geo-srs 规则 min=max=build.rs::EXPECTED_SRS_COUNT，
  // 以及完整配置门的真实 `route.rule_set` 初始化；二者共同覆盖数量/魔数与核可读格式。
});

test('平台资源目录只选择对应腿，dashboard 走四平台', () => {
  for (const [path, platforms] of [
    ['resources/linux/sing-box', ['linux']],
    ['resources/win/libcronet.dll', ['windows']],
    ['resources/mac-arm64/polaris-helper', ['macos-arm64']],
    ['resources/mac-x64/polaris-helper', ['macos-x64']],
    ['resources/dashboard/index.html', [...ALL_PACKAGE_PLATFORMS]],
  ]) {
    assert.deepEqual(
      compact([path]),
      { kernel: false, platforms, preflight: true, hasPackage: true },
      path,
    );
  }
});

test('resources 根下的散文件不进任何包，也不进自曝表', () => {
  // 四份 conf 的 bundle.resources 只列 data/ 、dashboard/ 与本平台目录，根下文件不在包里。
  assert.deepEqual(compact(['resources/.gitkeep']), {
    kernel: false,
    platforms: [],
    preflight: false,
    hasPackage: false,
  });
  assert.deepEqual(classifyImpact(['resources/.gitkeep']).unregisteredScopes, []);
});

test('resources 下新增未登记子树故障关闭为内核门加四平台并自曝', () => {
  const result = classifyImpact(['resources/__not_registered__/blob.bin']);
  assert.equal(result.kernel, true);
  assert.deepEqual(result.platforms, [...ALL_PACKAGE_PLATFORMS]);
  assert.deepEqual(result.unregisteredScopes, ['resources/__not_registered__/']);
});
