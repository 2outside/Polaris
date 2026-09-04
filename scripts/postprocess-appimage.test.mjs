import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { APPIMAGE_HOST_WAYLAND_LIBS, appImageRuntimeViolations } from './postprocess-appimage.mjs';

// 判据与修复同源：`appImageRuntimeViolations` 由 postprocess-appimage.mjs 导出、被
// verify-packaging.mjs 的 payload 门 import（`verify-packaging.mjs:71` / `:1454`），即
// **动手的人和判分的人是同一段代码**。谓词写歪一点，重封和门会同时瞎，产物照样出厂。
// 故本文件的承重面是**反向对照**：把 2026-08-24 那个真实坏 AppDir 的形态原样喂进去，
// 断言它必须报满 5 项 —— 谓词退化成恒绿时这里立刻红。
//
// 历史真缺陷（Ubuntu 26.04 / GNOME Wayland，AppImage `45058e3`）：linuxdeploy 随包带入
// 构建机的四个 libwayland-*，与宿主 Mesa/EGL 混用 ⇒ WebKitWebProcess 以 EGL_BAD_PARAMETER
// 连崩（apport 记录 6 次 SIGABRT）；GTK hook 只设 GIO_EXTRA_MODULES ⇒ bundled 旧 GLib 仍
// 装载宿主 GVfs module ⇒ 主进程 undefined symbol 致命退出（2 次 SIGTRAP）。修复为 `e64e6f1`。

const GIO_RELATIVE = 'usr/lib/x86_64-linux-gnu/gio/modules';
const BUNDLED_GIO = `"$APPDIR/${GIO_RELATIVE}"`;

/**
 * 造一个 AppDir 夹具。默认参数**刻意就是坏形态**（四个 wayland 库俱在、hook 没有
 * GIO_MODULE_DIR），即 2026-08-24 真机上那个 AppDir 的结构切片。
 */
function makeAppDir({
  waylandLibs = APPIMAGE_HOST_WAYLAND_LIBS,
  gioExtra = [BUNDLED_GIO],
  gioModuleDir = [],
  hook = true,
  modulesDir = true,
  extraDirs = [],
} = {}) {
  const appDir = mkdtempSync(join(tmpdir(), 'polaris-appdir-'));
  mkdirSync(join(appDir, 'usr', 'lib'), { recursive: true });
  if (modulesDir) mkdirSync(join(appDir, GIO_RELATIVE), { recursive: true });
  for (const relative of extraDirs) mkdirSync(join(appDir, relative), { recursive: true });
  for (const name of waylandLibs) {
    writeFileSync(join(appDir, 'usr', 'lib', name), 'ELF-stub');
  }
  if (hook) {
    mkdirSync(join(appDir, 'apprun-hooks'), { recursive: true });
    const lines = [
      '#! /usr/bin/env bash',
      'export GSETTINGS_SCHEMA_DIR="$APPDIR/usr/share/glib-2.0/schemas"',
      ...gioExtra.map((rhs) => `export GIO_EXTRA_MODULES=${rhs}`),
      ...gioModuleDir.map((rhs) => `export GIO_MODULE_DIR=${rhs}`),
    ];
    writeFileSync(join(appDir, 'apprun-hooks', 'linuxdeploy-plugin-gtk.sh'), `${lines.join('\n')}\n`);
  }
  return appDir;
}

/** 每个用例自带清理：夹具落在 tmpdir，留下来会攒垃圾。 */
function withAppDir(t, options) {
  const appDir = makeAppDir(options);
  t.after(() => rmSync(appDir, { recursive: true, force: true }));
  return appDir;
}

test('反向对照：2026-08-24 那个坏 AppDir 必须报满 5 项（四个 wayland 库 + 缺 GIO_MODULE_DIR）', (t) => {
  const appDir = withAppDir(t);
  const violations = appImageRuntimeViolations(appDir);
  assert.deepEqual(violations, [
    'AppDir 仍捆绑 libwayland-client.so.0（会与新宿主 Mesa/EGL 混用）',
    'AppDir 仍捆绑 libwayland-cursor.so.0（会与新宿主 Mesa/EGL 混用）',
    'AppDir 仍捆绑 libwayland-egl.so.1（会与新宿主 Mesa/EGL 混用）',
    'AppDir 仍捆绑 libwayland-server.so.0（会与新宿主 Mesa/EGL 混用）',
    'GIO_MODULE_DIR export 应恰有 1 条，实为 0 条',
  ]);
});

test('正面断言：后处理修好的 AppDir 违反为空', (t) => {
  const appDir = withAppDir(t, { waylandLibs: [], gioModuleDir: [BUNDLED_GIO] });
  assert.deepEqual(appImageRuntimeViolations(appDir), []);
});

test('四个冲突库逐个独立成条，不是「有没有 wayland」一把梭', (t) => {
  for (const name of APPIMAGE_HOST_WAYLAND_LIBS) {
    const appDir = withAppDir(t, { waylandLibs: [name], gioModuleDir: [BUNDLED_GIO] });
    assert.deepEqual(appImageRuntimeViolations(appDir), [
      `AppDir 仍捆绑 ${name}（会与新宿主 Mesa/EGL 混用）`,
    ]);
  }
});

test('GIO_MODULE_DIR 与 GIO_EXTRA_MODULES 指向不同目录即红', (t) => {
  // 目标目录**造出来**，好让这一格只剩「两侧不一致」这一条违反：一次变异只应点亮一盏灯，
  // 否则「存在性」那条会顺带遮住「一致性」这条是死是活。
  const appDir = withAppDir(t, {
    waylandLibs: [],
    gioModuleDir: ['"$APPDIR/usr/lib/gio/modules"'],
    extraDirs: ['usr/lib/gio/modules'],
  });
  assert.deepEqual(appImageRuntimeViolations(appDir), [
    `GIO_MODULE_DIR 必须与 bundled GIO_EXTRA_MODULES 指向同一目录："$APPDIR/usr/lib/gio/modules" != ${BUNDLED_GIO}`,
  ]);
});

test('GIO_MODULE_DIR 逃出 $APPDIR 即红 —— 那正是加载宿主 GVfs module 的原病理', (t) => {
  const hostPath = '"/usr/lib/x86_64-linux-gnu/gio/modules"';
  const appDir = withAppDir(t, {
    waylandLibs: [],
    gioExtra: [hostPath],
    gioModuleDir: [hostPath],
  });
  assert.deepEqual(appImageRuntimeViolations(appDir), [
    `GIO_MODULE_DIR 必须锚在 $APPDIR 内，实为 ${hostPath}`,
  ]);
});

test('GIO_MODULE_DIR 锚对了但 bundled 目录不存在即红（路径写对≠东西在包里）', (t) => {
  const appDir = withAppDir(t, {
    waylandLibs: [],
    gioModuleDir: [BUNDLED_GIO],
    modulesDir: false,
  });
  assert.deepEqual(appImageRuntimeViolations(appDir), [
    `GIO_MODULE_DIR 指向的 bundled 目录不存在：${join(appDir, GIO_RELATIVE)}`,
  ]);
});

test('重复 export 行不被当成「有一条」放过', (t) => {
  const appDir = withAppDir(t, {
    waylandLibs: [],
    gioModuleDir: [BUNDLED_GIO, BUNDLED_GIO],
  });
  assert.deepEqual(appImageRuntimeViolations(appDir), [
    'GIO_MODULE_DIR export 应恰有 1 条，实为 2 条',
  ]);
});

test('缺 GTK hook 时短路返回，不再声称 GIO 契约成立', (t) => {
  const appDir = withAppDir(t, { waylandLibs: [], hook: false });
  assert.deepEqual(appImageRuntimeViolations(appDir), [
    `缺 GTK AppRun hook：${join(appDir, 'apprun-hooks', 'linuxdeploy-plugin-gtk.sh')}`,
  ]);
});

test('冲突库清单本身是判据的一部分：四项且逐字锁定', () => {
  assert.deepEqual([...APPIMAGE_HOST_WAYLAND_LIBS], [
    'libwayland-client.so.0',
    'libwayland-cursor.so.0',
    'libwayland-egl.so.1',
    'libwayland-server.so.0',
  ]);
});
