#!/usr/bin/env node
/**
 * 修正 Tauri 2.11 AppImage 在新发行版上的图形栈兼容性，再用 Tauri 已下载的官方输出插件重封。
 *
 * 根因（Ubuntu 26.04 + Mesa 25 真机复现）：linuxdeploy 把构建机的 libwayland-* 一并塞进 AppImage，
 * 运行时却加载宿主 Mesa/EGL；新 Mesa 与旧 Wayland ABI 混用后 WebKitWebProcess 以 EGL_BAD_PARAMETER
 * 退出。与此同时 GTK hook 只设置 GIO_EXTRA_MODULES，GLib 仍会加载宿主 GVfs module，旧 bundled
 * GLib 遇到新 GVfs 符号会报 undefined symbol。
 *
 * 最小修复：只让四个 Wayland 基础库回到宿主版本，并把 GIO module 搜索根锁在 AppDir 内。
 * bundled WebKitGTK/GTK/GLib 其余部分全部保留；不把 AppImage 退化成依赖宿主 WebKitGTK 的第二份 deb。
 *
 * 用法：
 *   node scripts/postprocess-appimage.mjs \
 *     --root target/release/bundle/appimage \
 *     --tool "$HOME/.cache/tauri/linuxdeploy-plugin-appimage.AppImage" \
 *     --arch x86_64
 */

import {
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'fs';
import { spawnSync } from 'child_process';
import { basename, dirname, join, resolve } from 'path';
import { fileURLToPath } from 'url';

export const APPIMAGE_HOST_WAYLAND_LIBS = Object.freeze([
  'libwayland-client.so.0',
  'libwayland-cursor.so.0',
  'libwayland-egl.so.1',
  'libwayland-server.so.0',
]);

const GIO_EXTRA_PREFIX = 'export GIO_EXTRA_MODULES=';
const GIO_DIR_PREFIX = 'export GIO_MODULE_DIR=';

function argOf(flag) {
  const index = process.argv.indexOf(flag);
  return index >= 0 && index + 1 < process.argv.length ? process.argv[index + 1] : null;
}

function oneEntry(root, suffix, kind) {
  const matches = readdirSync(root, { withFileTypes: true }).filter((entry) => {
    if (!entry.name.endsWith(suffix)) return false;
    return kind === 'dir' ? entry.isDirectory() : entry.isFile();
  });
  if (matches.length !== 1) {
    throw new Error(`${root} 中应恰有 1 个 ${suffix} ${kind === 'dir' ? '目录' : '文件'}，实为 ${matches.length} 个：${matches.map((e) => e.name).join(', ')}`);
  }
  return join(root, matches[0].name);
}

function exportLines(source, prefix) {
  return source
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.startsWith(prefix));
}

/**
 * 返回 AppDir 运行时兼容契约的全部违反；后处理脚本与 verify-packaging 共用，避免两份判据漂移。
 */
export function appImageRuntimeViolations(appDir) {
  const violations = [];
  const libDir = join(appDir, 'usr', 'lib');
  for (const name of APPIMAGE_HOST_WAYLAND_LIBS) {
    if (existsSync(join(libDir, name))) {
      violations.push(`AppDir 仍捆绑 ${name}（会与新宿主 Mesa/EGL 混用）`);
    }
  }

  const hook = join(appDir, 'apprun-hooks', 'linuxdeploy-plugin-gtk.sh');
  if (!existsSync(hook)) {
    violations.push(`缺 GTK AppRun hook：${hook}`);
    return violations;
  }
  const source = readFileSync(hook, 'utf8');
  const extra = exportLines(source, GIO_EXTRA_PREFIX);
  const moduleDir = exportLines(source, GIO_DIR_PREFIX);
  if (extra.length !== 1) violations.push(`GIO_EXTRA_MODULES export 应恰有 1 条，实为 ${extra.length} 条`);
  if (moduleDir.length !== 1) violations.push(`GIO_MODULE_DIR export 应恰有 1 条，实为 ${moduleDir.length} 条`);
  if (extra.length === 1 && moduleDir.length === 1) {
    const extraRhs = extra[0].slice(GIO_EXTRA_PREFIX.length);
    const moduleRhs = moduleDir[0].slice(GIO_DIR_PREFIX.length);
    if (extraRhs !== moduleRhs) {
      violations.push(`GIO_MODULE_DIR 必须与 bundled GIO_EXTRA_MODULES 指向同一目录：${moduleRhs} != ${extraRhs}`);
    }
    const unquoted = moduleRhs.replace(/^(["'])(.*)\1$/, '$2');
    if (!unquoted.startsWith('$APPDIR/')) {
      violations.push(`GIO_MODULE_DIR 必须锚在 $APPDIR 内，实为 ${moduleRhs}`);
    } else {
      const resolved = join(appDir, unquoted.slice('$APPDIR/'.length));
      if (!existsSync(resolved) || !statSync(resolved).isDirectory()) {
        violations.push(`GIO_MODULE_DIR 指向的 bundled 目录不存在：${resolved}`);
      }
    }
  }
  return violations;
}

function patchGtkHook(appDir) {
  const hook = join(appDir, 'apprun-hooks', 'linuxdeploy-plugin-gtk.sh');
  if (!existsSync(hook)) throw new Error(`缺 GTK AppRun hook：${hook}`);
  const source = readFileSync(hook, 'utf8');
  const extra = exportLines(source, GIO_EXTRA_PREFIX);
  if (extra.length !== 1) {
    throw new Error(`无法安全修补 GTK hook：GIO_EXTRA_MODULES export 应恰有 1 条，实为 ${extra.length} 条`);
  }
  const desired = `${GIO_DIR_PREFIX}${extra[0].slice(GIO_EXTRA_PREFIX.length)}`;
  const current = exportLines(source, GIO_DIR_PREFIX);
  if (current.length === 1 && current[0] === desired) return false;
  if (current.length !== 0) {
    throw new Error(`无法安全修补 GTK hook：已有非预期 GIO_MODULE_DIR export：${current.join(' | ')}`);
  }
  const marker = extra[0];
  const occurrences = source.split(marker).length - 1;
  if (occurrences !== 1) {
    throw new Error(`无法安全修补 GTK hook：目标行出现 ${occurrences} 次（期望 1）`);
  }
  writeFileSync(hook, source.replace(marker, `${marker}\n${desired}`));
  return true;
}

function main() {
  const rootArg = argOf('--root');
  const toolArg = argOf('--tool');
  const arch = argOf('--arch');
  if (!rootArg || !toolArg || !arch) {
    console.error('用法: node scripts/postprocess-appimage.mjs --root <bundle/appimage> --tool <linuxdeploy-plugin-appimage.AppImage> --arch <x86_64>');
    process.exit(2);
  }

  const root = resolve(rootArg);
  const tool = resolve(toolArg);
  if (!existsSync(root) || !statSync(root).isDirectory()) throw new Error(`AppImage 产物目录不存在：${root}`);
  if (!existsSync(tool) || !lstatSync(tool).isFile()) throw new Error(`Tauri AppImage 输出插件不存在：${tool}`);

  const appDir = oneEntry(root, '.AppDir', 'dir');
  const artifact = oneEntry(root, '.AppImage', 'file');
  const libDir = join(appDir, 'usr', 'lib');
  for (const name of APPIMAGE_HOST_WAYLAND_LIBS) {
    const path = join(libDir, name);
    if (existsSync(path)) {
      if (lstatSync(path).isDirectory()) throw new Error(`拒绝删除非文件的冲突项：${path}`);
      unlinkSync(path);
      console.log(`removed: ${path}`);
    }
  }
  const hookChanged = patchGtkHook(appDir);
  console.log(`GTK hook: ${hookChanged ? '已补 GIO_MODULE_DIR' : '已有正确 GIO_MODULE_DIR'}`);

  const violations = appImageRuntimeViolations(appDir);
  if (violations.length > 0) throw new Error(`AppDir 兼容契约未成立：\n  - ${violations.join('\n  - ')}`);

  const temporary = join(dirname(artifact), `.${basename(artifact)}.postprocess.AppImage`);
  if (existsSync(temporary)) throw new Error(`拒绝覆盖上次失败残件：${temporary}`);
  try {
    const run = spawnSync(tool, [`--appdir=${appDir}`], {
      env: {
        ...process.env,
        APPIMAGE_EXTRACT_AND_RUN: '1',
        ARCH: arch,
        LDAI_OUTPUT: temporary,
      },
      stdio: 'inherit',
    });
    if (run.error) throw run.error;
    if (run.status !== 0) throw new Error(`AppImage 重封失败：输出插件退出码 ${run.status}`);
    if (!existsSync(temporary) || statSync(temporary).size < 1024 * 1024) {
      throw new Error(`AppImage 重封结果缺失或异常小：${temporary}`);
    }
    renameSync(temporary, artifact);
  } finally {
    if (existsSync(temporary)) unlinkSync(temporary);
  }
  console.log(`ok: AppImage host graphics compatibility → ${artifact} (${statSync(artifact).size} bytes)`);
}

const invoked = process.argv[1] ? resolve(process.argv[1]) : '';
if (invoked === fileURLToPath(import.meta.url)) main();
