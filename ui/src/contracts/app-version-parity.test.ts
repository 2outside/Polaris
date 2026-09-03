/**
 * 应用版本号的**两处独立定义**必须逐字相等。
 *
 * # 两份真值各喂谁
 *
 *  - 工作区 `Cargo.toml` 的 `version` → `env!("CARGO_PKG_VERSION")` → 订阅 User-Agent
 *    （`commands/subscription.rs`）、`--version` 输出（`main.rs`）、启动日志、HTTP UA。
 *  - `src-tauri/tauri.conf.json` 的 `version` → Tauri 的 `package_info().version` → `version_get_info`
 *    回给「关于」页的 appVersion、备份文件里的 appVersion，以及安装包/bundle 版本。
 *
 * 两者互不引用，改一处漏另一处**不会有任何东西转红**：装出来的包写 1.0.1、关于页也写 1.0.1，
 * 而 UA 与 `--version` 仍是 1.0.0（或反过来）。发版时这正是最容易漏的一格。
 *
 * # 为什么是这道门而不是「合成一处」
 *
 * Tauri 2 的 conf 里 `version` 缺省才回落 Cargo 版本；删掉它属于 runtime 行为改动（bundle 版本来源换轨），
 * 不在门整改批的射程内。故先加对拍：两处不等即红，并把不等的具体值打出来。
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const read = (rel: string) => readFileSync(join(REPO_ROOT, rel), 'utf8');

/** 工作区根 `[workspace.package]` 段里的 `version = "x.y.z"`。 */
function cargoWorkspaceVersion(): string | null {
  const src = read('Cargo.toml');
  const section = src.match(/\n\[workspace\.package\]\n([\s\S]*?)(?=\n\[|$)/)?.[1];
  if (!section) return null;
  return section.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1] ?? null;
}

describe('应用版本号对拍', () => {
  it('Cargo 工作区版本与 tauri.conf.json 版本逐字相等', () => {
    const cargo = cargoWorkspaceVersion();
    // 取材面自曝：任一侧读不出来时不许拿 undefined === undefined 判绿。
    expect(cargo, 'Cargo.toml 的 [workspace.package] version 未解析到 —— 本门此刻没有判据').toMatch(
      /^\d+\.\d+\.\d+/
    );
    const conf = (JSON.parse(read('src-tauri/tauri.conf.json')) as { version?: string }).version;
    expect(conf, 'tauri.conf.json 缺 version 字段 —— 本门此刻没有判据').toMatch(/^\d+\.\d+\.\d+/);
    expect(
      conf,
      `版本号两处定义不一致：Cargo.toml=${cargo} / tauri.conf.json=${conf}。` +
        'UA、--version 与启动日志走前者，关于页 appVersion、备份 appVersion 与安装包版本走后者'
    ).toBe(cargo);
  });
});
