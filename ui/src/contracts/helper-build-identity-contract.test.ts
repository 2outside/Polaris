/**
 * W24 防回潮：package job 分开编译 helper 与 app，两次 Cargo 调用必须继承同一个 commit build id。
 *
 * 行为侧由 helper-proto/manager 的 Rust 测试覆盖；这里守住 CI 注入点，避免源码逻辑正确、真正出包
 * 却都退回 1.0.0，导致同 protocol 旧 helper 再次无法识别。
 */
import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { productionRsFilesUnder } from './rust-source.test-support';

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const read = (rel: string): string => readFileSync(join(REPO_ROOT, rel), 'utf8');

describe('W24：app/helper 共享出包构建身份', () => {
  it('package job 以 job-level env 把 github.sha 同时注入 helper 与 app', () => {
    const workflow = read('.github/workflows/package.yml');
    const packageStart = workflow.indexOf('\n  package:');
    const releaseStart = workflow.indexOf('\n  release:', packageStart + 1);
    expect(packageStart, 'package job 消失').toBeGreaterThanOrEqual(0);
    const packageJob = workflow.slice(packageStart, releaseStart === -1 ? undefined : releaseStart);

    expect(
      packageJob.includes('env:\n      POLARIS_BUILD_ID: ${{ github.sha }}'),
      'POLARIS_BUILD_ID 必须在 package job 级注入；只放 helper 或 tauri 单步会让两侧身份分叉',
    ).toBe(true);
    expect(packageJob.includes('cargo build --release -p polaris-helper'), 'helper 构建腿消失').toBe(
      true,
    );
    expect(packageJob.includes('uses: tauri-apps/tauri-action@v1'), 'app 构建腿消失').toBe(true);
  });

  it('shared crate 是唯一读取 POLARIS_BUILD_ID 的 Rust 真值点', () => {
    const NEEDLE = 'option_env!("POLARIS_BUILD_ID")';
    /** 唯一合法消费点，以磁盘上的定义处为准（`crates/helper-proto/src/lib.rs:99`）。 */
    const OWNERS = new Set(['crates/helper-proto/src/lib.rs']);

    // 意图面是「helper 侧只有 shared crate 读 build id」，因此取材面必须是 helper 侧 + app 运行时
    // 的**整片生产区**：早先那版逐个登记 5 个模块，只堵住了模块内搬家，任何**跨模块新增**的消费点
    // （例如 `src-tauri/src/runtime/` 下另起一个文件）都在射程外，门恒绿。
    const cratesDir = join(REPO_ROOT, 'crates');
    const helperCrates = readdirSync(cratesDir, { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && entry.name.startsWith('helper'))
      .map((entry) => `crates/${entry.name}`)
      .sort();
    expect(helperCrates, 'crates/helper* 一个都没扫到 —— 取材根被搬走了').not.toEqual([]);

    const files = [...helperCrates, 'src-tauri/src/runtime'].flatMap((root) =>
      productionRsFilesUnder(root),
    );

    // 故障关闭下界：目录改名、过滤条件写错、crate 拆分都会让语料塌掉，而**否定型断言在空语料上恒真**。
    // 阈值 = 建门当日 108 个生产 `.rs` 的六成取整，只兜「塌了」，正常增删不会误报。
    const FLOOR = 64;
    expect(
      files.length,
      `取材面塌了：只扫到 ${files.length} 个生产 .rs（下界 ${FLOOR}）—— 此时「没有别人读 build id」没有信息量`,
    ).toBeGreaterThanOrEqual(FLOOR);

    const consumers = files
      .filter((file) => readFileSync(file, 'utf8').includes(NEEDLE))
      .map((file) => relative(REPO_ROOT, file).replaceAll('\\', '/'))
      .sort();
    expect(consumers, `${NEEDLE} 的真值点消失了 —— 出包身份不再有唯一来源`).toEqual([
      ...OWNERS,
    ]);
  });

  it('升级卡片区分 protocol 落后与同 protocol build 漂移，且不硬编码期望版本', () => {
    const screen = read('ui/src/components/screens/settings/SettingsHelper.tsx');
    expect(screen.includes('status.version < status.expectedProtocolVersion')).toBe(true);
    expect(screen.includes("t('helper.buildVersionMismatch')")).toBe(true);
    expect(screen.includes('required: status.expectedProtocolVersion')).toBe(true);
    expect(screen.includes('required: 3'), 'shared protocol 已是 v1，UI 不得残留 v3 硬编码').toBe(false);
  });
});
