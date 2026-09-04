/**
 * package(all) → reusable CI 的矩阵入口契约。
 *
 * GitHub workflow_call 会继承外层 workflow_dispatch 的 event_name/payload。package.yml 的输入叫
 * `platform`，没有 ci.yml 自身手动入口的 `os`；因此 package(all) 调 CI 时
 * `github.event.inputs.os === ''`。空串若只经过 `!= 'all'` 判定，会被误当成具体平台并生成 `[""]`，
 * 最终是 `runs-on: ""` / labels=[] 的永久 pending job（run 32357370395 的真实失败形态）。
 */

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));

function workflow(name: string): string {
  return readFileSync(join(REPO_ROOT, '.github/workflows', name), 'utf8');
}

/**
 * 取出 `jobs:` 下某个 job 的整段文本（含其注释），从 `\n  <name>:\n` 到下一个同缩进 job 键为止。
 *
 * 为什么必须按 job 切片、而不是对整个文件 `toContain`：判据是「这套 allowlist 挂在**哪个** job 上」。
 * 2026-09-04 打包腿与质量门改并行，两门的 allowlist 从 `package` 搬到了 `release`；如果断言只看
 * 全文，搬家前后同样通过——门在，但对「挂错 job」这件事完全没有牙。
 */
function jobBlock(src: string, name: string): string {
  const start = src.indexOf(`\n  ${name}:\n`);
  if (start < 0) throw new Error(`package.yml 里找不到 job '${name}' —— 取材面塌了，本门此刻没有判据`);
  const rest = src.slice(start + 1);
  const next = rest.slice(1).search(/\n {2}[a-z][a-z0-9_-]*:\n/);
  return next < 0 ? rest : rest.slice(0, next + 1);
}

/**
 * 剥掉整行注释，只留 job 的可执行部分。
 *
 * 为什么必须剥：本文件的判据字符串（`needs.package.result == 'success'` 等）在同一段 YAML 的
 * **解释性注释里也逐字出现**。不剥注释就是「判据被自己污染」——把 `if:` 里的那条判据整行删掉，
 * 断言仍然从注释里读到同一串字而通过。2026-09-04 的变异实测确实出现过这个假绿。
 */
function executable(block: string): string {
  return block
    .split('\n')
    .filter((line) => !/^\s*#/.test(line))
    .join('\n');
}

describe('package 全平台前置 CI 的矩阵输入', () => {
  it('空 os 必须回到完整矩阵，只有显式非 all 的 os 才能走单平台', () => {
    const ci = workflow('ci.yml');
    expect(ci).toMatch(
      /github\.event_name == 'workflow_dispatch'\s*&& github\.event\.inputs\.os != ''\s*&& github\.event\.inputs\.os != 'all'/s,
    );
    expect(ci).toContain(`fromJSON(format('["{0}"]', github.event.inputs.os))`);
    expect(ci).toContain(`fromJSON('["ubuntu-22.04","windows-2022","macos-14"]')`);
  });

  it('package 的 dispatch 输入确实只有 platform，并复用 ci.yml 作全平台门', () => {
    const pkg = workflow('package.yml');
    const dispatch = pkg.slice(pkg.indexOf('workflow_dispatch:'), pkg.indexOf('# 最小权限'));
    expect(dispatch).toContain('platform:');
    expect(dispatch).not.toMatch(/^\s+os:/m);
    expect(pkg).toContain('uses: ./.github/workflows/ci.yml');
    expect(pkg).toContain("needs.setup.outputs.full == 'true'");
    expect(pkg).toContain('inputs.skip_quality_gates != true');
  });

  it('独立门与 Package 复用门必须按调用方隔离并发组，不能互相取消制造假红', () => {
    expect(workflow('ci.yml')).toContain(
      'group: ci-${{ github.workflow }}-${{ github.ref }}',
    );
    expect(workflow('ui.yml')).toContain(
      'group: ui-${{ github.workflow }}-${{ github.ref }}',
    );
  });

  it('切片器本身有效：两个 job 都切得出非平凡的块', () => {
    // 正面自检。少了这条，jobBlock 若因缩进/命名变化退化成空串，下面两条全部真空通过。
    const pkg = workflow('package.yml');
    for (const name of ['package', 'release']) {
      const block = jobBlock(pkg, name);
      expect(block.length, `job '${name}' 的切片过短，取材面可疑`).toBeGreaterThan(200);
      expect(block, `job '${name}' 的切片没包含它自己的 needs`).toContain('needs:');
      // 切片不得越界到下一个 job：package 的块里不该出现 release 的 job 名行。
      expect(block).not.toMatch(/\n {2}(?!$)(?:release|package):\n(?![\s\S]*^$)/m);
    }
  });

  it('发布腿只接受成功或按设计跳过的质量门，取消态不得被当成可放行', () => {
    const pkg = workflow('package.yml');
    const release = executable(jobBlock(pkg, 'release'));

    // 剥注释自检（正面断言）：剥完必须还剩下 if 与 needs，否则下面全是真空通过。
    expect(release, '剥注释后 release 块空了 —— 取材面塌了').toMatch(/^\s+if:/m);
    expect(release).toMatch(/^\s+needs:/m);
    expect(release, '剥注释没生效 —— 块里仍有整行注释').not.toMatch(/^\s*#/m);

    // 判据挂在 release 上（2026-09-04 起打包与门并行，门从 package 下移到发布）。
    expect(release).toContain("needs: [setup, ci, ui, package]");
    expect(release).toContain(
      "needs.ci.result == 'success' || needs.ci.result == 'skipped'",
    );
    expect(release).toContain(
      "needs.ui.result == 'success' || needs.ui.result == 'skipped'",
    );

    // always() 关掉了「needs 全绿才跑」的默认语义，故这条必须被显式写回，否则打包腿挂了也照发。
    expect(release).toContain('always()');
    expect(
      release,
      'release 的 if 里加了 always() 却没显式要求 package 成功 —— 打包腿全挂也会发布',
    ).toContain("needs.package.result == 'success'");

    // cancelled 也满足「不等于 failure」：全文范围内都不许出现这种放行式判据。
    expect(pkg).not.toContain("needs.ci.result != 'failure'");
    expect(pkg).not.toContain("needs.ui.result != 'failure'");
    expect(pkg).not.toContain("needs.package.result != 'failure'");
  });

  it('打包腿与质量门并行：package 不得把 ci/ui 写进 needs（写了就退回串行）', () => {
    const pkg = workflow('package.yml');
    const pkgJob = executable(jobBlock(pkg, 'package'));
    expect(pkgJob, '剥注释后 package 块空了 —— 取材面塌了').toMatch(/^\s+if:/m);
    expect(pkgJob).toContain('needs: [setup]');
    // needs 即等待。package 一旦能读到 needs.ci/needs.ui，就说明它在等两门，并行拓扑已被推翻。
    expect(
      pkgJob,
      'package job 引用了 needs.ci / needs.ui —— 它又串回门后面了',
    ).not.toMatch(/needs\.(ci|ui)\./);
  });
});
