import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const read = (name: string) => readFileSync(join(REPO_ROOT, '.github/workflows', name), 'utf8');

/**
 * 截出一个顶层 job 的段落：`  <name>:` 那行起，到下一个同级 job 头（两空格缩进）为止。
 *
 * 扫描型判据必须先收射程：`/\n  package:[\s\S]*?…/` 从 `package:` 起可以一路延伸到文件尾，
 * 于是「package job 不带 strategy 矩阵」这条否定断言实际问的是「整份 YAML 此后再没有 strategy」——
 * 取材面宽于意图面，同形字面量落在后面任何 job 里都会误红。
 */
const jobSection = (src: string, name: string, file: string) => {
  const lines = src.split('\n');
  const start = lines.findIndex((l) => l === `  ${name}:`);
  expect(start, `${file} 里找不到 job \`${name}\` —— 取材面塌了，本门此刻没有判据`).toBeGreaterThanOrEqual(0);
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^ {2}[A-Za-z_][\w-]*:/.test(lines[i])) {
      end = i;
      break;
    }
  }
  // 切片自检：段边界确实找到了（不是一路吃到文件尾 —— 那就等于没收射程）。
  expect(end, `${file} 的 job \`${name}\` 之后没有同级 job 头，切片延伸到了文件尾`).toBeLessThan(
    lines.length
  );
  return lines.slice(start, end).join('\n');
};

describe('合入前发布风险门', () => {
  const risk = read('release-risk.yml');
  const pkg = read('package.yml');

  it('PR、merge queue 与 main push 均触发，且 workflow 本身不做路径过滤', () => {
    expect(risk).toContain('pull_request:');
    expect(risk).toContain('merge_group:');
    expect(risk).toContain('push:');
    expect(risk).not.toMatch(/^\s+paths(?:-ignore)?:/m);
  });

  it('路径判据由仓库脚本持有，最终 required check 始终运行', () => {
    expect(risk).toContain('node scripts/classify-ci-impact.mjs');
    expect(risk).toContain('name: release risk gate');
    expect(risk).toMatch(/\n  gate:[\s\S]*?\n    if: always\(\)/);
  });

  it('gate 对「未登记影响面」有牙：分类器自曝的 scope 必须当场红并点名', () => {
    // 与 ci-impact-coverage-contract 的完备性门**独立**：那条门在 ui.yml 里跑，ui.yml 挂了/被 skip
    // 就没牙；这条在 release-risk 自己的 required check 里，且 gate 是 `if: always()`。
    // 缺陷类回放：未登记 scope 此前只被 fail-closed 成「内核门 + 四平台」——多花钱但 CI 全绿，
    // 没有任何东西会红，登记表就永远补不上。
    expect(risk).toContain("unregistered=$(jq -r '.unregisteredScopes | join(\" \")' \"$result\")");
    expect(risk).toMatch(/\n\s+unregistered: \$\{\{ steps\.impact\.outputs\.unregistered \}\}/);
    expect(risk).toMatch(/\n\s+UNREGISTERED: \$\{\{ needs\.classify\.outputs\.unregistered \}\}/);
    expect(risk).toMatch(/\[ -z "\$UNREGISTERED" \] \|\| \{\n\s+echo "::error::[^"]*\$UNREGISTERED"; exit 1; \}/);
  });

  it('自动安装包验证复用 Package，但不上传产物也不重复内核门', () => {
    expect(risk).toContain('uses: ./.github/workflows/package.yml');
    expect(risk).toContain('needs: [classify, preflight]');
    expect(risk).toContain("needs.preflight.result == 'success'");
    const pkgJob = jobSection(risk, 'package', 'release-risk.yml');
    // 切片自检：拿到的确实是这个 job，且没有把下一个 job 卷进来。
    expect(pkgJob).toContain('uses: ./.github/workflows/package.yml');
    expect(pkgJob).not.toContain('name: release risk gate');
    expect(pkgJob).toMatch(/permissions:\n\s+contents: write/);
    expect(risk).toContain('run_kernel_gates: false');
    expect(risk).toContain('upload_artifacts: false');
    expect(risk).toContain('platforms: ${{ needs.classify.outputs.platforms }}');
    expect(risk).toContain('skip_quality_gates: true');
    expect(pkgJob).not.toMatch(/\n {4}strategy:/);
    expect(pkg).toContain('workflow_call:');
    expect(pkg).toContain('PLATFORMS_JSON: ${{ inputs.platforms');
    expect(pkg).toContain("if: env.POLARIS_UPLOAD_ARTIFACTS == '1'");
  });

  it('四道随包内核门在 package.yml 与 release-risk.yml 两份定义之间逐条对拍', () => {
    // Rust 侧四条 `ci_step_still_wired`（crates/config-engine/tests/*.rs）只 grep package.yml。
    // 但**合入前路径上真正在跑的是 release-risk.yml 这一份**：删掉它 129-132 里任意一行，
    // 四条 Rust 断言零转红、合入前内核门静默少一道。本条把接线断言扩到两文件。
    const gatesIn = (src: string) => [
      ...new Set(
        [...src.matchAll(/cargo test -p polaris-config-engine --test ([a-z_]+)/g)].map((m) => m[1])
      ),
    ].sort();
    const pkgGates = gatesIn(pkg);
    const riskGates = gatesIn(risk);
    // 取材面自曝：两侧都枚举不到时不许「空集 === 空集」判绿。
    expect(pkgGates.length, 'package.yml 里一道随包内核门都没枚举到 —— 取材面塌了，本门此刻没有判据')
      .toBeGreaterThan(0);
    expect(riskGates, 'release-risk.yml 与 package.yml 的随包内核门清单不一致').toEqual(pkgGates);
    // 强制腿也是双份定义：少了它「核没拉到」会静默跳过而不是红。
    expect(pkg).toContain("POLARIS_REQUIRE_KERNEL_GATE: '1'");
    expect(risk).toContain("POLARIS_REQUIRE_KERNEL_GATE: '1'");
  });

  it('CI 与 UI 都覆盖 merge_group，避免 merge queue 等不到 required check', () => {
    expect(read('ci.yml')).toContain('merge_group:');
    expect(read('ui.yml')).toContain('merge_group:');
  });
});
