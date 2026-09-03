/**
 * CI 影响分类器的**完备性门**（门 4，2026-08-30）。
 *
 * # 背景：一道 fail-open 造出的「绿而零信息量」
 *
 * `scripts/classify-ci-impact.mjs` 枚举「哪些路径影响打包」，其余一律默认无影响。实测后果：改动
 * `crates/system-integration/`、`crates/helper-client/`、`crates/stats-engine/`、
 * `src-tauri/src/runtime/` 时分类器输出 `kernel=false platforms=[] preflight=false hasPackage=false`
 * ⇒ `release-risk.yml` 的 preflight / package 两个 job 全 skip ⇒ gate job 的三条断言（`PREFLIGHT_REQUIRED`
 * / `PACKAGE_REQUIRED` 为 false 时）全不生效 ⇒ **required check 绿，但一个字节的打包信息都没有**。
 *
 * 这不是「这次漏了」：每新增一个 crate、每新建一个 `src-tauri/src` 子树，它就永久落在全部打包门
 * 之外，且没有任何东西会提醒。本门把「有没有判过」与「判成什么」拆开：
 *
 *  - 分类器持有两张表（`PACKAGE_IMPACT_SCOPES` / `NO_PACKAGE_IMPACT_SCOPES`），后者带理由；
 *  - 本门按**文件系统实况**枚举 scope，逐个要求它出现在某张表里 —— 新增 crate ⇒ 硬红；
 *  - 登记根第三条腿 `resources/`（2026-08-30 补）：`resources/data/` 的 28 个 `.srs` 入库且被四份 conf
 *    的 `bundle.resources` 带进每个安装包，而分类器此前对 `resources/**` 输出全 false —— 与 `crates/`、
 *    `src-tauri/` 同一个 fail-open。往 `resources/` 加子目录而不登记，现在同样硬红；
 *  - 分类器自身对登记根内的未登记路径 fail-closed（内核门 + 四平台 + `unregisteredScopes` 自曝），
 *    所以「本门没跑」时默认后果是多花钱，不是静默放行。
 *
 * # 这门抓不到什么（如实登记）
 *
 * - **登记根之外**（`ui/`、`scripts/`、`packaging/`、仓库根文件）没有可枚举边界，本门不做完备性
 *   断言；只用两条反向断言兜住其中风险最高的两类（下面第 4、5 条）：打包 workflow 真正 `run:` 的
 *   脚本、verify-packaging 当判据读的源文件。
 * - **判定内容的对错**：本门只保证「有人显式判过并留了理由」，不保证那句理由是对的。
 *   `crates/x/` 被判成不影响打包而其实影响，本门不会红 —— 这是本门的设计边界，不是漏洞：
 *   判定质量由第 4、5 条（按下游**实际读取面**反推）与 review 覆盖。
 * - **scope 内部的更细粒度**：`src-tauri/src/runtime/` 整体判为不影响（`proxy.rs` 的历史单列例外
 *   已随 F8 消失，见分类器登记表本条注释）。若将来又有 runtime 文件成为打包判据源而没重新单列，
 *   只有第 4 条能抓到它（前提是抓取方是 verify-packaging）。
 * - **YAML / JS 注释剥离**是行级的（只丢整行注释），行尾注释仍会进取材面。方向是「多取」，
 *   失败形态是多要求登记一个脚本，而不是漏掉一个。
 */
import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));

type Impact = {
  kernel: boolean;
  platforms: string[];
  preflight: boolean;
  hasPackage: boolean;
  unregisteredScopes: string[];
};

type Classifier = {
  classifyImpact: (paths: string[], options?: { forceFull?: boolean }) => Impact;
  scopeOf: (path: string) => string | null;
  isScopeRegistered: (scopeKey: string) => boolean;
  ALL_PACKAGE_PLATFORMS: readonly string[];
  REGISTRY_ROOTS: readonly string[];
  PACKAGE_IMPACT_SCOPES: Record<string, { kernel: boolean; platforms: readonly string[]; why: string }>;
  NO_PACKAGE_IMPACT_SCOPES: Record<string, string>;
};

const classifier: Classifier = await import(
  pathToFileURL(join(REPO_ROOT, 'scripts/classify-ci-impact.mjs')).href
);

const {
  classifyImpact,
  scopeOf,
  isScopeRegistered,
  ALL_PACKAGE_PLATFORMS,
  PACKAGE_IMPACT_SCOPES,
  NO_PACKAGE_IMPACT_SCOPES,
} = classifier;

/** 目录 → `<path>/`，文件 → `<path>`；与分类器 `scopeOf` 的归一形态一致。 */
function scopeKeys(relDir: string): string[] {
  return readdirSync(join(REPO_ROOT, relDir), { withFileTypes: true })
    .map((entry) => (entry.isDirectory() ? `${relDir}/${entry.name}/` : `${relDir}/${entry.name}`))
    .sort();
}

/**
 * 文件系统实况：登记根内的全部 scope（`src-tauri/src` 展开一层）。
 *
 * `resources/` 只展开一层：data/ dashboard/ 与四个平台目录各是一个 scope。其中除 data/ 与
 * `.gitkeep` 外全部被 .gitignore（CI 现拉），**在没 fetch 过的机器上根本不在盘上** ⇒ 枚举面
 * 因机器而异。这不削弱本门：枚举到的每一条都必须登记（多枚举 ⇒ 多要求一次登记，方向是严不是松），
 * 而没枚举到的那几条已经预先登记在表里，第 2 条断言照样按分类器实际输出校验它们。
 */
function scopesOnDisk(): string[] {
  const srcTauri = scopeKeys('src-tauri').filter((key) => key !== 'src-tauri/src/');
  return [
    ...scopeKeys('crates'),
    ...srcTauri,
    ...scopeKeys('src-tauri/src'),
    ...scopeKeys('resources'),
  ].sort();
}

/** scope key → 一条落在它内部的探针路径（用来问分类器「你实际怎么判这块」）。 */
function probeOf(key: string): string {
  return key.endsWith('/') ? `${key}__scope_probe__.rs` : key;
}

function compact(paths: string[]) {
  const { kernel, platforms, preflight, hasPackage } = classifyImpact(paths);
  return { kernel, platforms, preflight, hasPackage };
}

/** 行级剥注释：只丢整行注释（`//` `#` `*` 开头），不动行尾 —— 方向是「宁可多取」。 */
function stripLineComments(source: string, kind: 'js' | 'yaml'): string {
  const isComment =
    kind === 'js'
      ? (line: string) => /^\s*(\/\/|\/\*|\*)/.test(line)
      : (line: string) => /^\s*#/.test(line);
  return source
    .split('\n')
    .map((line) => (isComment(line) ? '' : line))
    .join('\n');
}

describe('CI 影响分类器的完备性（fail-open 根治）', () => {
  it('每个 crate / 每个 src-tauri 顶层子树都显式落在两张登记表之一', () => {
    const onDisk = scopesOnDisk();

    // 哨兵：readdir 变哑（空表 / 少读一棵树）在此红，而不是让下面的 for 循环恒真。
    expect(onDisk.length, `枚举到的 scope 太少（${onDisk.length}）—— 枚举器坏了，门在裸奔`).toBeGreaterThan(35);
    for (const known of [
      'crates/system-integration/',
      'crates/helper-client/',
      'crates/stats-engine/',
      'crates/config-engine/',
      'src-tauri/src/runtime/',
      'src-tauri/tauri.conf.json',
      // resources/data/ 的 28 个 .srs 入库且进四个包（见分类器的 PACKAGE_IMPACT_SCOPES）；
      // 它掉出枚举面 = 整个 resources/ 登记根没被扫到，那正是 2026-08-30 前的 fail-open 形态。
      'resources/data/',
    ]) {
      expect(onDisk, `枚举结果里没有 ${known} —— 枚举器的取材面漏了整棵树`).toContain(known);
    }

    // 「算不算已登记」只有分类器那一份实现（含 `foo.rs` ↔ `foo/` 模块别名）。在这里另写一份
    // `new Set(Object.keys(...)).has(key)` 就是同一事实两处实现：本门会因此与真正的分类结果背离
    // —— 门说「没登记」而分类器说「登记了」，或者反过来（后者是静默放行）。
    const missing = onDisk.filter((key) => !isScopeRegistered(key));
    expect(
      missing,
      `这些 scope 在 scripts/classify-ci-impact.mjs 的两张表里都没有：\n` +
        missing.map((key) => `  · ${key}`).join('\n') +
        `\n新增 crate / 新建 src 子树时必须显式判一次：影响打包 ⇒ 写进 PACKAGE_IMPACT_SCOPES` +
        `（带 kernel / platforms）；不影响 ⇒ 写进 NO_PACKAGE_IMPACT_SCOPES 并附一句理由。` +
        `不判的默认后果是分类器 fail-closed 成内核门 + 四平台。`,
    ).toEqual([]);
  });

  it('登记表不是装饰：每条登记的判定必须等于分类器对该 scope 的实际输出', () => {
    // 表里写「四平台」而分类器实际什么都不加（或反过来），在这里红。
    // 没有这条，两张表就退化成注释——注释对执行没有强制力。
    expect(Object.keys(PACKAGE_IMPACT_SCOPES).length).toBeGreaterThan(20);
    expect(Object.keys(NO_PACKAGE_IMPACT_SCOPES).length).toBeGreaterThan(30);

    for (const [key, decision] of Object.entries(PACKAGE_IMPACT_SCOPES)) {
      const actual = compact([probeOf(key)]);
      expect(actual.kernel, `PACKAGE_IMPACT_SCOPES['${key}'].kernel 与实际分类不一致`).toBe(
        decision.kernel,
      );
      expect(actual.platforms, `PACKAGE_IMPACT_SCOPES['${key}'].platforms 与实际分类不一致`).toEqual(
        ALL_PACKAGE_PLATFORMS.filter((platform) => decision.platforms.includes(platform)),
      );
      expect(
        decision.why.length,
        `PACKAGE_IMPACT_SCOPES['${key}'] 缺少可读的判据（why）`,
      ).toBeGreaterThan(10);
    }

    for (const [key, why] of Object.entries(NO_PACKAGE_IMPACT_SCOPES)) {
      expect(
        compact([probeOf(key)]),
        `NO_PACKAGE_IMPACT_SCOPES['${key}'] 声称不影响打包，但分类器对它加了腿/内核门 —— 两者必须同真值`,
      ).toEqual({ kernel: false, platforms: [], preflight: false, hasPackage: false });
      expect(why.length, `NO_PACKAGE_IMPACT_SCOPES['${key}'] 的理由太短，等于没判`).toBeGreaterThan(10);
    }
  });

  it('登记根内的未登记路径 fail-closed 为内核门 + 四平台，并在输出里自曝', () => {
    // 「本门没跑 / 有人绕过本门」时的兜底：默认后果必须是多花钱，不是静默放行。
    for (const [probe, scope] of [
      ['crates/__not_registered__/src/lib.rs', 'crates/__not_registered__/'],
      ['src-tauri/src/__not_registered__/mod.rs', 'src-tauri/src/__not_registered__/'],
      ['src-tauri/__not_registered__.json', 'src-tauri/__not_registered__.json'],
      ['resources/__not_registered__/x.srs', 'resources/__not_registered__/'],
    ]) {
      const result = classifyImpact([probe]);
      expect(scopeOf(probe), `scopeOf('${probe}') 归一结果与预期 scope 不一致`).toBe(scope);
      expect(result.kernel, `${probe} 未登记却没触发内核门`).toBe(true);
      expect(result.platforms, `${probe} 未登记却没触发四平台`).toEqual([...ALL_PACKAGE_PLATFORMS]);
      expect(
        result.unregisteredScopes,
        `${probe} 未登记却没进 unregisteredScopes —— 「为什么这次全量」在日志里读不出来`,
      ).toEqual([scope]);
    }

    // 反向对照：已登记的路径不得进自曝表（否则上面那条恒真，等于没检查）。
    expect(classifyImpact(['crates/stats-engine/src/lib.rs']).unregisteredScopes).toEqual([]);
    expect(classifyImpact(['resources/data/geosite-cn.srs']).unregisteredScopes).toEqual([]);
  });

  it('真实 `.srs` 资源变更必须点亮完整配置真核门所需的 release-risk 路径', () => {
    // 这不是只验证「resources/data 已登记」：完整配置门现在让 sing-box 真读 route.rule_set 的
    // `.srs`，故分类为 kernel=false 会令 release-risk 跳过 Fetch core/cronet 与 mandatory gates。
    expect(compact(['resources/data/geosite-cn.srs'])).toEqual({
      kernel: true,
      platforms: [...ALL_PACKAGE_PLATFORMS],
      preflight: true,
      hasPackage: true,
    });
  });

  it('verify-packaging 当判据读的每个 src-tauri 源文件都必须触发打包腿', () => {
    // 根因形态：判据的**消费者**（verify-packaging.mjs）在影响表里，判据的**来源**却不在。
    // 历史形态：改 proxy.rs 的 LINUX_BUNDLE_PRODUCT_DIR 不触发任何腿，confs 门要等下一次真打包才炸。
    // 那个常量已随 F8 消失（productName 由 build.rs 注入，事实只剩一份），但本门要守的是**类**，
    // 不是那一个文件：今天的取材面是 build.rs 的 EXPECTED_SRS_COUNT + 两份 conf。
    const source = stripLineComments(
      readFileSync(join(REPO_ROOT, 'scripts/verify-packaging.mjs'), 'utf8'),
      'js',
    );

    // 切片自检：注释里确实提到过别的源文件路径，剥干净了才轮到下面的断言说话。
    expect(
      source.includes('crates/updater/src/github.rs'),
      '注释剥离失效：这个路径只出现在 verify-packaging.mjs 的注释里，却仍留在取材面上',
    ).toBe(false);

    const reads = [
      ...source.matchAll(/(?:join|resolve|readJson|readFileSync)\(\s*SRC_TAURI\s*,\s*'([^']+)'/g),
    ].map((match) => `src-tauri/${match[1]}`);

    // 哨兵：抓取器变哑（空表 / 漏条）在此红，否则下面的 for 恒真。
    // 取「必须包含」而非逐字等值：新增一处读取由下面的 for 直接判（不登记就红），不必回来改哨兵；
    // 而某处读取**消失**仍会在这里红一次，逼作者确认那条不变量是真没了、还是搬了家。
    for (const known of [
      'src-tauri/build.rs',
      'src-tauri/tauri.conf.json',
      'src-tauri/core-manifest.json',
    ]) {
      expect(
        [...new Set(reads)].sort(),
        `抓取器没读到 ${known} —— 要么它变哑了（门在裸奔，先修抓取器），` +
          '要么 verify-packaging.mjs 真的不再读它（那么本哨兵该跟着改）',
      ).toContain(known);
    }

    for (const path of new Set(reads)) {
      expect(
        classifyImpact([path]).hasPackage,
        `${path} 是 verify-packaging confs 的判据源，但改它不触发任何打包腿 —— ` +
          `release-risk.yml 的「Verify packaging conf invariants」步骤条件是 has_package == 'true'，` +
          `不加腿就等于这条不变量在合入前从不被检查`,
      ).toBe(true);
    }
  });

  it('打包 workflow 真正执行的每个仓库脚本都必须触发打包腿', () => {
    // 同一个 fail-open 在 scripts/ 的姊妹腿：package.yml 真跑 `node scripts/fetch-protoc.mjs`，
    // 而它 2026-08-30 前不在任何表里 —— 改坏它，合入前零信号，打包链在发布时才断。
    const invoked = new Map<string, string>();
    for (const workflow of ['package.yml', 'release-risk.yml']) {
      const raw = readFileSync(join(REPO_ROOT, '.github/workflows', workflow), 'utf8');
      const source = stripLineComments(raw, 'yaml');
      if (workflow === 'package.yml') {
        // 切片自检：这句只在注释里出现，剥干净了取材面才是「真跑的命令」。
        expect(
          source.includes('root cause：此前每次 main push'),
          'YAML 注释剥离失效：整行注释仍留在取材面上',
        ).toBe(false);
      }
      for (const match of source.matchAll(
        /(?:^|[\s;&|(`])(?:node|sh|bash)\s+(?:--test\s+)?(scripts\/[A-Za-z0-9._-]+)/g,
      )) {
        invoked.set(match[1], workflow);
      }
    }

    // 哨兵：抓取器变哑在此红（空表会让下面的 for 恒真）。
    expect([...invoked.keys()].sort()).toEqual([
      'scripts/classify-ci-impact.mjs',
      'scripts/fetch-core.mjs',
      'scripts/fetch-cronet.mjs',
      'scripts/fetch-dashboard.mjs',
      'scripts/fetch-protoc.mjs',
      'scripts/gate-node-test.sh',
      'scripts/postprocess-appimage.mjs',
      'scripts/verify-packaging.mjs',
    ]);

    for (const [script, workflow] of invoked) {
      expect(
        classifyImpact([script]).hasPackage,
        `${workflow} 里真跑 ${script}，但改它不触发任何打包腿 —— 打包链的一环没有合入前信号`,
      ).toBe(true);
    }
  });
});
