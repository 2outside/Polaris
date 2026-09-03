/**
 * UserConfig 写入口接线守卫 —— 钉死「**每一个**写 config 的调用点都被显式分过类」。
 *
 * # 为什么必须是源码结构守卫（逻辑单测替代不了）
 *
 * `lib/staged-config.test.ts` 那一批一直是绿的：`editRoute` 的三张表、重放、撤销、冲突全都对。
 * 而 `~/docs/polaris/design/polaris-userconfig-write-entrypoints-2026-07-29.md` 盘出来的事实是
 * **100+ 个写 config 的调用点里只有 1 个查过 `editRoute`**——判据正确与判据被调用是两件事，
 * 前者有测、后者一条门都没有。该文最后一段点名的风险正是这条：
 *
 * > 新增任何一个写入口都会**静默**漏掉闸门（没有任何门会因此转红）。
 *
 * 本文件就是那盏红灯。判据面 = 所有能把字节写进 `config.json` 的前端调用形态（下方 `PATTERNS`），
 * 每一个扫到的 `(文件, 被调方法)` 必须在 `SITES` 表里有一行，并带一个**说得出因由**的去向。
 * 表里有、树上没有 ⇒ 也红（陈旧登记同样危险：它会让人以为某个入口还在被管辖）。
 *
 * # 为什么闸门挂调用点、而不是像 commit `3db36c7` 那样挂广播回声腿
 *
 * 那份 handoff 的结论「闸门不能挂调用点」管的是**路由判定**——它举的 `SettingsNetwork.tsx:179`
 * 一个调用点跨 `mixedPort`(Class B) / `controlPort`(Class A) 两个 class，确实不能在调用点手写 if。
 * 那条已经解决了：路由判定收口在 `editRoute` 单点，设置页那 46 个调用点全部经 `useConfig().update`
 * 漏斗**按键**在运行期判（`config-patch-route.ts`），调用点一个 class 判定都不写。
 *
 * 剩下的另一半——**生成一条有标签的 `StagedEntry`**（「编辑节点 香港 IEPL 01」）——只有编辑点知道：
 * Rust 侧的收口点看得见的只是「一份新 config」，造不出「用户刚才想干什么」这条意图。
 * 所以逐入口接是必要的，代价就是本文件。
 *
 * # 守的是形态不是措辞
 *
 * 断言落在「哪个文件调了哪个写方法 / 该文件有没有经 `editRoute` 分流」这类结构事实上；
 * 改注释、改文案、改变量命名不会误伤，新增/挪走一个写入口则必然转红。
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

import { STAGED_CONFIG_ENABLED, editRoute } from '@/lib/staged-config';
import { USER_CONFIG_FIELDS } from '@/contracts/user-config-fields';

const SRC = fileURLToPath(new URL('..', import.meta.url));

// ─────────────────────────────── 扫描器 ───────────────────────────────

/**
 * 去掉注释、**但保留行号**（把注释体换成等量空白，不是删掉）——报错要能指回真实行。
 *
 * 两个方向都必要：本仓注释习惯逐字引用被禁的旧形态（本文件头就写着 `SettingsNetwork.tsx:179`），
 * 扫原文会被说明文字误伤；反过来只在注释里提一句 `editRoute` 就能让正向断言变绿，那是假绿。
 * `[^:]` 前瞻避免把 `https://` 当行注释切掉。
 */
function code(src: string): string {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/(^|[^:])\/\/.*$/gm, (m, p1: string) => p1 + ' '.repeat(m.length - p1.length));
}

/** 递归收集产品代码（跳过测试自身，否则本文件里的示例串会污染扫描面）。 */
function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) sourceFiles(p, out);
    else if (/\.tsx?$/.test(e.name) && !/\.(test|spec)\.tsx?$/.test(e.name)) out.push(p);
  }
  return out;
}

/**
 * 判据面 —— 前端能把字节写进 `config.json` 的**全部**形态，按 handoff 的 W-a..W-d 分组。
 *
 * `W-e`（Rust 侧自主写：自动换节点 / 备份导入 / 订阅自动更新）结构上不经前端 config 对象，
 * 且**全部不是「用户在 UI 上的编辑意图」**，故不在本守卫射程；它们由 Rust 侧自己的门管。
 */
const PATTERNS: ReadonlyArray<readonly [string, RegExp]> = [
  // W-a：设置页漏斗。只认对象字面量实参 —— `update(idx, next)` 那种同名的列表编辑器局部函数不是写 config。
  ['W-a', /(?<![.\w$])update\s*\(\s*\{/g],
  // W-b：通用 config 写（版本化整份 save / 原子 patch / 实体事务 / store 包装）。
  ['W-b', /(?:\b(?:api\.config|configApi)\s*\.\s*(?:save|patch|mutateEntities)|\b(?:saveConfig|mutateConfigEntities))\s*\(/g],
  // W-d：专用 IPC 写腿 —— 前端发的是「加一个节点」而不是「写 servers 键」，但落盘的是同一份 config。
  [
    'W-d',
    /\b(?:api\.(?:server|rules|subscription|ruleResources)|(?:server|rules|subscription|ruleResources)Api)\s*\.\s*(?:add|addBulk|createStart|update|updateServers|delete|deleteBatch|reorder|switch|registerWarp|applyWarpLicense|download|redownload|cancel|resetBuiltin|setAutoUpdate|updateAll|tailscaleLogin|tailscaleLogout|tailscaleLoginCancel)\s*\(/g,
  ],
];

interface Hit {
  readonly file: string;
  /** 被调方法的归一化写法（去空白），如 `api.server.add(`。`(文件, 方法)` 是本守卫的登记粒度。 */
  readonly callee: string;
  readonly line: number;
  readonly tag: string;
}

/**
 * 登记粒度取 `(文件, 方法)` 而**不是** `文件:行号`：行号随任何无关编辑漂移，会把守卫变成每次改动
 * 都要重刷的噪音表（噪音表的下场是被人整体重刷，等于没门）。代价是「同一文件里第二次调同一个写方法」
 * 不转红 —— 那一格由「同文件同方法归属同一去向」兜住：真要换去向必然得改这一行登记。
 */
function scan(): Hit[] {
  const hits: Hit[] = [];
  for (const p of sourceFiles(SRC)) {
    // api-client（barrel + 按域拆分的 ipc/api/ 目录）是这些方法的**定义**处，不是调用点。
    if (p.endsWith(join('ipc', 'api-client.ts')) || p.includes(join('ipc', 'api') + '/')) continue;
    const src = code(readFileSync(p, 'utf8'));
    for (const [tag, re] of PATTERNS) {
      for (const m of src.matchAll(re)) {
        hits.push({
          file: p.slice(SRC.length).split(/[\\/]/).join('/'),
          callee: m[0].replace(/\s+/g, ''),
          line: src.slice(0, m.index).split('\n').length,
          tag,
        });
      }
    }
  }
  return hits;
}

const FILES = sourceFiles(SRC);
const HITS = scan();

/**
 * **自曝纪律**（模块加载期就抛，不留给断言）：扫空了 / 过滤过头 ⇒ 下面每一条断言都会变成空跑恒绿，
 * 而那正是本守卫要防的那种「没有任何门会转红」。抛出来比绿着更诚实。
 */
if (FILES.length < 100) throw new Error(`接线守卫扫不到源码（只收到 ${FILES.length} 个文件）`);
if (HITS.length < 90) throw new Error(`接线守卫只扫到 ${HITS.length} 个写入口，判据面已失配`);

const SOURCE = new Map(FILES.map((p) => [p.slice(SRC.length).split(/[\\/]/).join('/'), code(readFileSync(p, 'utf8'))]));

// ─────────────────────────────── 去向登记表 ───────────────────────────────

/**
 * - `funnel` —— 经 `useConfig().update` 漏斗，路由在漏斗里**按键**判（调用点不写任何 class 判定）。
 * - `staged` —— 调用点自身经 `editRoute(...) === 'staged'` 分流，命中即只产生一条 `StagedEntry`。
 * - `direct` —— **豁免或绕过**：Class A（键 ∉ `UserConfig`）或 W-1/W-2/W-3。理由必须点名谓词。
 * - `blocked` —— **既不豁免也不绕过，本该进暂存但现契约表达不了**。与 `direct` 分开正是为了不让
 *   「做不到」伪装成「不该做」：这几行是欠账清单，不是白名单。
 * - `primitive` —— 写原语/暂存层自身的落盘腿，闸门在它上游。
 */
type Route = 'funnel' | 'staged' | 'direct' | 'blocked' | 'primitive';

interface Site {
  readonly file: string;
  readonly callee: string;
  readonly route: Route;
  /** 为什么是这个去向。`direct` 必须点名 W-0/Class A 或 W-1/W-2/W-3；`blocked` 必须写清卡在哪。 */
  readonly why: string;
}

const SITES: readonly Site[] = [
  // ── W-a：设置子页与 DNS 资源工作区共用 `useConfig().update` 漏斗 ──
  // 漏斗按键判是硬要求而非风格：`SettingsNetwork` 的 `update({ [key]: next })` 一个调用点跨
  // `mixedPort`(Class B) / `controlPort`(Class A) 两个 class，静态判必错一半。
  ...(
    [
      'components/screens/settings/SettingsDisplay.tsx',
      'components/screens/settings/SettingsDns.tsx',
      'components/screens/settings/SettingsGeneral.tsx',
      'components/screens/settings/SettingsNetwork.tsx',
      'components/screens/settings/SettingsTun.tsx',
      'components/screens/settings/SettingsUpdate.tsx',
      'components/screens/settings/AppUpdateCard.tsx',
      'components/screens/settings/CoreUpdateCard.tsx',
      'components/dialogs/DnsResourceDialog.tsx',
      'components/screens/rules/DnsPolicyWorkspace.tsx',
    ] as const
  ).map((file): Site => ({
    file,
    callee: 'update({',
    route: 'funnel',
    why: '经 useConfig().update 漏斗，逐键走 splitPatchByRoute → editRoute；调用点不做 class 判定',
  })),

  // ── W-b：通用 config 写 ──
  {
    file: 'components/screens/home/HomeScreen.tsx',
    callee: 'saveConfig(',
    route: 'direct',
    why: 'W-1 切节点（直连哨兵写 selectedServerId）+ W-2 系统代理接管（proxyModeType 有 OS 活态回读）；同批被 applyFakeIpTunEntry 连带纠正的 dnsConfig 是这次原子模式切换的一半，拆开暂存会让 UI 与 OS 活态分叉',
  },
  {
    file: 'components/screens/logs/LogsScreen.tsx',
    callee: 'saveConfig(',
    route: 'staged',
    why: 'logLevel 是 UserConfig 字段（Class B，喂 sing-box log.level 需重启核）',
  },
  {
    file: 'components/screens/rules/RulesScreen.tsx',
    callee: 'saveConfig(',
    route: 'staged',
    why: 'regionRouting 是 UserConfig 字段（Class B）',
  },
  {
    file: 'components/screens/settings/use-config.ts',
    callee: 'configApi.patch(',
    route: 'funnel',
    why: '漏斗自身的直写腿：只把 direct 顶层字段原子合入后端最新配置',
  },
  {
    file: 'store/app-store.ts',
    callee: 'api.config.patch(',
    route: 'primitive',
    why: '即时补丁原语（saveConfig 本体），只提交调用点明确变动的顶层字段',
  },
  {
    file: 'store/app-store.ts',
    callee: 'api.config.mutateEntities(',
    route: 'primitive',
    why: '集合实体事务原语：在后端最新数组上按主键提交，并让同批多实体全成或全不成',
  },
  {
    file: 'store/app-store.ts',
    callee: 'saveConfig(',
    route: 'direct',
    why: 'W-1 分流模式切换复用即时顶层 patch，并由主页 routingBusy 保持用户动作顺序',
  },
  {
    file: 'store/staged-config-store.ts',
    callee: 'api.config.save(',
    route: 'primitive',
    why: '暂存层自己的「保存」腿：把 staged 重放到磁盘现值后落盘',
  },
  {
    file: 'tray/TrayMenu.tsx',
    callee: 'api.config.patch(',
    route: 'direct',
    why: 'W-1 模式/出口与 W-2 系统代理接管：只提交本动作字段；托盘虽是独立 webview，未提交字段仍由后端锁内保留',
  },

  {
    file: 'components/dialogs/AppAddDialog.tsx',
    callee: 'mutateConfigEntities(',
    route: 'staged',
    why: 'customAppPresets Class B；暂存关闭时仍按 id 在后端最新集合上追加，避免旧数组覆盖',
  },
  {
    file: 'components/screens/app-policy/AppPolicyScreen.tsx',
    callee: 'mutateConfigEntities(',
    route: 'staged',
    why: 'appRules / customAppPresets 均为 Class B；删除预设与关联规则在同一实体事务内原子提交',
  },
  {
    file: 'components/screens/app-policy/AppPolicyScreen.tsx',
    callee: 'saveConfig(',
    route: 'staged',
    why: 'appRoutingEnabled 是 Class B；暂存关闭时标量经原子顶层 patch 提交',
  },

  // 旧 W-c（裸 setValue/updateMode）已清零：标量统一走 patch，集合统一走实体事务。

  // ── W-d：专用 IPC 写腿 —— servers 族 ──
  {
    file: 'components/dialogs/NodeDialog.tsx',
    callee: 'api.server.add(',
    route: 'staged',
    why: 'servers 是 UserConfig 首字段（Class B），表单提交的就是整个 ServerConfig，天然满足重放要求的幂等整体替换',
  },
  {
    file: 'components/dialogs/NodeDialog.tsx',
    callee: 'api.server.update(',
    route: 'staged',
    why: 'servers Class B；编辑提交的同样是整个 ServerConfig（base 起底保全非模型字段）',
  },
  {
    file: 'components/dialogs/WgDialog.tsx',
    callee: 'api.server.add(',
    route: 'staged',
    why: 'servers Class B；手填 / 粘贴 .conf 两条来源都无远端副作用',
  },
  {
    file: 'components/dialogs/WgDialog.tsx',
    callee: 'api.server.update(',
    route: 'staged',
    why: 'servers Class B；编辑 WG 节点同样无远端副作用',
  },
  {
    file: 'components/dialogs/ImportDialog.tsx',
    callee: 'api.server.addBulk(',
    route: 'staged',
    why: 'servers Class B；解析在 localImport.parse 已完成，addBulk 本身是纯 servers 写 ⇒ 逐节点一条条目',
  },
  {
    file: 'components/dialogs/TsSettingsDialog.tsx',
    callee: 'api.server.update(',
    route: 'staged',
    why: 'servers Class B；写的是该节点的 tailscaleSettings，没有远端副作用（弹窗里从活态回读的只是出口候选列表，不是被写的字段）',
  },
  {
    // cloneServer（含这个调用点）2026-08-30 随 5B 拆分外提到 use-node-actions.ts，登记表跟着落点走。
    file: 'components/screens/nodes/use-node-actions.ts',
    callee: 'api.server.add(',
    route: 'staged',
    why: 'servers Class B（克隆 = 造一个新节点，无副作用）',
  },
  {
    file: 'components/dialogs/TsLoginDialog.tsx',
    callee: 'api.server.add(',
    route: 'direct',
    why: 'W-3：紧接着的 tailscaleLogin 是有远端效应的登录流程，且它按节点 id 寻址 —— 节点必须先真落盘',
  },
  {
    file: 'components/dialogs/TsLoginDialog.tsx',
    callee: 'api.server.update(',
    route: 'direct',
    why: 'W-3：登录流程按节点 id 寻址，编辑态同样要求节点已经在磁盘上',
  },
  {
    file: 'components/dialogs/TsLoginDialog.tsx',
    callee: 'api.server.tailscaleLogin(',
    route: 'direct',
    why: 'W-3：发起远端登录会话（拿授权 URL），暂存一个「还没发生」的登录无语义',
  },
  {
    file: 'components/dialogs/TsLoginDialog.tsx',
    callee: 'api.server.tailscaleLoginCancel(',
    route: 'direct',
    why: 'W-3：撤销已发起的远端登录会话，副作用已经在远端发生',
  },
  {
    file: 'components/dialogs/TsSettingsDialog.tsx',
    callee: 'api.server.tailscaleLogout(',
    route: 'direct',
    why: 'W-3：清 tailscale state 目录不可逆（BYPASS_TABLE 的 deleteTailscaleNode 同族）',
  },
  {
    file: 'components/screens/nodes/NodesScreen.tsx',
    callee: 'api.server.tailscaleLogout(',
    route: 'direct',
    why: 'W-3：清 tailscale state 目录不可逆，「重置」只能退回一个空壳坏节点',
  },
  {
    file: 'components/dialogs/WarpDialog.tsx',
    callee: 'api.server.registerWarp(',
    route: 'direct',
    why: 'W-3：向 Cloudflare 真注册设备',
  },
  {
    file: 'components/dialogs/WarpDialog.tsx',
    callee: 'api.server.add(',
    route: 'direct',
    why: 'W-3：registerWarp 的远端设备已经建好，暂存这条节点会留下「远端有设备、本地无节点」的不可回滚状态',
  },
  { file: 'components/dialogs/WarpDialog.tsx', callee: 'api.server.update(', route: 'direct', why: 'W-3：applyWarpLicense 已改过远端账户绑定' },
  {
    file: 'components/dialogs/WarpDialog.tsx',
    callee: 'api.server.applyWarpLicense(',
    route: 'direct',
    why: 'W-3：向 Cloudflare 提交 license，远端账户等级当场改变，「重置」退不回去',
  },
  {
    file: 'components/screens/nodes/use-node-deletion.ts',
    callee: 'api.server.delete(',
    route: 'staged',
    why: 'servers Class B；全部节点先产生 nextValue:null，TS state/WARP 注销由后端持久删除意图延后到 Apply；仅暂存未启用时调用本 IPC',
  },
  {
    file: 'components/screens/nodes/use-node-deletion.ts',
    callee: 'api.server.deleteBatch(',
    route: 'staged',
    why: 'servers Class B；批量删除同样统一暂存，远端/文件副作用只在 Apply 消费；未知 id 或暂存未启用才交后端即时路径',
  },
  {
    file: 'store/app-store.ts',
    callee: 'api.server.switch(',
    route: 'direct',
    why: 'W-1 switchServer（BYPASS_TABLE 明列）：首页出口框 / 状态栏节点名 / willRestartOnSelect 都实时回显它',
  },
  {
    file: 'tray/TrayMenu.tsx',
    callee: 'api.server.switch(',
    route: 'direct',
    why: 'W-1 switchServer；且托盘是独立 webview，够不着主窗的暂存 store',
  },

  // ── W-d：customRules 族 ──
  // 提交逻辑（含这两个 IPC 调用）2026-08-30 随 5C 拆分外提到 rule-submit.ts（RuleDialog 只剩一个
  // 薄封装调用 submitRule(...)），登记表跟着落点走。
  { file: 'components/dialogs/rule-submit.ts', callee: 'api.rules.add(', route: 'staged', why: 'customRules 是 UserConfig 字段（Class B），提交的是完整 Rule' },
  {
    file: 'components/dialogs/rule-submit.ts',
    callee: 'api.rules.update(',
    route: 'staged',
    why: 'customRules Class B；编辑提交的同样是完整 Rule（base 起底保全 tlsSpoof 等非模型字段）',
  },
  {
    // 规则删除的唯一执行腿（列表行内垃圾桶 + 规则弹窗 footer 共用），2026-07-30 从 RuleDialog 抽出。
    file: 'lib/use-rule-delete.ts',
    callee: 'api.rules.delete(',
    route: 'staged',
    why: 'customRules Class B；删规则无不可逆副作用（不同于删节点），集合实体删除 = nextValue 取 null',
  },
  {
    file: 'components/screens/rules/RulesScreen.tsx',
    callee: 'api.rules.add(',
    route: 'staged',
    why: 'customRules Class B（行内复制，载荷来自 duplicateRulePayload，无副作用）',
  },
  {
    file: 'components/screens/rules/RulesScreen.tsx',
    callee: 'api.rules.update(',
    route: 'staged',
    why: 'customRules Class B（行内启停开关，提交的是整条 Rule）',
  },
  {
    file: 'components/screens/rules/RulesScreen.tsx',
    callee: 'api.rules.reorder(',
    route: 'staged',
    why: 'customRules Class B；顺序条目 entityPath=[集合] 单段、nextValue=主键序列，replay 分两趟（实体在前、顺序在后）⇒ 与同批增删改可交换',
  },
  {
    file: 'components/screens/home/ConnectionTopology.tsx',
    callee: 'api.rules.add(',
    route: 'staged',
    why: 'customRules Class B（拓扑图右键「为其加规则」，纯新增无副作用）',
  },
  {
    file: 'components/RuleSubjectMenuItems.tsx',
    callee: 'api.rules.update(',
    route: 'staged',
    why: 'customRules Class B；「加入已有规则」追加腿写的是**整条** Rule（appendSubjectToRule 的返回值，{...base} 起底 + 镜像同步）⇒ 幂等整体替换。拓扑与连接页两个菜单共用本文件这一条腿',
  },

  // ── W-d：subscriptions 族 ──
  {
    file: 'store/subscription-create-operation-store.ts',
    callee: 'api.subscription.createStart(',
    route: 'direct',
    why: 'W-3：新增订阅启动后端持有的 fetch/parse/commit operation；commit 才原子写 config，renderer 重建可重附，暂存「重置」仍不能回退该网络副作用',
  },
  {
    file: 'components/dialogs/SubDialog.tsx',
    callee: 'api.subscription.update(',
    route: 'direct',
    why: 'W-3：改 URL 会触发后端重拉；subscriptions 已因订阅级网卡策略进入 UserConfig，但这里按副作用绕过而非按 Class A 豁免',
  },
  {
    file: 'components/screens/nodes/use-node-subscription-actions.ts',
    callee: 'api.subscription.delete(',
    route: 'staged',
    why: 'subscriptions 与其下 servers 以同一 groupId 形成原子删除意图；重放只走全量 config 保存，不再调用后端级联腿，TS/WARP 副作用由 Apply 消费',
  },
  {
    file: 'domain/subscription-refresh.ts',
    callee: 'api.subscription.updateServers(',
    route: 'direct',
    why: 'W-3 refreshSubscription（BYPASS_TABLE 明列）：已发网络请求 + 已拿到新节点集',
  },

  // ── W-d：ruleResources 族（下载/覆盖即时；删除则由 Apply 事务延迟物理 unlink）──
  {
    file: 'components/dialogs/ResCatalogDialog.tsx',
    callee: 'api.ruleResources.download(',
    route: 'direct',
    why: 'W-3：真下载并把 .srs 落盘，「重置」删不掉已经写下的文件',
  },
  {
    file: 'components/dialogs/ResUrlDialog.tsx',
    callee: 'api.ruleResources.download(',
    route: 'direct',
    why: 'W-3：按 URL 真下载并落盘，「重置」删不掉已经写下的文件',
  },
  {
    file: 'components/screens/resources/ResourcesScreen.tsx',
    callee: 'api.ruleResources.updateAll(',
    route: 'direct',
    why: 'W-3：批量重新下载并覆盖本地规则文件，「重置」退不回旧内容',
  },
  {
    file: 'components/screens/resources/ResourcesScreen.tsx',
    callee: 'api.ruleResources.redownload(',
    route: 'direct',
    why: 'W-3：重新下载并覆盖该资源的本地文件，「重置」退不回旧内容',
  },
  {
    file: 'components/screens/resources/ResourcesScreen.tsx',
    callee: 'api.ruleResources.delete(',
    route: 'staged',
    why: 'ruleResources Class B；先暂存 config 实体删除，保存只写持久删除意图，Apply/冷启动才 unlink 本地规则文件',
  },
  {
    file: 'components/screens/resources/ResourcesScreen.tsx',
    callee: 'api.ruleResources.resetBuiltin(',
    route: 'direct',
    why: 'W-3：重置内置集 = 重新下载并覆盖本地文件',
  },
  {
    file: 'components/screens/resources/ResourcesScreen.tsx',
    callee: 'api.ruleResources.cancel(',
    route: 'direct',
    why: 'Class A：中止在途下载不写 config（被取消的下载不落盘不入册）',
  },
];

// ─────────────────────────────── 断言 ───────────────────────────────

const key = (s: { file: string; callee: string }) => `${s.file} | ${s.callee}`;

describe('守卫自检：扫到的确实是源码（防扫空 / 过滤过头 → 断言恒真）', () => {
  it('测试文件与 api-client 定义处（barrel + ipc/api/ 目录）都被排除在扫描面外', () => {
    expect(FILES.some((p) => /\.(test|spec)\.tsx?$/.test(p))).toBe(false);
    expect(HITS.some((h) => h.file.endsWith('ipc/api-client.ts') || h.file.includes('ipc/api/'))).toBe(
      false
    );
  });

  it('每组判据面都有实扫命中（任一组归零 = 该组正则已失配）', () => {
    for (const [tag] of PATTERNS) {
      expect(HITS.filter((h) => h.tag === tag).length, `${tag} 一个调用点都没扫到`).toBeGreaterThan(0);
    }
  });

  it('去注释后仍是可断言的代码（防 code() 把源码整段吃掉）', () => {
    for (const s of SITES) {
      const src = SOURCE.get(s.file);
      expect(src, `${s.file} 不在扫描面里（路径写错 / 文件已删）`).toBeDefined();
      const raw = readFileSync(join(SRC, s.file), 'utf8');
      expect(src!.replace(/\s+/g, '').length, `${s.file} 去注释后几乎空了`).toBeGreaterThan(raw.length / 8);
    }
  });

  it('锚点仍在：已知的两个基准调用点必须被扫到', () => {
    const found = new Set(HITS.map(key));
    // NodeDialog 是实体写入口锚点；app-store 是即时补丁原语。两者任一消失都说明判据面失配。
    expect(found.has('components/dialogs/NodeDialog.tsx | api.server.add(')).toBe(true);
    expect(found.has('store/app-store.ts | api.config.patch(')).toBe(true);
  });
});

describe('T1：写入口全登记（新增写 config 的路径 ⇒ 必须显式选一个去向）', () => {
  it('树上扫到的每一个 (文件, 写方法) 都在登记表里', () => {
    const registered = new Set(SITES.map(key));
    const unregistered = [...new Set(HITS.map(key))].filter((k) => !registered.has(k)).sort();
    expect(
      unregistered,
      `以下写 config 的调用点未登记 —— 先按 spec §2.5 Q3/Q3-b 判去向，再补进 SITES：\n${unregistered.join('\n')}`
    ).toEqual([]);
  });

  it('登记表里没有陈旧行（登记了却在树上找不到）', () => {
    const found = new Set(HITS.map(key));
    const stale = SITES.map(key).filter((k) => !found.has(k)).sort();
    expect(stale, `以下登记已陈旧（调用点被删/改名），删掉或改对：\n${stale.join('\n')}`).toEqual([]);
  });

  it('登记表自身不重复（同一 (文件, 方法) 不得有两个去向）', () => {
    const seen = new Set<string>();
    const dup = SITES.map(key).filter((k) => (seen.has(k) ? true : (seen.add(k), false)));
    expect(dup).toEqual([]);
  });
});

describe('T2：白名单是数据不是借口（每条 direct/blocked 都得点名判据）', () => {
  it('direct 的理由必须点名 W-0/Class A 或 W-1/W-2/W-3', () => {
    for (const s of SITES.filter((x) => x.route === 'direct')) {
      expect(s.why, `${key(s)} 的理由没点名任何绕过/豁免谓词`).toMatch(/W-1|W-2|W-3|W-0|Class A/);
    }
  });

  /**
   * 欠账已清零（原 4 行：appRules / customAppPresets 两行靠把条目模型的主键从写死的 `id` 改成
   * 「集合 → 主键字段」映射解决；`rules.reorder` 靠新增整集合顺序条目解决；`subscription.delete`
   * 是错分类 —— 它本就是 W-3，已归位 `BYPASS_TABLE`）。
   *
   * 断言按本组原注释的字面要求从 `toBeGreaterThan(0)` 改成 `toBe(0)`：**这不是放松**。
   * 门的牙从「欠账必须可见」换成了更紧的「欠账必须为零」—— 再想登记一条 `blocked`，
   * 就必须先动这一行，那正是要逼出来的那次显式决定（而不是往表里悄悄多加一行）。
   * `Route` 保留 `'blocked'` 成员与它的语义文档：真出现表达不了的入口时，它仍是唯一诚实的去向。
   */
  it('契约阻塞欠账为零（再开一条必须先改本断言，不得悄悄加行）', () => {
    const blocked = SITES.filter((x) => x.route === 'blocked');
    expect(blocked.map(key)).toEqual([]);
  });

  it('每条登记都有非空理由', () => {
    for (const s of SITES) expect(s.why.length, key(s)).toBeGreaterThan(10);
  });
});

describe('T3：staged 去向必须真的经 editRoute 分流（登记了不算，得在源码里）', () => {
  // 两个 hook 文件的 `stage` 由调用方（NodesScreen/RuleDialog）注入为参数，不在文件内部
  // `useStagedConfigStore()`——闸门本体（`editRoute(...) === 'staged'`）仍在文件内、仍被下面第二条
  // 断言钉住，这里只豁免「必须自己 import useStagedConfigStore」这条子检查。
  const stagedFiles = [...new Set(SITES.filter((s) => s.route === 'staged').map((s) => s.file))]
    .filter(
      (f) =>
        f !== 'components/screens/nodes/use-node-deletion.ts' &&
        f !== 'components/screens/nodes/use-node-actions.ts' &&
        f !== 'components/dialogs/rule-submit.ts',
    );

  it('至少有一批入口真的接了（防登记表被整体降级成 direct 后本组空跑）', () => {
    expect(stagedFiles.length).toBeGreaterThan(6);
  });

  it('每个 staged 文件都从 @/lib/staged-config 取 editRoute、从 store 取 stage', () => {
    for (const f of stagedFiles) {
      const src = SOURCE.get(f)!;
      expect(src, `${f} 没 import editRoute`).toMatch(
        /import\s*\{[^}]*\beditRoute\b[^}]*\}\s*from\s*'@\/lib\/staged-config'/
      );
      expect(src, `${f} 没 import useStagedConfigStore`).toMatch(
        /import\s*\{[^}]*\buseStagedConfigStore\b[^}]*\}\s*from\s*'@\/store\/staged-config-store'/
      );
    }
  });

  it('闸门形态固定：editRoute(<键字面量>, stagingEnabled[, op]) === "staged"', () => {
    for (const f of stagedFiles) {
      const src = SOURCE.get(f)!;
      const gates = [...src.matchAll(/editRoute\(([^)]*)\)\s*===\s*'staged'/g)];
      expect(gates.length, `${f} 没有一处 editRoute(...) === 'staged' 分流`).toBeGreaterThan(0);
      for (const g of gates) {
        expect(g[1], `${f} 的闸门实参形态不对（键必须是字面量、开关必须取自 store）`).toMatch(
          /^\s*'[A-Za-z][A-Za-z0-9.]*'\s*,\s*stagingEnabled\s*(,\s*'[A-Za-z]+'\s*)?$/
        );
      }
    }
  });

  it('**不得**给 editRoute 传死开关（传 true 就绕过了总开关，本轮的零变化承诺当场作废）', () => {
    for (const [f, src] of SOURCE) {
      // `staged-config.ts` 自身的文档/实现不在此列（它定义 editRoute），测试文件已被排除在扫描面外。
      if (f === 'lib/staged-config.ts') continue;
      expect(src, `${f} 给 editRoute 传了字面量开关`).not.toMatch(/editRoute\([^)]*,\s*(true|false)\b/);
    }
  });
});

describe('T4：`enabled=false` 时的行为契约（关闭态必须等价于暂存层不存在）', () => {
  /**
   * 原标题是「总开关关着 ⇒ 本轮改动在产品行为上零变化」，那是开关翻开前的框架，已过时：
   * 开关 2026-07-29 起为 `true`，产品默认行为就是「默认进暂存」。
   *
   * 本组保留的价值在于**关闭态仍是一条必须成立的退路**（回滚手段 = 把常量翻回 `false`），
   * 故下面各条一律显式传 `enabled=false` 测函数契约，不再依赖编译期默认值。
   */
  it('编译期开关为开（翻回 false 是产品行为变更，必须显式改本断言）', () => {
    expect(STAGED_CONFIG_ENABLED).toBe(true);
  });

  it('开关关时每一个 UserConfig 字段都路由到 direct（含全部 Class B 键）', () => {
    for (const k of USER_CONFIG_FIELDS) expect(editRoute(k, false), k).toBe('direct');
    // 子键路径与 Class A 键同样恒 direct —— 入口侧不该出现第二处 if。
    expect(editRoute('dnsConfig.enableFakeIp', false)).toBe('direct');
    expect(editRoute('autoStart', false)).toBe('direct');
  });
});

/**
 * T5：组网单例节点（Tailscale / WARP）的远端注册/登录写腿**恒 `direct`**。
 *
 * # 为什么这条门属于本文件，又为什么它是给别处用的
 *
 * `lib/entity-action-wiring.test.ts` 里有四行登记（TS 登出 ×2 / WARP applyLicense / WARP update）
 * 走 `block` 策略，因为它们触达 state 目录或远端设备。这里钉住其创建/登录来源仍走 W-3 直写，
 * 防止把“已发起远端会话”拆成一条可重置的本地配置意图。
 *
 * 手填/导入可能产生 staged-only 的 endpoint，这不削弱本门：对那类节点，远端动作由
 * `ENTITY_ACTION_TABLE` 明确 block；普通配置删除则按节点类型另行分流。
 */
describe('T5：TS / WARP 的远端注册/登录写腿恒 direct', () => {
  const MESH_SINGLETON_FILES = [
    'components/dialogs/TsLoginDialog.tsx',
    'components/dialogs/WarpDialog.tsx',
  ] as const;

  const rows = SITES.filter((s) => (MESH_SINGLETON_FILES as readonly string[]).includes(s.file));

  it('两个弹窗都真的有写腿被登记（扫空 ⇒ 下面那条恒真）', () => {
    for (const f of MESH_SINGLETON_FILES) {
      expect(
        rows.filter((s) => s.file === f).length,
        `${f} 一条写腿都没登记 —— 判据面已失配，下面那条断言会空跑`
      ).toBeGreaterThan(0);
    }
  });

  it('这两个文件里没有任何一条写腿走 staged', () => {
    const staged = rows.filter((s) => s.route !== 'direct').map((s) => `${s.file} | ${s.callee} → ${s.route}`);
    expect(
      staged,
      'TS / WARP 的远端注册/登录写腿不再恒直落盘 ⇒ 已发生的远端副作用会被伪装成可重置配置'
    ).toEqual([]);
  });
});
