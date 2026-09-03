/**
 * `useNodesRenderWindow` —— 节点屏的**渲染窗口**：可见集投影（`visibleServers`）+ 渲染尾分批
 * （`renderedServers` / `gridRef` / 三个采样器）。整块逐字外提自 `NodesScreen.tsx`，行为不变。
 *
 * 边界：**只切渲染尾，不切数据**。`visibleServers` 是 search / protoFilter 作用后的**完整结果**，
 * 全选 / 工具栏「测速」（可见集）/ 批选条三处继续读它；`renderedServers` 只喂 `.map()`。
 * 该不变量由 `nodes-render-budget.test.tsx` 钉住。
 *
 * state 一律留在根组件（`NodesScreen`），本 hook 只吃 props、不持有 tab/搜索/排序任何一档。
 */
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef } from 'react';
import type { ServerGroup } from '@/domain/server-grouping';
import { useLatencyStore } from '@/store/use-latency-store';
import { useScrollBatch } from '@/lib/use-scroll-batch';
import { latencySortSelector } from './nodes-logic';
import { projectVisibleServers, type NodesListSortKey } from './nodes-list-projection';

/**
 * SSR 安全的 layout effect。补批要在 paint **之前**收敛（见 topUpBatch 下方那条 effect 的判据），
 * 但 `renderToStaticMarkup` 下 `useLayoutEffect` 会打 React 警告，而本屏的首帧真渲染门
 * （`nodes-render-budget.test.tsx` 门 4）正跑在 node 里。
 *
 * 判据用 `window` 而**不是** `document`：本仓多个 node 环境测试会给 `globalThis.document` 垫桩
 * （i18n 在模块加载期就要写 `<html lang>`），拿 document 判会在那些测试里错误地选到 layout 分支。
 */
const useIsomorphicLayoutEffect = typeof window === 'undefined' ? useEffect : useLayoutEffect;

/**
 * 分批监听挂不上时的**运行期自曝**（开发者可见日志，非用户文案）。
 *
 * `nodes-render-budget.test.tsx` 的锚点门只覆盖**一个**向量：`.main-scroll` 这个类名被改掉。
 * 另一个向量它覆盖不到 —— 网格在运行期不是该容器的后代（AppShell 换层级、本屏被别处复用、
 * 渲染进 portal）：两个类名都还在、门照绿，而 `closest` 返回 null。故那一路由代码本身 fail-open
 * 兜底（见 topUpBatch），再由这条日志把「兜底真的被走到了」说出来。
 * 一次会话报一次：fail-open 之后每次提交都会再走一遍这条路径，逐次打印只会淹没控制台。
 */
let missingScrollerWarned = false;
function warnMissingScroller(): void {
  if (missingScrollerWarned) return;
  missingScrollerWarned = true;
  console.warn(
    '[NodesScreen] 找不到 .main-scroll 滚动祖先：节点网格的滚动分批已 fail-open（本次一次性渲染全部节点）。'
  );
}

/* ════════════════════════════════════════════════════════════════════════════
 * 为什么补批**放弃枚举触发面、改成观测结果**（2026-08-16 复审结论，留档）
 * ════════════════════════════════════════════════════════════════════════════
 *
 * 补批收敛于「距底 > `SCROLL_BATCH_AHEAD_PX`(240px)」。曾经的做法是：把「能改变网格高度」的向量
 * 逐条枚举进 layout effect 的依赖数组，并论证其余向量的幅度都 < 240px 余量（滚动条还在 ⇒ 用户
 * 一滚就续上 ⇒ 至多「多滚一次」，不是永久卡死）。**这条路是错的**，两处实证：
 *
 * ① **枚举读不到过渡中的几何**。`.side` 带 `transition:width .3s ease-out`（components.css:717）。
 *    `sidebarCollapsed` 翻转那一次，layout effect 在 commit 后立刻量 —— 此刻过渡 progress=0，
 *    `.side` 的 used value 还是**旧宽度**，`.main{flex:1}` ⇒ 主区宽还是旧的 ⇒ `auto-fill` 列数
 *    还是旧的 ⇒ 量到的是折叠**前**那份更高的内容，判「仍溢出」⇒ 不补批。300ms 后列数 4→5、
 *    行数 15→12、内容矮 3×141 + 3×12(gap) ≈ 459px ⇒ 不再溢出 ⇒ 卡死。把键换成折叠钮，缺陷与它
 *    本要修的那条逐字同型。
 *    （展开是安全侧；坏的是折叠这一侧。）
 *
 * ② **枚举漏得掉，而且漏的是最高频的那颗**。原表把「角标增减」判成「量级仍是一行文本」——
 *    读反了 `grid-auto-rows:1fr`：它的效果是**所有行等于全局最高卡**（prototype.css:679 自己的
 *    注释就写着「stretch+auto-rows:1fr=全卡跨行统一等高(全局最高卡)」），故总幅度 = **行数 × Δ**。
 *    k=60、N=4 ⇒ 15 行，一排 chip ≈ 20~25px ⇒ 300~375px，**直接跨过 240px 余量**。
 *    这行结论今天侥幸成立，靠的是 `.nd-card{min-height:141px}`（screens.css:117）这个地板把一排
 *    chip 的自然高吃掉了 —— 而地板只在自然高 < 141px 时有效，原表从头到尾没提过它。
 *    更要命的是漏项：`selectedServerId`（点卡设为出口，本屏最高频动作）会把 `.nd-cur` chip 从 A 卡
 *    挪到 B 卡；A 卡若原本是唯一最高卡、且正因这颗 chip 排到 3 行，掉回 2 行 ⇒ 15 行各矮 ~23px
 *    ⇒ 内容矮 345px。它不改 `renderCount`、不改 `visibleServers.length`、不发 resize。
 *    同型的还有 `stagedOnly` / `invalidReason` / `shadowedCidrs`。
 *    **一张列到 12 行的表仍漏了它** —— 每加一颗角标就多一条要枚举的边，而漏一条的后果是
 *    「用户永远点不到剩下的节点且看不出少了」。这就是改用观测的理由。
 *
 * 现在是**三个采样器**，各自观测结果、不枚举原因。三条合起来才叫「不枚举」，缺任一条都有洞：
 *
 *  ① **每次 commit 一采**（layout effect 无依赖数组）—— 覆盖**瞬时**内容变化：增删节点、搜索/
 *     筛选、切 tab、`selectedServerId` 换出口、`stagedOnly`/`invalidReason`/`shadowedCidrs` 角标
 *     增减、语言切换。这些不带 CSS 过渡，commit 那一刻量到的就是真值，一次采样够。
 *  ② **`ResizeObserver` on `.main-scroll`** —— 覆盖**容器盒子**变化：窗口 resize / 缩放 / 全屏、
 *     侧栏折叠的整个 300ms 过渡（连续回报）、差集条与更新横幅进出、滚动条出现/消失。
 *     它取代了原来的 `window.addEventListener('resize')`：今天所有改窗口几何的路径都落在这个盒子上，
 *     旧监听是它的子集。（**不写「必然」**：Windows per-monitor DPI 迁移会给出等逻辑尺寸的新 rect，
 *     CSS px 不变、RO 不发；那一档也不改 auto-fill 列数，无害，但断言不能过强。）
 *  ③ **委派 `transitionend` on `.main-scroll`** —— 覆盖**带 CSS 过渡的内容高度**变化，纯防御性保留。
 *     **2026-08-17 更新**：曾经在用的那一条（视图档切换的几何变化）已被收窄掉。`.nd-card` 的
 *     transition 原是无 property 限定的简写 `.14s`（⇒ `transition-property:all`），列表档把
 *     `min-height`/`padding`/`border-width`（screens.css:364-365）一并改掉 ⇒ 切档那一次，①量到的
 *     是**过渡前**的卡高，而②只看容器盒子、内容变矮不改它 —— 那一维在两者之间是个洞，与侧栏那条
 *     High 同型。现在 `.nd-card` 的 transition 已收窄到六个「不参与盒模型」的绘制层属性（完整清单
 *     见 screens.css:61 注释），几何属性随切档瞬切 ⇒ scrollHeight 单次采样即是终值，`view` 这一维
 *     不再需要③补齐（但 border-color/background/box-shadow/outline/border-radius/outline-offset
 *     仍按 140ms 渐变，是混合过渡不是纯瞬切——只是不影响几何采样，见 screens.css:61 的详细说明）。
 *     **仍不删的理由**：③守的是「`.main-scroll` 内任何带 CSS 过渡的内容高度变化」这整条机制，不是
 *     `view` 这一个案例——给 `.nd-card` 或本屏其它元素今后新加任何动画化几何属性的样式，它立刻
 *     重新变成非它不可。删掉它等于把「今天没有已知触发案例」误判成「以后也用不到」，是本屏刚放弃
 *     的「枚举触发面」思路（见上方「为什么补批放弃枚举触发面」整段）从「布局向量」换个马甲搬回
 *     「过渡属性」。
 *     **成本如实记账（别被「view 已不触发」误读成③几乎不响）**：③今天的主触发源不是 view 切换，
 *     是**悬停**——`.nd-card:hover`（border-color/box-shadow）、`.nd-a:hover`、`.proto-chip:hover`
 *     等一切冒泡到 `.main-scroll` 的 `transitionend` 都会进 `topUpBatch` 读一次 `scrollHeight`（强制
 *     一次布局），鼠标划过节点网格时相当高频。这在收窄前后同频、不是本次改动引入的回归，只是
 *     narrowing 前容易被「反正 view 才是大头」的直觉带偏——它一直是次要开销，成本极低（一次强制
 *     布局读 + `advanceBatch` 同值 bail-out），不值得为省它把③整条撤掉。
 *
 * **已收窄（2026-08-17，陈先生拍板执行；同日复审 F1/F2/F5/F7/F8 追加修正，一并留档）**：`.nd-card`
 * 的 `transition:.14s` 曾写成无 property 限定的简写（= `all`）。判据是「不参与盒模型的绘制层属性
 * 才收进来」，不是「只列 hover 用到的那几个」——首版漏了 `border-radius`（符合判据却被漏收）、
 * 且被 `outline` 简写不含的 `outline-offset` 摆了一道，复审后按判据重扫，收窄到六个属性：
 * `border-color`/`box-shadow`/`background`/`border-radius`/`outline`/`outline-offset`
 * （screens.css:114-117 + index.css 的收窄覆盖层——完整的选择器核对清单、`gap` 为何刻意不收进来，
 * 都写在 screens.css:61 的姊妹注释里，此处不复述）。`screens.css` 那份声明单独存在不生效：
 * `prototype.css:682` 有逐字同选择器、同特异性的未收窄声明，且是 `index.css` 的最后一个 `@import`
 * ⇒ 同特异性后者胜，真正生效的是 index.css 覆盖层；两处 transition 取值必须逐字相等，
 * `style-invariants.test.ts` 有专门的门钉住。
 *
 * **F1（真实缺陷，已随本次收窄一并修）**：列表档 `border:0`/`border-bottom:0`（screens.css:365/366）
 * 是简写，未提到的 border-*-color 会复位成 `currentcolor`（`.nd-card` 继承 body 的 `--fg`）。收窄让
 * `border-width` 瞬切、`border-color` 仍按 140ms 渐变 ⇒ 若不管，会在「切档」以及**更高频的**「滚动
 * 分批推进/搜索击键导致哪张卡是 `:last-child` 改变」两条路径上闪一道近黑/近白边框再淡到
 * `--line`/`--hair`。已在 index.css 覆盖层里把 border-color 显式钉死在 `--line`/`--hair`、两态都
 * 不含 currentcolor（完整推导见 index.css 里紧邻 `.nd-card.confirming` 的那条注释）。
 *
 * 六个属性均不参与盒模型，故视图档切换的几何变化（`min-height`/`padding`/`border-width`/`gap`/
 * `flex-direction`）随之变回瞬切 ⇒ 采样器③对 `view` 这一维随之变成冗余（仍保留，见上方该采样器
 * 条目——它守的是机制，不是这一个案例）。**但这不是纯瞬切**：上面六个绘制层属性仍按 140ms 渐变，
 * 只是它们不影响 `scrollHeight`，故不改变采样器③已冗余这个结论——是「几何瞬切 + 颜色/圆角/描边
 * 仍渐变」的混合过渡，向量表那一行按此口径记账，别读成「整条规则不再有过渡」。
 * **用户可见的取舍（如实记）**：卡片↔列表切换的**几何**（尺寸/位置）从渐变 morph 变成瞬切，颜色/
 * 圆角/描边仍柔化过渡。纯几何渐变的代价是 60+ 张卡的 `min-height` 逐帧参与布局重算（本屏这份分批
 * 基础设施的存在理由之一）；几何瞬切换回来的是零几何动画开销、且从根上消掉「过渡中途采样陈旧几何」
 * 这整类缺陷的触发面。
 *
 * 下表是**留档**，不再是判据来源（像素取自各自 CSS 盒模型，量级判定非精确测绘）：
 *
 * | 向量 | 改的是 | 幅度 | 曾经的判定 | 现在由谁收 |
 * |---|---|---|---|---|
 * | 视图档 `view`（卡片↔列表，**2026-08-17 起几何瞬切、颜色/圆角/描边仍 140ms 渐变**，见上方「已收窄」段） | 几何（min-height/padding/border-width/gap/flex-direction） | 行高 141px ↔ ~40px；60 条差 2~3 倍 scrollHeight | 收窄前：会卡死 → 进依赖（`transition:all`，③ transitionend 补） | ① 每次 commit（几何瞬切，一采即真值——scrollHeight 不吃仍在渐变的颜色/圆角/描边；③ 仍挂着，对这一维是无害空转，见上方③条目「成本如实记账」） |
 * | 侧栏折叠 | 主区宽 ±92px / mac ±68px → 列数 ±1 | 窄窗 N=4、k=60 时 15→12 行 = 3×141 + 3×12(gap) ≈ 459px | 会卡死 → 进依赖（**读到的是旧几何，实际没收住**） | ② RO（过渡全程连续回报） |
 * | 窗口 resize / 缩放 / 全屏 | 可视区 + 内容 | 无界 | `window resize` 监听 | ② RO（旧监听已撤；per-monitor DPI 迁移那一档 RO 不发，见上） |
 * | **出口切换 `selectedServerId`** | 内容（`.nd-cur` chip 换卡 → 最高卡行数变 → **每行**跟着变） | 15 行 × ~23px = 345px | **整条漏列** | ① 每次 commit（无过渡，一采即真值） |
 * | `stagedOnly` / `invalidReason` / `shadowedCidrs` 角标增减 | 同上 | 行数 × ~20~25px，今天靠 141px 地板吃掉 | 判成「一行文本」（读反 1fr） | ① 每次 commit |
 * | 语言切换 / 字体换装 | 同上 | 同上 | 同上 | ① 每次 commit |
 * | 搜索 / 协议筛选 / 切 tab | 内容 + 结果集身份 | — | resetKey 复位 + 长度变 | ① 每次 commit |
 * | 增删节点 / 订阅刷新 / staged 变更 | 内容 | — | 长度变 | ① 每次 commit |
 * | 批选条进出（`.batch-bar`） | 内容 ±~62px（padding 20 + border 2 + margin-bottom 14 + 行高） | < 240 | 余量兜底 | ① 每次 commit |
 * | PendingChangesBar 出现/消失 | **可视区** ±36px（`.pending-bar.show`；在 `.main-scroll` 之外） | < 240 | 余量兜底 | ② RO |
 * | AppUpdateBanner 出现/消失 | **可视区** ±~74px（同上，在 `.main-scroll` 之外） | < 240 | 余量兜底 | ② RO |
 * | SubInfoBar 出现/消失 | 内容 ±~80px | < 240 | 余量兜底 | ① 每次 commit |
 * | 延迟数值回填 | 内容：`.nd-lat` 是**条件渲染**（NodeCard:274），盒高 11px×1.5+4=20.5px > `.nd-name` 的 18.9px 行盒 ⇒ 首个结果到达时 `.nd-top` 涨 ~1.6px，再经 1fr 摊到每行 | ~1.6px × 行数 | 判成「0」（**当时写的是断言不是测量**） | ① 每次 commit |
 *
 * 两处「结论成立但理由写错了」的更正（Low-2，一并留档）：
 *  · 批选条不改卡高。旧理由（「`.nd-check` 是 absolute」）**对卡片档成立**（screens.css:160），
 *    但只覆盖卡片档 —— 列表档它是 `position:static; order:-1`（:375）在流内。列表档成立的理由是
 *    行高由 `.nd-acts` 里 27px 的 `.nd-a` 撑住，18~21px 的勾选框够不着。
 *  · 「延迟数值回填零高度变化」不成立，见上表该行。方向安全、量级也小，但那是断言不是测量值。
 * ════════════════════════════════════════════════════════════════════════════ */

export function useNodesRenderWindow(params: {
  activeGroup: ServerGroup | undefined;
  search: string;
  protoFilter: string;
  sortKey: NodesListSortKey;
  /** 分批 `resetKey` 的一维（结果集身份），不参与投影本身。 */
  activeTab: string;
}) {
  const { activeGroup, search, protoFilter, sortKey, activeTab } = params;
  /**
   * 父层**只在按延迟排序时**才订整张表 —— 那时排序结果必须随每次回包同步重排（不变量①），
   * 重渲是必要的；其余三档排序（默认/名称/协议）下父层根本不读延迟，订了就是每轮测速几十上百次
   * 白重渲整片网格。
   *
   * 非 `lat` 档由 `latencySortSelector` 返回**模块级常量哨兵**（`EMPTY_LATENCY_MAP`）。
   * 这一点是本改动成立的全部前提：zustand 默认按 `Object.is` 比较选择器结果，选择器里若写
   * `: {}` 字面量，每次提交都是新对象、判不等，父层照样每次提交重渲 —— 改了等于白改。
   * 判据与真断言见 `nodes-logic.ts` 的 `EMPTY_LATENCY_MAP` 头注 + `nodes-render-budget.test.tsx`。
   *
   * 单卡的延迟不再从这里灌下去：每张 `NodeCard` 按自身 id 细粒度订阅（见该文件头注）。
   * 需要「此刻最新的整张表」的是三条**动作腿**（删/批删/注销 WARP 的兜底出口），它们在点击当刻
   * 用 `useLatencyStore.getState()` 现取，既拿到最新快照，又不制造一条订阅。
   */
  const latencies = useLatencyStore(latencySortSelector(sortKey === 'lat'));
  const visibleServers = useMemo(
    () => projectVisibleServers(activeGroup, search, protoFilter, sortKey, latencies),
    [activeGroup, search, protoFilter, sortKey, latencies],
  );

  /* ── 节点网格的**渲染尾**分批（复用 `lib/use-scroll-batch`，本仓第三个消费方，零新依赖）──
   *
   * 只切渲染尾，不切数据：`visibleServers` 已是 search / protoFilter 作用后的**完整结果**，
   * 全选、工具栏「测速」（可见集）、批选条三处**必须继续读它**。把切片回灌那三处，就是日志页
   * 「500 行以外搜不到」那类回归的同型复发 —— 用户以为自己在对「筛出来的全部」操作，实际只对
   * 屏幕上恰好画出来的那一批。该不变量由 `nodes-render-budget.test.tsx` 钉住。
   *
   * `resetKey` = 结果集身份（tab + 搜索 + 协议筛选 + 排序键）：一变即回首批，否则从窄结果切回
   * 宽结果时会残留一个大计数，分批等于白做。分隔符用 `\u0000` 免得 `a|b` 与 `a` + `|b` 撞。 */
  const gridRef = useRef<HTMLDivElement>(null);
  const {
    count: renderCount,
    onScroll: onGridScroll,
    renderAll: renderAllServers,
  } = useScrollBatch(
    visibleServers.length,
    `${activeTab}\u0000${search}\u0000${protoFilter}\u0000${sortKey}`
  );
  const renderedServers = useMemo(
    () => visibleServers.slice(0, renderCount),
    [visibleServers, renderCount]
  );
  /* hook 每次渲染都返回新的闭包（它们捕获着当轮的 total）。用 latest-ref 转发，
     使下面那条监听只在挂载/卸载时装拆一次，而不是每渲染一次就重挂一次。
     这条同步**必须**也是 layout 档、且声明在补批 effect 之前：layout effect 整体跑在 passive 之前，
     写成 useEffect 会让补批读到上一轮的闭包（旧 total），节点变多时补批会停在旧上限。 */
  const gridScrollRef = useRef(onGridScroll);
  const renderAllRef = useRef(renderAllServers);
  /** `closest('.main-scroll')` 落空过 —— 由 layout 档的 `topUpBatch` 置位、passive 档的 fail-open 消费。
   *  走 ref 不走 state：置位发生在 layout effect 里，用 state 会多一次同步重渲才轮到兜底。 */
  const scrollerMissingRef = useRef(false);
  useIsomorphicLayoutEffect(() => {
    gridScrollRef.current = onGridScroll;
    renderAllRef.current = renderAllServers;
  });
  /**
   * 追加下一批的触发器。**滚动容器是 `AppShell` 的 `.main-scroll`**：本屏是普通 `.screen`
   * （`flex:1 0 auto; display:block`），自己不滚，整页滚在那个祖先上。scroll 事件不冒泡、
   * React 的 `onScroll` 也不做委派，故这里必须找到那个祖先自己挂原生监听 —— 把 `onScroll`
   * 挂在 `.node-grid` 上是一行不会报错、也永远不会触发的死代码。
   *
   * 找不到祖先时**不**在这里兜底，只置位 `scrollerMissingRef`：`topUpBatch` 跑在 layout 档，
   * 而兜底动作是「一次取到底」，压在 paint 之前就是数秒白屏。真正的兜底在下方那条**独立的
   * passive effect** 里（判据写在它自己的头注上）。
   */
  const topUpBatch = useCallback(() => {
    const scroller = gridRef.current?.closest<HTMLElement>('.main-scroll');
    if (scroller) gridScrollRef.current({ currentTarget: scroller });
    else scrollerMissingRef.current = true;
  }, []);
  useEffect(() => {
    const scroller = gridRef.current?.closest<HTMLElement>('.main-scroll');
    if (!scroller) {
      scrollerMissingRef.current = true;
      return;
    }
    scroller.addEventListener('scroll', topUpBatch, { passive: true });
    /* 采样器②：**容器盒子**。观测 `.main-scroll` 自身，覆盖窗口/侧栏过渡/缩放这一维。
       同款用法本仓已有先例：`home/ConnectionTopology.tsx:154` 观测 `.sankey`。

       **不带 `box` 参数**（默认 content-box，别改）：`.main-scroll` 是 `overflow-y:auto`，
       Win/Linux 经典滚动条下内容从「不溢出」跨到「溢出」会让 content-box 宽缩约 15px ——
       那一维**恰恰要**观测（网格变窄 ⇒ auto-fill 列数变 ⇒ 行数变）。改成 `border-box`
       会把它整条丢掉，而全部门仍绿。

       它**确实**构成一条回调 → 自身盒子变化 → 再回调的反馈边（就是上面那 15px）。不自激的理由
       不是「盒子不变」，而是 `count` 单调不减 + `total` 封顶 + `advanceBatch` 按值 bail-out
       （同值 ⇒ React 就地停），外加 `shouldAdvance` 的 `clientHeight <= 0` 短路。 */
    const ro = new ResizeObserver(topUpBatch);
    ro.observe(scroller);
    /* 采样器③：**带 CSS 过渡的内容高度变化**，纯防御性保留（2026-08-17 更新，详见文件头注）。
       `transitionend` 冒泡，故一条委派监听即可。

       曾经非它不可的那个案例已被消掉：`.nd-card` 原写的是 `transition:.14s`（简写、无 property
       限定 ⇒ `transition-property:all`），列表档把 `min-height`/`padding`/`border-width`
       （screens.css:364-365）一并改掉 ⇒ 切视图档那一次，commit 后立刻量到的是**过渡前**的卡高。
       现在 `.nd-card` 的 transition 已收窄到六个不参与盒模型的绘制层属性（border-color/box-shadow/
       background/border-radius/outline/outline-offset，完整清单见 screens.css:61）⇒ 几何属性随
       切档瞬切，采样器①单次采样即是终值——**但这六个属性本身仍按 140ms 渐变**，不是整条规则变
       瞬切，只是它们不影响 scrollHeight，不改变「①单次采样即真值」这个结论。

       **仍不删的理由**：这条守的是「`.main-scroll` 内任何带 CSS 过渡的内容高度变化」这整条机制，
       不是 `view` 这一个案例——给 `.nd-card` 或本屏其它元素今后新加任何动画化几何属性的样式，它
       立刻重新变成非它不可，删掉等于把「今天没有已知触发案例」误判成「以后也用不到」。

       成本如实记账（别被「view 已不触发」带偏，以为③今天几乎不响）：③今天的主触发源是**悬停**——
       `.nd-card:hover`（border-color/box-shadow）、`.nd-a:hover`、`.proto-chip:hover` 等一切
       冒泡到 `.main-scroll` 的 `transitionend` 都会进这里读一次 `scrollHeight`（强制一次布局），
       鼠标划过节点网格时相当高频；card↔list 切换本身也仍会触发（六个绘制层属性在两档间的值确有
       不同，只是不再影响几何）。这些事件读到的值和采样器①已经一致，`advanceBatch` 同值
       bail-out，是无副作用的空转，成本是一次强制布局读，不是错误重算，也不是本次改动引入的新
       开销（悬停触发在收窄前后同频）。不做 propertyName 过滤：过滤就是又一张要维护的枚举表，
       正是本屏刚放弃的那条路。 */
    scroller.addEventListener('transitionend', topUpBatch);
    return () => {
      scroller.removeEventListener('scroll', topUpBatch);
      scroller.removeEventListener('transitionend', topUpBatch);
      ro.disconnect();
    };
  }, [topUpBatch]);
  /**
   * `closest` 落空时的 **fail-open**：一次取到底，宁可多画，不许静默只剩首批（用户没有滚动条、
   * 没有任何「还有更多」的暗示，看不出少了，而全选/测速读的仍是全集 ⇒ 界面与操作对象脱节）。
   *
   * 刻意留在 **passive** 档、且刻意不设上限：
   *  · passive —— `renderAll()` 会把 count 顶到 total，几千张卡（本仓每卡 ≥22 个 DOM 元素、
   *    含 10 处内联 SVG）的 VDOM+DOM 若压在 paint 之前，用户连「至少有 60 个」都看不到，
   *    「少显示节点」被换成「窗口冻住数秒」。放 passive 档 = 先让首批画出来，再补齐剩下的。
   *  · 不设上限 —— 上限（如 600）会把这条兜底重新变成一个静默截断，而它存在的全部理由正是
   *    消灭静默截断。这条路径意味着 AppShell 的结构已经坏了，一次长帧是诚实的代价。
   * 无依赖数组：结果集变大时要再顶一次；已到顶时 `renderAll` 返回同值 ⇒ React 就地 bail-out。
   */
  useEffect(() => {
    if (!scrollerMissingRef.current) return;
    warnMissingScroller();
    renderAllRef.current();
  });
  /**
   * **初批必须覆盖视口**，否则整个分批是个陷阱：内容没撑出滚动条 ⇒ 永远收不到 scroll 事件 ⇒
   * 剩下的节点再也出不来（而用户看不出少了 —— 没有滚动条就没有「还有更多」的暗示）。
   * 每次提交后按同一条判据（距底不足 `SCROLL_BATCH_AHEAD_PX` 就再来一批）补批，收敛于
   * 「撑出滚动条」或「取完」两者之一：`advanceBatch` 在不该推进或 `c >= total` 时返回同一个
   * count，React 就地 bail-out，不会自激。
   *
   * 走 **layout** 档而不是 `useEffect`：4K / 超宽下首屏容量远大于每批 60，收敛要连跑三四轮，
   * 而 passive effect 每轮之间都夹着一次真实绘制 ⇒ 用户看见网格分段自下而上长出来（2026-08-16
   * 复审报的量级：约 50~65ms 可见抖动）。layout 档把收敛循环整个压在 paint 之前跑完。
   *
   * **没有依赖数组**（= 文件顶部的**采样器①**）—— 每次提交都重量一次，覆盖**瞬时**内容变化。
   * 它单独并不够：带 CSS 过渡的高度变化在这一刻量到的还是过渡前的值（那一维归采样器③
   * `transitionend`），容器盒子变化根本不经过本屏 commit（归采样器② RO）。三条的分工见文件顶部。
   * 代价如实记账：
   *  · 每次本屏 commit 多一次强制 layout 读（`scrollHeight`/`clientHeight`）。按延迟排序的一轮
   *    测速里父层每个回包都重渲 ⇒ 约 200 次；但那些 layout 本来在 paint 时也要做，这里只是提前，
   *    不是凭空多出一遍（真正被消掉的重渲在别处：非 `lat` 档的条件订阅 + 单卡 memo）。
   *  · 收敛循环本身：每轮一次 `slice` + 一批卡片的 VDOM，换的是「首帧即定稿」。
   */
  useIsomorphicLayoutEffect(topUpBatch);

  return { visibleServers, renderedServers, gridRef };
}
