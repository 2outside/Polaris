/**
 * 托盘浮层的「窗高收敛」纯逻辑：非 main 视图期间的高度保持锁，以及屏幕换代时的重新武装。
 *
 * 抽出来不是为了复用（消费点只有 `TrayMenu.tsx` 一处），是为了**可测**：本仓 vitest 跑 node 环境、
 * 刻意不装 jsdom（见 `vite.config.ts` test 段），真 hook/effect 一行都跑不起来 —— 而这次缺陷的全部
 * 所在恰恰就是这两件事。同款做法见 `components/screens/settings/settings-logic.ts` 的
 * `wireUpdateProgress`：把接线本身注入化，让它离开 React 也能跑。
 */

/** 高度锁的容器。与 React `useRef` 结构同型 ⇒ 组件把 ref 原样传进来，不必再包一层。 */
export interface TrayHeightLock {
  current: number | null;
}

/**
 * 本次测量应回报给宿主的窗高：**主视图最近一次量到的值胜**。
 *
 * `settled` = 配置已 hydrate 且停在主视图 —— 只有这种测量值有资格进锁。锁的原意是「节点视图
 * 折叠/展开只改变卡片内部的滚动内容，不让外层菜单跟着忽高忽低」，而挡住那件事的是 `settled` 里的
 * `view === 'main'` 那一半，**不是**「只认第一次」：非 main 视图的测量本来就进不了锁，那段时间
 * 回报的仍是上一次主视图的值。原意图与「只认第一次」无关，删掉后者不动它分毫。
 *
 * # 为什么「只认第一次」必须去掉
 *
 * 它给锁加了一个**时间**维度：某次主视图测量若是脏的（Web 字体尚未换上、屏幕刚换代、config 刚
 * 到位那一帧），后面量得再准也写不进去，只能等某条腿主动来清锁。于是「漏掉一个触发源」从
 * 「晚一拍自愈」被放大成「**永久错**」——而触发源是枚举出来的（展开 / 屏幕换代 / 字体落定），
 * 枚举天然不完备，缺一条就是一类用户永远看到被裁的菜单。改成最近值胜之后，任何一次
 * `ResizeObserver` 触发都会把锁刷成当下的真值，错态最多活到下一次重排。
 *
 * 锁因此收窄成「**非 main 视图期间的保持值**」——只在 `settled=false` 时被读到。清锁仍有必要，
 * 为什么见 [`resetTrayHeightLock`]。
 */
export function trayReportedHeight(
  lock: TrayHeightLock,
  measured: number,
  settled: boolean,
): number {
  if (settled) lock.current = measured;
  return lock.current ?? measured;
}

/**
 * 清锁：下一次测量重新收敛。
 *
 * 最近值胜之后这条**仍不能删**，但理由换了一条：展开那一刻若**正停在非 main 视图**（用户上次
 * 收起时停在「全部节点」，而 `keepTrayMenuWarm` 默认开启 ⇒ 日常隐藏不回收 WebView，下一次展开
 * 就从那里起步），`settled` 恒为 false ⇒ 当次实测一个字节也进不了锁，回报的还是**上一代**主视图
 * 的高。上一代若量在大屏上，这次在小屏上就是窗体超出屏幕被裁（排在最底下的「退出」连滚都够不到）；
 * 反过来则是菜单内部滚动。清掉锁，`lock.current ?? measured` 才回落到当次实测。
 *
 * 所以「什么时候清」= 「那个高度什么时候可能已经不成立」：每次展开（腿 A，宿主经
 * `tray/window.rs::show_ready_overlay` 的 eval 桥通知）+ 展开期间屏幕换代（腿 B，权威信号在宿主侧，
 * 见 `tray/platform.rs::install_screen_change_observer` 与 `tray/window.rs` 的 `ScaleFactorChanged`
 * 分支；前端侧的次级触发见 [`armScreenChangeRemeasure`]）。
 *
 * 不用「`Math.max` 单调增长」代替清锁：换到小屏那一档它完全帮不上忙，反而把窗永久钉在大屏量到的
 * 高度上 —— 把「矮了滚动」换成更难救的「高了被裁」。
 */
export function resetTrayHeightLock(lock: TrayHeightLock): void {
  lock.current = null;
}

/** `MediaQueryList` 的最小可注入面（node 环境无 DOM，单测要喂假的）。 */
export interface TrayMediaQueryList {
  addEventListener(type: 'change', listener: () => void): void;
  removeEventListener(type: 'change', listener: () => void): void;
}

/** `window` 的最小可注入面 —— `window` 本身结构上就满足它，生产侧直接传 `window`。 */
export interface TrayScreenView {
  matchMedia(query: string): TrayMediaQueryList;
  readonly devicePixelRatio: number;
  readonly screen: { readonly width: number; readonly height: number };
}

/**
 * 当下这块屏的三条**等值**查询串：每条都写死武装那一刻的值 ⇒ 任一条 fire 就说明该维度变了。
 *
 * 三条而不是一条：改分辨率会同时动 dppx 与几何，但「拖到另一块同 DPI 的屏」只动几何、
 * 「同一块屏改缩放」只动 dppx —— 少一条就漏一类。
 *
 * `device-width` / `device-height` 在 MQ Level 4 里标了 deprecated（仍要求实现），核实程度**分平台**，
 * 不是笼统的「尽力而为」：
 * - **Windows**：WebView2 的渲染引擎就是 Blink，而本仓已在 Blink（headless Chrome）上实测过 ——
 *   三条 query 的 `matches` 全为 true，把宽度 +137px 的对照串为 false ⇒ 匹配不是恒真。故这条腿在
 *   Windows 上是**已核实**的，且正是 Windows 几何变化（改分辨率、拖到另一块同 DPI 的屏）的主力：
 *   宿主侧够得着的 `ScaleFactorChanged` 只覆盖 DPI 那一半。
 * - **macOS**：WKWebView **未核实**（无 mac、禁起 App）。mac 的几何/排布变化由宿主侧的
 *   `NSApplicationDidChangeScreenParametersNotification` 兜（见 `tray/platform.rs`），本腿在 mac 上
 *   只算次级触发。
 */
export function screenMetricQueries(view: TrayScreenView): string[] {
  return [
    `(resolution: ${view.devicePixelRatio}dppx)`,
    `(device-width: ${view.screen.width}px)`,
    `(device-height: ${view.screen.height}px)`,
  ];
}

/**
 * 屏幕换代（DPI / 几何）即回调，并**用新值重新武装**。
 *
 * # 定位：次级触发，不是权威源
 *
 * 「屏幕参数变了」这件事只有系统知道，权威信号在宿主侧（mac 的
 * `NSApplicationDidChangeScreenParametersNotification`、Win 的 `WM_DPICHANGED` 经 tao 归一成的
 * `WindowEvent::ScaleFactorChanged`，都在 `tray/{platform,window}.rs`）。本腿留着是因为它便宜且
 * 覆盖宿主够不着的一类：浏览器级缩放（Ctrl +/-，只改 `devicePixelRatio`，不发系统屏幕通知），
 * 以及 Windows 上宿主拿不到的几何变化（`WM_DISPLAYCHANGE` 要自挂窗口过程，见 `window.rs` 的
 * `ScaleFactorChanged` 分支注释）。核实程度分平台，见 [`screenMetricQueries`]。
 *
 * 最近值胜（见 [`trayReportedHeight`]）之后，多触发一次重量是**幂等**的 —— 两条腿同时 fire 只是
 * 多量一遍，不会互相打架；这也是「留着一条不确定的腿」在这里没有代价的原因。
 *
 * # 重新武装是要害
 *
 * 查询串里写死的是**武装那一刻**的值，一旦 fire，那条 query 的条件此后恒 false、再也不会 fire ⇒
 * 只武装一次的写法只跟得上第一次变化，用户第二次改分辨率就又回到旧缺陷。（同款模式见 MDN
 * `Window.devicePixelRatio` 的示例。）
 *
 * **看屏幕不看窗**：窗尺寸正是我们自己经 `tray_resize` 改的，监听窗的 resize 会形成
 * 「改尺寸 → 收事件 → 重量 → 改尺寸」的正反馈环 —— `tray/window.rs` 的 `TRAY_MAX_HEIGHT_LOGICAL`
 * 注释里就记着一次被 ResizeObserver 正反馈推到上限的实例。屏幕不是我们改的，结构上没有这个环。
 *
 * 返回拆监听闭包，可直接作 React effect 的 cleanup。
 */
export function armScreenChangeRemeasure(
  view: TrayScreenView,
  onChange: () => void,
): () => void {
  let armed: Array<{ mq: TrayMediaQueryList; fire: () => void }> = [];
  let disposed = false;

  const disarm = (): void => {
    for (const { mq, fire } of armed) mq.removeEventListener('change', fire);
    armed = [];
  };

  const arm = (): void => {
    armed = screenMetricQueries(view).map((query) => {
      const mq = view.matchMedia(query);
      // 先整批换新、再回调：改分辨率会同时动 dppx 与几何，没 fire 的那几条同样已经不是
      // 「当下值」了，只换 fire 的那一条会让它们此后永远沉默。
      const fire = (): void => {
        if (disposed) return;
        disarm();
        arm();
        onChange();
      };
      mq.addEventListener('change', fire);
      return { mq, fire };
    });
  };

  arm();
  return () => {
    disposed = true;
    disarm();
  };
}

/** `document` 的最小可注入面：只要字体是否落定这一件事（node 环境无 DOM，单测喂假的）。 */
export interface TrayFontsView {
  readonly fonts?: { readonly ready: Promise<unknown> };
}

/**
 * 字体落定后重量一次（腿 C）。
 *
 * 腿 A/B 都是**外因**触发（宿主展开、屏幕换代），而这次缺陷最初被报出来的那一次谁都没触发：
 * 全新安装后**第一次**展开，`config` 到位可能早于 Web 字体换上 —— 字体一换文本度量就变、行高与
 * 换行数跟着变，而锁在字体落定**之前**就合上了，量到的是回落字体那份偏矮的高度。
 *
 * 最近值胜（见 [`trayReportedHeight`]）之后本腿从**必需**降级为**双保险**：字体换上会引起真实
 * 重排，`ResizeObserver` 本来就会 fire，那一次测量会直接把锁刷成新值。留着它的理由是
 * 「字体落定」与「布局重排」不是同一件事的两个名字 —— 若某代 WebView 的换字体没有触发观察到的
 * 尺寸变化（同宽字体回落、只改基线），本腿仍是那一次唯一的信号，而它的成本是一个 promise 回调。
 *
 * 一代 WebView 只需一次：字体不会换回去。`document.fonts` 缺席（老 WebView / 测试桩）⇒ 静默 no-op，
 * 退化成腿 A/B 的行为，不为一条尽力而为的腿制造崩溃面。
 *
 * 返回取消闭包：本腿 resolve 可能晚于卸载，届时不该再去动一个已经不存在的窗的高度。
 */
export function armFontsReadyRemeasure(
  view: TrayFontsView,
  onChange: () => void,
): () => void {
  let cancelled = false;
  const ready = view.fonts?.ready;
  if (!ready) return () => undefined;
  void ready.then(() => {
    if (!cancelled) onChange();
  });
  return () => {
    cancelled = true;
  };
}
