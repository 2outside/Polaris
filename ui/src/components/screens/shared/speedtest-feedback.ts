/**
 * 测速反馈文案（Home / Nodes 共用，纯函数）。
 *
 * 两屏都调 `api.server.speedTest`，反馈口径必须一致——否则同一个后端 code 在两处显示成不同说法，
 * 用户会以为是两种毛病。抽这里而非各屏内联，也让 vitest（node 环境，不引 jsdom）能直接测。
 */

import type { TFunction } from 'i18next';
import { IpcError } from '@/ipc';
import type { SpeedTestInvokeResult } from '@/contracts/speed-test';
import type { SpeedTestBlockReason } from '../nodes/nodes-logic';

/**
 * 超限文案里那个**可执行的数**：单个临时测速核一次能带多少个 naive 节点。
 *
 * # 为什么是前端一个保守常量，而不是后端现算的那个数
 *
 * 后端 `temp_core_max_naive(n)` 算的是精确值，但它只到得了**诊断串**：失败信封只有 `error` + `code`
 * 两格（`src-tauri/src/response.rs`），没有数据面；而后端诊断串是中文原文、不能直接显示给用户
 * （本仓纪律：UI 只落当前语种的安全总结）。要把这个数结构化地送过来，得给 `ApiResponse` 的失败腿
 * 加数据字段并让 `IpcError` 带上它 —— 那是 95 个命令共用的信封类型，为一句文案改它不划算。
 *
 * 取整数而不是精确值：`n` 项（0.105 ms/节点）会让真实上限随本批节点数缓慢下滑
 * （n=0 时 144、n=10 000 时 118）。往**小**取才是安全方向 —— 报大了用户照着砍完仍被拒，
 * 那正是这条文案要消灭的「只能二分猜」。本值由 `speedtest-feedback.test.ts` 的
 * 「超限文案里那个『最多带 N 个』」那道门直接读 Rust 常量现算并对拍：后端系数一改（多点实测之后
 * 必然要改），它会转红并要求同步本值与五份译文。
 *
 * # ⚠️ T1-R1（分批）把这个数从 700 改成了 110
 *
 * 改前它对着的是 `TEMP_CORE_READY_TIMEOUT_CAP_MS`（60s 单核耐心上限）算出来的 ≈727。分批之后
 * 单批真正的窗口是「前端静默兜底 20s − 批间固定开销 8s = 12s」：用户照 700 砍完，单批预算 ≈30s，
 * **远超前端 20s 的静默兜底** ⇒ 他会拿到一条假的「测速中断」，而现场没有任何东西指向批太大。
 * **自曝腿把用户引向第二个坑，比不给建议更糟。** 新值与后端 `temp_core_max_naive` 同源
 * （同一条批预算），照它砍下去这一轮真的跑得通。
 *
 * 精确值仍在日志里（`runtime/speedtest.rs` 越界腿的 `log::warn!` 与报错原文都带它）。
 */
export const TEMP_CORE_NAIVE_CEILING_HINT = 110;

/**
 * 测速失败 → 展示文案。按后端结构化 code 分流：笼统报「测速失败」会让用户以为节点坏了，
 * 而真实原因是「本轮测不了这些节点」（见 `commands/speedtest.rs` 的 `SpeedTestPlan` 边界登记）。
 *
 * `SPEEDTEST_PROBE_POOL_UNWIRED` 的**语义已变**（码名是历史遗留）：探针池早已接线
 * （`run_pool_speed_test` 分波批量测速是常规路径），该码现在只在**本次起核时池端口分配失败已回退**
 * 的降级态下出现 ⇒ 文案必须说成「本次不可用」的暂态，不能说成「产品只支持测当前节点」的常态。
 */
export function speedTestErrorMessage(err: unknown, t: TFunction): string {
  const code = err instanceof IpcError ? err.code : undefined;
  switch (code) {
    case 'SPEEDTEST_NO_ACTIVE_EXIT':
      return t('nodes.speedTestNoActiveExit');
    case 'SPEEDTEST_PROBE_POOL_UNWIRED':
      return t('nodes.speedTestOnlyActive');
    case 'SPEEDTEST_NONE_IN_POOL':
    case 'SPEEDTEST_TEMP_CORE_NONE_TESTABLE':
      return t('nodes.speedTestNotApplicable');
    // 🔴 规模超限**必须**与就绪超时分流。合并到下面那组 ⇒ 屏幕上显示「测速中断」，与「核起不来」
    // 逐字相同，用户会去查网络/端口，而真因是本轮 naive 节点太多、少选一些当场就能测。
    // 后端的对应码来自 `TempCoreOutcome::Oversized`（起核前拒绝，一个端口都没烧）。
    case 'SPEEDTEST_TEMP_CORE_OVERSIZED':
      return t('nodes.speedTestTooManyNaive', { max: TEMP_CORE_NAIVE_CEILING_HINT });
    case 'SPEEDTEST_ALL_DIRTY':
      return t('nodes.speedTestBlockedStagedOnly');
    case 'SPEEDTEST_TS_NOT_READY':
      return t('nodes.speedTestBlockedTsCoreNotReady');
    case 'SPEEDTEST_IN_FLIGHT':
    case 'SPEEDTEST_CORE_STARTING':
    case 'SPEEDTEST_TEMP_CORE_FAILED':
      return t('nodes.speedTestInterrupted');
    default:
      // 诊断串仍由 IpcError/后端日志保留；UI 只能落在当前语种的安全总结。
      return t('nodes.speedTestInterrupted');
  }
}

/**
 * 本波「请求了但没测」的节点 → 提示文案；全测到则返 null（不打扰）。
 *
 * # 两类缺席**分开报**，不再合计（2026-07-31 修）
 *
 * 后端把它们分成两个键，因为它们是不同的物理事实、有**不同的修法**：
 *  - `notInPool`（`commands/speedtest.rs::partition_pool`）= 不在**运行核**的测速池里（订阅新增/改址后
 *    没重启核 ⇒ 其出站 tag 不是 `probe-selector-k` 成员）→ 修法是重启内核纳入；
 *  - `tsNotReady`（同文件 `partition_ts_not_ready`，判据 `ts_node_ready`）= 协议为 tailscale 但**尚未登录
 *    就绪**。此时运行核对该出口已让位直连（`login_fallback`），测它量到的是直连 RTT ⇒ 波前缺席 →
 *    修法是**去登录那个节点**。
 *
 * 合计成一条会把 TS 未登录说成「未入运行核测速池，重启内核后纳入」—— 用户照着去重启内核，重启完照旧，
 * 因为真正缺的是登录。本函数此前正是这么写的（连带一条注释断言 `tsNotReady` 判据「至今未接线、
 * `run_pool_speed_test` 恒返空数组」，那已不成立：`server_speed_test` 在
 * `commands/speedtest.rs` 里以 `ts_pending` 实参喂进 `partition_pool`，该列表在真机上非空）。
 *
 * 两类并存 → 两句都报（只报一半会让用户按错误的修法折腾，与后端 `zero_testable_envelope` 的
 * 「每一类非零的数都报」同口径）。`dirty`（已编辑未生效）后端另有独立键，渲染端尚未接线 ——
 * 同一事实由 Home 的「N 项待应用」操作条承载，故非静默，登记为已知残留。
 */
export function notInPoolMessage(
  r: Pick<SpeedTestInvokeResult, 'notInPool' | 'tsNotReady'>,
  t: TFunction
): string | null {
  const parts: string[] = [];
  const notInPool = r?.notInPool?.length ?? 0;
  const tsNotReady = r?.tsNotReady?.length ?? 0;
  if (notInPool > 0) {
    parts.push(
      t('nodes.speedTestSkipped', {
        count: notInPool,
      })
    );
  }
  if (tsNotReady > 0) {
    parts.push(
      t('nodes.speedTestSkippedTsNotReady', {
        count: tsNotReady,
      })
    );
  }
  return parts.length > 0 ? parts.join('\n') : null;
}

/**
 * 不可测原因码 → 已本地化说明。**Home / Nodes 共用同一份措辞**。
 *
 * 原本只在 `NodesScreen` 内联（挂灰 ⚡ 的 tooltip）。首页「网络检测」改成只测当前出口后，
 * 它在「当前出口结构上不可测」时同样要把原因讲出来（不然按钮点下去毫无动静，与失灵无从区分）——
 * 两处若各写一套 switch，同一个 `ts-no-exit` 会在 tooltip 和 toast 里说成两种话。
 *
 * **逐分支静态 `t('...')`，不做键名拼接**：i18n 的可寻址性门（`locale-parity.test.ts::extractTKeys`）
 * 只扫得到字面量键，动态拼键会绕过它、把缺译留到运行期才发现。
 */
export function speedTestBlockedMessage(reason: SpeedTestBlockReason, t: TFunction): string {
  switch (reason) {
    case 'staged-only':
      return t('nodes.speedTestBlockedStagedOnly');
    case 'system-interface':
      return t('nodes.speedTestBlockedSystem');
    case 'ts-no-exit':
      return t('nodes.speedTestBlockedTsNoExit');
    case 'lan-only':
      return t('nodes.speedTestBlockedLanOnly');
    case 'ts-core-not-ready':
      return t('nodes.speedTestBlockedTsCoreNotReady');
    case 'custom-endpoint':
      return t('nodes.speedTestBlockedCustomEndpoint');
    default:
      return t('nodes.speedTestNotApplicable');
  }
}
