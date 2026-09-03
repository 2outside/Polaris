/**
 * 内存治理的跨层接线门。
 *
 * 纯函数测试能证明“裁剪 / 对账怎么算”，本文件负责证明这些能力真的接在页面、IPC 与窗口销毁路径上；
 * 否则下一次重构很容易留下一个测试全绿、生产所有权已断开的孤立 helper。
 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { moduleSource } from '@/contracts/rust-source.test-support';

function source(relative: string): string {
  return readFileSync(fileURLToPath(new URL(relative, import.meta.url)), 'utf8');
}

/**
 * 按首尾锚文本切片，**故障关闭**：任一锚点找不到当场抛并点名那段锚文本。
 *
 * 裸 `indexOf` 的返回值 `-1` 在 `slice` 里是合法下标（= 倒数第一个字符），函数被改名或搬走时
 * 切片会静默退化成空串 —— 其上的 `.not.toContain` 全部恒真，门还在、报告还是绿的，判据已经没了。
 */
function sliceBetween(text: string, startAnchor: string, endAnchor: string): string {
  const start = text.indexOf(startAnchor);
  if (start < 0) {
    throw new Error(
      `取材锚点消失：找不到 \`${startAnchor}\` —— 别把它当成「这段代码是干净的」，` +
        '空切片上的否定型断言恒真。',
    );
  }
  const end = text.indexOf(endAnchor, start + startAnchor.length);
  if (end < 0) {
    throw new Error(
      `取材锚点消失：\`${startAnchor}\` 之后找不到收尾锚 \`${endAnchor}\` —— ` +
        '切片边界已失效，判据覆盖面不再是原本那一段。',
    );
  }
  return text.slice(start, end);
}

/** api-client 已按域拆成 barrel + `./ipc/api/` 目录；内容扫描要看整个模块面。 */
function apiClientSource(): string {
  const dir = fileURLToPath(new URL('./ipc/api/', import.meta.url));
  const files = readdirSync(dir).map((f) => readFileSync(join(dir, f), 'utf8'));
  return source('./ipc/api-client.ts') + '\n' + files.join('\n');
}

describe('长期内存所有权接线', () => {
  it('日志页以 mount token 成对登记与退订，且监听先于水合', () => {
    const logs = source('./components/screens/logs/LogsScreen.tsx');
    const listenAt = logs.indexOf('api.logs.onReceivedBatchReady(onBatch)');
    const getAt = logs.indexOf('.get(subscriptionId, MAX_BUFFERED_ROWS)');
    expect(listenAt).toBeGreaterThan(0);
    expect(getAt).toBeGreaterThan(listenAt);
    expect(logs).toContain('api.logs.unsubscribe(subscriptionId)');
    expect(logs).toContain('followRef.current');
    expect(logs).toContain('const LOG_PAGE_SIZE = 20;');
    expect(logs).toContain('renderedLogs.map');
    expect(logs).not.toContain('{visible.map((l, i) =>');
  });

  it('窗口 reload 与销毁都兜底清理日志订阅', () => {
    const main = source('../../src-tauri/src/main.rs');
    // 取材面按**模块**（`tray.rs` + `tray/**`，剔除 `tests/`），不是写死那一个 `.rs`：
    // 被断言的这条调用在 `enter_lightweight_transition`，按拆分设计要进 `tray/transition.rs`。
    const tray = moduleSource('src-tauri/src/tray');
    expect(main).toContain('commands::misc::clear_log_stream_window("main")');
    expect(tray).toContain('crate::commands::misc::clear_log_stream_window("main")');
  });

  it('主窗重建、销毁和后台可见性探针共用跨平台生命周期边界', () => {
    const main = source('../../src-tauri/src/main.rs');
    // 同上：`mark_main_window_destroying()` 在 `enter_lightweight_transition`（→ `tray/transition.rs`），
    // `window_alive: AtomicBool` 在 `VisibilityCache`（→ `runtime/stats/gate.rs`）。
    const tray = moduleSource('src-tauri/src/tray');
    const stats = moduleSource('src-tauri/src/runtime/stats');
    const misc = source('../../src-tauri/src/commands/misc/logs.rs');

    // W18b：唤出漏斗先 spawn 脱帧再排回主线程（接收者名会漂移，钉「点调用+实参」形态）。
    expect(main).toContain('tauri::async_runtime::spawn(async move {');
    expect(main).toContain('.run_on_main_thread(move ||');
    expect(main).toContain('rt.stats().mark_main_window_created()');
    expect(tray).toContain('rt.stats().mark_main_window_destroying()');
    expect(stats).toContain('window_alive: AtomicBool');
    expect(misc).toContain('runtime.stats().window_visible(app)');

    const visibleLogWindows = sliceBetween(misc, 'fn visible_log_windows(', '\n/// 取尾部最多');
    expect(visibleLogWindows).not.toContain('.is_visible(');
    expect(visibleLogWindows).not.toContain('.is_minimized(');
  });

  it('权威配置水合后统一对账全部节点与订阅缓存', () => {
    const app = source('./App.tsx');
    expect(app).toContain('if (!config) return;');
    for (const call of [
      'useLatencyStore.getState().retainServerIds(serverIds)',
      'useAppStore.getState().retainServerIds(serverIds)',
      'useTailscaleLoginCacheStore.getState().retainServerIds(serverIds)',
      'useSubscriptionProgressStore.getState().retainSubscriptionIds(subscriptionIds)',
    ]) {
      expect(app).toContain(call);
    }
    expect(app).not.toContain('useRef<Set<string>>(new Set())');
    expect(app).toContain('useRef<Map<string, string>>(new Map())');
  });

  it('日志 API 的 get/search/unsubscribe 跨层通道成对存在', () => {
    const channels = source('./domain/ipc-channels.ts');
    const client = apiClientSource();
    const main = source('../../src-tauri/src/main.rs');
    expect(channels).toContain("LOGS_UNSUBSCRIBE: 'logs_unsubscribe'");
    expect(channels).toContain("LOGS_SEARCH: 'logs_search'");
    expect(client).toContain('invoke(IPC_CHANNELS.LOGS_UNSUBSCRIBE, { subscriptionId })');
    expect(client).toContain('invoke(IPC_CHANNELS.LOGS_SEARCH, { query, level, source, limit })');
    expect(main).toContain('logs_unsubscribe,');
    expect(main).toContain('logs_search,');
  });
});
