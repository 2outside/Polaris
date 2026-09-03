/**
 * Polaris api-client —— Polaris api-client 的 Tauri 2 移植。
 *
 * 设计纪律（迁移核心约束）：
 *  1. **方法签名 100% 对齐 Polaris**（方法名 / 参数 / 返回类型不变）——前端组件调用零改动，只换底层
 *     （Electron ipcRenderer → Tauri invoke/listen）。这样后续阶段补组件时 import 路径与方法全部沿用。
 *  2. 命令名 = Rust `#[tauri::command]` 函数名（snake_case，如 'proxy_start'、'config_get'），
 *     经 IPC_CHANNELS 引用。**注意**：Tauri 的命令名就是 Rust 函数名，冒号在 Rust 标识符里不合法，
 *     故 Electron 风格的 'proxy:start' 永远匹配不上（历史坑：曾按「Rust 注册名 = IPC_CHANNELS 串」
 *     设计，但 Tauri 不支持带冒号的命令名，运行期全部 `Command not found`）。命名规则见 ipc-channels.ts 头注释。
 *     event 名不受此限（自由字符串，保留冒号，对齐 src-tauri/src/events.rs）。
 *  3. **有 {success, data} 信封，且已由 ipc-client 拆掉**：Rust 侧所有 command 统一返回
 *     `ApiResponse<T>` = `{ success, data?, error?, code? }`（见 src-tauri/src/response.rs，95/95 零例外），
 *     与 Polaris Electron 期 registerIpcHandler 自封的信封逐字段一致。拆包点唯一——`ipc-client.invoke`：
 *     `success:true` → 返 data；`success:false` → throw IpcError（带 error/code）。
 *     故**本层方法签名一律标「解包后」的类型**（`Promise<UserConfig>` 而非 `Promise<ApiResponse<UserConfig>>`），
 *     后端业务失败以 IpcError 走 Promise reject，前端 catch 即得错误文案 + 结构化 code。
 *  4. 裸标量参数（Polaris 直接传 string/boolean 的通道，如 privacy:setPassword 的某些路径）经 invokeScalar
 *     包成 { value }——前端调用方仍传裸标量（签名兼容），仅底层转换。
 *
 * 覆盖范围：proxy / config / privacy / server / rules / logs / autoStart / connections / system /
 * ruleResources / ipInfo / unlock / version / update / coreUpdate / subscription / localImport /
 * backup / diagnostic / helper / app / window。与 Polaris api-client.ts 全方法对齐（933 行 → 同语义）。
 *
 * 本文件是按域拆分后的聚合出口（barrel）——各域实现见 ./api/*；此处只做重导出 + `api` 聚合对象组装。
 */

import { proxyApi } from './api/proxy';
import { configApi, privacyApi } from './api/config';
import { serverApi } from './api/servers';
import { vpnApi } from './api/vpn';
import { rulesApi, ruleResourcesApi, iconApi } from './api/rules';
import { logsApi, diagnosticApi } from './api/logs';
import { statsApi, connectionsApi } from './api/stats';
import { autoStartApi, systemApi, windowApi, helperApi, appApi } from './api/system';
import { versionApi, updateApi, coreUpdateApi } from './api/updater';
import { subscriptionApi, localImportApi, backupApi } from './api/subscriptions';
import { ipInfoApi } from './api/ip-info';

export * from './api/proxy';
export * from './api/config';
export * from './api/servers';
export * from './api/vpn';
export * from './api/rules';
export * from './api/logs';
export * from './api/stats';
export * from './api/system';
export * from './api/updater';
export * from './api/subscriptions';
export * from './api/ip-info';
export * from './api/unlock';

// ============================================================================
// 聚合导出（与 Polaris `api` 形状完全一致，组件 import { api } from '@/ipc' 沿用）
// ============================================================================

export const api = {
  proxy: proxyApi,
  config: configApi,
  privacy: privacyApi,
  server: serverApi,
  vpn: vpnApi,
  rules: rulesApi,
  logs: logsApi,
  autoStart: autoStartApi,
  stats: statsApi,
  connections: connectionsApi,
  system: systemApi,
  ruleResources: ruleResourcesApi,
  icon: iconApi,
  ipInfo: ipInfoApi,
  version: versionApi,
  update: updateApi,
  coreUpdate: coreUpdateApi,
  subscription: subscriptionApi,
  localImport: localImportApi,
  backup: backupApi,
  diagnostic: diagnosticApi,
  helper: helperApi,
  app: appApi,
  window: windowApi,
};

export default api;
