/**
 * ScreenRouter —— 按 nav-store active screen 渲染对应页面。
 *
 * 已接入真实组件：home / nodes / rules / apppolicy / resources / connections / logs / settings。
 * settings scope 渲染 SettingsPage（内部按 settingsScreen 路由 9 子页）。
 */

import { useLayoutEffect, type ReactNode } from 'react';
import { useNavStore } from '@/store/nav-store';
import { reportRendererReady } from '@/lib/renderer-ready';
import AppPolicyScreen from './app-policy/AppPolicyScreen';
import ConnectionsScreen from './connections/ConnectionsScreen';
import HomeScreen from './home/HomeScreen';
import LogsScreen from './logs/LogsScreen';
import NodesScreen from './nodes/NodesScreen';
import ResourcesScreen from './resources/ResourcesScreen';
import RulesScreen from './rules/RulesScreen';
import SettingsPage from './settings/SettingsPage';

/* ──────────────────────────────────────────────────────────────────────────────
 * 为什么导航层**不做**代码分割（8 个主屏与 9 个设置子页一律静态 import）
 *
 * `React.lazy` 买的是**网络下载**：把首屏不需要的字节推迟到某次网络往返之后。本应用没有这一步——
 * 所有 chunk 经 tauri-codegen 编进二进制、由本地自定义协议直出，剩下的只有解析/求值成本。而那点成本
 * 已被实测否定：`~/docs/polaris/design/polaris-memory-headroom-2026-08-16.md`（vault，仓外）的硬分类里
 * graphics 146.2 MiB、WebKit Malloc 65.5 MiB，JS JIT 仅数 MiB，且该文自己标注「本项对这三个数贡献恒为 0」。
 *
 * 卖出去的却是确定的：React 一挂起就**同步提交** fallback，哪怕 chunk 下一个微任务就到，用户每次
 * 首访一个页面仍会看到一次转圈闪烁；外加「首屏 chunk 得在语言包后面再串一段 import 瀑布」这套预取
 * 编排，以及随之而来的一整类「这个 loader 忘了预热」缺陷面。
 *
 * 静态绑定后导航路径上没有挂起源，转圈**结构上不存在**，不是靠预取赛跑赢掉。这条不变式由
 * `contracts/navigation-static-binding.test.ts` 逐屏正面钉住（任一屏改回 lazy 即红）。
 * 仍然分包的是**另外两类**、且理由与此正交：各语言 locale 只加载当前语种（`i18n/index.ts`），
 * 托盘浮层与更新弹窗是各自独立的窗口入口（`vite.config.ts` 的多入口）。
 * ────────────────────────────────────────────────────────────────────────────── */

/**
 * `renderer:ready` 必须描述「真实页面已提交」，不能描述 App 外壳已提交：旧信号在 App 首次 commit 就发，
 * 主窗会带着空壳先上屏，正是 W27 的“窗口已出现但渲染仍滞后”。静态绑定让这条约束**自然成立**——首次
 * commit 提交的就是整棵真实页面 DOM，本边界的 layout effect 紧随其后、业务 passive effects 之前
 * 运行；此前需要把它塞进 Suspense 内容腿，只是为了避开 fallback 腿那次抢跑的 commit。文档级去重见
 * `reportRendererReady`。
 */
function RendererReadyBoundary({ children }: { children: ReactNode }) {
  useLayoutEffect(() => reportRendererReady(), []);
  return children;
}

export function ScreenRouter() {
  const scope = useNavStore((s) => s.scope);
  const mainScreen = useNavStore((s) => s.mainScreen);

  // settings scope：渲染 9 子页容器（SettingsPage 内部按 settingsScreen 路由）。
  // 子侧栏 SettingsSidebar 由 AppShell 在 settings scope 下替换主 Sidebar 渲染。
  if (scope === 'settings') {
    return (
      <RendererReadyBoundary>
        <SettingsPage />
      </RendererReadyBoundary>
    );
  }

  let screen: ReactNode;
  switch (mainScreen) {
    case 'home':
      screen = <HomeScreen />;
      break;
    case 'nodes':
      screen = <NodesScreen />;
      break;
    case 'rules':
      screen = <RulesScreen plane="route" />;
      break;
    case 'dnsrules':
      screen = <RulesScreen plane="dns" />;
      break;
    case 'apppolicy':
      screen = <AppPolicyScreen />;
      break;
    case 'resources':
      screen = <ResourcesScreen />;
      break;
    case 'connections':
      screen = <ConnectionsScreen />;
      break;
    case 'logs':
      screen = <LogsScreen />;
      break;
    default:
      // 防御性兜底：未来新增 MainScreen 未接组件时显式占位，不静默白屏。
      screen = (
        <section className="screen">
          <div className="phead">
            <h1>{mainScreen}</h1>
          </div>
        </section>
      );
      break;
  }
  return <RendererReadyBoundary>{screen}</RendererReadyBoundary>;
}

export default ScreenRouter;
