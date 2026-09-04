/**
 * SettingsPage —— settings 屏容器（9 子页；DNS 子页只承载全局运行时设置）。
 *
 * 职责：
 *  1. 渲染 SettingsSidebar（9 子页导航，对齐 nav-store.settingsScreen）；
 *  2. 用 useConfig 加载 UserConfig 一次，传给当前子页；
 *  3. 按 settingsScreen 路由到对应子页组件。
 *
 * 子页对齐原型 .set-section[data-sec]：
 *   general | display | network | dns | tun | update | backup | helper | about
 *
 * 注：SettingsSidebar 由 AppShell 在 settings scope 下替换主 Sidebar 渲染（见 ScreenRouter 协议）。
 * 本组件只渲染 main 内容区 + 子页路由；侧栏切换在 AppShell 层处理。
 */

import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavStore } from '@/store/nav-store';
import { Spinner } from './Primitives';
import { useConfig } from './use-config';
import SettingsAbout from './SettingsAbout';
import SettingsBackup from './SettingsBackup';
import SettingsDisplay from './SettingsDisplay';
import SettingsDns from './SettingsDns';
import SettingsGeneral from './SettingsGeneral';
import SettingsHelper from './SettingsHelper';
import SettingsNetwork from './SettingsNetwork';
import SettingsTun from './SettingsTun';
import SettingsUpdate from './SettingsUpdate';

// 9 子页静态绑定，理由与 8 个主屏同源（完整论证见 `ScreenRouter.tsx` 顶部）：分包换来的是每次首访
// 一次 Suspense 转圈，而本地协议直出的 chunk 本就没有「下载」这一步可省。

export function SettingsPage() {
  const { t } = useTranslation();
  const settingsScreen = useNavStore((s) => s.settingsScreen);
  const { config, loading, error, update, reload } = useConfig();

  // loading/error 态不在原型里（静态 demo 无真实异步加载）——沿用 .screen 容器 + 原型原语按钮，
  // 不新发明布局类；居中/间距用内联 style，不是逐字复现对象。
  //
  // `loading` 现在是**冷启动回落腿**：app-store 已 hydrate 时 `useConfig` 首帧就有种子（见
  // `use-config.ts` 头注「首帧不转圈」），日常进设置页这屏 Spinner 不出现。但托盘「打开设置」、
  // 启动即进 settings scope 这两条路上 store 未必已 hydrate ⇒ 删掉这个分支 = 那两条路白屏。
  if (loading) {
    return (
      <section className="screen" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <Spinner />
      </section>
    );
  }

  // 只有**加载**失败才塌成错误屏（useConfig.error 已收窄为 load-only：保存失败走 toast，
  // 否则一次瞬时保存失败会把用户正在编辑的子页整个卸载，且文案说错原因）。
  if (error || !config) {
    return (
      <section className="screen">
        <div style={{ fontSize: 13, color: 'hsl(var(--err))' }}>
          {t('common.configLoadFail')}
        </div>
        <button type="button" onClick={() => void reload()} className="btn ghost sm" style={{ marginTop: 12 }}>
          <span>{t('common.retry')}</span>
        </button>
      </section>
    );
  }

  // 9 子页统一接 { config, update }；各自按需补子 store（如 update/helper 状态）。
  let page: ReactNode;
  switch (settingsScreen) {
    case 'general':
      page = <SettingsGeneral config={config} update={update} />;
      break;
    case 'display':
      page = <SettingsDisplay config={config} update={update} />;
      break;
    case 'network':
      page = <SettingsNetwork config={config} update={update} />;
      break;
    case 'dns':
      page = <SettingsDns config={config} update={update} section="runtime" />;
      break;
    case 'tun':
      page = <SettingsTun config={config} update={update} />;
      break;
    case 'update':
      page = <SettingsUpdate config={config} update={update} />;
      break;
    case 'backup':
      page = <SettingsBackup config={config} />;
      break;
    case 'helper':
      page = <SettingsHelper />;
      break;
    case 'about':
      page = <SettingsAbout />;
      break;
    default:
      page = <SettingsGeneral config={config} update={update} />;
  }
  return page;
}

export default SettingsPage;
