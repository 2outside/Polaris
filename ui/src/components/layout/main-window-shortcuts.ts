/**
 * 主窗跨平台快捷键判据。
 *
 * macOS 的 ⌘Q 归系统顶部应用菜单所有；Windows/Linux 主窗是无边框自绘形态，
 * 不能为了 accelerator 给 GTK/窗口系统挂一棵隐藏的 app menu（Linux 会泄出独立
 * `Polaris` 横栏）。因此非 macOS 的 Ctrl+Q 由渲染层识别，再交给后端统一退出命令。
 */

export type MainWindowShortcutPlatform = 'mac' | 'win' | 'lin';

export interface MainWindowShortcutEvent {
  key: string;
  ctrlKey: boolean;
  metaKey: boolean;
  altKey: boolean;
  shiftKey: boolean;
  repeat: boolean;
  isComposing: boolean;
}

/** 仅接受精确的 Ctrl+Q；组合键、输入法合成帧和按键重复帧均不触发。 */
export function isMainWindowQuitShortcut(
  event: MainWindowShortcutEvent,
  platform: MainWindowShortcutPlatform,
): boolean {
  return (
    platform !== 'mac' &&
    event.ctrlKey &&
    !event.metaKey &&
    !event.altKey &&
    !event.shiftKey &&
    !event.repeat &&
    !event.isComposing &&
    event.key.toLowerCase() === 'q'
  );
}
