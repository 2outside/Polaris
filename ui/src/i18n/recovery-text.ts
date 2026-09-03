import { createAuxI18n } from './auxiliary';
import { native as zhCN } from './locales/auxiliary/zh-CN.json';
import { native as zhTW } from './locales/auxiliary/zh-TW.json';
import { native as enUS } from './locales/auxiliary/en-US.json';
import { native as ru } from './locales/auxiliary/ru.json';
import { native as fa } from './locales/auxiliary/fa.json';

/**
 * renderer 逃生页的五语最小词表。
 *
 * 它不依赖 i18next 或主语言 chunk：若主 i18n 初始化本身失败，仍按与辅助窗口相同的
 * localStorage/系统语言判据从 `auxiliary/*.json` 取文案。翻译单一真值仍在 locale，不维护散落兜底串。
 */
type FatalPageKey =
  | 'native.fatalPageTitle'
  | 'native.fatalPageBody'
  | 'native.fatalPageReload';

const recoveryI18n = createAuxI18n<FatalPageKey>('native', {
  'zh-CN': zhCN,
  'zh-TW': zhTW,
  'en-US': enUS,
  ru,
  fa,
});

const RECOVERY_KEY = {
  title: 'native.fatalPageTitle',
  body: 'native.fatalPageBody',
  reload: 'native.fatalPageReload',
} as const satisfies Readonly<Record<string, FatalPageKey>>;

export type RecoveryTextId = keyof typeof RECOVERY_KEY;

export function recoveryText(id: RecoveryTextId): string {
  return recoveryI18n.t(RECOVERY_KEY[id]);
}
