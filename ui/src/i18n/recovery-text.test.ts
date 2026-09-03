import { describe, expect, it } from 'vitest';
import { recoveryText } from './recovery-text';

describe('renderer recovery text', () => {
  it('不依赖主 i18next 初始化即可从辅助 locale 读取完整逃生文案', () => {
    for (const id of ['title', 'body', 'reload'] as const) {
      const text = recoveryText(id);
      expect(text).not.toContain('native.fatalPage');
      expect(text.length).toBeGreaterThan(2);
    }
  });
});
