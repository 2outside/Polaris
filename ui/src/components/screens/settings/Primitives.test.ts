import { describe, expect, it } from 'vitest';
import { optionLabelText } from './Primitives';

describe('Select option 标签文本归一化', () => {
  it('多个 React 文本子节点连续拼接，不插入数组逗号', () => {
    expect(optionLabelText(['Bootstrap DNS', ''])).toBe('Bootstrap DNS');
    expect(optionLabelText(['远程 DNS', ' · 同时也是成员'])).toBe('远程 DNS · 同时也是成员');
  });

  it('忽略空值与布尔条件节点', () => {
    expect(optionLabelText(['DNS', null, false, 53])).toBe('DNS53');
  });
});
