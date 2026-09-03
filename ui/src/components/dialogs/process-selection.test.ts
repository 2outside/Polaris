import { describe, expect, it } from 'vitest';
import { normalizeProcessNames, parseProcessNames } from './process-selection';

describe('process selection normalization', () => {
  it('parses comma/newline input, trims it and removes case-only duplicates', () => {
    expect(parseProcessNames(' chrome.exe, Slack\nCHROME.EXE,  ')).toEqual([
      'chrome.exe',
      'Slack',
    ]);
  });

  it('preserves the order and spelling of hidden or stopped saved processes', () => {
    expect(normalizeProcessNames(['StoppedAgent', 'Visible.exe', 'stoppedagent'])).toEqual([
      'StoppedAgent',
      'Visible.exe',
    ]);
  });
});
