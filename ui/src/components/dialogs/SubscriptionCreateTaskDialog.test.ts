import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  subscriptionCreateSuccessToastKey,
  subscriptionCreateTaskCloseLocked,
  subscriptionCreatePublicationCanFinalize,
} from './SubscriptionCreateTaskDialog';

const SRC = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'SubscriptionCreateTaskDialog.tsx'), 'utf8');

describe('subscription create recovery task close gate', () => {
  it('succeeded 的首个 render 已封锁 X/ESC/scrim/footer，不能等 effect 设置 settling 才锁', () => {
    expect(subscriptionCreateTaskCloseLocked({
      phase: 'succeeded', cancelling: false, settling: false,
    })).toBe(true);
  });

  it('发布失败仍保持 terminal task 可见并改为刷新重试，不允许手动清除', () => {
    expect(subscriptionCreateTaskCloseLocked({
      phase: 'succeeded', cancelling: false, settling: false,
    })).toBe(true);
  });

  it('provider 部分成功只消费稳定 partial 标记，不展示上游 warning 原文', () => {
    expect(subscriptionCreateSuccessToastKey(true)).toBe('sub.addedPartial');
    expect(subscriptionCreateSuccessToastKey(false)).toBe('sub.added');
  });

  it('deferred force-load 后若 task 已卸载，不消费 handled；重建可再次发布', () => {
    expect(subscriptionCreatePublicationCanFinalize(true, false)).toBe(false);
    expect(subscriptionCreatePublicationCanFinalize(true, true)).toBe(true);
    const load = SRC.indexOf('await loadConfig(true)');
    const instance = SRC.indexOf('subscriptionCreatePublicationCanFinalize(published, hasInstance(instanceId))');
    const mark = SRC.lastIndexOf('markTerminalHandled(operationId, snapshot.revision)');
    expect(load).toBeGreaterThanOrEqual(0);
    expect(instance).toBeGreaterThan(load);
    expect(mark).toBeGreaterThan(instance);
  });
});
