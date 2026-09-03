import { describe, expect, it } from 'vitest';
import { renderToString } from 'react-dom/server';
import { useSubscriptionCreateDialogOperation } from './use-subscription-create-dialog-operation';

function FirstRenderHarness() {
  useSubscriptionCreateDialogOperation({
    instanceId: 'first-render',
    requestFormClose: () => undefined,
    externalCloseLocked: false,
  });
  return null;
}

describe('subscription create dialog operation first render', () => {
  it('executes the real hook without reading operationId in its temporal dead zone', () => {
    expect(() => renderToString(<FirstRenderHarness />)).not.toThrow();
  });
});
