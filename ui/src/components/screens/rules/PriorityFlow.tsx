import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

export interface PriorityFlowStep {
  id: string;
  label: ReactNode;
  active?: boolean;
}
/**
 * 规则阶段流程条。流量与 DNS 共用同一 DOM/CSS，避免两套“优先级”表达再次分叉。
 * 它只表达全局阶段顺序；阶段内部的拖拽排序留给列表自己的按需提示。
 */
export function PriorityFlow({
  label,
  steps,
  className,
}: {
  label: ReactNode;
  steps: readonly PriorityFlowStep[];
  className?: string;
}) {
  return (
    <div className={cn('geo-flow', className)}>
      <div className="field-lbl"><span>{label}</span></div>
      <div className="rl-chain-flow">
        {steps.map((step, index) => (
          <span key={step.id} style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <span className={cn('rl-step', step.active && 'on')}>{step.label}</span>
            {index < steps.length - 1 && <span className="rl-arrow">›</span>}
          </span>
        ))}
      </div>
    </div>
  );
}
