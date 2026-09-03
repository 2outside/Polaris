import { useMemo } from 'react';
import type { TFunction } from 'i18next';
import { computeTestMatch, type Cond, type TestResult } from './rule-cond';
import { revealOnToggle } from '@/components/reveal';

function Chevron() {
  return (
    <svg className="rule-test-caret" viewBox="0 0 24 24" width={14} fill="none" stroke="currentColor" strokeWidth={1.8}>
      <path d="M6 9l6 6 6-6" />
    </svg>
  );
}

/** 测试匹配结果——客户端启发式即时反馈，从 `RuleForm` 外提，供状态与其消费的 JSX 共用。 */
export function useRuleTestFold(conds: readonly Cond[], logic: 'and' | 'or', test: string): TestResult {
  return useMemo(() => computeTestMatch(conds, logic, test), [conds, logic, test]);
}

interface RuleTestFoldProps {
  t: TFunction;
  test: string;
  setTest: (v: string) => void;
  testResult: TestResult;
}

/** 测试匹配（折叠，客户端启发式即时反馈）。 */
export function RuleTestFold({ t, test, setTest, testResult }: RuleTestFoldProps) {
  return (
    <div className="fld">
      <details className="rule-test-det" onToggle={revealOnToggle}>
        <summary className="fld-l" style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
          <span>{t('rules.testMatch')}</span>
          <Chevron />
        </summary>
        <label className="input" style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '0 11px', marginTop: 8 }}>
          <svg viewBox="0 0 24 24" width={14} fill="none" stroke="currentColor" strokeWidth={1.8} style={{ color: 'hsl(var(--fg-faint))', flex: 'none' }}>
            <circle cx="11" cy="11" r="7" />
            <path d="M20 20l-3-3" />
          </svg>
          <input
            value={test}
            onChange={(e) => setTest(e.target.value)}
            placeholder={t('rules.testPh')}
            aria-label={t('rules.testMatch')}
            style={{ border: 0, background: 'none', outline: 'none', flex: 1, padding: '8px 0', font: 'inherit', color: 'inherit' }}
          />
        </label>
        <div className="card-sub" style={{ marginTop: 6 }}>
          {testResult === 'hit' && (
            <span style={{ color: 'hsl(var(--ok))' }}>✓ {t('rules.testHit')}</span>
          )}
          {testResult === 'miss' && (
            <span style={{ color: 'hsl(var(--fg-faint))' }}>{t('rules.testMiss')}</span>
          )}
          {testResult === 'untestable' && (
            <span style={{ color: 'hsl(var(--fg-faint))' }}>
              {t('rules.testUntestable')}
            </span>
          )}
        </div>
      </details>
    </div>
  );
}
