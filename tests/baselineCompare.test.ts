import { describe, expect, it } from 'vitest';
import {
  compareToBaseline,
  rankParameterName,
  sortByParamPriority,
} from '../src/platform/engines/verification/baselineCompare';

describe('compareToBaseline', () => {
  it('flags SQL error markers only on probe', () => {
    const diff = compareToBaseline(
      { status: 200, body: '{"ok":true}' },
      { status: 500, body: 'You have an error in your SQL syntax' },
    );
    expect(diff.suspiciousError).toBe(true);
    expect(diff.significant).toBe(true);
    expect(diff.signals).toContain('error-marker');
  });

  it('ignores identical soft errors on both sides', () => {
    const body = 'SQL syntax error near x';
    const diff = compareToBaseline({ status: 500, body }, { status: 500, body });
    expect(diff.suspiciousError).toBe(false);
    expect(diff.significant).toBe(false);
  });
});

describe('param ranking', () => {
  it('ranks id/search ahead of csrf', () => {
    expect(rankParameterName('id')).toBeLessThan(rankParameterName('csrf'));
    expect(rankParameterName('search')).toBeLessThan(rankParameterName('token'));
    const sorted = sortByParamPriority([
      { parameter: 'csrf' },
      { parameter: 'q' },
      { parameter: 'foo' },
    ]);
    expect(sorted[0].parameter).toBe('q');
    expect(sorted[sorted.length - 1].parameter).toBe('csrf');
  });
});
