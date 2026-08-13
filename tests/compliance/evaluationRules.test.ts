import { describe, it, expect } from 'vitest';
import { ruleMatches } from '../../src/compliance/cis/evaluationRules';

describe('ruleMatches', () => {
  it('equals / not-equals', () => {
    expect(ruleMatches({ field: 'active', operator: 'equals', value: 'true' }, { active: true })).toBe(true);
    expect(ruleMatches({ field: 'active', operator: 'not-equals', value: 'true' }, { active: false })).toBe(true);
  });

  it('contains / not-contains', () => {
    expect(ruleMatches({ field: 'content', operator: 'contains', value: 'no' }, { content: 'PermitRootLogin no' })).toBe(true);
    expect(ruleMatches({ field: 'content', operator: 'not-contains', value: 'yes' }, { content: 'PermitRootLogin no' })).toBe(true);
  });

  it('matches-regex / not-matches-regex', () => {
    expect(
      ruleMatches({ field: 'content', operator: 'matches-regex', value: '^PermitRootLogin no$' }, { content: 'PermitRootLogin no' }),
    ).toBe(true);
    expect(
      ruleMatches({ field: 'content', operator: 'not-matches-regex', value: 'Protocol 1' }, { content: 'Protocol 2' }),
    ).toBe(true);
  });

  it('exists / not-exists', () => {
    expect(ruleMatches({ field: 'mode', operator: 'exists' }, { mode: '644' })).toBe(true);
    expect(ruleMatches({ field: 'missing', operator: 'not-exists' }, { mode: '644' })).toBe(true);
  });

  it('permission-at-most allows equal or stricter modes and rejects looser ones', () => {
    expect(ruleMatches({ field: 'mode', operator: 'permission-at-most', value: '644' }, { mode: '644' })).toBe(true);
    expect(ruleMatches({ field: 'mode', operator: 'permission-at-most', value: '644' }, { mode: '600' })).toBe(true);
    expect(ruleMatches({ field: 'mode', operator: 'permission-at-most', value: '644' }, { mode: '666' })).toBe(false);
    expect(ruleMatches({ field: 'mode', operator: 'permission-at-most', value: '644' }, { mode: '777' })).toBe(false);
  });

  it('returns false for malformed permission values instead of throwing', () => {
    expect(ruleMatches({ field: 'mode', operator: 'permission-at-most', value: '644' }, { mode: 'not-a-mode' })).toBe(false);
  });

  it('supports PCRE-style inline flag groups like (?im) used in benchmark JSON', () => {
    expect(
      ruleMatches(
        { field: 'content', operator: 'matches-regex', value: '(?im)^\\s*PermitRootLogin\\s+no\\s*$' },
        { content: 'Foo\nPermitRootLogin no\nBar' },
      ),
    ).toBe(true);
    expect(
      ruleMatches(
        { field: 'content', operator: 'matches-regex', value: '(?im)^\\s*PermitRootLogin\\s+no\\s*$' },
        { content: 'Foo\nPermitRootLogin yes\nBar' },
      ),
    ).toBe(false);
  });
});
