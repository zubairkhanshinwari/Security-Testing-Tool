import { describe, expect, it } from 'vitest';
import { prioritizeByFocus } from '../src/platform/plugins/focusTargets.js';

describe('prioritizeByFocus', () => {
  it('puts focus endpoints first', () => {
    const items = [
      { endpoint: 'https://example.com/a', parameter: 'q' },
      { endpoint: 'https://example.com/api/users', parameter: 'id' },
      { endpoint: 'https://example.com/b', parameter: 'x' },
    ];
    const out = prioritizeByFocus(items, ['https://example.com/api/users'], 2);
    expect(out[0].endpoint).toContain('/api/users');
    expect(out).toHaveLength(2);
  });

  it('returns plain slice when no focus list', () => {
    const items = [{ endpoint: '/1' }, { endpoint: '/2' }, { endpoint: '/3' }];
    expect(prioritizeByFocus(items, undefined, 2)).toEqual([{ endpoint: '/1' }, { endpoint: '/2' }]);
  });
});
