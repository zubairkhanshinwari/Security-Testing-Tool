import { describe, it, expect } from 'vitest';
import { redactSecrets, redactString } from '../src/platform/core/safety/redact';

describe('redactSecrets', () => {
  it('redacts authorization fields', () => {
    const out = redactSecrets({
      authorization: 'eyJhbGciOiJIUzI1NiJ9.aaa.bbb',
      nested: { password: 'secret', ok: true },
    });
    expect(out.authorization).toBe('[REDACTED]');
    expect(out.nested.password).toBe('[REDACTED]');
    expect(out.nested.ok).toBe(true);
  });

  it('redacts JWT-like strings', () => {
    const s = redactString('token=eyJhbGciOiJIUzI1NiJ9.aaa.bbb end');
    expect(s).toContain('[REDACTED_JWT]');
  });
});
