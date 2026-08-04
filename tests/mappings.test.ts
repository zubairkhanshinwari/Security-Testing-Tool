import { describe, it, expect } from 'vitest';
import { mappingsFor, cvssFor } from '../src/platform/core/standards/mappings';

describe('standards mappings', () => {
  it('maps nosqli to CWE-943 and OWASP injection', () => {
    const m = mappingsFor('nosqli');
    expect(m.cwe).toContain('CWE-943');
    expect(m.owaspTop10?.[0]).toMatch(/Injection/);
  });

  it('returns CVSS v4 vector for sqli', () => {
    const c = cvssFor('sqli');
    expect(c?.vector).toMatch(/^CVSS:4\.0/);
    expect(c!.score).toBeGreaterThan(8);
  });
});
