import { describe, expect, it } from 'vitest';
import {
  resolveBusinessImpact,
  inferImpactKey,
} from '../src/platform/engines/knowledge/businessImpactNarratives.js';

describe('businessImpactNarratives', () => {
  it('returns 2–3 sentence attacker/business impact for issues', () => {
    const text = resolveBusinessImpact({
      issueFound: true,
      pluginId: 'sql-injection',
      title: 'SQL injection on q',
      mappings: { cwe: ['CWE-89'] },
    });
    expect(text.split(/[.!?]/).filter((s) => s.trim()).length).toBeGreaterThanOrEqual(2);
    expect(text.toLowerCase()).toMatch(/data|attacker|breach|fraud/);
  });

  it('specializes NoSQL postal regex findings', () => {
    const text = resolveBusinessImpact({
      issueFound: true,
      pluginId: 'nosql-injection',
      title: 'NoSQL regex injection in path parameter "postal_code"',
      description: 'compiled as a MongoDB regular expression',
    });
    expect(text.toLowerCase()).toMatch(/postal|listing|scrap/);
  });

  it('marks pass findings as N/A', () => {
    expect(resolveBusinessImpact({ issueFound: false, pluginId: 'xss' })).toMatch(/N\/A/i);
  });

  it('infers SSTI and cookie keys', () => {
    expect(inferImpactKey({ pluginId: 'ssti', title: 'Possible SSTI' })).toBe('ssti');
    expect(inferImpactKey({ module: 'Cookie Security', title: 'Cookie security issues' })).toBe(
      'cookie',
    );
  });
});
