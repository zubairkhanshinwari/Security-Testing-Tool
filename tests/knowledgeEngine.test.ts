import { describe, it, expect } from 'vitest';
import { KnowledgeEngine } from '../src/platform/engines/knowledge/KnowledgeEngine';
import type { Finding } from '../src/platform/core/types/finding';

describe('KnowledgeEngine', () => {
  it('enriches nosqli findings with remediation and mappings', () => {
    const engine = new KnowledgeEngine();
    const [f] = engine.enrich([
      {
        id: '1',
        pluginId: 'nosql-injection',
        title: 'NoSQL Injection',
        description: 'regex',
        severity: 'High',
        confidence: 'Confirmed',
        mappings: { cwe: ['CWE-943'] },
        affectedUrl: 'https://x',
        affectedEndpoint: '/api',
        evidence: ['e'],
        impact: '',
        remediation: '',
        references: [],
        status: 'Confirmed',
        issueFound: true,
        testMode: 'active-safe',
      } as Finding,
    ]);
    const knowledge = f.knowledge as {
      secureCodingExamples?: unknown[];
      businessImpact?: string;
    } | undefined;
    expect(knowledge?.secureCodingExamples?.length).toBeGreaterThan(0);
    expect(f.mappings.cwe).toContain('CWE-943');
    expect(f.remediation).toMatch(/Allow-list|schema/i);
    expect(f.impact.length).toBeGreaterThan(80);
    expect(f.impact).toMatch(/listing|data|scrap|enumer/i);
    expect(knowledge?.businessImpact).toBe(f.impact);
  });

  it('uses JWT long-lived narrative when title mentions exp', () => {
    const engine = new KnowledgeEngine();
    const [f] = engine.enrich([
      {
        id: '2',
        pluginId: 'jwt',
        title: 'JWT weaknesses: extremely long-lived exp, exp > 1 year',
        description: 'exp > 1 year',
        severity: 'Medium',
        confidence: 'Possible',
        mappings: { cwe: ['CWE-347'] },
        affectedUrl: 'https://x',
        affectedEndpoint: '/',
        evidence: [],
        impact: '',
        remediation: '',
        references: [],
        status: 'Possible',
        issueFound: true,
        testMode: 'active-safe',
      } as Finding,
    ]);
    expect(f.impact).toMatch(/stolen|token|impersonation|long/i);
    expect(f.impact.split(/[.!?]/).filter(Boolean).length).toBeGreaterThanOrEqual(2);
  });
});
