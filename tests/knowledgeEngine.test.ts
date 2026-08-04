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
    const knowledge = f.knowledge as { secureCodingExamples?: unknown[] } | undefined;
    expect(knowledge?.secureCodingExamples?.length).toBeGreaterThan(0);
    expect(f.mappings.cwe).toContain('CWE-943');
    expect(f.remediation).toMatch(/Allow-list|schema/i);
  });
});
