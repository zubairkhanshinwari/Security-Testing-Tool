import { describe, it, expect } from 'vitest';
import { ReportingEngine } from '../src/platform/engines/reporting/ReportingEngine';
import { createLogger } from '../src/platform/core/logging/logger';
import type { Finding, ScanResult } from '../src/platform/core/types/finding';

describe('ReportingEngine exporters', () => {
  const engine = new ReportingEngine('reports', createLogger('test', 'error'));

  const sample: ScanResult = {
    meta: { version: '2.0.0' },
    attackSurface: {
      hosts: [],
      subdomains: [],
      pages: [],
      endpoints: [],
      parameters: [],
      forms: [],
      cookies: [],
      headers: {},
      frameworks: [],
      libraries: [],
      authEndpoints: [],
      apiBases: [],
      websockets: [],
      graphql: [],
      openapi: [],
      storageKeys: [],
    },
    findings: [
      {
        id: 'FIND-001',
        pluginId: 'security-headers',
        title: 'Missing CSP',
        description: 'CSP missing',
        severity: 'Medium',
        confidence: 'Confirmed',
        mappings: { cwe: ['CWE-693'], owaspTop10: ['A05:2021-Security Misconfiguration'] },
        affectedUrl: 'https://example.com',
        affectedEndpoint: 'https://example.com',
        evidence: ['missing CSP'],
        impact: 'i',
        remediation: 'r',
        references: [],
        status: 'Confirmed',
        issueFound: true,
        testMode: 'passive',
      } as Finding,
    ],
    risk: {
      overallScore: 94,
      overallRisk: 'Medium',
      severityCounts: { Critical: 0, High: 0, Medium: 1, Low: 0, Informational: 0 },
      owaspCoverage: {},
      riskPriority: [],
    },
    assessmentSummary: [],
    stats: { totalFindings: 1 },
  };

  it('builds SARIF 2.1 document', () => {
    const sarif: any = engine.toSarif(sample);
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0].results).toHaveLength(1);
  });

  it('builds CSV with header', () => {
    const csv = engine.toCsv(sample.findings);
    expect(csv.split('\n')[0]).toContain('severity');
    expect(csv).toContain('Missing CSP');
  });

  it('builds JUnit with failures', () => {
    const xml = engine.toJunit(sample.findings);
    expect(xml).toContain('<testsuite');
    expect(xml).toContain('<failure');
  });
});
