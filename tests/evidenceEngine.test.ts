import { describe, expect, it } from 'vitest';
import { EvidenceEngine } from '../src/platform/engines/evidence/EvidenceEngine';
import { createLogger } from '../src/platform/core/logging/logger';
import type { Finding } from '../src/platform/core/types/finding';

function finding(partial: Partial<Finding>): Finding {
  return {
    id: 'FIND-001',
    pluginId: 'test',
    title: 'Issue',
    description: 'd',
    severity: 'High',
    confidence: 'High Confidence',
    mappings: { cwe: [] },
    affectedUrl: 'https://example.com',
    affectedEndpoint: 'https://example.com',
    evidence: ['e'],
    impact: '',
    remediation: '',
    references: [],
    status: 'Likely',
    issueFound: true,
    testMode: 'active-safe',
    ...partial,
  };
}

describe('EvidenceEngine', () => {
  const logger = createLogger('test', 'error', false);

  it('selects only verified C/H/M/L issues by default', () => {
    const engine = new EvidenceEngine(logger, {
      reporting: {
        includeScreenshots: true,
        evidence: { onlyVerified: true, severities: ['Critical', 'High', 'Medium', 'Low'] },
      },
    });

    const eligible = engine.selectEligible([
      finding({ id: '1', status: 'Likely', severity: 'High' }),
      finding({ id: '2', status: 'Pass', issueFound: false, severity: 'Informational' }),
      finding({
        id: '3',
        status: 'Informational',
        issueFound: true,
        severity: 'Informational',
        confidence: 'Informational',
      }),
      finding({ id: '4', status: 'Confirmed', severity: 'Medium' }),
    ]);

    expect(eligible.map((f) => f.id).sort()).toEqual(['1', '4']);
  });

  it('skips capture entirely when includeScreenshots is false', async () => {
    const engine = new EvidenceEngine(logger, {
      reporting: { includeScreenshots: false, evidence: { onlyVerified: true } },
    });
    const input = [finding({ id: '1' })];
    const out = await engine.collect({
      findings: input,
      targetUrl: 'https://example.com',
      outDir: 'reports/screenshots/test-evidence',
      standalone: true,
    });
    expect(out).toEqual(input);
    expect(out[0].screenshotBase64).toBeUndefined();
  });
});
