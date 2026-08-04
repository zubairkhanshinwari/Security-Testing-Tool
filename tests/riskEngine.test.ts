import { describe, it, expect } from 'vitest';
import { RiskEngine } from '../src/platform/engines/risk/RiskEngine';
import { createLogger } from '../src/platform/core/logging/logger';
import type { Finding } from '../src/platform/core/types/finding';

function finding(partial: Partial<Finding>): Finding {
  return {
    id: 'F1',
    pluginId: 'test',
    title: 't',
    description: 'd',
    severity: 'High',
    confidence: 'Confirmed',
    mappings: { cwe: ['CWE-943'], owaspTop10: ['A03:2021-Injection'] },
    affectedUrl: 'https://x',
    affectedEndpoint: '/api/x',
    evidence: ['e'],
    impact: 'i',
    remediation: 'r',
    references: [],
    status: 'Confirmed',
    issueFound: true,
    testMode: 'active-safe',
    ...partial,
  };
}

describe('RiskEngine', () => {
  const engine = new RiskEngine(createLogger('test', 'error'));

  it('starts near 100 with no issues', () => {
    const risk = engine.evaluate([finding({ issueFound: false, severity: 'Informational' })]);
    expect(risk.overallScore).toBe(100);
    expect(risk.overallRisk).toBe('Informational');
  });

  it('deducts for confirmed high findings', () => {
    const risk = engine.evaluate([finding({ severity: 'High', confidence: 'Confirmed' })]);
    expect(risk.overallScore).toBeLessThan(100);
    expect(risk.overallRisk).toBe('High');
    expect(risk.severityCounts.High).toBe(1);
  });

  it('applies lower weight for Possible confidence', () => {
    const confirmed = engine.evaluate([finding({ confidence: 'Confirmed' })]);
    const possible = engine.evaluate([finding({ confidence: 'Possible' })]);
    expect(possible.overallScore).toBeGreaterThan(confirmed.overallScore);
  });

  it('does not flatten many same-family findings to 0', () => {
    const many = Array.from({ length: 12 }, (_, i) =>
      finding({
        id: `F-${i}`,
        pluginId: 'idor-bac',
        title: `Possible IDOR / BOLA on /api/listings/${i} (anonymous)`,
        severity: 'High',
        confidence: 'Likely',
        mappings: { cwe: ['CWE-639'] },
        cvss: { vector: 'x', score: 7.1, severity: 'High' },
      }),
    );
    const risk = engine.evaluate(many);
    expect(risk.overallScore).toBeGreaterThan(20);
    expect(risk.overallScore).toBeLessThan(100);
    expect(risk.overallRisk).toBe('High');
  });
});
