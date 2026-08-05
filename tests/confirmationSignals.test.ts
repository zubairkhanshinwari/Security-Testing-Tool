import { describe, expect, it } from 'vitest';
import {
  extractStructuredSignals,
  hasProof,
  uniqueSignals,
} from '../src/platform/engines/verification/confirmationSignals';
import { VerificationEngine } from '../src/platform/engines/verification/VerificationEngine';
import type { Finding } from '../src/platform/core/types/finding';
import type { Logger } from '../src/platform/core/logging/logger';

const logger = {
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
  debug: () => undefined,
  child: () => logger,
} as unknown as Logger;

function finding(partial: Partial<Finding>): Finding {
  return {
    id: partial.id || '1',
    pluginId: partial.pluginId || 'sql-injection',
    title: partial.title || 'Test',
    description: partial.description || 'desc',
    severity: partial.severity || 'High',
    confidence: partial.confidence || 'Likely',
    mappings: partial.mappings || { cwe: ['CWE-89'] },
    affectedUrl: 'https://x/?id=1',
    affectedEndpoint: 'https://x/',
    evidence: partial.evidence || [{ technique: 't' }],
    http: partial.http || [
      { request: { method: 'GET', url: 'a' }, response: { status: 200 } },
      { request: { method: 'GET', url: 'b' }, response: { status: 200 } },
    ],
    impact: '',
    remediation: '',
    references: [],
    status: partial.status || 'Likely',
    issueFound: partial.issueFound !== false,
    testMode: 'active-safe',
    techniques: partial.techniques || ['Boolean Logic Validation'],
    ...partial,
  };
}

describe('confirmationSignals', () => {
  it('detects proof signals from structured evidence', () => {
    const signals = extractStructuredSignals([
      { technique: 'x', signals: ['boolean-diff', 'reproducible'] },
      { technique: 'y', unencoded: true },
    ]);
    expect(hasProof(signals)).toBe(true);
    expect(uniqueSignals(signals)).toContain('boolean-diff');
    expect(signals).toContain('reflection-unencoded');
  });
});

describe('VerificationEngine confirmation-depth', () => {
  const engine = new VerificationEngine(logger);

  it('promotes to Confirmed when proof + support signals exist', () => {
    const out = engine.verifyFindings([
      finding({
        evidence: [
          {
            technique: 'Boolean Logic Validation',
            signals: ['boolean-diff', 'reproducible'],
            confirmationSignals: ['boolean-diff', 'reproducible', 'differential'],
          },
          { technique: 'baseline-compare', baselineDiff: { signals: ['body-diff'] } },
        ],
        techniques: ['Boolean Logic Validation', 'Reproducible differential'],
      }),
    ]);
    expect(out[0].confidence).toBe('Confirmed');
    expect(out[0].status).toBe('Confirmed');
    expect(out[0].verification?.signals).toEqual(
      expect.arrayContaining(['boolean-diff', 'reproducible']),
    );
  });

  it('demotes Confirmed without proof on retest gate', () => {
    const out = engine.retestConfirmed([
      finding({
        confidence: 'Confirmed',
        status: 'Confirmed',
        evidence: [{ technique: 'weak', note: 'no proof' }],
        verification: { signalCount: 2, signals: ['evidence', 'http'] },
      }),
    ]);
    expect(out[0].status).toBe('Likely');
    expect(out[0].verification?.signals).toContain('confirmed-retest-demote');
  });

  it('keeps Confirmed when proof present on retest', () => {
    const out = engine.retestConfirmed([
      finding({
        confidence: 'Confirmed',
        status: 'Confirmed',
        evidence: [{ technique: 'x', signals: ['cross-user', 'negative-control'] }],
        verification: { signalCount: 3, signals: ['cross-user', 'negative-control', 'http'] },
      }),
    ]);
    expect(out[0].status).toBe('Confirmed');
    expect((out[0].verification as any).retested).toBe(true);
  });
});
