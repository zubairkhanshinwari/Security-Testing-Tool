import { describe, expect, it } from 'vitest';
import {
  evaluateGate,
  extractFindings,
  findingsFromSarif,
} from '../scripts/ci-gate.js';

describe('ci-gate', () => {
  it('fails on Confirmed High/Critical', () => {
    const r = evaluateGate([
      { title: 'SQLi', severity: 'High', confidence: 'Confirmed' },
      { title: 'noise', severity: 'Medium', confidence: 'Confirmed' },
    ]);
    expect(r.ok).toBe(false);
    expect(r.blockers).toHaveLength(1);
    expect(r.blockers[0].title).toBe('SQLi');
  });

  it('passes when High is only Likely', () => {
    const r = evaluateGate([{ title: 'XSS', severity: 'High', confidence: 'Likely' }]);
    expect(r.ok).toBe(true);
  });

  it('allow-likely blocks Likely High', () => {
    const r = evaluateGate([{ title: 'XSS', severity: 'High', confidence: 'Likely' }], {
      requireConfirmed: false,
    });
    expect(r.ok).toBe(false);
  });

  it('reads confidence from SARIF rule properties', () => {
    const sarif = {
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              rules: [
                {
                  id: 'f1',
                  name: 'BOLA',
                  properties: { severity: 'High', confidence: 'Confirmed' },
                },
              ],
            },
          },
          results: [{ ruleId: 'f1', level: 'error', message: { text: 'BOLA' } }],
        },
      ],
    };
    const findings = findingsFromSarif(sarif);
    expect(extractFindings(sarif)).toHaveLength(1);
    const gate = evaluateGate(findings);
    expect(gate.ok).toBe(false);
  });

  it('reads scan-result JSON findings', () => {
    const doc = {
      findings: [
        {
          issueFound: true,
          title: 'IDOR',
          severity: 'Critical',
          confidence: 'Confirmed',
          affectedEndpoint: '/api/u/1',
        },
      ],
    };
    expect(evaluateGate(extractFindings(doc)).ok).toBe(false);
  });
});
