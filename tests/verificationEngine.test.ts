import { describe, it, expect } from 'vitest';
import { VerificationEngine } from '../src/platform/engines/verification/VerificationEngine';
import { createLogger } from '../src/platform/core/logging/logger';
import type { Finding } from '../src/platform/core/types/finding';

describe('VerificationEngine', () => {
  const engine = new VerificationEngine(createLogger('test', 'error'));

  it('process() assigns ids, dedupes, and verifies', () => {
    const out = engine.process([
      {
        pluginId: 'x',
        title: 'Dup via param a',
        description: 'x',
        severity: 'Medium',
        confidence: 'Possible',
        mappings: { cwe: ['CWE-89'] },
        affectedUrl: 'u',
        affectedEndpoint: 'e',
        evidence: ['one'],
        impact: '',
        remediation: '',
        references: [],
        status: 'Possible',
        issueFound: true,
        testMode: 'active-safe',
      } as unknown as Finding,
      {
        pluginId: 'x',
        title: 'Dup via param b',
        description: 'x',
        severity: 'Medium',
        confidence: 'Possible',
        mappings: { cwe: ['CWE-89'] },
        affectedUrl: 'u',
        affectedEndpoint: 'e',
        evidence: ['one', 'two'],
        impact: '',
        remediation: '',
        references: [],
        status: 'Possible',
        issueFound: true,
        testMode: 'active-safe',
      } as unknown as Finding,
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].id).toMatch(/^FIND-/);
    expect(out[0].evidence).toHaveLength(2);
    expect(out[0].verification?.signalCount).toBeGreaterThan(0);
  });

  it('drops issue findings without evidence', () => {
    const out = engine.verifyFindings([
      {
        id: '1',
        pluginId: 'x',
        title: 'No evidence',
        description: 'x',
        severity: 'High',
        confidence: 'Possible',
        mappings: { cwe: [] },
        affectedUrl: 'u',
        affectedEndpoint: 'e',
        evidence: [],
        impact: '',
        remediation: '',
        references: [],
        status: 'Possible',
        issueFound: true,
        testMode: 'active-safe',
      } as Finding,
    ]);
    expect(out).toHaveLength(0);
  });

  it('marks rich multi-signal evidence as Confirmed', () => {
    const out = engine.verifyFindings([
      {
        id: '2',
        pluginId: 'nosql',
        title: 'NoSQL regex confirmed',
        description: 'MongoDB differential reproduced',
        severity: 'High',
        confidence: 'Likely',
        mappings: { cwe: ['CWE-943'] },
        affectedUrl: 'u',
        affectedEndpoint: 'e',
        evidence: ['a', 'b'],
        http: [
          { request: { method: 'GET', url: 'u1' }, response: { status: 200 } },
          { request: { method: 'GET', url: 'u2' }, response: { status: 200 } },
        ],
        impact: '',
        remediation: '',
        references: [],
        status: 'Likely',
        issueFound: true,
        testMode: 'active-safe',
        techniques: ['regex', 'differential'],
      } as Finding,
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].confidence).toBe('Confirmed');
  });

  it('tempers high severity with single weak signal', () => {
    const out = engine.verifyFindings([
      {
        id: '3',
        pluginId: 'x',
        title: 'Maybe issue',
        description: 'weak',
        severity: 'High',
        confidence: 'Possible',
        mappings: { cwe: [] },
        affectedUrl: 'u',
        affectedEndpoint: 'e',
        evidence: ['one'],
        impact: '',
        remediation: '',
        references: [],
        status: 'Possible',
        issueFound: true,
        testMode: 'active-safe',
      } as Finding,
    ]);
    expect(out[0].severity).toBe('Medium');
    expect(out[0].confidence).toBe('Low Confidence');
    expect(out[0].description).toMatch(/Precision/);
  });

  it('gates High injection without baseline/differential down to Medium', () => {
    const out = engine.verifyFindings([
      {
        id: '4',
        pluginId: 'xss',
        title: 'Reflected XSS indicator',
        description: 'maybe',
        severity: 'High',
        confidence: 'Likely',
        mappings: { cwe: ['CWE-79'] },
        affectedUrl: 'https://x/?q=1',
        affectedEndpoint: 'https://x/',
        evidence: [{ technique: 'xss' }],
        http: [{ request: { method: 'GET', url: 'u' }, response: { status: 200 } }],
        impact: '',
        remediation: '',
        references: [],
        status: 'Likely',
        issueFound: true,
        testMode: 'active-safe',
        techniques: ['Reflected XSS Testing'],
      } as Finding,
    ]);
    expect(out[0].severity).toBe('Medium');
    expect(out[0].verification?.signals).toContain('precision-injection-gate');
  });

  it('merges same-family findings and keeps richest evidence', () => {
    const out = engine.process([
      {
        pluginId: 'idor-bac',
        title: 'Possible IDOR / BOLA on /api/users/1 (anonymous)',
        description: 'a',
        severity: 'High',
        confidence: 'Likely',
        mappings: { cwe: ['CWE-639'] },
        affectedUrl: 'https://x/api/users/1',
        affectedEndpoint: 'https://x/api/users/1',
        evidence: [{ a: 1 }],
        impact: '',
        remediation: '',
        references: [],
        status: 'Likely',
        issueFound: true,
        testMode: 'active-safe',
      } as unknown as Finding,
      {
        pluginId: 'idor-bac',
        title: 'Possible IDOR / BOLA on /api/users/2 (anonymous)',
        description: 'b',
        severity: 'High',
        confidence: 'Likely',
        mappings: { cwe: ['CWE-639'] },
        affectedUrl: 'https://x/api/users/2',
        affectedEndpoint: 'https://x/api/users/2',
        evidence: [{ a: 1 }, { b: 2 }],
        impact: '',
        remediation: '',
        references: [],
        status: 'Likely',
        issueFound: true,
        testMode: 'active-safe',
      } as unknown as Finding,
    ]);
    expect(out.filter((f) => f.issueFound)).toHaveLength(1);
    expect(out[0].evidence.length).toBeGreaterThanOrEqual(2);
  });
});

