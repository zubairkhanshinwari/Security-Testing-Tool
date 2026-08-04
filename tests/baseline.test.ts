import { describe, expect, it } from 'vitest';
import {
  buildBaselineFromResult,
  diffBaseline,
  endpointKey,
  findingKey,
} from '../src/platform/dashboard/baseline';
import type { AttackSurface, ScanResult } from '../src/platform/core/types/finding';

const surface = (endpoints: Array<{ url: string; method?: string }>): AttackSurface => ({
  hosts: ['example.com'],
  subdomains: [],
  pages: ['https://example.com/'],
  endpoints: endpoints.map((e) => ({ url: e.url, method: e.method || 'GET' })),
  parameters: [],
  forms: [],
  cookies: [],
  headers: {},
  frameworks: [],
  libraries: [],
  authEndpoints: [],
  apiBases: ['https://example.com/api'],
  websockets: [],
  graphql: [],
  openapi: [],
  storageKeys: [],
});

describe('baseline helpers', () => {
  it('builds baseline from scan result and diffs new endpoints', () => {
    const result = {
      meta: { targetUrl: 'https://example.com', technology: { server: ['nginx'] } },
      attackSurface: surface([
        { url: 'https://example.com/api/users' },
        { url: 'https://example.com/api/login', method: 'POST' },
      ]),
      findings: [
        {
          id: 'FIND-001',
          pluginId: 'sql-injection',
          title: 'SQLi via id',
          description: '',
          severity: 'High',
          confidence: 'Confirmed',
          mappings: { cwe: ['CWE-89'] },
          affectedUrl: 'https://example.com/api/users',
          affectedEndpoint: 'https://example.com/api/users',
          evidence: ['x'],
          impact: '',
          remediation: '',
          references: [],
          status: 'Confirmed',
          issueFound: true,
          testMode: 'active-safe',
        },
      ],
      risk: {
        overallScore: 70,
        overallRisk: 'High',
        severityCounts: {
          Critical: 0,
          High: 1,
          Medium: 0,
          Low: 0,
          Informational: 0,
        },
        owaspCoverage: {},
        riskPriority: [],
      },
      assessmentSummary: [],
      stats: {},
    } as ScanResult;

    const baseline = buildBaselineFromResult('proj-1', 'scan-1', result);
    expect(baseline.endpoints).toHaveLength(2);
    expect(baseline.confirmedFindings).toHaveLength(1);
    expect(baseline.confirmedFindings[0].pluginId).toBe('sql-injection');
    expect(findingKey(baseline.confirmedFindings[0] as any)).toContain('CWE-89');

    const nextSurface = surface([
      { url: 'https://example.com/api/users' },
      { url: 'https://example.com/api/login', method: 'POST' },
      { url: 'https://example.com/api/orders' },
    ]);
    const diff = diffBaseline(baseline, nextSurface);
    expect(diff.available).toBe(true);
    expect(diff.newEndpoints).toEqual(['https://example.com/api/orders']);
    expect(diff.focusEndpoints).toEqual(
      expect.arrayContaining([
        'https://example.com/api/orders',
        'https://example.com/api/users',
      ]),
    );
    expect(diff.retestPluginIds).toEqual(['sql-injection']);
    expect(endpointKey('https://example.com/api/users/', 'get')).toBe(
      'GET https://example.com/api/users',
    );
  });

  it('returns unavailable diff when baseline is null', () => {
    const diff = diffBaseline(null, surface([{ url: 'https://example.com/' }]));
    expect(diff.available).toBe(false);
    expect(diff.focusEndpoints).toEqual([]);
  });
});
