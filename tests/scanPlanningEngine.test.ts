import { describe, expect, it } from 'vitest';
import { ScanPlanningEngine } from '../src/platform/engines/planning/ScanPlanningEngine';
import { createLogger } from '../src/platform/core/logging/logger';
import type { SecurityPlugin } from '../src/platform/core/types/plugin';
import type { AttackSurface, PluginManifest } from '../src/platform/core/types/finding';
import type { PluginManager } from '../src/platform/plugins/PluginManager';

function manifest(partial: Partial<PluginManifest> & { id: string }): PluginManifest {
  return {
    name: partial.id,
    version: '1.0.0',
    description: '',
    category: 'test',
    enabledByDefault: true,
    recommended: true,
    securityTypeIds: [],
    owasp: [],
    cwe: [],
    modes: ['passive', 'active-safe', 'authenticated'],
    ...partial,
  };
}

function stubPlugin(m: PluginManifest): SecurityPlugin {
  return {
    manifest: m,
    async discover() {
      return { targets: [] };
    },
    async scan() {
      return [];
    },
    async verify() {
      return [];
    },
    async report() {
      return {};
    },
    async score() {
      return { delta: 0, notes: [] };
    },
  };
}

function fakeManager(plugins: SecurityPlugin[]): PluginManager {
  return {
    list: () => plugins,
    resolveForTypes(selectedTypes: string[], explicitIds?: string[]) {
      if (explicitIds?.length) return plugins.filter((p) => explicitIds.includes(p.manifest.id));
      const set = new Set(selectedTypes);
      return plugins.filter((p) => p.manifest.securityTypeIds.some((id) => set.has(id)));
    },
  } as unknown as PluginManager;
}

const emptySurface = (over: Partial<AttackSurface> = {}): AttackSurface => ({
  hosts: ['example.com'],
  subdomains: [],
  pages: ['https://example.com/'],
  endpoints: [{ url: 'https://example.com/api', method: 'GET' }],
  parameters: [{ endpoint: 'https://example.com/api', name: 'q', location: 'query' }],
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
  ...over,
});

describe('ScanPlanningEngine', () => {
  const logger = createLogger('test', 'error', false);

  const headers = stubPlugin(
    manifest({ id: 'security-headers', securityTypeIds: ['http_headers', 'security_misconfig'] }),
  );
  const cors = stubPlugin(manifest({ id: 'cors', securityTypeIds: ['cors'] }));
  const sqli = stubPlugin(manifest({ id: 'sql-injection', securityTypeIds: ['sqli'] }));
  const gql = stubPlugin(
    manifest({ id: 'graphql-checks', securityTypeIds: ['graphql'], tags: ['graphql'] }),
  );

  it('orders cheap HTTP plugins before injection and builds residual surface types', () => {
    const xss = stubPlugin(
      manifest({
        id: 'xss',
        securityTypeIds: ['xss'],
        tags: ['xss'],
        recommended: true,
      }),
    );
    const planner = new ScanPlanningEngine(
      logger,
      fakeManager([sqli, headers, cors, xss]),
    );
    const plan = planner.plan({
      requestedTypes: ['sqli', 'http_headers', 'cors', 'xss'],
      selectedTypes: ['sqli', 'http_headers', 'cors', 'xss', 'security_misconfig'],
      mode: 'active-safe',
      attackSurface: emptySurface(),
    });

    expect(plan.pluginIds).toEqual(['security-headers', 'cors', 'xss', 'sql-injection']);
    expect(plan.tasks[0].pluginId).toBe('security-headers');
    expect(plan.tasks[0].lane).toBe('http');
    expect(plan.surfaceTypes).not.toContain('xss'); // owned by xss plugin
    expect(plan.surfaceTypes).not.toContain('sqli'); // owned by plugin
    expect(plan.summary).toMatch(/4 plugin/);
  });

  it('skips injection plugins in passive mode', () => {
    const planner = new ScanPlanningEngine(logger, fakeManager([sqli, headers]));
    const plan = planner.plan({
      requestedTypes: ['sqli', 'http_headers'],
      selectedTypes: ['sqli', 'http_headers'],
      mode: 'passive',
      attackSurface: emptySurface(),
    });

    expect(plan.pluginIds).toEqual(['security-headers']);
    expect(plan.skippedPlugins.some((s) => s.id === 'sql-injection')).toBe(true);
    expect(plan.surfaceTypes).not.toContain('sqli');
  });

  it('skips GraphQL plugins when no GraphQL surface exists', () => {
    const planner = new ScanPlanningEngine(logger, fakeManager([headers, gql]));
    const plan = planner.plan({
      requestedTypes: ['http_headers', 'graphql'],
      selectedTypes: ['http_headers', 'graphql'],
      mode: 'active-safe',
      attackSurface: emptySurface({ graphql: [] }),
    });

    expect(plan.pluginIds).toEqual(['security-headers']);
    expect(plan.skippedPlugins).toEqual([
      { id: 'graphql-checks', reason: 'no GraphQL endpoints discovered' },
    ]);
  });

  it('reduces concurrency hint when WAF is fingerprinted', () => {
    const planner = new ScanPlanningEngine(logger, fakeManager([headers]));
    const plan = planner.plan({
      requestedTypes: ['http_headers'],
      selectedTypes: ['http_headers'],
      mode: 'active-safe',
      attackSurface: emptySurface(),
      fingerprint: { waf: 'cloudflare' },
      maxConcurrentProbes: 8,
    });
    expect(plan.httpConcurrencyHint).toBe(4);
  });

  it('boosts retest plugins first in incremental mode', () => {
    const planner = new ScanPlanningEngine(logger, fakeManager([headers, sqli, cors]));
    const plan = planner.plan({
      requestedTypes: ['sqli', 'http_headers', 'cors'],
      selectedTypes: ['sqli', 'http_headers', 'cors'],
      mode: 'active-safe',
      attackSurface: emptySurface(),
      incremental: true,
      retestConfirmed: true,
      baselineDiff: {
        available: true,
        baselineScanId: 'scan-prev',
        newEndpoints: ['https://example.com/api/new'],
        removedEndpoints: [],
        unchangedEndpoints: [],
        priorConfirmed: [
          {
            key: 'k',
            title: 'SQLi',
            severity: 'High',
            endpoint: 'https://example.com/api',
            pluginId: 'sql-injection',
            cwe: ['CWE-89'],
          },
        ],
        focusEndpoints: ['https://example.com/api/new', 'https://example.com/api'],
        retestPluginIds: ['sql-injection'],
      },
    });

    expect(plan.incremental).toBe(true);
    expect(plan.retestPluginIds).toEqual(['sql-injection']);
    expect(plan.tasks[0].pluginId).toBe('sql-injection');
    expect(plan.tasks[0].reason).toMatch(/Incremental retest/);
    expect(plan.focusEndpoints).toContain('https://example.com/api/new');
  });
});
