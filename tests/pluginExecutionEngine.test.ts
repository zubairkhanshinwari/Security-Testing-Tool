import { describe, expect, it } from 'vitest';
import { PluginExecutionEngine } from '../src/platform/engines/execution/PluginExecutionEngine';
import { KnowledgeRepository, createScanId } from '../src/platform/core/knowledge';
import { createLogger } from '../src/platform/core/logging/logger';
import type { SecurityPlugin } from '../src/platform/core/types/plugin';
import type { ScanPlan } from '../src/platform/engines/planning/ScanPlanningEngine';
import type { AttackSurface, PluginManifest } from '../src/platform/core/types/finding';

function manifest(id: string): PluginManifest {
  return {
    id,
    name: id,
    version: '1.0.0',
    description: '',
    category: 'test',
    enabledByDefault: true,
    recommended: true,
    securityTypeIds: ['http_headers'],
    owasp: [],
    cwe: [],
    modes: ['active-safe'],
  };
}

function makePlugin(
  id: string,
  hooks: {
    delayMs?: number;
    fail?: boolean;
    onRun?: () => void;
  } = {},
): SecurityPlugin {
  return {
    manifest: manifest(id),
    async initialize() {
      /* optional */
    },
    async discover() {
      return { targets: [] };
    },
    async scan() {
      hooks.onRun?.();
      if (hooks.delayMs) await new Promise((r) => setTimeout(r, hooks.delayMs));
      if (hooks.fail) throw new Error(`${id} failed`);
      return [];
    },
    async verify() {
      return [
        {
          id: undefined as any,
          pluginId: id,
          title: `${id} ok`,
          description: '',
          severity: 'Informational',
          confidence: 'Informational',
          mappings: { cwe: [] },
          affectedUrl: 'https://example.com',
          affectedEndpoint: 'https://example.com',
          evidence: [],
          impact: 'None',
          remediation: 'n/a',
          references: [],
          status: 'Pass',
          issueFound: false,
          testMode: 'active-safe',
        },
      ];
    },
    async cleanup() {
      /* optional */
    },
    async report() {
      return {};
    },
    async score() {
      return { delta: 0, notes: [] };
    },
  };
}

const surface: AttackSurface = {
  hosts: ['example.com'],
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
};

describe('PluginExecutionEngine', () => {
  const logger = createLogger('test', 'error', false);

  it('runs HTTP-lane plugins concurrently and isolates failures', async () => {
    const running: number[] = [];
    let peak = 0;
    const bump = () => {
      running.push(1);
      peak = Math.max(peak, running.length);
    };
    const drop = () => {
      running.pop();
    };

    const a = makePlugin('a', {
      delayMs: 40,
      onRun: () => {
        bump();
      },
    });
    const b = makePlugin('b', {
      delayMs: 40,
      onRun: () => {
        bump();
      },
    });
    const c = makePlugin('c', { fail: true });

    // Wrap scan to drop concurrency after finish
    for (const p of [a, b]) {
      const orig = p.scan.bind(p);
      p.scan = async (ctx, d) => {
        try {
          return await orig(ctx, d);
        } finally {
          drop();
        }
      };
    }

    const plan: ScanPlan = {
      plugins: [a, b, c],
      pluginIds: ['a', 'b', 'c'],
      tasks: [
        {
          id: 't-a',
          kind: 'plugin',
          pluginId: 'a',
          priority: 10,
          lane: 'http',
          reason: 'test',
        },
        {
          id: 't-b',
          kind: 'plugin',
          pluginId: 'b',
          priority: 10,
          lane: 'http',
          reason: 'test',
        },
        {
          id: 't-c',
          kind: 'plugin',
          pluginId: 'c',
          priority: 10,
          lane: 'http',
          reason: 'test',
        },
      ],
      surfaceTypes: [],
      skippedPlugins: [],
      mode: 'active-safe',
      httpConcurrencyHint: 2,
      summary: 'test',
    };

    const repo = new KnowledgeRepository(
      {
        scanId: createScanId(),
        request: { targetUrl: 'https://example.com', authorized: true },
        mode: 'active-safe',
        requestedTypes: [],
        selectedTypes: [],
        catalogSize: 0,
        startedAt: new Date(),
      },
      logger,
    );
    repo.setAttackSurface(surface);
    repo.setSession({ ok: false, type: 'none' });

    const executor = new PluginExecutionEngine(logger, {});
    const result = await executor.execute({
      plan,
      ctx: {
        request: { targetUrl: 'https://example.com', authorized: true },
        attackSurface: surface,
        auth: { ok: false, type: 'none' },
        page: {},
        browserContext: {},
        logger,
        config: {},
        selectedTypes: [],
      },
      repo,
      targetUrl: 'https://example.com',
    });

    expect(result.errors.some((e) => e.pluginId === 'c')).toBe(true);
    expect(repo.getFindings().filter((f) => f.pluginId === 'a' || f.pluginId === 'b')).toHaveLength(
      2,
    );
    expect(peak).toBeGreaterThanOrEqual(2);
    repo.dispose();
  });

  it('invokes initialize and cleanup hooks', async () => {
    const calls: string[] = [];
    const plugin = makePlugin('hooks');
    plugin.initialize = async () => {
      calls.push('init');
    };
    plugin.cleanup = async () => {
      calls.push('cleanup');
    };
    const origVerify = plugin.verify.bind(plugin);
    plugin.verify = async (ctx, c) => {
      calls.push('verify');
      return origVerify(ctx, c);
    };

    const plan: ScanPlan = {
      plugins: [plugin],
      pluginIds: ['hooks'],
      tasks: [
        {
          id: 't-hooks',
          kind: 'plugin',
          pluginId: 'hooks',
          priority: 10,
          lane: 'browser',
          reason: 'test',
        },
      ],
      surfaceTypes: [],
      skippedPlugins: [],
      mode: 'active-safe',
      httpConcurrencyHint: 1,
      summary: 'hooks',
    };

    const repo = new KnowledgeRepository(
      {
        scanId: createScanId(),
        request: { targetUrl: 'https://example.com', authorized: true },
        mode: 'active-safe',
        requestedTypes: [],
        selectedTypes: [],
        catalogSize: 0,
        startedAt: new Date(),
      },
      logger,
    );
    repo.setAttackSurface(surface);

    const executor = new PluginExecutionEngine(logger, { scan: { browserLaneConcurrency: 1 } });
    await executor.execute({
      plan,
      ctx: {
        request: { targetUrl: 'https://example.com', authorized: true },
        attackSurface: surface,
        auth: { ok: false, type: 'none' },
        page: {},
        browserContext: {},
        logger,
        config: {},
        selectedTypes: [],
      },
      repo,
      targetUrl: 'https://example.com',
    });

    expect(calls).toEqual(['init', 'verify', 'cleanup']);
    // discover/scan also run; ensure cleanup always last
    expect(calls[calls.length - 1]).toBe('cleanup');
    repo.dispose();
  });
});
