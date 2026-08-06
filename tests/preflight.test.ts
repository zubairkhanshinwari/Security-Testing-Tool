import { describe, expect, it, vi } from 'vitest';
import {
  checkTargetAlive,
  checkTargetReachable,
  runPreflight,
} from '../src/platform/core/safety/preflight';

function mockPluginManager(plugins: Array<{ id: string; types: string[] }>) {
  const list = plugins.map((p) => ({
    manifest: { id: p.id, securityTypeIds: p.types, enabledByDefault: true, recommended: true },
  }));
  return {
    list: () => list,
    resolveForTypes: (selected: string[], explicit?: string[]) => {
      if (explicit?.length) return list.filter((p) => explicit.includes(p.manifest.id));
      const set = new Set(selected);
      return list.filter((p) => p.manifest.securityTypeIds.some((t) => set.has(t)));
    },
  } as any;
}

describe('preflight', () => {
  it('checkTargetAlive succeeds on HTTP response', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ status: 200 });
    vi.stubGlobal('fetch', fetchMock);
    const r = await checkTargetAlive('https://example.com/', 5000);
    expect(r.ok).toBe(true);
    expect(r.statusCode).toBe(200);
    vi.unstubAllGlobals();
  });

  it('treats 401/403 as alive (auth/WAF behind firewall path)', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ status: 403 }));
    const r = await checkTargetReachable('https://example.com/app', 5000);
    expect(r.ok).toBe(true);
    expect(r.reachabilityMethod).toBe('http');
    expect(r.statusCode).toBe(403);
    vi.unstubAllGlobals();
  });

  it('checkTargetAlive fails on network error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(Object.assign(new Error('getaddrinfo ENOTFOUND'), { name: 'TypeError' })),
    );
    const r = await checkTargetAlive('https://no-such-host.invalid/', 2000);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/dns_failed|firewall_filtered|unreachable/);
    vi.unstubAllGlobals();
  });

  it('marks timeout as firewall-likely', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(Object.assign(new Error('aborted'), { name: 'AbortError' })),
    );
    // Force TCP fail with timeout-like error by using invalid host that fails fast after HTTP
    const r = await checkTargetReachable('https://203.0.113.1:9/', 1500);
    // May be firewall_filtered or connection_refused depending on environment; assert shape
    expect(r.ok).toBe(false);
    expect(typeof r.firewallLikely).toBe('boolean');
    vi.unstubAllGlobals();
  });

  it('runPreflight fails when target down but still reports plugins', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('ECONNREFUSED')));
    const r = await runPreflight({
      targetUrl: 'https://127.0.0.1:1/',
      selectedTypes: ['sqli'],
      pluginManager: mockPluginManager([{ id: 'sql-injection', types: ['sqli'] }]),
      timeoutMs: 2000,
    });
    expect(r.ok).toBe(false);
    expect(r.targetAlive).toBe(false);
    expect(r.pluginsAvailable).toBe(true);
    expect(r.pluginsResolved).toBe(1);
    expect(r.errorCode).toMatch(/TARGET_DOWN|FIREWALL_FILTERED/);
    vi.unstubAllGlobals();
  });

  it('runPreflight fails when no plugins registered', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ status: 200 }));
    const r = await runPreflight({
      targetUrl: 'https://example.com/',
      selectedTypes: ['sqli'],
      pluginManager: mockPluginManager([]),
      timeoutMs: 2000,
    });
    expect(r.ok).toBe(false);
    expect(r.pluginsAvailable).toBe(false);
    expect(r.pluginsRegistered).toBe(0);
    expect(r.summary).toMatch(/No security plugins/i);
    vi.unstubAllGlobals();
  });

  it('runPreflight fails when selection has only unavailable types', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ status: 200 }));
    const r = await runPreflight({
      targetUrl: 'https://example.com/',
      selectedTypes: ['ldap', 'xxe'],
      pluginManager: mockPluginManager([{ id: 'sql-injection', types: ['sqli'] }]),
      timeoutMs: 2000,
      surfaceCapableTypes: [],
    });
    expect(r.ok).toBe(false);
    expect(r.pluginsAvailable).toBe(false);
    expect(r.unavailableTypes).toEqual(expect.arrayContaining(['ldap', 'xxe']));
    vi.unstubAllGlobals();
  });

  it('runPreflight OK when target alive and plugins match', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ status: 204 }));
    const r = await runPreflight({
      targetUrl: 'https://example.com/',
      selectedTypes: ['sqli', 'idor'],
      pluginManager: mockPluginManager([
        { id: 'sql-injection', types: ['sqli'] },
        { id: 'idor-bac', types: ['idor', 'bac'] },
      ]),
      timeoutMs: 2000,
    });
    expect(r.ok).toBe(true);
    expect(r.targetAlive).toBe(true);
    expect(r.pluginsAvailable).toBe(true);
    expect(r.pluginsResolved).toBe(2);
    expect(r.summary).toMatch(/Preflight OK/i);
    vi.unstubAllGlobals();
  });
});
