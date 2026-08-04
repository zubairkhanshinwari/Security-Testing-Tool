import path from 'path';
import { describe, it, expect } from 'vitest';
import { PluginManager } from '../src/platform/plugins/PluginManager';
import { createLogger } from '../src/platform/core/logging/logger';

describe('PluginManager', () => {
  it('auto-registers modules with manifests', async () => {
    const mgr = new PluginManager(
      path.join(process.cwd(), 'modules'),
      createLogger('test', 'error'),
      [],
    );
    const plugins = await mgr.autoRegister();
    expect(plugins.length).toBeGreaterThanOrEqual(14);
    const ids = plugins.map((p) => p.manifest.id);
    expect(ids).toContain('sql-injection');
    expect(ids).toContain('nosql-injection');
    expect(ids).toContain('security-headers');
    expect(ids).toContain('xss');
    expect(ids).toContain('idor-bac');
    expect(ids).toContain('jwt');
    expect(ids).toContain('csrf');
    expect(ids).toContain('open-redirect');
    expect(ids).toContain('ssrf');
    expect(ids).toContain('ssti');
    expect(ids).toContain('lfi');
    expect(ids).toContain('cookie-security');
    expect(ids).toContain('session-mgmt');
  });

  it('filters by security types', async () => {
    const mgr = new PluginManager(
      path.join(process.cwd(), 'modules'),
      createLogger('test', 'error'),
      [],
    );
    await mgr.autoRegister();
    const selected = mgr.resolveForTypes(['http_headers']);
    expect(selected.map((p) => p.manifest.id)).toContain('security-headers');
  });

  it('runs all plugins when Select All (>=30 types)', async () => {
    const mgr = new PluginManager(
      path.join(process.cwd(), 'modules'),
      createLogger('test', 'error'),
      [],
    );
    const plugins = await mgr.autoRegister();
    const many = Array.from({ length: 35 }, (_, i) => `type_${i}`);
    const selected = mgr.resolveForTypes(many);
    expect(selected.length).toBe(plugins.length);
  });
});
