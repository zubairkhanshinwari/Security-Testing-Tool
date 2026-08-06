import { describe, expect, it } from 'vitest';
import {
  applyProfileToConfig,
  normalizeFocusEndpoints,
  profileEtaLabel,
  resolveScanProfile,
} from '../src/platform/core/config/scanProfiles';

describe('scanProfiles', () => {
  it('resolves quick/standard/deep/openapi/focused', () => {
    expect(resolveScanProfile('quick').discovery.maxPagesCrawl).toBe(4);
    expect(resolveScanProfile('deep').discovery.maxPagesCrawl).toBe(16);
    expect(resolveScanProfile('openapi').discovery.prioritizeOpenApi).toBe(true);
    expect(resolveScanProfile('openapi').discovery.maxOpenApiPaths).toBe(120);
    expect(resolveScanProfile('focused').discovery.prioritizeFocusSeeds).toBe(true);
    expect(resolveScanProfile('nope').id).toBe('standard');
  });

  it('boosts deep OpenAPI knobs when openApiUrl is set (keeps deep id)', () => {
    const { profile } = applyProfileToConfig({}, 'deep', {
      openApiUrl: 'https://dev.example.com/openapi.json',
    });
    expect(profile.id).toBe('deep');
    expect(profile.label).toBe('Deep');
    expect(profile.discovery.prioritizeOpenApi).toBe(true);
    expect(profile.discovery.maxOpenApiPaths).toBeGreaterThanOrEqual(120);
  });

  it('exposes ETA labels', () => {
    expect(profileEtaLabel(resolveScanProfile('quick'))).toMatch(/2/);
    expect(profileEtaLabel(resolveScanProfile('deep'))).toMatch(/15/);
  });

  it('merges profile into config', () => {
    const { config, profile } = applyProfileToConfig(
      { safety: { maxConcurrentProbes: 2 }, scan: { discovery: { parseOpenApi: true } } },
      'quick',
    );
    expect(profile.id).toBe('quick');
    expect(config.scan.discovery.maxPagesCrawl).toBe(4);
    expect(config.scan.discovery.parseOpenApi).toBe(true);
    expect(config.safety.requestTimeoutMs).toBe(8000);
  });

  it('normalizes focus endpoints against target origin', () => {
    const focus = normalizeFocusEndpoints('https://dev.example.com/app', [
      '/api/users',
      'https://dev.example.com/admin',
      'https://evil.com/x',
      'api/orders',
    ]);
    expect(focus).toContain('https://dev.example.com/api/users');
    expect(focus).toContain('https://dev.example.com/admin');
    expect(focus).toContain('https://dev.example.com/api/orders');
    expect(focus.some((u) => u.includes('evil.com'))).toBe(false);
  });

  it('accepts newline / comma focus strings', () => {
    const focus = normalizeFocusEndpoints(
      'https://app.example.com',
      '/a\n/b, /c',
    );
    expect(focus).toHaveLength(3);
  });
});
