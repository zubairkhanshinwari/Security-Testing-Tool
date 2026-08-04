import { describe, expect, it } from 'vitest';
import { applyProfileToConfig, resolveScanProfile } from '../src/platform/core/config/scanProfiles';

describe('scanProfiles', () => {
  it('resolves quick/standard/deep', () => {
    expect(resolveScanProfile('quick').discovery.maxPagesCrawl).toBe(4);
    expect(resolveScanProfile('deep').discovery.maxPagesCrawl).toBe(16);
    expect(resolveScanProfile('nope').id).toBe('standard');
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
});
