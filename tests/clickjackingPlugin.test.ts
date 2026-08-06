import { describe, expect, it } from 'vitest';
import {
  createPlugin,
  analyzeFrameProtection,
  extractFrameAncestors,
} from '../modules/clickjacking/scanner.js';
import manifest from '../modules/clickjacking/manifest.json';

describe('Clickjacking plugin', () => {
  const plugin = createPlugin(manifest as any);

  it('is enabled and maps clickjacking', () => {
    expect(manifest.enabledByDefault).toBe(true);
    expect(manifest.recommended).toBe(true);
    expect(manifest.securityTypeIds).toContain('clickjacking');
  });

  it('extracts frame-ancestors from CSP', () => {
    expect(extractFrameAncestors("default-src 'self'; frame-ancestors 'none'")).toBe("'none'");
    expect(extractFrameAncestors("frame-ancestors 'self' https://partner.example")).toContain("'self'");
    expect(extractFrameAncestors("default-src 'self'")).toBeNull();
  });

  it('treats DENY / SAMEORIGIN / frame-ancestors as protected', () => {
    expect(analyzeFrameProtection({ 'x-frame-options': 'DENY' }).protected).toBe(true);
    expect(analyzeFrameProtection({ 'x-frame-options': 'SAMEORIGIN' }).protected).toBe(true);
    expect(
      analyzeFrameProtection({ 'content-security-policy': "frame-ancestors 'none'" }).protected,
    ).toBe(true);
    expect(
      analyzeFrameProtection({ 'content-security-policy': "frame-ancestors 'self'" }).level,
    ).toBe('ok');
  });

  it('flags missing and weak policies', () => {
    const missing = analyzeFrameProtection({});
    expect(missing.protected).toBe(false);
    expect(missing.level).toBe('missing');

    const weakStar = analyzeFrameProtection({
      'content-security-policy': 'frame-ancestors *',
    });
    expect(weakStar.protected).toBe(false);
    expect(weakStar.level).toBe('weak');

    const weakAllowFrom = analyzeFrameProtection({
      'x-frame-options': 'ALLOW-FROM https://evil.example',
    });
    expect(weakAllowFrom.protected).toBe(false);
    expect(weakAllowFrom.level).toBe('weak');
  });

  it('discover includes homepage', async () => {
    const { targets } = await plugin.discover({
      request: { targetUrl: 'https://example.com/app' },
      attackSurface: { endpoints: [], forms: [] },
    } as any);
    expect(targets.some((t: any) => t.endpoint.includes('example.com'))).toBe(true);
  });

  it('verify raises on missing frame protection', async () => {
    const findings = await plugin.verify({} as any, [
      {
        endpoint: 'https://example.com/login',
        note: 'homepage',
        status: 200,
        headers: {},
        analysis: analyzeFrameProtection({}),
      },
    ]);
    expect(findings[0].issueFound).toBe(true);
    expect(findings[0].module).toBe('Clickjacking');
    expect(findings[0].severity).toBe('Medium');
  });

  it('verify passes when protected', async () => {
    const headers = { 'x-frame-options': 'DENY' };
    const findings = await plugin.verify({} as any, [
      {
        endpoint: 'https://example.com/',
        note: 'homepage',
        status: 200,
        headers,
        analysis: analyzeFrameProtection(headers),
      },
    ]);
    expect(findings[0].issueFound).toBe(false);
    expect(findings[0].status).toBe('Pass');
  });
});
