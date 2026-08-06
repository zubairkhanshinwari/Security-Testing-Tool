import { describe, expect, it } from 'vitest';
import { createPlugin, FILE_PARAMS, FILE_PROBES } from '../modules/lfi/scanner.js';
import manifest from '../modules/lfi/manifest.json';

describe('LFI plugin', () => {
  const plugin = createPlugin(manifest as any);

  it('is enabled and maps lfi + path_traversal', () => {
    expect(manifest.enabledByDefault).toBe(true);
    expect(manifest.recommended).toBe(true);
    expect(manifest.securityTypeIds).toContain('lfi');
    expect(manifest.securityTypeIds).toContain('path_traversal');
  });

  it('recognizes file-like parameter names', () => {
    expect(FILE_PARAMS.test('file')).toBe(true);
    expect(FILE_PARAMS.test('filepath')).toBe(true);
    expect(FILE_PARAMS.test('include')).toBe(true);
    expect(FILE_PARAMS.test('q')).toBe(false);
  });

  it('includes unix and windows safe probes', () => {
    expect(FILE_PROBES.some((p) => p.platform === 'unix')).toBe(true);
    expect(FILE_PROBES.some((p) => p.platform === 'windows')).toBe(true);
    expect(FILE_PROBES.every((p) => Array.isArray(p.markers) && p.markers.length)).toBe(true);
  });

  it('discover seeds file/path params even without surface hints', async () => {
    const { targets } = await plugin.discover({
      request: { targetUrl: 'https://example.com/app' },
      attackSurface: { parameters: [], endpoints: [], forms: [] },
    } as any);
    expect(targets.length).toBeGreaterThan(0);
    expect(targets.some((t: any) => t.parameter === 'file')).toBe(true);
  });

  it('verify marks pass when no hits', async () => {
    const findings = await plugin.verify({} as any, [
      {
        endpoint: 'https://example.com/?file=x',
        parameter: 'file',
        payload: '../../../etc/passwd',
        hit: false,
        status: 200,
        bodySnippet: 'ok',
        signals: [],
      },
    ]);
    expect(findings[0].issueFound).toBe(false);
    expect(findings[0].status).toBe('Pass');
  });

  it('verify raises Likely High on strong baseline-diff hit', async () => {
    const findings = await plugin.verify({} as any, [
      {
        endpoint: 'https://example.com/?file=../../../etc/passwd',
        parameter: 'file',
        payload: '../../../etc/passwd',
        platform: 'unix',
        soft: false,
        hit: true,
        status: 200,
        bodySnippet: 'root:x:0:0:root:/root:/bin/bash',
        signals: ['baseline-diff', 'file-marker', 'os-file-signature'],
      },
    ]);
    expect(findings[0].issueFound).toBe(true);
    expect(findings[0].severity).toBe('High');
    expect(findings[0].confidence).toBe('Likely');
    expect(findings[0].module).toMatch(/LFI/i);
  });
});
