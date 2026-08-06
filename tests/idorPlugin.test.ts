import { describe, expect, it } from 'vitest';
import {
  createPlugin,
  ID_PARAMS,
  OBJECT_PATH_RE,
  neighborIds,
  negativeControlUrl,
  isSensitiveExposure,
  replaceObjectId,
} from '../modules/idor-bac/scanner.js';
import manifest from '../modules/idor-bac/manifest.json';

describe('IDOR / BAC plugin', () => {
  const plugin = createPlugin(manifest as any);

  it('is enabled and maps idor + bac', () => {
    expect(manifest.enabledByDefault).toBe(true);
    expect(manifest.recommended).toBe(true);
    expect(manifest.securityTypeIds).toContain('idor');
    expect(manifest.securityTypeIds).toContain('bac');
  });

  it('recognizes object paths and id params', () => {
    expect('/api/users/42'.match(OBJECT_PATH_RE)?.[2]).toBe('42');
    expect('/api/orders/9'.match(OBJECT_PATH_RE)?.[1]).toMatch(/orders?/i);
    expect('/api/tickets/1'.match(OBJECT_PATH_RE)).toBeTruthy();
    expect(ID_PARAMS.test('userId')).toBe(true);
    expect(ID_PARAMS.test('order_id')).toBe(true);
    expect(ID_PARAMS.test('q')).toBe(false);
  });

  it('generates numeric neighbor ids', () => {
    expect(neighborIds('10')).toEqual(expect.arrayContaining(['11', '9', '12']));
    expect(neighborIds('abc-uuid')).toEqual([]);
  });

  it('builds negative control and replaces path ids', () => {
    expect(negativeControlUrl('https://ex.com/api/users/5')).toContain('/users/999999991');
    expect(replaceObjectId('https://ex.com/api/users/5', '5', '6')).toContain('/users/6');
  });

  it('detects sensitive JSON exposure', () => {
    expect(
      isSensitiveExposure({
        status: 200,
        contentType: 'application/json',
        bodySnippet: '{"email":"a@b.com","role":"user"}',
      }),
    ).toBe(true);
    expect(
      isSensitiveExposure({
        status: 200,
        contentType: 'text/html',
        bodySnippet: '<!doctype html><html>',
      }),
    ).toBe(false);
  });

  it('discover seeds object endpoints from apiBases', async () => {
    const { targets } = await plugin.discover({
      request: { targetUrl: 'https://example.com/app' },
      attackSurface: {
        parameters: [{ name: 'userId', endpoint: 'https://example.com/api/profile' }],
        endpoints: [{ method: 'GET', url: 'https://example.com/api/orders/55' }],
        apiBases: ['https://example.com/api'],
        forms: [],
      },
    } as any);
    expect(targets.length).toBeGreaterThan(0);
    expect(targets.some((t: any) => String(t.url).includes('/orders/'))).toBe(true);
    expect(targets.some((t: any) => String(t.url).includes('userId='))).toBe(true);
  });

  it('verify passes when no unauthorized exposure', async () => {
    const findings = await plugin.verify({} as any, [
      { mode: 'meta', dualAccount: false, hasAccountBCreds: false },
      {
        url: 'https://example.com/api/users/1',
        objectId: '1',
        mode: 'authenticated',
        status: 200,
        contentType: 'application/json',
        bodySnippet: '{"ok":true}',
        http: [],
      },
    ]);
    expect(findings[0].issueFound).toBe(false);
    expect(findings[0].status).toBe('Pass');
  });

  it('verify raises on anonymous sensitive exposure', async () => {
    const findings = await plugin.verify({} as any, [
      { mode: 'meta', dualAccount: false, hasAccountBCreds: false },
      {
        url: 'https://example.com/api/users/1',
        objectId: '1',
        mode: 'anonymous',
        status: 200,
        contentType: 'application/json',
        bodySnippet: '{"email":"victim@example.com","role":"admin"}',
        http: [{ request: { method: 'GET', url: 'https://example.com/api/users/1' } }],
      },
      {
        url: 'https://example.com/api/users/999999991',
        objectId: '999999991',
        mode: 'negative-control',
        negativeOf: 'https://example.com/api/users/1',
        status: 404,
        contentType: 'application/json',
        bodySnippet: '{"error":"not found"}',
        http: [],
      },
    ]);
    expect(findings[0].issueFound).toBe(true);
    expect(findings[0].severity).toBe('High');
    expect(findings[0].module).toMatch(/IDOR/i);
    expect(findings[0].title).toMatch(/anonymous/i);
  });

  it('verify raises on cross-user sensitive exposure', async () => {
    const findings = await plugin.verify({} as any, [
      { mode: 'meta', dualAccount: true, hasAccountBCreds: true },
      {
        url: 'https://example.com/api/orders/7',
        objectId: '7',
        mode: 'cross-user',
        status: 200,
        contentType: 'application/json',
        bodySnippet: '{"email":"owner@example.com","accountNumber":"99"}',
        http: [{ request: { method: 'GET', url: 'https://example.com/api/orders/7' } }],
        altUser: true,
      },
    ]);
    expect(findings[0].issueFound).toBe(true);
    expect(findings[0].title).toMatch(/Account B/i);
    expect(findings[0].techniques).toEqual(
      expect.arrayContaining(['Dual-account access (Account A → Account B)']),
    );
  });
});
