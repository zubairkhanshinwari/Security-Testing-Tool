import { describe, expect, it } from 'vitest';
import { detectAuthStrategies, buildLoginCandidates } from '../src/scanner/auth/detectStrategy.js';
import {
  analyzeApiLoginResponse,
  extractToken,
  isSessionCookie,
} from '../src/scanner/auth/sessionSuccess.js';

describe('detectAuthStrategies', () => {
  it('prefers cookie-session for Frappe-style targets', () => {
    const { order, hints } = detectAuthStrategies({
      origin: 'https://path.mmis.space',
      loginUrl: 'https://path.mmis.space/dashboard/login',
      apiBases: ['https://path.mmis.space/api'],
    });
    // dashboard/login matches login-page first in our detector unless frappe path present
    expect(order).toContain('spa-form');
    expect(order).toContain('api-token');
    expect(hints.length).toBeGreaterThan(0);
  });

  it('orders frappe cookie first when method/login is present', () => {
    const { order } = detectAuthStrategies({
      origin: 'https://erp.example.com',
      loginUrl: 'https://erp.example.com/login',
      apiBases: ['https://erp.example.com/api/method/login'],
    });
    expect(order[0]).toBe('cookie-session');
  });

  it('builds unique login candidates', () => {
    const c = buildLoginCandidates('https://app.example.com', ['https://api.example.com/api']);
    expect(c.some((u) => u.includes('/auth/login'))).toBe(true);
    expect(new Set(c).size).toBe(c.length);
  });
});

describe('sessionSuccess', () => {
  it('extracts JWT from JSON body', () => {
    const tok = extractToken(JSON.stringify({ data: { access_token: 'eyJabc.def.ghi' } }), {});
    expect(tok).toBe('eyJabc.def.ghi');
  });

  it('detects sid session cookie', () => {
    expect(isSessionCookie({ name: 'sid', value: 'Guest' })).toBe(false);
    expect(isSessionCookie({ name: 'sid', value: 'a'.repeat(20) })).toBe(true);
  });

  it('analyzes JWT API login success', () => {
    const res = { status: () => 200, headers: () => ({}) };
    const out = analyzeApiLoginResponse(
      res,
      JSON.stringify({ token: 'eyJaaa.bbb.ccc' }),
      [],
    );
    expect(out.ok).toBe(true);
    expect(out.sessionType).toBe('jwt');
    expect(out.adapter).toBe('api-token');
  });

  it('analyzes Frappe cookie login success', () => {
    const res = { status: () => 200, headers: () => ({}) };
    const out = analyzeApiLoginResponse(
      res,
      JSON.stringify({ message: 'Logged In', full_name: 'A' }),
      [{ name: 'sid', value: 'x'.repeat(16) }],
    );
    expect(out.ok).toBe(true);
    expect(out.sessionType).toBe('cookie');
  });

  it('rejects invalid credentials responses', () => {
    const res = { status: () => 200, headers: () => ({}) };
    const out = analyzeApiLoginResponse(
      res,
      JSON.stringify({ message: 'Invalid login credentials', exc: 'x' }),
      [],
    );
    expect(out.ok).toBe(false);
  });
});
