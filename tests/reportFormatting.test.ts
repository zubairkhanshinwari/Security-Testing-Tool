import { describe, expect, it } from 'vitest';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const { formatCvss } = require('../src/report/htmlReport.js');
const { isAnalyticsCookie } = require('../modules/cookie-security/scanner.js');

describe('trust pack formatting helpers', () => {
  it('formats CVSS objects instead of [object Object]', () => {
    expect(formatCvss({ score: 7.5, severity: 'High', vector: 'CVSS:4.0/AV:N' })).toMatch(/7\.5/);
    expect(formatCvss({ score: 7.5, severity: 'High', vector: 'CVSS:4.0/AV:N' })).not.toMatch(/object Object/);
    expect(formatCvss(9.1)).toBe('9.1');
    expect(formatCvss(null)).toBe('N/A');
  });

  it('skips analytics cookies', () => {
    expect(isAnalyticsCookie('_ga')).toBe(true);
    expect(isAnalyticsCookie('_fbp')).toBe(true);
    expect(isAnalyticsCookie('session_id')).toBe(false);
    expect(isAnalyticsCookie('auth_token')).toBe(false);
  });
});
