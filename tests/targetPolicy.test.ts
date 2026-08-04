import { describe, it, expect } from 'vitest';
import { validateTargetUrl, isBlockedIp } from '../src/platform/core/safety/targetPolicy';

describe('targetPolicy', () => {
  it('allows public https URLs', () => {
    const r = validateTargetUrl('https://example.com/app');
    expect(r.ok).toBe(true);
  });

  it('blocks localhost', () => {
    const r = validateTargetUrl('http://localhost:3000');
    expect(r.ok).toBe(false);
  });

  it('blocks private IPv4', () => {
    expect(isBlockedIp('10.0.0.5')).toBe(true);
    expect(isBlockedIp('192.168.1.1')).toBe(true);
    expect(isBlockedIp('172.16.0.1')).toBe(true);
    expect(isBlockedIp('8.8.8.8')).toBe(false);
  });

  it('blocks metadata IP', () => {
    const r = validateTargetUrl('http://169.254.169.254/latest/meta-data');
    expect(r.ok).toBe(false);
  });
});
