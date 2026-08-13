import { describe, it, expect, afterEach } from 'vitest';
import { validateLinuxTarget, isAllowedLinuxHost } from '../../src/compliance/safety/linuxHostPolicy';

const ORIGINAL = process.env.SECUREASSESS_LINUX_ALLOWLIST;

afterEach(() => {
  if (ORIGINAL === undefined) delete process.env.SECUREASSESS_LINUX_ALLOWLIST;
  else process.env.SECUREASSESS_LINUX_ALLOWLIST = ORIGINAL;
});

describe('linuxHostPolicy', () => {
  it('rejects when authorized is false regardless of allowlist', () => {
    process.env.SECUREASSESS_LINUX_ALLOWLIST = 'internal-host.example';
    const result = validateLinuxTarget({ hostname: 'internal-host.example', authorized: false });
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/authorization is required/i);
  });

  it('rejects a host not present on the allowlist', () => {
    process.env.SECUREASSESS_LINUX_ALLOWLIST = 'internal-host.example';
    const result = validateLinuxTarget({ hostname: 'random-other-host.example', authorized: true });
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/not on the authorized/i);
  });

  it('accepts an exact-match allowlisted host when authorized', () => {
    process.env.SECUREASSESS_LINUX_ALLOWLIST = 'internal-host.example,10.0.0.5';
    expect(validateLinuxTarget({ hostname: 'internal-host.example', authorized: true }).ok).toBe(true);
    expect(validateLinuxTarget({ hostname: '10.0.0.5', authorized: true }).ok).toBe(true);
  });

  it('supports domain-suffix allowlist entries (leading dot)', () => {
    process.env.SECUREASSESS_LINUX_ALLOWLIST = '.corp.example';
    expect(isAllowedLinuxHost('web-01.corp.example')).toBe(true);
    expect(isAllowedLinuxHost('web-01.notcorp.example')).toBe(false);
  });

  it('rejects everything when no allowlist is configured (fail closed)', () => {
    delete process.env.SECUREASSESS_LINUX_ALLOWLIST;
    expect(validateLinuxTarget({ hostname: 'anything.example', authorized: true }).ok).toBe(false);
  });

  it('rejects a missing hostname', () => {
    process.env.SECUREASSESS_LINUX_ALLOWLIST = 'host.example';
    expect(validateLinuxTarget({ hostname: '', authorized: true }).ok).toBe(false);
  });
});
