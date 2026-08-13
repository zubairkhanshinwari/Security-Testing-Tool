/**
 * Authorization gate for CIS Linux assessment targets. Deliberately a
 * separate module from src/platform/core/safety/targetPolicy.ts rather than
 * a modification of it — targetPolicy.ts blocks private/loopback/internal
 * hosts by design (correct for a DAST web scan), which is the *opposite* of
 * what a CIS Linux assessment target usually is (an internal server reached
 * over SSH). This module requires an explicit allowlist instead of blocking
 * private ranges.
 */

export interface LinuxHostPolicyResult {
  ok: boolean;
  reason?: string;
  hostname?: string;
}

export interface LinuxHostPolicyInput {
  hostname: string;
  authorized: boolean;
}

/**
 * Reads SECUREASSESS_LINUX_ALLOWLIST (comma-separated hostnames/IPs, optional
 * leading "." for domain-suffix match) at call time so tests can mutate
 * process.env between assertions without module-reload gymnastics.
 */
function getAllowlist(): string[] {
  return (process.env.SECUREASSESS_LINUX_ALLOWLIST || '')
    .split(',')
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
}

export function isAllowedLinuxHost(hostname: string): boolean {
  const allowlist = getAllowlist();
  if (allowlist.length === 0) return false;
  const host = hostname.toLowerCase();
  return allowlist.some((entry) => (entry.startsWith('.') ? host.endsWith(entry) : host === entry));
}

export function validateLinuxTarget(input: LinuxHostPolicyInput): LinuxHostPolicyResult {
  if (!input.authorized) {
    return { ok: false, reason: 'Explicit authorization is required before assessing a Linux host.' };
  }
  if (!input.hostname) {
    return { ok: false, reason: 'A target hostname/IP is required.' };
  }
  if (!isAllowedLinuxHost(input.hostname)) {
    return {
      ok: false,
      reason:
        'Target host is not on the authorized Linux assessment allowlist (SECUREASSESS_LINUX_ALLOWLIST).',
      hostname: input.hostname,
    };
  }
  return { ok: true, hostname: input.hostname };
}
