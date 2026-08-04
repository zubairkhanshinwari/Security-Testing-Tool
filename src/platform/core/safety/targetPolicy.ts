import { isIP } from 'net';
import { URL } from 'url';

export interface TargetPolicyResult {
  ok: boolean;
  reason?: string;
  hostname?: string;
}

/**
 * Blocks scans against loopback, RFC1918, link-local, and cloud metadata hosts.
 * Optional allowlist via SECUREASSESS_ALLOWLIST=example.com,.example.com
 * Override private block with SECUREASSESS_ALLOW_PRIVATE=1 (local lab only).
 */
export function validateTargetUrl(targetUrl: string): TargetPolicyResult {
  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    return { ok: false, reason: 'Invalid URL' };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { ok: false, reason: 'Only http/https targets are allowed' };
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!hostname) return { ok: false, reason: 'Missing hostname' };

  const allowPrivate = process.env.SECUREASSESS_ALLOW_PRIVATE === '1';
  const allowlist = (process.env.SECUREASSESS_ALLOWLIST || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);

  if (allowlist.length) {
    const allowed = allowlist.some((entry) => {
      if (entry.startsWith('.')) return hostname.endsWith(entry) || hostname === entry.slice(1);
      return hostname === entry || hostname.endsWith(`.${entry}`);
    });
    if (!allowed) {
      return {
        ok: false,
        reason: `Host ${hostname} is not in SECUREASSESS_ALLOWLIST`,
        hostname,
      };
    }
  }

  if (!allowPrivate && isBlockedHost(hostname)) {
    return {
      ok: false,
      reason:
        `Target host "${hostname}" is blocked (loopback/private/link-local/metadata). ` +
        `For local labs set SECUREASSESS_ALLOW_PRIVATE=1.`,
      hostname,
    };
  }

  return { ok: true, hostname };
}

export function isBlockedHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost') || h === '0.0.0.0') return true;
  if (h === 'metadata.google.internal' || h === 'metadata' || h.endsWith('.internal')) {
    // cloud metadata / internal DNS patterns commonly abused for SSRF
    if (h.includes('metadata')) return true;
  }
  if (h === '169.254.169.254' || h.startsWith('169.254.')) return true;

  const ipVersion = isIP(h);
  if (ipVersion) return isBlockedIp(h);

  return false;
}

export function isBlockedIp(ip: string): boolean {
  if (ip.includes(':')) {
    // IPv6 loopback / unique local / link-local
    const v = ip.toLowerCase();
    if (v === '::1' || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80')) return true;
    return false;
  }
  const parts = ip.split('.').map((n) => Number(n));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return false;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  return false;
}
