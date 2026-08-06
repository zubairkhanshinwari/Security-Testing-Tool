import net from 'net';
import { URL } from 'url';
import type { PluginManager } from '../../plugins/PluginManager';

export interface PreflightInput {
  targetUrl: string;
  selectedTypes: string[];
  pluginIds?: string[] | null;
  /** Soft timeout for liveness probe (ms). */
  timeoutMs?: number;
  pluginManager: PluginManager;
  /** Type ids known to have residual surfaceChecks coverage even without a dedicated plugin. */
  surfaceCapableTypes?: string[];
}

export interface PreflightResult {
  ok: boolean;
  targetAlive: boolean;
  /** True when failure looks like firewall drop / filtered path (not DNS/refused). */
  firewallLikely: boolean;
  reachabilityMethod: 'http' | 'tcp' | null;
  statusCode: number | null;
  latencyMs: number | null;
  errorCode: string | null;
  pluginsAvailable: boolean;
  pluginsRegistered: number;
  pluginsResolved: number;
  pluginIds: string[];
  implementedTypes: string[];
  unavailableTypes: string[];
  errors: string[];
  warnings: string[];
  summary: string;
}

const DEFAULT_SURFACE_TYPES = [
  'http_headers',
  'security_misconfig',
  'cors',
  'cookie_security',
  'session_mgmt',
  'sensitive_data',
  'info_disclosure',
  'jwt',
  'open_redirect',
  'xss',
  'api_security',
  'bac',
  'idor',
  'ssrf',
  'csrf',
  'rate_limiting',
  'broken_auth',
  'sqli',
  'nosqli',
  'weak_password',
  'file_upload',
  'clickjacking',
  'lfi',
  'path_traversal',
];

/**
 * Run before browser launch / recon (firewall-aware):
 * 1) Target must be reachable via HTTP (preferred) or TCP on the URL port
 *    — ICMP ping is NOT used (usually blocked behind firewalls)
 * 2) Security plugins must be registered and match the selection
 *
 * Plugin checks always run so operators see plugin status even when the node is filtered.
 */
export async function runPreflight(input: PreflightInput): Promise<PreflightResult> {
  const errors: string[] = [];
  const warnings: string[] = [];
  const timeoutMs = Math.max(3000, Number(input.timeoutMs || 12000));

  const alive = await checkTargetReachable(input.targetUrl, timeoutMs);
  if (!alive.ok) {
    const fwHint = alive.firewallLikely
      ? ' — node may be behind a firewall / filtered path; confirm VPN, allowlist, or exposed port'
      : '';
    errors.push(
      `Target not reachable (${alive.error || 'connection failed'})${fwHint}` +
        (alive.detail ? ` [${alive.detail}]` : ''),
    );
  } else if (alive.reachabilityMethod === 'tcp') {
    warnings.push(
      'HTTP probe failed but TCP port is open — host may be firewalled at layer-7 or require a different path/TLS.',
    );
  } else if (alive.statusCode && alive.statusCode >= 500) {
    warnings.push(
      `Target responded with HTTP ${alive.statusCode} — reachable (possibly through firewall) but may be unhealthy.`,
    );
  } else if (alive.statusCode === 401 || alive.statusCode === 403) {
    warnings.push(
      `Target returned HTTP ${alive.statusCode} — endpoint is alive behind auth/WAF; continue with credentials if authorized.`,
    );
  }

  // Always evaluate plugins — even when the node is down/firewalled
  const registered = input.pluginManager.list();
  const pluginsRegistered = registered.length;
  if (pluginsRegistered === 0) {
    errors.push('No security plugins are registered. Check the modules/ directory and server logs.');
  }

  const resolved = input.pluginManager.resolveForTypes(
    input.selectedTypes || [],
    input.pluginIds?.length ? input.pluginIds : undefined,
  );
  const pluginIds = resolved.map((p) => p.manifest.id);
  const pluginsResolved = pluginIds.length;

  const coveredTypeIds = new Set<string>();
  for (const p of resolved) {
    for (const id of p.manifest.securityTypeIds || []) coveredTypeIds.add(id);
  }

  const surfaceSet = new Set(input.surfaceCapableTypes || DEFAULT_SURFACE_TYPES);
  const selected = [...new Set(input.selectedTypes || [])].filter((t) => t !== 'owasp_top10');
  const implementedTypes: string[] = [];
  const unavailableTypes: string[] = [];

  for (const t of selected) {
    const byPlugin =
      coveredTypeIds.has(t) || resolved.some((p) => (p.manifest.securityTypeIds || []).includes(t));
    const bySurface = surfaceSet.has(t);
    const anyPluginForType = registered.some((p) => (p.manifest.securityTypeIds || []).includes(t));
    if (byPlugin || anyPluginForType || bySurface) {
      implementedTypes.push(t);
    } else {
      unavailableTypes.push(t);
    }
  }

  if (unavailableTypes.length && implementedTypes.length) {
    warnings.push(
      `Catalog-only types (no scanner): ${unavailableTypes.slice(0, 8).join(', ')}${
        unavailableTypes.length > 8 ? '…' : ''
      }`,
    );
  }

  let pluginsOk = pluginsRegistered > 0 && pluginsResolved > 0;
  if (pluginsRegistered > 0 && pluginsResolved === 0) {
    const surfaceOnly = selected.some((t) => surfaceSet.has(t));
    if (!surfaceOnly && selected.length) {
      errors.push(
        `Security plugins not available for selected types (${selected.slice(0, 10).join(', ') || 'none'}). ` +
          `Use Select available / Select recommended.`,
      );
      pluginsOk = false;
    } else if (!selected.length) {
      errors.push('No security types selected and no plugins resolved.');
      pluginsOk = false;
    } else if (surfaceOnly && unavailableTypes.length === selected.length) {
      errors.push('Selected types have no implemented plugin coverage.');
      pluginsOk = false;
    } else {
      // Residual surface-only path — allow but warn
      pluginsOk = surfaceOnly;
      if (surfaceOnly) {
        warnings.push('No dedicated plugins matched; residual surface checks may still run.');
      }
    }
  }

  if (selected.length && implementedTypes.length === 0 && pluginsResolved === 0) {
    errors.push(
      `None of the selected security methods have a plugin: ${
        unavailableTypes.join(', ') || selected.join(', ')
      }`,
    );
    pluginsOk = false;
  }

  const ok = errors.length === 0 && alive.ok;
  const summary = ok
    ? `Preflight OK — target reachable via ${alive.reachabilityMethod?.toUpperCase()} ` +
      `(HTTP ${alive.statusCode ?? 'n/a'}, ${alive.latencyMs ?? '?'}ms); ` +
      `plugins available ${pluginsResolved}/${pluginsRegistered}` +
      (warnings.length ? `; ${warnings.length} warning(s)` : '')
    : `Preflight FAILED — ${errors.join(' | ')}` +
      (pluginsRegistered
        ? ` | plugins: ${pluginsResolved}/${pluginsRegistered} matched`
        : ' | plugins: none registered');

  return {
    ok,
    targetAlive: alive.ok,
    firewallLikely: Boolean(alive.firewallLikely),
    reachabilityMethod: alive.reachabilityMethod,
    statusCode: alive.statusCode,
    latencyMs: alive.latencyMs,
    errorCode: ok ? null : alive.ok ? 'PLUGINS' : alive.firewallLikely ? 'FIREWALL_FILTERED' : 'TARGET_DOWN',
    pluginsAvailable: pluginsOk,
    pluginsRegistered,
    pluginsResolved,
    pluginIds,
    implementedTypes,
    unavailableTypes,
    errors,
    warnings,
    summary,
  };
}

/** @deprecated use checkTargetReachable — kept for tests / callers */
export async function checkTargetAlive(targetUrl: string, timeoutMs = 12000) {
  const r = await checkTargetReachable(targetUrl, timeoutMs);
  return {
    ok: r.ok,
    statusCode: r.statusCode,
    latencyMs: r.latencyMs,
    error: r.error,
    detail: r.detail,
  };
}

/**
 * Firewall-aware reachability:
 * - HTTP HEAD → GET (any status including 401/403/WAF = alive)
 * - If HTTP times out / host unreachable → TCP connect to URL port
 * - Does NOT use ICMP ping (almost always blocked behind corporate firewalls)
 */
export async function checkTargetReachable(
  targetUrl: string,
  timeoutMs = 12000,
): Promise<{
  ok: boolean;
  statusCode: number | null;
  latencyMs: number | null;
  reachabilityMethod: 'http' | 'tcp' | null;
  firewallLikely: boolean;
  error?: string;
  detail?: string;
}> {
  const started = Date.now();
  const httpTimeout = Math.max(2000, Math.floor(timeoutMs * 0.7));
  const tcpTimeout = Math.max(1500, timeoutMs - httpTimeout);

  const http = await probeHttp(targetUrl, httpTimeout);
  if (http.ok) {
    return {
      ok: true,
      statusCode: http.statusCode,
      latencyMs: Date.now() - started,
      reachabilityMethod: 'http',
      firewallLikely: false,
    };
  }

  // HTTP failed — try TCP to distinguish closed port vs firewall drop
  const tcp = await probeTcp(targetUrl, tcpTimeout);
  if (tcp.ok) {
    return {
      ok: true,
      statusCode: null,
      latencyMs: Date.now() - started,
      reachabilityMethod: 'tcp',
      firewallLikely: http.firewallLikely,
      detail: `HTTP failed (${http.error}); TCP port open`,
    };
  }

  const firewallLikely =
    http.firewallLikely ||
    tcp.firewallLikely ||
    http.error === 'timeout' ||
    tcp.error === 'timeout' ||
    http.error === 'host_unreachable' ||
    tcp.error === 'host_unreachable';

  return {
    ok: false,
    statusCode: null,
    latencyMs: Date.now() - started,
    reachabilityMethod: null,
    firewallLikely,
    error: firewallLikely ? 'firewall_filtered' : http.error || tcp.error || 'unreachable',
    detail: [http.detail, tcp.detail].filter(Boolean).join('; ').slice(0, 240),
  };
}

async function probeHttp(
  targetUrl: string,
  timeoutMs: number,
): Promise<{
  ok: boolean;
  statusCode: number | null;
  error?: string;
  detail?: string;
  firewallLikely: boolean;
}> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let res = await fetch(targetUrl, {
      method: 'HEAD',
      redirect: 'follow',
      signal: controller.signal,
      headers: { 'user-agent': 'SecureAssess-Preflight/2.0' },
    }).catch(() => null);

    if (!res || res.status === 405 || res.status === 501) {
      res = await fetch(targetUrl, {
        method: 'GET',
        redirect: 'follow',
        signal: controller.signal,
        headers: { 'user-agent': 'SecureAssess-Preflight/2.0' },
      });
    }

    // Any HTTP response (incl. 401/403/404/5xx) means the node path is alive
    return { ok: true, statusCode: res.status, firewallLikely: false };
  } catch (err: any) {
    const classified = classifyNetworkError(err);
    return {
      ok: false,
      statusCode: null,
      error: classified.error,
      detail: classified.detail,
      firewallLikely: classified.firewallLikely,
    };
  } finally {
    clearTimeout(timer);
  }
}

function probeTcp(
  targetUrl: string,
  timeoutMs: number,
): Promise<{
  ok: boolean;
  error?: string;
  detail?: string;
  firewallLikely: boolean;
}> {
  return new Promise((resolve) => {
    let host: string;
    let port: number;
    try {
      const u = new URL(targetUrl);
      host = u.hostname.replace(/^\[|\]$/g, '');
      port = u.port ? Number(u.port) : u.protocol === 'https:' ? 443 : 80;
    } catch {
      resolve({ ok: false, error: 'invalid_url', firewallLikely: false });
      return;
    }

    const socket = new net.Socket();
    let settled = false;
    const finish = (result: {
      ok: boolean;
      error?: string;
      detail?: string;
      firewallLikely: boolean;
    }) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {
        /* ignore */
      }
      resolve(result);
    };

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish({ ok: true, firewallLikely: false }));
    socket.once('timeout', () =>
      finish({
        ok: false,
        error: 'timeout',
        detail: `TCP ${host}:${port} timed out`,
        firewallLikely: true,
      }),
    );
    socket.once('error', (err: NodeJS.ErrnoException) => {
      const classified = classifyNetworkError(err);
      finish({
        ok: false,
        error: classified.error,
        detail: `TCP ${host}:${port}: ${classified.detail}`,
        firewallLikely: classified.firewallLikely,
      });
    });
    socket.connect(port, host);
  });
}

function classifyNetworkError(err: any): {
  error: string;
  detail: string;
  firewallLikely: boolean;
} {
  const name = err?.name || '';
  const code = String(err?.code || '');
  const msg = String(err?.message || err);
  const blob = `${code} ${msg}`;

  if (name === 'AbortError' || /aborted|timeout|ETIMEDOUT/i.test(blob)) {
    return { error: 'timeout', detail: msg.slice(0, 200), firewallLikely: true };
  }
  if (/ENOTFOUND|getaddrinfo/i.test(blob)) {
    return { error: 'dns_failed', detail: msg.slice(0, 200), firewallLikely: false };
  }
  if (/ECONNREFUSED/i.test(blob)) {
    return { error: 'connection_refused', detail: msg.slice(0, 200), firewallLikely: false };
  }
  if (/EHOSTUNREACH|ENETUNREACH|ECONNRESET/i.test(blob)) {
    return { error: 'host_unreachable', detail: msg.slice(0, 200), firewallLikely: true };
  }
  if (/CERT|SSL|TLS|UNABLE_TO_VERIFY/i.test(blob)) {
    // TLS error usually means something answered — treat as reachability signal at TCP layer;
    // for HTTP fetch failure, operator may need allow-insecure in lab only.
    return { error: 'tls_error', detail: msg.slice(0, 200), firewallLikely: false };
  }
  return { error: 'unreachable', detail: msg.slice(0, 200), firewallLikely: /filter|firewall|drop/i.test(blob) };
}
