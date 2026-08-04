/**
 * Precision helper — compare a probe response against a clean baseline.
 * Used to cut false positives from generic 500s / soft error pages.
 */

export interface ResponseSnapshot {
  status: number;
  body?: string;
  length?: number;
  ms?: number;
  contentType?: string;
}

export interface BaselineDiff {
  statusDiff: boolean;
  lengthDelta: number;
  relativeLengthDelta: number;
  bodyChanged: boolean;
  suspiciousError: boolean;
  timeDeltaMs: number;
  /** True when probe differs from baseline in a security-relevant way */
  significant: boolean;
  signals: string[];
}

const ERROR_MARKERS =
  /sql syntax|mysql_|postgresql|ora-\d+|mongodb|cast to objectid|sqlite_|odbc|unhandled exception|stack trace|syntax error/i;

export function compareToBaseline(baseline: ResponseSnapshot, probe: ResponseSnapshot): BaselineDiff {
  const baseLen = baseline.length ?? (baseline.body || '').length;
  const probeLen = probe.length ?? (probe.body || '').length;
  const lengthDelta = Math.abs(probeLen - baseLen);
  const relativeLengthDelta = baseLen > 0 ? lengthDelta / baseLen : lengthDelta > 0 ? 1 : 0;
  const statusDiff = (baseline.status || 0) !== (probe.status || 0);
  const bodyChanged =
    Boolean(baseline.body || probe.body) &&
    String(baseline.body || '').slice(0, 800) !== String(probe.body || '').slice(0, 800);
  const suspiciousError = ERROR_MARKERS.test(probe.body || '') && !ERROR_MARKERS.test(baseline.body || '');
  const timeDeltaMs = Math.abs((probe.ms || 0) - (baseline.ms || 0));

  const signals: string[] = [];
  if (statusDiff) signals.push('status-diff');
  if (lengthDelta >= 40 || relativeLengthDelta >= 0.08) signals.push('length-diff');
  if (bodyChanged) signals.push('body-diff');
  if (suspiciousError) signals.push('error-marker');
  if (timeDeltaMs >= 2500) signals.push('timing-diff');

  const significant =
    suspiciousError ||
    (statusDiff && bodyChanged) ||
    (signals.includes('length-diff') && bodyChanged) ||
    signals.includes('timing-diff');

  return {
    statusDiff,
    lengthDelta,
    relativeLengthDelta,
    bodyChanged,
    suspiciousError,
    timeDeltaMs,
    significant,
    signals,
  };
}

/** Prefer high-value injection parameters first. */
export function rankParameterName(name: string): number {
  const n = String(name || '').toLowerCase();
  if (/^(id|user_?id|account_?id|order_?id|q|query|search|keyword|email|file|path|url|redirect|next|callback)$/.test(n)) {
    return 0;
  }
  if (/id$|name|term|filter|sort|page|limit|offset/.test(n)) return 1;
  if (/password|csrf|token|_method|captcha|nonce/.test(n)) return 9;
  return 5;
}

export function sortByParamPriority<T extends { parameter?: string; name?: string }>(items: T[]): T[] {
  return [...items].sort(
    (a, b) =>
      rankParameterName(String(a.parameter || a.name || '')) -
      rankParameterName(String(b.parameter || b.name || '')),
  );
}
