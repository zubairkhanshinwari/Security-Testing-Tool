/**
 * CommonJS mirror of baselineCompare for plugins.
 */

const ERROR_MARKERS =
  /sql syntax|mysql_|postgresql|ora-\d+|mongodb|cast to objectid|sqlite_|odbc|unhandled exception|stack trace|syntax error/i;

function compareToBaseline(baseline, probe) {
  const baseLen = baseline.length ?? (baseline.body || '').length;
  const probeLen = probe.length ?? (probe.body || '').length;
  const lengthDelta = Math.abs(probeLen - baseLen);
  const relativeLengthDelta = baseLen > 0 ? lengthDelta / baseLen : lengthDelta > 0 ? 1 : 0;
  const statusDiff = (baseline.status || 0) !== (probe.status || 0);
  const bodyChanged =
    Boolean(baseline.body || probe.body) &&
    String(baseline.body || '').slice(0, 800) !== String(probe.body || '').slice(0, 800);
  const suspiciousError =
    ERROR_MARKERS.test(probe.body || '') && !ERROR_MARKERS.test(baseline.body || '');
  const timeDeltaMs = Math.abs((probe.ms || 0) - (baseline.ms || 0));

  const signals = [];
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

module.exports = { compareToBaseline };
