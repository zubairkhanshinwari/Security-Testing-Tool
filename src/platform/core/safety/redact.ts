const SENSITIVE_KEY =
  /(authorization|access[_-]?token|refresh[_-]?token|password|passwd|secret|api[_-]?key|cookie|set-cookie|x-api-key)/i;

/**
 * Deep-redact secrets from objects before persistence / reporting.
 */
export function redactSecrets<T>(input: T, depth = 0): T {
  if (depth > 12 || input == null) return input;
  if (typeof input === 'string') return redactString(input) as unknown as T;
  if (Array.isArray(input)) return input.map((v) => redactSecrets(v, depth + 1)) as unknown as T;
  if (typeof input === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
      if (SENSITIVE_KEY.test(k)) {
        out[k] = typeof v === 'string' && v.length ? '[REDACTED]' : v == null ? v : '[REDACTED]';
      } else if (/^screenshot(Base64|LiveBase64)$/i.test(k) && typeof v === 'string') {
        // Preserve evidence image payloads (large binary strings)
        out[k] = v;
      } else {
        out[k] = redactSecrets(v, depth + 1);
      }
    }
    return out as T;
  }
  return input;
}

export function redactString(value: string): string {
  let s = value;
  s = s.replace(/Bearer\s+[A-Za-z0-9._\-]+/gi, 'Bearer [REDACTED]');
  s = s.replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '[REDACTED_JWT]');
  s = s.replace(/(Authorization\s*[:=]\s*)([^\s,;]+)/gi, '$1[REDACTED]');
  return s;
}
