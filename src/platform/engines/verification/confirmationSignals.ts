/** Typed confirmation signals — keep in sync with plugins/confirmationSignals.js */

export const SUPPORT_SIGNALS = [
  'evidence',
  'multi-evidence',
  'http',
  'cross-request',
  'baseline-diff',
  'multi-technique',
  'technology-error',
  'json-typed',
  'body-diff',
  'length-diff',
  'status-diff',
] as const;

export const PROOF_SIGNALS = [
  'boolean-diff',
  'cross-user',
  'reflection-unencoded',
  'error-marker',
  'negative-control',
  'reproducible',
  'timing-diff',
  'context-probe',
] as const;

export type ProofSignal = (typeof PROOF_SIGNALS)[number];

export function uniqueSignals(list: unknown[]): string[] {
  return [...new Set((list || []).filter(Boolean).map(String))];
}

export function hasProof(signals: string[]): boolean {
  const set = new Set(uniqueSignals(signals));
  return PROOF_SIGNALS.some((s) => set.has(s));
}

export function extractStructuredSignals(evidence: Array<string | Record<string, unknown>> | undefined): string[] {
  const out: string[] = [];
  for (const ev of evidence || []) {
    if (!ev || typeof ev !== 'object') continue;
    const o = ev as Record<string, unknown>;
    if (Array.isArray(o.signals)) out.push(...(o.signals as string[]));
    if (Array.isArray(o.confirmationSignals)) out.push(...(o.confirmationSignals as string[]));
    if (o.technique === 'baseline-compare' || o.baselineDiff) out.push('baseline-diff');
    if (o.unencoded === true) out.push('reflection-unencoded');
    if (o.crossUser === true) out.push('cross-user');
    if (o.reproducible === true) out.push('reproducible');
    if (o.negativeControl === true) out.push('negative-control');
  }
  return uniqueSignals(out);
}
