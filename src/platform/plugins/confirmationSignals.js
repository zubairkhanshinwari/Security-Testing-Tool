/**
 * Typed confirmation signals for precision / confirmation-depth pack.
 * Confirmed requires at least one PROOF signal plus supporting evidence.
 */

const SUPPORT_SIGNALS = [
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
];

/** Independent proof that elevates beyond heuristics */
const PROOF_SIGNALS = [
  'boolean-diff',
  'cross-user',
  'reflection-unencoded',
  'error-marker',
  'negative-control',
  'reproducible',
  'timing-diff',
  'context-probe',
];

function uniqueSignals(list) {
  return [...new Set((list || []).filter(Boolean).map(String))];
}

function hasProof(signals) {
  const set = new Set(uniqueSignals(signals));
  return PROOF_SIGNALS.some((s) => set.has(s));
}

/**
 * Grade confidence from typed signals.
 * @returns {'Confirmed'|'Likely'|'Possible'|'Informational'}
 */
function gradeFromSignals(signals, { issueFound = true } = {}) {
  if (!issueFound) return 'Informational';
  const labels = uniqueSignals(signals);
  const proof = labels.filter((s) => PROOF_SIGNALS.includes(s));
  const support = labels.filter((s) => SUPPORT_SIGNALS.includes(s) || !PROOF_SIGNALS.includes(s));
  const total = labels.length;

  if (proof.length >= 1 && (total >= 3 || proof.length >= 2)) return 'Confirmed';
  if (proof.length >= 1 || total >= 3) return 'Likely';
  if (total >= 1) return 'Possible';
  return 'Informational';
}

function evidenceWithSignals(technique, signals, extra = {}) {
  return {
    technique,
    signals: uniqueSignals(signals),
    significant: hasProof(signals),
    ...extra,
  };
}

module.exports = {
  SUPPORT_SIGNALS,
  PROOF_SIGNALS,
  uniqueSignals,
  hasProof,
  gradeFromSignals,
  evidenceWithSignals,
};
