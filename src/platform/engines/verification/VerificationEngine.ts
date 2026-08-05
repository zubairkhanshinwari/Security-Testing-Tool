import type { Confidence, Finding, Severity } from '../../core/types/finding';
import type { Logger } from '../../core/logging/logger';
import { extractStructuredSignals, hasProof, uniqueSignals } from './confirmationSignals';

/**
 * Verification Engine — normalize → family-dedupe → multi-signal confidence.
 * Confirmation-depth: Confirmed requires a PROOF signal (boolean-diff, cross-user,
 * reflection-unencoded, error-marker, etc.) plus supporting evidence.
 */
export class VerificationEngine {
  constructor(private readonly logger: Logger) {}

  /** Full post-probe pipeline: assign ids → dedupe issues → confidence / FP tempering. */
  process(findings: Finding[]): Finding[] {
    return this.verifyFindings(this.dedupe(this.normalizeIds(findings)));
  }

  /**
   * End-of-scan gate: Confirmed without proof signals is demoted (no live re-exploit).
   * Marks verification.retested = true when proof is present.
   */
  retestConfirmed(findings: Finding[]): Finding[] {
    return findings.map((raw) => {
      const f = { ...raw };
      if (!f.issueFound) return f;
      const signals = uniqueSignals([
        ...(f.verification?.signals || []),
        ...extractStructuredSignals(f.evidence),
      ]);
      const proof = hasProof(signals);
      if (f.status === 'Confirmed' || f.confidence === 'Confirmed') {
        if (!proof) {
          f.confidence = 'High Confidence';
          f.status = 'Likely';
          f.description = `${f.description}\n\n[Confirmation] Demoted — Confirmed requires a proof signal (boolean-diff / cross-user / unencoded reflection / error-marker).`;
          f.verification = {
            signalCount: signals.length,
            signals: [...signals, 'confirmed-retest-demote'],
            retestRecommended: true,
          };
        } else {
          f.verification = {
            signalCount: signals.length,
            signals,
            retestRecommended: false,
            retested: true,
          } as Finding['verification'];
        }
      }
      return f;
    });
  }

  normalizeIds(findings: Finding[]): Finding[] {
    let i = 1;
    let p = 1;
    return findings.map((f) => {
      const copy = { ...f };
      if (!copy.id) {
        copy.id = copy.issueFound
          ? `FIND-${String(i++).padStart(3, '0')}`
          : `PASS-${String(p++).padStart(3, '0')}`;
      }
      return copy;
    });
  }

  dedupe(findings: Finding[]): Finding[] {
    const issues = new Map<string, Finding>();
    const passes: Finding[] = [];
    for (const f of findings) {
      if (!f.issueFound) {
        passes.push(f);
        continue;
      }
      const key = familyKey(f);
      const prev = issues.get(key);
      if (!prev) {
        issues.set(key, f);
        continue;
      }
      issues.set(key, mergeFindings(prev, f));
    }
    return [...issues.values(), ...passes];
  }

  verifyFindings(findings: Finding[]): Finding[] {
    const out: Finding[] = [];
    for (const raw of findings) {
      const f = { ...raw, confidence: this.normalizeConfidence(raw.confidence) };
      if (!f.issueFound) {
        f.confidence = 'Informational';
        f.status = 'Pass';
        out.push(f);
        continue;
      }

      const signals = this.collectSignals(f);
      let confidence = this.calculateConfidence(f, signals);

      // Precision gate: High/Critical need ≥2 signals; otherwise temper severity/confidence
      if ((f.severity === 'Critical' || f.severity === 'High') && signals.count < 2) {
        f.severity = this.downgrade(f.severity);
        if (confidence === 'Confirmed' || confidence === 'High Confidence') {
          confidence = 'Medium Confidence';
        }
        f.description = `${f.description}\n\n[Precision] Severity tempered — fewer than two independent evidence signals (baseline/differential/http).`;
      }

      // Confirmation-depth: never keep Confirmed without a proof signal
      if (confidence === 'Confirmed' && !hasProof(signals.labels)) {
        confidence = 'High Confidence';
        f.description = `${f.description}\n\n[Confirmation] Needs a proof signal for Confirmed (boolean-diff / cross-user / reflection-unencoded / error-marker).`;
      }

      f.confidence = confidence;
      f.verification = {
        signalCount: signals.count,
        signals: signals.labels,
        retestRecommended: confidence !== 'Confirmed',
      };

      f.status =
        confidence === 'Confirmed'
          ? 'Confirmed'
          : confidence === 'Informational'
            ? 'Informational'
            : confidence === 'High Confidence'
              ? 'Likely'
              : 'Possible';

      const hasEvidence =
        (f.evidence && f.evidence.length > 0) || (f.http && f.http.length > 0);
      if (!hasEvidence) {
        this.logger.warn('Dropping finding without evidence', { title: f.title });
        continue;
      }

      // Require baseline/differential OR multi-http for injection CWEs at High+
      const injection = (f.mappings?.cwe || []).some((c) =>
        ['CWE-89', 'CWE-79', 'CWE-943', 'CWE-918', 'CWE-94', 'CWE-1336'].includes(c),
      );
      if (
        injection &&
        (raw.severity === 'Critical' || raw.severity === 'High') &&
        !signals.labels.includes('differential') &&
        !signals.labels.includes('baseline-diff') &&
        !signals.labels.includes('boolean-diff') &&
        !signals.labels.includes('error-marker') &&
        !signals.labels.includes('reflection-unencoded') &&
        !signals.httpPair &&
        signals.count < 3
      ) {
        f.severity = 'Medium';
        f.confidence = 'Medium Confidence';
        f.status = 'Possible';
        f.description = `${f.description}\n\n[Precision] Injection finding needs baseline/differential confirmation for High severity.`;
        f.verification = {
          ...f.verification,
          signals: [...(f.verification?.signals || []), 'precision-injection-gate'],
          retestRecommended: true,
        };
      }

      out.push(f);
    }
    return out;
  }

  normalizeConfidence(c: string | undefined): Confidence {
    switch (c) {
      case 'Confirmed':
        return 'Confirmed';
      case 'High Confidence':
      case 'Likely':
        return 'High Confidence';
      case 'Medium Confidence':
      case 'Possible':
        return 'Medium Confidence';
      case 'Low Confidence':
        return 'Low Confidence';
      case 'Informational':
        return 'Informational';
      default:
        return 'Medium Confidence';
    }
  }

  private collectSignals(f: Finding) {
    const labels: string[] = [];
    let count = 0;
    const push = (label: string) => {
      if (!labels.includes(label)) {
        labels.push(label);
        count += 1;
      }
    };

    const evidenceCount = f.evidence?.length || 0;
    const httpCount = f.http?.length || 0;
    if (evidenceCount >= 1) push('evidence');
    if (evidenceCount >= 2) push('multi-evidence');
    if (httpCount >= 1) push('http');
    if (httpCount >= 2) push('cross-request');

    const structured = extractStructuredSignals(f.evidence);
    for (const s of structured) push(s);

    const blob = `${f.title} ${f.description} ${JSON.stringify(f.evidence || []).slice(0, 1200)}`;
    if (/differential|boolean|time-based|reproduced|confirmed|baseline/i.test(blob)) {
      push('differential');
    }
    if (/baseline-diff|significant.*baseline|compareToBaseline/i.test(blob)) {
      push('baseline-diff');
    }
    if (/sql error|mongodb|cast to objectid|syntax error|51091|root:.*:0:0:/i.test(blob)) {
      push('technology-error');
    }
    if ((f.techniques || []).length >= 2) push('multi-technique');

    for (const ev of f.evidence || []) {
      if (ev && typeof ev === 'object') {
        const o = ev as Record<string, unknown>;
        if (o.baselineDiff || o.significant === true || o.technique === 'baseline-compare') {
          push('baseline-diff');
        }
      }
    }
    return { count, labels: uniqueSignals(labels), httpPair: httpCount >= 2 };
  }

  calculateConfidence(f: Finding, signals = this.collectSignals(f)): Confidence {
    const proof = hasProof(signals.labels);
    // Confirmed: proof + enough support (or dual proof)
    if (proof && (signals.count >= 3 || signals.labels.filter((l) => hasProof([l])).length >= 2)) {
      return 'Confirmed';
    }
    if (proof || signals.count >= 3 || (signals.httpPair && signals.labels.includes('technology-error'))) {
      return 'High Confidence';
    }
    if (signals.count >= 2) return 'Medium Confidence';
    if (signals.count >= 1) return 'Low Confidence';
    return 'Informational';
  }

  private downgrade(sev: Severity): Severity {
    if (sev === 'Critical') return 'High';
    if (sev === 'High') return 'Medium';
    return sev;
  }
}

function familyKey(f: Finding): string {
  const cwe = (f.mappings?.cwe || f.cwe || []).slice(0, 2).join(',') || 'none';
  const endpoint = String(f.affectedEndpoint || f.affectedUrl || '')
    .split('?')[0]
    .replace(/\/\d+/g, '/{id}')
    .replace(/\/[0-9a-f]{8,}/gi, '/{id}')
    .toLowerCase();
  const title = String(f.title || '')
    .replace(/\([^)]*\)/g, '')
    .replace(/on\s+\S+/gi, 'on')
    .replace(/via\s+.*/i, '')
    .replace(/["'`]/g, '')
    .trim()
    .toLowerCase()
    .slice(0, 60);
  return `${f.pluginId || 'plugin'}|${cwe}|${endpoint}|${title}`;
}

function mergeFindings(a: Finding, b: Finding): Finding {
  const evidence = [...(a.evidence || [])];
  for (const e of b.evidence || []) {
    const key = JSON.stringify(e).slice(0, 200);
    if (!evidence.some((x) => JSON.stringify(x).slice(0, 200) === key)) evidence.push(e);
  }
  const http = [...(a.http || []), ...(b.http || [])].slice(0, 8);
  const techniques = [...new Set([...(a.techniques || []), ...(b.techniques || [])])];
  const richer = (b.evidence?.length || 0) > (a.evidence?.length || 0) ? b : a;
  return {
    ...richer,
    evidence: evidence.slice(0, 12),
    http,
    techniques,
    description: richer.description,
  };
}
