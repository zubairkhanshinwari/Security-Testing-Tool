import type { Finding, RiskSummary, Severity } from '../../core/types/finding';
import type { Logger } from '../../core/logging/logger';

/** Base points deducted for the first finding in a family (manual-assessment model). */
const SEV_WEIGHT: Record<Severity, number> = {
  Critical: 30,
  High: 18,
  Medium: 6,
  Low: 4,
  Informational: 0,
};

const CONF_FACTOR: Record<string, number> = {
  Confirmed: 1,
  'High Confidence': 0.9,
  Likely: 0.85,
  'Medium Confidence': 0.65,
  Possible: 0.55,
  'Low Confidence': 0.35,
  Informational: 0.15,
};

/** Extra occurrences of the same issue family count less (avoids 0/100 from duplicate IDOR paths). */
const FAMILY_DIMINISH = [1, 0.45, 0.22, 0.12, 0.08];

/**
 * Risk Engine — CVSS-aware weighted scoring with confidence & family diminishing returns.
 * Phase 5: consume findings only after VerificationEngine (+ optional EvidenceEngine).
 */
export class RiskEngine {
  constructor(private readonly logger: Logger) {}

  /** Alias emphasizing post-verification input (Phase 5 pipeline). */
  evaluateVerified(findings: Finding[]): RiskSummary {
    return this.evaluate(findings);
  }

  evaluate(findings: Finding[]): RiskSummary {
    const issues = findings.filter((f) => f.issueFound);
    const severityCounts: Record<Severity, number> = {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
      Informational: 0,
    };

    let deduction = 0;
    const riskPriority: RiskSummary['riskPriority'] = [];
    const owaspCoverage: Record<string, number> = {};

    for (const f of issues) {
      severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
    }

    const families = new Map<string, Finding[]>();
    for (const f of issues) {
      const key = familyKey(f);
      if (!families.has(key)) families.set(key, []);
      families.get(key)!.push(f);
    }

    for (const [, group] of families) {
      // Strongest confidence / CVSS first so the full weight applies to the best signal
      group.sort((a, b) => confRank(b.confidence) - confRank(a.confidence));

      group.forEach((f, index) => {
        const conf = CONF_FACTOR[normalizeConfidence(f.confidence)] ?? 0.55;
        const dim = FAMILY_DIMINISH[Math.min(index, FAMILY_DIMINISH.length - 1)];
        const cvssAdj = f.cvss?.score
          ? Math.min(1.15, Math.max(0.85, f.cvss.score / 8))
          : 1;
        const delta = SEV_WEIGHT[f.severity] * conf * dim * cvssAdj;
        deduction += delta;

        riskPriority.push({
          findingId: f.id,
          priority: Math.round(delta * 10),
          rationale: `${f.severity}/${f.confidence}; family#${index + 1}; CVSS ${f.cvss?.score ?? 'n/a'}`,
        });

        for (const o of f.mappings?.owaspTop10 || []) {
          owaspCoverage[o] = (owaspCoverage[o] || 0) + 1;
        }
        if (f.owasp) owaspCoverage[String(f.owasp)] = (owaspCoverage[String(f.owasp)] || 0) + 1;
      });
    }

    riskPriority.sort((a, b) => b.priority - a.priority);

    // Soft ceiling keeps a readable band; Critical-heavy scans can still reach near-zero
    const maxDeduction = severityCounts.Critical >= 2 ? 98 : severityCounts.Critical ? 92 : 88;
    const overallScore = Math.max(0, Math.min(100, Math.round(100 - Math.min(deduction, maxDeduction))));
    const overallRisk = this.overallRisk(severityCounts);

    this.logger.info('Risk evaluated', {
      overallScore,
      overallRisk,
      issues: issues.length,
      families: families.size,
      rawDeduction: Math.round(deduction),
    });

    return {
      overallScore,
      overallRisk,
      severityCounts,
      owaspCoverage,
      riskPriority,
    };
  }

  private overallRisk(counts: Record<Severity, number>): Severity {
    if (counts.Critical) return 'Critical';
    if (counts.High) return 'High';
    if (counts.Medium) return 'Medium';
    if (counts.Low) return 'Low';
    return 'Informational';
  }
}

function normalizeConfidence(value: string | undefined): string {
  const v = String(value || '').trim();
  if (/^high/i.test(v)) return 'High Confidence';
  if (/^medium/i.test(v)) return 'Medium Confidence';
  if (/^low/i.test(v)) return 'Low Confidence';
  return v;
}

function confRank(value: string | undefined): number {
  return CONF_FACTOR[normalizeConfidence(value)] ?? 0.5;
}

function familyKey(f: Finding): string {
  const cwe = (f.mappings?.cwe || f.cwe || [])[0] || 'none';
  const title = String(f.title || '')
    .replace(/\([^)]*\)/g, '')
    .replace(/on\s+\S+/gi, 'on')
    .replace(/via\s+.*/i, '')
    .replace(/["'`]/g, '')
    .trim()
    .toLowerCase()
    .slice(0, 80);
  return `${f.pluginId || 'plugin'}|${f.severity}|${cwe}|${title}`;
}
