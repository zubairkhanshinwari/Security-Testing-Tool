import type { ComplianceEvidence } from '../models/ComplianceEvidence';
import type { ComplianceControl } from '../models/ComplianceControl';

/**
 * Thin adapter that hands LinuxCollector output to CISControlEvaluator in the
 * shape it expects (a flat field-value map matched against
 * EvaluationRule.field). Kept as its own class so the evaluator never reaches
 * into ComplianceEvidence.data's per-evidence-type parsing directly — it asks
 * this provider for "the fields for this control" instead.
 */
export class LinuxEvidenceProvider {
  /**
   * Flattens the (already-sanitized) evidence for a control into a single
   * field map. When multiple evidence requirements exist, later items take
   * precedence on field-name collision (controls with more than one
   * requirement are expected to target distinct fields in practice).
   */
  fieldsFor(_control: ComplianceControl, evidence: ComplianceEvidence[]): Record<string, unknown> {
    const fields: Record<string, unknown> = {};
    for (const item of evidence) {
      if (item.error) continue;
      const data = item.data as Record<string, unknown> | null;
      if (data && typeof data === 'object') {
        Object.assign(fields, data);
      }
    }
    return fields;
  }

  hasCollectionErrors(evidence: ComplianceEvidence[]): boolean {
    return evidence.some((e) => Boolean(e.error));
  }

  collectionErrors(evidence: ComplianceEvidence[]): string[] {
    return evidence.filter((e) => e.error).map((e) => e.error as string);
  }
}
