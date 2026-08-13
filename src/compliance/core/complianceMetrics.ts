import type { ComplianceResult } from '../models/ComplianceResult';
import type { ComplianceMetrics } from '../models/ComplianceAssessment';

/**
 * compliancePercentage = (passed / applicableControls) * 100
 *   where applicableControls = totalControls - notApplicable
 * MANUAL_REVIEW and ERROR count against the denominator but are never
 * counted as passed — this is what stops an assessment from ever reading as
 * "100% compliant" purely because manual/errored controls were excluded.
 */
export function calculateComplianceMetrics(results: ComplianceResult[]): ComplianceMetrics {
  const totalControls = results.length;
  const passed = results.filter((r) => r.status === 'PASS').length;
  const failed = results.filter((r) => r.status === 'FAIL').length;
  const manualReview = results.filter((r) => r.status === 'MANUAL_REVIEW').length;
  const notApplicable = results.filter((r) => r.status === 'NOT_APPLICABLE').length;
  const errors = results.filter((r) => r.status === 'ERROR').length;

  const applicableControls = totalControls - notApplicable;
  const compliancePercentage =
    applicableControls > 0 ? Math.round((passed / applicableControls) * 1000) / 10 : 0;

  return {
    totalControls,
    applicableControls,
    passed,
    failed,
    manualReview,
    notApplicable,
    errors,
    compliancePercentage,
  };
}
