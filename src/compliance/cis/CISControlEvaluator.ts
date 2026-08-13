import type { ComplianceContext } from '../core/ComplianceContext';
import type { ComplianceControl } from '../models/ComplianceControl';
import type { ComplianceEvidence } from '../models/ComplianceEvidence';
import type { ComplianceResult } from '../models/ComplianceResult';

/**
 * Standard interface every CIS control evaluator implements. This is the one
 * seam that keeps CIS controls independent from the DAST plugin architecture
 * (SecurityPlugin's discover/scan/verify lifecycle assumes a Playwright page —
 * wrong tool for "run an allowlisted SSH command and check its output").
 */
export interface CISControlEvaluator {
  canEvaluate(control: ComplianceControl): boolean;
  collectEvidence(control: ComplianceControl, context: ComplianceContext): Promise<ComplianceEvidence[]>;
  evaluate(
    control: ComplianceControl,
    evidence: ComplianceEvidence[],
    context: ComplianceContext,
  ): Promise<ComplianceResult>;
  getResult(): ComplianceResult | undefined;
}
