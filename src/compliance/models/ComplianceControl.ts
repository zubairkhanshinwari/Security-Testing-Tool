/**
 * Data-driven CIS control model. Control content (title/rationale/evaluation rule)
 * is loaded from benchmark JSON under src/benchmarks/ — never hardcoded in TS.
 */

export type ControlLevel = '1' | '2';

export type EvidenceType =
  | 'file-content'
  | 'command-output'
  | 'service-state'
  | 'package-state'
  | 'permission-metadata'
  | 'sysctl-value';

/**
 * Points at a fixed, allowlisted collection operation — never a raw shell string.
 * `collectionMethod` must match a key in the LinuxCollector's allowlisted operation map.
 */
export interface EvidenceRequirement {
  evidenceType: EvidenceType;
  target: string;
  collectionMethod: string;
  description?: string;
}

export type EvaluationOperator =
  | 'equals'
  | 'not-equals'
  | 'contains'
  | 'not-contains'
  | 'matches-regex'
  | 'not-matches-regex'
  | 'exists'
  | 'not-exists'
  | 'permission-at-most';

/**
 * A data-driven predicate: "evidence[field] <operator> value".
 * Kept intentionally small/declarative so evaluation logic lives in one
 * generic interpreter rather than one bespoke function per control.
 */
export interface EvaluationRule {
  field: string;
  operator: EvaluationOperator;
  value?: string | number;
}

export interface EvaluationDefinition {
  /** All rules must pass (AND) for the control to evaluate PASS. */
  rules: EvaluationRule[];
  /** Human-readable explanation shown in report when the rule fails. */
  failureReason?: string;
}

export interface RemediationMetadata {
  summary: string;
  references?: string[];
}

export interface ComplianceControl {
  controlId: string;
  title: string;
  level: ControlLevel;
  automated: boolean;
  evidenceRequirements: EvidenceRequirement[];
  evaluationDefinition?: EvaluationDefinition;
  remediationMetadata: RemediationMetadata;
  /** Free-form rationale/description text, sourced from licensed benchmark content. */
  description?: string;
  tags?: string[];
}
