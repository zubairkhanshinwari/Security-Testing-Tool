export type ComplianceEventType =
  | 'compliance.assessment.started'
  | 'compliance.control.evaluation.started'
  | 'compliance.evidence.collected'
  | 'compliance.control.evaluated'
  | 'compliance.assessment.completed'
  | 'compliance.assessment.failed'
  | 'compliance.connection.established'
  | 'compliance.connection.failed';

export interface ComplianceEvent<T = unknown> {
  type: ComplianceEventType;
  assessmentId: string;
  at: string;
  payload?: T;
}

export type ComplianceEventHandler = (event: ComplianceEvent) => void;
