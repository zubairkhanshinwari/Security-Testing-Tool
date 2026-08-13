export type ControlStatus = 'PASS' | 'FAIL' | 'MANUAL_REVIEW' | 'NOT_APPLICABLE' | 'ERROR';

export type ResultConfidence = 'high' | 'medium' | 'low' | 'not-applicable';

export interface ComplianceResult {
  controlId: string;
  assessmentId: string;
  status: ControlStatus;
  reason: string;
  confidence: ResultConfidence;
  evidenceRefs: string[];
  evaluatedAt: string;
  remediation?: string;
  errorDetail?: string;
}
