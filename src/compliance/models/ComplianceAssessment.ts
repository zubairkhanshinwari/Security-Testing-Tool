import type { ComplianceResult } from './ComplianceResult';

export type ComplianceAssessmentStatus = 'running' | 'completed' | 'failed';

export interface ComplianceMetrics {
  totalControls: number;
  applicableControls: number;
  passed: number;
  failed: number;
  manualReview: number;
  notApplicable: number;
  errors: number;
  /** (passed / applicableControls) * 100, where applicableControls = total - notApplicable. Rounded to 1 decimal. */
  compliancePercentage: number;
}

export interface ComplianceAssessment {
  assessmentId: string;
  projectId?: string;
  assetId: string;
  benchmarkId: string;
  benchmarkVersion: string;
  profile: string;
  status: ComplianceAssessmentStatus;
  startedAt: string;
  finishedAt?: string;
  requestedBy?: string;
  authorized: true;
  controlResults: ComplianceResult[];
  metrics?: ComplianceMetrics;
  error?: string;
}
