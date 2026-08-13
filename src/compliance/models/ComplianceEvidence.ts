export interface ComplianceEvidence {
  evidenceId: string;
  assessmentId: string;
  controlId: string;
  assetId: string;
  timestamp: string;
  /** e.g. "ssh-collector", "local-collector" */
  source: string;
  /** Sanitized payload — never raw credential material. */
  data: unknown;
  sanitized: boolean;
  evidenceType?: string;
  collectionMethod?: string;
  error?: string;
}
