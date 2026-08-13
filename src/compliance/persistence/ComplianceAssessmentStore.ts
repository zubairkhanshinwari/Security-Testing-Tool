import fs from 'fs';
import path from 'path';
import type { Logger } from '../../platform/core/logging/logger';
import type { ComplianceAssessment } from '../models/ComplianceAssessment';
import type { ComplianceEvidence } from '../models/ComplianceEvidence';
import { redactSecrets } from '../../platform/core/safety/redact';
import type { EvidenceRepository } from '../core/ComplianceContext';

/**
 * File-backed store for compliance assessments, mirroring ProjectStore's
 * on-disk-JSON pattern as a separate class/directory rather than a
 * modification of ProjectStore.ts. Existing DAST Project/ScanRecord types and
 * files are untouched; the only integration point is reading Project records
 * (by projectId) via the caller-supplied ProjectStore reference in the API
 * layer, never writing to it.
 */
export class ComplianceAssessmentStore {
  constructor(
    private readonly assessmentsDir: string,
    private readonly evidenceDir: string,
    private readonly logger: Logger,
  ) {
    fs.mkdirSync(assessmentsDir, { recursive: true });
    fs.mkdirSync(evidenceDir, { recursive: true });
  }

  saveAssessment(assessment: ComplianceAssessment): void {
    const sanitized = redactSecrets(assessment);
    fs.writeFileSync(
      this.assessmentPath(assessment.assessmentId),
      JSON.stringify(sanitized, null, 2),
    );
    this.logger.info('Compliance assessment saved', {
      assessmentId: assessment.assessmentId,
      status: assessment.status,
    });
  }

  getAssessment(assessmentId: string): ComplianceAssessment | null {
    const p = this.assessmentPath(assessmentId);
    if (!fs.existsSync(p)) return null;
    return JSON.parse(fs.readFileSync(p, 'utf8')) as ComplianceAssessment;
  }

  listAssessments(projectId?: string): ComplianceAssessment[] {
    if (!fs.existsSync(this.assessmentsDir)) return [];
    return fs
      .readdirSync(this.assessmentsDir)
      .filter((f) => f.endsWith('.json'))
      .map((f) => JSON.parse(fs.readFileSync(path.join(this.assessmentsDir, f), 'utf8')) as ComplianceAssessment)
      .filter((a) => (projectId ? a.projectId === projectId : true))
      .sort((a, b) => b.startedAt.localeCompare(a.startedAt));
  }

  /**
   * Evidence repository facade for a single assessment. Returned object
   * satisfies the ComplianceContext.evidenceRepository shape and persists
   * each item as it's added (append-only, one file per assessment).
   */
  evidenceRepositoryFor(assessmentId: string): EvidenceRepository {
    const buffered: ComplianceEvidence[] = this.loadEvidence(assessmentId);
    const evidencePath = this.evidencePath(assessmentId);
    return {
      add: (evidence: ComplianceEvidence) => {
        const sanitized = redactSecrets(evidence);
        buffered.push(sanitized);
        fs.writeFileSync(evidencePath, JSON.stringify(buffered, null, 2));
      },
      list: (controlId?: string) =>
        controlId ? buffered.filter((e) => e.controlId === controlId) : [...buffered],
    };
  }

  private loadEvidence(assessmentId: string): ComplianceEvidence[] {
    const p = this.evidencePath(assessmentId);
    if (!fs.existsSync(p)) return [];
    try {
      return JSON.parse(fs.readFileSync(p, 'utf8')) as ComplianceEvidence[];
    } catch {
      return [];
    }
  }

  private assessmentPath(assessmentId: string): string {
    return path.join(this.assessmentsDir, `${assessmentId}.json`);
  }

  private evidencePath(assessmentId: string): string {
    return path.join(this.evidenceDir, `${assessmentId}.evidence.json`);
  }
}
