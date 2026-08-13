import type { Logger } from '../../platform/core/logging/logger';
import type { LinuxAsset, CredentialReference } from '../models/LinuxAsset';
import type { CISBenchmark } from '../models/CISBenchmark';
import type { ComplianceEventBus } from './ComplianceEventBus';
import type { ComplianceEvidence } from '../models/ComplianceEvidence';

/**
 * Read-only evidence accumulator interface exposed to engines/evaluators via
 * ComplianceContext. Kept minimal and decoupled from any concrete storage
 * implementation (ComplianceAssessmentStore implements this shape, but tests
 * can supply an in-memory stub).
 */
export interface EvidenceRepository {
  add(evidence: ComplianceEvidence): void;
  list(controlId?: string): ComplianceEvidence[];
}

export interface ComplianceConfiguration {
  commandTimeoutMs: number;
  rateLimitPerHostPerMinute: number;
  maxControlsPerAssessment: number;
}

/**
 * Explicit, dependency-injected context passed through the compliance pipeline.
 * No global/module-level mutable state — every engine/evaluator receives this
 * by reference, which keeps the assessment independently testable (a test can
 * construct a ComplianceContext with mock connection/evidence/logger and run
 * the pipeline with zero process-wide state).
 */
export interface ComplianceContext {
  assessmentId: string;
  projectId?: string;
  target: LinuxAsset;
  benchmark: CISBenchmark;
  benchmarkVersion: string;
  profile: string;
  selectedControls: string[];
  credentialRef: CredentialReference;
  evidenceRepository: EvidenceRepository;
  configuration: ComplianceConfiguration;
  logger: Logger;
  eventBus: ComplianceEventBus;
}
