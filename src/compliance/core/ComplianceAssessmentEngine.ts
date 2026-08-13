import { randomUUID } from 'crypto';
import type { Logger } from '../../platform/core/logging/logger';
import type { LinuxAsset, CredentialReference } from '../models/LinuxAsset';
import type { ComplianceAssessment } from '../models/ComplianceAssessment';
import { CISBenchmarkManager } from '../cis/CISBenchmarkManager';
import { LinuxAssessmentEngine } from '../linux/LinuxAssessmentEngine';
import { CompliancePlanner } from '../planning/CompliancePlanner';
import { ComplianceEventBus } from './ComplianceEventBus';
import { calculateComplianceMetrics } from './complianceMetrics';
import type { ComplianceConfiguration, ComplianceContext, EvidenceRepository } from './ComplianceContext';
import { validateLinuxTarget } from '../safety/linuxHostPolicy';

export interface ComplianceAssessmentRequest {
  projectId?: string;
  target: Omit<LinuxAsset, 'assetId' | 'createdAt'> & { assetId?: string };
  benchmarkId: string;
  benchmarkVersion: string;
  profile: string;
  selectedControls?: string[];
  credentialRef: CredentialReference;
  requestedBy?: string;
  authorized: boolean;
}

const DEFAULT_CONFIGURATION: ComplianceConfiguration = {
  commandTimeoutMs: 10_000,
  rateLimitPerHostPerMinute: 30,
  maxControlsPerAssessment: 500,
};

/**
 * Owns the CIS assessment lifecycle end to end. This is the compliance-side
 * peer of ScanOrchestrator — not a subordinate of it, and ScanOrchestrator
 * itself is never imported here. Delegation between DAST and CIS_LINUX
 * happens one layer above this class (see AssessmentRouter).
 */
export class ComplianceAssessmentEngine {
  constructor(
    private readonly benchmarkManager: CISBenchmarkManager,
    private readonly linuxAssessmentEngine: LinuxAssessmentEngine,
    private readonly planner: CompliancePlanner,
    private readonly evidenceRepositoryFactory: (assessmentId: string) => EvidenceRepository,
    private readonly logger: Logger,
    private readonly configuration: ComplianceConfiguration = DEFAULT_CONFIGURATION,
  ) {}

  async run(request: ComplianceAssessmentRequest): Promise<ComplianceAssessment> {
    if (!request.authorized) {
      throw new Error('You must confirm authorization before running a CIS Linux assessment.');
    }

    const target: LinuxAsset = {
      assetId: request.target.assetId || randomUUID(),
      hostname: request.target.hostname,
      port: request.target.port,
      osFamily: 'ubuntu',
      osVersion: request.target.osVersion,
      label: request.target.label,
      projectId: request.projectId,
      createdAt: new Date().toISOString(),
    };

    const hostPolicy = validateLinuxTarget({ hostname: target.hostname, authorized: request.authorized });
    if (!hostPolicy.ok) {
      throw new Error(hostPolicy.reason || 'Target host is not authorized for CIS Linux assessment.');
    }

    const assessmentId = randomUUID();
    const eventBus = new ComplianceEventBus();
    const evidenceRepository = this.evidenceRepositoryFactory(assessmentId);

    const assessment: ComplianceAssessment = {
      assessmentId,
      projectId: request.projectId,
      assetId: target.assetId,
      benchmarkId: request.benchmarkId,
      benchmarkVersion: request.benchmarkVersion,
      profile: request.profile,
      status: 'running',
      startedAt: new Date().toISOString(),
      requestedBy: request.requestedBy,
      authorized: true,
      controlResults: [],
    };

    eventBus.emit('compliance.assessment.started', assessmentId, {
      assetId: target.assetId,
      benchmarkId: request.benchmarkId,
    });

    try {
      const benchmark = await this.benchmarkManager.loadBenchmark(
        request.benchmarkId,
        request.benchmarkVersion,
      );
      const plan = this.planner.plan(benchmark, request.profile, request);

      const context: ComplianceContext = {
        assessmentId,
        projectId: request.projectId,
        target,
        benchmark,
        benchmarkVersion: request.benchmarkVersion,
        profile: request.profile,
        selectedControls: plan.selectedControls.map((c) => c.controlId),
        credentialRef: request.credentialRef,
        evidenceRepository,
        configuration: this.configuration,
        logger: this.logger,
        eventBus,
      };

      const results = await this.linuxAssessmentEngine.assess(context, plan.selectedControls);

      assessment.controlResults = results;
      assessment.metrics = calculateComplianceMetrics(results);
      assessment.status = 'completed';
      assessment.finishedAt = new Date().toISOString();

      eventBus.emit('compliance.assessment.completed', assessmentId, {
        metrics: assessment.metrics,
      });
      return assessment;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown compliance assessment error';
      assessment.status = 'failed';
      assessment.error = message;
      assessment.finishedAt = new Date().toISOString();
      eventBus.emit('compliance.assessment.failed', assessmentId, { error: message });
      throw err;
    } finally {
      eventBus.clear();
    }
  }
}
