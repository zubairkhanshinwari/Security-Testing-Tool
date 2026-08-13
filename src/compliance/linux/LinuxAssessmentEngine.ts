import type { Logger } from '../../platform/core/logging/logger';
import type { ComplianceContext } from '../core/ComplianceContext';
import type { ComplianceControl } from '../models/ComplianceControl';
import type { ComplianceResult } from '../models/ComplianceResult';
import type { LinuxConnectionProvider, LinuxSession } from './connection/LinuxConnectionProvider';
import { LinuxCollector } from './LinuxCollector';
import { LinuxEvidenceProvider } from './LinuxEvidenceProvider';
import { DefaultCISControlEvaluator } from '../cis/DefaultCISControlEvaluator';

/**
 * Coordinates Linux evidence collection and CIS control evaluation for one
 * assessment. Connects once (session reused across all controls, not
 * per-control), then evaluates each control in isolation so a single
 * control's failure/exception never aborts the assessment (§17).
 */
export class LinuxAssessmentEngine {
  constructor(
    private readonly connectionProvider: LinuxConnectionProvider,
    private readonly logger: Logger,
  ) {}

  async assess(context: ComplianceContext, controls: ComplianceControl[]): Promise<ComplianceResult[]> {
    let session: LinuxSession;
    try {
      session = await this.connectionProvider.connect(context.target, context.credentialRef);
      context.eventBus.emit('compliance.connection.established', context.assessmentId, {
        assetId: context.target.assetId,
      });
    } catch (err) {
      context.eventBus.emit('compliance.connection.failed', context.assessmentId, {
        assetId: context.target.assetId,
      });
      // Infrastructure failure (cannot connect at all) is distinct from a
      // per-control failure: every requested control is reported as ERROR
      // rather than silently omitted from the assessment.
      const message = err instanceof Error ? err.message : 'Connection failed';
      return controls.map((control) => ({
        controlId: control.controlId,
        assessmentId: context.assessmentId,
        status: 'ERROR',
        reason: `Could not connect to target: ${message}`,
        confidence: 'not-applicable',
        evidenceRefs: [],
        evaluatedAt: new Date().toISOString(),
        errorDetail: 'connection-error',
      }));
    }

    const collector = new LinuxCollector(this.connectionProvider, this.logger);
    const evidenceProvider = new LinuxEvidenceProvider();
    const results: ComplianceResult[] = [];

    try {
      for (const control of controls) {
        results.push(await this.evaluateOneControl(context, control, session, collector, evidenceProvider));
      }
    } finally {
      await this.connectionProvider.disconnect(session);
    }

    return results;
  }

  private async evaluateOneControl(
    context: ComplianceContext,
    control: ComplianceControl,
    session: LinuxSession,
    collector: LinuxCollector,
    evidenceProvider: LinuxEvidenceProvider,
  ): Promise<ComplianceResult> {
    context.eventBus.emit('compliance.control.evaluation.started', context.assessmentId, {
      controlId: control.controlId,
    });

    const evaluator = new DefaultCISControlEvaluator(session, collector, evidenceProvider);

    try {
      if (!evaluator.canEvaluate(control)) {
        const result: ComplianceResult = control.automated
          ? {
              controlId: control.controlId,
              assessmentId: context.assessmentId,
              status: 'NOT_APPLICABLE',
              reason: 'Control has no automated evaluation rule defined for this benchmark version.',
              confidence: 'not-applicable',
              evidenceRefs: [],
              evaluatedAt: new Date().toISOString(),
            }
          : {
              controlId: control.controlId,
              assessmentId: context.assessmentId,
              status: 'MANUAL_REVIEW',
              reason: 'Control is defined as requiring manual review.',
              confidence: 'not-applicable',
              evidenceRefs: [],
              evaluatedAt: new Date().toISOString(),
              remediation: control.remediationMetadata.summary,
            };
        context.eventBus.emit('compliance.control.evaluated', context.assessmentId, {
          controlId: control.controlId,
          status: result.status,
        });
        return result;
      }

      const evidence = await evaluator.collectEvidence(control, context);
      const result = await evaluator.evaluate(control, evidence, context);
      context.eventBus.emit('compliance.control.evaluated', context.assessmentId, {
        controlId: control.controlId,
        status: result.status,
      });
      return result;
    } catch (err) {
      // A control-level exception (evidence collection throwing, malformed
      // evaluation definition, etc.) must not abort the rest of the assessment.
      const message = err instanceof Error ? err.message : 'Unknown control evaluation error';
      this.logger.warn('Control evaluation error', { controlId: control.controlId, error: message });
      const result: ComplianceResult = {
        controlId: control.controlId,
        assessmentId: context.assessmentId,
        status: 'ERROR',
        reason: `Unhandled error during control evaluation: ${message}`,
        confidence: 'not-applicable',
        evidenceRefs: [],
        evaluatedAt: new Date().toISOString(),
        errorDetail: 'control-evaluation-error',
      };
      context.eventBus.emit('compliance.control.evaluated', context.assessmentId, {
        controlId: control.controlId,
        status: result.status,
      });
      return result;
    }
  }
}
