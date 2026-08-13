import type { ComplianceContext } from '../core/ComplianceContext';
import type { ComplianceControl } from '../models/ComplianceControl';
import type { ComplianceEvidence } from '../models/ComplianceEvidence';
import type { ComplianceResult } from '../models/ComplianceResult';
import type { LinuxCollector, CollectContext } from '../linux/LinuxCollector';
import type { LinuxEvidenceProvider } from '../linux/LinuxEvidenceProvider';
import type { LinuxSession } from '../linux/connection/LinuxConnectionProvider';
import type { CISControlEvaluator } from './CISControlEvaluator';
import { ruleMatches } from './evaluationRules';

/**
 * Default, data-driven CISControlEvaluator implementation. Reads
 * control.evaluationDefinition (a set of declarative rules) rather than
 * containing any per-control if/else business logic — new controls added to
 * benchmark JSON are evaluated without touching this class.
 */
export class DefaultCISControlEvaluator implements CISControlEvaluator {
  private lastResult: ComplianceResult | undefined;

  constructor(
    private readonly session: LinuxSession,
    private readonly collector: LinuxCollector,
    private readonly evidenceProvider: LinuxEvidenceProvider,
  ) {}

  canEvaluate(control: ComplianceControl): boolean {
    return control.automated && Boolean(control.evaluationDefinition?.rules?.length);
  }

  async collectEvidence(control: ComplianceControl, context: ComplianceContext): Promise<ComplianceEvidence[]> {
    const collectCtx: CollectContext = {
      assessmentId: context.assessmentId,
      controlId: control.controlId,
      assetId: context.target.assetId,
    };
    const evidence = await this.collector.collectEvidence(
      this.session,
      control.evidenceRequirements,
      collectCtx,
    );
    for (const item of evidence) context.evidenceRepository.add(item);
    context.eventBus.emit('compliance.evidence.collected', context.assessmentId, {
      controlId: control.controlId,
      evidenceCount: evidence.length,
    });
    return evidence;
  }

  async evaluate(
    control: ComplianceControl,
    evidence: ComplianceEvidence[],
    context: ComplianceContext,
  ): Promise<ComplianceResult> {
    const now = new Date().toISOString();

    if (!control.automated) {
      this.lastResult = {
        controlId: control.controlId,
        assessmentId: context.assessmentId,
        status: 'MANUAL_REVIEW',
        reason: 'Control is defined as requiring manual review.',
        confidence: 'not-applicable',
        evidenceRefs: evidence.map((e) => e.evidenceId),
        evaluatedAt: now,
        remediation: control.remediationMetadata.summary,
      };
      return this.lastResult;
    }

    if (this.evidenceProvider.hasCollectionErrors(evidence)) {
      this.lastResult = {
        controlId: control.controlId,
        assessmentId: context.assessmentId,
        status: 'ERROR',
        reason: `Evidence collection failed: ${this.evidenceProvider.collectionErrors(evidence).join('; ')}`,
        confidence: 'not-applicable',
        evidenceRefs: evidence.map((e) => e.evidenceId),
        evaluatedAt: now,
        errorDetail: 'evidence-collection-error',
      };
      return this.lastResult;
    }

    if (!evidence.length || !control.evaluationDefinition?.rules?.length) {
      // Never mark PASS on insufficient evidence — falls to MANUAL_REVIEW instead.
      this.lastResult = {
        controlId: control.controlId,
        assessmentId: context.assessmentId,
        status: 'MANUAL_REVIEW',
        reason: 'Insufficient evidence or no automated evaluation rule defined for this control.',
        confidence: 'not-applicable',
        evidenceRefs: evidence.map((e) => e.evidenceId),
        evaluatedAt: now,
        remediation: control.remediationMetadata.summary,
      };
      return this.lastResult;
    }

    const fields = this.evidenceProvider.fieldsFor(control, evidence);
    const allRulesPass = control.evaluationDefinition.rules.every((rule) => ruleMatches(rule, fields));

    this.lastResult = {
      controlId: control.controlId,
      assessmentId: context.assessmentId,
      status: allRulesPass ? 'PASS' : 'FAIL',
      reason: allRulesPass
        ? 'All evaluation rules satisfied by collected evidence.'
        : control.evaluationDefinition.failureReason || 'One or more evaluation rules failed.',
      confidence: 'high',
      evidenceRefs: evidence.map((e) => e.evidenceId),
      evaluatedAt: now,
      remediation: allRulesPass ? undefined : control.remediationMetadata.summary,
    };
    return this.lastResult;
  }

  getResult(): ComplianceResult | undefined {
    return this.lastResult;
  }
}
