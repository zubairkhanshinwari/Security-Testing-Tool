import fs from 'fs';
import path from 'path';
import type { Logger } from '../../platform/core/logging/logger';
import type { ComplianceAssessment } from '../models/ComplianceAssessment';
import type { ComplianceControl } from '../models/ComplianceControl';
import type { ComplianceEvidence } from '../models/ComplianceEvidence';
import { buildComplianceHtmlReport } from './complianceHtmlReport';

export interface ComplianceReportArtifacts {
  htmlPath?: string;
  jsonPath?: string;
}

/**
 * Sibling to (not an extension of) ReportingEngine — generates a dedicated
 * CIS Compliance report, never mixed into vulnerability-findings output.
 */
export class ComplianceReportingEngine {
  constructor(
    private readonly reportsDir: string,
    private readonly logger: Logger,
  ) {}

  async generate(
    assessment: ComplianceAssessment,
    context: {
      controls: ComplianceControl[];
      evidence: ComplianceEvidence[];
      targetHostname: string;
    },
    formats: string[] = ['html', 'json'],
  ): Promise<ComplianceReportArtifacts> {
    fs.mkdirSync(this.reportsDir, { recursive: true });
    const stamp = assessment.assessmentId;
    const artifacts: ComplianceReportArtifacts = {};

    const controlsById = new Map(context.controls.map((c) => [c.controlId, c]));
    const evidenceByControl = new Map<string, ComplianceEvidence[]>();
    for (const item of context.evidence) {
      const list = evidenceByControl.get(item.controlId) || [];
      list.push(item);
      evidenceByControl.set(item.controlId, list);
    }

    if (formats.includes('json')) {
      const jsonPath = path.join(this.reportsDir, `compliance-${stamp}.json`);
      fs.writeFileSync(
        jsonPath,
        JSON.stringify(
          {
            assessment,
            controls: context.controls,
            evidence: context.evidence,
          },
          null,
          2,
        ),
      );
      artifacts.jsonPath = jsonPath;
    }

    if (formats.includes('html')) {
      const htmlPath = path.join(this.reportsDir, `compliance-${stamp}.html`);
      const html = buildComplianceHtmlReport({
        assessment,
        controlsById,
        evidenceByControl,
        targetHostname: context.targetHostname,
      });
      fs.writeFileSync(htmlPath, html);
      artifacts.htmlPath = htmlPath;
    }

    this.logger.info('Compliance report generated', { assessmentId: assessment.assessmentId, formats });
    return artifacts;
  }
}
