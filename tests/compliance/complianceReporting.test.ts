import { describe, it, expect, afterEach } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { ComplianceReportingEngine } from '../../src/compliance/reporting/ComplianceReportingEngine';
import { createLogger } from '../../src/platform/core/logging/logger';
import type { ComplianceAssessment } from '../../src/compliance/models/ComplianceAssessment';
import type { ComplianceControl } from '../../src/compliance/models/ComplianceControl';
import type { ComplianceEvidence } from '../../src/compliance/models/ComplianceEvidence';

let tmpDir: string;

afterEach(() => {
  if (tmpDir && fs.existsSync(tmpDir)) fs.rmSync(tmpDir, { recursive: true, force: true });
});

function makeAssessment(): ComplianceAssessment {
  return {
    assessmentId: 'assess-1',
    assetId: 'asset-1',
    benchmarkId: 'cis-ubuntu-linux',
    benchmarkVersion: '1.0.0',
    profile: 'server-level-1',
    status: 'completed',
    startedAt: new Date().toISOString(),
    finishedAt: new Date().toISOString(),
    authorized: true,
    controlResults: [
      { controlId: 'EX-1.1', assessmentId: 'assess-1', status: 'PASS', reason: 'ok', confidence: 'high', evidenceRefs: [], evaluatedAt: '' },
      { controlId: 'EX-1.2', assessmentId: 'assess-1', status: 'FAIL', reason: 'bad', confidence: 'high', evidenceRefs: [], evaluatedAt: '' },
      { controlId: 'EX-2.2', assessmentId: 'assess-1', status: 'MANUAL_REVIEW', reason: 'review needed', confidence: 'not-applicable', evidenceRefs: [], evaluatedAt: '' },
    ],
    metrics: {
      totalControls: 3,
      applicableControls: 3,
      passed: 1,
      failed: 1,
      manualReview: 1,
      notApplicable: 0,
      errors: 0,
      compliancePercentage: 33.3,
    },
  };
}

const controls: ComplianceControl[] = [
  { controlId: 'EX-1.1', title: 'SSH root login disabled', level: '1', automated: true, evidenceRequirements: [], remediationMetadata: { summary: 'fix' } },
  { controlId: 'EX-1.2', title: 'SSH protocol version', level: '1', automated: true, evidenceRequirements: [], remediationMetadata: { summary: 'fix2' } },
  { controlId: 'EX-2.2', title: '/tmp partition', level: '2', automated: false, evidenceRequirements: [], remediationMetadata: { summary: 'review' } },
];

const evidence: ComplianceEvidence[] = [];

describe('ComplianceReportingEngine', () => {
  it('generates an HTML report containing all required summary sections', async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compliance-report-'));
    const engine = new ComplianceReportingEngine(tmpDir, createLogger('test', 'error'));
    const assessment = makeAssessment();
    const artifacts = await engine.generate(assessment, { controls, evidence, targetHostname: 'host.example' }, ['html']);

    expect(artifacts.htmlPath).toBeDefined();
    const html = fs.readFileSync(artifacts.htmlPath!, 'utf8');

    expect(html).toContain('Executive Summary');
    expect(html).toContain('host.example');
    expect(html).toContain('cis-ubuntu-linux');
    expect(html).toContain('1.0.0');
    expect(html).toContain('server-level-1');
    expect(html).toContain('Control Results');
    expect(html).toContain('EX-1.1');
    expect(html).toContain('EX-1.2');
    // Manual review controls must never be hidden from the report.
    expect(html).toContain('EX-2.2');
    expect(html).toContain('MANUAL_REVIEW');
    expect(html).toContain('Compliance %');
    expect(html).toContain('33.3%');
  });

  it('generates a JSON report containing assessment + controls + evidence', async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compliance-report-'));
    const engine = new ComplianceReportingEngine(tmpDir, createLogger('test', 'error'));
    const assessment = makeAssessment();
    const artifacts = await engine.generate(assessment, { controls, evidence, targetHostname: 'host.example' }, ['json']);

    expect(artifacts.jsonPath).toBeDefined();
    const parsed = JSON.parse(fs.readFileSync(artifacts.jsonPath!, 'utf8'));
    expect(parsed.assessment.assessmentId).toBe('assess-1');
    expect(parsed.controls).toHaveLength(3);
  });

  it('never omits a MANUAL_REVIEW control result from the HTML output', async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'compliance-report-'));
    const engine = new ComplianceReportingEngine(tmpDir, createLogger('test', 'error'));
    const assessment = makeAssessment();
    const artifacts = await engine.generate(assessment, { controls, evidence, targetHostname: 'host.example' }, ['html']);
    const html = fs.readFileSync(artifacts.htmlPath!, 'utf8');
    const manualReviewCount = (html.match(/MANUAL_REVIEW/g) || []).length;
    expect(manualReviewCount).toBeGreaterThan(0);
  });
});
