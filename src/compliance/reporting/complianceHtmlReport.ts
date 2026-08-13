import type { ComplianceAssessment } from '../models/ComplianceAssessment';
import type { ComplianceControl } from '../models/ComplianceControl';
import type { ComplianceEvidence } from '../models/ComplianceEvidence';
import type { ComplianceResult, ControlStatus } from '../models/ComplianceResult';

export interface ComplianceReportData {
  assessment: ComplianceAssessment;
  controlsById: Map<string, ComplianceControl>;
  evidenceByControl: Map<string, ComplianceEvidence[]>;
  targetHostname: string;
}

const STATUS_COLOR: Record<ControlStatus, string> = {
  PASS: '#1f7a3f',
  FAIL: '#b3261e',
  MANUAL_REVIEW: '#8a6d00',
  NOT_APPLICABLE: '#5f6368',
  ERROR: '#8c2f00',
};

/**
 * Programmatic HTML builder — deliberately NOT routed through the legacy
 * src/report/htmlReport.js string-builder (that module is Finding/severity
 * shaped and part of the existing DAST reporting path). CIS controls never
 * appear inside a vulnerability-findings report; this is a fully separate
 * template.
 */
export function buildComplianceHtmlReport(data: ComplianceReportData): string {
  const { assessment, controlsById, evidenceByControl, targetHostname } = data;
  const m = assessment.metrics;

  const rows = assessment.controlResults
    .map((result) => renderControlRow(result, controlsById.get(result.controlId), evidenceByControl.get(result.controlId) || []))
    .join('\n');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>CIS Linux Compliance Report — ${escapeHtml(assessment.benchmarkId)}</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 2rem; background: #f7f7f8; color: #1a1a1a; }
  h1 { font-size: 1.4rem; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin: 1.5rem 0; }
  .stat { background: #fff; border: 1px solid #e0e0e0; border-radius: 8px; padding: 12px 16px; }
  .stat .value { font-size: 1.6rem; font-weight: 700; }
  .stat .label { font-size: 0.8rem; color: #555; text-transform: uppercase; letter-spacing: 0.04em; }
  table { width: 100%; border-collapse: collapse; background: #fff; }
  th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #eee; font-size: 0.85rem; vertical-align: top; }
  th { background: #fafafa; position: sticky; top: 0; }
  .status-badge { display: inline-block; padding: 2px 10px; border-radius: 999px; color: #fff; font-weight: 600; font-size: 0.75rem; }
  .evidence-block { background: #f4f4f5; border-radius: 6px; padding: 8px; font-family: monospace; font-size: 0.75rem; white-space: pre-wrap; max-height: 160px; overflow-y: auto; }
  .meta-table td:first-child { font-weight: 600; width: 220px; color: #444; }
</style>
</head>
<body>
  <h1>CIS Linux Compliance Report</h1>

  <table class="meta-table">
    <tr><td>Target Linux Server</td><td>${escapeHtml(targetHostname)}</td></tr>
    <tr><td>Benchmark</td><td>${escapeHtml(assessment.benchmarkId)}</td></tr>
    <tr><td>Benchmark Version</td><td>${escapeHtml(assessment.benchmarkVersion)}</td></tr>
    <tr><td>Profile</td><td>${escapeHtml(assessment.profile)}</td></tr>
    <tr><td>Assessment Date</td><td>${escapeHtml(assessment.startedAt)}</td></tr>
    <tr><td>Status</td><td>${escapeHtml(assessment.status)}</td></tr>
  </table>

  <h2>Executive Summary</h2>
  <div class="summary-grid">
    ${statTile('Total Controls', m?.totalControls ?? 0)}
    ${statTile('Applicable', m?.applicableControls ?? 0)}
    ${statTile('Passed', m?.passed ?? 0)}
    ${statTile('Failed', m?.failed ?? 0)}
    ${statTile('Manual Review', m?.manualReview ?? 0)}
    ${statTile('Not Applicable', m?.notApplicable ?? 0)}
    ${statTile('Errors', m?.errors ?? 0)}
    ${statTile('Compliance %', `${m?.compliancePercentage ?? 0}%`)}
  </div>
  <p><em>Compliance percentage reflects automated PASS results over applicable controls only.
     Manual Review controls (${m?.manualReview ?? 0}) require human verification and are not counted as passed —
     this report is not a claim of full CIS compliance based solely on automated checks.</em></p>

  <h2>Control Results</h2>
  <table>
    <thead>
      <tr>
        <th>Control ID</th><th>Title</th><th>Status</th><th>Level</th>
        <th>Reason / Confidence</th><th>Evidence</th><th>Remediation</th>
      </tr>
    </thead>
    <tbody>
      ${rows}
    </tbody>
  </table>
</body>
</html>`;
}

function statTile(label: string, value: string | number): string {
  return `<div class="stat"><div class="value">${escapeHtml(String(value))}</div><div class="label">${escapeHtml(label)}</div></div>`;
}

function renderControlRow(
  result: ComplianceResult,
  control: ComplianceControl | undefined,
  evidence: ComplianceEvidence[],
): string {
  const evidenceText = evidence
    .map((e) => `[${e.evidenceType || 'evidence'}] ${e.error ? `ERROR: ${e.error}` : JSON.stringify(e.data)}`)
    .join('\n') || '(no evidence collected)';

  return `<tr>
    <td>${escapeHtml(result.controlId)}</td>
    <td>${escapeHtml(control?.title || '(unknown control)')}</td>
    <td><span class="status-badge" style="background:${STATUS_COLOR[result.status]}">${result.status}</span></td>
    <td>${escapeHtml(control?.level || '-')}</td>
    <td>${escapeHtml(result.reason)}<br/><small>Confidence: ${escapeHtml(result.confidence)}</small></td>
    <td><div class="evidence-block">${escapeHtml(evidenceText)}</div></td>
    <td>${escapeHtml(result.remediation || control?.remediationMetadata?.summary || '-')}</td>
  </tr>`;
}

function escapeHtml(value: string): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
