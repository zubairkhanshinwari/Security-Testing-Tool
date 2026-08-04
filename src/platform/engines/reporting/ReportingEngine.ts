import fs from 'fs';
import path from 'path';
import { createRequire } from 'module';
import type { Finding, ScanResult } from '../../core/types/finding';
import type { Logger } from '../../core/logging/logger';
import { EvidenceEngine } from '../evidence/EvidenceEngine';

const nodeRequire = createRequire(__filename);

export interface ReportArtifacts {
  htmlPath?: string;
  pdfPath?: string;
  jsonPath?: string;
  sarifPath?: string;
  csvPath?: string;
  junitPath?: string;
  base: string;
}

/**
 * Reporting Engine — multi-format export with v1 HTML/PDF compatibility.
 * Phase 5: uses EvidenceEngine so only verified C/H/M/L get screenshots.
 */
export class ReportingEngine {
  private readonly evidence: EvidenceEngine;

  constructor(
    private readonly reportsDir: string,
    private readonly logger: Logger,
    config: Record<string, any> = {},
  ) {
    this.evidence = new EvidenceEngine(logger.child('evidence'), config);
  }

  async generate(result: ScanResult, formats: string[] = ['html', 'pdf', 'json', 'sarif', 'csv', 'junit']): Promise<ReportArtifacts> {
    fs.mkdirSync(this.reportsDir, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const base = `secureassess-${stamp}`;
    const artifacts: ReportArtifacts = { base };

    // Attach evidence only for verified eligible findings (never Pass / Informational noise)
    const eligibleMissing = this.evidence
      .selectEligible(result.findings)
      .filter((f) => !f.screenshotBase64);
    if (eligibleMissing.length) {
      const shotDir = path.join(this.reportsDir, 'screenshots', base);
      const targetUrl = String(result.meta?.targetUrl || '');
      result.findings = await this.evidence.collect({
        findings: result.findings,
        targetUrl,
        outDir: shotDir,
        standalone: true,
      });
      this.logger.info('Verified issue screenshots attached for report', {
        count: result.findings.filter((f) => f.screenshotBase64).length,
        dir: shotDir,
      });
    }

    // Normalize for legacy HTML builder
    const legacyCompatible = this.toLegacyShape(result);

    if (formats.includes('json')) {
      artifacts.jsonPath = path.join(this.reportsDir, `${base}.json`);
      fs.writeFileSync(artifacts.jsonPath, JSON.stringify(result, null, 2), 'utf8');
    }

    if (formats.includes('html') || formats.includes('pdf')) {
      // Bust require cache so screenshot/report changes apply without full process restart
      const pdfReportPath = path.join(process.cwd(), 'src', 'report', 'pdfReport.js');
      const htmlReportPath = path.join(process.cwd(), 'src', 'report', 'htmlReport.js');
      const attachPath = path.join(process.cwd(), 'src', 'report', 'attachScreenshots.js');
      for (const p of [pdfReportPath, htmlReportPath, attachPath]) {
        try {
          delete require.cache[require.resolve(p)];
        } catch {
          /* ignore */
        }
      }
      const { generateReports } = nodeRequire(pdfReportPath);
      const legacy = await generateReports(legacyCompatible, this.reportsDir);
      // Rename conceptually — keep generated files; also copy aliases
      artifacts.htmlPath = legacy.htmlPath;
      artifacts.pdfPath = legacy.pdfPath;
      if (!artifacts.jsonPath) artifacts.jsonPath = legacy.jsonPath;
    }

    if (formats.includes('sarif')) {
      artifacts.sarifPath = path.join(this.reportsDir, `${base}.sarif.json`);
      fs.writeFileSync(artifacts.sarifPath, JSON.stringify(this.toSarif(result), null, 2), 'utf8');
    }

    if (formats.includes('csv')) {
      artifacts.csvPath = path.join(this.reportsDir, `${base}.csv`);
      fs.writeFileSync(artifacts.csvPath, this.toCsv(result.findings), 'utf8');
    }

    if (formats.includes('junit')) {
      artifacts.junitPath = path.join(this.reportsDir, `${base}.junit.xml`);
      fs.writeFileSync(artifacts.junitPath, this.toJunit(result.findings), 'utf8');
    }

    this.logger.info('Reports generated', { base, formats });
    return artifacts;
  }

  toLegacyShape(result: ScanResult): any {
    return {
      meta: result.meta,
      recon: result.recon || {
        pageTitle: result.attackSurface?.raw?.pageTitle,
        forms: result.attackSurface?.forms?.length || 0,
        linksVisited: result.attackSurface?.pages?.length || 0,
        apisObserved: result.attackSurface?.endpoints?.length || 0,
        querySurfaces: result.attackSurface?.parameters?.length || 0,
        apiBases: result.attackSurface?.apiBases || [],
        bundleRoutes: result.attackSurface?.raw?.bundleRoutes || [],
        apis: result.attackSurface?.endpoints?.slice(0, 40) || [],
        visitedUrls: result.attackSurface?.pages || [],
      },
      findings: result.findings.map((f) => this.findingToLegacy(f)),
      assessmentSummary: result.assessmentSummary,
      stats: {
        ...result.stats,
        securityScore: result.risk.overallScore,
        overallRisk: result.risk.overallRisk,
        severityCounts: result.risk.severityCounts,
        totalFindings: result.findings.filter((f) => f.issueFound).length,
      },
    };
  }

  findingToLegacy(f: Finding): any {
    return {
      ...f,
      cwe: f.mappings?.cwe || f.cwe || [],
      owasp: f.mappings?.owaspTop10?.[0] || f.owasp,
      severity: f.severity,
      endpoint: f.affectedEndpoint,
      fullUrl: f.affectedUrl,
      status: f.status,
    };
  }

  toSarif(result: ScanResult): object {
    const runs = [
      {
        tool: {
          driver: {
            name: 'SecureAssess Platform',
            informationUri: 'https://localhost/secureassess',
            version: String(result.meta?.version || '2.0.0'),
            rules: result.findings
              .filter((f) => f.issueFound)
              .map((f) => ({
                id: f.id,
                name: f.title,
                shortDescription: { text: f.title },
                fullDescription: { text: f.description },
                helpUri: f.references?.[0],
                properties: {
                  severity: f.severity,
                  confidence: f.confidence,
                  cwe: f.mappings?.cwe,
                  owasp: f.mappings?.owaspTop10,
                },
              })),
          },
        },
        results: result.findings
          .filter((f) => f.issueFound)
          .map((f) => ({
            ruleId: f.id,
            level: f.severity === 'Critical' || f.severity === 'High' ? 'error' : 'warning',
            message: { text: f.title },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: f.affectedEndpoint || f.affectedUrl },
                },
              },
            ],
          })),
      },
    ];
    return { $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0', runs };
  }

  toCsv(findings: Finding[]): string {
    const header = [
      'id',
      'title',
      'severity',
      'confidence',
      'endpoint',
      'parameter',
      'cwe',
      'owasp',
      'issueFound',
    ];
    const rows = findings.map((f) =>
      [
        f.id,
        csv(f.title),
        f.severity,
        f.confidence,
        csv(f.affectedEndpoint),
        csv(f.parameter || ''),
        (f.mappings?.cwe || []).join('|'),
        (f.mappings?.owaspTop10 || []).join('|'),
        f.issueFound,
      ].join(','),
    );
    return [header.join(','), ...rows].join('\n');
  }

  toJunit(findings: Finding[]): string {
    const issues = findings.filter((f) => f.issueFound);
    const cases = findings
      .map((f) => {
        if (!f.issueFound) {
          return `<testcase classname="${xml(f.pluginId)}" name="${xml(f.title)}" />`;
        }
        return `<testcase classname="${xml(f.pluginId)}" name="${xml(f.title)}"><failure message="${xml(f.severity)}">${xml(f.description)}</failure></testcase>`;
      })
      .join('\n');
    return `<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="SecureAssess" tests="${findings.length}" failures="${issues.length}">\n${cases}\n</testsuite>`;
  }
}

function csv(v: string): string {
  const s = String(v ?? '').replace(/"/g, '""');
  return `"${s}"`;
}

function xml(v: string): string {
  return String(v ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
