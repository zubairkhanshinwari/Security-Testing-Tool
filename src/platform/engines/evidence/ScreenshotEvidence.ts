import fs from 'fs';
import path from 'path';
import { chromium } from 'playwright';
import type { Finding, Severity } from '../../core/types/finding';
import type { Logger } from '../../core/logging/logger';

const REPORT_SEVERITIES = new Set<Severity>(['Critical', 'High', 'Medium', 'Low']);

function slug(s: string, max = 48): string {
  return (
    String(s || 'issue')
      .replace(/[^a-zA-Z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, max) || 'issue'
  );
}

function issueType(f: Finding): string {
  const cwe = (f.mappings?.cwe || f.cwe || [])[0] || '';
  const mod = f.module || f.pluginId || 'Finding';
  if (cwe) return `${mod} (${cwe})`;
  return String(mod);
}

function fileNameFor(f: Finding, index: number): string {
  const sev = f.severity || 'Info';
  const type = slug(String(f.module || f.pluginId || 'Issue'), 28);
  const title = slug(f.title || f.id || 'finding', 40);
  return `${String(index + 1).padStart(2, '0')}-${sev}-${type}-${title}.png`;
}

export function isScreenshotEligible(f: Finding): boolean {
  return Boolean(f.issueFound) && REPORT_SEVERITIES.has(f.severity as Severity);
}

/**
 * Capture labeled evidence screenshots for Critical/High/Medium/Low findings.
 * Naming: NN-Severity-IssueType-Title.png
 */
export class ScreenshotEvidence {
  constructor(private readonly logger: Logger) {}

  /** Capture using an existing Playwright page (scan orchestrator). */
  async captureForFindings(
    page: any,
    findings: Finding[],
    targetUrl: string,
    outDir: string,
  ): Promise<Finding[]> {
    return this.capture(findings, targetUrl, outDir, page);
  }

  /** Capture with a dedicated browser (report generation / regeneration). */
  async captureStandalone(
    findings: Finding[],
    targetUrl: string,
    outDir: string,
  ): Promise<Finding[]> {
    const browser = await chromium.launch({ headless: true });
    try {
      const context = await browser.newContext({
        ignoreHTTPSErrors: true,
        viewport: { width: 1280, height: 800 },
      });
      const page = await context.newPage();
      return await this.capture(findings, targetUrl, outDir, page);
    } finally {
      await browser.close();
    }
  }

  private async capture(
    findings: Finding[],
    targetUrl: string,
    outDir: string,
    page: any,
  ): Promise<Finding[]> {
    const issues = findings.filter(isScreenshotEligible);
    if (!issues.length) {
      this.logger.info('No Critical/High/Medium/Low findings for screenshots');
      return findings;
    }

    fs.mkdirSync(outDir, { recursive: true });
    const byId = new Map(findings.map((f) => [f.id, { ...f }]));

    for (let i = 0; i < issues.length; i++) {
      const f = issues[i];
      try {
        const name = fileNameFor(f, i);
        const filePath = path.join(outDir, name);
        const caption = `${f.severity} · ${issueType(f)} · ${f.title}`;

        let liveBase64: string | null = null;
        const url = f.affectedUrl || f.affectedEndpoint || targetUrl;
        if (url && /^https?:\/\//i.test(String(url)) && !/[{\}]/.test(String(url))) {
          try {
            await page.goto(String(url), { waitUntil: 'domcontentloaded', timeout: 15000 });
            const buf = await page.screenshot({ fullPage: false, type: 'png' });
            liveBase64 = Buffer.from(buf).toString('base64');
          } catch {
            /* evidence card only */
          }
        }

        await page.setContent(this.buildEvidenceHtml(f, caption, targetUrl, liveBase64), {
          waitUntil: 'domcontentloaded',
        });
        await page.setViewportSize({ width: 1280, height: 900 });
        const cardBuf = await page.screenshot({ fullPage: true, type: 'png' });
        fs.writeFileSync(filePath, cardBuf);
        const base64 = Buffer.from(cardBuf).toString('base64');

        const updated = byId.get(f.id) || { ...f };
        updated.screenshotPath = filePath;
        updated.screenshotFileName = name;
        updated.screenshotCaption = caption;
        updated.screenshotBase64 = base64;
        if (liveBase64) updated.screenshotLiveBase64 = liveBase64;
        byId.set(f.id, updated);
        this.logger.info('Screenshot captured', { name, findingId: f.id, severity: f.severity });
      } catch (err: any) {
        this.logger.warn('Screenshot failed', {
          findingId: f.id,
          error: err?.message || String(err),
        });
      }
    }

    return findings.map((f) => byId.get(f.id) || f);
  }

  private buildEvidenceHtml(
    f: Finding,
    caption: string,
    targetUrl: string,
    liveThumbBase64: string | null,
  ): string {
    const sev = f.severity || 'Informational';
    const sevColor =
      sev === 'Critical'
        ? '#7f1d1d'
        : sev === 'High'
          ? '#dc2626'
          : sev === 'Medium'
            ? '#ea580c'
            : sev === 'Low'
              ? '#ca8a04'
              : '#2563eb';
    const evidenceText = JSON.stringify(f.evidence || [], null, 2).slice(0, 1400);
    const live = liveThumbBase64
      ? `<div class="live"><div class="sub">Live page capture</div><img src="data:image/png;base64,${liveThumbBase64}" /></div>`
      : '';

    return `<!DOCTYPE html><html><head><meta charset="utf-8" />
<style>
  body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#0b1f3a;color:#0f172a}
  .wrap{padding:18px}
  .card{background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 10px 30px rgba(0,0,0,.25)}
  .banner{background:${sevColor};color:#fff;padding:14px 18px}
  .banner .sev{font-size:12px;font-weight:800;letter-spacing:.08em;text-transform:uppercase}
  .banner h1{margin:6px 0 0;font-size:20px}
  .banner .type{margin-top:6px;opacity:.92;font-size:13px}
  .body{padding:16px 18px}
  .row{display:grid;grid-template-columns:140px 1fr;gap:8px;font-size:13px;margin:0 0 8px}
  .k{color:#64748b;font-weight:700}
  .v{word-break:break-word}
  pre{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:10px;font-size:11px;overflow:auto;max-height:200px;white-space:pre-wrap}
  .live{margin-top:12px}
  .live img{width:100%;border:1px solid #e2e8f0;border-radius:8px}
  .sub{font-size:11px;color:#64748b;font-weight:700;margin-bottom:6px;text-transform:uppercase}
  .foot{padding:10px 18px;background:#f1f5f9;font-size:11px;color:#475569}
</style></head><body><div class="wrap"><div class="card">
  <div class="banner">
    <div class="sev">${escapeHtml(sev)} severity</div>
    <h1>${escapeHtml(f.title || 'Security Finding')}</h1>
    <div class="type">Issue type: ${escapeHtml(issueType(f))} · ${escapeHtml(f.id || '')}</div>
  </div>
  <div class="body">
    <div class="row"><div class="k">Finding ID</div><div class="v">${escapeHtml(f.id || '')}</div></div>
    <div class="row"><div class="k">Caption</div><div class="v">${escapeHtml(caption)}</div></div>
    <div class="row"><div class="k">Endpoint</div><div class="v">${escapeHtml(String(f.affectedEndpoint || f.endpoint || ''))}</div></div>
    <div class="row"><div class="k">Parameter</div><div class="v">${escapeHtml(String(f.parameter || 'n/a'))}</div></div>
    <div class="row"><div class="k">Target</div><div class="v">${escapeHtml(targetUrl)}</div></div>
    <div class="row"><div class="k">Confidence</div><div class="v">${escapeHtml(String(f.confidence || ''))}</div></div>
    <div class="sub">Evidence</div>
    <pre>${escapeHtml(evidenceText)}</pre>
    ${live}
  </div>
  <div class="foot">SecureAssess evidence screenshot · Authorized assessment only</div>
</div></div></body></html>`;
  }
}

function escapeHtml(s: string): string {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
