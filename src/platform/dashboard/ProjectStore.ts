import fs from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';
import type { Logger } from '../core/logging/logger';
import type { AttackSurface, ScanResult } from '../core/types/finding';
import {
  buildBaselineFromResult,
  diffBaseline,
  type BaselineDiff,
  type ScanBaseline,
} from './baseline';

export interface Project {
  id: string;
  /** Human display id, e.g. project-001 */
  code: string;
  name: string;
  targetUrl?: string;
  createdAt: string;
  updatedAt: string;
  owner?: string;
  tags?: string[];
}

export interface ScanRecord {
  id: string;
  /** Human display id, e.g. scan-001 */
  code: string;
  projectId: string;
  createdAt: string;
  targetUrl: string;
  score: number;
  risk: string;
  findings: number;
  meta?: Record<string, unknown>;
  files?: Record<string, string>;
  resultPath?: string;
}

/**
 * File-backed project/scan store for historical dashboard & trend support.
 */
export class ProjectStore {
  constructor(
    private readonly projectsDir: string,
    private readonly scansDir: string,
    private readonly logger: Logger,
  ) {
    fs.mkdirSync(projectsDir, { recursive: true });
    fs.mkdirSync(scansDir, { recursive: true });
  }

  listProjects(): Project[] {
    this.backfillProjectCodes();
    return this.readAllProjects().sort((a, b) => {
      const byCode = codeSortKey(a.code).localeCompare(codeSortKey(b.code));
      if (byCode !== 0) return byCode;
      return a.createdAt.localeCompare(b.createdAt);
    });
  }

  getProject(id: string): Project | null {
    this.backfillProjectCodes();
    const p = path.join(this.projectsDir, `${id}.json`);
    if (!fs.existsSync(p)) return null;
    return JSON.parse(fs.readFileSync(p, 'utf8')) as Project;
  }

  createProject(input: { name: string; targetUrl?: string; owner?: string; tags?: string[] }): Project {
    const project: Project = {
      id: randomUUID(),
      code: this.nextCode('project'),
      name: input.name,
      targetUrl: input.targetUrl,
      owner: input.owner,
      tags: input.tags || [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    fs.writeFileSync(path.join(this.projectsDir, `${project.id}.json`), JSON.stringify(project, null, 2));
    this.logger.info('Project created', { id: project.id, code: project.code, name: project.name });
    return project;
  }

  /**
   * Deletes a project and its associated scan history (meta + result files).
   * Report artifacts under reports/ are left intact unless unlinkReports is true.
   */
  deleteProject(id: string): { ok: boolean; deletedScans: number } {
    const projectPath = path.join(this.projectsDir, `${id}.json`);
    if (!fs.existsSync(projectPath)) {
      return { ok: false, deletedScans: 0 };
    }

    const scans = this.listScans(id);
    for (const scan of scans) {
      const metaPath = path.join(this.scansDir, `${scan.id}.meta.json`);
      if (fs.existsSync(metaPath)) fs.unlinkSync(metaPath);
      if (scan.resultPath && fs.existsSync(scan.resultPath)) fs.unlinkSync(scan.resultPath);
      const resultFallback = path.join(this.scansDir, `${scan.id}.result.json`);
      if (fs.existsSync(resultFallback)) fs.unlinkSync(resultFallback);
    }

    const baselinePath = this.baselinePath(id);
    if (fs.existsSync(baselinePath)) fs.unlinkSync(baselinePath);

    fs.unlinkSync(projectPath);
    this.logger.info('Project deleted', { id, deletedScans: scans.length });
    return { ok: true, deletedScans: scans.length };
  }

  /** Chronological ascending (oldest → newest) so new rows appear below on the dashboard. */
  listScans(projectId?: string): ScanRecord[] {
    this.backfillScanCodes();
    return this.readAllScans()
      .filter((s) => (projectId ? s.projectId === projectId : true))
      .sort((a, b) => {
        const byCode = codeSortKey(a.code).localeCompare(codeSortKey(b.code));
        if (byCode !== 0) return byCode;
        return a.createdAt.localeCompare(b.createdAt);
      });
  }

  /** Newest-first helper for inventory / regression logic. */
  private listScansNewestFirst(projectId?: string): ScanRecord[] {
    return this.listScans(projectId)
      .slice()
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  getScan(id: string): { meta: ScanRecord; result?: any } | null {
    this.backfillScanCodes();
    const metaPath = path.join(this.scansDir, `${id}.meta.json`);
    if (!fs.existsSync(metaPath)) return null;
    const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8')) as ScanRecord;
    let result;
    if (meta.resultPath && fs.existsSync(meta.resultPath)) {
      result = JSON.parse(fs.readFileSync(meta.resultPath, 'utf8'));
    }
    return { meta, result };
  }

  /**
   * Latest scan inventory for project detail: tech stack + API counts.
   */
  getLatestInventory(projectId: string) {
    const scans = this.listScansNewestFirst(projectId);
    if (!scans.length) {
      return { available: false as const, message: 'No scans yet — run an assessment to discover stack and APIs.' };
    }
    const latest = this.getScan(scans[0].id);
    if (!latest?.result) {
      return {
        available: false as const,
        message: 'Latest scan metadata found, but full result is missing.',
        scanId: scans[0].id,
        score: scans[0].score,
        risk: scans[0].risk,
      };
    }

    const result = latest.result;
    const tech =
      result.meta?.technology ||
      result.recon?.technology ||
      {};
    const attackSurface = result.attackSurface || {};
    const recon = result.recon || {};
    const stats = result.stats || {};
    const findings = Array.isArray(result.findings) ? result.findings : [];

    const databases = inferDatabases(tech, findings, recon);
    const languages = inferLanguages(tech, findings);

    const endpoints = Array.isArray(attackSurface.endpoints) ? attackSurface.endpoints : [];
    const apiBases = attackSurface.apiBases || recon.apiBases || [];
    const uniqueApiUrls = new Set(
      endpoints.map((e: any) => String(e.url || '').split('?')[0]).filter(Boolean),
    );

    return {
      available: true as const,
      scanId: scans[0].id,
      scannedAt: scans[0].createdAt,
      targetUrl: scans[0].targetUrl,
      score: scans[0].score,
      risk: scans[0].risk,
      findings: scans[0].findings,
      stack: {
        frontend: tech.frontend || [],
        backend: tech.backend || [],
        languages,
        database: databases,
        server: tech.server || [],
        cdn: tech.cdn || [],
        cloud: tech.cloud || [],
        waf: tech.waf || [],
        auth: tech.auth || [],
        frameworks: attackSurface.frameworks || [],
      },
      apis: {
        apiBases: apiBases.length,
        apiBasesList: apiBases.slice(0, 8),
        endpointsDiscovered: uniqueApiUrls.size || endpoints.length || Number(recon.apisObserved || 0),
        endpointsTested: Number(stats.endpointsTested || 0),
        parametersTested: Number(stats.parametersTested || 0),
        apisObservedInTraffic: Number(recon.apisObserved || endpoints.length || 0),
        openapiDocs: Array.isArray(recon.openapi) ? recon.openapi.length : (attackSurface.openapi || []).length,
        authEndpoints: Array.isArray(attackSurface.authEndpoints) ? attackSurface.authEndpoints.length : 0,
        pagesDiscovered: Array.isArray(attackSurface.pages) ? attackSurface.pages.length : Number(recon.linksVisited || 0),
        formsDiscovered: Number(recon.forms || (attackSurface.forms || []).length || 0),
      },
      sampleEndpoints: endpoints.slice(0, 8).map((e: any) => ({
        method: e.method || 'GET',
        url: e.url,
      })),
    };
  }

  saveScan(record: Omit<ScanRecord, 'id' | 'createdAt' | 'code'> & { result?: any }): ScanRecord {
    const id = randomUUID();
    const createdAt = new Date().toISOString();
    let resultPath: string | undefined;
    if (record.result) {
      resultPath = path.join(this.scansDir, `${id}.result.json`);
      fs.writeFileSync(resultPath, JSON.stringify(record.result, null, 2));
    }
    const meta: ScanRecord = {
      id,
      code: this.nextCode('scan'),
      projectId: record.projectId,
      createdAt,
      targetUrl: record.targetUrl,
      score: record.score,
      risk: record.risk,
      findings: record.findings,
      meta: record.meta,
      files: record.files,
      resultPath,
    };
    fs.writeFileSync(path.join(this.scansDir, `${id}.meta.json`), JSON.stringify(meta, null, 2));

    const project = this.getProject(record.projectId);
    if (project) {
      project.updatedAt = createdAt;
      fs.writeFileSync(
        path.join(this.projectsDir, `${project.id}.json`),
        JSON.stringify(project, null, 2),
      );
    }

    // Phase 6: persist project baseline for incremental re-scans
    if (record.result) {
      try {
        this.saveBaseline(
          buildBaselineFromResult(record.projectId, meta.id, record.result as ScanResult),
        );
      } catch (err: any) {
        this.logger.warn('Baseline save failed', { error: err?.message || String(err) });
      }
    }

    this.logger.info('Scan saved', { id: meta.id, code: meta.code, projectId: meta.projectId });
    return meta;
  }

  /** Latest persisted baseline for a project (sidecar, else rebuilt from newest scan). */
  getBaseline(projectId: string): ScanBaseline | null {
    const baselinePath = this.baselinePath(projectId);
    if (fs.existsSync(baselinePath)) {
      try {
        return JSON.parse(fs.readFileSync(baselinePath, 'utf8')) as ScanBaseline;
      } catch {
        /* fall through */
      }
    }
    const scans = this.listScansNewestFirst(projectId);
    if (!scans.length) return null;
    const latest = this.getScan(scans[0].id);
    if (!latest?.result) return null;
    return buildBaselineFromResult(projectId, scans[0].id, latest.result as ScanResult);
  }

  saveBaseline(baseline: ScanBaseline): void {
    fs.writeFileSync(this.baselinePath(baseline.projectId), JSON.stringify(baseline, null, 2));
    this.logger.info('Baseline saved', {
      projectId: baseline.projectId,
      scanId: baseline.scanId,
      endpoints: baseline.endpoints.length,
      confirmed: baseline.confirmedFindings.length,
    });
  }

  /** Diff current attack surface against the project baseline. */
  diffBaseline(projectId: string, surface: AttackSurface): BaselineDiff {
    return diffBaseline(this.getBaseline(projectId), surface);
  }

  private baselinePath(projectId: string): string {
    return path.join(this.projectsDir, `${projectId}.baseline.json`);
  }

  trends(projectId: string): Array<{ date: string; score: number; findings: number; risk: string }> {
    return this.listScans(projectId).map((s) => ({
      date: s.createdAt,
      score: s.score,
      findings: s.findings,
      risk: s.risk,
    }));
  }

  detectRegression(projectId: string): { regressed: boolean; details: string } {
    const scans = this.listScansNewestFirst(projectId);
    if (scans.length < 2) return { regressed: false, details: 'Not enough history' };
    const [latest, prev] = scans;
    if (latest.score < prev.score - 5 || latest.findings > prev.findings) {
      return {
        regressed: true,
        details: `Score ${prev.score}→${latest.score}, findings ${prev.findings}→${latest.findings}`,
      };
    }
    return { regressed: false, details: 'No significant regression' };
  }

  /**
   * Baseline comparison between two scans (or latest vs previous for a project).
   */
  compareScans(baselineId: string, currentId: string) {
    const baseline = this.getScan(baselineId);
    const current = this.getScan(currentId);
    if (!baseline?.result || !current?.result) {
      return { ok: false as const, error: 'Both scans must exist with persisted results' };
    }

    const baseIssues = new Map<string, any>(
      (baseline.result.findings || [])
        .filter((f: any) => f.issueFound)
        .map((f: any) => [findingFamilyKey(f), f]),
    );
    const currIssues = new Map<string, any>(
      (current.result.findings || [])
        .filter((f: any) => f.issueFound)
        .map((f: any) => [findingFamilyKey(f), f]),
    );

    const fixed: any[] = [];
    const neu: any[] = [];
    const changedSeverity: any[] = [];
    const unchanged: any[] = [];
    const rows: Array<{
      delta: 'New' | 'Fixed' | 'Unchanged' | 'SeverityChanged';
      title: string;
      severity: string;
      previousSeverity?: string;
      endpoint: string;
      confidence?: string;
      cwe?: string[];
    }> = [];

    for (const [k, bf] of baseIssues) {
      const cf = currIssues.get(k);
      if (!cf) {
        const s = summarizeFinding(bf);
        fixed.push(s);
        rows.push({
          delta: 'Fixed',
          title: s.title,
          severity: s.severity,
          endpoint: s.endpoint || '',
          confidence: s.confidence,
          cwe: s.cwe,
        });
      } else if (cf.severity !== bf.severity) {
        changedSeverity.push({
          title: cf.title,
          from: bf.severity,
          to: cf.severity,
          endpoint: cf.affectedEndpoint || cf.endpoint,
        });
        const s = summarizeFinding(cf);
        unchanged.push(s);
        rows.push({
          delta: 'SeverityChanged',
          title: s.title,
          severity: s.severity,
          previousSeverity: bf.severity,
          endpoint: s.endpoint || '',
          confidence: s.confidence,
          cwe: s.cwe,
        });
      } else {
        const s = summarizeFinding(cf);
        unchanged.push(s);
        rows.push({
          delta: 'Unchanged',
          title: s.title,
          severity: s.severity,
          endpoint: s.endpoint || '',
          confidence: s.confidence,
          cwe: s.cwe,
        });
      }
    }
    for (const [k, cf] of currIssues) {
      if (!baseIssues.has(k)) {
        const s = summarizeFinding(cf);
        neu.push(s);
        rows.push({
          delta: 'New',
          title: s.title,
          severity: s.severity,
          endpoint: s.endpoint || '',
          confidence: s.confidence,
          cwe: s.cwe,
        });
      }
    }

    // Prefer New → SeverityChanged → Unchanged → Fixed for UI scanning
    const order = { New: 0, SeverityChanged: 1, Unchanged: 2, Fixed: 3 } as const;
    rows.sort((a, b) => order[a.delta] - order[b.delta] || String(a.title).localeCompare(String(b.title)));

    return {
      ok: true as const,
      baseline: {
        id: baseline.meta.id,
        code: baseline.meta.code,
        score: baseline.meta.score,
        risk: baseline.meta.risk,
        findings: baseline.meta.findings,
        createdAt: baseline.meta.createdAt,
      },
      current: {
        id: current.meta.id,
        code: current.meta.code,
        score: current.meta.score,
        risk: current.meta.risk,
        findings: current.meta.findings,
        createdAt: current.meta.createdAt,
      },
      delta: {
        score: current.meta.score - baseline.meta.score,
        findings: current.meta.findings - baseline.meta.findings,
      },
      /** Team-ready aliases */
      newFindings: neu,
      fixed,
      unchanged,
      /** Legacy aliases */
      resolved: fixed,
      persistent: unchanged,
      changedSeverity,
      rows,
      summary: {
        newCount: neu.length,
        fixedCount: fixed.length,
        unchangedCount: unchanged.length,
        severityChangedCount: changedSeverity.length,
        net: fixed.length - neu.length,
      },
      developerProgress: {
        resolvedCount: fixed.length,
        newCount: neu.length,
        net: fixed.length - neu.length,
      },
    };
  }

  compareLatest(projectId: string) {
    const scans = this.listScansNewestFirst(projectId);
    if (scans.length < 2) return { ok: false as const, error: 'Need at least two scans' };
    return this.compareScans(scans[1].id, scans[0].id);
  }

  private readAllProjects(): Project[] {
    if (!fs.existsSync(this.projectsDir)) return [];
    return fs
      .readdirSync(this.projectsDir)
      .filter((f) => f.endsWith('.json'))
      .map((f) => JSON.parse(fs.readFileSync(path.join(this.projectsDir, f), 'utf8')) as Project);
  }

  private readAllScans(): ScanRecord[] {
    if (!fs.existsSync(this.scansDir)) return [];
    return fs
      .readdirSync(this.scansDir)
      .filter((f) => f.endsWith('.meta.json'))
      .map((f) => JSON.parse(fs.readFileSync(path.join(this.scansDir, f), 'utf8')) as ScanRecord);
  }

  private nextCode(prefix: 'project' | 'scan'): string {
    const codes =
      prefix === 'project'
        ? this.readAllProjects().map((p) => p.code)
        : this.readAllScans().map((s) => s.code);
    let max = 0;
    const re = new RegExp(`^${prefix}-(\\d+)$`, 'i');
    for (const c of codes) {
      const m = String(c || '').match(re);
      if (m) max = Math.max(max, Number(m[1]));
    }
    return `${prefix}-${String(max + 1).padStart(3, '0')}`;
  }

  private backfillProjectCodes(): void {
    const all = this.readAllProjects().sort((a, b) => a.createdAt.localeCompare(b.createdAt));
    const used = new Set(
      all.filter((p) => /^project-\d+$/i.test(p.code || '')).map((p) => String(p.code).toLowerCase()),
    );
    let n = 1;
    for (const p of all) {
      if (p.code && /^project-\d+$/i.test(p.code)) continue;
      while (used.has(`project-${String(n).padStart(3, '0')}`)) n += 1;
      const code = `project-${String(n).padStart(3, '0')}`;
      p.code = code;
      used.add(code);
      n += 1;
      fs.writeFileSync(path.join(this.projectsDir, `${p.id}.json`), JSON.stringify(p, null, 2));
    }
  }

  private backfillScanCodes(): void {
    const all = this.readAllScans().sort((a, b) => a.createdAt.localeCompare(b.createdAt));
    const used = new Set(
      all.filter((s) => /^scan-\d+$/i.test(s.code || '')).map((s) => String(s.code).toLowerCase()),
    );
    let n = 1;
    for (const s of all) {
      if (s.code && /^scan-\d+$/i.test(s.code)) continue;
      while (used.has(`scan-${String(n).padStart(3, '0')}`)) n += 1;
      const code = `scan-${String(n).padStart(3, '0')}`;
      s.code = code;
      used.add(code);
      n += 1;
      fs.writeFileSync(path.join(this.scansDir, `${s.id}.meta.json`), JSON.stringify(s, null, 2));
    }
  }
}

function codeSortKey(code?: string): string {
  const m = String(code || '').match(/^(project|scan)-(\d+)$/i);
  if (!m) return code || '';
  return `${m[1].toLowerCase()}-${m[2].padStart(6, '0')}`;
}

function findingFamilyKey(f: any): string {
  const cwe = (f.mappings?.cwe || f.cwe || []).slice(0, 2).join(',') || 'none';
  const endpoint = String(f.affectedEndpoint || f.affectedUrl || f.endpoint || '')
    .split('?')[0]
    .replace(/\/\d+/g, '/{id}')
    .replace(/\/[0-9a-f]{8,}/gi, '/{id}')
    .toLowerCase();
  const title = String(f.title || '')
    .replace(/\([^)]*\)/g, '')
    .replace(/on\s+\S+/gi, 'on')
    .replace(/via\s+.*/i, '')
    .replace(/["'`]/g, '')
    .trim()
    .toLowerCase()
    .slice(0, 80);
  return `${f.pluginId || 'plugin'}|${cwe}|${endpoint}|${title}`;
}

function summarizeFinding(f: any) {
  return {
    id: f.id,
    title: f.title,
    severity: f.severity,
    confidence: f.confidence,
    status: f.status,
    endpoint: f.affectedEndpoint || f.endpoint,
    cwe: f.mappings?.cwe || f.cwe || [],
    pluginId: f.pluginId,
  };
}

function inferDatabases(tech: any, findings: any[], recon: any): string[] {
  const out = new Set<string>(tech.database || []);
  const blob = JSON.stringify({
    tech,
    findings: findings.slice(0, 30).map((f) => ({ t: f.title, d: f.description, e: f.evidence })),
    routes: recon.bundleRoutes || [],
  }).toLowerCase();
  if (/mongo|mongoose|objectid|cwe-943|nosql/.test(blob)) out.add('MongoDB');
  if (/postgres|postgresql|pg_/.test(blob)) out.add('PostgreSQL');
  if (/mysql|mariadb/.test(blob)) out.add('MySQL');
  if (/sqlite/.test(blob)) out.add('SQLite');
  if (/redis/.test(blob)) out.add('Redis');
  if (/sql server|mssql/.test(blob)) out.add('Microsoft SQL Server');
  return [...out];
}

function inferLanguages(tech: any, findings: any[]): string[] {
  const out = new Set<string>(tech.languages || []);
  const backend = (tech.backend || []).join(' ').toLowerCase();
  const server = (tech.server || []).join(' ').toLowerCase();
  const blob = `${backend} ${server} ${JSON.stringify(findings.slice(0, 10)).toLowerCase()}`;
  if (/node|express|javascript|next\.js|nestjs/.test(blob)) out.add('JavaScript/TypeScript (Node.js)');
  if (/php/.test(blob)) out.add('PHP');
  if (/asp\.net|csharp|\.net/.test(blob)) out.add('C# / .NET');
  if (/python|django|flask|fastapi/.test(blob)) out.add('Python');
  if (/java|spring/.test(blob)) out.add('Java');
  if (/ruby|rails/.test(blob)) out.add('Ruby');
  if (/go\b|golang/.test(blob)) out.add('Go');
  if ((tech.frontend || []).some((f: string) => /angular|react|vue/i.test(f))) {
    out.add('JavaScript/TypeScript (Frontend)');
  }
  return [...out];
}
