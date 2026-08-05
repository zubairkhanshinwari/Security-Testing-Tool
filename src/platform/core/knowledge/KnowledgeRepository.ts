import type {
  AttackSurface,
  AuthSession,
  Finding,
  RiskSummary,
  ScanRequest,
  ScanResult,
  TestMode,
} from '../types/finding';
import type { Logger } from '../logging/logger';
import { ScanEventBus } from './ScanEventBus';

export interface TypeCoverageRow {
  typeId: string;
  plugins: string[];
  surfaceCheck: boolean;
  status: string;
  findingCount?: number;
}

export interface ScanContextMeta {
  scanId: string;
  request: ScanRequest;
  mode: TestMode;
  requestedTypes: string[];
  selectedTypes: string[];
  catalogSize: number;
  startedAt: Date;
  platformVersion?: string;
}

/**
 * Central in-memory knowledge store for one scan.
 * Engines read/write here instead of passing large recon blobs between stages.
 */
export class KnowledgeRepository {
  readonly bus: ScanEventBus;
  readonly meta: ScanContextMeta;

  private discovery: Record<string, any> | null = null;
  private fingerprint: Record<string, unknown> | null = null;
  private session: AuthSession | null = null;
  private attackSurface: AttackSurface | null = null;
  private findings: Finding[] = [];
  private typeCoverage: TypeCoverageRow[] = [];
  private pluginIds: string[] = [];
  private phaseTimingsMs: Record<string, number> = {};
  private risk: RiskSummary | null = null;
  private assessmentSummary: Array<Record<string, unknown>> = [];
  private plan: Record<string, unknown> | null = null;
  private stage: string = 'init';

  constructor(
    meta: ScanContextMeta,
    private readonly logger: Logger,
    bus?: ScanEventBus,
  ) {
    this.meta = meta;
    this.bus = bus || new ScanEventBus();
  }

  get scanId(): string {
    return this.meta.scanId;
  }

  beginStage(stage: string, message?: string): void {
    this.stage = stage;
    this.bus.emit('stage.start', this.scanId, { stage, message });
  }

  endStage(stage: string, durationMs?: number): void {
    if (typeof durationMs === 'number') this.phaseTimingsMs[stage] = durationMs;
    this.bus.emit('stage.end', this.scanId, { stage, durationMs });
  }

  markPhase(phase: string, durationMs: number): void {
    this.phaseTimingsMs[phase] = durationMs;
  }

  getPhaseTimings(): Record<string, number> {
    return { ...this.phaseTimingsMs };
  }

  setDiscovery(recon: Record<string, any>): void {
    this.discovery = recon;
    this.emitDiscoveryEvents(recon);
    this.logger.info('Knowledge: discovery stored', {
      pages: Array.isArray(recon.visitedUrls) ? recon.visitedUrls.length : 0,
      apis: Array.isArray(recon.apis) ? recon.apis.length : 0,
      forms: recon.pageInfo?.forms?.length || 0,
    });
  }

  /**
   * Phase A — merge a second discovery pass (e.g. post-auth crawl) into the store.
   */
  mergeDiscovery(incoming: Record<string, any>): void {
    if (!this.discovery) {
      this.setDiscovery(incoming);
      return;
    }
    const prev = this.discovery;
    const mergedApis = dedupeByKey(
      [...(prev.apis || []), ...(incoming.apis || [])],
      (a) => `${a.method || 'GET'}|${String(a.url || '').split('?')[0]}`,
    );
    const mergedVisited = [
      ...new Set([...(prev.visitedUrls || []), ...(incoming.visitedUrls || [])]),
    ];
    const mergedForms = dedupeByKey(
      [...(prev.pageInfo?.forms || []), ...(incoming.pageInfo?.forms || [])],
      (f) =>
        `${f.method}|${f.action}|${(f.fields || []).map((x: any) => x.name).join(',')}`,
    );
    const mergedQuery = dedupeByKey(
      [...(prev.querySurfaces || []), ...(incoming.querySurfaces || [])],
      (q) => q.baseUrl,
    );
    const mergedOpenapiEps = dedupeByKey(
      [...(prev.openapiEndpoints || []), ...(incoming.openapiEndpoints || [])],
      (a) => `${a.method || 'GET'}|${String(a.url || '').split('?')[0]}`,
    );

    this.discovery = {
      ...prev,
      ...incoming,
      apis: mergedApis,
      visitedUrls: mergedVisited,
      querySurfaces: mergedQuery,
      openapiEndpoints: mergedOpenapiEps,
      openapiCandidates: [
        ...new Set([...(prev.openapiCandidates || []), ...(incoming.openapiCandidates || [])]),
      ],
      sitemapUrls: [
        ...new Set([...(prev.sitemapUrls || []), ...(incoming.sitemapUrls || [])]),
      ],
      apiBases: [...new Set([...(prev.apiBases || []), ...(incoming.apiBases || [])])],
      bundleRoutes: [
        ...new Set([...(prev.bundleRoutes || []), ...(incoming.bundleRoutes || [])]),
      ],
      pageInfo: {
        ...(prev.pageInfo || {}),
        ...(incoming.pageInfo || {}),
        forms: mergedForms,
        tokens: {
          ...(prev.pageInfo?.tokens || {}),
          ...(incoming.pageInfo?.tokens || {}),
        },
      },
      frameworks: [
        ...new Set([...(prev.frameworks || []), ...(incoming.frameworks || [])]),
      ],
      discoveredToken: incoming.discoveredToken || prev.discoveredToken || null,
    };

    this.emitDiscoveryEvents(incoming);
    this.logger.info('Knowledge: discovery merged', {
      pages: mergedVisited.length,
      apis: mergedApis.length,
      forms: mergedForms.length,
    });
  }

  private emitDiscoveryEvents(recon: Record<string, any>): void {
    const pages: string[] = Array.isArray(recon.visitedUrls) ? recon.visitedUrls : [];
    for (const url of pages.slice(0, 200)) {
      this.bus.emit('page.found', this.scanId, { url });
    }
    const apis: any[] = Array.isArray(recon.apis) ? recon.apis : [];
    for (const api of apis.slice(0, 200)) {
      this.bus.emit('endpoint.found', this.scanId, {
        url: api.url || api.endpoint,
        method: api.method || 'GET',
        source: 'discovery',
      });
    }
  }

  getDiscovery<T = Record<string, any>>(): T {
    if (!this.discovery) throw new Error('KnowledgeRepository: discovery not set');
    return this.discovery as T;
  }

  hasDiscovery(): boolean {
    return this.discovery != null;
  }

  setFingerprint(tech: Record<string, unknown>): void {
    this.fingerprint = tech;
  }

  getFingerprint(): Record<string, unknown> {
    return this.fingerprint || {};
  }

  setSession(session: AuthSession): void {
    this.session = session;
  }

  getSession(): AuthSession {
    if (!this.session) {
      return { ok: false, type: 'none', message: 'No session established' };
    }
    return this.session;
  }

  setAttackSurface(surface: AttackSurface): void {
    this.attackSurface = surface;
    for (const ep of (surface.endpoints || []).slice(0, 300)) {
      this.bus.emit('endpoint.found', this.scanId, {
        url: ep.url,
        method: ep.method,
        source: ep.source || 'attack-surface',
      });
    }
  }

  getAttackSurface(): AttackSurface {
    if (!this.attackSurface) throw new Error('KnowledgeRepository: attack surface not set');
    return this.attackSurface;
  }

  setPlugins(pluginIds: string[]): void {
    this.pluginIds = [...pluginIds];
  }

  getPlugins(): string[] {
    return [...this.pluginIds];
  }

  setPlan(plan: {
    pluginIds: string[];
    surfaceTypes: string[];
    skippedPlugins?: Array<{ id: string; reason: string }>;
    mode?: string;
    summary?: string;
    httpConcurrencyHint?: number;
    incremental?: boolean;
    focusEndpoints?: string[];
    retestPluginIds?: string[];
    baselineScanId?: string;
    tasks?: unknown[];
  }): void {
    // Persist a serializable snapshot (plugins themselves stay on the live ScanPlan).
    this.plan = {
      pluginIds: plan.pluginIds,
      surfaceTypes: plan.surfaceTypes,
      skippedPlugins: plan.skippedPlugins || [],
      mode: plan.mode,
      summary: plan.summary,
      httpConcurrencyHint: plan.httpConcurrencyHint,
      incremental: Boolean(plan.incremental),
      focusEndpoints: plan.focusEndpoints || [],
      retestPluginIds: plan.retestPluginIds || [],
      baselineScanId: plan.baselineScanId,
      tasks: (plan.tasks || []).map((task) => {
        const t = task as {
          id?: string;
          kind?: string;
          pluginId?: string;
          priority?: number;
          lane?: string;
          reason?: string;
        };
        return {
          id: t.id,
          kind: t.kind,
          pluginId: t.pluginId,
          priority: t.priority,
          lane: t.lane,
          reason: t.reason,
        };
      }),
    };
    this.pluginIds = [...plan.pluginIds];
  }

  getPlan(): Record<string, unknown> | null {
    return this.plan ? { ...this.plan } : null;
  }

  addFindings(items: Finding[], kind: 'draft' | 'verified' = 'draft'): void {
    if (!items.length) return;
    this.findings.push(...items);
    const eventType = kind === 'verified' ? 'finding.verified' : 'finding.draft';
    for (const f of items) {
      this.bus.emit(eventType, this.scanId, {
        id: f.id,
        pluginId: f.pluginId,
        title: f.title,
        issueFound: f.issueFound,
        severity: f.severity,
      });
    }
  }

  replaceFindings(items: Finding[]): void {
    this.findings = [...items];
  }

  getFindings(): Finding[] {
    return this.findings;
  }

  setTypeCoverage(coverage: TypeCoverageRow[]): void {
    this.typeCoverage = coverage;
    this.bus.emit('coverage.updated', this.scanId, { count: coverage.length });
  }

  getTypeCoverage(): TypeCoverageRow[] {
    return this.typeCoverage;
  }

  setRisk(risk: RiskSummary): void {
    this.risk = risk;
  }

  getRisk(): RiskSummary {
    if (!this.risk) throw new Error('KnowledgeRepository: risk not set');
    return this.risk;
  }

  setAssessmentSummary(summary: Array<Record<string, unknown>>): void {
    this.assessmentSummary = summary;
  }

  buildReconSummary(): Record<string, unknown> {
    const recon = this.discovery || {};
    const tech = this.getFingerprint();
    return {
      pageTitle: recon.pageInfo?.title,
      forms: recon.pageInfo?.forms?.length || 0,
      linksVisited: (recon.visitedUrls || []).length,
      apisObserved: (recon.apis || []).length,
      querySurfaces: (recon.querySurfaces || []).length,
      apiBases: recon.apiBases || [],
      bundleRoutes: (recon.bundleRoutes || []).slice(0, 40),
      apis: (recon.apis || []).slice(0, 40),
      visitedUrls: recon.visitedUrls || [],
      robots: recon.robots,
      openapi: recon.openapiCandidates || [],
      technology: tech,
    };
  }

  toScanResult(finishedAt = new Date()): ScanResult {
    const { request, mode, requestedTypes, selectedTypes, catalogSize, startedAt } = this.meta;
    const auth = this.getSession();
    const findings = this.findings;
    const risk = this.getRisk();
    const attackSurface = this.getAttackSurface();
    const assessmentSummary = this.assessmentSummary;
    const phaseTimings = this.getPhaseTimings();
    const tech = this.getFingerprint();

    return {
      meta: {
        projectName: request.projectName || 'Web Security Assessment',
        projectId: request.projectId || null,
        targetUrl: request.targetUrl,
        environment: request.environment || 'Development',
        testerName: request.testerName || 'SecureAssess Platform',
        assessmentType: 'Web Security Assessment',
        standard: 'OWASP WSTG / OWASP Top 10 (2021) / ASVS / CWE / CVSS v4',
        startedAt: startedAt.toISOString(),
        finishedAt: finishedAt.toISOString(),
        durationMinutes: Math.max(
          1,
          Math.round((finishedAt.getTime() - startedAt.getTime()) / 60000),
        ),
        authUsed: Boolean(auth.ok && auth.ready !== false && (auth.token || auth.type === 'cookie' || auth.type === 'jwt')),
        loginAttempted: Boolean(request.username && request.password),
        loginSuccess: Boolean(
          auth.ok &&
            auth.ready !== false &&
            (auth.type === 'password' ||
              auth.type === 'cookie' ||
              auth.type === 'jwt' ||
              auth.type === 'discovered'),
        ),
        authAdapter: auth.adapter || null,
        loginMessage: auth.message,
        securityTypesRequested: requestedTypes,
        securityTypes: selectedTypes,
        securityTypesCount: requestedTypes.length,
        selectedAll: catalogSize > 0 && requestedTypes.length >= catalogSize,
        typeCoverage: this.typeCoverage,
        plugins: this.pluginIds,
        scanPlan: this.plan,
        mode,
        technology: tech,
        phaseTimingsMs: phaseTimings,
        version: this.meta.platformVersion || '2.0.0',
        platform: 'SecureAssess',
        scanId: this.scanId,
        knowledgeRepository: true,
        scanProfile: request.profile || this.plan?.profile || 'standard',
        precisionPack: 'verification-baseline-v1',
        confirmationPack: 'confirmation-depth-v1',
        coveragePack: 'coverage-focus-v1',
        focusEndpointCount: Array.isArray(request.focusEndpoints)
          ? request.focusEndpoints.length
          : 0,
        openApiUrl: request.openApiUrl || null,
        safety: {
          nonDestructive: true,
          authorizationRequired: true,
          targetPolicyEnforced: true,
          modes: ['passive', 'active-safe', 'authenticated'],
          modeEnforced: true,
        },
      },
      attackSurface,
      findings,
      risk,
      assessmentSummary,
      recon: this.buildReconSummary(),
      stats: {
        totalFindings: findings.filter((f) => f.issueFound).length,
        confirmedSqli: findings.filter(
          (f) => f.issueFound && (f.mappings?.cwe || []).includes('CWE-89'),
        ).length,
        severityCounts: risk.severityCounts,
        endpointsTested: new Set(findings.map((f) => f.affectedEndpoint)).size,
        parametersTested: findings.length,
        modulesTested: assessmentSummary.length,
        securityScore: risk.overallScore,
        overallRisk: risk.overallRisk,
        authUsed: Boolean(auth.ok && (auth.token || auth.type === 'cookie')),
        authGap: !auth.ok,
        owaspCoverage: risk.owaspCoverage,
        testMode: mode,
        phaseTimingsMs: phaseTimings,
      },
    };
  }

  dispose(): void {
    this.bus.emit('scan.done', this.scanId, { stage: this.stage });
    this.bus.clear();
  }
}

export function createScanId(): string {
  return `scan-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function dedupeByKey<T>(items: T[], keyFn: (item: T) => string): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const item of items) {
    const key = keyFn(item);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}
