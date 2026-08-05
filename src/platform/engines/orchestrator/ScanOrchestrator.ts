import path from 'path';
import { createRequire } from 'module';
import type { Finding, ScanRequest, ScanResult } from '../../core/types/finding';
import type { Logger } from '../../core/logging/logger';
import type { BrowserEngine } from '../browser/BrowserEngine';
import type { SessionEngine } from '../session/SessionEngine';
import type { DiscoveryEngine } from '../discovery/DiscoveryEngine';
import type { AttackSurfaceEngine } from '../attack-surface/AttackSurfaceEngine';
import type { ScanPlanningEngine } from '../planning/ScanPlanningEngine';
import type { PluginExecutionEngine } from '../execution/PluginExecutionEngine';
import type { VerificationEngine } from '../verification/VerificationEngine';
import type { EvidenceEngine } from '../evidence/EvidenceEngine';
import type { RiskEngine } from '../risk/RiskEngine';
import type { ReportingEngine } from '../reporting/ReportingEngine';
import type { ProjectStore } from '../../dashboard/ProjectStore';
import type { PluginContext } from '../../core/types/plugin';
import { validateTargetUrl } from '../../core/safety/targetPolicy';
import { redactSecrets } from '../../core/safety/redact';
import { KnowledgeRepository, createScanId } from '../../core/knowledge';
import { KnowledgeEngine } from '../knowledge/KnowledgeEngine';
import { FingerprintEngine } from '../fingerprint/FingerprintEngine';
import type { BaselineDiff } from '../../dashboard/baseline';
import {
  applyProfileToConfig,
  normalizeFocusEndpoints,
  profileEtaLabel,
} from '../../core/config/scanProfiles';

const nodeRequire = createRequire(__filename);

/**
 * Scan Orchestrator — thin lifecycle coordinator (Architecture v2 Phase 6).
 *
 * Owns: start/cancel/progress/failure policy and engine sequencing.
 * Incremental mode: ProjectStore baseline → planner focus (new endpoints + prior issues).
 *
 * Flow: policy → browser → discovery → fingerprint → session → surface →
 * plan → execute → verify → evidence → risk → result
 */
export class ScanOrchestrator {
  private readonly knowledge = new KnowledgeEngine();
  private readonly fingerprint = new FingerprintEngine();

  constructor(
    private readonly logger: Logger,
    private readonly browserEngine: BrowserEngine,
    private readonly sessionEngine: SessionEngine,
    private readonly discovery: DiscoveryEngine,
    private readonly surface: AttackSurfaceEngine,
    private readonly planner: ScanPlanningEngine,
    private readonly executor: PluginExecutionEngine,
    private readonly verification: VerificationEngine,
    private readonly evidence: EvidenceEngine,
    private readonly risk: RiskEngine,
    private readonly reporting: ReportingEngine,
    private readonly store: ProjectStore,
    private readonly config: Record<string, any>,
  ) {}

  async run(request: ScanRequest): Promise<ScanResult> {
    if (!request.authorized && this.config.safety?.requireAuthorization !== false) {
      throw new Error('Authorization confirmation is required before scanning.');
    }
    if (!request.targetUrl) throw new Error('targetUrl is required');

    const policy = validateTargetUrl(request.targetUrl);
    if (!policy.ok) throw new Error(policy.reason || 'Target rejected by safety policy');

    const mode = request.mode || 'active-safe';
    const progress = request.onProgress || (() => undefined);
    const startedAt = new Date();
    const throwIfCancelled = () => {
      if (request.signal?.aborted) throw new Error('Scan cancelled');
    };

    const { config: scanConfig, profile } = applyProfileToConfig(this.config, request.profile);
    const userFocus = normalizeFocusEndpoints(request.targetUrl, request.focusEndpoints);
    const openApiUrl =
      request.openApiUrl && /^https?:\/\//i.test(String(request.openApiUrl))
        ? String(request.openApiUrl)
        : null;
    this.logger.info('Scan profile applied', {
      profile: profile.id,
      label: profile.label,
      eta: profileEtaLabel(profile),
      focusEndpoints: userFocus.length,
      openApiUrl: Boolean(openApiUrl),
    });

    const { requestedTypes, selectedTypes, catalogSize } = this.resolveTypes(request.securityTypes);
    const repo = new KnowledgeRepository(
      {
        scanId: createScanId(),
        request,
        mode,
        requestedTypes,
        selectedTypes,
        catalogSize,
        startedAt,
        platformVersion: this.config.app?.version || '2.0.0',
      },
      this.logger.child('knowledge-repo'),
    );

    const mark = (phase: string, t0: number) => {
      repo.markPhase(phase, Date.now() - t0);
      repo.endStage(phase, Date.now() - t0);
    };

    let t0 = Date.now();
    repo.beginStage('launch', 'Launching browser');
    progress({ stage: 'launch', message: 'Launching browser…', percent: 5 });
    this.logger.info('Security types selection', {
      scanId: repo.scanId,
      requested: requestedTypes.length,
      expanded: selectedTypes.length,
      catalogSize,
      mode,
      sample: requestedTypes.slice(0, 12),
    });
    const { page, context } = await this.browserEngine.launch({ headless: true });
    mark('launch', t0);

    try {
      throwIfCancelled();
      t0 = Date.now();
      repo.beginStage('recon', 'Discovery');
      progress({
        stage: 'recon',
        message: `Running ${profile.label} discovery (${profileEtaLabel(profile)})…`,
        percent: 15,
      });
      const discoveryCfg = scanConfig.scan?.discovery || {};
      const maxLinks = Number(
        discoveryCfg.maxPagesCrawl ?? scanConfig.safety?.maxPagesCrawl ?? 8,
      );
      // Focused profile: seed crawl heavily from operator routes; others merge as extras
      const seedLinks =
        profile.id === 'focused' && userFocus.length
          ? userFocus
          : userFocus;
      await this.discovery.discover(request.targetUrl, {
        maxLinks,
        parseOpenApi: discoveryCfg.parseOpenApi !== false,
        maxOpenApiPaths: Number(discoveryCfg.maxOpenApiPaths || 30),
        maxSitemapUrls: Number(discoveryCfg.maxSitemapUrls || 15),
        collectFormsOnCrawl: discoveryCfg.collectFormsOnCrawl !== false,
        pageSettleMs: Number(discoveryCfg.pageSettleMs || 350),
        homeSettleMs: Number(discoveryCfg.homeSettleMs || 700),
        scriptScanLimit: Number(discoveryCfg.scriptScanLimit || 6),
        extraSeedLinks: seedLinks,
        openApiUrls: openApiUrl ? [openApiUrl] : undefined,
        repo,
      });
      mark('recon', t0);

      throwIfCancelled();
      t0 = Date.now();
      repo.beginStage('fingerprint');
      progress({ stage: 'fingerprint', message: 'Fingerprinting technology stack…', percent: 20 });
      const techFingerprint = await this.fingerprint.fingerprint(
        page,
        request.targetUrl,
        repo.getDiscovery(),
      );
      repo.setFingerprint(techFingerprint as Record<string, unknown>);
      mark('fingerprint', t0);

      throwIfCancelled();
      t0 = Date.now();
      repo.beginStage('auth', 'Session');
      progress({ stage: 'auth', message: 'Establishing session…', percent: 25 });
      const session = await this.sessionEngine.establish(request, repo);
      mark('auth', t0);

      // Phase A: authenticated second-pass discovery — only when session is ready
      if (session?.ok && session.ready !== false && discoveryCfg.authRecrawl !== false) {
        throwIfCancelled();
        t0 = Date.now();
        repo.beginStage('auth-recon', 'Authenticated discovery');
        progress({
          stage: 'auth-recon',
          message: `Re-discovering after ${session.adapter || 'auth'} session…`,
          percent: 30,
        });
        const authMax = Number(discoveryCfg.authMaxPagesCrawl || Math.min(maxLinks, 8));
        // Prefer adapter post-login URL, then current page, then original target
        let authCrawlUrl = session.postLoginUrl || request.targetUrl;
        try {
          const { page } = this.browserEngine.getSession();
          const current = page.url();
          if (current && /^https?:\/\//i.test(current) && !/\/login/i.test(current)) {
            authCrawlUrl = current;
          } else if (session.postLoginUrl && !/\/login/i.test(session.postLoginUrl)) {
            authCrawlUrl = session.postLoginUrl;
          }
        } catch {
          /* keep postLoginUrl / targetUrl */
        }
        await this.discovery.discover(authCrawlUrl, {
          maxLinks: authMax,
          parseOpenApi: false,
          collectFormsOnCrawl: discoveryCfg.collectFormsOnCrawl !== false,
          merge: true,
          repo,
        });
        mark('auth-recon', t0);
      }

      throwIfCancelled();
      t0 = Date.now();
      repo.beginStage('surface');
      progress({ stage: 'surface', message: 'Building attack surface inventory…', percent: 35 });
      const attackSurface = this.surface.build(request.targetUrl, repo.getDiscovery());
      repo.setAttackSurface(attackSurface);
      mark('surface', t0);

      // Phase 6: optional incremental baseline diff
      const incremental =
        Boolean(request.incremental) || Boolean(scanConfig.scan?.incremental?.enabled);
      let baselineDiff: BaselineDiff | undefined;
      if (incremental && request.projectId) {
        baselineDiff = this.store.diffBaseline(request.projectId, attackSurface);
        this.logger.info('Incremental baseline diff', {
          available: baselineDiff.available,
          newEndpoints: baselineDiff.newEndpoints.length,
          priorConfirmed: baselineDiff.priorConfirmed.length,
          focusEndpoints: baselineDiff.focusEndpoints.length,
          baselineScanId: baselineDiff.baselineScanId,
        });
      }

      throwIfCancelled();
      t0 = Date.now();
      repo.beginStage('plan');
      progress({
        stage: 'plan',
        message: incremental
          ? `Building incremental scan plan${baselineDiff?.available ? ' (baseline found)' : ' (no baseline yet)'}…`
          : `Building ${profile.label} scan plan…`,
        percent: 38,
      });
      // Also fold OpenAPI-derived endpoints into focus when Focused profile
      const openApiFocus = (repo.getDiscovery()?.openapiEndpoints || [])
        .map((e: any) => e.url || e.path)
        .filter(Boolean)
        .slice(0, 40);
      const planFocus = normalizeFocusEndpoints(request.targetUrl, [
        ...userFocus,
        ...(profile.id === 'focused' ? openApiFocus : []),
      ]);
      const plan = this.planner.plan({
        requestedTypes,
        selectedTypes,
        explicitPluginIds: request.pluginIds,
        mode,
        attackSurface: repo.getAttackSurface(),
        fingerprint: repo.getFingerprint(),
        repo,
        maxConcurrentProbes: Number(
          scanConfig.scan?.httpLaneConcurrency ||
            scanConfig.safety?.maxConcurrentProbes ||
            4,
        ),
        incremental,
        baselineDiff,
        retestConfirmed: scanConfig.scan?.incremental?.retestConfirmed !== false,
        focusEndpoints: planFocus,
      });
      mark('plan', t0);
      this.logger.info('Executing scan plan', {
        scanId: repo.scanId,
        summary: plan.summary,
        httpConcurrencyHint: plan.httpConcurrencyHint,
        incremental: plan.incremental,
        profile: profile.id,
        focusEndpoints: plan.focusEndpoints?.length || 0,
      });

      const pluginsToRun = plan.plugins;
      const pluginCtx: PluginContext = {
        request: { ...request, focusEndpoints: planFocus },
        attackSurface: repo.getAttackSurface(),
        auth: repo.getSession(),
        page,
        browserContext: context,
        logger: this.logger.child('plugin'),
        config: scanConfig,
        selectedTypes,
        fingerprint: repo.getFingerprint(),
        focusEndpoints: plan.focusEndpoints,
        incremental: plan.incremental,
      };

      throwIfCancelled();
      t0 = Date.now();
      repo.beginStage('execute');
      progress({
        stage: 'probe',
        message: `Executing plan (${plan.pluginIds.length} plugins, dual lanes)…`,
        percent: 40,
      });
      const execution = await this.executor.execute({
        plan,
        ctx: pluginCtx,
        repo,
        targetUrl: request.targetUrl,
        signal: request.signal,
        onProgress: (p) => progress(p),
        percentRange: { start: 40, end: 78 },
      });
      if (execution.errors.length) {
        this.logger.warn('Probe execution completed with isolated failures', {
          scanId: repo.scanId,
          errors: execution.errors,
        });
      }
      mark('execute', t0);

      const typeCoverage = this.buildTypeCoverage(
        requestedTypes,
        selectedTypes,
        pluginsToRun.map((p) => p.manifest),
        repo.getFindings(),
      );
      repo.setTypeCoverage(typeCoverage);
      repo.addFindings(this.coverageFindings(typeCoverage, request.targetUrl), 'draft');

      throwIfCancelled();
      t0 = Date.now();
      repo.beginStage('verify');
      progress({ stage: 'verify', message: 'Multi-signal verification & confirmation gates…', percent: 86 });
      let findings = this.verification.process(repo.getFindings());
      progress({
        stage: 'verify',
        message: 'Confirmation retest gate (proof signals)…',
        percent: 89,
      });
      findings = this.verification.retestConfirmed(findings);
      findings = this.knowledge.enrich(findings);
      repo.replaceFindings(findings);
      for (const f of findings.filter((x) => x.issueFound)) {
        repo.bus.emit('finding.verified', repo.scanId, {
          id: f.id,
          pluginId: f.pluginId,
          title: f.title,
          severity: f.severity,
          status: f.status,
          confidence: f.confidence,
        });
      }
      mark('verify', t0);

      // Evidence only after verification (Phase 5) — never for Pass / Informational noise
      throwIfCancelled();
      t0 = Date.now();
      repo.beginStage('evidence');
      const eligible = this.evidence.selectEligible(repo.getFindings());
      progress({
        stage: 'evidence',
        message: `Collecting evidence (${eligible.length} verified C/H/M/L)…`,
        percent: 92,
      });
      const shotDir = this.evidence.defaultOutDir(
        path.join(process.cwd(), this.config.storage?.reportsDir || 'reports'),
        `scan-${startedAt.toISOString().replace(/[:.]/g, '-')}`,
      );
      findings = await this.evidence.collect({
        page,
        findings: repo.getFindings(),
        targetUrl: request.targetUrl,
        outDir: shotDir,
      });
      repo.replaceFindings(findings);
      mark('evidence', t0);

      t0 = Date.now();
      repo.beginStage('risk');
      const risk = this.risk.evaluateVerified(repo.getFindings());
      repo.setRisk(risk);
      repo.setAssessmentSummary(this.buildModuleSummary(repo.getFindings()));
      mark('risk', t0);

      const result = repo.toScanResult(new Date());
      progress({ stage: 'done', message: 'Assessment complete', percent: 100 });
      return redactSecrets(result);
    } finally {
      repo.dispose();
      await this.browserEngine.close();
    }
  }

  async runAndReport(request: ScanRequest) {
    const result = await this.run(request);
    const formats =
      (this.config.reporting?.formats as string[]) ||
      ['html', 'pdf', 'json', 'sarif', 'csv', 'junit'];
    const files = await this.reporting.generate(result, formats);
    return { result, files };
  }

  private resolveTypes(types?: string[]): {
    requestedTypes: string[];
    selectedTypes: string[];
    catalogSize: number;
  } {
    const { expandSecurityTypes, DEFAULT_SELECTED, SECURITY_TYPES } = nodeRequire(path.join(
      process.cwd(),
      'src',
      'scanner',
      'securityTypes.js',
    ));
    const catalogSize = Array.isArray(SECURITY_TYPES) ? SECURITY_TYPES.length : 0;
    const requestedTypes =
      Array.isArray(types) && types.length ? [...new Set(types)] : [...DEFAULT_SELECTED];
    const selectedTypes = expandSecurityTypes(requestedTypes);
    return { requestedTypes, selectedTypes, catalogSize };
  }

  private buildTypeCoverage(
    requested: string[],
    expanded: string[],
    manifests: Array<{ id: string; securityTypeIds: string[] }>,
    findings: Finding[],
  ) {
    const SURFACE_TYPES = new Set([
      'http_headers',
      'security_misconfig',
      'clickjacking',
      'cors',
      'cookie_security',
      'session_mgmt',
      'sensitive_data',
      'info_disclosure',
      'jwt',
      'open_redirect',
      'xss',
      'api_security',
      'bac',
      'idor',
      'ssrf',
      'csrf',
      'rate_limiting',
      'broken_auth',
      'sqli',
      'nosqli',
    ]);
    const all = [...new Set([...requested, ...expanded])];
    return all.map((typeId) => {
      const plugins = manifests
        .filter((m) => m.securityTypeIds.includes(typeId) || (typeId === 'owasp_top10' && m.securityTypeIds.includes('owasp_top10')))
        .map((m) => m.id);
      const surface = SURFACE_TYPES.has(typeId);
      const related = findings.filter(
        (f) =>
          (f.pluginId && plugins.includes(f.pluginId)) ||
          (f.module && typeId.replace(/_/g, ' ').toLowerCase().includes(String(f.module).toLowerCase().slice(0, 4))) ||
          (typeId === 'xss' && /xss/i.test(f.module || f.title || '')) ||
          (typeId === 'jwt' && /jwt/i.test(f.module || f.title || '')) ||
          (typeId === 'cors' && /cors/i.test(f.module || f.title || '')) ||
          (typeId === 'csrf' && /csrf/i.test(f.module || f.title || '')) ||
          (typeId === 'sqli' && /sql/i.test(f.module || f.title || '') && !/nosql/i.test(f.module || '')) ||
          (typeId === 'nosqli' && /nosql/i.test(f.module || f.title || '')),
      );
      let status: 'executed' | 'partial' | 'queued-no-deep-scanner' = 'queued-no-deep-scanner';
      if (plugins.length || surface) status = related.some((f) => f.issueFound) || related.length ? 'executed' : 'partial';
      if ((plugins.length || surface) && related.length === 0) status = 'partial';
      return {
        typeId,
        plugins,
        surfaceCheck: surface,
        status,
        findingCount: related.filter((f) => f.issueFound).length,
      };
    });
  }

  private coverageFindings(
    coverage: Array<{ typeId: string; plugins: string[]; surfaceCheck: boolean; status: string }>,
    targetUrl: string,
  ): Finding[] {
    const missingDeep = coverage.filter((c) => !c.plugins.length && !c.surfaceCheck);
    if (!missingDeep.length) return [];
    return [
      {
        id: undefined as any,
        pluginId: 'selection-coverage',
        title: `Selected types without deep scanner (${missingDeep.length})`,
        description:
          `You selected these security types, but no deep plugin/surface module is implemented yet: ` +
          `${missingDeep.map((m) => m.typeId).join(', ')}. ` +
          `They are recorded for coverage tracking; enable/implement plugins to execute them fully.`,
        severity: 'Informational',
        confidence: 'Informational',
        cvss: null,
        mappings: { cwe: [] },
        affectedUrl: targetUrl,
        affectedEndpoint: targetUrl,
        evidence: missingDeep.map((m) => m.typeId),
        impact: 'None directly — indicates assessment coverage gaps for selected types.',
        remediation: 'Keep types selected for reporting, and add plugins under modules/ for full verification.',
        references: [],
        status: 'Informational',
        issueFound: false,
        testMode: 'passive',
        module: 'Selection Coverage',
        techniques: ['Coverage Matrix'],
      },
    ];
  }

  private buildModuleSummary(findings: Finding[]) {
    const modules: Record<string, any> = {};
    for (const f of findings) {
      const m = f.module || f.pluginId || 'Other';
      if (!modules[m]) {
        modules[m] = { urls: new Set(), params: new Set(), findings: 0, highest: 'None' };
      }
      modules[m].urls.add(f.affectedEndpoint);
      modules[m].params.add(f.parameter || 'n/a');
      if (f.issueFound) {
        modules[m].findings += 1;
        const order = ['Critical', 'High', 'Medium', 'Low', 'Informational', 'None'];
        if (order.indexOf(f.severity) < order.indexOf(modules[m].highest)) {
          modules[m].highest = f.severity;
        }
      }
    }
    return Object.entries(modules).map(([name, m]) => ({
      module: name,
      urlsTested: m.urls.size,
      parametersTested: m.params.size,
      findings: m.findings,
      highestSeverity: m.highest,
    }));
  }
}
