import path from 'path';
import { createRequire } from 'module';
import type { Finding } from '../../core/types/finding';
import type { PluginContext, SecurityPlugin } from '../../core/types/plugin';
import type { Logger } from '../../core/logging/logger';
import type { KnowledgeRepository } from '../../core/knowledge';
import type { ScanPlan, ScanTask } from '../planning/ScanPlanningEngine';

const nodeRequire = createRequire(__filename);

export interface ExecutionProgress {
  stage: string;
  message: string;
  percent?: number;
}

export interface ExecutionResult {
  findings: Finding[];
  errors: Array<{ taskId: string; pluginId?: string; error: string }>;
  completedTasks: number;
}

type PluginWithHooks = SecurityPlugin & {
  initialize?: (ctx: PluginContext) => Promise<void> | void;
  cleanup?: (ctx: PluginContext) => Promise<void> | void;
};

/**
 * Plugin Execution Engine — runs planned tasks with lane-aware concurrency.
 * HTTP lane: parallel request-style plugins. Browser lane: limited concurrency (shared page).
 */
export class PluginExecutionEngine {
  constructor(
    private readonly logger: Logger,
    private readonly config: Record<string, any> = {},
  ) {}

  async execute(options: {
    plan: ScanPlan;
    ctx: PluginContext;
    repo: KnowledgeRepository;
    targetUrl: string;
    signal?: AbortSignal;
    onProgress?: (p: ExecutionProgress) => void;
    percentRange?: { start: number; end: number };
  }): Promise<ExecutionResult> {
    const { plan, ctx, repo, targetUrl, signal, onProgress } = options;
    const range = options.percentRange || { start: 40, end: 78 };
    const errors: Array<{ taskId: string; pluginId?: string; error: string }> = [];
    const findings: Finding[] = [];

    const throwIfCancelled = () => {
      if (signal?.aborted) throw new Error('Scan cancelled');
    };

    const pluginById = new Map(plan.plugins.map((p) => [p.manifest.id, p as PluginWithHooks]));
    const pluginTasks = plan.tasks.filter((t) => t.kind === 'plugin');
    const surfaceTask = plan.tasks.find((t) => t.kind === 'surface-check');

    const httpTasks = pluginTasks.filter((t) => t.lane === 'http');
    const browserTasks = pluginTasks.filter((t) => t.lane !== 'http');

    let completed = 0;
    const totalSteps = pluginTasks.length + (surfaceTask ? 1 : 0);

    const reportProgress = (message: string) => {
      const pct =
        range.start +
        Math.round((completed / Math.max(totalSteps, 1)) * (range.end - range.start));
      onProgress?.({ stage: 'probe', message, percent: pct });
    };

    const runOnePlugin = async (task: ScanTask) => {
      throwIfCancelled();
      const plugin = task.pluginId ? pluginById.get(task.pluginId) : undefined;
      if (!plugin) {
        errors.push({ taskId: task.id, pluginId: task.pluginId, error: 'Plugin not found in plan' });
        return;
      }

      reportProgress(
        `Plugin ${plugin.manifest.name} · ${task.lane} (${completed + 1}/${totalSteps})`,
      );

      try {
        if (typeof plugin.initialize === 'function') {
          await plugin.initialize(ctx);
        }
        const discovery = await plugin.discover(ctx);
        const candidates = await plugin.scan(ctx, discovery);
        const verified = await plugin.verify(ctx, candidates);
        findings.push(...verified);
        repo.addFindings(verified, 'draft');
      } catch (err: any) {
        const message = err?.message || String(err);
        this.logger.error('Plugin failed', { id: plugin.manifest.id, error: message });
        errors.push({ taskId: task.id, pluginId: plugin.manifest.id, error: message });
        repo.bus.emit('scan.error', repo.scanId, {
          pluginId: plugin.manifest.id,
          error: message,
        });
      } finally {
        try {
          if (typeof plugin.cleanup === 'function') {
            await plugin.cleanup(ctx);
          }
        } catch (err: any) {
          this.logger.warn('Plugin cleanup failed', {
            id: plugin.manifest.id,
            error: err?.message || String(err),
          });
        }
        completed += 1;
      }
    };

    // HTTP lane — parallel (Playwright APIRequestContext is safe for concurrent fetches)
    const httpConcurrency = Math.max(1, plan.httpConcurrencyHint || 4);
    this.logger.info('Executing HTTP-lane plugins', {
      count: httpTasks.length,
      concurrency: httpConcurrency,
    });
    await this.mapPool(httpTasks, httpConcurrency, runOnePlugin);

    // Browser lane — limited concurrency (default 1; shared page)
    const browserConcurrency = Math.max(
      1,
      Number(this.config.scan?.browserLaneConcurrency || 1),
    );
    this.logger.info('Executing browser-lane plugins', {
      count: browserTasks.length,
      concurrency: browserConcurrency,
    });
    await this.mapPool(browserTasks, browserConcurrency, runOnePlugin);

    // Residual surface checks (treated as browser-lane work)
    if (surfaceTask && plan.surfaceTypes.length) {
      throwIfCancelled();
      reportProgress(
        `Residual surface verification (${plan.surfaceTypes.length} types)…`,
      );
      try {
        const surfaceFindings = await this.runSurfaceChecks(
          ctx,
          targetUrl,
          plan.surfaceTypes,
        );
        findings.push(...surfaceFindings);
        repo.addFindings(surfaceFindings, 'draft');
      } catch (err: any) {
        const message = err?.message || String(err);
        this.logger.warn('Surface checks failed', { error: message });
        errors.push({ taskId: surfaceTask.id, error: message });
      } finally {
        completed += 1;
      }
    }

    reportProgress(`Probe complete (${completed}/${totalSteps})`);
    return { findings, errors, completedTasks: completed };
  }

  private async runSurfaceChecks(
    ctx: PluginContext,
    targetUrl: string,
    surfaceTypes: string[],
  ): Promise<Finding[]> {
    const { runSurfaceChecks } = nodeRequire(path.join(
      process.cwd(),
      'src',
      'scanner',
      'modules',
      'surfaceChecks.js',
    ));
    const surfaceRaw = await runSurfaceChecks(ctx.page, targetUrl, surfaceTypes, {
      apiBases: ctx.attackSurface.apiBases || [],
    });
    return surfaceRaw.map((f: any) => this.legacySurfaceToFinding(f));
  }

  private legacySurfaceToFinding(f: any): Finding {
    const { getSeverity } = nodeRequire(path.join(process.cwd(), 'src', 'scanner', 'severity.js'));
    const severity = getSeverity(f) || f.severity || (f.issueFound ? 'Medium' : 'Informational');
    return {
      id: f.id,
      pluginId: 'surface-checks',
      title: f.title || 'Surface check',
      description: f.description || '',
      severity,
      confidence: f.issueFound ? 'Likely' : 'Informational',
      cvss: f.cvss
        ? {
            vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N',
            score: f.cvss,
            severity,
          }
        : null,
      mappings: {
        cwe: f.cwe || [],
        owaspTop10: f.owasp ? [f.owasp] : [],
      },
      affectedUrl: f.fullUrl || f.endpoint,
      affectedEndpoint: f.endpoint,
      parameter: f.parameter,
      method: f.method || 'GET',
      evidence: f.evidence || [],
      http: [],
      impact: f.issueFound ? 'May increase application risk depending on exploitability.' : 'None',
      remediation: f.issueFound
        ? 'Review and remediate according to OWASP guidance for this control.'
        : 'No action required for this check.',
      references: ['https://owasp.org/www-project-web-security-testing-guide/'],
      status: f.status || (f.issueFound ? 'Confirmed' : 'Pass'),
      issueFound: Boolean(f.issueFound),
      testMode: 'active-safe',
      module: f.module || 'Surface Checks',
      featureName: f.featureName,
      techniques: f.techniques,
      cwe: f.cwe,
      owasp: f.owasp,
    };
  }

  /** Run async work over items with a fixed concurrency pool. */
  private async mapPool<T>(
    items: T[],
    concurrency: number,
    worker: (item: T) => Promise<void>,
  ): Promise<void> {
    if (!items.length) return;
    const queue = [...items];
    const runners = Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
      while (queue.length) {
        const item = queue.shift();
        if (item === undefined) break;
        await worker(item);
      }
    });
    await Promise.all(runners);
  }
}
