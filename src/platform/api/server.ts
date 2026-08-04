import express from 'express';
import path from 'path';
import fs from 'fs';
import { createRequire } from 'module';
import { bootstrap } from '../bootstrap';
import { JobController } from '../engines/jobs/JobController';
import { validateTargetUrl } from '../core/safety/targetPolicy';
import { redactSecrets } from '../core/safety/redact';

const nodeRequire = createRequire(__filename);

async function main() {
  const root = process.cwd();
  const { config, logger, orchestrator, pluginManager, store } = await bootstrap(root);
  const app = express();
  const PORT = Number(process.env.PORT || config.app.port || 3847);
  const REPORTS = path.join(root, config.storage.reportsDir);
  const maxConcurrent = Number(config.safety?.maxConcurrentScans || config.safety?.maxConcurrentProbes || 1);
  const jobs = new JobController(Math.max(1, Math.min(4, maxConcurrent)));
  const apiKeyRequired = process.env.SECUREASSESS_API_KEY || '';

  fs.mkdirSync(REPORTS, { recursive: true });
  app.use(express.json({ limit: '2mb' }));
  app.use(express.static(path.join(root, 'public')));
  app.use('/reports', express.static(REPORTS));

  // Optional API key for enterprise deployments (backward compatible when unset)
  app.use('/api', (req, res, next) => {
    if (!apiKeyRequired) return next();
    if (req.path === '/health' || req.path === '/openapi.json') return next();
    const key = req.header('x-api-key') || '';
    if (key !== apiKeyRequired) {
      return res.status(401).json({ error: 'Invalid or missing x-api-key' });
    }
    return next();
  });

  function isHttpUrl(value: string) {
    try {
      const u = new URL(value);
      return u.protocol === 'http:' || u.protocol === 'https:';
    } catch {
      return false;
    }
  }

  app.get('/api/health', (_req, res) => {
    res.json({
      ok: true,
      tool: config.app.name,
      version: config.app.version,
      platform: 'SecureAssess',
      plugins: pluginManager.list().map((p) => p.manifest.id),
      jobs: {
        running: jobs.runningJobs().length,
        maxConcurrent,
      },
      safety: {
        targetPolicy: true,
        apiKeyRequired: Boolean(apiKeyRequired),
        allowPrivate: process.env.SECUREASSESS_ALLOW_PRIVATE === '1',
      },
    });
  });

  app.get('/api/openapi.json', (_req, res) => {
    const specPath = path.join(root, 'docs', 'openapi.json');
    if (fs.existsSync(specPath)) return res.sendFile(specPath);
    return res.status(404).json({ error: 'OpenAPI spec not found' });
  });

  app.get('/api/security-types', (_req, res) => {
    const { SECURITY_TYPES, DEFAULT_SELECTED } = nodeRequire(path.join(
      root,
      'src/scanner/securityTypes.js',
    ));
    res.json({ types: SECURITY_TYPES, defaultSelected: DEFAULT_SELECTED });
  });

  app.get('/api/plugins', (_req, res) => {
    res.json({ plugins: pluginManager.list().map((p) => p.manifest) });
  });

  app.get('/api/projects', (_req, res) => {
    res.json({ projects: store.listProjects() });
  });

  app.post('/api/projects', (req, res) => {
    const { name, targetUrl, owner, tags } = req.body || {};
    if (!name) return res.status(400).json({ error: 'name is required' });
    const project = store.createProject({ name, targetUrl, owner, tags });
    res.status(201).json(project);
  });

  app.get('/api/projects/:id', (req, res) => {
    const project = store.getProject(req.params.id);
    if (!project) return res.status(404).json({ error: 'Project not found' });
    res.json({
      project,
      scans: store.listScans(project.id),
      trends: store.trends(project.id),
      regression: store.detectRegression(project.id),
      baselineCompare: store.compareLatest(project.id),
      inventory: store.getLatestInventory(project.id),
      baseline: store.getBaseline(project.id),
    });
  });

  app.get('/api/projects/:id/baseline', (req, res) => {
    const project = store.getProject(req.params.id);
    if (!project) return res.status(404).json({ error: 'Project not found' });
    const baseline = store.getBaseline(project.id);
    if (!baseline) return res.status(404).json({ error: 'No baseline yet — run a full scan first.' });
    res.json({ baseline });
  });

  app.delete('/api/projects/:id', (req, res) => {
    const result = store.deleteProject(req.params.id);
    if (!result.ok) return res.status(404).json({ error: 'Project not found' });
    res.json({ ok: true, deleted: req.params.id, deletedScans: result.deletedScans });
  });

  app.get('/api/scans', (req, res) => {
    const projectId = req.query.projectId ? String(req.query.projectId) : undefined;
    res.json({ scans: store.listScans(projectId) });
  });

  app.get('/api/scans/compare', (req, res) => {
    const baselineId = String(req.query.baselineId || '');
    const currentId = String(req.query.currentId || '');
    const projectId = req.query.projectId ? String(req.query.projectId) : '';
    if (projectId && !baselineId && !currentId) {
      return res.json(store.compareLatest(projectId));
    }
    if (!baselineId || !currentId) {
      return res.status(400).json({ error: 'baselineId and currentId are required' });
    }
    return res.json(store.compareScans(baselineId, currentId));
  });

  app.get('/api/scans/:id', (req, res) => {
    const scan = store.getScan(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    res.json(redactSecrets(scan));
  });

  /**
   * Compatible scan API — same contract as v1 POST /api/scan
   * Extended: projectId, apiKey, mode, pluginIds, cancel via DELETE /api/scan/:jobId
   */
  app.post('/api/scan', async (req, res) => {
    const {
      targetUrl,
      projectName = 'Web Security Assessment',
      projectId,
      environment = 'Development',
      testerName = 'SecureAssess Platform',
      username = '',
      password = '',
      authHeader = '',
      apiKey = '',
      securityTypes,
      pluginIds,
      mode = 'active-safe',
      incremental = false,
      profile = 'standard',
      authorized = false,
    } = req.body || {};

    if (!authorized) {
      return res.status(400).json({ error: 'You must confirm authorization before scanning.' });
    }
    if (!targetUrl || !isHttpUrl(targetUrl)) {
      return res.status(400).json({ error: 'A valid http(s) target URL is required.' });
    }

    const policy = validateTargetUrl(targetUrl);
    if (!policy.ok) {
      return res.status(400).json({ error: policy.reason, code: 'TARGET_POLICY' });
    }

    let resolvedProjectId = projectId;
    if (!resolvedProjectId) {
      const project = store.createProject({
        name: projectName || 'Web Security Assessment',
        targetUrl,
        owner: testerName,
      });
      resolvedProjectId = project.id;
    }

    const jobId = `job-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const job = jobs.create({
      id: jobId,
      projectId: resolvedProjectId,
      targetUrl,
      projectName,
    });

    res.json({
      jobId,
      status: job.status,
      projectId: resolvedProjectId,
      targetUrl,
      mode,
      incremental: Boolean(incremental),
      profile: profile || 'standard',
    });

    (async () => {
      try {
        const { result, files } = await jobs.runLimited(jobId, async (signal) =>
          orchestrator.runAndReport({
            targetUrl,
            projectId: resolvedProjectId,
            projectName,
            environment,
            testerName,
            username: username || null,
            password: password || null,
            authHeader: authHeader || null,
            apiKey: apiKey || null,
            securityTypes,
            pluginIds,
            mode,
            incremental: Boolean(incremental),
            profile: profile || 'standard',
            authorized: true,
            signal,
            onProgress: (p) => {
              jobs.update(jobId, { progress: p });
            },
          }),
        );

        if (signalAborted(jobId, jobs)) {
          jobs.update(jobId, {
            status: 'cancelled',
            progress: { stage: 'cancelled', message: 'Cancelled' },
            finishedAt: new Date().toISOString(),
          });
          return;
        }

        const publicFiles: Record<string, string> = {};
        for (const [k, v] of Object.entries(files)) {
          if (typeof v === 'string' && k.endsWith('Path')) {
            publicFiles[k.replace(/Path$/, '')] = `/reports/${path.basename(v)}`;
          }
        }

        store.saveScan({
          projectId: resolvedProjectId!,
          targetUrl,
          score: result.risk.overallScore,
          risk: result.risk.overallRisk,
          findings: result.stats.totalFindings as number,
          meta: result.meta,
          files: publicFiles,
          result: redactSecrets(result),
        });

        jobs.update(jobId, {
          status: 'completed',
          progress: { stage: 'done', message: 'Report ready' },
          finishedAt: new Date().toISOString(),
          stats: result.stats,
          meta: result.meta,
          risk: result.risk,
          files: {
            pdf: publicFiles.pdf,
            html: publicFiles.html,
            json: publicFiles.json,
            sarif: publicFiles.sarif,
            csv: publicFiles.csv,
            junit: publicFiles.junit,
          },
        });
      } catch (err: any) {
        const cancelled = /cancel/i.test(err?.message || '') || signalAborted(jobId, jobs);
        logger.error('Scan job failed', { jobId, error: err?.message || String(err), cancelled });
        jobs.update(jobId, {
          status: cancelled ? 'cancelled' : 'failed',
          progress: {
            stage: cancelled ? 'cancelled' : 'error',
            message: err?.message || 'failed',
          },
          error: err?.message,
          finishedAt: new Date().toISOString(),
        });
      }
    })();
  });

  app.get('/api/jobs', (_req, res) => {
    const list = jobs.list().map((j) => jobs.toPublic(j));
    res.json({
      jobs: list,
      running: list.filter((j) => j.status === 'running' || j.status === 'queued'),
    });
  });

  app.get('/api/scan/:jobId', (req, res) => {
    const job = jobs.get(req.params.jobId);
    if (!job) return res.status(404).json({ error: 'Job not found' });
    res.json(jobs.toPublic(job));
  });

  app.delete('/api/scan/:jobId', (req, res) => {
    const ok = jobs.requestCancel(req.params.jobId);
    if (!ok) return res.status(404).json({ error: 'Job not found or already finished' });
    res.json({ ok: true, jobId: req.params.jobId, status: 'cancel_requested' });
  });

  app.post('/api/scan/:jobId/cancel', (req, res) => {
    const ok = jobs.requestCancel(req.params.jobId);
    if (!ok) return res.status(404).json({ error: 'Job not found or already finished' });
    res.json({ ok: true, jobId: req.params.jobId, status: 'cancel_requested' });
  });

  app.listen(PORT, () => {
    console.log('');
    console.log(`  ${config.app.name} v${config.app.version}`);
    console.log(`  Open UI:        http://localhost:${PORT}`);
    console.log(`  OpenAPI:        http://localhost:${PORT}/api/openapi.json`);
    console.log(`  Dashboard API:  http://localhost:${PORT}/api/projects`);
    console.log(`  Plugins:        ${pluginManager.list().length} loaded`);
    console.log(`  Max concurrent: ${maxConcurrent}`);
    console.log(`  Reports:        ${REPORTS}`);
    console.log('');
    console.log('  Authorized, non-destructive testing only. Target policy enforced.');
    console.log('');
  });
}

function signalAborted(jobId: string, jobs: JobController) {
  return Boolean(jobs.get(jobId)?.cancelRequested || jobs.get(jobId)?.abortController.signal.aborted);
}

main().catch((err) => {
  console.error('Failed to start SecureAssess:', err);
  process.exit(1);
});
