import { Router } from 'express';
import type { Logger } from '../../platform/core/logging/logger';
import type { JobController } from '../../platform/engines/jobs/JobController';
import type { ComplianceAssessmentEngine, ComplianceAssessmentRequest } from '../core/ComplianceAssessmentEngine';
import type { ComplianceAssessmentStore } from '../persistence/ComplianceAssessmentStore';
import type { ComplianceReportingEngine } from '../reporting/ComplianceReportingEngine';
import type { CISBenchmarkManager } from '../cis/CISBenchmarkManager';

export interface ComplianceRouterDeps {
  complianceEngine: ComplianceAssessmentEngine;
  complianceStore: ComplianceAssessmentStore;
  complianceReporting: ComplianceReportingEngine;
  benchmarkManager: CISBenchmarkManager;
  jobs: JobController;
  logger: Logger;
}

/**
 * Additive Express Router mounted at /api/compliance. Does not modify any
 * existing route in server.ts — POST /api/scan and friends are untouched.
 */
export function complianceRouter(deps: ComplianceRouterDeps): Router {
  const { complianceEngine, complianceStore, complianceReporting, benchmarkManager, jobs, logger } = deps;
  const router = Router();

  router.get('/benchmarks', async (_req, res) => {
    const benchmarks = await benchmarkManager.listAvailable();
    res.json({ benchmarks });
  });

  router.get('/benchmarks/:id/:version/controls', async (req, res) => {
    try {
      const benchmark = await benchmarkManager.loadBenchmark(req.params.id, req.params.version);
      res.json({ controls: benchmark.controls });
    } catch (err: any) {
      res.status(404).json({ error: err?.message || 'Benchmark not found' });
    }
  });

  router.post('/scan', async (req, res) => {
    const body = (req.body || {}) as Partial<ComplianceAssessmentRequest> & { authorized?: boolean };

    if (!body.authorized) {
      return res.status(400).json({ error: 'You must confirm authorization before running a CIS Linux assessment.' });
    }
    if (!body.target?.hostname) {
      return res.status(400).json({ error: 'target.hostname is required.' });
    }
    if (!body.benchmarkId || !body.benchmarkVersion) {
      return res.status(400).json({ error: 'benchmarkId and benchmarkVersion are required.' });
    }
    if (!body.credentialRef?.type || !body.credentialRef?.ref) {
      return res.status(400).json({ error: 'credentialRef (type + ref) is required.' });
    }

    const jobId = `compliance-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const job = jobs.create({
      id: jobId,
      projectId: body.projectId,
      targetUrl: body.target.hostname,
      projectName: 'CIS Linux Assessment',
    });

    res.json({ jobId, status: job.status });

    (async () => {
      try {
        const assessment = await jobs.runLimited(jobId, () =>
          complianceEngine.run({
            projectId: body.projectId,
            target: {
              hostname: body.target!.hostname,
              port: body.target!.port || 22,
              osFamily: 'ubuntu',
              osVersion: body.target!.osVersion,
              label: body.target!.label,
            },
            benchmarkId: body.benchmarkId!,
            benchmarkVersion: body.benchmarkVersion!,
            profile: body.profile || 'server-level-1',
            selectedControls: body.selectedControls,
            credentialRef: body.credentialRef!,
            requestedBy: body.requestedBy,
            authorized: true,
          }),
        );

        complianceStore.saveAssessment(assessment);

        const benchmark = await benchmarkManager.loadBenchmark(assessment.benchmarkId, assessment.benchmarkVersion);
        const evidence = complianceStore.evidenceRepositoryFor(assessment.assessmentId).list();
        const files = await complianceReporting.generate(assessment, {
          controls: benchmark.controls,
          evidence,
          targetHostname: body.target!.hostname,
        });

        jobs.update(jobId, {
          status: 'completed',
          progress: { stage: 'done', message: 'Compliance report ready' },
          finishedAt: new Date().toISOString(),
          meta: { assessmentId: assessment.assessmentId, metrics: assessment.metrics },
          files: { html: files.htmlPath || '', json: files.jsonPath || '' },
        });
      } catch (err: any) {
        logger.error('Compliance assessment job failed', { jobId, error: err?.message || String(err) });
        jobs.update(jobId, {
          status: 'failed',
          progress: { stage: 'error', message: err?.message || 'failed' },
          error: err?.message,
          finishedAt: new Date().toISOString(),
        });
      }
    })();
  });

  router.get('/jobs/:jobId', (req, res) => {
    const job = jobs.get(req.params.jobId);
    if (!job) return res.status(404).json({ error: 'Job not found' });
    res.json(jobs.toPublic(job));
  });

  router.get('/:assessmentId', (req, res) => {
    const assessment = complianceStore.getAssessment(req.params.assessmentId);
    if (!assessment) return res.status(404).json({ error: 'Assessment not found' });
    res.json({ assessment });
  });

  router.get('/:assessmentId/results', (req, res) => {
    const assessment = complianceStore.getAssessment(req.params.assessmentId);
    if (!assessment) return res.status(404).json({ error: 'Assessment not found' });
    res.json({ controlResults: assessment.controlResults, metrics: assessment.metrics });
  });

  router.get('/:assessmentId/report', (req, res) => {
    const assessment = complianceStore.getAssessment(req.params.assessmentId);
    if (!assessment) return res.status(404).json({ error: 'Assessment not found' });
    res.json({
      html: `/reports/compliance-${assessment.assessmentId}.html`,
      json: `/reports/compliance-${assessment.assessmentId}.json`,
    });
  });

  return router;
}
