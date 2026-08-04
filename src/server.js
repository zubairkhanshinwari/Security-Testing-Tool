const express = require('express');
const path = require('path');
const fs = require('fs');
const { runAssessment } = require('./scanner');
const { generateReports } = require('./report/pdfReport');
const { SECURITY_TYPES, DEFAULT_SELECTED } = require('./scanner/securityTypes');

const app = express();
const PORT = process.env.PORT || 3847;
const ROOT = path.join(__dirname, '..');
const REPORTS = path.join(ROOT, 'reports');
const JOBS = new Map();

fs.mkdirSync(REPORTS, { recursive: true });

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(ROOT, 'public')));
app.use('/reports', express.static(REPORTS));

function isHttpUrl(value) {
  try {
    const u = new URL(value);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, tool: 'Web Security Assessment Tool', version: '1.1.0' });
});

app.get('/api/security-types', (_req, res) => {
  res.json({
    types: SECURITY_TYPES,
    defaultSelected: DEFAULT_SELECTED,
  });
});

app.post('/api/scan', async (req, res) => {
  const {
    targetUrl,
    projectName = 'Web Security Assessment',
    environment = 'Development',
    testerName = 'Security Assessment Tool',
    username = '',
    password = '',
    securityTypes,
    authorized = false,
  } = req.body || {};

  if (!authorized) {
    return res.status(400).json({
      error: 'You must confirm authorization before scanning.',
    });
  }
  if (!targetUrl || !isHttpUrl(targetUrl)) {
    return res.status(400).json({ error: 'A valid http(s) target URL is required.' });
  }

  const types = Array.isArray(securityTypes) && securityTypes.length
    ? securityTypes
    : DEFAULT_SELECTED;

  const jobId = `job-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  JOBS.set(jobId, {
    id: jobId,
    status: 'running',
    progress: { stage: 'queued', message: 'Queued' },
    createdAt: new Date().toISOString(),
  });

  res.json({ jobId, status: 'running' });

  (async () => {
    try {
      const data = await runAssessment({
        targetUrl,
        projectName,
        environment,
        testerName,
        username: username || null,
        password: password || null,
        securityTypes: types,
        onProgress: (p) => {
          const job = JOBS.get(jobId);
          if (job) job.progress = p;
        },
      });

      const files = await generateReports(data, REPORTS);
      JOBS.set(jobId, {
        id: jobId,
        status: 'completed',
        progress: { stage: 'done', message: 'Report ready' },
        createdAt: JOBS.get(jobId)?.createdAt,
        finishedAt: new Date().toISOString(),
        stats: data.stats,
        meta: data.meta,
        files: {
          pdf: `/reports/${path.basename(files.pdfPath)}`,
          html: `/reports/${path.basename(files.htmlPath)}`,
          json: `/reports/${path.basename(files.jsonPath)}`,
        },
      });
    } catch (err) {
      JOBS.set(jobId, {
        id: jobId,
        status: 'failed',
        progress: { stage: 'error', message: err.message },
        error: err.message,
        createdAt: JOBS.get(jobId)?.createdAt,
        finishedAt: new Date().toISOString(),
      });
    }
  })();
});

app.get('/api/scan/:jobId', (req, res) => {
  const job = JOBS.get(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  res.json(job);
});

app.listen(PORT, () => {
  console.log('');
  console.log('  Web Security Assessment Tool');
  console.log(`  Open UI:  http://localhost:${PORT}`);
  console.log(`  Reports:  ${REPORTS}`);
  console.log('');
  console.log('  Use only on systems you own or are authorized to test.');
  console.log('');
});
