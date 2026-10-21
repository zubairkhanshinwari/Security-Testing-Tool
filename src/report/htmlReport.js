const fs = require('fs');
const { getSeverity } = require('../scanner/severity');
const { resolveBusinessImpact } = require('../platform/engines/knowledge/businessImpactNarratives');

function resolveScreenshotBase64(f) {
  if (f && f.screenshotBase64) return f.screenshotBase64;
  try {
    if (f && f.screenshotPath && fs.existsSync(f.screenshotPath)) {
      return fs.readFileSync(f.screenshotPath).toString('base64');
    }
  } catch {
    /* ignore */
  }
  return null;
}

/** Normalize heterogeneous evidence objects into table cells (no undefined). */
function formatEvidenceRow(e) {
  if (e == null) {
    return {
      technique: '—',
      payload: '—',
      status: '—',
      time: '—',
      length: '—',
      body: '—',
    };
  }
  if (typeof e === 'string') {
    return {
      technique: 'Note',
      payload: '—',
      status: '—',
      time: '—',
      length: String(e.length),
      body: e.slice(0, 160),
    };
  }

  const technique =
    e.technique ||
    e.check ||
    e.type ||
    (Array.isArray(e.missing) ? 'Missing security headers' : null) ||
    (e.snippet != null ? 'Content sample' : null) ||
    'Evidence';

  const payload =
    e.payload != null
      ? e.payload
      : Array.isArray(e.missing)
        ? e.missing.join(', ')
        : e.header || e.name || '—';

  const status = e.status != null ? e.status : e.ok === true ? 'OK' : e.ok === false ? 'Fail' : '—';

  const msRaw = e.ms ?? e.timingMs ?? e.timeMs ?? e.durationMs ?? e.elapsedMs;
  const time =
    msRaw != null && msRaw !== '' && !Number.isNaN(Number(msRaw)) ? `${Number(msRaw)}ms` : '—';

  const bodyRaw = e.body ?? e.snippet ?? e.bodySnippet ?? e.message ?? '';
  const body =
    typeof bodyRaw === 'string'
      ? bodyRaw
      : bodyRaw != null
        ? JSON.stringify(bodyRaw)
        : Array.isArray(e.sampleHeaders)
          ? `Headers: ${e.sampleHeaders.slice(0, 12).join(', ')}`
          : '';

  let lenRaw = e.len ?? e.length ?? e.bodyLength ?? e.contentLength;
  if ((lenRaw == null || lenRaw === '') && body) lenRaw = body.length;
  const length = lenRaw != null && lenRaw !== '' && !Number.isNaN(Number(lenRaw)) ? String(Number(lenRaw)) : '—';

  return {
    technique: String(technique),
    payload: String(payload),
    status: String(status),
    time,
    length,
    body: String(body).slice(0, 160) || '—',
  };
}

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** CVSS may be a number or { score, vector, severity }. */
function formatCvss(cvss) {
  if (cvss == null || cvss === '') return 'N/A';
  if (typeof cvss === 'number' && Number.isFinite(cvss)) return String(cvss);
  if (typeof cvss === 'object') {
    const score = cvss.score != null ? Number(cvss.score) : NaN;
    const severity = cvss.severity ? String(cvss.severity) : '';
    const vector = cvss.vector ? String(cvss.vector) : '';
    if (Number.isFinite(score) && vector) return `${score.toFixed(1)} (${severity || '—'}) · ${vector}`;
    if (Number.isFinite(score)) return `${score.toFixed(1)}${severity ? ` (${severity})` : ''}`;
    if (vector) return vector;
  }
  const asNum = Number(cvss);
  if (Number.isFinite(asNum)) return String(asNum);
  const s = String(cvss);
  return s === '[object Object]' ? 'N/A' : s;
}

function formatRemediationSteps(f) {
  const steps = f.knowledge?.verificationSteps;
  if (Array.isArray(steps) && steps.length) {
    return `<ol class="doc-list-ol">${steps.map((s) => `<li>${esc(s)}</li>`).join('')}</ol>`;
  }
  const param = f.parameter && f.parameter !== 'n/a' ? f.parameter : 'the affected input';
  return `<ol class="doc-list-ol">
    <li>Locate where <code>${esc(param)}</code> is processed on the server.</li>
    <li>Apply the developer recommendation above (typed binds / allow-lists / secure flags as applicable).</li>
    <li>Return generic client errors; keep detail in server logs only.</li>
    <li>Retest the same probe to confirm closure.</li>
  </ol>`;
}

function formatReferences(f) {
  const refs = Array.isArray(f.references) ? f.references.filter(Boolean) : [];
  const cwes = f.cwe || f.mappings?.cwe || [];
  if (refs.length) {
    return `<ul class="doc-list-ul">${refs
      .slice(0, 6)
      .map((r) => {
        const text = String(r);
        if (/^https?:\/\//i.test(text)) {
          return `<li><a href="${esc(text)}" target="_blank" class="doc-link">${esc(text)}</a></li>`;
        }
        return `<li>${esc(text)}</li>`;
      })
      .join('')}${cwes.length ? `<li>CWE: ${esc(cwes.join(', '))}</li>` : ''}</ul>`;
  }
  return `<p class="doc-p">${cwes.length ? `CWE: ${esc(cwes.join(', '))}` : 'See OWASP ASVS / WSTG for the mapped control family.'}</p>`;
}

function formatExpectedBehavior(f) {
  const tech = f.knowledge?.technicalExplanation;
  if (tech) {
    return `Secure behavior: avoid the weakness described — ${esc(tech)} Validate inputs at the trust boundary and fail closed.`;
  }
  return 'Validate and authorize every untrusted input at the trust boundary; return generic errors to clients.';
}

function formatCoverageSection(meta) {
  const rows = Array.isArray(meta.typeCoverage) ? meta.typeCoverage : [];
  if (!rows.length) return '';
  const implemented = rows.filter((r) => (r.plugins && r.plugins.length) || r.surfaceCheck);
  const unavailable = rows.filter((r) => !((r.plugins && r.plugins.length) || r.surfaceCheck));
  const body = rows
    .slice(0, 60)
    .map((r) => {
      const depth =
        r.plugins?.length ? `Plugin: ${(r.plugins || []).join(', ')}` : r.surfaceCheck ? 'Surface check' : 'No scanner yet';
      const label = r.plugins?.length || r.surfaceCheck ? 'Available' : 'Unavailable';
      return `<tr>
        <td class="mono">${esc(r.typeId)}</td>
        <td><span class="pill ${label === 'Available' ? 'ok' : ''}">${esc(label)}</span></td>
        <td style="color:var(--text-secondary)">${esc(depth)}</td>
        <td><span class="pill">${esc(r.status || '—')}</span></td>
        <td class="mono" style="font-weight:700">${esc(r.findingCount ?? 0)}</td>
      </tr>`;
    })
    .join('');
  return `
<section class="doc-subcard" id="coverage-honesty" style="margin-top:16px;">
  <h3 class="doc-h3">Coverage Honesty &amp; Depth</h3>
  <p class="doc-hint" style="margin-bottom:12px">
    Selected types with a deep plugin or surface check: <strong>${implemented.length}</strong>.
    Selected without a scanner (tracked only): <strong>${unavailable.length}</strong>.
    “Select all” in the UI does not mean every OWASP category was deeply probed.
  </p>
  <div class="table-wrap">
    <table class="doc-table">
      <thead><tr><th>Type</th><th>Scanner</th><th>Depth</th><th>Status</th><th>Issues</th></tr></thead>
      <tbody>${body}</tbody>
    </table>
  </div>
</section>`;
}

function sevClass(sev) {
  const s = String(sev || '').toLowerCase();
  if (s === 'critical') return 'critical';
  if (s === 'high') return 'high';
  if (s === 'medium') return 'medium';
  if (s === 'low') return 'low';
  return 'info';
}

const SEV_COLORS = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#84cc16',
  Informational: '#38bdf8',
};

const SEV_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Informational'];

function polarToCartesian(cx, cy, r, angleDeg) {
  const rad = ((angleDeg - 90) * Math.PI) / 180;
  return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
}

function describeArc(cx, cy, r, startAngle, endAngle) {
  const start = polarToCartesian(cx, cy, r, endAngle);
  const end = polarToCartesian(cx, cy, r, startAngle);
  const largeArc = endAngle - startAngle > 180 ? 1 : 0;
  return `M ${cx} ${cy} L ${start.x} ${start.y} A ${r} ${r} 0 ${largeArc} 0 ${end.x} ${end.y} Z`;
}

function buildSeverityPieSvg(counts) {
  const slices = SEV_ORDER.map((name) => ({
    name,
    count: Number(counts[name] || 0),
    color: SEV_COLORS[name],
  })).filter((s) => s.count > 0);

  const pieTotal = SEV_ORDER.reduce((sum, name) => sum + Number(counts[name] || 0), 0);
  const legend = SEV_ORDER.map(
    (name) =>
      `<span class="legend-item"><i style="background:${SEV_COLORS[name]}"></i>${esc(name)} (${Number(counts[name] || 0)})</span>`
  ).join('');

  if (pieTotal === 0 || slices.length === 0) {
    return `<div class="chart-empty">No confirmed findings to chart by severity.</div>
      <div class="legend">${legend}</div>`;
  }

  const cx = 90;
  const cy = 90;
  const r = 78;
  let angle = 0;
  let paths = '';

  if (slices.length === 1) {
    paths = `<circle cx="${cx}" cy="${cy}" r="${r}" fill="${slices[0].color}" />`;
  } else {
    for (const slice of slices) {
      const sweep = (slice.count / pieTotal) * 360;
      const end = angle + sweep;
      paths += `<path d="${describeArc(cx, cy, r, angle, end)}" fill="${slice.color}" stroke="var(--bg-surface)" stroke-width="2"/>`;
      angle = end;
    }
  }

  return `<svg viewBox="0 0 180 180" width="180" height="180" role="img" aria-label="Findings by severity pie chart">
      ${paths}
      <circle cx="${cx}" cy="${cy}" r="38" fill="var(--bg-surface)" stroke="var(--border-subtle)" stroke-width="2"/>
      <text x="${cx}" y="${cy - 2}" text-anchor="middle" font-size="20" font-weight="700" fill="var(--text-primary)" font-family="'JetBrains Mono', Consolas, monospace">${pieTotal}</text>
      <text x="${cx}" y="${cy + 15}" text-anchor="middle" font-size="9" font-weight="600" fill="var(--text-muted)" text-transform="uppercase" letter-spacing="1">Total</text>
    </svg>
    <div class="legend">${legend}</div>`;
}

function buildModuleBarSvg(assessmentSummary) {
  if (!assessmentSummary.length) {
    return `<div class="chart-empty">No module data available.</div>`;
  }

  const max = Math.max(1, ...assessmentSummary.map((m) => Number(m.findings) || 0));
  const rowH = 28;
  const labelW = 140;
  const chartW = 320;
  const padL = labelW + 8;
  const height = Math.max(80, assessmentSummary.length * rowH + 16);

  const rows = assessmentSummary
    .map((m, i) => {
      const n = Number(m.findings) || 0;
      const barW = Math.max(n > 0 ? 6 : 0, Math.round((n / max) * chartW));
      const y = 12 + i * rowH;
      return `<text x="0" y="${y + 12}" font-size="10.5" fill="var(--text-secondary)" font-family="'JetBrains Mono', Consolas, monospace">${esc(m.module)}</text>
        <rect x="${padL}" y="${y}" width="${barW}" height="16" rx="3" fill="#3b82f6"/>
        <text x="${padL + barW + 8}" y="${y + 12}" font-size="11" font-weight="700" fill="var(--text-primary)" font-family="'JetBrains Mono', Consolas, monospace">${n}</text>`;
    })
    .join('');

  return `<svg viewBox="0 0 ${padL + chartW + 40} ${height}" width="100%" height="${height}" role="img" aria-label="Findings by module">
    ${rows}
  </svg>`;
}

function buildStatusBarSvg(confirmedCount, passCount) {
  const items = [
    { label: 'Confirmed', count: confirmedCount, color: '#f97316' },
    { label: 'Pass', count: passCount, color: '#22c55e' },
  ];
  const max = Math.max(1, ...items.map((i) => i.count));
  const chartH = 120;
  const barMax = 100;
  const width = 220;
  const gap = 60;
  const barW = 44;
  const baseY = 130;

  const bars = items
    .map((item, i) => {
      const h = item.count === 0 ? 0 : Math.max(6, Math.round((item.count / max) * barMax));
      const x = 40 + i * gap;
      const y = baseY - h;
      return `<rect x="${x}" y="${y}" width="${barW}" height="${h}" rx="4" fill="${item.color}"/>
        <text x="${x + barW / 2}" y="${y - 8}" text-anchor="middle" font-size="12" font-weight="700" fill="var(--text-primary)" font-family="'JetBrains Mono', Consolas, monospace">${item.count}</text>
        <text x="${x + barW / 2}" y="${baseY + 16}" text-anchor="middle" font-size="10" font-weight="600" fill="var(--text-secondary)" font-family="'JetBrains Mono', Consolas, monospace">${esc(item.label)}</text>`;
    })
    .join('');

  return `<svg viewBox="0 0 ${width} ${chartH + 40}" width="${width}" height="${chartH + 40}" role="img" aria-label="Findings by status">
    <line x1="20" y1="${baseY}" x2="${width - 10}" y2="${baseY}" stroke="var(--border-subtle)" stroke-width="1"/>
    ${bars}
  </svg>`;
}

function severityKpiRow(counts) {
  return `<div class="sev-kpi-row">
    ${SEV_ORDER.map(
      (name) =>
        `<div class="sev-kpi">
          <span class="sev ${sevClass(name)}">${esc(name)}</span>
          <div class="sev-kpi-n" style="color:${SEV_COLORS[name]}">${Number(counts[name] || 0)}</div>
        </div>`
    ).join('')}
  </div>`;
}

function buildHtmlReport(data = {}) {
  const meta = {
    projectName: 'Web Security Assessment',
    targetUrl: '',
    environment: 'Unknown',
    testerName: 'Security Assessment Tool',
    startedAt: new Date().toISOString(),
    durationMinutes: 1,
    ...(data.meta || {}),
  };
  const findings = Array.isArray(data.findings) ? data.findings : [];
  const assessmentSummary = Array.isArray(data.assessmentSummary) ? data.assessmentSummary : [];
  const recon = {
    pageTitle: 'N/A',
    forms: 0,
    linksVisited: 0,
    apisObserved: 0,
    querySurfaces: 0,
    ...(data.recon || {}),
  };
  const stats = {
    totalFindings: 0,
    confirmedSqli: 0,
    endpointsTested: 0,
    parametersTested: 0,
    modulesTested: 0,
    securityScore: 100,
    overallRisk: 'Informational',
    authGap: false,
    severityCounts: { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 },
    ...(data.stats || {}),
  };
  stats.severityCounts = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Informational: 0,
    ...(stats.severityCounts || {}),
  };

  const confirmed = findings.filter((f) => f.issueFound);
  const passes = findings.filter((f) => !f.issueFound);
  const sqliNone =
    stats.confirmedSqli === 0
      ? 'No confirmed SQL Injection vulnerabilities were identified during this authorized assessment.'
      : `${stats.confirmedSqli} confirmed SQL Injection finding(s) were identified.`;

  const pie = stats.severityCounts;

  const statusConfirmed = confirmed.length;
  const statusPass = passes.length;
  const hasConfirmedFindings = confirmed.length > 0;

  const authGapCallout = stats.authGap
    ? `<div class="callout-warn"><strong>Authentication Notice:</strong> Authenticated testing incomplete: protected API endpoints returned 401/403. Provide valid credentials on next scan to obtain session tokens and validate High-severity injection issues.</div>`
    : '';
  const loginNote =
    meta.loginAttempted && meta.authStatus === 'not-ready'
      ? `<div class="callout-warn">Login appeared to succeed but session was <strong>not ready</strong> (no token/cookie proof): ${esc(meta.loginMessage || meta.authWarning || 'session gate failed')}. Authenticated coverage is limited.</div>`
      : meta.loginAttempted && !meta.loginSuccess
        ? `<div class="callout-warn">Login attempted but failed: ${esc(meta.loginMessage || 'unknown error')}. Authenticated checks may be incomplete.</div>`
        : meta.loginSuccess && meta.authUsed
          ? `<div class="callout-ok">Authenticated session ready${meta.authAdapter ? ` via <strong>${esc(meta.authAdapter)}</strong>` : ''}${Array.isArray(meta.sessionProof) && meta.sessionProof.length ? ` (proof: ${esc(meta.sessionProof.join(', '))})` : ''}.</div>`
          : '';
  const profileNote = meta.scanProfile
    ? `<div class="callout-info">Scan profile: <strong>${esc(meta.scanProfile)}</strong>. Score reflects grey-box testing depth for this run.</div>`
    : '';
  const typesList =
    Array.isArray(meta.securityTypes) && meta.securityTypes.length
      ? meta.securityTypes.join(', ')
      : 'Recommended defaults';
  const coverageSection = formatCoverageSection(meta);

  const findingRows = findings
    .map((f) => {
      const sev = getSeverity(f) || 'Informational';
      const endpoint = f.endpoint || f.affectedEndpoint || f.fullUrl || f.affectedUrl || '';
      return `<tr>
      <td><a href="#${esc(f.id)}" class="code-id">${esc(f.id)}</a></td>
      <td style="font-weight:600">${esc(f.module)}</td>
      <td class="mono">${esc(endpoint)}</td>
      <td class="mono" style="color:var(--accent-blue)">${esc(f.parameter || '—')}</td>
      <td style="color:var(--text-secondary)">${esc((f.techniques || []).join(', ') || '—')}</td>
      <td><span class="pill ${f.issueFound ? 'high' : 'ok'}">${f.issueFound ? 'YES' : 'NO'}</span></td>
      <td><span class="sev ${sevClass(sev)}">${esc(sev)}</span></td>
      <td><span class="status ${f.issueFound ? 'confirmed' : 'pass'}">${esc(f.status)}</span></td>
    </tr>`;
    })
    .join('');

  const summaryRows = assessmentSummary
    .map((m) => {
      const highest = m.highestSeverity;
      const badgeClass = highest === 'None' || !highest ? 'info' : sevClass(highest);
      return `<tr>
      <td><strong style="color:var(--text-primary)">${esc(m.module)}</strong></td>
      <td class="mono">${m.urlsTested}</td>
      <td class="mono">${m.parametersTested}</td>
      <td class="mono" style="font-weight:700">${m.findings}</td>
      <td><span class="sev ${badgeClass}">${esc(highest || 'None')}</span></td>
    </tr>`;
    })
    .join('');

  const detailed = confirmed.length
    ? confirmed
        .map((f) => {
          const sev = getSeverity(f) || 'Informational';
          const ev = (f.evidence || [])
            .slice(0, 5)
            .map((raw) => {
              const e = formatEvidenceRow(raw);
              return `<tr>
                <td style="font-weight:600">${esc(e.technique)}</td>
                <td class="mono" style="color:var(--accent-blue)">${esc(e.payload)}</td>
                <td><span class="pill ${e.status === '200' || e.status === 'OK' ? 'ok' : ''}">${esc(e.status)}</span></td>
                <td class="mono">${esc(e.time)}</td>
                <td class="mono">${esc(e.length)}</td>
                <td class="mono" style="color:var(--text-secondary)">${esc(e.body)}</td>
              </tr>`;
            })
            .join('');
          const affected =
            Array.isArray(f.affectedEndpoints) && f.affectedEndpoints.length
              ? `<tr><td>Affected Endpoints</td><td class="mono">${f.affectedEndpoints
                  .map((u) => esc(u))
                  .join('<br/>')}</td></tr>`
              : '';
          return `
      <article class="doc-finding-card ${sevClass(sev)}" id="${esc(f.id)}">
        <header class="doc-finding-header">
          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
            <span class="code-id">${esc(f.id)}</span>
            <h3 class="doc-finding-title">${esc(f.title)}</h3>
          </div>
          <span class="sev ${sevClass(sev)}">${esc(sev)}</span>
        </header>

        <div class="doc-finding-body">
          <div class="table-wrap">
            <table class="doc-meta-table">
              <tr><td>Finding ID</td><td class="mono">${esc(f.id)}</td></tr>
              <tr><td>Module</td><td><strong>${esc(f.module)}</strong></td></tr>
              <tr><td>Full URL</td><td class="mono" style="color:var(--accent-blue)">${esc(f.fullUrl || f.affectedUrl || f.endpoint)}</td></tr>
              ${affected}
              <tr><td>HTTP Method</td><td class="mono">${esc(f.method || 'GET')}</td></tr>
              <tr><td>Parameter</td><td class="mono">${esc(f.parameter || 'n/a')}</td></tr>
              <tr><td>Authentication Required</td><td>${f.authRequired ? 'Yes' : 'No'}</td></tr>
              <tr><td>Assessment Status</td><td><span class="pill high">${esc(f.status)}</span></td></tr>
              <tr><td>Technique Evaluated</td><td style="color:var(--text-secondary)">${esc((f.techniques || []).join('; '))}</td></tr>
              <tr><td>Severity</td><td><span class="sev ${sevClass(sev)}">${esc(sev)}</span></td></tr>
              <tr><td>Confidence</td><td><span class="pill">${esc(f.confidence || 'Confirmed')}</span></td></tr>
              <tr><td>CWE Mapping</td><td class="mono">${esc((f.cwe || []).join(', ') || 'N/A')}</td></tr>
              <tr><td>OWASP Category</td><td>${esc(f.owasp || 'N/A')}</td></tr>
              <tr><td>CVSS Score</td><td class="mono" style="font-weight:700">${esc(formatCvss(f.cvss))}</td></tr>
            </table>
          </div>

          <h4 class="doc-section-h4">Business Impact</h4>
          <div class="doc-impact-box">${esc(
            f.issueFound
              ? f.impact ||
                  f.knowledge?.businessImpact ||
                  resolveBusinessImpact(f)
              : 'N/A — no issue confirmed for this check.',
          )}</div>

          <h4 class="doc-section-h4">Description &amp; Observed Vulnerability</h4>
          <p class="doc-p">${esc(f.description)}</p>

          <h4 class="doc-section-h4">Expected Secure Behavior</h4>
          <p class="doc-p" style="color:var(--accent-green)">${formatExpectedBehavior(f)}</p>

          <h4 class="doc-section-h4">Evidence &amp; Probe Trace</h4>
          <div class="table-wrap">
            <table class="doc-table">
              <thead><tr><th>Technique</th><th>Payload</th><th>Status</th><th>Time</th><th>Length</th><th>Body (truncated)</th></tr></thead>
              <tbody>${ev || '<tr><td colspan="6" style="color:var(--text-muted)">No probe rows captured</td></tr>'}</tbody>
            </table>
          </div>

          <h4 class="doc-section-h4">Developer Recommendation</h4>
          <div class="doc-code-callout">${esc(
            f.remediation ||
              (Array.isArray(f.knowledge?.secureCodingExamples) && f.knowledge.secureCodingExamples[0]) ||
              'Follow OWASP guidance for this control family; prefer secure defaults and deny-by-default authorization.',
          )}</div>
          ${
            Array.isArray(f.knowledge?.secureCodingExamples) && f.knowledge.secureCodingExamples.length
              ? `<h4 class="doc-section-h4">Secure Coding Examples</h4>
                 <ul class="doc-list-ul">${f.knowledge.secureCodingExamples
                  .slice(0, 4)
                  .map((ex) => `<li><code>${esc(ex)}</code></li>`)
                  .join('')}</ul>`
              : ''
          }

          <h4 class="doc-section-h4">Remediation Steps</h4>
          ${formatRemediationSteps(f)}

          <h4 class="doc-section-h4">References &amp; Mappings</h4>
          ${formatReferences(f)}

          ${
            (() => {
              if (!['Critical', 'High', 'Medium', 'Low'].includes(sev)) return '';
              const shot = resolveScreenshotBase64(f);
              if (!shot) {
                return `<div class="doc-shot-missing">Screenshot not captured or not available for ${esc(f.id)} (${esc(sev)}).</div>`;
              }
              return `<div class="doc-shot-card">
                <h4 class="doc-section-h4" style="margin-top:0;">Issue Evidence Screenshot — ${esc(f.id)}</h4>
                <div class="doc-shot-meta">
                  <span class="sev ${sevClass(sev)}">${esc(sev)}</span>
                  <span class="pill">${esc(f.module || f.pluginId || 'Issue')}</span>
                  <strong style="color:var(--text-primary)">${esc(f.title)}</strong>
                  ${f.screenshotFileName ? `<span class="mono" style="color:var(--text-muted);font-size:10px">${esc(f.screenshotFileName)}</span>` : ''}
                </div>
                <figure class="doc-shot-figure">
                  <img src="data:image/png;base64,${shot}" alt="${esc(f.screenshotCaption || `${sev} ${f.title}`)}" />
                </figure>
              </div>`;
            })()
          }
        </div>
      </article>`;
        })
        .join('\n')
    : `<div class="callout-ok">${esc(sqliNone)}</div>`;

  const matrixPlace = { hl: [], hm: [], hh: [], ml: [], mm: [], mh: [], ll: [], lm: [], lh: [] };
  for (const f of confirmed) {
    const sev = getSeverity(f);
    let likelihood = 'm';
    let impact = 'm';
    if (sev === 'Critical') {
      likelihood = 'h';
      impact = 'h';
    } else if (sev === 'High') {
      likelihood = 'm';
      impact = 'h';
    } else if (sev === 'Medium') {
      likelihood = 'm';
      impact = 'm';
    } else {
      likelihood = 'm';
      impact = 'l';
    }
    matrixPlace[`${likelihood}${impact[0]}`].push(f.id);
  }
  const cell = (key, cls) =>
    `<td class="${cls}">${
      matrixPlace[key].length
        ? matrixPlace[key].map((id) => `<a href="#${esc(id)}" class="code-id" style="margin:2px">${esc(id)}</a>`).join(' ')
        : '<span style="color:var(--text-muted)">—</span>'
    }</td>`;

  const chartsBody = hasConfirmedFindings
    ? `<div class="doc-chart-grid">
        <div class="doc-chart-card">
          <h4 class="doc-chart-title">Findings by Severity</h4>
          <div class="pie-wrap">${buildSeverityPieSvg(pie)}</div>
        </div>
        <div class="doc-chart-card">
          <h4 class="doc-chart-title">Findings by Status</h4>
          <div class="chart-center">${buildStatusBarSvg(statusConfirmed, statusPass)}</div>
        </div>
        <div class="doc-chart-card" style="grid-column:1/-1">
          <h4 class="doc-chart-title">Findings by Security Module</h4>
          ${buildModuleBarSvg(assessmentSummary)}
        </div>
      </div>`
    : `<div class="doc-chart-card" style="padding:20px;text-align:center;">
        <div class="chart-empty" style="margin-bottom:14px">No confirmed vulnerability findings — severity charts are clean.</div>
        <div class="doc-chart-grid">
          <div class="doc-chart-card">
            <h4 class="doc-chart-title">Findings by Severity</h4>
            <div class="pie-wrap">${buildSeverityPieSvg(pie)}</div>
          </div>
          <div class="doc-chart-card">
            <h4 class="doc-chart-title">Findings by Status</h4>
            <div class="chart-center">${buildStatusBarSvg(statusConfirmed, statusPass)}</div>
          </div>
        </div>
      </div>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${esc(meta.projectName)} — Web Security Assessment Report</title>
<link rel="stylesheet" href="/index.css" />
<script>
  (function() {
    const saved = localStorage.getItem('secureassess.theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
  })();
</script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

  :root,
  [data-theme="dark"] {
    --bg-base: #08090b;
    --bg-surface: #0f1115;
    --bg-surface-elevated: #16181f;
    --bg-surface-active: #1c2028;
    --border-subtle: #1e2229;
    --border-medium: #2a303a;
    --border-focus: #3b82f6;
    --text-primary: #f1f5f9;
    --text-secondary: #94a3b8;
    --text-muted: #525e6f;
    --accent-blue: #38bdf8;
    --accent-green: #22c55e;
    --accent-amber: #eab308;
    --accent-red: #ef4444;
    --font-mono: 'JetBrains Mono', Consolas, Menlo, Monaco, monospace;
    --font-sans: 'Inter', -apple-system, sans-serif;
  }

  :root[data-theme="light"],
  html[data-theme="light"],
  body[data-theme="light"],
  [data-theme="light"] {
    --bg-base: #f1f5f9;
    --bg-surface: #ffffff;
    --bg-surface-elevated: #f8fafc;
    --bg-surface-active: #e2e8f0;
    --border-subtle: #e2e8f0;
    --border-medium: #cbd5e1;
    --border-focus: #2563eb;
    --text-primary: #0f172a;
    --text-secondary: #334155;
    --text-muted: #64748b;
    --accent-blue: #2563eb;
    --accent-green: #16a34a;
    --accent-amber: #d97706;
    --accent-red: #dc2626;
  }

  html[data-theme="light"] .doc-card,
  html[data-theme="light"] .doc-finding-card,
  html[data-theme="light"] .doc-chart-card,
  html[data-theme="light"] .doc-top-bar {
    box-shadow: 0 1px 3px rgba(15, 23, 42, 0.08), 0 1px 2px rgba(15, 23, 42, 0.04);
  }

  .theme-toggle-floating {
    position: fixed;
    bottom: 24px;
    right: 24px;
    z-index: 99999;
    background-color: var(--bg-surface);
    border: 1px solid var(--border-medium);
    color: var(--text-primary);
    width: 44px;
    height: 44px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    outline: none;
    backdrop-filter: blur(8px);
  }

  .theme-toggle-floating:hover {
    transform: translateY(-2px) scale(1.06);
    border-color: var(--accent-blue);
    box-shadow: 0 6px 20px rgba(56, 189, 248, 0.3);
  }

  .theme-toggle-floating svg {
    width: 20px;
    height: 20px;
  }

  html {
    scroll-behavior: smooth;
    background-color: var(--bg-base);
    color: var(--text-primary);
  }

  body {
    margin: 0;
    padding: 0;
    font-family: var(--font-sans);
    font-size: 13px;
    line-height: 1.6;
    background-color: var(--bg-base);
    color: var(--text-primary);
  }

  /* DOCUMENTATION TWO-COLUMN CONTAINER */
  .doc-layout {
    display: flex;
    min-height: 100vh;
  }

  /* STICKY LEFT DOCUMENTATION SIDEBAR */
  .doc-sidebar {
    width: 320px;
    flex-shrink: 0;
    height: 100vh;
    position: sticky;
    top: 0;
    background-color: var(--bg-surface);
    border-right: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    overflow-y: auto;
    z-index: 100;
  }

  .doc-sidebar-header {
    padding: 16px 16px 12px;
    border-bottom: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    gap: 10px;
    background-color: var(--bg-surface);
    position: sticky;
    top: 0;
    z-index: 10;
  }

  .doc-search-input {
    width: 100%;
    background-color: var(--bg-base);
    border: 1px solid var(--border-medium);
    border-radius: 6px;
    padding: 7px 10px;
    color: var(--text-primary);
    font-family: var(--font-mono);
    font-size: 11px;
    outline: none;
    box-sizing: border-box;
  }

  .doc-search-input:focus {
    border-color: var(--border-focus);
  }

  .doc-nav {
    padding: 12px 10px 30px;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  /* COLLAPSIBLE TOPICS IN SIDEBAR */
  details.doc-topic {
    border-radius: 6px;
    transition: background-color 0.15s;
  }

  details.doc-topic summary {
    list-style: none;
    padding: 8px 10px;
    font-family: var(--font-mono);
    font-size: 11.5px;
    font-weight: 600;
    color: var(--text-secondary);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-radius: 6px;
    user-select: none;
  }

  details.doc-topic summary::-webkit-details-marker {
    display: none;
  }

  details.doc-topic summary:hover {
    background-color: var(--bg-surface-elevated);
    color: var(--text-primary);
  }

  details.doc-topic[open] summary {
    color: var(--accent-blue);
  }

  .topic-left {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .topic-num {
    font-size: 10px;
    color: var(--text-muted);
    font-weight: 700;
  }

  .topic-chevron {
    font-size: 10px;
    color: var(--text-muted);
    transition: transform 0.2s ease;
  }

  details.doc-topic[open] .topic-chevron {
    transform: rotate(90deg);
    color: var(--accent-blue);
  }

  .doc-subnav {
    list-style: none;
    padding: 2px 0 6px 20px;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .doc-subnav li a {
    display: block;
    padding: 5px 10px;
    color: var(--text-muted);
    text-decoration: none;
    font-size: 11px;
    font-family: var(--font-sans);
    border-radius: 4px;
    border-left: 1px solid var(--border-subtle);
    transition: all 0.15s ease;
  }

  .doc-subnav li a:hover {
    color: var(--text-primary);
    background-color: var(--bg-surface-elevated);
    border-left-color: var(--accent-blue);
  }

  .doc-subnav li a.active {
    color: var(--accent-blue);
    background-color: var(--bg-surface-active);
    border-left-color: var(--accent-blue);
    font-weight: 600;
  }

  /* MAIN CONTENT AREA */
  .doc-main {
    flex: 1;
    min-width: 0;
    padding: 24px 36px 80px;
    max-width: 1280px;
  }

  /* TOP COMMAND HEADER */
  .doc-top-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background-color: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: 10px;
    padding: 12px 18px;
    gap: 16px;
    flex-wrap: wrap;
    margin-bottom: 24px;
  }

  .doc-target-meta {
    display: flex;
    align-items: center;
    gap: 10px;
    font-family: var(--font-mono);
    font-size: 12px;
  }

  .target-badge {
    color: var(--text-muted);
    font-weight: 700;
  }

  .target-url {
    color: var(--text-primary);
    font-weight: 600;
  }

  .target-env {
    color: var(--accent-blue);
    background-color: rgba(56, 189, 248, 0.12);
    border: 1px solid rgba(56, 189, 248, 0.25);
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
  }

  .doc-top-actions {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  /* DOCUMENT CARDS & SECTIONS */
  .doc-card {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: 10px;
    padding: 24px;
    margin-bottom: 24px;
  }

  .doc-card-header {
    border-bottom: 1px solid var(--border-subtle);
    padding-bottom: 12px;
    margin-bottom: 18px;
  }

  .doc-h2 {
    margin: 0;
    font-family: var(--font-mono);
    font-size: 15px;
    font-weight: 700;
    color: var(--text-primary);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .doc-h3 {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--text-secondary);
    text-transform: uppercase;
    margin: 18px 0 8px;
  }

  .doc-section-h4 {
    font-family: var(--font-mono);
    font-size: 11px;
    text-transform: uppercase;
    color: var(--text-secondary);
    margin: 16px 0 6px;
    letter-spacing: 0.05em;
  }

  .doc-p {
    font-size: 13px;
    line-height: 1.6;
    color: var(--text-primary);
    margin: 0 0 12px;
  }

  .doc-hint {
    font-size: 12px;
    color: var(--text-muted);
    margin: 0 0 10px;
  }

  /* TABLES */
  .table-wrap {
    overflow-x: auto;
    border: 1px solid var(--border-subtle);
    border-radius: 6px;
    background-color: var(--bg-base);
    margin-bottom: 14px;
  }

  .doc-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
    text-align: left;
  }

  .doc-table th {
    background-color: var(--bg-surface-elevated);
    color: var(--text-muted);
    font-family: var(--font-mono);
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    padding: 8px 12px;
    border-bottom: 1px solid var(--border-medium);
  }

  .doc-table td {
    padding: 9px 12px;
    border-bottom: 1px solid var(--border-subtle);
    color: var(--text-primary);
    vertical-align: top;
  }

  .doc-table tr:hover td {
    background-color: var(--bg-surface-elevated);
  }

  .doc-meta-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }

  .doc-meta-table td {
    padding: 8px 12px;
    border-bottom: 1px solid var(--border-subtle);
    color: var(--text-primary);
  }

  .doc-meta-table td:first-child {
    width: 25%;
    font-family: var(--font-mono);
    font-size: 11px;
    font-weight: 600;
    color: var(--text-secondary);
    background-color: var(--bg-surface-elevated);
    border-right: 1px solid var(--border-subtle);
  }

  .mono {
    font-family: var(--font-mono);
    font-size: 11px;
    word-break: break-all;
  }

  /* CALLOUTS */
  .callout-ok {
    background-color: rgba(34, 197, 94, 0.1);
    border: 1px solid rgba(34, 197, 94, 0.25);
    color: var(--accent-green);
    padding: 12px 14px;
    border-radius: 6px;
    font-size: 12px;
    margin-bottom: 14px;
  }

  .callout-warn {
    background-color: rgba(234, 179, 8, 0.1);
    border: 1px solid rgba(234, 179, 8, 0.3);
    color: var(--accent-amber);
    padding: 12px 14px;
    border-radius: 6px;
    font-size: 12px;
    margin-bottom: 14px;
  }

  .callout-info {
    background-color: rgba(56, 189, 248, 0.1);
    border: 1px solid rgba(56, 189, 248, 0.25);
    color: var(--accent-blue);
    padding: 12px 14px;
    border-radius: 6px;
    font-size: 12px;
    margin-bottom: 14px;
  }

  /* KPIS & SCORES */
  .kpi-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 10px;
    margin: 16px 0;
  }

  .kpi-tile {
    background-color: var(--bg-base);
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
    padding: 12px;
    text-align: center;
  }

  .kpi-tile .n {
    font-family: var(--font-mono);
    font-size: 22px;
    font-weight: 700;
    color: var(--text-primary);
  }

  .kpi-tile .l {
    font-family: var(--font-mono);
    font-size: 9px;
    text-transform: uppercase;
    color: var(--text-muted);
    letter-spacing: 0.05em;
    margin-top: 4px;
  }

  .score-hud-box {
    display: flex;
    align-items: center;
    gap: 20px;
    background-color: var(--bg-base);
    border: 1px solid var(--border-medium);
    border-radius: 8px;
    padding: 16px 20px;
    margin-top: 14px;
  }

  .score-circle {
    width: 72px;
    height: 72px;
    border-radius: 50%;
    border: 5px solid var(--border-focus);
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    background-color: var(--bg-surface);
  }

  .score-circle .big {
    font-family: var(--font-mono);
    font-size: 20px;
    font-weight: 700;
    color: var(--text-primary);
    line-height: 1;
  }

  .score-circle .sub {
    font-family: var(--font-mono);
    font-size: 8px;
    color: var(--text-muted);
  }

  /* CHARTS */
  .doc-chart-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 14px;
    margin: 14px 0;
  }

  .doc-chart-card {
    background-color: var(--bg-base);
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
    padding: 16px;
  }

  .doc-chart-title {
    margin: 0 0 12px;
    font-family: var(--font-mono);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-secondary);
  }

  .pie-wrap, .chart-center {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 180px;
  }

  .legend {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-top: 12px;
    justify-content: center;
  }

  .legend-item {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-family: var(--font-mono);
    font-size: 10px;
    color: var(--text-secondary);
  }

  .legend-item i {
    width: 8px;
    height: 8px;
    border-radius: 2px;
  }

  /* RISK MATRIX */
  .matrix {
    width: 100%;
    border-collapse: collapse;
    table-layout: fixed;
    background-color: var(--bg-base);
  }

  .matrix th, .matrix td {
    border: 1px solid var(--border-subtle);
    text-align: center;
    padding: 12px 8px;
    height: 56px;
  }

  .matrix th {
    background-color: var(--bg-surface-elevated);
    color: var(--text-muted);
    font-family: var(--font-mono);
    font-size: 11px;
  }

  .matrix .axis {
    background-color: var(--bg-surface);
    color: var(--text-secondary);
    font-weight: 700;
  }

  .cell-ll { background-color: rgba(34, 197, 94, 0.05); }
  .cell-lm, .cell-ml { background-color: rgba(234, 179, 8, 0.06); }
  .cell-lh, .cell-mm, .cell-hl { background-color: rgba(249, 115, 22, 0.08); }
  .cell-mh, .cell-hm, .cell-hh { background-color: rgba(239, 68, 68, 0.12); }

  /* DETAILED FINDINGS CARD */
  .doc-finding-card {
    background-color: var(--bg-surface);
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
    margin-bottom: 20px;
    overflow: hidden;
  }

  .doc-finding-card.critical { border-left: 4px solid var(--accent-red); }
  .doc-finding-card.high { border-left: 4px solid var(--accent-amber); }
  .doc-finding-card.medium { border-left: 4px solid var(--accent-amber); }
  .doc-finding-card.low { border-left: 4px solid var(--accent-green); }
  .doc-finding-card.info { border-left: 4px solid var(--accent-blue); }

  .doc-finding-header {
    background-color: var(--bg-surface-elevated);
    padding: 12px 16px;
    border-bottom: 1px solid var(--border-subtle);
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
  }

  .doc-finding-title {
    margin: 0;
    font-size: 13px;
    font-weight: 700;
    color: var(--text-primary);
  }

  .doc-finding-body {
    padding: 16px;
  }

  .doc-impact-box {
    background-color: var(--bg-base);
    border: 1px solid var(--border-medium);
    border-radius: 6px;
    padding: 12px;
    font-size: 12px;
    color: var(--text-primary);
    line-height: 1.5;
  }

  .doc-code-callout {
    background-color: var(--bg-base);
    border: 1px solid var(--border-medium);
    border-radius: 6px;
    padding: 12px;
    font-family: var(--font-mono);
    font-size: 11.5px;
    color: var(--accent-blue);
    line-height: 1.5;
  }

  .doc-list-ol, .doc-list-ul {
    padding-left: 20px;
    margin: 8px 0;
    font-size: 12px;
    color: var(--text-secondary);
  }

  .doc-list-ol li, .doc-list-ul li {
    margin-bottom: 4px;
  }

  .doc-list-ol li code, .doc-list-ul li code {
    font-family: var(--font-mono);
    color: var(--accent-blue);
    background-color: var(--bg-base);
    padding: 2px 6px;
    border-radius: 4px;
  }

  .doc-link {
    color: var(--accent-blue);
    text-decoration: none;
  }

  .doc-link:hover {
    text-decoration: underline;
  }

  /* SCREENSHOT CARD */
  .doc-shot-card {
    margin-top: 16px;
    background-color: var(--bg-base);
    border: 1px solid var(--border-medium);
    border-radius: 8px;
    padding: 14px;
  }

  .doc-shot-meta {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    margin-bottom: 10px;
  }

  .doc-shot-figure {
    margin: 0;
    border: 1px solid var(--border-subtle);
    border-radius: 6px;
    overflow: hidden;
    background-color: #000;
  }

  .doc-shot-figure img {
    display: block;
    width: 100%;
    height: auto;
  }

  .doc-shot-missing {
    margin-top: 14px;
    background-color: var(--bg-base);
    border: 1px dashed var(--border-medium);
    border-radius: 6px;
    padding: 10px 14px;
    font-size: 11px;
    color: var(--text-muted);
  }

  /* BADGES & PILLS */
  .badge-sev {
    display: inline-block;
    padding: 1px 5px;
    border-radius: 3px;
    font-family: var(--font-mono);
    font-size: 9px;
    font-weight: 700;
    color: #fff;
    text-transform: uppercase;
  }
  .badge-sev.critical { background: var(--accent-red); }
  .badge-sev.high { background: var(--accent-amber); }
  .badge-sev.medium { background: var(--accent-amber); color:#000; }
  .badge-sev.low { background: var(--accent-green); color:#000; }
  .badge-sev.info { background: var(--accent-blue); }

  .badge-count {
    background-color: var(--bg-surface-elevated);
    border: 1px solid var(--border-medium);
    border-radius: 10px;
    padding: 1px 6px;
    font-size: 10px;
    color: var(--text-secondary);
  }

  .checklist {
    list-style: none;
    padding-left: 0;
  }

  .checklist li {
    padding: 6px 0;
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
  }

  .checklist li::before {
    content: "✓";
    font-family: var(--font-mono);
    font-size: 12px;
    font-weight: 700;
    color: var(--accent-green);
    background-color: rgba(34, 197, 94, 0.12);
    border: 1px solid rgba(34, 197, 94, 0.25);
    width: 18px;
    height: 18px;
    border-radius: 4px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }

  @media print {
    .doc-sidebar, .doc-top-bar { display: none !important; }
    .doc-main { max-width: 100% !important; padding: 0 !important; }
    body, html { background: #fff !important; color: #000 !important; }
    .doc-card, .doc-finding-card { border-color: #ddd !important; background: #fff !important; color: #000 !important; }
  }

  @media (max-width: 900px) {
    .doc-layout { flex-direction: column; }
    .doc-sidebar { width: 100%; height: auto; position: static; }
    .doc-main { padding: 16px; }
  }
</style>
</head>
<body>

<div class="doc-layout">
  <!-- =================================================================
       LEFT DOCUMENTATION SIDEBAR (Collapsible Topics & Subheadings)
       ================================================================= -->
  <aside class="doc-sidebar">
    <div class="doc-sidebar-header">
      <div class="brand-section">
        <span class="brand-title">SecureAssess</span>
        <span class="brand-sep">//</span>
        <span class="brand-sub">Report Docs</span>
      </div>
      <input type="text" id="docSearch" class="doc-search-input" placeholder="Search headings / findings..." />
    </div>

    <nav class="doc-nav" id="docNav">
      <!-- 01 Executive Summary -->
      <details open class="doc-topic">
        <summary>
          <div class="topic-left">
            <span class="topic-num">01</span>
            <span>Executive Summary</span>
          </div>
          <span class="topic-chevron">&#9656;</span>
        </summary>
        <ul class="doc-subnav">
          <li><a href="#executive-summary">Overview &amp; Findings</a></li>
          <li><a href="#metadata-breakdown">Assessment Parameters</a></li>
          <li><a href="#score-rationale">Security Score &amp; Rationale</a></li>
        </ul>
      </details>

      <!-- 02 Assessment Scope -->
      <details open class="doc-topic">
        <summary>
          <div class="topic-left">
            <span class="topic-num">02</span>
            <span>Assessment Scope</span>
          </div>
          <span class="topic-chevron">&#9656;</span>
        </summary>
        <ul class="doc-subnav">
          <li><a href="#scope">Target &amp; Surface Recon</a></li>
          <li><a href="#safety-controls">Safety &amp; Controls</a></li>
          <li><a href="#coverage-honesty">Coverage Honesty</a></li>
        </ul>
      </details>

      <!-- 03 Methodology -->
      <details class="doc-topic">
        <summary>
          <div class="topic-left">
            <span class="topic-num">03</span>
            <span>Methodology</span>
          </div>
          <span class="topic-chevron">&#9656;</span>
        </summary>
        <ul class="doc-subnav">
          <li><a href="#methodology">5-Stage DAST Pipeline</a></li>
          <li><a href="#methodology">Playwright Automation</a></li>
        </ul>
      </details>

      <!-- 04 Overall Results -->
      <details class="doc-topic">
        <summary>
          <div class="topic-left">
            <span class="topic-num">04</span>
            <span>Overall Results</span>
          </div>
          <span class="topic-chevron">&#9656;</span>
        </summary>
        <ul class="doc-subnav">
          <li><a href="#overall">Severity Counts</a></li>
        </ul>
      </details>

      <!-- 05 Summary Table -->
      <details class="doc-topic">
        <summary>
          <div class="topic-left">
            <span class="topic-num">05</span>
            <span>Summary Table</span>
          </div>
          <span class="topic-chevron">&#9656;</span>
        </summary>
        <ul class="doc-subnav">
          <li><a href="#summary-table">Tested Modules Matrix</a></li>
        </ul>
      </details>

      <!-- 06 Finding Table -->
      <details class="doc-topic">
        <summary>
          <div class="topic-left">
            <span class="topic-num">06</span>
            <span>Finding Table</span>
          </div>
          <span class="topic-chevron">&#9656;</span>
        </summary>
        <ul class="doc-subnav">
          <li><a href="#finding-table">All Evaluated Checks (${findings.length})</a></li>
        </ul>
      </details>

      <!-- 07 Charts -->
      <details class="doc-topic">
        <summary>
          <div class="topic-left">
            <span class="topic-num">07</span>
            <span>Charts &amp; Visuals</span>
          </div>
          <span class="topic-chevron">&#9656;</span>
        </summary>
        <ul class="doc-subnav">
          <li><a href="#charts">Severity Breakdown</a></li>
          <li><a href="#charts">Status Distribution</a></li>
          <li><a href="#charts">Module Coverage</a></li>
        </ul>
      </details>

      <!-- 08 Risk Matrix -->
      <details class="doc-topic">
        <summary>
          <div class="topic-left">
            <span class="topic-num">08</span>
            <span>Risk Matrix</span>
          </div>
          <span class="topic-chevron">&#9656;</span>
        </summary>
        <ul class="doc-subnav">
          <li><a href="#risk-matrix">Likelihood &times; Impact Grid</a></li>
        </ul>
      </details>

      <!-- 09 Detailed Findings (Collapsible list of findings!) -->
      <details open class="doc-topic">
        <summary>
          <div class="topic-left">
            <span class="topic-num">09</span>
            <span>Detailed Findings</span>
          </div>
          <div style="display:flex;align-items:center;gap:6px">
            <span class="badge-count">${confirmed.length}</span>
            <span class="topic-chevron">&#9656;</span>
          </div>
        </summary>
        <ul class="doc-subnav">
          ${
            confirmed.length
              ? confirmed
                  .map((f) => {
                    const sev = getSeverity(f) || 'Informational';
                    return `<li><a href="#${esc(f.id)}"><span class="badge-sev ${sevClass(sev)}">${esc(sev.slice(0, 1))}</span> ${esc(f.id)}</a></li>`;
                  })
                  .join('')
              : `<li><a href="#detailed" style="color:var(--accent-green)">None confirmed</a></li>`
          }
        </ul>
      </details>

      <!-- 10 Recommendations -->
      <details class="doc-topic">
        <summary>
          <div class="topic-left">
            <span class="topic-num">10</span>
            <span>Recommendations</span>
          </div>
          <span class="topic-chevron">&#9656;</span>
        </summary>
        <ul class="doc-subnav">
          <li><a href="#rec-immediate">Immediate Actions</a></li>
          <li><a href="#rec-high">High Priority Fixes</a></li>
          <li><a href="#rec-practices">Secure Coding Practices</a></li>
          <li><a href="#rec-checklist">Developer Checklist</a></li>
        </ul>
      </details>

      <!-- 11 Appendix -->
      <details class="doc-topic">
        <summary>
          <div class="topic-left">
            <span class="topic-num">11</span>
            <span>Appendix</span>
          </div>
          <span class="topic-chevron">&#9656;</span>
        </summary>
        <ul class="doc-subnav">
          <li><a href="#app-owasp">OWASP Standards</a></li>
          <li><a href="#app-cwe">CWE References</a></li>
          <li><a href="#app-glossary">Glossary &amp; Terms</a></li>
        </ul>
      </details>
    </nav>
  </aside>

  <!-- =================================================================
       MAIN DOCUMENT CONTENT AREA
       ================================================================= -->
  <main class="doc-main">
    <!-- Top Command & Control Header -->
    <header class="doc-top-bar">
      <div class="doc-target-meta">
        <span class="target-badge">TARGET &gt;</span>
        <span class="target-url">${esc(meta.targetUrl || 'Authorized Application')}</span>
        <span class="target-env">${esc(meta.environment || 'Development')}</span>
      </div>

      <div class="doc-top-actions">
        <span class="pill ${sevClass(stats.overallRisk)}">${esc(stats.overallRisk)} Risk</span>
        <span class="pill score">Score: ${stats.securityScore}/100</span>
        <button type="button" class="btn-dash" onclick="window.print()">Print Report</button>
        <a href="/dashboard.html" class="btn-dash">&larr; Dashboard</a>
      </div>
    </header>

    <!-- SECTION 1: EXECUTIVE SUMMARY -->
    <section class="doc-card" id="executive-summary">
      <div class="doc-card-header">
        <h2 class="doc-h2"><span class="code-id">01</span> Executive Summary</h2>
      </div>

      ${authGapCallout}
      ${loginNote}
      ${profileNote}
      <div class="callout-ok">${esc(sqliNone)}</div>

      <div class="kpi-grid">
        <div class="kpi-tile"><div class="n">${stats.totalFindings}</div><div class="l">Total Findings</div></div>
        <div class="kpi-tile"><div class="n" style="color:var(--accent-green)">${stats.confirmedSqli}</div><div class="l">Confirmed SQLi</div></div>
        <div class="kpi-tile"><div class="n">${stats.endpointsTested}</div><div class="l">Endpoints Tested</div></div>
        <div class="kpi-tile"><div class="n" style="color:var(--accent-blue)">${stats.securityScore}</div><div class="l">Security Score</div></div>
      </div>

      <div class="score-hud-box" id="score-rationale">
        <div class="score-circle">
          <div class="big">${stats.securityScore}</div>
          <div class="sub">/ 100</div>
        </div>
        <div>
          <h4 style="margin:0 0 4px;font-family:var(--font-mono);font-size:12px;color:var(--text-primary)">Score Rationale &amp; Deductions</h4>
          <p class="doc-p" style="margin:0;font-size:12px;color:var(--text-secondary)">
            Assessment score starts at 100 and applies risk deductions per confirmed vulnerability: Critical (−30), High (−18), Medium (−8), Low (−4). Validated safe passes produce zero penalty.
          </p>
        </div>
      </div>

      <h3 class="doc-h3" id="metadata-breakdown">Assessment Parameters</h3>
      <div class="table-wrap">
        <table class="doc-meta-table">
          <tr><td>Project Name</td><td><strong>${esc(meta.projectName)}</strong></td></tr>
          <tr><td>Target URL</td><td class="mono" style="color:var(--accent-blue)">${esc(meta.targetUrl)}</td></tr>
          <tr><td>Environment</td><td><span class="pill">${esc(meta.environment)}</span></td></tr>
          <tr><td>Assessment Date</td><td class="mono">${esc(meta.startedAt.slice(0, 10))}</td></tr>
          <tr><td>Duration</td><td class="mono">${meta.durationMinutes} minute(s)</td></tr>
          <tr><td>Scan Profile</td><td><span class="pill">${esc(meta.scanProfile || 'standard')}</span></td></tr>
          <tr><td>Security Types</td><td style="color:var(--text-secondary)">${esc(typesList)}</td></tr>
          <tr><td>Authenticated</td><td>${
            meta.authUsed
              ? `<span class="pill ok">Yes — session ready${meta.authAdapter ? ` (${esc(meta.authAdapter)})` : ''}</span>`
              : meta.loginAttempted
                ? `<span class="pill high">No — ${esc(meta.authStatus || 'login failed')}</span>`
                : '<span class="pill">No</span>'
          }</td></tr>
          <tr><td>Modules Tested</td><td class="mono">${stats.modulesTested}</td></tr>
          <tr><td>Endpoints / Parameters</td><td class="mono">${stats.endpointsTested} endpoints / ${stats.parametersTested} params</td></tr>
          <tr><td>Overall Risk Rating</td><td><span class="sev ${sevClass(stats.overallRisk)}">${esc(stats.overallRisk)}</span></td></tr>
        </table>
      </div>

      ${severityKpiRow(pie)}
    </section>

    <!-- SECTION 2: ASSESSMENT SCOPE -->
    <section class="doc-card" id="scope">
      <div class="doc-card-header">
        <h2 class="doc-h2"><span class="code-id">02</span> Assessment Scope &amp; Reconnaissance</h2>
      </div>

      <div class="table-wrap">
        <table class="doc-meta-table">
          <tr><td>Target Host</td><td class="mono">${esc(meta.targetUrl)}</td></tr>
          <tr><td>Page Title Observed</td><td>${esc(recon.pageTitle || 'N/A')}</td></tr>
          <tr><td>Forms Discovered</td><td class="mono">${recon.forms}</td></tr>
          <tr><td>Links Crawled</td><td class="mono">${recon.linksVisited}</td></tr>
          <tr><td>APIs Observed</td><td class="mono">${recon.apisObserved}</td></tr>
          <tr><td>Attack Query Surfaces</td><td class="mono">${recon.querySurfaces}</td></tr>
        </table>
      </div>

      <div id="safety-controls" style="margin-top:14px;">
        <h3 class="doc-h3">Safety &amp; Authorization Controls</h3>
        <p class="doc-p">
          All security assessment activities were performed under strict authorized non-destructive parameters: no persistent data modifications, no denial-of-service volumetric floods, and rate-limited injection probes.
        </p>
      </div>

      ${coverageSection}
    </section>

    <!-- SECTION 3: METHODOLOGY -->
    <section class="doc-card" id="methodology">
      <div class="doc-card-header">
        <h2 class="doc-h2"><span class="code-id">03</span> Assessment Methodology</h2>
      </div>

      <ol class="doc-list-ol" style="font-size:13px;line-height:1.7;">
        <li><strong>Playwright Headless Reconnaissance:</strong> Crawl application attack surface, dynamic single-page DOM elements, and API XHR/Fetch endpoints.</li>
        <li><strong>Attack Surface Enumeration:</strong> Extract and normalize URL query parameters, form bodies, JSON API payloads, and header vectors.</li>
        <li><strong>Safe Verification Engine:</strong> Execute multi-signal differential probes (error signatures, boolean differentials, limited time delays, and NoSQL syntax guards).</li>
        <li><strong>Evidence Capture:</strong> Preserve HTTP request/response artifacts, status codes, timing metrics, and screenshot evidence for confirmable findings.</li>
        <li><strong>Risk Scoring &amp; Standards Mapping:</strong> Align confirmed weaknesses to OWASP Top 10, CWE IDs, and CVSS v3.1 scoring formulas.</li>
      </ol>
    </section>

    <!-- SECTION 4: OVERALL RESULTS -->
    <section class="doc-card" id="overall">
      <div class="doc-card-header">
        <h2 class="doc-h2"><span class="code-id">04</span> Overall Results</h2>
      </div>

      ${authGapCallout}
      <div class="callout-ok">${esc(sqliNone)}</div>

      <div class="table-wrap">
        <table class="doc-table">
          <thead><tr><th>Severity Level</th><th>Detections</th><th>Impact Rationale</th></tr></thead>
          <tbody>
            <tr><td><span class="sev critical">Critical</span></td><td class="mono"><strong>${pie.Critical}</strong></td><td style="color:var(--text-secondary)">Immediate threat of full remote takeover or unauthorized data compromise</td></tr>
            <tr><td><span class="sev high">High</span></td><td class="mono"><strong>${pie.High}</strong></td><td style="color:var(--text-secondary)">Direct unauthorized privilege escalation, sensitive data leak, or injection</td></tr>
            <tr><td><span class="sev medium">Medium</span></td><td class="mono"><strong>${pie.Medium}</strong></td><td style="color:var(--text-secondary)">Conditional vulnerability requiring specific user interaction or environment state</td></tr>
            <tr><td><span class="sev low">Low</span></td><td class="mono"><strong>${pie.Low}</strong></td><td style="color:var(--text-secondary)">Minor configuration flaw or defense-in-depth deviation</td></tr>
            <tr><td><span class="sev info">Informational</span></td><td class="mono"><strong>${pie.Informational}</strong></td><td style="color:var(--text-secondary)">Architectural observations and non-exploitable security notices</td></tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- SECTION 5: SUMMARY TABLE -->
    <section class="doc-card" id="summary-table">
      <div class="doc-card-header">
        <h2 class="doc-h2"><span class="code-id">05</span> Assessment Summary Table</h2>
      </div>

      <div class="table-wrap">
        <table class="doc-table">
          <thead><tr><th>Module</th><th>URLs Tested</th><th>Parameters Tested</th><th>Findings</th><th>Highest Severity</th></tr></thead>
          <tbody>${summaryRows || '<tr><td colspan="5" style="color:var(--text-muted)">No modules evaluated</td></tr>'}</tbody>
        </table>
      </div>
    </section>

    <!-- SECTION 6: FINDING TABLE -->
    <section class="doc-card" id="finding-table">
      <div class="doc-card-header">
        <h2 class="doc-h2"><span class="code-id">06</span> Evaluated Findings Index</h2>
      </div>

      <div class="table-wrap">
        <table class="doc-table">
          <thead><tr><th>ID</th><th>Module</th><th>URL / Endpoint</th><th>Param</th><th>Techniques</th><th>Issue?</th><th>Severity</th><th>Status</th></tr></thead>
          <tbody>${findingRows}</tbody>
        </table>
      </div>
    </section>

    <!-- SECTION 7: CHARTS -->
    <section class="doc-card" id="charts">
      <div class="doc-card-header">
        <h2 class="doc-h2"><span class="code-id">07</span> Visualizations &amp; Distribution Charts</h2>
      </div>

      ${severityKpiRow(pie)}
      ${chartsBody}
    </section>

    <!-- SECTION 8: RISK MATRIX -->
    <section class="doc-card" id="risk-matrix">
      <div class="doc-card-header">
        <h2 class="doc-h2"><span class="code-id">08</span> Vulnerability Risk Matrix</h2>
      </div>

      <div class="table-wrap">
        <table class="matrix">
          <thead><tr><th>Likelihood \\ Impact</th><th>Low</th><th>Medium</th><th>High</th></tr></thead>
          <tbody>
            <tr><th class="axis">High</th>${cell('hl', 'cell-hl')}${cell('hm', 'cell-hm')}${cell('hh', 'cell-hh')}</tr>
            <tr><th class="axis">Medium</th>${cell('ml', 'cell-ml')}${cell('mm', 'cell-mm')}${cell('mh', 'cell-mh')}</tr>
            <tr><th class="axis">Low</th>${cell('ll', 'cell-ll')}${cell('lm', 'cell-lm')}${cell('lh', 'cell-lh')}</tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- SECTION 9: DETAILED FINDINGS -->
    <section class="doc-card" id="detailed">
      <div class="doc-card-header" style="display:flex;justify-content:space-between;align-items:center;">
        <h2 class="doc-h2"><span class="code-id">09</span> Detailed Vulnerability Findings (${confirmed.length})</h2>
      </div>

      ${detailed}
    </section>

    <!-- SECTION 10: RECOMMENDATIONS -->
    <section class="doc-card" id="recommendations">
      <div class="doc-card-header">
        <h2 class="doc-h2"><span class="code-id">10</span> Remediation Recommendations</h2>
      </div>

      <div id="rec-immediate">
        <h3 class="doc-h3" style="color:var(--accent-red)">Immediate Actions (Critical &amp; High)</h3>
        <ul class="doc-list-ul">
          <li>Remediate all confirmed injection and authorization bypass findings prior to production deployment.</li>
          <li>Enforce strict authentication barriers on administrative and data-mutation endpoints.</li>
        </ul>
      </div>

      <div id="rec-high" style="margin-top:14px;">
        <h3 class="doc-h3" style="color:var(--accent-amber)">High Priority Architecture Fixes</h3>
        <ul class="doc-list-ul">
          <li>Replace dynamic string concatenation in database queries with prepared statements or typed ODM filters.</li>
          <li>Implement cross-user object-level access control validation (BOLA / IDOR protection).</li>
        </ul>
      </div>

      <div id="rec-practices" style="margin-top:14px;">
        <h3 class="doc-h3">Secure Coding Best Practices</h3>
        <ul class="doc-list-ul">
          <li>Validate all untrusted input type, length, and syntax at the perimeter boundary.</li>
          <li>Return generic sanitized errors to API callers; keep detailed stack traces in server logs only.</li>
          <li>Enforce least-privilege database user account credentials.</li>
        </ul>
      </div>

      <div id="rec-checklist" style="margin-top:16px;">
        <h3 class="doc-h3">Engineering Checklist</h3>
        <ul class="checklist">
          <li>Parameterized database queries verified across all modules</li>
          <li>Strict allow-list validation on IDs, search, and filter parameters</li>
          <li>Session token and cookie security flags enforced (HttpOnly, Secure, SameSite)</li>
          <li>Automated regression security scanning enabled in CI/CD pipeline</li>
        </ul>
      </div>
    </section>

    <!-- SECTION 11: APPENDIX -->
    <section class="doc-card" id="appendix">
      <div class="doc-card-header">
        <h2 class="doc-h2"><span class="code-id">11</span> Appendix &amp; Standards Mapping</h2>
      </div>

      <div id="app-owasp">
        <h3 class="doc-h3">OWASP Standards References</h3>
        <ul class="doc-list-ul">
          <li>OWASP WSTG-INPV-05 — Testing for SQL Injection</li>
          <li>OWASP WSTG-INPV-06 — Testing for NoSQL Injection</li>
          <li>OWASP Top 10 (2021) — A01:2021-Broken Access Control &amp; A03:2021-Injection</li>
        </ul>
      </div>

      <div id="app-cwe" style="margin-top:14px;">
        <h3 class="doc-h3">CWE Mapping Standards</h3>
        <ul class="doc-list-ul">
          <li>CWE-89: SQL Injection</li>
          <li>CWE-943: Improper Neutralization of Special Elements in Data Query Logic</li>
          <li>CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)</li>
        </ul>
      </div>

      <div id="app-glossary" style="margin-top:14px;">
        <h3 class="doc-h3">Glossary</h3>
        <p class="doc-p">
          <strong>DAST:</strong> Dynamic Application Security Testing.<br />
          <strong>BOLA / IDOR:</strong> Broken Object Level Authorization / Insecure Direct Object Reference.<br />
          <strong>CVSS:</strong> Common Vulnerability Scoring System (v3.1).
        </p>
      </div>

      <div class="cyber-footer" style="margin-top:24px;">
        Generated by SecureAssess Platform &bull; Authorized assessment report &bull; Non-destructive evidence-backed testing
      </div>
    </section>
  </main>
</div>

<!-- Floating Theme Toggle Button -->
<button type="button" id="themeToggleBtn" class="theme-toggle-floating" title="Switch Theme (Light / Dark)" aria-label="Toggle theme">
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <circle cx="12" cy="12" r="5"/>
    <line x1="12" y1="1" x2="12" y2="3"/>
    <line x1="12" y1="21" x2="12" y2="23"/>
    <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>
    <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
    <line x1="1" y1="12" x2="3" y2="12"/>
    <line x1="21" y1="12" x2="23" y2="12"/>
    <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>
    <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
  </svg>
</button>

<script>
  // Interactive Documentation Sidebar Filtering & Active Link Tracking
  (function initDocInteractions() {
    const search = document.getElementById('docSearch');
    const topics = document.querySelectorAll('.doc-topic');

    if (search) {
      search.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase().trim();
        topics.forEach((topic) => {
          const text = topic.textContent.toLowerCase();
          const match = text.includes(query);
          topic.style.display = match ? 'block' : 'none';
          if (query && match) {
            topic.open = true;
          }
        });
      });
    }

    // Active heading tracking on scroll
    const sections = document.querySelectorAll('.doc-card, .doc-finding-card');
    const links = document.querySelectorAll('.doc-subnav a');

    window.addEventListener('scroll', () => {
      let currentId = '';
      sections.forEach((sec) => {
        const top = sec.getBoundingClientRect().top;
        if (top <= 120 && top >= -sec.offsetHeight) {
          currentId = sec.id;
        }
      });

      if (currentId) {
        links.forEach((link) => {
          const href = link.getAttribute('href') || '';
          if (href === '#' + currentId) {
            link.classList.add('active');
            const parentDetails = link.closest('details');
            if (parentDetails) parentDetails.open = true;
          } else {
            link.classList.remove('active');
          }
        });
      }
    });
  })();

  (function initThemeToggle() {
    const THEME_KEY = 'secureassess.theme';
    const sunSvg = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>';
    const moonSvg = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';

    function getBtn() {
      return document.getElementById('themeToggleBtn');
    }

    function apply(theme) {
      const isLight = theme === 'light';
      document.documentElement.setAttribute('data-theme', theme);
      if (document.body) document.body.setAttribute('data-theme', theme);
      const btn = getBtn();
      if (btn) {
        btn.innerHTML = isLight ? moonSvg : sunSvg;
        btn.title = isLight ? 'Switch to Dark Mode' : 'Switch to Light Mode';
        btn.setAttribute('aria-label', isLight ? 'Switch to Dark Mode' : 'Switch to Light Mode');
      }
    }

    function toggle() {
      const active = document.documentElement.getAttribute('data-theme') || 'dark';
      const next = active === 'dark' ? 'light' : 'dark';
      try {
        localStorage.setItem(THEME_KEY, next);
      } catch (e) {}
      apply(next);
    }

    function setup() {
      const btn = getBtn();
      if (btn) {
        btn.onclick = toggle;
      }
      let currentTheme = 'dark';
      try {
        currentTheme = localStorage.getItem(THEME_KEY) || 'dark';
      } catch (e) {}
      apply(currentTheme);
    }

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', setup);
    } else {
      setup();
    }
  })();
</script>
</body>
</html>`;
}

module.exports = { buildHtmlReport, formatCvss, formatReferences, resolveBusinessImpact };
