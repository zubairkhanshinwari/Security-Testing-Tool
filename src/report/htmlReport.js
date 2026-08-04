const fs = require('fs');
const { getSeverity } = require('../scanner/severity');

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

function sevClass(sev) {
  const s = String(sev || '').toLowerCase();
  if (s === 'critical') return 'critical';
  if (s === 'high') return 'high';
  if (s === 'medium') return 'medium';
  if (s === 'low') return 'low';
  return 'info';
}

const SEV_COLORS = {
  Critical: '#7f1d1d',
  High: '#dc2626',
  Medium: '#ea580c',
  Low: '#ca8a04',
  Informational: '#2563eb',
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
      `<span><i style="background:${SEV_COLORS[name]}"></i>${esc(name)} (${Number(counts[name] || 0)})</span>`
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
      paths += `<path d="${describeArc(cx, cy, r, angle, end)}" fill="${slice.color}" stroke="#fff" stroke-width="1.5"/>`;
      angle = end;
    }
  }

  return `<svg viewBox="0 0 180 180" width="180" height="180" role="img" aria-label="Findings by severity pie chart">
      ${paths}
      <circle cx="${cx}" cy="${cy}" r="38" fill="#fff"/>
      <text x="${cx}" y="${cy - 4}" text-anchor="middle" font-size="18" font-weight="700" fill="#0b1f3a">${pieTotal}</text>
      <text x="${cx}" y="${cy + 14}" text-anchor="middle" font-size="9" fill="#64748b">Total</text>
    </svg>
    <div class="legend">${legend}</div>`;
}

function buildModuleBarSvg(assessmentSummary) {
  if (!assessmentSummary.length) {
    return `<div class="chart-empty">No module data available.</div>`;
  }

  const max = Math.max(1, ...assessmentSummary.map((m) => Number(m.findings) || 0));
  const rowH = 28;
  const labelW = 120;
  const chartW = 320;
  const padL = labelW + 8;
  const height = Math.max(80, assessmentSummary.length * rowH + 16);

  const rows = assessmentSummary
    .map((m, i) => {
      const n = Number(m.findings) || 0;
      const barW = Math.max(n > 0 ? 6 : 0, Math.round((n / max) * chartW));
      const y = 12 + i * rowH;
      return `<text x="0" y="${y + 12}" font-size="10" fill="#334155">${esc(m.module)}</text>
        <rect x="${padL}" y="${y}" width="${barW}" height="16" rx="3" fill="#1f6feb"/>
        <text x="${padL + barW + 6}" y="${y + 12}" font-size="10" font-weight="700" fill="#0b1f3a">${n}</text>`;
    })
    .join('');

  return `<svg viewBox="0 0 ${padL + chartW + 40} ${height}" width="100%" height="${height}" role="img" aria-label="Findings by module">
    ${rows}
  </svg>`;
}

function buildStatusBarSvg(confirmedCount, passCount) {
  const items = [
    { label: 'Confirmed', count: confirmedCount, color: '#ea580c' },
    { label: 'Pass', count: passCount, color: '#059669' },
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
        <text x="${x + barW / 2}" y="${y - 8}" text-anchor="middle" font-size="12" font-weight="700" fill="#0b1f3a">${item.count}</text>
        <text x="${x + barW / 2}" y="${baseY + 16}" text-anchor="middle" font-size="10" fill="#64748b">${esc(item.label)}</text>`;
    })
    .join('');

  return `<svg viewBox="0 0 ${width} ${chartH + 40}" width="${width}" height="${chartH + 40}" role="img" aria-label="Findings by status">
    <line x1="20" y1="${baseY}" x2="${width - 10}" y2="${baseY}" stroke="#e2e8f0" stroke-width="1"/>
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
    ? `<div class="callout-warn">Authenticated testing incomplete: protected API endpoints returned 401/403. Provide a valid username and password on the next scan so the tool can obtain a session token and validate High-severity injection issues (for example postal_code NoSQL regex).</div>`
    : '';
  const loginNote =
    meta.loginAttempted && !meta.loginSuccess
      ? `<div class="callout-warn">Login attempted but failed: ${esc(meta.loginMessage || 'unknown error')}. Authenticated checks may be incomplete.</div>`
      : meta.loginSuccess
        ? `<div class="callout-ok">Authenticated session established via login credentials.</div>`
        : '';
  const typesList =
    Array.isArray(meta.securityTypes) && meta.securityTypes.length
      ? meta.securityTypes.join(', ')
      : 'Recommended defaults';

  const findingRows = findings
    .map((f) => {
      const sev = getSeverity(f) || 'Informational';
      const endpoint = f.endpoint || f.affectedEndpoint || f.fullUrl || f.affectedUrl || '';
      return `<tr>
      <td>${esc(f.id)}</td>
      <td>${esc(f.module)}</td>
      <td class="mono">${esc(endpoint)}</td>
      <td>${esc(f.parameter)}</td>
      <td>${esc((f.techniques || []).join(', '))}</td>
      <td>${f.issueFound ? 'Yes' : 'No'}</td>
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
      <td>${esc(m.module)}</td>
      <td>${m.urlsTested}</td>
      <td>${m.parametersTested}</td>
      <td>${m.findings}</td>
      <td><span class="sev ${badgeClass}">${esc(highest)}</span></td>
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
              return `<tr><td>${esc(e.technique)}</td><td class="mono">${esc(e.payload)}</td><td>${esc(
                e.status,
              )}</td><td>${esc(e.time)}</td><td>${esc(e.length)}</td><td class="mono">${esc(e.body)}</td></tr>`;
            })
            .join('');
          const affected =
            Array.isArray(f.affectedEndpoints) && f.affectedEndpoints.length
              ? `<tr><td>Affected Endpoints</td><td class="mono">${f.affectedEndpoints
                  .map((u) => esc(u))
                  .join('<br/>')}</td></tr>`
              : '';
          return `<article class="finding ${sevClass(sev)} avoid-break" id="${esc(f.id)}">
        <div class="finding-head">
          <h3>${esc(f.id)} — ${esc(f.title)}</h3>
          <span class="sev ${sevClass(sev)}">${esc(sev)}</span>
        </div>
        <div class="finding-body">
          <table class="finding-meta">
            <tr><td>Finding ID</td><td>${esc(f.id)}</td></tr>
            <tr><td>Module</td><td>${esc(f.module)}</td></tr>
            <tr><td>Page Name</td><td>${esc(f.pageName || '—')}</td></tr>
            <tr><td>Full URL</td><td class="mono">${esc(f.fullUrl || f.affectedUrl || f.endpoint)}</td></tr>
            ${affected}
            <tr><td>HTTP Method</td><td>${esc(f.method)}</td></tr>
            <tr><td>Parameter Name</td><td>${esc(f.parameter || 'n/a')}</td></tr>
            <tr><td>Input Type</td><td>${esc(f.inputType || 'n/a')}</td></tr>
            <tr><td>Authentication Required</td><td>${f.authRequired ? 'Yes' : 'No'}</td></tr>
            <tr><td>Assessment Status</td><td>${esc(f.status)}</td></tr>
            <tr><td>Issue Found</td><td>${f.issueFound ? 'Yes' : 'No'}</td></tr>
            <tr><td>Technique Evaluated</td><td>${esc((f.techniques || []).join('; '))}</td></tr>
            <tr><td>Severity</td><td><span class="sev ${sevClass(sev)}">${esc(sev)}</span></td></tr>
            <tr><td>Confidence</td><td>${esc(f.confidence)}</td></tr>
            <tr><td>CWE Mapping</td><td>${esc((f.cwe || []).join(', ') || 'N/A')}</td></tr>
            <tr><td>OWASP Category</td><td>${esc(f.owasp)}</td></tr>
            <tr><td>CVSS Score</td><td>${esc(f.cvss ?? 'N/A')}</td></tr>
          </table>
          <h4>Business Impact</h4>
          <p>${
            f.issueFound
              ? 'Successful injection or information leakage can expose data, enable authentication bypass, or assist further attacks depending on the sink and privileges.'
              : 'N/A'
          }</p>
          <h4>Description</h4>
          <p>${esc(f.description)}</p>
          <h4>Expected Secure Behavior</h4>
          <p>User input should be strictly validated and bound via parameterized queries / typed ODM filters. Errors should be generic.</p>
          <h4>Observed Result</h4>
          <p>${esc(f.description)}</p>
          <h4>Evidence</h4>
          <table>
            <thead><tr><th>Technique</th><th>Payload</th><th>Status</th><th>Time</th><th>Length</th><th>Body (truncated)</th></tr></thead>
            <tbody>${ev || '<tr><td colspan="6">No probe rows captured</td></tr>'}</tbody>
          </table>
          <h4>Developer Recommendation</h4>
          <p>Use parameterized queries / prepared statements (SQL) or typed exact-match ODM queries (NoSQL). Validate allow-lists at the boundary. Never concatenate untrusted input into queries or regex sources.</p>
          <h4>Remediation Steps</h4>
          <ol>
            <li>Identify the query construction path for <code>${esc(f.parameter)}</code>.</li>
            <li>Replace dynamic concatenation with parameterized / typed bindings.</li>
            <li>Add allow-list validation for the parameter type.</li>
            <li>Return generic errors to clients; log details server-side.</li>
            <li>Retest with the same probes to confirm closure.</li>
          </ol>
          <h4>References</h4>
          <p>OWASP WSTG-INPV-05; OWASP SQL Injection Prevention Cheat Sheet; ${(f.cwe || [])
            .map((c) => esc(c))
            .join(', ') || 'CWE-89'}.</p>
          ${
            (() => {
              if (!['Critical', 'High', 'Medium', 'Low'].includes(sev)) return '';
              const shot = resolveScreenshotBase64(f);
              if (!shot) {
                return `<div class="shot-missing">Screenshot not available for ${esc(f.id)} (${esc(sev)}).</div>`;
              }
              return `<div class="shot-block">
          <h4>Issue Screenshot — ${esc(f.id)}</h4>
          <p class="shot-label"><span class="sev ${sevClass(sev)}">${esc(sev)}</span>
            <span class="shot-type">${esc(f.module || f.pluginId || 'Issue')}</span>
            <strong>${esc(f.title)}</strong>
            ${
              f.screenshotFileName
                ? `<span class="shot-name mono">${esc(f.screenshotFileName)}</span>`
                : ''
            }
          </p>
          <figure class="shot">
            <img src="data:image/png;base64,${shot}" alt="${esc(
              f.screenshotCaption || `${sev} ${f.title}`,
            )}" />
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
        ? matrixPlace[key].map((id) => `<span class="tag">${esc(id)}</span>`).join(' ')
        : '—'
    }</td>`;

  const moduleChartData = assessmentSummary;

  const chartsBody = hasConfirmedFindings
    ? `<div class="chart-grid">
    <div class="chart-card">
      <h4>Findings by Severity</h4>
      <div class="pie-wrap">${buildSeverityPieSvg(pie)}</div>
    </div>
    <div class="chart-card">
      <h4>Findings by Status</h4>
      <div class="chart-center">${buildStatusBarSvg(statusConfirmed, statusPass)}</div>
    </div>
    <div class="chart-card" style="grid-column:1/-1">
      <h4>Findings by Module</h4>
      ${buildModuleBarSvg(moduleChartData)}
    </div>
  </div>`
    : `<div class="chart-empty-block">
      <div class="chart-empty">No confirmed findings — charts are empty. Severity KPIs below remain available for reference.</div>
      <div class="chart-grid">
        <div class="chart-card">
          <h4>Findings by Severity</h4>
          <div class="pie-wrap">${buildSeverityPieSvg(pie)}</div>
        </div>
        <div class="chart-card">
          <h4>Findings by Status</h4>
          <div class="chart-center">${buildStatusBarSvg(statusConfirmed, statusPass)}</div>
        </div>
        <div class="chart-card" style="grid-column:1/-1">
          <h4>Findings by Module</h4>
          ${buildModuleBarSvg(moduleChartData)}
        </div>
      </div>
    </div>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>${esc(meta.projectName)} — Web Security Assessment Report</title>
<style>
  @page { size: A4; margin: 18mm 14mm 18mm 14mm; }
  :root {
    --navy:#0b1f3a; --accent:#1f6feb; --critical:#7f1d1d; --high:#dc2626;
    --medium:#ea580c; --low:#ca8a04; --info:#2563eb; --ok:#059669;
    --muted:#64748b; --line:#e2e8f0; --bg:#f8fafc; --text:#0f172a; --warn:#c2410c;
  }
  *{box-sizing:border-box}
  body{margin:0;font-family:"Segoe UI",Calibri,Arial,sans-serif;color:var(--text);font-size:11pt;line-height:1.45}
  h1,h2,h3,h4{color:var(--navy);page-break-after:avoid;margin:0 0 .55em}
  h1{font-size:24pt} h2{font-size:14pt;border-bottom:2px solid var(--accent);padding-bottom:6px}
  h3{font-size:12pt} p{margin:0 0 .7em}
  .page-break{page-break-before:always}
  .avoid-break{page-break-inside:avoid}
  .cover{min-height:250mm;background:linear-gradient(160deg,#0b1f3a,#12355b 55%,#1e4976);color:#fff;padding:28mm 18mm 20mm;margin:-18mm -14mm 0;display:flex;flex-direction:column;justify-content:space-between}
  .logo-box{width:72px;height:72px;border:2px solid rgba(255,255,255,.55);border-radius:12px;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:18pt;background:rgba(255,255,255,.08)}
  .cover h1{color:#fff;border:0;margin:12px 0 8px}
  .cover-meta{display:grid;grid-template-columns:1fr 1fr;gap:10px 24px;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.18);border-radius:10px;padding:18px 20px;max-width:560px}
  .cover-meta .label{font-size:8pt;text-transform:uppercase;letter-spacing:.08em;opacity:.7}
  .cover-meta .value{font-size:11pt;font-weight:600;margin-top:2px}
  .pill{display:inline-block;padding:4px 10px;border-radius:999px;font-size:8.5pt;font-weight:700;margin-right:6px}
  .pill.ok{background:#059669;color:#fff} .pill.risk{background:#dc2626;color:#fff} .pill.score{background:#fff;color:#0b1f3a}
  .callout-ok{background:#ecfdf5;border:1px solid #a7f3d0;color:#065f46;padding:12px 14px;border-radius:8px;font-weight:600;margin:12px 0}
  .callout-warn{background:#fff7ed;border:2px solid #ea580c;color:#9a3412;padding:14px 16px;border-radius:8px;font-weight:700;margin:14px 0;font-size:10.5pt;line-height:1.5}
  .kpi-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:14px 0}
  .kpi{border:1px solid var(--line);border-radius:8px;padding:12px;text-align:center}
  .kpi .n{font-size:20pt;font-weight:700;color:var(--navy)} .kpi .l{font-size:8pt;text-transform:uppercase;color:var(--muted);margin-top:4px}
  .kpi.critical .n{color:var(--critical)} .kpi.high .n{color:var(--high)} .kpi.medium .n{color:var(--medium)} .kpi.low .n{color:var(--low)}
  .sev-kpi-row{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:14px 0}
  .sev-kpi{border:1px solid var(--line);border-radius:8px;padding:12px 8px;text-align:center;background:#fff}
  .sev-kpi-n{font-size:18pt;font-weight:700;margin-top:8px}
  .sev{display:inline-block;min-width:70px;text-align:center;padding:2px 8px;border-radius:4px;color:#fff;font-size:8.5pt;font-weight:700;text-transform:uppercase}
  .sev.critical{background:var(--critical)} .sev.high{background:var(--high)} .sev.medium{background:var(--medium)} .sev.low{background:var(--low);color:#1f2937} .sev.info{background:var(--info)}
  .status{display:inline-block;padding:2px 8px;border-radius:4px;font-size:8.5pt;font-weight:700}
  .status.confirmed{background:#ffedd5;color:#9a3412} .status.pass{background:#d1fae5;color:#065f46}
  table{width:100%;border-collapse:collapse;margin:10px 0 16px;font-size:9pt}
  th{background:var(--navy);color:#fff;text-align:left;padding:7px 8px}
  td{padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
  tr:nth-child(even) td{background:#f8fafc}
  .meta-table td:first-child,.finding-meta td:first-child{width:30%;font-weight:600;background:#f1f5f9;color:#12355b}
  .mono{font-family:Consolas,"Courier New",monospace;font-size:8.5pt;word-break:break-all}
  .toc{list-style:none;padding:0;margin:0}
  .toc li{padding:7px 0;border-bottom:1px dotted #cbd5e1}
  .toc a{color:var(--navy);font-weight:600;text-decoration:none}
  .chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
  .chart-card{border:1px solid var(--line);border-radius:8px;padding:12px}
  .pie-wrap{display:flex;flex-direction:column;align-items:center;gap:8px;min-height:200px;justify-content:center}
  .chart-center{display:flex;justify-content:center;align-items:flex-end;min-height:160px}
  .chart-empty{background:#f8fafc;border:1px dashed #cbd5e1;color:var(--muted);padding:16px;border-radius:8px;text-align:center;font-size:9.5pt;font-weight:600;margin:8px 0}
  .chart-empty-block{margin-top:4px}
  .legend{display:flex;flex-wrap:wrap;gap:10px;font-size:8.5pt;margin-top:8px;justify-content:center}
  .legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px}
  .matrix{width:100%;border-collapse:collapse;table-layout:fixed}
  .matrix th,.matrix td{border:1px solid #cbd5e1;text-align:center;padding:12px 8px;height:60px}
  .matrix th{background:var(--navy);color:#fff}
  .matrix .axis{background:#e2e8f0;color:var(--navy);font-weight:700}
  .cell-ll{background:#ecfdf5}.cell-lm{background:#fef9c3}.cell-lh{background:#ffedd5}
  .cell-ml{background:#fef9c3}.cell-mm{background:#ffedd5}.cell-mh{background:#fecaca}
  .cell-hl{background:#ffedd5}.cell-hm{background:#fecaca}.cell-hh{background:#fecaca}
  .tag{display:inline-block;background:#fff;border:1px solid #94a3b8;border-radius:4px;padding:2px 6px;font-size:8pt;font-weight:700;margin:2px}
  .finding{border:1px solid var(--line);border-radius:8px;margin:0 0 16px;overflow:hidden}
  .finding.high{border-top:4px solid var(--high)} .finding.critical{border-top:4px solid var(--critical)}
  .finding.medium{border-top:4px solid var(--medium)} .finding.low{border-top:4px solid var(--low)}
  .finding.info{border-top:4px solid var(--info)}
  .finding-head{display:flex;justify-content:space-between;gap:12px;padding:10px 14px;background:#f1f5f9;border-bottom:1px solid var(--line)}
  .finding-body{padding:12px 14px}
  .checklist li{list-style:none;margin-left:0}
  .checklist li::before{content:"☐ ";color:var(--accent);font-weight:700}
  .footer-note{margin-top:16px;padding-top:10px;border-top:1px solid var(--line);font-size:8.5pt;color:var(--muted)}
  .score-box{display:flex;gap:16px;align-items:center;border:1px solid var(--line);border-radius:8px;padding:14px;background:linear-gradient(90deg,#eff6ff,#fff)}
  .score-circle{width:84px;height:84px;border-radius:50%;border:7px solid var(--accent);display:flex;align-items:center;justify-content:center;flex-direction:column}
  .score-circle .big{font-size:20pt;font-weight:700;color:var(--navy)}
  .shot-block{margin-top:16px;padding-top:12px;border-top:2px solid var(--accent)}
  .shot-block h4{margin-bottom:8px}
  .shot-label{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:0 0 10px;font-size:9.5pt}
  .shot{margin:0;padding:0;border:1px solid var(--line);border-radius:8px;overflow:hidden;background:#fff}
  .shot-caption{padding:8px 12px;background:#f1f5f9;font-size:9pt;font-weight:600}
  .shot img,.shot-card img{display:block;width:100%;height:auto}
  .shot-name{color:var(--muted);font-weight:500}
  .shot-missing{margin-top:12px;padding:10px 12px;background:#fff7ed;border:1px dashed #fdba74;border-radius:8px;color:#9a3412;font-size:9pt;font-weight:600}
  .shot-grid{display:flex;flex-direction:column;gap:18px}
  .shot-card{border:1px solid var(--line);border-radius:10px;overflow:hidden;background:#fff;margin:0}
  .shot-card h3{margin:0;padding:10px 14px 0;font-size:12pt}
  .shot-meta{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:12px 14px 0}
  .shot-type{font-size:9pt;font-weight:700;color:#12355b;background:#e2e8f0;padding:2px 8px;border-radius:4px}
  .shot-file{padding:0 14px 10px;margin:0;color:var(--muted)}
  .shot-card .shot-caption{border:0;padding:6px 14px 10px;background:transparent}
</style>
</head>
<body>
<section class="cover">
  <div>
    <div class="logo-box">SEC</div>
    <div style="text-transform:uppercase;letter-spacing:.18em;font-size:9pt;opacity:.8;margin-top:28px">Application Security Assessment</div>
    <h1>Web Security Assessment Report</h1>
    <div style="opacity:.9;margin-bottom:18px">${esc(
      meta.standard || 'OWASP WSTG / OWASP Top 10 (2021)',
    )} — Authorized Assessment</div>
    <div>
      <span class="pill ok">${stats.totalFindings} Finding(s)</span>
      <span class="pill risk">Overall Risk: ${esc(stats.overallRisk)}</span>
      <span class="pill score">Security Score: ${stats.securityScore} / 100</span>
    </div>
  </div>
  <div class="cover-meta">
    <div><div class="label">Project Name</div><div class="value">${esc(meta.projectName)}</div></div>
    <div><div class="label">Environment</div><div class="value">${esc(meta.environment)}</div></div>
    <div><div class="label">Target URL</div><div class="value">${esc(meta.targetUrl)}</div></div>
    <div><div class="label">Assessment Date</div><div class="value">${esc(meta.startedAt.slice(0, 10))}</div></div>
    <div><div class="label">Tester</div><div class="value">${esc(meta.testerName)}</div></div>
    <div><div class="label">Assessment Type</div><div class="value">${esc(
      meta.assessmentType || 'Web Security Assessment',
    )}</div></div>
  </div>
  <div style="border-top:1px solid rgba(255,255,255,.2);padding-top:14px;font-size:9pt;opacity:.85;display:flex;justify-content:space-between">
    <div>Company Logo Placeholder<br/>Security Assessment Tool</div>
    <div style="text-align:right">Document Version 1.0<br/>Authorized Use Only</div>
  </div>
</section>

<section class="page-break">
  <h2>Table of Contents</h2>
  <ol class="toc">
    <li><a href="#executive-summary">1. Executive Summary</a></li>
    <li><a href="#scope">2. Assessment Scope</a></li>
    <li><a href="#methodology">3. Methodology</a></li>
    <li><a href="#overall">4. Overall Results</a></li>
    <li><a href="#summary-table">5. Assessment Summary Table</a></li>
    <li><a href="#finding-table">6. Finding Table</a></li>
    <li><a href="#charts">7. Charts</a></li>
    <li><a href="#risk-matrix">8. Risk Matrix</a></li>
    <li><a href="#detailed">9. Detailed Findings</a></li>
    <li><a href="#recommendations">10. Recommendations</a></li>
    <li><a href="#appendix">11. Appendix</a></li>
  </ol>
</section>

<section class="page-break" id="executive-summary">
  <h2>1. Executive Summary</h2>
  ${authGapCallout}
  ${loginNote}
  <div class="callout-ok">${esc(sqliNone)}</div>
  <table class="meta-table">
    <tr><td>Project Name</td><td>${esc(meta.projectName)}</td></tr>
    <tr><td>Target URL</td><td>${esc(meta.targetUrl)}</td></tr>
    <tr><td>Environment</td><td>${esc(meta.environment)}</td></tr>
    <tr><td>Assessment Date</td><td>${esc(meta.startedAt.slice(0, 10))}</td></tr>
    <tr><td>Assessment Duration</td><td>${meta.durationMinutes} minute(s)</td></tr>
    <tr><td>Assessment Type</td><td>${esc(meta.assessmentType || 'Web Security Assessment')}</td></tr>
    <tr><td>Security Testing Types</td><td>${esc(typesList)}</td></tr>
    <tr><td>Authenticated</td><td>${meta.authUsed ? 'Yes' : 'No'}${meta.loginSuccess ? ' (via username/password)' : ''}</td></tr>
    <tr><td>Modules Tested</td><td>${stats.modulesTested}</td></tr>
    <tr><td>Endpoints Tested</td><td>${stats.endpointsTested}</td></tr>
    <tr><td>Parameters Tested</td><td>${stats.parametersTested}</td></tr>
    <tr><td>Overall Risk Rating</td><td><span class="sev ${sevClass(stats.overallRisk)}">${esc(
      stats.overallRisk
    )}</span></td></tr>
    <tr><td>Security Score</td><td><strong>${stats.securityScore} / 100</strong></td></tr>
  </table>
  ${severityKpiRow(pie)}
  <div class="kpi-grid">
    <div class="kpi"><div class="n">${stats.totalFindings}</div><div class="l">Total Findings</div></div>
    <div class="kpi"><div class="n" style="color:#059669">${stats.confirmedSqli}</div><div class="l">Confirmed SQLi</div></div>
    <div class="kpi"><div class="n">${stats.endpointsTested}</div><div class="l">Endpoints</div></div>
    <div class="kpi"><div class="n">${stats.securityScore}</div><div class="l">Score</div></div>
  </div>
  <div class="score-box avoid-break">
    <div class="score-circle"><div class="big">${stats.securityScore}</div><div style="font-size:8pt;color:#64748b">/ 100</div></div>
    <div>
      <h4 style="margin:0 0 6px">Score Rationale</h4>
      <p style="margin:0;font-size:9.5pt">Score starts at 100 and decreases for confirmed findings by severity (Critical −30, High −18, Medium −8, Low −4). Pass results do not reduce the score.</p>
    </div>
  </div>
</section>

<section class="page-break" id="scope">
  <h2>2. Assessment Scope</h2>
  <ul>
    <li>Target: ${esc(meta.targetUrl)}</li>
    <li>Page title observed: ${esc(recon.pageTitle || 'N/A')}</li>
    <li>Forms discovered: ${recon.forms}</li>
    <li>Links visited: ${recon.linksVisited}</li>
    <li>API calls observed: ${recon.apisObserved}</li>
    <li>Query surfaces: ${recon.querySurfaces}</li>
  </ul>
  <p><strong>Safety controls:</strong> non-destructive probes only; no database dumps; no intentional data modification; time-based delays limited.</p>
</section>

<section class="page-break" id="methodology">
  <h2>3. Methodology</h2>
  <ol>
    <li>Reconnaissance with Playwright (forms, links, XHR/fetch APIs).</li>
    <li>Input enumeration (query, path, JSON auth bodies, form fields).</li>
    <li>Safe validation: error-based, boolean differential, limited time-based, NoSQL operator checks.</li>
    <li>Evidence capture (status, length, timing, truncated body).</li>
    <li>Professional PDF reporting aligned to OWASP WSTG-INPV-05.</li>
  </ol>
</section>

<section class="page-break" id="overall">
  <h2>4. Overall Results</h2>
  ${authGapCallout}
  <div class="callout-ok">${esc(sqliNone)}</div>
  <table>
    <thead><tr><th>Severity</th><th>Count</th></tr></thead>
    <tbody>
      <tr><td><span class="sev critical">Critical</span></td><td>${pie.Critical}</td></tr>
      <tr><td><span class="sev high">High</span></td><td>${pie.High}</td></tr>
      <tr><td><span class="sev medium">Medium</span></td><td>${pie.Medium}</td></tr>
      <tr><td><span class="sev low">Low</span></td><td>${pie.Low}</td></tr>
      <tr><td><span class="sev info">Informational</span></td><td>${pie.Informational}</td></tr>
    </tbody>
  </table>
</section>

<section class="page-break" id="summary-table">
  <h2>5. Assessment Summary Table</h2>
  <table>
    <thead><tr><th>Module</th><th>URLs Tested</th><th>Parameters Tested</th><th>Findings</th><th>Highest Severity</th></tr></thead>
    <tbody>${summaryRows || '<tr><td colspan="5">No modules tested</td></tr>'}</tbody>
  </table>
</section>

<section class="page-break" id="finding-table">
  <h2>6. Finding Table</h2>
  <table>
    <thead><tr><th>ID</th><th>Module</th><th>URL</th><th>Parameter</th><th>Technique Evaluated</th><th>Issue Found</th><th>Severity</th><th>Status</th></tr></thead>
    <tbody>${findingRows}</tbody>
  </table>
</section>

<section class="page-break" id="charts">
  <h2>7. Charts</h2>
  ${severityKpiRow(pie)}
  ${chartsBody}
</section>

<section class="page-break" id="risk-matrix">
  <h2>8. Risk Matrix</h2>
  <table class="matrix">
    <thead><tr><th>Likelihood \\ Impact</th><th>Low</th><th>Medium</th><th>High</th></tr></thead>
    <tbody>
      <tr><th class="axis">High</th>${cell('hl', 'cell-hl')}${cell('hm', 'cell-hm')}${cell('hh', 'cell-hh')}</tr>
      <tr><th class="axis">Medium</th>${cell('ml', 'cell-ml')}${cell('mm', 'cell-mm')}${cell('mh', 'cell-mh')}</tr>
      <tr><th class="axis">Low</th>${cell('ll', 'cell-ll')}${cell('lm', 'cell-lm')}${cell('lh', 'cell-lh')}</tr>
    </tbody>
  </table>
</section>

<section class="page-break" id="detailed">
  <h2>9. Detailed Findings</h2>
  ${detailed}
</section>

<section class="page-break" id="recommendations">
  <h2>10. Recommendations</h2>
  <h3>Immediate Actions</h3>
  <ul>
    <li>Remediate all Critical and High findings before promoting code.</li>
    <li>Confirm authorization scope covers every tested host/API.</li>
  </ul>
  <h3>High Priority Fixes</h3>
  <ul>
    <li>Eliminate dynamic SQL/NoSQL construction from user input.</li>
    <li>Enforce parameterized queries / typed ODM filters everywhere.</li>
  </ul>
  <h3>Medium Priority Fixes</h3>
  <ul>
    <li>Generic error handling; hide driver/ODM internals.</li>
    <li>Strict allow-list validation on IDs, search, filters, pagination.</li>
  </ul>
  <h3>Low Priority Improvements</h3>
  <ul>
    <li>Add SAST/DAST for injection classes in CI.</li>
    <li>Review auth token lifetime and CORS policy.</li>
  </ul>
  <h3>Secure Coding Best Practices</h3>
  <ul>
    <li>Never concatenate untrusted input into queries.</li>
    <li>Prefer allow-lists over deny-lists.</li>
    <li>Least-privilege database accounts.</li>
  </ul>
  <h3>Database Security Recommendations</h3>
  <ul>
    <li>Least privilege DB roles; disable dangerous routines where unused.</li>
    <li>Query timeouts / maxTimeMS for NoSQL.</li>
  </ul>
  <h3>Input Validation Recommendations</h3>
  <ul>
    <li>Validate type, length, and format at the trust boundary.</li>
  </ul>
  <h3>Parameterized Query Recommendations</h3>
  <ul>
    <li>Use prepared statements / bound parameters for SQL.</li>
    <li>Use typed filters for Mongo/ODM; never raw regex from user input.</li>
  </ul>
  <h3>Error Handling Recommendations</h3>
  <ul>
    <li>Generic client errors + server-side correlation IDs.</li>
  </ul>
  <h3>Developer Checklist</h3>
  <ul class="checklist">
    <li>All queries parameterized / typed</li>
    <li>Allow-list validation on every parameter</li>
    <li>No raw user input in regex / $where / dynamic SQL</li>
    <li>Generic error handler in production</li>
    <li>Injection regression tests in CI</li>
  </ul>
</section>

<section class="page-break" id="appendix">
  <h2>11. Appendix</h2>
  <h3>Testing Methodology</h3>
  <p>Authorized grey-box assessment using Playwright recon and safe injection probes only.</p>
  <h3>OWASP References</h3>
  <ul>
    <li>OWASP WSTG-INPV-05 — Testing for SQL Injection</li>
    <li>OWASP WSTG-INPV-06 — Testing for NoSQL Injection</li>
    <li>OWASP SQL Injection Prevention Cheat Sheet</li>
  </ul>
  <h3>CWE References</h3>
  <ul>
    <li>CWE-89 — SQL Injection</li>
    <li>CWE-943 — Improper Neutralization of Special Elements in Data Query Logic</li>
    <li>CWE-209 — Error Message Information Disclosure</li>
  </ul>
  <h3>Glossary</h3>
  <p><strong>SQLi</strong>: SQL Injection. <strong>NoSQLi</strong>: NoSQL Injection. <strong>ODM</strong>: Object Document Mapper.</p>
  <h3>Abbreviations</h3>
  <p>API, CWE, JWT, OWASP, REST, WSTG, CVSS.</p>
  <div class="footer-note">Generated by Web Security Assessment Tool. Use only against systems you own or are explicitly authorized to test. Findings are limited to evidenced probe results; no vulnerability is claimed without supporting evidence.</div>
</section>
</body>
</html>`;
}

module.exports = { buildHtmlReport };
