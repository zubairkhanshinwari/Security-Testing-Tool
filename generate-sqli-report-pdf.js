/**
 * Generate professional SQL Injection Assessment PDF from assessment data.
 * Usage: node generate-sqli-report-pdf.js
 */
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const OUT_DIR = __dirname;
const HTML_PATH = path.join(OUT_DIR, 'SQL-Injection-Assessment-Report.html');
const PDF_PATH = path.join(OUT_DIR, 'SQL-Injection-Assessment-Report.pdf');

function buildHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>SQL Injection Security Assessment Report — Falaya Dev</title>
<style>
  @page { size: A4; margin: 18mm 16mm 20mm 16mm; }
  @page landscape { size: A4 landscape; margin: 14mm 12mm 18mm 12mm; }

  :root {
    --navy: #0b1f3a;
    --navy-2: #12355b;
    --accent: #1f6feb;
    --critical: #7f1d1d;
    --high: #dc2626;
    --medium: #ea580c;
    --low: #ca8a04;
    --info: #2563eb;
    --ok: #059669;
    --muted: #64748b;
    --line: #e2e8f0;
    --bg: #f8fafc;
    --card: #ffffff;
    --text: #0f172a;
  }

  * { box-sizing: border-box; }
  html { font-size: 11pt; }
  body {
    margin: 0;
    font-family: "Segoe UI", Calibri, "Helvetica Neue", Arial, sans-serif;
    color: var(--text);
    background: #fff;
    line-height: 1.45;
  }

  h1, h2, h3, h4 {
    font-family: "Segoe UI Semibold", "Segoe UI", Calibri, sans-serif;
    color: var(--navy);
    margin: 0 0 0.55em;
    page-break-after: avoid;
  }
  h1 { font-size: 22pt; letter-spacing: -0.02em; }
  h2 {
    font-size: 14pt;
    border-bottom: 2px solid var(--accent);
    padding-bottom: 6px;
    margin-top: 0;
  }
  h3 { font-size: 12pt; margin-top: 1.1em; }
  h4 { font-size: 11pt; color: var(--navy-2); }
  p { margin: 0 0 0.7em; }
  ul, ol { margin: 0.2em 0 0.8em 1.2em; padding: 0; }
  li { margin: 0.2em 0; }
  a { color: var(--accent); text-decoration: none; }
  code, .mono {
    font-family: Consolas, "Courier New", monospace;
    font-size: 9.5pt;
    background: #f1f5f9;
    padding: 1px 4px;
    border-radius: 3px;
  }
  pre {
    font-family: Consolas, "Courier New", monospace;
    font-size: 8.5pt;
    background: #0b1f3a;
    color: #e2e8f0;
    padding: 12px 14px;
    border-radius: 6px;
    overflow: hidden;
    white-space: pre-wrap;
    page-break-inside: avoid;
  }

  .page-break { page-break-before: always; break-before: page; }
  .avoid-break { page-break-inside: avoid; break-inside: avoid; }

  /* Cover */
  .cover {
    min-height: 250mm;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    background: linear-gradient(160deg, #0b1f3a 0%, #12355b 55%, #1e4976 100%);
    color: #fff;
    padding: 28mm 18mm 20mm;
    margin: -18mm -16mm 0;
  }
  .logo-box {
    width: 72px; height: 72px;
    border: 2px solid rgba(255,255,255,0.55);
    border-radius: 12px;
    display: flex; align-items: center; justify-content: center;
    font-weight: 700; font-size: 18pt; letter-spacing: 0.04em;
    background: rgba(255,255,255,0.08);
  }
  .cover-kicker {
    text-transform: uppercase; letter-spacing: 0.18em;
    font-size: 9pt; opacity: 0.8; margin-top: 28px;
  }
  .cover h1 {
    color: #fff; font-size: 28pt; margin: 10px 0 8px; border: 0;
  }
  .cover .subtitle { font-size: 13pt; opacity: 0.9; margin-bottom: 28px; }
  .cover-meta {
    display: grid; grid-template-columns: 1fr 1fr; gap: 10px 24px;
    background: rgba(255,255,255,0.08);
    border: 1px solid rgba(255,255,255,0.18);
    border-radius: 10px; padding: 18px 20px; max-width: 520px;
  }
  .cover-meta .label { font-size: 8pt; text-transform: uppercase; letter-spacing: 0.08em; opacity: 0.7; }
  .cover-meta .value { font-size: 11pt; font-weight: 600; margin-top: 2px; }
  .cover-footer {
    display: flex; justify-content: space-between; align-items: flex-end;
    border-top: 1px solid rgba(255,255,255,0.2); padding-top: 14px; font-size: 9pt; opacity: 0.85;
  }
  .badge-row { display: flex; gap: 8px; margin: 14px 0 0; flex-wrap: wrap; }
  .pill {
    display: inline-block; padding: 4px 10px; border-radius: 999px;
    font-size: 8.5pt; font-weight: 700; letter-spacing: 0.03em;
  }
  .pill.sqli-none { background: #059669; color: #fff; }
  .pill.risk-high { background: var(--high); color: #fff; }
  .pill.score { background: #fff; color: var(--navy); }

  /* Sections */
  .section { margin-top: 8px; }
  .lead {
    background: var(--bg); border-left: 4px solid var(--accent);
    padding: 12px 14px; border-radius: 0 6px 6px 0; margin-bottom: 14px;
  }
  .callout-ok {
    background: #ecfdf5; border: 1px solid #a7f3d0; color: #065f46;
    padding: 12px 14px; border-radius: 8px; font-weight: 600; margin: 12px 0;
  }
  .callout-warn {
    background: #fff7ed; border: 1px solid #fdba74; color: #9a3412;
    padding: 12px 14px; border-radius: 8px; margin: 12px 0;
  }

  /* KPI cards */
  .kpi-grid {
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px;
    margin: 14px 0 18px;
  }
  .kpi {
    background: var(--card); border: 1px solid var(--line); border-radius: 8px;
    padding: 12px; text-align: center; page-break-inside: avoid;
  }
  .kpi .n { font-size: 20pt; font-weight: 700; color: var(--navy); line-height: 1; }
  .kpi .l { font-size: 8pt; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); margin-top: 4px; }
  .kpi.critical .n { color: var(--critical); }
  .kpi.high .n { color: var(--high); }
  .kpi.medium .n { color: var(--medium); }
  .kpi.low .n { color: var(--low); }
  .kpi.info .n { color: var(--info); }
  .kpi.total .n { color: var(--accent); }

  /* Severity badges */
  .sev {
    display: inline-block; min-width: 72px; text-align: center;
    padding: 2px 8px; border-radius: 4px; color: #fff;
    font-size: 8.5pt; font-weight: 700; text-transform: uppercase;
  }
  .sev.critical { background: var(--critical); }
  .sev.high { background: var(--high); }
  .sev.medium { background: var(--medium); }
  .sev.low { background: var(--low); color: #1f2937; }
  .sev.info { background: var(--info); }
  .sev.none { background: var(--ok); }
  .status {
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 8.5pt; font-weight: 700;
  }
  .status.open { background: #fee2e2; color: #991b1b; }
  .status.confirmed { background: #ffedd5; color: #9a3412; }
  .status.pass { background: #d1fae5; color: #065f46; }

  /* Tables */
  table {
    width: 100%; border-collapse: collapse; margin: 10px 0 16px;
    font-size: 9pt; page-break-inside: auto;
  }
  thead { display: table-header-group; }
  th {
    background: var(--navy); color: #fff; text-align: left;
    padding: 7px 8px; font-weight: 600; font-size: 8.5pt;
  }
  td {
    padding: 6px 8px; border-bottom: 1px solid var(--line);
    vertical-align: top;
  }
  tr:nth-child(even) td { background: #f8fafc; }
  .table-landscape { page-break-before: always; }
  .meta-table td:first-child {
    width: 34%; font-weight: 600; color: var(--navy-2); background: #f1f5f9;
  }
  .finding-meta td:first-child { width: 28%; }

  /* TOC */
  .toc { list-style: none; margin: 0; padding: 0; }
  .toc li {
    display: flex; justify-content: space-between; gap: 12px;
    padding: 7px 0; border-bottom: 1px dotted #cbd5e1;
  }
  .toc a { color: var(--navy); font-weight: 600; }
  .toc .dot { flex: 1; border-bottom: 1px dotted #94a3b8; margin: 0 6px 4px; opacity: 0.5; }
  .toc .num { color: var(--muted); font-size: 9pt; }

  /* Charts */
  .chart-grid {
    display: grid; grid-template-columns: 1fr 1fr; gap: 16px;
    margin: 12px 0 18px;
  }
  .chart-card {
    border: 1px solid var(--line); border-radius: 8px; padding: 12px;
    page-break-inside: avoid; background: #fff;
  }
  .chart-card h4 { margin-bottom: 8px; }
  .chart-card.full { grid-column: 1 / -1; }
  .chart-svg { width: 100%; height: auto; display: block; }
  .legend { display: flex; flex-wrap: wrap; gap: 8px 14px; margin-top: 8px; font-size: 8.5pt; }
  .legend span::before {
    content: ""; display: inline-block; width: 9px; height: 9px;
    border-radius: 2px; margin-right: 5px; vertical-align: -1px;
  }

  /* Risk matrix */
  .matrix {
    width: 100%; border-collapse: collapse; table-layout: fixed;
    margin: 12px 0 8px; font-size: 9pt;
  }
  .matrix th, .matrix td {
    border: 1px solid #cbd5e1; text-align: center; padding: 12px 8px;
    vertical-align: middle; height: 64px;
  }
  .matrix th { background: var(--navy); color: #fff; }
  .matrix .axis { background: #e2e8f0; color: var(--navy); font-weight: 700; }
  .cell-ll { background: #ecfdf5; }
  .cell-lm { background: #fef9c3; }
  .cell-lh { background: #ffedd5; }
  .cell-ml { background: #fef9c3; }
  .cell-mm { background: #ffedd5; }
  .cell-mh { background: #fecaca; }
  .cell-hl { background: #ffedd5; }
  .cell-hm { background: #fecaca; }
  .cell-hh { background: #fecaca; }
  .matrix .tag {
    display: inline-block; background: #fff; border: 1px solid #94a3b8;
    border-radius: 4px; padding: 2px 6px; font-size: 8pt; font-weight: 700;
    margin: 2px;
  }
  .matrix .tag.high { border-color: var(--high); color: var(--high); }
  .matrix .tag.medium { border-color: var(--medium); color: var(--medium); }
  .matrix .tag.low { border-color: var(--low); color: #854d0e; }

  /* Finding card */
  .finding {
    border: 1px solid var(--line); border-radius: 8px;
    margin: 0 0 18px; overflow: hidden; page-break-inside: avoid;
  }
  .finding-head {
    display: flex; justify-content: space-between; align-items: center;
    gap: 12px; padding: 10px 14px; background: #f1f5f9;
    border-bottom: 1px solid var(--line);
  }
  .finding-head h3 { margin: 0; font-size: 11.5pt; }
  .finding-body { padding: 12px 14px; }
  .finding.high { border-top: 4px solid var(--high); }
  .finding.medium { border-top: 4px solid var(--medium); }
  .finding.low { border-top: 4px solid var(--low); }

  .two-col {
    display: grid; grid-template-columns: 1fr 1fr; gap: 12px;
  }
  .checklist li { list-style: none; margin-left: 0; }
  .checklist li::before { content: "☐ "; color: var(--accent); font-weight: 700; }

  .footer-note {
    margin-top: 18px; padding-top: 10px; border-top: 1px solid var(--line);
    font-size: 8.5pt; color: var(--muted);
  }
  .score-box {
    display: flex; align-items: center; gap: 16px;
    border: 1px solid var(--line); border-radius: 8px; padding: 14px;
    margin: 12px 0; background: linear-gradient(90deg, #eff6ff, #fff);
  }
  .score-circle {
    width: 84px; height: 84px; border-radius: 50%;
    border: 7px solid var(--accent); display: flex; align-items: center;
    justify-content: center; flex-direction: column; background: #fff;
  }
  .score-circle .big { font-size: 20pt; font-weight: 700; color: var(--navy); line-height: 1; }
  .score-circle .sub { font-size: 8pt; color: var(--muted); }
</style>
</head>
<body>

<!-- ===================== COVER ===================== -->
<section class="cover" id="cover">
  <div>
    <div class="logo-box">SEC</div>
    <div class="cover-kicker">Application Security Assessment</div>
    <h1>SQL Injection Security Assessment Report</h1>
    <div class="subtitle">OWASP WSTG-INPV-05 Authorized Assessment</div>
    <div class="badge-row">
      <span class="pill sqli-none">0 Confirmed SQL Injection Findings</span>
      <span class="pill risk-high">Overall Risk: High</span>
      <span class="pill score">Security Score: 72 / 100</span>
    </div>
  </div>
  <div class="cover-meta">
    <div>
      <div class="label">Project Name</div>
      <div class="value">Falaya Dev — SQL Injection Assessment</div>
    </div>
    <div>
      <div class="label">Environment</div>
      <div class="value">Development</div>
    </div>
    <div>
      <div class="label">Target URL</div>
      <div class="value">https://dev.falaya.com/</div>
    </div>
    <div>
      <div class="label">API Backend</div>
      <div class="value">https://devapi.falaya.com/api/</div>
    </div>
    <div>
      <div class="label">Assessment Date</div>
      <div class="value">03 August 2026</div>
    </div>
    <div>
      <div class="label">Tester</div>
      <div class="value">Senior Application Security Engineer</div>
    </div>
    <div>
      <div class="label">Assessment Type</div>
      <div class="value">SQL Injection Security Assessment</div>
    </div>
    <div>
      <div class="label">Classification</div>
      <div class="value">Confidential — Authorized Testing</div>
    </div>
  </div>
  <div class="cover-footer">
    <div>Company Logo Placeholder<br/>Security Assessment Practice</div>
    <div style="text-align:right">Document Version 1.0<br/>Export-ready PDF Report</div>
  </div>
</section>

<!-- ===================== TOC ===================== -->
<section class="page-break section" id="toc">
  <h2>Table of Contents</h2>
  <ol class="toc">
    <li><a href="#executive-summary">1. Executive Summary</a><span class="dot"></span><span class="num">03</span></li>
    <li><a href="#project-info">2. Project Information</a><span class="dot"></span><span class="num">04</span></li>
    <li><a href="#scope">3. Assessment Scope</a><span class="dot"></span><span class="num">04</span></li>
    <li><a href="#methodology">4. Methodology</a><span class="dot"></span><span class="num">05</span></li>
    <li><a href="#overall-results">5. Overall Results</a><span class="dot"></span><span class="num">06</span></li>
    <li><a href="#assessment-summary">6. Assessment Summary Table</a><span class="dot"></span><span class="num">07</span></li>
    <li><a href="#finding-table">7. Finding Table</a><span class="dot"></span><span class="num">08</span></li>
    <li><a href="#charts">8. Charts &amp; Visual Analytics</a><span class="dot"></span><span class="num">09</span></li>
    <li><a href="#risk-matrix">9. Risk Matrix</a><span class="dot"></span><span class="num">10</span></li>
    <li><a href="#detailed-findings">10. Detailed Findings</a><span class="dot"></span><span class="num">11</span></li>
    <li><a href="#recommendations">11. Recommendations</a><span class="dot"></span><span class="num">16</span></li>
    <li><a href="#appendix">12. Appendix</a><span class="dot"></span><span class="num">18</span></li>
  </ol>
</section>

<!-- ===================== EXECUTIVE SUMMARY ===================== -->
<section class="page-break section" id="executive-summary">
  <h2>1. Executive Summary</h2>

  <div class="callout-ok">
    No confirmed SQL Injection vulnerabilities were identified during this authorized assessment.
  </div>

  <p class="lead">
    An authorized, non-destructive SQL Injection assessment was performed against the Falaya development
    environment following OWASP WSTG-INPV-05. The application is an Angular frontend over a Node.js/Express
    REST API backed by <strong>MongoDB (Mongoose ODM)</strong>. Classic SQL Injection does not apply because
    no SQL database is present in the request path. The same methodology confirmed related injection and
    information-disclosure issues that are included below using only evidenced assessment results.
  </p>

  <table class="meta-table avoid-break">
    <tr><td>Project Name</td><td>Falaya Dev — SQL Injection Assessment</td></tr>
    <tr><td>Target URL</td><td>https://dev.falaya.com/</td></tr>
    <tr><td>API Backend</td><td>https://devapi.falaya.com/api/</td></tr>
    <tr><td>Environment</td><td>Development</td></tr>
    <tr><td>Assessment Date</td><td>03 August 2026</td></tr>
    <tr><td>Assessment Duration</td><td>~1 business day (single assessment session)</td></tr>
    <tr><td>Assessment Type</td><td>SQL Injection Security Assessment (Grey-box, authenticated low-privilege user)</td></tr>
    <tr><td>Modules Tested</td><td>Authentication, Notifications, Listings / Property Search, Admin (role-gated), Session/Headers/Cookies</td></tr>
    <tr><td>Endpoints Tested</td><td>12+ reachable API endpoints / route surfaces (auth, notifications, listings, search, postal lookup, admin)</td></tr>
    <tr><td>Parameters Tested</td><td>email, password, offset, limit, id, postal_code, search/q/keyword, state, authorization JWT, analytics cookies</td></tr>
    <tr><td>Overall Risk Rating</td><td><span class="sev high">High</span> (driven by NoSQLi-01; no confirmed SQLi)</td></tr>
    <tr><td>Security Score</td><td><strong>72 / 100</strong></td></tr>
  </table>

  <h3>Findings Summary</h3>
  <div class="kpi-grid">
    <div class="kpi total"><div class="n">3</div><div class="l">Total Findings</div></div>
    <div class="kpi critical"><div class="n">0</div><div class="l">Critical</div></div>
    <div class="kpi high"><div class="n">1</div><div class="l">High</div></div>
    <div class="kpi medium"><div class="n">1</div><div class="l">Medium</div></div>
  </div>
  <div class="kpi-grid">
    <div class="kpi low"><div class="n">1</div><div class="l">Low</div></div>
    <div class="kpi info"><div class="n">5</div><div class="l">Informational (Positive Controls)</div></div>
    <div class="kpi"><div class="n" style="color:#059669">0</div><div class="l">Confirmed SQLi</div></div>
    <div class="kpi"><div class="n">72</div><div class="l">Security Score</div></div>
  </div>

  <div class="score-box avoid-break">
    <div class="score-circle">
      <div class="big">72</div>
      <div class="sub">/ 100</div>
    </div>
    <div>
      <h4 style="margin:0 0 6px">Score Rationale</h4>
      <p style="margin:0;font-size:9.5pt">
        Strong authentication input handling and absence of SQL Injection exposure are positives.
        Score deductions: High NoSQL <code>$regex</code> injection (−18), verbose DB error disclosure (−6),
        unhandled exceptions / hardening gaps (−4). Score is expected to rise to ~90+ after remediation of
        NoSQLi-01 and the global error handler.
      </p>
    </div>
  </div>
</section>

<!-- ===================== PROJECT INFO + SCOPE ===================== -->
<section class="page-break section" id="project-info">
  <h2>2. Project Information</h2>
  <table class="meta-table avoid-break">
    <tr><td>Project Name</td><td>Falaya Dev — SQL Injection Assessment</td></tr>
    <tr><td>Client / Owner</td><td>Authorized development environment owner</td></tr>
    <tr><td>Target URL</td><td>https://dev.falaya.com/</td></tr>
    <tr><td>API Target</td><td>https://devapi.falaya.com/api/</td></tr>
    <tr><td>Environment</td><td>Development</td></tr>
    <tr><td>Assessment Date</td><td>03 August 2026</td></tr>
    <tr><td>Tester Name</td><td>Senior Application Security Engineer / Penetration Tester</td></tr>
    <tr><td>Standard</td><td>OWASP WSTG-INPV-05; OWASP SQL Injection Prevention Cheat Sheet</td></tr>
    <tr><td>Tooling</td><td>Playwright-driven browser, in-context fetch() replay, network inspection</td></tr>
    <tr><td>Document Version</td><td>1.0</td></tr>
  </table>
</section>

<section class="section" id="scope">
  <h2>3. Assessment Scope</h2>
  <h3>3.1 In Scope</h3>
  <ul>
    <li>Query parameters, path parameters, JSON request bodies</li>
    <li>REST API parameters, cookies, HTTP headers (authorization JWT)</li>
    <li>Login / forgot-password flows, search / filter / pagination parameters</li>
    <li>Listing identifiers, postal-code lookup, notifications pagination</li>
    <li>Safe validation techniques only: error-based, boolean-based, time-based indicators; input validation and parameter handling review</li>
  </ul>
  <h3>3.2 Out of Scope / Safety Controls</h3>
  <ul>
    <li>Destructive actions, data modification, database dumping, or sensitive record extraction</li>
    <li>Production data changes; ReDoS / DoS payload execution</li>
    <li>Writable testing of file-upload / multipart endpoints (upload routes present but not exercised for mutation)</li>
  </ul>
  <h3>3.3 Datastore Fingerprint (Assessment Result)</h3>
  <table class="avoid-break">
    <thead><tr><th>Signal</th><th>Evidence</th><th>Conclusion</th></tr></thead>
    <tbody>
      <tr><td>Server banner</td><td><code>x-powered-by: Express</code>, <code>server: nginx/1.18.0</code></td><td>Node.js / Express API</td></tr>
      <tr><td>User identifier</td><td>JWT id = 24-hex ObjectId</td><td>MongoDB ObjectId</td></tr>
      <tr><td>ODM error</td><td>Cast to ObjectId failed … model "Listing"</td><td>Mongoose ODM (MongoDB)</td></tr>
      <tr><td>Pagination error</td><td>invalid argument to $limit / $skip … NaN</td><td>MongoDB aggregation pipeline</td></tr>
      <tr><td>Regex error</td><td>MongoDB code 51091 / Location51091</td><td>MongoDB $regex engine</td></tr>
    </tbody>
  </table>
</section>

<!-- ===================== METHODOLOGY ===================== -->
<section class="page-break section" id="methodology">
  <h2>4. Methodology</h2>
  <p>Testing followed OWASP WSTG-INPV-05 with safe, non-destructive validation:</p>
  <ol>
    <li><strong>Reconnaissance</strong> — map frontend routes, extract API surfaces from Angular bundles, capture live network traffic.</li>
    <li><strong>Input enumeration</strong> — identify query, path, JSON body, cookie, and header inputs that may reach a database.</li>
    <li><strong>Safe injection validation</strong> — error-based probes, boolean true/false differentials, limited time-based delays (≤3s), operator-injection checks for NoSQL.</li>
    <li><strong>Evidence recording</strong> — HTTP status, response length, timing, error messages; stop after safe confirmation.</li>
    <li><strong>Reporting</strong> — severity, CVSS estimate, CWE/OWASP mapping, remediation guidance.</li>
  </ol>
  <h3>Techniques Evaluated</h3>
  <ul>
    <li>Error Handling Review</li>
    <li>Boolean Logic Validation</li>
    <li>Time-Based Validation</li>
    <li>Input Validation Review</li>
    <li>Parameter Handling Review</li>
    <li>JSON Parameter / Operator Injection Review (adjacent NoSQL class)</li>
  </ul>
</section>

<!-- ===================== OVERALL RESULTS ===================== -->
<section class="page-break section" id="overall-results">
  <h2>5. Overall Results</h2>
  <div class="callout-ok">
    No confirmed SQL Injection vulnerabilities were identified during this authorized assessment.
  </div>
  <p>
    All SQL-oriented payloads produced MongoDB/Mongoose behaviour rather than SQL engine behaviour.
    Three related findings were confirmed and are documented in Section 10.
  </p>
  <table class="avoid-break">
    <thead><tr><th>Severity</th><th>Count</th><th>Notes</th></tr></thead>
    <tbody>
      <tr><td><span class="sev critical">Critical</span></td><td>0</td><td>—</td></tr>
      <tr><td><span class="sev high">High</span></td><td>1</td><td>NoSQLi-01 — MongoDB $regex injection</td></tr>
      <tr><td><span class="sev medium">Medium</span></td><td>1</td><td>INFO-01 — Verbose DB/driver error disclosure</td></tr>
      <tr><td><span class="sev low">Low</span></td><td>1</td><td>INFO-02 — Unhandled null-dereference exceptions</td></tr>
      <tr><td><span class="sev info">Informational</span></td><td>5</td><td>Positive controls that held (auth, forgot, pagination, ObjectId cast, admin gating)</td></tr>
      <tr><td><span class="sev none">Confirmed SQLi</span></td><td>0</td><td>No SQL database in request path</td></tr>
    </tbody>
  </table>

  <h3>Positive Security Observations</h3>
  <ul>
    <li><strong>Login (<code>auth/signin</code>)</strong> resisted SQL and NoSQL operator payloads; no auth bypass; no token issuance.</li>
    <li><strong><code>auth/forgot</code></strong> returned a generic existence message with no SQL/driver error on quote injection.</li>
    <li><strong>Pagination</strong> inputs are coerced to integers (NaN rejection), eliminating numeric SQLi vectors.</li>
    <li><strong>Object IDs</strong> are cast/validated by Mongoose on <code>:id</code> routes.</li>
    <li><strong>Admin endpoints</strong> are role-gated (<code>Access Denied</code> for standard users).</li>
  </ul>
</section>

<!-- ===================== ASSESSMENT SUMMARY ===================== -->
<section class="page-break section" id="assessment-summary">
  <h2>6. Assessment Summary Table</h2>
  <table class="avoid-break">
    <thead>
      <tr>
        <th>Module</th>
        <th>URLs Tested</th>
        <th>Parameters Tested</th>
        <th>Findings</th>
        <th>Highest Severity</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>Authentication</td>
        <td>auth/signin, auth/forgot</td>
        <td>email, password (JSON)</td>
        <td>0</td>
        <td><span class="sev none">None</span></td>
      </tr>
      <tr>
        <td>Notifications</td>
        <td>notifications/users</td>
        <td>offset, limit</td>
        <td>1 (shared INFO-01)</td>
        <td><span class="sev medium">Medium</span></td>
      </tr>
      <tr>
        <td>Listings / Property Lookup</td>
        <td>listings/:id, listings/:zip/postal_code, listings/search/all/listings, listings/getCityStats, listings/getParishStats, listings/getAddressByStateName/:state</td>
        <td>id, postal_code, search/q/keyword, state</td>
        <td>3 (NoSQLi-01, INFO-01, INFO-02)</td>
        <td><span class="sev high">High</span></td>
      </tr>
      <tr>
        <td>Session / Headers / Cookies</td>
        <td>authorization header; analytics cookies</td>
        <td>JWT, _ga/_fbp/_clck</td>
        <td>0</td>
        <td><span class="sev none">None</span></td>
      </tr>
      <tr>
        <td>Admin</td>
        <td>admin/* (role-gated probe)</td>
        <td>role-gated access</td>
        <td>0</td>
        <td><span class="sev none">None</span></td>
      </tr>
    </tbody>
  </table>
</section>

<!-- ===================== FINDING TABLE (landscape-friendly) ===================== -->
<section class="page-break section" id="finding-table">
  <h2>7. Finding Table</h2>
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>Module</th>
        <th>URL</th>
        <th>Parameter</th>
        <th>Technique Evaluated</th>
        <th>Issue Found</th>
        <th>Severity</th>
        <th>Status</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>NoSQLi-01</td>
        <td>Listings</td>
        <td>/api/listings/{postal_code}/postal_code</td>
        <td>postal_code</td>
        <td>Input Validation Review; Parameter Handling Review; Error Handling Review; Boolean Logic Validation; Time-Based Validation</td>
        <td>Yes (NoSQL $regex injection; not SQLi)</td>
        <td><span class="sev high">High</span></td>
        <td><span class="status confirmed">Confirmed</span></td>
      </tr>
      <tr>
        <td>INFO-01</td>
        <td>Listings / Notifications</td>
        <td>Multiple listing &amp; notification endpoints</td>
        <td>Multiple</td>
        <td>Error Handling Review</td>
        <td>Yes (verbose DB/driver errors)</td>
        <td><span class="sev medium">Medium</span></td>
        <td><span class="status confirmed">Confirmed</span></td>
      </tr>
      <tr>
        <td>INFO-02</td>
        <td>Listings</td>
        <td>/api/listings/:id, /api/listings/getCityStats</td>
        <td>id (and related)</td>
        <td>Error Handling Review; Parameter Handling Review</td>
        <td>Yes (null-dereference exceptions)</td>
        <td><span class="sev low">Low</span></td>
        <td><span class="status confirmed">Confirmed</span></td>
      </tr>
      <tr>
        <td>SQLi-AUTH-01</td>
        <td>Authentication</td>
        <td>/api/auth/signin</td>
        <td>email, password</td>
        <td>Error / Boolean / Time-Based / Operator Injection Review</td>
        <td>No</td>
        <td><span class="sev none">None</span></td>
        <td><span class="status pass">Pass</span></td>
      </tr>
      <tr>
        <td>SQLi-AUTH-02</td>
        <td>Authentication</td>
        <td>/api/auth/forgot</td>
        <td>email</td>
        <td>Error Handling Review; Input Validation Review</td>
        <td>No</td>
        <td><span class="sev none">None</span></td>
        <td><span class="status pass">Pass</span></td>
      </tr>
      <tr>
        <td>SQLi-NOTIF-01</td>
        <td>Notifications</td>
        <td>/api/notifications/users</td>
        <td>offset, limit</td>
        <td>Boolean Logic Validation; Time-Based Validation; Parameter Handling Review</td>
        <td>No (SQLi); aggregation NaN errors only</td>
        <td><span class="sev none">None</span></td>
        <td><span class="status pass">Pass</span></td>
      </tr>
    </tbody>
  </table>
  <p class="footer-note">Pass rows document surfaces evaluated for SQL Injection with no confirmed SQLi issue. Confirmed rows are the only vulnerability findings from the assessment data.</p>
</section>

<!-- ===================== CHARTS ===================== -->
<section class="page-break section" id="charts">
  <h2>8. Charts &amp; Visual Analytics</h2>

  <div class="chart-grid">
    <div class="chart-card">
      <h4>Findings by Severity (Pie)</h4>
      <!-- Pie: High=1, Medium=1, Low=1 → equal thirds. Informational positive controls noted separately. -->
      <svg class="chart-svg" viewBox="0 0 320 220" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Pie chart findings by severity">
        <circle cx="110" cy="110" r="70" fill="#f1f5f9"/>
        <!-- three equal 120° slices -->
        <path d="M110,110 L110,40 A70,70 0 0,1 170.62,145 Z" fill="#dc2626"/>
        <path d="M110,110 L170.62,145 A70,70 0 0,1 49.38,145 Z" fill="#ea580c"/>
        <path d="M110,110 L49.38,145 A70,70 0 0,1 110,40 Z" fill="#ca8a04"/>
        <circle cx="110" cy="110" r="38" fill="#fff"/>
        <text x="110" y="106" text-anchor="middle" font-size="16" font-weight="700" fill="#0b1f3a">3</text>
        <text x="110" y="122" text-anchor="middle" font-size="9" fill="#64748b">Findings</text>
        <rect x="200" y="55" width="12" height="12" fill="#dc2626" rx="2"/><text x="218" y="65" font-size="11" fill="#0f172a">High (1)</text>
        <rect x="200" y="80" width="12" height="12" fill="#ea580c" rx="2"/><text x="218" y="90" font-size="11" fill="#0f172a">Medium (1)</text>
        <rect x="200" y="105" width="12" height="12" fill="#ca8a04" rx="2"/><text x="218" y="115" font-size="11" fill="#0f172a">Low (1)</text>
        <rect x="200" y="130" width="12" height="12" fill="#2563eb" rx="2"/><text x="218" y="140" font-size="11" fill="#0f172a">Info+ (5)</text>
        <rect x="200" y="155" width="12" height="12" fill="#059669" rx="2"/><text x="218" y="165" font-size="11" fill="#0f172a">SQLi (0)</text>
      </svg>
    </div>

    <div class="chart-card">
      <h4>Findings by Module (Bar)</h4>
      <svg class="chart-svg" viewBox="0 0 360 220" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Bar chart findings by module">
        <line x1="50" y1="20" x2="50" y2="170" stroke="#94a3b8" stroke-width="1"/>
        <line x1="50" y1="170" x2="340" y2="170" stroke="#94a3b8" stroke-width="1"/>
        <!-- Auth 0 -->
        <rect x="70" y="170" width="36" height="0" fill="#059669"/>
        <text x="88" y="188" text-anchor="middle" font-size="9" fill="#475569">Auth</text>
        <text x="88" y="165" text-anchor="middle" font-size="10" font-weight="700" fill="#059669">0</text>
        <!-- Notifications 1 (shared INFO-01 counted under Listings primarily; module chart uses assessment attribution) -->
        <rect x="130" y="120" width="36" height="50" fill="#ea580c"/>
        <text x="148" y="188" text-anchor="middle" font-size="9" fill="#475569">Notif*</text>
        <text x="148" y="114" text-anchor="middle" font-size="10" font-weight="700" fill="#0f172a">1</text>
        <!-- Listings 3 -->
        <rect x="190" y="20" width="36" height="150" fill="#dc2626"/>
        <text x="208" y="188" text-anchor="middle" font-size="9" fill="#475569">Listings</text>
        <text x="208" y="16" text-anchor="middle" font-size="10" font-weight="700" fill="#0f172a">3</text>
        <!-- Session 0 -->
        <rect x="250" y="170" width="36" height="0" fill="#059669"/>
        <text x="268" y="188" text-anchor="middle" font-size="9" fill="#475569">Session</text>
        <text x="268" y="165" text-anchor="middle" font-size="10" font-weight="700" fill="#059669">0</text>
        <!-- Admin 0 -->
        <rect x="310" y="170" width="28" height="0" fill="#059669"/>
        <text x="324" y="188" text-anchor="middle" font-size="9" fill="#475569">Admin</text>
        <text x="324" y="165" text-anchor="middle" font-size="10" font-weight="700" fill="#059669">0</text>
        <text x="10" y="25" font-size="9" fill="#64748b">3</text>
        <text x="10" y="75" font-size="9" fill="#64748b">2</text>
        <text x="10" y="125" font-size="9" fill="#64748b">1</text>
        <text x="10" y="170" font-size="9" fill="#64748b">0</text>
      </svg>
      <p style="font-size:8pt;color:#64748b;margin:0">*Notifications shares INFO-01 with Listings endpoints (assessment attribution).</p>
    </div>

    <div class="chart-card full">
      <h4>Findings by Status (Bar)</h4>
      <svg class="chart-svg" viewBox="0 0 520 160" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Bar chart findings by status">
        <line x1="80" y1="20" x2="80" y2="120" stroke="#94a3b8"/>
        <line x1="80" y1="120" x2="480" y2="120" stroke="#94a3b8"/>
        <!-- Confirmed 3 -->
        <rect x="120" y="30" width="70" height="90" fill="#ea580c"/>
        <text x="155" y="24" text-anchor="middle" font-size="12" font-weight="700">3</text>
        <text x="155" y="138" text-anchor="middle" font-size="10" fill="#475569">Confirmed</text>
        <!-- Pass / No SQLi 3 documented pass surfaces -->
        <rect x="240" y="30" width="70" height="90" fill="#059669"/>
        <text x="275" y="24" text-anchor="middle" font-size="12" font-weight="700">3</text>
        <text x="275" y="138" text-anchor="middle" font-size="10" fill="#475569">Pass (No SQLi)</text>
        <!-- Open 0 -->
        <rect x="360" y="120" width="70" height="0" fill="#94a3b8"/>
        <text x="395" y="114" text-anchor="middle" font-size="12" font-weight="700" fill="#059669">0</text>
        <text x="395" y="138" text-anchor="middle" font-size="10" fill="#475569">Open / Unresolved</text>
      </svg>
    </div>
  </div>
</section>

<!-- ===================== RISK MATRIX ===================== -->
<section class="page-break section" id="risk-matrix">
  <h2>9. Risk Matrix</h2>
  <p>Likelihood × Impact placement for every confirmed finding from the assessment data.</p>
  <table class="matrix avoid-break">
    <thead>
      <tr>
        <th style="width:18%">Likelihood \\ Impact</th>
        <th>Low</th>
        <th>Medium</th>
        <th>High</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <th class="axis">High</th>
        <td class="cell-hl">—</td>
        <td class="cell-hm">—</td>
        <td class="cell-hh">—</td>
      </tr>
      <tr>
        <th class="axis">Medium</th>
        <td class="cell-ml">
          <span class="tag low">INFO-02</span><br/>
          <span style="font-size:8pt">Null dereference</span>
        </td>
        <td class="cell-mm">
          <span class="tag medium">INFO-01</span><br/>
          <span style="font-size:8pt">Error disclosure</span>
        </td>
        <td class="cell-mh">
          <span class="tag high">NoSQLi-01</span><br/>
          <span style="font-size:8pt">$regex injection</span>
        </td>
      </tr>
      <tr>
        <th class="axis">Low</th>
        <td class="cell-ll">—</td>
        <td class="cell-lm">—</td>
        <td class="cell-lh">—</td>
      </tr>
    </tbody>
  </table>
  <p class="footer-note">No finding falls in High Likelihood × High Impact. NoSQLi-01 is the top remediation priority. Assessment likelihood for NoSQLi-01 was recorded as Medium–High; placed in Medium likelihood row per matrix bands used in the source assessment.</p>
</section>

<!-- ===================== DETAILED FINDINGS ===================== -->
<section class="page-break section" id="detailed-findings">
  <h2>10. Detailed Findings</h2>
  <div class="callout-ok">
    No confirmed SQL Injection vulnerabilities were identified during this authorized assessment.
  </div>
  <p>The following findings are reproduced exclusively from the completed assessment results.</p>

  <!-- FINDING NoSQLi-01 -->
  <article class="finding high avoid-break" id="finding-nosqli-01">
    <div class="finding-head">
      <h3>NoSQLi-01 — MongoDB $regex (NoSQL) Injection in postal_code Lookup</h3>
      <span class="sev high">High</span>
    </div>
    <div class="finding-body">
      <table class="finding-meta">
        <tr><td>Finding ID</td><td>NoSQLi-01</td></tr>
        <tr><td>Module Name</td><td>Listings / Property Lookup</td></tr>
        <tr><td>Feature Name</td><td>Postal code listing lookup</td></tr>
        <tr><td>Page Name</td><td>N/A (API-driven; frontend https://dev.falaya.com/)</td></tr>
        <tr><td>Full URL</td><td>https://devapi.falaya.com/api/listings/{postal_code}/postal_code</td></tr>
        <tr><td>API Endpoint</td><td>/api/listings/{postal_code}/postal_code</td></tr>
        <tr><td>HTTP Method</td><td>GET</td></tr>
        <tr><td>Parameter Name</td><td>postal_code (path segment)</td></tr>
        <tr><td>Input Type</td><td>String</td></tr>
        <tr><td>Authentication Required</td><td>Yes (low-privilege role: user)</td></tr>
        <tr><td>Assessment Status</td><td><span class="status confirmed">Confirmed</span></td></tr>
        <tr><td>Issue Found</td><td><strong>Yes</strong> (NoSQL $regex injection — not classic SQL Injection)</td></tr>
        <tr><td>SQL Injection Technique Evaluated</td><td>Error Handling Review; Boolean Logic Validation; Time-Based Validation; Input Validation Review; Parameter Handling Review</td></tr>
        <tr><td>Severity</td><td><span class="sev high">High</span></td></tr>
        <tr><td>Confidence</td><td>High</td></tr>
        <tr><td>CWE Mapping</td><td>CWE-943; CWE-1333</td></tr>
        <tr><td>OWASP Category</td><td>A03:2021 – Injection; WSTG-INPV-05 methodology / NoSQL variant (WSTG-INPV-06)</td></tr>
        <tr><td>CVSS Score</td><td>7.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:L)</td></tr>
      </table>

      <h4>Business Impact</h4>
      <ul>
        <li>Data exposure / filter bypass: enumerate and harvest the full Listing collection (392+ records) and pattern-filter beyond intended access.</li>
        <li>Denial of Service (ReDoS) potential via malicious regex (not exercised during testing).</li>
        <li>Injection foothold confirming unsanitised input reaches query construction.</li>
      </ul>

      <h4>Description</h4>
      <p>
        Unescaped user input in the <code>postal_code</code> path parameter is compiled as a MongoDB regular expression.
        SQL payloads did not produce SQL behaviour; population-count differentials and MongoDB regex error <code>51091</code>
        prove direct <code>$regex</code> usage without escaping.
      </p>

      <h4>Expected Secure Behavior</h4>
      <p>Input treated as a literal postal-code value (exact match); non-matching input returns empty; malformed input rejected with a generic 400/error.</p>

      <h4>Observed Result</h4>
      <p>Input is compiled as a regular expression, enabling query broadening, full-collection return, arbitrary pattern filtering, and potential catastrophic-backtracking regexes.</p>

      <h4>Evidence</h4>
      <table>
        <thead><tr><th>Injected postal_code</th><th>HTTP</th><th>Records</th><th>Interpretation</th></tr></thead>
        <tbody>
          <tr><td><code>70601</code></td><td>200</td><td>0</td><td>Exact/normal match</td></tr>
          <tr><td><code>00000</code> / <code>abc</code></td><td>200</td><td>0</td><td>No match</td></tr>
          <tr><td><code>.*</code></td><td>200</td><td><strong>392</strong></td><td>Full collection returned</td></tr>
          <tr><td><code>a||b</code></td><td>200</td><td><strong>392</strong></td><td>Full collection returned</td></tr>
          <tr><td><code>^7</code></td><td>200</td><td><strong>9</strong></td><td>Regex anchor honoured</td></tr>
          <tr><td><code>(</code></td><td>200/error body</td><td>—</td><td>MongoDB code 51091 / Location51091</td></tr>
        </tbody>
      </table>

      <h4>Developer Recommendation</h4>
      <p>Use exact-match queries; never place raw user input into <code>$regex</code>. Validate postal codes with a strict allow-list (e.g. <code>^\\d{5}(-\\d{4})?$</code>). Escape metacharacters only if pattern search is a true requirement.</p>

      <h4>Remediation Steps</h4>
      <ol>
        <li>Replace <code>$regex</code> with exact equality: <code>{ postal_code: value }</code>.</li>
        <li>Validate <code>postal_code</code> at the route boundary; reject invalid values with generic 400.</li>
        <li>If substring search is required, escape regex metacharacters and anchor the pattern, or use a text index.</li>
        <li>Add schema validation middleware (Joi/Zod/express-validator) on the route.</li>
        <li>Regression-test with <code>.*</code>, <code>^7</code>, and unbalanced <code>(</code> payloads.</li>
      </ol>

      <h4>References</h4>
      <p>OWASP WSTG-INPV-05; OWASP WSTG-INPV-06; OWASP SQL Injection Prevention Cheat Sheet; CWE-943; CWE-1333.</p>
    </div>
  </article>
</section>

<section class="page-break section">
  <!-- FINDING INFO-01 -->
  <article class="finding medium avoid-break" id="finding-info-01">
    <div class="finding-head">
      <h3>INFO-01 — Verbose Database / Driver Error Disclosure</h3>
      <span class="sev medium">Medium</span>
    </div>
    <div class="finding-body">
      <table class="finding-meta">
        <tr><td>Finding ID</td><td>INFO-01</td></tr>
        <tr><td>Module Name</td><td>Listings / Notifications</td></tr>
        <tr><td>Feature Name</td><td>Error handling across DB-backed endpoints</td></tr>
        <tr><td>Page Name</td><td>N/A (API)</td></tr>
        <tr><td>Full URL</td><td>Multiple — listings/:id, listings/getParishStats, notifications/users, listings/:zip/postal_code</td></tr>
        <tr><td>API Endpoint</td><td>Multiple (see Full URL)</td></tr>
        <tr><td>HTTP Method</td><td>GET</td></tr>
        <tr><td>Parameter Name</td><td>Multiple</td></tr>
        <tr><td>Input Type</td><td>Path / Query</td></tr>
        <tr><td>Authentication Required</td><td>Yes</td></tr>
        <tr><td>Assessment Status</td><td><span class="status confirmed">Confirmed</span></td></tr>
        <tr><td>Issue Found</td><td><strong>Yes</strong></td></tr>
        <tr><td>SQL Injection Technique Evaluated</td><td>Error Handling Review</td></tr>
        <tr><td>Severity</td><td><span class="sev medium">Medium</span></td></tr>
        <tr><td>Confidence</td><td>High</td></tr>
        <tr><td>CWE Mapping</td><td>CWE-209; CWE-211</td></tr>
        <tr><td>OWASP Category</td><td>A05:2021 – Security Misconfiguration; WSTG-ERRH-01/02</td></tr>
        <tr><td>CVSS Score</td><td>5.3 (AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N)</td></tr>
      </table>

      <h4>Business Impact</h4>
      <p>Confirms datastore (MongoDB), ODM (Mongoose), collection/field names, and query construction — accelerating targeted attacks. Cluster signature/keyId leakage is unnecessary internal exposure.</p>

      <h4>Description</h4>
      <p>Raw Mongoose/MongoDB driver errors are returned to clients, including cast failures, aggregation-pipeline internals, and regex compilation objects with cluster metadata.</p>

      <h4>Expected Secure Behavior</h4>
      <p>Generic client-facing error with correlation ID; full detail logged server-side only.</p>

      <h4>Observed Result</h4>
      <p>Clients receive detailed ODM/driver messages and, in one case, a raw MongoDB driver object including <code>code:51091</code>, <code>codeName:"Location51091"</code>, and <code>$clusterTime</code> signature metadata.</p>

      <h4>Evidence</h4>
      <ul>
        <li><code>{"statusCode":500,"message":"Cast to ObjectId failed for value \\"1'\\" (type string) at path \\"_id\\" for model \\"Listing\\""}</code></li>
        <li><code>{"statusCode":500,"message":"invalid argument to $limit stage: Expected an integer, but found NaN in: $limit: nan.0"}</code></li>
        <li>Regex error body included MongoDB driver object with <code>code:51091</code> and <code>$clusterTime.signature.hash/keyId</code>.</li>
      </ul>

      <h4>Developer Recommendation</h4>
      <p>Implement a global Express error handler; never serialise driver error objects to clients; set <code>NODE_ENV=production</code>.</p>

      <h4>Remediation Steps</h4>
      <ol>
        <li>Add a centralized error middleware returning <code>{"message":"Internal server error","correlationId":"..."}</code>.</li>
        <li>Log full stack/driver detail server-side only.</li>
        <li>Ensure production deployments set <code>NODE_ENV=production</code>.</li>
        <li>Retest previously leaking endpoints to confirm generic responses.</li>
      </ol>

      <h4>References</h4>
      <p>OWASP WSTG-ERRH-01; CWE-209; CWE-211.</p>
    </div>
  </article>
</section>

<section class="page-break section">
  <!-- FINDING INFO-02 -->
  <article class="finding low avoid-break" id="finding-info-02">
    <div class="finding-head">
      <h3>INFO-02 — Unhandled Null-Dereference Exceptions</h3>
      <span class="sev low">Low</span>
    </div>
    <div class="finding-body">
      <table class="finding-meta">
        <tr><td>Finding ID</td><td>INFO-02</td></tr>
        <tr><td>Module Name</td><td>Listings</td></tr>
        <tr><td>Feature Name</td><td>Listing retrieval / city stats</td></tr>
        <tr><td>Page Name</td><td>N/A (API)</td></tr>
        <tr><td>Full URL</td><td>https://devapi.falaya.com/api/listings/:id ; https://devapi.falaya.com/api/listings/getCityStats</td></tr>
        <tr><td>API Endpoint</td><td>/api/listings/:id , /api/listings/getCityStats</td></tr>
        <tr><td>HTTP Method</td><td>GET</td></tr>
        <tr><td>Parameter Name</td><td>id (and related lookup inputs)</td></tr>
        <tr><td>Input Type</td><td>ObjectId / Path</td></tr>
        <tr><td>Authentication Required</td><td>Yes</td></tr>
        <tr><td>Assessment Status</td><td><span class="status confirmed">Confirmed</span></td></tr>
        <tr><td>Issue Found</td><td><strong>Yes</strong></td></tr>
        <tr><td>SQL Injection Technique Evaluated</td><td>Error Handling Review; Parameter Handling Review</td></tr>
        <tr><td>Severity</td><td><span class="sev low">Low</span></td></tr>
        <tr><td>Confidence</td><td>High</td></tr>
        <tr><td>CWE Mapping</td><td>CWE-476; CWE-754</td></tr>
        <tr><td>OWASP Category</td><td>A04:2021 – Insecure Design / robustness; WSTG-ERRH</td></tr>
        <tr><td>CVSS Score</td><td>4.3 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L)</td></tr>
      </table>

      <h4>Business Impact</h4>
      <p>Attacker can reliably trigger server-side exceptions; at scale this contributes to instability and noisy error channels; confirms weak input/return-value validation.</p>

      <h4>Description</h4>
      <p>Missing null checks after database lookups lead to <code>Cannot read property 'status' of null</code> when a well-formed-but-absent ObjectId (or similar) is supplied.</p>

      <h4>Expected Secure Behavior</h4>
      <p>Return a clean HTTP 404 when a document is not found; never dereference null query results.</p>

      <h4>Observed Result</h4>
      <p><code>{"statusCode":500,"message":"Cannot read property 'status' of null"}</code></p>

      <h4>Evidence</h4>
      <p>Observed on <code>listings/:id</code> (example path with absent ObjectId) and <code>listings/getCityStats</code> during assessment probing. Reproducibility: Deterministic.</p>

      <h4>Developer Recommendation</h4>
      <p>Check for null documents after every <code>findById</code>/<code>findOne</code> and return 404 cleanly. Add defensive guards before property access.</p>

      <h4>Remediation Steps</h4>
      <ol>
        <li>After each DB lookup, if result is null/undefined, return 404.</li>
        <li>Add unit/integration tests for missing documents.</li>
        <li>Ensure the global error handler (INFO-01) still returns generic messages for unexpected exceptions.</li>
      </ol>

      <h4>References</h4>
      <p>CWE-476; CWE-754.</p>
    </div>
  </article>

  <div class="callout-warn avoid-break">
    <strong>Related observations (outside SQLi scope, from assessment Appendix A):</strong>
    excessively long-lived JWT (<code>exp</code> effectively non-expiring) and CORS wildcard
    <code>access-control-allow-origin: *</code>. These are awareness items only and are not scored as SQLi findings.
  </div>
</section>

<!-- ===================== RECOMMENDATIONS ===================== -->
<section class="page-break section" id="recommendations">
  <h2>11. Recommendations</h2>

  <h3>Immediate Actions</h3>
  <ul>
    <li>Fix NoSQLi-01: replace <code>$regex</code> on <code>postal_code</code> with exact-match query + strict validation.</li>
    <li>Stop returning raw MongoDB/Mongoose driver errors to clients (INFO-01).</li>
  </ul>

  <h3>High Priority Fixes</h3>
  <ul>
    <li>P1 — NoSQLi-01 (<code>postal_code</code> $regex injection): exact match + <code>^\\d{5}(-\\d{4})?$</code> validation.</li>
    <li>P2 — INFO-01: global Express error handler; <code>NODE_ENV=production</code>; no driver object serialisation.</li>
  </ul>

  <h3>Medium Priority Fixes</h3>
  <ul>
    <li>P3 — Audit all <code>$regex</code> / dynamic query usage across search/filter/sort endpoints for the same unescaped-input pattern.</li>
    <li>P4 — INFO-02: null-result checks after DB lookups; clean 404s.</li>
  </ul>

  <h3>Low Priority Improvements</h3>
  <ul>
    <li>P5 — Schema validation middleware on every route; ReDoS-safe regex handling; query <code>maxTimeMS</code>.</li>
    <li>Review JWT lifetime and tighten CORS origin allow-list (Appendix awareness items).</li>
  </ul>

  <h3>Secure Coding Best Practices</h3>
  <ul>
    <li>Treat all path/query/body/header values as untrusted.</li>
    <li>Bind values as typed exact-match query fields; never as query operators or regex source.</li>
    <li>Reject object-valued scalar fields (blocks <code>$ne</code>/<code>$gt</code> operator injection), e.g. <code>express-mongo-sanitize</code>.</li>
  </ul>

  <h3>Database Security Recommendations</h3>
  <ul>
    <li>Principle of least privilege for the database account.</li>
    <li>Set per-query <code>maxTimeMS</code>; avoid raw <code>$where</code>/<code>$expr</code> with user input.</li>
    <li>Prefer MongoDB text indexes over raw <code>$regex</code> for search features.</li>
  </ul>

  <h3>Input Validation Recommendations</h3>
  <ul>
    <li>Allow-list validation at every route boundary (path, query, body, header).</li>
    <li>Strict formats for postal codes, ObjectIds, numeric pagination fields.</li>
    <li>Use Joi / Zod / express-validator consistently.</li>
  </ul>

  <h3>Parameterized Query Recommendations</h3>
  <ul>
    <li>Although no SQL engine is present, the equivalent for MongoDB is typed ODM queries with bound values — never string-concatenated query fragments or unescaped regex sources.</li>
    <li>If a SQL datastore is introduced later, use prepared statements / parameterized queries exclusively (OWASP SQL Injection Prevention Cheat Sheet).</li>
  </ul>

  <h3>Error Handling Recommendations</h3>
  <ul>
    <li>Generic client messages + correlation IDs.</li>
    <li>Full detail logged server-side only.</li>
    <li>Never return stack traces, ODM cast messages, or driver objects in production responses.</li>
  </ul>

  <h3>Developer Checklist</h3>
  <ul class="checklist">
    <li><code>postal_code</code> (and all lookups) use exact-match queries, not <code>$regex</code> on raw input.</li>
    <li>Strict input validation/allow-lists on every path, query, body, and header parameter.</li>
    <li><code>express-mongo-sanitize</code> (or equivalent) rejects object-valued scalar fields.</li>
    <li>All dynamic <code>$regex</code>/<code>$where</code>/<code>$expr</code> usages audited and escaped/removed.</li>
    <li>Global error handler hides driver/ODM internals; <code>NODE_ENV=production</code>.</li>
    <li>Null checks after every <code>findById</code>/<code>findOne</code>; clean 404 on not-found.</li>
    <li>Query <code>maxTimeMS</code> and ReDoS-safe regex handling in place.</li>
    <li>DB account runs with least privilege.</li>
    <li>Automated SAST/DAST covers injection (SQL and NoSQL) in CI.</li>
    <li>JWT lifetime reviewed and CORS policy tightened.</li>
  </ul>
</section>

<!-- ===================== APPENDIX ===================== -->
<section class="page-break section" id="appendix">
  <h2>12. Appendix</h2>

  <h3>12.1 Testing Methodology</h3>
  <p>
    Grey-box assessment with a low-privilege authenticated user JWT. Read-only / non-mutating endpoints only.
    No database dumping, record extraction, or data modification. Time-based payloads limited to ~3-second sleeps.
    On confirmation of regex injection, testing stopped at proof-of-concept (population-count differential).
  </p>

  <h3>12.2 OWASP References</h3>
  <ul>
    <li>OWASP Web Security Testing Guide — WSTG-INPV-05 (Testing for SQL Injection)</li>
    <li>OWASP Web Security Testing Guide — WSTG-INPV-06 (Testing for NoSQL Injection)</li>
    <li>OWASP SQL Injection Prevention Cheat Sheet</li>
    <li>OWASP Top 10:2021 — A03 Injection; A04 Insecure Design; A05 Security Misconfiguration</li>
    <li>OWASP WSTG-ERRH-01 / WSTG-ERRH-02 (Error Handling)</li>
  </ul>

  <h3>12.3 CWE References</h3>
  <ul>
    <li>CWE-943 — Improper Neutralization of Special Elements in Data Query Logic</li>
    <li>CWE-1333 — Inefficient Regular Expression Complexity</li>
    <li>CWE-209 — Generation of Error Message Containing Sensitive Information</li>
    <li>CWE-211 — Internally Generated Error Message Containing Sensitive Information</li>
    <li>CWE-476 — NULL Pointer Dereference</li>
    <li>CWE-754 — Improper Check for Unusual Conditions</li>
  </ul>

  <h3>12.4 Glossary</h3>
  <table class="avoid-break">
    <thead><tr><th>Term</th><th>Definition</th></tr></thead>
    <tbody>
      <tr><td>SQL Injection (SQLi)</td><td>Injection of untrusted input into a SQL query, altering query logic.</td></tr>
      <tr><td>NoSQL Injection</td><td>Injection affecting NoSQL query construction (operators, regex, etc.).</td></tr>
      <tr><td>$regex</td><td>MongoDB query operator that matches string fields using regular expressions.</td></tr>
      <tr><td>ODM</td><td>Object-Document Mapper (here: Mongoose for MongoDB).</td></tr>
      <tr><td>CVSS</td><td>Common Vulnerability Scoring System.</td></tr>
      <tr><td>ReDoS</td><td>Regular Expression Denial of Service.</td></tr>
      <tr><td>Grey-box</td><td>Testing with partial knowledge / authenticated access.</td></tr>
    </tbody>
  </table>

  <h3>12.5 Abbreviations</h3>
  <table class="avoid-break">
    <thead><tr><th>Abbreviation</th><th>Meaning</th></tr></thead>
    <tbody>
      <tr><td>API</td><td>Application Programming Interface</td></tr>
      <tr><td>CWE</td><td>Common Weakness Enumeration</td></tr>
      <tr><td>JWT</td><td>JSON Web Token</td></tr>
      <tr><td>ODM</td><td>Object-Document Mapper</td></tr>
      <tr><td>OWASP</td><td>Open Worldwide Application Security Project</td></tr>
      <tr><td>REST</td><td>Representational State Transfer</td></tr>
      <tr><td>SQLi</td><td>SQL Injection</td></tr>
      <tr><td>WSTG</td><td>Web Security Testing Guide</td></tr>
    </tbody>
  </table>

  <h3>12.6 Evidence Artifacts (from assessment)</h3>
  <ul>
    <li>Datastore fingerprints: Mongoose Cast to ObjectId; aggregation $limit/$skip NaN; MongoDB regex 51091.</li>
    <li>NoSQLi oracle: <code>.*</code>→392, <code>a||b</code>→392, <code>^7</code>→9, <code>(</code>→regex error, clean→0.</li>
    <li>Auth resilience: identical incorrect-credentials response for SQL/NoSQL payloads with no token.</li>
  </ul>

  <div class="footer-note">
    Prepared in accordance with OWASP WSTG-INPV-05 and the OWASP SQL Injection Prevention Cheat Sheet.
    Findings are limited to what was safely and reproducibly evidenced in the completed assessment;
    no vulnerability is claimed without supporting proof. This PDF was generated as a professional
    export of those results for developers, QA, project managers, and security auditors.
  </div>
</section>

</body>
</html>`;
}

async function main() {
  const html = buildHtml();
  fs.writeFileSync(HTML_PATH, html, 'utf8');
  console.log('Wrote HTML:', HTML_PATH);

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.goto('file:///' + HTML_PATH.replace(/\\/g, '/'), { waitUntil: 'networkidle' });

  await page.pdf({
    path: PDF_PATH,
    format: 'A4',
    printBackground: true,
    displayHeaderFooter: true,
    headerTemplate: `
      <div style="font-size:8px; width:100%; padding:0 16mm; color:#64748b; display:flex; justify-content:space-between; font-family:Segoe UI, Arial, sans-serif;">
        <span>Falaya Dev — SQL Injection Security Assessment</span>
        <span>Confidential</span>
      </div>`,
    footerTemplate: `
      <div style="font-size:8px; width:100%; padding:0 16mm; color:#64748b; display:flex; justify-content:space-between; font-family:Segoe UI, Arial, sans-serif;">
        <span>OWASP WSTG-INPV-05 | Document v1.0</span>
        <span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
      </div>`,
    margin: { top: '18mm', bottom: '18mm', left: '14mm', right: '14mm' },
    outline: true,
    tagged: true,
  });

  await browser.close();
  console.log('Wrote PDF:', PDF_PATH);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
