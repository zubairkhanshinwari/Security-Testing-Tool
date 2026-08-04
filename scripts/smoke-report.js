const { buildHtmlReport } = require('../src/report/htmlReport');
const { getSeverity, setSeverity } = require('../src/scanner/severity');

const f = {
  id: 'FIND-01',
  issueFound: true,
  cvss: 7.5,
  title: 'NoSQL regex injection',
  cwe: ['CWE-943'],
  endpoint: 'https://devapi.falaya.com/api/listings/{postal_code}/postal_code',
  affectedEndpoints: [
    'https://devapi.falaya.com/api/listings/{postal_code}/postal_code',
    'https://api.falaya.com/api/listings/{postal_code}/postal_code',
  ],
  module: 'REST API',
  parameter: 'postal_code',
  techniques: ['Parameter Handling Review'],
  status: 'Confirmed',
  confidence: 'High',
  owasp: 'A03',
  description: 'test',
  method: 'GET',
  inputType: 'Path',
  authRequired: true,
  featureName: 'Path',
  pageName: 'API',
  evidence: [],
};
setSeverity(f, 'High');

const m = {
  id: 'FIND-02',
  issueFound: true,
  cvss: 5.3,
  title: 'Verbose error disclosure',
  cwe: ['CWE-209'],
  endpoint: 'https://devapi.falaya.com/api/listings/{id}',
  module: 'REST API',
  parameter: 'id',
  techniques: ['Error Handling Review'],
  status: 'Confirmed',
  confidence: 'High',
  owasp: 'A05',
  description: 'test',
  method: 'GET',
  inputType: 'Path',
  authRequired: false,
  featureName: 'Path',
  pageName: 'API',
  evidence: [],
};
setSeverity(m, 'Medium');

const l = {
  id: 'FIND-03',
  issueFound: true,
  cvss: 4.3,
  title: 'Null deref',
  cwe: ['CWE-476'],
  endpoint: 'https://devapi.falaya.com/api/listings/{id}',
  module: 'REST API',
  parameter: 'id',
  techniques: ['Error Handling Review'],
  status: 'Confirmed',
  confidence: 'High',
  owasp: 'A04',
  description: 'test',
  method: 'GET',
  inputType: 'Path',
  authRequired: false,
  featureName: 'Path',
  pageName: 'API',
  evidence: [],
};
setSeverity(l, 'Low');

const html = buildHtmlReport({
  meta: {
    startedAt: new Date().toISOString(),
    projectName: 'Falaya Dev',
    targetUrl: 'https://dev.falaya.com/',
    environment: 'Development',
    testerName: 'Tester',
    durationMinutes: 1,
  },
  findings: [f, m, l],
  assessmentSummary: [
    { module: 'REST API', urlsTested: 3, parametersTested: 3, findings: 3, highestSeverity: 'High' },
  ],
  recon: { pageTitle: 'Falaya', forms: 0, linksVisited: 1, apisObserved: 3, querySurfaces: 0 },
  stats: {
    totalFindings: 3,
    confirmedSqli: 0,
    securityScore: 72,
    overallRisk: 'High',
    severityCounts: { Critical: 0, High: 1, Medium: 1, Low: 1, Informational: 0 },
    authGap: true,
    endpointsTested: 3,
    parametersTested: 3,
    modulesTested: 1,
  },
});

const checks = {
  highBadge: /High/i.test(html) && /sev high|class="sev high"/i.test(html),
  mediumBadge: /Medium/i.test(html),
  lowBadge: /Low/i.test(html),
  authCallout: /Authenticated testing incomplete|JWT/i.test(html),
  svg: /<svg/i.test(html),
  score72: html.includes('72'),
  affected: /affectedEndpoints|Affected Endpoints/i.test(html),
  getSeverityHigh: getSeverity(f) === 'High',
};

console.log(checks);
if (!Object.values(checks).every(Boolean)) process.exit(1);
console.log('smoke-report ok');
