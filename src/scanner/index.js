const { chromium } = require('playwright');
const { URL } = require('url');
const { discoverSurfaces, isAppApiUrl } = require('./recon');
const { probeGetParam, probeJsonAuth, probePathParam } = require('./probes');
const { getSeverity, setSeverity, normalizeSeverity } = require('./severity');
const { DEFAULT_SELECTED, expandSecurityTypes, isSelected } = require('./securityTypes');
const { loginWithCredentials } = require('./login');
const { runSurfaceChecks } = require('./modules/surfaceChecks');

/** Match the manual assessment model: High −18, Medium −6, Low −4 */
function scoreFromFindings(findings) {
  let score = 100;
  for (const f of findings.filter((x) => x.issueFound)) {
    const sev = getSeverity(f);
    if (sev === 'Critical') score -= 30;
    else if (sev === 'High') score -= 18;
    else if (sev === 'Medium') score -= 6;
    else if (sev === 'Low') score -= 4;
  }
  return Math.max(0, Math.min(100, score));
}

function issueDedupeKey(f) {
  const cwe = (f.cwe && f.cwe[0]) || 'none';
  const sev = getSeverity(f) || 'Informational';
  if (cwe === 'CWE-943') return 'nosql-regex|High|CWE-943';
  if (cwe === 'CWE-89') return 'sqli|High|CWE-89';
  if (cwe === 'CWE-209') return 'error-disclosure|Medium|CWE-209';
  if (cwe === 'CWE-476') return 'null-deref|Low|CWE-476';
  return `${cwe}|${sev}|${(f.title || '').replace(/via.*/, '').trim().toLowerCase()}`;
}

function normalizeAuthHeader(value) {
  if (!value) return null;
  let v = String(value).trim();
  if (!v) return null;
  // Falaya-style APIs expect raw JWT in Authorization (no Bearer prefix required)
  if (/^bearer\s+/i.test(v)) return v;
  return v;
}

function overallRisk(findings) {
  const order = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
  let best = 'Informational';
  for (const f of findings.filter((x) => x.issueFound)) {
    const sev = getSeverity(f);
    if (order.indexOf(sev) < order.indexOf(best)) best = sev;
  }
  if (!findings.some((f) => f.issueFound)) return 'Low';
  return best;
}

function countBySeverity(findings) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
  for (const f of findings.filter((x) => x.issueFound)) {
    const sev = normalizeSeverity(getSeverity(f), f.cvss);
    setSeverity(f, sev);
    counts[sev] += 1;
  }
  return counts;
}

function guessAuthEndpoints(apis, apiBases, origin) {
  const out = [];
  for (const a of apis) {
    const u = a.url.toLowerCase();
    if (/(auth\/signin|auth\/login|\/login|\/signin|auth\/forgot)/i.test(u)) {
      out.push(a.url.split('?')[0]);
    }
  }
  for (const base of apiBases || []) {
    try {
      const originBase = base.includes('://') ? new URL(base).origin : base;
      const root = /\/api$/i.test(base) ? base : `${originBase}/api`;
      out.push(
        `${root}/auth/signin`,
        `${root}/auth/login`,
        `${root}/auth/forgot`,
        `${root}/login`
      );
    } catch {
      // ignore
    }
  }
  out.push(`${origin}/api/auth/signin`, `${origin}/login`);
  return [...new Set(out)];
}

function extractPathTemplates(apis, apiBases) {
  const templates = new Set();

  for (const a of apis) {
    try {
      const u = new URL(a.url);
      const parts = u.pathname.split('/').filter(Boolean);
      if (!parts.length) continue;

      // Explicit placeholders already present
      if (u.pathname.includes('{') && u.pathname.includes('}')) {
        templates.add(`${u.origin}${u.pathname}`);
        continue;
      }

      const last = parts[parts.length - 1];
      if (/^[0-9a-f]{24}$/i.test(last) || /^\d+$/.test(last)) {
        const copy = [...parts];
        copy[copy.length - 1] = '{id}';
        templates.add(`${u.origin}/${copy.join('/')}`);
      }

      const idx = parts.findIndex((p) => p === 'postal_code');
      if (idx > 0) {
        const copy = [...parts];
        copy[idx - 1] = '{postal_code}';
        templates.add(`${u.origin}/${copy.join('/')}`);
      }
    } catch {
      // ignore
    }
  }

  // Always seed high-value templates on discovered API bases
  for (const base of apiBases || []) {
    try {
      const originBase = base.includes('://') ? new URL(base).origin : base;
      const root = /\/api$/i.test(base) ? base : `${originBase}/api`;
      templates.add(`${root}/listings/{postal_code}/postal_code`);
      templates.add(`${root}/listings/{id}`);
      templates.add(`${root}/documents/{id}`);
      templates.add(`${root}/users/{id}`);
    } catch {
      // ignore
    }
  }

  // Prioritize postal_code / id templates
  return [...templates]
    .sort((a, b) => {
      const rank = (u) =>
        /postal_code/i.test(u) ? 0 : /\{id\}/i.test(u) ? 1 : 2;
      return rank(a) - rank(b);
    })
    .slice(0, 16);
}

function extractApiQueryTargets(apis, targetUrl) {
  const out = [];
  for (const api of apis) {
    if (api.method !== 'GET') continue;
    if (!isAppApiUrl(api.url, targetUrl) && api.source !== 'bundle') continue;
    try {
      const u = new URL(api.url);
      const params = [...u.searchParams.keys()];
      if (!params.length) continue;
      out.push({
        baseUrl: `${u.origin}${u.pathname}`,
        parameters: params,
        authHeader: api.authHeader,
        fullUrl: api.url,
      });
    } catch {
      // ignore
    }
  }
  return out;
}

/**
 * Run an authorized, non-destructive security assessment for selected test types.
 */
async function runAssessment(options) {
  const {
    targetUrl,
    projectName = 'Web Security Assessment',
    environment = 'Unknown',
    testerName = 'Security Assessment Tool',
    authHeader = null,
    username = null,
    password = null,
    securityTypes = DEFAULT_SELECTED,
    maxParams = 25,
    onProgress = () => {},
  } = options;

  const selectedTypes = expandSecurityTypes(
    Array.isArray(securityTypes) && securityTypes.length ? securityTypes : DEFAULT_SELECTED
  );
  const runInjection =
    isSelected(selectedTypes, 'sqli') ||
    isSelected(selectedTypes, 'nosqli') ||
    isSelected(selectedTypes, 'injection');

  const startedAt = new Date();
  onProgress({ stage: 'launch', message: 'Launching browser…' });

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    userAgent: 'SecurityAssessmentTool/1.0 (+authorized-testing; Playwright)',
  });
  const page = await context.newPage();

  let recon;
  try {
    onProgress({ stage: 'recon', message: 'Discovering forms, JS API routes, and backends…' });
    recon = await discoverSurfaces(page, targetUrl, { maxLinks: 8 });
  } catch (err) {
    await browser.close();
    throw new Error(`Reconnaissance failed: ${err.message}`);
  }

  const origin = new URL(targetUrl).origin;
  const apiBases = recon.apiBases || [];
  let loginInfo = { ok: false, message: 'No credentials provided' };

  let effectiveAuth = normalizeAuthHeader(authHeader);
  if (!effectiveAuth && username && password) {
    onProgress({ stage: 'auth', message: 'Logging in with provided username/password…' });
    loginInfo = await loginWithCredentials(page, {
      username,
      password,
      apiBases,
      origin,
    });
    if (loginInfo.ok && loginInfo.token) {
      effectiveAuth = normalizeAuthHeader(loginInfo.token);
      try {
        await page.evaluate((tok) => {
          localStorage.setItem('access_u_token', tok);
          localStorage.setItem('access_token', tok);
        }, effectiveAuth);
      } catch {
        // ignore
      }
      onProgress({ stage: 'auth', message: loginInfo.message || 'Login successful' });
    } else {
      onProgress({ stage: 'auth', message: loginInfo.message || 'Login failed' });
    }
  }

  if (!effectiveAuth) {
    const fromTraffic = recon.apis.find((a) => a.authHeader)?.authHeader;
    if (fromTraffic) effectiveAuth = normalizeAuthHeader(fromTraffic);
  }
  if (!effectiveAuth && recon.discoveredToken) {
    effectiveAuth = normalizeAuthHeader(recon.discoveredToken);
  }

  if (effectiveAuth) {
    await context.setExtraHTTPHeaders({ authorization: effectiveAuth });
  }

  const findings = [];

  onProgress({
    stage: 'recon',
    message: `Types: ${selectedTypes.length} · API bases: ${apiBases.slice(0, 3).join(', ') || 'none'}`,
  });

  // Surface / config / auth / header modules
  onProgress({ stage: 'probe', message: 'Running selected surface security checks…' });
  try {
    const surfaceFindings = await runSurfaceChecks(page, targetUrl, selectedTypes, { apiBases });
    // If we obtained a JWT via login, re-run JWT check with token in storage already set
    findings.push(...surfaceFindings);
  } catch {
    // continue
  }

  // Injection modules (SQLi / NoSQLi)
  let authBlockedCount = 0;
  let probed = 0;
  if (runInjection) {
    onProgress({ stage: 'probe', message: 'Probing API path parameters…' });
    for (const template of extractPathTemplates(recon.apis, apiBases)) {
      try {
        onProgress({ stage: 'probe', message: `PATH ${template}` });
        const results = await probePathParam(page, template, effectiveAuth);
        const list = Array.isArray(results) ? results : [results];
        for (const result of list) {
          if (result.authBlocked) authBlockedCount += 1;
          result.module = 'REST API';
          result.featureName = 'Path parameter';
          result.pageName = recon.pageInfo.title || 'API';
          result.fullUrl = template;
          findings.push(result);
        }
      } catch {
        // continue
      }
    }

    onProgress({ stage: 'probe', message: 'Probing authentication endpoints…' });
    for (const endpoint of guessAuthEndpoints(recon.apis, apiBases, origin).slice(0, 6)) {
      try {
        onProgress({ stage: 'probe', message: `AUTH ${endpoint}` });
        const result = await probeJsonAuth(page, endpoint, null);
        const all404 = (result.evidence || []).every((e) => e.status === 404);
        if (all404 && (result.baseline?.status === 404 || result.baseline?.status === 0)) continue;
        result.module = 'Authentication';
        result.featureName = 'Login / credential submission';
        result.pageName = 'Login';
        result.fullUrl = endpoint;
        findings.push(result);
      } catch {
        // continue
      }
    }

    onProgress({ stage: 'probe', message: 'Probing API query parameters…' });
    for (const surface of extractApiQueryTargets(recon.apis, targetUrl)) {
      for (const param of surface.parameters) {
        if (probed >= maxParams) break;
        if (/^(utm_|fbclid|gclid|v$|_v|tid|cid|gtm)/i.test(param)) continue;
        onProgress({ stage: 'probe', message: `GET ${surface.baseUrl}?${param}` });
        try {
          const result = await probeGetParam(
            page,
            surface.baseUrl,
            param,
            effectiveAuth || surface.authHeader
          );
          result.module = 'REST API';
          result.featureName = 'API query parameter';
          result.pageName = recon.pageInfo.title || 'API';
          result.fullUrl = surface.fullUrl;
          findings.push(result);
          probed += 1;
        } catch {
          // continue
        }
      }
      if (probed >= maxParams) break;
    }

    onProgress({ stage: 'probe', message: 'Probing page query parameters…' });
    for (const surface of recon.querySurfaces.slice(0, 8)) {
      for (const param of surface.parameters.slice(0, 3)) {
        if (probed >= maxParams + 8) break;
        if (/^(utm_|fbclid|gclid)/i.test(param)) continue;
        try {
          const result = await probeGetParam(page, surface.baseUrl, param, effectiveAuth);
          result.module = 'Query Parameters';
          result.featureName = 'URL query input';
          result.pageName = recon.pageInfo.title || 'Application';
          result.fullUrl = `${surface.baseUrl}?${param}=…`;
          findings.push(result);
          probed += 1;
        } catch {
          // continue
        }
      }
    }

    onProgress({ stage: 'probe', message: 'Probing HTML form fields…' });
    for (const form of recon.pageInfo.forms.slice(0, 5)) {
      if (form.method !== 'GET') continue;
      for (const field of form.fields.slice(0, 4)) {
        try {
          const action = form.action || targetUrl;
          const result = await probeGetParam(page, action.split('?')[0], field.name, effectiveAuth);
          result.module = 'Forms';
          result.featureName = 'HTML form field';
          result.pageName = recon.pageInfo.title || 'Form page';
          result.fullUrl = action;
          result.inputType = `Form/${field.type || 'text'}`;
          findings.push(result);
        } catch {
          // continue
        }
      }
    }
  } else {
    onProgress({ stage: 'probe', message: 'Skipping injection probes (not selected)…' });
  }

  await browser.close();
  const finishedAt = new Date();

  // First pass: keep pass rows per endpoint+param; merge confirmed issues by vulnerability class
  const passMap = new Map();
  const issueMap = new Map();
  for (const f of findings) {
    setSeverity(f, normalizeSeverity(getSeverity(f), f.cvss));
    if (!f.issueFound) {
      const key = `${f.method}|${f.endpoint}|${f.parameter}|pass`;
      if (!passMap.has(key)) passMap.set(key, f);
      continue;
    }
    const key = issueDedupeKey(f);
    const prev = issueMap.get(key);
    if (!prev) {
      f.affectedEndpoints = [f.endpoint];
      issueMap.set(key, f);
    } else {
      prev.affectedEndpoints = [...new Set([...(prev.affectedEndpoints || [prev.endpoint]), f.endpoint])];
      prev.evidence = [...(prev.evidence || []), ...(f.evidence || [])].slice(0, 10);
      // Prefer the evidence-richer / higher-confidence record
      if ((f.evidence || []).length > (prev.evidence || []).length) {
        prev.description = f.description;
        prev.title = f.title;
      }
    }
  }
  const uniqueFindings = [...issueMap.values(), ...passMap.values()];

  let iSqli = 1;
  let iOther = 1;
  for (const f of uniqueFindings) {
    if (f.issueFound && f.cwe?.includes('CWE-89')) f.id = `SQLi-${String(iSqli++).padStart(2, '0')}`;
    else if (f.issueFound) f.id = `FIND-${String(iOther++).padStart(2, '0')}`;
    else f.id = `PASS-${String(iOther++).padStart(2, '0')}`;
  }

  const severityCounts = countBySeverity(uniqueFindings);
  const confirmedSqli = uniqueFindings.filter(
    (f) => f.issueFound && (f.cwe || []).includes('CWE-89')
  ).length;

  const modules = {};
  for (const f of uniqueFindings) {
    const m = f.module || 'Other';
    if (!modules[m]) modules[m] = { urls: new Set(), params: new Set(), findings: 0, highest: 'None' };
    modules[m].urls.add(f.endpoint);
    modules[m].params.add(f.parameter);
    if (f.issueFound) {
      modules[m].findings += 1;
      const order = ['Critical', 'High', 'Medium', 'Low', 'Informational', 'None'];
      const sev = getSeverity(f);
      if (order.indexOf(sev) < order.indexOf(modules[m].highest)) {
        modules[m].highest = sev;
      }
    }
  }

  const assessmentSummary = Object.entries(modules).map(([name, m]) => ({
    module: name,
    urlsTested: m.urls.size,
    parametersTested: m.params.size,
    findings: m.findings,
    highestSeverity: m.highest,
  }));

  const securityScore = scoreFromFindings(uniqueFindings);
  const risk = overallRisk(uniqueFindings);

  onProgress({ stage: 'done', message: 'Assessment complete' });

  return {
    meta: {
      projectName,
      targetUrl,
      environment,
      testerName,
      assessmentType: 'Web Security Assessment',
      standard: 'OWASP WSTG / OWASP Top 10 (2021)',
      startedAt: startedAt.toISOString(),
      finishedAt: finishedAt.toISOString(),
      durationMinutes: Math.max(1, Math.round((finishedAt - startedAt) / 60000)),
      authUsed: Boolean(effectiveAuth),
      loginAttempted: Boolean(username && password),
      loginSuccess: Boolean(loginInfo && loginInfo.ok),
      loginMessage: loginInfo ? loginInfo.message : null,
      securityTypes: selectedTypes,
    },
    recon: {
      pageTitle: recon.pageInfo.title,
      forms: recon.pageInfo.forms.length,
      linksVisited: recon.visitedUrls.length,
      apisObserved: recon.apis.length,
      querySurfaces: recon.querySurfaces.length,
      apiBases,
      bundleRoutes: (recon.bundleRoutes || []).slice(0, 40),
      apis: recon.apis.filter((a) => a.source !== 'bundle' || /auth|listing|notification|postal/i.test(a.url)).slice(0, 40),
      visitedUrls: recon.visitedUrls,
    },
    findings: uniqueFindings,
    assessmentSummary,
    stats: {
      totalFindings: uniqueFindings.filter((f) => f.issueFound).length,
      confirmedSqli,
      severityCounts,
      endpointsTested: new Set(uniqueFindings.map((f) => f.endpoint)).size,
      parametersTested: uniqueFindings.length,
      modulesTested: assessmentSummary.length,
      securityScore,
      overallRisk: risk,
      authUsed: Boolean(effectiveAuth),
      authGap: !effectiveAuth && authBlockedCount > 0,
      authBlockedCount,
    },
  };
}

module.exports = { runAssessment };
