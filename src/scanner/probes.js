const { URL } = require('url');
const {
  ERROR_STRING,
  BOOLEAN_TRUE,
  BOOLEAN_FALSE,
  TIME_BASED,
  NOSQL_OPERATORS,
  SQL_ERROR_MARKERS,
  NOSQL_ERROR_MARKERS,
} = require('./payloads');
const { SEVERITY_KEY } = require('./severity');

function hasAny(text, regexes) {
  return regexes.some((re) => re.test(text || ''));
}

/**
 * Use Playwright APIRequestContext (not in-page fetch) to avoid CORS and
 * reliably hit backend API hosts discovered from the frontend.
 */
async function timedFetch(page, url, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const headers = { ...(options.headers || {}) };
  const t0 = Date.now();
  try {
    const request = page.context().request;
    const res = await request.fetch(url, {
      method,
      headers,
      data: options.body,
      failOnStatusCode: false,
      timeout: 20000,
      maxRedirects: 5,
    });
    const text = await res.text();
    return {
      ok: true,
      status: res.status(),
      ms: Date.now() - t0,
      len: text.length,
      body: text.slice(0, 1200),
    };
  } catch (e) {
    return {
      ok: false,
      status: 0,
      ms: Date.now() - t0,
      len: 0,
      body: String(e && e.message ? e.message : e),
      error: true,
    };
  }
}

function classifyResponse(body, baseline, probe) {
  const sqlError = hasAny(body, SQL_ERROR_MARKERS);
  const nosqlError = hasAny(body, NOSQL_ERROR_MARKERS);
  const timeDelta = (probe.ms || 0) - (baseline.ms || 0);
  const lenDelta = Math.abs((probe.len || 0) - (baseline.len || 0));
  const statusDiff = probe.status !== baseline.status;

  return {
    sqlError,
    nosqlError,
    timeDelta,
    lenDelta,
    statusDiff,
    suspiciousTime: timeDelta >= 2500,
    suspiciousBoolean: statusDiff || lenDelta >= 40,
  };
}

/**
 * Probe a GET query parameter safely.
 */
async function probeGetParam(page, baseUrl, param, authHeader) {
  const headers = { accept: 'application/json,text/html,*/*' };
  if (authHeader) headers.authorization = authHeader;

  const build = (value) => {
    const u = new URL(baseUrl);
    u.searchParams.set(param, value);
    return u.toString();
  };

  const baseline = await timedFetch(page, build('1'), { headers, method: 'GET' });
  const evidence = [];
  let issue = false;
  let severity = null;
  let techniques = [];
  let title = null;
  let description = null;
  let cwe = [];
  let owasp = 'A03:2021 – Injection; WSTG-INPV-05';
  let cvss = null;

  // Error-based
  for (const payload of ERROR_STRING.slice(0, 3)) {
    const r = await timedFetch(page, build(payload), { headers, method: 'GET' });
    const c = classifyResponse(r.body, baseline, r);
    evidence.push({ technique: 'Error Handling Review', payload, ...r, ...c });
    if (c.sqlError) {
      issue = true;
      severity = 'High';
      title = `Error-based SQL Injection indicator in parameter "${param}"`;
      description =
        'Server responses include SQL engine error patterns when special characters are supplied, indicating unsanitized input may reach a SQL query.';
      techniques = ['Error Handling Review'];
      cwe = ['CWE-89'];
      cvss = 8.6;
      break;
    }
    if (c.nosqlError && /\$regex|invalid regular expression|location51091/i.test(r.body)) {
      issue = true;
      severity = 'High';
      title = `NoSQL / regex injection indicator in parameter "${param}"`;
      description =
        'Server responses include MongoDB/Mongoose regex or cast errors suggesting user input reaches query construction unsafely.';
      techniques = ['Error Handling Review', 'Input Validation Review'];
      cwe = ['CWE-943'];
      owasp = 'A03:2021 – Injection; WSTG-INPV-06';
      cvss = 7.5;
      break;
    }
  }

  // Boolean differential (only if no confirmed error-based yet for SQLi)
  if (!issue) {
    const t = await timedFetch(page, build(BOOLEAN_TRUE[0]), { headers, method: 'GET' });
    const f = await timedFetch(page, build(BOOLEAN_FALSE[0]), { headers, method: 'GET' });
    evidence.push({ technique: 'Boolean Logic Validation', payload: BOOLEAN_TRUE[0], ...t });
    evidence.push({ technique: 'Boolean Logic Validation', payload: BOOLEAN_FALSE[0], ...f });
    const lenGap = Math.abs((t.len || 0) - (f.len || 0));
    const statusGap = t.status !== f.status;
    if ((statusGap || lenGap >= 80) && t.status < 500 && f.status < 500) {
      issue = true;
      severity = 'Medium';
      title = `Boolean-based SQL Injection indicator in parameter "${param}"`;
      description =
        'True/false boolean payloads produced a meaningful response differential (status or length), which can indicate blind SQL injection.';
      techniques = ['Boolean Logic Validation'];
      cwe = ['CWE-89'];
      cvss = 7.5;
    }
  }

  // Time-based (single safe sleep payload)
  if (!issue) {
    const r = await timedFetch(page, build(TIME_BASED[0]), { headers, method: 'GET' });
    const c = classifyResponse(r.body, baseline, r);
    evidence.push({ technique: 'Time-Based Validation', payload: TIME_BASED[0], ...r, ...c });
    if (c.suspiciousTime) {
      issue = true;
      severity = 'High';
      title = `Time-based SQL Injection indicator in parameter "${param}"`;
      description =
        'A time-delay payload increased response latency by ≥2.5s versus baseline, which can indicate time-based blind SQL injection.';
      techniques = ['Time-Based Validation'];
      cwe = ['CWE-89'];
      cvss = 8.1;
    }
  }

  // Regex oracle for path-like values (postal-style)
  if (!issue && /postal|zip|code|search|q|query|filter|id/i.test(param)) {
    const clean = await timedFetch(page, build('00000'), { headers, method: 'GET' });
    const star = await timedFetch(page, build('.*'), { headers, method: 'GET' });
    evidence.push({ technique: 'Parameter Handling Review', payload: '.*', ...star });
    if ((star.len || 0) - (clean.len || 0) > 5000 || /\"count\":\s*[1-9]/i.test(star.body)) {
      issue = true;
      severity = 'High';
      title = `Possible NoSQL regex / query broadening in parameter "${param}"`;
      description =
        'Payload ".*" returned a substantially larger response than a non-matching baseline, consistent with unescaped regex query usage.';
      techniques = ['Parameter Handling Review', 'Input Validation Review'];
      cwe = ['CWE-943'];
      owasp = 'A03:2021 – Injection; WSTG-INPV-06';
      cvss = 7.5;
    }
  }

  // Verbose error disclosure (informational/medium), only if no higher issue
  if (!issue) {
    const leak = evidence.find(
      (e) =>
        e.sqlError ||
        e.nosqlError ||
        /stack|exception|at Object\.|Cast to ObjectId|Internal server error/i.test(e.body || '')
    );
    if (leak && (leak.sqlError || leak.nosqlError || /Cast to ObjectId|\$limit|\$skip/i.test(leak.body || ''))) {
      issue = true;
      severity = 'Medium';
      title = `Verbose database / application error disclosure via parameter "${param}"`;
      description =
        'Malformed input triggers detailed database/ODM/driver errors returned to the client, aiding attackers in fingerprinting the stack.';
      techniques = ['Error Handling Review'];
      cwe = ['CWE-209'];
      owasp = 'A05:2021 – Security Misconfiguration; WSTG-ERRH-01';
      cvss = 5.3;
    }
  }

  return {
    endpoint: baseUrl,
    method: 'GET',
    parameter: param,
    inputType: 'Query',
    authRequired: Boolean(authHeader),
    issueFound: issue,
    severity: severity || 'Informational',
    confidence: issue ? 'Medium' : 'High',
    techniques: techniques.length ? techniques : ['Input Validation Review', 'Parameter Handling Review'],
    title: title || `No SQL Injection confirmed for parameter "${param}"`,
    description:
      description ||
      'Safe SQL Injection probes (error, boolean, time-based) did not produce confirmed injection evidence for this parameter.',
    cwe: cwe.length ? cwe : [],
    owasp,
    cvss,
    baseline,
    evidence: evidence.slice(0, 8),
    status: issue ? 'Confirmed' : 'Pass',
  };
}

/**
 * Probe JSON login-like POST bodies safely (no account takeover attempts beyond auth bypass check).
 */
async function probeJsonAuth(page, endpoint, authHeader) {
  const headers = {
    accept: 'application/json',
    'content-type': 'application/json',
  };
  if (authHeader) headers.authorization = authHeader;

  const baselineBody = { email: 'nobody_probe_12345@example.com', password: 'WrongPass123!' };
  const baseline = await timedFetch(page, endpoint, {
    method: 'POST',
    headers,
    body: JSON.stringify(baselineBody),
  });

  const evidence = [];
  let issue = false;
  let finding = {
    title: `No SQL Injection confirmed for auth endpoint`,
    severity: 'Informational',
    description: 'Auth endpoint rejected SQL/NoSQL operator payloads without token issuance or SQL errors.',
    techniques: ['Error Handling Review', 'Boolean Logic Validation', 'Input Validation Review'],
    cwe: [],
    owasp: 'A03:2021 – Injection; WSTG-INPV-05',
    cvss: null,
  };

  for (const payload of ["' OR '1'='1", "admin'--", "test'"]) {
    const r = await timedFetch(page, endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify({ email: payload, password: 'x' }),
    });
    const c = classifyResponse(r.body, baseline, r);
    evidence.push({ technique: 'Error Handling Review', payload, ...r, ...c });
    if (c.sqlError) {
      issue = true;
      finding = {
        title: 'Error-based SQL Injection indicator on authentication endpoint',
        severity: 'Critical',
        description: 'SQL error patterns observed when injecting into login JSON fields.',
        techniques: ['Error Handling Review'],
        cwe: ['CWE-89'],
        owasp: 'A03:2021 – Injection; WSTG-INPV-05',
        cvss: 9.8,
      };
      break;
    }
    if (/token|access_token|jwt/i.test(r.body) && r.status >= 200 && r.status < 300) {
      issue = true;
      finding = {
        title: 'Possible authentication bypass via injection on login endpoint',
        severity: 'Critical',
        description: 'Injection payload appears to have resulted in a successful authentication response.',
        techniques: ['Boolean Logic Validation', 'Input Validation Review'],
        cwe: ['CWE-89', 'CWE-287'],
        owasp: 'A03:2021 – Injection; A07:2021 – Identification and Authentication Failures',
        cvss: 9.8,
      };
      break;
    }
  }

  if (!issue) {
    for (const body of NOSQL_OPERATORS) {
      const r = await timedFetch(page, endpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
      });
      evidence.push({ technique: 'JSON Parameter Injection Review', payload: JSON.stringify(body), ...r });
      if (/token|access_token|jwt/i.test(r.body) && r.status >= 200 && r.status < 300) {
        issue = true;
        finding = {
          title: 'NoSQL operator injection authentication bypass',
          severity: 'Critical',
          description: 'JSON operator payloads ($ne/$gt) appear to bypass authentication.',
          techniques: ['JSON Parameter Injection Review'],
          cwe: ['CWE-943', 'CWE-287'],
          owasp: 'A03:2021 – Injection; WSTG-INPV-06',
          cvss: 9.8,
        };
        break;
      }
    }
  }

  return {
    endpoint,
    method: 'POST',
    parameter: 'email / password',
    inputType: 'JSON',
    authRequired: false,
    issueFound: issue,
    severity: issue
      ? finding.cvss >= 9
        ? 'Critical'
        : finding.cvss >= 7
          ? 'High'
          : finding.cvss >= 5
            ? 'Medium'
            : 'Low'
      : 'Informational',
    confidence: issue ? 'High' : 'High',
    techniques: finding.techniques,
    title: finding.title,
    description: finding.description,
    cwe: finding.cwe,
    owasp: finding.owasp,
    cvss: finding.cvss,
    baseline,
    evidence: evidence.slice(0, 8),
    status: issue ? 'Confirmed' : 'Pass',
  };
}

function makeFinding(base, overlay) {
  const out = {
    ...base,
    ...overlay,
    issueFound: overlay.issueFound !== false && Boolean(overlay.cvss || overlay.issueFound),
    status: overlay.issueFound === false ? 'Pass' : 'Confirmed',
  };
  out[SEVERITY_KEY] = overlay[SEVERITY_KEY] || overlay.severityLevel || 'Informational';
  delete out.severityLevel;
  return out;
}

/**
 * Probe path segment parameters, e.g. /resource/{id}
 * Returns an ARRAY of findings so High / Medium / Low issues can all be reported.
 */
async function probePathParam(page, templateUrl, authHeader) {
  const match = templateUrl.match(/\{([^}]+)\}/);
  const param = match ? match[1] : 'id';
  const headers = { accept: 'application/json,text/html,*/*' };
  if (authHeader) headers.authorization = authHeader;

  const fill = (value) => templateUrl.replace(`{${param}}`, encodeURIComponent(value));
  const baseline = await timedFetch(page, fill('1'), { headers, method: 'GET' });
  const evidence = [];
  const found = [];

  const base = {
    endpoint: templateUrl,
    method: 'GET',
    parameter: param,
    inputType: 'Path',
    authRequired: Boolean(authHeader),
    confidence: 'High',
    baseline,
  };

  for (const payload of ["'", "1'", "1' OR '1'='1"]) {
    const r = await timedFetch(page, fill(payload), { headers, method: 'GET' });
    const c = classifyResponse(r.body, baseline, r);
    evidence.push({ technique: 'Error Handling Review', payload, ...r, ...c });
    if (c.sqlError) {
      found.push(
        makeFinding(base, {
          issueFound: true,
          severityLevel: 'High',
          title: `Error-based SQL Injection indicator in path parameter "${param}"`,
          description: 'SQL error patterns observed for path parameter injection probes.',
          techniques: ['Error Handling Review'],
          cwe: ['CWE-89'],
          owasp: 'A03:2021 – Injection; WSTG-INPV-05',
          cvss: 8.6,
          evidence: evidence.slice(0, 8),
        })
      );
      break;
    }
  }

  // NoSQL / regex checks — especially postal_code style routes
  const looksRegexSink = /postal|zip|code|search|filter/i.test(param) || /postal_code|search/i.test(templateUrl);
  if (looksRegexSink) {
    const clean = await timedFetch(page, fill('00000'), { headers, method: 'GET' });
    const star = await timedFetch(page, fill('.*'), { headers, method: 'GET' });
    const anchor = await timedFetch(page, fill('^7'), { headers, method: 'GET' });
    const badRegex = await timedFetch(page, fill('('), { headers, method: 'GET' });
    evidence.push({ technique: 'Parameter Handling Review', payload: '.*', ...star });
    evidence.push({ technique: 'Parameter Handling Review', payload: '^7', ...anchor });
    evidence.push({ technique: 'Error Handling Review', payload: '(', ...badRegex });

    const countOf = (body) => {
      try {
        const j = JSON.parse(body);
        if (Array.isArray(j)) return j.length;
        if (Array.isArray(j.data)) return j.data.length;
        if (Array.isArray(j.results)) return j.results.length;
      } catch {
        // ignore
      }
      return null;
    };
    const cleanCount = countOf(clean.body) ?? 0;
    const starCount = countOf(star.body);
    const anchorCount = countOf(anchor.body);
    const regexError =
      /51091|Location51091|invalid regular expression|\$regex/i.test(badRegex.body || '') ||
      /51091|Location51091|invalid regular expression/i.test(star.body || '');
    const authBlocked = [clean, star, anchor, badRegex].every((x) => x.status === 401 || x.status === 403);

    if (
      !authBlocked &&
      (regexError ||
        (starCount != null && starCount >= 20 && starCount > cleanCount + 5) ||
        ((star.len || 0) > (clean.len || 0) + 5000 && (star.status === 200 || star.status === 201)) ||
        (anchorCount != null && cleanCount === 0 && anchorCount > 0 && anchorCount < (starCount || 999999)))
    ) {
      found.push(
        makeFinding(base, {
          issueFound: true,
          severityLevel: 'High',
          title: `NoSQL regex injection in path parameter "${param}"`,
          description:
            'Path input appears to be compiled as a MongoDB regular expression (population/oracle differentials and/or regex engine errors), allowing query broadening beyond intended exact matches.',
          techniques: ['Parameter Handling Review', 'Input Validation Review', 'Error Handling Review'],
          cwe: ['CWE-943'],
          owasp: 'A03:2021 – Injection; WSTG-INPV-06',
          cvss: 7.5,
          evidence: evidence.slice(-6),
        })
      );
    } else if (authBlocked) {
      base.authBlocked = true;
    }
  }

  const nullDeref = evidence.find((e) =>
    /Cannot read property ['\"]status['\"] of null|Cannot read properties of null/i.test(e.body || '')
  );
  const leak = evidence.find(
    (e) =>
      e.sqlError ||
      e.nosqlError ||
      /Cast to ObjectId|\$limit stage|\$skip stage|mongoose|MongoError|Location51091/i.test(e.body || '')
  );

  // Medium and Low can coexist with each other (and with High on other params)
  if (leak && !found.some((f) => (f.cwe || []).includes('CWE-209'))) {
    found.push(
      makeFinding(base, {
        issueFound: true,
        severityLevel: 'Medium',
        title: `Verbose database / driver error disclosure via "${param}"`,
        description:
          'Malformed path values produce detailed database/ODM/driver errors (for example Mongoose Cast to ObjectId), revealing stack internals to clients.',
        techniques: ['Error Handling Review'],
        cwe: ['CWE-209'],
        owasp: 'A05:2021 – Security Misconfiguration; WSTG-ERRH-01',
        cvss: 5.3,
        evidence: evidence.filter((e) => /Cast to ObjectId|\$limit|\$skip|mongoose|Mongo|51091/i.test(e.body || '')).slice(0, 6),
      })
    );
  }

  if (nullDeref && !found.some((f) => (f.cwe || []).includes('CWE-476'))) {
    found.push(
      makeFinding(base, {
        issueFound: true,
        severityLevel: 'Low',
        title: `Unhandled null-dereference exception via "${param}"`,
        description:
          'Invalid or missing records cause unhandled null property access, returning raw runtime exceptions to clients.',
        techniques: ['Error Handling Review', 'Parameter Handling Review'],
        cwe: ['CWE-476'],
        owasp: 'A04:2021 – Insecure Design; WSTG-ERRH',
        cvss: 4.3,
        evidence: evidence.filter((e) => /null/i.test(e.body || '')).slice(0, 4),
      })
    );
  }

  if (!found.length) {
    found.push(
      makeFinding(base, {
        issueFound: false,
        severityLevel: 'Informational',
        title: `No SQL Injection confirmed for path parameter "${param}"`,
        description: base.authBlocked
          ? 'Endpoint requires authentication (401/403); path injection could not be fully validated without a valid token.'
          : 'Path parameter probes did not confirm SQL/NoSQL injection for this template.',
        techniques: ['Parameter Handling Review', 'Error Handling Review'],
        cwe: [],
        owasp: 'A03:2021 – Injection; WSTG-INPV-05',
        cvss: null,
        evidence: evidence.slice(0, 8),
        status: 'Pass',
      })
    );
  }

  for (const f of found) f.evidence = (f.evidence && f.evidence.length ? f.evidence : evidence).slice(0, 8);
  return found;
}

module.exports = {
  probeGetParam,
  probeJsonAuth,
  probePathParam,
  timedFetch,
};
