const { SEVERITY_KEY } = require('../severity');

function finding(partial) {
  const f = {
    module: partial.module || 'Surface Checks',
    featureName: partial.featureName || 'Security control',
    pageName: partial.pageName || 'Application',
    fullUrl: partial.fullUrl || partial.endpoint,
    endpoint: partial.endpoint,
    method: partial.method || 'GET',
    parameter: partial.parameter || 'n/a',
    inputType: partial.inputType || 'Passive',
    authRequired: Boolean(partial.authRequired),
    issueFound: Boolean(partial.issueFound),
    confidence: partial.confidence || 'Medium',
    techniques: partial.techniques || ['Configuration Review'],
    title: partial.title,
    description: partial.description,
    cwe: partial.cwe || [],
    owasp: partial.owasp || 'A05:2021 – Security Misconfiguration',
    cvss: partial.cvss ?? null,
    evidence: partial.evidence || [],
    status: partial.issueFound ? 'Confirmed' : 'Pass',
  };
  f[SEVERITY_KEY] = partial.severityLevel || (partial.issueFound ? 'Medium' : 'Informational');
  return f;
}

/**
 * Safe passive / light-touch checks for selected non-injection security types.
 */
async function runSurfaceChecks(page, targetUrl, selected, { apiBases = [] } = {}) {
  const out = [];
  const request = page.context().request;
  const origin = new URL(targetUrl).origin;

  let homepage;
  try {
    homepage = await request.fetch(targetUrl, { failOnStatusCode: false, timeout: 20000 });
  } catch (e) {
    return [
      finding({
        issueFound: false,
        title: 'Homepage unreachable for surface checks',
        description: String(e.message || e),
        endpoint: targetUrl,
        severityLevel: 'Informational',
      }),
    ];
  }

  const headers = homepage.headers();
  const headerMap = {};
  for (const [k, v] of Object.entries(headers)) headerMap[k.toLowerCase()] = v;

  // HTTP security headers
  if (selected.includes('http_headers') || selected.includes('security_misconfig') || selected.includes('clickjacking')) {
    const needed = {
      'content-security-policy': 'CSP',
      'strict-transport-security': 'HSTS',
      'x-content-type-options': 'X-Content-Type-Options',
      'x-frame-options': 'X-Frame-Options',
      'referrer-policy': 'Referrer-Policy',
      'permissions-policy': 'Permissions-Policy',
    };
    const missing = Object.entries(needed)
      .filter(([k]) => !headerMap[k])
      .map(([, label]) => label);

    out.push(
      finding({
        module: 'HTTP Header Security',
        issueFound: missing.length > 0,
        severityLevel: missing.length >= 3 ? 'Medium' : missing.length ? 'Low' : 'Informational',
        title: missing.length
          ? `Missing security headers (${missing.length})`
          : 'Security headers present',
        description: missing.length
          ? `The following recommended headers were not observed: ${missing.join(', ')}.`
          : 'Common security headers were observed on the target response.',
        endpoint: targetUrl,
        cwe: ['CWE-693'],
        owasp: 'A05:2021 – Security Misconfiguration',
        cvss: missing.length >= 3 ? 5.3 : missing.length ? 3.7 : null,
        evidence: [{ technique: 'Header Review', body: JSON.stringify(missing), status: homepage.status() }],
        techniques: ['HTTP Header Security Review'],
        parameter: 'response-headers',
      })
    );

    if (selected.includes('clickjacking') && !headerMap['x-frame-options'] && !(headerMap['content-security-policy'] || '').includes('frame-ancestors')) {
      out.push(
        finding({
          module: 'Clickjacking',
          issueFound: true,
          severityLevel: 'Medium',
          title: 'Clickjacking protections not evident',
          description: 'Neither X-Frame-Options nor CSP frame-ancestors was detected.',
          endpoint: targetUrl,
          cwe: ['CWE-1021'],
          cvss: 5.3,
          techniques: ['Clickjacking Review'],
        })
      );
    }
  }

  // CORS
  if (selected.includes('cors')) {
    try {
      const corsRes = await request.fetch(targetUrl, {
        method: 'GET',
        headers: { origin: 'https://evil-example-assessment.invalid' },
        failOnStatusCode: false,
        timeout: 15000,
      });
      const acao = (corsRes.headers()['access-control-allow-origin'] || '').trim();
      const acac = (corsRes.headers()['access-control-allow-credentials'] || '').trim();
      const wildcard = acao === '*';
      const reflectsEvil = acao.includes('evil-example-assessment.invalid');
      const bad = wildcard || reflectsEvil;
      out.push(
        finding({
          module: 'CORS',
          issueFound: bad,
          severityLevel: reflectsEvil && /true/i.test(acac) ? 'High' : bad ? 'Medium' : 'Informational',
          title: bad ? 'CORS misconfiguration detected' : 'CORS does not appear overly permissive on homepage',
          description: bad
            ? `Access-Control-Allow-Origin was "${acao}"${acac ? ` with credentials=${acac}` : ''}.`
            : 'No obvious wildcard/reflected Origin ACAO was observed on the homepage response.',
          endpoint: targetUrl,
          cwe: ['CWE-942'],
          cvss: reflectsEvil && /true/i.test(acac) ? 7.5 : bad ? 5.3 : null,
          evidence: [{ technique: 'CORS Probe', body: `ACAO=${acao}; ACAC=${acac}`, status: corsRes.status() }],
          techniques: ['CORS Misconfiguration Review'],
          parameter: 'Origin',
        })
      );
    } catch (e) {
      out.push(
        finding({
          module: 'CORS',
          issueFound: false,
          title: 'CORS probe skipped',
          description: String(e.message || e),
          endpoint: targetUrl,
        })
      );
    }
  }

  // Cookie security
  if (selected.includes('cookie_security') || selected.includes('session_mgmt')) {
    const cookies = await page.context().cookies(targetUrl);
    const weak = cookies.filter((c) => !c.httpOnly || !c.secure || !c.sameSite || c.sameSite === 'None');
    out.push(
      finding({
        module: 'Cookie Security',
        issueFound: weak.length > 0,
        severityLevel: weak.length ? 'Medium' : 'Informational',
        title: weak.length ? `Cookie security flags incomplete (${weak.length} cookie(s))` : 'Cookie flags look reasonable',
        description: weak.length
          ? `One or more cookies are missing HttpOnly/Secure/SameSite controls: ${weak
              .map((c) => c.name)
              .slice(0, 8)
              .join(', ')}.`
          : cookies.length
            ? 'Observed cookies include expected security attributes.'
            : 'No cookies observed on the target URL during this check.',
        endpoint: targetUrl,
        cwe: ['CWE-614', 'CWE-1004'],
        cvss: weak.length ? 5.3 : null,
        evidence: cookies.slice(0, 8).map((c) => ({
          technique: 'Cookie Review',
          payload: c.name,
          body: `httpOnly=${c.httpOnly}; secure=${c.secure}; sameSite=${c.sameSite}`,
          status: 200,
        })),
        techniques: ['Cookie Security Testing'],
        parameter: 'Set-Cookie',
      })
    );
  }

  // Sensitive data / HTTPS
  if (selected.includes('sensitive_data')) {
    const isHttps = targetUrl.startsWith('https://');
    out.push(
      finding({
        module: 'Sensitive Data Exposure',
        issueFound: !isHttps,
        severityLevel: isHttps ? 'Informational' : 'High',
        title: isHttps ? 'Target is served over HTTPS' : 'Target is not using HTTPS',
        description: isHttps
          ? 'Transport encryption is enabled for the target URL.'
          : 'The target URL is not HTTPS, increasing exposure of credentials and tokens in transit.',
        endpoint: targetUrl,
        cwe: ['CWE-319'],
        cvss: isHttps ? null : 7.5,
        techniques: ['Sensitive Data Exposure Review'],
      })
    );
  }

  // Information disclosure common paths
  if (selected.includes('info_disclosure') || selected.includes('security_misconfig')) {
    const paths = ['/.env', '/.git/HEAD', '/server-status', '/actuator/health', '/phpinfo.php', '/config.json'];
    for (const p of paths) {
      try {
        const url = origin + p;
        const res = await request.fetch(url, { failOnStatusCode: false, timeout: 10000 });
        const body = await res.text();
        const interesting =
          res.status() === 200 &&
          body.length > 20 &&
          !/<!doctype html|<html/i.test(body.slice(0, 200)) &&
          /(APP_KEY|DB_PASSWORD|ref:|phpinfo|mongo|secret|api[_-]?key)/i.test(body);
        if (interesting) {
          out.push(
            finding({
              module: 'Information Disclosure',
              issueFound: true,
              severityLevel: 'High',
              title: `Sensitive path accessible: ${p}`,
              description: `The path ${p} returned HTTP 200 with content that appears sensitive or diagnostic.`,
              endpoint: url,
              cwe: ['CWE-200'],
              cvss: 7.5,
              evidence: [{ technique: 'Path Probe', status: res.status(), len: body.length, body: body.slice(0, 180) }],
              techniques: ['Information Disclosure Review'],
              parameter: p,
            })
          );
        }
      } catch {
        // ignore
      }
    }
  }

  // JWT security (if token available later — caller may pass token via page storage)
  if (selected.includes('jwt')) {
    const token = await page.evaluate(() => {
      for (const k of Object.keys(localStorage || {})) {
        const v = localStorage.getItem(k);
        if (v && /^eyJ/.test(v)) return v;
      }
      return null;
    }).catch(() => null);

    if (token) {
      try {
        const [, payload] = token.split('.');
        const json = JSON.parse(Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
        const algHeader = JSON.parse(
          Buffer.from(token.split('.')[0].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')
        );
        const issues = [];
        if (algHeader.alg === 'none' || algHeader.alg === 'HS256' && !algHeader.typ) {
          /* HS256 alone is not a finding */
        }
        if (algHeader.alg === 'none') issues.push('alg=none');
        if (json.exp && json.exp > 20000000000) issues.push('extremely long-lived exp');
        if (!json.exp) issues.push('missing exp');
        out.push(
          finding({
            module: 'JWT Security',
            issueFound: issues.length > 0,
            severityLevel: issues.length ? 'Medium' : 'Informational',
            title: issues.length ? `JWT weaknesses: ${issues.join(', ')}` : 'JWT structure looks conventional',
            description: issues.length
              ? `Observed JWT concerns: ${issues.join('; ')}.`
              : 'A JWT was observed with a conventional header/payload structure.',
            endpoint: targetUrl,
            cwe: ['CWE-347'],
            cvss: issues.length ? 5.3 : null,
            evidence: [{ technique: 'JWT Review', body: JSON.stringify({ alg: algHeader.alg, exp: json.exp }), status: 200 }],
            techniques: ['JWT Security Testing'],
            parameter: 'Authorization/token',
            authRequired: true,
          })
        );
      } catch {
        // ignore parse errors
      }
    }
  }

  // Open redirect parameter discovery (light)
  if (selected.includes('open_redirect')) {
    const probes = ['redirect', 'url', 'next', 'returnUrl', 'return_to', 'continue'];
    for (const param of probes) {
      const u = `${origin}/?${param}=https://evil-example-assessment.invalid`;
      try {
        const res = await request.fetch(u, { failOnStatusCode: false, maxRedirects: 0, timeout: 10000 });
        const loc = res.headers()['location'] || '';
        if (/evil-example-assessment\.invalid/i.test(loc)) {
          out.push(
            finding({
              module: 'Open Redirect',
              issueFound: true,
              severityLevel: 'Medium',
              title: `Open redirect via parameter "${param}"`,
              description: `Server issued a Location redirect to an external attacker-controlled host via ${param}.`,
              endpoint: u,
              cwe: ['CWE-601'],
              cvss: 5.4,
              evidence: [{ technique: 'Open Redirect Probe', status: res.status(), body: `Location=${loc}` }],
              techniques: ['Open Redirect Testing'],
              parameter: param,
            })
          );
          break;
        }
      } catch {
        // ignore
      }
    }
  }

  // XSS reflected (safe alert-free marker)
  if (selected.includes('xss')) {
    const marker = 'xssprobe' + Date.now().toString().slice(-6);
    const payload = `<svg/onload=/**/('${marker}')>`;
    try {
      const u = `${origin}/?q=${encodeURIComponent(payload)}&search=${encodeURIComponent(payload)}`;
      const res = await request.fetch(u, { failOnStatusCode: false, timeout: 15000 });
      const body = await res.text();
      const reflected = body.includes(marker) && /<svg|onload=/i.test(body);
      out.push(
        finding({
          module: 'XSS',
          issueFound: reflected,
          severityLevel: reflected ? 'High' : 'Informational',
          title: reflected ? 'Reflected XSS indicator on query parameter' : 'No obvious reflected XSS on homepage query params',
          description: reflected
            ? 'Attacker-controlled markup/marker was reflected without apparent encoding on a query parameter.'
            : 'Safe reflected-XSS marker was not returned unencoded on basic homepage query parameters.',
          endpoint: u,
          cwe: ['CWE-79'],
          cvss: reflected ? 7.1 : null,
          evidence: [{ technique: 'Reflected XSS Probe', status: res.status(), body: body.slice(0, 200) }],
          techniques: ['Cross-Site Scripting Testing'],
          parameter: 'q/search',
        })
      );
    } catch (e) {
      out.push(
        finding({
          module: 'XSS',
          issueFound: false,
          title: 'XSS probe skipped',
          description: String(e.message || e),
          endpoint: targetUrl,
        })
      );
    }
  }

  // API security / BAC-IDOR light signal using api bases without destructive actions
  if (selected.includes('api_security') || selected.includes('bac') || selected.includes('idor')) {
    for (const base of apiBases.slice(0, 3)) {
      try {
        const originBase = base.includes('://') ? new URL(base).origin : base;
        const root = /\/api$/i.test(base) ? base : `${originBase}/api`;
        const probeUrl = `${root}/users/1`;
        const res = await request.fetch(probeUrl, { failOnStatusCode: false, timeout: 12000 });
        const body = await res.text();
        const exposed =
          res.status() === 200 &&
          /("email"|"phone"|"password"|"role")/i.test(body) &&
          !/<!doctype html/i.test(body.slice(0, 40));
        if (exposed) {
          out.push(
            finding({
              module: 'Broken Access Control / IDOR',
              issueFound: true,
              severityLevel: 'High',
              title: 'Possible IDOR / object access on /users/1',
              description: 'An unauthenticated or low-privilege request to a user object endpoint returned user-like JSON fields.',
              endpoint: probeUrl,
              cwe: ['CWE-639', 'CWE-284'],
              cvss: 7.5,
              evidence: [{ technique: 'IDOR Probe', status: res.status(), body: body.slice(0, 200) }],
              techniques: ['Broken Access Control', 'IDOR Testing'],
              parameter: 'id',
            })
          );
          break;
        }
      } catch {
        // ignore
      }
    }
  }

  // SSRF - only parameter presence note / safe internal URL probe on known params (non-destructive)
  if (selected.includes('ssrf')) {
    out.push(
      finding({
        module: 'SSRF',
        issueFound: false,
        severityLevel: 'Informational',
        title: 'SSRF deep testing requires endpoint-specific request sinks',
        description:
          'No confirmed SSRF was validated in this safe pass. Review URL-fetching features (webhooks, importers, previewers) manually or enable authenticated API traffic capture for deeper SSRF probes.',
        endpoint: targetUrl,
        techniques: ['SSRF Review'],
        cwe: ['CWE-918'],
      })
    );
  }

  // CSRF - cookie SameSite / token presence heuristic
  if (selected.includes('csrf')) {
    const cookies = await page.context().cookies(targetUrl);
    const noSameSite = cookies.filter((c) => !c.sameSite || c.sameSite === 'None');
    out.push(
      finding({
        module: 'CSRF',
        issueFound: noSameSite.length > 0,
        severityLevel: noSameSite.length ? 'Low' : 'Informational',
        title: noSameSite.length ? 'CSRF risk signals in cookie SameSite policy' : 'No strong CSRF cookie signal observed',
        description: noSameSite.length
          ? 'One or more cookies lack strict SameSite controls, which can contribute to CSRF risk if state-changing requests rely only on cookies.'
          : 'Cookie SameSite attributes did not show an obvious CSRF weakness in this pass. Also verify anti-CSRF tokens on state-changing forms.',
        endpoint: targetUrl,
        cwe: ['CWE-352'],
        cvss: noSameSite.length ? 4.3 : null,
        techniques: ['CSRF Testing'],
        parameter: 'cookies/forms',
      })
    );
  }

  // Rate limiting — informational unless credentials provided (handled by caller lightly)
  if (selected.includes('rate_limiting')) {
    out.push(
      finding({
        module: 'Rate Limiting',
        issueFound: false,
        severityLevel: 'Informational',
        title: 'Rate-limiting not aggressively tested (safe mode)',
        description:
          'To avoid account lockouts/DoS, this tool does not flood login endpoints. Review WAF/rate-limit configuration and perform authorized controlled tests separately.',
        endpoint: targetUrl,
        techniques: ['Rate Limiting Review'],
      })
    );
  }

  // Broken auth — only if homepage/login reachable
  if (selected.includes('broken_auth')) {
    out.push(
      finding({
        module: 'Broken Authentication',
        issueFound: false,
        severityLevel: 'Informational',
        title: 'Authentication controls require credentialed workflow review',
        description:
          'Provide username/password to exercise login token issuance, or manually review MFA, password reset, and session invalidation. Injection auth probes are covered under SQLi/NoSQLi modules when selected.',
        endpoint: `${origin}/login`,
        techniques: ['Broken Authentication Review'],
      })
    );
  }

  return out;
}

module.exports = { runSurfaceChecks };
